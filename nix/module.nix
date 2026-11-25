# NixOS module for the Sentinel backend.
#
# Import it and set services.sentinel.enable = true; this installs the Plasma
# applet and the two services that feed it:
#
#   sentinel.service          vulnxscan over /run/current-system -> status.json
#   sentinel-tracker.service  tracker annotations + triage verdicts, folded
#                             into the same status.json
#
# The applet reads status.json only. The tracker pass runs after every scan and
# every 15 minutes to resume/refresh tracker state; the triage step is part of
# that pass, so there is no third unit and no second file to keep in sync.
{ config, lib, pkgs, ... }:

let
  cfg = config.services.sentinel;
  stateDir = "/var/lib/sentinel";
  cacheDir = "/var/cache/sentinel";
  trackerTokenFile = "${stateDir}/tracker-token";

  appletConfig =
    if cfg.user != null
    then "${config.users.users.${cfg.user}.home}/.config/plasma-org.kde.plasma.desktop-appletsrc"
    else null;

  serviceEnvironment = [
    "LANG=C.UTF-8"
    "SSL_CERT_FILE=/etc/ssl/certs/ca-bundle.crt"
    "SENTINEL_SYSTEM_RELEASE=${config.system.nixos.release}"
    # Shown in the applet as "nixpkgs/<channel> (<rev>)": the revision this
    # system closure was built from.
    "SENTINEL_NIXPKGS_REV=${config.system.nixos.revision}"
    "SENTINEL_TRACKER_TOKEN_FILE=${trackerTokenFile}"
    # The report step reads the runtime closure graph to turn the scanner's
    # component evidence into "introduced by" chains.
    "SENTINEL_NIX_STORE=${pkgs.nix}/bin/nix-store"
    "SENTINEL_ORIGIN_ROOT=/run/current-system"
  ] ++ lib.optional (appletConfig != null) "SENTINEL_APPLET_CONFIG=${appletConfig}";

  scan = pkgs.writeShellScript "sentinel-status" ''
    set -u

    report=${stateDir}/report.csv
    evidence=${stateDir}/evidence.json
    log=${stateDir}/last.log
    status=${stateDir}/status.json

    # Drop the previous report and evidence so a failed scan is reported as
    # UNKNOWN rather than silently reusing stale results.
    rm -f "$report" "$evidence"

    ${pkgs.sbomnix}/bin/vulnxscan --format csv -o "$report" \
      --evidence-out "$evidence" /run/current-system >"$log" 2>&1
    rc=$?

    ${pkgs.python3}/bin/python3 ${./backend/sentinel-status.py} report \
      "$report" "$status" "$log" "$rc" "$evidence" >>"$log" 2>&1
  '';

  tracker = pkgs.writeShellScript "sentinel-tracker" ''
    set -u
    log=${stateDir}/last.log

    ${pkgs.python3}/bin/python3 ${./backend/sentinel-status.py} tracker \
      ${stateDir}/status.json ${cacheDir}/tracker-cache.json >>"$log" 2>&1

    # Classify the findings and fold the verdicts into status.json, so the
    # applet reads a single file. A triage failure must not fail the scan;
    # the previous verdicts stay in place.
    if ! ${pkgs.nodejs}/bin/node ${../tools/triage.mjs} \
        --status ${stateDir}/status.json \
        --evidence ${stateDir}/evidence.json \
        --cache ${cacheDir}/triage-cache \
        --ignore ${stateDir}/triage-ignore.json \
        --embed >>"$log" 2>&1; then
      echo "WARN     triage pass failed, keeping the previous verdicts" >>"$log"
      ${pkgs.python3}/bin/python3 ${./backend/sentinel-status.py} \
        triage-failed ${stateDir}/status.json >>"$log" 2>&1 || true
    fi
  '';
in
{
  options.services.sentinel = {
    enable = lib.mkEnableOption "the Sentinel NixOS vulnerability scanner";

    user = lib.mkOption {
      type = lib.types.nullOr lib.types.str;
      default = null;
      example = "alice";
      description = ''
        User whose Plasma applet configuration holds the tracker API token.
        With `null`, only the root-readable token file
        {file}`/var/lib/sentinel/tracker-token` is used.
      '';
    };

    package = lib.mkOption {
      type = lib.types.package;
      description = ''
        The Sentinel Plasma applet package to install. The flake's
        {option}`nixosModules.default` sets this to the matching applet.
      '';
    };
  };

  config = lib.mkIf cfg.enable {
    environment.systemPackages = [ cfg.package ];

    systemd.services.sentinel = {
      description = "Scan the NixOS system closure for known vulnerabilities";
      wants = [ "network-online.target" ];
      after = [ "network-online.target" ];
      serviceConfig = {
        Type = "oneshot";
        ExecStart = scan;
        # Start a tracker refresh from the old scan. --no-block keeps the scan
        # fast; the tracker then reads the new status.json.
        ExecStartPost = "${config.systemd.package}/bin/systemctl --no-block restart sentinel-tracker.service";
        StateDirectory = "sentinel";
        # Keeps the scanner databases out of /root.
        CacheDirectory = "sentinel";
        WorkingDirectory = stateDir;
        Environment = serviceEnvironment;
        # The first run downloads the vulnerability databases and scans the
        # whole closure; later runs are much faster.
        TimeoutStartSec = "2h";
        Nice = 10;
        IOSchedulingClass = "idle";
      };
    };

    # Runs after sentinel.service. The first tracker pass can take a long time
    # without a token; status.json is updated while it runs so the applet can
    # show progress.
    systemd.services.sentinel-tracker = {
      description = "Check NixOS vulnerabilities against the Nixpkgs security tracker";
      wants = [ "network-online.target" ];
      after = [ "network-online.target" "sentinel.service" ];
      serviceConfig = {
        Type = "oneshot";
        ExecStart = tracker;
        StateDirectory = "sentinel";
        CacheDirectory = "sentinel";
        WorkingDirectory = stateDir;
        Environment = serviceEnvironment;
        TimeoutStartSec = "2h";
        Nice = 10;
        IOSchedulingClass = "idle";
      };
    };

    # Resume an interrupted tracker pass (rate limit, crash, reboot) without
    # waiting for the next daily scan. The service is cheap when everything is
    # already cached, and the triage step rides along with it.
    systemd.timers.sentinel-tracker = {
      wantedBy = [ "timers.target" ];
      timerConfig = {
        OnBootSec = "45min";
        OnUnitActiveSec = "15min";
        Persistent = true;
      };
    };

    systemd.timers.sentinel = {
      wantedBy = [ "timers.target" ];
      timerConfig = {
        OnBootSec = "30min";
        OnCalendar = "*-*-* 04:00:00";
        Persistent = true;
      };
    };

    # Let wheel users trigger the scan from the applet without a password
    # prompt. Only this unit and only the start verb are allowed.
    security.polkit.extraConfig = ''
      polkit.addRule(function(action, subject) {
        if (action.id == "org.freedesktop.systemd1.manage-units" &&
            action.lookup("unit") == "sentinel.service" &&
            action.lookup("verb") == "start" &&
            subject.isInGroup("wheel")) {
          return polkit.Result.YES;
        }
      });
    '';
  };
}
