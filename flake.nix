{
  description = "Sentinel — Plasma 6 security dashboard for NixOS";

  inputs.nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";

  outputs = { self, nixpkgs }:
    let
      systems = [ "x86_64-linux" "aarch64-linux" ];
      forAllSystems = nixpkgs.lib.genAttrs systems;
      pkgsFor = system: import nixpkgs { inherit system; };

      system = "x86_64-linux";
      pkgs = pkgsFor system;
      kde = pkgs.kdePackages;
    in {
      packages = forAllSystems (system: {
        sentinel-widget = (pkgsFor system).callPackage ./nix/applet.nix { };
        default = self.packages.${system}.sentinel-widget;
      });

      # Import this from a NixOS configuration and set
      # services.sentinel.enable = true. The applet package is filled in here
      # so the applet and the backend always come from the same revision.
      nixosModules.default = { pkgs, ... }: {
        imports = [ ./nix/module.nix ];
        services.sentinel.package = pkgs.lib.mkDefault
          (self.packages.${pkgs.stdenv.hostPlatform.system}.sentinel-widget);
      };

      devShells.${system}.default = pkgs.mkShell {
        packages = with pkgs; [
          gettext
          jq
          nodejs
          python3
          kde.qtdeclarative
          kde.kirigami
          kde.plasma-workspace
          kde.plasma5support
          kde.plasma-sdk
          kde.kpackage
        ];

        shellHook = ''
          export QML2_IMPORT_PATH="${kde.qtdeclarative}/lib/qt-6/qml:${kde.kirigami}/lib/qt-6/qml:${kde.plasma-workspace}/lib/qt-6/qml''${QML2_IMPORT_PATH:+:$QML2_IMPORT_PATH}"
          # KF6 looks up the plasma5support dataengines (executable, etc.)
          # through the Qt plugin path. A desktop session exports it, but a
          # headless shell does not, so QML tests that run commands through
          # Plasma5Support would otherwise fail on CI.
          export QT_PLUGIN_PATH="${kde.plasma5support}/lib/qt-6/plugins''${QT_PLUGIN_PATH:+:$QT_PLUGIN_PATH}"
          export QML_XHR_ALLOW_FILE_READ=1
          echo "Sentinel dev shell: run ./scripts/check.sh"
        '';
      };
    };
}
