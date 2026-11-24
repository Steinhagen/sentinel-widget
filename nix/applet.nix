# The Plasma applet, built straight from this repository.
#
# metadata.json is the package manifest and contents/ the applet itself; the
# tests, docs and tools are not part of the installed plasmoid.
{ lib, stdenv }:

let
  src = lib.cleanSource ../.;
  pluginId = (lib.importJSON (src + "/metadata.json")).KPlugin.Id;
in
stdenv.mkDerivation {
  pname = "sentinel-widget";
  version = "0.2-unstable";

  inherit src;

  dontConfigure = true;
  dontBuild = true;

  installPhase = ''
    runHook preInstall
    dest=$out/share/plasma/plasmoids/${pluginId}
    mkdir -p "$dest"
    cp -r metadata.json contents "$dest/"

    iconDest=$out/share/icons/hicolor/scalable/status
    mkdir -p "$iconDest"
    cp contents/icons/sentinel-severity-*.svg "$iconDest/"
    runHook postInstall
  '';

  meta = {
    description = "Plasma 6 security dashboard for NixOS vulnerability scans";
    homepage = "https://github.com/Steinhagen/sentinel-widget";
    license = lib.licenses.mit;
    platforms = lib.platforms.linux;
  };
}
