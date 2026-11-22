{ stdenv, lib }:

stdenv.mkDerivation {
  pname = "sentinel-widget";
  version = "0.2.0";

  src = ./.;

  dontConfigure = true;
  dontBuild = true;

  installPhase = ''
    runHook preInstall
    mkdir -p $out/share/plasma/plasmoids/io.github.steinhagen.sentinel
    cp -r metadata.json contents $out/share/plasma/plasmoids/io.github.steinhagen.sentinel/
    runHook postInstall
  '';

  meta = {
    description = "Plasma 6 security dashboard for NixOS vulnerability scans";
    license = lib.licenses.mit;
    platforms = lib.platforms.linux;
  };
}
