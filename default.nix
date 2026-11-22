# Convenience entry point for non-flake builds; the flake uses nix/applet.nix
# directly. `nix-build -E 'with import <nixpkgs> {}; callPackage ./default.nix {}'`
{ lib, stdenv }:
import ./nix/applet.nix { inherit lib stdenv; }
