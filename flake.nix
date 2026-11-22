{
  description = "Sentinel — Plasma 6 security dashboard for NixOS";

  inputs.nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";

  outputs = { self, nixpkgs }:
    let
      system = "x86_64-linux";
      pkgs = import nixpkgs { inherit system; };
      kde = pkgs.kdePackages;
    in {
      devShells.${system}.default = pkgs.mkShell {
        packages = with pkgs; [
          jq
          nodejs
          python3
          kde.qtdeclarative
          kde.kirigami
          kde.plasma-workspace
          kde.plasma-sdk
          kde.kpackage
        ];

        shellHook = ''
          export QML2_IMPORT_PATH="${kde.qtdeclarative}/lib/qt-6/qml:${kde.kirigami}/lib/qt-6/qml:${kde.plasma-workspace}/lib/qt-6/qml''${QML2_IMPORT_PATH:+:$QML2_IMPORT_PATH}"
          export QML_XHR_ALLOW_FILE_READ=1
          echo "Sentinel dev shell: run ./scripts/check.sh"
        '';
      };
    };
}
