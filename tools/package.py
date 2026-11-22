#!/usr/bin/env python3
"""Build the KDE Store .plasmoid archive from this checkout."""

from __future__ import annotations

import json
import zipfile
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent
METADATA = ROOT / "metadata.json"
CONTENTS = ROOT / "contents"
DIST = ROOT / "dist"


def main() -> None:
    data = json.loads(METADATA.read_text(encoding="utf-8"))
    version = data["KPlugin"]["Version"]
    output = DIST / f"sentinel-{version}.plasmoid"
    DIST.mkdir(parents=True, exist_ok=True)

    with zipfile.ZipFile(output, "w", zipfile.ZIP_DEFLATED) as archive:
        archive.write(METADATA, "metadata.json")
        for path in sorted(CONTENTS.rglob("*")):
            if path.is_file():
                archive.write(path, path.relative_to(ROOT))

    print(output)


if __name__ == "__main__":
    main()
