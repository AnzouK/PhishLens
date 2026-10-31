#!/usr/bin/env python3
"""The extension zip for a browser store, from extension/.

    python3 scripts/build_extension.py chrome  dist/PhishLens-chrome-2.0.12.zip
    python3 scripts/build_extension.py firefox dist/PhishLens-firefox-2.0.12.zip

Chrome gets extension/ as it is. Firefox gets the same files with three
manifest changes:
  - the background runs as an event page (Firefox has no extension
    service worker): background.scripts lists the libraries that
    background.js loads with importScripts in Chrome, then background.js;
  - browser_specific_settings.gecko: the add-on id, which must never
    change once published, the minimum Firefox version, and the data the
    add-on sends out, which Firefox shows to the user before install;
  - nothing else: same permissions, content scripts and files.
"""

from __future__ import annotations

import json
import re
import sys
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
EXT = ROOT / "extension"

FIREFOX_ID = "phishlens@phishlens.dev"
# data_collection_permissions needs Firefox 140 on desktop.
FIREFOX_MIN = "140.0"
# What leaves the browser (docs: Firefox built-in data consent).
#   personalCommunications  the email being scanned goes to the server
#   websiteContent          read from the open Gmail or Outlook page
#   technicalAndInteraction a report or shared statistics, only when the
#                           user sends them
FIREFOX_DATA = {
    "required": ["personalCommunications", "websiteContent"],
    "optional": ["technicalAndInteraction"],
}

SKIP = {".DS_Store"}


def background_libraries() -> list[str]:
    """The files background.js passes to importScripts, in order."""
    src = (EXT / "background.js").read_text(encoding="utf-8")
    call = re.search(r"importScripts\(([^)]*)\)", src)
    if not call:
        raise SystemExit("background.js: no importScripts call found")
    return re.findall(r'"([^"]+\.js)"', call.group(1))


def manifest_for(browser: str) -> dict:
    manifest = json.loads((EXT / "manifest.json").read_text(encoding="utf-8"))
    if browser == "chrome":
        return manifest
    manifest["background"] = {"scripts": [*background_libraries(), "background.js"]}
    manifest["browser_specific_settings"] = {
        "gecko": {
            "id": FIREFOX_ID,
            "strict_min_version": FIREFOX_MIN,
            "data_collection_permissions": FIREFOX_DATA,
        }
    }
    return manifest


def build(browser: str, out: Path) -> list[str]:
    manifest = manifest_for(browser)
    files = sorted(
        p
        for p in EXT.rglob("*")
        if p.is_file() and p.name not in SKIP and p.name != "manifest.json"
    )
    missing = [
        f for f in manifest.get("background", {}).get("scripts", []) if not (EXT / f).is_file()
    ]
    if missing:
        raise SystemExit(f"missing background scripts: {missing}")
    out.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(out, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr("manifest.json", json.dumps(manifest, indent=2, ensure_ascii=False) + "\n")
        for p in files:
            z.write(p, p.relative_to(EXT).as_posix())
    return ["manifest.json", *(p.relative_to(EXT).as_posix() for p in files)]


def main() -> int:
    if len(sys.argv) != 3 or sys.argv[1] not in ("chrome", "firefox"):
        print(__doc__, file=sys.stderr)
        return 2
    names = build(sys.argv[1], Path(sys.argv[2]))
    print(f"{sys.argv[2]}: {len(names)} files")
    return 0


if __name__ == "__main__":
    sys.exit(main())
