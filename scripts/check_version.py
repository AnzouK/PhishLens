"""Fail when the backend and the extension disagree on the version.

The extension and the backend share one version number (CHANGELOG.md):
backend/settings.py VERSION and extension/manifest.json "version".
"""

from __future__ import annotations

import ast
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def backend_version() -> str:
    tree = ast.parse((ROOT / "backend" / "settings.py").read_text())
    for node in tree.body:
        if isinstance(node, ast.Assign) and any(
            getattr(t, "id", "") == "VERSION" for t in node.targets
        ):
            return ast.literal_eval(node.value)
    raise SystemExit("VERSION not found in backend/settings.py")


def main() -> None:
    backend = backend_version()
    extension = json.loads((ROOT / "extension" / "manifest.json").read_text())["version"]
    if backend != extension:
        sys.exit(
            f"Version mismatch: backend/settings.py {backend}, extension/manifest.json {extension}"
        )
    print(f"version {backend}")


if __name__ == "__main__":
    main()
