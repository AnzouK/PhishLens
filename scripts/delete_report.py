#!/usr/bin/env python3
"""Delete reports by reference (a user asked for it). On a self-hosted
server, from the repository checkout:

    python3 scripts/delete_report.py --dir ~/phishlens_data/feedback a1b2c3d4e5f6

Removes the report's own file (YYYY-MM/<reference>.json) and, for reports
received by an older server, rewrites the monthly feedback-YYYY-MM.jsonl
files without the matching lines. Prints how many were removed. Default
folder: $FEEDBACK_DIR.

On PhishLens Cloud the folder is a Cloud Storage bucket: remove the file
with `gcloud storage rm "gs://BUCKET/*/<reference>.json"` instead
(docs/operations.md).
"""

from __future__ import annotations

import argparse
import fcntl
import json
import os
from pathlib import Path


def delete(folder: Path, references: set[str]) -> int:
    removed = 0
    for path in sorted(folder.glob("[0-9]*-[0-9]*/*.json")):
        if path.stem in references:
            path.unlink()
            removed += 1
    # Older servers appended to the monthly files under this lock; it is
    # kept for a server not yet updated.
    fd = os.open(folder / ".lock", os.O_WRONLY | os.O_CREAT, 0o600)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX)
        return removed + _delete_legacy(folder, references)
    finally:
        os.close(fd)


def _delete_legacy(folder: Path, references: set[str]) -> int:
    removed = 0
    for path in sorted(folder.glob("feedback-*.jsonl")):
        kept, here = [], 0
        for line in path.read_text(encoding="utf-8").splitlines():
            try:
                ref = json.loads(line).get("reference")
            except (json.JSONDecodeError, AttributeError):
                ref = None
            if ref in references:
                here += 1
            else:
                kept.append(line)
        if not here:
            continue
        removed += here
        tmp = path.with_suffix(".tmp")
        tmp.write_text("".join(x + "\n" for x in kept), encoding="utf-8")
        os.chmod(tmp, 0o600)
        tmp.replace(path)
    return removed


def main() -> None:
    ap = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    ap.add_argument("references", nargs="+")
    ap.add_argument("--dir", default=os.environ.get("FEEDBACK_DIR", ""))
    a = ap.parse_args()
    if not a.dir:
        raise SystemExit("no folder: set FEEDBACK_DIR or pass --dir")
    n = delete(Path(a.dir).expanduser(), set(a.references))
    print(f"{n} report(s) deleted")


if __name__ == "__main__":
    main()
