#!/usr/bin/env python3
"""Publishable copy of a benchmark run (scripts/benchmark.py --cache).

Keeps, per email: its id (the first 16 hex digits of the SHA-256 of the
raw message, so anyone with the same public dataset finds the same
email), the label, the verdict, the scores, the language and the trust
path. Nothing of the email itself. Use it only on runs over public
datasets (phishing_pot, Nazario, the Apache mailing lists), never on a
personal inbox.

    python3 scripts/export_benchmark.py docs/benchmark/fresh-phishing.jsonl ~/bench/fresh-live.jsonl --label phishing
    python3 scripts/export_benchmark.py docs/benchmark/apache-legit.jsonl ~/bench/r7b/apache-r4.jsonl --label legit

Then check a published file against your own run:

    python3 scripts/export_benchmark.py --compare docs/benchmark/fresh-phishing.jsonl my-run.jsonl
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

KEEP = ("id", "label", "verdict", "score", "lang", "trust_path", "agents", "override")


def read(paths: list[str], label: str | None) -> dict[str, dict]:
    rows: dict[str, dict] = {}
    for p in paths:
        for line in Path(p).expanduser().read_text(encoding="utf-8").splitlines():
            if not line.strip():
                continue
            r = json.loads(line)
            if "verdict" not in r or (label and r.get("label") != label):
                continue
            rows[r["id"]] = {k: r[k] for k in KEEP if k in r}
    return rows


def summary(rows: dict[str, dict]) -> str:
    n = len(rows)
    flagged = sum(r["verdict"] == "phishing" for r in rows.values())
    return f"{flagged} of {n} flagged as phishing ({flagged / n:.1%})" if n else "no rows"


def main() -> int:
    ap = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    ap.add_argument("out", help="file to write (or, with --compare, the published file)")
    ap.add_argument("caches", nargs="+", help="benchmark.py --cache files")
    ap.add_argument("--label", choices=["phishing", "legit"], help="keep only this label")
    ap.add_argument(
        "--compare", action="store_true", help="compare a published file with your own run"
    )
    args = ap.parse_args()

    mine = read(args.caches, args.label)
    if args.compare:
        published = read([args.out], args.label)
        common = published.keys() & mine.keys()
        differ = [i for i in sorted(common) if published[i]["verdict"] != mine[i]["verdict"]]
        print(f"published: {summary(published)}")
        print(f"yours:     {summary(mine)}")
        print(f"{len(common)} emails in both, {len(differ)} with another verdict")
        for i in differ[:20]:
            print(f"  {i}: published {published[i]['verdict']}, yours {mine[i]['verdict']}")
        return 0

    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(
        "".join(json.dumps(mine[i], sort_keys=True) + "\n" for i in sorted(mine)), encoding="utf-8"
    )
    print(f"{out}: {summary(mine)}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
