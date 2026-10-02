#!/usr/bin/env python3
"""
Live evaluation report from an exported PhishLens scan history.

Export the history from the popup (Insights, JSON), review the scans
there first ("Right" / "Wrong" on each one), then:

    python3 scripts/live_eval.py phishlens-history.json
    python3 scripts/live_eval.py phishlens-history.json --markdown > live-eval.md

Only reviewed scans count. Ground truth comes from the review: a "Right"
phishing verdict is a true positive, a "Wrong" one a false positive; a
"Right" safe verdict is a true negative, a "Wrong" one a missed phishing
email. Standard library only. Prints no subject or sender, so the output
can go into a report as is.
"""
from __future__ import annotations

import argparse
import json
import math
from collections import defaultdict


def wilson(k: int, n: int, z: float = 1.96) -> tuple[float, float] | None:
    """95% Wilson score interval for a proportion k/n."""
    if n == 0:
        return None
    p = k / n
    d = 1 + z * z / n
    c = p + z * z / (2 * n)
    r = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n))
    return ((c - r) / d, (c + r) / d)


def confusion(rows: list[dict]) -> dict[str, int]:
    m = {"tp": 0, "fp": 0, "tn": 0, "fn": 0}
    for e in rows:
        ph = e.get("verdict") == "phishing"
        ok = e.get("label") == "correct"
        m["tp" if ph and ok else "fp" if ph else "tn" if ok else "fn"] += 1
    return m


def metrics(m: dict[str, int]) -> dict[str, tuple[int, int]]:
    """Each metric as (numerator, denominator)."""
    return {
        "accuracy": (m["tp"] + m["tn"], sum(m.values())),
        "precision": (m["tp"], m["tp"] + m["fp"]),
        "recall (phishing caught)": (m["tp"], m["tp"] + m["fn"]),
        "false-positive rate": (m["fp"], m["fp"] + m["tn"]),
    }


def fmt(k: int, n: int) -> str:
    if n == 0:
        return "n/a"
    lo, hi = wilson(k, n)
    return f"{k / n:.1%} ({k}/{n}, 95% CI {lo:.1%} to {hi:.1%})"


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("history_json")
    ap.add_argument("--markdown", action="store_true", help="print a Markdown report")
    args = ap.parse_args()

    with open(args.history_json, encoding="utf-8") as f:
        history = json.load(f)
    reviewed = [e for e in history if e.get("label") in ("correct", "wrong")]

    by_source: dict[str, list[dict]] = defaultdict(list)
    for e in reviewed:
        by_source[e.get("source", "unknown")].append(e)

    m = confusion(reviewed)
    lines = []
    h = "## " if args.markdown else ""
    lines.append(f"{h}PhishLens live evaluation")
    lines.append(f"Scans in history: {len(history)}, reviewed: {len(reviewed)}")
    if reviewed:
        ts = sorted(e["ts"] for e in reviewed if "ts" in e)
        if ts:
            import datetime as dt
            day = lambda t: dt.datetime.fromtimestamp(t / 1000).date().isoformat()  # noqa: E731
            lines.append(f"Period: {day(ts[0])} to {day(ts[-1])}")
    lines.append("")
    lines.append(f"{h}Confusion matrix")
    if args.markdown:
        lines += ["| | Actually phishing | Actually legitimate |", "| --- | --- | --- |",
                  f"| Flagged phishing | {m['tp']} (TP) | {m['fp']} (FP) |",
                  f"| Marked safe | {m['fn']} (FN) | {m['tn']} (TN) |"]
    else:
        lines += [f"  TP {m['tp']}   FP {m['fp']}", f"  FN {m['fn']}   TN {m['tn']}"]
    lines.append("")
    lines.append(f"{h}Metrics")
    for name, (k, n) in metrics(m).items():
        lines.append(f"{'- ' if args.markdown else '  '}{name}: {fmt(k, n)}")
    if len(by_source) > 1:
        lines.append("")
        lines.append(f"{h}By source")
        for src, rows in sorted(by_source.items()):
            sm = confusion(rows)
            acc = metrics(sm)["accuracy"]
            lines.append(f"{'- ' if args.markdown else '  '}{src}: {len(rows)} reviewed, accuracy {fmt(*acc)}")
    if 0 < len(reviewed) < 30:
        lines.append("")
        lines.append("Note: fewer than 30 reviewed scans; the intervals are wide.")
    print("\n".join(lines))


if __name__ == "__main__":
    main()
