#!/usr/bin/env python3
"""
Public, reproducible benchmark of a PhishLens server.

Sends labelled emails (.eml files, folders of them, or .mbox files) to a
PhishLens server exactly as the extension would, and reports, per
language the server detects and overall: the confusion matrix, the share
of legitimate emails flagged and the share of phishing caught, each with
a 95% Wilson confidence interval.

    python3 scripts/benchmark.py \\
        --phishing phishing_pot/email nazario-2025.mbox \\
        --legit my-public-legit.mbox \\
        --since 2026-01-01 --sample 500 --server http://127.0.0.1:8000 --markdown

It measures the whole system (text model, links, sender checks, threat
intelligence), not one model. Every answer is kept in --cache (JSON
lines: a hash of the email, the label, the result; never the email), so
an interrupted run resumes and the per-email results can be shared.
Standard library only. See docs/evaluation.md for the protocol and the
public sources.
"""

from __future__ import annotations

import argparse
import base64
import email
import email.policy
import hashlib
import json
import mailbox
import sys
import time
import urllib.error
import urllib.request
from collections import Counter, defaultdict
from collections.abc import Iterator
from datetime import datetime, timezone
from email.utils import parseaddr, parsedate_to_datetime
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from live_eval import fmt  # noqa: E402

LABELS = {"phishing": 1, "legit": 0}


def emails_in(source: str) -> Iterator[bytes]:
    """Raw bytes of each email in a .eml file, a folder or an .mbox file."""
    p = Path(source)
    if p.is_dir():
        for f in sorted(p.rglob("*.eml")):
            yield f.read_bytes()
    elif p.suffix.lower() == ".mbox":
        for msg in mailbox.mbox(str(p)):
            yield msg.as_bytes()
    elif p.is_file():
        yield p.read_bytes()
    else:
        raise SystemExit(f"not found: {source}")


def sent_on(raw: bytes) -> datetime | None:
    head = raw[:20000].decode("utf-8", "replace")
    for line in head.splitlines():
        if line.lower().startswith("date:"):
            try:
                d = parsedate_to_datetime(line[5:].strip())
            except (TypeError, ValueError):
                return None
            return d if d.tzinfo else d.replace(tzinfo=timezone.utc)
        if not line.strip():
            break
    return None


def analyse(server: str, raw: bytes, timeout: float = 60) -> dict:
    body = json.dumps({"raw_email_b64": base64.b64encode(raw).decode()}).encode()
    req = urllib.request.Request(
        server.rstrip("/") + "/analyse",
        data=body,
        headers={"Content-Type": "application/json", "User-Agent": "PhishLens-benchmark"},
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return json.loads(r.read())


def load_cache(path: Path) -> dict[str, dict]:
    if not path.exists():
        return {}
    rows = (json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line)
    return {r["id"]: r for r in rows}


def _kept(args, since) -> Iterator[tuple[str, str, bytes]]:
    """(label, id, raw) of every email the date filter keeps, minus the
    emails of earlier runs given with --exclude."""
    excluded = getattr(args, "excluded_ids", None) or set()
    for label, sources in (("phishing", args.phishing), ("legit", args.legit)):
        for source in sources or []:
            for raw in emails_in(source):
                if since:
                    d = sent_on(raw)
                    if d is None or d < since:
                        continue
                eid = hashlib.sha256(raw).hexdigest()[:16]
                if eid not in excluded:
                    yield label, eid, raw


def _selection(args, since) -> tuple[set[str] | None, dict[str, int]]:
    """Ids to score with --sample (per label, the N smallest ids: a fixed,
    reproducible pick), and how many emails each label has."""
    ids: dict[str, list[str]] = {"phishing": [], "legit": []}
    for label, eid, _raw in _kept(args, since):
        ids[label].append(eid)
    counts = {k: len(v) for k, v in ids.items()}
    if not args.sample:
        return None, counts
    return {e for v in ids.values() for e in sorted(set(v))[: args.sample]}, counts


def _error_name(e: Exception) -> str:
    """ "HTTP 413: <detail>" for an answer the server refused, the exception
    name otherwise (timeouts, connection errors)."""
    if isinstance(e, urllib.error.HTTPError):
        detail = ""
        try:
            detail = str(json.loads(e.read() or b"{}").get("detail") or "")[:80]
        except (ValueError, AttributeError, OSError):
            pass
        return f"HTTP {e.code}" + (f": {detail}" if detail else "")
    return type(e).__name__


def _progress(done: int, total: int, cached: int, errors: int, pause: float) -> None:
    left = (total - done) * pause / 60
    eta = f", about {left:.0f} min left" if pause and done < total else ""
    print(
        f"\r\x1b[K{done}/{total} emails ({cached} from the cache, {errors} errors){eta}",
        end="",
        file=sys.stderr,
        flush=True,
    )


def _ids_in(path: str | None) -> set[str]:
    """Email ids listed in a text file, one per line (# starts a comment)."""
    if not path:
        return set()
    lines = Path(path).read_text(encoding="utf-8").splitlines()
    return {line.split("#", 1)[0].strip() for line in lines} - {""}


def show_errors(args, results: list[dict]) -> None:
    """Print, on this machine only, the sender domain and subject of
    each false alarm and missed phishing, so a mislabelled email (a
    phishing in an inbox export) can be found and listed with --drop.
    Nothing of it goes to the cache or the report."""
    wrong = {
        r["id"]: ("false alarm" if r["label"] == "legit" else "missed")
        for r in results
        if "verdict" in r and (r["verdict"] == "phishing") != (r["label"] == "phishing")
    }
    if not wrong:
        return
    since = datetime.fromisoformat(args.since).replace(tzinfo=timezone.utc) if args.since else None
    by_id = {r["id"]: r for r in results}
    print("\nErrors, for review (local only):", file=sys.stderr)
    for _label, eid, raw in _kept(args, since):
        if eid not in wrong:
            continue
        msg = email.message_from_bytes(raw[:200_000], policy=email.policy.default)
        sender = parseaddr(str(msg.get("from", "")))[1].rsplit("@", 1)[-1]
        subject = " ".join(str(msg.get("subject", "")).split())[:70]
        a = by_id[eid].get("agents") or {}
        print(
            f"{eid}  {wrong.pop(eid):11s} {by_id[eid].get('trust_path') or '?':16s} "
            f"text {a.get('text', 0):.2f} links {a.get('url', 0):.2f} "
            f"sender {a.get('metadata', 0):.2f}  {sender}  {subject}",
            file=sys.stderr,
        )


def _enrich(args, results: list[dict], key: str, compute) -> int:
    """Add `key` = compute(raw) to each scored email of the cache that has
    no such value yet, then rewrite the cache; returns how many got one."""
    cache_path = Path(args.cache)
    todo = {r["id"] for r in results if "verdict" in r and key not in r}
    if not todo:
        return 0
    since = datetime.fromisoformat(args.since).replace(tzinfo=timezone.utc) if args.since else None
    by_id = {r["id"]: r for r in results}
    done = 0
    for _label, eid, raw in _kept(args, since):
        if eid in todo:
            todo.discard(eid)
            by_id[eid][key] = compute(raw)
            done += 1
            print(f"\r\x1b[K{key}: {done}", end="", file=sys.stderr, flush=True)
    print(file=sys.stderr)
    rows = load_cache(cache_path)
    rows.update({eid: r for eid, r in by_id.items() if "verdict" in r})
    tmp = cache_path.with_suffix(".tmp")
    tmp.write_text("".join(json.dumps(r) + "\n" for r in rows.values()), encoding="utf-8")
    tmp.replace(cache_path)
    return done


def add_domain_ages(args, results: list[dict], ages=None) -> int:
    """The age in days of the sender's domain when the email was sent
    ("domain_age_days", None when unknown), looked up on this machine
    (domain_age.py)."""
    from domain_age import DomainAges

    ages = ages or DomainAges(Path(args.cache).with_suffix(".domains-private.json"))
    return _enrich(args, results, "domain_age_days", lambda raw: ages.age_days(raw, sent_on(raw)))


def add_link_profiles(args, results: list[dict]) -> int:
    """Where the links go compared with the sender's domain ("link_profile":
    counts only, link_profile.py)."""
    from link_profile import profile

    return _enrich(args, results, "link_profile", profile)


def run(args, send=analyse) -> list[dict]:
    cache_path = Path(args.cache)
    cache = load_cache(cache_path)
    args.excluded_ids = {
        eid for path in getattr(args, "exclude", None) or [] for eid in load_cache(Path(path))
    }
    dropped = _ids_in(getattr(args, "drop", None))
    if dropped:
        print(f"{len(dropped)} emails dropped as mislabelled (--drop)", file=sys.stderr)
        args.excluded_ids |= dropped
    if args.excluded_ids:
        print(f"{len(args.excluded_ids)} emails of earlier runs left out", file=sys.stderr)
    since = datetime.fromisoformat(args.since).replace(tzinfo=timezone.utc) if args.since else None
    pause = 60.0 / args.per_minute if args.per_minute else 0.0
    chosen, counts = _selection(args, since)
    total = len(chosen) if chosen is not None else sum(counts.values())
    print(
        f"{counts['phishing']} phishing and {counts['legit']} legitimate emails"
        + (f" after {args.since}" if args.since else "")
        + (f"; scoring {total} (--sample {args.sample} per label)" if chosen is not None else ""),
        file=sys.stderr,
    )
    results, cached, errors, seen = [], 0, 0, set()
    try:
        with cache_path.open("a", encoding="utf-8") as out:
            for label, eid, raw in _kept(args, since):
                if eid in seen or (chosen is not None and eid not in chosen):
                    continue
                seen.add(eid)
                if eid in cache:
                    results.append(cache[eid])
                    cached += 1
                    _progress(len(results), total, cached, errors, pause)
                    continue
                try:
                    r = send(args.server, raw)
                    row = {
                        "id": eid,
                        "label": label,
                        "verdict": r.get("verdict"),
                        "score": r.get("fused_score"),
                        "lang": (r.get("language") or {}).get("code") or "und",
                        "trust_path": r.get("trust_path"),
                        "agents": {
                            k: round(
                                float(
                                    (r.get("agents") or {}).get(k, {}).get("phishing_probability")
                                    or 0
                                ),
                                3,
                            )
                            for k in ("text", "url", "metadata")
                        },
                        "sources": {
                            k: (r.get("agents") or {}).get(k, {}).get("source")
                            for k in ("url", "metadata")
                        },
                        "override": bool(r.get("high_confidence_override")),
                    }
                except (urllib.error.URLError, TimeoutError, ValueError) as e:
                    row = {"id": eid, "label": label, "error": _error_name(e)}
                    errors += 1
                if "error" not in row:
                    out.write(json.dumps(row) + "\n")
                    out.flush()
                results.append(row)
                _progress(len(results), total, cached, errors, pause)
                if pause:
                    time.sleep(pause)
    except KeyboardInterrupt:
        print("\nInterrupted: the report below covers the emails scored so far.", file=sys.stderr)
    print(file=sys.stderr)
    return results


def summary(results: list[dict]) -> dict[str, dict[str, int]]:
    """Confusion counts per detected language, and overall ("all")."""
    groups: dict[str, dict[str, int]] = defaultdict(lambda: {"tp": 0, "fn": 0, "fp": 0, "tn": 0})
    for r in results:
        if "error" in r:
            continue
        flagged = r["verdict"] == "phishing"
        key = (
            ("tp" if flagged else "fn") if r["label"] == "phishing" else ("fp" if flagged else "tn")
        )
        for g in (r["lang"], "all"):
            groups[g][key] += 1
    return dict(groups)


def _why(results: list[dict]) -> str:
    """Mean score of each check over the false alarms and the missed
    phishing, and how often one check alone decided: where to look."""
    lines = []
    for name, wrong in (
        (
            "False alarms",
            [r for r in results if r.get("label") == "legit" and r.get("verdict") == "phishing"],
        ),
        (
            "Missed phishing",
            [r for r in results if r.get("label") == "phishing" and r.get("verdict") == "safe"],
        ),
    ):
        wrong = [r for r in wrong if "agents" in r]
        if not wrong:
            continue
        mean = {
            k: sum(r["agents"][k] for r in wrong) / len(wrong) for k in ("text", "url", "metadata")
        }
        forced = sum(1 for r in wrong if r.get("override"))
        paths = Counter(r.get("trust_path") or "?" for r in wrong)
        lines.append(
            f"{name} ({len(wrong)}): mean wording {mean['text']:.0%}, links {mean['url']:.0%}, "
            f"sender {mean['metadata']:.0%}; decided by one check alone: {forced}; "
            "trust paths: " + ", ".join(f"{k} {v}" for k, v in paths.most_common())
        )
    return "\n".join(lines)


def report(results: list[dict], markdown: bool = False) -> str:
    groups = summary(results)
    errors = sum(1 for r in results if "error" in r)
    order = ["all"] + sorted(g for g in groups if g != "all")
    lines = []
    if markdown:
        lines += [
            "| Language | Legitimate flagged (false alarms) | Phishing caught | TP | FN | FP | TN |",
            "| --- | --- | --- | --- | --- | --- | --- |",
        ]
    for g in order:
        m = groups.get(g)
        if not m:
            continue
        fa = fmt(m["fp"], m["fp"] + m["tn"])
        caught = fmt(m["tp"], m["tp"] + m["fn"])
        if markdown:
            lines.append(
                f"| {g} | {fa} | {caught} | {m['tp']} | {m['fn']} | {m['fp']} | {m['tn']} |"
            )
        else:
            lines.append(f"{g}: false alarms {fa}; phishing caught {caught}")
    if errors:
        kinds = Counter(r["error"] for r in results if "error" in r)
        lines.append(
            f"\n{errors} emails could not be scored: "
            + "; ".join(f"{k} ({v})" for k, v in kinds.most_common())
            + ". A 4xx answer is the server refusing that email and comes back on"
            " every run; timeouts and 5xx answers may pass when run again."
        )
    why = _why(results)
    if why:
        lines.append("\n" + why)
    small = [g for g in order if g in groups and sum(groups[g].values()) < 30]
    if small:
        lines.append(
            f"\nFewer than 30 emails in: {', '.join(small)}. Read those intervals as wide."
        )
    return "\n".join(lines)


def main() -> None:
    ap = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    ap.add_argument("--phishing", nargs="+", default=[], help=".eml, folder or .mbox")
    ap.add_argument("--legit", nargs="+", default=[], help=".eml, folder or .mbox")
    ap.add_argument("--server", default="http://127.0.0.1:8000")
    ap.add_argument("--since", help="keep emails sent on or after this date (YYYY-MM-DD)")
    ap.add_argument(
        "--per-minute",
        type=float,
        default=0,
        help="requests per minute (PhishLens Cloud allows 30; 0: no pause)",
    )
    ap.add_argument(
        "--sample", type=int, default=0, help="score at most N emails per label (a fixed pick)"
    )
    ap.add_argument(
        "--exclude",
        nargs="+",
        default=[],
        help="caches of earlier runs: their emails are left out (a control sample)",
    )
    ap.add_argument(
        "--drop",
        help="file of email ids (one per line) checked by hand and found mislabelled",
    )
    ap.add_argument(
        "--show-errors",
        action="store_true",
        help="print the sender domain and subject of each error (local only)",
    )
    ap.add_argument(
        "--domain-age",
        action="store_true",
        help="add the sender domain's age (RDAP, looked up from this machine) to the cache",
    )
    ap.add_argument(
        "--link-profile",
        action="store_true",
        help="add where the links go compared with the sender's domain (counts only) to the cache",
    )
    ap.add_argument("--cache", default="benchmark-results.jsonl")
    ap.add_argument("--markdown", action="store_true")
    args = ap.parse_args()
    if not (args.phishing or args.legit):
        ap.error("give --phishing and/or --legit")
    results = run(args)
    if args.domain_age:
        add_domain_ages(args, results)
    if args.link_profile:
        add_link_profiles(args, results)
    if args.show_errors:
        show_errors(args, results)
    print(report(results, markdown=args.markdown))


if __name__ == "__main__":
    main()
