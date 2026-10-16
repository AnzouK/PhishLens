"""scripts/benchmark.py: reading emails, the date filter, resuming from the
cache, and the per-language report with confidence intervals."""

import mailbox
import sys
from argparse import Namespace
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "scripts"))
import benchmark as bm  # noqa: E402


def eml(subject: str, date: str = "Mon, 05 Jan 2026 10:00:00 +0000") -> bytes:
    return f"From: a@example.org\nDate: {date}\nSubject: {subject}\n\nHello {subject}\n".encode()


def make_args(tmp_path, phishing, legit, since=None):
    return Namespace(
        phishing=phishing,
        legit=legit,
        server="http://test",
        since=since,
        per_minute=0,
        cache=str(tmp_path / "cache.jsonl"),
        markdown=True,
    )


def fake_server(calls):
    def send(_server, raw):
        calls.append(raw)
        text = raw.decode()
        return {
            "verdict": "phishing" if "bad" in text else "safe",
            "fused_score": 0.9 if "bad" in text else 0.1,
            "language": {"code": "fr" if "bonjour" in text else "en"},
        }

    return send


def test_counts_dates_and_resume(tmp_path):
    phish = tmp_path / "phish"
    phish.mkdir()
    (phish / "1.eml").write_bytes(eml("bad one"))
    (phish / "2.eml").write_bytes(eml("bad two bonjour"))
    (phish / "3.eml").write_bytes(eml("missed"))
    (phish / "old.eml").write_bytes(eml("bad old", "Mon, 05 Jan 2015 10:00:00 +0000"))
    box = mailbox.mbox(str(tmp_path / "legit.mbox"))
    box.add(eml("fine"))
    box.add(eml("bad but legit"))
    box.flush()
    calls = []
    args = make_args(tmp_path, [str(phish)], [str(tmp_path / "legit.mbox")], since="2026-01-01")
    results = bm.run(args, send=fake_server(calls))
    assert len(calls) == 5 and len(results) == 5
    groups = bm.summary(results)
    assert groups["all"] == {"tp": 2, "fn": 1, "fp": 1, "tn": 1}
    assert groups["fr"] == {"tp": 1, "fn": 0, "fp": 0, "tn": 0}
    report = bm.report(results, markdown=True)
    assert "| all | 50.0% (1/2, 95% CI" in report
    assert "66.7% (2/3" in report
    # A second run reads every answer from the cache.
    calls.clear()
    assert len(bm.run(args, send=fake_server(calls))) == 5
    assert calls == []


def test_server_errors_are_not_cached(tmp_path):
    (tmp_path / "a.eml").write_bytes(eml("bad"))

    def broken(_server, _raw):
        raise TimeoutError

    args = make_args(tmp_path, [str(tmp_path / "a.eml")], [])
    results = bm.run(args, send=broken)
    assert results[0]["error"] == "TimeoutError"
    assert "could not be scored" in bm.report(results)
    assert not (tmp_path / "cache.jsonl").read_text()
