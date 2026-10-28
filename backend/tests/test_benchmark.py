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
        sample=0,
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
            "agents": {"metadata": {"phishing_probability": 0.95 if "bad" in text else 0.1}},
            "high_confidence_override": "bad" in text,
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
    assert (
        "False alarms (1): mean wording 0%, links 0%, sender 95%; decided by one check alone: 1"
        in report
    )
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


def test_sample_is_a_fixed_pick_per_label(tmp_path):
    phish = tmp_path / "phish"
    phish.mkdir()
    for i in range(6):
        (phish / f"{i}.eml").write_bytes(eml(f"bad {i}"))
    args = make_args(tmp_path, [str(phish)], [])
    args.sample = 3
    first = {r["id"] for r in bm.run(args, send=fake_server([]))}
    (tmp_path / "cache.jsonl").unlink()
    again = {r["id"] for r in bm.run(args, send=fake_server([]))}
    assert len(first) == 3 and first == again


def test_interrupt_keeps_what_was_scored(tmp_path):
    for i in range(3):
        (tmp_path / f"{i}.eml").write_bytes(eml(f"bad {i}"))
    calls = []

    def stop_after_one(server, raw):
        if calls:
            raise KeyboardInterrupt
        calls.append(raw)
        return {"verdict": "phishing", "fused_score": 0.9, "language": {"code": "en"}}

    results = bm.run(make_args(tmp_path, [str(tmp_path)], []), send=stop_after_one)
    assert len(results) == 1


def test_exclude_gives_a_disjoint_control_sample(tmp_path):
    phish = tmp_path / "phish"
    phish.mkdir()
    for i in range(6):
        (phish / f"{i}.eml").write_bytes(eml(f"bad {i}"))
    args = make_args(tmp_path, [str(phish)], [])
    args.sample = 3
    first = {r["id"] for r in bm.run(args, send=fake_server([]))}
    control = make_args(tmp_path, [str(phish)], [])
    control.sample = 3
    control.cache = str(tmp_path / "control.jsonl")
    control.exclude = [str(tmp_path / "cache.jsonl")]
    second = {r["id"] for r in bm.run(control, send=fake_server([]))}
    assert len(second) == 3 and not first & second


def test_refused_email_says_why(tmp_path):
    import io
    import urllib.error

    (tmp_path / "a.eml").write_bytes(eml("bad"))

    def refuses(_server, _raw):
        body = io.BytesIO(b'{"detail": "raw_email_b64 is too large."}')
        raise urllib.error.HTTPError("http://test/analyse", 413, "Too large", {}, body)

    args = make_args(tmp_path, [str(tmp_path / "a.eml")], [])
    results = bm.run(args, send=refuses)
    assert results[0]["error"] == "HTTP 413: raw_email_b64 is too large."
    assert "HTTP 413: raw_email_b64 is too large. (1)" in bm.report(results)


def test_show_errors_and_drop(tmp_path, capsys):
    legit = tmp_path / "legit"
    legit.mkdir()
    (legit / "a.eml").write_bytes(eml("bad but legit"))
    (legit / "b.eml").write_bytes(eml("fine"))
    args = make_args(tmp_path, [], [str(legit)])
    results = bm.run(args, send=fake_server([]))
    bm.show_errors(args, results)
    err = capsys.readouterr().err
    assert "false alarm" in err and "Subject" not in err and "bad but legit" in err
    fa = next(r["id"] for r in results if r["verdict"] == "phishing")
    (tmp_path / "drop.txt").write_text(f"{fa}  # a real phishing in the inbox\n")
    args = make_args(tmp_path, [], [str(legit)])
    args.drop = str(tmp_path / "drop.txt")
    again = bm.run(args, send=fake_server([]))
    assert [r["id"] for r in again] != [] and fa not in {r["id"] for r in again}


def test_interval_never_prints_negative_zero():
    from live_eval import fmt

    assert "-0.0%" not in fmt(0, 81)
    assert fmt(0, 81).endswith("(0/81, 95% CI 0.0% to 4.5%)")


def test_domain_ages_are_added_to_the_cache(tmp_path):
    import json

    import domain_age as da

    legit = tmp_path / "legit"
    legit.mkdir()
    (legit / "a.eml").write_bytes(
        b"From: Shop <news@mail.young-shop.example>\nDate: Mon, 05 Jan 2026 10:00:00 +0000\n"
        b"Subject: hi\n\nHello there\n"
    )
    (legit / "b.eml").write_bytes(eml("fine"))
    args = make_args(tmp_path, [], [str(legit)])
    results = bm.run(args, send=fake_server([]))
    asked = []

    def fetch(domain):
        asked.append(domain)
        return "2025-12-26" if domain == "young-shop.example" else da.UNKNOWN

    ages = da.DomainAges(tmp_path / "ages.json", fetch=fetch, pause=0)
    assert bm.add_domain_ages(args, results, ages=ages) == 2
    rows = [json.loads(x) for x in (tmp_path / "cache.jsonl").read_text().splitlines()]
    assert sorted(r["domain_age_days"] is None for r in rows) == [False, True]
    assert 10 in {r["domain_age_days"] for r in rows}
    assert asked == ["young-shop.example", "example.org"]
    # already there: nothing asked again
    assert bm.add_domain_ages(args, rows, ages=ages) == 0


def test_rdap_registration_event():
    import domain_age as da

    rdap = {
        "events": [
            {"eventAction": "last changed", "eventDate": "2026-01-01T00:00:00Z"},
            {"eventAction": "registration", "eventDate": "2019-03-04T12:00:00Z"},
        ]
    }
    assert da.registration_date(rdap) == "2019-03-04"
    assert da.registration_date({}) is None


def test_link_profile_counts_where_links_go(tmp_path):
    import json

    import link_profile as lp

    raw = (
        b"From: Bank <alerts@mail.bank.example>\nDate: Mon, 05 Jan 2026 10:00:00 +0000\n"
        b"Subject: hi\nContent-Type: text/html\n\n"
        b'<a href="https://www.bank.example/account">a</a> <a href="https://github.com/x">b</a>'
        b' <a href="http://evil.example/login">c</a> <a href="http://evil.example/login">dup</a>'
        b' <a href="https://u1.ct.sendgrid.net/ls/click?x">t</a>'
        b' <link href="https://fonts.googleapis.com/css?family=Roboto">\n'
    )
    assert lp.profile(raw) == {
        "links": 4,
        "aligned": 1,
        "well_known": 1,
        "cloud": 0,
        "tracking": 1,
        "other": 1,
    }
    legit = tmp_path / "legit"
    legit.mkdir()
    (legit / "a.eml").write_bytes(raw)
    args = make_args(tmp_path, [], [str(legit)])
    results = bm.run(args, send=fake_server([]))
    assert bm.add_link_profiles(args, results) == 1
    row = json.loads((tmp_path / "cache.jsonl").read_text())
    assert row["link_profile"]["aligned"] == 1 and "evil" not in json.dumps(row)


def test_export_keeps_scores_not_content(tmp_path):
    import importlib.util
    import json

    spec = importlib.util.spec_from_file_location(
        "export_benchmark", Path(__file__).resolve().parents[2] / "scripts" / "export_benchmark.py"
    )
    exp = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(exp)
    cache = tmp_path / "run.jsonl"
    cache.write_text(
        json.dumps(
            {"id": "a1", "label": "phishing", "verdict": "phishing", "score": 0.9, "subject": "x"}
        )
        + "\n"
        + json.dumps({"id": "b2", "label": "legit", "verdict": "safe", "score": 0.1})
        + "\n"
        + json.dumps({"id": "c3", "label": "phishing", "error": "HTTPError"})
        + "\n"
    )
    rows = exp.read([str(cache)], "phishing")
    assert rows == {"a1": {"id": "a1", "label": "phishing", "verdict": "phishing", "score": 0.9}}
