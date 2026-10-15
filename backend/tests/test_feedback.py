import json

import pytest
from fastapi.testclient import TestClient

import extension_backend as eb
import feedback

REPORT = {
    "kind": "false_positive",
    "text": "Hi Kalinda, your UBA account was credited with 250000 NGN. Details: https://uba.example/x?id=9",
    "verdict": "phishing",
    "fused_score": 0.91,
    "agents": {"text": 0.99, "url": 0.2, "metadata": 0.1},
    "lang": "en",
    "lang_user": "en",
    "version": "2.0.0",
}


@pytest.fixture
def client(monkeypatch, tmp_path):
    monkeypatch.setattr(feedback, "FEEDBACK_DIR", str(tmp_path))
    return TestClient(eb.app), tmp_path


def _stored(folder):
    lines = [json.loads(x) for f in folder.glob("*.jsonl") for x in f.read_text().splitlines()]
    return lines


def test_report_is_redacted_and_stored_without_request_data(client):
    c, folder = client
    r = c.post("/feedback", json=REPORT)
    assert r.status_code == 200 and len(r.json()["reference"]) == 12
    (rec,) = _stored(folder)
    assert rec["reference"] == r.json()["reference"] and rec["kind"] == "false_positive"
    assert (
        "Kalinda" not in rec["text"] and "250000" not in rec["text"] and "id=9" not in rec["text"]
    )
    assert "<URL:uba.example>" in rec["text"]
    assert "ip" not in json.dumps(rec).lower().replace("ship", "")
    assert set(rec) >= {"received", "version", "agents", "lang_user"}


def test_stats_carry_no_text(client):
    c, folder = client
    rows = [
        {
            "day": "2026-10-14",
            "source": "gmail",
            "verdict": "safe",
            "score": 0.1,
            "agents": {"text": 0.1, "url": 0.0, "metadata": 0.2},
            "label": "correct",
            "lang": "fr",
        }
    ]
    assert c.post("/feedback", json={"kind": "stats", "rows": rows}).status_code == 200
    (rec,) = _stored(folder)
    assert rec["rows"][0]["lang"] == "fr" and "text" not in rec


@pytest.mark.parametrize(
    "bad",
    [
        {"kind": "false_positive", "text": "hi"},
        {"kind": "stats", "rows": []},
        {"kind": "something_else", "text": "a b c d"},
        {**REPORT, "lang": "<script>"},
        {**REPORT, "text": "x " * 20_001},
    ],
)
def test_bad_reports_are_refused(client, bad):
    c, folder = client
    assert c.post("/feedback", json=bad).status_code in (400, 422)
    assert not _stored(folder)


def test_disabled_without_a_folder(monkeypatch):
    monkeypatch.setattr(feedback, "FEEDBACK_DIR", "")
    assert TestClient(eb.app).post("/feedback", json=REPORT).status_code == 503


def test_full_storage_refuses(client, monkeypatch):
    c, folder = client
    monkeypatch.setattr(feedback, "FEEDBACK_MAX_MB", 0)
    assert c.post("/feedback", json=REPORT).status_code == 503
