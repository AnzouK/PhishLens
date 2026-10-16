"""Legitimate mailing-list mail sent as a raw .eml must not be forced to
phishing by the trained metadata model, which is off by default."""

import base64

import pytest
from fastapi.testclient import TestClient

import extension_backend as eb
import structured_agents as sa
import text_model as tm

LIST_EMAIL = b"""\
Return-Path: <dev-return-1234-archive=example.org@commons.apache.org>
Received: from mail.apache.org (mail.apache.org [151.101.2.132])
\tby mx.example.org with ESMTPS id abc123; Mon, 5 Jan 2026 10:00:00 +0000
ARC-Seal: i=1; a=rsa-sha256; t=1767607200; cv=none; d=example.org; s=arc; b=xyz
Authentication-Results: mx.example.org; spf=pass smtp.mailfrom=commons.apache.org;
 dkim=pass header.d=apache.org; dmarc=pass header.from=apache.org
Mailing-List: contact dev-help@commons.apache.org; run by ezmlm
List-Id: <dev.commons.apache.org>
List-Unsubscribe: <mailto:dev-unsubscribe@commons.apache.org>
Precedence: bulk
From: Jane Developer <jane@apache.org>
To: dev@commons.apache.org
Subject: [VOTE] Release Commons Text 1.15.0 based on RC1
Date: Mon, 5 Jan 2026 10:00:00 +0000
Message-ID: <CAF1234@mail.gmail.com>
Content-Type: text/plain; charset=UTF-8

Please review the release candidate and vote. The artifacts are at
https://dist.apache.org/repos/dist/dev/commons/text/1.15.0-RC1/ and the
tag is on GitHub. The vote stays open for at least 72 hours.
"""


class _AlwaysPhishing:
    def get_prediction_with_confidence(self, _feats):
        return {"phishing_probability": 0.99}


class _Features:
    def extract_metadata_features(self, _raw):
        return {}


@pytest.fixture
def client(monkeypatch):
    monkeypatch.setenv("REPUTATION_ENABLE_DBL", "0")
    monkeypatch.setattr(eb, "_REPUTATION_AVAILABLE", False)
    monkeypatch.setattr(eb, "_AUTH_HEADERS_AVAILABLE", False)
    monkeypatch.setattr(sa, "_URL_AGENT", None)
    monkeypatch.setattr(sa, "_METADATA_AGENT", _AlwaysPhishing())
    monkeypatch.setattr(sa, "_FEATURE_EXTRACT", _Features())
    monkeypatch.setattr(tm, "text_agent", lambda _body: 0.02)
    eb._RESULT_CACHE.clear()
    return TestClient(eb.app)


def _scan(client):
    return client.post(
        "/analyse",
        json={"raw_email_b64": base64.b64encode(LIST_EMAIL).decode()},
    ).json()


def test_mailing_list_eml_uses_the_rules(client):
    j = _scan(client)
    meta = j["agents"]["metadata"]
    assert meta["source"] == "rules"
    assert meta["phishing_probability"] < 0.5
    assert j["verdict"] != "phishing"


def test_trained_model_only_when_enabled(client, monkeypatch):
    monkeypatch.setattr(eb, "METADATA_MODEL_ENABLED", True)
    j = _scan(client)
    assert j["agents"]["metadata"]["source"] == "model"
    assert j["agents"]["metadata"]["phishing_probability_raw"] >= 0.9


def test_text_model_reads_the_subject(client, monkeypatch):
    seen = []
    monkeypatch.setattr(tm, "text_agent", lambda text: seen.append(text) or 0.02)
    _scan(client)
    client.post(
        "/analyse",
        json={
            "raw_text": "Please review the release candidate and vote by Friday.",
            "client_context": {"origin": "outlook", "subject": "  [VOTE]   Release 1.15.0 "},
        },
    )
    client.post(
        "/analyse",
        json={
            "raw_text": "[VOTE] Release 1.15.0\nPlease vote.",
            "client_context": {"origin": "gmail", "subject": "[VOTE] Release 1.15.0"},
        },
    )
    assert seen[0].startswith("[VOTE] Release Commons Text 1.15.0 based on RC1\nPlease review")
    assert (
        seen[1] == "[VOTE] Release 1.15.0\nPlease review the release candidate and vote by Friday."
    )
    assert seen[2] == "[VOTE] Release 1.15.0\nPlease vote."
