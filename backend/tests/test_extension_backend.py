"""
Endpoint and fusion tests for extension_backend.py.

The DistilBERT model is never loaded: TestClient is used without a
`with` block, so the lifespan hook does not run, and `text_agent` is
patched to return a fixed probability. The URL reputation cascade and
the Spamhaus DNS lookup are switched off. What is left is exactly the
logic we want to pin: request parsing, the heuristic agents, the trust
paths (trusted sender / crypto verified / Gmail inbox soft / default),
and the attachment scoring rules.
"""
from __future__ import annotations

import base64

import pytest

pytest.importorskip("fastapi")
pytest.importorskip("httpx")          # TestClient transport

from fastapi.testclient import TestClient  # noqa: E402

import extension_backend as eb  # noqa: E402  (conftest stubs heavy deps first)


def b64(data: bytes) -> str:
    return base64.b64encode(data).decode()


@pytest.fixture
def client(monkeypatch):
    monkeypatch.setenv("REPUTATION_ENABLE_DBL", "0")
    monkeypatch.setattr(eb, "_REPUTATION_AVAILABLE", False)
    monkeypatch.setattr(eb, "_URL_AGENT", None)
    monkeypatch.setattr(eb, "_METADATA_AGENT", None)
    monkeypatch.setattr(eb, "text_agent", lambda _body: 0.02)
    return TestClient(eb.app)


def text_score(monkeypatch, p: float):
    monkeypatch.setattr(eb, "text_agent", lambda _body: p)


# ---------------------------------------------------------------------
# Small pure helpers
# ---------------------------------------------------------------------
class TestHelpers:
    def test_sender_domain(self):
        assert eb._sender_domain('"Bank" <alerts@GTBank.com>') == "gtbank.com"
        assert eb._sender_domain("") is None
        assert eb._sender_domain("no-at-sign") is None

    def test_trusted_domain_and_subdomain(self):
        assert eb.is_trusted_domain("gtbank.com")
        assert eb.is_trusted_domain("mail.gtbank.com")
        assert not eb.is_trusted_domain("gtbank.com.evil.tld")
        assert not eb.is_trusted_domain("gmail.com")
        assert not eb.is_trusted_domain(None)

    def test_verdict_label(self):
        assert eb.verdict_label(0.5) == "Phishing"
        assert eb.verdict_label(0.49) == "Safe"

    def test_parse_eml_extracts_body_urls_headers(self):
        raw = (b"From: a@b.com\r\nSubject: hi\r\nContent-Type: text/plain\r\n\r\n"
               b"see https://example.com/x please")
        body, urls, headers = eb.parse_eml(raw)
        assert "please" in body
        assert urls == ["https://example.com/x"]
        assert headers["subject"] == "hi"

    def test_synthesized_auth_only_for_gmail(self):
        assert eb._synthesize_auth_results({"origin": "outlook"}, "a@b.com") == ""
        assert eb._synthesize_auth_results({"origin": "gmail"}, "a@b.com") == ""

    def test_synthesized_auth_aligned_gives_dmarc_pass(self):
        ctx = {"origin": "gmail", "gmail_signed_by": "mail.paypal.com"}
        h = eb._synthesize_auth_results(ctx, "service@paypal.com")
        assert "dkim=pass" in h
        assert "dmarc=pass" in h

    def test_synthesized_auth_misaligned_no_dmarc(self):
        ctx = {"origin": "gmail", "gmail_signed_by": "evil.tld"}
        h = eb._synthesize_auth_results(ctx, "service@paypal.com")
        assert "dkim=pass" in h
        assert "dmarc=pass" not in h


# ---------------------------------------------------------------------
# Heuristic agents
# ---------------------------------------------------------------------
class TestHeuristicAgents:
    def test_url_agent_no_urls_is_low(self, monkeypatch):
        monkeypatch.setattr(eb, "_URL_AGENT", None)
        assert eb.url_agent([]) == pytest.approx(0.05)

    def test_url_agent_ip_url_is_high(self, monkeypatch):
        monkeypatch.setattr(eb, "_URL_AGENT", None)
        assert eb.url_agent(["http://10.0.0.1/login"]) >= 0.7

    def test_metadata_display_name_impersonation(self, monkeypatch):
        monkeypatch.setattr(eb, "_METADATA_AGENT", None)
        score = eb.metadata_agent({"from": "PayPal Support <support@evil.tld>"})
        # +0.15 (no auth header) +0.35 (brand in display name, not in domain)
        assert score == pytest.approx(0.50)

    def test_metadata_real_brand_not_penalised(self, monkeypatch):
        monkeypatch.setattr(eb, "_METADATA_AGENT", None)
        score = eb.metadata_agent({"from": "PayPal <service@paypal.com>",
                                   "authentication-results": "spf=pass"})
        assert score == pytest.approx(0.0)

    def test_metadata_reply_to_mismatch(self, monkeypatch):
        monkeypatch.setattr(eb, "_METADATA_AGENT", None)
        score = eb.metadata_agent({"from": "a@x.com", "reply-to": "b@y.com",
                                   "authentication-results": "spf=pass"})
        assert score == pytest.approx(0.45)

    def test_metadata_huge_from_header_is_fast(self, monkeypatch):
        # Regression for CodeQL py/polynomial-redos: a crafted From: must
        # not hang the heuristic.
        monkeypatch.setattr(eb, "_METADATA_AGENT", None)
        evil = '"' + "!" + " " * 50_000 + "<x@y.z>"
        assert 0.0 <= eb.metadata_agent({"from": evil}) <= 1.0


# ---------------------------------------------------------------------
# Simple endpoints
# ---------------------------------------------------------------------
class TestSimpleEndpoints:
    def test_health(self, client):
        r = client.get("/health")
        assert r.status_code == 200
        assert r.json()["status"] == "ok"

    def test_reputation_stats_when_disabled(self, client):
        r = client.get("/reputation/stats")
        assert r.status_code == 200
        assert r.json()["enabled"] is False


# ---------------------------------------------------------------------
# /analyse
# ---------------------------------------------------------------------
class TestAnalyse:
    def test_requires_a_payload(self, client):
        r = client.post("/analyse", json={})
        assert r.status_code == 400

    def test_blank_text_rejected(self, client):
        r = client.post("/analyse", json={"raw_text": "   "})
        assert r.status_code == 400

    def test_garbage_base64_rejected(self, client):
        r = client.post("/analyse", json={"raw_email_b64": "!!!not-base64!!!"})
        assert r.status_code == 400

    def test_benign_text_is_safe(self, client):
        r = client.post("/analyse", json={"raw_text": "Hi team, meeting moved to 3pm."})
        assert r.status_code == 200
        j = r.json()
        assert j["verdict"] == "safe"
        assert j["trust_path"] == "default"
        assert set(j["agents"]) == {"text", "url", "metadata"}
        assert j["url_reputation"]["checked"] == 0

    def test_confident_text_agent_forces_phishing(self, client, monkeypatch):
        text_score(monkeypatch, 0.97)
        r = client.post("/analyse", json={"raw_text": "Verify your account now"})
        j = r.json()
        assert j["verdict"] == "phishing"
        assert j["high_confidence_override"] is True

    def test_trusted_sender_softens_text_agent(self, client, monkeypatch):
        text_score(monkeypatch, 0.97)
        r = client.post("/analyse", json={
            "raw_text": "Your debit alert. Verify your account balance.",
            "sender_email": "alerts@gtbank.com",
        })
        j = r.json()
        assert j["trusted_sender"] is True
        assert j["sender_domain"] == "gtbank.com"
        assert j["trust_path"] == "trusted_sender"
        assert j["verdict"] == "safe"

    def test_gmail_inbox_soft_path(self, client, monkeypatch):
        text_score(monkeypatch, 0.90)
        r = client.post("/analyse", json={
            "raw_text": "Please confirm your email address to continue.",
            "sender_email": "hello@unknownco.com",
            "client_context": {"origin": "gmail", "gmail_in_inbox": True},
        })
        j = r.json()
        assert j["sender_auth"]["gmail_inbox_soft_verified"] is True
        assert j["trust_path"] == "gmail_inbox_soft"
        assert j["verdict"] == "safe"

    def test_same_text_without_gmail_context_is_phishing(self, client, monkeypatch):
        text_score(monkeypatch, 0.90)
        r = client.post("/analyse", json={
            "raw_text": "Please confirm your email address to continue.",
            "sender_email": "hello@unknownco.com",
        })
        assert r.json()["verdict"] == "phishing"

    def test_crypto_verified_path(self, client, monkeypatch):
        text_score(monkeypatch, 0.90)
        r = client.post("/analyse", json={
            "raw_text": "Your statement is ready.",
            # not in TRUSTED_DOMAINS, so only the DKIM alignment can save it
            "sender_email": "billing@acme-corp.io",
            "client_context": {"origin": "gmail",
                               "gmail_signed_by": "acme-corp.io",
                               "gmail_mailed_by": "mail.acme-corp.io"},
        })
        j = r.json()
        assert j["sender_auth"]["cryptographically_verified"] is True
        assert j["trust_path"] == "crypto_verified"
        assert j["verdict"] == "safe"

    def test_full_eml_spoof_is_phishing(self, client, monkeypatch):
        text_score(monkeypatch, 0.30)
        eml = (
            b"From: PayPal Security <alert@paypa1-support.xyz>\r\n"
            b"Reply-To: collector@evil.example\r\n"
            b"Subject: Verify your account\r\n"
            b"Authentication-Results: mx.example.com; spf=fail smtp.mailfrom=paypa1-support.xyz;"
            b" dkim=fail header.d=paypa1-support.xyz; dmarc=fail header.from=paypa1-support.xyz\r\n"
            b"Content-Type: text/plain\r\n\r\n"
            b"Click http://paypa1-support.xyz/login to avoid suspension.\r\n"
        )
        r = client.post("/analyse", json={"raw_email_b64": b64(eml)})
        assert r.status_code == 200
        j = r.json()
        assert j["verdict"] == "phishing"
        assert j["agents"]["metadata"]["phishing_probability"] >= 0.85


# ---------------------------------------------------------------------
# /analyse_attachment
# ---------------------------------------------------------------------
LOGIN_PAGE = (b"<html><body><form action='http://attacker.tld/login'>"
              b"<input type='password' name='p'></form></body></html>")
NOTES_PAGE = b"<html><body><p>Minutes of the board meeting, action items below.</p></body></html>"


class TestAnalyseAttachment:
    def test_unsupported_type_is_400(self, client):
        r = client.post("/analyse_attachment", json={
            "content_b64": b64(b"PK\x03\x04garbage"), "filename": "x.docx"})
        assert r.status_code == 400

    def test_html_login_page_is_phishing(self, client, monkeypatch):
        text_score(monkeypatch, 0.10)
        r = client.post("/analyse_attachment", json={
            "content_b64": b64(LOGIN_PAGE), "filename": "invoice.html",
            "mime_type": "text/html"})
        assert r.status_code == 200
        j = r.json()
        assert j["verdict"] == "phishing"
        assert "contains_password_field" in j["attachment"]["notable_features"]

    def test_trusted_parent_does_not_hide_login_page(self, client, monkeypatch):
        text_score(monkeypatch, 0.10)
        r = client.post("/analyse_attachment", json={
            "content_b64": b64(LOGIN_PAGE), "filename": "invoice.html",
            "mime_type": "text/html",
            "parent_email": {"gmail_delivered": True}})
        j = r.json()
        assert j["parent_trusted"] is True
        assert j["verdict"] == "phishing"

    def test_trusted_parent_absorbs_text_false_positive(self, client, monkeypatch):
        text_score(monkeypatch, 0.90)
        payload = {"content_b64": b64(NOTES_PAGE), "filename": "notes.html",
                   "mime_type": "text/html"}
        untrusted = client.post("/analyse_attachment", json=payload).json()
        trusted = client.post("/analyse_attachment", json={
            **payload, "parent_email": {"gmail_delivered": True}}).json()
        assert untrusted["verdict"] == "phishing"
        assert trusted["verdict"] == "safe"


# ---------------------------------------------------------------------
# /metrics (only when the Prometheus instrumentator is installed)
# ---------------------------------------------------------------------
class TestMetrics:
    def test_metrics_exposes_verdict_counter(self, client):
        pytest.importorskip("prometheus_fastapi_instrumentator")
        client.post("/analyse", json={"raw_text": "Hello there"})
        r = client.get("/metrics")
        assert r.status_code == 200
        assert "phishlens_verdicts_total" in r.text
