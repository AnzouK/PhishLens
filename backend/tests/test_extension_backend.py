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

from tests.conftest import import_extension_backend  # noqa: E402

eb = import_extension_backend()


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

    def test_trained_url_agent_skipped_without_urls(self, monkeypatch):
        # Regression (v1.10.1): the trained RF returned ~0.9 on link-free
        # text and forced a phishing verdict on "meeting moved to 3pm".
        class AlwaysPhishy:
            def get_prediction_with_confidence(self, _feats):
                return {"phishing_probability": 0.9}
        monkeypatch.setattr(eb, "_URL_AGENT", AlwaysPhishy())
        monkeypatch.setattr(eb, "_FEATURE_EXTRACT", object())
        assert eb.url_agent([], body_text="Meeting moved to 3pm.") == pytest.approx(0.05)

    def test_link_free_text_is_safe_with_trained_url_agent(self, client, monkeypatch):
        class AlwaysPhishy:
            def get_prediction_with_confidence(self, _feats):
                return {"phishing_probability": 0.9}

        class NoFeatures:
            def extract_url_features(self, _text):
                return {}
        monkeypatch.setattr(eb, "_URL_AGENT", AlwaysPhishy())
        monkeypatch.setattr(eb, "_FEATURE_EXTRACT", NoFeatures())
        r = client.post("/analyse", json={"raw_text": "Hi team, the meeting moved to 3pm."})
        j = r.json()
        assert j["agents"]["url"]["phishing_probability"] == pytest.approx(0.05)
        assert j["verdict"] == "safe"

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

    def test_gsb_hit_overrides_allowlist(self, client, monkeypatch):
        # Regression (v1.11.0): an allowlisted sender carrying a Safe
        # Browsing-listed link used to stay "safe" because the trusted
        # path disabled every override.
        import types

        async def fake_check_urls(urls):
            return [{"url": u, "malicious": True, "score": 1.0,
                     "sources": ["google_safe_browsing"],
                     "threat_types": ["SOCIAL_ENGINEERING"]} for u in urls]
        monkeypatch.setattr(eb, "_REPUTATION_AVAILABLE", True)
        monkeypatch.setattr(eb, "_reputation",
                            types.SimpleNamespace(check_urls=fake_check_urls),
                            raising=False)
        text_score(monkeypatch, 0.10)
        r = client.post("/analyse", json={
            "raw_text": "Your statement: https://gtbank-secure.example/login",
            "sender_email": "alerts@gtbank.com",
        })
        j = r.json()
        assert j["trust_path"] == "trusted_sender"
        assert j["url_reputation"]["sources_hit"] == ["google_safe_browsing"]
        assert j["verdict"] == "phishing"

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


    def test_macro_document_forces_phishing_even_from_trusted_parent(self, client, monkeypatch):
        import io
        import zipfile
        text_score(monkeypatch, 0.05)
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w") as z:
            z.writestr("[Content_Types].xml", "<Types/>")
            z.writestr("word/document.xml",
                       '<w:document xmlns:w="x"><w:body><w:p><w:r><w:t>Enable content</w:t>'
                       '</w:r></w:p></w:body></w:document>')
            z.writestr("word/vbaProject.bin", b"x")
        r = client.post("/analyse_attachment", json={
            "content_b64": b64(buf.getvalue()), "filename": "invoice.docm",
            "parent_email": {"gmail_delivered": True}})
        assert r.status_code == 200
        j = r.json()
        assert j["attachment"]["dropper_techniques"] == ["contains_macros"]
        assert j["verdict"] == "phishing"


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


# ---------------------------------------------------------------------
# Link targets sent by the Gmail extension (client_context.link_urls)
# ---------------------------------------------------------------------
class TestLinkUrls:
    def test_merge_filters_and_dedupes(self):
        out = eb._merge_link_urls(
            ["https://a.example/x"],
            ["https://a.example/x", "javascript:alert(1)", "mailto:x@y.z",
             42, "http://b.example/" + "p" * 3000, " https://c.example/login "],
        )
        assert out == ["https://a.example/x", "https://c.example/login"]

    def test_merge_caps_and_ignores_non_lists(self):
        many = [f"https://h{i}.example/" for i in range(200)]
        assert len(eb._merge_link_urls([], many)) == eb.MAX_LINK_URLS
        assert eb._merge_link_urls(["https://a.example/"], "https://b.example/") == ["https://a.example/"]

    def test_hidden_link_reaches_url_agent(self, client, monkeypatch):
        seen = {}

        def fake_url_agent(urls, body_text=""):
            seen["urls"] = list(urls)
            return 0.0
        monkeypatch.setattr(eb, "url_agent", fake_url_agent)
        client.post("/analyse", json={
            "raw_text": "Your parcel is waiting. Click here to schedule delivery.",
            "client_context": {"origin": "gmail",
                               "link_urls": ["https://parcel-redelivery.example/track"]},
        })
        assert seen["urls"] == ["https://parcel-redelivery.example/track"]


# ---------------------------------------------------------------------
# v1.14: forwarded emails, near-empty bodies, shared-file links,
# archives through the endpoint
# ---------------------------------------------------------------------
class TestV114:
    def test_forwarded_from_trusted_sender_gets_no_discount(self, client, monkeypatch):
        text_score(monkeypatch, 0.95)
        body = ("FYI, is this real?\n\n---------- Forwarded message ---------\n"
                "From: GTBank <alerts@gtbank-secure.xyz>\n"
                "Your account is suspended, verify your identity immediately.")
        j = client.post("/analyse", json={
            "raw_text": body, "sender_email": "colleague@gtbank.com",
            "client_context": {"origin": "gmail", "gmail_in_inbox": True},
        }).json()
        assert j["forwarded"] == {"detected": True, "original_sender": "alerts@gtbank-secure.xyz"}
        assert j["trust_path"] == "default"
        assert j["trusted_sender"] is False
        assert j["verdict"] == "phishing"

    def test_detect_forwarded_variants(self):
        assert eb.detect_forwarded("-------- Message transféré --------\nDe : <a@b.fr>")["original_sender"] == "a@b.fr"
        assert eb.detect_forwarded("Begin forwarded message:\n\nFrom: x@y.io")["detected"]
        assert eb.detect_forwarded("hello", "TR: facture")["detected"]
        assert not eb.detect_forwarded("hello", "Re: meeting")["detected"]

    def test_short_text_is_left_out_of_fusion(self, client, monkeypatch):
        text_score(monkeypatch, 0.99)          # would trigger the override alone
        j = client.post("/analyse", json={"raw_text": "Invoice attached"}).json()
        assert j["text_agent_used"] is False
        assert j["high_confidence_override"] is False
        assert j["verdict"] == "safe"

    def test_shared_links_reported(self, client):
        j = client.post("/analyse", json={
            "raw_text": "Please review the document I shared with you today, thanks.",
            "client_context": {"link_urls": ["https://docs.google.com/forms/d/e/x/viewform",
                                             "https://www.dropbox.com/s/abc/file.pdf"]},
        }).json()
        assert j["shared_links"]["services"] == ["Google Forms", "Dropbox"]

    def test_encrypted_zip_scored(self, client, monkeypatch):
        import io
        import zipfile
        text_score(monkeypatch, 0.05)
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w") as z:
            z.writestr("run.js", "x")
        j = client.post("/analyse_attachment", json={
            "content_b64": b64(buf.getvalue()), "filename": "invoice.zip",
            "parent_email": {"gmail_delivered": True}}).json()
        assert j["attachment"]["kind"] == "archive"
        assert j["attachment"]["dropper_techniques"] == ["script_in_archive"]
        assert j["verdict"] == "phishing"


def test_forwarded_sender_parsing_is_bounded():
    body = "---------- Forwarded message ---------\nFrom: " + "a" * 200_000
    assert eb.detect_forwarded(body) == {"detected": True, "original_sender": None}


def test_eml_html_href_targets_are_extracted():
    eml = (b"From: a@b.co\r\nSubject: hi\r\nMIME-Version: 1.0\r\n"
           b"Content-Type: multipart/alternative; boundary=X\r\n\r\n"
           b"--X\r\nContent-Type: text/plain\r\n\r\nClick here to verify\r\n"
           b"--X\r\nContent-Type: text/html\r\nContent-Transfer-Encoding: quoted-printable\r\n\r\n"
           b"<a href=3D\"https://evil.example/login\">Click here</a>\r\n--X--\r\n")
    _body, urls, _headers = eb.parse_eml(eml)
    assert urls == ["https://evil.example/login"]


def test_html_to_text_drops_css_and_scripts():
    html = ('<html><head><style>.itinerarytable{font:25px roboto}</style></head>'
            '<body><h1 class="heading">Your flight</h1><p>Check &amp; confirm</p>'
            '<script>var x = 1</script></body></html>')
    text = eb.html_to_text(html)
    assert "Your flight" in text and "Check & confirm" in text
    for noise in ("25px", "roboto", "itinerarytable", "var x"):
        assert noise not in text


class TestShowOriginal:
    EML = (b"From: Bank <alerts@bank.example>\r\nSubject: Statement ready\r\n"
           b"Authentication-Results: mx.google.com; dkim=pass header.i=@bank.example\r\n"
           b"Content-Type: text/plain\r\n\r\nYour monthly statement is ready to view online.\r\n")

    def test_trained_meta_model_skipped_for_gmail_show_original(self, client, monkeypatch):
        calls = []

        def fake_meta(headers, raw_email=None):
            calls.append(raw_email)
            return 0.1
        monkeypatch.setattr(eb, "metadata_agent", fake_meta)
        client.post("/analyse", json={"raw_email_b64": b64(self.EML)})
        client.post("/analyse", json={"raw_email_b64": b64(self.EML),
                                      "client_context": {"origin": "gmail", "headers_source": "gmail_show_original"}})
        assert calls[0] is not None and calls[1] is None

    def test_attachment_only_eml_is_scored(self, client):
        eml = (b"From: a@b.example\r\nSubject: Invoice\r\nMIME-Version: 1.0\r\n"
               b"Content-Type: multipart/mixed; boundary=X\r\n\r\n--X\r\n"
               b"Content-Type: application/pdf\r\nContent-Disposition: attachment; filename=a.pdf\r\n\r\n"
               b"--X--\r\n")
        r = client.post("/analyse", json={"raw_email_b64": b64(eml)})
        assert r.status_code == 200
        assert r.json()["text_agent_used"] is False


class TestV115Scoring:
    def test_hidden_links_get_rules_not_the_trained_model(self, monkeypatch):
        class RF:
            def get_prediction_with_confidence(self, feats):
                return {"phishing_probability": 0.95}

        class FX:
            @staticmethod
            def extract_url_features(text):
                return {}
        monkeypatch.setattr(eb, "_URL_AGENT", RF())
        monkeypatch.setattr(eb, "_FEATURE_EXTRACT", FX())
        text = "Your CI run failed. View results."
        # hidden, harmless link: rules only
        assert eb.url_agent(["https://github.com/AnzouK/PhishLens/actions/runs/1"], text) < 0.2
        # hidden, risky link: the rules still catch it
        assert eb.url_agent(["http://192.168.0.1/login-verify"], text) >= 0.7
        # a link written in the text: the trained model decides
        assert eb.url_agent(["https://x.example/a"], "see https://x.example/a") == 0.95

    def test_page_text_wins_over_eml_text_part(self, client, monkeypatch):
        seen = {}

        def fake_text(body):
            seen["body"] = body
            return 0.1
        monkeypatch.setattr(eb, "text_agent", fake_text)
        eml = (b"From: a@b.example\r\nSubject: CI\r\nContent-Type: text/plain\r\n\r\n"
               b"View results: https://github.com/x/y/actions/runs/1\r\n")
        client.post("/analyse", json={"raw_email_b64": b64(eml),
                                      "raw_text": "Run failed. View results"})
        assert seen["body"] == "Run failed. View results"

    def test_eml_prefers_rendered_html_part(self):
        eml = (b"From: a@b.co\r\nSubject: CI\r\nMIME-Version: 1.0\r\n"
               b"Content-Type: multipart/alternative; boundary=X\r\n\r\n"
               b"--X\r\nContent-Type: text/plain\r\n\r\nView results: https://github.com/x/y/actions/runs/1\r\n"
               b"--X\r\nContent-Type: text/html\r\n\r\n<p>Run failed. <a href=\"https://github.com/x/y/actions/runs/1\">View results</a></p>\r\n"
               b"--X--\r\n")
        body, urls, _h = eb.parse_eml(eml)
        assert body == "Run failed. View results"
        assert urls == ["https://github.com/x/y/actions/runs/1"]


class TestUrlOverrideNeedsConfirmation:
    def _rf(self, monkeypatch, p):
        monkeypatch.setattr(eb, "url_agent", lambda urls, body_text="": p)

    def test_clean_link_alone_does_not_force_phishing(self, client, monkeypatch):
        text_score(monkeypatch, 0.10)
        self._rf(monkeypatch, 0.95)
        j = client.post("/analyse", json={
            "raw_text": "The agenda for Monday is at https://github.com/AnzouK/PhishLens/wiki today."}).json()
        assert j["high_confidence_override"] is False
        assert j["verdict"] == "safe"

    def test_risky_link_still_forces_phishing(self, client, monkeypatch):
        text_score(monkeypatch, 0.10)
        self._rf(monkeypatch, 0.95)
        j = client.post("/analyse", json={
            "raw_text": "Please confirm your details at http://192.168.10.5/login before Monday."}).json()
        assert j["high_confidence_override"] is True
        assert j["verdict"] == "phishing"


class TestOutlookInternal:
    BODY = "Dear student, please find your attendance details below and have a fruitful day."

    def test_internal_sender_from_trusted_org(self, client, monkeypatch):
        text_score(monkeypatch, 0.99)
        j = client.post("/analyse", json={"raw_text": self.BODY, "client_context": {
            "origin": "outlook", "outlook_internal": True, "org_domain": "gtbank.com"}}).json()
        assert j["trust_path"] == "trusted_sender"
        assert j["verdict"] == "safe"

    def test_internal_sender_soft_path(self, client, monkeypatch):
        text_score(monkeypatch, 0.99)
        j = client.post("/analyse", json={"raw_text": self.BODY, "client_context": {
            "origin": "outlook", "outlook_internal": True, "org_domain": "example-university.edu"}}).json()
        assert j["trust_path"] == "outlook_internal"
        assert j["sender_auth"]["outlook_internal"] is True
        assert j["verdict"] == "safe"

    def test_outlook_external_unknown_gets_no_discount(self, client, monkeypatch):
        text_score(monkeypatch, 0.99)
        j = client.post("/analyse", json={"raw_text": self.BODY, "sender_email": "x@unknown.example",
                                          "client_context": {"origin": "outlook"}}).json()
        assert j["trust_path"] == "default"
        assert j["verdict"] == "phishing"

    def test_bad_org_domain_ignored(self, client, monkeypatch):
        text_score(monkeypatch, 0.10)
        j = client.post("/analyse", json={"raw_text": self.BODY, "client_context": {
            "origin": "outlook", "outlook_internal": True, "org_domain": "not a domain"}}).json()
        assert j["sender_domain"] is None
