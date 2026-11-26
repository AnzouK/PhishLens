"""Signed notifications sent through a mailer, and the attacks that look like them.

Regression tests for the false alarms of the November 2026 monthly
benchmark on personal mail. All domains are made up; only the structure
of the real messages is kept:

- a DKIM-aligned sender whose links all go through its mailer's click
  tracking (Brevo, Intercom, Tencent Cloud SES), with wording the text
  model scores near 1.0;
- a bank whose mailer signs with its own DKIM domain while the bounce
  domain is the bank's, so DMARC passes through SPF alignment only.

Each legitimate case has its attack twin, which must still be caught:
a link that really leads elsewhere, a lookalike of a tracking host, an
unaligned or failing DMARC, a brand name over another domain, a Safe
Browsing hit.
"""

from __future__ import annotations

import base64
import types

import pytest
from fastapi.testclient import TestClient

import extension_backend as eb
import structured_agents as sa
import text_model as tm
from auth_headers import parse_authentication_results
from link_alignment import link_profile, links_elsewhere_only

# Transactional wording the text model mistakes for phishing.
LURE_SCORE = 0.98


@pytest.fixture
def client(monkeypatch):
    monkeypatch.setenv("REPUTATION_ENABLE_DBL", "0")
    monkeypatch.setattr(eb, "_REPUTATION_AVAILABLE", False)
    monkeypatch.setattr(sa, "_URL_AGENT", None)
    monkeypatch.setattr(sa, "_METADATA_AGENT", None)
    monkeypatch.setattr(tm, "text_agent", lambda _body: LURE_SCORE)
    eb._RESULT_CACHE.clear()
    yield TestClient(eb.app)
    eb._RESULT_CACHE.clear()


def safe_browsing_flags_everything(monkeypatch):
    async def fake_check_urls(urls):
        return [
            {
                "url": u,
                "malicious": True,
                "score": 1.0,
                "sources": ["google_safe_browsing"],
                "threat_types": ["SOCIAL_ENGINEERING"],
            }
            for u in urls
        ]

    monkeypatch.setattr(eb, "_REPUTATION_AVAILABLE", True)
    monkeypatch.setattr(
        eb,
        "_reputation",
        types.SimpleNamespace(check_urls=fake_check_urls, fully_checked=lambda v: True),
        raising=False,
    )


def email(from_: str, auth: str, links: list[str], *, arc_only: bool = False) -> bytes:
    header = "ARC-Authentication-Results: i=1; " if arc_only else "Authentication-Results: "
    anchors = "".join(f'<p><a href="{u}">Open</a></p>' for u in links)
    return (
        f"From: {from_}\r\n"
        f"{header}mx.google.com; {auth}\r\n"
        "Subject: Security notice for your account\r\n"
        "Content-Type: text/html\r\n\r\n"
        "<p>A new device signed in to your account. If this was not you, "
        "verify your account and change your password now.</p>"
        f"{anchors}\r\n"
    ).encode()


def analyse(client, raw: bytes, **ctx) -> dict:
    body = {"raw_email_b64": base64.b64encode(raw).decode()}
    if ctx:
        body["client_context"] = ctx
    r = client.post("/analyse", json=body)
    assert r.status_code == 200
    return r.json()


# A DKIM-aligned sender (crypto_verified) whose links all go through its
# mailer's click tracking.
SIGNED = (
    "dkim=pass header.i=@notify.bank-notify.example header.s=k1; "
    "spf=pass smtp.mailfrom=notify.bank-notify.example; "
    "dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=notify.bank-notify.example"
)
SIGNED_FROM = "Bank Notify <no-reply@notify.bank-notify.example>"
ESP_LINKS = [
    "https://1234567890-sg.callback.suredeliverses.com/c/abc?x=1",
    "https://abcde.r.tsp1-brevo.net/tr/cl/xyz",
    "https://banknotify-1a2b3c.intercom-clicks.com/via/e?ob=abc",
    "https://banknotify-1a2b3c.intercom-mail.com/subscriptions/unsubscribe?x=1",
]
PHISHING_PAGE = "https://bank-notify-secure.example/login"


class TestMailerClickTracking:
    @pytest.mark.parametrize("url", ESP_LINKS)
    def test_mailer_tracking_hosts_are_counted_as_tracking(self, url):
        counts = link_profile([url], SIGNED_FROM)
        assert counts["tracking"] == 1 and counts["other"] == 0
        assert not links_elsewhere_only(counts)

    @pytest.mark.parametrize(
        "url",
        [
            # Only the listed organisational domain counts, not a name that
            # contains it.
            "https://tsp1-brevo.net.bank-notify-secure.example/tr/cl/x",
            "https://suredeliverses.com-login.example/c/abc",
            "https://evil-intercom-clicks.com/via/e",
            "https://intercom-clicks.com.evil.example/via/e",
            "https://callback.suredeliverses.example/c/abc",
        ],
    )
    def test_lookalike_tracking_hosts_still_lead_elsewhere(self, url):
        counts = link_profile([url], SIGNED_FROM)
        assert counts["tracking"] == 0 and counts["other"] == 1
        assert links_elsewhere_only(counts)

    def test_signed_notification_through_click_tracking_is_safe(self, client):
        j = analyse(client, email(SIGNED_FROM, SIGNED, ESP_LINKS))
        assert j["trust_path"] == "crypto_verified"
        assert j["link_alignment"]["tracking"] == len(ESP_LINKS)
        assert j["link_alignment"]["other"] == 0
        assert j["links_elsewhere"] is False
        assert j["verdict"] == "safe" and j["forced_by"] == []

    def test_tracking_links_do_not_hide_a_link_elsewhere(self, client):
        j = analyse(client, email(SIGNED_FROM, SIGNED, [*ESP_LINKS, PHISHING_PAGE]))
        assert j["trust_path"] == "crypto_verified"
        assert j["verdict"] == "phishing" and j["forced_by"] == ["links_elsewhere"]

    def test_attacker_signing_their_own_domain_is_still_caught(self, client):
        # DKIM, SPF and DMARC all pass for the attacker's own domain.
        auth = (
            "dkim=pass header.i=@bank-notify-alerts.example; "
            "spf=pass smtp.mailfrom=bank-notify-alerts.example; "
            "dmarc=pass header.from=bank-notify-alerts.example"
        )
        raw = email("Bank Notify <no-reply@bank-notify-alerts.example>", auth, [PHISHING_PAGE])
        j = analyse(client, raw)
        assert j["trust_path"] == "crypto_verified"
        assert j["verdict"] == "phishing" and j["forced_by"] == ["links_elsewhere"]

    def test_lookalike_tracking_host_from_a_signed_sender_is_caught(self, client):
        raw = email(SIGNED_FROM, SIGNED, ["https://abcde.r.tsp1-brevo.net.evil.example/tr/cl/x"])
        j = analyse(client, raw)
        assert j["verdict"] == "phishing" and j["forced_by"] == ["links_elsewhere"]

    def test_safe_browsing_hit_on_a_tracking_link_still_forces_phishing(self, client, monkeypatch):
        safe_browsing_flags_everything(monkeypatch)
        j = analyse(client, email(SIGNED_FROM, SIGNED, ESP_LINKS))
        assert j["trust_path"] == "crypto_verified"
        assert j["verdict"] == "phishing" and "safe_browsing" in j["forced_by"]


# A bank whose mailer signs with the mailer's own DKIM domain; DMARC
# passes because the bounce domain (SPF) is the bank's.
SPF_ALIGNED = (
    "dkim=pass header.i=@s51.mailer-esp.example header.s=fbl51; "
    "spf=pass smtp.mailfrom=bounce.e.bank-notify.example; "
    "dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=bank-notify.example"
)
BANK_FROM = "Notification <alerts@bank-notify.example>"
BANK_LINK = ["https://click.e.bank-notify.example/?qs=abc"]


class TestDmarcAlignedThroughSpf:
    def test_parser_sees_dmarc_alignment_without_dkim_alignment(self):
        av = parse_authentication_results(
            {"from": BANK_FROM, "authentication-results": "mx.google.com; " + SPF_ALIGNED}
        )
        assert av.dmarc_aligned and av.aligned
        assert not av.cryptographically_verified

    @pytest.mark.parametrize(
        "auth",
        [
            # DMARC passed for some other domain, not the From: one.
            "dkim=pass header.i=@attacker.example; spf=pass smtp.mailfrom=attacker.example; "
            "dmarc=pass header.from=attacker.example",
            # The attacker's own SPF and DKIM pass; DMARC for the From: fails.
            "dkim=pass header.i=@attacker.example; spf=pass smtp.mailfrom=attacker.example; "
            "dmarc=fail header.from=bank-notify.example",
            # Lookalike organisational domain.
            "spf=pass smtp.mailfrom=bounce.bank-notify.example.attacker.example; "
            "dmarc=pass header.from=bank-notify.example.attacker.example",
            "spf=pass smtp.mailfrom=bounce.e.bank-notify.example; dmarc=none",
        ],
    )
    def test_no_dmarc_alignment_for_the_from_domain(self, auth):
        av = parse_authentication_results(
            {"from": BANK_FROM, "authentication-results": "mx.google.com; " + auth}
        )
        assert not av.dmarc_aligned

    def test_arc_copy_proves_nothing(self):
        av = parse_authentication_results(
            {"from": BANK_FROM, "arc-authentication-results": "i=1; mx.google.com; " + SPF_ALIGNED}
        )
        assert not av.dmarc_aligned

    def test_two_from_addresses_prove_nothing(self):
        av = parse_authentication_results(
            {
                "from": "alerts@bank-notify.example, x@attacker.example",
                "authentication-results": "mx.google.com; " + SPF_ALIGNED,
            }
        )
        assert not av.dmarc_aligned

    def test_bank_notice_aligned_through_spf_is_safe(self, client):
        j = analyse(client, email(BANK_FROM, SPF_ALIGNED, BANK_LINK))
        assert j["trust_path"] == "dmarc_verified"
        assert j["sender_auth"]["dmarc_verified"] is True
        assert j["sender_auth"]["cryptographically_verified"] is False
        assert j["trusted_sender"] is False
        assert j["verdict"] == "safe" and j["forced_by"] == []

    def test_same_wording_without_dmarc_alignment_is_still_forced(self, client):
        auth = (
            "dkim=pass header.i=@attacker.example; spf=pass smtp.mailfrom=attacker.example; "
            "dmarc=fail header.from=bank-notify.example"
        )
        j = analyse(client, email(BANK_FROM, auth, BANK_LINK))
        assert j["trust_path"] == "default"
        assert j["verdict"] == "phishing" and "confident_text" in j["forced_by"]

    def test_arc_only_copy_keeps_the_default_path(self, client):
        j = analyse(client, email(BANK_FROM, SPF_ALIGNED, BANK_LINK, arc_only=True))
        assert j["trust_path"] == "default" and j["verdict"] == "phishing"

    def test_links_elsewhere_still_force_phishing(self, client):
        j = analyse(client, email(BANK_FROM, SPF_ALIGNED, [PHISHING_PAGE]))
        assert j["trust_path"] == "dmarc_verified"
        assert j["verdict"] == "phishing" and j["forced_by"] == ["links_elsewhere"]
        assert j["links_elsewhere"] is True

    def test_link_rule_applies_even_in_the_gmail_inbox(self, client):
        # The Gmail inbox path has no link rule. A sender that passes DMARC
        # without DKIM gets dmarc_verified first, which keeps it.
        raw = email(BANK_FROM, SPF_ALIGNED, [PHISHING_PAGE])
        j = analyse(client, raw, origin="gmail", gmail_in_inbox=True)
        assert j["trust_path"] == "dmarc_verified"
        assert j["verdict"] == "phishing" and j["forced_by"] == ["links_elsewhere"]

    def test_brand_name_over_another_domain_is_impersonation(self, client):
        # DMARC passes for the impostor's domain; the display name is a brand.
        auth = (
            "dkim=pass header.i=@mailer-esp.example; "
            "spf=pass smtp.mailfrom=bounce.bank-notify.example; "
            "dmarc=pass header.from=bank-notify.example"
        )
        raw = email("PayPal Security <alerts@bank-notify.example>", auth, BANK_LINK)
        j = analyse(client, raw)
        assert j["sender_auth"]["impersonation"]["brand"] == "paypal"
        assert j["sender_auth"]["dmarc_verified"] is False
        assert j["trust_path"] == "default" and j["verdict"] == "phishing"

    def test_safe_browsing_hit_still_forces_phishing(self, client, monkeypatch):
        safe_browsing_flags_everything(monkeypatch)
        j = analyse(client, email(BANK_FROM, SPF_ALIGNED, BANK_LINK))
        assert j["trust_path"] == "dmarc_verified"
        assert j["verdict"] == "phishing" and "safe_browsing" in j["forced_by"]

    def test_allowlist_needs_dkim(self, client):
        # gtbank.com is on the allowlist; SPF alignment alone is not enough
        # for the trusted_sender path.
        auth = (
            "dkim=pass header.i=@s51.mailer-esp.example; "
            "spf=pass smtp.mailfrom=bounce.gtbank.com; dmarc=pass header.from=gtbank.com"
        )
        j = analyse(client, email("GTBank <alerts@gtbank.com>", auth, ["https://gtbank.com/x"]))
        assert j["trust_path"] == "dmarc_verified" and j["trusted_sender"] is False
