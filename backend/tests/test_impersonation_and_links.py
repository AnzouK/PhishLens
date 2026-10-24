"""Brand names over another domain's address, links to public cloud hosts
and to large known sites, and the readable explanation words."""

import pytest
from fastapi.testclient import TestClient

import extension_backend as eb
import structured_agents as sa
import text_model as tm
from language import FUNCTION_WORDS
from sender_trust import impersonated_brand


@pytest.fixture
def client(monkeypatch):
    monkeypatch.setenv("REPUTATION_ENABLE_DBL", "0")
    monkeypatch.setattr(eb, "_REPUTATION_AVAILABLE", False)
    monkeypatch.setattr(sa, "_URL_AGENT", None)
    monkeypatch.setattr(sa, "_METADATA_AGENT", None)
    monkeypatch.setattr(tm, "text_agent", lambda _body: 0.10)
    eb._RESULT_CACHE.clear()
    return TestClient(eb.app)


@pytest.mark.parametrize(
    ("value", "brand"),
    [
        ("Chronopost <info@qdsoddsmn.us>", "chronopost"),
        ("𝐒𝐩𝐨𝐭𝐢𝐟𝐲 <a@zsu3evkwzsu3evkw.ca>", "spotify"),
        ("La Poste Colis <x@evil.example>", "la poste"),
        ("impots.gouv <x@dgfip-impots.com>", "impots"),
        ("UPS Delivery <x@evil.example>", "ups"),
        ("Chronopost <no-reply@chronopost.fr>", None),
        ("Coinbase <no-reply@info.coinbase.com>", None),
        ("Impots.gouv.fr <ne-pas-repondre@dgfip.finances.gouv.fr>", None),
        ("John (via Google Docs) <drive-shares-dm-noreply@google.com>", None),
        ("Jean Dupont <jean@gmail.com>", None),
        ("Startups weekly <news@startups.example>", None),
        ("info@qdsoddsmn.us", None),
    ],
)
def test_impersonated_brand(value, brand):
    assert impersonated_brand(value) == brand


def test_impersonation_cancels_the_authenticated_path(client):
    j = client.post(
        "/analyse",
        json={
            "raw_text": "Your parcel is waiting, pay the customs fee to receive it.",
            "sender_email": "info@qdsoddsmn.us",
            "sender_name": "Chronopost",
            "client_context": {"origin": "gmail", "gmail_signed_by": "qdsoddsmn.us"},
        },
    ).json()
    assert j["sender_auth"]["impersonation"] == {"brand": "chronopost", "domain": "qdsoddsmn.us"}
    assert j["trust_path"] == "default"
    assert j["agents"]["metadata"]["phishing_probability"] >= 0.9
    assert j["verdict"] == "phishing"


def test_the_real_brand_is_not_flagged(client):
    j = client.post(
        "/analyse",
        json={
            "raw_text": "Your parcel will be delivered tomorrow between 9 and 12.",
            "sender_email": "no-reply@chronopost.fr",
            "sender_name": "Chronopost",
            "client_context": {"origin": "gmail", "gmail_signed_by": "chronopost.fr"},
        },
    ).json()
    assert j["sender_auth"]["impersonation"] is None
    assert j["verdict"] == "safe"


def test_sender_not_checked_without_headers(client):
    j = client.post(
        "/analyse", json={"raw_text": "Hi team, the review moved to Thursday at 3pm."}
    ).json()
    assert j["agents"]["metadata"]["checked"] is False
    j = client.post(
        "/analyse",
        json={
            "raw_text": "Hi team, the review moved to Thursday at 3pm.",
            "sender_email": "a@chronopost.fr",
            "client_context": {"origin": "gmail", "gmail_signed_by": "chronopost.fr"},
        },
    ).json()
    assert j["agents"]["metadata"]["checked"] is True


def test_cloud_file_hosts_raise_the_link_score():
    url = "https://storage.googleapis.com/bucket-x/colis/index.html"
    assert sa.on_cloud_file_host(url)
    assert sa.on_cloud_file_host("https://login-check.web.app/")
    assert sa.url_heuristic([url]) >= 0.45
    assert not sa.on_cloud_file_host("https://www.google.com/")


def test_well_known_links_skip_the_trained_model(monkeypatch):
    class AlwaysPhishy:
        def get_prediction_with_confidence(self, _feats):
            return {"phishing_probability": 0.97}

    class Features:
        def extract_url_features(self, _text):
            return {}

    monkeypatch.setattr(sa, "_URL_AGENT", AlwaysPhishy())
    monkeypatch.setattr(sa, "_FEATURE_EXTRACT", Features())
    amazon = "https://www.amazon.com/gp/your-account/order-details?orderID=123-456&ref=pe_1"
    assert sa.url_agent([amazon], body_text=f"Your order {amazon}") <= 0.10
    redirect = "https://www.google.com/url?q=https://evil.example/login"
    assert not sa.well_known_link(redirect)
    assert sa.url_agent([redirect], body_text=f"Open {redirect}") == pytest.approx(0.97)


def test_function_words_are_not_explanation_words():
    for word in ("votre", "est", "the", "your", "und"):
        assert word in FUNCTION_WORDS
    for word in ("account", "click", "dear", "verify", "cher", "client"):
        assert word not in FUNCTION_WORDS


@pytest.mark.parametrize(
    ("urls", "strong"),
    [
        (
            ["http://ci.apache.org/builders/commons-text/builds/1234/steps/compile/logs/stdio"],
            False,
        ),
        (["http://httpd.example.com/blog/2026/01/05/release-notes"], False),
        (["https://github.com/apache/commons-text/pull/12"], False),
        (["http://192.168.10.5/login"], True),
        (["https://paypal.com@evil.example/x"], True),
        (["https://secure-login.click/x"], True),
        (["https://storage.googleapis.com/bucket/invoice.html"], True),
    ],
)
def test_strong_link_sign(urls, strong):
    assert sa.strong_link_sign(urls) is strong


def test_plain_http_mailing_list_link_does_not_force_phishing(client, monkeypatch):
    monkeypatch.setattr(sa, "url_agent", lambda urls, body_text="": 0.95)
    j = client.post(
        "/analyse",
        json={
            "raw_text": "Build failed, logs at http://ci.apache.org/builders/x/builds/1/steps/compile/logs/stdio for the record."
        },
    ).json()
    assert j["high_confidence_override"] is False
    assert j["verdict"] == "safe"


RELAYED = (
    b"Return-Path: <office@nileuniversity.edu.ng>\r\n"
    b"Authentication-Results: mx.google.com; dkim=pass header.i=@nileuniversity.edu.ng "
    b"header.s=selector1; spf=pass smtp.mailfrom=nileuniversity.edu.ng; "
    b"dmarc=pass header.from=nileuniversity.edu.ng\r\n"
    b"DKIM-Signature: v=1; a=rsa-sha256; d=nileuniversity.edu.ng; s=selector1; b=x\r\n"
    b"From: ACADEMIC DIVISION <office@nileuniversity.edu.ng>\r\n"
    b"Subject: Processed request for attestation letter\r\n"
    b"authentication-results: mx.microsoft.com 1; dkim=none (message not signed) "
    b"header.d=none;dmarc=none action=none header.from=nileuniversity.edu.ng;\r\n"
    b"Content-Type: text/plain\r\n\r\n"
    b"Your request for an attestation letter has been processed. Please log in to the portal.\r\n"
)


def test_topmost_authentication_results_wins():
    from email_parsing import parse_eml

    _body, _urls, headers = parse_eml(RELAYED)
    # the provider's verdict, not the internal relay's "dkim=none"
    ar = headers["authentication-results"]
    assert "dkim=pass" in ar and "dkim=none" not in ar


def test_microsoft_relay_keeps_the_trusted_path(client):
    import base64

    j = client.post("/analyse", json={"raw_email_b64": base64.b64encode(RELAYED).decode()}).json()
    assert j["trust_path"] == "trusted_sender"


# The standard parser raises on this To: header (a group with an empty
# address): the email used to be refused with "Could not parse".
UNPARSEABLE = (
    b"From: Bank <alerts@evil.example>\r\n"
    b'To: undisclosed-recipients:;; "" <@>\r\n'
    b"Subject: Your account is locked\r\n"
    b"Content-Type: text/html\r\n\r\n"
    b'<p>Confirm your password <a href="http://evil.example/login">here</a> today.</p>\r\n'
)


def test_unparseable_email_is_read_leniently():
    from email_parsing import parse_eml

    body, urls, headers = parse_eml(UNPARSEABLE)
    assert "Confirm your password" in body
    assert "http://evil.example/login" in urls
    assert headers["from"].startswith("Bank")


def test_unparseable_email_is_scanned_not_refused(client):
    import base64

    r = client.post("/analyse", json={"raw_email_b64": base64.b64encode(UNPARSEABLE).decode()})
    assert r.status_code == 200
    assert r.json()["agents"]["url"]["phishing_probability"] > 0


def test_garbage_falls_back_to_the_raw_text():
    from email_parsing import _parse_lenient

    body, urls, _headers = _parse_lenient(b"\xff\xfe not an email http://x.example/a")
    assert "not an email" in body and urls == ["http://x.example/a"]


SIGNED_ELSEWHERE = (
    b"From: Billing <billing@old-shop.example>\r\n"
    b"Authentication-Results: mx.google.com; dkim=pass header.i=@old-shop.example; "
    b"spf=pass smtp.mailfrom=old-shop.example; dmarc=pass header.from=old-shop.example\r\n"
    b"Subject: Your account will be closed\r\n"
    b"Content-Type: text/html\r\n\r\n"
    b'<p>Confirm your payment details <a href="https://secure-verify.example/login">here</a>.</p>\r\n'
)


@pytest.mark.parametrize(
    ("urls", "elsewhere"),
    [
        (["https://www.old-shop.example/a", "https://secure-verify.example/x"], False),
        (["https://secure-verify.example/x"], True),
        (["https://u1.ct.sendgrid.net/ls/click?x", "https://fonts.googleapis.com/css"], False),
        (["https://github.com/x"], False),
        ([], False),
    ],
)
def test_links_elsewhere_only(urls, elsewhere):
    from link_alignment import link_profile, links_elsewhere_only

    counts = link_profile(urls, "Billing <billing@mail.old-shop.example>")
    assert links_elsewhere_only(counts) is elsewhere


def test_crypto_link_rule_is_off_by_default(client, monkeypatch):
    import base64

    monkeypatch.setattr(tm, "text_agent", lambda _t: 0.8)
    body = {"raw_email_b64": base64.b64encode(SIGNED_ELSEWHERE).decode()}
    j = client.post("/analyse", json=body).json()
    assert j["trust_path"] == "crypto_verified" and j["verdict"] == "safe"
    assert j["links_elsewhere"] is False
    assert j["link_alignment"]["aligned"] == 0 and j["link_alignment"]["other"] == 1
    monkeypatch.setattr(eb, "CRYPTO_LINK_RULE", True)
    eb._RESULT_CACHE.clear()
    j = client.post("/analyse", json=body).json()
    assert j["trust_path"] == "crypto_verified" and j["verdict"] == "phishing"
    assert j["links_elsewhere"] is True
