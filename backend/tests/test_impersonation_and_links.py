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
