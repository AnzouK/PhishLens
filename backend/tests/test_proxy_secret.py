"""
PROXY_SECRET: with it set, only requests carrying the shared secret in
X-PhishLens-Proxy (added by the phishlens.dev Pages Function) are
served; without it, every request passes as before.

No model and no network: the lifespan hook does not run (TestClient
without a `with` block) and only /health is called.
"""

from __future__ import annotations

import pytest

pytest.importorskip("fastapi")
pytest.importorskip("httpx")  # TestClient transport

from fastapi.testclient import TestClient  # noqa: E402

from tests.conftest import import_extension_backend  # noqa: E402

eb = import_extension_backend()

SECRET = "test-proxy-secret-0123456789abcdef"


@pytest.fixture
def client():
    return TestClient(eb.app)


def test_secret_unset_requests_pass(client, monkeypatch):
    monkeypatch.setattr(eb, "PROXY_SECRET", "")
    assert client.get("/health").status_code == 200
    assert client.get("/health", headers={"X-PhishLens-Proxy": "anything"}).status_code == 200


@pytest.mark.parametrize(
    "headers",
    [
        {},
        {"X-PhishLens-Proxy": ""},
        {"X-PhishLens-Proxy": "wrong"},
        {"X-PhishLens-Proxy": SECRET + "x"},
        {"X-PhishLens-Proxy": SECRET[:-1]},
    ],
)
def test_secret_set_missing_or_wrong_header_is_403(client, monkeypatch, headers):
    monkeypatch.setattr(eb, "PROXY_SECRET", SECRET)
    r = client.get("/health", headers=headers)
    assert r.status_code == 403
    assert r.json() == {"detail": "Forbidden."}
    assert SECRET not in r.text


def test_secret_set_checked_before_routes(client, monkeypatch):
    """A POST to an API route is refused before the body is looked at."""
    monkeypatch.setattr(eb, "PROXY_SECRET", SECRET)
    r = client.post("/analyse", json={"text": "hello"}, headers={"X-Forwarded-For": "203.0.113.7"})
    assert r.status_code == 403


def test_secret_set_right_header_passes(client, monkeypatch):
    monkeypatch.setattr(eb, "PROXY_SECRET", SECRET)
    assert client.get("/health", headers={"X-PhishLens-Proxy": SECRET}).status_code == 200
