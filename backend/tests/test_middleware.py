"""
Middleware order: the size check's 411 and 413 and the rate limit's 429
carry CORS headers, the default rate limit applies to routes without
their own, and /health is never limited.
"""

from __future__ import annotations

import pytest

pytest.importorskip("fastapi")
pytest.importorskip("httpx")
pytest.importorskip("slowapi")

from fastapi.testclient import TestClient  # noqa: E402

from tests.conftest import import_extension_backend  # noqa: E402

eb = import_extension_backend()
ORIGIN = {"Origin": "chrome-extension://abcdefghijklmnopabcdefghijklmnop"}


@pytest.fixture
def client(monkeypatch):
    monkeypatch.setattr(eb, "PROXY_SECRET", "")
    yield TestClient(eb.app)


def test_too_large_answer_has_cors_headers(client):
    headers = {**ORIGIN, "Content-Length": str(eb.MAX_BODY_BYTES + 1)}
    r = client.post("/analyse", content=b"{}", headers=headers)
    assert r.status_code == 413
    assert r.headers.get("access-control-allow-origin") in ("*", ORIGIN["Origin"])


def test_length_required_answer_has_cors_headers(client):
    def chunks():
        yield b"{}"

    r = client.post("/analyse", content=chunks(), headers=ORIGIN)
    assert r.status_code == 411
    assert r.headers.get("access-control-allow-origin") in ("*", ORIGIN["Origin"])


def test_default_limit_applies_but_not_to_health(client):
    n = int(eb.RATE_LIMIT_DEFAULT.split("/")[0])
    codes = [client.get("/", headers=ORIGIN).status_code for _ in range(n + 1)]
    assert codes[:n] == [200] * n and codes[n] == 429
    r = client.get("/", headers=ORIGIN)
    assert r.headers.get("access-control-allow-origin") in ("*", ORIGIN["Origin"])
    assert all(client.get("/health").status_code == 200 for _ in range(n + 5))


def test_route_limits_stay_their_own(client, monkeypatch):
    import feedback

    monkeypatch.setattr(feedback, "FEEDBACK_DIR", "")
    n = int(eb.RATE_LIMIT_FEEDBACK.split("/")[0])
    codes = [client.post("/feedback", json={"kind": "stats"}).status_code for _ in range(n + 1)]
    assert codes[:n] == [503] * n and codes[n] == 429
