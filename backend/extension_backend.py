"""
PhishLens API: the HTTP backend of the PhishLens Chrome extension.

Endpoints
    POST /analyse              an email -> verdict, agent scores, sender
                               checks, threat intelligence
    POST /explain              the words behind the text agent's score (LIME)
    POST /analyse_attachment   one attachment -> verdict and its risky features
    POST /feedback             a report the user chose to send (redacted again)
    GET  /health               liveness, version, which agents run a model
    GET  /reputation/stats     cache and quota counters
    GET  /metrics              Prometheus (block it at the reverse proxy)

This module only wires requests to the other modules.
    settings.py           version, environment, scoring constants
    email_parsing.py      text, links and headers of an email
    sender_trust.py       sender domain, allowlist, Gmail auth hints
    text_model.py         text agent and LIME
    structured_agents.py  URL and metadata agents
    fusion.py             scores -> verdict (pure functions)
    auth_headers.py       SPF / DKIM / DMARC, Spamhaus DBL
    reputation.py         Safe Browsing, PhishTank, URLhaus, Spamhaus
    attachment_analysis   PDF, HTML, images, Office, archives, invites
    language.py           language of the email
    feedback.py           reports users send, with redaction.py

Run locally:
    uvicorn extension_backend:app --host 127.0.0.1 --port 8000
"""

from __future__ import annotations

import asyncio
import base64
import hmac
import logging
import os
import time
import uuid
from contextlib import asynccontextmanager
from dataclasses import dataclass
from email.utils import getaddresses, parseaddr
from typing import Any

from fastapi import FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field
from starlette.concurrency import run_in_threadpool

import feedback
import fusion
import structured_agents
import text_model
from email_parsing import (
    FORWARDED_ELSEWHERE,
    FROM_UNPROVEN,
    Ranked,
    client_links,
    detect_forwarded,
    detect_shared_links,
    is_page_source,
    looks_like_source,
    parse_eml,
    rank_links,
    strip_markup_noise,
    urls_in_text,
)
from language import detect_language
from link_alignment import link_profile, links_elsewhere_only
from result_cache import ResultCache, make_key
from sender_trust import (
    impersonated_brand,
    is_hostname,
    is_trusted_domain,
    sender_domain,
    sender_domains,
    synthesize_auth_results,
)
from settings import (
    CORS_ALLOW_ORIGINS,
    CRYPTO_LINK_RULE,
    CRYPTO_LINK_TEXT_MIN,
    ENABLE_DBL,
    IMPERSONATION_META,
    INNER_FILE_WORDING_THRESHOLD,
    MAX_ATTACHMENT_B64_CHARS,
    MAX_BODY_BYTES,
    MAX_EMAIL_B64_CHARS,
    MAX_LINK_URLS,
    MAX_PAGE_TEXT_CHARS,
    MAX_TEXT_CHARS,
    MAX_URL_SCAN_CHARS,
    METADATA_MODEL_ENABLED,
    METRICS_ENABLED,
    MIN_TEXT_WORDS,
    PROXY_SECRET,
    RATE_LIMIT_ANALYSE,
    RATE_LIMIT_ATTACHMENT,
    RATE_LIMIT_DEFAULT,
    RATE_LIMIT_EXPLAIN,
    RATE_LIMIT_FEEDBACK,
    RATE_LIMIT_STORAGE,
    TRUSTED_META_CEILING,
    VERSION,
)
from unicode_text import collapse_invisible, without_invisible

# uvicorn only configures its own loggers. Without this our
# "phishlens.*" INFO messages would be dropped.
logging.basicConfig(
    level=os.environ.get("LOG_LEVEL", "INFO").upper(),
    format="%(asctime)s %(levelname)s %(name)s: %(message)s",
)
logger = logging.getLogger("phishlens.api")

__all__ = ["MAX_LINK_URLS", "app"]

# Optional modules. Without them the API still starts and uses rules only.
try:
    from auth_headers import build_metadata_auth_signal

    _AUTH_HEADERS_AVAILABLE = True
except Exception as _e:
    _AUTH_HEADERS_AVAILABLE = False
    logger.warning("auth_headers not loaded (%s): SPF/DKIM/DMARC and Spamhaus DBL off.", _e)

try:
    import reputation as _reputation

    _REPUTATION_AVAILABLE = True
except Exception as _e:
    _REPUTATION_AVAILABLE = False
    logger.warning("reputation not loaded (%s): Safe Browsing, PhishTank, URLhaus off.", _e)

try:
    import attachment_analysis as _attachments

    _ATTACHMENTS_AVAILABLE = True
except Exception as _e:
    _ATTACHMENTS_AVAILABLE = False
    logger.warning("attachment_analysis not loaded (%s): /analyse_attachment returns 501.", _e)


# Application
@asynccontextmanager
async def lifespan(_app: FastAPI):
    text_model.load()
    structured_agents.load()
    # Load the model first so a slow PhishTank download can't delay startup.
    if _REPUTATION_AVAILABLE:
        try:
            await _reputation.startup()
        except Exception as e:
            logger.warning("reputation.startup() failed: %s", e)
    yield
    if _REPUTATION_AVAILABLE:
        try:
            await _reputation.shutdown()
        except Exception as e:
            logger.debug("reputation.shutdown() failed: %s", e)
    text_model.unload()


app = FastAPI(title="PhishLens API", version=VERSION, lifespan=lifespan)

# Per-IP rate limiting with slowapi, in memory. Set SLOWAPI_STORAGE_URI to
# a redis:// URL when running several instances. The expensive endpoints
# have their own limits and the middleware below applies
# RATE_LIMIT_DEFAULT to the rest. /health is exempt because keep-warm jobs
# and uptime monitors call it.
try:
    from slowapi import Limiter, _rate_limit_exceeded_handler
    from slowapi.errors import RateLimitExceeded
    from slowapi.middleware import SlowAPIMiddleware
    from slowapi.util import get_remote_address

    _limiter = Limiter(
        key_func=get_remote_address,
        default_limits=[RATE_LIMIT_DEFAULT],
        storage_uri=RATE_LIMIT_STORAGE,
    )
    app.state.limiter = _limiter
    app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)
    _RATE_LIMIT_OK = True
except Exception as _e:
    logger.warning("slowapi not available (%s): rate limiting off.", _e)
    _limiter = None
    _RATE_LIMIT_OK = False


def _rate_limited(limit: str):
    return _limiter.limit(limit) if _RATE_LIMIT_OK else (lambda f: f)


def _not_rate_limited(f):
    return _limiter.exempt(f) if _RATE_LIMIT_OK else f


@app.middleware("http")
async def _limit_body_size(request: Request, call_next):
    """Refuse bodies over MAX_BODY_BYTES before reading them.

    Chunked bodies are refused too, since we'd have to read them to know
    their size. Browsers and the extension always send a length.
    """
    length = request.headers.get("content-length")
    if length and length.isdigit() and int(length) > MAX_BODY_BYTES:
        return JSONResponse({"detail": "Request too large."}, status_code=413)
    if request.method in ("POST", "PUT", "PATCH") and not length:
        return JSONResponse({"detail": "Content-Length required."}, status_code=411)
    return await call_next(request)


# Middleware added later runs earlier. From the outside in the order is
# proxy secret, CORS, default rate limit, body size check. CORS has to wrap
# the last two so a browser can read their 411, 413 and 429 responses.
if _RATE_LIMIT_OK:
    app.add_middleware(SlowAPIMiddleware)

# Extensions call from chrome-extension://<id>. The public backend accepts
# any origin because it uses no cookies. Self-hosted servers can restrict it.
app.add_middleware(
    CORSMiddleware,
    allow_origins=CORS_ALLOW_ORIGINS,
    allow_credentials=False,
    allow_methods=["POST", "GET", "OPTIONS"],
    allow_headers=["*"],
)


# Added last so it runs first. A request that skipped the proxy is refused
# before anything else runs.
@app.middleware("http")
async def _require_proxy_secret(request: Request, call_next):
    """Require the X-PhishLens-Proxy header when PROXY_SECRET is set.

    The comparison is constant-time and neither value is ever logged.
    """
    if PROXY_SECRET:
        sent = request.headers.get("x-phishlens-proxy", "")
        if not hmac.compare_digest(sent.encode(), PROXY_SECRET.encode()):
            return JSONResponse({"detail": "Forbidden."}, status_code=403)
    return await call_next(request)


# Prometheus metrics. Besides the standard HTTP ones we count verdicts per
# endpoint and trust path. A swing in the phishing ratio means either an
# attack wave or a model regression.
_VERDICTS = None
if METRICS_ENABLED:
    try:
        from prometheus_client import Counter
        from prometheus_fastapi_instrumentator import Instrumentator

        Instrumentator(excluded_handlers=["/metrics", "/health"]).instrument(app).expose(
            app, endpoint="/metrics", include_in_schema=False
        )
        _VERDICTS = Counter(
            "phishlens_verdicts_total",
            "Final verdicts returned by the scoring endpoints.",
            ["endpoint", "verdict", "trust_path"],
        )
    except Exception as _e:
        logger.warning("Prometheus metrics off (%s).", _e)


def _count_verdict(endpoint: str, is_phishing: bool, trust_path: str) -> None:
    if _VERDICTS is not None:
        _VERDICTS.labels(endpoint, "phishing" if is_phishing else "safe", trust_path).inc()


# Identical requests get the cached answer for 24 h (result_cache.py), or
# one hour for a safe verdict on an email with links.
_RESULT_CACHE = ResultCache()
SAFE_WITH_LINKS_CACHE_TTL = 3600.0


def _server_error(what: str) -> HTTPException:
    """Log the exception under a short reference and return a generic 500.

    Internal details stay in the logs.
    """
    ref = uuid.uuid4().hex[:8]
    logger.exception("%s failed (ref %s)", what, ref)
    return HTTPException(500, f"{what} failed (reference {ref}).")


def _verdict_label(p: float) -> str:
    return "Phishing" if p >= 0.5 else "Safe"


# Requests
class AnalyseRequest(BaseModel):
    """An email to analyse, as a base64 .eml, as page text, or both.

    sender_email and sender_name describe the sender when only text is
    sent. client_context holds hints from the mail page and is loosely
    typed so new hints don't need an API change.

    Gmail sends origin, gmail_signed_by, gmail_mailed_by, gmail_via,
    gmail_in_inbox, headers_source ("gmail_show_original", or "attachment"
    for an attached .eml), link_urls, hidden_link_urls and subject.
    Outlook sends origin, outlook_internal and org_domain.

    The hints can only change the caller's own result.
    """

    raw_email_b64: str | None = Field(None, max_length=MAX_EMAIL_B64_CHARS)
    raw_text: str | None = Field(None, max_length=MAX_TEXT_CHARS)
    sender_email: str | None = Field(None, max_length=512)
    # Older extensions send the display name uncut. A long one must not fail
    # the scan, and _from_value keeps 200 characters anyway.
    sender_name: str | None = Field(None, max_length=2000)
    client_context: dict[str, Any] | None = None


def _from_value(email: str, name: str | None, original: str = "") -> str:
    """Build a From: value from the client's address and display name.

    The impersonation check needs both to compare the name with the address.
    """
    display = name or parseaddr(original)[0] or ""
    # Strip invisible characters before cutting, so zero-width padding
    # can't push the brand name out.
    display = without_invisible(display)
    display = " ".join(display.split())[:200]
    # Quote per RFC 5322. An unescaped trailing backslash would escape the
    # closing quote, drop the name and skip the impersonation check.
    display = display.replace("\\", "\\\\").replace('"', '\\"')
    return f'"{display}" <{email}>' if display else email


class AttachmentRequest(BaseModel):
    """One attachment, at most 10 MB once decoded.

    mime_type is only a hint because we sniff the real type. parent_email
    carries the trust flags of the email it came from.
    """

    content_b64: str = Field(max_length=MAX_ATTACHMENT_B64_CHARS)
    filename: str | None = Field(None, max_length=1024)
    mime_type: str | None = Field(None, max_length=255)
    parent_email: dict[str, Any] | None = None


def _client_link_groups(ctx: dict[str, Any]) -> tuple[list[str], list[str]]:
    """Return the page's visible and hidden link targets as two lists.

    Keeping them apart stops a hidden link from outranking a visible one.
    Older extensions send everything in link_urls, visible first.
    """
    return client_links(ctx.get("link_urls")), client_links(ctx.get("hidden_link_urls"))


def _resolve_email(req: AnalyseRequest) -> tuple[str, list[str], dict[str, str], bytes | None]:
    """Return (body, urls, headers, raw_bytes) for the request.

    With raw_text only, headers holds the given sender plus a synthetic
    Authentication-Results header if Gmail's "signed-by" and "mailed-by"
    were sent. When both raw_text and raw_email_b64 arrive we prefer the
    page text over the plain-text part, which spells out every URL and
    pushes the text model toward phishing.
    """
    ctx = req.client_context or {}
    if req.raw_text and not req.raw_email_b64:
        full = req.raw_text.strip()
        if looks_like_source(full):
            full = strip_markup_noise(full)
        body = full[:MAX_PAGE_TEXT_CHARS]
        # The text model reads the start, but links further down still count.
        urls = rank_links(*_client_link_groups(ctx), urls_in_text(full[:MAX_URL_SCAN_CHARS]))
        headers: dict[str, str] = {}
        _keep_forward_marker(full, body, headers)
        if req.sender_email:
            headers["from"] = _from_value(req.sender_email, req.sender_name)
        synth = synthesize_auth_results(ctx, req.sender_email)
        if synth:
            headers["authentication-results"] = synth
        return collapse_invisible(body), urls, headers, None
    if not req.raw_email_b64:
        raise HTTPException(400, "Provide either raw_email_b64 or raw_text.")
    try:
        raw_bytes = base64.b64decode(req.raw_email_b64)
    except Exception as e:
        raise HTTPException(400, "raw_email_b64 is not valid base64.") from e
    try:
        body, urls, headers = parse_eml(raw_bytes)
    except Exception as e:
        logger.info("EML parse error: %s", e)
        raise HTTPException(400, "Could not parse this email.") from e
    if ctx.get("headers_source") == "attachment":
        # For an attached email, whoever attached it wrote the
        # authentication results, so we ignore them.
        for key in ("authentication-results", "arc-authentication-results"):
            headers.pop(key, None)
    if req.sender_email:
        # Keep the message's own From: when the page shows less than it says,
        # such as several addresses (Gmail shows only the first) or another
        # domain. In that case it proves nothing either.
        original = headers.get("from", "")
        addresses = [a for _n, a in getaddresses([original]) if "@" in a]
        domains = sender_domains(original)
        if (
            len(addresses) > 1
            or len(domains) > 1
            or (domains and domains[0] != sender_domain(req.sender_email))
        ):
            headers[FROM_UNPROVEN] = "1"
        else:
            headers["from"] = _from_value(req.sender_email, req.sender_name, original)
    # Use the page text because it reflects the styles the browser applied.
    # If the page shows the email's source instead, the parsed message is
    # better.
    text_urls: list[str] = []
    page = (req.raw_text or "").strip()
    if page and not is_page_source(page):
        page_full = strip_markup_noise(page) if looks_like_source(page) else page
        page = page_full[:MAX_PAGE_TEXT_CHARS]
        if len(page.split()) >= MIN_TEXT_WORDS:
            # The client sends at most MAX_PAGE_TEXT_CHARS, so a forward
            # marker further down the message still has to count.
            _keep_forward_marker(body, page, headers)
            body = page
            text_urls = urls_in_text(page_full[:MAX_URL_SCAN_CHARS])
    # Order is page visible links, then the message's links (visible first),
    # then the page's hidden links. A link the browser saw as hidden stays
    # hidden wherever the message lists it.
    shown, unseen = _client_link_groups(ctx)
    hidden_here = set(unseen)
    urls = rank_links(shown, Ranked(u for u in urls if u not in hidden_here), unseen, text_urls)
    # Cut each run of invisible characters to one, so a long padding does
    # not push the words out of the text model's window.
    return collapse_invisible(body), urls, headers, raw_bytes


def _keep_forward_marker(full: str, used: str, headers: dict[str, str]) -> None:
    """Flag a forward marker that only appears in the part of the text we cut off."""
    if detect_forwarded(used)["detected"]:
        return
    found = detect_forwarded(full)
    if found["detected"]:
        headers[FORWARDED_ELSEWHERE] = found["original_sender"] or "1"


def _model_text(body: str, headers: dict[str, str], ctx: dict[str, Any]) -> str:
    """Return the subject followed by the body, which is what the text model reads.

    The model was trained and measured on "subject + body". On the body
    alone it scored the public benchmark's missed phishing 10% on average,
    against 94% with the subject. If the body already starts with the
    subject we leave it alone.
    """
    subject = headers.get("subject") or ctx.get("subject")
    if not isinstance(subject, str):
        return body
    subject = " ".join(subject.split())[:300]
    if not subject or body.startswith(subject):
        return body
    return f"{subject}\n{body}"


def _run_agents(
    text: str, body: str, urls: list[str], headers: dict[str, str], raw_email: bytes | None
) -> tuple[float, float, float]:
    return (
        text_model.text_agent(text),
        structured_agents.url_agent(urls, body_text=body),
        structured_agents.metadata_agent(headers, raw_email=raw_email),
    )


async def _check_urls(urls: list[str]) -> list[dict[str, Any]]:
    if not (_REPUTATION_AVAILABLE and urls):
        return []
    return await _reputation.check_urls(urls)


# Small endpoints
@app.api_route("/", methods=["GET", "HEAD"])
def root():
    return {
        "status": "ok",
        "version": VERSION,
        "endpoints": [
            "/analyse",
            "/explain",
            "/analyse_attachment",
            "/health",
            "/reputation/stats",
        ],
    }


_PURGE_EVERY_S = 3600.0
_last_purge = 0.0


def _purge_expired_caches() -> None:
    """Purge expired cache entries, at most once an hour.

    The warm-up job calls /health every 10 minutes, so an idle instance
    still drops them.
    """
    global _last_purge
    now = time.monotonic()
    if _last_purge and now - _last_purge < _PURGE_EVERY_S:
        return
    _last_purge = now
    _RESULT_CACHE.purge_expired()
    if _REPUTATION_AVAILABLE:
        try:
            _reputation.purge_if_due()
        except Exception as e:
            logger.debug("reputation cache purge failed: %s", e)


# Also answer HEAD, which UptimeRobot's free plan uses.
@app.api_route("/health", methods=["GET", "HEAD"])
@_not_rate_limited
def health():
    """Report liveness, version and which agents run a trained model."""
    _purge_expired_caches()
    return {
        "status": "ok",
        "version": VERSION,
        "agents": {
            "text": "model" if text_model.STATE else "not_loaded",
            "url": "model" if structured_agents.url_model_ready() else "rules",
            "metadata": "model" if structured_agents.metadata_model_ready() else "rules",
        },
        # Which text model runs and how its input and scores are handled.
        "text_model": {
            **text_model.STATE.get("meta", {}),
            "source": text_model.STATE.get("source"),
            "revision": text_model.STATE.get("revision"),
            "name": text_model.STATE.get("name"),
            # The English v1 model is much weaker on real mail than the
            # multilingual one (docs/multilingual-model.md). The extension
            # warns about it.
            "legacy": text_model.STATE.get("source") == text_model.LEGACY_REPO,
        }
        if text_model.STATE
        else None,
    }


_STATS_TTL_S = 30.0
_stats_cache: dict[str, Any] = {}


@app.get("/reputation/stats")
def reputation_stats():
    """Return cache hit rate, Safe Browsing quota and PhishTank feed size.

    Counting a large cache table takes seconds and the website asks on
    every visit, so we keep the answer for _STATS_TTL_S seconds.
    """
    now = time.monotonic()
    if _stats_cache and now - _stats_cache["at"] < _STATS_TTL_S:
        return _stats_cache["body"]
    if not _REPUTATION_AVAILABLE:
        body = {
            "enabled": False,
            "reason": "reputation module not loaded",
            "result_cache": _RESULT_CACHE.stats(),
        }
    else:
        body = {"enabled": True, **_reputation.stats(), "result_cache": _RESULT_CACHE.stats()}
    _stats_cache.update(at=now, body=body)
    return body


@app.post("/feedback")
@_rate_limited(RATE_LIMIT_FEEDBACK)
def send_feedback(request: Request, req: feedback.FeedbackRequest):
    """Store a report the user chose to send, after redacting it again.

    Reports cover a wrong verdict, a wrong language or reviewed statistics.
    """
    if not feedback.enabled():
        raise HTTPException(503, "This server does not collect reports.")
    try:
        reference = feedback.store(req)
    except ValueError as e:
        raise HTTPException(400, str(e)) from e
    except OSError as e:
        raise HTTPException(503, "Reports cannot be stored right now.") from e
    return {"ok": True, "reference": reference}


@app.post("/explain")
@_rate_limited(RATE_LIMIT_EXPLAIN)
def explain(request: Request, req: AnalyseRequest):
    """Return the top words behind the text score (LIME).

    The endpoint is sync, so FastAPI runs it in a worker thread.
    """
    body, _, headers, _ = _resolve_email(req)
    if not body:
        raise HTTPException(400, "Could not extract any text from this email.")
    text = _model_text(body, headers, req.client_context or {})
    cache_key = make_key("explain", {"body": text[:800], "n": text_model.LIME_NUM_SAMPLES})
    cached = _RESULT_CACHE.get(cache_key)
    if cached is not None:
        return cached
    try:
        result = {"features": text_model.explain(text)}
    except Exception as e:
        raise _server_error("Explanation") from e
    _RESULT_CACHE.set(cache_key, result)
    return result


# /analyse
@dataclass
class _Scores:
    """Agent scores after threat intelligence and sender checks, plus what the response shows."""

    p_text: float
    p_url: float
    p_meta: float
    p_url_raw: float
    p_meta_raw: float
    auth_signal: dict[str, Any]
    rep: fusion.Reputation
    meta_model_used: bool
    cacheable: bool  # a partial result is not cached


@dataclass
class _Sender:
    """Who sent the email and how well that is proven."""

    domain: str
    crypto_verified: bool
    dmarc_verified: bool
    outlook_internal: bool
    trusted_sender: bool
    inbox_soft: bool
    forwarded: dict[str, Any]
    impersonation: str | None


_NO_AUTH_SIGNAL: dict[str, Any] = {
    "score_delta": 0.0,
    "reasons": [],
    "auth": {},
    "spamhaus_dbl": {},
}


async def _score(
    body: str,
    urls: list[str],
    headers: dict[str, str],
    raw_bytes: bytes | None,
    ctx: dict[str, Any],
) -> _Scores:
    """Run the agents, sender authentication and URL reputation."""
    # Start the network calls first and collect them after model inference.
    auth_task = (
        asyncio.create_task(build_metadata_auth_signal(headers, enable_dbl=ENABLE_DBL))
        if _AUTH_HEADERS_AVAILABLE
        else None
    )
    rep_task = asyncio.create_task(_check_urls(urls))

    # The trained metadata model scores modern provider and mailing-list
    # headers (ARC, X-Gm-*, List-*, long Received chains) near 1.0 on real
    # mail. We use rules and the actual SPF/DKIM/DMARC results unless
    # METADATA_MODEL_ENABLED is set. Gmail's "Show original" headers never
    # go to the model.
    raw_for_meta_model = (
        raw_bytes
        if METADATA_MODEL_ENABLED and ctx.get("headers_source") != "gmail_show_original"
        else None
    )
    try:
        p_text, p_url, p_meta = await run_in_threadpool(
            _run_agents,
            _model_text(body, headers, ctx),
            body,
            urls,
            headers,
            raw_for_meta_model,
        )
    except Exception as e:
        for task in (auth_task, rep_task):
            if task:
                task.cancel()
        raise _server_error("Inference") from e

    cacheable = True
    auth_signal = dict(_NO_AUTH_SIGNAL)
    if auth_task:
        try:
            auth_signal = await auth_task
        except Exception as e:
            logger.warning("auth signal failed: %s", e)
            cacheable = False
    try:
        rep = fusion.summarize_reputation(await rep_task)
    except Exception as e:
        logger.warning("reputation check failed: %s", e)
        rep = fusion.summarize_reputation([])
        cacheable = False
    # If Safe Browsing couldn't check a link we don't know it is clean, so
    # the answer isn't cached.
    if rep.verdicts and not _reputation.fully_checked(rep.verdicts):
        cacheable = False

    return _Scores(
        p_text=p_text,
        p_url=fusion.apply_reputation(p_url, rep),
        p_meta=max(0.0, min(1.0, p_meta + float(auth_signal.get("score_delta", 0.0)))),
        p_url_raw=p_url,
        p_meta_raw=p_meta,
        auth_signal=auth_signal,
        rep=rep,
        meta_model_used=bool(structured_agents.metadata_model_ready() and raw_for_meta_model),
        cacheable=cacheable,
    )


def _sender(body: str, headers: dict[str, str], ctx: dict[str, Any], auth: dict) -> _Sender:
    """Work out who the sender is and whether that is proven, for the trust path."""
    domain = sender_domain(headers.get("from", ""))
    allowlisted = is_trusted_domain(domain)
    crypto_verified = bool(auth.get("cryptographically_verified"))
    # DMARC passed for the From: domain without an aligned DKIM signature
    # (aligned through SPF). Proven, but never enough for the allowlist.
    dmarc_verified = not crypto_verified and bool(auth.get("dmarc_aligned"))
    # Outlook on the web shows only the name for senders in the user's own
    # organisation. The organisation's server authenticated that mail, so
    # its domain stands in for the sender's. This only applies when no
    # sender address was found. If the page showed one, it isn't internal
    # mail whatever the client says.
    outlook_internal = (
        ctx.get("origin") == "outlook"
        and ctx.get("outlook_internal") is True
        and not crypto_verified
        and not domain
    )
    if outlook_internal:
        org = str(ctx.get("org_domain") or "").strip().lower()[:253]
        if is_hostname(org):
            domain = org

    subject = headers.get("subject") or ctx.get("subject")
    forwarded = detect_forwarded(body, subject if isinstance(subject, str) else None)
    hint = headers.get(FORWARDED_ELSEWHERE)
    # The hint also gives the original sender when the scored text only
    # had the "Fwd:" subject.
    if hint and (not forwarded["detected"] or (not forwarded["original_sender"] and "@" in hint)):
        forwarded = {"detected": True, "original_sender": hint if "@" in hint else None}
    # A brand name over someone else's address. Authentication only proves
    # who the impostor is, so no softer path. We check forwards too, so a
    # "TR:" subject can't hide it.
    impersonation = impersonated_brand(headers.get("from", ""))
    if forwarded["detected"] or impersonation:
        # The sender only vouches for the act of forwarding, and an
        # impostor's authentication proves nothing.
        allowlisted = crypto_verified = dmarc_verified = outlook_internal = False
    # Gmail put the message in the inbox after its own SPF/DKIM/DMARC
    # checks. That is a soft signal for when nothing stronger is available,
    # so it is off when DMARC already proved the sender (the interface
    # would otherwise show "Delivered by Gmail" next to that path).
    inbox_soft = (
        not crypto_verified
        and not dmarc_verified
        and not impersonation
        and not forwarded["detected"]
        and ((ctx.get("origin") == "gmail" and bool(ctx.get("gmail_in_inbox"))) or outlook_internal)
        and auth.get("dmarc") != "fail"
        and auth.get("dkim") != "fail"
    )
    return _Sender(
        domain=domain,
        crypto_verified=crypto_verified,
        dmarc_verified=dmarc_verified,
        outlook_internal=outlook_internal,
        # The allowlist only counts for a signature-proven sender, since the
        # From: text can be forged. "Internal" comes from the page alone
        # (no address shown), so it only gets the soft path.
        trusted_sender=allowlisted and crypto_verified,
        inbox_soft=inbox_soft,
        forwarded=forwarded,
        impersonation=impersonation,
    )


def _agents_block(
    s: _Scores, body: str, urls: list[str], meta_checked: bool
) -> dict[str, dict[str, Any]]:
    if not urls:
        url_source = "none"
    elif structured_agents.url_model_ready() and set(urls) & set(urls_in_text(body)):
        url_source = "model"
    else:
        url_source = "rules"
    return {
        "text": {
            "phishing_probability": s.p_text,
            "verdict": _verdict_label(s.p_text),
            "source": "model",
        },
        "url": {
            "phishing_probability": s.p_url,
            "phishing_probability_raw": s.p_url_raw,
            "verdict": _verdict_label(s.p_url),
            "source": url_source,
        },
        "metadata": {
            "phishing_probability": s.p_meta,
            "phishing_probability_raw": s.p_meta_raw,
            "verdict": _verdict_label(s.p_meta),
            "checked": meta_checked,
            "source": "model" if s.meta_model_used else "rules",
        },
    }


def _sender_auth_block(s: _Scores, who: _Sender) -> dict[str, Any]:
    auth = s.auth_signal.get("auth", {})
    return {
        "cryptographically_verified": who.crypto_verified,
        "dmarc_verified": who.dmarc_verified,
        "gmail_inbox_soft_verified": bool(who.inbox_soft and not who.outlook_internal),
        "outlook_internal": bool(who.outlook_internal),
        "spf": auth.get("spf", "none"),
        "dkim": auth.get("dkim", "none"),
        "dmarc": auth.get("dmarc", "none"),
        "aligned": auth.get("aligned", False),
        "spamhaus_dbl_listed": bool(s.auth_signal.get("spamhaus_dbl", {}).get("listed")),
        "reasons": s.auth_signal.get("reasons", []),
        "impersonation": (
            {"brand": who.impersonation, "domain": who.domain or ""} if who.impersonation else None
        ),
        "score_delta": s.auth_signal.get("score_delta", 0.0),
    }


def _auth_source(headers: dict[str, str]) -> str:
    """Report whether the sender checks used real headers or Gmail's displayed values.

    Gmail verified the displayed values, not us.
    """
    auth_header = headers.get("authentication-results", "") or ""
    if auth_header.startswith("gmail-client-context"):
        return "gmail_ui"
    return "headers" if auth_header else "none"


@app.post("/analyse")
@_rate_limited(RATE_LIMIT_ANALYSE)
async def analyse(request: Request, req: AnalyseRequest):
    cache_key = make_key("analyse", req.model_dump())
    cached = _RESULT_CACHE.get(cache_key)
    if cached is not None:
        _count_verdict(
            "/analyse", cached.get("verdict") == "phishing", cached.get("trust_path", "default")
        )
        return {**cached, "cached": True}

    # Parsing a large email is CPU work, so keep it off the event loop.
    body, urls, headers, raw_bytes = await run_in_threadpool(_resolve_email, req)
    if not body and raw_bytes:
        # For an attachment-only email the subject stands in for the text.
        # It is usually too short for the text agent (MIN_TEXT_WORDS).
        body = (headers.get("subject") or "").strip() or "(no text)"
    if not body:
        raise HTTPException(400, "Could not extract any text from this email.")
    ctx = req.client_context or {}

    s = await _score(body, urls, headers, raw_bytes, ctx)
    who = _sender(body, headers, ctx, s.auth_signal.get("auth", {}))
    if who.impersonation:
        s.p_meta = max(s.p_meta, IMPERSONATION_META)
    if who.trusted_sender:
        s.p_meta = min(s.p_meta, TRUSTED_META_CEILING)

    path = fusion.choose_trust_path(
        trusted_sender=who.trusted_sender,
        crypto_verified=who.crypto_verified,
        dmarc_verified=who.dmarc_verified,
        inbox_soft=who.inbox_soft,
        outlook_internal=who.outlook_internal,
    )
    text_used = len(body.split()) >= MIN_TEXT_WORDS
    links = link_profile(urls, headers.get("from", ""))
    verdict = fusion.decide_email(
        s.p_text,
        s.p_url,
        s.p_meta,
        text_used=text_used,
        path=path,
        rep=s.rep,
        strong_link=structured_agents.strong_link_sign(urls),
        text_override=text_model.override_threshold(),
        links_elsewhere=CRYPTO_LINK_RULE and links_elsewhere_only(links),
    )
    # Tell the interface when the link rule lifted the signed-sender
    # discount, since it shows a "DKIM verified" badge next to the verdict.
    links_rule_fired = bool(
        CRYPTO_LINK_RULE
        and "links_elsewhere" in path.forcing
        and links_elsewhere_only(links)
        and s.p_text >= CRYPTO_LINK_TEXT_MIN
    )
    _count_verdict("/analyse", verdict.is_phishing, verdict.trust_path)

    # With no headers (pasted text, or a client that sent none) there is no
    # sender to check. The sender score falls back to a neutral default
    # shown as "not checked".
    meta_checked = bool(
        raw_bytes
        or headers.get("authentication-results")
        or who.impersonation
        or ctx.get("gmail_in_inbox")
    )
    result = {
        "verdict": "phishing" if verdict.is_phishing else "safe",
        "fused_score": float(verdict.fused),
        "high_confidence_override": bool(verdict.high_conf),
        "forced_by": list(verdict.forced_by),
        # trusted_sender > crypto_verified > dmarc_verified >
        # gmail_inbox_soft / outlook_internal > default
        "trust_path": verdict.trust_path,
        "trusted_sender": bool(who.trusted_sender),
        "sender_domain": who.domain,
        "forwarded": who.forwarded,
        "shared_links": detect_shared_links(urls),
        "link_alignment": links,
        "links_elsewhere": links_rule_fired,
        "text_agent_used": text_used,
        "language": detect_language(body),
        "sender_auth": _sender_auth_block(s, who),
        "url_reputation": s.rep.as_dict(),
        "agents": _agents_block(s, body, urls, meta_checked),
        "auth_source": _auth_source(headers),
        "cached": False,
    }
    if s.cacheable:
        # Cache a safe verdict on an email with links for an hour at most, so
        # a link blocklisted later is caught on the next scan.
        ttl = SAFE_WITH_LINKS_CACHE_TTL if urls and not verdict.is_phishing else None
        _RESULT_CACHE.set(cache_key, result, ttl=ttl)
    return result


# /analyse_attachment
# Inner-file features we name in an archive's per-file report.
_INNER_REASONS = {
    "contains_macros": "macros",
    "remote_template": "remote template",
    "dde_field": "DDE field",
    "contains_activex": "ActiveX control",
    "embedded_ole_object": "embedded object",
    "contains_javascript": "JavaScript",
    "auto_execute_on_open": "runs on open",
    "launch_external_action": "launches a program",
    "contains_password_field": "password form",
    "submits_form_to_url": "sends a form",
    "encrypted_document": "password-protected",
    "contains_qr_code": "QR code",
}


def _archive_file_report(extracted: dict, reputation_verdicts: list[dict]) -> list[dict]:
    """List up to 20 archive members that explain the verdict, worst first.

    A member qualifies with a risky name, a risky inner document, phishing
    wording or a link flagged by threat intelligence.
    """
    bad_urls = {v.get("url") for v in reputation_verdicts if v.get("malicious")}
    report: dict[str, list[str]] = {}
    for name in extracted.get("_all_entries") or extracted.get("entries") or []:
        reasons = _attachments.archives.entry_reasons(name)
        if reasons:
            report[name] = reasons
    for f in extracted.get("inner_files") or []:
        reasons = report.setdefault(f.get("filename") or "?", [])
        for flag in f.get("notable_features") or []:
            label = _INNER_REASONS.get(flag)
            if label and label not in reasons:
                reasons.append(label)
        if any(u in bad_urls for u in f.get("_urls") or []):
            reasons.append("flagged link")
        text = f.get("_text") or ""
        if len(text.split()) >= MIN_TEXT_WORDS:
            try:
                if text_model.text_agent(text) >= INNER_FILE_WORDING_THRESHOLD:
                    reasons.append("phishing wording")
            except Exception as e:
                logger.warning("text agent failed on an inner file: %s", e)
    rows = [{"name": n, "reasons": r} for n, r in report.items() if r]
    rows.sort(key=lambda row: -len(row["reasons"]))
    return rows[:20]


def _score_attachment_text(text: str, urls: list[str]) -> tuple[float, float]:
    """Score an attachment with the text and URL agents. A failing agent counts as 0."""
    p_text = p_url = 0.0
    if text.strip():
        try:
            p_text = text_model.text_agent(text)
        except Exception as e:
            logger.warning("text agent failed on an attachment: %s", e)
    try:
        p_url = structured_agents.url_agent(urls, body_text=text)
    except Exception as e:
        logger.warning("url agent failed on an attachment: %s", e)
    return p_text, p_url


@app.post("/analyse_attachment")
@_rate_limited(RATE_LIMIT_ATTACHMENT)
async def analyse_attachment(request: Request, req: AttachmentRequest):
    if not _ATTACHMENTS_AVAILABLE:
        raise HTTPException(501, "Attachment analysis is not available on this server.")
    try:
        # Parsing, OCR and decompression are CPU-bound, so use a worker thread.
        extracted = await run_in_threadpool(
            _attachments.analyse_attachment,
            req.content_b64,
            filename=req.filename or "",
            mime_type=req.mime_type,
        )
    except ValueError as e:
        # Unsupported type, oversized, bad base64. These messages are
        # written for the user.
        raise HTTPException(400, str(e)) from e
    except RuntimeError as e:
        # The request is valid but the file doesn't parse (a corrupt PDF, say).
        raise HTTPException(422, str(e)) from e
    except Exception as e:
        raise _server_error("Attachment analysis") from e

    text = extracted.get("extracted_text", "") or ""
    urls = extracted.get("extracted_urls", []) or []
    p_text, p_url = await run_in_threadpool(_score_attachment_text, text, urls)
    try:
        rep = fusion.summarize_reputation(await _check_urls(urls))
    except Exception as e:
        logger.warning("reputation check failed on an attachment: %s", e)
        rep = fusion.summarize_reputation([])
    p_url_raw = p_url
    p_url = fusion.apply_reputation(p_url, rep)

    notable = extracted.get("notable_features", []) or []
    feature_bonus = fusion.attachment_feature_bonus(notable)
    dropper = fusion.dropper_techniques(notable)
    # parent_email is an unverifiable client hint. A false claim only
    # softens the caller's own result, and Safe Browsing hits and dropper
    # techniques override it. Never use it for anything shared.
    parent = req.parent_email or {}
    parent_trusted = bool(
        parent.get("crypto_verified")
        or parent.get("gmail_inbox_soft_verified")
        or parent.get("trusted_sender")
        or parent.get("gmail_delivered")
    )
    verdict = fusion.decide_attachment(
        p_text,
        p_url,
        feature_bonus=feature_bonus,
        parent_trusted=parent_trusted,
        rep=rep,
        dropper=dropper,
        url_rule_score=structured_agents.url_heuristic(urls),
        text_override=text_model.override_threshold(),
    )
    _count_verdict(
        "/analyse_attachment",
        verdict.is_phishing,
        "parent_trusted" if parent_trusted else "default",
    )

    # Archives, and Office files that contain other files.
    is_archive = (
        extracted.get("kind") == "archive"
        or bool(extracted.get("inner_files"))
        or bool(extracted.get("_all_entries"))
    )
    suspicious_files = (
        await run_in_threadpool(_archive_file_report, extracted, rep.verdicts) if is_archive else []
    )
    inner_public = [
        {k: v for k, v in f.items() if not k.startswith("_")}
        for f in (extracted.get("inner_files") or [])
    ]
    return {
        "verdict": "phishing" if verdict.is_phishing else "safe",
        "fused_score": float(verdict.fused),
        "high_confidence_override": bool(verdict.high_conf),
        "language": detect_language(text),
        "attachment": {
            "filename": extracted.get("filename"),
            "kind": extracted.get("kind"),
            "size_bytes": extracted.get("size_bytes"),
            "page_count": extracted.get("page_count"),
            "pages_read": extracted.get("pages_read"),
            "extracted_text_chars": extracted.get("extracted_text_chars"),
            "extracted_urls_count": len(urls),
            "notable_features": notable,
            "feature_bonus": round(feature_bonus, 3),
            "qr_urls": extracted.get("qr_urls", []),
            "ocr_used": bool(extracted.get("ocr_used")),
            "capabilities": extracted.get("capabilities"),
            "dropper_techniques": dropper,
            # archives and calendar invites (None for other kinds)
            "archive_format": extracted.get("archive_format"),
            "entries": extracted.get("entries"),
            "entry_count": extracted.get("entry_count"),
            "encrypted": extracted.get("encrypted"),
            "inner_files": inner_public if is_archive else None,
            "suspicious_files": suspicious_files,
            "organizer": extracted.get("organizer"),
        },
        "parent_email": req.parent_email or None,
        "parent_trusted": parent_trusted,
        "url_reputation": rep.as_dict(),
        "agents": {
            "text": {"phishing_probability": p_text, "verdict": _verdict_label(p_text)},
            "url": {
                "phishing_probability": p_url,
                "phishing_probability_raw": p_url_raw,
                "verdict": _verdict_label(p_url),
            },
            "metadata": {
                "phishing_probability": 0.0,
                "verdict": "Safe",
                "note": "not applicable to attachments",
            },
        },
    }
