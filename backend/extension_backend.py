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

This module only wires requests to the other modules:
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
    MAX_TEXT_CHARS,
    METADATA_MODEL_ENABLED,
    METRICS_ENABLED,
    MIN_TEXT_WORDS,
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

# uvicorn configures its own loggers only: without this, the
# "phishlens.*" INFO messages would be dropped.
logging.basicConfig(
    level=os.environ.get("LOG_LEVEL", "INFO").upper(),
    format="%(asctime)s %(levelname)s %(name)s: %(message)s",
)
logger = logging.getLogger("phishlens.api")

__all__ = ["MAX_LINK_URLS", "app"]

# Optional modules: the API still starts without them, with rules only.
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


# ---------------------------------------------------------------------
# Application
# ---------------------------------------------------------------------
@asynccontextmanager
async def lifespan(_app: FastAPI):
    text_model.load()
    structured_agents.load()
    # After the model: a slow PhishTank download must not delay startup.
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

# Extensions call from chrome-extension://<id>; the public backend accepts
# any origin (no cookies are used). Self-hosted servers can restrict it.
app.add_middleware(
    CORSMiddleware,
    allow_origins=CORS_ALLOW_ORIGINS,
    allow_credentials=False,
    allow_methods=["POST", "GET", "OPTIONS"],
    allow_headers=["*"],
)


@app.middleware("http")
async def _limit_body_size(request: Request, call_next):
    """Refuse a body above MAX_BODY_BYTES before reading it. A body sent
    without a length (chunked) is refused too: its size could only be
    known by reading it. Browsers and the extension always send one."""
    length = request.headers.get("content-length")
    if length and length.isdigit() and int(length) > MAX_BODY_BYTES:
        return JSONResponse({"detail": "Request too large."}, status_code=413)
    if request.method in ("POST", "PUT", "PATCH") and not length:
        return JSONResponse({"detail": "Content-Length required."}, status_code=411)
    return await call_next(request)


# Rate limiting per client IP on the expensive endpoints (slowapi,
# in memory; SLOWAPI_STORAGE_URI=redis://... when scaling out).
try:
    from slowapi import Limiter, _rate_limit_exceeded_handler
    from slowapi.errors import RateLimitExceeded
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


# Prometheus metrics: standard HTTP metrics plus the verdicts per endpoint
# and trust path (a swing in the phishing ratio means an attack wave or a
# model regression).
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


# Same request, same answer for 24 h (result_cache.py), an hour for a safe
# verdict on an email with links.
_RESULT_CACHE = ResultCache()
SAFE_WITH_LINKS_CACHE_TTL = 3600.0


def _server_error(what: str) -> HTTPException:
    """Log the current exception with a short reference and return a
    generic 500: internal details stay in the logs."""
    ref = uuid.uuid4().hex[:8]
    logger.exception("%s failed (ref %s)", what, ref)
    return HTTPException(500, f"{what} failed (reference {ref}).")


def _verdict_label(p: float) -> str:
    return "Phishing" if p >= 0.5 else "Safe"


# ---------------------------------------------------------------------
# Requests
# ---------------------------------------------------------------------
class AnalyseRequest(BaseModel):
    """An email: raw_email_b64 (a base64 .eml) and/or raw_text (the text
    as the page shows it).

    sender_email gives the sender when only the text is sent, and
    sender_name the name the mail client shows for it.
    client_context carries hints from the mail client page, loosely typed
    so new hints need no API change. Gmail: origin, gmail_signed_by,
    gmail_mailed_by, gmail_via, gmail_in_inbox, headers_source
    ("gmail_show_original", or "attachment" for an attached .eml),
    link_urls, hidden_link_urls, subject. Outlook: origin,
    outlook_internal, org_domain.
    These hints only affect the caller's own result.
    """

    raw_email_b64: str | None = Field(None, max_length=MAX_EMAIL_B64_CHARS)
    raw_text: str | None = Field(None, max_length=MAX_TEXT_CHARS)
    sender_email: str | None = Field(None, max_length=512)
    # Display names come from the email: a long one must not fail the scan
    # (older extensions send it uncut); _from_value keeps 200 characters.
    sender_name: str | None = Field(None, max_length=2000)
    client_context: dict[str, Any] | None = None


def _from_value(email: str, name: str | None, original: str = "") -> str:
    """From: built from the address the client sent and the name it shows
    (or the name of the original header), so that the name can be checked
    against the address (impersonation)."""
    display = name or parseaddr(original)[0] or ""
    # Invisible characters out before the cut: 200 zero-width spaces used
    # to push the brand name past it.
    display = without_invisible(display)
    display = " ".join(display.split())[:200]
    # Quoted as RFC 5322 says: a name ending in a backslash escaped the
    # closing quote, and the name was lost (with the impersonation check).
    display = display.replace("\\", "\\\\").replace('"', '\\"')
    return f'"{display}" <{email}>' if display else email


class AttachmentRequest(BaseModel):
    """One attachment (10 MB at most once decoded). mime_type is a hint;
    the real type is sniffed. parent_email carries the trust flags of the
    email it came from."""

    content_b64: str = Field(max_length=MAX_ATTACHMENT_B64_CHARS)
    filename: str | None = Field(None, max_length=1024)
    mime_type: str | None = Field(None, max_length=255)
    parent_email: dict[str, Any] | None = None


def _client_link_groups(ctx: dict[str, Any]) -> tuple[list[str], list[str]]:
    """Visible and hidden link targets the page sent, apart: no hidden one
    is ranked before a visible one (older extensions send them all in
    link_urls, visible first)."""
    return client_links(ctx.get("link_urls")), client_links(ctx.get("hidden_link_urls"))


def _resolve_email(req: AnalyseRequest) -> tuple[str, list[str], dict[str, str], bytes | None]:
    """(body, urls, headers, raw_bytes) of the request.

    With raw_text only, headers holds the given sender and, when Gmail's
    "signed-by" / "mailed-by" were sent, a synthetic Authentication-Results
    header. With raw_email_b64, the page text (raw_text) is preferred to
    the plain-text part when both are sent: plain-text parts spell every
    URL out, which the text model reads as phishing.
    """
    ctx = req.client_context or {}
    if req.raw_text and not req.raw_email_b64:
        body = req.raw_text.strip()
        if looks_like_source(body):
            body = strip_markup_noise(body)
        urls = rank_links(*_client_link_groups(ctx), urls_in_text(body))
        headers: dict[str, str] = {}
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
        # An email attached to another one: its authentication results were
        # written by whoever attached it, so they are not read at all.
        for key in ("authentication-results", "arc-authentication-results"):
            headers.pop(key, None)
    if req.sender_email:
        # The message's own From: is kept when the page's sender does not
        # say all it says: several addresses (Gmail shows only the first),
        # or another domain. Then it proves nothing either.
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
    # The page text, unless it is the email's source shown as text: then
    # the text parsed from the original message is better. The page text
    # reflects the styles the browser applied (hidden parts last), which
    # the parsed message cannot.
    text_urls: list[str] = []
    page = (req.raw_text or "").strip()
    if page and not is_page_source(page):
        page = strip_markup_noise(page) if looks_like_source(page) else page
        if len(page.split()) >= MIN_TEXT_WORDS:
            body = page
            text_urls = urls_in_text(body)
    # Visible links of the page, then those of the message (its own
    # visible ones first), then the page's hidden ones.
    # A link the browser saw hidden (a 1 px image, a rule for screens)
    # stays with the hidden ones, wherever the message lists it.
    shown, unseen = _client_link_groups(ctx)
    hidden_here = set(unseen)
    urls = rank_links(shown, Ranked(u for u in urls if u not in hidden_here), unseen, text_urls)
    # Without invisible characters, as the reader sees it: for the text
    # model, the forward and language checks alike.
    return collapse_invisible(body), urls, headers, raw_bytes


def _model_text(body: str, headers: dict[str, str], ctx: dict[str, Any]) -> str:
    """The text the text model reads: subject, then body. The model was
    trained and measured on "subject + body"; on the body alone it scored
    the public benchmark's missed phishing 10% on average, against 94%
    with the subject. Unchanged when the body already starts with it."""
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


# ---------------------------------------------------------------------
# Small endpoints
# ---------------------------------------------------------------------
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


# HEAD too: uptime monitors (UptimeRobot's free plan) probe with HEAD.
@app.api_route("/health", methods=["GET", "HEAD"])
def health():
    """Liveness, version, and which agents run a trained model."""
    return {
        "status": "ok",
        "version": VERSION,
        "agents": {
            "text": "model" if text_model.STATE else "not_loaded",
            "url": "model" if structured_agents.url_model_ready() else "rules",
            "metadata": "model" if structured_agents.metadata_model_ready() else "rules",
        },
        # which text model runs, and how its input and scores are handled
        "text_model": {
            **text_model.STATE.get("meta", {}),
            "source": text_model.STATE.get("source"),
            "revision": text_model.STATE.get("revision"),
            "name": text_model.STATE.get("name"),
            # The English v1 model: much weaker on real mail than the
            # multilingual one (docs/multilingual-model.md); the extension
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
    """Cache hit rate, Safe Browsing quota, PhishTank feed size. Counting
    the cache table takes seconds once it is large, and the website asks
    on every visit: the answer is kept _STATS_TTL_S seconds."""
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
    """A report the user chose to send (wrong verdict, wrong language or
    reviewed statistics). The text is redacted again before it is stored."""
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
    """Top words behind the text agent's score (LIME). A sync endpoint:
    FastAPI runs it in a worker thread."""
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


# ---------------------------------------------------------------------
# /analyse
# ---------------------------------------------------------------------
@dataclass
class _Scores:
    """The three agents' scores, after threat intelligence and sender
    authentication, with what the response reports about them."""

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
    """Who sent the email, and how far that is proven."""

    domain: str
    crypto_verified: bool
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
    # Sender authentication and URL reputation are network calls: started
    # first, collected after the model inference.
    auth_task = (
        asyncio.create_task(build_metadata_auth_signal(headers, enable_dbl=ENABLE_DBL))
        if _AUTH_HEADERS_AVAILABLE
        else None
    )
    rep_task = asyncio.create_task(_check_urls(urls))

    # The trained metadata model scores modern provider and mailing-list
    # headers (ARC, X-Gm-*, List-*, long Received chains) near 1.0 on
    # legitimate mail, so the rules and the real SPF/DKIM/DMARC results
    # are used unless METADATA_MODEL_ENABLED is set. Gmail's "Show
    # original" headers never go to it.
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
    # A link Safe Browsing could not check (quota, outage) is not known
    # to be clean: the answer is not reused.
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
    """Who the sender is and whether it is proven: the inputs of the
    trust path."""
    domain = sender_domain(headers.get("from", ""))
    allowlisted = is_trusted_domain(domain)
    crypto_verified = bool(auth.get("cryptographically_verified"))
    # Outlook on the web shows only the name of senders from the user's own
    # organisation; that mail was authenticated by the organisation's
    # server, and the organisation's domain stands in for the sender's.
    # Only when no sender address was found: a page that showed one is not
    # internal mail, whatever the client says.
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
    # A brand's name over another domain's address: authentication only
    # proves who the impostor is, so no softer path. Checked on forwards
    # too: a "TR:" in the subject must not hide it.
    impersonation = impersonated_brand(headers.get("from", ""))
    if forwarded["detected"] or impersonation:
        # The sender vouches for the forward, not for the forwarded
        # content; an impostor's authentication proves nothing.
        allowlisted = crypto_verified = outlook_internal = False
    # Gmail delivered the message to the inbox after its own SPF/DKIM/DMARC
    # checks: a soft signal, used when nothing stronger is available.
    inbox_soft = (
        not crypto_verified
        and not impersonation
        and not forwarded["detected"]
        and ((ctx.get("origin") == "gmail" and bool(ctx.get("gmail_in_inbox"))) or outlook_internal)
        and auth.get("dmarc") != "fail"
        and auth.get("dkim") != "fail"
    )
    return _Sender(
        domain=domain,
        crypto_verified=crypto_verified,
        outlook_internal=outlook_internal,
        # The allowlist counts only for a sender proven by its signature:
        # the From: text alone can be forged, and "internal" is only read
        # from the page (no address shown), so it gets the soft path.
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
    """Where the sender checks came from: real headers, or the values
    Gmail shows (Gmail verified them, we did not)."""
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

    # Decoding and parsing a large email takes CPU time: off the event loop.
    body, urls, headers, raw_bytes = await run_in_threadpool(_resolve_email, req)
    if not body and raw_bytes:
        # Attachment-only email: the subject stands in for the text (too
        # short for the text agent, see MIN_TEXT_WORDS).
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
    # The signed-sender discount was lifted by the link rule: said in the
    # interface, next to a "DKIM verified" badge.
    links_rule_fired = bool(
        CRYPTO_LINK_RULE
        and path is fusion.PATH_CRYPTO
        and links_elsewhere_only(links)
        and s.p_text >= CRYPTO_LINK_TEXT_MIN
    )
    _count_verdict("/analyse", verdict.is_phishing, verdict.trust_path)

    # Without headers there is no sender to check (pasted text, a client
    # that sent no headers): the sender score is then a neutral default,
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
        # trusted_sender > crypto_verified > gmail_inbox_soft / outlook_internal > default
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
        # A safe verdict on an email with links is kept an hour at most:
        # a link added to the blocklists later must reach the next scan.
        ttl = SAFE_WITH_LINKS_CACHE_TTL if urls and not verdict.is_phishing else None
        _RESULT_CACHE.set(cache_key, result, ttl=ttl)
    return result


# ---------------------------------------------------------------------
# /analyse_attachment
# ---------------------------------------------------------------------
# Inner-file features worth naming in the per-file report of an archive.
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
    """Members of an archive that explain the verdict: risky names,
    risky inner documents, phishing wording, or a link flagged by threat
    intelligence. Most reasons first; at most 20."""
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
    """Text and URL agent scores of an attachment; a failing agent counts 0."""
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
        # Parsing, OCR and decompression are CPU-bound: worker thread.
        extracted = await run_in_threadpool(
            _attachments.analyse_attachment,
            req.content_b64,
            filename=req.filename or "",
            mime_type=req.mime_type,
        )
    except ValueError as e:
        # Unsupported type, oversized, bad base64: our own messages, for the user.
        raise HTTPException(400, str(e)) from e
    except RuntimeError as e:
        # A valid request whose file does not parse (corrupt PDF...).
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
    # parent_email is a client hint we cannot verify: a false claim only
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

    # Archives, and Office files that hold other files (read as members).
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
