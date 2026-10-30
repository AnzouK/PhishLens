"""
The URL and metadata agents.

Each agent has a trained Random Forest (from AnzouKiona/phishlens-agents,
or local files) and a rule-based fallback that is always available. The
trained models were trained on older mail: the callers below only use
them where they are reliable (see url_agent and the headers_source rule
in the API).
"""

from __future__ import annotations

import logging
import os
import re
from pathlib import Path
from urllib.parse import urlsplit

from email_parsing import urls_in_text
from known_domains import SUSPICIOUS_TLDS
from link_alignment import authority_of, browser_url, ip_host, on_cloud_file_host, well_known_link
from link_alignment import link_host as _host
from sender_trust import impersonated_brand, sender_domain
from settings import AGENTS_ALLOW_PICKLE, HF_AGENTS_REPO, HF_AGENTS_REVISION

try:
    from auth_headers import org_domain
except Exception:  # auth_headers missing: the host itself

    def org_domain(d: str) -> str:
        return (d or "").lower().strip(".")


logger = logging.getLogger("phishlens.structured_agents")


_URL_AGENT = None
_METADATA_AGENT = None
_FEATURE_EXTRACT = None


def _hf_fetch(filename: str) -> Path | None:
    try:
        from huggingface_hub import hf_hub_download

        return Path(
            hf_hub_download(
                repo_id=HF_AGENTS_REPO,
                revision=HF_AGENTS_REVISION,
                filename=filename,
                repo_type="model",
                local_dir="./agents",
            )
        )
    except Exception as e:
        logger.info("%s not fetched from %s: %s", filename, HF_AGENTS_REPO, e)
        return None


def _resolve_agent_file(stem: str, env_var: str) -> Path | None:
    """Local override first, then <stem>.skops, then <stem>.joblib."""
    local = os.environ.get(env_var)
    if local and Path(local).exists():
        return Path(local)
    path = _hf_fetch(f"{stem}.skops")
    if path:
        return path
    if AGENTS_ALLOW_PICKLE:
        path = _hf_fetch(f"{stem}.joblib")
        if path:
            logger.warning(
                "Loading %s with pickle (AGENTS_ALLOW_PICKLE=1): convert it to "
                "%s.skops with convert_agents_to_skops.py.",
                path.name,
                stem,
            )
        return path
    return None


def _load_agent(agent, path: Path):
    if path.suffix == ".skops":
        import agent_io

        return agent_io.apply_state(agent, agent_io.load_skops_state(path))
    if not AGENTS_ALLOW_PICKLE:
        raise RuntimeError(f"{path.name} is a pickle file; set AGENTS_ALLOW_PICKLE=1 to load it")
    agent.load_model(str(path))
    return agent


def _init_agent(stem: str, env_var: str, factory):
    """Load one trained agent; any failure leaves the heuristic in place."""
    try:
        path = _resolve_agent_file(stem, env_var)
        if not path:
            return None
        agent = _load_agent(factory(), path)
        logger.info("Loaded trained %s from %s", stem, path)
        return agent
    except Exception as e:
        logger.warning("Could not load %s, using the rules instead: %s", stem, e)
        return None


def url_heuristic(urls: list[str]) -> float:
    """Rule-based URL score (worst URL): plain http, raw IP host, "@" in
    the URL, very long URL, suspicious TLD, credential keywords, a file
    or page on a public cloud host."""
    bad = 0.0
    for u in urls:
        score = 0.0
        host = _host(u)
        if u.lower().startswith("http://"):
            score += 0.25
        if ip_host(host):
            score += 0.40
        if _has_userinfo(u):
            score += 0.35
        if len(u) > 75:
            score += 0.15
        if host.rsplit(".", 1)[-1] in SUSPICIOUS_TLDS:
            score += 0.30
        if _lookalike_host(host):
            score += 0.30
        if re.search(r"(login|verify|account|update|secure)", u, re.I):
            score += 0.10
        if on_cloud_file_host(u):
            score += 0.45
        if well_known_link(u):
            score = min(score, 0.10)
        bad = max(bad, min(score, 1.0))
    return bad


def _has_userinfo(url: str) -> bool:
    """A "name@" part before the host (https://paypal.com@evil.example)."""
    url = browser_url(url)
    try:
        return "@" in urlsplit(url if "://" in url else "http://" + url).netloc
    except ValueError:
        return "@" in authority_of(url)


def _lookalike_host(host: str) -> bool:
    """A host written with non-Latin letters, directly or in its
    punycode form (xn--...): the usual way to imitate a brand's domain
    with look-alike letters."""
    return bool(host) and (not host.isascii() or any(p.startswith("xn--") for p in host.split(".")))


def strong_link_sign(urls: list[str]) -> bool:
    """A link sign that legitimate mail rarely shows: a raw IP host, "@"
    before the host, a suspicious TLD, a look-alike (punycode) host, a
    file on a public cloud host. Plain http, length and keywords are left
    out: build servers, archives and personal sites written out in
    mailing-list mail have them."""
    for u in urls:
        if well_known_link(u):
            continue
        host = _host(u)
        if ip_host(host) or _has_userinfo(u) or _lookalike_host(host):
            return True
        if host.rsplit(".", 1)[-1] in SUSPICIOUS_TLDS or on_cloud_file_host(u):
            return True
    return False


def url_agent(urls: list[str], body_text: str = "") -> float:
    """URL score.

    The trained Random Forest extracts its features from the text, and
    was trained on emails whose links were written out in the text: it
    only judges the URLs that appear in `body_text`. URLs that are not in
    the text (Gmail link targets, HTML hrefs, QR codes) get the rule-based
    score instead: on real 2026 mail the RF scores almost any URL with a
    path at ~0.95 (github.com/user/repo, wikipedia.org/wiki/...), so
    feeding it hidden link targets flagged nearly every HTML email. Those
    hidden URLs are still checked against threat intelligence by the
    caller, which is where most of their value lies.
    """
    # No links, no URL risk. Checked before the trained path on purpose:
    # on an all-zero feature vector the RF outputs a high probability.
    if not urls:
        return 0.05
    # Written in the text: compared as read (urls_in_text normalises
    # "HTTPS://", "www.", a final dot), not character for character.
    written = set(urls_in_text(body_text))
    visible = [u for u in urls if u in written or u in body_text]
    hidden = [u for u in urls if u not in visible]

    score = 0.05
    if visible:
        score = url_heuristic(visible)
        # Links that only go to large known sites keep the rule score: the
        # trained model reads their long tracking links as phishing.
        if (
            _URL_AGENT is not None
            and _FEATURE_EXTRACT is not None
            and not all(well_known_link(u) for u in visible)
        ):
            try:
                # The links as read (lower-case scheme, "www." made a URL):
                # the model's own pattern misses "HTTPS://" and "www.",
                # and a harmless link was all it saw next to them.
                feats = _FEATURE_EXTRACT.extract_url_features(" ".join(visible))
                pred = _URL_AGENT.get_prediction_with_confidence(feats)
                score = float(pred["phishing_probability"])
            except Exception as e:
                logger.warning("url_agent trained path failed (%s); rules used", e)
    if hidden:
        score = max(score, url_heuristic(hidden))
    return score


def metadata_agent(headers: dict[str, str], raw_email: bytes | None = None) -> float:
    """Metadata score: trained RF on the raw email when available,
    heuristic on the parsed header dict otherwise."""
    if _METADATA_AGENT is not None and _FEATURE_EXTRACT is not None and raw_email:
        try:
            feats = _FEATURE_EXTRACT.extract_metadata_features(raw_email)
            pred = _METADATA_AGENT.get_prediction_with_confidence(feats)
            return float(pred["phishing_probability"])
        except Exception as e:
            logger.warning("metadata_agent trained path failed (%s); rules used", e)
    score = 0.0
    sender = sender_domain(headers.get("from", "")) or ""
    reply_to = sender_domain(headers.get("reply-to", "")) or ""
    if reply_to and reply_to != sender:
        score += 0.45
    # No DKIM / SPF / Authentication-Results
    auth = headers.get("authentication-results", "")
    if "dkim=fail" in auth or "spf=fail" in auth:
        score += 0.40
    if "authentication-results" not in headers:
        score += 0.15
    # A brand's name over another domain's address (extension_backend
    # also raises the sender score to IMPERSONATION_META for it).
    if impersonated_brand(headers.get("from", "")):
        score += 0.35
    return min(score, 1.0)


def load() -> None:
    """Load the feature extractor and whichever trained agents are
    available; anything missing leaves the rule-based fallback in place."""
    global _URL_AGENT, _METADATA_AGENT, _FEATURE_EXTRACT
    try:
        from feature_extraction import FeatureExtractor
        from metadata_agent import MetadataAgent
        from url_agent import URLAgent

        _FEATURE_EXTRACT = FeatureExtractor()
        _URL_AGENT = _init_agent("url_agent", "URL_AGENT_PATH", URLAgent)
        _METADATA_AGENT = _init_agent("metadata_agent", "METADATA_AGENT_PATH", MetadataAgent)
        if not _URL_AGENT and not _METADATA_AGENT:
            logger.info("No trained agents loaded: rule-based fallbacks only.")
    except Exception as e:
        logger.warning("Feature extractor init failed, rules only: %s", e)


def url_model_ready() -> bool:
    return _URL_AGENT is not None and _FEATURE_EXTRACT is not None


def metadata_model_ready() -> bool:
    return _METADATA_AGENT is not None and _FEATURE_EXTRACT is not None
