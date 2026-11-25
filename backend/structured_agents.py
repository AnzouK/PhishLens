"""
PhishLens: the URL and metadata agents.

Each agent has a trained Random Forest (from AnzouKiona/phishlens-agents
or local files) and a rule-based fallback that always works. The forests
learned from older mail, so we only use them where they hold up (see
url_agent and the headers_source rule in the API).
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
    """Find the agent file, trying the local override, then .skops, then .joblib."""
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
    """Load one trained agent. If anything fails the heuristic stays in place."""
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
    """Score the worst URL with simple rules.

    The rules look at plain http, a raw IP host, "@" in the URL, length,
    suspicious TLDs, credential keywords and files on public cloud hosts.
    """
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
    """Return True for a "name@" part before the host, as in https://paypal.com@evil.example."""
    url = browser_url(url)
    try:
        return "@" in urlsplit(url if "://" in url else "http://" + url).netloc
    except ValueError:
        return "@" in authority_of(url)


def _lookalike_host(host: str) -> bool:
    """Return True for a host with non-Latin letters or punycode (xn--).

    That is the usual way to fake a brand domain with look-alike letters.
    """
    return bool(host) and (not host.isascii() or any(p.startswith("xn--") for p in host.split(".")))


def strong_link_sign(urls: list[str]) -> bool:
    """Return True for a link sign that real mail rarely shows.

    That means a raw IP host, "@" before the host, a suspicious TLD, a
    punycode host or a file on a public cloud host. Plain http, length and
    keywords don't count, because build servers, archives and personal
    sites in mailing-list mail have them too.
    """
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
    """Return the URL score.

    The forest was trained on emails with links written out in the text,
    and it extracts features from the text. So it only judges URLs that
    appear in `body_text`. Other URLs (Gmail link targets, HTML hrefs, QR
    codes) get the rule score. On real 2026 mail the forest scores almost
    any URL with a path around 0.95 (github.com/user/repo,
    wikipedia.org/wiki/...), and feeding it hidden targets flagged nearly
    every HTML email. The caller still checks those URLs against threat
    intelligence, which is where most of their value is.
    """
    # Return early with no links. On an all-zero feature vector the forest
    # outputs a high probability.
    if not urls:
        return 0.05
    # Compare URLs as urls_in_text normalises them ("HTTPS://", "www.", a
    # trailing dot), not character for character.
    written = set(urls_in_text(body_text))
    visible = [u for u in urls if u in written or u in body_text]
    hidden = [u for u in urls if u not in visible]

    score = 0.05
    if visible:
        score = url_heuristic(visible)
        # Links to large known sites keep the rule score. The forest reads
        # their long tracking links as phishing.
        if (
            _URL_AGENT is not None
            and _FEATURE_EXTRACT is not None
            and not all(well_known_link(u) for u in visible)
        ):
            try:
                # Pass the normalised links. The model's own pattern misses
                # "HTTPS://" and "www." and would only see the harmless
                # links next to them.
                feats = _FEATURE_EXTRACT.extract_url_features(" ".join(visible))
                pred = _URL_AGENT.get_prediction_with_confidence(feats)
                # The model can raise the rule score but never lower it. It
                # predates common cloud-hosted pages, IDN hosts and numeric
                # IPs, and reads them as harmless.
                score = max(score, float(pred["phishing_probability"]))
            except Exception as e:
                logger.warning("url_agent trained path failed (%s); rules used", e)
    if hidden:
        score = max(score, url_heuristic(hidden))
    return score


def metadata_agent(headers: dict[str, str], raw_email: bytes | None = None) -> float:
    """Return the metadata score from the forest on the raw email, or from header rules."""
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
    # Brand name over someone else's address. extension_backend also raises
    # the sender score to IMPERSONATION_META for this.
    if impersonated_brand(headers.get("from", "")):
        score += 0.35
    return min(score, 1.0)


def load() -> None:
    """Load the feature extractor and any trained agents that are available.

    Whatever is missing falls back to the rules.
    """
    global _URL_AGENT, _METADATA_AGENT, _FEATURE_EXTRACT
    try:
        from feature_extraction import FeatureExtractor
        from rf_agent import RandomForestAgent

        _FEATURE_EXTRACT = FeatureExtractor()
        _URL_AGENT = _init_agent("url_agent", "URL_AGENT_PATH", RandomForestAgent)
        _METADATA_AGENT = _init_agent("metadata_agent", "METADATA_AGENT_PATH", RandomForestAgent)
        if not _URL_AGENT and not _METADATA_AGENT:
            logger.info("No trained agents loaded: rule-based fallbacks only.")
    except Exception as e:
        logger.warning("Feature extractor init failed, rules only: %s", e)


def url_model_ready() -> bool:
    return _URL_AGENT is not None and _FEATURE_EXTRACT is not None


def metadata_model_ready() -> bool:
    return _METADATA_AGENT is not None and _FEATURE_EXTRACT is not None
