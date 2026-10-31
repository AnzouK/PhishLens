"""
The features the trained URL and metadata Random Forests read.

These agents were trained on exactly these names and computations
(PhishingDetector repository): changing one changes what the models
see, so this module stays as they were trained, even where the rest of
the server reads the same thing better (auth_headers.sender_domain,
link_alignment.link_host). The metadata model is off by default
(METADATA_MODEL_ENABLED, docs/architecture.md).

url_features(text)        -> dict, from the URLs written in the text
metadata_features(raw)    -> dict, from the headers of a raw email
"""

from __future__ import annotations

import logging
import re
from difflib import SequenceMatcher
from email import policy
from email.parser import BytesParser
from urllib.parse import urlparse

logger = logging.getLogger("phishlens." + __name__)

# Words the metadata model counts in the subject.
URGENT_KEYWORDS = (
    "urgent",
    "immediate",
    "action required",
    "verify",
    "suspend",
    "limited time",
    "act now",
    "confirm",
    "click here",
    "update",
    "security alert",
    "unusual activity",
    "locked",
    "expired",
    "validate",
    "authenticate",
    "prize",
    "winner",
    "congratulations",
    "claim",
    "refund",
    "suspended",
    "verify your account",
)
# Domains a brand name or a near-identical spelling is compared with.
LEGITIMATE_DOMAINS = (
    "google.com",
    "microsoft.com",
    "apple.com",
    "amazon.com",
    "facebook.com",
    "linkedin.com",
    "twitter.com",
    "instagram.com",
)
_BRAND_KEYWORDS = (
    "paypal",
    "amazon",
    "google",
    "microsoft",
    "apple",
    "facebook",
    "netflix",
    "bank",
    "secure",
)
_SHORTENERS = ("bit.ly", "tinyurl.com", "goo.gl", "t.co", "ow.ly")
_PATH_KEYWORDS = ("verify", "account", "signin", "login", "update", "confirm")
_SUSPICIOUS_TLDS = (".tk", ".ml", ".ga", ".cf", ".gq", ".xyz")
_SUSPICIOUS_PARAMS = ("user", "id", "token", "session", "redirect")
_URL_RE = re.compile(r'https?://[^\s<>"{}|\\^`\[\]]+')
_IP_RE = re.compile(r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}")
_PRIVATE_IP_RE = re.compile(r"192\.168\.|10\.|172\.(1[6-9]|2[0-9]|3[01])\.")
_ADDRESS_RE = re.compile(r"[\w\.-]+@[\w\.-]+\.\w+")

# Per-URL flags (an email has the flag when one of its URLs has it), and
# per-URL counts (the email gets the largest).
_ANY_KEYS = (
    "domain_has_ip",
    "domain_has_hyphen",
    "domain_has_at_symbol",
    "excessive_subdomains",
    "domain_has_suspicious_tld",
    "domain_length_suspicious",
    "possible_brand_spoofing",
    "path_has_suspicious_keywords",
    "url_has_encoding",
    "url_has_redirection",
    "has_query_params",
    "uses_non_standard_port",
    "is_shortened_url",
    "potential_typosquatting",
)
_MAX_KEYS = (
    "domain_length",
    "domain_dots_count",
    "path_length",
    "query_param_count",
    "suspicious_param_count",
)
URL_FEATURES = ("url_count", "has_urls", "excessive_urls", *_ANY_KEYS, *_MAX_KEYS, "uses_https")

METADATA_FEATURES = (
    "sender_domain_length",
    "sender_has_subdomain",
    "sender_has_digits",
    "sender_has_hyphen",
    "reply_to_mismatch",
    "has_reply_to",
    "return_path_mismatch",
    "spf_pass",
    "spf_fail",
    "spf_softfail",
    "spf_none",
    "dkim_pass",
    "dkim_fail",
    "dkim_none",
    "dmarc_pass",
    "dmarc_fail",
    "dmarc_none",
    "num_received_headers",
    "excessive_received_headers",
    "suspicious_ip_count",
    "subject_length",
    "subject_has_re",
    "subject_has_fwd",
    "subject_all_caps",
    "subject_excessive_punctuation",
    "subject_urgent_keywords",
    "message_id_domain_mismatch",
    "has_message_id",
    "num_x_headers",
    "has_x_mailer",
    "has_x_originating_ip",
    "has_date",
    "has_mime_version",
    "mime_version_1_0",
    "is_multipart",
    "is_html",
    "high_priority",
)


def similarity(a: str, b: str) -> float:
    """0 to 1; "paypa1.com" against "paypal.com" is 0.9."""
    if not a or not b:
        return 0.0
    return SequenceMatcher(None, a, b).ratio()


def address_domain(value: str) -> str:
    """Domain of the first address in a header value, the way the models
    were trained (a regex, not an address parser)."""
    m = _ADDRESS_RE.search(value or "")
    return m.group(0).split("@")[-1] if m else ""


def _one_url(url: str) -> dict[str, int]:
    parsed = urlparse(url)
    domain = parsed.netloc.lower()
    query = parsed.query
    try:
        port = parsed.port
    except ValueError:  # "http://host:TheCloud/path"
        port = None
    known = any(domain == d or domain.endswith("." + d) for d in LEGITIMATE_DOMAINS)
    return {
        "domain_length": len(domain),
        "domain_has_ip": int(bool(_IP_RE.fullmatch(domain))),
        "domain_has_hyphen": int("-" in domain),
        "domain_has_at_symbol": int("@" in url),
        "domain_dots_count": domain.count("."),
        "excessive_subdomains": int(domain.count(".") > 3),
        "domain_has_suspicious_tld": int(domain.endswith(_SUSPICIOUS_TLDS)),
        "domain_length_suspicious": int(len(domain) > 30),
        "possible_brand_spoofing": int(any(b in domain for b in _BRAND_KEYWORDS) and not known),
        "path_length": len(parsed.path),
        "path_has_suspicious_keywords": int(any(k in parsed.path.lower() for k in _PATH_KEYWORDS)),
        "url_has_encoding": int("%" in url),
        "url_has_redirection": int("//" in url.split("://")[1]),
        "has_query_params": int(bool(query)),
        "query_param_count": len(query.split("&")) if query else 0,
        "suspicious_param_count": sum(1 for p in _SUSPICIOUS_PARAMS if p in query.lower()),
        "uses_non_standard_port": int(port is not None and port not in (80, 443)),
        "is_shortened_url": int(any(s in domain for s in _SHORTENERS)),
        "uses_https": int(parsed.scheme == "https"),
        "potential_typosquatting": int(
            any(similarity(domain, d) > 0.8 and domain != d for d in LEGITIMATE_DOMAINS)
        ),
    }


def url_features(text: str) -> dict[str, int]:
    """Features of every URL written in the text, combined into the most
    suspicious values (one bad link among good ones counts), all 0 when
    there is none or the text cannot be read."""
    try:
        urls = _URL_RE.findall(text)
        features = dict.fromkeys(URL_FEATURES, 0)
        features.update(
            url_count=len(urls), has_urls=int(bool(urls)), excessive_urls=int(len(urls) > 5)
        )
        if urls:
            each = [_one_url(u) for u in urls]
            for key in _ANY_KEYS:
                features[key] = int(any(u[key] for u in each))
            for key in _MAX_KEYS:
                features[key] = max(u[key] for u in each)
            # HTTPS counts only when every link uses it.
            features["uses_https"] = int(all(u["uses_https"] for u in each))
        return features
    except Exception as e:
        logger.warning("URL features not computed: %s", type(e).__name__)
        return dict.fromkeys(URL_FEATURES, 0)


def metadata_features(raw: bytes | str) -> dict[str, int]:
    """Features of the headers of a raw email; all 0 when it cannot be
    parsed. spf_* read Received-SPF and dkim_* / dmarc_* the
    Authentication-Results header, as in training."""
    try:
        msg = BytesParser(policy=policy.default).parsebytes(
            raw.encode() if isinstance(raw, str) else raw
        )
        sender = address_domain(msg.get("From", ""))
        reply_to = msg.get("Reply-To", "")
        return_path = msg.get("Return-Path", "")
        spf = msg.get("Received-SPF", "").lower()
        auth = msg.get("Authentication-Results", "").lower()
        received = msg.get_all("Received", [])
        subject = msg.get("Subject", "")
        message_id = msg.get("Message-ID", "")
        mime_version = msg.get("MIME-Version", "")
        content_type = msg.get("Content-Type", "").lower()
        priority = msg.get("X-Priority", "").lower()
        importance = msg.get("Importance", "").lower()
        softfail = "softfail" in spf
        fail = "fail" in spf and not softfail
        return {
            "sender_domain_length": len(sender),
            "sender_has_subdomain": int(sender.count(".") > 1),
            "sender_has_digits": int(bool(re.search(r"\d", sender))),
            "sender_has_hyphen": int("-" in sender),
            "reply_to_mismatch": int(address_domain(reply_to) != sender and reply_to != ""),
            "has_reply_to": int(bool(reply_to)),
            "return_path_mismatch": int(
                address_domain(return_path) != sender and return_path != ""
            ),
            "spf_pass": int("pass" in spf and not softfail and not fail),
            "spf_fail": int(fail),
            "spf_softfail": int(softfail),
            "spf_none": int(not spf or "none" in spf),
            "dkim_pass": int("dkim=pass" in auth),
            "dkim_fail": int("dkim=fail" in auth),
            "dkim_none": int("dkim=none" in auth or "dkim" not in auth),
            "dmarc_pass": int("dmarc=pass" in auth),
            "dmarc_fail": int("dmarc=fail" in auth),
            "dmarc_none": int("dmarc=none" in auth or "dmarc" not in auth),
            "num_received_headers": len(received),
            "excessive_received_headers": int(len(received) > 10),
            "suspicious_ip_count": sum(1 for h in received if _PRIVATE_IP_RE.search(h)),
            "subject_length": len(subject),
            "subject_has_re": int(subject.lower().startswith("re:")),
            "subject_has_fwd": int(subject.lower().startswith("fwd:")),
            "subject_all_caps": int(subject.isupper() and len(subject) > 5),
            "subject_excessive_punctuation": int(sum(c in "!?" for c in subject) > 3),
            "subject_urgent_keywords": sum(k in subject.lower() for k in URGENT_KEYWORDS),
            "message_id_domain_mismatch": int(
                address_domain(message_id) != sender and message_id != ""
            ),
            "has_message_id": int(bool(message_id)),
            "num_x_headers": sum(1 for k in msg.keys() if k.startswith("X-")),  # noqa: SIM118
            "has_x_mailer": int("X-Mailer" in msg),
            "has_x_originating_ip": int("X-Originating-IP" in msg),
            "has_date": int(bool(msg.get("Date", ""))),
            "has_mime_version": int(bool(mime_version)),
            "mime_version_1_0": int(mime_version == "1.0"),
            "is_multipart": int("multipart" in content_type),
            "is_html": int("text/html" in content_type),
            "high_priority": int("high" in priority or "high" in importance or "1" in priority),
        }
    except Exception as e:
        logger.warning("metadata features not computed: %s", type(e).__name__)
        return dict.fromkeys(METADATA_FEATURES, 0)


class FeatureExtractor:
    """The interface the agents are loaded with (structured_agents)."""

    extract_url_features = staticmethod(url_features)
    extract_metadata_features = staticmethod(metadata_features)
