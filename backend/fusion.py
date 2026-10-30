"""
From agent scores to a verdict.

Pure functions, no I/O: everything that decides "phishing or safe" for an
email or an attachment lives here and is unit-tested directly
(tests/test_fusion.py). The constants come from settings.py; the trust
paths are described in docs/architecture.md.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from settings import (
    ATTACHMENT_FEATURE_BONUS_MAX,
    ATTACHMENT_THRESHOLD,
    ATTACHMENT_TRUSTED_TEXT_FACTOR,
    ATTACHMENT_TRUSTED_THRESHOLD,
    CRYPTO_LINK_TEXT_MIN,
    GSB_URL_FLOOR,
    HIGH_CONF_OVERRIDE,
    PATH_CRYPTO,
    PATH_DEFAULT,
    PATH_INBOX_SOFT,
    PATH_OUTLOOK_INTERNAL,
    PATH_TRUSTED,
    REP_BLEND,
    URL_OVERRIDE_RULE_MIN,
    W_META,
    W_TEXT,
    W_URL,
    TrustPath,
)

GSB = "google_safe_browsing"
# The signs a trust path may list in TrustPath.forcing (see decide_email).
FORCING_SIGNS = (
    "confident_text",
    "confident_sender",
    "confirmed_link",
    "safe_browsing",
    "links_elsewhere",
)


# ---------------------------------------------------------------------
# Threat intelligence
# ---------------------------------------------------------------------
@dataclass
class Reputation:
    """What the URL reputation cascade said about the links."""

    verdicts: list[dict[str, Any]] = field(default_factory=list)
    max_score: float = 0.0
    sources: set[str] = field(default_factory=set)
    threat_types: set[str] = field(default_factory=set)

    @property
    def gsb_hit(self) -> bool:
        return GSB in self.sources

    @property
    def any_hit(self) -> bool:
        return self.max_score > 0

    def as_dict(self) -> dict[str, Any]:
        return {
            "checked": len(self.verdicts),
            "malicious_count": sum(1 for v in self.verdicts if v.get("malicious")),
            "sources_hit": sorted(self.sources),
            "threat_types": sorted(self.threat_types),
            "verdicts": self.verdicts,
        }


def summarize_reputation(verdicts: list[dict[str, Any]]) -> Reputation:
    rep = Reputation(verdicts=verdicts)
    for v in verdicts:
        if v.get("malicious"):
            rep.max_score = max(rep.max_score, float(v.get("score", 0.0)))
            rep.sources.update(v.get("sources", []))
            rep.threat_types.update(v.get("threat_types", []))
    return rep


def apply_reputation(p_url: float, rep: Reputation) -> float:
    """URL score after threat intelligence: a Safe Browsing match lifts it
    to at least GSB_URL_FLOOR, another source blends in."""
    if rep.max_score >= 0.99:
        return max(p_url, GSB_URL_FLOOR)
    if rep.max_score > 0:
        return max(p_url, REP_BLEND * rep.max_score + (1 - REP_BLEND) * p_url)
    return p_url


# ---------------------------------------------------------------------
# Emails
# ---------------------------------------------------------------------
@dataclass(frozen=True)
class Verdict:
    is_phishing: bool
    fused: float
    threshold: float
    high_conf: bool
    trust_path: str
    forced_by: tuple[str, ...] = ()


def choose_trust_path(
    *, trusted_sender: bool, crypto_verified: bool, inbox_soft: bool, outlook_internal: bool
) -> TrustPath:
    """trusted_sender > crypto_verified > Gmail inbox / Outlook internal > default."""
    if trusted_sender:
        return PATH_TRUSTED
    if crypto_verified:
        return PATH_CRYPTO
    if inbox_soft:
        return PATH_OUTLOOK_INTERNAL if outlook_internal else PATH_INBOX_SOFT
    return PATH_DEFAULT


def fuse(
    p_text: float, p_url: float, p_meta: float, *, text_used: bool, text_factor: float = 1.0
) -> float:
    """Weighted sum of the agents. Without usable text, the URL and
    metadata agents share the whole weight."""
    if text_used:
        return W_TEXT * text_factor * p_text + W_URL * p_url + W_META * p_meta
    return (W_URL * p_url + W_META * p_meta) / (W_URL + W_META)


def url_confirmed(rep: Reputation, url_rule_score: float) -> bool:
    """For an attachment, the URL agent alone may force the verdict only
    with a concrete sign:
    a threat-intel hit or a rule (raw IP, plain http, "@", suspicious TLD).
    The trained URL model alone scores most real URLs with a path high."""
    return rep.any_hit or url_rule_score >= URL_OVERRIDE_RULE_MIN


def decide_email(
    p_text: float,
    p_url: float,
    p_meta: float,
    *,
    text_used: bool,
    path: TrustPath,
    rep: Reputation,
    strong_link: bool = False,
    text_override: float = HIGH_CONF_OVERRIDE,
    links_elsewhere: bool = False,
) -> Verdict:
    """Verdict for an email: phishing when the fused score reaches the
    trust path's threshold, or when one of the path's forcing signs holds
    (settings.TrustPath.forcing). On the softer paths only a Safe Browsing
    hit forces phishing (and on crypto_verified, links that all lead
    elsewhere with phishing-like wording); on the default path a confident
    text or sender score does, and the link score only with a
    threat-intelligence hit or a strong link sign (structured_agents.strong_link_sign): the trained
    URL model scores the written-out links of legitimate mailing-list
    mail near 1.0, and plain http was enough to confirm it (14 of 14
    false alarms of the public benchmark). text_override is the text model's own
    threshold (lower for a calibrated model, see
    text_model.override_threshold)."""
    fused = fuse(p_text, p_url, p_meta, text_used=text_used, text_factor=path.text_factor)
    signs = {
        "confident_text": text_used and p_text >= text_override,
        "confident_sender": p_meta >= HIGH_CONF_OVERRIDE,
        "confirmed_link": p_url >= HIGH_CONF_OVERRIDE and (rep.any_hit or strong_link),
        "safe_browsing": rep.gsb_hit,
        # links_elsewhere is set only when CRYPTO_LINK_RULE is on.
        "links_elsewhere": links_elsewhere and p_text >= CRYPTO_LINK_TEXT_MIN,
    }
    forced_by = tuple(sign for sign in path.forcing if signs[sign])
    high_conf = bool(forced_by)
    return Verdict(
        is_phishing=fused >= path.threshold or high_conf,
        fused=fused,
        threshold=path.threshold,
        high_conf=high_conf,
        trust_path=path.name,
        forced_by=forced_by,
    )


# ---------------------------------------------------------------------
# Attachments
# ---------------------------------------------------------------------
# Risk added by each feature found in an attachment. These features are
# often the whole signal (little or no text), so the bonus can reach
# ATTACHMENT_FEATURE_BONUS_MAX.
FEATURE_RISK: dict[str, float] = {
    # PDF
    "contains_javascript": 0.20,
    "auto_execute_on_open": 0.30,
    "launch_external_action": 0.35,
    "embeds_another_file": 0.20,
    "submits_form_to_url": 0.25,
    "contains_link_annotation": 0.00,  # too common in legitimate PDFs
    "remote_link_action": 0.10,
    "flash_or_richmedia": 0.15,
    # HTML
    "contains_form": 0.15,
    "contains_password_field": 0.40,  # a login page as an attachment
    "contains_iframe": 0.10,
    "meta_refresh_redirect": 0.20,
    # Images and scanned PDFs
    "image_only_pdf": 0.10,  # no text layer: evasion, or a real scan
    "contains_qr_code": 0.20,  # quishing: the link hides from text scanners
    "text_from_ocr": 0.00,  # informational
    # Office documents
    "contains_macros": 0.45,
    "remote_template": 0.45,  # template injection
    "dde_field": 0.40,
    "contains_activex": 0.25,
    "embedded_ole_object": 0.20,
    "external_data_connection": 0.20,
    "encrypted_document": 0.30,  # the password in the email blinds scanners
    "legacy_office_format": 0.10,
    "suspicious_xml_doctype": 0.20,
    "document_not_fully_read": 0.10,  # built to be slow to read
    # Archives, calendar invites, risky file types
    "encrypted_archive": 0.35,  # scanners cannot open it
    "uninspectable_archive": 0.20,  # RAR / 7z the server cannot open
    "inner_files_not_extracted": 0.10,
    "nested_archive": 0.10,
    "zip_bomb_suspected": 0.30,
    "disk_image_in_archive": 0.40,
    "disk_image_attachment": 0.40,
    "oversized_inner_file": 0.00,
    "calendar_invite": 0.00,
    "calendar_with_links": 0.10,
}

# Dropper techniques force the phishing verdict on every path, like a
# Safe Browsing hit: an authenticated parent email says nothing about what
# a macro or an executable does, and compromised accounts are how they
# travel.
DROPPER_FEATURES = frozenset(
    {
        "contains_macros",
        "remote_template",
        "dde_field",
        "dangerous_file_type",
        "executable_in_archive",
        "script_in_archive",
        "shortcut_in_archive",
        "double_extension",
    }
)


def attachment_feature_bonus(notable: list[str]) -> float:
    bonus = sum(FEATURE_RISK.get(f, 0.0) for f in notable)
    if "contains_form" in notable and "contains_password_field" in notable:
        bonus += 0.10  # a full login page
    return min(bonus, ATTACHMENT_FEATURE_BONUS_MAX)


def dropper_techniques(notable: list[str]) -> list[str]:
    return sorted(set(notable) & DROPPER_FEATURES)


def decide_attachment(
    p_text: float,
    p_url: float,
    *,
    feature_bonus: float,
    parent_trusted: bool,
    rep: Reputation,
    dropper: list[str],
    url_rule_score: float,
    text_override: float = HIGH_CONF_OVERRIDE,
) -> Verdict:
    """Verdict for an attachment. An authenticated parent email softens
    the text agent (legitimate documents share phishing vocabulary),
    unless threat intelligence or a dropper technique says otherwise."""
    if parent_trusted and not rep.gsb_hit and not dropper:
        fused = ATTACHMENT_TRUSTED_TEXT_FACTOR * 0.5 * p_text + 0.5 * p_url + feature_bonus
        threshold = ATTACHMENT_TRUSTED_THRESHOLD
        high_conf = False
        path = "parent_trusted"
    else:
        fused = 0.5 * p_text + 0.5 * p_url + feature_bonus
        threshold = ATTACHMENT_THRESHOLD
        high_conf = (
            rep.gsb_hit
            or bool(dropper)
            or p_text >= text_override
            or (p_url >= HIGH_CONF_OVERRIDE and url_confirmed(rep, url_rule_score))
        )
        path = "default"
    fused = min(1.0, fused)
    return Verdict(
        is_phishing=fused >= threshold or high_conf,
        fused=fused,
        threshold=threshold,
        high_conf=high_conf,
        trust_path=path,
    )
