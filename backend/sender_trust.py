"""
Who sent the email, and can we believe it.

- sender_domain(): the domain of a From: value.
- is_trusted_domain(): allowlist match (trusted_domains.py). The caller
  applies it only to an authenticated sender.
- impersonated_brand(): a From: whose name is a known brand while the
  address belongs to another domain.
- synthesize_auth_results(): an Authentication-Results header built from
  the "signed-by" / "mailed-by" values Gmail shows, so auth_headers can
  check alignment the same way as for real headers.
"""

from __future__ import annotations

import re
import unicodedata
from email.utils import getaddresses, parseaddr
from typing import Any

from auth_headers import SHARED_SUFFIXES, org_domain, sender_domain
from known_domains import BRANDS, SUSPICIOUS_TLDS
from trusted_domains import TRUSTED_DOMAINS

_ANGLE_ADDR_RE = re.compile(r"<\s*([^<>\s@]{1,200}@[^<>\s@]{1,253})\s*>")
_HOST_CHARS = set("abcdefghijklmnopqrstuvwxyz0123456789-")


def is_trusted_domain(domain: str | None) -> bool:
    """The domain or one of its parents is allowlisted."""
    if not domain:
        return False
    d = domain.lower()
    return d in TRUSTED_DOMAINS or any(d.endswith("." + td) for td in TRUSTED_DOMAINS)


# Latin look-alikes from other scripts ("PаyPal" with a Cyrillic "а"),
# which Unicode normalisation leaves as they are.
_CONFUSABLES = str.maketrans(
    "аеорсухіјѕԁһӏАВЕКМНОРСТХІЈЅαεικνορτυχΑΒΕΗΙΚΜΝΟΡΤΥΧΖ",
    "aeopcyxijsdhlABEKMHOPCTXIJSaeikvoptuxABEHIKMNOPTYXZ",
)


def _plain_words(text: str, lower: bool = True) -> str:
    """Accents and look-alike letters folded (NFKC turns the mathematical
    bold letters some phishing uses into plain ones, _CONFUSABLES the
    Cyrillic and Greek ones), invisible characters removed ("Chrono" +
    zero-width space + "post" is "Chronopost" on screen), every other
    character a space; padded so that whole words match. Dots are kept
    ("booking.com") and the same words are added with dots as spaces
    ("impots.gouv" also gives "impots gouv")."""
    text = "".join(c for c in text if unicodedata.category(c) != "Cf")
    folded = unicodedata.normalize("NFKD", unicodedata.normalize("NFKC", text))
    folded = "".join(c for c in folded if not unicodedata.combining(c)).translate(_CONFUSABLES)
    if lower:
        folded = folded.lower()
    kept = " ".join("".join(c if c.isalnum() or c == "." else " " for c in folded).split())
    return f" {kept} {kept.replace('.', ' ')} "


# Top-level domains a brand's own address may use with one of its names:
# generic ones and country codes, except the ones sold for any use or
# almost free ("paypal.tk", "paypal.co"). A brand's own top-level domain
# ("e.leclerc") is listed in full in known_domains.BRANDS.
_BRAND_TLDS = frozenset({"com", "net", "org", "edu", "gov", "int", "eu", "info", "group"})
_OPEN_CCTLDS = frozenset(
    {"co", "io", "me", "ly", "to", "cc", "ws", "su", "gg", "ai", "tv", "so", "sh", "la", "pw"}
)


def _brand_owns(brand_domains: frozenset[str], domain: str) -> bool:
    """The organisational domain of `domain` is one of the brand's: listed
    in full, or one of its names under a generic or country-code TLD.
    Never a customer subdomain of a shared host (paypal.duckdns.org)."""
    org = org_domain(domain)
    if not org:
        return False
    if org in brand_domains:
        return True
    label, _, rest = org.partition(".")
    tld = org.rsplit(".", 1)[-1]
    if rest in SHARED_SUFFIXES or label not in brand_domains:
        return False
    if tld in SUSPICIOUS_TLDS or tld in _OPEN_CCTLDS:
        return False
    return tld in _BRAND_TLDS or (len(tld) == 2 and tld.isascii() and tld.isalpha())


def _display_names(header: str) -> str:
    """Every display name of a From: value. A header with several
    addresses ('"Info" <x@evil.example>, "PayPal" <x@evil.example>') has
    several names; a malformed one ('"PayPal\\" <x@evil.example>') parses
    with none, while mail programs still show its text: then the text
    before the last <address> is the name."""
    names = [name for name, _addr in getaddresses([header]) if name]
    _name, addr = parseaddr(header)
    if not names or " " in addr or "<" in addr:
        angles = list(_ANGLE_ADDR_RE.finditer(header))
        if angles:
            names.append(header[: angles[-1].start()])
    return " ".join(names)


def impersonated_brand(from_header: str) -> str | None:
    """The brand a From: claims when its address is not the brand's.

    "Chronopost <info@qdsoddsmn.us>" -> "chronopost". The names are
    checked as whole words against known_domains.BRANDS (brands of three
    letters or fewer only in capitals, "UPS" but not "ups"); the address
    passes when its organisational domain is the brand's (_brand_owns).
    """
    header = (from_header or "")[:2000]
    name = _display_names(header)
    if not name.strip(' <>"\\'):
        return None
    # The same domain every other check reads (sender_domain).
    domain = sender_domain(header) or ""
    words = _plain_words(name)
    upper = _plain_words(name, lower=False)
    for brand, domains in BRANDS.items():
        found = f" {brand.upper()} " in upper if len(brand) <= 3 else f" {brand} " in words
        if found and not _brand_owns(domains, domain):
            return brand
    return None


def is_hostname(name: str) -> bool:
    """A DNS hostname with at least two labels, checked without a regex
    (linear on any input)."""
    labels = name.split(".")
    return (
        0 < len(name) <= 253
        and len(labels) >= 2
        and all(0 < len(lab) <= 63 and set(lab) <= _HOST_CHARS for lab in labels)
    )


def synthesize_auth_results(ctx: Any, sender_email: str | None) -> str:
    """Authentication-Results header from Gmail's UI signals.

    Gmail shows "mailed-by" (the SPF-authenticated domain) and "signed-by"
    (the DKIM signing domain). DMARC pass is only written when the signing
    domain aligns with From: at the organisational level, so a message
    signed by attacker.co.uk claiming to be from paypal.co.uk does not
    align. Returns "" when there is nothing to build from.
    """
    if not isinstance(ctx, dict) or ctx.get("origin") != "gmail":
        return ""

    def host(key: str) -> str:
        # Written into a header below: anything but a host name is dropped.
        value = ctx.get(key)
        value = value.strip().lower().rstrip(".") if isinstance(value, str) else ""
        return value if is_hostname(value) else ""

    signed_by, mailed_by, via = host("gmail_signed_by"), host("gmail_mailed_by"), host("gmail_via")
    if not (signed_by or mailed_by or via):
        return ""

    from_domain = sender_domain(sender_email or "") or ""

    parts = ["gmail-client-context"]
    if signed_by:
        parts.append(f"dkim=pass header.i=@{signed_by}")
    if mailed_by or via:
        parts.append(f"spf=pass smtp.mailfrom={mailed_by or via}")
    if signed_by and from_domain and org_domain(signed_by) == org_domain(from_domain):
        parts.append(f"dmarc=pass header.from={from_domain}")
    return "; ".join(parts)
