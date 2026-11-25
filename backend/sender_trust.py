"""
PhishLens: who sent the email, and whether we can believe it.

The allowlist in trusted_domains.py only means something for an
authenticated sender, and the caller makes that check. impersonated_brand
catches a From: whose display name is a known brand while the address
belongs to someone else. When we only have Gmail's "signed-by" and
"mailed-by" values, synthesize_auth_results turns them into an
Authentication-Results header so auth_headers can check alignment as usual.
"""

from __future__ import annotations

import re
import unicodedata
from email.utils import getaddresses
from typing import Any

from auth_headers import SHARED_SUFFIXES, org_domain, sender_domain, sender_domains
from known_domains import BRANDS, WELL_KNOWN
from trusted_domains import TRUSTED_DOMAINS
from unicode_text import without_invisible

_ANGLE_ADDR_RE = re.compile(r"<\s*([^<>\s]{1,200}@[^<>\s@]{1,253})\s*>")
_HOST_CHARS = set("abcdefghijklmnopqrstuvwxyz0123456789-")


def is_trusted_domain(domain: str | None) -> bool:
    """Return True if the domain or one of its parents is allowlisted."""
    if not domain:
        return False
    d = domain.lower()
    return d in TRUSTED_DOMAINS or any(d.endswith("." + td) for td in TRUSTED_DOMAINS)


# Look-alikes of Latin letters that NFKC leaves alone. This covers
# Cyrillic and Greek ("PаyPal" with a Cyrillic "а"), stroked or dotless
# Latin letters ("PayPał", "Amelı"), small capitals ("ᴘᴀʏᴘᴀʟ"), Armenian
# ("օ", "ս", "հ"), Cherokee capitals and IPA. Small capitals map to
# capitals so that "ᴜᴘs" reads as "UPS".
_MORE_CONFUSABLES = {
    "\u0585": "o",
    "\u057d": "u",
    "\u0570": "h",
    "\u0578": "n",
    "\u0581": "g",
    "\u0566": "q",
    "\u0561": "w",
    "\u13aa": "A",
    "\u13f4": "B",
    "\u13df": "C",
    "\u13ac": "E",
    "\u13c0": "G",
    "\u13bb": "H",
    "\u13ab": "J",
    "\u13e6": "K",
    "\u13de": "L",
    "\u13b7": "M",
    "\u13e2": "P",
    "\u13da": "S",
    "\u13a2": "T",
    "\u13d9": "V",
    "\u13b3": "W",
    "\u13c3": "Z",
    "\u0251": "a",
    "\u0261": "g",
    "\u0269": "i",
    "\u026a": "I",
    "\u0280": "R",
    "\u01c0": "l",
    "\u0131": "i",
    "\u03f2": "c",
    "\u03f3": "j",
    "\u051b": "q",
    "\u051d": "w",
    "\u0475": "v",
    "\u04bb": "h",
    "\u0501": "d",
    "\u04cf": "l",
    "\u0455": "s",
    "\u0456": "i",
    "\u0458": "j",
    "\u03bf": "o",
    "\u03c1": "p",
}
_CONFUSABLES = {
    **str.maketrans(
        "аеорсухіјѕԁһӏАВЕКМНОРСТХІЈЅαεικνορτυχΑΒΕΗΙΚΜΝΟΡΤΥΧΖıłŁøØđĐħŧƚȷᴀʙᴄᴅᴇꜰɢʜɪᴊᴋʟᴍɴᴏᴘʀꜱᴛᴜᴠᴡʏᴢ",
        "aeopcyxijsdhlABEKMHOPCTXIJSaeikvoptuxABEHIKMNOPTYXZilLoOdDhtljABCDEFGHIJKLMNOPRSTUVWYZ",
    ),
    **str.maketrans(_MORE_CONFUSABLES),
}


def _plain_words(text: str, lower: bool = True) -> str:
    """Fold a display name so brand names can be matched as whole words.

    NFKC turns mathematical bold letters into plain ones, accents are
    dropped and _CONFUSABLES handles look-alikes. Invisible characters are removed, since "Chrono" +
    zero-width space + "post" shows as "Chronopost". Everything else that
    isn't a letter, digit or dot becomes a space. We also append a copy
    with dots as spaces, so "impots.gouv" matches "impots gouv".
    """
    text = without_invisible(text)
    folded = unicodedata.normalize("NFKD", unicodedata.normalize("NFKC", text))
    folded = "".join(c for c in folded if not unicodedata.combining(c)).translate(_CONFUSABLES)
    # Some scripts need joiners between letters. Those don't split a word.
    folded = folded.replace("\u200c", "").replace("\u200d", "")
    if lower:
        folded = folded.lower()
    kept = " ".join("".join(c if c.isalnum() or c == "." else " " for c in folded).split())
    return f" {kept} {kept.replace('.', ' ')} "


# TLDs where a domain named after a brand is assumed to be the brand's.
# Brands nearly always register .com, .net and .org themselves, plus the
# country codes of the markets PhishLens serves (paypal.fr, dhl.de). On
# other TLDs ("paypal.vc", "chronopost.us") the full domain has to be in
# known_domains.BRANDS, WELL_KNOWN or the allowlist. A fork for another
# region should add its own country codes.
_BRAND_TLDS = frozenset({"com", "net", "org"})
_HOME_CCTLDS = frozenset(
    {"fr", "be", "ch", "lu", "de", "at", "nl", "es", "pt", "it", "uk", "ie", "ng", "ca", "jp"}
)


def _brand_owns(brand_domains: frozenset[str], domain: str) -> bool:
    """Return True if `domain` belongs to the brand (see _BRAND_TLDS).

    A customer subdomain on a shared host, like paypal.duckdns.org, never does.
    """
    org = org_domain(domain)
    if not org:
        return False
    if org in brand_domains:
        return True
    label, _, rest = org.partition(".")
    if rest in SHARED_SUFFIXES or label not in brand_domains:
        return False
    tld = org.rsplit(".", 1)[-1]
    if tld in _BRAND_TLDS or tld in _HOME_CCTLDS:
        return True
    return org in WELL_KNOWN or org in TRUSTED_DOMAINS


# Services that send on a person's behalf and put that person's address
# in the display name, as in "Jane (jane@outlook.com) via Google Docs"
# <drive-shares-dm-noreply@google.com>. This list is only for display
# names. Their links are not trusted, because anyone can share a file.
_RELAY_SENDERS = frozenset(
    [
        "google.com",
        "docusign.net",
        "docusign.com",
        "dropbox.com",
        "dropboxmail.com",
        "atlassian.net",
        "github.com",
        "gitlab.com",
        "linkedin.com",
        "slack.com",
        "zoom.us",
        "calendly.com",
        "notion.so",
        "figma.com",
        "canva.com",
        "box.com",
        "wetransfer.com",
        "microsoft.com",
        "sharepointonline.com",
    ]
)


def _comments(header: str) -> str:
    """Return the text of every "(...)" comment, nested ones included."""
    out: list[str] = []
    depth = 0
    for ch in header:
        if ch == "(":
            depth += 1
            out.append(" ")
        elif ch == ")" and depth:
            depth -= 1
            out.append(" ")
        elif depth:
            out.append(ch)
    return "".join(out)


def _display_names(header: str) -> str:
    """Return every display name a mail program might show for a From: value.

    That includes each parsed name, the text before the last "<" with
    addresses removed (for malformed headers such as
    '"PayPal\\" <x@evil.example'), and comments such as
    '<x@evil.example> (PayPal (Support))'.
    """
    names = [name for name, _addr in getaddresses([header]) if name]
    if "<" in header:
        names.append(_ANGLE_ADDR_RE.sub(" ", header.rpartition("<")[0]))
    if "(" in header:
        names.append(_comments(header))
    return " ".join(names)


# A person's address inside a display name, on any domain, since a
# colleague at microsoft.com shares Google Docs too. We only drop it for
# known, relaying or allowlisted senders, and only when other words remain.
_WEBMAIL_IN_NAME_RE = re.compile(r"[\w.+-]+@[\w-]+(?:\.[\w-]+)+\b", re.IGNORECASE)


def impersonated_brand(from_header: str) -> str | None:
    """Return the brand a From: claims when the address isn't the brand's.

    "Chronopost <info@qdsoddsmn.us>" gives "chronopost". Names are matched
    as whole words against known_domains.BRANDS. Brands of three letters or
    fewer only match in capitals, so "UPS" counts and "ups" doesn't.
    """
    # Read the whole value as header_dict stored it (spaces collapsed,
    # 8,000 characters).
    header = " ".join((from_header or "")[:32_000].split())[:8000]
    name = _display_names(header)
    # Check every address. A brand address next to an impostor's
    # ('"PayPal" <service@paypal.com>, <scam@evil.example>') doesn't vouch
    # for the impostor. The other checks read the first one.
    addresses = set(sender_domains(header)) or {""}
    # In "Jane (jane@gmail.com) via GitHub" <notifications@github.com> the
    # gmail address doesn't claim to be Gmail. We drop it when the sender is
    # a known, relaying or allowlisted site and other words remain. From
    # anyone else ('"Security <security@gmail.com>" <x@evil>') it counts
    # like any other address in a name.
    if all(
        org_domain(d) in WELL_KNOWN or org_domain(d) in _RELAY_SENDERS or is_trusted_domain(d)
        for d in addresses
    ):
        rest = _WEBMAIL_IN_NAME_RE.sub(" ", name)
        if rest != name and re.search(r"[^\W\d_]{2}", rest):
            name = rest
    if not name.strip(' <>"\\'):
        return None
    words = _plain_words(name)
    upper = _plain_words(name, lower=False)
    for brand, domains in BRANDS.items():
        found = f" {brand.upper()} " in upper if len(brand) <= 3 else f" {brand} " in words
        if found and not all(_brand_owns(domains, d) for d in addresses):
            return brand
    return None


def is_hostname(name: str) -> bool:
    """Return True for a hostname with at least two labels. No regex, so it stays linear."""
    labels = name.split(".")
    return (
        0 < len(name) <= 253
        and len(labels) >= 2
        and all(0 < len(lab) <= 63 and set(lab) <= _HOST_CHARS for lab in labels)
    )


def synthesize_auth_results(ctx: Any, sender_email: str | None) -> str:
    """Build an Authentication-Results header from what Gmail shows.

    "mailed-by" is the SPF domain and "signed-by" the DKIM domain. We only
    write dmarc=pass when the signing domain aligns with From:, so
    attacker.co.uk signing for paypal.co.uk doesn't align. Returns "" when
    there is nothing to build from.
    """
    if not isinstance(ctx, dict) or ctx.get("origin") != "gmail":
        return ""

    def host(key: str) -> str:
        # This goes into a header, so drop anything that isn't a hostname.
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
