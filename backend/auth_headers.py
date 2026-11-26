"""
PhishLens: email authentication headers and the Spamhaus DBL lookup.

The domain in From: proves nothing by itself. Gmail and most modern mail
servers add an Authentication-Results header to every message, and we
read SPF, DKIM and DMARC from it.

We follow the alignment rule of RFC 7489. The From: domain has to match
a domain that actually passed, so a message signed by attacker.tld can't
pass as "From: paypal.com". We only call a message cryptographically
verified when DKIM passed for a domain aligned with From:.

The Spamhaus DBL is a DNS block list at dbl.spamhaus.org. A sender or
link domain listed there is a known spam, malware or phishing source.
"""

from __future__ import annotations

import asyncio
import logging
import re
import socket
from dataclasses import asdict, dataclass
from email.utils import getaddresses
from typing import Any

# email_parsing.header_dict sets this when a message has several From: headers.
FROM_UNPROVEN = "x-phishlens-from-unproven"

logger = logging.getLogger("phishlens." + __name__.split(".")[-1])


# Authentication-Results parsing

# Authenticated identity for each method.
_SPF_ID_RE = re.compile(r"smtp\.mailfrom=([^\s;]+)", re.IGNORECASE)
_DKIM_ID_RE = re.compile(r"header\.(?:i|d)=@?([^\s;]+)", re.IGNORECASE)
_DMARC_ID_RE = re.compile(r"header\.from=([^\s;]+)", re.IGNORECASE)
_ID_RE = {"spf": _SPF_ID_RE, "dkim": _DKIM_ID_RE, "dmarc": _DMARC_ID_RE}


def _without_comments(value: str) -> str:
    """Strip RFC 5322 comments and the contents of quoted strings.

    The sender controls both. A quoted local part such as
    '"dkim=pass header.i=@bank.example"@attacker.example', or a comment the
    receiving server copies from the message, must not read as a result.
    Runs in linear time.
    """
    out: list[str] = []
    depth, quoted, escaped = 0, False, False
    for ch in value:
        if escaped:
            escaped = False
            continue
        if ch == "\\" and (quoted or depth):
            escaped = True
            continue
        if quoted:
            if ch == '"':
                quoted = False
                out.append('q"')
            continue
        if ch == '"' and not depth:
            quoted = True
            out.append('"')
        elif ch == "(":
            depth += 1
        elif ch == ")" and depth:
            depth -= 1
            if not depth:
                out.append(" ")
        elif not depth:
            out.append(ch)
    return "".join(out)


_CLAUSE_RE = re.compile(
    r"\s*(?P<method>spf|dkim|dmarc)\s*=\s*(?P<result>pass|fail|softfail|neutral|"
    r"temperror|permerror|none|bestguesspass|policy)\b",
    re.IGNORECASE,
)


def _clauses(ar: str):
    """Yield (method, result, rest) for each clause of an Authentication-Results value.

    RFC 8601 puts one result per ";"-separated clause, starting with the
    method. The server name comes first, though Microsoft 365 omits it. A
    "dkim=pass" in the middle of a clause is not a result.
    """
    for segment in _without_comments(ar[:20_000]).split(";"):
        m = _CLAUSE_RE.match(segment)
        if m:
            yield m.group("method").lower(), m.group("result").lower(), segment[m.end() :]


@dataclass
class AuthVerdict:
    """Parsed Authentication-Results."""

    # Results as the receiving MTA reported them.
    spf: str = "none"  # "pass" | "fail" | "softfail" | "none" | ...
    dkim: str = "none"
    dmarc: str = "none"

    # Domain the receiving MTA actually authenticated (may differ from From:)
    spf_domain: str = ""
    dkim_domain: str = ""
    dmarc_domain: str = ""

    from_domain: str = ""
    aligned: bool = False  # From: domain matches at least one authenticated domain
    all_pass: bool = False  # all three of SPF/DKIM/DMARC are "pass"
    cryptographically_verified: bool = False  # DKIM pass from a domain aligned with From:
    # The receiving server's DMARC passed for the From: domain itself, which
    # also covers mail aligned through SPF only (a mailer that signs with
    # its own DKIM domain but uses the sender's bounce domain).
    dmarc_aligned: bool = False
    header_present: bool = False  # Authentication-Results was actually there

    # The raw header, for logging.
    raw: str = ""

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


_ANGLE_RE = re.compile(r"<([^<>]{1,500})>")
_AT_DOMAIN_RE = re.compile(r"@([A-Za-z0-9.\-_]+)")


def _address_domain(addr: str) -> str:
    """Return the domain after the last "@".

    A quoted local part can contain its own "@", so
    '"service@paypal.com"@evil.example' belongs to evil.example.
    """
    m = _AT_DOMAIN_RE.match("@" + addr.rsplit("@", 1)[-1].strip()) if "@" in addr else None
    return m.group(1).lower().rstrip(".") if m else ""


def sender_domains(value: str) -> list[str]:
    """Return every domain a From: value names, in order.

    We take each parsed address and each <...> block, since two blocks
    with no comma are two addresses whatever the parser thinks. If nothing
    parses we fall back to every "@" in the line. More than one domain
    means the header doesn't name a single sender.
    """
    if not value:
        return []
    value = value[:8000]
    # Only look outside quoted names and comments.
    # '"Jane <jane@gmail.com> (via Docs)" <drive@google.com>' names one
    # sender, google.com.
    bare = _without_comments(value)
    addrs = [a for _n, a in getaddresses([value]) if "@" in a]
    addrs += [a for a in _ANGLE_RE.findall(bare) if "@" in a]
    found = []
    for a in addrs:
        # '"ceo@victim.example"@evil.example' names two domains.
        local = a.rpartition("@")[0]
        found += [d.lower().rstrip(".") for d in _AT_DOMAIN_RE.findall(local)]
        found.append(_address_domain(a))
    if not any(found):
        found = [d.lower().rstrip(".") for d in _AT_DOMAIN_RE.findall(bare)]
    if not any(found):
        found = [d.lower().rstrip(".") for d in _AT_DOMAIN_RE.findall(value)]
    return list(dict.fromkeys(d for d in found if d))


def sender_domain(value: str) -> str | None:
    """Return the sender domain of an address or a 'Name <addr@domain>' header.

    We use the address, not the first "@" in the line, because the display
    name can hold a fake one ('"support@gtbank.com" <scam@attacker.example>').
    If the header doesn't parse we take the last domain, since the address
    follows the name. All sender checks go through here.
    """
    if not value:
        return None
    value = value[:8000]
    parsed = [a for _n, a in getaddresses([value]) if "@" in a]
    if parsed and _address_domain(parsed[0]):
        return _address_domain(parsed[0])
    domains = sender_domains(value)
    return domains[-1] if domains else None


def _domain_of(addr: str) -> str:
    """Extract the domain part from either 'foo@bar.tld' or a bare 'bar.tld'."""
    if not addr:
        return ""
    addr = addr.strip().strip("<>").strip('"').lower()
    if "@" in addr:
        addr = addr.rsplit("@", 1)[1]
    return addr.rstrip(".").split(">")[0].strip()


# Second-level labels used under country-code TLDs (paypal.co.uk,
# firstbank.com.ng, unilag.edu.ng, uct.ac.za). Under a two-letter TLD, a
# domain ending in one of these keeps three labels.
_GENERIC_SLDS = {
    "co",
    "com",
    "net",
    "org",
    "gov",
    "edu",
    "ac",
    "sch",
    "mil",
    "gob",
    "gouv",
    "nic",
    "or",
    "ne",
    "go",
    "ltd",
    "plc",
    "info",
    "biz",
    "nom",
    "int",
    "res",
    "lg",
    "ad",
    "ed",
    "gr",
    "mod",
    "police",
    "nhs",
}
# Shared hosting suffixes where each customer gets a subdomain. The
# customer label is the organisation, not the suffix.
SHARED_SUFFIXES = {
    "github.io",
    "herokuapp.com",
    "web.app",
    "firebaseapp.com",
    "pages.dev",
    "netlify.app",
    "vercel.app",
    "blogspot.com",
    "duckdns.org",
    "azurewebsites.net",
    "cloudfront.net",
    "appspot.com",
    "wixsite.com",
    "weebly.com",
    "glitch.me",
}


def org_domain(domain: str) -> str:
    """Return the organisational domain, e.g. 'billing.paypal.co.uk' -> 'paypal.co.uk'.

    This is not the full Public Suffix List. It covers the country-code
    registries that use generic second-level labels and the common shared
    hosting suffixes, which is enough to keep attacker.co.uk and
    paypal.co.uk apart. Every alignment check uses it, including the one
    built from Gmail's "signed-by".
    """
    if not domain:
        return ""
    parts = [p for p in domain.lower().strip().strip(".").split(".") if p]
    if len(parts) <= 2:
        return ".".join(parts)
    tail2 = ".".join(parts[-2:])
    if tail2 in SHARED_SUFFIXES:
        return ".".join(parts[-3:])
    if len(parts[-1]) == 2 and parts[-2] in _GENERIC_SLDS:
        return ".".join(parts[-3:])
    return tail2


def parse_authentication_results(headers: dict[str, str]) -> AuthVerdict:
    """Parse Authentication-Results from the lowercased header dict of parse_eml().

    Without the header, every result stays "none" and header_present is False.
    """
    verdict = AuthVerdict()

    # The alignment check needs the From: domain.
    verdict.from_domain = sender_domain(headers.get("from", "")) or ""

    ar = headers.get("authentication-results", "") or ""
    # Without Authentication-Results we show the ARC copy, but it proves
    # nothing. No receiving server vouched for it and a sender can write
    # one into the message.
    arc_only = not ar
    if arc_only:
        ar = headers.get("arc-authentication-results", "") or ""
    if not ar:
        return verdict

    verdict.header_present = True
    verdict.raw = ar[:500]  # capped for logging

    # Keep one result per method, read with the identity from the same
    # clause. An email can carry a failing DKIM signature for the brand and
    # a passing one for the sender's own domain, and those must not merge
    # into "pass for the brand". We prefer an aligned pass, then any pass,
    # then the first result listed.
    fod = org_domain(verdict.from_domain)
    chosen: dict[str, tuple[int, str, str]] = {}
    for method, result, clause in _clauses(ar):
        idm = _ID_RE[method].search(clause)
        domain = _domain_of(idm.group(1)) if idm else ""
        rank = 0
        if result == "pass":
            rank = 2 if domain and org_domain(domain) == fod else 1
        if method not in chosen or rank > chosen[method][0]:
            chosen[method] = (rank, result, domain)
    for method, (_rank, result, domain) in chosen.items():
        setattr(verdict, method, result)
        setattr(verdict, f"{method}_domain", domain)

    verdict.all_pass = verdict.spf == "pass" and verdict.dkim == "pass" and verdict.dmarc == "pass"

    # The From: domain must match the organisational domain of a method that
    # passed. Otherwise an attacker who DKIM-signs attacker.tld would pass
    # because header.from=paypal.com appears in the DMARC field, which is
    # copied from From: and never authenticated.
    aligned_domains = []
    if verdict.spf == "pass" and verdict.spf_domain:
        aligned_domains.append(verdict.spf_domain)
    if verdict.dkim == "pass" and verdict.dkim_domain:
        aligned_domains.append(verdict.dkim_domain)
    if verdict.dmarc == "pass" and verdict.dmarc_domain:
        aligned_domains.append(verdict.dmarc_domain)
    # With two From: headers a mail program shows one while checks read the
    # other. DMARC fails such a message and so do we. A From: with several
    # addresses is the same trick in one header.
    from_value = headers.get("from", "")[:8000]
    from_addresses = {a.lower() for _n, a in getaddresses([from_value]) if a}
    proven = (
        not arc_only
        and not headers.get(FROM_UNPROVEN)
        and len(from_addresses) <= 1
        and len(sender_domains(from_value)) <= 1
    )
    verdict.aligned = proven and bool(fod) and any(org_domain(d) == fod for d in aligned_domains)

    # DKIM is the only cryptographic method. SPF covers the envelope only
    # and DMARC is a policy on top of the other two. So we need a DKIM pass
    # from a domain aligned with From:.
    dkim_aligned = (
        verdict.dkim == "pass" and verdict.dkim_domain and org_domain(verdict.dkim_domain) == fod
    )
    verdict.cryptographically_verified = proven and bool(dkim_aligned)
    # DMARC pass is the receiving server's own check that SPF or DKIM
    # aligned with From:. The header.from it reports must be the From:
    # domain we read, and the same proof rules apply. A DKIM failure with
    # no passing signature at all cancels it, as it cancels the Gmail
    # inbox path. "bestguesspass" (no DMARC record) is not a pass.
    verdict.dmarc_aligned = (
        proven
        and bool(fod)
        and verdict.dmarc == "pass"
        and verdict.dkim != "fail"
        and bool(verdict.dmarc_domain)
        and org_domain(verdict.dmarc_domain) == fod
    )

    return verdict


# Spamhaus DBL: Domain Block List (DNS-based)

DBL_ZONE = "dbl.spamhaus.org"

# Listing codes mapped to (threat type, category).
# https://www.spamhaus.org/faq/section/Spamhaus%20DBL#291
_DBL_CODES = {
    "127.0.1.2": ("SPAM", "spam"),
    "127.0.1.4": ("SOCIAL_ENGINEERING", "phish"),
    "127.0.1.5": ("MALWARE", "malware"),
    "127.0.1.6": ("BOTNET_CC", "botnet_cc"),
    "127.0.1.102": ("SPAM", "abused_legit_spam"),
    "127.0.1.103": ("SUSPICIOUS", "abused_legit_redirector"),
    "127.0.1.104": ("SOCIAL_ENGINEERING", "abused_legit_phish"),
    "127.0.1.105": ("MALWARE", "abused_legit_malware"),
    "127.0.1.106": ("BOTNET_CC", "abused_legit_botnet_cc"),
}
_policy_logged = False


async def spamhaus_dbl(domain: str, timeout: float = 2.0) -> dict[str, Any] | None:
    """Look a domain up in the Spamhaus DBL.

    Returns {"threat_type", "category", "code"}, or None when the domain is
    not listed or there was no answer. reputation.py uses it for link
    domains too.

    Spamhaus answers 127.255.255.x to refuse queries from public or
    anonymous resolvers. Counting those would flag every domain, so we log
    them once and treat them as no answer.
    """
    global _policy_logged
    domain = _domain_of(domain)
    if not domain or "." not in domain:
        return None
    try:
        code = await asyncio.wait_for(
            asyncio.get_running_loop().run_in_executor(
                None, socket.gethostbyname, f"{domain}.{DBL_ZONE}"
            ),
            timeout=timeout,
        )
    except Exception:  # NXDOMAIN (not listed), timeout, resolver error
        return None
    if code.startswith("127.255.255."):
        if not _policy_logged:
            logger.warning(
                "Spamhaus DBL refused the query (%s): this host's DNS resolver is "
                "public or blocked; DBL lookups count as unavailable. A private "
                "recursive resolver or Spamhaus DQS enables them.",
                code,
            )
            _policy_logged = True
        return None
    if not code.startswith("127.0.1."):
        return None  # not a documented DBL answer
    threat_type, category = _DBL_CODES.get(code, ("SUSPICIOUS", "listed_unknown_code"))
    return {"threat_type": threat_type, "category": category, "code": code}


async def build_metadata_auth_signal(
    headers: dict[str, str], enable_dbl: bool = True
) -> dict[str, Any]:
    """Build the auth signal for /analyse from Authentication-Results and the DBL.

    Contribution to the metadata score:
      * cryptographically_verified  -> -0.20   (bonus)
      * all_pass                    -> -0.10   (bonus)
      * SPF fail                    -> +0.15
      * DKIM fail                   -> +0.20
      * DMARC fail                  -> +0.25
      * From: domain in Spamhaus    -> +0.60
      * header_absent               -> +0.10   (a modern inbox always adds it)
    """
    av = parse_authentication_results(headers)

    listing = await spamhaus_dbl(av.from_domain) if enable_dbl and av.from_domain else None
    dbl = {"listed": bool(listing), "category": listing["category"] if listing else None}

    delta = 0.0
    reasons: list[str] = []

    if av.cryptographically_verified:
        delta -= 0.20
        reasons.append("dkim_aligned")
    if av.all_pass:
        delta -= 0.10
        reasons.append("spf+dkim+dmarc_pass")
    if av.spf == "fail":
        delta += 0.15
        reasons.append("spf_fail")
    if av.dkim == "fail":
        delta += 0.20
        reasons.append("dkim_fail")
    if av.dmarc == "fail":
        delta += 0.25
        reasons.append("dmarc_fail")
    if dbl.get("listed"):
        delta += 0.60
        reasons.append(f"spamhaus_dbl:{dbl.get('category')}")
    if not av.header_present:
        delta += 0.10
        reasons.append("no_auth_header")

    return {
        "auth": av.to_dict(),
        "spamhaus_dbl": dbl,
        "score_delta": round(delta, 3),
        "reasons": reasons,
    }
