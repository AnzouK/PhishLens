"""
Email authentication header parsing + Spamhaus DBL DNS lookup.

Adds a real sender-authentication signal to the metadata pipeline.
"paypal.com" in the From: line means nothing on its own, so this module reads
the Authentication-Results header that Gmail (and most modern MTAs) adds to
every message, and reports whether SPF / DKIM / DMARC actually passed.

A domain is only considered "cryptographically legitimate" when SPF passes,
DKIM passes, AND the From: domain aligns with one of them (DMARC pass or
aligned SPF/DKIM). That's the RFC-7489 alignment rule; it's what stops a
spoofer from putting "From: paypal.com" on a message that was actually
signed by attacker.tld.

We also expose a Spamhaus DBL (Domain Block List) lookup: a DNS query
against dbl.spamhaus.org. If the sender domain (or any URL domain) has a
record there, it's a known spam / malware / phish source.

Public API:
    parse_authentication_results(headers) -> AuthVerdict
    spamhaus_dbl(domain)                  -> Awaitable[dict | None]
    build_metadata_auth_signal(headers)   -> dict   (ready for JSON output)
"""

from __future__ import annotations

import asyncio
import logging
import re
import socket
from dataclasses import asdict, dataclass
from email.utils import getaddresses, parseaddr
from typing import Any

# Set by email_parsing.header_dict when a message has several From: headers.
FROM_UNPROVEN = "x-phishlens-from-unproven"

logger = logging.getLogger("phishlens." + __name__.split(".")[-1])


# =====================================================================
# Authentication-Results parsing
# =====================================================================

# Extracts the authenticated identity for each method.
_SPF_ID_RE = re.compile(r"smtp\.mailfrom=([^\s;]+)", re.IGNORECASE)
_DKIM_ID_RE = re.compile(r"header\.(?:i|d)=@?([^\s;]+)", re.IGNORECASE)
_DMARC_ID_RE = re.compile(r"header\.from=([^\s;]+)", re.IGNORECASE)
_ID_RE = {"spf": _SPF_ID_RE, "dkim": _DKIM_ID_RE, "dmarc": _DMARC_ID_RE}


def _without_comments(value: str) -> str:
    """The value with its comments "(...)", nested or not, and the
    contents of its quoted strings removed (RFC 5322). Both are free text
    the sender can influence: a quoted local part in the envelope address
    ('"dkim=pass header.i=@bank.example"@attacker.example') or a comment
    the receiving server copies from the message must not read as a
    result. Linear on any input."""
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
    """(method, result, rest of the clause) for each result of an
    Authentication-Results value: one result per ";"-separated clause,
    each starting with its method (RFC 8601). The server's name comes
    first (Microsoft 365 leaves it out); a "dkim=pass" anywhere else in a
    clause is not a result."""
    for segment in _without_comments(ar[:20_000]).split(";"):
        m = _CLAUSE_RE.match(segment)
        if m:
            yield m.group("method").lower(), m.group("result").lower(), segment[m.end() :]


@dataclass
class AuthVerdict:
    """Structured result of Authentication-Results parsing."""

    # Raw verdicts as reported by the receiving MTA
    spf: str = "none"  # "pass" | "fail" | "softfail" | "none" | ...
    dkim: str = "none"
    dmarc: str = "none"

    # Domain the receiving MTA actually authenticated (may differ from From:)
    spf_domain: str = ""
    dkim_domain: str = ""
    dmarc_domain: str = ""

    # Higher-level signals derived from the above
    from_domain: str = ""
    aligned: bool = False  # From: domain matches at least one authenticated domain
    all_pass: bool = False  # all three of SPF/DKIM/DMARC are "pass"
    cryptographically_verified: bool = False  # aligned AND at least DKIM pass
    header_present: bool = False  # Authentication-Results was actually there

    # Extras: the raw header for debug / logging
    raw: str = ""

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def sender_domain(value: str) -> str | None:
    """Domain of a bare address or a 'Name <addr@domain>' header: the
    address itself, not the first "@" of the line, since a display name
    can carry another one ('"support@gtbank.com" <scam@attacker.example>').
    Every check of the sender reads it from here."""
    if not value:
        return None
    value = value[:8000]
    addr = parseaddr(value)[1]
    m = re.search(r"@([A-Za-z0-9.\-_]+)", addr if "@" in addr else value)
    if not m:
        return None
    return m.group(1).lower().rstrip(".") or None


def _domain_of(addr: str) -> str:
    """Extract the domain part from either 'foo@bar.tld' or a bare 'bar.tld'."""
    if not addr:
        return ""
    addr = addr.strip().strip("<>").strip('"').lower()
    if "@" in addr:
        addr = addr.rsplit("@", 1)[1]
    return addr.rstrip(".").split(">")[0].strip()


# Second-level labels that registries use under country-code TLDs
# (paypal.co.uk, firstbank.com.ng, unilag.edu.ng, uct.ac.za, ...): under a
# two-letter TLD, a domain ending in one of these keeps three labels.
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
# Shared hosting suffixes where every customer gets a subdomain: the
# customer label is the organisation, never the suffix itself.
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


def _org_domain(domain: str) -> str:
    """
    Organisational domain ("registrable" domain): 'mail.paypal.com' ->
    'paypal.com', 'billing.paypal.co.uk' -> 'paypal.co.uk',
    'x.firstbank.com.ng' -> 'firstbank.com.ng'.

    Not the full Public Suffix List, but it covers every country-code
    registry that uses generic second-level labels (co, com, org, gov, edu,
    ac, ...) and common shared-hosting suffixes, so two different
    organisations under the same public suffix never compare equal
    (attacker.co.uk vs paypal.co.uk). Used by every alignment check,
    including the one built from Gmail's "signed-by".
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


def org_domain(domain: str) -> str:
    """Public name for _org_domain (used by extension_backend)."""
    return _org_domain(domain)


def parse_authentication_results(headers: dict[str, str]) -> AuthVerdict:
    """
    Parse the Authentication-Results header into a structured verdict.

    `headers` should be the parsed header dict from parse_eml(): keys
    lowercased. Missing header -> AuthVerdict(header_present=False) with
    all verdicts defaulting to "none".
    """
    verdict = AuthVerdict()

    # From: domain first, needed for the alignment check. The address
    # itself, not the first "@" of the line: a display name can carry
    # another address ('"support@paypal.com" <scam@attacker.example>').
    verdict.from_domain = sender_domain(headers.get("from", "")) or ""

    ar = headers.get("authentication-results", "") or ""
    # Without Authentication-Results, the ARC copy is shown, but it proves
    # nothing: no receiving server vouched for it, and a sender can write
    # one in its own message.
    arc_only = not ar
    if arc_only:
        ar = headers.get("arc-authentication-results", "") or ""
    if not ar:
        return verdict

    verdict.header_present = True
    verdict.raw = ar[:500]  # cap for logging

    # One result per method, each with the identity written in its own
    # clause. An email can carry several DKIM signatures: a failing one in
    # the brand's name next to a passing one for the sender's own domain
    # must not combine into "pass for the brand". Per method, the result
    # kept is an aligned pass, else any pass, else the first one listed.
    fod = _org_domain(verdict.from_domain)
    chosen: dict[str, tuple[int, str, str]] = {}
    for method, result, clause in _clauses(ar):
        idm = _ID_RE[method].search(clause)
        domain = _domain_of(idm.group(1)) if idm else ""
        rank = 0
        if result == "pass":
            rank = 2 if domain and _org_domain(domain) == fod else 1
        if method not in chosen or rank > chosen[method][0]:
            chosen[method] = (rank, result, domain)
    for method, (_rank, result, domain) in chosen.items():
        setattr(verdict, method, result)
        setattr(verdict, f"{method}_domain", domain)

    # Compute derived signals
    verdict.all_pass = verdict.spf == "pass" and verdict.dkim == "pass" and verdict.dmarc == "pass"

    # Alignment: the visible From: domain must match an authenticated one at
    # the organizational-domain level, AND that method must have passed.
    # An attacker who DKIM-signs their own attacker.tld would otherwise pass
    # this check just because their spoofed header.from=paypal.com happens
    # to appear in the DMARC identifier field (which is copied from From:,
    # not authenticated). Only "pass" verdicts count.
    aligned_domains = []
    if verdict.spf == "pass" and verdict.spf_domain:
        aligned_domains.append(verdict.spf_domain)
    if verdict.dkim == "pass" and verdict.dkim_domain:
        aligned_domains.append(verdict.dkim_domain)
    if verdict.dmarc == "pass" and verdict.dmarc_domain:
        aligned_domains.append(verdict.dmarc_domain)
    # Two From: headers: a mail program shows one, the checks read the
    # other. DMARC treats such a message as failing; so does PhishLens.
    # A From: with several addresses is the same trick in one header.
    from_addresses = {a.lower() for _n, a in getaddresses([headers.get("from", "")[:8000]]) if a}
    proven = not arc_only and not headers.get(FROM_UNPROVEN) and len(from_addresses) <= 1
    verdict.aligned = proven and bool(fod) and any(_org_domain(d) == fod for d in aligned_domains)

    # Cryptographic verification requires DKIM (the only crypto method: SPF
    # is envelope-only, DMARC is a policy layer on top of the other two) to
    # have passed AND the DKIM-signing domain to align with From:.
    dkim_aligned = (
        verdict.dkim == "pass" and verdict.dkim_domain and _org_domain(verdict.dkim_domain) == fod
    )
    verdict.cryptographically_verified = proven and bool(dkim_aligned)

    return verdict


# =====================================================================
# Spamhaus DBL: Domain Block List (DNS-based)
# =====================================================================

DBL_ZONE = "dbl.spamhaus.org"

# Listing codes: (threat type, category).
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
    """The Spamhaus DBL listing of a domain: {"threat_type", "category",
    "code"}, or None when it is not listed or the lookup gave no answer.
    Used for the sender's domain here and for link domains in reputation.

    127.255.255.x answers are not listings: Spamhaus refuses queries from
    public or anonymous resolvers that way. Counting them would flag every
    domain; they are logged once and treated as no answer.
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


# =====================================================================
# High-level convenience: one call, everything you need
# =====================================================================


async def build_metadata_auth_signal(
    headers: dict[str, str], enable_dbl: bool = True
) -> dict[str, Any]:
    """
    Convenience wrapper used by extension_backend's metadata_agent().

    Combines Authentication-Results parsing with a Spamhaus DBL lookup on
    the From: domain, and returns a JSON-serialisable dict ready to attach
    to the /analyse response.

    Score contribution to the metadata agent:
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


# =====================================================================
# Sync wrapper: for callers not in an async context.
# =====================================================================


def build_metadata_auth_signal_sync(
    headers: dict[str, str], enable_dbl: bool = True
) -> dict[str, Any]:
    """
    Synchronous variant. Runs the async coroutine to completion.
    Safe to call from FastAPI sync endpoints (which run in a threadpool).
    """
    try:
        loop = asyncio.get_event_loop()
        if loop.is_running():
            # Rare but possible: called from inside an event loop.
            # Schedule in a fresh loop on a helper thread instead of deadlocking.
            import concurrent.futures

            with concurrent.futures.ThreadPoolExecutor(max_workers=1) as ex:
                fut = ex.submit(asyncio.run, build_metadata_auth_signal(headers, enable_dbl))
                return fut.result(timeout=5)
    except RuntimeError:
        pass
    return asyncio.run(build_metadata_auth_signal(headers, enable_dbl))
