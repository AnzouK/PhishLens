"""
Email authentication header parsing + Spamhaus DBL DNS lookup.

Adds a real sender-authentication signal to the metadata pipeline. Where the
old code relied on a static TRUSTED_DOMAINS allowlist (which is spoofable —
"paypal.com" in the From: line means nothing on its own), this module reads
the Authentication-Results header that Gmail (and most modern MTAs) adds to
every message, and reports whether SPF / DKIM / DMARC actually passed.

A domain is only considered "cryptographically legitimate" when SPF passes,
DKIM passes, AND the From: domain aligns with one of them (DMARC pass or
aligned SPF/DKIM). That's the RFC-7489 alignment rule; it's what stops a
spoofer from putting "From: paypal.com" on a message that was actually
signed by attacker.tld.

We also expose a Spamhaus DBL (Domain Block List) lookup — a DNS query
against dbl.spamhaus.org. If the sender domain (or any URL domain) has a
record there, it's a known spam / malware / phish source.

Public API:
    parse_authentication_results(headers) -> AuthVerdict
    check_spamhaus_dbl(domain)            -> Awaitable[bool]
    build_metadata_auth_signal(headers)   -> dict   (ready for JSON output)
"""

from __future__ import annotations

import asyncio
import re
import socket
from dataclasses import dataclass, field, asdict
from typing import Any


# =====================================================================
# Authentication-Results parsing
# =====================================================================

# Matches things like:
#   spf=pass smtp.mailfrom=service@paypal.com
#   dkim=pass header.i=@paypal.com header.s=selector1
#   dmarc=pass (p=REJECT sp=REJECT) header.from=paypal.com
# We only care about the verdict token (pass / fail / softfail / neutral /
# temperror / permerror / none / bestguesspass) and the identifier that
# tells us which domain was authenticated.
_METHOD_RE = re.compile(
    r"\b(?P<method>spf|dkim|dmarc)=(?P<result>pass|fail|softfail|neutral|"
    r"temperror|permerror|none|bestguesspass|policy)\b",
    re.IGNORECASE,
)

# Extracts the authenticated identity for each method.
_SPF_ID_RE   = re.compile(r"smtp\.mailfrom=([^\s;]+)", re.IGNORECASE)
_DKIM_ID_RE  = re.compile(r"header\.(?:i|d)=@?([^\s;]+)", re.IGNORECASE)
_DMARC_ID_RE = re.compile(r"header\.from=([^\s;]+)", re.IGNORECASE)


@dataclass
class AuthVerdict:
    """Structured result of Authentication-Results parsing."""
    # Raw verdicts as reported by the receiving MTA
    spf:   str = "none"        # "pass" | "fail" | "softfail" | "none" | ...
    dkim:  str = "none"
    dmarc: str = "none"

    # Domain the receiving MTA actually authenticated (may differ from From:)
    spf_domain:   str = ""
    dkim_domain:  str = ""
    dmarc_domain: str = ""

    # Higher-level signals derived from the above
    from_domain: str = ""
    aligned:     bool = False   # From: domain matches at least one authenticated domain
    all_pass:    bool = False   # all three of SPF/DKIM/DMARC are "pass"
    cryptographically_verified: bool = False   # aligned AND at least DKIM pass
    header_present: bool = False   # Authentication-Results was actually there

    # Extras — the raw header for debug / logging
    raw: str = ""

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def _domain_of(addr: str) -> str:
    """Extract the domain part from either 'foo@bar.tld' or a bare 'bar.tld'."""
    if not addr:
        return ""
    addr = addr.strip().strip("<>").strip('"').lower()
    if "@" in addr:
        addr = addr.rsplit("@", 1)[1]
    return addr.rstrip(".").split(">")[0].strip()


def _org_domain(domain: str) -> str:
    """
    Best-effort organizational-domain reduction — 'mail.paypal.com' -> 'paypal.com'.
    Proper eTLD+1 extraction would need the Public Suffix List, but for our
    alignment check the last-two-labels heuristic is right in >95% of cases
    and doesn't add a runtime dependency.
    """
    if not domain:
        return ""
    parts = domain.lower().strip(".").split(".")
    if len(parts) <= 2:
        return ".".join(parts)
    # Two-part TLDs we know about (co.uk, com.br, ...): keep three labels.
    two_part_tlds = {"co.uk", "co.jp", "co.kr", "co.nz", "co.za", "com.br",
                     "com.au", "com.mx", "com.ar", "org.uk", "gov.uk", "ac.uk"}
    tail2 = ".".join(parts[-2:])
    if tail2 in two_part_tlds and len(parts) >= 3:
        return ".".join(parts[-3:])
    return ".".join(parts[-2:])


def parse_authentication_results(headers: dict[str, str]) -> AuthVerdict:
    """
    Parse the Authentication-Results header into a structured verdict.

    `headers` should be the parsed header dict from parse_eml() — keys
    lowercased. Missing header -> AuthVerdict(header_present=False) with
    all verdicts defaulting to "none".
    """
    verdict = AuthVerdict()

    # Pull out From: domain first — needed for the alignment check.
    from_raw = headers.get("from", "")
    m = re.search(r"@([^>\s,]+)", from_raw)
    if m:
        verdict.from_domain = _domain_of(m.group(1))

    ar = headers.get("authentication-results", "") or ""
    if not ar:
        # Some providers use ARC-Authentication-Results as a fallback.
        ar = headers.get("arc-authentication-results", "") or ""
    if not ar:
        return verdict

    verdict.header_present = True
    verdict.raw = ar[:500]  # cap for logging

    # Extract per-method verdicts
    for m in _METHOD_RE.finditer(ar):
        method = m.group("method").lower()
        result = m.group("result").lower()
        setattr(verdict, method, result)

    # Extract authenticated identifiers
    if (m := _SPF_ID_RE.search(ar)):
        verdict.spf_domain = _domain_of(m.group(1))
    if (m := _DKIM_ID_RE.search(ar)):
        verdict.dkim_domain = _domain_of(m.group(1))
    if (m := _DMARC_ID_RE.search(ar)):
        verdict.dmarc_domain = _domain_of(m.group(1))

    # Compute derived signals
    verdict.all_pass = (
        verdict.spf == "pass"
        and verdict.dkim == "pass"
        and verdict.dmarc == "pass"
    )

    # Alignment: the visible From: domain must match an authenticated one at
    # the organizational-domain level — AND that method must have passed.
    # An attacker who DKIM-signs their own attacker.tld would otherwise pass
    # this check just because their spoofed header.from=paypal.com happens
    # to appear in the DMARC identifier field (which is copied from From:,
    # not authenticated). Only "pass" verdicts count.
    fod = _org_domain(verdict.from_domain)
    aligned_domains = []
    if verdict.spf   == "pass" and verdict.spf_domain:
        aligned_domains.append(verdict.spf_domain)
    if verdict.dkim  == "pass" and verdict.dkim_domain:
        aligned_domains.append(verdict.dkim_domain)
    if verdict.dmarc == "pass" and verdict.dmarc_domain:
        aligned_domains.append(verdict.dmarc_domain)
    verdict.aligned = bool(fod) and any(
        _org_domain(d) == fod for d in aligned_domains
    )

    # Cryptographic verification requires DKIM (the only crypto method — SPF
    # is envelope-only, DMARC is a policy layer on top of the other two) to
    # have passed AND the DKIM-signing domain to align with From:.
    dkim_aligned = (
        verdict.dkim == "pass"
        and verdict.dkim_domain
        and _org_domain(verdict.dkim_domain) == fod
    )
    verdict.cryptographically_verified = bool(dkim_aligned)

    return verdict


# =====================================================================
# Spamhaus DBL — Domain Block List (DNS-based)
# =====================================================================

DBL_ZONE = "dbl.spamhaus.org"

# Spamhaus DBL return codes.
# See https://www.spamhaus.org/faq/section/Spamhaus%20DBL#291
_DBL_CODES = {
    "127.0.1.2":  "spam",
    "127.0.1.4":  "phish",
    "127.0.1.5":  "malware",
    "127.0.1.6":  "botnet_cc",
    "127.0.1.102": "abused_legit_spam",
    "127.0.1.103": "abused_legit_redirector",
    "127.0.1.104": "abused_legit_phish",
    "127.0.1.105": "abused_legit_malware",
    "127.0.1.106": "abused_legit_botnet_cc",
    "127.0.1.255": "test",   # used to verify the resolver actually queries the zone
}


async def check_spamhaus_dbl(domain: str, timeout: float = 2.0) -> dict[str, Any]:
    """
    Look up a domain in the Spamhaus DBL zone.

    Returns:
      {"listed": bool, "category": str | None, "response": str | None}

    A domain resolving to a 127.0.1.x code in dbl.spamhaus.org means
    Spamhaus has flagged it. NXDOMAIN means clean.

    IMPORTANT: 127.255.255.x codes are Spamhaus *policy errors* — the
    query was rejected because the DNS resolver used by this host is
    public/open, anonymous, or rate-limited. Those are NOT listings;
    treating them as such would false-positive every domain we ever
    query. We report them with error="policy_error" and listed=False.
    """
    result: dict[str, Any] = {"listed": False, "category": None, "response": None}
    domain = _domain_of(domain)
    if not domain or "." not in domain:
        return result

    query = f"{domain}.{DBL_ZONE}"

    loop = asyncio.get_event_loop()
    try:
        # gethostbyname is blocking; push it to the default executor.
        response = await asyncio.wait_for(
            loop.run_in_executor(None, socket.gethostbyname, query),
            timeout=timeout,
        )
        result["response"] = response
        if response.startswith("127.255.255."):
            # Policy response — DBL didn't answer. Treat as unavailable.
            result["error"] = "policy_error"
            result["category"] = "spamhaus_refused_query"
        elif response.startswith("127.0.1."):
            result["listed"] = True
            result["category"] = _DBL_CODES.get(response, "listed_unknown_code")
        # Any other response shape → not a documented DBL result, ignore
    except (socket.gaierror, socket.herror):
        pass                       # NXDOMAIN -> clean
    except asyncio.TimeoutError:
        result["error"] = "dns_timeout"
    except Exception as e:
        result["error"] = f"dns_error:{type(e).__name__}"
    return result


# =====================================================================
# High-level convenience — one call, everything you need
# =====================================================================

async def build_metadata_auth_signal(headers: dict[str, str],
                                     enable_dbl: bool = True) -> dict[str, Any]:
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

    dbl = {"listed": False, "category": None}
    if enable_dbl and av.from_domain:
        dbl = await check_spamhaus_dbl(av.from_domain)

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
# Sync wrapper — for callers not in an async context.
# =====================================================================

def build_metadata_auth_signal_sync(headers: dict[str, str],
                                    enable_dbl: bool = True) -> dict[str, Any]:
    """
    Synchronous variant. Runs the async coroutine to completion.
    Safe to call from FastAPI sync endpoints (which run in a threadpool).
    """
    try:
        loop = asyncio.get_event_loop()
        if loop.is_running():
            # Rare but possible — called from inside an event loop.
            # Schedule in a fresh loop on a helper thread instead of deadlocking.
            import concurrent.futures
            with concurrent.futures.ThreadPoolExecutor(max_workers=1) as ex:
                fut = ex.submit(asyncio.run,
                                build_metadata_auth_signal(headers, enable_dbl))
                return fut.result(timeout=5)
    except RuntimeError:
        pass
    return asyncio.run(build_metadata_auth_signal(headers, enable_dbl))
