"""
Who sent the email, and can we believe it.

- sender_domain(): the domain of a From: value.
- is_trusted_domain(): allowlist match (trusted_domains.py). The caller
  applies it only to an authenticated sender.
- synthesize_auth_results(): an Authentication-Results header built from
  the "signed-by" / "mailed-by" values Gmail shows, so auth_headers can
  check alignment the same way as for real headers.
"""
from __future__ import annotations

import re
from typing import Any

from trusted_domains import TRUSTED_DOMAINS

try:
    from auth_headers import org_domain
except Exception:                       # auth_headers missing: strict fallback
    def org_domain(d: str) -> str:
        return (d or "").lower().strip(".")

_HOST_CHARS = set("abcdefghijklmnopqrstuvwxyz0123456789-")


def sender_domain(value: str) -> str | None:
    """Domain of a bare address or a 'Name <addr@domain>' header."""
    if not value:
        return None
    m = re.search(r"@([A-Za-z0-9.\-_]+)", value)
    if not m:
        return None
    return m.group(1).lower().rstrip(".") or None


def is_trusted_domain(domain: str | None) -> bool:
    """The domain or one of its parents is allowlisted."""
    if not domain:
        return False
    d = domain.lower()
    return d in TRUSTED_DOMAINS or any(d.endswith("." + td) for td in TRUSTED_DOMAINS)


def is_hostname(name: str) -> bool:
    """A DNS hostname with at least two labels, checked without a regex
    (linear on any input)."""
    labels = name.split(".")
    return (0 < len(name) <= 253 and len(labels) >= 2
            and all(0 < len(lab) <= 63 and set(lab) <= _HOST_CHARS for lab in labels))


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
    signed_by = (ctx.get("gmail_signed_by") or "").strip().lower()
    mailed_by = (ctx.get("gmail_mailed_by") or "").strip().lower()
    via = (ctx.get("gmail_via") or "").strip().lower()
    if not (signed_by or mailed_by or via):
        return ""

    m = re.search(r"@([^>\s,]+)", (sender_email or "").strip())
    from_domain = m.group(1).lower() if m else ""

    parts = ["gmail-client-context;"]
    if signed_by:
        parts.append(f"dkim=pass header.i=@{signed_by}")
    if mailed_by or via:
        parts.append(f"spf=pass smtp.mailfrom={mailed_by or via}")
    if signed_by and from_domain and org_domain(signed_by) == org_domain(from_domain):
        parts.append(f"dmarc=pass header.from={from_domain}")
    return " ".join(parts)
