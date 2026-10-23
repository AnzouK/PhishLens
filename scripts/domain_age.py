"""Age of the sender's domain when an email was sent, from RDAP.

Used by `benchmark.py --domain-age` to measure, before anything ships,
whether a young domain separates phishing from legitimate mail on the
`crypto_verified` path (phishing DKIM-signed by the attacker's own
domain). Runs on the machine running the benchmark: only organisational
domain names go to rdap.org, nothing goes to the PhishLens server.

Lookups are kept in a local JSON file (domain -> registration date), so
each domain is asked once. That file lists sender domains: keep it
private, it is not part of the publishable results.

Standard library only.
"""

from __future__ import annotations

import json
import sys
import time
import urllib.error
import urllib.request
from datetime import date, datetime, timezone
from email import message_from_bytes, policy
from email.utils import parseaddr
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "backend"))
from auth_headers import org_domain  # noqa: E402

RDAP = "https://rdap.org/domain/"
UNKNOWN = "unknown"


def sender_org_domain(raw: bytes) -> str:
    try:
        msg = message_from_bytes(raw[:200_000], policy=policy.compat32)
        addr = parseaddr(str(msg.get("from", "")))[1]
    except Exception:
        return ""
    domain = addr.rsplit("@", 1)[-1].lower() if "@" in addr else ""
    return org_domain(domain)


def registration_date(rdap: dict) -> str | None:
    """The "registration" event of an RDAP domain answer, as YYYY-MM-DD."""
    for event in rdap.get("events") or []:
        if str(event.get("eventAction", "")).lower() == "registration":
            when = str(event.get("eventDate", ""))[:10]
            try:
                date.fromisoformat(when)
            except ValueError:
                return None
            return when
    return None


def lookup(domain: str, timeout: float = 10) -> str:
    """Registration date of `domain`, or UNKNOWN."""
    req = urllib.request.Request(
        RDAP + domain,
        headers={"Accept": "application/rdap+json", "User-Agent": "PhishLens-benchmark"},
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return registration_date(json.loads(r.read())) or UNKNOWN
    except (urllib.error.URLError, TimeoutError, ValueError, OSError):
        return UNKNOWN


class DomainAges:
    """Registration dates, looked up once per domain and kept on disk."""

    def __init__(self, path: Path, fetch=lookup, pause: float = 0.5):
        self.path, self.fetch, self.pause = path, fetch, pause
        self.known: dict[str, str] = {}
        if path.exists():
            self.known = json.loads(path.read_text(encoding="utf-8"))

    def registered(self, domain: str) -> str:
        if domain not in self.known:
            self.known[domain] = self.fetch(domain)
            self.path.write_text(json.dumps(self.known, indent=0), encoding="utf-8")
            if self.pause:
                time.sleep(self.pause)
        return self.known[domain]

    def age_days(self, raw: bytes, sent: datetime | None) -> int | None:
        """Days between the domain's registration and the email's date
        (today when the email has none); None when unknown."""
        domain = sender_org_domain(raw)
        if not domain:
            return None
        when = self.registered(domain)
        if when == UNKNOWN:
            return None
        sent_day = (sent or datetime.now(timezone.utc)).date()
        return max(0, (sent_day - date.fromisoformat(when)).days)
