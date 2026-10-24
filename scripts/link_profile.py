"""Where an email's links go, compared with its sender's domain.

Used by `benchmark.py --link-profile` to measure, before anything ships,
whether phishing DKIM-signed by the attacker's own domain can be told
from legitimate signed mail by its links: a bank's notification links
to the bank, a phishing email sent from an old or compromised domain
usually links somewhere else. Only counts are kept, never a domain or a
link. Standard library only (plus the backend's own parsing helpers).
"""

from __future__ import annotations

import sys
from email.utils import parseaddr
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "backend"))
from auth_headers import org_domain  # noqa: E402
from email_parsing import parse_eml  # noqa: E402
from known_domains import CLOUD_FILE_HOSTS, WELL_KNOWN  # noqa: E402


def _host(url: str) -> str:
    return url.split("://", 1)[-1].split("/", 1)[0].split("?", 1)[0].split(":", 1)[0].lower()


def profile(raw: bytes) -> dict[str, int]:
    """Counts of distinct links: to the sender's own organisational domain
    ("aligned"), to large known sites, to public file hosts, elsewhere."""
    _body, urls, headers = parse_eml(raw)
    sender = parseaddr(headers.get("from", ""))[1]
    own = org_domain(sender.rsplit("@", 1)[-1]) if "@" in sender else ""
    counts = {"links": 0, "aligned": 0, "well_known": 0, "cloud": 0, "other": 0}
    for url in dict.fromkeys(urls):
        host = _host(url)
        if not host:
            continue
        org = org_domain(host)
        counts["links"] += 1
        if own and org == own:
            counts["aligned"] += 1
        elif any(host == h or host.endswith("." + h) for h in CLOUD_FILE_HOSTS):
            counts["cloud"] += 1
        elif host in WELL_KNOWN or org in WELL_KNOWN:
            counts["well_known"] += 1
        else:
            counts["other"] += 1
    return counts
