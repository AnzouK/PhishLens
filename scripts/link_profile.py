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

# Click-tracking hosts of mass-mailing platforms: a legitimate company's
# notification often links only through them (u123.ct.sendgrid.net), and
# so can phishing sent through a hijacked account. Counted apart.
TRACKING = frozenset(
    [
        "sendgrid.net",
        "list-manage.com",
        "mailchi.mp",
        "hubspotlinks.com",
        "hubspotemail.net",
        "mandrillapp.com",
        "sparkpostmail.com",
        "awstrack.me",
        "mailgun.org",
        "klclick.com",
        "klclick1.com",
        "sendibt2.com",
        "sendibm1.com",
        "mjt.lu",
        "cmail19.com",
        "cmail20.com",
        "rs6.net",
    ]
)
# Not links a reader clicks: style sheets and web fonts (<link href=...>).
ASSET_HOSTS = frozenset({"fonts.googleapis.com", "fonts.gstatic.com"})


def _host(url: str) -> str:
    return url.split("://", 1)[-1].split("/", 1)[0].split("?", 1)[0].split(":", 1)[0].lower()


def profile(raw: bytes) -> dict[str, int]:
    """Counts of distinct links: to the sender's own organisational domain
    ("aligned"), to large known sites, to public file hosts, through a
    mass-mailing platform's click tracking, elsewhere. Style sheets and
    web fonts are not counted."""
    _body, urls, headers = parse_eml(raw)
    sender = parseaddr(headers.get("from", ""))[1]
    own = org_domain(sender.rsplit("@", 1)[-1]) if "@" in sender else ""
    counts = {"links": 0, "aligned": 0, "well_known": 0, "cloud": 0, "tracking": 0, "other": 0}
    for url in dict.fromkeys(urls):
        host = _host(url)
        if not host or host in ASSET_HOSTS or url.split("?", 1)[0].lower().endswith(".css"):
            continue
        org = org_domain(host)
        counts["links"] += 1
        if own and org == own:
            counts["aligned"] += 1
        elif org in TRACKING:
            counts["tracking"] += 1
        elif any(host == h or host.endswith("." + h) for h in CLOUD_FILE_HOSTS):
            counts["cloud"] += 1
        elif host in WELL_KNOWN or org in WELL_KNOWN:
            counts["well_known"] += 1
        else:
            counts["other"] += 1
    return counts
