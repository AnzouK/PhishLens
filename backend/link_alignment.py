"""
Where an email's links go, compared with its sender's domain.

A bank's notification links to the bank; phishing sent from an old or
hijacked domain that signs its own mail (the `crypto_verified` path)
usually links somewhere else. Measured on the public benchmark before
use (docs/evaluation.md): on that path, no link to the sender's own
domain plus at least one elsewhere, with a text score of 0.5 or more,
separates the two.

Links through a mass-mailing platform's click tracking (SendGrid,
Mailchimp...) are counted apart: legitimate companies send their
notifications through them. Style sheets and web fonts are not links.
"""

from __future__ import annotations

from email.utils import parseaddr
from urllib.parse import urlsplit

from auth_headers import org_domain
from known_domains import CLOUD_FILE_HOSTS, WELL_KNOWN

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
        "email-messaging.com",
    ]
)
ASSET_HOSTS = frozenset({"fonts.googleapis.com", "fonts.gstatic.com"})


def _host(url: str) -> str:
    """Host name of a link, after any "user:password@" part: in
    https://paypal.com:443@evil.example/ the host is evil.example."""
    try:
        return (urlsplit(url if "://" in url else "http://" + url).hostname or "").lower()
    except ValueError:
        return ""


def link_profile(urls: list[str], from_header: str) -> dict[str, int]:
    """Counts of distinct links: to the sender's own organisational domain
    ("aligned"), to large known sites, to public file hosts, through
    click tracking, elsewhere."""
    sender = parseaddr(from_header or "")[1]
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


def links_elsewhere_only(counts: dict[str, int]) -> bool:
    """No link to the sender's own domain and at least one to an unknown
    site (click tracking and known sites aside), or any link to a public
    file host: one decoy link to the sender's own domain must not hide
    it. On the benchmark the second part changed no verdict (L50EC in
    simulate_fusion), so it closes the bypass at no measured cost."""
    if counts["cloud"] > 0:
        return True
    return counts["aligned"] == 0 and counts["other"] > 0
