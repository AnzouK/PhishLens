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

import ipaddress
import re
import unicodedata
from email.utils import parseaddr
from urllib.parse import quote, unquote, urlsplit

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


_SPECIAL_SCHEME_RE = re.compile(r"^\s*(https?):[/\\]*", re.IGNORECASE)
_DOTS = str.maketrans({"\u3002": ".", "\uff0e": ".", "\uff61": "."})


# A host that contains one of these after decoding is not one a browser
# opens ("evil.tk%40paypal.com"): it is left as written.
_FORBIDDEN_IN_HOST = frozenset("/\\?#@[]% :")


def browser_url(url: str) -> str:
    """An http(s) address as a browser reads it: the scheme in lower case
    with "//" after it however many slashes or backslashes were written
    ("HTTPS:\\\\evil.tk", "https:evil.tk"), backslashes as slashes, brackets
    in a "user@" part encoded, and the host percent-decoded, in
    compatibility form, with ideographic dots as dots and no final dot
    ("https://%65vil.tk", "https://evil\u3002tk", "https://evil.tk."). A
    host that decodes to something no browser opens is left as written.
    Anything else is returned as it is."""
    m = _SPECIAL_SCHEME_RE.match(url)
    if not m:
        return url
    rest = url[m.end() :].replace("\\", "/")
    authority, sep, tail = rest.partition("/")
    for mark in ("?", "#"):
        if mark in authority:
            authority, extra = authority.split(mark, 1)
            tail, sep = mark + extra + sep + tail, ""
    userinfo, at, hostport = authority.rpartition("@")
    # Percent-encoded as browsers do: a character such as "\u2105" (c/o
    # under NFKC) made Python refuse the address, and the fallback read
    # the host after a later "@" ("https://\u2105@evil.tk#@paypal.com").
    userinfo = quote(userinfo, safe="!$&'()*+,;=:%")
    host, port = _split_port(hostport)
    if not host.startswith("["):
        decoded = unicodedata.normalize("NFKC", unquote(host)).translate(_DOTS)
        if not _FORBIDDEN_IN_HOST.intersection(decoded):
            host = decoded
        host = host.lower().rstrip(".")
    return f"{m.group(1).lower()}://{userinfo}{at}{host}{port}{'/' if sep else ''}{tail}"


def _split_port(hostport: str) -> tuple[str, str]:
    """("host", ":port") of "host:port"; an empty port is dropped, an
    IPv6 literal keeps its brackets."""
    if hostport.startswith("["):
        end = hostport.find("]")
        if end > 0:
            port = hostport[end + 1 :]
            return hostport[: end + 1], port if port[1:].isdigit() else ""
    host, colon, port = hostport.rpartition(":")
    if colon and (port.isdigit() or not port):
        return host, (":" + port) if port else ""
    return hostport, ""


def authority_of(url: str) -> str:
    """The "user@host:port" part of an address: up to the first "/", "?"
    or "#" after the scheme."""
    return re.split(r"[/\\?#]", url.split("://", 1)[-1], maxsplit=1)[0]


def link_host(url: str) -> str:
    """Host name of a link as a browser reads it (browser_url), after any
    "user:password@" part: in https://paypal.com:443@evil.example/ the
    host is evil.example; in https://evil.tk?login it is evil.tk; in
    https://evil.tk./ it is evil.tk."""
    url = browser_url(url)
    try:
        host = urlsplit(url if "://" in url else "http://" + url).hostname or ""
    except ValueError:
        # Not a host Python accepts ("evil.tk\uff20paypal.com"): read it as
        # written, so the link still counts as one going somewhere unknown.
        authority = authority_of(url)
        host = _split_port(authority.rpartition("@")[2])[0]
    return host.lower().rstrip(".")


_host = link_host


def ip_host(host: str) -> bool:
    """An IP address as host, in any form a browser accepts: dotted,
    IPv6, or a single number (http://3232235777/ is 192.168.1.1),
    decimal, octal or hexadecimal."""
    if not host:
        return False
    host = host.strip("[]").rstrip(".")
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        pass
    parts = host.split(".")
    return 1 <= len(parts) <= 4 and all(_ip_number(p) for p in parts)


def _ip_number(part: str) -> bool:
    if part[:2] in ("0x", "0X"):
        return len(part) > 2 and all(c in "0123456789abcdefABCDEF" for c in part[2:])
    return part.isdigit()


def on_cloud_file_host(url: str) -> bool:
    """The link points to storage or a page anyone can publish
    (storage.googleapis.com, *.web.app, *.r2.dev...)."""
    host = link_host(url)
    return any(host == h or host.endswith("." + h) for h in CLOUD_FILE_HOSTS)


# "://" or "=//" after the host, also percent-encoded once or twice or
# with backslashes: an address carried inside the link ("?q=//evil.example"
# is a protocol-relative one).
# Another address carried by a link, once its path, query and fragment
# are decoded (twice: "%253A" is ":"): a scheme ("https:" with any number
# of slashes, browsers accept "https:evil.tk"), or two slashes in a row
# ("?q=//evil.tk", "?q=+//evil.tk", backslashes too). Google's AMP viewer
# ("/amp/s/evil.tk/...") takes the address in its path.
_EMBEDDED_URL_RE = re.compile(r"https?:|[/\\]{2}|^/amp/(?:s/)?[\w-]+(?:\.[\w-]+)+", re.IGNORECASE)


def well_known_link(url: str) -> bool:
    """The link goes to a large, known site and carries no other address
    (an open redirect such as ...?url=https://elsewhere is not known)."""
    url = browser_url(url)
    host = link_host(url)
    if not host or on_cloud_file_host(url):
        return False
    try:
        parts = urlsplit(url if "://" in url else "http://" + url)
    except ValueError:
        return False
    rest = f"{parts.path}?{parts.query}#{parts.fragment}"
    for _ in range(2):
        rest = unquote(rest)
    if _EMBEDDED_URL_RE.search(rest):
        return False
    return host in WELL_KNOWN or org_domain(host) in WELL_KNOWN


def link_profile(urls: list[str], from_header: str) -> dict[str, int]:
    """Counts of distinct links: to the sender's own organisational domain
    ("aligned"), to large known sites, to public file hosts, through
    click tracking, elsewhere."""
    sender = parseaddr(from_header or "")[1]
    own = org_domain(sender.rsplit("@", 1)[-1]) if "@" in sender else ""
    counts = {"links": 0, "aligned": 0, "well_known": 0, "cloud": 0, "tracking": 0, "other": 0}
    for url in dict.fromkeys(urls):
        host = _host(url)
        # Only links reach here (<a>, <area>, addresses in the text): a
        # path ending in ".css" was once skipped, and "#.css" after a
        # phishing page hid it from the link rule.
        if not host or host in ASSET_HOSTS:
            continue
        org = org_domain(host)
        counts["links"] += 1
        if own and org == own:
            counts["aligned"] += 1
        elif org in TRACKING:
            counts["tracking"] += 1
        elif on_cloud_file_host(url):
            counts["cloud"] += 1
        elif well_known_link(url):
            # A known site's redirect to another address is not known.
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
