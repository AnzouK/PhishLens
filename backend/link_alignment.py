"""
PhishLens: where an email's links go, compared with the sender's domain.

A bank's notification links to the bank. Phishing sent from an old or
hijacked domain that signs its own mail (the `crypto_verified` path)
usually links somewhere else. We measured this on the public benchmark
before using it (docs/evaluation.md). On that path, no link to the
sender's own domain, at least one link elsewhere and a text score of
0.5 or more separate the two.

Click-tracking links from bulk senders such as SendGrid or Mailchimp are
counted separately, because real companies send notifications through
them. Stylesheets and web fonts are not counted as links.
"""

from __future__ import annotations

import ipaddress
import re
import unicodedata
from urllib.parse import quote, unquote, urlsplit

from auth_headers import org_domain, sender_domain
from known_domains import CLOUD_FILE_HOSTS, USER_CONTENT_HOSTS, WELL_KNOWN

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


# A browser won't open a host that decodes to one of these
# ("evil.tk%40paypal.com"), so we leave it as written.
_FORBIDDEN_IN_HOST = frozenset("/\\?#@[]% :")


def browser_url(url: str) -> str:
    """Normalise an http(s) URL the way a browser reads it.

    Browsers accept "HTTPS:\\\\evil.tk" and "https:evil.tk", treat
    backslashes as slashes, and percent-decode and NFKC-fold the host.
    They also read ideographic dots as dots and ignore a trailing dot, so
    "https://%65vil.tk", "https://evil\u3002tk" and "https://evil.tk." all
    open evil.tk. Brackets in a "user@" part are encoded. A host that
    decodes to something no browser opens is left as written, and
    non-http input is returned unchanged.
    """
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
    # Percent-encode like browsers do. Python rejects characters such as
    # "\u2105" (c/o under NFKC), and its fallback would then pick the host
    # after a later "@" ("https://\u2105@evil.tk#@paypal.com").
    userinfo = quote(userinfo, safe="!$&'()*+,;=:%")
    host, port = _split_port(hostport)
    if not host.startswith("["):
        decoded = unicodedata.normalize("NFKC", unquote(host)).translate(_DOTS)
        if not _FORBIDDEN_IN_HOST.intersection(decoded):
            host = decoded
        host = host.lower().rstrip(".")
    return f"{m.group(1).lower()}://{userinfo}{at}{host}{port}{'/' if sep else ''}{tail}"


def _split_port(hostport: str) -> tuple[str, str]:
    """Split "host:port" into ("host", ":port").

    An empty port is dropped and an IPv6 literal keeps its brackets.
    """
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
    """Return the "user@host:port" part, up to the first "/", "?" or "#"."""
    return re.split(r"[/\\?#]", url.split("://", 1)[-1], maxsplit=1)[0]


def link_host(url: str) -> str:
    """Return the host a browser would connect to.

    The "user:password@" part is skipped, so https://paypal.com:443@evil.example/
    goes to evil.example. https://evil.tk?login and https://evil.tk./ both
    go to evil.tk.
    """
    url = browser_url(url)
    try:
        host = urlsplit(url if "://" in url else "http://" + url).hostname or ""
    except ValueError:
        # Python rejects hosts like "evil.tk\uff20paypal.com". Keep it as
        # written so the link still counts as going somewhere unknown.
        authority = authority_of(url)
        host = _split_port(authority.rpartition("@")[2])[0]
    return host.lower().rstrip(".")


_host = link_host


def ip_host(host: str) -> bool:
    """Return the IP address used as host, in any form a browser accepts.

    Besides dotted and IPv6 forms, browsers take a single decimal, octal or
    hex number, so http://3232235777/ is 192.168.1.1.
    """
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
    """Return True for hosts where anyone can publish, like storage.googleapis.com or *.web.app."""
    host = link_host(url)
    return any(host == h or host.endswith("." + h) for h in CLOUD_FILE_HOSTS)


# A second address inside a link, after decoding the path, query and
# fragment twice ("%253A" is ":"). It can be a scheme with any number of
# slashes, two slashes in a row ("?q=//evil.tk"), or a parameter starting
# with "www." that redirectors complete. Google's AMP viewer takes the
# address in its path ("/amp/s/evil.tk/...").
_EMBEDDED_URL_RE = re.compile(
    r"https?:|[/\\]{2}|[=?&#]\s*www\.[\w-]+\."
    r"|^/amp/(?:s/)?[\w-]+(?:\.[\w-]+)+"
    # Paths that always redirect, whatever the target looks like
    # ("/url?q=evil.tk", "/redirect?q=...", "/l.php?u=...").
    r"|^/(?:url|redirect|l\.php|slink|linkredirect|iclouddrive|safe_redirect|away)(?:[/?#.]|$)",
    re.IGNORECASE,
)


def browser_path(path: str) -> str:
    """Return the path the browser actually requests.

    Encoded dots and slashes are decoded, backslashes become "/", and "."
    and ".." segments are resolved, so "/a/../url" is "/url".
    """
    path = unquote(path or "/").replace("\\", "/")
    out: list[str] = []
    # Drop empty segments so they can't absorb a "..".
    for seg in path.split("/"):
        if not seg or seg == ".":
            continue
        if seg == "..":
            if out:
                out.pop()
            continue
        out.append(seg)
    trailing = "/" if path.endswith(("/.", "/..")) and out else ""
    return "/" + "/".join(out) + trailing


def well_known_link(url: str) -> bool:
    """Return True for a link to a large known site that carries no second address.

    An open redirect like ...?url=https://elsewhere doesn't count as known.
    """
    url = browser_url(url)
    host = link_host(url)
    if not host or on_cloud_file_host(url):
        return False
    if any(host == h or host.endswith("." + h) for h in USER_CONTENT_HOSTS):
        return False
    try:
        parts = urlsplit(url if "://" in url else "http://" + url)
    except ValueError:
        return False
    rest = f"{browser_path(parts.path)}?{parts.query}#{parts.fragment}"
    for _ in range(2):
        rest = unquote(rest)
    if _EMBEDDED_URL_RE.search(rest):
        return False
    return host in WELL_KNOWN or org_domain(host) in WELL_KNOWN


def link_profile(urls: list[str], from_header: str) -> dict[str, int]:
    """Count distinct links by where they go.

    The buckets are the sender's own domain ("aligned"), large known sites,
    public file hosts, click tracking and everything else.
    """
    domain = sender_domain(from_header or "")
    own = org_domain(domain) if domain else ""
    counts = {"links": 0, "aligned": 0, "well_known": 0, "cloud": 0, "tracking": 0, "other": 0}
    for url in dict.fromkeys(urls):
        host = _host(url)
        # Only real links reach this point, so a path ending in ".css" is not
        # skipped as an asset. Otherwise appending "#.css" would hide a
        # phishing page from the link rule.
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
            # A redirect through a known site is not known.
            counts["well_known"] += 1
        else:
            counts["other"] += 1
    return counts


def links_elsewhere_only(counts: dict[str, int]) -> bool:
    """Return True when the links lead away from the sender.

    That is no link to the sender's domain and at least one to an unknown
    site, ignoring click tracking and known sites. Any link to a public
    file host also counts, so one decoy link to the sender's domain can't
    hide it. On the benchmark that second rule changed no verdict (L50EC
    in simulate_fusion), so it closes the bypass at no measured cost.
    """
    if counts["cloud"] > 0:
        return True
    return counts["aligned"] == 0 and counts["other"] > 0
