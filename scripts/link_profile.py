"""Where an email's links go, compared with its sender's domain, for
`benchmark.py --link-profile`: the backend's own counting
(backend/link_alignment.py) on a raw email. Only counts are kept, never
a domain or a link."""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "backend"))
from email_parsing import parse_eml  # noqa: E402
from link_alignment import ASSET_HOSTS, TRACKING, link_profile  # noqa: E402, F401


def profile(raw: bytes) -> dict[str, int]:
    _body, urls, headers = parse_eml(raw)
    return link_profile(urls, headers.get("from", ""))
