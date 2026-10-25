"""scripts/build_site.py: the schema.org block of the home pages."""

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "scripts"))
import build_site as bs  # noqa: E402


def test_jsonld_describes_a_free_chrome_extension_in_every_language():
    strings = bs.load_strings()
    for lang in bs.LANGS:
        block = bs.jsonld(lang, strings[lang])
        body = block.split("\n", 1)[1].rsplit("\n", 1)[0]
        assert "<" not in body
        data = json.loads(body)
        assert data["@type"] == "SoftwareApplication"
        assert data["offers"]["price"] == "0" and data["isAccessibleForFree"] is True
        assert data["url"] == bs.url(lang, "index.html")
        assert "author" not in data  # no personal name in public pages
