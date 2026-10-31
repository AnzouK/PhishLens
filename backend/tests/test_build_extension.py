"""The browser-specific extension zips (scripts/build_extension.py)."""

import json
import sys
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts"))
import build_extension as be  # noqa: E402

# The data types Firefox accepts in data_collection_permissions.
FIREFOX_TYPES = {
    "none",
    "authenticationInfo",
    "bookmarksInfo",
    "browsingActivity",
    "financialAndPaymentInfo",
    "healthInfo",
    "locationInfo",
    "personalCommunications",
    "personallyIdentifyingInfo",
    "searchTerms",
    "technicalAndInteraction",
    "websiteActivity",
    "websiteContent",
}


def _manifest(path):
    with zipfile.ZipFile(path) as z:
        return json.loads(z.read("manifest.json")), set(z.namelist())


def test_chrome_zip_is_the_extension_folder(tmp_path):
    be.build("chrome", tmp_path / "c.zip")
    manifest, names = _manifest(tmp_path / "c.zip")
    assert manifest == json.loads((be.EXT / "manifest.json").read_text())
    assert "background.js" in names and not any(n.endswith(".DS_Store") for n in names)


def test_firefox_zip_runs_the_background_as_an_event_page(tmp_path):
    be.build("firefox", tmp_path / "f.zip")
    manifest, names = _manifest(tmp_path / "f.zip")
    scripts = manifest["background"]["scripts"]
    assert "service_worker" not in manifest["background"]
    assert scripts[-1] == "background.js" and "lib/i18n.js" in scripts
    assert all(s in names for s in scripts)
    gecko = manifest["browser_specific_settings"]["gecko"]
    assert gecko["id"] == "phishlens@phishlens.dev"  # never change once published
    data = gecko["data_collection_permissions"]
    assert set(data["required"]) | set(data["optional"]) <= FIREFOX_TYPES
    # Everything else is the Chrome manifest.
    chrome = json.loads((be.EXT / "manifest.json").read_text())
    for key in ("permissions", "host_permissions", "content_scripts", "version", "action"):
        assert manifest[key] == chrome[key]
