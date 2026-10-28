"""The website's translations carry the same figures as the English
page: a benchmark update must reach every language."""

import json
import re
from pathlib import Path

import pytest

STRINGS = Path(__file__).resolve().parents[2] / "site-src" / "strings"
# 1,812 / 1.812 / 1 812 (thousands), 90.6 / 90,6 (decimals), plain numbers.
NUMBER = re.compile("\\d{1,3}(?:[.,\u00a0\u202f ]\\d{3})+(?!\\d)|\\d+(?:[.,]\\d+)?")


def figures(text: str) -> list[str]:
    """The numbers of a text, separators left out ("1,812" and "1 812" agree)."""
    return sorted(re.sub(r"\D", "", n) for n in NUMBER.findall(re.sub(r"<[^>]*>", " ", text)))


EN = json.loads((STRINGS / "en.json").read_text(encoding="utf-8"))


@pytest.mark.parametrize(
    "path", sorted(p for p in STRINGS.glob("*.json") if p.stem != "en"), ids=lambda p: p.stem
)
def test_translations_have_the_english_figures(path):
    other = json.loads(path.read_text(encoding="utf-8"))
    assert other.keys() == EN.keys()
    differ = [k for k in EN if figures(EN[k]) != figures(other[k])]
    assert differ == [], f"{path.name}: figures differ from en.json in {differ}"
