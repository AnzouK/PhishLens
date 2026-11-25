"""Links to a heading of README.md or of a doc page point at a heading
that exists. GitHub builds the anchor from the heading text, so renaming
a heading silently breaks the links in the popup, the website and the
release notes."""

import re
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
SKIP_DIRS = {".git", "node_modules", ".venv", "venv", "__pycache__", ".pytest_cache"}
SUFFIXES = {".md", ".html", ".js", ".mjs", ".json", ".yml", ".yaml", ".py", ".txt"}
REPO = "https://github.com/AnzouK/PhishLens"
# README itself, or a file on the main branch.
REPO_LINK = re.compile(re.escape(REPO) + r"(?:/blob/main/([\w./-]+\.md))?#([\w-]+)")
# Relative links between Markdown files: [text](docs/x.md#anchor).
RELATIVE_LINK = re.compile(r"\]\(((?!https?:)[\w./-]+\.md)#([\w-]+)\)")


def slug(heading: str) -> str:
    """GitHub's anchor for a heading: lower case, punctuation dropped,
    spaces turned into hyphens."""
    text = re.sub(r"\[([^\]]*)\]\([^)]*\)", r"\1", heading)
    text = re.sub(r"[^\w\- ]", "", text.strip().lower())
    return text.replace(" ", "-")


def anchors(path: Path) -> set[str]:
    found: set[str] = set()
    seen: dict[str, int] = {}
    fenced = False
    for line in path.read_text(encoding="utf-8").splitlines():
        if line.lstrip().startswith("```"):
            fenced = not fenced
            continue
        match = re.match(r"#{1,6}\s+(.*?)\s*#*\s*$", line)
        if fenced or not match:
            continue
        base = slug(match.group(1))
        count = seen.get(base, 0)
        seen[base] = count + 1
        found.add(base if count == 0 else f"{base}-{count}")
    return found


def unreleased_only(text: str) -> str:
    """The changelog's released entries keep the links of their day."""
    start = text.find("## [Unreleased]")
    if start < 0:
        return ""
    end = text.find("\n## [", start + 1)
    return text[start:] if end < 0 else text[start:end]


def scanned_files():
    for path in sorted(ROOT.rglob("*")):
        if path.suffix not in SUFFIXES or not path.is_file():
            continue
        if SKIP_DIRS.intersection(path.relative_to(ROOT).parts):
            continue
        yield path


def links():
    for path in scanned_files():
        text = path.read_text(encoding="utf-8", errors="replace")
        if path.name == "CHANGELOG.md":
            text = unreleased_only(text)
        for target, anchor in REPO_LINK.findall(text):
            yield path, ROOT / (target or "README.md"), anchor
        if path.suffix == ".md":
            for target, anchor in RELATIVE_LINK.findall(text):
                yield path, (path.parent / target).resolve(), anchor


LINKS = sorted(set(links()))


def test_some_links_are_checked():
    assert any(target.name == "README.md" for _, target, _ in LINKS)


@pytest.mark.parametrize(
    ("source", "target", "anchor"),
    LINKS,
    ids=[f"{s.relative_to(ROOT)}->{t.name}#{a}" for s, t, a in LINKS],
)
def test_anchor_exists(source, target, anchor):
    assert target.is_file(), f"{source.relative_to(ROOT)} links to missing {target}"
    assert anchor in anchors(target), (
        f"{source.relative_to(ROOT)} links to {target.relative_to(ROOT)}#{anchor}, "
        "which is not a heading there"
    )
