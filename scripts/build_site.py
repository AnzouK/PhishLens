#!/usr/bin/env python3
"""Build the website in every language from site-src/ (needs pandoc).
Run from the repository root:

    python3 scripts/build_site.py

Sources
    site-src/index.html           home page template ({{key}} = a string)
    site-src/strings/<lang>.json  every text of the site, per language
    PRIVACY.md, TERMS.md          legal pages, English (the reference)
    site-src/legal/<lang>/*.md    their translations

Output (in site/, deployed as is)
    index.html, privacy.html, terms.html, 404.html   English, at the root
    <lang>/index.html, privacy.html, terms.html      the other languages
    i18n/<lang>.js                                   texts used by app.js
    redact.js                                        copy of extension/lib/redact.js
    sitemap.xml                                      every page, with hreflang

A {{key}} ending in _html is inserted as is; any other is HTML-escaped.
"""

from __future__ import annotations

import hashlib
import html
import json
import re
import shutil
import subprocess
from datetime import date
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SRC = ROOT / "site-src"
OUT = ROOT / "site"
SITE = "https://phishlens.dev"
GITHUB = "https://github.com/AnzouK/PhishLens/blob/main/"

# Native names, in the order of the language menu.
LANGS = {
    "en": "English",
    "fr": "Français",
    "pt": "Português",
    "es": "Español",
    "de": "Deutsch",
    "it": "Italiano",
    "nl": "Nederlands",
    "ha": "Hausa",
}
OG_LOCALE = {
    "en": "en_US",
    "fr": "fr_FR",
    "pt": "pt_PT",
    "es": "es_ES",
    "de": "de_DE",
    "it": "it_IT",
    "nl": "nl_NL",
    "ha": "ha_NG",
}
PAGES = ("index.html", "privacy.html", "terms.html")


def esc(text: str) -> str:
    """HTML-escape for text and double-quoted attributes (apostrophes stay)."""
    return html.escape(text, quote=False).replace('"', "&quot;")


def load_strings() -> dict[str, dict[str, str]]:
    strings = {lang: json.loads((SRC / "strings" / f"{lang}.json").read_text()) for lang in LANGS}
    missing = {lang: sorted(set(strings["en"]) - set(s)) for lang, s in strings.items()}
    missing = {k: v for k, v in missing.items() if v}
    if missing:
        raise SystemExit(f"missing strings: {missing}")
    return strings


def prefix(lang: str) -> str:
    """Folder of a language, relative to the site root."""
    return "" if lang == "en" else f"{lang}/"


def url(lang: str, page: str) -> str:
    return f"{SITE}/{prefix(lang)}{'' if page == 'index.html' else page}"


def link(base: str, lang: str, page: str) -> str:
    """Link from a page whose root is `base` to `page` in `lang`."""
    target = base + prefix(lang) + ("" if page == "index.html" else page)
    return target or "./"


def fill(text: str, s: dict[str, str], **extra: str) -> str:
    def sub(m: re.Match) -> str:
        key = m.group(1)
        if key in extra:
            return extra[key]
        value = s[key]
        return value if key.endswith("_html") else esc(value)

    return re.sub(r"\{\{(\w+)\}\}", sub, text)


def jsonld(lang: str, s: dict[str, str]) -> str:
    """schema.org description of the extension for search engines: a free,
    open-source security application for Chrome. No author name, and no
    version number: the committed site is not rebuilt at each release."""
    data = {
        "@context": "https://schema.org",
        "@type": "SoftwareApplication",
        "name": "PhishLens",
        "url": url(lang, "index.html"),
        "description": s["meta_desc"],
        "applicationCategory": "SecurityApplication",
        "operatingSystem": "Chrome",
        "browserRequirements": "Google Chrome, with Gmail or Outlook on the web",
        "inLanguage": lang,
        "availableLanguage": list(LANGS),
        "isAccessibleForFree": True,
        "offers": {"@type": "Offer", "price": "0", "priceCurrency": "USD"},
        "license": "https://www.gnu.org/licenses/agpl-3.0.html",
        "downloadUrl": "https://github.com/AnzouK/PhishLens/releases/latest",
        "image": f"{SITE}/{asset('', 'img/og.png')}",
        "sameAs": ["https://github.com/AnzouK/PhishLens"],
    }
    # "<" escaped so that no text can close the script element.
    body = json.dumps(data, ensure_ascii=False, indent=1).replace("<", "\\u003c")
    return f'<script type="application/ld+json">\n{body}\n</script>'


def head(
    lang, s, *, title, desc, base, page, og_desc=None, scripts=False, noindex=False, ld=False
) -> str:
    out = [
        "<!DOCTYPE html>",
        f'<html lang="{lang}">',
        "<head>",
        '<meta charset="utf-8">',
        '<meta name="viewport" content="width=device-width, initial-scale=1">',
        f"<title>{esc(title)}</title>",
        f'<meta name="description" content="{esc(desc)}">',
    ]
    if page:
        out.append(f'<link rel="canonical" href="{url(lang, page)}">')
        out += [
            f'<link rel="alternate" hreflang="{code}" href="{url(code, page)}">' for code in LANGS
        ]
        out.append(f'<link rel="alternate" hreflang="x-default" href="{url("en", page)}">')
    if noindex:
        out.append('<meta name="robots" content="noindex">')
    out += [
        '<meta name="theme-color" content="#16181c">',
        '<meta property="og:type" content="website">',
        '<meta property="og:site_name" content="PhishLens">',
        f'<meta property="og:locale" content="{OG_LOCALE[lang]}">',
        f'<meta property="og:title" content="{esc(title)}">',
        f'<meta property="og:description" content="{esc(og_desc or desc)}">',
    ]
    if page:
        out.append(f'<meta property="og:url" content="{url(lang, page)}">')
    out += [
        f'<meta property="og:image" content="{SITE}/{asset("", "img/og.png")}">',
        '<meta property="og:image:width" content="1200">',
        '<meta property="og:image:height" content="630">',
        f'<meta property="og:image:alt" content="{esc(s["og_alt"])}">',
        '<meta name="twitter:card" content="summary_large_image">',
        f'<link rel="icon" href="{base}favicon.ico" sizes="any">',
        f'<link rel="icon" href="{base}icon.png" type="image/png">',
        f'<link rel="apple-touch-icon" href="{base}apple-touch-icon.png">',
        f'<link rel="stylesheet" href="{asset(base, "style.css")}">',
        f'<script src="{base}i18n/{lang}.js?v={strings_digest()}" defer></script>',
        f'<script src="{asset(base, "lang.js")}" defer></script>',
        f'<script src="{asset(base, "nav.js")}" defer></script>',
    ]
    if ld:
        out.append(jsonld(lang, s))
    if scripts:
        out.append(f'<script src="{asset(base, "redact.js")}" defer></script>')
        out.append(f'<script src="{asset(base, "app.js")}" defer></script>')
    out += ["</head>", "<body>"]
    return "\n".join(out) + "\n"


def strings_digest() -> str:
    """Short hash of every strings file: i18n/<lang>.js is built from them."""
    h = hashlib.sha256()
    for f in sorted((SRC / "strings").glob("*.json")):
        h.update(f.read_bytes())
    return h.hexdigest()[:10]


def asset(base: str, name: str) -> str:
    """URL of a site file with a short hash of its content, so a browser
    fetches it again as soon as it changes."""
    path = OUT / name
    if name == "redact.js":
        path = OUT.parent / "extension" / "lib" / "redact.js"
    digest = hashlib.sha256(path.read_bytes()).hexdigest()[:10] if path.exists() else "0"
    return f"{base}{name}?v={digest}"


def header(lang, s, *, base, page) -> str:
    home = link(base, lang, "index.html")
    anchor = "" if page == "index.html" else home
    current = ' aria-current="page"'
    items = "\n".join(
        f'          <li><a href="{link(base, code, page or "index.html")}" hreflang="{code}" lang="{code}"'
        f"{current if code == lang else ''}>{name}</a></li>"
        for code, name in LANGS.items()
    )
    return f"""<a class="skip" href="#main">{esc(s["skip"])}</a>

<header class="site-head">
  <div class="wrap">
    <a class="brand" href="{home}"><img src="{base}icon.png" alt="" width="28" height="28">PhishLens</a>
    <nav class="site-nav" aria-label="{esc(s["nav_aria"])}">
      <a href="{anchor}#checks">{esc(s["nav_checks"])}</a>
      <a href="{anchor}#features">{esc(s["nav_features"])}</a>
      <a href="{anchor}#try">{esc(s["nav_try"])}</a>
      <details class="lang-menu">
        <summary aria-label="{esc(s["lang_label"])}: {LANGS[lang]}">{lang.upper()}</summary>
        <ul>
{items}
        </ul>
      </details>
      <a class="cta" href="{anchor}#install">{esc(s["cta"])}</a>
    </nav>
  </div>
</header>
"""


def footer(lang, s, *, base) -> str:
    here = base + prefix(lang)
    return f"""
<footer class="site-foot">
  <div class="wrap">
    <div>{esc(s["footer_text"])}</div>
    <nav aria-label="{esc(s["footer_aria"])}">
      <a href="{here}privacy.html">{esc(s["f_privacy"])}</a>
      <a href="{here}terms.html">{esc(s["f_terms"])}</a>
      <a href="https://github.com/AnzouK/PhishLens">GitHub</a>
      <a href="{GITHUB}docs/architecture.md">{esc(s["f_arch"])}</a>
      <a href="{GITHUB}SECURITY.md">{esc(s["f_security"])}</a>
      <a href="https://github.com/AnzouK/PhishLens/blob/main/docs/multilingual-model.md">{esc(s["f_model"])}</a>
    </nav>
  </div>
</footer>
</body>
</html>
"""


def markdown(path: Path) -> str:
    out = subprocess.check_output(["pandoc", str(path), "-f", "gfm", "-t", "html5"]).decode()
    for name in ("CHANGELOG.md", "SECURITY.md", "LICENSE"):
        out = out.replace(f'href="{name}"', f'href="{GITHUB}{name}"')
    out = out.replace('href="PRIVACY.md"', 'href="privacy.html"')
    out = out.replace('href="TERMS.md"', 'href="terms.html"')
    out = out.replace("<table>", '<div class="table-wrap"><table>').replace(
        "</table>", "</table></div>"
    )
    return out


def write(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text)


def build_lang(lang: str, strings: dict[str, dict[str, str]]) -> None:
    s = strings[lang]
    base = "" if lang == "en" else "../"
    folder = OUT / prefix(lang)

    template = (SRC / "index.html").read_text()
    page = template.replace(
        "{{>head}}",
        head(
            lang,
            s,
            title=s["meta_title"],
            desc=s["meta_desc"],
            base=base,
            page="index.html",
            og_desc=s["og_desc"],
            scripts=True,
            ld=True,
        ),
    )
    page = page.replace("{{>header}}", header(lang, s, base=base, page="index.html"))
    page = page.replace("{{>footer}}", footer(lang, s, base=base).lstrip("\n"))
    write(folder / "index.html", fill(page, s, b=base))

    for name, md in (("privacy.html", "PRIVACY.md"), ("terms.html", "TERMS.md")):
        source = ROOT / md if lang == "en" else SRC / "legal" / lang / md
        body = markdown(source)
        if lang != "en":
            note = s["legal_note_html"].replace("{en_href}", f"{base}{name}")
            body = f'<p class="legal-note">{note}</p>\n{body}'
        key = name.split(".")[0]
        write(
            folder / name,
            head(lang, s, title=s[f"{key}_title"], desc=s[f"{key}_desc"], base=base, page=name)
            + header(lang, s, base=base, page=name)
            + f'<main id="main" class="wrap">\n<article class="prose">\n{body}</article>\n</main>\n'
            + footer(lang, s, base=base),
        )

    # Texts app.js and lang.js need, and where every language lives.
    data = {
        "lang": lang,
        "t": {k: v for k, v in s.items() if k.startswith("js_")},
        "langs": {code: {"name": name, "path": prefix(code)} for code, name in LANGS.items()},
        # "Read this page in ..." in every language, for lang.js
        "suggest": {code: strings[code]["suggest"] for code in LANGS},
    }
    write(
        OUT / "i18n" / f"{lang}.js",
        "// Generated by scripts/build_site.py\n"
        f"window.PhishLensSite = {json.dumps(data, ensure_ascii=False)};\n",
    )


def build_404(strings) -> None:
    s = strings["en"]
    body = (
        f"<h1>{esc(s['nf_h1'])}</h1>\n<p>{esc(s['nf_p1'])}</p>\n"
        f"<p>{s['nf_p2_html'].replace('{home}', '/').replace('{b}', '/')}</p>\n"
    )
    write(
        OUT / "404.html",
        head("en", s, title=s["nf_title"], desc=s["nf_desc"], base="/", page=None, noindex=True)
        + header("en", s, base="/", page=None)
        + f'<main id="main" class="wrap">\n<article class="prose">\n{body}</article>\n</main>\n'
        + footer("en", s, base="/"),
    )


def build_sitemap() -> None:
    today = date.today().isoformat()
    rows = []
    for page in PAGES:
        alts = "".join(
            f'\n    <xhtml:link rel="alternate" hreflang="{code}" href="{url(code, page)}"/>'
            for code in LANGS
        )
        for lang in LANGS:
            rows.append(
                f"  <url>\n    <loc>{url(lang, page)}</loc>\n    <lastmod>{today}</lastmod>{alts}\n  </url>"
            )
    write(
        OUT / "sitemap.xml",
        '<?xml version="1.0" encoding="UTF-8"?>\n'
        '<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9" '
        'xmlns:xhtml="http://www.w3.org/1999/xhtml">\n' + "\n".join(rows) + "\n</urlset>\n",
    )


if __name__ == "__main__":
    strings = load_strings()
    for lang in LANGS:
        build_lang(lang, strings)
    build_404(strings)
    build_sitemap()
    # The site redacts reports with the extension's own rules.
    shutil.copyfile(OUT.parent / "extension" / "lib" / "redact.js", OUT / "redact.js")
    print(f"site built: {len(LANGS)} languages, {len(PAGES)} pages each")
