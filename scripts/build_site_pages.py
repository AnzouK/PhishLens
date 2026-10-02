#!/usr/bin/env python3
"""Rebuild site/privacy.html, site/terms.html and site/404.html from
PRIVACY.md and TERMS.md (needs pandoc). Run from the repository root:

    python3 scripts/build_site_pages.py
"""
import html
import re
import subprocess

HEAD = '''<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{title}</title>
<meta name="description" content="{desc}">
{canon}<meta name="theme-color" content="#16181c">
<meta property="og:type" content="website">
<meta property="og:site_name" content="PhishLens">
<meta property="og:title" content="{title}">
<meta property="og:description" content="{desc}">
<meta property="og:image" content="https://anzouk.duckdns.org/img/og.png">
<meta name="twitter:card" content="summary_large_image">
{robots}<link rel="icon" href="{b}favicon.ico" sizes="any">
<link rel="icon" href="{b}icon.png" type="image/png">
<link rel="apple-touch-icon" href="{b}apple-touch-icon.png">
<link rel="stylesheet" href="{b}style.css">
</head>
<body>
<a class="skip" href="#main">Skip to content</a>
<header class="site-head">
  <div class="wrap">
    <a class="brand" href="{home}"><img src="{b}icon.png" alt="" width="28" height="28">PhishLens</a>
    <nav class="site-nav" aria-label="Main">
      <a href="{home}#checks">What it checks</a>
      <a href="{home}#how">How it works</a>
      <a href="{home}#try">Try it</a>
      <a class="cta" href="{home}#install">Install PhishLens</a>
    </nav>
  </div>
</header>
<main id="main" class="wrap">
<article class="prose">
'''
FOOT = '''</article>
</main>
<footer class="site-foot">
  <div class="wrap">
    <div>PhishLens, final-year project, B.Sc. Cybersecurity, Nile University of Nigeria, 2025/2026. MIT license. No cookies on this site.</div>
    <nav aria-label="Footer">
      <a href="{b}privacy.html">Privacy</a>
      <a href="{b}terms.html">Terms</a>
      <a href="https://github.com/AnzouK/PhishLens">GitHub</a>
      <a href="https://github.com/AnzouK/PhishLens/blob/main/docs/architecture.md">Architecture</a>
      <a href="https://github.com/AnzouK/PhishLens/blob/main/SECURITY.md">Security</a>
      <a href="https://huggingface.co/AnzouKiona/phishlens-distilbert">Model</a>
    </nav>
  </div>
</footer>
</body>
</html>
'''
def build(out, title, desc, body, path=None, noindex=False, base=""):
    canon = f'<link rel="canonical" href="https://anzouk.duckdns.org{path}">\n' if path else ""
    robots = '<meta name="robots" content="noindex">\n' if noindex else ""
    open(out, "w").write((HEAD.format(title=html.escape(title), desc=html.escape(desc), canon=canon, robots=robots, b=base, home=base or "./")
                            + body.replace('href="/', f'href="{base}') + FOOT.format(b=base)))


GITHUB = "https://github.com/AnzouK/PhishLens/blob/main/"


def md(path):
    out = subprocess.check_output(["pandoc", path, "-f", "gfm", "-t", "html5"]).decode()
    for name in ("CHANGELOG.md", "SECURITY.md", "LICENSE"):
        out = out.replace(f'href="{name}"', f'href="{GITHUB}{name}"')
    out = out.replace('href="PRIVACY.md"', 'href="/privacy.html"').replace('href="TERMS.md"', 'href="/terms.html"')
    out = re.sub(r"<table>", '<div class="table-wrap"><table>', out).replace("</table>", "</table></div>")
    return out


NOT_FOUND = """<h1>Page not found</h1>
<p>There is nothing at this address. It may have moved, or the link may have a typo.</p>
<p>From here you can go to the <a href="/">home page</a>, <a href="/#try">check an email</a>, or read the <a href="/privacy.html">privacy policy</a>.</p>
"""

if __name__ == "__main__":
    build("site/privacy.html", "Privacy policy · PhishLens",
          "What the PhishLens extension, website and PhishLens Cloud handle, where it goes and what is kept.",
          md("PRIVACY.md"), "/privacy.html")
    build("site/terms.html", "Terms of use · PhishLens",
          "The terms for using the PhishLens extension, website and PhishLens Cloud.",
          md("TERMS.md"), "/terms.html")
    build("site/404.html", "Page not found · PhishLens", "This page does not exist.", NOT_FOUND, None, noindex=True, base="/")
    print("site pages rebuilt")
