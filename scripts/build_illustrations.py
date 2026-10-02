#!/usr/bin/env python3
"""Build the light and dark versions of the README / website illustrations.

    python3 scripts/build_illustrations.py

- Gmail banner and attachment results: drawn in Gmail's light colours in
  docs/illustrations-src/; the dark versions use the colours the extension
  really uses in dark mode (content_scripts/banner.css).
- Popup: drawn here from the popup's real palettes (popup/popup.css),
  light and dark.

Writes docs/<name>-light.svg and docs/<name>-dark.svg, and copies the dark
versions to site/img/ (the website is dark).
"""
import base64
import pathlib
import re
import shutil

ROOT = pathlib.Path(__file__).resolve().parent.parent
SRC = ROOT / "docs" / "illustrations-src"
DOCS = ROOT / "docs"
SITE_IMG = ROOT / "site" / "img"


def blend(fg: str, bg: str, alpha: float) -> str:
    """Opaque colour of `fg` at `alpha` over `bg` (both #rrggbb)."""
    f = [int(fg[i:i + 2], 16) for i in (1, 3, 5)]
    b = [int(bg[i:i + 2], 16) for i in (1, 3, 5)]
    return "#" + "".join(f"{round(fc * alpha + bc * (1 - alpha)):02x}" for fc, bc in zip(f, b))


# --- Gmail-side illustrations: light colour -> dark colour (banner.css) ---
SURFACE = "#1f2329"
BAD, GOOD, WARN = "#ff8a80", "#81c995", "#fdd663"
GMAIL_DARK = {
    "#f6f8fc": "#1d2025",                  # canvas (Gmail page) = site frame
    "#ffffff": SURFACE,                    # banner / button surface
    "#fdf2f1": blend("#f28b82", SURFACE, 0.10),   # phishing banner background
    "#fce8e6": blend("#f28b82", SURFACE, 0.16),   # bad soft (chips, icon tile)
    "#f5c2bf": blend("#f28b82", SURFACE, 0.35),   # bad line
    "#c5221f": BAD,
    "#e6f4ea": blend(GOOD, SURFACE, 0.14),
    "#b7dfc2": blend(GOOD, SURFACE, 0.35),
    "#137333": GOOD,
    "#fef7e0": blend(WARN, SURFACE, 0.12),
    "#f6d68b": blend(WARN, SURFACE, 0.35),
    "#b06000": WARN,
    "#1f1f1f": "#e8eaed",                  # text
    "#5f6368": "#a6adb7",                  # secondary text
    "#dadce0": "#3a4049",                  # lines
    "#e8eaed": "#3a4049",                  # meter tracks
    "#e8590c": "#ff8a4c",                  # accent
    "#9c2c00": "#ffb08a",                  # text on orange token
}


def to_dark(svg: str, mapping: dict) -> str:
    pattern = re.compile("|".join(re.escape(k) for k in mapping), re.IGNORECASE)
    return pattern.sub(lambda m: mapping[m.group(0).lower()], svg)


# --- Popup: real palettes from popup.css ---
POPUP = {
    "dark": dict(bg="#16181c", card="#1d2025", line="#2c3037", text="#e7e9ec", mute="#a6acb5",
                 bad="#f2877b", warn="#e3b55b", good="#6fcf8a", accent="#f08a5d", track="#2c3037"),
    "light": dict(bg="#f5f2eb", card="#ffffff", line="#d6d0c2", text="#1f1e1b", mute="#4a4740",
                  bad="#a3271c", warn="#7a5200", good="#2c6b38", accent="#a83d0e", track="#e3ddd0"),
}


# Header icons, same paths as the popup's own sprite (popup/popup.html).
CHART = "M4 20V10M10 20V4M16 20v-7M22 20H2"
GEAR = ("M19.4 15a1.7 1.7 0 00.3 1.8l.1.1a2 2 0 11-2.8 2.8l-.1-.1a1.7 1.7 0 00-1.8-.3 1.7 1.7 0 00-1 1.5V21"
        "a2 2 0 01-4 0v-.1a1.7 1.7 0 00-1.1-1.5 1.7 1.7 0 00-1.8.3l-.1.1a2 2 0 11-2.8-2.8l.1-.1a1.7 1.7 0 00"
        ".3-1.8 1.7 1.7 0 00-1.5-1H3a2 2 0 010-4h.1a1.7 1.7 0 001.5-1.1 1.7 1.7 0 00-.3-1.8l-.1-.1a2 2 0 112.8"
        "-2.8l.1.1a1.7 1.7 0 001.8.3H9a1.7 1.7 0 001-1.5V3a2 2 0 014 0v.1a1.7 1.7 0 001 1.5 1.7 1.7 0 001.8-.3"
        "l.1-.1a2 2 0 112.8 2.8l-.1.1a1.7 1.7 0 00-.3 1.8V9a1.7 1.7 0 001.5 1H21a2 2 0 010 4h-.1a1.7 1.7 0 00"
        "-1.5 1z")


def popup_svg(theme: str, logo_b64: str) -> str:
    c = POPUP[theme]
    soft = lambda col, a: blend(col, c["card"], a)   # noqa: E731
    bad_soft, warn_soft, good_soft = soft(c["bad"], .18), soft(c["warn"], .18), soft(c["good"], .18)

    def agent(y, name, pct, colour, chips):
        w = round(326 * pct / 100)
        out = [f'<rect x="20" y="{y}" width="360" height="84" rx="4" fill="{c["card"]}" stroke="{c["line"]}"/>',
               f'<text x="36" y="{y + 26}" font-size="13.5" font-weight="600" fill="{c["text"]}">{name}</text>',
               f'<text x="364" y="{y + 26}" font-size="13.5" font-weight="700" fill="{colour}" text-anchor="end">{pct}%</text>',
               f'<rect x="36" y="{y + 36}" width="328" height="5" rx="2.5" fill="{c["track"]}"/>',
               f'<rect x="36" y="{y + 36}" width="{w}" height="5" rx="2.5" fill="{colour}"/>']
        x = 36
        for label, col in chips:
            wd = 13 + len(label) * 6.3
            fill = bad_soft if col == c["bad"] else warn_soft if col == c["warn"] else good_soft
            out.append(f'<rect x="{x}" y="{y + 52}" width="{wd:.0f}" height="20" rx="4" fill="{fill}"/>')
            out.append(f'<text x="{x + 7}" y="{y + 66}" font-size="11" font-weight="600" fill="{col}">{label}</text>')
            x += wd + 6
        return "\n  ".join(out)

    tokens = [("verify", "p", .55), ("suspended", "p", .45), ("immediately", "p", .38), ("account", "p", .28),
              ("payment", "p", .22), ("team", "s", .30), ("agenda", "s", .22)]
    tok_svg, x, y = [], 36, 528
    for word, kind, a in tokens:
        wd = 16 + len(word) * 6.6
        if x + wd > 366:
            x, y = 36, y + 28
        col = c["bad"] if kind == "p" else c["good"]
        tok_svg.append(f'<rect x="{x:.0f}" y="{y}" width="{wd:.0f}" height="22" rx="4" fill="{soft(col, a)}"/>')
        tok_svg.append(f'<text x="{x + 8:.0f}" y="{y + 15}" font-size="11.5" fill="{c["text"]}">{word}</text>')
        x += wd + 6

    icon = f'class="ic" stroke="{c["mute"]}"'
    return f'''<svg xmlns="http://www.w3.org/2000/svg" width="400" height="620" viewBox="0 0 400 620" role="img" aria-labelledby="t d">
  <title id="t">PhishLens popup showing a phishing verdict</title>
  <desc id="d">The extension popup after scanning an email: a phishing verdict, a score per check with a bar, threat-intelligence and authentication badges, and the words that influenced the text model.</desc>
  <style>
    text {{ font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif; }}
    .ic {{ fill: none; stroke-width: 1.7; stroke-linecap: round; stroke-linejoin: round; }}
  </style>
  <rect x="0.5" y="0.5" width="399" height="619" rx="6" fill="{c["bg"]}" stroke="{c["line"]}"/>

  <image x="20" y="18" width="34" height="34" href="data:image/png;base64,{logo_b64}"/>
  <text x="64" y="34" font-size="16" font-weight="700" fill="{c["text"]}">PhishLens</text>
  <text x="64" y="51" font-size="12" fill="{c["mute"]}">Detect &amp; explain phishing emails</text>
  <g>
    <rect x="276" y="20" width="30" height="30" rx="4" fill="none" stroke="{c["line"]}"/>
    <g transform="translate(282 26) scale(.75)" {icon} stroke-width="2"><path d="{CHART}"/></g>
    <rect x="312" y="20" width="30" height="30" rx="4" fill="none" stroke="{c["line"]}"/>
    <g transform="translate(318 26) scale(.75)" {icon} stroke-width="2"><circle cx="12" cy="12" r="3"/><path d="{GEAR}"/></g>
    <rect x="348" y="20" width="30" height="30" rx="4" fill="none" stroke="{c["line"]}"/>
    <g transform="translate(354 26) scale(.75)" {icon} stroke-width="2"><circle cx="12" cy="12" r="9"/><path d="M12 3a9 9 0 000 18z" fill="{c["mute"]}"/></g>
  </g>
  <line x1="0" y1="68" x2="400" y2="68" stroke="{c["line"]}"/>

  <rect x="20" y="84" width="360" height="62" rx="4" fill="{soft(c["bad"], .10)}" stroke="{c["bad"]}"/>
  <path transform="translate(38 101)" class="ic" stroke="{c["bad"]}" d="M10.3 1.9L1.4 17a2 2 0 001.7 3h17.8a2 2 0 001.7-3L13.7 1.9a2 2 0 00-3.4 0zM12 8v4M12 16h.01" stroke-width="2"/>
  <text x="74" y="111" font-size="15" font-weight="700" fill="{c["text"]}">This email looks like phishing</text>
  <text x="74" y="130" font-size="12.5" fill="{c["mute"]}">We recommend not clicking any links.</text>

  {agent(160, "Message content", 97, c["bad"], [])}
  <text x="36" y="226" font-size="12" fill="{c["mute"]}">The message content reads like a scam.</text>
  {agent(256, "Links in the email", 88, c["bad"], [("Flagged by Google Safe Browsing", c["bad"])])}
  {agent(352, "Sender &amp; headers", 64, c["warn"], [("DMARC fail", c["bad"]), ("SPF fail", c["warn"])])}

  <rect x="20" y="448" width="360" height="152" rx="4" fill="{c["card"]}" stroke="{c["line"]}"/>
  <text x="36" y="474" font-size="13.5" font-weight="600" fill="{c["text"]}">Why this verdict?</text>
  <path d="M356 470l5-5 5 5" class="ic" stroke="{c["mute"]}"/>
  <text x="36" y="496" font-size="11.5" fill="{c["mute"]}">The words that influenced the text model most.</text>
  <text x="36" y="512" font-size="11.5" fill="{c["mute"]}">Red points to phishing, green to safe.</text>
  {chr(10).join("  " + t for t in tok_svg)}
</svg>
'''


def main():
    logo = base64.b64encode((ROOT / "extension" / "icons" / "48.png").read_bytes()).decode()
    outputs = {}
    for name in ("gmail-verdicts", "attachments"):
        # Transparent canvas: the picture takes the page's own background
        # (GitHub light/dark, or the website frame) instead of a second one.
        light = (SRC / f"{name}.svg").read_text().replace('rx="18" fill="#f6f8fc"', 'rx="18" fill="none"')
        outputs[name] = {"light": light, "dark": to_dark(light, GMAIL_DARK)}
    outputs["popup"] = {t: popup_svg(t, logo) for t in ("light", "dark")}
    SITE_IMG.mkdir(parents=True, exist_ok=True)
    for name, variants in outputs.items():
        for theme, svg in variants.items():
            (DOCS / f"{name}-{theme}.svg").write_text(svg)
        shutil.copyfile(DOCS / f"{name}-dark.svg", SITE_IMG / f"{name}.svg")
    print("illustrations built:", ", ".join(f"{n}-{t}" for n in outputs for t in outputs[n]))


if __name__ == "__main__":
    main()
