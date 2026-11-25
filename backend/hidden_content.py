"""
PhishLens: finding what an HTML email hides from its reader.

Attackers put hidden text before the message to fill the text model's
window with words nobody sees, and hidden links to push the real ones
out of the link list. We move hidden parts after the visible ones
instead of dropping them, because a phone stylesheet can show them again.

An element's style is its <style> rules in order, with !important
respected, followed by its inline style. Backgrounds are composed from
the white page down, alpha included. Some styles hide a whole box
(display, opacity, clipping). Others only make the element's own text
unreadable (colour, size, visibility), and then each child is judged on
its own because it may set its own colour.

The extension makes the same call from the browser's computed styles
(PL.isHidden in content_scripts/core.js). Both sides are tested against
tests/fixtures/hidden_cases.json.
"""

from __future__ import annotations

import colorsys
import re
import time

import soupsieve
from bs4 import Comment

# Styles that hide an element and all of its content. visibility is not
# here because a child can set it back to visible (see _invisible).
_HIDING_STYLES = {
    "display": {"none"},
    "mso-hide": {"all"},
}
# Smallest readable font size per unit. Other units only need to be above 0.
_MIN_FONT = {"px": 2.0, "pt": 2.0, "em": 0.2, "rem": 0.2, "%": 20.0, "": 2.0}
_SCALE_RE = re.compile(r"scale(?:x|y|3d)?\(([^()]{0,100})\)")
# Below this contrast ratio, text can't be read against its background.
_MIN_CONTRAST = 1.2
# Email clients draw black text on white unless told otherwise.
PAGE = (255, 255, 255)
_INK = (0, 0, 0, 1.0)
# The CSS colour names (CSS Color 4).
_NAMED_HEX = [
    "aliceblue",
    "f0f8ff",
    "antiquewhite",
    "faebd7",
    "aqua",
    "00ffff",
    "aquamarine",
    "7fffd4",
    "azure",
    "f0ffff",
    "beige",
    "f5f5dc",
    "bisque",
    "ffe4c4",
    "black",
    "000000",
    "blanchedalmond",
    "ffebcd",
    "blue",
    "0000ff",
    "blueviolet",
    "8a2be2",
    "brown",
    "a52a2a",
    "burlywood",
    "deb887",
    "cadetblue",
    "5f9ea0",
    "chartreuse",
    "7fff00",
    "chocolate",
    "d2691e",
    "coral",
    "ff7f50",
    "cornflowerblue",
    "6495ed",
    "cornsilk",
    "fff8dc",
    "crimson",
    "dc143c",
    "cyan",
    "00ffff",
    "darkblue",
    "00008b",
    "darkcyan",
    "008b8b",
    "darkgoldenrod",
    "b8860b",
    "darkgray",
    "a9a9a9",
    "darkgreen",
    "006400",
    "darkgrey",
    "a9a9a9",
    "darkkhaki",
    "bdb76b",
    "darkmagenta",
    "8b008b",
    "darkolivegreen",
    "556b2f",
    "darkorange",
    "ff8c00",
    "darkorchid",
    "9932cc",
    "darkred",
    "8b0000",
    "darksalmon",
    "e9967a",
    "darkseagreen",
    "8fbc8f",
    "darkslateblue",
    "483d8b",
    "darkslategray",
    "2f4f4f",
    "darkslategrey",
    "2f4f4f",
    "darkturquoise",
    "00ced1",
    "darkviolet",
    "9400d3",
    "deeppink",
    "ff1493",
    "deepskyblue",
    "00bfff",
    "dimgray",
    "696969",
    "dimgrey",
    "696969",
    "dodgerblue",
    "1e90ff",
    "firebrick",
    "b22222",
    "floralwhite",
    "fffaf0",
    "forestgreen",
    "228b22",
    "fuchsia",
    "ff00ff",
    "gainsboro",
    "dcdcdc",
    "ghostwhite",
    "f8f8ff",
    "gold",
    "ffd700",
    "goldenrod",
    "daa520",
    "gray",
    "808080",
    "green",
    "008000",
    "greenyellow",
    "adff2f",
    "grey",
    "808080",
    "honeydew",
    "f0fff0",
    "hotpink",
    "ff69b4",
    "indianred",
    "cd5c5c",
    "indigo",
    "4b0082",
    "ivory",
    "fffff0",
    "khaki",
    "f0e68c",
    "lavender",
    "e6e6fa",
    "lavenderblush",
    "fff0f5",
    "lawngreen",
    "7cfc00",
    "lemonchiffon",
    "fffacd",
    "lightblue",
    "add8e6",
    "lightcoral",
    "f08080",
    "lightcyan",
    "e0ffff",
    "lightgoldenrodyellow",
    "fafad2",
    "lightgray",
    "d3d3d3",
    "lightgreen",
    "90ee90",
    "lightgrey",
    "d3d3d3",
    "lightpink",
    "ffb6c1",
    "lightsalmon",
    "ffa07a",
    "lightseagreen",
    "20b2aa",
    "lightskyblue",
    "87cefa",
    "lightslategray",
    "778899",
    "lightslategrey",
    "778899",
    "lightsteelblue",
    "b0c4de",
    "lightyellow",
    "ffffe0",
    "lime",
    "00ff00",
    "limegreen",
    "32cd32",
    "linen",
    "faf0e6",
    "magenta",
    "ff00ff",
    "maroon",
    "800000",
    "mediumaquamarine",
    "66cdaa",
    "mediumblue",
    "0000cd",
    "mediumorchid",
    "ba55d3",
    "mediumpurple",
    "9370db",
    "mediumseagreen",
    "3cb371",
    "mediumslateblue",
    "7b68ee",
    "mediumspringgreen",
    "00fa9a",
    "mediumturquoise",
    "48d1cc",
    "mediumvioletred",
    "c71585",
    "midnightblue",
    "191970",
    "mintcream",
    "f5fffa",
    "mistyrose",
    "ffe4e1",
    "moccasin",
    "ffe4b5",
    "navajowhite",
    "ffdead",
    "navy",
    "000080",
    "oldlace",
    "fdf5e6",
    "olive",
    "808000",
    "olivedrab",
    "6b8e23",
    "orange",
    "ffa500",
    "orangered",
    "ff4500",
    "orchid",
    "da70d6",
    "palegoldenrod",
    "eee8aa",
    "palegreen",
    "98fb98",
    "paleturquoise",
    "afeeee",
    "palevioletred",
    "db7093",
    "papayawhip",
    "ffefd5",
    "peachpuff",
    "ffdab9",
    "peru",
    "cd853f",
    "pink",
    "ffc0cb",
    "plum",
    "dda0dd",
    "powderblue",
    "b0e0e6",
    "purple",
    "800080",
    "rebeccapurple",
    "663399",
    "red",
    "ff0000",
    "rosybrown",
    "bc8f8f",
    "royalblue",
    "4169e1",
    "saddlebrown",
    "8b4513",
    "salmon",
    "fa8072",
    "sandybrown",
    "f4a460",
    "seagreen",
    "2e8b57",
    "seashell",
    "fff5ee",
    "sienna",
    "a0522d",
    "silver",
    "c0c0c0",
    "skyblue",
    "87ceeb",
    "slateblue",
    "6a5acd",
    "slategray",
    "708090",
    "slategrey",
    "708090",
    "snow",
    "fffafa",
    "springgreen",
    "00ff7f",
    "steelblue",
    "4682b4",
    "tan",
    "d2b48c",
    "teal",
    "008080",
    "thistle",
    "d8bfd8",
    "tomato",
    "ff6347",
    "turquoise",
    "40e0d0",
    "violet",
    "ee82ee",
    "wheat",
    "f5deb3",
    "white",
    "ffffff",
    "whitesmoke",
    "f5f5f5",
    "yellow",
    "ffff00",
    "yellowgreen",
    "9acd32",
]
_NAMED = {
    name: tuple(int(code[i : i + 2], 16) for i in (0, 2, 4))
    for name, code in zip(_NAMED_HEX[::2], _NAMED_HEX[1::2], strict=True)
}
MAX_ELEMENTS = 20_000
_MAX_RULES = 20_000  # rules read (cheap); matching them is bounded by _SELECT_BUDGET

Colour = tuple[int, int, int]


def _length(value: str) -> tuple[float, str] | None:
    """Split a CSS length into (number, unit), e.g. "0.01em" -> (0.01, "em")."""
    value = value.strip().split(" ")[0].rstrip(")")
    num = value.rstrip("%abcdefghijklmnopqrstuvwxyz")
    try:
        return float(num), value[len(num) :]
    except ValueError:
        return None


def _channel(part: str) -> float:
    return float(part[:-1]) * 2.55 if part.endswith("%") else float(part)


def _alpha(part: str) -> float:
    return float(part[:-1]) / 100 if part.endswith("%") else float(part)


def parse_colour(value: str) -> tuple[int, int, int, float] | None:
    """Parse a CSS colour into (r, g, b, alpha), or return None.

    Handles hex forms, rgb() and hsl() with either syntax, named colours
    and transparent.
    """
    value = value.strip().lower()
    if value == "transparent":
        return (0, 0, 0, 0.0)
    if value in _NAMED:
        return (*_NAMED[value], 1.0)
    try:
        if value.startswith("#") and len(value) in (4, 5, 7, 9):
            digits = value[1:]
            if len(digits) <= 4:
                digits = "".join(c * 2 for c in digits)
            r, g, b = (int(digits[i : i + 2], 16) for i in (0, 2, 4))
            return (r, g, b, int(digits[6:8], 16) / 255 if len(digits) == 8 else 1.0)
        name, _, args = value.partition("(")
        parts = [p for p in args.rstrip(")").replace(",", " ").replace("/", " ").split() if p]
        alpha = _alpha(parts[3]) if len(parts) > 3 else 1.0
        if name in ("rgb", "rgba"):
            r, g, b = (round(min(255.0, max(0.0, _channel(p)))) for p in parts[:3])
            return (r, g, b, alpha)
        if name in ("hsl", "hsla"):
            h = float(parts[0].removesuffix("deg")) / 360
            s, light = (float(p.rstrip("%")) / 100 for p in parts[1:3])
            r, g, b = (round(c * 255) for c in colorsys.hls_to_rgb(h % 1, light, s))
            return (r, g, b, alpha)
    except (ValueError, IndexError):
        return None
    return None


def over(top: tuple, bottom: Colour) -> Colour:
    """Blend `top` (with alpha) over the opaque `bottom`."""
    a = top[3]
    return tuple(round(a * t + (1 - a) * b) for t, b in zip(top[:3], bottom, strict=True))


def _luminance(c: Colour) -> float:
    """WCAG relative luminance, 0 (black) to 1 (white)."""

    def linear(v: int) -> float:
        v = v / 255
        return v / 12.92 if v <= 0.04045 else ((v + 0.055) / 1.055) ** 2.4

    r, g, b = (linear(v) for v in c)
    return 0.2126 * r + 0.7152 * g + 0.0722 * b


def _same_colour(a: Colour, b: Colour) -> bool:
    """Return True if the WCAG contrast ratio is under _MIN_CONTRAST.

    For scale, white on #f0f0f0 is 1.1 and body text needs 4.5.
    """
    la, lb = sorted((_luminance(a), _luminance(b)))
    return (lb + 0.05) / (la + 0.05) < _MIN_CONTRAST


class Declarations(dict):
    """CSS declarations in lower case, with the !important ones tracked in `important`."""

    def __init__(self, *args, important=(), **kwargs):
        super().__init__(*args, **kwargs)
        self.important = set(important)

    def then(self, later: Declarations) -> Declarations:
        """Return a copy with `later` applied on top."""
        out = Declarations(self, important=self.important)
        out.apply(later)
        return out

    def apply(self, later: Declarations) -> None:
        """Apply `later` in place. An !important value survives a later plain one."""
        for key, value in later.items():
            if key in self.important and key not in later.important:
                continue
            self.pop(key, None)  # re-insert so dict order reflects which came later
            self[key] = value
            if key in later.important:
                self.important.add(key)


_COMMENT_RE = re.compile(r"/\*.*?\*/", re.S)
_IMPORTANT_RE = re.compile(r"!\s*important\b", re.IGNORECASE)


def style_declarations(style: str) -> Declarations:
    decl = Declarations()
    for item in _COMMENT_RE.sub(" ", (style or "")[:4000]).split(";"):
        key, sep, value = item.partition(":")
        if sep:
            key = key.strip().lower()
            # Lower-case everything except the text of "content".
            value = value if key == "content" else value.lower()
            important = bool(_IMPORTANT_RE.search(value))
            if key in decl.important and not important:
                continue  # an !important value is kept over a later plain one
            if important:
                decl.important.add(key)
            decl.pop(key, None)  # re-insert so dict order reflects which came later
            decl[key] = _IMPORTANT_RE.sub("", value).strip()
    return decl


_COLOUR_FN_RE = re.compile(r"(?:rgba?|hsla?)\([^()]{0,80}\)")


def _background_value(value: str) -> tuple | str | None:
    """Return the colour in a background value, "image", or None.

    Works on the shorthand too ("no-repeat center #0b57d0"). Images and
    gradients return "image".
    """
    if "url(" in value or "gradient(" in value or "image(" in value:
        return "image"
    found = _COLOUR_FN_RE.search(value)
    tokens = [found.group(0)] if found else value.split()
    for token in tokens:
        colour = parse_colour(token)
        if colour:
            return colour if colour[3] > 0 else None
    # Variables, currentColor and unknown names are treated as unknown.
    # Assuming white would mark light text on a dark section as hidden.
    words = set(value.split()) - {"none", "inherit", "initial", "unset", "transparent"}
    return "image" if words - _BACKGROUND_KEYWORDS else None


_BACKGROUND_KEYWORDS = frozenset(
    [
        "no-repeat",
        "repeat",
        "repeat-x",
        "repeat-y",
        "space",
        "round",
        "center",
        "top",
        "bottom",
        "left",
        "right",
        "scroll",
        "fixed",
        "local",
        "cover",
        "contain",
        "auto",
        "border-box",
        "padding-box",
        "content-box",
    ]
)


def _own_background(decl: dict[str, str], tag=None) -> tuple | str | None:
    """Return the element's own background as RGBA, "image" or None.

    The style wins (whichever of background and background-color comes
    last). Otherwise we fall back to the bgcolor or background attribute.
    """
    if decl.get("background-image", "none") != "none":
        return "image"
    for key in reversed([k for k in decl if k in ("background", "background-color")]):
        if decl[key]:
            return _background_value(decl[key])
    if tag is not None:
        if tag.get("background"):
            return "image"
        if tag.get("bgcolor"):
            value = str(tag["bgcolor"]).strip()
            # HTML reads bgcolor="0b57d0" as #0b57d0.
            if len(value) == 6 and all(c in "0123456789abcdefABCDEF" for c in value):
                value = "#" + value
            return _background_value(value.lower())
    return None


def _behind(decl: dict[str, str], parent: Colour | None, tag=None) -> Colour | None:
    """Return the colour behind the element's text, or None if an image shows through."""
    own = _own_background(decl, tag)
    if own == "image":
        return None
    if own is None:
        return parent
    if parent is None:
        return tuple(own[:3]) if own[3] >= 1 else None
    return over(own, parent)


def _hides_box(decl: dict[str, str]) -> bool:
    """Return True if the whole box is out of view (display, opacity, clip, position, scale)."""
    if any(decl.get(key) in hiding for key, hiding in _HIDING_STYLES.items()):
        return True
    opacity = _length(decl.get("opacity", "1"))
    return bool(opacity and opacity[0] <= 0.05) or _out_of_sight(decl)


def _tiny(decl: dict[str, str], parent_tiny: bool) -> bool:
    """Return True if the font is too small to read.

    The size is inherited, so 1em inside a tiny font stays tiny.
    """
    size = _length(decl.get("font-size", "")) if decl.get("font-size") else None
    if size is None:
        return parent_tiny
    if size[0] <= 0 or size[0] < _MIN_FONT.get(size[1], 0):
        return True
    return parent_tiny and size[1] in ("em", "%")


def _invisible(decl: dict[str, str], parent_invisible: bool) -> bool:
    """Return True for visibility:hidden, which a child can override."""
    value = decl.get("visibility")
    return value in ("hidden", "collapse") if value else parent_invisible


def _ink(decl: dict[str, str], parent_ink: tuple, tag=None) -> tuple:
    """Return the text colour as RGBA.

    We keep alpha so transparent text stays transparent. The element's own
    colour (style or <font color>) wins. Otherwise, or when the colour is
    unknown, we use the inherited one.
    """
    value = decl.get("color") or (
        tag.get("color") if tag is not None and tag.name == "font" else ""
    )
    colour = parse_colour(str(value).lower()) if value else None
    return colour or parent_ink


def _text_unreadable(behind: Colour | None, ink: tuple, tiny: bool, invisible: bool) -> bool:
    if tiny or invisible or ink[3] <= 0.05:
        return True
    return behind is not None and _same_colour(over(ink, behind), behind)


def is_hidden_style(style: str, background: tuple | None = None) -> bool:
    """Return True if an inline style hides its element's text.

    `background` is what lies behind the element and defaults to the white
    page. Besides the box-level checks, this catches tiny fonts, low
    contrast and a zero size with overflow hidden.
    """
    decl = style_declarations(style)
    parent = PAGE if background is None else tuple(background[:3])
    behind = _behind(decl, parent)
    ink = _ink(decl, _INK)
    return _hides_box(decl) or _text_unreadable(
        behind, ink, _tiny(decl, False), _invisible(decl, False)
    )


def _out_of_sight(decl: dict[str, str]) -> bool:
    """Return True if the box is clipped away, moved off the page or scaled to zero."""
    if {decl.get(k) for k in ("overflow", "overflow-x", "overflow-y")} & {"hidden", "clip"} and any(
        (_length(decl.get(k, "1")) or (1, ""))[0] < 1
        for k in ("max-height", "height", "max-width", "width")
    ):
        return True
    clip_path = decl.get("clip-path", "").replace(" ", "")
    if clip_path.startswith("inset(") and (_length(clip_path[6:]) or (0, ""))[0] >= 50:
        return True
    clip = decl.get("clip", "").replace(" ", "").replace("px", "")
    if clip_path.startswith("circle(0") or clip in ("rect(0,0,0,0)", "rect(0000)"):
        return True
    if decl.get("position") in ("absolute", "fixed") and any(
        (_length(decl.get(k, "0")) or (0, ""))[0] <= -500
        for k in ("left", "top", "right", "bottom")
    ):
        return True
    if (_length(decl.get("text-indent", "0")) or (0, ""))[0] <= -500:
        return True
    return any(
        (_length(a) or (1, ""))[0] == 0
        for args in _SCALE_RE.findall(decl.get("transform", ""))
        for a in args.split(",")
    )


def _applies_on_screen(condition: str) -> bool:
    """Return True for an @media block that applies on every screen.

    "@media screen" or "@media all" qualify. Blocks with a width or other
    feature are the phone versions and are skipped.
    """
    words = condition.lower().replace(",", " ").split()
    return bool(words) and words[0] == "@media" and set(words[1:]) <= {"screen", "all", "only"}


# Properties that can hide something. Rules without any of them are skipped.
_RELEVANT = frozenset(
    [
        "content",
        "display",
        "visibility",
        "opacity",
        "font-size",
        "color",
        "background",
        "background-color",
        "background-image",
        "overflow",
        "overflow-x",
        "overflow-y",
        "height",
        "max-height",
        "width",
        "max-width",
        "clip",
        "clip-path",
        "position",
        "left",
        "top",
        "right",
        "bottom",
        "text-indent",
        "transform",
        "mso-hide",
    ]
)


def _sheet_rules(css: str, out: list[tuple[str, Declarations]]) -> None:
    """Append (selectors, declarations) for each rule of a sheet to `out`.

    We keep top-level rules and rules inside @media blocks that apply on
    every screen. At-statements like @charset and @import end at their ";".
    """
    depth, start, head, body_start = 0, 0, "", 0
    for i, ch in enumerate(css):
        if len(out) >= _MAX_RULES:
            return
        if ch == ";" and depth == 0:
            start = i + 1
        elif ch == "{":
            if depth == 0:
                head, body_start = css[start:i].strip(), i + 1
            depth += 1
        elif ch == "}" and depth:
            depth -= 1
            if depth == 0:
                body = css[body_start:i]
                if not head.startswith("@"):
                    decl = style_declarations(body)
                    if _RELEVANT.intersection(decl):
                        out.append((head, decl))
                elif _applies_on_screen(head):
                    _sheet_rules(body, out)
                start = i + 1


# Selectors made only of a tag, classes and an id ("td.dark", ".h", "#x").
# These are answered from an index without walking the document.
_SIMPLE_RE = re.compile(r"^([a-z][a-z0-9-]*|\*)?((?:[.#][a-z0-9_-]+)*)$", re.IGNORECASE)
# Work budget for all rules together, counted in elements checked. Without
# it a few thousand selectors over a large document take minutes. Rules
# past the budget are skipped. A sheet that long is suspect anyway.
_SELECT_BUDGET = 20_000
_SELECT_SECONDS = 0.5
# Cap on style merges across all rules. "div" in 5,000 rules over 5,000
# elements would be 25 million.
_MAX_MERGES = 3_000_000


# Tags, classes and ids in a selector, after removing attribute tests and
# pseudo-classes.
_TOKEN_RE = re.compile(
    r"([.#])(-?[a-z_][a-z0-9_-]*)|(?<![a-z0-9_.#-])()([a-z][a-z0-9-]*)", re.IGNORECASE
)
_ATTRS_RE = re.compile(r"\[[^\]]*\]|::?[a-z-]+(?:\([^)]*\))?", re.IGNORECASE)


class _Index:
    """Index of the document's elements by tag, class and id."""

    def __init__(self, soup):
        self.all = soup.find_all(True, limit=MAX_ELEMENTS)
        self.by_class: dict[str, list] = {}
        self.by_id: dict[str, list] = {}
        self.by_tag: dict[str, list] = {}
        self._simple: dict[str, list | None] = {}
        for tag in self.all:
            self.by_tag.setdefault(tag.name, []).append(tag)
            for name in tag.get("class") or []:
                self.by_class.setdefault(name.lower(), []).append(tag)
            if tag.get("id"):
                self.by_id.setdefault(str(tag["id"]).lower(), []).append(tag)

    def select(self, selector: str, budget: list) -> list:
        """Return the elements a selector matches.

        Simple selectors are free. Others cost one unit per candidate from
        `budget` ([units left, deadline]). Once the budget runs out they
        match nothing. A selector naming a tag, class or id that the email
        doesn't have is skipped without cost.
        """
        matched = self.simple(selector)
        if matched is not None:
            return matched
        if budget[0] <= 0 or time.monotonic() > budget[1]:
            return []
        for mark, ident, _bare, tag_name in _TOKEN_RE.findall(_ATTRS_RE.sub("", selector)):
            kind, name = (mark, ident) if mark else ("", tag_name)
            table = {"": self.by_tag, ".": self.by_class, "#": self.by_id}[kind]
            if name.lower() not in table:
                return []
        candidates = self.simple(_last_compound(selector))
        if candidates is None:
            candidates = self.all
        if budget[0] < len(candidates):
            return []
        budget[0] -= len(candidates)
        try:
            compiled = soupsieve.compile(selector)
        except Exception:  # soupsieve doesn't support this selector
            return []
        matched = []
        for n, tag in enumerate(candidates):
            # ":nth-child" over a thousand siblings costs far more per
            # element, so the deadline applies too.
            if n % 100 == 0 and time.monotonic() > budget[1]:
                break
            if compiled.match(tag):
                matched.append(tag)
        return matched

    def simple(self, selector: str) -> list | None:
        """Return matches for a simple selector, or None if it isn't simple.

        Memoised, because a sheet can repeat the same selector thousands of times.
        """
        key = selector.lower()
        if key not in self._simple:
            self._simple[key] = self._simple_uncached(key)
        return self._simple[key]

    def _simple_uncached(self, selector: str) -> list | None:
        m = _SIMPLE_RE.match(selector)
        if not m or not (m.group(1) or m.group(2)):
            return None
        name, rest = (m.group(1) or "*").lower(), m.group(2).lower()
        classes = re.findall(r"\.([a-z0-9_-]+)", rest)
        ids = re.findall(r"#([a-z0-9_-]+)", rest)
        if ids:
            pool = self.by_id.get(ids[0], [])
        elif classes:
            pool = self.by_class.get(classes[0], [])
        else:
            pool = self.all if name == "*" else self.by_tag.get(name, [])
        return [
            t
            for t in pool
            if (name == "*" or t.name == name)
            and all(c in {x.lower() for x in t.get("class") or []} for c in classes)
            and all(str(t.get("id", "")).lower() == i for i in ids)
        ]


def _rules_of(soup) -> list[tuple[str, Declarations]]:
    """Collect the rules of all <style> sheets, reading at most 300,000 characters."""
    rules: list[tuple[str, Declarations]] = []
    left = 300_000
    for sheet in soup.find_all("style", limit=50):
        css = sheet.get_text()[:left]
        left -= len(css)
        # Email templates often wrap sheets in "<!--" and "-->". CSS ignores
        # these CDO/CDC tokens, so they must not stick to the first selector.
        css = _COMMENT_RE.sub(" ", css).replace("<!--", " ").replace("-->", " ")
        _sheet_rules(css, rules)
        if left <= 0:
            break
    return rules


_PSEUDO_RE = re.compile(r"::?(?:before|after)\b", re.IGNORECASE)
_QUOTED_RE = re.compile(r"\"([^\"]{0,500})\"|'([^']{0,500})'")


def generated_text(soup, hidden: list | None = None) -> str:
    """Return the words a sheet draws with ::before and ::after content.

    The reader sees them but they are not in the document text, so a lure
    written there used to escape the text model. We skip content that its
    own rule hides, content that would be unreadable on its element, and
    content for elements that are missing or inside a `hidden` part.
    Matching stays within the selector budget and returns 200 words at most.
    """
    hidden_ids = {id(t) for t in hidden or []}
    states = getattr(soup, "pll_text_states", {})
    index, words, budget = None, [], [20_000, time.monotonic() + _SELECT_SECONDS]
    for selector, decl in _rules_of(soup):
        content = decl.get("content", "")
        if not _PSEUDO_RE.search(selector) or not _QUOTED_RE.search(content):
            continue
        if _hides_box(decl):
            continue
        index = index or _Index(soup)
        for part in selector.split(","):
            base = _PSEUDO_RE.sub("", part).strip() or "*"
            shown = [
                t
                for t in index.select(base, budget)
                if not any(id(p) in hidden_ids for p in (t, *t.parents))
                and _pseudo_readable(decl, states.get(id(t)))
            ]
            if shown:
                words += [a or b for a, b in _QUOTED_RE.findall(content)]
                break
        if len(words) >= 200:
            break
    return " ".join(w.replace("\\a", " ") for w in words)


def _pseudo_readable(decl: Declarations, state: tuple | None) -> bool:
    """Return True if generated content on this element would be readable.

    `state` holds (behind, ink, tiny, invisible). Unknown elements default
    to black ink on the page.
    """
    behind, ink, tiny, invisible = state or (PAGE, _INK, False, False)
    return not _text_unreadable(
        _behind(decl, behind),
        _ink(decl, ink),
        _tiny(decl, tiny),
        _invisible(decl, invisible),
    )


def _cascade(soup) -> dict[int, Declarations]:
    """Map id(element) to the declarations its <style> rules give it.

    Later rules win and specificity is ignored. Simple selectors use the
    index and the rest go through BeautifulSoup within _SELECT_BUDGET.
    """
    rules = _rules_of(soup)
    if not rules:
        return {}
    index = _Index(soup)
    budget = [_SELECT_BUDGET, time.monotonic() + _SELECT_SECONDS]
    # Match rules that can hide something first, so junk rules placed ahead
    # of them can't use up the budget. They are still applied in source
    # order, and a repeated selector is matched once.
    memo: dict[str, list] = {}

    def elements(selectors: str) -> list[list]:
        out = []
        for selector in dict.fromkeys(part.strip() for part in selectors.split(",")):
            if selector not in memo:
                memo[selector] = index.select(selector, budget)
            out.append(memo[selector])
        return out

    found = {
        i: elements(rules[i][0])
        for i in sorted(range(len(rules)), key=lambda i: (_tier(rules[i][1]), i))
    }
    # Each element styled costs one merge. Under _MAX_MERGES the rules that
    # can hide get priority, and the ones kept run in source order.
    kept, merges = [], _MAX_MERGES
    for i in sorted(found, key=lambda i: (_tier(rules[i][1]), i)):
        merges -= sum(len(group) for group in found[i])
        if merges < 0:
            break
        kept.append(i)
    styles: dict[int, Declarations] = {}
    for i in sorted(kept):
        decl = rules[i][1]
        for group in found[i]:
            for tag in group:
                own = styles.get(id(tag))
                if own is None:
                    styles[id(tag)] = own = Declarations()
                own.apply(decl)
    return styles


_COMBINATOR_RE = re.compile(r"[\s>+~]+")


def _last_compound(selector: str) -> str:
    """Return the last compound of a selector, e.g. "td.dark" for "table > tr td.dark:hover"."""
    last = _COMBINATOR_RE.split(selector.strip())[-1]
    return re.split(r"[\[:]", last, maxsplit=1)[0]


def _tier(decl: Declarations) -> int:
    """Sort key that puts rules able to hide something first."""
    return 0 if _hides_box(decl) or _may_hide(decl) else 1


def _may_hide(decl: Declarations) -> bool:
    return _hides_box(decl) or bool(
        {"color", "font-size", "visibility", "background", "background-color"} & decl.keys()
    )


def hidden_tags(soup) -> list:
    """Return the outermost hidden parts of a document in page order.

    A whole element is hidden by the hidden attribute, by <template>, by a
    closed <details> (except its <summary>) or by a box-level style. When a
    style only makes text unreadable, we wrap just that element's own text
    in a <span>. That way a dark section whose paragraphs set a light colour
    stays visible.

    Only the first MAX_ELEMENTS elements are examined. Call this before the
    <style> elements are removed.
    """
    sheet = _cascade(soup)
    state: dict[int, tuple] = {}  # id -> (behind, ink, tiny, invisible)
    hidden, ids = [], set()

    def add(tag) -> None:
        if not any(id(p) in ids for p in (tag, *tag.parents)):
            hidden.append(tag)
            ids.add(id(tag))

    for tag in soup.find_all(True, limit=MAX_ELEMENTS):
        p_behind, p_ink, p_tiny, p_invisible = state.get(id(tag.parent), (PAGE, _INK, False, False))
        decl = sheet.get(id(tag), Declarations()).then(style_declarations(tag.get("style", "")))
        behind = _behind(decl, p_behind, tag)
        ink = _ink(decl, p_ink, tag)
        tiny, invisible = _tiny(decl, p_tiny), _invisible(decl, p_invisible)
        state[id(tag)] = (behind, ink, tiny, invisible)
        if tag.name == "template" or tag.has_attr("hidden") or _hides_box(decl):
            add(tag)
            continue
        if tag.name in _MEDIA and (invisible or _tiny_box(decl, tag)):
            add(tag)  # invisible image (visibility hidden or 1 px)
            continue
        own_text = [
            c
            for c in tag.children
            if c.name is None and not isinstance(c, Comment) and str(c).strip()
        ]
        if tag.name == "details" and not tag.has_attr("open"):
            # Hide everything except the first <summary>, loose text included.
            summary = tag.find("summary", recursive=False)
            for child in list(tag.children):
                if child is summary or child in own_text:
                    continue
                add(child)
            for text in own_text:
                add(text.wrap(soup.new_tag("span")))
        elif own_text and _text_unreadable(behind, ink, tiny, invisible):
            for text in own_text:
                add(text.wrap(soup.new_tag("span")))
    # generated_text needs to know how each element's text is drawn.
    soup.pll_text_states = state
    return hidden


_MEDIA = frozenset({"img", "svg", "picture", "video", "canvas", "object", "embed", "iframe"})
# SVG shapes. A link wrapped around a <rect> shows the shape. The same list
# lives in content_scripts/core.js (shownLink).
_SHAPES = frozenset(
    {"rect", "path", "circle", "ellipse", "polygon", "polyline", "line", "use", "image"}
)
_NOT_SHOWN = frozenset(
    {"style", "script", "noscript", "noembed", "noframes", "title", "template", "head", "meta"}
)


def _tiny_box(decl: dict[str, str], tag) -> bool:
    """Return True if the width or height is 1 px or less (attribute or style)."""
    for key in ("width", "height", "max-width", "max-height"):
        for value in (decl.get(key), tag.get(key) if not key.startswith("max") else None):
            size = _length(str(value)) if value else None
            if size and size[0] <= 1 and size[1] in ("", "px"):
                return True
    return False


def shown_link(tag, hidden_ids: set[int], maps: frozenset[str] | None = None) -> bool:
    """Return True if the reader can see this link.

    It must sit outside every hidden part and show something, so links with
    transparent text can't stand in for the real one. An <area> has nothing
    of its own to show. It counts when an image that uses its <map> is
    visible. `maps` comes from shown_maps and is computed if not given.
    """
    if any(id(p) in hidden_ids for p in (tag, *tag.parents)):
        return False
    if tag.name != "area":
        return visible_content(tag, hidden_ids)
    area_map = tag.find_parent("map")
    name = str((area_map.get("name") or area_map.get("id") or "") if area_map else "").lower()
    if not name:
        return False
    if maps is None:
        root = tag
        while root.parent is not None:
            root = root.parent
        maps = shown_maps(root, hidden_ids)
    return name in maps


def shown_maps(soup, hidden_ids: set[int]) -> frozenset[str]:
    """Return the <map> names referenced by visible images (usemap="#name")."""
    return frozenset(
        str(img.get("usemap", "")).lower().lstrip("#")
        for img in soup.find_all(["img", "object"], usemap=True, limit=1000)
        if not any(id(p) in hidden_ids for p in (img, *img.parents))
    )


def visible_content(tag, hidden_ids: set[int]) -> bool:
    """Return True if the element shows text or media outside the hidden parts.

    Hidden subtrees are skipped without walking them.
    """
    stack = list(tag.children)
    while stack:
        node = stack.pop()
        if node.name is None:
            if not isinstance(node, Comment) and str(node).strip():
                return True
        elif id(node) in hidden_ids or node.name in _NOT_SHOWN:
            continue
        elif node.name in _MEDIA or node.name in _SHAPES:
            return True
        else:
            stack.extend(node.children)
    return False


def visible_text_first(soup, hidden: list | None = None, generated: str = "") -> str:
    """Return the visible text and generated words, then the hidden text."""
    hidden = [tag.extract() for tag in (hidden_tags(soup) if hidden is None else hidden)]
    text = soup.get_text(separator=" ") + (f"\n{generated}" if generated else "")
    tail = " ".join(tag.get_text(separator=" ") for tag in hidden)
    return f"{text}\n{tail}" if tail.strip() else text
