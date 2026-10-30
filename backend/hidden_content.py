"""
What an HTML email hides from its reader.

Hidden text placed before the message filled the text model's window with
words nobody sees, and hidden links pushed the real ones out. Hidden
parts are moved after the visible ones rather than dropped: a rule for
phones can show them again, and the reader may then see them.

Each element's style is its <style> rules (in order, !important kept)
then its inline style; backgrounds are composed from the page (white)
down, alpha included. A style can hide a whole box (display, opacity,
clipping...) or only make an element's own text unreadable (colour,
size, visibility): then its children, which may set their own, are
judged on their own. The extension makes the same decision from the styles the
browser computed (content_scripts/core.js, PL.isHidden); both sides are
checked against tests/fixtures/hidden_cases.json.

hidden_tags(soup)          outermost hidden elements of a parsed document
visible_text_first(soup)   its text, the hidden parts last
is_hidden_style(style)     one inline style, on a given background
"""

from __future__ import annotations

import colorsys
import re
import time

import soupsieve
from bs4 import Comment

# Styles that hide an element and everything in it. visibility is not
# one: a child can say visible again (see _invisible).
_HIDING_STYLES = {
    "display": {"none"},
    "mso-hide": {"all"},
}
# Smallest readable font size per unit (any other unit: above 0).
_MIN_FONT = {"px": 2.0, "pt": 2.0, "em": 0.2, "rem": 0.2, "%": 20.0, "": 2.0}
_SCALE_RE = re.compile(r"scale(?:x|y|3d)?\(([^()]{0,100})\)")
# Text and background with a contrast ratio under this cannot be read.
_MIN_CONTRAST = 1.2
# An email is drawn in black on white unless it says otherwise.
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
    """(number, unit) of a CSS length ("0.01em" -> (0.01, "em")), or None."""
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
    """(r, g, b, alpha) of a CSS colour: #rgb, #rgba, #rrggbb, #rrggbbaa,
    rgb()/rgba() in numbers or percentages, hsl()/hsla(), the space and
    "/" syntax, a few names, transparent; None otherwise."""
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
    """`top` (r, g, b, alpha) drawn over the opaque `bottom`."""
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
    """Too little contrast to read: a WCAG contrast ratio under
    _MIN_CONTRAST (white on #f0f0f0 is 1.1; body text needs 4.5)."""
    la, lb = sorted((_luminance(a), _luminance(b)))
    return (lb + 0.05) / (la + 0.05) < _MIN_CONTRAST


class Declarations(dict):
    """Property -> value, lower case, with the properties marked
    !important in `important`."""

    def __init__(self, *args, important=(), **kwargs):
        super().__init__(*args, **kwargs)
        self.important = set(important)

    def then(self, later: Declarations) -> Declarations:
        """These declarations with `later` applied over them: a later value
        wins unless this one is !important and the later one is not."""
        out = Declarations(self, important=self.important)
        for key, value in later.items():
            if key in self.important and key not in later.important:
                continue
            out.pop(key, None)  # moved last: the order says which came later
            out[key] = value
            if key in later.important:
                out.important.add(key)
        return out


_COMMENT_RE = re.compile(r"/\*.*?\*/", re.S)
_IMPORTANT_RE = re.compile(r"!\s*important\b", re.IGNORECASE)


def style_declarations(style: str) -> Declarations:
    decl = Declarations()
    for item in _COMMENT_RE.sub(" ", (style or "")[:4000]).split(";"):
        key, sep, value = item.partition(":")
        if sep:
            key = key.strip().lower()
            # Values in lower case, but the words of "content" as written.
            value = value if key == "content" else value.lower()
            important = bool(_IMPORTANT_RE.search(value))
            if key in decl.important and not important:
                continue  # an !important value is kept over a later plain one
            if important:
                decl.important.add(key)
            decl.pop(key, None)  # moved last: the order says which came later
            decl[key] = _IMPORTANT_RE.sub("", value).strip()
    return decl


_COLOUR_FN_RE = re.compile(r"(?:rgba?|hsla?)\([^()]{0,80}\)")


def _background_value(value: str) -> tuple | str | None:
    """The colour of a background value, shorthand included ("no-repeat
    center #0b57d0", "rgb(11, 87, 208) no-repeat"); "image" for an image
    or a gradient; None for none."""
    if "url(" in value or "gradient(" in value or "image(" in value:
        return "image"
    found = _COLOUR_FN_RE.search(value)
    tokens = [found.group(0)] if found else value.split()
    for token in tokens:
        colour = parse_colour(token)
        if colour:
            return colour if colour[3] > 0 else None
    # A value with no colour this module reads (a variable, currentColor,
    # a name it does not know): unknown, never assumed white.
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
    """The background an element paints: (r, g, b, alpha), "image"
    (unknown colour), or None. From its style (the later of background
    and background-color), else its bgcolor or background attribute."""
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
    """The colour behind an element's text: its own background over its
    parent's. None when unknown (an image is drawn, and nothing opaque
    covers it)."""
    own = _own_background(decl, tag)
    if own == "image":
        return None
    if own is None:
        return parent
    if parent is None:
        return tuple(own[:3]) if own[3] >= 1 else None
    return over(own, parent)


def _hides_box(decl: dict[str, str]) -> bool:
    """The element and everything in it are out of view: display:none,
    opacity near 0, clipped, off the page or scaled to nothing."""
    if any(decl.get(key) in hiding for key, hiding in _HIDING_STYLES.items()):
        return True
    opacity = _length(decl.get("opacity", "1"))
    return bool(opacity and opacity[0] <= 0.05) or _out_of_sight(decl)


def _tiny(decl: dict[str, str], parent_tiny: bool) -> bool:
    """The font is too small to read: set so here, or inherited (an em or
    percent size of a tiny font stays tiny)."""
    size = _length(decl.get("font-size", "")) if decl.get("font-size") else None
    if size is None:
        return parent_tiny
    if size[0] <= 0 or size[0] < _MIN_FONT.get(size[1], 0):
        return True
    return parent_tiny and size[1] in ("em", "%")


def _invisible(decl: dict[str, str], parent_invisible: bool) -> bool:
    """visibility:hidden, inherited until a child says visible."""
    value = decl.get("visibility")
    return value in ("hidden", "collapse") if value else parent_invisible


def _ink(decl: dict[str, str], parent_ink: tuple, tag=None) -> tuple:
    """The colour text is drawn in, (r, g, b, alpha), alpha kept
    (transparent text stays transparent whatever is behind it): its own
    (style, or <font color>), else inherited. An unknown colour is
    inherited too."""
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
    """True when an inline style hides the text of its element: display
    none, visibility hidden, opacity near 0, an unreadably small font, a
    colour too close to the background behind it (its own over
    `background`, by default the white page), no height or width with the
    overflow hidden, clipped away, placed far off the page, or scaled to
    nothing."""
    decl = style_declarations(style)
    parent = PAGE if background is None else tuple(background[:3])
    behind = _behind(decl, parent)
    ink = _ink(decl, _INK)
    return _hides_box(decl) or _text_unreadable(
        behind, ink, _tiny(decl, False), _invisible(decl, False)
    )


def _out_of_sight(decl: dict[str, str]) -> bool:
    """Clipped to nothing, far off the page, or scaled to nothing."""
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
    """An @media block every screen reads: "@media screen", "@media all"
    (no width or other feature: those are the phone copies)."""
    words = condition.lower().replace(",", " ").split()
    return bool(words) and words[0] == "@media" and set(words[1:]) <= {"screen", "all", "only"}


# Properties that can hide something; a rule without any is skipped.
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
    """(selectors, declarations) of the rules of a style sheet, in order:
    top-level ones and those of @media blocks every screen reads.
    Statements such as @charset and @import end at their ";"."""
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


# A selector made of a tag, classes and an id only ("td.dark", ".h", "#x"):
# matched from an index, without walking the document.
_SIMPLE_RE = re.compile(r"^([a-z][a-z0-9-]*|\*)?((?:[.#][a-z0-9_-]+)*)$", re.IGNORECASE)
# Work allowed for all rules together, in elements checked or styled: 2,000
# selectors over 10,000 elements took two minutes. Rules past it are not
# applied (the email's own <style> is long enough to be suspect anyway).
_SELECT_BUDGET = 20_000
_SELECT_SECONDS = 0.5
# Styles given to elements, all rules together ("div" repeated in 5,000
# rules over 5,000 elements is 25 million).
_MAX_MERGES = 500_000


# Tags, classes and ids named in a selector; attribute tests and
# pseudo-classes are set aside first.
_TOKEN_RE = re.compile(r"([.#]?)([a-z][a-z0-9_-]*)", re.IGNORECASE)
_ATTRS_RE = re.compile(r"\[[^\]]*\]|::?[a-z-]+(?:\([^)]*\))?", re.IGNORECASE)


class _Index:
    """The document's elements by tag, class and id."""

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
        """The elements a selector matches. Simple selectors come from the
        index at no cost. Others cost one unit per candidate, taken from
        `budget` ([units left, deadline]); they match nothing once it is
        spent or past, or when they name a tag, class or id the email does
        not have."""
        matched = self.simple(selector)
        if matched is not None:
            return matched
        if budget[0] <= 0 or time.monotonic() > budget[1]:
            return []
        for kind, name in _TOKEN_RE.findall(_ATTRS_RE.sub("", selector)):
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
        except Exception:  # a selector soupsieve does not support
            return []
        matched = []
        for n, tag in enumerate(candidates):
            # Some selectors cost far more per element (":nth-child" over
            # a thousand siblings): the clock bounds them too.
            if n % 100 == 0 and time.monotonic() > budget[1]:
                break
            if compiled.match(tag):
                matched.append(tag)
        return matched

    def simple(self, selector: str) -> list | None:
        """The elements a simple selector matches, or None when it is not
        a simple one (memoised: a sheet can repeat one thousands of
        times)."""
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
    """The rules of the document's <style> sheets (300,000 characters of
    CSS at most, all sheets together)."""
    rules: list[tuple[str, Declarations]] = []
    left = 300_000
    for sheet in soup.find_all("style", limit=50):
        css = sheet.get_text()[:left]
        left -= len(css)
        _sheet_rules(_COMMENT_RE.sub(" ", css), rules)
        if left <= 0:
            break
    return rules


_PSEUDO_RE = re.compile(r"::?(?:before|after)\b", re.IGNORECASE)
_QUOTED_RE = re.compile(r"\"([^\"]{0,500})\"|'([^']{0,500})'")


def generated_text(soup, hidden: list | None = None) -> str:
    """Words a <style> sheet writes on the page itself (::before and
    ::after content): the reader sees them, the document's text does not
    hold them, so a lure written there was out of the text model's reach.
    Left out: rules whose content is hidden (display, size, visibility,
    transparent colour), rules for elements not in the email or inside a
    `hidden` part; selectors are matched within a work budget, 200 words
    at most."""
    hidden_ids = {id(t) for t in hidden or []}
    index, words, budget = None, [], [20_000, time.monotonic() + _SELECT_SECONDS]
    for selector, decl in _rules_of(soup):
        content = decl.get("content", "")
        if not _PSEUDO_RE.search(selector) or not _QUOTED_RE.search(content):
            continue
        if _hides_box(decl) or _text_unreadable(
            None, _ink(decl, _INK), _tiny(decl, False), _invisible(decl, False)
        ):
            continue
        index = index or _Index(soup)
        for part in selector.split(","):
            base = _PSEUDO_RE.sub("", part).strip() or "*"
            shown = [
                t
                for t in index.select(base, budget)
                if not any(id(p) in hidden_ids for p in (t, *t.parents))
            ]
            if shown:
                words += [a or b for a, b in _QUOTED_RE.findall(content)]
                break
        if len(words) >= 200:
            break
    return " ".join(w.replace("\\a", " ") for w in words)


def _cascade(soup) -> dict[int, Declarations]:
    """id(element) -> the declarations its <style> rules give it, later
    rules over earlier ones (specificity is not weighed). Simple selectors
    come from an index, others from BeautifulSoup, within _SELECT_BUDGET."""
    rules = _rules_of(soup)
    if not rules:
        return {}
    index = _Index(soup)
    budget = [_SELECT_BUDGET, time.monotonic() + _SELECT_SECONDS]
    # Rules that hide a box are matched first, then those that change
    # colour, size or visibility, then the rest, so that junk rules placed
    # before them cannot spend the budget; all are then applied in their
    # own order.
    order = sorted(range(len(rules)), key=lambda i: (_tier(rules[i][1]), i))
    matches: dict[int, list] = {}
    merges = _MAX_MERGES
    for i in order:
        found: list = []
        for selector in dict.fromkeys(part.strip() for part in rules[i][0].split(",")):
            found += index.select(selector, budget)
        merges -= len(found)
        if merges < 0:
            break
        matches[i] = found
    styles: dict[int, Declarations] = {}
    for i in sorted(matches):
        for tag in matches[i]:
            styles[id(tag)] = styles.get(id(tag), Declarations()).then(rules[i][1])
    return styles


_COMBINATOR_RE = re.compile(r"[\s>+~]+")


def _last_compound(selector: str) -> str:
    """The last compound of a selector, without attributes or
    pseudo-classes: "td.dark" in "table > tr td.dark:hover"."""
    last = _COMBINATOR_RE.split(selector.strip())[-1]
    return re.split(r"[\[:]", last, maxsplit=1)[0]


def _tier(decl: Declarations) -> int:
    if _hides_box(decl):
        return 0
    return 1 if _may_hide(decl) else 2


def _may_hide(decl: Declarations) -> bool:
    return _hides_box(decl) or bool(
        {"color", "font-size", "visibility", "background", "background-color"} & decl.keys()
    )


def hidden_tags(soup) -> list:
    """The outermost hidden parts of a document, in page order. An element
    is hidden whole by an attribute, a <template>, a closed <details>
    (all but its <summary>), or a style that hides its box (display,
    opacity, clipping, position, scale). A style that only makes text
    unreadable (colour, size, visibility) hides that element's own text,
    wrapped in a <span>: a dark section whose paragraphs set a light
    colour stays visible. Styles are its <style> rules then inline; the
    first MAX_ELEMENTS elements are examined. Call it before removing the
    document's <style> elements."""
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
            add(tag)  # an image no one sees: visibility hidden, or 1 px
            continue
        own_text = [
            c
            for c in tag.children
            if c.name is None and not isinstance(c, Comment) and str(c).strip()
        ]
        if tag.name == "details" and not tag.has_attr("open"):
            # Everything but its first <summary>, bare text included.
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
    return hidden


_MEDIA = frozenset({"img", "svg", "picture", "video", "canvas", "object", "embed", "iframe"})
_NOT_SHOWN = frozenset({"style", "script", "noscript", "title", "template", "head", "meta"})


def _tiny_box(decl: dict[str, str], tag) -> bool:
    """Width or height of 1 px or less, from the attributes or the style."""
    for key in ("width", "height", "max-width", "max-height"):
        for value in (decl.get(key), tag.get(key) if not key.startswith("max") else None):
            size = _length(str(value)) if value else None
            if size and size[0] <= 1 and size[1] in ("", "px"):
                return True
    return False


def shown_link(tag, hidden_ids: set[int]) -> bool:
    """A link the reader can see: outside every hidden part, and showing
    something (an <area> always does). Fifty links whose only text was
    transparent once filled the place of the real one."""
    if any(id(p) in hidden_ids for p in (tag, *tag.parents)):
        return False
    return tag.name == "area" or visible_content(tag, hidden_ids)


def visible_content(tag, hidden_ids: set[int]) -> bool:
    """True when an element shows something outside the hidden parts: some
    text, or an image or other media hidden_tags did not set aside.
    Hidden subtrees are skipped, not walked."""
    stack = list(tag.children)
    while stack:
        node = stack.pop()
        if node.name is None:
            if not isinstance(node, Comment) and str(node).strip():
                return True
        elif id(node) in hidden_ids or node.name in _NOT_SHOWN:
            continue
        elif node.name in _MEDIA:
            return True
        else:
            stack.extend(node.children)
    return False


def visible_text_first(soup, hidden: list | None = None, generated: str = "") -> str:
    """Text of a parsed HTML document: the visible text and the words its
    style sheets write (`generated`), then the text of the hidden elements
    (hidden_tags, unless given)."""
    hidden = [tag.extract() for tag in (hidden_tags(soup) if hidden is None else hidden)]
    text = soup.get_text(separator=" ") + (f"\n{generated}" if generated else "")
    tail = " ".join(tag.get_text(separator=" ") for tag in hidden)
    return f"{text}\n{tail}" if tail.strip() else text
