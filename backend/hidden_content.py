"""
What an HTML email hides from its reader.

Hidden text placed before the message filled the text model's window with
words nobody sees, and hidden links pushed the real ones out. Hidden
parts are moved after the visible ones rather than dropped: a rule for
phones can show them again, and the reader may then see them.

Each element's style is its <style> rules (in order) then its inline
style; backgrounds are composed from the page (white) down, alpha
included. The extension makes the same decision from the styles the
browser computed (content_scripts/core.js, PL.isHidden); both sides are
checked against tests/fixtures/hidden_cases.json.

hidden_tags(soup)          outermost hidden elements of a parsed document
visible_text_first(soup)   its text, the hidden parts last
is_hidden_style(style)     one inline style, on a given background
"""

from __future__ import annotations

import colorsys
import re

_HIDING_STYLES = {
    "display": {"none"},
    "visibility": {"hidden", "collapse"},
    "mso-hide": {"all"},
}
# Smallest readable font size per unit (any other unit: above 0).
_MIN_FONT = {"px": 2.0, "pt": 2.0, "em": 0.2, "rem": 0.2, "%": 20.0, "": 2.0}
_SCALE_RE = re.compile(r"scale(?:x|y|3d)?\(([^()]{0,100})\)")
# Text and background with a contrast ratio under this cannot be read.
_MIN_CONTRAST = 1.2
# An email is drawn in black on white unless it says otherwise.
PAGE = (255, 255, 255)
_INK = (0, 0, 0)
_NAMED = {
    "white": (255, 255, 255),
    "black": (0, 0, 0),
    "silver": (192, 192, 192),
    "gray": (128, 128, 128),
    "grey": (128, 128, 128),
}
MAX_ELEMENTS = 20_000
_MAX_RULES = 300

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


def style_declarations(style: str) -> dict[str, str]:
    decl: dict[str, str] = {}
    for item in (style or "")[:4000].lower().split(";"):
        key, sep, value = item.partition(":")
        if sep:
            decl[key.strip()] = value.replace("!important", "").strip()
    return decl


def _own_background(decl: dict[str, str], tag=None) -> tuple | str | None:
    """The background an element paints: (r, g, b, alpha), "image"
    (unknown colour), or None. From its style, else its bgcolor or
    background attribute."""
    if "url(" in decl.get("background", "") or decl.get("background-image", "none") != "none":
        return "image"
    value = decl.get("background-color") or decl.get("background", "")
    if value:
        colour = parse_colour(value if value.startswith(("rgb", "hsl")) else value.split()[0])
        return colour if colour and colour[3] > 0 else None
    if tag is not None:
        if tag.get("background"):
            return "image"
        if tag.get("bgcolor"):
            return parse_colour(str(tag["bgcolor"]))
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


def is_hidden_style(style: str, background: tuple | None = None) -> bool:
    """True when an inline style hides its text: display:none,
    visibility:hidden, opacity near 0, an unreadably small font, a colour
    too close to the background behind it (its own over `background`, by
    default the white page), no height or width with the overflow hidden,
    clipped away, placed far off the page, or scaled to nothing."""
    decl = style_declarations(style)
    parent = PAGE if background is None else tuple(background[:3])
    return _hides(decl, _behind(decl, parent))


def _hides(decl: dict[str, str], behind: Colour | None, ink: Colour | None = None) -> bool:
    if any(decl.get(key) in hiding for key, hiding in _HIDING_STYLES.items()):
        return True
    return _unreadable(decl, behind, ink) or _out_of_sight(decl)


def _unreadable(decl: dict[str, str], behind: Colour | None, ink: Colour | None) -> bool:
    opacity = _length(decl.get("opacity", "1"))
    if opacity and opacity[0] <= 0.05:
        return True
    size = _length(decl.get("font-size", ""))
    if size and (size[0] <= 0 or size[0] < _MIN_FONT.get(size[1], 0)):
        return True
    colour = parse_colour(decl["color"]) if decl.get("color") else None
    if colour and colour[3] <= 0.05:
        return True
    if behind is None:
        return False
    text = over(colour, behind) if colour else ink
    return text is not None and _same_colour(text, behind)


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


def _sheet_rules(css: str, out: list[tuple[str, dict[str, str]]]) -> None:
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
                    out.append((head, style_declarations(body)))
                elif _applies_on_screen(head):
                    _sheet_rules(body, out)
                start = i + 1


def _cascade(soup) -> dict[int, dict[str, str]]:
    """id(element) -> the declarations its <style> rules give it, later
    rules over earlier ones (specificity is not weighed)."""
    rules: list[tuple[str, dict[str, str]]] = []
    for sheet in soup.find_all("style", limit=50):
        css = re.sub(r"/\*.*?\*/", " ", sheet.get_text()[:200_000], flags=re.S)
        _sheet_rules(css, rules)
    styles: dict[int, dict[str, str]] = {}
    for selectors, decl in rules:
        for selector in selectors.split(","):
            try:
                matched = soup.select(selector.strip(), limit=MAX_ELEMENTS)
            except Exception:  # a selector soupsieve does not support
                continue
            for tag in matched:
                styles.setdefault(id(tag), {}).update(decl)
    return styles


def hidden_tags(soup) -> list:
    """The outermost hidden elements: hidden by an attribute, their style
    (<style> rules then inline), a closed <details> (all but its
    <summary>) or a <template>; the first MAX_ELEMENTS elements are
    examined. Call it before removing the document's <style> elements."""
    sheet = _cascade(soup)
    behind: dict[int, Colour | None] = {}
    ink: dict[int, Colour | None] = {}
    hidden, ids = [], set()

    def add(tag) -> None:
        if not any(id(p) in ids for p in (tag, *tag.parents)):
            hidden.append(tag)
            ids.add(id(tag))

    for tag in soup.find_all(True, limit=MAX_ELEMENTS):
        parent = tag.parent
        parent_behind = behind.get(id(parent), PAGE) if parent is not None else PAGE
        parent_ink = ink.get(id(parent), _INK) if parent is not None else _INK
        decl = {**sheet.get(id(tag), {}), **style_declarations(tag.get("style", ""))}
        behind[id(tag)] = _behind(decl, parent_behind, tag)
        colour = parse_colour(decl["color"]) if decl.get("color") else None
        ink[id(tag)] = (
            over(colour, behind[id(tag)] or PAGE) if colour and colour[3] > 0.05 else parent_ink
        )
        if tag.name == "details" and not tag.has_attr("open"):
            # Everything but the <summary>, its bare text included.
            for child in list(tag.children):
                if getattr(child, "name", None) == "summary":
                    continue
                if child.name is None:
                    if not str(child).strip():
                        continue
                    child = child.wrap(soup.new_tag("span"))
                add(child)
        # The colour check only where this element sets a colour or a
        # background: its children are checked where they change them.
        paints = "color" in decl or _own_background(decl, tag) is not None
        if (
            tag.name == "template"
            or tag.has_attr("hidden")
            or ((decl or paints) and _hides(decl, behind[id(tag)] if paints else None, parent_ink))
        ):
            add(tag)
    return hidden


def visible_text_first(soup, hidden: list | None = None) -> str:
    """Text of a parsed HTML document: the visible text, then the text of
    the hidden elements (hidden_tags, unless given)."""
    hidden = [tag.extract() for tag in (hidden_tags(soup) if hidden is None else hidden)]
    text = soup.get_text(separator=" ")
    tail = " ".join(tag.get_text(separator=" ") for tag in hidden)
    return f"{text}\n{tail}" if tail.strip() else text
