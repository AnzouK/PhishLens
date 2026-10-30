"""
What an HTML email hides from its reader.

Hidden text placed before the message filled the text model's window with
words nobody sees, and hidden links pushed the real ones out. Hidden
parts are moved after the visible ones rather than dropped: a rule for
phones can show them again, and the reader may then see them.

The extension makes the same decision from the styles the browser
computed (content_scripts/core.js, PL.isHidden); both sides are checked
against tests/fixtures/hidden_cases.json.

hidden_tags(soup)          outermost hidden elements of a parsed document
visible_text_first(soup)   its text, the hidden parts last
is_hidden_style(style)     one inline style
"""

from __future__ import annotations

import re

_HIDING_STYLES = {
    "display": {"none"},
    "visibility": {"hidden", "collapse"},
    "mso-hide": {"all"},
}
# Smallest readable font size per unit (any other unit: above 0).
_MIN_FONT = {"px": 2.0, "pt": 2.0, "em": 0.2, "rem": 0.2, "%": 20.0, "": 2.0}
_SCALE_RE = re.compile(r"scale(?:x|y|3d)?\(([^()]{0,100})\)")
# Two colours closer than this on every channel look the same.
_SAME_COLOUR = 10
# An email is drawn on white unless it says otherwise.
_PAGE = (255, 255, 255)
_NAMED = {"white": (255, 255, 255), "black": (0, 0, 0)}
MAX_ELEMENTS = 20_000


def _length(value: str) -> tuple[float, str] | None:
    """(number, unit) of a CSS length ("0.01em" -> (0.01, "em")), or None."""
    value = value.strip().split(" ")[0].rstrip(")")
    num = value.rstrip("%abcdefghijklmnopqrstuvwxyz")
    try:
        return float(num), value[len(num) :]
    except ValueError:
        return None


def parse_colour(value: str) -> tuple[int, int, int, float] | None:
    """(r, g, b, alpha) of #rgb, #rgba, #rrggbb, #rrggbbaa, rgb(), rgba(),
    "rgb(r g b / a)", white, black or transparent; None otherwise."""
    value = value.strip().lower().replace(" ", ",").replace("/", ",")
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
            alpha = int(digits[6:8], 16) / 255 if len(digits) == 8 else 1.0
            return (r, g, b, alpha)
        if value.startswith(("rgb(", "rgba(")):
            parts = [p for p in value[value.index("(") + 1 :].rstrip(")").split(",") if p]
            r, g, b = (int(float(p.rstrip("%"))) for p in parts[:3])
            alpha = (
                float(parts[3].rstrip("%")) / (100 if parts[3].endswith("%") else 1)
                if len(parts) > 3
                else 1.0
            )
            return (r, g, b, alpha)
    except (ValueError, IndexError):
        return None
    return None


def _same_colour(a: tuple, b: tuple) -> bool:
    return all(abs(x - y) <= _SAME_COLOUR for x, y in zip(a[:3], b[:3], strict=True))


def style_declarations(style: str) -> dict[str, str]:
    decl: dict[str, str] = {}
    for item in (style or "")[:2000].lower().split(";"):
        key, sep, value = item.partition(":")
        if sep:
            decl[key.strip()] = value.replace("!important", "").strip()
    return decl


def background_colour(decl: dict[str, str]) -> tuple[int, int, int, float] | None | str:
    """The background a style sets: a colour, "image" (unknown, an image
    is drawn), or None (none set)."""
    background = decl.get("background-color") or decl.get("background", "")
    if "url(" in decl.get("background", "") or decl.get("background-image", "none") != "none":
        return "image"
    if not background:
        return None
    colour = parse_colour(background.split()[0] if background.startswith("#") else background)
    return colour if colour and colour[3] > 0.05 else None


def is_hidden_style(style: str, background: tuple | str | None = None) -> bool:
    """True when an inline style hides its text: display:none,
    visibility:hidden, opacity near 0, an unreadably small font, a
    transparent colour or one too close to the background (its own, else
    `background`, else white), no height or width with the overflow
    hidden, clipped away, placed far off the page, or scaled to nothing."""
    decl = style_declarations(style)
    if any(decl.get(key) in hiding for key, hiding in _HIDING_STYLES.items()):
        return True
    return _unreadable(decl, background) or _out_of_sight(decl)


def _unreadable(decl: dict[str, str], background) -> bool:
    opacity = _length(decl.get("opacity", "1"))
    if opacity and opacity[0] <= 0.05:
        return True
    size = _length(decl.get("font-size", ""))
    if size and (size[0] <= 0 or size[0] < _MIN_FONT.get(size[1], 0)):
        return True
    colour = parse_colour(decl["color"]) if decl.get("color") else None
    if not colour:
        return False
    if colour[3] <= 0.05:
        return True
    behind = background_colour(decl) or background or _PAGE
    return behind != "image" and _same_colour(colour, behind)


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


def _sheet_rules(soup) -> list[tuple[str, str]]:
    """(selector, declarations) of the top-level rules of the document's
    <style> sheets; rules inside @media and other at-rules are left out
    (a rule for phones shows or hides a copy of what the page has)."""
    rules: list[tuple[str, str]] = []
    for sheet in soup.find_all("style", limit=50):
        css = re.sub(r"/\*.*?\*/", " ", sheet.get_text()[:200_000], flags=re.S)
        depth, start, selector, body_start = 0, 0, "", 0
        for i, ch in enumerate(css):
            if ch == "{":
                if depth == 0:
                    selector, body_start = css[start:i].strip(), i + 1
                depth += 1
            elif ch == "}" and depth:
                depth -= 1
                if depth == 0:
                    if not selector.startswith("@"):
                        rules.append((selector, css[body_start:i]))
                    start = i + 1
                    if len(rules) >= 2000:
                        return rules
    return rules


def _hidden_by_sheets(soup, rules: list[tuple[str, str]]) -> list:
    """Elements a <style> rule hides (class, id, tag or any other selector
    BeautifulSoup understands)."""
    found = []
    for selectors, body in rules:
        if not is_hidden_style(body, background="image"):
            continue
        for selector in selectors.split(","):
            try:
                found += soup.select(selector.strip(), limit=MAX_ELEMENTS)
            except Exception:  # a selector soupsieve does not support
                continue
    return found


def _inherited_background(tag, sheets_paint: bool):
    """The background drawn behind a tag: the nearest set by it or an
    ancestor (style or bgcolor), "image" when one is an image or when a
    <style> sheet paints backgrounds and a class or id could pick one up
    (unknown here; the extension reads the real one)."""
    for node in (tag, *tag.parents):
        if not hasattr(node, "get"):
            break
        found = background_colour(style_declarations(node.get("style", "")))
        if found:
            return found
        if node.get("bgcolor"):
            colour = parse_colour(str(node["bgcolor"]))
            if colour:
                return colour
        if node.get("background") or (sheets_paint and (node.get("class") or node.get("id"))):
            return "image"
    return None


def hidden_tags(soup) -> list:
    """The outermost hidden elements: hidden by an attribute, an inline
    style, a <style> rule, a closed <details> (all but its <summary>) or
    a <template> (the first MAX_ELEMENTS elements are examined). Call it
    before removing the document's <style> elements."""
    hidden, ids = [], set()

    def add(tag) -> None:
        if id(tag) not in ids and not any(id(p) in ids for p in tag.parents):
            hidden.append(tag)
            ids.add(id(tag))

    rules = _sheet_rules(soup)
    sheets_paint = any("background" in body for _selector, body in rules)
    by_sheet = {id(t) for t in _hidden_by_sheets(soup, rules)}
    for tag in soup.find_all(True, limit=MAX_ELEMENTS):
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
        style = tag.get("style", "")
        if (
            tag.name == "template"
            or tag.has_attr("hidden")
            or id(tag) in by_sheet
            or (style and is_hidden_style(style, _inherited_background(tag.parent, sheets_paint)))
        ):
            add(tag)
    # Elements are examined in page order, so a parent comes before its
    # children; one listed earlier than its hidden parent was found by a
    # sheet rule: drop it.
    return [t for t in hidden if not any(id(p) in ids for p in t.parents)]


def visible_text_first(soup, hidden: list | None = None) -> str:
    """Text of a parsed HTML document: the visible text, then the text of
    the hidden elements (hidden_tags, unless given)."""
    hidden = [tag.extract() for tag in (hidden_tags(soup) if hidden is None else hidden)]
    text = soup.get_text(separator=" ")
    tail = " ".join(tag.get_text(separator=" ") for tag in hidden)
    return f"{text}\n{tail}" if tail.strip() else text
