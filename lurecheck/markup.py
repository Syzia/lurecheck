"""Find the links in an HTML message body.

Python's own HTML parser is not used. On input built to slow it down it takes
time proportional to the *square* of the length: 80 KB of unclosed tags took it
over a minute when measured for this project, and some inputs make it raise.
A message body can be megabytes, and a phisher chooses what is in it.

This scanner does far less, in time proportional to the length: it finds
``<a href>`` and ``<area href>`` tags and the text a reader sees for each. It
is not a browser. Where browsers disagree about broken markup, it may too.

Three rules keep it linear:

* a ``<`` that does not start a tag name is text, decided by looking one
  character ahead;
* a tag's closing ``>`` is looked for within a fixed distance, and if it is not
  there the whole stretch is treated as text and skipped in one step;
* comments, scripts and styles are skipped to their end marker in one search.
"""
from __future__ import annotations

import html as html_entities
import re
from dataclasses import dataclass
from typing import Dict, List, Optional, Tuple

MAX_TAG = 16 * 1024  # a real tag is never this long
MAX_LINK_TEXT = 500
MAX_ANCHORS = 2000

_NAME = re.compile(r"/?[A-Za-z][A-Za-z0-9:-]*")
_ATTRIBUTE = re.compile(r"""([^\s=/>"']+)(?:\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s>]*)))?""")
_RAW_TEXT_END = {"script": re.compile(r"</script", re.IGNORECASE), "style": re.compile(r"</style", re.IGNORECASE)}
_SPACE = re.compile(r"\s+")
# Tags that put a gap between the words on either side of them.
_BREAKS = frozenset("br p div td th tr li table h1 h2 h3 h4 h5 h6 hr img".split())


@dataclass(frozen=True)
class Anchor:
    href: str  # where the link goes, as written, with character references such as &amp; decoded
    text: str  # what the reader sees for it; "" for an image or an empty link


def _tag_end(text: str, start: int) -> int:
    """The index of the ``>`` closing the tag that opens at ``start``, or -1 if none is near.

    A ``>`` inside a quoted attribute value does not close the tag.
    """
    limit = min(len(text), start + MAX_TAG)
    first = text.find(">", start + 1, limit)
    if first < 0:
        return -1
    if '"' not in text[start:first] and "'" not in text[start:first]:
        return first  # the common case, found without looking at each character
    quote = ""
    after_equals = False
    for index in range(start + 1, limit):
        char = text[index]
        if quote:
            if char == quote:
                quote = ""
        elif char == ">":
            return index
        elif char in "\"'" and after_equals:
            quote = char
            after_equals = False
        elif char == "=":
            after_equals = True
        elif not char.isspace():
            after_equals = False
    return -1


def _attributes(tag: str, start: int) -> Dict[str, str]:
    found: Dict[str, str] = {}
    for match in _ATTRIBUTE.finditer(tag, start):
        name = match.group(1).lower()
        if name not in found:  # a repeated attribute: browsers keep the first, so this does too
            value = next((group for group in match.groups()[1:] if group is not None), "")
            found[name] = html_entities.unescape(value)
    return found


def find_anchors(text: str) -> Tuple[List[Anchor], bool]:
    """The links in an HTML document, and whether the list was cut short at MAX_ANCHORS."""
    anchors: List[Anchor] = []
    href: Optional[str] = None
    words: List[str] = []
    kept = 0

    def say(piece: str) -> None:
        nonlocal kept
        if href is not None and kept < MAX_LINK_TEXT * 4 and piece:
            words.append(piece[: MAX_LINK_TEXT * 4])
            kept += len(piece)

    def close() -> None:
        nonlocal href, words, kept
        if href is not None and len(anchors) < MAX_ANCHORS:
            shown = _SPACE.sub(" ", html_entities.unescape("".join(words))).strip()
            anchors.append(Anchor(href=href, text=shown[:MAX_LINK_TEXT]))
        href, words, kept = None, [], 0

    index, length = 0, len(text)
    while index < length and len(anchors) < MAX_ANCHORS:
        opening = text.find("<", index)
        if opening < 0:
            say(text[index:])
            break
        say(text[index:opening])
        if text.startswith("<!--", opening):
            end = text.find("-->", opening + 4)
            index = length if end < 0 else end + 3
            continue
        following = text[opening + 1 : opening + 2]
        if not (following.isalpha() or following == "/"):
            if following in ("!", "?"):  # a declaration or processing instruction: skip to its end
                end = text.find(">", opening + 1)
                index = length if end < 0 else end + 1
            else:
                say("<")  # a stray "<" in ordinary text
                index = opening + 1
            continue
        end = _tag_end(text, opening)
        if end < 0:
            # No closing ">" within reach, so this is not a tag. Skip the whole stretch at once:
            # looking again from every "<" inside it is what makes other parsers slow.
            index = min(length, opening + MAX_TAG)
            continue
        tag = text[opening + 1 : end]
        index = end + 1
        match = _NAME.match(tag)
        if match is None:
            continue
        name = match.group(0).lower()
        if name in _RAW_TEXT_END:
            finish = _RAW_TEXT_END[name].search(text, index)
            index = length if finish is None else finish.start()
        elif name in ("a", "area"):
            close()
            attributes = _attributes(tag, match.end())
            if "href" in attributes:
                href = attributes["href"]
                if name == "area":
                    say(attributes.get("alt", ""))
                    close()
        elif name == "/a":
            close()
        elif name.lstrip("/") in _BREAKS:
            say(" ")
    close()
    return anchors, len(anchors) >= MAX_ANCHORS
