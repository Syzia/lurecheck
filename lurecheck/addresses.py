"""Read the addresses out of a From, Reply-To or Return-Path header.

Python's own address parser gives different answers in different versions, and
quietly returns nothing for input it dislikes. A header built to confuse parsers
is exactly what this tool needs to look at, so this reads the structure itself
and reports anything odd instead of hiding it.

The structure is read from the header **as written**, before any encoded words
are decoded. Decoding first would let an encoded display name smuggle in angle
brackets or commas and change which part is taken to be the address.
"""
from __future__ import annotations

import re
import unicodedata
from dataclasses import dataclass
from typing import List, Tuple

from lurecheck.text import decode_words, domain_of

_DOMAIN = re.compile(r"(?:[^\s@<>()\[\]\\,;:\"]+|\[[0-9A-Fa-f:.]+\])")


@dataclass(frozen=True)
class Address:
    display: str  # the name shown to the reader, decoded; "" if there is none
    address: str  # the address itself, as written but with no spaces
    valid: bool = True  # False: it is not shaped like an address, so its domain cannot be trusted

    @property
    def domain(self) -> str:
        return domain_of(self.address) if self.valid and self.address else ""


def _split(value: str) -> Tuple[List[str], bool]:
    """Split a header on top-level commas. Also says whether quotes or brackets were left open."""
    pieces, current = [], []
    quoted = False
    comment = angle = 0
    index = 0
    while index < len(value):
        char = value[index]
        if char == "\\" and (quoted or comment) and index + 1 < len(value):
            current.append(value[index : index + 2])
            index += 2
            continue
        if quoted:
            quoted = char != '"'
        elif comment:
            comment += (char == "(") - (char == ")")
        elif char == '"':
            quoted = True
        elif char == "(":
            comment = 1
        elif char == "<":
            angle += 1
        elif char == ">":
            angle = max(0, angle - 1)
        elif char == "," and not angle:
            pieces.append("".join(current))
            current = []
            index += 1
            continue
        current.append(char)
        index += 1
    pieces.append("".join(current))
    return [piece.strip() for piece in pieces if piece.strip()], bool(quoted or comment or angle)


def _outside_quotes(text: str) -> str:
    """``text`` with quoted strings and (comments) blanked out, same length, for finding structure."""
    out = []
    quoted = False
    comment = 0
    index = 0
    while index < len(text):
        char = text[index]
        if char == "\\" and (quoted or comment) and index + 1 < len(text):
            out.append("  ")
            index += 2
            continue
        if quoted:
            quoted = char != '"'
            out.append(" ")
        elif comment:
            comment += (char == "(") - (char == ")")
            out.append(" ")
        elif char == '"':
            quoted = True
            out.append(" ")
        elif char == "(":
            comment = 1
            out.append(" ")
        else:
            out.append(char)
        index += 1
    return "".join(out)


def _strip_comments(text: str) -> str:
    """``text`` without (comments). Quoted strings are kept whole."""
    out = []
    quoted = False
    comment = 0
    index = 0
    while index < len(text):
        char = text[index]
        if char == "\\" and (quoted or comment) and index + 1 < len(text):
            if quoted:
                out.append(text[index : index + 2])
            index += 2
            continue
        if quoted:
            quoted = char != '"'
            out.append(char)
        elif comment:
            comment += (char == "(") - (char == ")")
        elif char == "(":
            comment = 1
        else:
            quoted = char == '"'
            out.append(char)
        index += 1
    return "".join(out)


def _unquote(text: str) -> str:
    text = text.strip()
    if len(text) >= 2 and text[0] == text[-1] == '"':
        text = re.sub(r"\\(.)", r"\1", text[1:-1])
    return text


def _valid(address: str) -> bool:
    if address.count("@") != 1 and not address.startswith('"'):
        return False
    local, _, domain = address.rpartition("@")
    if any(c.isspace() or unicodedata.category(c) == "Cc" for c in address):
        return False  # no address contains a space or a control character
    return bool(local) and bool(_DOMAIN.fullmatch(domain))


def parse_addresses(value: str) -> Tuple[List[Address], List[str]]:
    """The addresses in a header value, and a list of anything odd about how it was written."""
    oddities: List[str] = []
    pieces, unbalanced = _split(value)
    if unbalanced:
        oddities.append("a quote or bracket is never closed")
    addresses: List[Address] = []
    for piece in pieces:
        structure = _outside_quotes(piece)
        spans = [(m.start(), m.end()) for m in re.finditer(r"<[^<>]*>", structure)]
        if spans:
            if len(spans) > 1:
                oddities.append("more than one address in angle brackets")
            start, end = spans[-1]
            display, address = piece[:start], piece[start + 1 : end - 1]
            if structure[end:].strip():
                oddities.append("text after the address")
        else:
            # No angle brackets: the whole piece is the address, apart from any (comments).
            display, address = "", _strip_comments(piece)
        address = address.strip()
        stripped = "".join(address.split())
        if stripped != address:
            oddities.append("spaces inside the address")
        address = stripped
        if not address and spans:
            # "<>" is the empty address servers use for bounce messages. Nothing to report.
            addresses.append(Address(display=decode_words(_unquote(display)), address=""))
            continue
        valid = _valid(address)
        if not valid:
            oddities.append("not a valid address")
        addresses.append(Address(display=decode_words(_unquote(display)), address=address, valid=valid))
    return addresses, oddities
