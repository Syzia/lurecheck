"""Read an Authentication-Results header (RFC 8601).

When a mail server receives a message it checks who really sent it, and writes
down what it found in this header:

    Authentication-Results: mx.example.net;
        spf=pass smtp.mailfrom=news@shop.example;
        dkim=pass header.d=shop.example;
        dmarc=pass header.from=shop.example

The first item names the server that did the checking. Each item after it is one
check: a method (``spf``, ``dkim``, ``dmarc``), its result, and the details it
was about.

Anyone can type this header into a message they send. Only the copy added by
the reader's own mail server means anything, and deciding which copy that is
belongs to the caller (see ``lurecheck.checks.auth``).
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Dict, List, Mapping, Tuple

_EQUALS = re.compile(r"\s*=\s*")
_METHOD = re.compile(r"([A-Za-z0-9-]+)(?:/\d+)?=([A-Za-z0-9-]+)")


@dataclass(frozen=True)
class Result:
    method: str  # "spf", "dkim", "dmarc", ... lower-case
    result: str  # "pass", "fail", "softfail", "none", ... lower-case
    properties: Mapping[str, str]  # such as {"smtp.mailfrom": "news@shop.example"}; keys lower-case

    def describe(self) -> str:
        details = "".join(f" {key}={value}" for key, value in self.properties.items() if key != "reason")
        return f"{self.method}={self.result}{details}"


@dataclass(frozen=True)
class AuthResults:
    server: str  # who did the checking, lower-case. "" when the header does not say (Exchange Online omits it).
    results: Tuple[Result, ...]

    def of(self, method: str) -> List[Result]:
        return [result for result in self.results if result.method == method]


def _segments(value: str) -> List[str]:
    """Split on semicolons, dropping (comments). Quoted text is kept whole."""
    segments, current = [], []
    quoted = False
    comment = 0
    index = 0
    while index < len(value):
        char = value[index]
        if char == "\\" and (quoted or comment) and index + 1 < len(value):
            if quoted:
                current.append(value[index + 1])
            index += 2
            continue
        if quoted:
            quoted = char != '"'
            if quoted:
                current.append(char)
        elif comment:
            comment += (char == "(") - (char == ")")
        elif char == '"':
            quoted = True
        elif char == "(":
            comment = 1
            current.append(" ")
        elif char == ";":
            segments.append("".join(current))
            current = []
        else:
            current.append(char)
        index += 1
    segments.append("".join(current))
    return [_EQUALS.sub("=", segment).strip() for segment in segments]


def parse_auth_results(value: str) -> AuthResults:
    """Parse one Authentication-Results header value. Never raises: unreadable items are skipped."""
    segments = _segments(value)
    server = ""
    if segments and "=" not in segments[0]:
        words = segments.pop(0).split()
        server = words[0].lower() if words else ""
    results: List[Result] = []
    for segment in segments:
        words = segment.split()
        if not words:
            continue
        head = _METHOD.fullmatch(words[0])
        if head is None:
            continue  # "none", or something that is not a result
        properties: Dict[str, str] = {}
        for word in words[1:]:
            key, separator, detail = word.partition("=")
            if separator and key and key.lower() not in properties:
                properties[key.lower()] = detail
        results.append(Result(method=head.group(1).lower(), result=head.group(2).lower(), properties=properties))
    return AuthResults(server=server, results=tuple(results))
