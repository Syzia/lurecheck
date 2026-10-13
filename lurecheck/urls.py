"""Work out where a link really goes, without visiting it.

A web address can be written so that a person reads one destination and a
browser goes to another. Everything here is offline: the address is taken apart
as text, the way a browser would take it apart, and nothing is ever fetched.

Some links are wrappers: they go to a service that immediately sends the
visitor on to an address carried inside the link. Mail security products
rewrite every link this way, and so do search engines and social networks.
``read_target`` looks inside the wrappers it knows, so the destination it
reports is the last one it can see.
"""
from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass
from typing import List, Optional, Tuple
from urllib.parse import parse_qsl, unquote, urlsplit

MAX_URL_CHARS = 8192
MAX_HOPS = 5

WEB_SCHEMES = ("http", "https", "ftp")
# Addresses that run or contain something instead of going somewhere.
ACTIVE_SCHEMES = ("javascript", "data", "vbscript", "file")

# Services that shorten an address, hiding where it leads until it is opened.
SHORTENERS = frozenset(
    "bit.ly tinyurl.com t.co goo.gl ow.ly is.gd buff.ly rebrand.ly cutt.ly shorturl.at tiny.cc rb.gy "
    "t.ly lnkd.in s.id v.gd bl.ink qrco.de shorte.st adf.ly bit.do x.co soo.gd clck.ru u.to".split()
)

_NUMERIC_HOST = re.compile(r"(?:0x[0-9a-f]+|\d+)(?:\.(?:0x[0-9a-f]+|\d+)){0,3}", re.IGNORECASE)
_STRIP = "".join(chr(code) for code in range(0x21))  # spaces and control characters around an address
_PROOFPOINT_HEX = re.compile(r"-([0-9A-Fa-f]{2})")


@dataclass(frozen=True)
class Target:
    written: str  # the address as it appears in the message
    scheme: str  # "https", "javascript", ... lower-case. "" if it has none.
    host: str  # where it finally goes: lower-case, no trailing dot. "" if it names no host.
    through: Tuple[str, ...] = ()  # wrappers passed on the way, outermost first
    rewritten: bool = False  # every wrapper passed was a mail security service's own rewrite
    carried: str = ""  # a host found inside the address of a service that is not a known wrapper
    name_before_at: str = ""  # in https://name@host/, the part before the @
    oddities: Tuple[str, ...] = ()  # ways the address is written that browsers accept and people misread

    @property
    def is_web(self) -> bool:
        return self.scheme in WEB_SCHEMES


def host_kind(host: str) -> str:
    """"ip", "disguised-ip", or "name"."""
    try:
        ipaddress.ip_address(host.strip("[]"))
        return "ip"
    except ValueError:
        pass
    # Browsers also accept an address as one big number, in hexadecimal, in octal, or with
    # parts left out: http://3232235777/ and http://0xC0.0xA8.1/ are both 192.168.1.x.
    return "disguised-ip" if _NUMERIC_HOST.fullmatch(host) else "name"


def _clean(url: str) -> Tuple[str, List[str]]:
    """The address as a browser would read it, and what had to be changed to get there."""
    oddities: List[str] = []
    url = url[:MAX_URL_CHARS].strip(_STRIP)
    if any(char in url for char in "\t\r\n"):
        oddities.append("line breaks or tabs inside the address")  # browsers silently remove them
        url = url.replace("\t", "").replace("\r", "").replace("\n", "")
    if "\\" in url.split("?", 1)[0].split("#", 1)[0]:
        oddities.append("backslashes in place of slashes")  # browsers read \ as /
        head, separator, tail = url.partition("?")
        url = head.replace("\\", "/") + separator + tail
    return url, oddities


def _proofpoint_v2(value: str) -> str:
    return _PROOFPOINT_HEX.sub(lambda match: chr(int(match.group(1), 16)), value.replace("_", "/"))


def _inside(url: str, host: str, path: str, query: str) -> Tuple[Optional[str], bool, bool]:
    """An address carried inside this one: (address, the outer service forwards to it, it is a security rewrite)."""
    try:
        fields = parse_qsl(query, keep_blank_values=True, max_num_fields=200)
    except ValueError:
        fields = []

    def field(*names: str) -> Optional[str]:
        return next((value for name, value in fields if name.lower() in names and value), None)

    if host.endswith(".safelinks.protection.outlook.com"):
        return field("url"), True, True
    if host == "urldefense.proofpoint.com":
        inner = field("u")
        if inner and path.startswith("/v2/"):
            inner = _proofpoint_v2(inner)
        return inner, True, True
    if host == "urldefense.com" and "/v3/__" in url:
        inner = url.split("/v3/__", 1)[1].split("__;", 1)[0]
        return inner or None, True, True
    if host in ("google.com", "www.google.com") and path == "/url":
        return field("q", "url"), True, False
    for _, value in fields:
        if value.lower().startswith(("http://", "https://")):
            return value, False, False  # some other site, carrying an address it may or may not forward to
    return None, False, False


def read_target(url: str) -> Target:
    """Take an address apart. Never raises, and never touches the network."""
    written = url[:MAX_URL_CHARS]
    current, oddities = _clean(url)
    through: List[str] = []
    rewritten = True
    carried = ""
    scheme = host = name_before_at = ""
    for _ in range(MAX_HOPS + 1):
        if current.startswith("//"):
            current = "https:" + current  # no scheme given: browsers use the page's, which for mail means https
        try:
            parts = urlsplit(current)
            scheme, host = parts.scheme.lower(), (parts.hostname or "").rstrip(".").lower()
            netloc, path, query = parts.netloc, parts.path, parts.query
        except ValueError:
            oddities.append("the address cannot be read")
            scheme = current.split(":", 1)[0].lower() if ":" in current else ""
            host = ""
            break
        if scheme not in WEB_SCHEMES:
            host = ""
            break
        if "[" in netloc or "]" in netloc:
            # Brackets are only for a numeric IPv6 address. Python versions disagree about
            # anything else in them, so decide here: it is that, or it is unreadable.
            try:
                ipaddress.IPv6Address(host)
            except ValueError:
                oddities.append("the address cannot be read")
                host = ""
                break
        if "%" in host:
            oddities.append("the site name is partly percent-encoded")  # browsers decode it; people cannot
            host = unquote(host).lower()
        name_before_at = netloc.rpartition("@")[0] if "@" in netloc else ""
        inner, forwards, security = _inside(current, host, path, query)
        if not inner:
            break
        inner, more = _clean(unquote(inner) if "%" in inner and "://" not in inner else inner)
        if not forwards:
            try:
                carried = (urlsplit(inner).hostname or "").rstrip(".").lower()
            except ValueError:
                carried = ""
            break
        through.append(host)
        rewritten = rewritten and security
        oddities += more
        current = inner
    else:
        oddities.append(f"wrapped more than {MAX_HOPS} times")
    return Target(
        written=written,
        scheme=scheme,
        host=host,
        through=tuple(through),
        rewritten=bool(through) and rewritten,
        carried=carried if carried != host else "",
        name_before_at=name_before_at,
        oddities=tuple(dict.fromkeys(oddities)),
    )
