"""Small text helpers shared by the reader, the checks and the report.

Everything that passes through here came out of an email under suspicion, so
these helpers decode and compare text. They never interpret it.
"""
from __future__ import annotations

import re
import unicodedata
from email.errors import HeaderParseError
from email.header import decode_header, make_header

_FOLD = re.compile(r"\r?\n(?=[ \t])")
_BREAK = re.compile(r"\r\n|\r|\n")  # a line break that was not a fold: it has no business in a header

# Characters a reader cannot see, or that change the order the text around them is drawn in.
# Used to disguise a name: "Pay<zero-width space>Pal", or right-to-left overrides that
# make "gpj.exe" display as "exe.jpg".
_HIDDEN = frozenset(
    "\u00ad\u061c\u180e\u200b\u200c\u200e\u200f\u202a\u202b\u202c\u202d\u202e"
    "\u2060\u2061\u2062\u2063\u2064\u2066\u2067\u2068\u2069\ufeff"
)
_JOINER = "\u200d"  # zero-width joiner: hidden, except where it glues an emoji sequence together
_EMOJI_NEIGHBOURS = ("So", "Sk", "Mn", "Me")

# Two-label endings that are public suffixes: anyone can register a name under them, so two
# domains sharing one are not the same organisation. A stopgap until stage 3 brings a fuller list.
_SHARED_SUFFIXES = frozenset(
    "co.uk org.uk ac.uk gov.uk me.uk ltd.uk com.au net.au org.au edu.au gov.au co.nz org.nz "
    "co.jp ne.jp or.jp co.kr co.in net.in org.in com.br com.mx com.ar com.cn com.hk com.sg "
    "com.tr com.tw co.za co.il co.th com.my com.ph com.pk com.ua com.vn github.io gitlab.io "
    "herokuapp.com netlify.app vercel.app web.app pages.dev blogspot.com wordpress.com "
    "azurewebsites.net cloudfront.net amazonaws.com".split()
)


def unfold(value: str) -> str:
    """Join a header that was wrapped over several lines back into one."""
    return _BREAK.sub(" ", _FOLD.sub("", value)).strip()


def decode_words(value: str) -> str:
    """Decode encoded words such as ``=?utf-8?b?...?=``. Text that will not decode is returned as written."""
    if "=?" not in value:
        return value
    try:
        return str(make_header(decode_header(value)))
    except (LookupError, HeaderParseError, UnicodeError, ValueError):
        return value


def hidden_characters(text: str) -> list:
    """The invisible or direction-changing characters in ``text``, in order."""
    found = []
    for index, char in enumerate(text):
        if char in _HIDDEN:
            found.append(char)
        elif char == _JOINER:
            before = text[index - 1] if index else ""
            if not before or unicodedata.category(before) not in _EMOJI_NEIGHBOURS:
                found.append(char)
    return found


def visible(text: str, limit: int = 200) -> str:
    """``text`` made safe to print: nothing in it can move the cursor, hide itself or reorder the line.

    Control and format characters are shown as escapes (``\\x1b``, ``\\u202e``), and
    anything past ``limit`` characters is cut, with a note of how much.
    """
    out = []
    for char in text[:limit]:
        if unicodedata.category(char) in ("Cc", "Cf", "Co", "Cs", "Cn", "Zl", "Zp"):
            code = ord(char)
            out.append("\\x%02x" % code if code < 0x100 else "\\u%04x" % code if code < 0x10000 else "\\U%08x" % code)
        else:
            out.append(char)
    if len(text) > limit:
        out.append(f"… (+{len(text) - limit} more)")
    return "".join(out)


def domain_of(address: str) -> str:
    """The domain of an address, or of a bare domain: lower-cased, with no trailing dot."""
    return address.rsplit("@", 1)[-1].strip().strip(".").lower()


def related(first: str, second: str) -> bool:
    """Do two domains belong to the same organisation, as far as can be told offline?

    True when they are the same, or one is a subdomain of the other, unless the
    shorter one is a suffix anyone can register under (``co.uk``, ``github.io``).
    This is an approximation of DMARC's "relaxed alignment".
    """
    first, second = domain_of(first), domain_of(second)
    if not first or not second:
        return False
    if first == second:
        return True
    shorter, longer = sorted((first, second), key=len)
    if "." not in shorter or shorter in _SHARED_SUFFIXES:
        return False
    return longer.endswith("." + shorter)
