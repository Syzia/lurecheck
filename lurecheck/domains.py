"""Domain names: who owns one, and what it looks like to a person.

Two questions come up throughout Lurecheck:

* **Do two names belong to the same organisation?** ``mail.bank.example`` and
  ``bank.example`` do. ``bank.example.evil.example`` does not, whatever it
  starts with. The answer depends on the *registrable* part of a name: the part
  someone actually bought (``registrable``).
* **What does a name look like?** ``p\u0430ypal.com`` with a Cyrillic ``\u0430`` is a
  different name from ``paypal.com`` to a computer and the same name to a
  reader. ``skeleton`` reduces a name to how it looks, so the two compare equal.

Both are approximations made offline. The registrable part is worked out from a
short built-in list of endings that anyone can register under, not the full
Public Suffix List, and the lookalike table covers the letters most used to
imitate English ones, not all of Unicode.
"""
from __future__ import annotations

import ipaddress
import unicodedata
from typing import List

# Two-label endings that are public suffixes: anyone can register a name under them, so two
# domains sharing one are not the same organisation.
_SHARED_SUFFIXES = frozenset(
    "co.uk org.uk ac.uk gov.uk me.uk ltd.uk plc.uk net.uk sch.uk nhs.uk com.au net.au org.au edu.au gov.au id.au "
    "co.nz org.nz net.nz govt.nz ac.nz co.jp ne.jp or.jp ac.jp go.jp co.kr or.kr co.in net.in org.in gov.in "
    "com.br net.br org.br gov.br com.mx com.ar com.cn net.cn org.cn com.hk com.sg com.tr com.tw co.za org.za "
    "co.il org.il co.th com.my com.ph com.pk com.ua com.vn com.co com.pe com.sa com.eg com.ng co.ke co.id "
    "github.io gitlab.io herokuapp.com netlify.app vercel.app web.app firebaseapp.com pages.dev workers.dev "
    "blogspot.com wordpress.com azurewebsites.net cloudfront.net amazonaws.com appspot.com glitch.me "
    "ngrok.io ngrok-free.app duckdns.org no-ip.org r2.dev".split()
)

# Letters from other alphabets, and a few Latin ones, that are drawn like an English letter.
# A subset of Unicode's confusables table (UTS #39): the ones used to imitate domain names.
_LOOKS_LIKE = {
    # Cyrillic
    "\u0430": "a", "\u0435": "e", "\u0451": "e", "\u043e": "o", "\u0440": "p", "\u0441": "c", "\u0443": "y",
    "\u0445": "x", "\u0455": "s", "\u0456": "i", "\u0457": "i", "\u0458": "j", "\u0501": "d", "\u04bb": "h",
    "\u04cf": "l", "\u051b": "q", "\u051d": "w", "\u043a": "k", "\u0475": "v", "\u0461": "w", "\u0432": "b",
    # Greek
    "\u03b1": "a", "\u03bf": "o", "\u03c1": "p", "\u03bd": "v", "\u03b9": "i", "\u03ba": "k", "\u03c5": "u",
    "\u03b5": "e", "\u03f2": "c", "\u03f3": "j", "\u03c4": "t", "\u03c7": "x",
    # Armenian
    "\u0585": "o", "\u0570": "h", "\u057d": "u", "\u0581": "g", "\u0566": "q",
    # Latin letters that are not the English ones
    "\u0131": "i", "\u0269": "i", "\u0251": "a", "\u0261": "g", "\u0280": "r", "\u1d0f": "o", "\u0138": "k",
}  # fmt: skip
# Script pairs that legitimately share one name (Unicode's "highly restrictive" profile).
_MIXES_ALLOWED = (
    {"LATIN", "CJK", "HIRAGANA", "KATAKANA"},
    {"LATIN", "CJK", "BOPOMOFO"},
    {"LATIN", "CJK", "HANGUL"},
)


def domain_of(address: str) -> str:
    """The domain of an address, or of a bare domain: lower-cased, with no trailing dot."""
    return address.rsplit("@", 1)[-1].strip().strip(".").lower()


def _is_ip(domain: str) -> bool:
    try:
        ipaddress.ip_address(domain.strip("[]"))
        return True
    except ValueError:
        return False


def registrable(domain: str) -> str:
    """The part of a name someone registered: ``bank.example`` for ``mail.bank.example``.

    ``shop.co.uk`` for ``www.shop.co.uk``. "" for a name that is only an ending
    anyone can register under (``co.uk``, ``github.io``) or has no dot at all.
    A numeric address is its own registrable part.
    """
    domain = domain_of(domain)
    if not domain:
        return ""
    if _is_ip(domain):
        return domain.strip("[]")
    labels = domain.split(".")
    if len(labels) < 2:
        return ""
    if ".".join(labels[-2:]) in _SHARED_SUFFIXES:
        return ".".join(labels[-3:]) if len(labels) >= 3 else ""
    return ".".join(labels[-2:])


def related(first: str, second: str) -> bool:
    """Do two names belong to the same organisation, as far as can be told offline?

    True when they share a registrable part: the same name, a subdomain of it, or
    a sibling under it. This is an approximation of DMARC's "relaxed alignment".
    """
    owner = registrable(first)
    return bool(owner) and owner == registrable(second)


def unicode_form(domain: str) -> str:
    """A name as a reader would see it: ``xn--`` labels turned back into the letters they encode."""
    labels: List[str] = []
    for label in domain_of(domain).split("."):
        if label.startswith("xn--"):
            try:
                label = label[4:].encode("ascii").decode("punycode").lower()
            except (UnicodeError, ValueError):
                pass  # not valid; keep it as written
        labels.append(label)
    return ".".join(labels)


def skeleton(text: str) -> str:
    """What ``text`` looks like, reduced to plain English letters: ``p\u0430ypa1`` becomes ``paypal``.

    Accents are dropped, letters from other alphabets that are drawn like English
    ones are replaced, and the classic ASCII disguises are undone: ``rn`` for
    ``m``, ``vv`` for ``w``, ``0`` for ``o`` and ``1`` for ``l``.
    """
    decomposed = unicodedata.normalize("NFKD", text.lower())
    plain = "".join(_LOOKS_LIKE.get(char, char) for char in decomposed if unicodedata.category(char) != "Mn")
    return plain.replace("rn", "m").replace("vv", "w").replace("0", "o").replace("1", "l")


def scripts(label: str) -> List[str]:
    """The writing systems the letters of ``label`` come from, such as ["LATIN", "CYRILLIC"]."""
    found: List[str] = []
    for char in label:
        if unicodedata.category(char).startswith("L"):
            name = unicodedata.name(char, "UNKNOWN").split()[0]
            if name not in found:
                found.append(name)
    return found


def mixed_scripts(label: str) -> bool:
    """Does one label mix alphabets in a way no genuine name needs?"""
    used = set(scripts(label))
    return len(used) > 1 and not any(used <= allowed for allowed in _MIXES_ALLOWED)
