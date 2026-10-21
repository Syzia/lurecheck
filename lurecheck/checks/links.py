"""Where do the links in the message really go?

A phishing message needs its reader to end up somewhere, and nearly always that
is a link. The reader sees the link's *text*. The browser follows its *address*.
This check reads every link, works out where the address goes without visiting
it (see ``lurecheck.urls``), and reports the ways the two are made to differ.

One finding is reported per kind of trick, however many links use it, with a
few examples as evidence. A message with forty copies of a bad link is no more
suspicious than a message with one.
"""
from __future__ import annotations

import re
import unicodedata
from typing import Dict, List, Tuple

from lurecheck.checks import Options
from lurecheck.findings import Finding
from lurecheck.markup import find_anchors
from lurecheck.message import Email
from lurecheck.text import related
from lurecheck.urls import ACTIVE_SCHEMES, SHORTENERS, Target, host_kind, read_target

MAX_LINKS = 2000
EXAMPLES = 3

_URL_IN_TEXT = re.compile(r"""(?:(?:https?|ftp)://|www\.)[^\s<>"'`]+""", re.IGNORECASE)
_TRAILING = ".,;:!?)]}>'\""
_SHOWN_ADDRESS = re.compile(r"(?:https?://|(?=www\.))([^/\s?#]+)", re.IGNORECASE)
_BARE_DOMAIN = re.compile(r"((?:[a-z0-9-]+\.)+([a-z]{2,24}))(?:[/?#]\S*)?")

# Endings common enough that "word.ending" on its own reads as a web address. Left out on purpose:
# endings that are also everyday file types (.zip, .sh, .py, .md), so "invoice.zip" is not a site.
_COMMON_ENDINGS = frozenset(
    "com org net edu gov mil int info biz io co ai app dev me tv us uk ca au nz de fr es it nl be ch at se no dk fi "
    "ie pt cz ru ua jp cn kr in sg hk tw br mx ar za il tr online site shop store xyz top club cloud tech bank "
    "news blog live link example test".split()
)

Link = Tuple[str, Target]  # (the text a reader sees, where the address goes)


def collect(message: Email) -> Tuple[List[Link], bool]:
    """Every link in the message's text parts, and whether there were too many to read them all."""
    links: List[Link] = []
    seen = set()
    truncated = False

    def add(text: str, address: str) -> None:
        nonlocal truncated
        key = (text, address)
        if key in seen:
            return
        if len(links) >= MAX_LINKS:
            truncated = True
            return
        seen.add(key)
        links.append((text, read_target(address)))

    for part in message.parts:
        if part.text is None:
            continue
        if part.content_type == "text/html":
            anchors, cut = find_anchors(part.text)
            truncated = truncated or cut
            for anchor in anchors:
                add(anchor.text, anchor.href)
        else:
            for match in _URL_IN_TEXT.finditer(part.text):
                address = match.group(0).rstrip(_TRAILING)
                add("", address if "://" in address else "http://" + address)
    return links, truncated


def shown_site(text: str) -> str:
    """The site a link's visible text names, if the text reads as a web address. Otherwise ""."""
    # Invisible characters are dropped first, so they cannot be used to dodge the comparison.
    text = "".join(char for char in text if unicodedata.category(char) != "Cf").strip().lower()
    match = _SHOWN_ADDRESS.search(text)
    if match:
        return match.group(1).rpartition("@")[2].split(":")[0].strip(".")
    bare = _BARE_DOMAIN.fullmatch(text)
    if bare and bare.group(2) in _COMMON_ENDINGS:
        return bare.group(1)
    return ""


def _examples(items: List[str]) -> str:
    unique = list(dict.fromkeys(items))
    more = f"   (and {len(unique) - EXAMPLES} more)" if len(unique) > EXAMPLES else ""
    return "   ".join(unique[:EXAMPLES]) + more


def check(message: Email, options: Options) -> List[Finding]:
    links, truncated = collect(message)
    web = [(text, target) for text, target in links if target.is_web and target.host]
    found: Dict[str, List[str]] = {}

    def note(check_id: str, example: str) -> None:
        found.setdefault(check_id, []).append(example)

    for text, target in links:
        if target.scheme in ACTIVE_SCHEMES:
            note("link.runs-code", target.written[:120])
        if target.oddities and (target.is_web or target.scheme in ACTIVE_SCHEMES):
            note("link.malformed", f"{target.written[:120]}  ({'; '.join(target.oddities)})")
    for text, target in web:
        shown = shown_site(text)
        if shown and not related(shown, target.host):
            note("link.text-shows-another-site", f'"{text[:80]}" goes to {target.host}')
        if target.name_before_at:
            note("link.name-before-at", f"{target.written[:120]}  (goes to {target.host})")
        kind = host_kind(target.host)
        if kind == "ip":
            note("link.ip-address", target.written[:120])
        elif kind == "disguised-ip":
            note("link.disguised-ip-address", target.written[:120])
        elif target.host.startswith("xn--") or ".xn--" in target.host or not target.host.isascii():
            note("link.international-domain", target.host)
        if target.host in SHORTENERS:
            note("link.shortened", target.written[:120])
        if target.carried and not related(target.carried, target.host):
            note("link.carries-another-address", f"{target.host} carrying {target.carried}")
        if target.through and not target.rewritten:
            note("link.bounces-through", f"{' then '.join(target.through)} then {target.host}")
        if target.rewritten:
            note("link.rewritten-by-security-service", f"{target.through[0]} to {target.host}")

    def finding(check_id: str, severity: str, points: int, title: str, explanation: str) -> Finding:
        return Finding(check=check_id, severity=severity, points=points, title=title,
                       evidence=_examples(found[check_id]), explanation=explanation)  # fmt: skip

    catalogue = (
        ("link.text-shows-another-site", "medium", 25, "A link's text names one site and its address goes to another",
         "The text of a link is whatever the sender typed. Showing a trusted address while pointing somewhere else is "
         "the oldest trick in phishing. Mailing services that track clicks do it too, which is why this is not scored higher."),
        ("link.name-before-at", "high", 35, "A link puts a trusted-looking name before an @ sign",
         "In a web address, everything between // and @ is a login name that the site ignores. The real destination is "
         "what comes after the @. It is written this way only to be misread."),
        ("link.disguised-ip-address", "high", 35, "A link goes to a numeric address written to not look like one",
         "Browsers accept an address as a single large number, or in hexadecimal. Nobody writes one that way except to "
         "get past filters and readers that would recognise the ordinary form."),
        ("link.runs-code", "high", 30, "A link runs code or carries a page inside itself, instead of going to a site",
         "Addresses beginning javascript: or data: do not lead anywhere. They make the mail program or browser execute "
         "or display what the sender supplied. Genuine mail has no reason to contain one."),
        ("link.ip-address", "medium", 25, "A link goes to a bare numeric address, not a named site",
         "Organisations send people to names they own. A raw number usually means a rented or hijacked machine that "
         "nobody bothered, or dared, to give a name."),
        ("link.malformed", "medium", 20, "A link's address is written in a way browsers accept and people misread",
         "Browsers quietly repair addresses: they drop line breaks and read a backslash as a slash. A link relying on "
         "that reads as one thing to a person or a filter and goes somewhere else in the browser."),
        ("link.bounces-through", "low", 10, "A link bounces off a well-known site on its way somewhere else",
         "The address starts at a site people trust, which then forwards the visitor to the real destination. It lends "
         "the link a reputation it has not earned."),
        ("link.carries-another-address", "low", 10, "A link's address carries a second address inside it",
         "The site it goes to is being handed another site's address, often to forward the visitor there. Click "
         "tracking and sharing buttons work this way too. Lurecheck cannot tell which without following it, and it never does."),
        ("link.shortened", "low", 10, "A link uses a shortening service, hiding where it leads",
         "The real destination is only revealed by opening the link, which Lurecheck never does. Shorteners are common "
         "in text messages and social media and unusual in mail from an organisation."),
        ("link.international-domain", "low", 10, "A link goes to a site whose name uses non-English letters",
         "Normal for many organisations, and also how lookalike names are made: a letter from another alphabet that "
         "looks identical to an English one."),
        ("link.rewritten-by-security-service", "info", 0, "Links were rewritten by a mail security service, and read through",
         "Your mail provider replaced each link with one that passes through its scanner first. Lurecheck looked inside "
         "the rewrite, so the other findings are about where the links really go."),
    )  # fmt: skip
    findings = [finding(*entry) for entry in catalogue if entry[0] in found]

    if web:
        sites = list(dict.fromkeys(target.host for _, target in web))
        findings.append(
            Finding(
                check="link.sites",
                severity="info",
                points=0,
                title="The message links to 1 site" if len(sites) == 1 else f"The message links to {len(sites)} sites",
                evidence=", ".join(sites[:8]) + (f" (and {len(sites) - 8} more)" if len(sites) > 8 else ""),
                explanation="Where the links go once any wrappers have been read through. Nothing was visited to find this out.",
            )
        )
    if truncated:
        findings.append(
            Finding(
                check="link.too-many",
                severity="info",
                points=0,
                title=f"The message has more than {MAX_LINKS} links; the rest were not read",
                evidence=f"the first {MAX_LINKS} links were checked",
                explanation="A limit, so that a message cannot make the analysis run for ever.",
            )
        )
    return findings
