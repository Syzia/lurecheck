"""Is a domain in the message made to look like a well-known one?

The sender's domain, the domains replies go to, and the destinations of links
are each compared with the brands in ``lurecheck.brands`` and any domains given
with ``--protect``. Five kinds of imitation are recognised, strongest first:

* **lookalike characters**: ``p\u0430ypal.com`` with a Cyrillic ``\u0430``, ``paypa1.com``
  with a digit, ``rnicrosoft.com`` with ``rn`` for ``m``. Read by a person, the
  same name.
* **the real name as a subdomain**: ``paypal.com.account-verify.example``. The
  name a reader recognises is at the start; the owner is at the end.
* **one letter off**: ``paypall.com``, ``micorsoft.com``. Only for names of
  six letters or more: below that, a one-letter change is often just another
  word (``chasm`` is not an imitation of ``chase``).
* **the real name plus other words**: ``paypal-support.example``.
* **the same name under a different ending**: ``paypal.co``. Weakest, because
  large organisations own many endings and the list here cannot know them all.

Separately: a label that mixes alphabets (Latin and Cyrillic in one word) is
reported whether or not it imitates anything, because no genuine name needs to;
and a display name that names a brand, sent from a domain that brand does not
use, is reported too.
"""
from __future__ import annotations

import re
import unicodedata
from dataclasses import dataclass
from typing import Dict, List, Optional, Sequence, Tuple

from lurecheck.addresses import parse_addresses
from lurecheck.checks.sender import ADDRESS_IN_TEXT
from lurecheck.brands import BUILT_IN, Brand, protected
from lurecheck.checks import Options
from lurecheck.checks.links import collect
from lurecheck.domains import mixed_scripts, registrable, related, scripts, skeleton, unicode_form
from lurecheck.findings import Finding
from lurecheck.message import Email
from lurecheck.urls import host_kind

EXAMPLES = 3
KINDS = ("characters", "brand-in-subdomain", "one-letter-off", "brand-plus-words", "different-ending")


@dataclass(frozen=True)
class Imitation:
    kind: str  # one of KINDS
    brand: Brand
    imitated: str  # the brand's domain it imitates


def _split(owner: str) -> Tuple[str, str]:
    """``("paypal", "com")`` for ``paypal.com``; ``("shop", "co.uk")`` for ``shop.co.uk``."""
    label, _, ending = owner.partition(".")
    return label, ending


def _distance(first: str, second: str, limit: int) -> int:
    """Edit distance, counting a swap of neighbouring letters as one edit. Stops early above ``limit``."""
    if abs(len(first) - len(second)) > limit:
        return limit + 1
    previous2: List[int] = []
    previous = list(range(len(second) + 1))
    for i, a in enumerate(first, 1):
        current = [i] + [0] * len(second)
        for j, b in enumerate(second, 1):
            current[j] = min(previous[j] + 1, current[j - 1] + 1, previous[j - 1] + (a != b))
            if i > 1 and j > 1 and a == second[j - 2] and first[i - 2] == b:
                current[j] = min(current[j], previous2[j - 2] + 1)
        if min(current) > limit:
            return limit + 1
        previous2, previous = previous, current
    return previous[-1]


def imitation(host: str, brands: Sequence[Brand]) -> Optional[Imitation]:
    """The strongest way ``host`` imitates one of ``brands``, or None. A brand's own domain imitates nothing."""
    owner = registrable(host)
    if not owner or host_kind(owner) != "name":
        return None
    if any(related(host, domain) for brand in brands for domain in brand.domains):
        return None
    shown_owner = unicode_form(owner)
    label, ending = _split(shown_owner)
    label_shape = skeleton(label)
    shown_host = unicode_form(host)
    subdomains = shown_host[: -len(shown_owner)].rstrip(".") if shown_host.endswith(shown_owner) else ""
    found: List[Imitation] = []
    for brand in brands:
        for domain in brand.domains:
            real_label, real_ending = _split(registrable(domain) or domain)
            real_shape = skeleton(real_label)
            if label_shape == real_shape and label != real_label:
                found.append(Imitation("characters", brand, domain))
            elif subdomains and (("." + subdomains + ".").find("." + domain + ".") >= 0 or real_label in subdomains.split(".")):
                found.append(Imitation("brand-in-subdomain", brand, domain))
            elif len(real_label) >= 6 and label != real_label and _distance(label_shape, real_shape, 1) == 1:
                found.append(Imitation("one-letter-off", brand, domain))
            elif label != real_label and (
                (len(real_label) >= 5 and real_shape in label_shape)
                or real_label in re.split(r"[-_]", label)
            ):
                found.append(Imitation("brand-plus-words", brand, domain))
            elif label == real_label and ending != real_ending:
                found.append(Imitation("different-ending", brand, domain))
    return min(found, key=lambda item: KINDS.index(item.kind)) if found else None


def _brands(options: Options) -> List[Brand]:
    return protected(options.protected) + list(BUILT_IN)


def _readable(host: str) -> str:
    """The host, plus how it reads if it is written in xn-- form, naming the letters that are not English.

    The foreign letter is the whole point, and it is invisible to a reader, so it is spelled out.
    """
    shown = unicode_form(host)
    if shown == host:
        return host
    foreign = list(dict.fromkeys(char for char in shown if not char.isascii()))
    names = "; ".join(f"{char} is {unicodedata.name(char, 'an unnamed character').lower()}" for char in foreign[:3])
    return f"{host} (reads as {shown}; {names})" if names else f"{host} (reads as {shown})"


def check(message: Email, options: Options) -> List[Finding]:
    brands = _brands(options)
    places: Dict[str, List[str]] = {}  # host -> where it appears

    def seen(host: str, where: str) -> None:
        if host and where not in places.setdefault(host, []):
            places[host].append(where)

    senders, _ = parse_addresses(message.first("From") or "")
    for sender in senders[:1]:
        seen(sender.domain, "From")
    for reply in parse_addresses(message.first("Reply-To") or "")[0]:
        seen(reply.domain, "Reply-To")
    links, _ = collect(message)
    for _, target in links:
        if target.is_web and target.host:
            seen(target.host, "link")

    by_kind: Dict[str, List[str]] = {}
    first_of_kind: Dict[str, Imitation] = {}
    mixed: List[str] = []
    for host, where in places.items():
        match = imitation(host, brands)
        if match:
            by_kind.setdefault(match.kind, []).append(f"{_readable(host)} in {', '.join(where)} imitates {match.imitated}")
            first_of_kind.setdefault(match.kind, match)
        labels = unicode_form(registrable(host) or host).split(".")
        tangled = [label for label in labels if mixed_scripts(label)]
        if tangled and not match:  # an imitation already says more than this would
            mixed.append(f"{_readable(host)} in {', '.join(where)}: {' + '.join(scripts(tangled[0])).title()}")

    def examples(items: List[str]) -> str:
        more = f"   (and {len(items) - EXAMPLES} more)" if len(items) > EXAMPLES else ""
        return "   ".join(items[:EXAMPLES]) + more

    catalogue = {
        "characters": ("lookalike.characters", "high", 40, "imitates {brand} with lookalike characters",
                       "The name is spelled with letters or digits that look like the real ones: a Cyrillic letter in place of "
                       "a Latin one, a 1 for an l, rn for m. To a reader it is the same name. To a computer it is somebody else's."),
        "brand-in-subdomain": ("lookalike.brand-in-subdomain", "high", 35, "puts {brand}'s name in front of someone else's domain",
                               "A domain is read from the right: the owner is the last part before the ending. Putting a well-known "
                               "name at the front makes the link look like it belongs to that organisation when it does not."),
        "one-letter-off": ("lookalike.one-letter-off", "medium", 25, "is one letter away from {brand}'s domain",
                           "A doubled, missing or swapped letter in a long, well-known name is rarely an accident. Typing errors "
                           "are what these domains are registered to catch."),
        "brand-plus-words": ("lookalike.brand-plus-words", "medium", 20, "combines {brand}'s name with other words",
                             "Names like brand-support or brand-secure-login are cheap to register and look official. The genuine "
                             "organisation may own some of them; the list Lurecheck compares with cannot know them all."),
        "different-ending": ("lookalike.different-ending", "low", 10, "is {brand}'s name under a different ending",
                             "The same name with a different ending (.co instead of .com) is a different owner, unless the "
                             "organisation registered both. Large ones often do, which is why this counts for little on its own."),
    }  # fmt: skip
    findings: List[Finding] = []
    for kind in KINDS:
        if kind in by_kind:
            check_id, severity, points, title, explanation = catalogue[kind]
            findings.append(
                Finding(
                    check=check_id,
                    severity=severity,
                    points=points,
                    title="A domain in the message " + title.format(brand=first_of_kind[kind].brand.name),
                    evidence=examples(by_kind[kind]),
                    explanation=explanation,
                )
            )
    if mixed:
        findings.append(
            Finding(
                check="lookalike.mixed-alphabets",
                severity="medium",
                points=20,
                title="A domain mixes letters from different alphabets in one word",
                evidence=examples(mixed),
                explanation=(
                    "Genuine names are written in one alphabet. Mixing Latin with Cyrillic or Greek letters inside one "
                    "word is how a name is made to look familiar while being different."
                ),
            )
        )

    if senders and senders[0].domain:
        sender = senders[0]
        # An address typed into the name is the sender check's finding. Take it out here, so the
        # same trick is not counted twice, and read hyphens as spaces: "Northwind-Bank" is "northwind bank".
        named = re.sub(r"[-_]", " ", ADDRESS_IN_TEXT.sub(" ", sender.display).lower())
        for brand in brands:
            phrase = next((p for p in brand.phrases if re.search(r"(?<![a-z0-9])" + re.escape(p) + r"(?![a-z0-9])", named)), None)
            if phrase and not any(related(sender.domain, domain) for domain in brand.domains):
                own_label = _split(unicode_form(registrable(sender.domain)))[0]
                if any(own_label == _split(registrable(domain) or domain)[0] for domain in brand.domains):
                    # The domain *is* the brand's name under another ending. Claiming that name adds
                    # nothing; the ending is the question, and it is reported as an imitation of its own.
                    break
                findings.append(
                    Finding(
                        check="lookalike.name-claims-brand",
                        severity="medium",
                        points=25,
                        title=f"The sender's name says {brand.name}, but the message is not from {brand.name}'s domains",
                        evidence=f'"{sender.display}" <{sender.address}>   ({brand.name} uses {", ".join(brand.domains[:3])})',
                        explanation=(
                            "The name shown for a sender is free text. A message calling itself a well-known organisation "
                            "from a domain that organisation does not use is either sent on its behalf by a third party, "
                            "or pretending."
                        ),
                    )
                )
                break
    return findings
