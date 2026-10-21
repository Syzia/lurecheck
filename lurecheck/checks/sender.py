"""Is the sender who they appear to be?

What a reader sees is the *display name* and, sometimes, the address in From.
Neither is verified by anything, and several other headers decide where replies
and bounces really go. This check looks for the gaps between them.
"""
from __future__ import annotations

import re
from typing import List

from lurecheck.addresses import Address, parse_addresses
from lurecheck.checks import Options
from lurecheck.findings import Finding
from lurecheck.message import Email
from lurecheck.text import decode_words, domain_of, hidden_characters, related

ADDRESS_IN_TEXT = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+")


def _show(address: Address) -> str:
    return f'"{address.display}" <{address.address}>' if address.display else f"<{address.address}>"


def check(message: Email, options: Options) -> List[Finding]:
    findings: List[Finding] = []
    from_headers = message.all("From")
    if not from_headers:
        return [
            Finding(
                check="sender.no-from",
                severity="medium",
                points=20,
                title="The message has no From header",
                evidence="no From header",
                explanation="Every genuine message says who it is from. Mail programs show something anyway, which may be a guess.",
            )
        ]
    if len(from_headers) > 1:
        findings.append(
            Finding(
                check="sender.several-from-headers",
                severity="high",
                points=40,
                title=f"The message has {len(from_headers)} From headers",
                evidence=" | ".join(decode_words(value) for value in from_headers),
                explanation=(
                    "A message should have exactly one. With several, the server that checks the sender and the "
                    "mail program that shows it may each pick a different one, which is the point of doing it."
                ),
            )
        )

    addresses, oddities = parse_addresses(from_headers[0])
    written = decode_words(from_headers[0])
    if oddities or not addresses or not addresses[0].address:
        findings.append(
            Finding(
                check="sender.malformed-from",
                severity="medium",
                points=20,
                title="The From header is not written the way mail programs write it",
                evidence=f"{written}  ({'; '.join(oddities) or 'no address found'})",
                explanation=(
                    "Different programs read a malformed From line differently. That is used to show a reader one "
                    "sender while the checks look at another."
                ),
            )
        )
    if len(addresses) > 1:
        findings.append(
            Finding(
                check="sender.several-from-addresses",
                severity="medium",
                points=20,
                title=f"The From header lists {len(addresses)} senders",
                evidence=written,
                explanation="Almost no genuine mail has more than one author address. Readers are usually shown only the first.",
            )
        )
    if not addresses:
        return findings
    sender = addresses[0]

    for found in ADDRESS_IN_TEXT.findall(sender.display):
        if sender.domain and not related(domain_of(found), sender.domain):
            findings.append(
                Finding(
                    check="sender.name-shows-another-address",
                    severity="high",
                    points=35,
                    title=f"The sender's name displays {found}, but the real address is {sender.address}",
                    evidence=_show(sender),
                    explanation=(
                        "The name part of From is free text. Putting a trusted address there makes many mail "
                        "programs, phones especially, show only that and hide the address the message came from."
                    ),
                )
            )
            break

    hidden = hidden_characters(sender.display) + hidden_characters(sender.address)
    if hidden:
        findings.append(
            Finding(
                check="sender.hidden-characters",
                severity="medium",
                points=20,
                title=f"The sender's name or address contains {len(hidden)} invisible character(s)",
                evidence=_show(sender),
                explanation=(
                    "Characters that take up no space, or reverse the direction of text, have no place in a "
                    "sender's name. They make a name look right to a person while differing to a filter."
                ),
            )
        )

    if sender.domain.startswith("xn--") or ".xn--" in sender.domain or not sender.domain.isascii():
        findings.append(
            Finding(
                check="sender.international-domain",
                severity="info",
                points=0,
                title="The sender's domain uses non-English letters",
                evidence=sender.address,
                explanation=(
                    "Perfectly normal for many organisations. Whether it imitates a well-known name is the lookalike "
                    "check's job, which compares how it looks, not which alphabet it uses."
                ),
            )
        )

    reply_to, _ = parse_addresses(message.first("Reply-To") or "")
    elsewhere = [a for a in reply_to if a.domain and sender.domain and not related(a.domain, sender.domain)]
    if elsewhere:
        findings.append(
            Finding(
                check="sender.reply-goes-elsewhere",
                severity="medium",
                points=25,
                title=f"Replies go to {elsewhere[0].domain}, not to {sender.domain}",
                evidence=f"From: {_show(sender)}   Reply-To: {_show(elsewhere[0])}",
                explanation=(
                    "A reply would reach a different organisation from the one the message appears to come from. "
                    "That is how a forged sender still gets the victim's answer. Some newsletters and help desks "
                    "do this legitimately."
                ),
            )
        )

    return_path, _ = parse_addresses(message.first("Return-Path") or "")
    bounce = [a for a in return_path if a.domain and sender.domain and not related(a.domain, sender.domain)]
    if bounce:
        findings.append(
            Finding(
                check="sender.sent-through-another-domain",
                severity="info",
                points=0,
                title=f"The message was sent through {bounce[0].domain}",
                evidence=f"From: <{sender.address}>   Return-Path: <{bounce[0].address}>",
                explanation=(
                    "The technical sender differs from the one shown. Most bulk mail is sent this way through a "
                    "mailing service, so on its own this means little. The authentication results say whether "
                    "the shown domain agreed to it."
                ),
            )
        )
    return findings
