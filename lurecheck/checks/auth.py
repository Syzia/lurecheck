"""Did the message really come from the domain it claims?

Three mechanisms answer that, and the receiving mail server records the results:

* **SPF**: was the sending machine allowed to send for the *envelope* domain?
* **DKIM**: does a cryptographic signature from some domain match the message?
* **DMARC**: did SPF or DKIM pass **for the domain shown in From**? This is the
  one that matters. A phisher can pass SPF and DKIM for a domain of their own
  while showing the reader someone else's.

This check reads the results. It does not redo them: that would need DNS
lookups, and by default Lurecheck never touches the network.

**Which results to believe.** Anyone can type an Authentication-Results header
into the message they send. Mail servers add theirs at the top, so the topmost
one was added last, by the server closest to the reader. That is the one used.
If you know your mail server's name, ``Options.trusted_server`` pins it.
"""
from __future__ import annotations

from typing import List, Optional

from lurecheck.addresses import parse_addresses
from lurecheck.authresults import AuthResults, Result, parse_auth_results
from lurecheck.checks import Options
from lurecheck.findings import Finding
from lurecheck.message import Email
from lurecheck.text import domain_of, related

HEADER = "Authentication-Results"


def _from_domain(message: Email) -> str:
    addresses, _ = parse_addresses(message.first("From") or "")
    return addresses[0].domain if addresses else ""


def _spf_domain(result: Result) -> str:
    return domain_of(result.properties.get("smtp.mailfrom") or result.properties.get("smtp.helo") or "")


def _dkim_domain(result: Result) -> str:
    return domain_of(result.properties.get("header.d") or result.properties.get("header.i") or "")


def _describe(results: List[Result]) -> str:
    return "; ".join(result.describe() for result in results)


def check(message: Email, options: Options) -> List[Finding]:
    headers = [parse_auth_results(value) for value in message.all(HEADER)]
    if not headers:
        return [
            Finding(
                check="auth.no-results",
                severity="low",
                points=5,
                title="No sender-authentication results in the message",
                evidence=f"no {HEADER} header",
                explanation=(
                    "The receiving mail server normally records whether the sender was verified. Without that, "
                    "there is no way to tell from the file alone. Messages saved from a Sent folder, or by some "
                    "mail programs, lack it for innocent reasons."
                ),
            )
        ]

    findings: List[Finding] = []
    trusted: Optional[AuthResults] = headers[0]
    if options.trusted_server:
        wanted = options.trusted_server.lower()
        trusted = next((header for header in headers if header.server == wanted), None)
        if trusted is None:
            seen = ", ".join(sorted({header.server or "(unnamed)" for header in headers}))
            return [
                Finding(
                    check="auth.no-trusted-results",
                    severity="medium",
                    points=15,
                    title=f"No authentication results from {wanted}",
                    evidence=f"{len(headers)} {HEADER} header(s), from: {seen}",
                    explanation=(
                        "You named the mail server whose results you trust, and none of the results in this "
                        "message came from it. Results from any other server could have been written by the sender."
                    ),
                )
            ]
    ignored = [header for header in headers if header is not trusted]
    who = trusted.server or "a server that did not give its name"
    if ignored:
        findings.append(
            Finding(
                check="auth.other-results-ignored",
                severity="info",
                points=0,
                title=f"{len(ignored)} other set(s) of authentication results were ignored",
                evidence="ignored: " + " | ".join(
                    f"{header.server or '(unnamed)'}: {_describe(list(header.results)) or 'nothing'}" for header in ignored
                ),
                explanation=(
                    f"Only the results recorded by {who} were used. Anything further down the message could have "
                    "been typed in by the sender, so a 'pass' there proves nothing."
                ),
            )
        )

    shown = _from_domain(message)
    spf, dkim, dmarc = trusted.of("spf"), trusted.of("dkim"), trusted.of("dmarc")
    recorded = f" (recorded by {who})"

    # A server is meant to delete any older results carrying its own name before adding its own
    # (RFC 8601, section 5). So a second set under the same name, claiming a pass the real one
    # does not, is most likely the sender's own work.
    for header in ignored:
        if not trusted.server or header.server != trusted.server:
            continue
        claimed = [
            result for result in header.results
            if result.result == "pass" and not any(r.result == "pass" for r in trusted.of(result.method))
        ]  # fmt: skip
        if claimed:
            findings.append(
                Finding(
                    check="auth.conflicting-results",
                    severity="medium",
                    points=15,
                    title=f"A second set of results, also signed {who}, claims checks passed that did not",
                    evidence=f"lower in the message: {_describe(claimed)}   topmost: {_describe(list(trusted.results)) or 'nothing'}",
                    explanation=(
                        "A mail server removes older results bearing its own name before adding its own, so there "
                        "should only be one set. A second, more favourable set is usually typed in by the sender "
                        "to fool people and tools that read the wrong one. A message forwarded within the same "
                        "mail service is the innocent explanation."
                    ),
                )
            )
            break

    if any(result.result == "fail" for result in dmarc):
        findings.append(
            Finding(
                check="auth.dmarc-fail",
                severity="high",
                points=40,
                title=f"DMARC failed: the message did not come from {shown or 'the domain it shows'}",
                evidence=_describe(dmarc + spf + dkim) + recorded,
                explanation=(
                    "The domain shown in From publishes how its genuine mail can be recognised, and this message "
                    "does not match. Someone is using that domain's name without being able to send as it."
                ),
            )
        )
        return findings

    passed = [result for result in dmarc if result.result == "pass"]
    if passed:
        claimed = domain_of(passed[0].properties.get("header.from", ""))
        if claimed and shown and not related(claimed, shown):
            findings.append(
                Finding(
                    check="auth.dmarc-other-domain",
                    severity="high",
                    points=35,
                    title=f"DMARC passed for {claimed}, not for the domain shown ({shown})",
                    evidence=_describe(passed) + recorded,
                    explanation=(
                        "The server verified one domain while the From line a reader sees names another. That "
                        "happens when a message carries more than one From, built so the checker and the reader "
                        "look at different ones."
                    ),
                )
            )
        else:
            findings.append(
                Finding(
                    check="auth.dmarc-pass",
                    severity="info",
                    points=0,
                    title=f"DMARC passed for {claimed or shown or 'the From domain'}",
                    evidence=_describe(passed) + recorded,
                    explanation=(
                        "The message really was sent by, or on behalf of, the domain shown in From. That says who "
                        "sent it, not that they mean well: a phisher's own domain passes too."
                    ),
                )
            )
        return findings

    # No DMARC verdict. Work out what DMARC would look at: did SPF or DKIM pass for the From domain?
    spf_passes = [result for result in spf if result.result == "pass"]
    dkim_passes = [result for result in dkim if result.result == "pass"]
    aligned = [r for r in spf_passes if related(_spf_domain(r), shown)] + [
        r for r in dkim_passes if related(_dkim_domain(r), shown)
    ]
    if aligned:
        findings.append(
            Finding(
                check="auth.aligned-pass",
                severity="info",
                points=0,
                title=f"The sender was verified for {shown}",
                evidence=_describe(aligned) + recorded,
                explanation=(
                    "No DMARC result was recorded, but a check passed for the same domain the From line shows, "
                    "which is what DMARC tests."
                ),
            )
        )
        return findings

    if spf_passes or dkim_passes:
        others = sorted({_spf_domain(r) for r in spf_passes} | {_dkim_domain(r) for r in dkim_passes} - {""})
        findings.append(
            Finding(
                check="auth.passed-for-other-domain",
                severity="medium",
                points=20,
                title=f"The sender was verified, but as {', '.join(others) or 'another domain'}, not {shown or 'the From domain'}",
                evidence=_describe(spf_passes + dkim_passes) + recorded,
                explanation=(
                    "The checks passed for a different domain from the one the reader is shown. Legitimate "
                    "mailing services do this too, but it is also the standard way to pass the checks while "
                    "displaying someone else's name."
                ),
            )
        )
    for result in spf:
        if result.result in ("fail", "softfail"):
            soft = result.result == "softfail"
            findings.append(
                Finding(
                    check="auth.spf-softfail" if soft else "auth.spf-fail",
                    severity="low" if soft else "medium",
                    points=10 if soft else 20,
                    title="SPF soft-failed: the sending machine is probably not allowed to send for that domain"
                    if soft
                    else "SPF failed: the sending machine is not allowed to send for that domain",
                    evidence=result.describe() + recorded,
                    explanation=(
                        "The domain lists which machines may send its mail, and this one is not on the list. "
                        "Forwarded mail can fail this innocently."
                    ),
                )
            )
            break
    if any(result.result == "fail" for result in dkim):
        failed = [result for result in dkim if result.result == "fail"]
        findings.append(
            Finding(
                check="auth.dkim-fail",
                severity="medium",
                points=15,
                title="A DKIM signature did not match the message",
                evidence=_describe(failed) + recorded,
                explanation=(
                    "The message carries a signature that does not verify: it was altered after signing, or the "
                    "signature was copied from somewhere else. Mailing lists that edit messages cause this too."
                ),
            )
        )
    if not any(f.check != "auth.other-results-ignored" for f in findings):
        findings.append(
            Finding(
                check="auth.nothing-verified",
                severity="low",
                points=10,
                title="Nothing verified who sent this",
                evidence=(_describe(list(trusted.results)) or "no results listed") + recorded,
                explanation=(
                    "The receiving server checked, and no check passed. The sender's domain may simply not have "
                    "set these protections up, which is itself more common among throwaway domains."
                ),
            )
        )
    return findings
