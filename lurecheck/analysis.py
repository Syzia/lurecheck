"""Run every check over a message and collect the result."""
from __future__ import annotations

from typing import Callable, List, Optional, Sequence

from lurecheck.checks import Options, auth, links, sender
from lurecheck.findings import SEVERITIES, Finding, Report
from lurecheck.message import Email

Check = Callable[[Email, Options], List[Finding]]
CHECKS: Sequence[Check] = (sender.check, auth.check, links.check)
SUMMARY_HEADERS = ("From", "Reply-To", "To", "Subject", "Date")


def analyze(message: Email, source: str = "message", options: Optional[Options] = None) -> Report:
    options = options or Options()
    findings: List[Finding] = []
    for check in CHECKS:
        findings.extend(check(message, options))
    # Most serious first. Within a severity, the order the checks reported them in.
    findings.sort(key=lambda finding: (-SEVERITIES.index(finding.severity), -finding.points))
    summary = {name: message.text(name) for name in SUMMARY_HEADERS if message.first(name) is not None}
    return Report(source=source, summary=summary, findings=tuple(findings), notes=message.notes)
