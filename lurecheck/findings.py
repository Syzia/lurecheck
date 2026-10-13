"""What a check reports, and how reports add up to a verdict."""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Mapping, Tuple

SEVERITIES = ("info", "low", "medium", "high")

# Score needed for each verdict, highest first. These bands are provisional: they are
# first guesses until stage 4 measures them against a labelled set of messages.
VERDICTS = (
    (50, "likely phishing"),
    (20, "suspicious"),
    (0, "no strong signs of phishing"),
)
MAX_SCORE = 100


@dataclass(frozen=True)
class Finding:
    check: str  # a stable id, such as "auth.dmarc-fail"
    severity: str  # one of SEVERITIES. "info" is something worth knowing that adds no risk.
    points: int  # what this adds to the risk score
    title: str  # one line, for a person
    evidence: str  # the part of the message that caused it, as written
    explanation: str  # why it matters, in plain words

    def __post_init__(self) -> None:
        if self.severity not in SEVERITIES:
            raise ValueError(f"unknown severity {self.severity!r}")
        if self.points < 0 or (self.severity == "info") != (self.points == 0):
            raise ValueError("an info finding scores 0 and every other finding scores more than 0")


@dataclass(frozen=True)
class Report:
    source: str  # what was analysed, usually a file name
    summary: Mapping[str, str] = field(default_factory=dict)  # header name -> decoded value, for the top of the report
    findings: Tuple[Finding, ...] = ()
    notes: Tuple[str, ...] = ()  # oddities noticed while reading the file

    @property
    def score(self) -> int:
        return min(MAX_SCORE, sum(finding.points for finding in self.findings))

    @property
    def verdict(self) -> str:
        return next(name for threshold, name in VERDICTS if self.score >= threshold)
