"""Turn a Report into something to read: plain text for a terminal, or JSON for another program.

Everything printed here came out of a hostile message. ``visible`` makes each
piece safe for a terminal first: an email must not be able to clear the screen,
recolour the output or forge lines of this report.
"""
from __future__ import annotations

import textwrap
from typing import Any, Dict, List

from lurecheck.findings import MAX_SCORE, Report
from lurecheck.text import visible

WIDTH = 100


def to_dict(report: Report) -> Dict[str, Any]:
    return {
        "source": report.source,
        "verdict": report.verdict,
        "score": report.score,
        "max_score": MAX_SCORE,
        "summary": dict(report.summary),
        "findings": [
            {
                "check": finding.check,
                "severity": finding.severity,
                "points": finding.points,
                "title": finding.title,
                "evidence": finding.evidence,
                "explanation": finding.explanation,
            }
            for finding in report.findings
        ],
        "notes": list(report.notes),
    }


def _wrap(label: str, text: str, limit: int) -> List[str]:
    indent = " " * 6
    # Addresses and domains are never split across lines: a broken one is hard to read and to copy.
    return textwrap.wrap(
        f"{label}: {visible(text, limit)}", width=WIDTH, initial_indent=indent, subsequent_indent=indent + "  ",
        break_on_hyphens=False, break_long_words=False,
    ) or [indent + label + ":"]  # fmt: skip


def render_text(report: Report) -> str:
    lines = [f"Lurecheck report: {visible(report.source, 120)}", ""]
    lines.append(f"Verdict: {report.verdict.upper()}  (risk score {report.score} of {MAX_SCORE})")
    lines.append("")
    for name, value in report.summary.items():
        lines.append(f"  {name + ':':<10} {visible(value, 160)}")

    scored = [finding for finding in report.findings if finding.points]
    noted = [finding for finding in report.findings if not finding.points]
    lines += ["", "Findings" if scored else "Findings: none that raise the risk score"]
    for finding in scored:
        lines.append(f"  [{finding.severity:<6} +{finding.points:>2}] {visible(finding.title, 160)}")
        lines += _wrap("Evidence", finding.evidence, 400)
        lines += _wrap("Why it matters", finding.explanation, 600)
        lines.append("")
    if noted:
        if not scored:
            lines.append("")
        lines.append("Also noted (adds nothing to the score)")
        for finding in noted:
            lines.append(f"  [info] {visible(finding.title, 160)}")
            lines += _wrap("Evidence", finding.evidence, 400)
            lines += _wrap("What it means", finding.explanation, 600)
            lines.append("")
    if report.notes:
        lines.append("While reading the file")
        lines += [f"  - {visible(note, 200)}" for note in report.notes]
        lines.append("")
    lines.append(
        "A low score means these checks found little, not that the message is safe. "
        "The score bands are provisional until they have been measured."
    )
    return "\n".join(line.rstrip() for line in lines) + "\n"
