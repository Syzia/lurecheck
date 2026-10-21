"""Measure Lurecheck: how often it flags phishing, and how often it flags legitimate mail.

    python -m lurecheck.evaluate                              # 20 simulated runs of every scenario
    python -m lurecheck.evaluate --published                  # exactly the tables in docs/results.md
    python -m lurecheck.evaluate --folder ~/phishing-samples  # your own saved emails, in phish/ and benign/

A message counts as **flagged** when its score reaches the "suspicious" band,
the point at which the report tells a reader to be careful. The tables never
contain an address, a subject or any other text from a message: only counts and
finding ids. That keeps them safe to share when they come from real email.
"""
from __future__ import annotations

import argparse
import os
from collections import Counter
from dataclasses import dataclass
from typing import Dict, Iterable, List, Optional, Sequence, Tuple

from lurecheck.analysis import analyze
from lurecheck.checks import Options
from lurecheck.findings import VERDICTS
from lurecheck.message import MessageError, load_email, read_email
from lurecheck.simulator import BENIGN, PHISH, PROTECTED, SCENARIOS, Sample, generate

FLAG_AT = next(threshold for threshold, name in VERDICTS if name == "suspicious")
LIKELY_AT = next(threshold for threshold, name in VERDICTS if name == "likely phishing")
PUBLISHED_SEEDS = range(1, 51)
SWEEP = (5, 10, 15, 20, 25, 30, 35, 40, 50, 60)
KIND = {PHISH: "phishing", BENIGN: "legitimate"}


@dataclass(frozen=True)
class Outcome:
    group: str  # the scenario's name, or the folder a real message was in
    label: str  # PHISH or BENIGN
    score: int
    scored: Tuple[str, ...]  # the findings that added points
    expected_flag: Optional[bool] = None  # what a simulated scenario expects; None for real mail
    documented: str = ""


def run(samples: Iterable[Sample], options: Options) -> List[Outcome]:
    outcomes = []
    for sample in samples:
        report = analyze(read_email(sample.data), options=options)
        outcomes.append(
            Outcome(
                group=sample.scenario.name, label=sample.scenario.label, score=report.score,
                scored=tuple(f.check for f in report.findings if f.points),
                expected_flag=sample.scenario.expected_flag, documented=sample.scenario.documented,
            )  # fmt: skip
        )
    return outcomes


def run_folder(root: str, options: Options) -> Tuple[List[Outcome], int]:
    """Every .eml under root/phish and root/benign. Returns the outcomes and how many files could not be read."""
    outcomes, unreadable = [], 0
    for label in (PHISH, BENIGN):
        folder = os.path.join(root, label)
        for current, folders, files in os.walk(folder):
            folders.sort()
            for name in sorted(files):
                if not name.lower().endswith(".eml"):
                    continue
                try:
                    report = analyze(load_email(os.path.join(current, name)), options=options)
                except MessageError:
                    unreadable += 1
                    continue
                group = os.path.relpath(current, os.path.dirname(folder))
                outcomes.append(Outcome(group=group, label=label, score=report.score,
                                        scored=tuple(f.check for f in report.findings if f.points)))  # fmt: skip
    return outcomes, unreadable


def _percent(part: int, whole: int) -> str:
    return f"{100 * part / whole:.1f}%" if whole else "n/a"


def _flagged(outcomes: Sequence[Outcome], threshold: int = FLAG_AT) -> int:
    return sum(outcome.score >= threshold for outcome in outcomes)


def summary_table(outcomes: Sequence[Outcome]) -> str:
    """Scenarios, not messages: how many are flagged every time, sometimes, or never."""
    rows = ["| | Scenarios | Flagged every time | Flagged sometimes | Never flagged |", "|---|---:|---:|---:|---:|"]
    for label in (PHISH, BENIGN):
        groups: Dict[str, List[Outcome]] = {}
        for outcome in outcomes:
            if outcome.label == label:
                groups.setdefault(outcome.group, []).append(outcome)
        counts = [_flagged(group) for group in groups.values()]
        always = sum(count == len(group) for count, group in zip(counts, groups.values()))
        never = sum(count == 0 for count in counts)
        rows.append(f"| {KIND[label].capitalize()} | {len(groups)} | {always} | {len(groups) - always - never} | {never} |")
    return "\n".join(rows)


def headline(outcomes: Sequence[Outcome]) -> str:
    rows = [
        f"| | Messages | Flagged (score {FLAG_AT}+) | Likely phishing (score {LIKELY_AT}+) |",
        "|---|---:|---:|---:|",
    ]
    for label in (PHISH, BENIGN):
        group = [outcome for outcome in outcomes if outcome.label == label]
        rows.append(f"| {KIND[label].capitalize()} | {len(group)} | {_flagged(group)} ({_percent(_flagged(group), len(group))}) "
                    f"| {_flagged(group, LIKELY_AT)} ({_percent(_flagged(group, LIKELY_AT), len(group))}) |")  # fmt: skip
    flagged = [outcome for outcome in outcomes if outcome.score >= FLAG_AT]
    lines = ["\n".join(rows), ""]
    lines.append(f"Of the messages flagged, {_percent(sum(o.label == PHISH for o in flagged), len(flagged))} were phishing.")
    expected = [outcome for outcome in outcomes if outcome.expected_flag is not None]
    if expected:
        right = sum((outcome.score >= FLAG_AT) == outcome.expected_flag for outcome in expected)
        lines.append(f"Handled as documented (including the known misses and false alarms): {right} of {len(expected)} "
                     f"({_percent(right, len(expected))}).")  # fmt: skip
    return "\n".join(lines)


def _expected(group: Sequence[Outcome]) -> str:
    first = group[0]
    if first.expected_flag is None:
        return "-"
    if first.label == PHISH:
        return "flagged" if first.expected_flag else "missed (documented)"
    return "false alarm (documented)" if first.expected_flag else "left alone"


def scenario_table(outcomes: Sequence[Outcome]) -> str:
    groups: Dict[str, List[Outcome]] = {}
    for outcome in outcomes:
        groups.setdefault(outcome.group, []).append(outcome)
    rows = ["| Scenario | Kind | Flagged | Score | Usually reported for | Expected |", "|---|---|---:|---|---|---|"]
    for name, group in groups.items():
        scores = [outcome.score for outcome in group]
        score = str(scores[0]) if min(scores) == max(scores) else f"{min(scores)} to {max(scores)}"
        counts = Counter(check for outcome in group for check in outcome.scored)
        usual = [check for check, count in counts.most_common() if count * 2 >= len(group)][:3]
        rows.append(f"| `{name}` | {KIND[group[0].label]} | {_flagged(group)} / {len(group)} | {score} "
                    f"| {', '.join(f'`{check}`' for check in usual) or 'nothing'} | {_expected(group)} |")  # fmt: skip
    return "\n".join(rows)


def sweep_table(outcomes: Sequence[Outcome], thresholds: Sequence[int] = SWEEP) -> str:
    phish = [outcome for outcome in outcomes if outcome.label == PHISH]
    benign = [outcome for outcome in outcomes if outcome.label == BENIGN]
    rows = ["| Flag from score | Phishing flagged | Legitimate flagged |", "|---:|---:|---:|"]
    for threshold in thresholds:
        marker = " (shipped)" if threshold == FLAG_AT else ""
        rows.append(f"| {threshold}{marker} | {_percent(_flagged(phish, threshold), len(phish))} "
                    f"| {_percent(_flagged(benign, threshold), len(benign))} |")  # fmt: skip
    return "\n".join(rows)


def findings_table(outcomes: Sequence[Outcome]) -> str:
    """How often each scoring finding fires, on phishing and on legitimate mail."""
    phish = [outcome for outcome in outcomes if outcome.label == PHISH]
    benign = [outcome for outcome in outcomes if outcome.label == BENIGN]
    counts_phish = Counter(check for outcome in phish for check in set(outcome.scored))
    counts_benign = Counter(check for outcome in benign for check in set(outcome.scored))
    checks = sorted(set(counts_phish) | set(counts_benign), key=lambda c: (-counts_benign[c], -counts_phish[c], c))
    rows = ["| Finding | On phishing | On legitimate mail |", "|---|---:|---:|"]
    for check in checks:
        rows.append(f"| `{check}` | {_percent(counts_phish[check], len(phish))} | {_percent(counts_benign[check], len(benign))} |")
    return "\n".join(rows)


def report(outcomes: Sequence[Outcome]) -> str:
    parts = (summary_table(outcomes), headline(outcomes), scenario_table(outcomes), sweep_table(outcomes), findings_table(outcomes))
    return "\n\n".join(parts) + "\n"


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(prog="python -m lurecheck.evaluate", description=__doc__.splitlines()[0])
    source = parser.add_mutually_exclusive_group()
    source.add_argument("--seeds", type=int, default=20, help="how many simulated runs of every scenario (default 20)")
    source.add_argument("--published", action="store_true", help="reproduce exactly the tables in docs/results.md")
    source.add_argument("--folder", metavar="DIR", help="measure your own saved emails, kept in DIR/phish and DIR/benign")
    parser.add_argument("--protect", action="append", default=None, metavar="DOMAIN",
                        help=f"domains to protect (default for simulations: {', '.join(PROTECTED)})")  # fmt: skip
    args = parser.parse_args(argv)
    if args.seeds < 1:
        parser.error("--seeds must be at least 1")
    if args.folder:
        options = Options(protected=tuple(args.protect or ()))
        if not all(os.path.isdir(os.path.join(args.folder, label)) for label in (PHISH, BENIGN)):
            parser.error(f"{args.folder} needs two folders inside it, phish and benign, each holding .eml files")
        outcomes, unreadable = run_folder(args.folder, options)
        print(f"Measured {len(outcomes)} saved message(s){f'; {unreadable} could not be read' if unreadable else ''}.\n")
    else:
        seeds = PUBLISHED_SEEDS if args.published else range(1, args.seeds + 1)
        options = Options(protected=tuple(args.protect) if args.protect else PROTECTED)
        outcomes = run(generate(seeds), options)
        print(f"Measured {len(outcomes)} simulated messages: {len(SCENARIOS)} scenarios, {len(seeds)} runs each, "
              f"protecting {', '.join(options.protected) or 'nothing'}.\n")  # fmt: skip
    if not outcomes:
        print("Nothing to measure.")
        return 1
    print(report(outcomes), end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
