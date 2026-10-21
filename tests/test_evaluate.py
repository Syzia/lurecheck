import contextlib
import io
import os
import shutil
import tempfile
import unittest

from lurecheck.checks import Options
from lurecheck.evaluate import (FLAG_AT, LIKELY_AT, Outcome, findings_table, headline, main, run, run_folder, scenario_table,
                                sweep_table)  # fmt: skip
from lurecheck.simulator import BENIGN, PHISH, PROTECTED, SCENARIOS, generate
from tests.helpers import fixture


def cli(*args):
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        try:
            code = main(list(args))
        except SystemExit as exit_:
            code = exit_.code
    return out.getvalue(), err.getvalue(), code


class AcceptanceTests(unittest.TestCase):
    """The stage 4 test: every simulated message is handled the way its scenario documents."""

    def test_every_scenario_behaves_as_documented(self):
        for outcome in run(generate(range(1, 11)), Options(protected=PROTECTED)):
            with self.subTest(scenario=outcome.group, score=outcome.score):
                self.assertEqual(outcome.score >= FLAG_AT, outcome.expected_flag)

    def test_the_bands_come_from_the_verdicts(self):
        self.assertEqual((FLAG_AT, LIKELY_AT), (20, 50))


def outcome(group, label, score, *scored, expected=None):
    return Outcome(group=group, label=label, score=score, scored=tuple(scored), expected_flag=expected)


SAMPLE = [
    outcome("a", PHISH, 60, "x.one", "x.two", expected=True), outcome("a", PHISH, 40, "x.one", expected=True),
    outcome("b", PHISH, 0, expected=False), outcome("c", BENIGN, 25, "x.three", expected=True), outcome("d", BENIGN, 0, expected=False),
    outcome("d", BENIGN, 5, "x.four", expected=False),
]  # fmt: skip


class TableTests(unittest.TestCase):
    def test_headline(self):
        text = headline(SAMPLE)
        self.assertIn("| Phishing | 3 | 2 (66.7%) | 1 (33.3%) |", text)
        self.assertIn("| Legitimate | 3 | 1 (33.3%) | 0 (0.0%) |", text)
        self.assertIn("Of the messages flagged, 66.7% were phishing.", text)
        self.assertIn("Handled as documented (including the known misses and false alarms): 6 of 6 (100.0%).", text)
        self.assertNotIn("documented", headline([outcome("r", PHISH, 30)]))  # real mail has no expectations

    def test_scenarios(self):
        rows = scenario_table(SAMPLE).splitlines()
        self.assertEqual(rows[2], "| `a` | phishing | 2 / 2 | 40 to 60 | `x.one`, `x.two` | flagged |")  # in at least half counts
        self.assertEqual(rows[3], "| `b` | phishing | 0 / 1 | 0 | nothing | missed (documented) |")
        self.assertEqual(rows[4], "| `c` | legitimate | 1 / 1 | 25 | `x.three` | false alarm (documented) |")
        self.assertEqual(rows[5], "| `d` | legitimate | 0 / 2 | 0 to 5 | `x.four` | left alone |")
        self.assertTrue(scenario_table([outcome("phish/2026", PHISH, 30)]).endswith("| - |"))

    def test_sweep(self):
        rows = sweep_table(SAMPLE, thresholds=(5, 20, 50)).splitlines()
        self.assertEqual(rows[2:], ["| 5 | 66.7% | 66.7% |", "| 20 (shipped) | 66.7% | 33.3% |", "| 50 | 33.3% | 0.0% |"])

    def test_findings(self):
        rows = findings_table(SAMPLE).splitlines()
        self.assertEqual(rows[2:], ["| `x.four` | 0.0% | 33.3% |", "| `x.three` | 0.0% | 33.3% |", "| `x.one` | 66.7% | 0.0% |",
                                    "| `x.two` | 33.3% | 0.0% |"])  # fmt: skip


class FolderTests(unittest.TestCase):
    def setUp(self):
        self.root = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.root)
        for label, names in ((PHISH, ("spoofed_bank.eml", "link_tricks.eml")), (BENIGN, ("legit_newsletter.eml",))):
            os.makedirs(os.path.join(self.root, label, "2026-10"))
            for name in names:
                shutil.copy(fixture(name), os.path.join(self.root, label, "2026-10", name))
        with open(os.path.join(self.root, BENIGN, "broken.eml"), "w") as handle:
            handle.write("not an email\n")
        with open(os.path.join(self.root, BENIGN, "notes.txt"), "w") as handle:
            handle.write("ignored: not .eml\n")

    def test_real_messages_are_measured_without_expectations(self):
        outcomes, unreadable = run_folder(self.root, Options())
        self.assertEqual(unreadable, 1)
        self.assertEqual(sorted((o.group, o.label, o.score) for o in outcomes),
                         [("benign/2026-10", BENIGN, 0), ("phish/2026-10", PHISH, 65), ("phish/2026-10", PHISH, 70)])
        self.assertTrue(all(o.expected_flag is None for o in outcomes))

    def test_the_report_contains_no_text_from_the_messages(self):
        out, _, code = cli("--folder", self.root)
        self.assertEqual(code, 0)
        self.assertTrue(out.startswith("Measured 3 saved message(s); 1 could not be read."))
        self.assertNotIn("@", out)
        self.assertNotIn("northwind", out.lower())
        self.assertNotIn("Northwind", out)

    def test_the_folders_must_be_there(self):
        os.rename(os.path.join(self.root, BENIGN), os.path.join(self.root, "legit"))
        _, err, code = cli("--folder", self.root)
        self.assertEqual(code, 2)
        self.assertIn("needs two folders inside it, phish and benign", err)


class CommandLineTests(unittest.TestCase):
    def test_simulated_run(self):
        out, _, code = cli("--seeds", "2")
        self.assertEqual(code, 0)
        self.assertTrue(out.startswith(f"Measured {2 * len(SCENARIOS)} simulated messages: {len(SCENARIOS)} scenarios, 2 runs each, "
                                       "protecting northwind-bank.example."))  # fmt: skip
        self.assertIn("| Flag from score | Phishing flagged | Legitimate flagged |", out)

    def test_protecting_nothing_changes_the_bank_scenarios(self):
        guarded, _, _ = cli("--seeds", "1")
        bare, _, _ = cli("--seeds", "1", "--protect", "other.example")
        self.assertNotEqual(guarded, bare)
        self.assertIn("protecting other.example", bare)

    def test_bad_arguments(self):
        self.assertEqual(cli("--seeds", "0")[2], 2)
        self.assertEqual(cli("--seeds", "2", "--published")[2], 2)


if __name__ == "__main__":
    unittest.main()
