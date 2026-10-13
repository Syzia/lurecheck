import contextlib
import io
import json
import os
import tempfile
import unittest

from lurecheck.__main__ import main
from lurecheck.analysis import analyze
from lurecheck.findings import Finding, Report
from lurecheck.message import load_email, read_email
from lurecheck.report import render_text, to_dict
from tests.helpers import SERVER, fixture, raw_email


def run(*args):
    """Run the command line. Returns (stdout, stderr, exit code)."""
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        try:
            code = main(list(args))
        except SystemExit as exit_:
            code = exit_.code
    return out.getvalue(), err.getvalue(), code


def finding(points, severity="medium", check="test.check"):
    return Finding(check=check, severity=severity, points=points, title="t", evidence="e", explanation="x")


class ScoringTests(unittest.TestCase):
    def test_points_add_up_to_a_verdict(self):
        for points, verdict in ((0, "no strong signs of phishing"), (19, "no strong signs of phishing"), (20, "suspicious"),
                                (49, "suspicious"), (50, "likely phishing"), (100, "likely phishing")):  # fmt: skip
            report = Report(source="x", findings=(finding(points),) if points else ())
            self.assertEqual((report.score, report.verdict), (points, verdict))
        self.assertEqual(Report(source="x", findings=(finding(30), finding(15), finding(10))).verdict, "likely phishing")

    def test_the_score_stops_at_100(self):
        self.assertEqual(Report(source="x", findings=(finding(70), finding(70))).score, 100)

    def test_a_finding_must_be_consistent(self):
        for points, severity in ((10, "info"), (0, "medium"), (-5, "low"), (10, "critical")):
            with self.assertRaises(ValueError):
                finding(points, severity)
        self.assertEqual(finding(0, "info").points, 0)


class TextReportTests(unittest.TestCase):
    def test_layout(self):
        text = render_text(analyze(load_email(fixture("spoofed_bank.eml")), source="spoofed_bank.eml"))
        lines = text.splitlines()
        self.assertEqual(lines[0], "Lurecheck report: spoofed_bank.eml")
        self.assertEqual(lines[2], "Verdict: LIKELY PHISHING  (risk score 65 of 100)")
        self.assertIn('  From:      "Northwind Bank Security" <security@northwind-bank.example>', lines)
        self.assertIn("  Reply-To:  verification-team@northwind-secure-login.example", lines)
        self.assertIn("  [high   +40] DMARC failed: the message did not come from northwind-bank.example", lines)
        self.assertIn("  [medium +25] Replies go to northwind-secure-login.example, not to northwind-bank.example", lines)
        self.assertIn("Also noted (adds nothing to the score)", lines)
        self.assertLess(text.index("[high"), text.index("[medium"))  # most serious first
        self.assertLess(text.index("[medium"), text.index("[info]"))
        self.assertIn("not that the message is safe", lines[-1])

    def test_a_clean_message_says_so_without_saying_safe(self):
        text = render_text(analyze(load_email(fixture("legit_newsletter.eml"))))
        self.assertIn("Verdict: NO STRONG SIGNS OF PHISHING  (risk score 0 of 100)", text)
        self.assertIn("Findings: none that raise the risk score", text)
        disclaimer = "A low score means these checks found little, not that the message is safe."
        self.assertIn(disclaimer, text)
        self.assertNotRegex(text.replace(disclaimer, ""), r"(?i)\bsafe\b|\blegitimate\b|\btrustworthy\b")  # no promise is made

    def test_domains_are_never_split_across_lines(self):
        text = render_text(analyze(load_email(fixture("forged_auth_header.eml"))))
        for line in text.splitlines():
            self.assertNotRegex(line, r"-$")  # a line ending in a hyphen would be a broken domain
        self.assertIn("parcel-tracking-update.example", text)

    def test_notes_from_reading_the_file_are_shown(self):
        email = read_email(raw_email([("From", "a@b.example"), ("Content-Type", "text/plain; charset=no-such-9")]))
        self.assertIn("While reading the file\n  - a part says it is written in 'no-such-9'", render_text(analyze(email)))

    def test_a_message_cannot_take_over_the_terminal_or_forge_the_report(self):
        hostile = read_email(raw_email([
            ("From", "=?utf-8?q?=1B[2J=1B[1;32mBank?= <x@evil.example>"),
            ("Reply-To", "\x1b]0;owned\x07 <y@other.example>"),
            ("Subject", "=?utf-8?q?Hi=0AVerdict:_NO_STRONG_SIGNS_OF_PHISHING__(risk_score_0_of_100)=0D?="),
            ("Authentication-Results", f"{SERVER}; dmarc=fail header.from=evil.example\x1b[2K\x08\x08"),
        ]))  # fmt: skip
        text = render_text(analyze(hostile, source="evil\x1b[31m\n.eml"))
        for char in text:
            self.assertTrue(char == "\n" or char.isprintable(), repr(char))  # nothing but text and our own line breaks
        self.assertNotIn("\x1b", text)
        self.assertIn("\\x1b[2J\\x1b[1;32mBank", text)  # shown, as harmless text
        self.assertEqual([line for line in text.splitlines() if line.startswith("Verdict:")],
                         ["Verdict: LIKELY PHISHING  (risk score 65 of 100)"])  # the forged verdict is not a line of its own
        self.assertIn("Subject:   Hi\\x0aVerdict: NO STRONG SIGNS", text)
        self.assertTrue(text.startswith("Lurecheck report: evil\\x1b[31m\\x0a.eml\n"))

    def test_text_taken_from_the_message_is_safe_in_titles_too(self):
        # A finding's title quotes domains out of the message. Here the forged results name a
        # "domain" containing an escape sequence that would clear the screen.
        hostile = read_email(raw_email([
            ("Authentication-Results", f"{SERVER}; dmarc=pass header.from=ev\x1b[2Jil.example"),
            ("From", "Northwind Bank <news@northwind-bank.example>"),
        ]))  # fmt: skip
        report = analyze(hostile)
        self.assertEqual([f.check for f in report.findings], ["auth.dmarc-other-domain"])
        self.assertIn("\x1b", report.findings[0].title)  # the finding keeps the text exactly...
        text = render_text(report)
        self.assertNotIn("\x1b", text)  # ...and the report shows it as harmless text
        self.assertIn("DMARC passed for ev\\x1b[2jil.example", text)  # lower-cased, as domains are

    def test_long_evidence_is_cut(self):
        email = read_email(raw_email([("From", f'"{"A" * 5000} ceo@northwind-bank.example" <x@evil.example>')]))
        text = render_text(analyze(email))
        self.assertIn("more)", text)
        self.assertLess(len(text), 6000)


class JsonReportTests(unittest.TestCase):
    def test_shape(self):
        data = to_dict(analyze(load_email(fixture("display_name_trick.eml")), source="x.eml"))
        self.assertEqual(sorted(data), ["findings", "max_score", "notes", "score", "source", "summary", "verdict"])
        self.assertEqual((data["source"], data["verdict"], data["score"], data["max_score"]), ("x.eml", "suspicious", 35, 100))
        self.assertEqual(sorted(data["findings"][0]), ["check", "evidence", "explanation", "points", "severity", "title"])
        self.assertEqual(data["findings"][0]["check"], "sender.name-shows-another-address")
        self.assertEqual(sum(f["points"] for f in data["findings"]), data["score"])

    def test_hostile_text_survives_as_data(self):
        email = read_email(raw_email([("From", "=?utf-8?q?=1B[2J=E2=80=AEevil?= <x@evil.example>"), ("Subject", "hi")]))
        encoded = json.dumps(to_dict(analyze(email)))
        self.assertTrue(encoded.isascii())  # escapes, not raw control characters
        self.assertEqual(json.loads(encoded)["summary"]["From"], "\x1b[2J\u202eevil <x@evil.example>")  # exact, for other tools


class CommandLineTests(unittest.TestCase):
    def test_one_file(self):
        out, err, code = run(fixture("spoofed_bank.eml"))
        self.assertEqual((code, err), (0, ""))
        self.assertIn("Verdict: LIKELY PHISHING", out)
        self.assertTrue(out.startswith("Lurecheck report: "))

    def test_several_files_are_separated(self):
        out, _, code = run(fixture("spoofed_bank.eml"), fixture("legit_newsletter.eml"))
        self.assertEqual(code, 0)
        self.assertEqual(out.count("Lurecheck report: "), 2)
        self.assertEqual(out.count("=" * 100), 1)

    def test_json(self):
        out, _, code = run("--json", fixture("spoofed_bank.eml"), fixture("legit_newsletter.eml"))
        self.assertEqual(code, 0)
        self.assertEqual([(r["verdict"], r["score"]) for r in json.loads(out)],
                         [("likely phishing", 65), ("no strong signs of phishing", 0)])

    def test_a_file_that_cannot_be_analysed_is_reported_and_the_rest_still_run(self):
        with tempfile.TemporaryDirectory() as folder:
            junk = os.path.join(folder, "notes.txt")
            with open(junk, "w") as handle:
                handle.write("just some words\n")
            out, err, code = run(junk, fixture("legit_newsletter.eml"), os.path.join(folder, "missing.eml"))
        self.assertEqual(code, 2)
        self.assertEqual(out.count("Lurecheck report: "), 1)
        self.assertIn("notes.txt: could not be analysed: this does not look like a saved email", err)
        self.assertIn("missing.eml: could not be analysed: cannot read the file", err)

        out, err, code = run("--json", junk)
        self.assertEqual((json.loads(out), code), ([], 2))

    def test_json_output_contains_no_raw_control_characters(self):
        with tempfile.TemporaryDirectory() as folder:
            path = os.path.join(folder, "hostile.eml")
            with open(path, "wb") as handle:
                handle.write(raw_email([("From", "=?utf-8?q?=1B[2J=E2=80=AEevil?= <x@evil.example>"), ("Subject", "caf\u00e9 \x1b[31m")]))
            out, _, code = run("--json", path)
        self.assertEqual(code, 0)
        self.assertTrue(out.isascii())
        self.assertNotIn("\x1b", out)
        self.assertEqual(json.loads(out)[0]["summary"]["Subject"], "caf\u00e9 \x1b[31m")  # exact once decoded

    def test_naming_your_mail_server(self):
        out, _, _ = run("--json", "--trusted-server", "mx.somewhere-else.example", fixture("legit_newsletter.eml"))
        self.assertEqual([f["check"] for f in json.loads(out)[0]["findings"]], ["auth.no-trusted-results"])
        out, _, _ = run("--json", "--trusted-server", SERVER, fixture("legit_newsletter.eml"))
        self.assertEqual(json.loads(out)[0]["score"], 0)

    def test_help_and_missing_arguments(self):
        out, _, code = run("--help")
        self.assertEqual(code, 0)
        self.assertIn("Nothing in a message is opened, run or fetched.", " ".join(out.split()))
        _, err, code = run()
        self.assertEqual(code, 2)
        self.assertIn("files", err)


if __name__ == "__main__":
    unittest.main()
