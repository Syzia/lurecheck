"""End to end: each made-up email in tests/fixtures, through the whole analysis."""
import ipaddress
import os
import re
import unittest

from lurecheck.analysis import analyze
from lurecheck.checks import Options
from lurecheck.message import load_email
from tests.helpers import FIXTURES, SERVER, fixture

# file -> (verdict, score, the findings that score, the findings that are only noted)
EXPECTED = {
    "legit_newsletter.eml": ("no strong signs of phishing", 0, [], ["auth.dmarc-pass"]),
    "exchange_style.eml": ("no strong signs of phishing", 0, [], ["auth.dmarc-pass"]),
    "no_auth_results.eml": ("no strong signs of phishing", 5, ["auth.no-results"], []),
    "display_name_trick.eml": ("suspicious", 35, ["sender.name-shows-another-address"], ["auth.dmarc-pass"]),
    "forged_auth_header.eml": (
        "likely phishing", 55, ["auth.dmarc-fail", "auth.conflicting-results"],
        ["sender.sent-through-another-domain", "auth.other-results-ignored"],
    ),
    "spoofed_bank.eml": (
        "likely phishing", 65, ["auth.dmarc-fail", "sender.reply-goes-elsewhere"], ["sender.sent-through-another-domain"],
    ),
    # Stage 2: links.
    "rewritten_links.eml": (
        "no strong signs of phishing", 0, [], ["auth.dmarc-pass", "link.rewritten-by-security-service", "link.sites"],
    ),
    "deceptive_link.eml": ("suspicious", 25, ["link.text-shows-another-site"], ["auth.dmarc-pass", "link.sites"]),
    "link_tricks.eml": (
        "likely phishing", 70, ["link.name-before-at", "link.ip-address", "link.shortened"], ["auth.dmarc-pass", "link.sites"],
    ),
    # Stage 3: lookalike domains, here of a built-in brand.
    "lookalike_microsoft.eml": (
        "likely phishing", 85, ["lookalike.characters", "lookalike.name-claims-brand", "lookalike.brand-plus-words"],
        ["auth.dmarc-pass", "link.international-domain", "link.sites"],
    ),
}  # fmt: skip

# The same messages when the reader's own bank, northwind-bank.example, is protected. Only the ones that
# imitate it change. The legitimate ones, which really come from it, must not.
PROTECTED = {
    "deceptive_link.eml": (100, ["lookalike.brand-in-subdomain", "link.text-shows-another-site", "lookalike.name-claims-brand",
                                 "lookalike.brand-plus-words"]),
}  # fmt: skip


class FixtureTests(unittest.TestCase):
    def test_every_fixture_has_an_expectation(self):
        self.assertEqual(sorted(name for name in os.listdir(FIXTURES) if name.endswith(".eml")), sorted(EXPECTED))

    def test_each_email_gets_the_expected_report(self):
        for name, (verdict, score, scored, noted) in EXPECTED.items():
            with self.subTest(email=name):
                report = analyze(load_email(fixture(name)), source=name)
                self.assertEqual((report.verdict, report.score), (verdict, score))
                self.assertEqual([f.check for f in report.findings if f.points], scored)  # most serious first
                self.assertEqual([f.check for f in report.findings if not f.points], noted)
                self.assertEqual(report.notes, ())
                self.assertEqual(report.source, name)

    def test_protecting_your_own_domain_changes_only_the_imitations(self):
        options = Options(protected=("northwind-bank.example",))
        for name, (verdict, score, scored, noted) in EXPECTED.items():
            with self.subTest(email=name):
                report = analyze(load_email(fixture(name)), options=options)
                if name in PROTECTED:
                    self.assertEqual((report.score, [f.check for f in report.findings if f.points]), PROTECTED[name])
                else:
                    self.assertEqual((report.verdict, report.score), (verdict, score))  # the genuine ones are left alone

    def test_the_summary_shows_decoded_headers(self):
        report = analyze(load_email(fixture("exchange_style.eml")))
        self.assertEqual(list(report.summary), ["From", "To", "Subject", "Date"])  # no Reply-To in this one
        self.assertEqual(report.summary["Subject"], "Quote for order 8812 – revised")
        self.assertIn("Reply-To", analyze(load_email(fixture("spoofed_bank.eml"))).summary)

    def test_passing_every_check_is_not_the_same_as_being_honest(self):
        # The display-name trick comes from a domain the attacker owns, so SPF, DKIM and DMARC all pass.
        report = analyze(load_email(fixture("display_name_trick.eml")))
        self.assertIn("auth.dmarc-pass", [f.check for f in report.findings])
        self.assertEqual(report.verdict, "suspicious")

    def test_a_forged_pass_does_not_lower_the_score(self):
        with_forgery = analyze(load_email(fixture("forged_auth_header.eml")))
        self.assertIn("auth.dmarc-fail", [f.check for f in with_forgery.findings])
        self.assertNotIn("auth.dmarc-pass", [f.check for f in with_forgery.findings])
        pinned = analyze(load_email(fixture("forged_auth_header.eml")), options=Options(trusted_server=SERVER))
        self.assertEqual(pinned.score, with_forgery.score)

    def test_links_are_judged_by_where_they_really_go(self):
        # The legitimate newsletter's links all pass through a security service's rewrite, and the text
        # of one shows the bank's address. Read through the rewrite, they match, and nothing is scored.
        rewritten = analyze(load_email(fixture("rewritten_links.eml")))
        sites = next(f for f in rewritten.findings if f.check == "link.sites")
        self.assertEqual(sites.evidence, "northwind-bank.example, www.northwind-bank.example")
        # The phish passes every authentication check, from a domain made to look like the bank's.
        deceptive = analyze(load_email(fixture("deceptive_link.eml")))
        self.assertEqual(deceptive.findings[0].evidence,
                         '"https://northwind-bank.example/login" goes to northwind-bank.example.account-verify.example')

    def test_every_finding_explains_itself(self):
        for name in EXPECTED:
            for finding in analyze(load_email(fixture(name))).findings:
                with self.subTest(email=name, check=finding.check):
                    self.assertRegex(finding.check, r"^(auth|sender|link|lookalike)\.[a-z-]+$")
                    self.assertTrue(finding.title and finding.evidence and finding.explanation)
                    self.assertGreater(len(finding.explanation), 60)  # a sentence, not a label


class FixtureHygieneTests(unittest.TestCase):
    """The project rule: no real email in the repository. Guard the fixtures against one being pasted in."""

    DOCUMENTATION = [ipaddress.ip_network(n) for n in ("192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24", "2001:db8::/32")]

    def texts(self):
        for name in sorted(os.listdir(FIXTURES)):
            with open(os.path.join(FIXTURES, name), encoding="utf-8") as handle:
                yield name, handle.read()

    # The only real names allowed are services Lurecheck itself recognises by name, which a
    # made-up email has to mention to exercise that recognition. Nothing here is a real message.
    KNOWN_SERVICES = ("nam01.safelinks.protection.outlook.com", "urldefense.proofpoint.com", "bit.ly")

    def test_every_domain_is_a_reserved_example_name(self):
        for name, text in self.texts():
            domains = set(re.findall(r"@([A-Za-z0-9.-]+)", text)) | set(re.findall(r"\b([a-z0-9-]+(?:\.[a-z0-9-]+)+\.[a-z]{2,})\b", text))
            for domain in domains:
                try:
                    ipaddress.ip_address(domain)
                    continue  # a numeric address: the next test checks those
                except ValueError:
                    pass
                with self.subTest(fixture=name, domain=domain):
                    domain = domain.rstrip(".").lower()
                    self.assertTrue(domain.endswith(".example") or domain in self.KNOWN_SERVICES,
                                    f"{domain} is not a reserved .example name")

    def test_every_address_is_from_a_documentation_range(self):
        for name, text in self.texts():
            for found in re.findall(r"\b\d{1,3}(?:\.\d{1,3}){3}\b", text) + re.findall(r"\b[0-9a-f]{1,4}(?::[0-9a-f]{0,4}){2,7}\b", text):
                try:
                    address = ipaddress.ip_address(found)
                except ValueError:
                    continue  # a time such as 09:14:07
                with self.subTest(fixture=name, address=found):
                    self.assertTrue(any(address in network for network in self.DOCUMENTATION))

    def test_git_ignores_email_files_everywhere_else(self):
        root = os.path.dirname(os.path.dirname(__file__))
        with open(os.path.join(root, ".gitignore"), encoding="utf-8") as handle:
            rules = handle.read().split()
        self.assertIn("*.eml", rules)
        self.assertIn("!tests/fixtures/*.eml", rules)
        self.assertLess(rules.index("*.eml"), rules.index("!tests/fixtures/*.eml"))  # the exception must come after the rule


if __name__ == "__main__":
    unittest.main()
