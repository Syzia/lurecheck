import unittest

from lurecheck.checks import Options, auth
from tests.helpers import SERVER, auth as results, build

BANK = "Northwind Bank <news@northwind-bank.example>"


def found(*headers, sender=BANK, trusted=None):
    """Run the check. Returns [(check id, points)], most serious first is not applied here."""
    return [(f.check, f.points) for f in auth.check(build(*headers, sender=sender), Options(trusted_server=trusted))]


class VerdictTests(unittest.TestCase):
    def test_no_results_at_all(self):
        self.assertEqual(found(), [("auth.no-results", 5)])

    def test_dmarc_fail_is_the_strongest_signal_and_is_counted_once(self):
        self.assertEqual(
            found(results("spf=fail smtp.mailfrom=x@cheap-host.example; dkim=fail header.d=cheap-host.example; "
                          "dmarc=fail header.from=northwind-bank.example")),
            [("auth.dmarc-fail", 40)],  # the SPF and DKIM failures are its evidence, not extra points
        )

    def test_dmarc_pass(self):
        self.assertEqual(found(results("spf=pass smtp.mailfrom=b@bounces.northwind-bank.example; "
                                       "dmarc=pass header.from=northwind-bank.example")), [("auth.dmarc-pass", 0)])
        # Forwarded mail: SPF fails at the forwarder, the signature still carries it.
        self.assertEqual(found(results("spf=fail smtp.mailfrom=x@forwarder.example; dkim=pass header.d=northwind-bank.example; "
                                       "dmarc=pass header.from=northwind-bank.example")), [("auth.dmarc-pass", 0)])
        # The From address may be on a subdomain of the domain DMARC names.
        self.assertEqual(found(results("dmarc=pass header.from=northwind-bank.example"),
                               sender="News <news@mail.northwind-bank.example>"), [("auth.dmarc-pass", 0)])
        self.assertEqual(found(results("dmarc=pass")), [("auth.dmarc-pass", 0)])  # some servers omit the domain

    def test_dmarc_pass_for_a_domain_the_reader_is_not_shown(self):
        self.assertEqual(found(results("dmarc=pass header.from=invoice-portal.example")), [("auth.dmarc-other-domain", 35)])

    def test_evidence_names_the_server_and_the_results(self):
        (finding,) = auth.check(build(results("spf=fail smtp.mailfrom=x@cheap-host.example; dmarc=fail header.from=northwind-bank.example")), Options())
        self.assertEqual(finding.evidence, "dmarc=fail header.from=northwind-bank.example; spf=fail smtp.mailfrom=x@cheap-host.example "
                                           f"(recorded by {SERVER})")
        self.assertIn("northwind-bank.example", finding.title)
        self.assertEqual(finding.severity, "high")


class WithoutDmarcTests(unittest.TestCase):
    """No DMARC verdict recorded: work out what DMARC would have looked at."""

    def test_a_pass_for_the_shown_domain_counts(self):
        self.assertEqual(found(results("spf=pass smtp.mailfrom=bounce@bounces.northwind-bank.example")), [("auth.aligned-pass", 0)])
        self.assertEqual(found(results("spf=none; dkim=pass header.d=northwind-bank.example")), [("auth.aligned-pass", 0)])
        self.assertEqual(found(results("dkim=pass header.i=@mail.northwind-bank.example")), [("auth.aligned-pass", 0)])
        self.assertEqual(found(results("spf=pass smtp.mailfrom=northwind-bank.example; dmarc=none")), [("auth.aligned-pass", 0)])
        # An aligned signature outweighs an SPF failure, as it does for DMARC.
        self.assertEqual(found(results("spf=fail smtp.mailfrom=x@forwarder.example; dkim=pass header.d=northwind-bank.example")),
                         [("auth.aligned-pass", 0)])

    def test_a_pass_for_some_other_domain_does_not(self):
        self.assertEqual(found(results("spf=pass smtp.mailfrom=x@cheap-host.example; dkim=pass header.d=cheap-host.example")),
                         [("auth.passed-for-other-domain", 20)])
        # Looks like the bank's name, but is a different registered domain.
        self.assertEqual(found(results("dkim=pass header.d=northwind-bank.example.cheap-host.example")),
                         [("auth.passed-for-other-domain", 20)])
        self.assertEqual(found(results("spf=pass smtp.mailfrom=x@evil-northwind-bank.example")), [("auth.passed-for-other-domain", 20)])
        self.assertEqual(found(results("spf=pass")), [("auth.passed-for-other-domain", 20)])  # a pass for nobody in particular

    def test_failures(self):
        self.assertEqual(found(results("spf=fail smtp.mailfrom=x@cheap-host.example")), [("auth.spf-fail", 20)])
        self.assertEqual(found(results("spf=softfail smtp.mailfrom=x@cheap-host.example")), [("auth.spf-softfail", 10)])
        self.assertEqual(found(results("dkim=fail header.d=northwind-bank.example")), [("auth.dkim-fail", 15)])
        self.assertEqual(found(results("spf=fail smtp.mailfrom=x@cheap-host.example; dkim=fail header.d=x.example")),
                         [("auth.spf-fail", 20), ("auth.dkim-fail", 15)])
        self.assertEqual(found(results("spf=pass smtp.mailfrom=x@cheap-host.example; dkim=fail header.d=northwind-bank.example")),
                         [("auth.passed-for-other-domain", 20), ("auth.dkim-fail", 15)])

    def test_nothing_verified(self):
        for value in ("spf=none; dkim=none; dmarc=none", "spf=neutral smtp.mailfrom=x@y.example", "none",
                      "spf=temperror; dkim=permerror", "dmarc=bestguesspass header.from=northwind-bank.example"):
            self.assertEqual(found(results(value)), [("auth.nothing-verified", 10)], value)

    def test_with_no_from_address_nothing_can_be_aligned(self):
        self.assertEqual(found(results("spf=pass smtp.mailfrom=x@cheap-host.example"), sender=None),
                         [("auth.passed-for-other-domain", 20)])
        self.assertEqual(found(results("dmarc=fail"), sender=None), [("auth.dmarc-fail", 40)])


class WhichResultsToBelieveTests(unittest.TestCase):
    """Anyone can type an Authentication-Results header into the message they send."""

    FAIL = "spf=softfail smtp.mailfrom=x@cheap-host.example; dmarc=fail header.from=northwind-bank.example"
    PASS = "spf=pass smtp.mailfrom=n@northwind-bank.example; dmarc=pass header.from=northwind-bank.example"

    def test_the_topmost_results_win(self):
        # The receiving server adds its header above everything the sender wrote.
        self.assertEqual(found(results(self.FAIL), results(self.PASS, server="mx.somewhere-else.example")),
                         [("auth.other-results-ignored", 0), ("auth.dmarc-fail", 40)])
        self.assertEqual(found(results(self.PASS), results(self.FAIL, server="mx.somewhere-else.example")),
                         [("auth.other-results-ignored", 0), ("auth.dmarc-pass", 0)])

    def test_a_second_set_under_the_same_name_claiming_a_pass_is_called_out(self):
        self.assertEqual(found(results(self.FAIL), results(self.PASS)),
                         [("auth.other-results-ignored", 0), ("auth.conflicting-results", 15), ("auth.dmarc-fail", 40)])
        # ...but not when it agrees, or claims nothing better, or the real one has no name to copy.
        self.assertEqual(found(results(self.PASS), results(self.PASS)), [("auth.other-results-ignored", 0), ("auth.dmarc-pass", 0)])
        self.assertEqual(found(results(self.PASS), results(self.FAIL)), [("auth.other-results-ignored", 0), ("auth.dmarc-pass", 0)])
        self.assertEqual(found(results(self.FAIL, server=""), results(self.PASS, server="")),
                         [("auth.other-results-ignored", 0), ("auth.dmarc-fail", 40)])

    def test_the_ignored_results_are_shown_as_evidence(self):
        findings = auth.check(build(results(self.FAIL), results(self.PASS, server="mx.somewhere-else.example")), Options())
        ignored = next(f for f in findings if f.check == "auth.other-results-ignored")
        self.assertIn("mx.somewhere-else.example: spf=pass", ignored.evidence)
        self.assertIn(SERVER, ignored.explanation)

    def test_naming_your_server_ignores_everyone_else(self):
        forged_on_top = (results(self.PASS, server="mx.attacker.example"), results(self.FAIL))
        self.assertEqual(found(*forged_on_top), [("auth.other-results-ignored", 0), ("auth.dmarc-pass", 0)])  # fooled by default
        self.assertEqual(found(*forged_on_top, trusted=SERVER), [("auth.other-results-ignored", 0), ("auth.dmarc-fail", 40)])
        self.assertEqual(found(*forged_on_top, trusted="MX.Harbor-Mail.Example"),
                         [("auth.other-results-ignored", 0), ("auth.dmarc-fail", 40)])  # letter case does not matter

    def test_no_results_from_the_server_you_named(self):
        self.assertEqual(found(results(self.PASS, server="mx.attacker.example"), trusted=SERVER), [("auth.no-trusted-results", 15)])
        self.assertEqual(found(results(self.PASS, server=""), trusted=SERVER), [("auth.no-trusted-results", 15)])
        # A name that merely contains yours is not yours.
        self.assertEqual(found(results(self.PASS, server=SERVER + ".attacker.example"), trusted=SERVER),
                         [("auth.no-trusted-results", 15)])
        self.assertEqual(found(trusted=SERVER), [("auth.no-results", 5)])

    def test_of_two_from_your_server_the_upper_one_is_used(self):
        self.assertEqual(found(results(self.FAIL), results(self.PASS), trusted=SERVER),
                         [("auth.other-results-ignored", 0), ("auth.conflicting-results", 15), ("auth.dmarc-fail", 40)])

    def test_a_result_smuggled_into_a_comment_is_not_believed(self):
        self.assertEqual(found(results("spf=fail (dmarc=pass header.from=northwind-bank.example) smtp.mailfrom=x@cheap-host.example")),
                         [("auth.spf-fail", 20)])


if __name__ == "__main__":
    unittest.main()
