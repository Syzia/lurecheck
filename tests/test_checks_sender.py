import unittest

from lurecheck.checks import Options, sender
from lurecheck.message import read_email
from tests.helpers import build, raw_email


def found(*headers, sender_header="Northwind Bank <news@northwind-bank.example>"):
    return [(f.check, f.points) for f in sender.check(build(*headers, sender=sender_header), Options())]


class OrdinarySenderTests(unittest.TestCase):
    def test_a_plain_sender_raises_nothing(self):
        self.assertEqual(found(), [])
        self.assertEqual(found(sender_header="news@northwind-bank.example"), [])
        self.assertEqual(found(sender_header='"Rivera, Alex (Finance)" <alex@harbor-mail.example>'), [])
        self.assertEqual(found(sender_header="=?utf-8?b?Tm9ydGh3aW5kIEJhbms=?= <news@northwind-bank.example>"), [])
        self.assertEqual(found(sender_header="Café Zürich 日本 <hello@cafe.example>"), [])
        self.assertEqual(found(sender_header="Family \U0001f468\u200d\U0001f469\u200d\U0001f467 News <hi@family.example>"), [])

    def test_replies_and_bounces_within_the_same_organisation_are_fine(self):
        self.assertEqual(found(("Reply-To", "support@northwind-bank.example")), [])
        self.assertEqual(found(("Reply-To", "Help <help@support.northwind-bank.example>")), [])
        self.assertEqual(found(("Return-Path", "<bounce-1@bounces.northwind-bank.example>")), [])
        self.assertEqual(found(("Return-Path", "<>")), [])  # the empty bounce address

    def test_a_name_showing_the_senders_own_address_is_fine(self):
        self.assertEqual(found(sender_header='"news@northwind-bank.example" <news@northwind-bank.example>'), [])
        self.assertEqual(found(sender_header='"help@support.northwind-bank.example" <news@northwind-bank.example>'), [])


class DeceptiveSenderTests(unittest.TestCase):
    def test_no_from(self):
        self.assertEqual(found(sender_header=None), [("sender.no-from", 20)])

    def test_several_from_headers(self):
        email = read_email(raw_email([("From", "Northwind Bank <news@northwind-bank.example>"), ("From", "x@evil.example"),
                                      ("Subject", "Hi")]))  # fmt: skip
        findings = sender.check(email, Options())
        self.assertEqual([(f.check, f.points) for f in findings], [("sender.several-from-headers", 40)])
        self.assertEqual(findings[0].evidence, "Northwind Bank <news@northwind-bank.example> | x@evil.example")

    def test_several_addresses_in_one_from(self):
        self.assertEqual(found(sender_header="ceo@northwind-bank.example, x@evil.example"), [("sender.several-from-addresses", 20)])

    def test_a_malformed_from(self):
        for value in ("Northwind Bank", "<ceo@northwind-bank.example> <x@evil.example>", "x@evil.example>", "a@b@c.example",
                      '"Northwind Bank <news@northwind-bank.example>', "news @ northwind-bank.example", "<>", "   "):
            self.assertIn(("sender.malformed-from", 20), found(sender_header=value), value)

    def test_a_name_that_displays_someone_elses_address(self):
        trick = '"accounts@northwind-bank.example" <billing@invoice-portal.example>'
        self.assertEqual(found(sender_header=trick), [("sender.name-shows-another-address", 35)])
        (finding,) = sender.check(build(sender=trick), Options())
        self.assertEqual(finding.evidence, trick)
        self.assertIn("accounts@northwind-bank.example", finding.title)
        self.assertIn("billing@invoice-portal.example", finding.title)
        # Unquoted, encoded, and buried in other words: all the same trick.
        self.assertEqual(found(sender_header="accounts@northwind-bank.example <billing@invoice-portal.example>"),
                         [("sender.name-shows-another-address", 35)])
        self.assertEqual(found(sender_header="=?utf-8?q?accounts=40northwind-bank.example?= <billing@invoice-portal.example>"),
                         [("sender.name-shows-another-address", 35)])
        self.assertEqual(found(sender_header='"Northwind (accounts@northwind-bank.example) via Portal" <billing@invoice-portal.example>'),
                         [("sender.name-shows-another-address", 35)])
        # A lookalike of the real domain is still another domain.
        self.assertEqual(found(sender_header='"news@northwind-bank.example" <news@northwind-bank.example.invoice-portal.example>'),
                         [("sender.name-shows-another-address", 35)])

    def test_invisible_characters(self):
        self.assertEqual(found(sender_header="North\u200bwind Bank <news@northwind-bank.example>"), [("sender.hidden-characters", 20)])
        self.assertEqual(found(sender_header="=?utf-8?b?4oCuTm9ydGh3aW5k?= <news@northwind-bank.example>"), [("sender.hidden-characters", 20)])
        self.assertEqual(found(sender_header="Pay\u200dPal <news@northwind-bank.example>"), [("sender.hidden-characters", 20)])
        # In the address itself, where it makes two addresses that look identical differ.
        self.assertEqual(found(sender_header="Northwind Bank <ne\u200bws@northwind-bank.example>"), [("sender.hidden-characters", 20)])
        (finding,) = sender.check(build(sender="Northwind Bank <ne\u200bws@northwind-bank.example>"), Options())
        self.assertIn("1 invisible character(s)", finding.title)

    def test_a_domain_in_another_alphabet(self):
        self.assertEqual(found(sender_header="Bank <news@xn--nrthwind-bank-0ob.example>"), [("sender.international-domain", 10)])
        self.assertEqual(found(sender_header="Bank <news@mail.xn--80ak6aa92e.example>"), [("sender.international-domain", 10)])
        self.assertEqual(found(sender_header="Bank <news@nоrthwind-bank.example>"), [("sender.international-domain", 10)])  # Cyrillic o

    def test_replies_going_to_another_organisation(self):
        self.assertEqual(found(("Reply-To", "verification-team@northwind-secure-login.example")), [("sender.reply-goes-elsewhere", 25)])
        (finding,) = sender.check(build(("Reply-To", "Help <h@northwind-secure-login.example>")), Options())
        self.assertEqual(finding.evidence, 'From: "Northwind Bank" <news@northwind-bank.example>   '
                                           'Reply-To: "Help" <h@northwind-secure-login.example>')
        self.assertEqual(found(("Reply-To", "ok@northwind-bank.example, other@free-mail.example")), [("sender.reply-goes-elsewhere", 25)])

    def test_sent_through_another_domain_is_noted_not_scored(self):
        self.assertEqual(found(("Return-Path", "<bounce@mailer.sendwell.example>")), [("sender.sent-through-another-domain", 0)])

    def test_tricks_add_up(self):
        self.assertEqual(
            found(("Reply-To", "x@free-mail.example"), sender_header='"ceo@northwind-bank.example\u200b" <x@evil.example>'),
            [("sender.name-shows-another-address", 35), ("sender.hidden-characters", 20), ("sender.reply-goes-elsewhere", 25)],
        )


if __name__ == "__main__":
    unittest.main()
