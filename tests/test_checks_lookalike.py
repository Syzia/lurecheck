import contextlib
import io
import unittest

from lurecheck.__main__ import main
from lurecheck.brands import BUILT_IN, Brand, protected
from lurecheck.checks import Options, lookalike
from lurecheck.checks.lookalike import imitation
from tests.helpers import build, fixture

BRANDS = protected(["northwind-bank.example"]) + list(BUILT_IN)
BANK = Options(protected=("northwind-bank.example",))


def kind(host, brands=BRANDS):
    match = imitation(host, brands)
    return (match.kind, match.imitated) if match else None


def found(message, options=BANK):
    return [(f.check, f.points) for f in lookalike.check(message, options)]


def page(html, sender="Alerts <alerts@service.example>"):
    return build(("Content-Type", 'text/html; charset="utf-8"'), sender=sender, body=html)


class ImitationTests(unittest.TestCase):
    def test_lookalike_characters(self):
        self.assertEqual(kind("xn--pypal-4ve.com"), ("characters", "paypal.com"))  # a Cyrillic a
        self.assertEqual(kind("xn--80ak6aa92e.com"), ("characters", "apple.com"))  # every letter Cyrillic
        self.assertEqual(kind("paypa1.com"), ("characters", "paypal.com"))
        self.assertEqual(kind("rnicrosoft.com"), ("characters", "microsoft.com"))
        self.assertEqual(kind("login.xn--mcrosoft-thh.example"), ("characters", "microsoft.com"))  # any ending
        self.assertEqual(kind("n0rthwind-bank.example"), ("characters", "northwind-bank.example"))

    def test_the_real_name_as_a_subdomain(self):
        self.assertEqual(kind("paypal.com.account-verify.example"), ("brand-in-subdomain", "paypal.com"))
        self.assertEqual(kind("paypal.evil.example"), ("brand-in-subdomain", "paypal.com"))
        self.assertEqual(kind("northwind-bank.example.account-verify.example"), ("brand-in-subdomain", "northwind-bank.example"))
        self.assertIsNone(kind("mypaypalthing.evil.example"))  # inside a word is not the name

    def test_one_letter_off(self):
        self.assertEqual(kind("paypall.com"), ("one-letter-off", "paypal.com"))
        self.assertEqual(kind("micorsoft.com"), ("one-letter-off", "microsoft.com"))  # two letters swapped
        self.assertEqual(kind("githud.com"), ("one-letter-off", "github.com"))
        self.assertEqual(kind("northwind-bnk.example"), ("one-letter-off", "northwind-bank.example"))
        self.assertIsNone(kind("chasm.example"))  # five letters: too short for this rule, and just a word
        self.assertIsNone(kind("micrsoftt.com"))  # two letters away is not one
        self.assertIsNone(kind("payment.com"))

    def test_the_real_name_plus_other_words(self):
        self.assertEqual(kind("paypal-support.example"), ("brand-plus-words", "paypal.com"))
        self.assertEqual(kind("securepaypal.example"), ("brand-plus-words", "paypal.com"))
        self.assertEqual(kind("micros0ft-alerts.example"), ("brand-plus-words", "microsoft.com"))
        self.assertEqual(kind("northwind-bank-alerts.example"), ("brand-plus-words", "northwind-bank.example"))
        self.assertEqual(kind("ups-delivery.example"), ("brand-plus-words", "ups.com"))  # a short name, as a whole word
        for innocent in ("groups.example", "cups.example", "tomato.example", "unable.example", "cities.example"):
            self.assertIsNone(kind(innocent), innocent)  # a short name inside another word is not the name

    def test_a_different_ending(self):
        self.assertEqual(kind("paypal.co"), ("different-ending", "paypal.com"))
        self.assertEqual(kind("northwind-bank.co.uk"), ("different-ending", "northwind-bank.example"))

    def test_a_brands_own_domains_imitate_nothing(self):
        for host in ("paypal.com", "www.paypal.com", "login.microsoftonline.com", "amazon.co.uk", "northwind-bank.example",
                     "mail.northwind-bank.example", "docusign.net", "ato.gov.au"):
            self.assertIsNone(kind(host), host)

    def test_things_that_are_not_names_imitate_nothing(self):
        for host in ("203.0.113.9", "2001:db8::1", "github.io", "co.uk", "", "localhost"):
            self.assertIsNone(kind(host), host)

    def test_the_strongest_imitation_is_reported(self):
        # Both a subdomain trick and a lookalike: the lookalike characters are the stronger finding.
        self.assertEqual(kind("paypal.com.xn--pypal-4ve.com")[0], "characters")
        # Lookalike characters of one brand, and only a different ending of another: the first wins.
        two = [Brand(name="One", domains=("paypal.com",)), Brand(name="Two", domains=("paypa1.org",))]
        self.assertEqual(kind("paypa1.example", two), ("characters", "paypal.com"))
        self.assertEqual(kind("paypa1.example", list(reversed(two))), ("characters", "paypal.com"))  # whatever the order

    def test_a_protected_domain_is_reduced_to_its_owner(self):
        (brand,) = protected(["mail.northwind-bank.example"])
        self.assertEqual((brand.name, brand.domains, brand.phrases), ("northwind-bank.example", ("northwind-bank.example",), ("northwind bank",)))
        self.assertEqual(protected(["co.uk", "203.0.113.9", "", "localhost"]), [])  # none of these is anyone's domain

    def test_without_protect_a_private_name_is_not_compared(self):
        self.assertIsNone(kind("northwind-bank-alerts.example", list(BUILT_IN)))


class CheckTests(unittest.TestCase):
    def test_sender_reply_and_links_are_all_compared(self):
        findings = lookalike.check(
            page('<a href="https://northwind-bank.example.account-verify.example/x">Sign in</a>',
                 sender="Alerts <alerts@paypa1.com>"), BANK)  # fmt: skip
        self.assertEqual([(f.check, f.points) for f in findings], [("lookalike.characters", 40), ("lookalike.brand-in-subdomain", 35)])
        self.assertEqual(findings[0].evidence, "paypa1.com in From imitates paypal.com")
        self.assertEqual(findings[1].evidence,
                         "northwind-bank.example.account-verify.example in link imitates northwind-bank.example")
        reply = build(("Reply-To", "help@northwind-bank-support.example"))
        self.assertEqual(found(reply), [("lookalike.brand-plus-words", 20)])

    def test_one_finding_per_kind_with_every_place_listed(self):
        message = page('<a href="https://paypa1.com/a">a</a> <a href="https://g00gle.com/b">b</a>', sender="X <x@paypa1.com>")
        (finding,) = lookalike.check(message, BANK)
        self.assertEqual((finding.check, finding.points), ("lookalike.characters", 40))
        self.assertEqual(finding.evidence, "paypa1.com in From, link imitates paypal.com   g00gle.com in link imitates google.com")
        self.assertIn("PayPal", finding.title)

    def test_a_place_is_listed_once_however_many_links_go_there(self):
        message = page('<a href="https://paypa1.com/a">a</a> <a href="https://paypa1.com/b">b</a>', sender="X <x@paypa1.com>")
        (finding,) = lookalike.check(message, BANK)
        self.assertEqual(finding.evidence, "paypa1.com in From, link imitates paypal.com")

    def test_only_a_few_examples_are_shown(self):
        hosts = ["paypa1.com", "g00gle.com", "rnicrosoft.com", "netf1ix.com", "dr0pbox.com"]
        (finding,) = lookalike.check(page(" ".join(f'<a href="https://{h}/">x</a>' for h in hosts)), BANK)
        self.assertEqual(finding.evidence.count(" imitates "), 3)
        self.assertTrue(finding.evidence.endswith("(and 2 more)"))

    def test_the_foreign_letters_are_named(self):
        (finding,) = lookalike.check(page('<a href="https://login.xn--mcrosoft-thh.example/">Review</a>'), BANK)
        self.assertEqual(finding.evidence,
                         "login.xn--mcrosoft-thh.example (reads as login.m\u0456crosoft.example; \u0456 is cyrillic small letter "
                         "byelorussian-ukrainian i) in link imitates microsoft.com")

    def test_mixed_alphabets_without_an_imitation(self):
        # Latin and Cyrillic in one word, imitating nothing on the list: still reported.
        host = "xn--bnkofnowhere-x9j.example"  # "bankofnowhere" with a Cyrillic a
        findings = lookalike.check(page(f'<a href="https://{host}/">x</a>'), BANK)
        self.assertEqual([(f.check, f.points) for f in findings], [("lookalike.mixed-alphabets", 20)])
        self.assertIn("Latin + Cyrillic", findings[0].evidence)

    def test_an_imitation_is_not_also_counted_as_mixed_alphabets(self):
        self.assertEqual(found(page('<a href="https://xn--pypal-4ve.com/">x</a>')), [("lookalike.characters", 40)])

    def test_honest_messages_report_nothing(self):
        self.assertEqual(found(build(sender="Northwind Bank <news@northwind-bank.example>")), [])
        self.assertEqual(found(page('<a href="https://www.paypal.com/">PayPal</a>', sender="PayPal <service@paypal.com>")), [])
        self.assertEqual(found(page('<a href="https://shop.example/">Shop</a>', sender="Shop <hi@shop.example>")), [])


class NameClaimsBrandTests(unittest.TestCase):
    def claims(self, sender, options=BANK):
        return [f.check for f in lookalike.check(build(sender=sender), options)].count("lookalike.name-claims-brand")

    def test_a_brand_name_from_a_domain_the_brand_does_not_use(self):
        self.assertEqual(self.claims("Microsoft account team <security@account-alerts.example>"), 1)
        self.assertEqual(self.claims("PAYPAL Service <noreply@billing-centre.example>"), 1)
        self.assertEqual(self.claims("Apple Support <help@device-care.example>"), 1)
        self.assertEqual(self.claims("Northwind Bank <service@alerts-centre.example>"), 1)  # from --protect
        self.assertEqual(self.claims("Northwind-Bank Security <service@alerts-centre.example>"), 1)  # hyphens read as spaces
        (finding,) = [f for f in lookalike.check(build(sender="Microsoft <x@account-alerts.example>"), BANK)
                      if f.check == "lookalike.name-claims-brand"]
        self.assertEqual(finding.points, 25)
        self.assertEqual(finding.evidence, '"Microsoft" <x@account-alerts.example>   (Microsoft uses microsoft.com, microsoftonline.com, office.com)')

    def test_the_brands_own_name_under_another_ending_is_not_also_a_claim(self):
        # Found by measurement: the bank's genuine mail from a second domain it owns was scored twice.
        checks = [f.check for f in lookalike.check(build(sender="Northwind Bank <news@northwind-bank.test>"), BANK)]
        self.assertEqual(checks, ["lookalike.different-ending"])
        self.assertEqual(self.claims("PayPal <service@paypal.co>"), 0)
        self.assertEqual(self.claims("PayPal <service@paypal-billing.example>"), 1)  # a different name altogether

    def test_a_name_claiming_two_brands_is_one_finding(self):
        self.assertEqual(self.claims("PayPal and Microsoft billing <x@other.example>"), 1)

    def test_the_brand_itself_is_fine(self):
        self.assertEqual(self.claims("Microsoft account team <account-security-noreply@accountprotection.microsoft.com>"), 0)
        self.assertEqual(self.claims("Northwind Bank <news@mail.northwind-bank.example>"), 0)

    def test_ordinary_words_are_not_brand_names(self):
        for sender in ("Apple Hill Farm <hello@applehill.example>", "Amazonia Tours <hi@amazonia.example>",
                       "The Weekly Outlook <news@weekly.example>", "Chase Taylor <chase@taylor.example>",
                       "Paypalooza <x@fest.example>", "Groups Team <g@groups.example>"):
            self.assertEqual(self.claims(sender), 0, sender)

    def test_an_address_in_the_name_is_left_to_the_sender_check(self):
        self.assertEqual(self.claims('"accounts@northwind-bank.example" <billing@invoice-portal.example>'), 0)

    def test_a_protected_name_too_short_to_be_a_phrase_is_not_matched(self):
        self.assertEqual(self.claims("Abc Team <x@other.example>", Options(protected=("abc.example",))), 0)


class CommandLineTests(unittest.TestCase):
    def run_cli(self, *args):
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            try:
                code = main(list(args))
            except SystemExit as exit_:
                code = exit_.code
        return out.getvalue(), err.getvalue(), code

    def test_protect(self):
        plain, _, _ = self.run_cli(fixture("deceptive_link.eml"))
        guarded, _, code = self.run_cli("--protect", "northwind-bank.example", fixture("deceptive_link.eml"))
        self.assertEqual(code, 0)
        self.assertIn("risk score 25 of 100", plain)
        self.assertIn("risk score 100 of 100", guarded)
        self.assertIn("in front of someone else's domain", guarded)

    def test_a_protect_value_that_is_not_a_domain_is_refused(self):
        for bad in ("203.0.113.9", "co.uk", "localhost", "not a domain"):
            _, err, code = self.run_cli("--protect", bad, fixture("legit_newsletter.eml"))
            self.assertEqual(code, 2, bad)
            self.assertIn("--protect needs a domain name", err)


if __name__ == "__main__":
    unittest.main()
