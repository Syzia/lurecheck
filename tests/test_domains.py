import unittest

from lurecheck.domains import mixed_scripts, registrable, related, scripts, skeleton, unicode_form


class RegistrableTests(unittest.TestCase):
    def test_the_part_someone_registered(self):
        for name, owner in (
            ("northwind-bank.example", "northwind-bank.example"),
            ("mail.news.northwind-bank.example", "northwind-bank.example"),
            ("NorthWind-Bank.EXAMPLE.", "northwind-bank.example"),
            ("news@northwind-bank.example", "northwind-bank.example"),
            ("www.shop.co.uk", "shop.co.uk"),
            ("shop.co.uk", "shop.co.uk"),
            ("someone.github.io", "someone.github.io"),
            ("a.b.someone.github.io", "someone.github.io"),
            ("northwind-bank.example.evil.example", "evil.example"),
            ("203.0.113.9", "203.0.113.9"),
            ("[2001:db8::1]", "2001:db8::1"),
        ):
            self.assertEqual(registrable(name), owner, name)

    def test_names_nobody_owns(self):
        for name in ("co.uk", "github.io", "example", "localhost", "", ".", "com"):
            self.assertEqual(registrable(name), "", name)

    def test_siblings_under_one_name_are_one_organisation(self):
        self.assertTrue(related("news.northwind-bank.example", "help.northwind-bank.example"))
        self.assertFalse(related("shop.co.uk", "bank.co.uk"))
        self.assertFalse(related("one.github.io", "two.github.io"))
        self.assertTrue(related("203.0.113.9", "203.0.113.9"))
        self.assertFalse(related("203.0.113.9", "203.0.113.10"))


class LooksTests(unittest.TestCase):
    def test_international_names_are_shown_as_read(self):
        self.assertEqual(unicode_form("xn--pypal-4ve.com"), "p\u0430ypal.com")
        self.assertEqual(unicode_form("login.XN--80AK6AA92E.com"), "login.\u0430\u0440\u0440\u04cf\u0435.com")
        self.assertEqual(unicode_form("xn--!!!.example"), "xn--!!!.example")  # not valid: kept as written
        self.assertEqual(unicode_form("plain.example"), "plain.example")

    def test_a_skeleton_is_what_a_name_looks_like(self):
        for text, shape in (
            ("p\u0430ypal", "paypal"),  # Cyrillic a
            ("\u0430\u0440\u0440\u04cf\u0435", "apple"),  # every letter Cyrillic
            ("\u03bf\u03c1\u03b5\u03bd", "opev"),  # Greek: its nu is drawn like a v, not an n
            ("paypa1", "paypal"),
            ("g00gle", "google"),
            ("rnicrosoft", "microsoft"),
            ("vvellsfargo", "wellsfargo"),
            ("caf\u00e9", "cafe"),  # an accent
            ("\uff50\uff41\uff59\uff50\uff41\uff4c", "paypal"),  # full-width letters
            ("PayPal", "paypal"),
            ("northwind-bank", "northwind-bank"),
        ):
            self.assertEqual(skeleton(text), shape, text)

    def test_alphabets(self):
        self.assertEqual(scripts("p\u0430ypal"), ["LATIN", "CYRILLIC"])
        self.assertEqual(scripts("bank-24"), ["LATIN"])  # digits and hyphens are not letters
        self.assertEqual(scripts("123"), [])
        self.assertTrue(mixed_scripts("p\u0430ypal"))
        self.assertTrue(mixed_scripts("\u03b1pple"))  # Greek and Latin
        self.assertFalse(mixed_scripts("\u0430\u0440\u0440\u04cf\u0435"))  # one alphabet throughout
        self.assertFalse(mixed_scripts("paypal"))
        self.assertFalse(mixed_scripts("\u6771\u4eac\u3068tokyo"))  # Japanese writing mixes scripts by design
        self.assertFalse(mixed_scripts("\ud55c\uad6dkorea"))
        self.assertFalse(mixed_scripts(""))


if __name__ == "__main__":
    unittest.main()
