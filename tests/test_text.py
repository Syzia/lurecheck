import unittest

from lurecheck.text import decode_words, domain_of, hidden_characters, related, unfold, visible


class UnfoldAndDecodeTests(unittest.TestCase):
    def test_a_wrapped_header_becomes_one_line(self):
        self.assertEqual(unfold("mx.example;\r\n spf=pass"), "mx.example; spf=pass")
        self.assertEqual(unfold("a\n\tb"), "a\tb")
        self.assertEqual(unfold("  a\r\nb\n"), "a b")  # a stray line break never survives

    def test_encoded_words_are_decoded(self):
        self.assertEqual(decode_words("=?utf-8?b?Tm9ydGh3aW5k?= Bank"), "Northwind Bank")
        self.assertEqual(decode_words("=?utf-8?q?caf=C3=A9?="), "café")
        self.assertEqual(decode_words("=?iso-8859-1?q?caf=E9?="), "café")
        self.assertEqual(decode_words("plain text"), "plain text")

    def test_text_that_will_not_decode_is_returned_as_written(self):
        for bad in ("=?no-such-charset?q?abc?=", "=?utf-8?b?!!!notbase64?=", "=?utf-8?x?abc?=", "=?"):
            self.assertEqual(decode_words(bad), bad)


class HiddenCharacterTests(unittest.TestCase):
    def test_invisible_and_direction_changing_characters_are_found(self):
        self.assertEqual(hidden_characters("Pay\u200bPal"), ["\u200b"])
        self.assertEqual(hidden_characters("invoice\u202egpj.exe"), ["\u202e"])
        self.assertEqual(hidden_characters("soft\u00adhyphen \ufeffbom"), ["\u00ad", "\ufeff"])
        self.assertEqual(hidden_characters("Northwind Bank"), [])
        self.assertEqual(hidden_characters("Café Zürich 日本"), [])

    def test_a_joiner_is_hidden_between_letters_but_not_inside_an_emoji(self):
        self.assertEqual(hidden_characters("Pay\u200dPal"), ["\u200d"])
        self.assertEqual(hidden_characters("\u200dstart"), ["\u200d"])
        self.assertEqual(hidden_characters("Family \U0001f468\u200d\U0001f469\u200d\U0001f467 news"), [])
        self.assertEqual(hidden_characters("Flag \U0001f3f3️\u200d\U0001f308"), [])


class VisibleTests(unittest.TestCase):
    def test_nothing_printed_can_control_the_terminal(self):
        self.assertEqual(visible("\x1b[2J\x1b[31mred"), "\\x1b[2J\\x1b[31mred")
        self.assertEqual(visible("line one\nVerdict: SAFE\r"), "line one\\x0aVerdict: SAFE\\x0d")
        self.assertEqual(visible("a\x00b\x07c\x7fd\x9be"), "a\\x00b\\x07c\\x7fd\\x9be")
        self.assertEqual(visible("tab\there"), "tab\\x09here")

    def test_hidden_characters_are_shown(self):
        self.assertEqual(visible("Pay\u200bPal \u202egpj"), "Pay\\u200bPal \\u202egpj")
        self.assertEqual(visible("tag\U000e0041"), "tag\\U000e0041")
        self.assertEqual(visible("line\u2028sep"), "line\\u2028sep")

    def test_ordinary_text_in_any_language_is_left_alone(self):
        for text in ("Northwind Bank <news@northwind-bank.example>", "Café Zürich", "日本語のメール", "Привет"):
            self.assertEqual(visible(text), text)

    def test_long_text_is_cut_with_a_note(self):
        self.assertEqual(visible("a" * 250, limit=200), "a" * 200 + "… (+50 more)")
        self.assertEqual(visible("a" * 200, limit=200), "a" * 200)
        self.assertLess(len(visible("\x1b" * 10_000, limit=50)), 300)  # escapes cannot defeat the limit


class DomainTests(unittest.TestCase):
    def test_domain_of(self):
        self.assertEqual(domain_of("News@Northwind-Bank.EXAMPLE"), "northwind-bank.example")
        self.assertEqual(domain_of("northwind-bank.example."), "northwind-bank.example")
        self.assertEqual(domain_of("@northwind-bank.example"), "northwind-bank.example")
        self.assertEqual(domain_of('"a@b"@c.example'), "c.example")
        self.assertEqual(domain_of(""), "")

    def test_same_organisation(self):
        for first, second in (
            ("northwind-bank.example", "northwind-bank.example"),
            ("bounces.northwind-bank.example", "northwind-bank.example"),
            ("northwind-bank.example", "a.b.northwind-bank.example"),
            ("NORTHWIND-BANK.example.", "news@northwind-bank.example"),
        ):
            self.assertTrue(related(first, second), (first, second))
            self.assertTrue(related(second, first), (second, first))

    def test_different_organisations(self):
        for first, second in (
            ("northwind-bank.example", "northwind-secure-login.example"),
            ("evil-northwind-bank.example", "northwind-bank.example"),  # ends with the name, but is not under it
            ("northwind-bank.example.evil.example", "northwind-bank.example"),  # starts with the name
            ("mail.one.example", "mail.two.example"),
            ("northwind-bank.example", "example"),  # sharing a top-level name means nothing
            ("shop.co.uk", "bank.co.uk"),
            ("shop.co.uk", "co.uk"),  # anyone can register under co.uk
            ("attacker.github.io", "github.io"),
            ("northwind-bank.example", ""),
            ("", ""),
        ):
            self.assertFalse(related(first, second), (first, second))
            self.assertFalse(related(second, first), (second, first))


if __name__ == "__main__":
    unittest.main()
