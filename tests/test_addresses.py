import unittest

from lurecheck.addresses import parse_addresses


def parsed(value):
    addresses, oddities = parse_addresses(value)
    return [(a.display, a.address) for a in addresses], oddities


class OrdinaryAddressTests(unittest.TestCase):
    def test_name_and_address(self):
        self.assertEqual(parsed("Northwind Bank <news@northwind-bank.example>"),
                         ([("Northwind Bank", "news@northwind-bank.example")], []))
        self.assertEqual(parsed('"Rivera, Alex" <alex@harbor-mail.example>'),
                         ([("Rivera, Alex", "alex@harbor-mail.example")], []))
        self.assertEqual(parsed("alex@harbor-mail.example"), ([("", "alex@harbor-mail.example")], []))
        self.assertEqual(parsed("<alex@harbor-mail.example>"), ([("", "alex@harbor-mail.example")], []))

    def test_comments_are_not_part_of_the_address(self):
        self.assertEqual(parsed("alex@harbor-mail.example (Alex)"), ([("", "alex@harbor-mail.example")], []))
        self.assertEqual(parsed("(note) alex@harbor-mail.example"), ([("", "alex@harbor-mail.example")], []))
        self.assertEqual(parsed('"odd (name)" <alex@harbor-mail.example>'), ([("odd (name)", "alex@harbor-mail.example")], []))

    def test_several_addresses(self):
        self.assertEqual(parsed("a@one.example, B <b@two.example>"), ([("", "a@one.example"), ("B", "b@two.example")], []))

    def test_encoded_names_are_decoded(self):
        self.assertEqual(parsed("=?utf-8?b?Tm9ydGh3aW5k?= <n@northwind-bank.example>"),
                         ([("Northwind", "n@northwind-bank.example")], []))

    def test_domain(self):
        (address,), _ = parse_addresses("News <News@Northwind-Bank.EXAMPLE>")
        self.assertEqual((address.domain, address.valid), ("northwind-bank.example", True))
        (literal,), _ = parse_addresses("user@[192.0.2.1]")
        self.assertEqual((literal.domain, literal.valid), ("[192.0.2.1]", True))
        (quoted,), _ = parse_addresses('"a@b"@c.example')
        self.assertEqual((quoted.domain, quoted.valid), ("c.example", True))

    def test_the_empty_bounce_address_is_not_an_oddity(self):
        self.assertEqual(parsed("<>"), ([("", "")], []))
        self.assertEqual(parsed(""), ([], []))
        self.assertEqual(parsed("   "), ([], []))


class DeceptiveAddressTests(unittest.TestCase):
    """Headers written to make a reader, or another parser, see the wrong sender."""

    def test_an_address_in_the_name_stays_in_the_name(self):
        self.assertEqual(parsed('"accounts@northwind-bank.example" <billing@invoice-portal.example>'),
                         ([("accounts@northwind-bank.example", "billing@invoice-portal.example")], []))
        self.assertEqual(parsed("accounts@northwind-bank.example <billing@invoice-portal.example>"),
                         ([("accounts@northwind-bank.example", "billing@invoice-portal.example")], []))

    def test_angle_brackets_inside_quotes_are_not_the_address(self):
        self.assertEqual(parsed('"Bank <ceo@northwind-bank.example>" <x@evil.example>'),
                         ([("Bank <ceo@northwind-bank.example>", "x@evil.example")], []))

    def test_an_encoded_name_cannot_change_which_part_is_the_address(self):
        # Decoded, the name is "<ceo@northwind-bank.example>". Read after decoding, that would look
        # like the address. The structure is read first, so it stays a name.
        addresses, oddities = parsed("=?utf-8?q?=3Cceo=40northwind-bank.example=3E?= <x@evil.example>")
        self.assertEqual(addresses, [("<ceo@northwind-bank.example>", "x@evil.example")])
        self.assertEqual(oddities, [])
        # The same for an encoded comma, which would otherwise split one sender into two.
        self.assertEqual(parsed("=?utf-8?q?a=40one.example=2C?= <x@evil.example>")[0], [("a@one.example,", "x@evil.example")])

    def test_two_bracketed_addresses_are_reported(self):
        addresses, oddities = parsed("<ceo@northwind-bank.example> <x@evil.example>")
        self.assertEqual(addresses, [("<ceo@northwind-bank.example>", "x@evil.example")])
        self.assertEqual(oddities, ["more than one address in angle brackets"])

    def test_malformed_addresses_are_reported_and_have_no_domain(self):
        for value, oddity in (
            ("no address here", "not a valid address"),
            ("a@b@c.example", "not a valid address"),
            ("x@evil.example>", "not a valid address"),
            ("@northwind-bank.example", "not a valid address"),
            ("alex@", "not a valid address"),
            ("x@ev\x1b[31mil.example", "not a valid address"),  # a control character
            ("x\x00@evil.example", "not a valid address"),
            ('"unclosed <a@b.example>', "a quote or bracket is never closed"),
            ("Name <a@b.example", "a quote or bracket is never closed"),
            ("a@b.example (unclosed", "a quote or bracket is never closed"),
        ):
            addresses, oddities = parse_addresses(value)
            self.assertIn(oddity, oddities, value)
            if "not a valid address" in oddities:
                self.assertEqual([(a.valid, a.domain) for a in addresses], [(False, "")], value)

    def test_spaces_and_trailing_text_are_reported(self):
        self.assertEqual(parsed("a @ b.example"), ([("", "a@b.example")], ["spaces inside the address"]))
        self.assertEqual(parsed("Name <a@b.example> extra"), ([("Name", "a@b.example")], ["text after the address"]))
        self.assertEqual(parsed("Name <a@b.example> (fine)"), ([("Name", "a@b.example")], []))

    def test_escapes_inside_quotes(self):
        self.assertEqual(parsed(r'"say \"hi\" <fake@bank.example>" <x@evil.example>'),
                         ([('say "hi" <fake@bank.example>', "x@evil.example")], []))

    def test_pathological_input_is_handled_quickly(self):
        for value in ("<" * 50_000, '"' * 50_001, "(" * 50_000, "a@b.example," * 20_000, "\\" * 50_000, "<a@b.example>" * 5_000):
            addresses, oddities = parse_addresses(value)  # must return, not hang or raise
            self.assertIsInstance(addresses, list)


if __name__ == "__main__":
    unittest.main()
