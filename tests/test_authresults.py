import unittest

from lurecheck.authresults import parse_auth_results


def summary(value):
    parsed = parse_auth_results(value)
    return parsed.server, [(r.method, r.result) for r in parsed.results]


class ParsingTests(unittest.TestCase):
    def test_the_usual_shape(self):
        parsed = parse_auth_results(
            "mx.harbor-mail.example; dkim=pass header.i=@northwind-bank.example header.s=news2026 header.b=Q2hlY2s; "
            "spf=pass (mx.harbor-mail.example: domain of bounce@bounces.northwind-bank.example designates 192.0.2.25 as "
            "permitted sender) smtp.mailfrom=bounce@bounces.northwind-bank.example; "
            "dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=northwind-bank.example"
        )
        self.assertEqual(parsed.server, "mx.harbor-mail.example")
        self.assertEqual([(r.method, r.result) for r in parsed.results], [("dkim", "pass"), ("spf", "pass"), ("dmarc", "pass")])
        (spf,) = parsed.of("spf")
        self.assertEqual(spf.properties, {"smtp.mailfrom": "bounce@bounces.northwind-bank.example"})  # the comment is gone
        self.assertEqual(parsed.of("dkim")[0].properties["header.i"], "@northwind-bank.example")
        self.assertEqual(parsed.of("dmarc")[0].properties, {"header.from": "northwind-bank.example"})
        self.assertEqual(parsed.of("arc"), [])
        self.assertEqual(spf.describe(), "spf=pass smtp.mailfrom=bounce@bounces.northwind-bank.example")

    def test_exchange_online_gives_no_server_name(self):
        parsed = parse_auth_results(
            "spf=pass (sender IP is 192.0.2.40) smtp.mailfrom=fabrikam-parts.example; dkim=pass (signature was verified) "
            "header.d=fabrikam-parts.example;dmarc=pass action=none header.from=fabrikam-parts.example;compauth=pass reason=100"
        )
        self.assertEqual(parsed.server, "")
        self.assertEqual([(r.method, r.result) for r in parsed.results],
                         [("spf", "pass"), ("dkim", "pass"), ("dmarc", "pass"), ("compauth", "pass")])
        self.assertEqual(parsed.of("dmarc")[0].properties, {"action": "none", "header.from": "fabrikam-parts.example"})
        self.assertEqual(parsed.of("compauth")[0].describe(), "compauth=pass")  # the reason is detail, not identity

    def test_no_results(self):
        self.assertEqual(summary("mx.harbor-mail.example; none"), ("mx.harbor-mail.example", []))
        self.assertEqual(summary("mx.harbor-mail.example"), ("mx.harbor-mail.example", []))
        self.assertEqual(summary(""), ("", []))
        self.assertEqual(summary(";;;"), ("", []))

    def test_spelling_variations(self):
        self.assertEqual(summary("MX.Harbor-Mail.EXAMPLE 1; SPF=Pass smtp.mailfrom=a@b.example"),
                         ("mx.harbor-mail.example", [("spf", "pass")]))  # names and results are lower-cased
        self.assertEqual(summary("mx.example; dkim/1 = pass header.d = b.example"), ("mx.example", [("dkim", "pass")]))
        self.assertEqual(parse_auth_results("mx.example; dkim/1 = pass header.d = b.example").results[0].properties,
                         {"header.d": "b.example"})
        self.assertEqual(parse_auth_results('mx.example; spf=pass smtp.mailfrom="a@b.example"').results[0].properties,
                         {"smtp.mailfrom": "a@b.example"})

    def test_several_signatures(self):
        parsed = parse_auth_results("mx.example; dkim=pass header.d=one.example; dkim=fail header.d=two.example")
        self.assertEqual([(r.result, r.properties["header.d"]) for r in parsed.of("dkim")],
                         [("pass", "one.example"), ("fail", "two.example")])


class HostileHeaderTests(unittest.TestCase):
    """The sender can write anything in this header, including text meant to confuse the reader of it."""

    def test_a_result_hidden_in_a_comment_is_not_a_result(self):
        self.assertEqual(summary("mx.example; spf=fail (dmarc=pass; dkim=pass) smtp.mailfrom=x@evil.example"),
                         ("mx.example", [("spf", "fail")]))
        self.assertEqual(summary("mx.example; spf=fail (a (nested; dmarc=pass) comment)"), ("mx.example", [("spf", "fail")]))
        self.assertEqual(summary(r"mx.example; spf=fail (escaped \) still a comment; dmarc=pass)"), ("mx.example", [("spf", "fail")]))

    def test_a_result_hidden_in_a_quoted_value_is_not_a_result(self):
        parsed = parse_auth_results('mx.example; spf=fail reason="x; dmarc=pass"; dkim=none')
        self.assertEqual([(r.method, r.result) for r in parsed.results], [("spf", "fail"), ("dkim", "none")])

    def test_a_property_cannot_be_overridden_by_repeating_it(self):
        parsed = parse_auth_results("mx.example; dmarc=fail header.from=northwind-bank.example header.from=evil.example")
        self.assertEqual(parsed.results[0].properties["header.from"], "northwind-bank.example")

    def test_an_unclosed_comment_hides_only_what_follows_it(self):
        self.assertEqual(summary("mx.example; spf=fail; dkim=none (never closed; dmarc=pass"),
                         ("mx.example", [("spf", "fail"), ("dkim", "none")]))

    def test_nonsense_is_skipped_without_error(self):
        for value in ("mx.example; =pass; spf=; =; pass; spf pass; ===", "\x00\x1b[31m; \xff=\xfe", "mx.example; spf=pass=fail",
                      "mx.example; spf==pass", "mx.example; ünïcödé=pass"):
            parsed = parse_auth_results(value)
            self.assertEqual([r for r in parsed.results if r.result == "pass" and r.method in ("spf", "dkim", "dmarc")], [], value)

    def test_pathological_input_is_handled_quickly(self):
        for value in ("(" * 100_000, "mx.example; " + "spf=pass; " * 20_000, '"' * 100_001, ";" * 100_000,
                      "mx.example; spf=pass " + "a=b " * 50_000, "\\" * 100_000, "mx.example; spf" + " = " * 30_000 + "pass"):
            parse_auth_results(value)  # must return, not hang or raise


if __name__ == "__main__":
    unittest.main()
