import unittest
from unittest import mock

from lurecheck.checks import Options, links
from lurecheck.checks.links import collect, shown_site
from lurecheck.message import read_email
from tests.helpers import build, raw_email

BANK = "https://northwind-bank.example/login"


def page(html):
    return build(("Content-Type", 'text/html; charset="utf-8"'), body=html)


def plain(text):
    return build(body=text)


def found(message):
    """[(check id, points)] for everything except the list of sites, which every linked message gets."""
    return [(f.check, f.points) for f in links.check(message, Options()) if f.check != "link.sites"]


def link(address, text="Sign in"):
    return page(f'<p><a href="{address}">{text}</a></p>')


class CollectingTests(unittest.TestCase):
    def test_links_from_html_and_from_plain_text(self):
        both = read_email(raw_email(
            [("From", "a@b.example"), ("Content-Type", 'multipart/alternative; boundary="x"')],
            '--x\r\nContent-Type: text/plain\r\n\r\nSign in at https://one.example/a, or (www.two.example/b).\r\n'
            '--x\r\nContent-Type: text/html\r\n\r\n<a href="https://one.example/a">Sign in</a>\r\n--x--\r\n',
        ))  # fmt: skip
        collected, truncated = collect(both)
        self.assertEqual([(text, target.written) for text, target in collected],
                         [("", "https://one.example/a"), ("", "http://www.two.example/b"), ("Sign in", "https://one.example/a")])
        self.assertFalse(truncated)

    def test_punctuation_after_an_address_in_text_is_not_part_of_it(self):
        for text in ("See https://a.example/x.", "(https://a.example/x)", "<https://a.example/x>", "'https://a.example/x';",
                     "Go to https://a.example/x, then reply!", "https://a.example/x\r\nnext line"):
            ((_, target),) = collect(plain(text))[0]
            self.assertEqual(target.written, "https://a.example/x", text)

    def test_a_repeated_link_is_read_once(self):
        message = page('<a href="https://a.example/">x</a>' * 40 + '<a href="https://a.example/">y</a>')
        self.assertEqual(len(collect(message)[0]), 2)

    def test_attachments_are_not_searched_for_links(self):
        message = read_email(raw_email(
            [("From", "a@b.example"), ("Content-Type", 'multipart/mixed; boundary="x"')],
            '--x\r\nContent-Type: text/plain\r\n\r\nSee attached.\r\n'
            '--x\r\nContent-Type: text/html; name="page.html"\r\nContent-Disposition: attachment\r\n\r\n<a href="https://evil.example/">x</a>\r\n--x--\r\n',
        ))  # fmt: skip
        self.assertEqual(collect(message)[0], [])

    def test_too_many_links_are_cut_and_reported(self):
        message = plain(" ".join(f"https://site{n}.example/" for n in range(30)))
        with mock.patch.object(links, "MAX_LINKS", 10):
            self.assertEqual((len(collect(message)[0]), collect(message)[1]), (10, True))
            self.assertIn(("link.too-many", 0), found(message))
        self.assertEqual(found(message), [])

    def test_a_page_with_too_many_links_is_reported_even_if_they_are_all_the_same(self):
        from lurecheck import markup

        message = page('<a href="https://a.example/">x</a>' * 10)
        with mock.patch.object(markup, "MAX_ANCHORS", 5):
            self.assertEqual((len(collect(message)[0]), collect(message)[1]), (1, True))
            self.assertEqual(found(message), [("link.too-many", 0)])

    def test_a_message_with_no_links_reports_nothing(self):
        self.assertEqual(links.check(plain("No links at all."), Options()), [])
        self.assertEqual(links.check(page("<p>No links <b>at all</b>.</p>"), Options()), [])


class ShownSiteTests(unittest.TestCase):
    def test_text_that_reads_as_a_web_address(self):
        for text, site in (
            ("https://northwind-bank.example/login", "northwind-bank.example"),
            ("HTTP://WWW.Northwind-Bank.example", "www.northwind-bank.example"),
            ("www.northwind-bank.example", "www.northwind-bank.example"),
            ("northwind-bank.example", "northwind-bank.example"),
            ("northwind-bank.example/offers/savings", "northwind-bank.example"),
            ("Visit https://northwind-bank.example/login today", "northwind-bank.example"),
            ("https://northwind-bank.example:443/x", "northwind-bank.example"),
            ("https://user@northwind-bank.example/", "northwind-bank.example"),
            ("north\u200bwind-bank.example", "northwind-bank.example"),  # an invisible character cannot dodge the comparison
            ("shop.co.uk", "shop.co.uk"),
        ):
            self.assertEqual(shown_site(text), site, text)

    def test_text_that_does_not(self):
        for text in ("Sign in", "Click here to verify your account", "", "invoice.pdf", "report.zip", "setup.sh", "notes.md",
                     "e.g. this", "Mr.Smith", "version 2.0", "alex@harbor-mail.example", "See northwind-bank.example for details",
                     "10.30am", "a.b"):
            self.assertEqual(shown_site(text), "", text)


class OrdinaryLinkTests(unittest.TestCase):
    def test_honest_links_raise_nothing(self):
        for message in (link(BANK), link(BANK, "https://northwind-bank.example/login"), link(BANK, "northwind-bank.example"),
                        link("https://www.northwind-bank.example/a", "northwind-bank.example"),  # a subdomain of what is shown
                        link("https://northwind-bank.example/", "www.northwind-bank.example"),
                        link(BANK, "Open invoice.pdf"), link("mailto:help@northwind-bank.example", "Email us"),
                        link("#section", "Jump"), link("tel:+15550100", "Call"), plain("Sign in at https://northwind-bank.example/login.")):
            self.assertEqual(found(message), [])

    def test_the_sites_linked_to_are_listed(self):
        (finding,) = links.check(page(f'<a href="{BANK}">a</a> <a href="https://help.northwind-bank.example/">b</a> '
                                      f'<a href="{BANK}?again">c</a>'), Options())
        self.assertEqual((finding.check, finding.points, finding.title),
                         ("link.sites", 0, "The message links to 2 sites"))
        self.assertEqual(finding.evidence, "northwind-bank.example, help.northwind-bank.example")
        self.assertEqual(links.check(link(BANK), Options())[0].title, "The message links to 1 site")
        many = page(" ".join(f'<a href="https://s{n}.example/">x</a>' for n in range(12)))
        self.assertTrue(links.check(many, Options())[0].evidence.endswith("s7.example (and 4 more)"))

    def test_links_rewritten_by_a_security_service_are_read_through(self):
        rewritten = "https://nam01.safelinks.protection.outlook.com/?url=https%3A%2F%2Fnorthwind-bank.example%2Foffers&amp;data=x"
        message = link(rewritten, "northwind-bank.example/offers")
        self.assertEqual(found(message), [("link.rewritten-by-security-service", 0)])  # the text matches where it really goes
        self.assertEqual([f.evidence for f in links.check(message, Options())],
                         ["nam01.safelinks.protection.outlook.com to northwind-bank.example", "northwind-bank.example"])


class DeceptiveLinkTests(unittest.TestCase):
    def test_text_that_names_another_site(self):
        evil = "https://northwind-bank.example.account-verify.example/login"
        self.assertEqual(found(link(evil, "https://northwind-bank.example/login")), [("link.text-shows-another-site", 25)])
        self.assertEqual(found(link(evil, "northwind-bank.example")), [("link.text-shows-another-site", 25)])
        self.assertEqual(found(link(evil, "www.<b>northwind-bank</b>.example")), [("link.text-shows-another-site", 25)])
        self.assertEqual(found(link("https://evil-northwind-bank.example/", "northwind-bank.example")), [("link.text-shows-another-site", 25)])
        (finding, _) = links.check(link(evil, "https://northwind-bank.example/login"), Options())
        self.assertEqual(finding.evidence, '"https://northwind-bank.example/login" goes to northwind-bank.example.account-verify.example')

    def test_a_security_rewrite_does_not_excuse_a_mismatch(self):
        rewritten = "https://nam01.safelinks.protection.outlook.com/?url=https%3A%2F%2Fevil.example%2Flogin&amp;data=x"
        self.assertEqual(found(link(rewritten, "northwind-bank.example")),
                         [("link.text-shows-another-site", 25), ("link.rewritten-by-security-service", 0)])

    def test_a_trusted_site_used_as_a_springboard(self):
        springboard = "https://www.google.com/url?q=https://evil.example/login&amp;sa=D"
        self.assertEqual(found(link(springboard)), [("link.bounces-through", 10)])
        # Showing the springboard's own name does not make it honest: the visitor ends up elsewhere.
        self.assertEqual(found(link(springboard, "www.google.com")), [("link.text-shows-another-site", 25), ("link.bounces-through", 10)])
        (_, bounce, _) = links.check(link(springboard, "www.google.com"), Options())
        self.assertEqual(bounce.evidence, "www.google.com then evil.example")

    def test_a_name_before_the_at_sign(self):
        self.assertEqual(found(link("https://northwind-bank.example@evil.example/login")), [("link.name-before-at", 35)])
        (finding, _) = links.check(link("https://northwind-bank.example@evil.example/login"), Options())
        self.assertEqual(finding.evidence, "https://northwind-bank.example@evil.example/login  (goes to evil.example)")

    def test_numeric_addresses(self):
        self.assertEqual(found(link("http://203.0.113.9/login")), [("link.ip-address", 25)])
        self.assertEqual(found(link("http://[2001:db8::1]/login")), [("link.ip-address", 25)])
        self.assertEqual(found(link("http://3405803785/login")), [("link.disguised-ip-address", 35)])
        self.assertEqual(found(link("http://0xCB.0x00.0x71.9/")), [("link.disguised-ip-address", 35)])
        self.assertEqual(found(plain("Track it: http://203.0.113.9/t?n=1")), [("link.ip-address", 25)])

    def test_addresses_that_run_code(self):
        self.assertEqual(found(link("javascript:document.location='https://evil.example/'")), [("link.runs-code", 30)])
        self.assertEqual(found(link("data:text/html;base64,PGh0bWw+")), [("link.runs-code", 30)])
        self.assertEqual(found(link("java&#9;script:alert(1)")), [("link.runs-code", 30), ("link.malformed", 20)])  # a tab, as a character reference

    def test_addresses_browsers_repair(self):
        self.assertEqual(found(link("https://northwind-bank.example\\@evil.example/")), [("link.malformed", 20)])
        self.assertEqual(found(link("ht&#10;tps://evil.example/")), [("link.malformed", 20)])
        self.assertEqual(found(link("https://evil%2Eexample/")), [("link.malformed", 20)])
        self.assertEqual(found(link("http://[not-an-address/")), [("link.malformed", 20)])
        self.assertEqual(found(link("mailto:a\\b@c.example")), [])  # not a web address: nothing to misread

    def test_shorteners_and_carried_addresses(self):
        self.assertEqual(found(link("https://bit.ly/3xAmPle")), [("link.shortened", 10)])
        self.assertEqual(found(link("https://BIT.LY./3xAmPle")), [("link.shortened", 10)])
        self.assertEqual(found(link("https://notbit.ly/x")), [])
        self.assertEqual(found(link("https://tracker.example/c?u=https://northwind-bank.example/offers")), [("link.carries-another-address", 10)])
        self.assertEqual(found(link("https://northwind-bank.example/out?next=https://help.northwind-bank.example/")), [])  # its own organisation

    def test_non_english_site_names(self):
        self.assertEqual(found(link("https://xn--nrthwind-bank-0ob.example/")), [("link.international-domain", 10)])
        self.assertEqual(found(link("https://nörthwind-bank.example/")), [("link.international-domain", 10)])
        self.assertEqual(found(link("https://mail.xn--80ak6aa92e.example/")), [("link.international-domain", 10)])  # not the first label

    def test_one_finding_per_trick_however_many_links_use_it(self):
        message = page("".join(f'<a href="http://203.0.113.{n}/x">link {n}</a> ' for n in range(1, 9)))
        (finding, sites) = links.check(message, Options())
        self.assertEqual((finding.check, finding.points), ("link.ip-address", 25))  # 25, not 8 x 25
        self.assertEqual(finding.evidence, "http://203.0.113.1/x   http://203.0.113.2/x   http://203.0.113.3/x   (and 5 more)")
        self.assertEqual(sites.title, "The message links to 8 sites")

    def test_the_same_example_is_shown_once(self):
        message = page('<a href="https://bit.ly/x">Pay now</a> <a href="https://bit.ly/x">Pay later</a>')
        (finding, _) = links.check(message, Options())
        self.assertEqual((finding.check, finding.evidence), ("link.shortened", "https://bit.ly/x"))

    def test_several_tricks_in_one_message_are_each_reported_most_serious_first(self):
        message = page('<a href="https://northwind-bank.example@203.0.113.44/r">Reschedule</a>'
                       '<a href="https://bit.ly/3xAmPle">Pay</a>'
                       '<a href="https://evil.example/">northwind-bank.example</a>')
        self.assertEqual(found(message), [("link.text-shows-another-site", 25), ("link.name-before-at", 35), ("link.ip-address", 25),
                                          ("link.shortened", 10)])

    def test_every_finding_has_evidence_and_an_explanation(self):
        message = page('<a href="https://northwind-bank.example@203.0.113.44/r">a</a><a href="http://3405803785/">b</a>'
                       '<a href="javascript:x">c</a><a href="https://bit.ly/x">d</a><a href="https://a.example\\x">e</a>'
                       '<a href="https://evil.example/">northwind-bank.example</a><a href="https://xn--80ak6aa92e.example/">f</a>'
                       '<a href="https://www.google.com/url?q=https://evil.example/">g</a><a href="https://t.example/?u=https://v.example/">h</a>')
        findings = links.check(message, Options())
        self.assertEqual(len(findings), 11)
        for finding in findings:
            self.assertTrue(finding.title and finding.evidence, finding.check)
            self.assertGreater(len(finding.explanation), 60, finding.check)


if __name__ == "__main__":
    unittest.main()
