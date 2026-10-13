import unittest

from lurecheck.urls import MAX_HOPS, host_kind, read_target


def goes_to(url):
    target = read_target(url)
    return target.scheme, target.host


class OrdinaryAddressTests(unittest.TestCase):
    def test_scheme_and_host(self):
        self.assertEqual(goes_to("https://northwind-bank.example/login?x=1#top"), ("https", "northwind-bank.example"))
        self.assertEqual(goes_to("HTTPS://Northwind-Bank.EXAMPLE./a"), ("https", "northwind-bank.example"))
        self.assertEqual(goes_to("http://northwind-bank.example:8080/"), ("http", "northwind-bank.example"))
        self.assertEqual(goes_to("  https://northwind-bank.example/ \n"), ("https", "northwind-bank.example"))
        self.assertEqual(goes_to("//northwind-bank.example/x"), ("https", "northwind-bank.example"))
        target = read_target("https://northwind-bank.example/a")
        self.assertEqual((target.through, target.rewritten, target.carried, target.name_before_at, target.oddities, target.is_web),
                         ((), False, "", "", (), True))

    def test_addresses_that_go_nowhere_on_the_web(self):
        for url, scheme in (("mailto:alex@harbor-mail.example", "mailto"), ("tel:+15550100", "tel"), ("#top", ""),
                            ("/relative/path", ""), ("", ""), ("cid:image001", "cid")):
            target = read_target(url)
            self.assertEqual((target.scheme, target.host, target.is_web), (scheme, "", False), url)
        # Even when such an address names a machine, it is not somewhere on the web.
        self.assertEqual(goes_to("file://fileserver.example/share/x"), ("file", ""))

    def test_kinds_of_host(self):
        for host, kind in (("northwind-bank.example", "name"), ("203.0.113.9", "ip"), ("2001:db8::1", "ip"),
                           ("3405803785", "disguised-ip"), ("0xcb007109", "disguised-ip"), ("0xCB.0x00.0x71.9", "disguised-ip"),
                           ("0313.0.0161.011", "disguised-ip"), ("203.0.113", "disguised-ip"), ("203.113", "disguised-ip"),
                           ("203.0.113.9.example", "name"), ("1e100.example", "name"), ("9", "disguised-ip")):
            self.assertEqual(host_kind(host), kind, host)
        self.assertEqual(goes_to("http://[2001:db8::1]:8080/x"), ("http", "2001:db8::1"))


class DeceptiveAddressTests(unittest.TestCase):
    def test_a_name_before_the_at_sign_is_not_the_destination(self):
        target = read_target("https://northwind-bank.example@evil.example/login")
        self.assertEqual((target.host, target.name_before_at), ("evil.example", "northwind-bank.example"))
        target = read_target("https://northwind-bank.example:secure@evil.example/")
        self.assertEqual((target.host, target.name_before_at), ("evil.example", "northwind-bank.example:secure"))
        target = read_target("https://northwind-bank.example%2Flogin@evil.example/")  # an encoded slash, to look like a path
        self.assertEqual((target.host, target.name_before_at), ("evil.example", "northwind-bank.example%2Flogin"))
        self.assertEqual(read_target("https://northwind-bank.example/@evil.example").name_before_at, "")  # after the slash it is a path

    def test_browsers_read_a_backslash_as_a_slash(self):
        # A filter that does not would see evil.example as a login name and the bank as the path, or the reverse.
        target = read_target("https://northwind-bank.example\\@evil.example/")
        self.assertEqual((target.host, target.oddities), ("northwind-bank.example", ("backslashes in place of slashes",)))
        target = read_target("https:\\\\evil.example\\login")
        self.assertEqual((target.host, target.oddities), ("evil.example", ("backslashes in place of slashes",)))
        self.assertEqual(read_target("https://a.example/x?path=C:\\temp").oddities, ())  # a backslash in the query is just data

    def test_browsers_remove_line_breaks_and_tabs(self):
        target = read_target("ht\ntps://ev\til.example/lo\r\ngin")
        self.assertEqual((target.scheme, target.host, target.oddities),
                         ("https", "evil.example", ("line breaks or tabs inside the address",)))
        target = read_target("java\tscript:alert(1)")
        self.assertEqual((target.scheme, target.host, target.is_web), ("javascript", "", False))

    def test_addresses_that_run_code(self):
        for url in ("javascript:alert(1)", "  JaVaScRiPt:alert(1)", "\x01\x02javascript:void(0)", "data:text/html;base64,PGh0bWw+",
                    "vbscript:msgbox(1)", "file:///etc/passwd"):
            self.assertIn(read_target(url).scheme, ("javascript", "data", "vbscript", "file"), url)
            self.assertEqual(read_target(url).host, "", url)

    def test_a_percent_encoded_site_name_is_decoded_and_noted(self):
        target = read_target("https://evil%2Eexample/login")
        self.assertEqual((target.host, target.oddities), ("evil.example", ("the site name is partly percent-encoded",)))

    def test_what_cannot_be_read_says_so(self):
        for url in ("http://[not-an-address/", "http://[evil.example]/", "https://[::1/", "http://]["):
            target = read_target(url)
            self.assertEqual((target.host, target.oddities), ("", ("the address cannot be read",)), url)

    def test_a_non_english_site_name_is_kept(self):
        self.assertEqual(goes_to("https://xn--nrthwind-bank-0ob.example/"), ("https", "xn--nrthwind-bank-0ob.example"))
        self.assertEqual(goes_to("https://N\u00d6RTHWIND.example/"), ("https", "n\u00f6rthwind.example"))


class WrapperTests(unittest.TestCase):
    """Links that go to a service which sends the visitor on to an address carried inside them."""

    def test_microsoft_safe_links(self):
        target = read_target("https://nam01.safelinks.protection.outlook.com/?url=https%3A%2F%2Fnorthwind-bank.example%2Fstatement&data=05%7C01&reserved=0")
        self.assertEqual((target.host, target.through, target.rewritten),
                         ("northwind-bank.example", ("nam01.safelinks.protection.outlook.com",), True))
        self.assertEqual(target.written[:29], "https://nam01.safelinks.prote")  # what was written is kept for the report

    def test_proofpoint(self):
        v2 = read_target("https://urldefense.proofpoint.com/v2/url?u=https-3A__www.northwind-2Dbank.example_rates-3Fref-3Dnews&d=DwMFaQ&c=abc")
        self.assertEqual((v2.host, v2.through, v2.rewritten), ("www.northwind-bank.example", ("urldefense.proofpoint.com",), True))
        v1 = read_target("https://urldefense.proofpoint.com/v1/url?u=https://northwind-bank.example/rates&k=x")
        self.assertEqual((v1.host, v1.rewritten), ("northwind-bank.example", True))
        v3 = read_target("https://urldefense.com/v3/__https://northwind-bank.example/statement?id=7__;!!abc!xyz$")
        self.assertEqual((v3.host, v3.through, v3.rewritten), ("northwind-bank.example", ("urldefense.com",), True))

    def test_a_trusted_site_used_as_a_springboard(self):
        target = read_target("https://www.google.com/url?q=https://evil.example/login&sa=D")
        self.assertEqual((target.host, target.through, target.rewritten), ("evil.example", ("www.google.com",), False))
        self.assertEqual(goes_to("https://www.google.com/search?q=https://evil.example/"), ("https", "www.google.com"))  # a search is not a redirect

    def test_wrappers_inside_wrappers(self):
        target = read_target("https://nam01.safelinks.protection.outlook.com/?url=https%3A%2F%2Fwww.google.com%2Furl%3Fq%3Dhttps%3A%2F%2Fevil.example%2F&data=x")
        self.assertEqual((target.host, target.through, target.rewritten),
                         ("evil.example", ("nam01.safelinks.protection.outlook.com", "www.google.com"), False))  # not purely a security rewrite

    def test_what_a_wrapper_hides_is_checked_like_any_address(self):
        target = read_target("https://nam01.safelinks.protection.outlook.com/?url=https%3A%2F%2Fnorthwind-bank.example%40203.0.113.9%2Fx")
        self.assertEqual((target.host, target.name_before_at), ("203.0.113.9", "northwind-bank.example"))
        target = read_target("https://nam01.safelinks.protection.outlook.com/?url=javascript%3Aalert(1)")
        self.assertEqual((target.scheme, target.host), ("javascript", ""))

    def test_an_unknown_site_carrying_an_address_is_not_assumed_to_forward(self):
        target = read_target("https://tracker.example/click?u=https://northwind-bank.example/offers&id=9")
        self.assertEqual((target.host, target.carried, target.through), ("tracker.example", "northwind-bank.example", ()))
        target = read_target("https://northwind-bank.example/out?next=https://evil.example/")
        self.assertEqual((target.host, target.carried), ("northwind-bank.example", "evil.example"))
        self.assertEqual(read_target("https://northwind-bank.example/a?back=https://northwind-bank.example/b").carried, "")  # itself

    def test_a_wrapper_with_nothing_usable_inside_is_just_a_site(self):
        for url in ("https://nam01.safelinks.protection.outlook.com/", "https://nam01.safelinks.protection.outlook.com/?url=",
                    "https://urldefense.proofpoint.com/v2/url?d=x", "https://www.google.com/url"):
            self.assertEqual(read_target(url).through, (), url)
        self.assertEqual(goes_to("https://evil.example/?x=.safelinks.protection.outlook.com"), ("https", "evil.example"))
        self.assertEqual(read_target("https://safelinks.protection.outlook.com.evil.example/?url=https://northwind-bank.example/").through, ())
        # A site that merely has the service's name inside its own is not the service.
        impostor = read_target("https://x.safelinks.protection.outlook.com.evil.example/?url=https://northwind-bank.example/")
        self.assertEqual((impostor.host, impostor.through, impostor.rewritten, impostor.carried),
                         ("x.safelinks.protection.outlook.com.evil.example", (), False, "northwind-bank.example"))

    def test_endless_wrapping_stops(self):
        url = "https://evil.example/"
        for _ in range(MAX_HOPS + 3):
            url = "https://www.google.com/url?q=" + url.replace("%", "%25").replace(":", "%3A").replace("/", "%2F").replace("?", "%3F").replace("=", "%3D").replace("&", "%26")
        target = read_target(url)
        self.assertEqual(len(target.through), MAX_HOPS + 1)
        self.assertIn(f"wrapped more than {MAX_HOPS} times", target.oddities)

    def test_hostile_addresses_never_raise(self):
        for url in ("https://" + "a" * 100_000, "https://a.example/?" + "&".join(f"k{n}=v" for n in range(5000)), "https://[" * 1000,
                    "https://a.example/?url=" + "%" * 5000, "\x00" * 100, "https://\ud800.example/", "://", "https://@/", "https://:@:/",
                    "https://urldefense.com/v3/__", "https://urldefense.proofpoint.com/v2/url?u=-ZZ-3A-G1__", "https://a.example:99999999/"):
            read_target(url)


if __name__ == "__main__":
    unittest.main()
