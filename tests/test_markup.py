import time
import unittest
from unittest import mock

from lurecheck import markup
from lurecheck.markup import find_anchors


def links(text):
    return [(anchor.href, anchor.text) for anchor in find_anchors(text)[0]]


class OrdinaryMarkupTests(unittest.TestCase):
    def test_a_link_and_the_text_a_reader_sees(self):
        self.assertEqual(links('<p>Hi <a href="https://a.example/x?y=1&amp;z=2">Click <b>here</b></a> now</p>'),
                         [("https://a.example/x?y=1&z=2", "Click here")])

    def test_any_letter_case_and_any_quoting(self):
        self.assertEqual(links("<A HREF='https://a.example/'>one</A><a href=https://b.example/>two</a><a\thref = \"https://c.example/\">three</a>"),
                         [("https://a.example/", "one"), ("https://b.example/", "two"), ("https://c.example/", "three")])

    def test_an_anchor_with_no_address_is_not_a_link(self):
        self.assertEqual(links('<a name="top">Top</a><a>bare</a><a href="">empty</a>'), [("", "empty")])

    def test_text_is_joined_and_tidied(self):
        self.assertEqual(links('<a href="https://a.example/">north<span>wind</span>-bank.example</a>'),
                         [("https://a.example/", "northwind-bank.example")])  # inline tags do not split a word
        self.assertEqual(links('<a href="https://a.example/">line<br>break&nbsp;and&#32;entity\n  &lt;tag&gt;</a>'),
                         [("https://a.example/", "line break and entity <tag>")])
        self.assertEqual(links('<a href="https://a.example/"><img src="x.png" alt="logo"></a>'), [("https://a.example/", "")])

    def test_image_map_areas_are_links(self):
        self.assertEqual(links('<map><area shape="rect" href="https://area.example/" alt="Sign in"></map>'),
                         [("https://area.example/", "Sign in")])

    def test_text_outside_links_is_ignored(self):
        self.assertEqual(links("no links here, just https://not-a-link.example/ in text"), [])
        self.assertEqual(links(""), [])


class DeceptiveMarkupTests(unittest.TestCase):
    """Markup written so that this reader and a browser might disagree about where a link goes."""

    def test_a_repeated_attribute_keeps_the_first_as_browsers_do(self):
        self.assertEqual(links('<a href="https://real.example/" href="https://decoy.example/">x</a>'), [("https://real.example/", "x")])

    def test_links_in_comments_scripts_and_styles_cannot_be_clicked(self):
        self.assertEqual(links('<!-- <a href="https://hidden.example/">c</a> --><a href="https://shown.example/">s</a>'),
                         [("https://shown.example/", "s")])
        # A ">" inside the comment does not end it. Only "-->" does.
        self.assertEqual(links('<!-- if a > b <a href="https://hidden.example/">c</a> --><a href="https://shown.example/">s</a>'),
                         [("https://shown.example/", "s")])
        self.assertEqual(links('<a href="https://shown.example/">s</a><!-- never closed <a href="https://hidden.example/">c</a>'),
                         [("https://shown.example/", "s")])
        self.assertEqual(links('<script>var x = "<a href=https://inscript.example/>";</script><a href="https://after.example/">a</a>'),
                         [("https://after.example/", "a")])
        self.assertEqual(links('<STYLE>a::after { content: "<a href=https://instyle.example/>" }</STYLE><a href="https://after.example/">a</a>'),
                         [("https://after.example/", "a")])

    def test_a_link_inside_a_declaration_cannot_be_clicked(self):
        # Browsers treat "<!" and "<?" as the start of a comment that runs to the next ">".
        self.assertEqual(links('<! <a href="https://hidden.example/">c</a> >'), [])
        self.assertEqual(links('<?xml <a href="https://hidden.example/">c</a> ?><a href="https://shown.example/">s</a>'),
                         [("https://shown.example/", "s")])
        self.assertEqual(links('<!DOCTYPE html><a href="https://shown.example/">s</a>'), [("https://shown.example/", "s")])

    def test_a_quote_only_starts_a_value_after_an_equals_sign(self):
        # The apostrophe in "it's" is part of an attribute name, as far as a browser is concerned.
        # Read as the start of a quoted value, it would swallow the rest of the page.
        self.assertEqual(links("<a href=https://real.example/ it's>text</a> <a href=\"https://b.example/\">b</a>"),
                         [("https://real.example/", "text"), ("https://b.example/", "b")])

    def test_a_bracket_inside_a_quoted_value_does_not_end_the_tag(self):
        self.assertEqual(links('<a title="a > b" href="https://real.example/">text</a>'), [("https://real.example/", "text")])
        self.assertEqual(links("<a title='x\"> <a href=\"https://decoy.example/\">' href='https://real.example/'>text</a>"),
                         [("https://real.example/", "text")])

    def test_a_link_that_is_never_closed_ends_at_the_next_one(self):
        self.assertEqual(links('<a href="https://a.example/">first <a href="https://b.example/">second</a> after'),
                         [("https://a.example/", "first"), ("https://b.example/", "second")])
        self.assertEqual(links('<a href="https://a.example/">runs to the end'), [("https://a.example/", "runs to the end")])

    def test_ordinary_angle_brackets_are_text(self):
        self.assertEqual(links('if a < b and c > d then <a href="https://a.example/">2 < 3</a>'), [("https://a.example/", "2 < 3")])

    def test_an_address_split_by_character_references_is_put_back_together(self):
        self.assertEqual(links('<a href="https&#58;//evil&#46;example&#x2F;login">x</a>'), [("https://evil.example/login", "x")])

    def test_text_shown_is_cut_at_a_limit(self):
        ((_, text),) = links('<a href="https://a.example/">' + "word " * 5000 + "</a>")
        self.assertEqual(len(text), markup.MAX_LINK_TEXT)


class HostileMarkupTests(unittest.TestCase):
    def test_too_many_links_are_cut_with_a_flag(self):
        page = '<a href="https://a.example/">x</a>' * 50
        with mock.patch.object(markup, "MAX_ANCHORS", 20):
            found, cut = find_anchors(page)
        self.assertEqual((len(found), cut), (20, True))
        self.assertEqual((len(find_anchors(page)[0]), find_anchors(page)[1]), (50, False))
        with mock.patch.object(markup, "MAX_ANCHORS", 20):  # also when the last one is never closed
            self.assertEqual(len(find_anchors('<a href="x">' * 50)[0]), 20)

    def test_a_stretch_with_no_tag_end_is_skipped_in_one_step(self):
        # 300 KB of "<a " with no ">" anywhere. Looking for the end of a tag from every one of the
        # 100,000 "<" is what makes other parsers slow. One look per 16 KB stretch is enough.
        with mock.patch.object(markup, "_tag_end", wraps=markup._tag_end) as looked:
            self.assertEqual(find_anchors("<a " * 100_000), ([], False))
        self.assertLess(looked.call_count, 50)

    def test_nonsense_never_raises(self):
        for text in ("<", "<<<<>>>>", "<a", "<a href", '<a href="', "</", "</a>", "<!", "<!--", "<![CDATA[", "<?", "<a href=>x</a>",
                     "<\x00a href='x'>", "<a\x00href='x'>y</a>", "\ud800<a href='\udfff'>z</a>", "<script>", "<style", "<a/href='x'>s</a>"):
            find_anchors(text)

    def test_input_built_to_slow_a_parser_down_is_read_in_proportion_to_its_size(self):
        # Python's own HTML parser took over a minute on 80 KB of the first of these. Each is 1 MB here.
        size = 1_000_000
        cases = {
            "unclosed tags": "<a " * (size // 3),
            "unclosed quotes": '<a b="' * (size // 6),
            "unclosed comments": "<!--" * (size // 4),
            "unclosed declarations": "<![" * (size // 3),
            "stray brackets": "< " * (size // 2),
            "quoted tag soup": "<a b='>" * (size // 7),
            "unclosed links": "<a href=x>" * (size // 10),
            "unclosed script": "<script>" * (size // 8),
            "far-away quotes": ('<a b="' + "x" * 16_000) * (size // 16_006),
            "ordinary page": "<p>hello <a href='https://a.example/'>x</a></p>" * (size // 46),
        }
        for name, text in cases.items():
            with self.subTest(case=name):
                start = time.perf_counter()
                find_anchors(text)
                self.assertLess(time.perf_counter() - start, 10)  # in practice well under a second


if __name__ == "__main__":
    unittest.main()
