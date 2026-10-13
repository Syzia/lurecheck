import os
import tempfile
import unittest
from unittest import mock

from lurecheck import message as message_module
from lurecheck.message import MessageError, load_email, read_email
from tests.helpers import build, fixture, raw_email

FROM = ("From", "Northwind Bank <news@northwind-bank.example>")


def multipart(*parts, boundary="b1"):
    body = "".join(f"--{boundary}\r\n{part}\r\n" for part in parts) + f"--{boundary}--\r\n"
    return raw_email([FROM, ("Content-Type", f'multipart/mixed; boundary="{boundary}"')], body)


def nested(depth):
    data = b"From: a@b.example\r\n"
    for level in range(depth):
        data += b"Content-Type: multipart/mixed; boundary=b%d\r\n\r\n--b%d\r\n" % (level, level)
    return data + b"Content-Type: text/plain\r\n\r\nhi\r\n"


class ReadingTests(unittest.TestCase):
    def test_headers_are_kept_in_order_and_as_written(self):
        email = load_email(fixture("exchange_style.eml"))
        self.assertEqual(email.headers[0][0], "Received")
        self.assertEqual(email.first("from"), "Priya Nair <priya.nair@fabrikam-parts.example>")  # any letter case
        self.assertEqual(email.first("Subject"), "=?utf-8?B?UXVvdGUgZm9yIG9yZGVyIDg4MTIg4oCTIHJldmlzZWQ=?=")
        self.assertEqual(email.text("Subject"), "Quote for order 8812 – revised")  # decoding is a separate step
        self.assertIsNone(email.first("Reply-To"))
        self.assertEqual(email.text("Reply-To"), "")
        self.assertNotIn("\n", email.first("Authentication-Results"))  # wrapped lines are joined

    def test_repeated_headers_come_back_topmost_first(self):
        email = load_email(fixture("forged_auth_header.eml"))
        first, second = email.all("Authentication-Results")
        self.assertIn("dmarc=fail", first)
        self.assertIn("dmarc=pass", second)
        self.assertEqual(len(email.all("Received")), 2)

    def test_text_parts(self):
        email = load_email(fixture("exchange_style.eml"))
        self.assertEqual([(p.content_type, p.attachment) for p in email.parts], [("text/plain", False), ("text/html", False)])
        self.assertIn("revised quote", email.parts[0].text)
        self.assertIn("<p>Hi Alex", email.parts[1].text)  # HTML is kept as text, never rendered
        self.assertEqual(email.notes, ())

    def test_attachments_are_measured_not_opened(self):
        email = read_email(multipart(
            'Content-Type: text/plain; charset="utf-8"\r\n\r\nSee attached.',
            'Content-Type: application/pdf; name="invoice.pdf"\r\nContent-Disposition: attachment; filename="invoice.pdf"\r\n'
            "Content-Transfer-Encoding: base64\r\n\r\nJVBERi0xLjQgZmFrZQ==",
            'Content-Type: text/html\r\nContent-Disposition: attachment; filename="=?utf-8?b?bG9naW4uaHRtbA==?="\r\n\r\n<form>',
            "Content-Type: image/png\r\nContent-Transfer-Encoding: base64\r\n\r\niVBORw0KGgo=",
            'Content-Type: text/html; name="statement.html"\r\n\r\n<form action="x">',
        ))  # fmt: skip
        body, pdf, page, image, named = email.parts
        # A text part that carries a file name is a file, whatever else it says about itself.
        self.assertEqual((named.filename, named.attachment, named.text), ("statement.html", True, None))
        self.assertEqual((body.attachment, body.text.strip()), (False, "See attached."))
        self.assertEqual((pdf.content_type, pdf.filename, pdf.size, pdf.attachment, pdf.text),
                         ("application/pdf", "invoice.pdf", 13, True, None))  # "%PDF-1.4 fake"
        self.assertEqual((page.filename, page.attachment, page.text), ("login.html", True, None))  # named, so an attachment
        self.assertEqual((image.filename, image.attachment), ("", True))  # not text, so an attachment

    def test_a_message_inside_a_message_is_read_too(self):
        inner = "Content-Type: message/rfc822\r\n\r\nFrom: inner@other.example\r\nSubject: inner\r\n\r\ninner body"
        email = read_email(multipart("Content-Type: text/plain\r\n\r\nouter", inner))
        self.assertEqual([p.text.strip() for p in email.parts], ["outer", "inner body"])

    def test_a_mailbox_separator_line_is_tolerated(self):
        data = b"From sender@x.example Mon Oct 12 09:14:02 2026\r\n" + raw_email([FROM, ("Subject", "Hi")])
        self.assertEqual(read_email(data).first("Subject"), "Hi")


class HostileInputTests(unittest.TestCase):
    """A message under suspicion may be built to break whatever reads it."""

    def test_things_that_are_not_emails_are_refused_with_a_reason(self):
        for data, reason in (
            (b"", "empty"),
            (b"  \r\n\r\n ", "empty"),
            (b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1" + b"\x00" * 64, "Outlook .msg"),
            (b"%PDF-1.4\n%\xe2\xe3\xcf\xd3\n1 0 obj", "does not look like a saved email"),
            (b"\x00\x01\x02\xff\xfe" * 100, "does not look like a saved email"),
            (b"just some words\nand more words\n", "does not look like a saved email"),
            (b"X-Custom: only an unknown header\r\n\r\nbody", "does not look like a saved email"),
        ):
            with self.assertRaisesRegex(MessageError, reason):
                read_email(data)

    def test_a_missing_file_or_a_folder_is_a_clear_error(self):
        with self.assertRaisesRegex(MessageError, "cannot read the file"):
            load_email(os.path.join(tempfile.gettempdir(), "lurecheck-no-such-file.eml"))
        with self.assertRaisesRegex(MessageError, "cannot read the file"):
            load_email(tempfile.gettempdir())

    def test_an_oversized_file_is_refused_before_it_is_read(self):
        with tempfile.TemporaryDirectory() as folder:
            path = os.path.join(folder, "big.eml")
            with open(path, "wb") as handle:
                handle.write(raw_email([FROM], "x" * 5000))
            with mock.patch.object(message_module, "MAX_MESSAGE_BYTES", 1000):
                with self.assertRaisesRegex(MessageError, "the limit is 1,000"), mock.patch("builtins.open") as opened:
                    load_email(path)
                opened.assert_not_called()
                with self.assertRaisesRegex(MessageError, "larger than the limit"):
                    read_email(raw_email([FROM], "x" * 5000))
            self.assertEqual(load_email(path).parts[0].size, 5000)  # fine under the real limit

    def test_absurd_nesting_is_refused_and_deep_nesting_is_read(self):
        with self.assertRaisesRegex(MessageError, "nested too deeply"):
            read_email(nested(3000))
        self.assertEqual(len(read_email(nested(100)).parts), 1)

    def test_too_many_parts_are_capped_with_a_note(self):
        data = multipart(*["Content-Type: text/plain\r\n\r\npart"] * 30)
        with mock.patch.object(message_module, "MAX_PARTS", 10):
            email = read_email(data)
        self.assertEqual(len(email.parts), 10)
        self.assertIn("the message has more than 10 parts; the rest were not read", email.notes)
        self.assertEqual(len(read_email(data).parts), 30)

    def test_too_many_or_too_long_headers_are_capped_with_a_note(self):
        many = raw_email([FROM] + [("X-Filler", str(n)) for n in range(50)])
        with mock.patch.object(message_module, "MAX_HEADERS", 20):
            email = read_email(many)
        self.assertEqual(len(email.headers), 20)
        self.assertIn("the message has 51 headers; only the first 20 were read", email.notes)

        with mock.patch.object(message_module, "MAX_HEADER_CHARS", 100):
            email = read_email(raw_email([FROM, ("Subject", "s" * 500)]))
        self.assertEqual(len(email.first("Subject")), 100)
        self.assertIn("the Subject header is 500 characters long; only the start was read", email.notes)

    def test_long_text_is_capped_with_a_note(self):
        with mock.patch.object(message_module, "MAX_TEXT_CHARS", 1000):
            email = read_email(raw_email([FROM], "é" * 5000))
        self.assertEqual(len(email.parts[0].text), 1000)
        self.assertEqual(email.parts[0].size, 10_000)  # the true size is still reported
        self.assertIn("a text/plain part is very long; only the start was read", email.notes)

    def test_an_encoding_that_does_not_exist_is_noted_not_fatal(self):
        email = read_email(raw_email([FROM, ("Content-Type", "text/plain; charset=no-such-charset-9")], "café"))
        self.assertIn("caf", email.parts[0].text)
        self.assertIn("a part says it is written in 'no-such-charset-9', which is not a known encoding", email.notes)

    def test_broken_transfer_encoding_does_not_stop_the_read(self):
        email = read_email(raw_email([FROM, ("Content-Transfer-Encoding", "base64")], "!!!! not base64 @@@@"))
        self.assertEqual(len(email.parts), 1)
        self.assertTrue(any("malformed" in note for note in email.notes))

    def test_raw_bytes_in_headers_and_bodies_are_survivable(self):
        data = b"From: caf\xe9 \xff\xfe <a@b.example>\r\nSubject: \x1b[2J\x00\x07 hi\r\n\r\nbody \x00\xff\x1b[31m"
        email = read_email(data)
        self.assertIn("<a@b.example>", email.first("From"))
        self.assertIn("\x1b", email.text("Subject"))  # kept as written here; made safe when printed
        self.assertIn("\x00", email.parts[0].text)

    def test_raw_non_english_bytes_in_a_header_are_read_not_lost(self):
        # Headers are meant to wrap such text in encoded words. Mail built to hide characters does not
        # bother, and the standard parser replaces what it finds with placeholders.
        hidden = "From: North\u200bwind Bank \u65e5\u672c <news@northwind-bank.example>\r\nSubject: caf\u00e9\r\n\r\nx".encode("utf-8")
        email = read_email(hidden)
        self.assertEqual(email.first("From"), "North\u200bwind Bank \u65e5\u672c <news@northwind-bank.example>")
        self.assertEqual(email.first("Subject"), "caf\u00e9")
        # Bytes that are not UTF-8 are read as Latin-1, which accepts anything.
        self.assertEqual(read_email(b"From: a@b.example\r\nSubject: caf\xe9\r\n\r\nx").first("Subject"), "caf\u00e9")
        named = multipart('Content-Type: application/pdf\r\nContent-Disposition: attachment; filename="r\u00e9sum\u00e9\u202egpj.exe"\r\n\r\nx')
        self.assertEqual(read_email(named).parts[0].filename, "r\u00e9sum\u00e9\u202egpj.exe")

    def test_a_hostile_content_type_or_filename_does_not_stop_the_read(self):
        for header in ("Content-Type: " + "/" * 5000, "Content-Type: text/plain; charset=" + '"' * 999,
                       "Content-Disposition: attachment; filename*=utf-8''%ff%fe%00%zz",
                       "Content-Disposition: attachment; filename*0*=bogus'x'%E2; filename*1*=%82",
                       "Content-Type: multipart/mixed"):  # multipart with no boundary
            email = read_email(raw_email([FROM]).replace(b"\r\n\r\n", ("\r\n" + header + "\r\n\r\n").encode(), 1))
            self.assertGreaterEqual(len(email.parts), 0, header)

    def test_reading_never_writes_to_disk(self):
        data = multipart('Content-Type: application/octet-stream\r\nContent-Disposition: attachment; filename="../../evil.sh"\r\n\r\n#!/bin/sh')
        with tempfile.TemporaryDirectory() as folder:
            before = os.getcwd()
            os.chdir(folder)
            try:
                email = read_email(data)
                self.assertEqual(os.listdir(folder), [])
            finally:
                os.chdir(before)
        self.assertEqual(email.parts[0].filename, "../../evil.sh")  # reported exactly as written


class HelperTests(unittest.TestCase):
    def test_build_makes_an_ordinary_message(self):
        email = build(("X-Extra", "1"))
        self.assertEqual([name for name, _ in email.headers], ["X-Extra", "From", "To", "Subject", "Date"])


if __name__ == "__main__":
    unittest.main()
