"""Read a saved email into a form the checks can use, without trusting any of it.

A message under suspicion may be built to break whatever reads it: a huge file,
thousands of nested parts, text labelled with an encoding that does not exist.
So everything here is bounded, nothing is executed, rendered or written to
disk, and anything odd is recorded as a note instead of raising an error.

Header values are kept **as written**. Decoding (``decode_words``) is a
separate, explicit step, because decoding too early changes what a header means.
"""
from __future__ import annotations

import email
import email.policy
import os
from dataclasses import dataclass
from typing import List, Optional, Tuple

from lurecheck.text import decode_words, unfold

MAX_MESSAGE_BYTES = 25 * 1024 * 1024  # larger than any mail provider accepts
MAX_HEADERS = 2000
MAX_HEADER_CHARS = 64 * 1024
MAX_PARTS = 500
MAX_TEXT_CHARS = 2 * 1024 * 1024  # of decoded text kept from one part

_OUTLOOK_MSG = b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"
_EXPECTED_HEADERS = ("from", "to", "subject", "date", "received", "message-id", "return-path")


class MessageError(Exception):
    """The file could not be read as an email. The message says why."""


@dataclass(frozen=True)
class Part:
    content_type: str  # lower-case, such as "text/html"
    filename: str  # decoded; "" if the part has none
    size: int  # bytes, after undoing base64 or quoted-printable
    text: Optional[str]  # the decoded text of a text/* part that is not an attachment
    attachment: bool


@dataclass(frozen=True)
class Email:
    headers: Tuple[Tuple[str, str], ...]  # (name, value as written, unfolded), topmost first
    parts: Tuple[Part, ...]
    notes: Tuple[str, ...]  # oddities noticed while reading
    size: int

    def all(self, name: str) -> List[str]:
        """Every value of a header, topmost first, as written."""
        wanted = name.lower()
        return [value for header, value in self.headers if header.lower() == wanted]

    def first(self, name: str) -> Optional[str]:
        values = self.all(name)
        return values[0] if values else None

    def text(self, name: str) -> str:
        """The topmost value of a header with encoded words decoded, or "" if it is absent."""
        return decode_words(self.first(name) or "")


def load_email(path: str) -> Email:
    """Read the file at ``path``. Raises MessageError if it is missing, too large or not an email."""
    try:
        size = os.path.getsize(path)
        if size > MAX_MESSAGE_BYTES:
            raise MessageError(f"the file is {size:,} bytes; the limit is {MAX_MESSAGE_BYTES:,}")
        with open(path, "rb") as handle:
            data = handle.read(MAX_MESSAGE_BYTES + 1)
    except OSError as error:
        raise MessageError(f"cannot read the file: {error.strerror or error}") from error
    return read_email(data)


def read_email(data: bytes) -> Email:
    """Parse the bytes of a saved email."""
    if len(data) > MAX_MESSAGE_BYTES:
        raise MessageError(f"the message is larger than the limit of {MAX_MESSAGE_BYTES:,} bytes")
    if not data.strip():
        raise MessageError("the file is empty")
    if data.startswith(_OUTLOOK_MSG):
        raise MessageError("this is an Outlook .msg file; save the message as .eml instead")
    try:
        # compat32 is the lenient, classic policy: reading a header never raises, whatever is in it.
        parsed = email.message_from_bytes(data, policy=email.policy.compat32)
    except RecursionError:
        raise MessageError("the message is nested too deeply to read, which genuine mail never is") from None

    notes: List[str] = []
    headers: List[Tuple[str, str]] = []
    for name, value in list(parsed.raw_items())[:MAX_HEADERS]:
        value = unfold(_as_text(value))
        if len(value) > MAX_HEADER_CHARS:
            notes.append(f"the {name} header is {len(value):,} characters long; only the start was read")
            value = value[:MAX_HEADER_CHARS]
        headers.append((str(name), value))
    if len(parsed) > MAX_HEADERS:
        notes.append(f"the message has {len(parsed):,} headers; only the first {MAX_HEADERS:,} were read")
    if not any(name.lower() in _EXPECTED_HEADERS for name, _ in headers):
        raise MessageError("this does not look like a saved email: it has none of the usual headers")

    parts: List[Part] = []
    try:
        for part in parsed.walk():
            if part.is_multipart():
                continue
            if len(parts) >= MAX_PARTS:
                notes.append(f"the message has more than {MAX_PARTS} parts; the rest were not read")
                break
            parts.append(_read_part(part, notes))
    except RecursionError:
        notes.append("the message is nested too deeply; only some parts were read")
    for defect in parsed.defects:
        notes.append(f"the mail structure is malformed ({type(defect).__name__})")
    return Email(headers=tuple(headers), parts=tuple(parts), notes=tuple(dict.fromkeys(notes)), size=len(data))


def _as_text(value: object) -> str:
    """A header value as text, when the message put raw non-English bytes in it.

    Headers are meant to be plain ASCII, with anything else wrapped in encoded
    words, but plenty of mail (and all mail built to hide characters) just
    writes the bytes. The parser hands those over as placeholders. Turn them
    back into bytes and read them as UTF-8, or as Latin-1 if they are not.
    """
    text = str(value)
    try:
        raw = text.encode("ascii", "surrogateescape")
    except UnicodeEncodeError:
        return text  # already real text
    try:
        return raw.decode("utf-8")
    except UnicodeDecodeError:
        return raw.decode("latin-1")


def _filename(part: "email.message.Message") -> str:
    """The name a part gives itself, including when it is written in raw non-English bytes.

    The standard parser replaces such bytes with placeholders before it reads the
    name, which would destroy exactly the names worth looking at (a direction
    override that makes "gpj.exe" display as "exe.jpg"). So the two headers that
    can carry a name are turned into real text first, then read.
    """
    shadow = email.message.Message()
    for name, value in part.raw_items():
        if name.lower() in ("content-disposition", "content-type"):
            shadow[name] = _as_text(value)
    return str(shadow.get_filename() or "")


def _read_part(part: "email.message.Message", notes: List[str]) -> Part:
    try:
        content_type = part.get_content_type().lower()
    except Exception:  # a hostile Content-Type must not stop the analysis
        content_type = "application/octet-stream"
    try:
        filename = unfold(decode_words(_filename(part)))
    except Exception:
        filename = ""
        notes.append("an attachment's name could not be read")
    try:
        disposition = str(part.get("Content-Disposition") or "").strip().lower()
    except Exception:
        disposition = ""
    try:
        payload = part.get_payload(decode=True) or b""
    except Exception:
        payload = b""
        notes.append(f"a {content_type} part could not be decoded")
    if not isinstance(payload, bytes):
        payload = b""
    attachment = disposition.startswith("attachment") or bool(filename) or not content_type.startswith("text/")
    text = None
    if not attachment:
        try:
            charset = part.get_content_charset() or "utf-8"
        except Exception:
            charset = "utf-8"
        # Each character is at most 4 bytes, so this slice cannot cut the kept text short.
        clipped = payload[: MAX_TEXT_CHARS * 4]
        try:
            text = clipped.decode(charset, errors="replace")
        except (LookupError, ValueError):
            notes.append(f"a part says it is written in {charset!r}, which is not a known encoding")
            text = clipped.decode("latin-1")
        if len(text) > MAX_TEXT_CHARS:
            notes.append(f"a {content_type} part is very long; only the start was read")
            text = text[:MAX_TEXT_CHARS]
    return Part(content_type=content_type, filename=filename, size=len(payload), text=text, attachment=attachment)
