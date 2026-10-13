"""Shared by the tests: build a made-up email from a list of headers."""
import os
from typing import Iterable, Tuple

from lurecheck.message import Email, read_email

FIXTURES = os.path.join(os.path.dirname(__file__), "fixtures")
SERVER = "mx.harbor-mail.example"


def fixture(name: str) -> str:
    return os.path.join(FIXTURES, name)


def raw_email(headers: Iterable[Tuple[str, str]], body: str = "Hello.\n") -> bytes:
    lines = [f"{name}: {value}" for name, value in headers]
    return ("\r\n".join(lines) + "\r\n\r\n" + body).encode("utf-8")


def build(*headers: Tuple[str, str], sender: str = "Northwind Bank <news@northwind-bank.example>", body: str = "Hello.\n") -> Email:
    """An email with the given headers on top of a plain From, To, Subject and Date."""
    base = [("To", "alex@harbor-mail.example"), ("Subject", "Hello"), ("Date", "Mon, 12 Oct 2026 09:14:02 +0000")]
    if sender is not None:
        base.insert(0, ("From", sender))
    return read_email(raw_email(list(headers) + base, body))


def auth(results: str, server: str = SERVER) -> Tuple[str, str]:
    """An Authentication-Results header from ``server`` (or with no server name, if it is empty)."""
    return ("Authentication-Results", f"{server}; {results}" if server else results)
