# Lurecheck

Reads a saved email (a `.eml` file) and says how likely it is to be phishing, and why.

> **Status: just started.** The repository has its structure, tests and CI, and no analysis yet. The stages below are the plan.

Phishing is where most intrusions start, and deciding whether one reported email is real is everyday work for a security analyst. Lurecheck does the first pass: it reads the message the way an analyst would, lists what it found, and shows the evidence for each finding so a person can agree or disagree.

## What it will check

- **Who really sent it.** The sender-authentication results the receiving mail server recorded (SPF, DKIM, DMARC), and whether the visible sender matches the addresses replies and bounces go to.
- **Where the links really go.** Links whose visible text names one site while the address goes to another, links hidden inside redirect wrappers, and links to a bare IP address.
- **Lookalike names.** Domains that imitate a well-known one with swapped or similar-looking characters.
- **A risk score with its reasons.** Every point on the score traces back to a named finding and the exact part of the email that caused it.

## Safety rules

An email under suspicion is hostile input, so:

- **It never opens a link.** "Unwrapping" a link means decoding it offline. Nothing in the message is fetched, and by default nothing is looked up on the network at all.
- **It never runs or saves an attachment.** Attachments are measured and described, not opened.
- **It never renders the message.** HTML is read as text, not displayed.
- **Real email stays out of this repository.** A real message carries personal data and may carry live malicious links. Every `.eml` here is made up, using reserved example domains, and `.gitignore` blocks the rest.

## Build stages

Each stage is usable and tested on its own.

| Stage | Deliverable | Status |
|-------|-------------|--------|
| 1 | Read an email safely; sender and authentication checks; a scored report on the command line | not started |
| 2 | Links: extract them, unwrap known redirect wrappers offline, flag deceptive ones | not started |
| 3 | Lookalike domains | not started |
| 4 | A labelled test set and measured results: what it catches, misses and wrongly flags (**MVP**) | not started |
| 5 | Attachments and HTML tricks | not started |
| 6 | Optional live checks, such as DNS lookups, behind an explicit flag (stretch) | not started |

## Running the tests

Needs Python 3.9 or newer, and nothing else to run. Tests use pytest:

```bash
python3 -m venv .venv
.venv/bin/python -m pip install pytest
.venv/bin/python -m pytest
```

## Safety

Only analyze email you are entitled to read. Do not put real messages, addresses or attachments in this repository.
