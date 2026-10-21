# Lurecheck

Reads a saved email (a `.eml` file) and says how likely it is to be phishing, and why.

> **Status: stage 4 of 6 (MVP).** It reads an email safely, checks who really sent it, where its links really go, and whether any domain in it imitates a well-known one, and its results are measured on a labelled set of messages. It does not look at attachments yet, and it has not been measured on real email.

Phishing is where most intrusions start, and deciding whether one reported email is real is everyday work for a security analyst. Lurecheck does the first pass: it reads the message the way an analyst would, lists what it found, and shows the evidence for each finding so a person can agree or disagree.

## Results

Measured on 950 labelled, made-up messages: 19 scenarios, 50 variations of each. Seven of the scenarios are there because Lurecheck is expected to get them **wrong**, and they are counted.

| | Scenarios | Flagged every time | Flagged sometimes | Never flagged |
|---|---:|---:|---:|---:|
| Phishing | 11 | 7 | 0 | 4 |
| Legitimate | 8 | 3 | 0 | 5 |

- **Every scenario behaves as documented.** Each is caught every time or never; the details that vary between runs never change the outcome.
- **The four phishing messages it misses** have no technical tell (a gift-card request from a free mail account, a phish from the attacker's own clean domain), hide behind a link shortener, or arrive as an attachment, which stage 5 will examine.
- **The three legitimate messages it flags** look exactly like tricks: a newsletter's click tracking, a help desk's reply address, and a mailing list that breaks the author's signature. None of them reaches "likely phishing".

The scenarios were written by the same person as the checks, so these numbers are a correctness check, not a claim about real mail. Every table, the threshold trade-offs and the known gaps are in [docs/results.md](docs/results.md), and a test regenerates it and fails if it drifts from the code.

## Try it

Needs Python 3.9 or newer and nothing else. The repository includes ten made-up emails:

```bash
python3 -m lurecheck tests/fixtures/display_name_trick.eml
```

The report, shortened:

```
Verdict: SUSPICIOUS  (risk score 35 of 100)

  From:      "accounts@northwind-bank.example" <billing@invoice-portal.example>
  Subject:   Invoice 20391 is overdue

Findings
  [high   +35] The sender's name displays accounts@northwind-bank.example, but the real address is billing@invoice-portal.example
      Evidence: "accounts@northwind-bank.example" <billing@invoice-portal.example>
      Why it matters: The name part of From is free text. Putting a trusted address there makes many
        mail programs, phones especially, show only that and hide the address the message came from.

Also noted (adds nothing to the score)
  [info] DMARC passed for invoice-portal.example
      What it means: The message really was sent by, or on behalf of, the domain shown in From. That
        says who sent it, not that they mean well: a phisher's own domain passes too.
```

That example is the point of the tool in one message: every authentication check **passed**, because the sender owns the domain it was sent from, and it is still a trick.

For the link checks, try `tests/fixtures/deceptive_link.eml` and `tests/fixtures/link_tricks.eml`. For lookalike domains, `tests/fixtures/lookalike_microsoft.eml`. The made-up bank in these examples is not on the built-in list of brands, so name it to have its imitations caught too:

```bash
python3 -m lurecheck --protect northwind-bank.example tests/fixtures/deceptive_link.eml
```

Options:

- `--json` prints the same report as JSON, for another program to read.
- `--trusted-server NAME` names your own mail server (see "Which results to believe" below).
- `--protect DOMAIN` adds a domain to watch for imitations of, usually your own organisation's. Repeat it for several.
- Several files can be given at once.
- `python3 -m lurecheck.evaluate` runs the measurement above. With `--folder DIR` it measures your own saved emails instead, from `DIR/phish/` and `DIR/benign/`, and prints only counts.

**Your own email.** Save a message as `.eml` and pass its path. In Gmail: open the message, choose *Show original*, then *Download Original*. In Apple Mail: *File → Save As…* with the format *Raw Message Source*. Keep saved messages outside this folder, for example in `~/phishing-samples/`: they contain personal data, and `.gitignore` refuses them anyway.

## What it checks

Each finding has a fixed id, a severity, the evidence that triggered it, and a plain explanation. `info` findings are worth knowing and add nothing to the score.

| Finding | Meaning | Severity |
|---------|---------|----------|
| `auth.dmarc-fail` | The message did not come from the domain shown in From | high |
| `auth.dmarc-other-domain` | The server verified one domain while From shows another | high |
| `auth.conflicting-results` | A second set of results under the same server name claims passes the real one does not | medium |
| `auth.passed-for-other-domain` | The checks passed, but for a different domain from the one shown | medium |
| `auth.spf-fail` | The sending machine is not allowed to send for that domain | medium |
| `auth.dkim-fail` | A signature on the message does not verify | medium |
| `auth.no-trusted-results` | No results from the mail server you named | medium |
| `auth.spf-softfail` | The sending machine is probably not allowed to send for that domain | low |
| `auth.nothing-verified` | The server checked and nothing passed | low |
| `auth.no-results` | The file has no authentication results at all | low |
| `auth.dmarc-pass` | The message was sent by the domain shown | info |
| `auth.aligned-pass` | No DMARC result, but a check passed for the domain shown | info |
| `auth.other-results-ignored` | Results further down the message were not used | info |
| `sender.several-from-headers` | More than one From header | high |
| `sender.name-shows-another-address` | The sender's name displays an address that is not the real one | high |
| `sender.reply-goes-elsewhere` | Replies go to a different organisation | medium |
| `sender.malformed-from` | The From header is not written the way mail programs write it | medium |
| `sender.several-from-addresses` | One From header lists several senders | medium |
| `sender.hidden-characters` | Invisible or direction-changing characters in the sender | medium |
| `sender.no-from` | No From header | medium |
| `sender.international-domain` | The sender's domain uses non-English letters | info |
| `sender.sent-through-another-domain` | Sent through a mailing service or other third party | info |
| `link.name-before-at` | A link puts a trusted-looking name before an `@`, which browsers ignore | high |
| `link.disguised-ip-address` | A link goes to a numeric address written to not look like one | high |
| `link.runs-code` | A link runs code or carries a page inside itself (`javascript:`, `data:`) | high |
| `link.text-shows-another-site` | A link's text names one site and its address goes to another | medium |
| `link.ip-address` | A link goes to a bare numeric address | medium |
| `link.malformed` | A link is written in a way browsers repair and people misread | medium |
| `link.bounces-through` | A link bounces off a well-known site on its way elsewhere | low |
| `link.carries-another-address` | A link's address has a second address inside it | low |
| `link.shortened` | A link uses a shortening service, hiding where it leads | low |
| `link.international-domain` | A link goes to a site whose name uses non-English letters | info |
| `link.rewritten-by-security-service` | Links were rewritten by a mail security service, and read through | info |
| `link.sites` | The sites the message links to | info |
| `link.too-many` | More links than the limit; the rest were not read | info |
| `lookalike.characters` | A domain imitates a well-known one with lookalike letters or digits | high |
| `lookalike.brand-in-subdomain` | A domain puts a well-known name in front of someone else's | high |
| `lookalike.one-letter-off` | A domain is one letter away from a well-known one | medium |
| `lookalike.name-claims-brand` | The sender's name says a brand the sending domain does not belong to | medium |
| `lookalike.brand-plus-words` | A domain combines a well-known name with other words | medium |
| `lookalike.mixed-alphabets` | A domain mixes alphabets inside one word | medium |
| `lookalike.different-ending` | A well-known name under a different ending | low |

### Which results to believe

A mail server records what it found about the sender in an `Authentication-Results` header. Anyone can type the same header into a message they send, saying everything passed.

Mail servers add their header at the top, so the topmost one was added last, by the server nearest the reader. Lurecheck uses that one and ignores the rest. If you know the name your mail server writes there (`mx.google.com`, for example), pass `--trusted-server` and only results under that name are used. That is safer, because it does not depend on the order of headers.

Lurecheck **reads** these results. It does not redo the checks, which would need DNS lookups, and by default it never touches the network.

### Where the links go

A reader sees a link's text. The browser follows its address. Lurecheck reads every link in the HTML and plain-text parts and works out where each address goes **without visiting it**:

- **The address is read the way a browser reads it.** Browsers drop line breaks, treat a backslash as a slash, and ignore anything before an `@`. A link that relies on one of those reads as one site to a person and goes to another.
- **Known wrappers are read through.** Mail security products rewrite every link to pass through their scanner (Microsoft Safe Links, Proofpoint URL Defense). Lurecheck decodes those offline and judges the link by its real destination, so a rewritten link is neither excused nor blamed for the rewrite. A link that bounces off a search engine's redirect is read through the same way, and noted.
- **One finding per trick.** Forty copies of a bad link score the same as one. The evidence shows up to three examples.

What it cannot know offline: where a shortened link leads, and whether an unfamiliar site carrying another address will forward to it. Those are reported as what they are, at low severity.

### Lookalike domains

The sender's domain, the domains replies go to, and every link's destination are compared with a built-in list of commonly imitated brands (banks, mail and cloud providers, couriers, tax offices) and with any domain given to `--protect`. Five kinds of imitation are recognised, strongest first:

| Kind | Example | Why it works |
|------|---------|--------------|
| Lookalike characters | `pаypal.com`, with a Cyrillic `а`; `paypa1.com`; `rnicrosoft.com` | To a reader it is the same name |
| The real name as a subdomain | `paypal.com.account-verify.example` | The owner is the part at the end, which people do not read |
| One letter off | `paypall.com`, `micorsoft.com` | Catches typing mistakes, and careless readers |
| The real name plus words | `paypal-support.example` | Looks official and costs nothing |
| A different ending | `paypal.co` | A different owner, unless the brand bought both |

A name written in another alphabet is reduced to what it **looks like** before comparing, using the confusable-characters idea from Unicode's security guidance: Cyrillic and Greek letters drawn like English ones, accents, and the old ASCII disguises (`rn` for `m`, `1` for `l`, `0` for `o`). The report spells out which letter is foreign, because it is invisible otherwise:

```
login.xn--mcrosoft-thh.example (reads as login.mіcrosoft.example; і is cyrillic small letter byelorussian-ukrainian i)
```

Separately, a word that mixes alphabets is reported even if it imitates nothing on the list, and a display name that names a brand ("Microsoft account team") is reported when the sending domain is not one the brand uses.

The two "non-English letters" findings from stages 1 and 2 now add nothing to the score. Many genuine organisations have names like that; whether one is an imitation is this check's question, and it answers it better.

### The score

Each scored finding adds its points, to a maximum of 100. From 20 the verdict is *suspicious*, from 50 *likely phishing*, below that *no strong signs of phishing*. Those lines were drawn before anything was measured and have not been moved: [docs/results.md](docs/results.md) shows what moving them would trade on the labelled set. At 50, nothing legitimate in it is flagged, and fewer than half of the phishing is.

A low score means these checks found little. It never means a message is safe.

## Safety rules

An email under suspicion is hostile input, so:

- **It never opens a link.** Nothing in the message is fetched, and by default nothing is looked up on the network at all.
- **It never runs or saves an attachment.** Attachments are measured and described, not opened or written to disk.
- **It never renders the message.** HTML is read as text, not displayed.
- **Real email stays out of this repository.** A real message carries personal data and may carry live malicious links. Every `.eml` here is made up, using reserved `.example` domains and documentation addresses. A test checks that, and `.gitignore` blocks the rest.

How Lurecheck protects itself:

- **Size limits everywhere.** A file over 25 MB is refused before it is read. Headers, parts, nesting and text length are capped, with a note in the report when a cap is hit.
- **Nothing in the message can stop the analysis.** Unknown encodings, broken base64 and malformed structure are noted and read around. A file that cannot be read at all is reported as such, which is itself unusual for genuine mail.
- **The report cannot be hijacked.** Text from the message is made safe before printing: control characters, escape sequences and invisible characters are shown as visible codes such as `\x1b`. A message cannot clear the screen, recolour the output or forge a line of the report.
- **Headers are read before they are decoded.** A sender's name can be encoded to contain `<`, `>` or a comma. Decoding first would let it change which part is taken as the address.
- **Its own HTML reader.** Python's built-in HTML parser slows down with the *square* of the input size when the markup is built to make it: 80 KB of unclosed tags took it over a minute when measured for this project, and some inputs crash it. A message body can be megabytes. Lurecheck uses a small scanner that only finds links and takes time proportional to the size: the same megabyte in under a second.
- **No invisible characters in the source.** The tool that looks for hidden characters must not contain any. A test scans every file.

## Known limits

- **It trusts the receiving server's results.** If the file was edited after delivery, or the topmost results header was not written by your server, the conclusion is wrong. `--trusted-server` narrows this, and does not close it.
- **Passing authentication is not innocence.** A phisher's own domain passes every check. The other findings exist for that case.
- **"Same organisation" is approximate.** Whether two domains belong together is decided from their names, with a short built-in list of suffixes anyone can register under (`co.uk`, `github.io`). An uncommon suffix can be misjudged.
- **Honest click tracking looks like a deceptive link.** A newsletter that shows its own address as link text and sends the click through a tracking service is flagged the same way as a phish. That is why `link.text-shows-another-site` is medium, not high. Stage 4 will measure how often it happens.
- **It is not a browser.** Where browsers disagree about broken markup, the link scanner may read it differently from the one your mail program uses. Only `<a>` and `<area>` links are read: not buttons built from forms, images, or scripts.
- **The brand list is short and cannot be complete.** A brand's genuine domain that is missing from it (a regional site, a newly bought name) can be reported as an imitation of that brand; the finding names both, so it is easy to check. A lookalike of a brand that is not on the list, and was not given to `--protect`, is not recognised at all.
- **The lookalike table covers the usual suspects, not all of Unicode.** Cyrillic, Greek, Armenian and the common Latin variants. A letter from an uncommon alphabet that happens to look English can get through.
- **A one-letter difference can be a real word.** That rule only applies to names of six letters or more, and is scored medium.
- **No attachments or body text yet.**
- **Measured only on simulated mail.** The labelled set was written by the same person as the checks. See [docs/results.md](docs/results.md).

## Build stages

Each stage is usable and tested on its own.

| Stage | Deliverable | Status |
|-------|-------------|--------|
| 1 | Read an email safely; sender and authentication checks; a scored report on the command line | done |
| 2 | Links: extract them, unwrap known redirect wrappers offline, flag deceptive ones | done |
| 3 | Lookalike domains | done |
| 4 | A labelled test set and measured results: what it catches, misses and wrongly flags (**MVP**) | done |
| 5 | Attachments and HTML tricks | not started |
| 6 | Optional live checks, such as DNS lookups, behind an explicit flag (stretch) | not started |

Mistakes and findings along the way are in [docs/devlog.md](docs/devlog.md).

## Running the tests

```bash
python3 -m venv .venv
.venv/bin/python -m pip install pytest
.venv/bin/python -m pytest
```

## Safety

Only analyze email you are entitled to read. Do not put real messages, addresses or attachments in this repository.
