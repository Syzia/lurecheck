# Lurecheck

Reads a saved email (a `.eml` file) and says how likely it is to be phishing, and why.

> **Status: stage 1 of 6.** It reads an email safely and checks who really sent it: the sender-authentication results and the sender's name and addresses. It does not look at links or attachments yet. The risk score is provisional: the thresholds are first guesses and have not been measured against real mail.

Phishing is where most intrusions start, and deciding whether one reported email is real is everyday work for a security analyst. Lurecheck does the first pass: it reads the message the way an analyst would, lists what it found, and shows the evidence for each finding so a person can agree or disagree.

## Try it

Needs Python 3.9 or newer and nothing else. The repository includes six made-up emails:

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

Options:

- `--json` prints the same report as JSON, for another program to read.
- `--trusted-server NAME` names your own mail server (see "Which results to believe" below).
- Several files can be given at once.

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
| `sender.international-domain` | The sender's domain uses non-English letters | low |
| `sender.sent-through-another-domain` | Sent through a mailing service or other third party | info |

### Which results to believe

A mail server records what it found about the sender in an `Authentication-Results` header. Anyone can type the same header into a message they send, saying everything passed.

Mail servers add their header at the top, so the topmost one was added last, by the server nearest the reader. Lurecheck uses that one and ignores the rest. If you know the name your mail server writes there (`mx.google.com`, for example), pass `--trusted-server` and only results under that name are used. That is safer, because it does not depend on the order of headers.

Lurecheck **reads** these results. It does not redo the checks, which would need DNS lookups, and by default it never touches the network.

### The score

Each scored finding adds its points, to a maximum of 100. From 20 the verdict is *suspicious*, from 50 *likely phishing*, below that *no strong signs of phishing*. Those numbers are judgement, not measurement. Stage 4 builds a labelled set of messages and reports what the tool catches, misses and wrongly flags, and the numbers will change then.

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
- **No invisible characters in the source.** The tool that looks for hidden characters must not contain any. A test scans every file.

## Known limits

- **It trusts the receiving server's results.** If the file was edited after delivery, or the topmost results header was not written by your server, the conclusion is wrong. `--trusted-server` narrows this, and does not close it.
- **Passing authentication is not innocence.** A phisher's own domain passes every check. The other findings exist for that case, and stage 1 has only a few of them.
- **"Same organisation" is approximate.** Whether two domains belong together is decided from their names, with a short built-in list of suffixes anyone can register under (`co.uk`, `github.io`). An uncommon suffix can be misjudged.
- **No links, attachments or body text yet.** A message whose only trick is a deceptive link scores zero today.
- **The scores are unmeasured.** See above.

## Build stages

Each stage is usable and tested on its own.

| Stage | Deliverable | Status |
|-------|-------------|--------|
| 1 | Read an email safely; sender and authentication checks; a scored report on the command line | done |
| 2 | Links: extract them, unwrap known redirect wrappers offline, flag deceptive ones | not started |
| 3 | Lookalike domains | not started |
| 4 | A labelled test set and measured results: what it catches, misses and wrongly flags (**MVP**) | not started |
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
