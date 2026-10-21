# Dev log

Important findings, mistakes and decisions, newest first. The things that were not in the plan, and the things the plan got wrong.

---

## 2026-10-21: Measured results (stage 4, the MVP)

**Summary.** A generator writes labelled, made-up emails from nineteen scenarios, and a measurement tool runs them through the real analysis and reports what is caught, missed and wrongly flagged. Seven scenarios are there because Lurecheck is expected to get them wrong. On 950 messages, every scenario behaves as documented.

- **The first run found a real false alarm.** The bank's genuine mail from a second domain it owns scored 35 and was flagged. The same fact was being counted twice: once because the domain is the bank's name under a different ending, and again because the sender's name said "Northwind Bank" while the domain was not on the protected list. The brand-name check now stands aside when the domain *is* the brand's name; the ending is reported on its own, at 10.
- **It also found a bug in the generator.** A lookalike Netflix link replaced an `l` with a Cyrillic `e`, which does not look like an `l`, so the "lookalike" was not one. A test now checks that every planted lookalike really reduces to the brand's name.
- **Every scenario is all or nothing.** Fifty variations of each change names, wording and addresses, and never the outcome. So the headline percentages are really a count of scenarios, and the mix of scenarios was chosen. The results page says this before it shows a number, and puts the scenario table first.
- **Moving the line trades one mistake for another.** Flagging from 30 instead of 20 removes two of the three false alarms, and stops catching a phishing link to a bare numeric address. From 50, nothing legitimate is flagged and fewer than half of the phishing is. The line stays at 20, because it was drawn before measuring and the simulated mix cannot say where it belongs for real mail.
- **The tables are safe to share for real mail.** The same tool measures a folder of the user's own saved messages. It prints counts and finding ids, never an address or a subject, and a test checks that.

**What the deliberate bugs found.** Thirty planted, twenty-eight caught on the first run. Both survivors were in the generator: nothing checked that the phishing attachment was actually attached, and no scenario used the common plain-text-plus-HTML shape, so that code was never run. The newsletter scenario now sends both parts, as real newsletters do, and a test checks the shape of each message.

**Not done.** No real email has been measured. The scenarios were written by the person who wrote the checks, which makes these results a correctness check rather than evidence about real phishing.

---

## 2026-10-21: Lookalike domains (stage 3)

**Summary.** Lurecheck now compares every domain in a message (the sender's, the reply address's, and each link's destination) with a list of commonly imitated brands and with any domain the user protects, and reports five kinds of imitation. A domain in another alphabet is first reduced to what it looks like, so `p\u0430ypal.com` with a Cyrillic letter compares equal to `paypal.com`.

- **The same trap, a third time.** The tests for lookalike letters contain lookalike letters, and some were written into the files as the letters themselves. This time they were visible (a Cyrillic `\u0430` looks exactly like a Latin `a`), so the stage 1 guard, which looks for invisible characters, could not see them. There is now a second guard: no source file may contain a letter from the lookalike table, except as an escape code. On its first run it also found a Russian word in an older test, and a Cyrillic letter in another.
- **"Same organisation" is now decided by who registered the name.** Until now two domains counted as related only if one was inside the other. That said `news.bank.example` and `help.bank.example` were different organisations, which is wrong and would have flagged a reply going to a bank's own help desk. Both now reduce to `bank.example`, the part someone bought, and are compared on that. The approximation is the same short list of endings anyone can register under (`co.uk`, `github.io`), not the full Public Suffix List.
- **"chasm" is not an imitation of "chase".** The first version reported any name one letter away from a brand's. For a five-letter brand, a one-letter change is often just another English word. The rule now applies to names of six letters or more.
- **One trick, one count.** A domain that imitates a brand with Cyrillic letters also mixes alphabets; reporting both would score the same evidence twice. A brand name typed into the sender's name as an address (`"accounts@bank.example" <x@evil.example>`) is the sender check's finding, so the brand-name check ignores addresses.
- **The old "non-English letters" findings now score nothing.** They were a stand-in for this check. Plenty of real organisations have international names, and now there is something that can tell an imitation from a name.
- **The invisible part is spelled out.** A report that says `login.mіcrosoft.example` imitates Microsoft is unconvincing when the Cyrillic letter looks exactly like the Latin one, so the report names it.

**What the deliberate bugs found.** Fifty-eight planted, fifty-one caught on the first run. Six of the seven survivors were missing tests: a protected domain given with a subdomain, a two-letter difference counted as one, the weaker of two imitations being reported, the same place listed twice, every example being shown, and one display name claiming two brands at once. The seventh compares numeric addresses with brand names, which can never match, so it changes nothing that can be observed.

**Not done.** The brand list is a few dozen names and cannot be complete in either direction: a genuine domain it does not know can be reported as an imitation, and an imitation of a brand it does not know goes unnoticed. That is what `--protect` is for. Only the common lookalike alphabets are covered.

---

## 2026-10-13: Where the links really go (stage 2)

**Summary.** Lurecheck now reads every link in a message and works out where its address goes without visiting it. It reads the address the way a browser does, looks inside the wrappers that mail security products and search engines put around links, and reports the ways a link's text and address are made to differ.

- **Python's HTML parser could not be used.** Measured before writing any code: 80 KB of unclosed tags took it 74 seconds, and doubling the size quadrupled the time. Another input made it raise an error outright. A message body can be megabytes and the sender chooses what is in it, so one email could have stalled the tool for hours. Lurecheck has its own scanner that only finds links, and reads the same megabyte in under a second. The trick that keeps it fast is refusing to look twice: when a tag has no end within reach, the whole stretch is skipped at once instead of being tried again from every `<` inside it.
- **Browsers repair addresses, and the repairs are the attack.** `https://bank.example\@evil.example/` goes to the bank in a browser, because a backslash is read as a slash. Python's own address reader says it goes to `evil.example`. Neither is wrong by its own rules. Lurecheck reads it the browser's way, because the browser is what the victim uses, and reports the backslash as a finding in its own right.
- **Square brackets are not left to Python.** Brackets in an address are only for a numeric IPv6 address, but this machine's Python reads `http://[evil.example]/` as a link to `evil.example`, and newer versions are stricter. The tests run on two versions, so Lurecheck decides for itself: brackets hold a numeric IPv6 address, or the link is unreadable.
- **A rewritten link is judged by where it ends up.** Mail security services replace every link with one of their own. Comparing a link's text with that would flag every link in every message. Comparing with the destination inside the rewrite flags only the dishonest ones. The same reading-through exposes a link that bounces off a search engine's redirect to borrow its reputation.
- **Not every address inside an address is a redirect.** A sharing button carries the page's address too. For a service it does not recognise, Lurecheck reports that the link carries a second address and does not claim to know where the click ends up.
- **"invoice.zip" is not a website.** Link text that looks like `word.ending` is only treated as a site when the ending is a common one that is not also an everyday file type. Without that, a link labelled with a file name would be reported as naming a site it does not go to.
- **The guard test caught its first stray character.** An invisible character was written literally into a new test file, the same mistake as in stage 1, and the test that scans the source failed straight away.
- **One finding per trick.** A message with forty copies of a bad link is not forty times as suspicious. Each kind of trick is reported once, with up to three examples.

**What the deliberate bugs found.** Eighty-four planted. Twelve survived the first run. Nine of those were missing tests, now written: a `>` inside a comment, a link inside a `<!` declaration, an apostrophe in a tag being taken for the start of a quoted value, a site with a security service's name buried inside its own, and five smaller ones. The other three change nothing that can be observed: each is a second line of defence behind a check that already holds, such as removing line breaks from an address that this version of Python removes anyway. The run now refuses to start unless every test passes first, after stage 1's meaningless perfect score.

**Not done.** Honest click tracking and a deceptive link look the same to the text-against-address check, so it is scored medium and waits for measurement. Only ordinary links are read: not forms, images or scripts. Shortened links cannot be resolved offline. A lookalike domain is still just a domain.

---

## 2026-10-13: Reading an email, and who sent it (stage 1)

**Summary.** Lurecheck reads a `.eml` file, checks the sender-authentication results and the sender's name and addresses, and prints a scored report with the evidence for each finding. Standard library only. Three things went wrong on the way, and each one would have let a real trick through.

- **Raw non-English bytes in a header were being thrown away.** Headers are meant to wrap such text in encoded words. The standard parser replaces anything else with placeholder characters. So a sender name with a zero-width space typed straight in, which is the lazy and common way to do it, lost the very character the check was looking for. A test for hidden characters caught it: the check found nothing. Headers are now turned back into bytes and read as UTF-8. Attachment names had the same problem one layer further down.
- **The tool's own source was full of invisible characters.** The list of hidden characters to look for had been written into the source as the characters themselves. It worked, and nobody could see or review it. It surfaced because a deliberately planted bug could not find the text it was meant to change. Every such character is now written as a visible escape code, and a test scans every file in the project for them.
- **A whole run of deliberate bugs passed for the wrong reason.** One test was failing at the time, so every planted bug was "caught" by that same failure. Ninety out of ninety looked like a perfect score and meant nothing. The check is only worth running when the suite is green first.

Decisions worth remembering:

- **Python's own address parser was not used.** It gives different answers in different versions, and returns nothing at all for input it dislikes. A header written to confuse parsers is exactly what this tool has to look at, so it reads the structure itself and reports anything odd.
- **Structure before decoding.** An encoded sender name can decode to `<ceo@bank.example>`. Decoded first, that looks like the address. The structure is read from the header as written, and names are decoded afterwards.
- **Authentication results are read, not redone.** Redoing them needs DNS lookups, and the default is no network at all. The cost is trusting a header anyone can forge, so the tool uses only the topmost one and lets the user name their own server.
- **A second set of results under the same server name is suspicious but not proof.** The standard says a server deletes older results carrying its own name, so two sets should not exist. A message forwarded within one mail service is the innocent explanation, which is why it is scored as medium and says so.
- **Passing every check scores zero, not negative.** A phisher's own domain passes SPF, DKIM and DMARC. One of the test emails does exactly that and is still flagged, by its sender name.

**What the deliberate bugs found.** Ninety were planned. On the first run two could not be applied, because of the invisible characters above, and four of the other eighty-eight survived. Each survivor showed a missing test: a text part that carries a file name, an invisible character inside the address itself, a finding's title printed without being made safe, and JSON output with raw control characters. All four now have tests, and addresses containing control characters are rejected outright. The final run, on a clean tree, caught ninety of ninety.

**Not done.** The score thresholds are guesses. Nothing looks at links, attachments or the body. Whether two domains are the same organisation is judged from their names with a short built-in list.
