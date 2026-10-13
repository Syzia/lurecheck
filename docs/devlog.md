# Dev log

Important findings, mistakes and decisions, newest first. The things that were not in the plan, and the things the plan got wrong.

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
