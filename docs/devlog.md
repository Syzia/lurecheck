# Dev log

Important findings, mistakes and decisions, newest first. The things that were not in the plan, and the things the plan got wrong.

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
