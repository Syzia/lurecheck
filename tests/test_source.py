"""Checks on the project's own files.

Lurecheck looks for invisible characters in other people's text. Its own source
must not contain any: a character nobody can see cannot be reviewed, and a
direction override in code can make it read differently from how it runs.
Write such characters as escapes (backslash-u and four hex digits) instead.
"""
import os
import unicodedata
import unittest

ROOT = os.path.dirname(os.path.dirname(__file__))
SKIPPED = {".git", ".venv", "__pycache__", ".pytest_cache", "build", "dist"}
TEXT_FILES = (".py", ".md", ".toml", ".yml", ".yaml", ".eml", ".json", ".txt", ".cfg", ".gitignore")


def project_files():
    for folder, folders, files in os.walk(ROOT):
        folders[:] = [name for name in folders if name not in SKIPPED and not name.endswith(".egg-info")]
        for name in files:
            if name.endswith(TEXT_FILES):
                yield os.path.join(folder, name)


class SourceTests(unittest.TestCase):
    def test_no_file_contains_an_invisible_or_control_character(self):
        checked = 0
        for path in project_files():
            with open(path, encoding="utf-8") as handle:
                text = handle.read()
            checked += 1
            for number, line in enumerate(text.split("\n"), 1):
                for char in line:
                    if char == "\t":
                        continue
                    with self.subTest(file=os.path.relpath(path, ROOT), line=number):
                        self.assertNotIn(unicodedata.category(char), ("Cc", "Cf", "Co", "Cs", "Zl", "Zp"),
                                         f"U+{ord(char):04X} is written literally; use an escape")  # fmt: skip
        self.assertGreater(checked, 15)  # the walk really found the project

    def test_the_readme_lists_exactly_the_findings_the_code_can_report(self):
        import re

        in_code = set()
        for path in project_files():
            if os.sep + "lurecheck" + os.sep in path and path.endswith(".py"):
                with open(path, encoding="utf-8") as handle:
                    in_code |= set(re.findall(r'"((?:auth|sender|link)\.[a-z-]+)"', handle.read()))
        with open(os.path.join(ROOT, "README.md"), encoding="utf-8") as handle:
            in_readme = set(re.findall(r"^\| `((?:auth|sender|link)\.[a-z-]+)` \|", handle.read(), flags=re.MULTILINE))
        self.assertEqual(in_readme, in_code)
        self.assertGreater(len(in_code), 20)


if __name__ == "__main__":
    unittest.main()
