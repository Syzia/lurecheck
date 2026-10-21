"""docs/results.md and the README's results must be what the code measures today."""
import os
import unittest

from lurecheck.checks import Options
from lurecheck.evaluate import PUBLISHED_SEEDS, findings_table, headline, run, scenario_table, summary_table, sweep_table
from lurecheck.simulator import PROTECTED, generate

ROOT = os.path.dirname(os.path.dirname(__file__))
STALE = "out of date: run `python tools/write_results.py`, and update the README's results table"


class ResultsDocTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.outcomes = run(generate(PUBLISHED_SEEDS), Options(protected=PROTECTED))

    def read(self, *path):
        with open(os.path.join(ROOT, *path), encoding="utf-8") as handle:
            return handle.read()

    def test_every_published_table_is_reproducible(self):
        doc = self.read("docs", "results.md")
        for table in (summary_table, headline, scenario_table, sweep_table, findings_table):
            with self.subTest(table=table.__name__):
                self.assertIn(table(self.outcomes), doc, "docs/results.md is " + STALE)

    def test_the_page_matches_its_generator(self):
        import importlib.util

        spec = importlib.util.spec_from_file_location("write_results", os.path.join(ROOT, "tools", "write_results.py"))
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        self.assertEqual(self.read("docs", "results.md"), module.document(), "docs/results.md is " + STALE)

    def test_the_readme_shows_the_same_summary(self):
        self.assertIn(summary_table(self.outcomes), self.read("README.md"), "the README's results table is " + STALE)


if __name__ == "__main__":
    unittest.main()
