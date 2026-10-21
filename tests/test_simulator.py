import ipaddress
import re
import unittest

from lurecheck.domains import skeleton, unicode_form
from lurecheck.message import read_email
from lurecheck.simulator import BENIGN, HOMOGRAPHS, PHISH, SCENARIOS, TYPOS, by_name, generate


class ScenarioTests(unittest.TestCase):
    def test_the_scenarios(self):
        self.assertEqual(len(by_name()), len(SCENARIOS))  # names are unique
        self.assertEqual({s.label for s in SCENARIOS}, {PHISH, BENIGN})
        documented = {s.name for s in SCENARIOS if s.documented}
        self.assertEqual(documented, {"shortened-link", "plain-phish", "gift-card-request", "html-attachment",
                                      "tracked-newsletter", "help-desk", "mailing-list"})  # fmt: skip
        for scenario in SCENARIOS:
            self.assertEqual(scenario.expected_flag, (scenario.label == PHISH) != bool(scenario.documented), scenario.name)
            self.assertTrue(scenario.description, scenario.name)

    def test_the_same_seeds_give_the_same_messages(self):
        first, second = generate([1, 2]), generate([1, 2])
        self.assertEqual([s.data for s in first], [s.data for s in second])
        self.assertEqual(len(first), 2 * len(SCENARIOS))
        self.assertNotEqual(generate([1])[0].data, generate([2])[0].data)

    def test_every_scenario_varies_between_runs(self):
        samples = generate(range(1, 11))
        for scenario in SCENARIOS:
            variants = {s.data for s in samples if s.scenario is scenario}
            self.assertGreater(len(variants), 1, scenario.name)

    def test_every_message_reads_cleanly(self):
        for sample in generate(range(1, 4)):
            with self.subTest(scenario=sample.scenario.name, seed=sample.seed):
                message = read_email(sample.data)
                self.assertEqual(message.notes, ())
                self.assertIsNotNone(message.first("From"))
                self.assertIsNotNone(message.first("Authentication-Results"))

    def test_the_message_shapes(self):
        samples = {s.scenario.name: read_email(s.data) for s in generate([1])}
        attached = [p for p in samples["html-attachment"].parts if p.attachment]
        self.assertEqual(len(attached), 1)
        self.assertTrue(attached[0].filename.endswith(".html"))
        self.assertEqual([p.content_type for p in samples["newsletter"].parts], ["text/plain", "text/html"])  # as real ones send

    def test_the_lookalikes_really_look_alike(self):
        # Found by the first measurement: one of these swapped a letter for one that does not resemble it.
        for shown, label, position, code in HOMOGRAPHS:
            fake = label[:position] + chr(code) + label[position + 1 :]
            self.assertEqual(skeleton(fake), label, shown)
            self.assertNotEqual(fake, label)
        for shown, typo in TYPOS:
            self.assertGreaterEqual(len(typo), 6, typo)  # long enough for the one-letter rule

    def test_nothing_real_is_in_the_messages(self):
        documentation = [ipaddress.ip_network(n) for n in ("192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24")]
        known_services = ("bit.ly", "nam01.safelinks.protection.outlook.com")
        for sample in generate(range(1, 6)):
            text = sample.data.decode("utf-8")
            for domain in set(re.findall(r"@([A-Za-z0-9.-]+)", text)) | set(re.findall(r"https?://(?:[^/@\s\"]+@)?([^/\s\"?:]+)", text)):
                try:
                    ipaddress.ip_address(domain)
                    continue
                except ValueError:
                    pass
                with self.subTest(scenario=sample.scenario.name, domain=domain):
                    shown = unicode_form(domain)
                    self.assertTrue(shown.endswith((".example", ".test")) or domain in known_services, domain)
            for found in re.findall(r"\b\d{1,3}(?:\.\d{1,3}){3}\b", text):
                with self.subTest(scenario=sample.scenario.name, address=found):
                    self.assertTrue(any(ipaddress.ip_address(found) in n for n in documentation), found)


if __name__ == "__main__":
    unittest.main()
