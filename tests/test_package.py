import unittest

import lurecheck


class PackageTests(unittest.TestCase):
    def test_package_imports_and_has_a_version(self):
        self.assertRegex(lurecheck.__version__, r"^\d+\.\d+\.\d+$")


if __name__ == "__main__":
    unittest.main()
