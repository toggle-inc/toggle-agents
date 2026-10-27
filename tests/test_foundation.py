"""Check canonical foundation and byte-for-byte standalone copies."""

import unittest

from foundation import test_conversation
from scripts.sync_foundation import sync


class FoundationPackagingTests(unittest.TestCase):
    def test_vendored_source_tests_and_policy_match_canonical_foundation(self):
        self.assertEqual(sync(), [])


def load_tests(loader, tests, pattern):
    tests.addTests(loader.loadTestsFromModule(test_conversation))
    return tests
