"""Pure metadata fixtures; executed only by remote controller preflight."""
import unittest
from summarize import summary_counts, test_inventory


class InventoryTests(unittest.TestCase):
    def tree(self, *nodes):
        return {'testNodes': [{'nodeType': 'Test Suite', 'children': list(nodes)}]}

    def case(self, identifier='Suite/testOne()', status='Passed', **extra):
        return dict(nodeType='Test Case', nodeIdentifier=identifier, result=status, **extra)

    def counts(self, passed=1, failed=0, skipped=0):
        return dict(totalTestCount=passed + failed + skipped, passedTests=passed, failedTests=failed, skippedTests=skipped)

    def test_nested_known_cases_and_unknown_skip_reasons(self):
        row = test_inventory(self.tree(self.case(), self.case('Suite/testSkipped()', 'Skipped', skipReason='DO NOT EXPORT')), self.counts(skipped=1))
        self.assertEqual(row['status'], 'complete')
        self.assertEqual(row['skipped_tests'], [{'identifier': 'Suite/testSkipped()', 'reason': None, 'reason_status': 'unknown'}])
        self.assertNotIn('DO NOT EXPORT', str(row))

    def test_known_fallback_identifier_and_status(self):
        row = test_inventory(self.tree({'nodeType': 'Test Case', 'testIdentifier': 'Module/Suite/testOne()', 'status': 'Passed'}), self.counts())
        self.assertEqual(row['status'], 'complete')

    def test_source_parameter_labels_without_runtime_values(self):
        for identifier in ['Suite/generatedAccountReadinessWithAndWithoutAttention(useAttention:)',
                           'Module/Suite/testBoth(first:second:)', 'Suite/testUnderscore(_:other_label:)']:
            row = test_inventory(self.tree(self.case(identifier=identifier)), self.counts())
            self.assertEqual(row['status'], 'complete')
        for identifier in ['Suite/test(value: true)', 'Suite/test(true)', 'Suite/test(42)',
                           'Suite/test("secret")', 'Suite/test(label:42)', 'Suite/test(label: value:)']:
            row = test_inventory(self.tree(self.case(identifier=identifier)), self.counts())
            self.assertEqual(row['status'], 'schema_unknown')
            self.assertIsNone(row['enumerated_counts'])

    def test_summary_total_must_match_typed_component_counts(self):
        counts = self.counts(); counts['totalTestCount'] = 2
        self.assertIsNone(summary_counts(counts))
        row = test_inventory(self.tree(self.case()), counts)
        self.assertEqual(row['status'], 'schema_unknown')
        self.assertIsNone(row['summary_counts'])

    def test_failures_remain_failures(self):
        row = test_inventory(self.tree(self.case(status='Failed')), self.counts(passed=0, failed=1))
        self.assertEqual(row['enumerated_counts']['failedTests'], 1)
        self.assertEqual(row['status'], 'complete')

    def test_missing_unknown_duplicate_or_dynamic_ids_are_unknown(self):
        fixtures = [self.tree({'nodeType': 'Test Case', 'result': 'Passed'}),
                    self.tree(self.case(status='Unknown')), self.tree(self.case(status={})),
                    self.tree(self.case(), self.case()),
                    self.tree(self.case(identifier='Suite/test(secret account)')),
                    self.tree({'nodeType': 'Test Case Run', 'nodeIdentifier': 'Suite/testOne()', 'result': 'Passed'})]
        for tree in fixtures:
            row = test_inventory(tree, self.counts())
            self.assertEqual(row['status'], 'schema_unknown')
            self.assertIsNone(row['enumerated_counts'])

    def test_summary_counts_are_typed_not_coerced(self):
        for value in [None, -1, True, '1']:
            counts = self.counts(); counts['skippedTests'] = value
            self.assertIsNone(summary_counts(counts))
            self.assertEqual(test_inventory(self.tree(self.case()), counts)['status'], 'schema_unknown')

    def test_unknown_or_empty_schema_never_means_zero_skips(self):
        for tree in [{}, [], {'testNodes': {}}, {'testNodes': []}]:
            row = test_inventory(tree, self.counts())
            self.assertNotEqual(row['status'], 'complete')
            self.assertIsNone(row['enumerated_counts'])

    def test_skip_and_total_mismatches_remain_explicit(self):
        row = test_inventory(self.tree(self.case()), self.counts(skipped=1))
        self.assertEqual(row['status'], 'count_mismatch')
        self.assertEqual(row['summary_counts']['skippedTests'], 1)
        self.assertEqual(row['enumerated_counts']['skippedTests'], 0)

    def test_depth_is_bounded(self):
        tree = self.case()
        for _ in range(70): tree = {'children': [tree]}
        self.assertEqual(test_inventory({'testNodes': [tree]}, self.counts())['status'], 'schema_limit_exceeded')


if __name__ == '__main__':
    unittest.main()
