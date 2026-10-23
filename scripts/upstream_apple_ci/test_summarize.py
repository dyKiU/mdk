"""Pure metadata fixtures; executed only by remote controller preflight."""
import unittest
from summarize import summary_counts, test_inventory, skip_reason_evidence


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


class SkipEvidenceTests(unittest.TestCase):
    tree = InventoryTests.tree
    case = InventoryTests.case
    counts = InventoryTests.counts
    def evidence(self, *nodes):
        tree = self.tree(self.case(), *nodes)
        inventory = test_inventory(tree, self.counts(skipped=len(nodes)))
        catalog = {'Suite/testSkipped()': {'identifier': 'Suite/testSkipped()',
                   'category': 'external_ui_driver', 'source_sha256': 'a' * 64,
                   'reasons': ['Requires the separate public XCTest UI driver']}}
        return skip_reason_evidence(tree, inventory, catalog)

    def test_actual_exact_source_literal_is_closed_and_complete(self):
        result = self.evidence(self.case('Suite/testSkipped()', 'Skipped',
                              skipReason='Requires the separate public XCTest UI driver'))
        self.assertEqual(result['status'], 'complete')
        self.assertEqual(result['skips'][0]['reason_status'], 'observed_source_literal')

    def test_missing_or_private_reason_never_complete_or_disclosed(self):
        for fields in [{}, {'skipReason': 'PRIVATE'}, {'skipReason': False}, {'reason': 'PRIVATE'}]:
            result = self.evidence(self.case('Suite/testSkipped()', 'Skipped', **fields))
            self.assertEqual(result['status'], 'unknown')
            self.assertIsNone(result['skips'][0]['reason'])
            self.assertNotIn('PRIVATE', str(result))
            self.assertEqual(result['unknown_reasons'], 1)

    def test_unknown_duplicate_ids_and_count_mismatch_stay_unknown(self):
        known = self.case('Suite/testSkipped()', 'Skipped',
                          skipReason='Requires the separate public XCTest UI driver')
        for nodes in [(self.case('Unknown/test()', 'Skipped'),), (known, known)]:
            self.assertEqual(self.evidence(*nodes)['status'], 'unknown')
        tree = self.tree(self.case(), known)
        inventory = test_inventory(tree, self.counts(skipped=2))
        self.assertEqual(skip_reason_evidence(tree, inventory, {})['status'], 'unknown')

    def test_source_inference_is_separate_from_actual_apple_reason(self):
        result = self.evidence(self.case('Suite/testSkipped()', 'Skipped'))
        self.assertEqual(result['skips'][0]['source_inferred_reason'],
                         'Requires the separate public XCTest UI driver')
        self.assertIsNone(result['skips'][0]['reason'])
        self.assertFalse(result['reason_export_complete'])
        self.assertTrue(result['coverage_inventory_complete'])

    def test_details_wrong_identity_or_unattributed_literal_never_proves_reason(self):
        tree = self.tree(self.case(), self.case('Suite/testSkipped()', 'Skipped'))
        inventory = test_inventory(tree, self.counts(skipped=1))
        catalog = {'Suite/testSkipped()': {'identifier': 'Suite/testSkipped()',
                   'category': 'external_ui_driver', 'source_sha256': 'a' * 64,
                   'reasons': ['Fixed source reason']}}
        valid = {'testIdentifier': 'Suite/testSkipped()', 'testResult': 'Skipped',
                 'skipReason': 'Fixed source reason'}
        result = skip_reason_evidence(tree, inventory, catalog, {'Suite/testSkipped()': valid})
        self.assertTrue(result['reason_export_complete'])
        for value in [dict(valid, testIdentifier='Unknown/test()'), dict(valid, testResult='Passed'),
                      {'details': 'Fixed source reason'}, dict(valid, skipReason='PRIVATE')]:
            result = skip_reason_evidence(tree, inventory, catalog, {'Suite/testSkipped()': value})
            self.assertFalse(result['reason_export_complete'])
            self.assertNotIn('PRIVATE', str(result))

    def test_details_help_is_verified_before_known_skip_only_query(self):
        import json
        import summarize
        from pathlib import Path
        from unittest.mock import patch
        inventory = {'skipped_tests': [{'identifier': 'Suite/testSkipped()'},
                                       {'identifier': 'Unknown/test()'}]}
        catalog = {'Suite/testSkipped()': {'identifier': 'Suite/testSkipped()', 'reasons': ['Fixed source reason']}}
        with patch.object(summarize, 'export_metadata', return_value=b'unknown tool help') as command:
            details, proof = summarize.export_skip_details(Path('/unused'), inventory, catalog)
        self.assertFalse(proof['help_support_confirmed'])
        self.assertEqual(details, {})
        self.assertEqual(command.call_count, 1)
        raw = json.dumps({'testIdentifier': 'Suite/testSkipped()', 'testResult': 'Skipped',
                          'skipReason': 'Fixed source reason'}).encode()
        with patch.object(summarize, 'export_metadata', side_effect=[b'test-details --path --test-id', raw]) as command:
            details, proof = summarize.export_skip_details(Path('/unused'), inventory, catalog)
        self.assertTrue(proof['help_support_confirmed'])
        self.assertEqual(list(details), ['Suite/testSkipped()'])
        self.assertEqual(command.call_count, 2)
        self.assertNotIn('Unknown/test()', str(command.call_args_list))

    def test_zero_actual_skips_needs_complete_nonempty_inventory(self):
        tree = self.tree(self.case())
        inventory = test_inventory(tree, self.counts())
        self.assertEqual(skip_reason_evidence(tree, inventory, {})['status'], 'complete')
        self.assertEqual(skip_reason_evidence({}, inventory, {})['status'], 'unknown')


class HostedVerifiedSettingsTests(unittest.TestCase):
    """Synthetic shell metadata only; no SDK/artifact/install qualification."""

    def invoke(self, response, failure=False):
        import importlib.util
        import os
        import subprocess
        from pathlib import Path
        from unittest.mock import patch
        path = Path(__file__).resolve().with_name('hosted-app-ui.py')
        spec = importlib.util.spec_from_file_location('hosted_settings_test', path)
        hosted = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(hosted)
        with patch.dict(os.environ, {'SDK_RUN_ID': '123', 'WN_CURRENT_SDK_API': '1',
                                    'WN_SDK_PROFILE': 'historical'}), \
                patch('subprocess.check_output', return_value=response,
                      side_effect=subprocess.CalledProcessError(1, ['bash']) if failure else None) as shell:
            result = hosted.verified_experimental_settings(Path('/SYNTHETIC-NOT-ACCESSED'), 'a' * 40)
            environment = shell.call_args.kwargs['env']
            self.assertEqual(environment['WN_SDK_SOURCE_SHA'], 'a' * 40)
            self.assertEqual(environment['WN_SDK_RUN_ID'], '123')
            self.assertEqual(environment['WN_SDK_PROFILE'], 'experimental')
            self.assertEqual(environment['WN_CURRENT_SDK_API'], '0')
            return result

    def test_authenticated_experimental_array_reaches_build_settings(self):
        flags = 'OTHER_SWIFT_FLAGS=$(inherited) -D WN_CURRENT_SDK_API -D WN_EXPERIMENTAL_DEVICE_SYNC'
        self.assertEqual(self.invoke('1\nexperimental\n' + flags + '\n'), [flags])

    def test_default_legacy_missing_and_extra_settings_are_rejected(self):
        valid = '1\nexperimental\nOTHER_SWIFT_FLAGS=$(inherited) -D WN_CURRENT_SDK_API -D WN_EXPERIMENTAL_DEVICE_SYNC\n'
        for response in ['0\n\n\n', '1\ndefault\nOTHER_SWIFT_FLAGS=$(inherited) -D WN_CURRENT_SDK_API\n',
                         '1\nexperimental\nOTHER_SWIFT_FLAGS=$(inherited) -D WN_EXPERIMENTAL_DEVICE_SYNC\n',
                         valid + 'UNEXPECTED\n', valid.replace(' -D WN_EXPERIMENTAL_DEVICE_SYNC', ' -D UNEXPECTED')]:
            with self.subTest(response_shape=len(response)), self.assertRaises(ValueError):
                self.invoke(response)

    def test_guard_failure_is_not_replaced_by_environment_flags(self):
        import subprocess
        with self.assertRaises(subprocess.CalledProcessError):
            self.invoke('', failure=True)


if __name__ == '__main__':
    unittest.main()
