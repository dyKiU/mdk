"""REMOTE synthetic cohort-routing metadata only; never SDK/install qualification."""
import importlib.util
import copy
from pathlib import Path
import unittest
from unittest.mock import patch

SPEC = importlib.util.spec_from_file_location('app_sdk_cohort', Path(__file__).with_name('app-sdk-cohort.py'))
cohort = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(cohort)
F = 'a' * 40  # Synthetic command-routing identity, not an artifact or qualified F.
R = '123'


class AppCohortRoutingTests(unittest.TestCase):
    def test_closed_platform_selector_defaults_and_preview_subsets(self):
        self.assertEqual(cohort.selected_platforms('both'), ['macos', 'ios'])
        self.assertEqual(cohort.selected_platforms('macos'), ['macos'])
        self.assertEqual(cohort.selected_platforms('ios'), ['ios'])

    def test_platform_selector_refuses_unknown_or_untyped_choices(self):
        for value in ('', 'all', 'mac', 'linux', None, True, ['macos'], {'platform': 'ios'}):
            with self.subTest(value=value), self.assertRaises(ValueError):
                cohort.selected_platforms(value)

    def test_default_environment_cannot_inherit_private_opt_in(self):
        with patch.dict(cohort.os.environ, {'WN_EXPERIMENTAL_DEVICE_SYNC': '1'}):
            env = cohort.environment_for('default', F, R)
        self.assertEqual(env['WN_EXPERIMENTAL_DEVICE_SYNC'], '0')
        self.assertEqual(env['WN_SDK_PROFILE'], 'default')
        self.assertEqual(env['WN_SDK_SOURCE_SHA'], F)
        self.assertEqual(env['WN_SDK_RUN_ID'], R)

    def test_experimental_environment_remains_explicit_private_one(self):
        env = cohort.environment_for('experimental', F, R)
        self.assertEqual(env['WN_EXPERIMENTAL_DEVICE_SYNC'], '1')
        self.assertEqual(env['WN_SDK_PROFILE'], 'experimental')
        self.assertIn('experimental-device-sync', cohort.FEATURES['experimental'])

    def test_historical_environment_has_neither_capability_request(self):
        env = cohort.environment_for('historical', F, R)
        self.assertEqual(env['WN_EXPERIMENTAL_DEVICE_SYNC'], '0')
        self.assertEqual(env['WN_CURRENT_SDK_API'], '0')
        self.assertEqual(env['WN_SDK_PROFILE'], '')
        self.assertEqual(env['WN_SDK_SOURCE_SHA'], '')
        self.assertEqual(env['WN_SDK_RUN_ID'], '')

    def test_synthetic_guard_response_cannot_add_private_flag_to_default(self):
        # This checks the wrapper's output contract only, not a guard or install
        # positive. Real guard metadata and actual SDK qualification are separate.
        reply = '1\ndefault\nOTHER_SWIFT_FLAGS=$(inherited) -D WN_CURRENT_SDK_API -D WN_EXPERIMENTAL_DEVICE_SYNC\n'
        with patch.object(cohort.subprocess, 'check_output', return_value=reply):
            with self.assertRaisesRegex(ValueError, 'exact cohort compiler settings'):
                cohort.guard_settings(Path('/SYNTHETIC-NEVER-ACCESSED'), 'default', {})


class AppCohortEvidenceBoundaryTests(unittest.TestCase):
    # These are intentionally synthetic metadata acceptance/parser controls.
    # They create no SDK, installation, Git checkout or qualification evidence.
    def counts(self, passed=1, failed=0, skipped=0):
        return dict(totalTestCount=passed + failed + skipped, passedTests=passed,
                    failedTests=failed, skippedTests=skipped)

    def inventory(self, platform='macos', skip=True):
        counts = self.counts(skipped=int(skip))
        identifier = next(iter(cohort.KNOWN_SKIPS[platform]))
        value = dict(status='complete', summary_counts=counts, enumerated_counts=copy.deepcopy(counts),
                     unknown_nodes=0, skipped_tests=[dict(identifier=identifier)] if skip else [])
        return value, counts

    def row(self):
        definition = cohort.MUTANTS['macos'][0]
        gate, name, source, selector = definition
        facts = dict(path=source, canonical_file=True, git_sha256='a' * 64,
                     physical_sha256='a' * 64, git_mode='100644', physical_mode=0o644, prepared_mode=0o644)
        row = dict(case=name, source_path=source, selector=selector,
                   original_sha256='a' * 64, mutant_sha256='b' * 64, final_source_sha256='a' * 64,
                   mutation_killed=True, source_restored=True, restored_control_passed=True,
                   runtime_red_confirmed=True,
                   runs=[dict(phase='mutant', exit_code=65, runtime_result_present=True,
                              summary=self.counts(passed=0, failed=1)),
                         dict(phase='restored-control', exit_code=0, runtime_result_present=True,
                              summary=self.counts())])
        return definition, facts, row

    def test_complete_inventory_preserves_named_separate_skip(self):
        inventory, counts = self.inventory()
        result = cohort.suite_inventory_gate(inventory, counts, 'macos')
        self.assertEqual(len(result), 1)
        self.assertFalse(result[0]['native_acceptance_waived'])
        self.assertEqual(result[0]['separate_gate'], 'native_fixture')
        inventory, counts = self.inventory(skip=False)
        self.assertEqual(cohort.suite_inventory_gate(inventory, counts, 'macos'), [])

    def test_unknown_inventory_and_count_mismatch_fail_closed(self):
        for key, value in [('status', 'unknown'), ('unknown_nodes', 1), ('unknown_nodes', False),
                           ('enumerated_counts', self.counts(passed=2))]:
            inventory, counts = self.inventory()
            inventory[key] = value
            with self.subTest(field=key), self.assertRaises(ValueError):
                cohort.suite_inventory_gate(inventory, counts, 'macos')
        inventory, _ = self.inventory()
        with self.assertRaises(ValueError):
            cohort.suite_inventory_gate(inventory, None, 'macos')

    def test_unknown_skipped_body_cannot_qualify(self):
        inventory, counts = self.inventory()
        inventory['skipped_tests'][0]['identifier'] = 'UnreviewedRequiredTests/missingCoverage()'
        with self.assertRaises(ValueError):
            cohort.suite_inventory_gate(inventory, counts, 'macos')

    def test_duplicate_alias_and_wrong_platform_skips_fail_closed(self):
        inventory, counts = self.inventory()
        inventory['skipped_tests'].append(dict(identifier='whitenoise_macTests/' + inventory['skipped_tests'][0]['identifier']))
        counts = self.counts(skipped=2)
        inventory['summary_counts'] = inventory['enumerated_counts'] = counts
        with self.assertRaises(ValueError):
            cohort.suite_inventory_gate(inventory, counts, 'macos')
        inventory, counts = self.inventory('ios')
        ios_only = 'NativePairingQRCodeTests/testActualThreeDevicePacketsPassAppCodecAndOriginalSdkAuthentication()'
        self.assertIn(ios_only, cohort.KNOWN_SKIPS['ios'])
        self.assertNotIn(ios_only, cohort.KNOWN_SKIPS['macos'])
        inventory['skipped_tests'][0]['identifier'] = ios_only
        with self.assertRaises(ValueError):
            cohort.suite_inventory_gate(inventory, counts, 'macos')

    def test_synthetic_valid_mutation_row_checks_schema_only(self):
        definition, facts, row = self.row()
        result = cohort.mutation_row_gate(row, definition, facts)
        self.assertTrue(result['accepted'])
        self.assertEqual([phase['exit_code'] for phase in result['phases']], [65, 0])
        self.assertEqual(result['source_mode'], 0o644)

    def test_missing_malformed_and_equal_mutation_hashes_rejected(self):
        for key in ['original_sha256', 'mutant_sha256', 'final_source_sha256']:
            for replacement in [None, '', 'z' * 64, True, 'a' * 63]:
                definition, facts, row = self.row()
                row[key] = replacement
                with self.subTest(field=key), self.assertRaises(ValueError):
                    cohort.mutation_row_gate(row, definition, facts)
        definition, facts, row = self.row()
        row['mutant_sha256'] = row['original_sha256']
        with self.assertRaises(ValueError):
            cohort.mutation_row_gate(row, definition, facts)

    def test_phase_exit_codes_and_native_counts_are_exact(self):
        changes = [('exit_code', 1), ('exit_code', False), ('exit_code', 0),
                   ('summary', self.counts(passed=0, failed=0)),
                   ('summary', self.counts(passed=0, failed=1, skipped=1))]
        for key, replacement in changes:
            definition, facts, row = self.row()
            row['runs'][0][key] = replacement
            with self.subTest(field=key), self.assertRaises(ValueError):
                cohort.mutation_row_gate(row, definition, facts)
        definition, facts, row = self.row()
        row['runs'][1]['exit_code'] = 65
        with self.assertRaises(ValueError):
            cohort.mutation_row_gate(row, definition, facts)

    def test_phase_order_runtime_receipts_and_boolean_flags_required(self):
        definition, facts, row = self.row()
        row['runs'].reverse()
        with self.assertRaises(ValueError):
            cohort.mutation_row_gate(row, definition, facts)
        for key in ['mutation_killed', 'source_restored', 'runtime_red_confirmed', 'restored_control_passed']:
            definition, facts, row = self.row()
            row[key] = 1
            with self.subTest(field=key), self.assertRaises(ValueError):
                cohort.mutation_row_gate(row, definition, facts)
        definition, facts, row = self.row()
        row['runs'][0]['runtime_result_present'] = False
        with self.assertRaises(ValueError):
            cohort.mutation_row_gate(row, definition, facts)

    def test_mutant_source_selector_and_name_are_exact(self):
        for key in ['case', 'source_path', 'selector']:
            definition, facts, row = self.row()
            row[key] += 'different'
            with self.subTest(field=key), self.assertRaises(ValueError):
                cohort.mutation_row_gate(row, definition, facts)

    def test_tools_app_profile_run_and_private_identity_are_bound(self):
        proof = dict(app_sha='a' * 40, sdk_source='b' * 40, sdk_run_id='123', tools_sha='c' * 40)
        value = dict(app_sha=proof['app_sha'], sdk_sha=proof['sdk_source'], sdk_run_id='123',
                     workflow_tools_sha=proof['tools_sha'], sdk_profile='default', private_flag='0')
        cohort.metadata_identity_gate(value, proof, 'default', 'macos', proof['tools_sha'])
        for key in ['app_sha', 'sdk_sha', 'sdk_run_id', 'workflow_tools_sha', 'sdk_profile', 'private_flag']:
            changed = dict(value, **{key: 'different'})
            with self.subTest(field=key), self.assertRaises(ValueError):
                cohort.metadata_identity_gate(changed, proof, 'default', 'macos', proof['tools_sha'])

    def test_unique_rows_and_exact_expected_mutant_count_required(self):
        definitions = cohort.MUTANTS['ios'][:2]
        rows = [dict(name=name, source=source, selector=selector) for _, name, source, selector in definitions]
        cohort.mutation_rows_gate(dict(mutants=rows, expected_mutants=2), definitions)
        for value in [dict(mutants=[rows[0], rows[0]], expected_mutants=2),
                      dict(mutants=rows, expected_mutants=True),
                      dict(mutants=rows[:1], expected_mutants=1)]:
            with self.assertRaises(ValueError):
                cohort.mutation_rows_gate(value, definitions)

    def test_restored_bytes_file_type_and_modes_must_match_git(self):
        definition, facts, row = self.row()
        for key, replacement in [('git_sha256', None), ('physical_sha256', 'b' * 64),
                                 ('physical_mode', 0o600), ('physical_mode', True),
                                 ('git_mode', '120000'), ('canonical_file', False)]:
            changed = dict(facts, **{key: replacement})
            with self.subTest(field=key), self.assertRaises(ValueError):
                cohort.mutation_row_gate(row, definition, changed)


if __name__ == '__main__':
    unittest.main(verbosity=2)
