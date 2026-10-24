"""Synthetic routing/oracle/restoration controls; never SDK or runtime qualification."""
import copy
import unittest
import ios_vision_runtime as vision


class VisionMetadataTests(unittest.TestCase):
    def observed(self, mutant=False):
        return dict(totalTestCount=1, passedTests=int(not mutant), failedTests=int(mutant), skippedTests=0)

    def test_closed_three_cases_and_immutable_inputs(self):
        config = vision.bindings()
        self.assertEqual(set(config['cases']), {'earliest', 'empty', 'pixel'})
        self.assertEqual(config['app_sha'], 'e236ae8668cea2bd76f1e100609106182cfcc590')
        self.assertEqual(config['sdk_run_id'], '40036892229')
        self.assertFalse(config['qualification_credit'])

    def test_exact_seven_body_schedule_and_mutant_order(self):
        rows = vision.schedule()
        self.assertEqual(len(rows), 7)
        self.assertEqual([r[1] for r in rows[:3]], ['earliest', 'empty', 'pixel'])
        self.assertEqual([r[0] for r in rows if r[2]], ['mutant-earliest', 'mutant-empty'])
        self.assertEqual([r[2] for r in rows], [False, False, False, True, False, True, False])

    def test_actual_counts_survive_bad_identity_and_interruption(self):
        rows = [{'label': 'known-wrong-owner', 'unit_invoked': True, 'counts': self.observed()},
                {'label': 'pending', 'unit_invoked': True, 'counts': None}]
        result = vision.totals(rows)
        self.assertEqual(result['known_executed'], 1)
        self.assertIsNone(result['executed'])
        self.assertEqual(result['unknown_phases'], ['pending'])

    def test_malformed_counts_never_become_known_execution(self):
        for counts in [dict(totalTestCount=True, passedTests=1, failedTests=0, skippedTests=0),
                       dict(totalTestCount=1, passedTests=2, failedTests=0, skippedTests=0)]:
            value = vision.totals([dict(label='bad', unit_invoked=True, counts=counts)])
            self.assertEqual(value['known_executed'], 0)
            self.assertIsNone(value['executed'])

    def test_expected_source_changes_only_owned_digest_not_mode(self):
        original = {'HEAD': 'same', 'index': 'same', 'files': {'owned': ['old', 420], 'other': ['keep', 493]}}
        changed = vision.expected_source(original, 'owned', b'new')
        self.assertEqual(original['files']['owned'], ['old', 420])
        self.assertEqual(changed['files']['owned'], [vision.policy.sha(b'new'), 420])
        self.assertEqual(changed['files']['other'], original['files']['other'])
        with self.assertRaises(ValueError): vision.expected_source(original, 'absent', b'new')

    def test_inverse_owner_cardinality_and_line_preservation(self):
        old = '        guard let revision = supported.first else {\n'
        source = ('    static func earliestSupportedBarcodeRevision(_ supported: IndexSet) throws -> Int {\n'
                  + old + '            throw Failure.empty\n        }\n        return revision\n    }\n'
                  '    static func payloads() {}\n').encode()
        changed = source.replace(b'supported.first', b'supported.last')
        case = dict(original_sha256=vision.policy.sha(source), old=old, new=old.replace('first', 'last'),
                    owner_start='    static func earliestSupportedBarcodeRevision(', owner_end='\n    static func payloads(',
                    mutant_sha256=vision.policy.sha(changed))
        self.assertEqual(vision.policy.transform(source, case), changed)
        for bad in [source.replace(b'earliestSupportedBarcodeRevision', b'decoy'), source + old.encode()]:
            copy_case = case | dict(original_sha256=vision.policy.sha(bad))
            with self.assertRaises(ValueError): vision.policy.transform(bad, copy_case)

    def test_positive_runtime_requires_empty_entire_compiler_and_failures(self):
        case = vision.bindings()['cases']['earliest']
        self.assertEqual(vision.policy.runtime(case, self.observed(), [], [], [], False), [])
        for build, body, failures in [([{}], [], []), ([], [{}], []), ([], [], [{}])]:
            with self.assertRaises(ValueError):
                vision.policy.runtime(case, self.observed(), build, body, failures, False)

    def test_mutant_requires_sole_exact_owned_source_and_fixed_message(self):
        for alias in ('earliest', 'empty'):
            case = vision.bindings()['cases'][alias]
            issue = case['issues'][0]
            row = dict(file=case['test_source'], line=issue['line'], column=issue['column'],
                       message='Expectation failed: ' + ' '.join(issue['message_tokens']))
            self.assertEqual(len(vision.policy.runtime(case, self.observed(True), [], [], [row], True)), 1)
            unknown_column = row | dict(column=None)
            self.assertIsNone(vision.policy.runtime(case, self.observed(True), [], [], [unknown_column], True)[0]['column'])
            for bad in [row | dict(file='other.swift'), row | dict(line=issue['line'] + 1),
                        row | dict(column=issue['column'] + 1), row | dict(message='Caught error: unrelated')]:
                with self.assertRaises(ValueError):
                    vision.policy.runtime(case, self.observed(True), [], [], [bad], True)
            with self.assertRaises(ValueError): vision.policy.runtime(case, self.observed(True), [], [], [row, row], True)
            with self.assertRaises(ValueError): vision.policy.runtime(case, self.observed(True), [{}], [], [row], True)

    def test_warning_blocked_runtime_retains_diagnostic_own_facts(self):
        case = vision.bindings()['cases']['earliest']
        issue = case['issues'][0]
        row = dict(file=case['test_source'], line=issue['line'], column=None,
                   message='Expectation failed: ' + ' '.join(issue['message_tokens']))
        facts = vision.observed_own_failure_facts(case, [row])
        self.assertFalse(facts['qualification_credit'])
        own = facts['failures'][0]
        self.assertTrue(own['exact_bound_own_site'])
        self.assertTrue(own['bounded_expectation_prefix'])
        self.assertTrue(all(own['fixed_expected_token_matches']))
        self.assertEqual(own['message_sha256'], vision.policy.sha(row['message'].encode()))
        self.assertIsNone(own['column'])
        self.assertNotIn('message', own)
        with self.assertRaises(ValueError):
            vision.policy.runtime(case, self.observed(True), [{'actual-warning': True}], [], [row], True)
        for bad in [row | dict(file='other.swift'), row | dict(line=issue['line'] + 1),
                    row | dict(column=issue['column'] + 1)]:
            observed = vision.observed_own_failure_facts(case, [row, bad])
            self.assertEqual(observed['entire_failure_count'], 2)
            self.assertEqual(len(observed['failures']), 2)
            self.assertFalse(observed['failures'][1]['exact_bound_own_site'])
            self.assertIsNone(observed['failures'][1]['fixed_expected_token_matches'])
        bad_message = vision.observed_own_failure_facts(case, [row | dict(message='unrelated')])['failures'][0]
        self.assertFalse(bad_message['bounded_expectation_prefix'])
        self.assertFalse(all(bad_message['fixed_expected_token_matches']))

    def test_final_pass_needs_all_restoration_and_phase_closures(self):
        proof = dict(source_restored=True, sdk_unchanged=True, relay_cleanup_passed=True, tools_unchanged=True,
                     phases=[dict(qualified=True, source_sdk_products_frozen=True,
                                  held_FD_inode_mode_verified=True) for _ in range(7)])
        self.assertTrue(vision.final_pass(proof))
        for field in ('source_restored', 'sdk_unchanged', 'relay_cleanup_passed', 'tools_unchanged'):
            self.assertFalse(vision.final_pass(proof | {field: False}))
        for field in ('qualified', 'source_sdk_products_frozen', 'held_FD_inode_mode_verified'):
            changed = copy.deepcopy(proof); changed['phases'][-1][field] = False
            self.assertFalse(vision.final_pass(changed))
        self.assertFalse(vision.final_pass(proof | dict(failure_category='ValueError')))
        self.assertFalse(vision.final_pass(proof | dict(restoration_error_kind='ValueError')))
        self.assertFalse(vision.final_pass(proof | dict(phases=proof['phases'][:-1])))


if __name__ == '__main__':
    unittest.main()
