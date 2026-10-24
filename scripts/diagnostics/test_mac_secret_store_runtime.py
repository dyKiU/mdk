import unittest
import mac_secret_store_runtime as security


class SecurityRuntimeMetadataTests(unittest.TestCase):
    def counts(self, mutant=False):
        return dict(totalTestCount=1, passedTests=int(not mutant), failedTests=int(mutant), skippedTests=0)

    def failures(self, case):
        return [dict(file=case['test_source'], line=issue['line'], column=issue['column'],
                     message='Expectation failed: ' + ' '.join(issue['message_tokens']))
                for issue in case['issues']]

    def test_closed_schedule_never_selects_protected_body(self):
        config = security.bindings()
        self.assertEqual(config['protected_item_tests_executed'], 0)
        self.assertEqual(set(config['cases']), {'context', 'reopen', 'purge', 'reset'})
        self.assertEqual(security.schedule(), [('positive-reopen', 'reopen', False),
            ('positive-purge', 'purge', False), ('positive-reset', 'reset', False),
            ('baseline-context', 'context', False), ('mutant-context', 'context', True),
            ('restored-context', 'context', False)])
        for case in config['cases'].values():
            self.assertIn('SyncDevelopmentSecretStoreTests/', case['selector'])
            self.assertNotIn('protectedCredential', case['selector'])
        self.assertEqual(config['app_sha'], '5cf8456c969b43912c12a960b3a9cf0b4f8e9185')
        self.assertEqual(config['sdk_run_id'], '40036892229')

    def test_only_actual_context_assignment_is_mutated(self):
        cases = security.bindings()['cases']
        case = cases['context']
        self.assertEqual(case['old'], '        context.interactionNotAllowed = true')
        self.assertEqual(case['new'], '        context.interactionNotAllowed = false')
        self.assertEqual(case['old'].count('\n'), case['new'].count('\n'))
        self.assertEqual(case['owner_start'], '    func accountQuery(')
        self.assertNotEqual(case['original_sha256'], case['mutant_sha256'])
        self.assertEqual([r['line'] for r in case['issues']], [22, 23, 24])
        for name in ('reopen', 'purge', 'reset'):
            self.assertNotIn('old', cases[name])
            self.assertNotIn('new', cases[name])
            self.assertEqual(cases[name]['issues'], [])

    def test_mutant_requires_all_three_exact_original_getter_failures(self):
        case = security.bindings()['cases']['context']
        rows = self.failures(case)
        self.assertEqual(len(security.policy.runtime(case, self.counts(True), [], [], rows, True)), 3)
        for invalid in [rows[:2], rows+rows[:1], rows[:2]+[rows[2] | {'line': 999}],
                        rows[:2]+[rows[2] | {'file': 'other.swift'}],
                        rows[:2]+[rows[2] | {'message': 'unrelated'}]]:
            with self.assertRaises(ValueError):
                security.policy.runtime(case, self.counts(True), [], [], invalid, True)
        for build, body in [([{'warning': True}], []), ([], [{'warning': True}])]:
            with self.assertRaises(ValueError):
                security.policy.runtime(case, self.counts(True), build, body, rows, True)

    def test_every_positive_requires_one_body_no_skips_and_empty_compiler(self):
        for case in security.bindings()['cases'].values():
            self.assertEqual(security.policy.runtime(case, self.counts(), [], [], [], False), [])
            for counts in [self.counts() | {'skippedTests': 1, 'totalTestCount': 2},
                           self.counts() | {'totalTestCount': 0, 'passedTests': 0}]:
                with self.assertRaises(ValueError):
                    security.policy.runtime(case, counts, [], [], [], False)
            with self.assertRaises(ValueError):
                security.policy.runtime(case, self.counts(), [{'warning': True}], [], [], False)

    def test_counts_are_retained_when_identity_or_execution_is_unknown(self):
        value = security.totals([dict(label='observed', unit_invoked=True, counts=self.counts()),
                                 dict(label='interrupted', unit_invoked=True, counts=None)])
        self.assertEqual(value['known_executed'], 1)
        self.assertIsNone(value['executed'])
        self.assertEqual(value['unknown_phases'], ['interrupted'])
        bad = security.totals([dict(label='malformed', unit_invoked=True, counts={'totalTestCount': True})])
        self.assertIsNone(bad['executed'])

    def test_final_gate_requires_all_six_phase_and_global_closures(self):
        row = dict(qualified=True, source_sdk_products_frozen=True, held_FD_inode_mode_verified=True)
        proof = dict(source_restored=True, sdk_unchanged=True, relay_cleanup_passed=True,
                     platform_cleanup_passed=True, tools_unchanged=True, phases=[dict(row, label=label, case=alias, intentional_mutant=mutant)
                             for label, alias, mutant in security.schedule()])
        self.assertTrue(security.final_pass(proof))
        for field in ('source_restored', 'sdk_unchanged', 'relay_cleanup_passed',
                      'platform_cleanup_passed', 'tools_unchanged'):
            self.assertFalse(security.final_pass(proof | {field: False}))
        self.assertFalse(security.final_pass(proof | {'phases': proof['phases'][:5]}))
        broken = [dict(item) for item in proof['phases']]
        broken[-1]['source_sdk_products_frozen'] = False
        self.assertFalse(security.final_pass(proof | {'phases': broken}))
