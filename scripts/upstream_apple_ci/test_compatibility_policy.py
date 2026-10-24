"""Synthetic fail-closed metadata controls; no app, SDK, Xcode or relay execution."""
import copy
import hashlib
import unittest
from unittest.mock import patch

import compatibility_policy as policy


class CompatibilityPolicyTests(unittest.TestCase):
    def case(self, platform='macos', index=0):
        return policy.cases(platform)['cases'][index]

    def count(self, failed=False):
        return dict(totalTestCount=1, passedTests=int(not failed), failedTests=int(failed), skippedTests=0)

    def failures(self, case, column=True):
        return [dict(file=case['test_source'], line=r['line'], column=r['column'] if column else None,
                     message='Expectation failed: ' + ' '.join(r['message_tokens'])) for r in case['issues']]

    def proof(self, platform='macos', profile='default'):
        app = policy.cases(platform)
        identity = dict(app_sha=app['commit'], platform=platform, profile=profile,
                        sdk_source='a' * 40, sdk_run_id='123', tools_sha='b' * 40)
        value = identity | dict(passed=True, source_restored=True, relay_cleanup_passed=True,
                                platform_cleanup_passed=True,
                                bindings_sha256=policy.sha((policy.HERE / 'compatibility-policy-sources.json').read_bytes()),
                                phases=[])
        for case in app['cases']:
            for name in ('baseline', 'mutant', 'restored'):
                mutant = name == 'mutant'
                row = dict(label=case['id'] + '/' + name, source_sha256=case['mutant_sha256'] if mutant else case['original_sha256'],
                           test_sha256=case['test_source_sha256'], unit_invoked=True, build_exit_code=0,
                           compiler_build_count=0, compiler_body_count=0, unit_exit_code=65 if mutant else 0,
                           counts=self.count(mutant), source_sdk_products_frozen=True, source_closure_exact=True,
                           qualified=True, inventory=dict(status='complete', selected=case['selector'],
                               actual_identifier=case['identifier_aliases'][0]),
                           issue_evidence=policy.runtime(case, self.count(mutant), [], [], self.failures(case) if mutant else [], mutant))
                value['phases'].append(row)
        value['totals'] = policy.totals(value['phases'])
        return value, identity

    def test_all_four_cases_accept_controls_and_unknown_columns(self):
        for platform in ('macos', 'ios'):
            for case in policy.cases(platform)['cases']:
                with self.subTest(case=case['id']):
                    self.assertEqual(policy.runtime(case, self.count(), [], [], [], False), [])
                    self.assertEqual(len(policy.runtime(case, self.count(True), [], [], self.failures(case), True)), len(case['issues']))
                    self.assertTrue(all(r['column'] is None for r in policy.runtime(case, self.count(True), [], [], self.failures(case, False), True)))

    def test_rejects_entire_wrong_failure_multisets(self):
        for platform in ('macos', 'ios'):
            for case in policy.cases(platform)['cases']:
                rows = self.failures(case)
                bad = [[], rows + rows, rows + [dict(rows[0], line=99999)],
                       [dict(rows[0], file='other.swift')] + rows[1:],
                       [dict(rows[0], line=rows[0]['line'] + 1)] + rows[1:],
                       [dict(rows[0], column=rows[0]['column'] + 1)] + rows[1:],
                       [dict(rows[0], message='Unrelated failure')] + rows[1:],
                       [dict(rows[0], message='Expectation failed: unrelated')] + rows[1:],
                       [dict(rows[0], message='Expectation failed: ' + 'x' * 8192)] + rows[1:],
                       [dict(rows[0], unexpected=True)] + rows[1:]]
                for index, failures in enumerate(bad):
                    with self.subTest(case=case['id'], invalid=index), self.assertRaises(ValueError):
                        policy.runtime(case, self.count(True), [], [], failures, True)

    def test_compiler_and_counts_are_not_runtime_kills(self):
        case = self.case()
        for counts in [dict(totalTestCount=0, passedTests=0, failedTests=0, skippedTests=0),
                       dict(totalTestCount=1, passedTests=0, failedTests=0, skippedTests=1),
                       dict(totalTestCount=True, passedTests=0, failedTests=1, skippedTests=0),
                       dict(totalTestCount=1, passedTests=1, failedTests=1, skippedTests=0), self.count()]:
            with self.subTest(counts=counts), self.assertRaises(ValueError):
                policy.runtime(case, counts, [], [], self.failures(case), True)
        for build, body in [([{'warning': True}], []), ([], [{'error': True}])]:
            with self.assertRaises(ValueError):
                policy.runtime(case, self.count(True), build, body, self.failures(case), True)

    def test_exact_transform_and_method_local_sites(self):
        original = b'func product() {\n    true\n}\n'
        mutant = b'func product() {\n    false\n}\n'
        case = dict(original_sha256=policy.sha(original), mutant_sha256=policy.sha(mutant),
                    old='    true', new='    false', owner_start='func product()', owner_end='\n}')
        self.assertEqual(policy.transform(original, case), mutant)
        for key, value in [('owner_start', 'func other()'), ('old', 'absent'), ('mutant_sha256', '0'*64)]:
            with self.subTest(key=key), self.assertRaises(ValueError):
                policy.transform(original, case | {key: value})
        text = b'    func other() {\n        #expect(value)\n    }\n    func chosen() {\n        #expect(value)\n    }\n'
        fixture = dict(method='chosen', test_source_sha256=policy.sha(text), test_source='Tests.swift',
                       issues=[dict(source_expression='#expect(value)', line=5, column=9)])
        self.assertEqual(policy.source_sites(text, fixture), [dict(file='Tests.swift', line=5, column=9)])
        with self.assertRaises(ValueError): policy.source_sites(text, fixture | {'method': 'missing'})

    def test_complete_receipts_both_profiles_and_apps(self):
        for platform in ('macos', 'ios'):
            for profile in ('default', 'experimental'):
                value, identity = self.proof(platform, profile)
                self.assertTrue(policy.receipt(value, identity, platform, profile, identity['tools_sha'])['passed'])

    def test_bad_identity_closure_counts_selector_and_multiset_rejected(self):
        value, identity = self.proof()
        mutations = []
        for key in ('app_sha', 'sdk_source', 'sdk_run_id', 'tools_sha', 'bindings_sha256'):
            changed = copy.deepcopy(value); changed[key] = 'wrong'; mutations.append(changed)
        for key in ('source_restored', 'relay_cleanup_passed', 'platform_cleanup_passed', 'passed'):
            changed = copy.deepcopy(value); changed[key] = False; mutations.append(changed)
        for key in ('source_sdk_products_frozen', 'source_closure_exact', 'qualified'):
            changed = copy.deepcopy(value); changed['phases'][0][key] = False; mutations.append(changed)
        for key in ('source_sha256', 'test_sha256'):
            changed = copy.deepcopy(value); changed['phases'][0][key] = 'wrong'; mutations.append(changed)
        for key in ('selected', 'actual_identifier', 'status'):
            changed = copy.deepcopy(value); changed['phases'][0]['inventory'][key] = 'wrong'; mutations.append(changed)
        changed=copy.deepcopy(value); changed['phases'][1]['issue_evidence'] *= 2; mutations.append(changed)
        changed=copy.deepcopy(value); changed['phases'].reverse(); mutations.append(changed)
        changed=copy.deepcopy(value); changed['phases'][0]['inventory']['extra'] = True; mutations.append(changed)
        changed=copy.deepcopy(value); changed['phases'][1]['issue_evidence'][0]['extra'] = True; mutations.append(changed)
        changed=copy.deepcopy(value); changed['phases'][0]['compiler_build_count'] = True; mutations.append(changed)
        for index, changed in enumerate(mutations):
            with self.subTest(index=index), self.assertRaises(ValueError):
                policy.receipt(changed, identity, 'macos', 'default', identity['tools_sha'])

    def test_interruption_and_bad_identity_preserve_known_counts(self):
        value, _ = self.proof()
        value['app_sha'] = 'wrong'
        self.assertEqual(policy.observed_execution(value)['executed'], 6)
        value['phases'][-1]['counts'] = None
        self.assertEqual(policy.observed_execution(value), dict(known_executed=5, executed=None, unknown_phases=['phase-5']))
        value['phases'][-1]['counts'] = dict(totalTestCount=1, passedTests=2, failedTests=0, skippedTests=0)
        self.assertIsNone(policy.observed_execution(value)['executed'])
        self.assertIsNone(policy.observed_execution(None)['executed'])


if __name__ == '__main__':
    unittest.main()
