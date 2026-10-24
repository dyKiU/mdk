"""Synthetic diagnostic metadata only; no app, SDK, Xcode, relay or native execution."""
import copy
import argparse
import json
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import patch

import ios_runtime_diagnostic as diagnostic


class IosRuntimeDiagnosticMetadataTests(unittest.TestCase):
    @staticmethod
    def string(value):
        return {'_type': {'_name': 'String'}, '_value': value}

    def record(self, failures):
        return {'issues': {'_type': {'_name': 'ResultIssueSummaries'},
                'testFailureSummaries': {'_type': {'_name': 'Array'}, '_values': failures}}}

    def fixture(self, app):
        source = app / 'Example.swift'
        source.write_text('#expect(predicate())\n')
        case = {'test_source': 'Example.swift', 'known_assertions': {'1': {
            'category': 'shared-wait-predicate',
            'source_line_sha256': diagnostic.policy.sha(b'#expect(predicate())')}}}
        raw = {'issueType': self.string('Assertion Failure'),
               'message': self.string('Expectation failed: PRIVATE_SENTINEL'),
               'documentLocationInCreatingWorkspace': {'url': self.string(
                   source.as_uri() + '#StartingLineNumber=0')}}
        return case, raw

    def test_closed_case_selection(self):
        self.assertEqual(diagnostic.selected_cases('both'), ['retired-status', 'suspension-storage'])
        for name in ('retired-status', 'suspension-storage'):
            self.assertEqual(diagnostic.selected_cases(name), [name])
        for value in ('', 'all', 'other', None, True, [], {}):
            with self.subTest(value=value), self.assertRaises(ValueError):
                diagnostic.selected_cases(value)

    def test_exact_committed_binding_metadata(self):
        config = diagnostic.bindings()
        self.assertTrue(config['diagnostic_only'])
        self.assertEqual(len(config['cases']), 2)
        self.assertEqual(config['sdk_source'], '6b8d9ea18406a6a0f588de91bece0cf6b29ef129')
        self.assertEqual(config['sdk_run_id'], '40036892229')

    def test_consistent_counts_survive_separate_bad_identity(self):
        counts = dict(totalTestCount=1, passedTests=0, failedTests=1, skippedTests=0)
        self.assertEqual(diagnostic.observed_counts(counts | {'bad_identity': 'wrong'}), counts)
        for value in (None, {}, counts | {'totalTestCount': True}, counts | {'passedTests': 1}):
            self.assertIsNone(diagnostic.observed_counts(value))

    def test_complete_exact_selected_body(self):
        case = {'selector': 'Target/Suite/testOne()', 'identifier_aliases': ['Suite/testOne()']}
        tree = {'testNodes': [{'nodeType': 'Test Case', 'nodeIdentifier': 'Suite/testOne()', 'result': 'Failed'}]}
        counts = dict(totalTestCount=1, passedTests=0, failedTests=1, skippedTests=0)
        self.assertTrue(diagnostic.exact_inventory(tree, counts, case)['complete'])
        for changed in ({'testNodes': []}, {'testNodes': tree['testNodes'] * 2},
                        {'testNodes': [dict(tree['testNodes'][0], nodeIdentifier='Other/testOne()')]},
                        {'testNodes': [dict(tree['testNodes'][0], nodeType='Test Case Run')]}):
            with self.subTest(tree=changed), self.assertRaises(ValueError):
                diagnostic.exact_inventory(changed, counts, case)

    def test_actual_line_unknown_column_fixed_expression_without_private_text(self):
        with TemporaryDirectory() as folder:
            app = Path(folder).resolve()
            case, raw = self.fixture(app)
            value = diagnostic.failure_inventory(self.record([raw]), app, {'Example.swift': []}, case)
            row = value['failures'][0]
            self.assertEqual((row['file'], row['line'], row['column']), ('Example.swift', 1, None))
            self.assertEqual(row['fixed_source_category'], 'shared-wait-predicate')
            self.assertEqual(row['message_category'], 'swift-expectation-failed')
            self.assertNotIn('PRIVATE_SENTINEL', str(value))

    def test_extra_duplicate_failures_and_actual_provided_columns_are_retained(self):
        with TemporaryDirectory() as folder:
            app = Path(folder).resolve()
            case, raw = self.fixture(app)
            raw['documentLocationInCreatingWorkspace']['url'] = self.string(
                (app / 'Example.swift').as_uri() + '#StartingLineNumber=0&StartingColumnNumber=7')
            value = diagnostic.failure_inventory(self.record([raw, copy.deepcopy(raw)]), app, {'Example.swift': []}, case)
            self.assertEqual(value['failure_count'], 2)
            self.assertEqual([r['column'] for r in value['failures']], [8, 8])

    def test_unknown_message_or_source_location_cannot_be_fabricated(self):
        with TemporaryDirectory() as folder:
            app = Path(folder).resolve()
            case, raw = self.fixture(app)
            raw['message'] = self.string('PRIVATE_UNCLASSIFIED')
            del raw['documentLocationInCreatingWorkspace']
            value = diagnostic.failure_inventory(self.record([raw]), app, {'Example.swift': []}, case)
            row = value['failures'][0]
            self.assertIsNone(row['message_category'])
            self.assertIsNone(row['file'])
            self.assertIsNone(row['fixed_source_category'])
            self.assertNotIn('PRIVATE_UNCLASSIFIED', str(value))

    def test_missing_or_extra_action_inventory_cannot_be_complete(self):
        with TemporaryDirectory() as folder:
            app = Path(folder).resolve()
            case, raw = self.fixture(app)
            value = self.record([])
            value['action'] = self.record([raw])['issues']
            for bad in ({}, value):
                with self.subTest(record=bad), self.assertRaises(ValueError):
                    diagnostic.failure_inventory(bad, app, {'Example.swift': []}, case)

    def test_second_case_runs_after_first_failure_and_unknown_counts_stay_unknown(self):
        for unknown in (False, True):
            with self.subTest(unknown=unknown), TemporaryDirectory() as folder:
                root = Path(folder).resolve()
                invoked = []
                def fake_run(args):
                    invoked.append(args.case)
                    failed = args.case == 'retired-status'
                    counts = dict(totalTestCount=1, passedTests=int(not failed), failedTests=int(failed), skippedTests=0)
                    if unknown and not failed: counts = None
                    args.output.write_text(json.dumps({'case': args.case, 'counts': counts,
                        'diagnostic_only': True, 'qualification_credit': False}))
                    return 65 if failed else 0
                args = argparse.Namespace(selection='both', cohort_evidence=root / 'prepare.json',
                                          output=root / 'diagnostic.json')
                with patch.object(diagnostic, 'run', side_effect=fake_run), patch.dict(
                        diagnostic.os.environ, {'RUNNER_TEMP': str(root), 'GITHUB_SHA': 'b' * 40}):
                    self.assertEqual(diagnostic.run_selected(args), 1)
                self.assertEqual(invoked, ['retired-status', 'suspension-storage'])
                value = json.loads(args.output.read_text())
                self.assertFalse(value['qualification_credit'])
                self.assertEqual(value['known_executed'], 1 if unknown else 2)
                self.assertEqual(value['executed'], None if unknown else 2)
        with TemporaryDirectory() as folder:
            root = Path(folder).resolve()
            invoked = []
            def interrupted(args):
                invoked.append(args.case)
                raise KeyboardInterrupt()
            args = argparse.Namespace(selection='both', cohort_evidence=root / 'prepare.json',
                                      output=root / 'diagnostic.json')
            with patch.object(diagnostic, 'run', side_effect=interrupted), patch.dict(
                    diagnostic.os.environ, {'RUNNER_TEMP': str(root), 'GITHUB_SHA': 'b' * 40}):
                self.assertEqual(diagnostic.run_selected(args), 1)
            self.assertEqual(invoked, ['retired-status'])
            self.assertTrue(json.loads(args.output.read_text())['interrupted'])


if __name__ == '__main__':
    unittest.main()
