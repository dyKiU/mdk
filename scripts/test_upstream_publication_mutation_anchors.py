"""Run remotely: source fixtures only, zero Rust compilation/runtime bodies."""
from pathlib import Path
import json
import unittest

from upstream_publication_mutation_anchors import (
    publication_mutant, publication_mutation_anchor,
    publication_runtime_oracle, FIXTURE,
)

CASES = {
    'automatic-publication': 'crates/marmot-app/src/client/account_chat_sharing/automatic.rs',
    'sibling-publication': 'crates/marmot-app/src/client/device_linking/sibling_sharing.rs',
}


class PublicationAnchors(unittest.TestCase):
    def test_actual_owned_source_has_one_exact_insertion_and_restores(self):
        for case, path in CASES.items():
            with self.subTest(case=case):
                source = Path(path).read_text()
                old, new = publication_mutation_anchor(case)
                self.assertEqual(source.count(old), 1)
                mutant = publication_mutant(source, case)
                offset = source.index(old) + len(old)
                addition = new[len(old):]
                self.assertEqual(mutant, source[:offset] + addition + source[offset:])
                self.assertEqual(mutant.replace(new, old, 1), source)
                self.assertEqual(mutant.count(addition), 1)
                self.assertIn('.publication.as_ref().expect(', addition)
                self.assertIn('.task.is_finished()', addition)
                self.assertIn('tokio::task::yield_now().await;', addition)
                # Every original byte remains in its original order; no future,
                # semaphore, retry, deadline, ACK or guard expression is removed.

    def test_automatic_wait_covers_the_generic_transport_hold(self):
        old, new = publication_mutation_anchor('automatic-publication')
        addition = new[len(old):]
        self.assertNotIn('if ', addition)
        self.assertNotIn('AccountSharingControl::', addition)
        self.assertIn('.task.is_finished()', addition)

    def test_bounded_runtime_envelope_preserves_exact_assertion_binding(self):
        fixture = Path(FIXTURE).read_text()
        case = 'sibling-publication'
        test = 'native_device_linking::automatic_pairing_acceptance::blocked_sibling_consent_does_not_starve_another_approved_peer'
        line = publication_runtime_oracle('', case, test, fixture)['expected_panic_line']
        marker = 'automatic-enrollment-control stage=sibling-consent-held-before-peer-progress'
        message = 'one blocked consent publication must not starve another approved sibling'
        for indent in ['', '  ', '        ', '\t']:
            for newline in ['\n', '\r\n']:
                raw = (marker + newline + indent + f"thread '{test}' (17) panicked at {FIXTURE}:{line}:9:" + newline
                       + indent + message + newline)
                row = publication_runtime_oracle(raw, case, test, fixture)
                self.assertTrue(row['intended_runtime_assertion'])
                self.assertEqual(row['actual_panic_facts'][0]['message_kind'], 'held_fairness')
        self.assertEqual(row['parsed_panic_header_count'], 1)
        self.assertFalse(row['unsupported_panic_format'])
        plain = marker + '\n' + f"thread '{test}' (17) panicked at {FIXTURE}:{line}:9:\n" + message + '\n'
        for bad in [plain.replace('thread ', '         thread '),
                    plain.replace('\n' + message, '\n         ' + message),
                    plain.replace('thread ', 'untrusted-prefix thread '),
                    plain.replace(test, 'unrelated_test'),
                    plain.replace(FIXTURE, 'crates/unrelated.rs'),
                    plain.replace(f':{line}:9:', f':{line + 1}:9:'),
                    plain.replace(message, message + ' PRIVATE-PAYLOAD'),
                    plain + plain,
                    plain + 'error[E0308]: mismatched types\n']:
            self.assertFalse(publication_runtime_oracle(bad, case, test, fixture)['intended_runtime_assertion'])

    def test_absent_duplicate_format_drift_and_already_mutated_refused(self):
        for case in CASES:
            old, new = publication_mutation_anchor(case)
            for bad in ['', old + '\n' + old, old.replace('outcome: None', 'outcome: Some(())'), new]:
                with self.subTest(case=case, invalid=bad[:30]):
                    with self.assertRaises(ValueError):
                        publication_mutant(bad, case)

    def test_unsupported_case_refused(self):
        with self.assertRaises(ValueError):
            publication_mutation_anchor('worker-spawn-stack')

    def test_named_runtime_assertions_and_unrelated_failure_refusal(self):
        fixture = Path(FIXTURE).read_text()
        for case in CASES:
            test = 'native_device_linking::automatic_pairing_acceptance::' + (
                'automatic_sync_does_not_block_foreground_enrollment_completion'
                if case == 'automatic-publication' else
                'blocked_sibling_consent_does_not_starve_another_approved_peer')
            meta = publication_runtime_oracle('', case, test, fixture)
            line = meta['expected_panic_line']
            marker = 'automatic-enrollment-control stage=' + (
                'automatic-publication-held-before-completion' if case == 'automatic-publication'
                else 'sibling-consent-held-before-peer-progress')
            message = ('automatic pairing did not reach required phase: expected=EnrollmentComplete observed=SharingPending'
                       if case == 'automatic-publication' else
                       'one blocked consent publication must not starve another approved sibling')
            panic = f"thread '{test}' (17) panicked at {FIXTURE}:{line}:9:\n{message}\n"
            raw = marker + '\n' + panic
            self.assertTrue(publication_runtime_oracle(raw, case, test, fixture)['intended_runtime_assertion'])
            negatives = [
                panic, panic + marker, raw + panic, raw + marker,
                raw.replace(test, 'unrelated_test'),
                raw.replace(FIXTURE, 'crates/unrelated.rs'),
                raw.replace(f':{line}:9:', f':{line + 1}:9:'),
                raw.replace(message, 'unrelated runtime assertion'),
                raw + 'error[E0308]: mismatched types\n',
                raw + 'error: could not compile\n',
            ]
            if case == 'automatic-publication':
                negatives.append(raw.replace('expected=EnrollmentComplete', 'expected=Comparison'))
            for bad in negatives:
                with self.subTest(case=case, invalid=bad[:30]):
                    self.assertFalse(publication_runtime_oracle(bad, case, test, fixture)['intended_runtime_assertion'])
            with self.assertRaises(ValueError):
                publication_runtime_oracle(raw, case, test, fixture + '\n' + fixture)

    def test_nextest_terminal_wrapper_is_not_a_rust_compiler_error(self):
        fixture = Path(FIXTURE).read_text()
        case = 'sibling-publication'
        test = 'native_device_linking::automatic_pairing_acceptance::blocked_sibling_consent_does_not_starve_another_approved_peer'
        line = publication_runtime_oracle('', case, test, fixture)['expected_panic_line']
        raw = ('automatic-enrollment-control stage=sibling-consent-held-before-peer-progress\n'
               f"thread '{test}' panicked at {FIXTURE}:{line}:9:\n"
               'one blocked consent publication must not starve another approved sibling\n')
        for terminal in ['error: test run failed\n', 'error: test run failed\r\n']:
            row = publication_runtime_oracle(raw + terminal, case, test, fixture)
            self.assertEqual(row['compiler_error_count'], 0)
            self.assertTrue(row['intended_runtime_assertion'])
        for compiler in ['error[E0308]: mismatched types\n', 'error: could not compile\n',
                         'error: test run failed: this is not the terminal wrapper\n']:
            row = publication_runtime_oracle(raw + compiler, case, test, fixture)
            self.assertEqual(row['compiler_error_count'], 1)
            self.assertFalse(row['intended_runtime_assertion'])

    def test_closed_actual_panic_facts_never_export_private_raw_values(self):
        fixture = Path(FIXTURE).read_text()
        case = 'automatic-publication'
        test = 'native_device_linking::automatic_pairing_acceptance::automatic_sync_does_not_block_foreground_enrollment_completion'
        raw = ("thread 'PRIVATE-THREAD-SECRET' panicked at /PRIVATE/PATH/SECRET.rs:99887766:9:\n"
               'PRIVATE-PAYLOAD-SECRET account=PRIVATE-ACCOUNT-SECRET\n')
        row = publication_runtime_oracle(raw, case, test, fixture)
        self.assertEqual(row['actual_panic_facts'], [{
            'expected_fixture_file': False, 'expected_test_thread': False,
            'line': None, 'message_kind': 'other',
        }])
        exported = json.dumps(row)
        for secret in ['PRIVATE-THREAD-SECRET', '/PRIVATE/PATH/SECRET.rs',
                       'PRIVATE-PAYLOAD-SECRET', 'PRIVATE-ACCOUNT-SECRET', '99887766']:
            self.assertNotIn(secret, exported)
        self.assertFalse(row['intended_runtime_assertion'])
        self.assertEqual(row['panic_header_count'], 1)

    def test_actual_known_failures_are_closed_classifications_not_kills(self):
        fixture = Path(FIXTURE).read_text()
        test = 'native_device_linking::automatic_pairing_acceptance::automatic_sync_does_not_block_foreground_enrollment_completion'
        hold = 'the actual automatic publication must be held before completion'
        self.assertEqual(fixture.count('"' + hold + '"'), 1)
        line = fixture[:fixture.index('"' + hold + '"')].count('\n') + 1
        messages = [
            (hold + ': Elapsed(())', 'hold_precondition'),
            ('genuine sibling consent publication did not reach its hold', 'hold_precondition'),
            ('one blocked consent publication must not starve another approved sibling', 'held_fairness'),
            ('automatic pairing did not reach required phase: expected=EnrollmentComplete observed=PRIVATE-OBSERVED-STATE', 'enrollment_complete_timeout'),
            ('automatic pairing did not reach required phase: expected=Comparison observed=PRIVATE-OBSERVED-STATE', 'other'),
        ]
        for message, kind in messages:
            raw = f"thread '{test}' (17) panicked at {FIXTURE}:{line}:9:\n{message}\n"
            row = publication_runtime_oracle(raw, 'automatic-publication', test, fixture)
            self.assertEqual(row['actual_panic_facts'], [{
                'expected_fixture_file': True, 'expected_test_thread': True,
                'line': line, 'message_kind': kind,
            }])
            self.assertNotIn('PRIVATE-OBSERVED-STATE', json.dumps(row))
            self.assertFalse(row['intended_runtime_assertion'])
        unknown_line = f"thread '{test}' panicked at {FIXTURE}:9999999:9:\nprivate\n"
        row = publication_runtime_oracle(unknown_line * 5, 'automatic-publication', test, fixture)
        self.assertEqual(len(row['actual_panic_facts']), 4)
        self.assertTrue(row['actual_panic_facts_truncated'])
        self.assertTrue(all(fact['line'] is None for fact in row['actual_panic_facts']))


    def priority_output(self, phase, indent='', newline='\n'):
        # New fixture-specific evidence only; historical reporter methods above
        # remain independently runnable against their actual old helper modules.
        from upstream_publication_mutation_anchors import (
            retry_priority_oracle, PRIORITY_FIXTURE, PRIORITY_NAME,
            PRIORITY_MESSAGE, PRIORITY_FACT_NAMES,
        )
        fixture = Path(PRIORITY_FIXTURE).read_text()
        line = retry_priority_oracle('', phase, fixture)['expected_line']
        marker = 'recipient-retry-priority ' + ' '.join(name + '=true' for name in PRIORITY_FACT_NAMES)
        selected = 'false' if phase == 'mutant' else 'true'
        marker += ' selected_proof=' + selected + ' runtime_closes=3 storage_closes=3 planes_shutdown=3 relay_closed=true attempt_completed=true'
        status, summary = ('FAIL', '0 passed, 1 failed') if phase == 'mutant' else ('PASS', '1 passed')
        output = indent + marker + newline
        if phase == 'mutant':
            output += indent + f"thread '{PRIORITY_NAME}' (17) panicked at {PRIORITY_FIXTURE}:{line}:5:" + newline
            output += indent + PRIORITY_MESSAGE + newline
        output += indent + status + ' [1.0s] (1/1) marmot-app ' + PRIORITY_NAME + newline
        output += 'Summary [1.0s] 1 test run: ' + summary + ', 103 skipped' + newline
        return fixture, output

    def test_recipient_priority_pinned_nextest_library_binary_id(self):
        from upstream_publication_mutation_anchors import retry_priority_oracle, PRIORITY_NAME
        # nextest 0.9.132 metadata TestBinaryId::from_parts uses the package
        # name for a library target; Rust's underscore crate name is not its id.
        for phase in ('baseline', 'mutant', 'restored-control'):
            fixture, output = self.priority_output(phase)
            rendered = output.replace('marmot-app::marmot_app ', 'marmot-app ')
            self.assertTrue(retry_priority_oracle(
                rendered, phase, fixture, capture_complete=True)['evidence_passed'])
            for other in ('marmot_app', 'marmot-app::marmot_app', 'wrong-package'):
                wrong = rendered.replace('marmot-app ' + PRIORITY_NAME, other + ' ' + PRIORITY_NAME)
                self.assertFalse(retry_priority_oracle(
                    wrong, phase, fixture, capture_complete=True)['evidence_passed'])

    def test_recipient_priority_actual_source_route_and_exact_omission(self):
        from upstream_publication_mutation_anchors import PRIORITY_NAME
        runner = Path('scripts/verify_upstream_boundary_mutations.py').read_text()
        branch = runner.split("elif args.case == 'sibling-retry-priority':", 1)[1].split('    else:', 1)[0]
        self.assertIn('test = PRIORITY_NAME', branch)
        self.assertIn("--final-status-level', 'none'", runner)
        self.assertIn('retry_priority_oracle(output, phase, Path(PRIORITY_FIXTURE).read_text(), capture_complete=True)', runner)
        self.assertIn("mutant['exit_code'] == 100 and mutant['evidence_passed']", runner)
        self.assertIn("proof['restored_control_passed'] &= control['evidence_passed']", runner)
        source = Path('crates/marmot-app/src/client/device_linking/sibling_sharing.rs').read_text()
        old = ('                && (!entry.ready\n'
               '                    || (entry.proof_published\n'
               '                        && entry.handshake_retry_at <= entry.proof_retry_at)))')
        self.assertEqual(source.count(old), 1)
        new = '                )'
        offset = source.index(old)
        mutant = source[:offset] + new + source[offset + len(old):]
        self.assertEqual(mutant[:offset] + old + mutant[offset + len(new):], source)
        self.assertNotIn('third_and_later_device_enrollment_need_no_extra_qr_or_manual_artifacts', branch)
        self.assertEqual(PRIORITY_NAME.rsplit('::', 1)[-1], 'older_recipient_proof_retry_precedes_later_consent_retry')

    def test_recipient_priority_controls_accept_real_source_shaped_envelopes(self):
        from upstream_publication_mutation_anchors import retry_priority_oracle
        for phase in ['baseline', 'restored-control']:
            for indent in ['', '  ', '\t', '        ']:
                for newline in ['\n', '\r\n']:
                    fixture, output = self.priority_output(phase, indent, newline)
                    for counter in ['(1/1)', '( 1/1)', '(        1/1)', '(\t1/1)']:
                        decorated = output.replace('(1/1)', counter)
                        row = retry_priority_oracle(decorated, phase, fixture, capture_complete=True)
                        self.assertTrue(row['evidence_passed'])
                    self.assertTrue(row['named_case_observed'])
                    self.assertEqual(row['summary_counts'], [1, 1, 0])
                    self.assertFalse(row['product_qualification'])

    def test_recipient_priority_intended_mutant_requires_actual_final_assertion(self):
        from upstream_publication_mutation_anchors import retry_priority_oracle
        fixture, output = self.priority_output('mutant', '  ', '\r\n')
        row = retry_priority_oracle(output, 'mutant', fixture, capture_complete=True)
        self.assertTrue(row['evidence_passed'])
        self.assertTrue(row['exact_intended_panic'])
        self.assertEqual(row['summary_counts'], [1, 0, 1])
        self.assertTrue(row['prerequisites_and_closure_known'])

    def test_recipient_priority_every_prerequisite_and_closure_is_required(self):
        from upstream_publication_mutation_anchors import retry_priority_oracle, PRIORITY_FACT_NAMES
        fixture, output = self.priority_output('mutant')
        bad = [output.replace(name + '=true', name + '=false') for name in PRIORITY_FACT_NAMES]
        bad += [output.replace(name + '=3', name + '=' + value) for name in
                ['runtime_closes', 'storage_closes', 'planes_shutdown'] for value in ['0', '2', '4', '03']]
        bad += [output.replace(name + '=true', name + '=false') for name in ['relay_closed', 'attempt_completed']]
        bad += [output.replace(' real_frontier=true', ''),
                output.replace('real_frontier=true', 'real_frontier=PRIVATE'),
                output.replace(' selected_proof=false', ' selected_proof=true'),
                output.replace(' attempt_completed=true', ' attempt_completed=true private=PRIVATE'),
                output + output.splitlines()[0] + '\n',
                output.replace('recipient-retry-priority ', '         recipient-retry-priority ')]
        for value in bad:
            row = retry_priority_oracle(value, 'mutant', fixture, capture_complete=True)
            self.assertFalse(row['evidence_passed'])
            self.assertNotIn('PRIVATE', json.dumps(row))
        self.assertFalse(retry_priority_oracle(output, 'mutant', fixture)['evidence_passed'])

    def test_recipient_priority_wrong_named_body_panic_and_compiler_are_not_kills(self):
        from upstream_publication_mutation_anchors import (
            retry_priority_oracle, PRIORITY_NAME, PRIORITY_FIXTURE, PRIORITY_MESSAGE,
        )
        fixture, output = self.priority_output('mutant')
        line = retry_priority_oracle(output, 'mutant', fixture)['expected_line']
        bad = [output.replace(PRIORITY_NAME, 'wrong_test'),
               output.replace(PRIORITY_FIXTURE, 'private/path.rs'),
               output.replace(f':{line}:5:', f':{line+1}:5:'),
               output.replace(PRIORITY_MESSAGE, 'real recipient retry prerequisites and cleanup must complete'),
               output.replace(PRIORITY_MESSAGE, PRIORITY_MESSAGE + ' PRIVATE'),
               output.replace("thread '", "         thread '"),
               output.replace('1 test run:', '0 tests run:'),
               output.replace('1 test run:', '2 tests run:'),
               output.replace('0 passed, 1 failed', '0 passed, 1 failed, 1 failed'),
               output.replace('FAIL [1.0s]', 'PASS [1.0s]'),
               output.replace('(1/1)', '(2/2)'),
               output.replace('(1/1)', '(2/1)'),
               output.replace('(1/1)', '(1/2)'),
               output.replace('(1/1)', '(         1/1)'),
               output + 'error[E0308]: PRIVATE\n',
               output + output[output.index("thread '"):output.index('FAIL [')]]
        for value in bad:
            row = retry_priority_oracle(value, 'mutant', fixture, capture_complete=True)
            self.assertFalse(row['evidence_passed'])
            self.assertNotIn('PRIVATE', json.dumps(row))
        for terminal in ['error: test run failed\n', 'error: test failed, to rerun pass `--lib`\n']:
            self.assertTrue(retry_priority_oracle(output + terminal, 'mutant', fixture, capture_complete=True)['evidence_passed'])
        with self.assertRaises(ValueError):
            retry_priority_oracle(output, 'mutant', fixture + '\n' + fixture, capture_complete=True)


class SecondarySchedulerOracles(unittest.TestCase):
    def test_actual_timeout_case_and_closed_metadata_oracles(self):
        from upstream_publication_mutation_anchors import (
            SECONDARY_CASES, SECONDARY_FIXTURE, SECONDARY_ASSERTION,
            SECONDARY_MARKER, secondary_scheduler_oracle,
        )
        fixture = Path(SECONDARY_FIXTURE).read_text()
        line = fixture[:fixture.index(SECONDARY_ASSERTION)].count('\n') + 1
        for case, name in SECONDARY_CASES.items():
            facts = {'deferred_count': 2 if case == 'secondary-deferred' else 0,
                     'drain_count': 1, 'pass_count': 3, 'turn_count': 12,
                     'last_turn': {'pending': 0, 'buffered': 0, 'yielded': False,
                                   'due': True, 'owed': False, 'retry_ready': True}}
            marker = SECONDARY_MARKER + json.dumps(facts) + '\n'
            raw = (f'test {name} ... FAILED\n' + marker + f"thread '{name}' (123) panicked at "
                   f'{SECONDARY_FIXTURE}:{line}:6:\n'
                   'the held admission gate makes the durable drain retry: Elapsed(())\n'
                   'test result: FAILED. 0 passed; 1 failed; 0 ignored; 999 filtered out\n')
            self.assertTrue(secondary_scheduler_oracle(raw, case, fixture, True)['evidence_passed'])
            self.assertEqual(secondary_scheduler_oracle(raw, case, fixture, True)['timeout_observation'], facts)
            passing = f'test {name} ... ok\ntest result: ok. 1 passed; 0 failed; 0 ignored; 999 filtered out\n'
            self.assertTrue(secondary_scheduler_oracle(passing, case, fixture, False)['evidence_passed'])
            bad = [raw.replace(name, 'PRIVATE'), raw.replace(f':{line}:6:', f':{line+1}:6:'),
                   raw.replace('the held admission gate makes the durable drain retry', 'PRIVATE'),
                   raw.replace(SECONDARY_MARKER, 'PRIVATE '), raw + raw,
                   raw.replace(marker, '') + marker,
                   raw.replace('0 passed; 1 failed', '0 passed; 0 failed'),
                   raw + 'error[E0308]: PRIVATE\n',
                   raw.replace(json.dumps(facts), json.dumps(dict(facts, private='PRIVATE'))),
                   raw.replace(json.dumps(facts), json.dumps(dict(facts, drain_count=True))),
                   raw.replace(json.dumps(facts), json.dumps(dict(facts, deferred_count=1))),
                   raw.replace(json.dumps(facts), json.dumps(dict(facts, last_turn=None))),
                   raw.replace(json.dumps(facts), json.dumps(dict(facts, last_turn=dict(facts['last_turn'], private='PRIVATE')))),
                   raw.replace(json.dumps(facts), json.dumps(dict(facts, last_turn=dict(facts['last_turn'], owed=1)))),
                   raw.replace(json.dumps(facts), json.dumps(dict(facts, last_turn=dict(facts['last_turn'], pending=True)))),
                   raw.replace(SECONDARY_MARKER, 'PRIVATE ' + SECONDARY_MARKER)]
            for output in bad:
                result = secondary_scheduler_oracle(output, case, fixture, True)
                self.assertFalse(result['evidence_passed'])
                self.assertNotIn('PRIVATE', json.dumps(result))


class CancelMaintenanceOracles(unittest.TestCase):
    def test_real_scope_retirement_requires_own_cancel_failure(self):
        from upstream_publication_mutation_anchors import (
            CANCEL_MAINTENANCE_FIXTURE, CANCEL_MAINTENANCE_NAME,
            CANCEL_MAINTENANCE_MARKER, CANCEL_MAINTENANCE_CHAIN,
            CANCEL_MAINTENANCE_FIELDS, CANCEL_MAINTENANCE_MESSAGE,
            cancel_maintenance_oracle,
        )
        fixture = Path(CANCEL_MAINTENANCE_FIXTURE).read_text()
        start = fixture.index(CANCEL_MAINTENANCE_MARKER)
        position = fixture.index(CANCEL_MAINTENANCE_CHAIN, start)
        line = fixture[:position + CANCEL_MAINTENANCE_CHAIN.index('.unwrap();')].count('\n') + 1
        facts = {key: True for key in CANCEL_MAINTENANCE_FIELDS}
        marker = CANCEL_MAINTENANCE_MARKER + json.dumps(facts) + '\n'
        raw = (f'test {CANCEL_MAINTENANCE_NAME} ... FAILED\n' + marker
               + f"thread '{CANCEL_MAINTENANCE_NAME}' (123) panicked at {CANCEL_MAINTENANCE_FIXTURE}:{line}:26:\n"
               + CANCEL_MAINTENANCE_MESSAGE + '\n'
               + 'test result: FAILED. 0 passed; 1 failed; 0 ignored; 999 filtered out\n')
        self.assertTrue(cancel_maintenance_oracle(raw, fixture)['evidence_passed'])
        negatives = [raw.replace(CANCEL_MAINTENANCE_NAME, 'PRIVATE'),
                     raw.replace(f':{line}:26:', f':{line+1}:26:'),
                     raw.replace(CANCEL_MAINTENANCE_MESSAGE, 'PRIVATE'),
                     raw.replace(marker, ''), raw + raw,
                     raw.replace(marker, '') + marker,
                     raw.replace('0 passed; 1 failed', '0 passed; 0 failed'),
                     raw.replace('0 passed; 1 failed', '1 passed; 0 failed'),
                     raw + 'error[E0308]: PRIVATE\n',
                     raw.replace(json.dumps(facts), json.dumps(dict(facts, private='PRIVATE'))),
                     raw.replace(json.dumps(facts), json.dumps(dict(facts, wrapped_owned=False))),
                     raw.replace(json.dumps(facts), json.dumps(dict(facts, same_retired_owned=1))),
                     raw.replace(CANCEL_MAINTENANCE_MARKER, 'PRIVATE ' + CANCEL_MAINTENANCE_MARKER)]
        for output in negatives:
            result = cancel_maintenance_oracle(output, fixture)
            self.assertFalse(result['evidence_passed'])
            self.assertNotIn('PRIVATE', json.dumps(result))
        with self.assertRaises(ValueError):
            cancel_maintenance_oracle(raw, fixture.replace(CANCEL_MAINTENANCE_CHAIN, 'PRIVATE'))

if __name__ == '__main__':
    unittest.main()
