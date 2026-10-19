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
    def test_finite_predecessor_insertion_is_the_only_runtime_omission(self):
        from upstream_publication_mutation_anchors import (
            SECONDARY_PREFIX_INSERT, SECONDARY_PREFIX_OMISSION, secondary_prefix_omission,
        )
        source = Path('crates/marmot-app/src/runtime/account_worker.rs').read_text()
        self.assertEqual(source.count(SECONDARY_PREFIX_INSERT), 1)
        changed = secondary_prefix_omission(source)
        self.assertEqual(changed.replace(SECONDARY_PREFIX_OMISSION, SECONDARY_PREFIX_INSERT), source)
        self.assertEqual(changed.count(SECONDARY_PREFIX_OMISSION), 1)
        for bad in (source.replace(SECONDARY_PREFIX_INSERT, ''), source + '\n' + SECONDARY_PREFIX_INSERT,
                    changed, source + '\n' + SECONDARY_PREFIX_OMISSION):
            with self.assertRaises(ValueError):
                secondary_prefix_omission(bad)

    def test_actual_timeout_case_and_closed_metadata_oracles(self):
        from upstream_publication_mutation_anchors import (
            SECONDARY_CASES, SECONDARY_FIXTURE, SECONDARY_ASSERTION,
            SECONDARY_MARKER, secondary_scheduler_oracle,
        )
        fixture = Path(SECONDARY_FIXTURE).read_text()
        line = fixture[:fixture.index(SECONDARY_ASSERTION)].count('\n') + 1
        for case, name in SECONDARY_CASES.items():
            facts = {'deferred_count': 2 if case == 'secondary-deferred' else 0,
                     'drain_count': 1, 'pass_count': 3, 'turn_count': 12, 'predecessor_command_count': 4,
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

class CancelMaintenanceGreenOracle(unittest.TestCase):
    def test_exact_green_marker_and_named_pass(self):
        from upstream_publication_mutation_anchors import (CANCEL_MAINTENANCE_FIXTURE, CANCEL_MAINTENANCE_NAME, CANCEL_MAINTENANCE_MARKER, CANCEL_MAINTENANCE_FIELDS, cancel_maintenance_oracle)
        fixture = Path(CANCEL_MAINTENANCE_FIXTURE).read_text()
        marker = CANCEL_MAINTENANCE_MARKER + json.dumps({key: True for key in CANCEL_MAINTENANCE_FIELDS}) + '\n'
        raw = f'test {CANCEL_MAINTENANCE_NAME} ... ok\n' + marker + 'test result: ok. 1 passed; 0 failed; 0 ignored; 999 filtered out\n'
        self.assertTrue(cancel_maintenance_oracle(raw, fixture, False)['evidence_passed'])
        for bad in [raw + raw, raw.replace(marker, ''), raw.replace('... ok', '... FAILED'), raw.replace('1 passed; 0 failed', '0 passed; 0 failed'), raw + 'error[E0308]: PRIVATE\n', raw + "thread 'PRIVATE' panicked at PRIVATE:1:1:\n", raw.replace('true', 'false'), raw.replace('true', '1'), raw.replace(CANCEL_MAINTENANCE_MARKER, 'PRIVATE ' + CANCEL_MAINTENANCE_MARKER)]:
            row = cancel_maintenance_oracle(bad, fixture, False)
            self.assertFalse(row['evidence_passed'])
            self.assertNotIn('PRIVATE', json.dumps(row))

    def test_cancellation_mutation_parent_replacement_is_rejected(self):
        import tempfile
        from upstream_publication_mutation_anchors import ExactCancellationMutation
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            parent = root / 'owned'
            outside = root / 'outside'
            parent.mkdir(); outside.mkdir()
            target = parent / 'source.rs'; target.write_bytes(b'ORIGINAL')
            foreign = outside / 'source.rs'; foreign.write_bytes(b'OUTSIDE')
            leaf = ExactCancellationMutation(target)
            leaf.write(b'MUTANT')
            parent.rename(root / 'moved')
            parent.symlink_to(outside, target_is_directory=True)
            try:
                with self.assertRaises(ValueError): leaf.write(b'ORIGINAL')
                self.assertEqual(foreign.read_bytes(), b'OUTSIDE')
            finally:
                leaf.close()

    def test_cancellation_mutation_exact_inode_and_mode_restored(self):
        import tempfile
        from upstream_publication_mutation_anchors import ExactCancellationMutation
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory).resolve() / 'source.rs'
            target.write_bytes(b'ORIGINAL'); target.chmod(0o600)
            inode = target.stat().st_ino
            leaf = ExactCancellationMutation(target)
            try:
                leaf.write(b'MUTANT'); leaf.write(b'ORIGINAL')
                self.assertEqual(target.read_bytes(), b'ORIGINAL')
                self.assertEqual(target.stat().st_ino, inode)
                self.assertEqual(target.stat().st_mode & 0o777, 0o600)
            finally:
                leaf.close()

class RealGuardPointerOracle(unittest.TestCase):
    def test_real_guard_green_and_exact_pointer_omission(self):
        from upstream_publication_mutation_anchors import REAL_GUARD_NAME, REAL_GUARD_EXPECT, REAL_GUARD_FIELDS, real_guard_oracle, CANCEL_MAINTENANCE_FIXTURE
        fixture = Path(CANCEL_MAINTENANCE_FIXTURE).read_text()
        literal = fixture.index('"' + REAL_GUARD_EXPECT + '"')
        line = fixture[:fixture.rfind('.expect', 0, literal)].count('\n') + 1
        marker = 'cancel-real-guard-control ' + json.dumps({key: True for key in REAL_GUARD_FIELDS}) + '\n'
        result = 'cancel-real-guard-result {"foreign_cancel_returned_ok":true}\n'
        failure = (f'test {REAL_GUARD_NAME} ... FAILED\n' + marker + result
                   + f"thread '{REAL_GUARD_NAME}' (123) panicked at {CANCEL_MAINTENANCE_FIXTURE}:{line}:26:\n"
                   + REAL_GUARD_EXPECT + ': Gate(NoLiveVerifier)\n'
                   + 'test result: FAILED. 0 passed; 1 failed; 0 ignored; 999 filtered out\n')
        green = f'test {REAL_GUARD_NAME} ... ok\n' + marker + result.replace('true','false') + 'test result: ok. 1 passed; 0 failed; 0 ignored; 999 filtered out\n'
        self.assertTrue(real_guard_oracle(failure, fixture, True)['evidence_passed'])
        self.assertTrue(real_guard_oracle(green, fixture, False)['evidence_passed'])
        negatives = [failure + failure, failure.replace(marker, ''), failure.replace(result, ''), failure.replace(result, result.replace('true','false')),
                     failure.replace(marker, marker.replace('true','false')), failure.replace(marker, marker.replace('true','1')),
                     failure.replace(marker, marker.replace('}', ',"PRIVATE":true}')), failure.replace(marker, marker.replace('{', '{"selected_original":true,')),
                     failure.replace(result, '{PRIVATE}'), failure.replace(marker, '') + marker, failure.replace('1 failed','0 failed'),
                     failure.replace(': Gate(NoLiveVerifier)', ': PRIVATE'), failure.replace(f':{line}:26:',f':{line+1}:26:'),
                     failure.replace(REAL_GUARD_NAME,'PRIVATE'), failure + 'error[E0308]: PRIVATE\n',
                     failure.replace('cancel-real-guard-control ', 'PRIVATE cancel-real-guard-control '), failure.replace(marker,marker+marker)]
        for raw in negatives:
            row = real_guard_oracle(raw, fixture, True)
            self.assertFalse(row['evidence_passed'])
            self.assertNotIn('PRIVATE',json.dumps(row))
        self.assertFalse(real_guard_oracle(green + green, fixture, False)['evidence_passed'])
        self.assertFalse(real_guard_oracle(green.replace('false','true'), fixture, False)['evidence_passed'])
        with self.assertRaises(ValueError): real_guard_oracle(failure, fixture, 'mutant')

class LateFirstRevokeOracle(unittest.TestCase):
    def test_actual_late_first_ack_requires_real_prerequisites_and_own_assertion(self):
        from upstream_publication_mutation_anchors import LATE_FIRST_NAME, LATE_FIRST_ASSERT, LATE_FIRST_PREREQS, late_first_revoke_oracle, CANCEL_MAINTENANCE_FIXTURE
        fixture = Path(CANCEL_MAINTENANCE_FIXTURE).read_text()
        literal = fixture.index('"' + LATE_FIRST_ASSERT + '"')
        line = fixture[:fixture.rfind('assert!(', 0, literal)].count('\n') + 1
        first = 'cancel-late-first-prerequisites ' + json.dumps({name: True for name in LATE_FIRST_PREREQS}) + '\n'
        second = 'cancel-late-first-result ' + json.dumps({'old_acknowledged':True,'old_stale_rejected':False,'current_revision_unchanged':False,'owned_runtimes_closed':True}) + '\n'
        raw = (f'test {LATE_FIRST_NAME} ... FAILED\n' + first + second
               + f"thread '{LATE_FIRST_NAME}' (123) panicked at {CANCEL_MAINTENANCE_FIXTURE}:{line}:26:\n"
               + LATE_FIRST_ASSERT + '\n' + 'test result: FAILED. 0 passed; 1 failed; 0 ignored; 999 filtered out\n')
        self.assertTrue(late_first_revoke_oracle(raw, fixture)['evidence_passed'])
        bad = [raw + raw, raw.replace(first,''), raw.replace(second,''), raw.replace(first,first.replace('true','false')),
               raw.replace(first,first.replace('true','1')), raw.replace(second,second.replace('true','false')),
               raw.replace(second,second.replace('false','true')), raw.replace(first,first.replace('}', ',"PRIVATE":true}')),
               raw.replace(first,first.replace('{', '{"old_slot_unrevoked":true,')), raw.replace(first,'')+first,
               raw.replace('0 passed; 1 failed','0 passed; 0 failed'), raw + 'error[E0308]: PRIVATE\n',
               raw.replace(LATE_FIRST_NAME,'PRIVATE'), raw.replace(LATE_FIRST_ASSERT,'PRIVATE'),
               raw.replace(f':{line}:26:',f':{line+1}:26:'), raw.replace('cancel-late-first-result ','PRIVATE cancel-late-first-result ')]
        for output in bad:
            row = late_first_revoke_oracle(output, fixture)
            self.assertFalse(row['evidence_passed'])
            self.assertNotIn('PRIVATE',json.dumps(row))


    def test_fixed_late_first_counter_inverse_requires_rejection_and_exact_unchanged_revision(self):
        from upstream_publication_mutation_anchors import LATE_FIRST_NAME, LATE_FIRST_ASSERT, LATE_FIRST_PREREQS, late_first_fixed_oracle, late_first_counter_inverse, CANCEL_MAINTENANCE_FIXTURE
        fixture = Path(CANCEL_MAINTENANCE_FIXTURE).read_text()
        literal = fixture.index('"' + LATE_FIRST_ASSERT + '"')
        line = fixture[:fixture.rfind('assert!(', 0, literal)].count('\n') + 1
        first = 'cancel-late-first-prerequisites ' + json.dumps({name: True for name in LATE_FIRST_PREREQS}) + '\n'
        def sample(mutant):
            second = 'cancel-late-first-result ' + json.dumps({'old_acknowledged':False,'old_stale_rejected':True,'current_revision_unchanged':not mutant,'owned_runtimes_closed':True}) + '\n'
            return (f'test {LATE_FIRST_NAME} ... ' + ('FAILED' if mutant else 'ok') + '\n' + first + second
                    + (f"thread '{LATE_FIRST_NAME}' (123) panicked at {CANCEL_MAINTENANCE_FIXTURE}:{line}:26:\n" + LATE_FIRST_ASSERT + '\n' if mutant else '')
                    + ('test result: FAILED. 0 passed; 1 failed; 0 ignored; 999 filtered out\n' if mutant else 'test result: ok. 1 passed; 0 failed; 0 ignored; 999 filtered out\n'))
        green, mutant = sample(False), sample(True)
        self.assertTrue(late_first_fixed_oracle(green, fixture, False)['evidence_passed'])
        self.assertTrue(late_first_fixed_oracle(mutant, fixture, True)['evidence_passed'])
        for output, phase in [(green,True),(mutant,False),(mutant+mutant,True),(mutant.replace(first,''),True),
                              (mutant.replace('"old_acknowledged": false','"old_acknowledged": true'),True),
                              (mutant.replace('"old_stale_rejected": true','"old_stale_rejected": false'),True),
                              (mutant.replace('"owned_runtimes_closed": true','"owned_runtimes_closed": false'),True),
                              (mutant.replace(first,first.replace('true','1')),True),
                              (mutant.replace(first,first.replace('}', ',"PRIVATE":true}')),True),
                              (mutant.replace(first,first.replace('{','{"old_slot_unrevoked":true,')),True),
                              (mutant.replace(first,'')+first,True),(mutant+'error[E0308]: PRIVATE\n',True),
                              (mutant.replace(LATE_FIRST_NAME,'PRIVATE'),True),(mutant.replace(LATE_FIRST_ASSERT,'PRIVATE'),True),
                              (mutant.replace(f':{line}:26:',f':{line+1}:26:'),True),
                              (mutant.replace('0 passed; 1 failed','0 passed; 0 failed'),True)]:
            row = late_first_fixed_oracle(output, fixture, phase)
            self.assertFalse(row['evidence_passed'])
            self.assertNotIn('PRIVATE',json.dumps(row))
        with self.assertRaises(ValueError): late_first_fixed_oracle(mutant, fixture, 'mutant')
        # Exercise the actual pure transform on the admitted product source, not a toy anchor.
        source = Path('crates/marmot-app/src/runtime/private_commit.rs').read_text()
        old, new = late_first_counter_inverse(source)
        self.assertEqual(new, old[:len(old)-len(old.lstrip(' '))] + 'gate.cancel();\n' + old)
        self.assertEqual(source.replace(old,new,1).replace(new,old,1),source)
        wrapped = old.replace('active.original_invite_revision', 'active\n' + ' ' * 20 + '.original_invite_revision')
        wrapped_old, wrapped_new = late_first_counter_inverse(wrapped)
        self.assertEqual(wrapped_new, wrapped_old[:len(wrapped_old)-len(wrapped_old.lstrip(' '))] + 'gate.cancel();\n' + wrapped_old)
        with self.assertRaises(ValueError): late_first_counter_inverse(source + '\n' + old)



class CanonicalLeafCleanup(unittest.TestCase):
    def fixture(self):
        from upstream_publication_mutation_anchors import CANONICAL_FIXTURE
        return Path(CANONICAL_FIXTURE).read_text()

    def shape(self, phase):
        from upstream_publication_mutation_anchors import CANONICAL_NAMES, CANONICAL_SIBLINGS, CANONICAL_FIXTURE, CANONICAL_LABEL, canonical_leaf_assertion_line
        failed = phase == 'mutant'
        names = CANONICAL_SIBLINGS if failed else CANONICAL_NAMES
        site = canonical_leaf_assertion_line(self.fixture())
        text = f'running {len(names)} tests\n' + ''.join(f'test {name} ... {"FAILED" if failed else "ok"}\n' for name in names)
        if failed:
            text += ''.join(f"thread '{name}' (3) panicked at {CANONICAL_FIXTURE}:{site}:5:\nassertion `left == right` failed: {CANONICAL_LABEL}\n  left: 2\n right: 1\n" for name in names)
        return text + f'test result: {"FAILED" if failed else "ok"}. {0 if failed else 3} passed; {2 if failed else 0} failed; 0 ignored; 0 measured; 10 filtered out; finished in 0.1s\n'

    def test_source_exact_one_empty_leaf_slice_inverse(self):
        from upstream_publication_mutation_anchors import CANONICAL_CLEANUP, CANONICAL_EMPTY
        source = Path('crates/marmot-app/src/client/sync.rs').read_text()
        self.assertEqual(source.count(CANONICAL_CLEANUP), 1)
        mutant = source.replace(CANONICAL_CLEANUP, CANONICAL_EMPTY, 1)
        self.assertEqual(mutant.replace(CANONICAL_EMPTY, CANONICAL_CLEANUP, 1), source)
        self.assertEqual(CANONICAL_CLEANUP.replace('                    leaves,', '                    &leaves[..0],'), CANONICAL_EMPTY)

    def test_three_positive_controls_and_two_owned_failures(self):
        from upstream_publication_mutation_anchors import canonical_leaf_oracle
        for phase in ['baseline', 'mutant', 'restored-control']:
            self.assertTrue(canonical_leaf_oracle(self.shape(phase), self.fixture(), phase)['evidence_passed'])
        for gap in ['\n', '\n\n', '\n\n\n']:
            raw = self.shape('mutant').replace(':5:\nassertion', ':5:' + gap + 'assertion')
            self.assertTrue(canonical_leaf_oracle(raw, self.fixture(), 'mutant')['evidence_passed'])

    def test_unknown_compile_duplicate_and_wrong_assertion_fail_closed(self):
        from upstream_publication_mutation_anchors import canonical_leaf_oracle, CANONICAL_FIXTURE, CANONICAL_SIBLINGS, CANONICAL_LABEL
        good = self.shape('mutant')
        for bad in [good + good, good.replace('2 failed;', '1 failed;'), good.replace('0 ignored;', '1 ignored;'),
                    good.replace(CANONICAL_SIBLINGS[0], 'private::unreviewed'), good.replace(CANONICAL_FIXTURE, 'private.rs'),
                    good.replace(CANONICAL_LABEL, 'PRIVATE_VALUE'), good.replace('left: 2', 'left: 3'),
                    good.replace('right: 1', 'right: 2'), good.replace('running 2 tests', 'running 0 tests'),
                    good + 'error[E0308]: PRIVATE_VALUE\n', good.replace('panicked at ', 'panic at ', 1),
                    good.replace(':5:\nassertion', ':5:\n\n\n\nassertion')]:
            row = canonical_leaf_oracle(bad, self.fixture(), 'mutant')
            self.assertFalse(row['evidence_passed'])
            self.assertNotIn('PRIVATE_VALUE', json.dumps(row))

    def test_terminal_libtest_wrapper_does_not_hide_real_compile_errors(self):
        from upstream_publication_mutation_anchors import canonical_leaf_oracle
        raw = self.shape('mutant')
        for suffix in ['error: test failed, to rerun pass `--lib`\n', 'error: test failed, to rerun pass `-p marmot-app --lib`\n']:
            self.assertTrue(canonical_leaf_oracle(raw + suffix, self.fixture(), 'mutant')['evidence_passed'])
        self.assertFalse(canonical_leaf_oracle(raw + 'error: unknown compilation failure\n', self.fixture(), 'mutant')['evidence_passed'])


if __name__ == '__main__':
    unittest.main()
