#!/usr/bin/env python3
"""Exercise real foreign-future and cleanup-isolation failures, restoring exact sources."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
from upstream_avatar_ready_turn_chain import compiler_diagnostics
from upstream_secondary_cutoff import runtime_panic_coordinates
from upstream_publication_mutation_anchors import PEER_TIMER_CASES, PEER_TIMER_NAMES, peer_leave_timer_control_oracle, CANONICAL_CASES, CANONICAL_FIXTURE, CANONICAL_NAMES, CANONICAL_SIBLINGS, CANONICAL_CLEANUP, CANONICAL_EMPTY, canonical_leaf_oracle, publication_mutation_anchor, publication_mutant, publication_runtime_oracle, FIXTURE, retry_priority_oracle, PRIORITY_FIXTURE, PRIORITY_NAME, SECONDARY_CASES, SECONDARY_FIXTURE, secondary_scheduler_oracle, CANCEL_MAINTENANCE_FIXTURE, CANCEL_MAINTENANCE_NAME, cancel_maintenance_oracle, ExactCancellationMutation, SECONDARY_PREFIX_INSERT, SECONDARY_PREFIX_OMISSION, secondary_prefix_omission, REAL_GUARD_NAME, REAL_GUARD_CHECK, REAL_GUARD_OMISSION, real_guard_oracle, LATE_FIRST_NAME, late_first_revoke_oracle, late_first_fixed_oracle, late_first_counter_inverse

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('--case', choices=['peer-leave-timer-default', 'peer-leave-timer-experimental', 'canonical-leaf-cleanup-default', 'canonical-leaf-cleanup-experimental', 'departure', 'worker-reap', 'relay-acquisition', 'upload-fixture', 'migration-default', 'migration-experimental', 'worker-spawn-stack', 'worker-stack-regression', 'automatic-publication', 'sibling-publication', 'sibling-retry-priority', 'outbound-mailbox-kind', 'secondary-deferred', 'secondary-buffered', 'cancel-maintenance-red', 'cancel-maintenance-pfp', 'cancel-maintenance-newer-owner', 'cancel-maintenance-slot-controls', 'cancel-maintenance-guard-control', 'cancel-maintenance-real-guard-pfp', 'cancel-late-first-red', 'cancel-late-first-pfp', 'cancel-late-first-slot-controls', 'cancel-invite-cas-controls', 'cancel-invite-cleanup-control'], required=True)
parser.add_argument('--output', type=Path, required=True)
parser.add_argument('--cohort-baseline', default=os.environ.get('UPSTREAM_EXTRACTION_COHORT_BASELINE'), help='Exact separately reviewed extraction merge; historical results are not reused')
parser.add_argument('--secondary-stage', choices=['red', 'green'], default='red')
args = parser.parse_args()
cohort = None
if args.cohort_baseline:
    from upstream_extraction_cohort import frozen_inputs, reviewed_cohort
    cohort = reviewed_cohort(args.cohort_baseline)
    frozen = frozen_inputs()
publication_cases = {'automatic-publication', 'sibling-publication', 'sibling-retry-priority'}
nextest_cases = publication_cases | {'worker-spawn-stack', 'worker-stack-regression'}
held_marker = None
failure_marker = None
cancellation_pfp_cases = {'cancel-maintenance-pfp', 'cancel-maintenance-real-guard-pfp', 'cancel-late-first-pfp'}
cancellation_cases = cancellation_pfp_cases | {'cancel-maintenance-newer-owner', 'cancel-maintenance-slot-controls', 'cancel-maintenance-guard-control', 'cancel-late-first-slot-controls', 'cancel-invite-cas-controls', 'cancel-invite-cleanup-control'}
if args.case in CANONICAL_CASES:
    if not cohort or os.environ.get('GITHUB_EVENT_NAME') != 'workflow_dispatch' or os.environ.get('RUST_MIN_STACK') != '4194304':
        raise ValueError('Canonical cleanup requires explicit reviewed manual source and original stack')
    source = Path('crates/marmot-app/src/client/sync.rs')
    old, new = CANONICAL_CLEANUP, CANONICAL_EMPTY
    expected = 3
    test = None
    features = 'marmot-app/test-policy-overrides,cgka-engine/test-policy-overrides,cgka-engine/test-crash-hooks'
    if args.case == 'canonical-leaf-cleanup-experimental': features += ',marmot-app/experimental-device-sync'
    command = ['cargo', 'test', '--locked', '-p', 'marmot-app', '--lib', '--features', features, '--', '--exact', '--test-threads=1', '--show-output']
elif args.case in PEER_TIMER_CASES:
    if not cohort or os.environ.get('GITHUB_EVENT_NAME') != 'workflow_dispatch' or os.environ.get('RUST_MIN_STACK') != '4194304':
        raise ValueError('Peer leave timer controls require exact reviewed manual source and original stack')
    source = Path('crates/marmot-app/src/tests.rs')
    old = 'async fn due_peer_leave_does_not_shorten_a_collecting_convergence_pass() {'
    new = old  # Positive controls exit before any mutation write.
    test = None
    expected = 2
    features = 'marmot-app/test-policy-overrides,cgka-engine/test-policy-overrides,cgka-engine/test-crash-hooks'
    if args.case == 'peer-leave-timer-experimental': features += ',marmot-app/experimental-device-sync'
    command = ['cargo', 'test', '--locked', '-p', 'marmot-app', '--lib', '--features', features,
               '--', '--exact', '--test-threads=1', '--show-output', *PEER_TIMER_NAMES]
elif args.case in cancellation_cases:
    if not cohort or os.environ.get('RUST_MIN_STACK') != '4194304':
        raise ValueError('Cancellation controls require exact reviewed source and original stack')
    source = Path('crates/marmot-app/src/runtime/account_worker.rs')
    old = 'super::private_commit::cancel_scope(client, &scope, publication_control)'
    new = 'client.cancel_device_linking_scope(&scope)'
    test = CANCEL_MAINTENANCE_NAME
    expected = 1
    package = 'marmot-app'
    if args.case == 'cancel-late-first-pfp':
        source = Path('crates/marmot-app/src/runtime/private_commit.rs')
        old, new = late_first_counter_inverse(source.read_text())
        test = LATE_FIRST_NAME
    elif args.case == 'cancel-late-first-slot-controls':
        test = 'runtime::private_commit::late_revoke_tests::'
    elif args.case == 'cancel-invite-cas-controls':
        test = 'device_linking::settlement::negative_revision_tests::'
        expected = 2
    elif args.case == 'cancel-invite-cleanup-control':
        test = 'device_linking::invite_gate::tests::old_revision_cleanup_cannot_clear_a_fresh_real_sdk_arm'
    elif args.case == 'cancel-maintenance-real-guard-pfp':
        source = Path('crates/cgka-engine/src/private_roster_settlement.rs')
        old, new = REAL_GUARD_CHECK, REAL_GUARD_OMISSION
        test = REAL_GUARD_NAME
    elif args.case == 'cancel-maintenance-newer-owner':
        test = 'runtime::device_linking::tests::device_linking_retired_cancel_cannot_ack_after_a_newer_terminal_reservation'
    elif args.case == 'cancel-maintenance-slot-controls':
        test = 'runtime::private_commit::negative_cancel_tests::'
        expected = 4
    elif args.case == 'cancel-maintenance-guard-control':
        package = 'cgka-engine'
        test = 'private_roster_settlement::tests::foreign_negative_guard_cannot_cancel_real_same_group_admission'
    features = ('experimental-device-sync,test-policy-overrides,test-crash-hooks' if package == 'cgka-engine' else
                'marmot-app/otlp-export,marmot-app/product-analytics-export,marmot-app/test-policy-overrides,marmot-app/experimental-device-sync,cgka-engine/test-policy-overrides,cgka-engine/test-crash-hooks')
    command = ['cargo', 'test', '--locked', '-p', package, '--lib', '--features', features,
               test, '--', '--test-threads=1', '--show-output']
    if args.case not in {'cancel-maintenance-slot-controls', 'cancel-late-first-slot-controls', 'cancel-invite-cas-controls'}: command.append('--exact')
elif args.case == 'cancel-late-first-red':
    if not cohort or os.environ.get('RUST_MIN_STACK') != '4194304':
        raise ValueError('Late first cancellation requires reviewed source and original stack')
    source = Path(CANCEL_MAINTENANCE_FIXTURE)
    old = 'async fn device_linking_first_old_cancel_after_newer_terminal_does_not_touch_current_gate() {'
    new = old  # Regression-first only; no install-revision fix or product mutation.
    test = LATE_FIRST_NAME
    command = ['cargo', 'test', '--locked', '-p', 'marmot-app', '--lib', '--features',
               'marmot-app/otlp-export,marmot-app/product-analytics-export,marmot-app/test-policy-overrides,marmot-app/experimental-device-sync,cgka-engine/test-policy-overrides,cgka-engine/test-crash-hooks',
               test, '--', '--exact', '--test-threads=1', '--show-output']
    expected = 1
elif args.case == 'cancel-maintenance-red':
    if not cohort or os.environ.get('RUST_MIN_STACK') != '4194304':
        raise ValueError('Cancellation race requires reviewed source and original 4 MiB stack')
    source = Path(CANCEL_MAINTENANCE_FIXTURE)
    old = 'async fn device_linking_original_sdk_cancel_after_real_maintenance_retires_owned_invite() {'
    new = old  # RED collection exits before the mutation stage; no product witness is added.
    test = CANCEL_MAINTENANCE_NAME
    command = ['cargo', 'test', '--locked', '-p', 'marmot-app', '--lib', '--features',
               'marmot-app/otlp-export,marmot-app/product-analytics-export,marmot-app/test-policy-overrides,marmot-app/experimental-device-sync,cgka-engine/test-policy-overrides,cgka-engine/test-crash-hooks',
               test, '--', '--exact', '--test-threads=1']
    expected = 1
elif args.case in SECONDARY_CASES:
    if not cohort or os.environ.get('RUST_MIN_STACK') != '4194304':
        raise ValueError('Secondary scheduling requires reviewed source and original 4 MiB stack')
    source = Path('crates/marmot-app/src/runtime/account_worker.rs')
    old = ('if yield_observation.peek().is_some() {'
           if args.secondary_stage == 'red' else SECONDARY_PREFIX_INSERT)
    new = SECONDARY_PREFIX_OMISSION
    test = SECONDARY_CASES[args.case]
    command = ['cargo', 'test', '--locked', '-p', 'marmot-app', '--lib', '--features',
               'marmot-app/otlp-export,marmot-app/product-analytics-export,marmot-app/test-policy-overrides,marmot-app/experimental-device-sync,cgka-engine/test-policy-overrides,cgka-engine/test-crash-hooks',
               test, '--', '--exact', '--test-threads=1']
    expected = 1
elif args.case == 'departure':
    source = Path('crates/marmot-uniffi/src/commands/account_chat_departure.rs')
    old, new = '#[marmot_uniffi_macros::on_tokio_runtime]\n#[uniffi::export]', '#[uniffi::export]'
    command = ['cargo', 'test', '--locked', '-p', 'marmot-uniffi', '--lib', '--features',
               'experimental-device-sync', 'commands::account_chat_departure::tests::',
               '--', '--test-threads=1']
    expected = 2
elif args.case == 'worker-reap':
    source = Path('crates/marmot-app/src/runtime/mod.rs')
    old, new = 'let completed = handle.is_finished();', 'let completed = true;'
    command = ['cargo', 'test', '--locked', '-p', 'marmot-app', '--lib', '--features',
               'cgka-engine/test-policy-overrides,cgka-engine/test-crash-hooks',
               'runtime::tests::stuck_worker_reap_does_not_block_a_healthy_account',
               '--', '--exact', '--test-threads=1']
    expected = 1
elif args.case == 'relay-acquisition':
    source = Path('crates/transport-nostr/src/tests.rs' if cohort else 'crates/marmot-app/src/relay_plane/tests.rs')
    old, new = 'let subscription = issued_subscription;', 'let subscription = legacy_subscription.clone();'
    command = ['cargo', 'test', '--locked', '-p', 'transport-nostr' if cohort else 'marmot-app', '--lib', '--features',
               'experimental-device-sync',
               ('tests::' if cohort else 'relay_plane::tests::') + 'enrollment_acquisition_delayed_notification_worker_preserves_clock_and_fifo_eose',
               '--', '--exact', '--test-threads=1']
    expected = 1

elif args.case == 'outbound-mailbox-kind':
    if not cohort:
        raise ValueError('Generic extracted mailbox requires an explicit reviewed cohort')
    source = Path('crates/transport-nostr/src/pairing.rs')
    old = 'if event.kind != self.event_kind || event.content.len() > 32768 || event.verify().is_err() {'
    new = 'if event.content.len() > 32768 || event.verify().is_err() {'
    test = 'pairing::tests::generic_mailbox_refuses_a_different_kind_and_an_expired_original'
    command = ['cargo', 'test', '--locked', '-p', 'transport-nostr', '--lib', '--features',
               'experimental-device-sync', test, '--', '--exact', '--test-threads=1']
    expected = 1
elif args.case == 'upload-fixture':
    source = Path('crates/marmot-app/src/client/upload_cleanup_tests.rs')
    old = ("            let mut first_byte = [0u8; 1];\n"
           "            if socket.peek(&mut first_byte).await.unwrap() == 0 {\n"
           "                continue;\n"
           "            }\n")
    new = ''
    command = ['env', '-u', 'RUST_MIN_STACK', 'cargo', 'test', '--locked',
               '-p', 'marmot-app', '--lib',
               'client::upload_cleanup_tests::outgoing_publication_ignores_empty_tcp_probes_and_rejects_truncation',
               '--', '--exact', '--test-threads=1']
    expected = 1
elif args.case in {'worker-spawn-stack', 'worker-stack-regression'}:
    if os.environ.get('RUST_MIN_STACK') != '4194304':
        raise ValueError('The original 4 MiB stack budget is required')
    source = Path('crates/marmot-app/src/runtime/account_worker.rs')
    old = 'tokio::spawn(Box::pin(run_app_runtime_account_worker(\n        runtime,\n        command_tx,\n        commands,\n        ready,\n        startup_progress,\n        shutdown,\n    )))'
    new = old.replace('tokio::spawn(Box::pin(', 'tokio::spawn(')[:-1]
    if args.case == 'worker-stack-regression':
        # The old outer-box inverse survived baseline/inverse/restored controls.
        # Preserve the real 4 MiB regression on the upstream spawn implementation;
        # this control makes no runtime mutation or inner-box necessity claim.
        old = new
    test = ('native_device_linking::tests::automatic_forwarding_non_admin_acceptance::'
            'automatic_nonadmin_leave_withdraws_mirrors_without_turning_local_hide_into_departure')
    command = ['cargo', 'nextest', 'run', '--locked', '-p', 'marmot-app', '--lib', '--features',
               'marmot-app/otlp-export,marmot-app/product-analytics-export,marmot-app/test-policy-overrides,marmot-app/experimental-device-sync,cgka-engine/test-policy-overrides,cgka-engine/test-crash-hooks',
               '--profile', 'm5-bounded', '--retries', '0', '--test-threads', '1', '--no-fail-fast',
               '--success-output', 'immediate', '-E', 'package(marmot-app) & test(=' + test + ')']
    expected = 1
elif args.case in publication_cases:
    if os.environ.get('RUST_MIN_STACK') != '4194304':
        raise ValueError('The original 4 MiB stack budget is required')
    prefix = 'native_device_linking::automatic_pairing_acceptance::'
    if args.case == 'automatic-publication':
        source = Path('crates/marmot-app/src/client/account_chat_sharing/automatic.rs')
        # The former optional-slot inverse is obsolete: both Body and handshake
        # sends now use bounded owned tasks. Keep the actual task and capacity.
        old, new = publication_mutation_anchor(args.case)
        test = prefix + 'automatic_sync_does_not_block_foreground_enrollment_completion'
        held_marker = 'automatic-enrollment-control stage=automatic-publication-held-before-completion'
        failure_marker = 'automatic pairing did not reach required phase: expected=EnrollmentComplete'
    elif args.case == 'sibling-retry-priority':
        source = Path('crates/marmot-app/src/client/device_linking/sibling_sharing.rs')
        old = ('                && (!entry.ready\n'
               '                    || (entry.proof_published\n'
               '                        && entry.handshake_retry_at <= entry.proof_retry_at)))')
        # Remove only the new ordering guard; preserve the original due timer.
        new = '                )'
        test = PRIORITY_NAME
        held_marker = 'recipient-retry-priority '
        failure_marker = 'older real recipient proof retry must precede a later Consent retry'
    else:
        source = Path('crates/marmot-app/src/client/device_linking/sibling_sharing.rs')
        old, new = publication_mutation_anchor(args.case)
        test = prefix + 'blocked_sibling_consent_does_not_starve_another_approved_peer'
        held_marker = 'automatic-enrollment-control stage=sibling-consent-held-before-peer-progress'
        failure_marker = 'one blocked consent publication must not starve another approved sibling'
    command = ['cargo', 'nextest', 'run', '--locked', '-p', 'marmot-app', '--lib', '--features',
               'marmot-app/otlp-export,marmot-app/product-analytics-export,marmot-app/test-policy-overrides,marmot-app/experimental-device-sync,cgka-engine/test-policy-overrides,cgka-engine/test-crash-hooks',
               '--profile', 'm5-bounded', '--retries', '0', '--test-threads', '1', '--no-fail-fast',
               '--success-output', 'immediate', '-E',
               'package(marmot-app) & binary(=marmot_app) & test(=' + test + ')']
    if args.case == 'sibling-retry-priority':
        command.extend(['--status-level', 'pass', '--final-status-level', 'none'])
    expected = 1
else:
    source = Path('crates/storage-sqlite/src/private_migration_ledger.rs')
    old = ('        applied += 1;\n    }\n'
           '    install_activation_triggers(&tx, schemas.last().unwrap())?;')
    new = old.replace('applied += 1;', 'applied += 0;')
    command = ['env', '-u', 'RUST_MIN_STACK', 'cargo', 'test', '--locked',
               '-p', 'storage-sqlite', '--lib']
    if args.case == 'migration-experimental':
        command.extend(['--features', 'experimental-device-sync'])
    command.extend([('base::' if cohort else '') + 'migrations::migration_0108_account_attachment_history::tests::populated_v106_upgrade_preserves_group_pages_and_installs_global_mutation_fences',
                    '--', '--exact', '--test-threads=1'])
    expected = 1

original = source.read_bytes()
text = original.decode()
if text.count(old) != 1:
    raise ValueError('Mutation anchor must match exactly once')
if args.case in SECONDARY_CASES and args.secondary_stage == 'green':
    secondary_prefix_omission(text)
if args.case in {'automatic-publication', 'sibling-publication'}:
    # Validate the complete pure transform before any baseline compile/run.
    publication_mutant(text, args.case)
mailbox_assertion_line = None
if args.case == 'outbound-mailbox-kind':
    assertion = '        assert_eq!(\n            mailbox.publish(&other_kind).await,\n            Err(PairingRelayError::Invalid)\n        );'
    if text.count(assertion) != 1:
        raise ValueError('Exact generic mailbox own assertion must remain unchanged')
    mailbox_assertion_line = text[:text.index(assertion)].count('\n') + 1
cancellation_leaf = ExactCancellationMutation(source) if args.case in cancellation_pfp_cases | CANONICAL_CASES else None
cancellation_head = subprocess.check_output(['git', 'rev-parse', 'HEAD'], text=True).strip() if args.case in cancellation_cases | CANONICAL_CASES | PEER_TIMER_CASES else None
cancellation_index = hashlib.sha256(subprocess.check_output(['git', 'ls-files', '--stage', '-z'])).hexdigest() if args.case in cancellation_cases | CANONICAL_CASES | PEER_TIMER_CASES else None
args.output.mkdir(parents=True, exist_ok=False)
proof = {'source_commit': subprocess.check_output(['git', 'rev-parse', 'HEAD'], text=True).strip(),
         'case': args.case, 'source_path': str(source),
         'original_sha256': hashlib.sha256(original).hexdigest(), 'command': command, 'runs': [],
         'completed': False, 'runtime_mutation_qualification': False}
if cohort:
    proof['reviewed_extraction_cohort'] = cohort


def save():
    (args.output / 'report.json').write_text(json.dumps(proof, indent=2) + '\n')


def execute(phase):
    if cohort:
        expected_inputs = dict(frozen)
        if phase == 'mutant':
            expected_inputs[str(source)] = dict(frozen[str(source)], sha256=hashlib.sha256(text.replace(old, new).encode()).hexdigest())
        if frozen_inputs() != expected_inputs:
            raise ValueError('Unexpected tracked source, mode or configuration drift before runtime phase')
    path = args.output / (phase + '.log')
    with path.open('x') as log:
        phase_command = command + (CANONICAL_SIBLINGS if phase == 'mutant' else CANONICAL_NAMES) if args.case in CANONICAL_CASES else command
        result = subprocess.run(phase_command, stdout=log, stderr=subprocess.STDOUT, timeout=1800)
    output = re.sub(r'\x1b\[[0-9;]*m', '', path.read_text())
    counts = re.findall(r'test result: (ok|FAILED)\. (\d+) passed; (\d+) failed; (\d+) ignored', output)
    runtime_signal = False
    if args.case in nextest_cases:
        summaries = re.findall(r'Summary\s+\[[^\]]*\]\s+(\d+)(?:/\d+)?\s+tests? run:\s*([^\n]*)', output)
        counts = []
        if len(summaries) == 1 and summaries[0][0] == '1':
            summary = summaries[0][1]
            def count(label):
                match = re.search(r'(\d+) ' + label, summary)
                return match[1] if match else '0'
            passed, failed = count('passed'), count('failed')
            # Nextest excludes ignored tests by default. One executed exact
            # body therefore proves one selected nonignored runtime attempt.
            counts = [('ok' if failed == '0' else 'FAILED', passed, failed, '0')]
        runtime_signal = (bool(re.search(r'\bSIG(?:ABRT|SEGV)\b', output))
                          and 'running 1 test' in output and test in output)
    row = {'phase': phase, 'exit_code': result.returncode, 'counts': counts, 'log': path.name}
    row['compiler_diagnostics'] = compiler_diagnostics(output.encode())
    if args.case in PEER_TIMER_CASES:
        row.update(peer_leave_timer_control_oracle(output))
    if args.case in CANONICAL_CASES:
        row['actual_command'] = phase_command
        row.update(canonical_leaf_oracle(output, Path(CANONICAL_FIXTURE).read_text(), phase))
    if args.case in SECONDARY_CASES:
        row['runtime_panic_coordinates'] = runtime_panic_coordinates(output.encode())
    proof['runs'].append(row)
    save()  # Preserve actual counts before supplementary oracle/physical checks.
    if cohort:
        row['all_tracked_inputs_exact_for_phase'] = frozen_inputs() == expected_inputs
        if not row['all_tracked_inputs_exact_for_phase']:
            raise ValueError('Tracked source changed during runtime phase')
    if args.case in {'worker-spawn-stack', 'worker-stack-regression'}:
        row['runtime_signal_observed'] = runtime_signal
        row['rust_min_stack_bytes'] = int(os.environ['RUST_MIN_STACK'])
        row['selected_nonignored_tests'] = 1 if counts else None
    if args.case in publication_cases:
        row['required_runtime_marker_observed'] = held_marker in output
        if args.case != 'sibling-retry-priority':
            row['held_publication_observed'] = held_marker in output
        row['liveness_assertion_observed'] = failure_marker in output
        row['runtime_marker_before_liveness_assertion'] = (
            held_marker in output and failure_marker in output
            and output.index(held_marker) < output.index(failure_marker))
        if args.case != 'sibling-retry-priority':
            row['held_before_liveness_assertion'] = row['runtime_marker_before_liveness_assertion']
        row['rust_min_stack_bytes'] = int(os.environ['RUST_MIN_STACK'])
        row['selected_nonignored_tests'] = 1 if counts else None
        if args.case in {'automatic-publication', 'sibling-publication'}:
            row.update(publication_runtime_oracle(output, args.case, test, Path(FIXTURE).read_text()))
    if args.case == 'sibling-retry-priority':
        row.update(retry_priority_oracle(output, phase, Path(PRIORITY_FIXTURE).read_text(), capture_complete=True))
    if args.case in SECONDARY_CASES:
        expect_failure = args.secondary_stage == 'red' or phase == 'mutant'
        row.update(secondary_scheduler_oracle(output, args.case, Path(SECONDARY_FIXTURE).read_text(), expect_failure))
    if args.case == 'cancel-maintenance-red':
        row.update(cancel_maintenance_oracle(output, source.read_text()))
    if args.case == 'cancel-late-first-red':
        row.update(late_first_revoke_oracle(output, source.read_text()))
    if args.case == 'cancel-late-first-pfp':
        row.update(late_first_fixed_oracle(output, Path(CANCEL_MAINTENANCE_FIXTURE).read_text(), phase == 'mutant'))
    if args.case == 'cancel-maintenance-pfp':
        row.update(cancel_maintenance_oracle(output, Path(CANCEL_MAINTENANCE_FIXTURE).read_text(), phase == 'mutant'))
    if args.case == 'cancel-maintenance-real-guard-pfp':
        row.update(real_guard_oracle(output, Path(CANCEL_MAINTENANCE_FIXTURE).read_text(), phase == 'mutant'))
    if args.case in cancellation_cases - cancellation_pfp_cases:
        expected_names = ([test + name for name in ['first_revocation_is_not_renewed_by_repeats', 'foreign_gate_and_later_revision_cannot_acknowledge', 'shutdown_and_inherited_install_cannot_refresh_witness', 'exact_current_slot_is_consumed_only_once']]
                          if args.case == 'cancel-maintenance-slot-controls' else [test])
        if args.case == 'cancel-late-first-slot-controls':
            expected_names = [test + 'first_stale_revoke_cannot_cancel_a_later_gate_revision_or_create_ack_witness']
        elif args.case == 'cancel-invite-cas-controls':
            expected_names = [test + name for name in ['cas_fence_is_exact_and_cannot_follow_a_later_revision', 'foreign_counter_closed_and_overflow_fail_without_witness']]
        statuses = re.findall(r'(?m)^test ([A-Za-z0-9_:]+) \.\.\. (ok|FAILED)[ \t]*\r?$', output)
        compiler = re.findall(r'(?m)^error(?:\[E[0-9]+\])?: (?!test failed(?:,|$)|test run failed\r?$)[^\n]*', output)
        row.update(actual_expected_names=(len(statuses) == expected and sorted(statuses) == sorted((name, 'ok') for name in expected_names)), compiler_error_count=len(compiler), panic_header_count=output.count('panicked at '))
        row['evidence_passed'] = row['actual_expected_names'] and not compiler and row['panic_header_count'] == 0
    if args.case == 'outbound-mailbox-kind':
        own_location = str(source) + ':' + str(mailbox_assertion_line) + ':'
        row['own_assertion_location'] = own_location
        row['exact_wrong_kind_assertion_observed'] = (
            re.search(r"thread '" + re.escape(test) + r"'(?: \(\d+\))? panicked at " + re.escape(own_location), output) is not None
            and output.count('panicked at ') == 1
            and "assertion `left == right` failed" in output
            and re.search(r'(?m)^\s*left: Ok\(\(\)\)\s*$', output) is not None
            and re.search(r'(?m)^\s*right: Err\(Invalid\)\s*$', output) is not None)
    if args.case in cancellation_cases | CANONICAL_CASES | PEER_TIMER_CASES:
        row['head_and_index_unchanged'] = (subprocess.check_output(['git', 'rev-parse', 'HEAD'], text=True).strip() == cancellation_head and hashlib.sha256(subprocess.check_output(['git', 'ls-files', '--stage', '-z'])).hexdigest() == cancellation_index)
        if not row['head_and_index_unchanged']:
            row['evidence_passed'] = False
    save()
    return row


def matches(row, passed, failed):
    return len(row['counts']) == 1 and list(row['counts'][0][1:]) == [str(passed), str(failed), '0']


baseline = execute('baseline')
if args.case in PEER_TIMER_CASES:
    proof.update(control_only=True, product_mutation_attempted=False, runtime_mutation_qualification=False,
                 completed=False, control_passed=False)
    try:
        proof['source_unchanged'] = source.read_bytes() == original
        proof['all_tracked_inputs_unchanged'] = frozen_inputs() == frozen
        proof['final_source_head_index_exact'] = (
            subprocess.check_output(['git', 'rev-parse', 'HEAD'], text=True).strip() == cancellation_head
            and hashlib.sha256(subprocess.check_output(['git', 'ls-files', '--stage', '-z'])).hexdigest() == cancellation_index)
        proof['control_passed'] = (baseline['exit_code'] == 0 and matches(baseline, 2, 0)
            and baseline['evidence_passed'] and proof['source_unchanged']
            and proof['all_tracked_inputs_unchanged'] and proof['final_source_head_index_exact'])
        proof['completed'] = proof['control_passed']
    except (OSError, ValueError, subprocess.SubprocessError) as error:
        proof.update(source_unchanged=False, all_tracked_inputs_unchanged=False,
                     final_source_head_index_exact=False, control_passed=False, completed=False,
                     final_closure_error_category=type(error).__name__)
    save()
    raise SystemExit(0 if proof['completed'] else 1)
if args.case == 'cancel-late-first-red':
    proof.update(expected_red_only=True, qualification_passed=False, original_case_passed=False,
                 runtime_mutation_qualification=False, product_mutation_attempted=False,
                 baseline_behavioral_red=(baseline['exit_code'] == 101 and matches(baseline, 0, 1)
                                          and baseline['evidence_passed']),
                 source_unchanged=source.read_bytes() == original,
                 all_inputs_restored=frozen_inputs() == frozen)
    proof['completed'] = proof['baseline_behavioral_red'] and proof['source_unchanged'] and proof['all_inputs_restored']
    save()
    raise SystemExit(0 if proof['completed'] else 1)
if args.case == 'cancel-maintenance-red':
    proof.update(expected_red_only=True, qualification_passed=False, original_case_passed=False,
                 runtime_mutation_qualification=False, product_mutation_attempted=False,
                 baseline_behavioral_red=(baseline['exit_code'] == 101 and matches(baseline, 0, 1)
                                          and baseline['evidence_passed']),
                 source_unchanged=source.read_bytes() == original,
                 all_inputs_restored=frozen_inputs() == frozen)
    proof['completed'] = proof['baseline_behavioral_red'] and proof['source_unchanged'] and proof['all_inputs_restored']
    save()
    raise SystemExit(0 if proof['completed'] else 1)
if args.case in SECONDARY_CASES and args.secondary_stage == 'red':
    proof.update(expected_red_only=True, qualification_passed=False, original_case_passed=False,
                 runtime_mutation_qualification=False,
                 baseline_behavioral_red=(baseline['exit_code'] == 101 and matches(baseline, 0, 1)
                                          and baseline['evidence_passed']),
                 source_unchanged=source.read_bytes() == original,
                 all_inputs_restored=frozen_inputs() == frozen)
    proof['completed'] = proof['baseline_behavioral_red'] and proof['source_unchanged'] and proof['all_inputs_restored']
    save()
    raise SystemExit(0 if proof['completed'] else 1)
if args.case in cancellation_cases | CANONICAL_CASES and not baseline['evidence_passed']:
    raise SystemExit('Exact cancellation baseline evidence incomplete')
if args.case in cancellation_cases - cancellation_pfp_cases:
    proof.update(control_only=True, runtime_mutation_qualification=False, completed=(baseline['exit_code'] == 0 and matches(baseline, expected, 0) and baseline['evidence_passed'] and frozen_inputs() == frozen))
    save()
    raise SystemExit(0 if proof['completed'] else 1)
if args.case in SECONDARY_CASES and not baseline['evidence_passed']:
    raise SystemExit('Exact secondary scheduling baseline evidence incomplete')
if (baseline['exit_code'] != 0 or not matches(baseline, expected, 0)
        or (args.case in publication_cases and not baseline['required_runtime_marker_observed'])
        or (args.case in {'automatic-publication', 'sibling-publication'}
            and (baseline['compiler_error_count'] != 0 or baseline['panic_header_count'] != 0))):
    raise SystemExit('Baseline did not execute the intended passing regression cohort')
if args.case == 'sibling-retry-priority' and not baseline['evidence_passed']:
    raise SystemExit('Recipient frontier baseline evidence incomplete')
if args.case == 'worker-stack-regression':
    proof.update(control_only=True, runtime_mutation_qualification=False,
                 historical_outer_necessity_retired=True,
                 historical_survivor_receipt_sha256='1e92254c71bfc89647a4b27fddf8db9a6decb91a7aeb25bdabc776c1ba638926',
                 source_unchanged=source.read_bytes() == original,
                 completed=source.read_bytes() == original)
    if cohort:
        proof['all_tracked_inputs_unchanged'] = frozen_inputs() == frozen
        proof['completed'] &= proof['all_tracked_inputs_unchanged']
    save()
    raise SystemExit(0 if proof['completed'] else 1)
attempt_error = None
try:
    if cancellation_leaf is not None:
        cancellation_leaf.write(text.replace(old, new).encode())
    else:
        source.write_text(text.replace(old, new))
    mutant = execute('mutant')
    proof['runtime_mutant_killed'] = mutant['exit_code'] != 0 and matches(mutant, 0, len(CANONICAL_SIBLINGS) if args.case in CANONICAL_CASES else expected)
    if args.case in cancellation_pfp_cases | CANONICAL_CASES:
        proof['runtime_mutant_killed'] &= mutant['exit_code'] == 101 and mutant['evidence_passed']
    if args.case in SECONDARY_CASES:
        proof['finite_predecessors_completed_before_mutant_timeout'] = (
            mutant.get('timeout_observation') is not None
            and mutant['timeout_observation']['predecessor_command_count'] == 4)
        proof['runtime_mutant_killed'] &= (mutant['exit_code'] == 101 and mutant['evidence_passed']
                                          and proof['finite_predecessors_completed_before_mutant_timeout'])
    if args.case == 'sibling-retry-priority':
        proof['runtime_mutant_killed'] &= mutant['exit_code'] == 100 and mutant['evidence_passed']
    if args.case == 'outbound-mailbox-kind':
        proof['runtime_mutant_killed'] &= mutant['exact_wrong_kind_assertion_observed']
    if args.case == 'worker-spawn-stack':
        proof['runtime_mutant_killed'] &= mutant['runtime_signal_observed']
    if args.case in publication_cases:
        proof['runtime_mutant_killed'] &= mutant['runtime_marker_before_liveness_assertion']
    if args.case in {'automatic-publication', 'sibling-publication'}:
        proof['runtime_mutant_killed'] &= (mutant['exit_code'] == 100
                                          and mutant['intended_runtime_assertion'])
except (OSError, subprocess.SubprocessError, ValueError) as error:
    attempt_error = type(error).__name__
    proof['mutation_error_category'] = attempt_error
finally:
    if cancellation_leaf is not None:
        try:
            cancellation_leaf.write(original)
        except (OSError, ValueError) as error:
            proof.update(source_restored=False, completed=False, runtime_mutation_qualification=False,
                         restoration_error_category=type(error).__name__)
            save()
            raise
        finally:
            cancellation_leaf.close()
    else:
        source.write_bytes(original)
    proof['source_restored'] = hashlib.sha256(source.read_bytes()).hexdigest() == proof['original_sha256']
    if cohort:
        proof['all_inputs_restored'] = frozen_inputs() == frozen
        proof['source_restored'] &= proof['all_inputs_restored']
    save()
if not proof['source_restored']:
    raise SystemExit('Exact source restoration failed')
control = execute('restored-control')
proof['restored_control_passed'] = (control['exit_code'] == 0 and matches(control, expected, 0)
                                  and (args.case not in publication_cases or control['required_runtime_marker_observed'])
                                  and (args.case not in {'automatic-publication', 'sibling-publication'}
                                       or (control['compiler_error_count'] == 0 and control['panic_header_count'] == 0)))
if args.case in CANONICAL_CASES:
    proof['restored_control_passed'] &= control['evidence_passed']
    proof['counterfactual'] = 'pass-only-empty-departed-leaf-slice-to-existing-push-token-cleanup'
if args.case in cancellation_pfp_cases:
    proof['restored_control_passed'] &= control['evidence_passed']
    if args.case == 'cancel-maintenance-pfp':
        proof['historical_real_red_run_id'] = 39313864372
    elif args.case == 'cancel-late-first-pfp':
        proof['counterfactual'] = 'add-only-unconditional-Invite-gate-cancel-before-existing-CAS'
        proof['historical_late_first_red_run_id'] = 39321232775
    else:
        proof['counterfactual'] = 'omit-only-Core-owned-guard-pointer-check'
if args.case in SECONDARY_CASES:
    proof['restored_control_passed'] &= control['evidence_passed']
if args.case == 'sibling-retry-priority':
    proof['restored_control_passed'] &= control['evidence_passed']
    proof['historical_enrollment_survivor_retained'] = True
    proof['historical_run_id'] = 39301330063
    proof['current_fixture'] = PRIORITY_FIXTURE
if args.case == 'worker-spawn-stack':
    proof['counterfactual_outcome'] = (
        'runtime-mutant-survived' if mutant['exit_code'] == 0 and matches(mutant, expected, 0)
        else 'runtime-stack-signal-detected' if proof.get('runtime_mutant_killed')
        else 'unqualified-counterfactual') if 'mutant' in globals() else 'not-executed'
    proof['survivor_interpretation'] = 'Inner owner command-future boxing may make outer spawn boxing redundant; no removal of owner boxing or deadline changes is authorized.'
proof['final_source_sha256'] = hashlib.sha256(source.read_bytes()).hexdigest()
proof['completed'] = (proof.get('runtime_mutant_killed', False) and proof['restored_control_passed']
                      and proof['final_source_sha256'] == proof['original_sha256'] and attempt_error is None)
if args.case in cancellation_pfp_cases | CANONICAL_CASES:
    try:
        proof['final_source_head_index_exact'] = (frozen_inputs() == frozen
            and subprocess.check_output(['git', 'rev-parse', 'HEAD'], text=True).strip() == cancellation_head
            and hashlib.sha256(subprocess.check_output(['git', 'ls-files', '--stage', '-z'])).hexdigest() == cancellation_index)
    except (OSError, ValueError, subprocess.SubprocessError) as error:
        proof['final_source_head_index_exact'] = False
        proof['final_closure_error_category'] = type(error).__name__
    proof['completed'] &= proof['final_source_head_index_exact']
    proof['runtime_mutation_qualification'] = bool(proof['completed'])
save()
if not proof['completed']:
    raise SystemExit('Runtime mutation/restoration qualification failed; compile or empty runs are not kills')
