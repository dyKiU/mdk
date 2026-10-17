#!/usr/bin/env python3
"""Focused remote checks of the reviewed 639 merge; no final qualification claim."""
import argparse
import io
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import zipfile
from types import SimpleNamespace

import qualify_upstream_storage_boundary as storage
from upstream_extraction_cohort import frozen_inputs

BASE = '4a7181e1250c202fb471ffa1c04263fee65a5b8f'
UPSTREAM = '639abe576b3b1fd57e336ccdd82b1b06ebd1906d'
SELF = 'scripts/qualify_upstream_639_merge.py'
WORKFLOW = '.github/workflows/experimental-sync-ci.yml'
OUT = Path('merge-639-evidence')
ADAPTER = 'crates/transport-nostr-adapter/src/sdk_client.rs'
PLANE = 'crates/transport-nostr/src/lib.rs'
PACKAGES = ['marmot-app', 'transport-nostr', 'transport-nostr-adapter', 'storage-sqlite']
ADAPTER_TESTS = [
    'forwarder_reports_relay_closed_with_the_sdk_disposition',
    'public_forwarder_reports_loss_while_delivery_is_blocked',
    'aborting_public_forwarder_cancels_blocked_delivery_child',
    'account_notification_watermarks_remain_independent_across_replacement',
    'lag_repair_recovers_an_end_of_stored_events_the_consumer_lost',
    'production_acquisition_cancel_and_drop_preserve_live_interest',
]
PLANE_TESTS = [
    'notification_consumer_reports_lag_without_silently_ending',
    'failed_notification_worker_latches_queued_loss_for_only_its_account',
    'busy_notification_worker_absorbs_rebuild_replay_without_loss',
    'notification_consumer_exit_closes_only_account_delivery',
    'live_notification_consumer_reports_relay_closed',
    'supervised_notification_lag_delivers_later_inbound_exactly_once',
]
CAPTURE_TEST = 'enrollment_acquisition_delayed_notification_worker_preserves_clock_and_fifo_eose'
CAPTURE_NAME = 'tests::' + CAPTURE_TEST
CAPTURE_TEST_FILE = 'crates/transport-nostr/src/tests.rs'
CONTROL_SOURCE = '764aef8f10c765bc5399762abd8d7f1378b6eac0'
CONTROL_RUN = '39069674431'
CONTROL_DIGESTS = {
    'preflight': '543a2b8dfcd80508babe64ba690709bd54b8739a841405b5a4c39c99e9432b2b',
    'runtime-default': '593e15478e1eb08ea140b9a63a49083b0239a5ad4931bc548735cbbee2745c70',
    'runtime-experimental': '3cb971fc93d656412d629c58cfcbea2811841c94213a674ceae4bbff51e6803c',
    'static-default': 'd6e2ac8f0963aacf1cf2d3e6f62de612edfcbad70d09d975ce4835d041565282',
    'static-experimental': '3b988df11a1fe94baf3db845576f5fda8f658e832937a69b8fbda55cc265b5ea',
    'production': '777daefb1e0b37a165a74e4a0aa52e876689d51dff8cb867716fd1de8fc3c2ff',
}
CONTROL_INPUT = '''      # MERGE_639_CONTROL_INPUT_BEGIN
      merge_639_control_run_id:
        description: Reviewed successful 35-control run on the unchanged product cohort
        type: string
        default: ''
      # MERGE_639_CONTROL_INPUT_END
'''
ensure, digest, capture = storage.ensure, storage.digest, storage.capture


def git(*args):
    return subprocess.check_output(['git', *args], text=True).strip()


def section(text, begin, end):
    ensure(text.count(begin) == 1 and text.count(end) == 1, 'unique-reviewed-source-section')
    return text[text.index(begin):text.index(end)]


def source_guard():
    head = git('rev-parse', 'HEAD')
    ensure(os.environ.get('GITHUB_ACTIONS') == 'true' and os.environ.get('GITHUB_REPOSITORY') == 'dyKiU/mdk'
           and os.environ.get('GITHUB_EVENT_NAME') == 'workflow_dispatch'
           and os.environ.get('GITHUB_SHA') == head
           and os.environ.get('GITHUB_REF', '').startswith('refs/heads/ci/upstream-639-merge-checks-')
           and os.environ.get('UPSTREAM_639_BASELINE') == BASE, 'explicit-owned-exact-639-actions-cohort')
    ensure(os.environ.get('GITHUB_WORKFLOW_REF') == 'dyKiU/mdk/' + WORKFLOW + '@' + os.environ['GITHUB_REF'], 'exact-existing-workflow-on-reviewed-ref')
    for ancestor in [BASE, UPSTREAM]:
        subprocess.run(['git', 'merge-base', '--is-ancestor', ancestor, head], check=True)
    ensure(not git('diff', '--name-only', 'HEAD'), 'pristine-tracked-source')
    changed = set(git('diff', '--name-only', BASE, head).splitlines())
    ensure(changed <= {SELF, WORKFLOW}, 'whole-product-and-existing-controller-tree-exact-reviewed-baseline')
    frozen = frozen_inputs()
    ensure(all(row['actual_executable'] == (row['mode'] == '100755') for row in frozen.values()
               if row['mode'] != '120000'), 'every-tracked-source-executable-mode-matches-index')
    ensure(all(row['mode'] == '100644' and not row['actual_executable'] for name, row in frozen.items() if name in changed), 'ordinary-metadata-file-modes')
    for name in git('ls-files', '--others', '--exclude-standard').splitlines():
        ensure(name.startswith(('merge-639-evidence/', 'storage-boundary-evidence/', 'late-consent-candidate-evidence/')), 'no-untracked-source-overlay')
    workflow = Path(WORKFLOW).read_text()
    begin, end = '  # MERGE_639_JOBS_BEGIN\n', '  # MERGE_639_JOBS_END\n'
    ensure(workflow.count(begin) == workflow.count(end) == 1, 'one-isolated-639-job-union')
    before, rest = workflow.split(begin)
    _, after = rest.split(end)
    restored = (before + after).replace('options: [639-preflight, 639-controls, 639-worker-diagnostic, 639-static-diagnostic, 639-capture-preflight, 639-capture-mutation, ', 'options: [', 1)
    ensure(restored.count(CONTROL_INPUT) == 1, 'one-exact-capture-controls-input')
    restored = restored.replace(CONTROL_INPUT, '', 1)
    ensure(restored.encode() == subprocess.check_output(['git', 'show', BASE + ':' + WORKFLOW]), 'all-existing-workflow-options-and-jobs-exact-reviewed-baseline')
    sdk, plane = Path(ADAPTER).read_text(), Path(PLANE).read_text()
    dispatch = section(sdk, 'async fn dispatch_sdk_notification_inner(', '\nimpl NostrSdkRelayClient {')
    ensure(dispatch.count('match notification {') == 1
           and dispatch.count('.handle_captured_live_relay_event(account_id, relay_event, capture)') == 1
           and 'observe(&observed_id, 0);' in dispatch and 'Ok(0) => 2' in dispatch
           and 'Ok(_) => 3' in dispatch and 'Err(_) => 4' in dispatch
           and '.handle_relay_eose(' in dispatch and 'classify_closed(&message)' in dispatch, 'one-canonical-dispatch-capture-result-eose-and-closed-oracles')
    consumer = section(plane, 'async fn run_relay_notification_consumer_scoped(', '\n#[cfg(test)]\nasync fn handle_relay_notification(')
    ensure(consumer.index('let capture = capture_live_notification') < consumer.index('sender.try_send((notification, capture))')
           and 'account_id.as_ref(),\n                capture,' in consumer, 'original-prequeue-account-capture-forwarded')
    route = section(plane, 'async fn handle_relay_notification_captured(', '\nfn recover_relay_notification_forwarder(')
    ensure('match notification {' not in route and 'NostrSdkRelayClient::dispatch_sdk_notification_captured(' in route
           and 'observer.record(id, slot);' in route, 'plane-delegates-with-original-test-only-result-observer')
    forwarder = section(sdk, '    pub fn spawn_notification_forwarder(', '\n    pub fn plan_subscription(')
    ensure('Self::dispatch_sdk_notification_captured(' in forwarder and '_capture,' in forwarder
           and forwarder.index('acquisition\n                                        .capture(') < forwarder.index('sender.try_send((notification, capture))'), 'forwarder-prequeue-capture-reaches-shared-dispatch')
    environment = {'CARGO_INCREMENTAL': '1', 'CARGO_BUILD_JOBS': '2', 'CARGO_PROFILE_DEV_DEBUG': '0',
                   'CARGO_PROFILE_TEST_DEBUG': '0', 'RUST_MIN_STACK': '4194304'}
    ensure(all(os.environ.get(key) == value for key, value in environment.items()), 'exact-reviewed-debug-and-stack-cohort')
    ensure(all(not os.environ.get(key) for key in ['RUSTFLAGS', 'CARGO_ENCODED_RUSTFLAGS', 'RUSTDOCFLAGS', 'CARGO_ENCODED_RUSTDOCFLAGS', 'RUSTC_BOOTSTRAP', 'CARGO_PROFILE_DEV_OPT_LEVEL', 'CARGO_PROFILE_TEST_OPT_LEVEL']), 'no-compiler-or-profile-overrides')
    return {'source': head, 'baseline': BASE, 'incoming_upstream': UPSTREAM,
            'source_tree': git('rev-parse', 'HEAD^{tree}'), 'baseline_tree': git('rev-parse', BASE + '^{tree}'),
            'workflow_identity': os.environ['GITHUB_WORKFLOW_REF'],
            'whole_product_controller_and_test_inputs_exact_reviewed_baseline': True,
            'all_existing_workflow_jobs_preserved': True,
            'source_scope_oracles_passed': True, 'metadata_overlay': sorted(changed),
            'input_manifest_sha256': digest(json.dumps(frozen, sort_keys=True).encode()),
            'historical_3aec_source_guard_or_green_reused': False,
            'historical_allow_list_prefix_retained_claim': False,
            'environment': environment}


def worker_panic_location():
    source = Path(PLANE).read_text()
    anchor = 'panic!("injected relay notification worker failure");'
    ensure(source.count(anchor) == 1, 'one-original-intentional-worker-panic-location')
    offset = source.index(anchor)
    return source[:offset].count('\n') + 1, offset - source.rfind('\n', 0, offset)


def panic_policy(raw, name):
    count = raw.count('panicked at ')
    intentional_case = 'tests::failed_notification_worker_latches_queued_loss_for_only_its_account'
    if name != intentional_case:
        return count == 0
    # Only this selected test deliberately fails a child. Require the original
    # macro's exact static location and payload, never an arbitrary caught panic.
    line, column = worker_panic_location()
    pattern = (r"^thread '(?:tokio-runtime-worker|tokio-rt-worker)'(?: \([0-9]+\))? panicked at "
               + re.escape(PLANE) + ':' + str(line) + ':' + str(column)
               + r':\ninjected relay notification worker failure\n')
    return count == 1 and len(re.findall(pattern, raw, re.M)) == 1


def parse_runtime(raw, code, name):
    summary = re.findall(r'^test result: (ok|FAILED)\. (\d+) passed; (\d+) failed; (\d+) ignored; (\d+) measured; (\d+) filtered out;', raw, re.M)
    names = re.findall(r'^test ([A-Za-z0-9_:]+) \.\.\. ', raw, re.M)
    row = {'actual_counts_complete': False, 'executed_nonignored': None, 'exit_code': code,
           'passed': None, 'failed': None, 'ignored': None,
           'compiler_error_count': len(re.findall(r'^error(?:\[E\d+\])?:', raw, re.M)),
           'panic_headers': raw.count('panicked at '), 'panic_policy_passed': panic_policy(raw, name),
           'safe_panic_diagnostics': safe_panic_diagnostics(raw, name),
           'passed_gate': False}
    if len(summary) == 1 and names == [name]:
        status, passed, failed, ignored, measured, _ = summary[0]
        passed, failed, ignored = int(passed), int(failed), int(ignored)
        if passed + failed == 1 and ignored == int(measured) == 0 and status == ('FAILED' if failed else 'ok'):
            row.update(actual_counts_complete=True, passed=passed, failed=failed, ignored=ignored, executed_nonignored=1)
            row['passed_gate'] = (code == 0 and passed == 1 and failed == 0
                                  and row['compiler_error_count'] == 0 and row['panic_policy_passed'])
    return row


def safe_panic_diagnostics(raw, name):
    # Diagnostic only: never broaden panic_policy or emit arbitrary thread,
    # path or message strings. Unknown values remain explicitly unknown.
    headers = re.findall(r"thread '([^'\n]{1,300})'(?: \([0-9]+\))? panicked at ([^\n]{1,600}):([0-9]+):([0-9]+):\n([^\n]{0,500})", raw)
    known = frozen_inputs()
    rows = []
    for thread, filename, line, column, message in headers[:4]:
        category = ('selected-test' if thread == name else thread if thread in {'tokio-runtime-worker', 'tokio-rt-worker'} else 'unknown')
        checkout = str(Path.cwd()) + '/'
        relative = filename[len(checkout):] if filename.startswith(checkout) else filename
        located = relative in known and relative.endswith('.rs') and 0 < int(line) <= 2147483647 and 0 < int(column) <= 2147483647
        form = ('checkout-absolute' if filename.startswith(checkout) else 'tracked-relative') if located else 'unknown'
        rows.append({'thread_category': category, 'known_source': relative if located else None, 'source_path_form': form,
                     'line': int(line) if located else None, 'column': int(column) if located else None,
                     'expected_worker_message': message == 'injected relay notification worker failure'})
    return {'headers_parsed': len(headers), 'unparsed_header_count': max(0, raw.count('panicked at ') - len(headers)),
            'truncated': len(headers) > 4, 'rows': rows}


def parser_preflight():
    name = 'tests::closed_selected_body'
    raw = 'test ' + name + ' ... ok\ntest result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 4 filtered out; finished in 0.1s\n'
    ensure(parse_runtime(raw, 0, name)['passed_gate'], 'one-actual-runtime-parser-positive')
    negatives = [raw.replace(name, 'foreign::body'), raw.replace('1 passed', '0 passed'), raw.replace('0 ignored', '1 ignored'),
                 raw.replace('0 measured', '1 measured'), raw + raw, 'error: compilation failed\n']
    for value in negatives:
        ensure(not parse_runtime(value, 0, name)['passed_gate'], 'runtime-parser-rejects-incomplete-foreign-or-compiler-result')
    ensure(not parse_runtime(raw, 101, name)['passed_gate'], 'runtime-parser-rejects-nonzero')
    worker = 'tests::failed_notification_worker_latches_queued_loss_for_only_its_account'
    line, column = worker_panic_location()
    panic = ("\nthread 'tokio-runtime-worker' (123) panicked at " + PLANE + ':' + str(line) + ':' + str(column)
             + ':\ninjected relay notification worker failure\n')
    worker_raw = raw.replace(name, worker).replace(' ... ok\n', ' ... ' + panic + 'ok\n')
    ensure(parse_runtime(worker_raw, 0, worker)['passed_gate'], 'exact-intentional-worker-panic-positive')
    ensure(parse_runtime(worker_raw.replace("' (123)", "'"), 0, worker)['passed_gate'], 'exact-worker-panic-without-thread-id-positive')
    actual_worker = worker_raw.replace('tokio-runtime-worker', 'tokio-rt-worker')
    ensure(parse_runtime(actual_worker, 0, worker)['passed_gate'], 'actual-ci-tokio-worker-name-positive')
    ensure(parse_runtime(actual_worker.replace("' (123)", "'"), 0, worker)['passed_gate'], 'actual-ci-tokio-worker-without-thread-id-positive')
    unexpected = [raw + panic, raw + "\nthread 'child' panicked at crates/other.rs:1:1:\nunrelated panic\n",
                  worker_raw.replace('injected relay notification worker failure', 'unrelated panic'),
                  worker_raw.replace(PLANE, 'crates/other.rs'),
                  worker_raw.replace(':' + str(line) + ':', ':' + str(line + 1) + ':'),
                  worker_raw.replace(':' + str(column) + ':', ':' + str(column + 1) + ':'),
                  worker_raw.replace('tokio-runtime-worker', 'unrelated-worker'),
                  worker_raw + panic, raw.replace(name, worker),
                  actual_worker.replace('tokio-rt-worker', 'unrelated-worker'),
                  actual_worker.replace('injected relay notification worker failure', 'unrelated panic'),
                  actual_worker.replace(PLANE, 'crates/other.rs'), actual_worker + panic]
    for index, value in enumerate(unexpected):
        selected = name if index < 2 else worker
        ensure(not parse_runtime(value, 0, selected)['passed_gate'], 'missing-extra-or-foreign-worker-panic-rejected')
    observed = safe_panic_diagnostics(panic, worker)
    ensure(observed['headers_parsed'] == 1 and observed['rows'] == [
        {'thread_category': 'tokio-runtime-worker', 'known_source': PLANE, 'line': line,
         'column': column, 'source_path_form': 'tracked-relative', 'expected_worker_message': True}], 'closed-known-panic-diagnostic-positive')
    absolute = safe_panic_diagnostics(panic.replace(PLANE, str(Path.cwd()) + '/' + PLANE), worker)
    ensure(absolute['rows'][0]['known_source'] == PLANE and absolute['rows'][0]['source_path_form'] == 'checkout-absolute', 'closed-checkout-absolute-panic-location-positive')
    private = "thread 'PRIVATE_RUNTIME_VALUE' panicked at /PRIVATE_RUNTIME_VALUE.rs:1:1:\nPRIVATE_RUNTIME_VALUE\n"
    unknown = safe_panic_diagnostics(private, worker)
    ensure(unknown['headers_parsed'] == 1 and unknown['rows'] == [
        {'thread_category': 'unknown', 'known_source': None, 'line': None, 'column': None,
         'source_path_form': 'unknown', 'expected_worker_message': False}] and 'PRIVATE_RUNTIME_VALUE' not in json.dumps(unknown), 'unknown-panic-values-never-exported')
    ensure(safe_panic_diagnostics(private * 5, worker)['truncated'] is True, 'panic-diagnostic-export-bounded')
    ensure(safe_panic_diagnostics('unparsed panicked at hidden\n', worker)['unparsed_header_count'] == 1, 'unknown-panic-header-explicit')
    return {'positive': 5, 'negative': len(negatives) + 1 + len(unexpected),
            'diagnostic_positive': 2, 'diagnostic_privacy_and_unknown_controls': 3, 'actual_runtime_bodies': 0}


def compile_package(package, cohort, row):
    features = ['sdk', 'test-policy-overrides'] if package == 'transport-nostr-adapter' else ['test-support', 'test-policy-overrides']
    if cohort == 'experimental':
        features.append('experimental-device-sync')
    command = ['cargo', 'test', '--locked', '--no-default-features', '-p', package, '--lib', '--no-run', '--message-format=json', '--features', ','.join(features)]
    code, raw, seconds = capture(command, 1800)
    events = [json.loads(line) for line in raw.splitlines() if line.startswith('{')]
    errors = sum(event.get('reason') == 'compiler-message' and event.get('message', {}).get('level') == 'error' for event in events)
    artifacts = [event for event in events if event.get('reason') == 'compiler-artifact']
    selected = [event for event in artifacts if event['target']['name'] == package.replace('-', '_')
                and event['target']['kind'] == ['lib'] and event['profile']['test'] and event.get('executable')]
    row['compilation'] = {'command': command, 'exit_code': code, 'compiler_error_count': errors,
                          'seconds': seconds, 'selected_artifacts': len(selected),
                          'safe_compiler_diagnostics': [storage.safe_compiler_diagnostic(event, frozen_inputs()) for event in events
                              if event.get('reason') == 'compiler-message' and event.get('message', {}).get('level') == 'error'][:16],
                          'diagnostics_truncated': errors > 16}
    ensure(code == errors == 0 and len(selected) == 1, 'actual-one-transport-library-compiled')
    expected = set(features)
    # SDK uses dep: activation, so optional dependencies are not extra named
    # crate features. Record the actual compiler artifact, never infer success.
    ensure(set(selected[0]['features']) == expected, 'exact-selected-transport-feature-identity')
    binary = Path(selected[0]['executable'])
    row['compilation'].update(binary_sha256=digest(binary.read_bytes()), compiled_features=sorted(selected[0]['features']),
                              all_artifact_features_sha256=digest(json.dumps(sorted(
                                  [{'package': event['package_id'], 'target': event['target']['name'],
                                    'kind': event['target']['kind'], 'features': sorted(event['features']),
                                    'profile': event['profile']} for event in artifacts],
                                  key=lambda value: json.dumps(value, sort_keys=True)), sort_keys=True).encode()))
    if package == 'transport-nostr':
        adapters = [event for event in artifacts if event['target']['name'] == 'transport_nostr_adapter' and event['target']['kind'] == ['lib']]
        sdks = [event for event in artifacts if event['target']['name'] == 'nostr_sdk' and event['target']['kind'] == ['lib']]
        required_adapter = {'sdk', 'test-policy-overrides'} | ({'experimental-device-sync'} if cohort == 'experimental' else set())
        row['compilation']['sdk_dependency_verified'] = bool(adapters and sdks) and all(required_adapter <= set(event['features']) for event in adapters)
        row['compilation']['adapter_dependency_features'] = [sorted(event['features']) for event in adapters]
    return binary


def transport_controls(cohort, report, frozen, save, worker_only=False):
    report['transport'] = {}
    selection = [('transport-nostr', ['failed_notification_worker_latches_queued_loss_for_only_its_account'], 'tests::')] if worker_only else [
        ('transport-nostr-adapter', ADAPTER_TESTS, 'sdk_client::tests::'),
        ('transport-nostr', PLANE_TESTS + ([CAPTURE_TEST] if cohort == 'experimental' else []), 'tests::')]
    for package, suffixes, prefix in selection:
        row = {'bodies': {}}
        report['transport'][package] = row
        try:
            binary = compile_package(package, cohort, row)
        finally:
            save()
        sha = row['compilation']['binary_sha256']
        for name in [prefix + suffix for suffix in suffixes]:
            code, listed, _ = capture([str(binary), name, '--exact', '--list', '--format', 'terse'], 60)
            lines = [line for line in listed.splitlines() if line]
            ensure(code == 0 and lines.count(name + ': test') == 1 and all(line in {name + ': test', '1 test, 0 benchmarks'} for line in lines), 'exact-selected-transport-test-name')
            code, ignored, _ = capture([str(binary), name, '--exact', '--ignored', '--list', '--format', 'terse'], 60)
            ensure(code == 0 and ignored.strip() in {'', '0 tests, 0 benchmarks'}, 'selected-transport-test-not-ignored')
            ensure(frozen_inputs() == frozen and digest(binary.read_bytes()) == sha, 'transport-inputs-exact-before-body')
            code, raw, seconds = capture([str(binary), name, '--exact', '--nocapture', '--test-threads=1'], 300)
            row['bodies'][name] = dict(parse_runtime(raw, code, name), seconds=seconds, binary_sha256=sha)
            save()
            ensure(frozen_inputs() == frozen and digest(binary.read_bytes()) == sha, 'transport-inputs-exact-after-body')
            ensure(row['bodies'][name]['passed_gate'], 'actual-selected-transport-body-not-green')


def storage_controls(cohort, preflight=False):
    def reviewed_guard(baseline, ownership):
        ensure(baseline == BASE and ownership, 'explicit-new-639-storage-cohort')
        return source_guard()
    # Only the obsolete source-cohort guard changes. Inventory, assertions,
    # compilation, features, parsers, counts and source restoration stay original.
    storage.source_guard = reviewed_guard
    arguments = sys.argv
    try:
        sys.argv = [SELF, '--cohort', cohort, '--cohort-baseline', BASE, '--ownership-adaptation'] + (['--preflight'] if preflight else [])
        ensure(storage.main() == 0, 'new-639-storage-controls-not-green')
    finally:
        sys.argv = arguments
    receipt = Path('storage-boundary-evidence/result.json')
    row = json.loads(receipt.read_text())
    ensure(row.get('inputs_pristine') is True and (row.get('preflight_passed') is True if preflight else
           row.get('actual_counts_complete') is True and type(row.get('actual_executed_nonignored')) is int
           and row['actual_executed_nonignored'] == 4 and row.get('boundary_controls_passed') is True), 'exact-new-storage-receipt')
    return {'receipt': str(receipt), 'sha256': digest(receipt.read_bytes()),
            'actual_executed_nonignored': 0 if preflight else 4}


def directed_controls(preflight=False):
    import qualify_upstream_late_consent_candidate as directed
    directed.source_guard = source_guard
    directed.main(SimpleNamespace(mode='green', cohort=None, preflight=preflight))
    receipt = Path('late-consent-candidate-evidence/result.json')
    row = json.loads(receipt.read_text())
    ensure(row.get('inputs_pristine') is True and (preflight or
           row.get('actual_counts_complete') is True and row.get('green_passed') is True
           and type(row.get('actual_executed_nonignored')) is int and row['actual_executed_nonignored'] == 2), 'exact-two-directed-runtime-receipt')
    return {'receipt': str(receipt), 'sha256': digest(receipt.read_bytes()),
            'actual_executed_nonignored': 0 if preflight else 2}


def static_checks(cohort, production, report):
    from upstream_completion_ci import DEFAULT_FEATURES, FEATURES
    features = 'marmot-app/experimental-device-sync,transport-nostr-adapter/sdk' if production else (FEATURES if cohort == 'experimental' else DEFAULT_FEATURES) + ',transport-nostr-adapter/sdk'
    command = ['cargo', 'check' if production else 'clippy', '--locked', '--message-format=json']
    for package in PACKAGES:
        command += ['-p', package]
    command += ['--lib' if production else '--all-targets', '--features', features]
    if not production:
        command += ['--', '-D', 'warnings']
    code, raw, seconds = capture(command, 1800)
    events = [json.loads(line) for line in raw.splitlines() if line.startswith('{')]
    errors = sum(event.get('reason') == 'compiler-message' and event.get('message', {}).get('level') == 'error' for event in events)
    artifacts = [event for event in events if event.get('reason') == 'compiler-artifact']
    selected = {event['target']['name']: sorted(event['features']) for event in artifacts if event['target']['name'] in {package.replace('-', '_') for package in PACKAGES}}
    report['static'] = {'command': command, 'exit_code': code, 'compiler_error_count': errors, 'seconds': seconds,
                        'compiled_package_features': selected, 'production_without_test_policy': production,
                        'safe_compiler_diagnostics': [storage.safe_compiler_diagnostic(event, frozen_inputs()) for event in events
                            if event.get('reason') == 'compiler-message' and event.get('message', {}).get('level') == 'error'][:16],
                        'diagnostics_truncated': errors > 16}
    closed_lints = {'clippy::type_complexity', 'clippy::too_many_arguments', 'private_interfaces', 'private_bounds'}
    report['static']['closed_lint_diagnostics'] = [
        {'lint': event['message']['code']['code'] if isinstance(event['message'].get('code'), dict)
             and event['message']['code'].get('code') in closed_lints else 'unknown',
         'location': storage.safe_compiler_diagnostic(event, frozen_inputs())}
        for event in events if event.get('reason') == 'compiler-message' and event.get('message', {}).get('level') == 'error'][:16]
    ensure(code == errors == 0 and set(selected) == {package.replace('-', '_') for package in PACKAGES}, 'all-four-affected-packages-actually-compiled')
    ensure(all(('experimental-device-sync' in values) == (production or cohort == 'experimental') for values in selected.values()), 'static-actual-experimental-cohort')
    if production:
        ensure(all('test-policy-overrides' not in event['features'] and 'test-support' not in event['features'] for event in artifacts), 'production-artifacts-without-test-policy-or-test-support')


def capture_assertion_line():
    source = Path(CAPTURE_TEST_FILE).read_text()
    anchor = '.expect("post-EOSE acquisition must remain eligible while worker is blocked");'
    ensure(source.count(anchor) == 1, 'one-original-capture-expect-oracle')
    return source[:source.index(anchor)].count('\n') + 1


def capture_mutation_killed(raw, code):
    row = parse_runtime(raw, code, CAPTURE_NAME)
    pattern = (r"^thread '" + re.escape(CAPTURE_NAME) + r"'(?: \([0-9]+\))? panicked at "
               + re.escape(CAPTURE_TEST_FILE) + ':' + str(capture_assertion_line())
               + r':[1-9][0-9]{0,8}:\npost-EOSE acquisition must remain eligible while worker is blocked\n')
    return (row['actual_counts_complete'] and code == 101 and row['passed'] == 0
            and row['failed'] == 1 and row['ignored'] == 0 and row['compiler_error_count'] == 0
            and row['panic_headers'] == 1 and len(re.findall(pattern, raw, re.M)) == 1)


def capture_parser_preflight():
    panic = ("\nthread '" + CAPTURE_NAME + "' (123) panicked at " + CAPTURE_TEST_FILE + ':'
             + str(capture_assertion_line()) + ':10:\npost-EOSE acquisition must remain eligible while worker is blocked\n')
    raw = ('test ' + CAPTURE_NAME + ' ... ' + panic
           + 'FAILED\ntest result: FAILED. 0 passed; 1 failed; 0 ignored; 0 measured; 12 filtered out; finished in 0.1s\n')
    ensure(capture_mutation_killed(raw, 101), 'exact-original-capture-runtime-assertion-parser-positive')
    negatives = [(raw, 0), (raw.replace('1 failed', '0 failed'), 101),
                 (raw.replace('0 ignored', '1 ignored'), 101), (raw.replace('0 measured', '1 measured'), 101),
                 (raw.replace(CAPTURE_NAME, 'tests::foreign'), 101),
                 (raw.replace(CAPTURE_TEST_FILE, 'crates/foreign.rs'), 101),
                 (raw.replace(':' + str(capture_assertion_line()) + ':', ':' + str(capture_assertion_line() + 1) + ':'), 101),
                 (raw.replace('post-EOSE acquisition must remain eligible while worker is blocked', 'unrelated failure'), 101),
                 (raw + panic, 101), (raw + raw, 101), ('error[E0001]: compilation failed\n', 101),
                 ('test result: ok. 0 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out;\n', 0)]
    for value, code in negatives:
        ensure(not capture_mutation_killed(value, code), 'capture-parser-rejects-nonruntime-unrelated-or-incomplete-kill')
    return {'positive': 1, 'negative': len(negatives), 'actual_runtime_bodies': 0}


def prior_639_controls(run_id, report, frozen):
    ensure(run_id == CONTROL_RUN, 'explicit-reviewed-35-controls-run-required')
    head = report['source_guard']['source']
    subprocess.run(['git', 'merge-base', '--is-ancestor', CONTROL_SOURCE, head], check=True)
    ensure(set(git('diff', '--name-only', CONTROL_SOURCE, head).splitlines()) <= {SELF, WORKFLOW}, 'prior-controls-product-tests-config-and-old-controllers-unchanged')
    prior_frozen = dict(frozen)
    for name in [SELF, WORKFLOW]:
        ensure(git('ls-tree', CONTROL_SOURCE, '--', name).split()[0] == '100644', 'prior-controls-ordinary-metadata-mode')
        prior_frozen[name] = {'mode': '100644', 'actual_executable': False,
                              'sha256': digest(subprocess.check_output(['git', 'show', CONTROL_SOURCE + ':' + name]))}
    prior_manifest = digest(json.dumps(prior_frozen, sort_keys=True).encode())
    product_manifest = digest(json.dumps({name: row for name, row in frozen.items() if name not in {SELF, WORKFLOW}}, sort_keys=True).encode())
    prefix = 'repos/dyKiU/mdk/actions/'
    run = storage.github_metadata(prefix + 'runs/' + run_id)
    ensure(run.get('head_sha') == CONTROL_SOURCE and run.get('event') == 'workflow_dispatch'
           and run.get('status') == 'completed' and run.get('conclusion') == 'success'
           and run.get('path') == WORKFLOW and run.get('head_repository', {}).get('full_name') == 'dyKiU/mdk', 'reviewed-successful-owned-control-run')
    inventory = storage.github_metadata(prefix + 'runs/' + run_id + '/artifacts?per_page=100')
    artifacts = inventory.get('artifacts')
    ensure(isinstance(artifacts, list) and inventory.get('total_count') == len(artifacts) <= 100, 'bounded-complete-controls-artifact-inventory')
    receipts = {}
    for label, expected_digest in CONTROL_DIGESTS.items():
        selected = [item for item in artifacts if item.get('name') == 'merge-639-' + label + '-' + CONTROL_SOURCE]
        ensure(len(selected) == 1 and selected[0].get('expired') is False, 'one-unexpired-reviewed-controls-artifact')
        item = selected[0]
        ensure(type(item.get('id')) is int and type(item.get('size_in_bytes')) is int
               and 0 < item['size_in_bytes'] <= 4 * 1024 * 1024, 'bounded-reviewed-controls-artifact')
        archive = storage.github_metadata(prefix + 'artifacts/' + str(item['id']) + '/zip', archive=True)
        checksum = digest(archive)
        ensure(checksum == expected_digest and item.get('digest') == 'sha256:' + checksum, 'exact-reviewed-and-api-controls-archive-digest')
        with zipfile.ZipFile(io.BytesIO(archive)) as bundle:
            files = bundle.infolist()
            ensure(len(files) <= 16 and len({info.filename for info in files}) == len(files)
                   and all(not info.flag_bits & 1 and info.file_size <= 512 * 1024 for info in files)
                   and sum(info.file_size for info in files) <= 2 * 1024 * 1024, 'bounded-unique-unencrypted-controls-archive')
            primary = bundle.read('mdk/mdk/merge-639-evidence/result.json')
            row = json.loads(primary)
            guard = row.get('source_guard', {})
            ensure(guard.get('source') == CONTROL_SOURCE and guard.get('baseline') == BASE
                   and guard.get('source_tree') == git('rev-parse', CONTROL_SOURCE + '^{tree}')
                   and guard.get('input_manifest_sha256') == prior_manifest
                   and guard.get('whole_product_controller_and_test_inputs_exact_reviewed_baseline') is True
                   and guard.get('all_existing_workflow_jobs_preserved') is True
                   and guard.get('source_scope_oracles_passed') is True
                   and guard.get('environment') == report['source_guard']['environment']
                   and row.get('toolchain') == report['toolchain'] and row.get('inputs_pristine') is True
                   and not row.get('failure_type'), 'reviewed-control-source-manifest-tools-environment-pristine')
            actual = 0
            if label == 'preflight':
                ensure(row.get('mode') == 'preflight' and row.get('preflight_passed') is True
                       and bundle.read('_temp/merge-639-formatting.patch') == b'', 'reviewed-parser-and-formatter-preflight-green')
            elif label.startswith('runtime-'):
                cohort = label.removeprefix('runtime-')
                expected_transport = 12 if cohort == 'default' else 13
                ensure(row.get('mode') == 'runtime' and row.get('cohort') == cohort and row.get('focused_checks_passed') is True
                       and row.get('actual_transport_counts_complete') is True
                       and type(row.get('actual_transport_executed_nonignored')) is int
                       and row['actual_transport_executed_nonignored'] == expected_transport, 'actual-reviewed-transport-counts-complete')
                transport = row.get('transport', {})
                expected_names = {'transport-nostr-adapter': ['sdk_client::tests::' + name for name in ADAPTER_TESTS],
                                  'transport-nostr': ['tests::' + name for name in PLANE_TESTS + ([CAPTURE_TEST] if cohort == 'experimental' else [])]}
                ensure(set(transport) == set(expected_names), 'both-reviewed-transport-packages')
                for package, names in expected_names.items():
                    bodies = transport[package].get('bodies', {})
                    ensure(set(bodies) == set(names), 'exact-reviewed-transport-body-inventory')
                    for body in bodies.values():
                        ensure(body.get('passed_gate') is True and body.get('actual_counts_complete') is True
                               and type(body.get('passed')) is int and body['passed'] == 1
                               and body.get('failed') == body.get('ignored') == body.get('compiler_error_count') == 0
                               and body.get('executed_nonignored') == 1, 'every-reviewed-transport-body-actual-green')
                stored = bundle.read('mdk/mdk/storage-boundary-evidence/result.json')
                storage_row = json.loads(stored)
                ensure(digest(stored) == row.get('storage', {}).get('sha256')
                       and storage_row.get('boundary_controls_passed') is True and storage_row.get('inputs_pristine') is True
                       and storage_row.get('actual_counts_complete') is True and storage_row.get('actual_executed_nonignored') == 4
                       and set(storage_row.get('bodies', {})) == set(storage.TESTS + [storage.ADDED_TEST]), 'four-reviewed-storage-controls-and-artifact-binding')
                actual = expected_transport + 4
                if cohort == 'experimental':
                    import qualify_upstream_late_consent_candidate as directed
                    directed_bytes = bundle.read('mdk/mdk/late-consent-candidate-evidence/result.json')
                    directed_row = json.loads(directed_bytes)
                    ensure(digest(directed_bytes) == row.get('directed', {}).get('sha256')
                           and directed_row.get('green_passed') is True and directed_row.get('inputs_pristine') is True
                           and directed_row.get('actual_counts_complete') is True and directed_row.get('actual_executed_nonignored') == 2
                           and directed.consent_green(directed_row.get('phases', {}).get('late_consent', {}).get('body', {}))
                           and directed.proof_green(directed_row.get('phases', {}).get('late_proof', {}).get('body', {})), 'two-reviewed-directed-controls-with-original-prerequisites-and-closes')
                    actual += 2
            else:
                static = row.get('static', {})
                ensure(row.get('focused_checks_passed') is True and static.get('exit_code') == static.get('compiler_error_count') == 0
                       and set(static.get('compiled_package_features', {})) == {name.replace('-', '_') for name in PACKAGES}
                       and static.get('production_without_test_policy') is (label == 'production'), 'both-reviewed-statics-and-production-green')
                ensure(row.get('mode') == ('production' if label == 'production' else 'static')
                       and (label == 'production' or row.get('cohort') == label.removeprefix('static-')), 'reviewed-static-mode-and-cohort')
        receipts[label] = {'artifact_id': item['id'], 'archive_sha256': checksum, 'primary_result_sha256': digest(primary),
                           'actual_runtime_bodies': actual}
    ensure(sum(row['actual_runtime_bodies'] for row in receipts.values()) == 35, 'all-35-reviewed-runtime-controls')
    return {'run_id': int(run_id), 'tested_source': CONTROL_SOURCE, 'current_source': head,
            'same_commit_claimed': False, 'metadata_only_descendant': True, 'prior_full_input_manifest_sha256': prior_manifest,
            'unchanged_nonmetadata_input_manifest_sha256': product_manifest, 'actual_prior_runtime_bodies': 35, 'receipts': receipts}


def capture_phase(label, expected, report, save):
    ensure(frozen_inputs() == expected, 'capture-phase-source-and-modes-exact-before-compilation')
    row = {'actual_counts_complete': False}
    report['capture_phases'][label] = row
    try:
        binary = compile_package('transport-nostr', 'experimental', row)
    finally:
        save()
    ensure(row['compilation'].get('sdk_dependency_verified') is True, 'actual-sdk-enabled-capture-dependency')
    sha = row['compilation']['binary_sha256']
    code, listed, _ = capture([str(binary), CAPTURE_NAME, '--exact', '--list', '--format', 'terse'], 60)
    ensure(code == 0 and [line for line in listed.splitlines() if line] == [CAPTURE_NAME + ': test', '1 test, 0 benchmarks'], 'exact-sole-capture-test-inventory')
    code, ignored, _ = capture([str(binary), CAPTURE_NAME, '--exact', '--ignored', '--list', '--format', 'terse'], 60)
    ensure(code == 0 and ignored.strip() in {'', '0 tests, 0 benchmarks'}, 'capture-case-not-ignored')
    ensure(frozen_inputs() == expected and digest(binary.read_bytes()) == sha, 'capture-phase-pristine-before-runtime')
    code, raw, seconds = capture([str(binary), CAPTURE_NAME, '--exact', '--nocapture', '--test-threads=1'], 300)
    row['body'] = dict(parse_runtime(raw, code, CAPTURE_NAME), seconds=seconds, binary_sha256=sha)
    row['actual_counts_complete'] = row['body']['actual_counts_complete']
    row['intended_capture_runtime_kill'] = capture_mutation_killed(raw, code)
    row['phase_passed'] = row['intended_capture_runtime_kill'] if label == 'mutant' else row['body']['passed_gate']
    save()
    ensure(frozen_inputs() == expected and digest(binary.read_bytes()) == sha, 'capture-phase-pristine-after-runtime')
    ensure(row['phase_passed'], 'capture-phase-did-not-meet-exact-runtime-oracle')
    return row


def capture_mutation(report, frozen, save, controls_run_id):
    report['prior_controls'] = prior_639_controls(controls_run_id, report, frozen)
    original = Path(ADAPTER).read_bytes()
    original_mode = Path(ADAPTER).stat().st_mode & 0o777
    old = b'.handle_captured_live_relay_event(account_id, relay_event, capture)'
    new = b'.handle_captured_live_relay_event(account_id, relay_event, capture.filter(|_| false))'
    ensure(original.count(old) == 1, 'unique-canonical-capture-argument-mutant')
    mutated = original.replace(old, new, 1)
    expected_mutant = dict(frozen)
    expected_mutant[ADAPTER] = dict(frozen[ADAPTER], sha256=digest(mutated))
    report['capture_phases'] = {}
    report['capture_scope'] = {'existing_case': CAPTURE_NAME, 'original_expect_line': capture_assertion_line(),
                               'native_or_mls_permission_claim': False, 'failing_path_cleanup_claim': False,
                               'legacy_wire_negative_assertion_reached_only_in_passing_controls': True}
    baseline = capture_phase('baseline', frozen, report, save)
    failure = None
    try:
        Path(ADAPTER).write_bytes(mutated)
        ensure(frozen_inputs() == expected_mutant, 'only-exact-owned-capture-substitution')
        capture_phase('mutant', expected_mutant, report, save)
    except Exception as error:
        failure = error
        report['capture_mutant_failure_type'] = type(error).__name__
        report['capture_mutant_failure_gate'] = str(error) if isinstance(error, storage.GateFailure) else None
    finally:
        Path(ADAPTER).write_bytes(original)
        os.chmod(ADAPTER, original_mode)
        report['capture_source_and_modes_restored'] = frozen_inputs() == frozen
        save()
    ensure(report['capture_source_and_modes_restored'], 'exact-capture-source-and-mode-restoration')
    restored = capture_phase('restored', frozen, report, save)
    if failure is not None:
        raise failure
    mutant = report['capture_phases']['mutant']
    fingerprints = [row['compilation'] for row in [baseline, mutant, restored]]
    ensure(fingerprints[0]['binary_sha256'] == fingerprints[2]['binary_sha256']
           and fingerprints[1]['binary_sha256'] != fingerprints[0]['binary_sha256'], 'restored-capture-binary-identical-and-mutant-different')
    ensure(all(row['compiled_features'] == fingerprints[0]['compiled_features']
               and row['all_artifact_features_sha256'] == fingerprints[0]['all_artifact_features_sha256'] for row in fingerprints), 'same-capture-compiled-feature-profile-manifest-all-three-phases')
    report['capture_binary_and_cohort_restored'] = True
    report['capture_mutation_passed'] = True



def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--mode', choices=['preflight', 'runtime', 'static', 'production', 'worker-diagnostic', 'capture-mutation'], required=True)
    parser.add_argument('--cohort', choices=['default', 'experimental'], default='experimental')
    parser.add_argument('--controls-run-id', default=os.environ.get('MERGE_639_CONTROL_RUN_ID'))
    args = parser.parse_args()
    os.umask(0o077)
    OUT.mkdir(exist_ok=True)
    report = {'mode': args.mode, 'cohort': args.cohort, 'qualification_passed': False, 'focused_checks_passed': False,
              'capture_mutation_passed': False}
    frozen = frozen_inputs()
    def save():
        (OUT / 'result.json').write_text(json.dumps(report, indent=2) + '\n')
    try:
        report['source_guard'] = source_guard()
        report['toolchain'] = {name: subprocess.check_output([name, '--version'], text=True).strip() for name in ['cargo', 'rustc']}
        report['parser_fixtures'] = parser_preflight()
        report['capture_parser_fixtures'] = capture_parser_preflight()
        save()
        if args.mode == 'preflight':
            report['storage'] = storage_controls('default', preflight=True)
            report['directed'] = directed_controls(preflight=True)
            report['preflight_passed'] = True
        elif args.mode == 'runtime':
            report['storage'] = storage_controls(args.cohort)
            transport_controls(args.cohort, report, frozen, save)
            if args.cohort == 'experimental':
                report['directed'] = directed_controls()
            report['focused_checks_passed'] = True
        elif args.mode == 'worker-diagnostic':
            ensure(args.cohort == 'default', 'worker-diagnostic-default-one-body-only')
            transport_controls(args.cohort, report, frozen, save, worker_only=True)
            report['diagnostic_case_passed_existing_strict_oracle'] = True
        elif args.mode == 'capture-mutation':
            ensure(args.cohort == 'experimental', 'capture-mutation-experimental-only')
            capture_mutation(report, frozen, save, args.controls_run_id)
        else:
            static_checks(args.cohort, args.mode == 'production', report)
            report['focused_checks_passed'] = True
    except Exception as error:
        report['failure_type'] = type(error).__name__
        report['failure_gate'] = str(error) if isinstance(error, storage.GateFailure) else None
        raise SystemExit(1)
    finally:
        bodies = [body for package in report.get('transport', {}).values() for body in package['bodies'].values()]
        report['expected_transport_bodies'] = 1 if args.mode == 'worker-diagnostic' else 13 if args.cohort == 'experimental' else 12
        report['actual_transport_counts_complete'] = len(bodies) == report['expected_transport_bodies'] and all(row['actual_counts_complete'] for row in bodies)
        report['actual_transport_executed_nonignored'] = sum(row['executed_nonignored'] for row in bodies) if bodies and all(row['actual_counts_complete'] for row in bodies) else None
        phases = report.get('capture_phases', {})
        report['capture_actual_counts_complete'] = set(phases) == {'baseline', 'mutant', 'restored'} and all(row.get('actual_counts_complete') is True for row in phases.values())
        report['capture_actual_executed_nonignored'] = sum(row['body']['executed_nonignored'] for row in phases.values()) if report['capture_actual_counts_complete'] else None
        for name in ['passed', 'failed', 'ignored']:
            report['capture_actual_' + name] = sum(row['body'][name] for row in phases.values()) if report['capture_actual_counts_complete'] else None
        report['inputs_pristine'] = frozen_inputs() == frozen
        save()
        if not report['inputs_pristine']:
            raise SystemExit(1)


if __name__ == '__main__':
    main()
