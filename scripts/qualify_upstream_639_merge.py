#!/usr/bin/env python3
"""Focused remote checks of the reviewed 639 merge; no final qualification claim."""
import argparse
import json
import os
from pathlib import Path
import re
import subprocess
import sys
from types import SimpleNamespace

import qualify_upstream_storage_boundary as storage
from upstream_extraction_cohort import frozen_inputs

BASE = 'db130f31a90210abd3f40991328032814d1cc65c'
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
    restored = (before + after).replace('options: [639-preflight, 639-controls, 639-worker-diagnostic, 639-static-diagnostic, ', 'options: [', 1)
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


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--mode', choices=['preflight', 'runtime', 'static', 'production', 'worker-diagnostic'], required=True)
    parser.add_argument('--cohort', choices=['default', 'experimental'], default='experimental')
    args = parser.parse_args()
    os.umask(0o077)
    OUT.mkdir(exist_ok=True)
    report = {'mode': args.mode, 'cohort': args.cohort, 'qualification_passed': False, 'focused_checks_passed': False}
    frozen = frozen_inputs()
    def save():
        (OUT / 'result.json').write_text(json.dumps(report, indent=2) + '\n')
    try:
        report['source_guard'] = source_guard()
        report['toolchain'] = {name: subprocess.check_output([name, '--version'], text=True).strip() for name in ['cargo', 'rustc']}
        report['parser_fixtures'] = parser_preflight()
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
        report['inputs_pristine'] = frozen_inputs() == frozen
        save()
        if not report['inputs_pristine']:
            raise SystemExit(1)


if __name__ == '__main__':
    main()
