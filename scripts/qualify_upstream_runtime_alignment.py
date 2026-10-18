#!/usr/bin/env python3
"""Required production, serial-stress and paused-clock runtime alignment controls."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import qualify_upstream_recipient_admission_candidate as historical
import qualify_upstream_storage_boundary as bounded
from qualify_upstream_body_negative import freeze, layout, feature_identity
from upstream_completion_ci import ORIGINALS, compile_cases, digest, ensure, environment, identity, parse_body

BASE = '714c8db51e8645146268e1cd18316fe1a534dca4'
RUST_BASE = '4dc7ed5101b2be35bd273ff67ea10bdc684cd617'
MANIFEST = 'scripts/upstream_runtime_alignment_manifest.json'
MANIFEST_SHA256 = 'ea359b11990ff02e745be84f600ca781a03568df59145c610be32454676044e6'
SELF = 'scripts/qualify_upstream_runtime_alignment.py'
WORKFLOW = '.github/workflows/experimental-sync-ci.yml'
REF = 'refs/heads/ci/upstream-runtime-alignment-20261018'
BEGIN = '  # RUNTIME_ALIGNMENT_JOBS_BEGIN\n'
END = '  # RUNTIME_ALIGNMENT_JOBS_END\n'
OPTIONS = 'options: [runtime-alignment-preflight, runtime-alignment-controls, runtime-alignment-clock-preflight, runtime-alignment-clock-red, '
OUT = Path('runtime-alignment-evidence')
PAIR_FILE = 'crates/marmot-app/src/native_device_linking/tests/automatic_pairing_acceptance.rs'
CLOCK_FILE = 'crates/marmot-app/src/runtime/device_linking.rs'
CLOCK_CASE = 'device_linking_worker_private_commit_deadline_actively_wakes_stalled_network'
CLOCK_NAME = 'runtime::device_linking::tests::' + CLOCK_CASE
POLICY_CASE = 'async_suites_choose_their_tokio_flavor'
POLICY_NAME = 'runtime::tests::' + POLICY_CASE
CLOCK_PANIC = '`time::pause()` requires the `current_thread` Tokio runtime. This is the default Runtime used by `#[tokio::test].'
TOKIO_VERSION = '1.53.1'
TOKIO_SOURCE = 'https://github.com/tokio-rs/tokio/blob/tokio-1.53.1/tokio/src/time/clock.rs'
PREFIX = 'native_device_linking::automatic_pairing_acceptance::'
STRESS_NAMES = ['single_thread_stress_four_device_enrollment', 'single_thread_stress_blocked_sibling_consent',
                'single_thread_stress_foreground_enrollment']
STRESS_BLOCK = '''// RUNTIME_SERIAL_STRESS_BEGIN
// One-thread stress retains the original serial-executor enrollment scenario.
#[tokio::test(flavor = "current_thread")]
async fn single_thread_stress_four_device_enrollment() {
    four_device_enrollment(HeldPublication::None).await;
}

// One-thread stress retains blocked-Consent fairness on the original executor.
#[tokio::test(flavor = "current_thread")]
async fn single_thread_stress_blocked_sibling_consent() {
    four_device_enrollment(HeldPublication::SiblingConsent).await;
}

// One-thread stress retains foreground enrollment under an automatic hold.
#[tokio::test(flavor = "current_thread")]
async fn single_thread_stress_foreground_enrollment() {
    four_device_enrollment(HeldPublication::Automatic).await;
}
// RUNTIME_SERIAL_STRESS_END

'''.encode()
STRESS_ANCHOR = b'// COMPLETION_TEST_BEGIN\n#[cfg(feature = "test-policy-overrides")]\n#[tokio::test(flavor = "multi_thread", worker_threads = 2)]\nasync fn completed_sibling_consent_services_initial_progress_without_periodic_tick() {'
CLOCK_RATIONALE = "    // Pauses Tokio's clock after actual publication entry; this requires one thread.\n"
# label, inventory suffix, actual full name, historical oracle label (if any)
CASES = [('policy', POLICY_CASE, POLICY_NAME, None)]
CASES += [(label, suffix, name, label) for label, suffix, name in historical.CASES]
CASES += [('stress_' + str(index), suffix, PREFIX + suffix, 'original_' + str(index)) for index, suffix in enumerate(STRESS_NAMES)]
CASES += [('paused_clock', CLOCK_CASE, CLOCK_NAME, None)]


def expected_file(name, base, entry, manifest):
    ensure(entry['baseline_git_mode'] == '100644' and digest(base) == entry['before_sha256'], 'manifest-frozen-baseline-content')
    blob = hashlib.sha1(b'blob ' + str(len(base)).encode() + b'\0' + base).hexdigest()
    ensure(blob == entry['baseline_blob_sha1'], 'manifest-frozen-baseline-blob')
    occurrences = [match.start() for match in re.finditer(rb'#\[tokio::test', base)]
    replacements = []
    for change in entry['changes']:
        offset, ordinal = change['baseline_byte_offset'], change['attribute_ordinal']
        ensure(type(offset) is int and offset >= 0 and type(ordinal) is int and 0 < ordinal <= len(occurrences), 'typed-baseline-offset-ordinal')
        before, after = change['before_bytes_utf8'].encode(), change['after_bytes_utf8'].encode()
        ensure(base[offset:offset + len(before)] == before and occurrences[ordinal - 1] == offset + before.index(b'#[tokio::test'), 'exact-original-attribute-position')
        ensure(base[:offset].count(b'\n') + 1 == change['baseline_line'], 'exact-original-line')
        function = re.search(rb'\basync fn ([A-Za-z0-9_]+)\b', base[offset + len(before):offset + len(before) + 1024])
        ensure(function is not None and function[1].decode() == change['function'], 'exact-original-function')
        if change['kind'] == 'bare_to_production_multi_thread':
            indent = before.split(b'#', 1)[0]
            ensure(not indent.strip() and before == indent + b'#[tokio::test]\n'
                   and after == indent + b'#[tokio::test(flavor = "multi_thread", worker_threads = 2)]\n', 'only-bare-to-two-worker-attribute')
        else:
            ensure(change['kind'] == 'existing_multithread_to_required_paused_clock_single_thread'
                   and name == CLOCK_FILE and change['function'] == CLOCK_CASE
                   and before == b'    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]\n'
                   and change['new_rationale_bytes_utf8'] == CLOCK_RATIONALE
                   and after == CLOCK_RATIONALE.encode() + b'    #[tokio::test(flavor = "current_thread")]\n', 'only-reviewed-real-paused-clock-exception')
        replacements.append((offset, before, after))
    replacements.sort()
    ensure(all(left[0] + len(left[1]) <= right[0] for left, right in zip(replacements, replacements[1:])), 'nonoverlapping-declared-attributes')
    result = base
    for offset, before, after in reversed(replacements):
        result = result[:offset] + after + result[offset + len(before):]
    if name == PAIR_FILE:
        stress = manifest['required_stress_block']
        ensure(stress['path'] == name and stress['block_bytes_utf8'].encode() == STRESS_BLOCK
               and stress['insert_before_after_attribute_migration_bytes_utf8'].encode() == STRESS_ANCHOR
               and result.count(STRESS_ANCHOR) == 1 and STRESS_BLOCK not in result
               and stress['all_cases_required'] is True and stress['ignore'] is False
               and stress['additional_cfg_exclusions'] is False and stress['helper_body_or_deadline_changes'] is False,
               'literal-required-stress-block-with-no-body-or-coverage-waiver')
        ensure(stress['cases'] == [{'function': suffix, 'original_function': ORIGINALS[index],
                                   'helper_call': 'four_device_enrollment(HeldPublication::' + ['None', 'SiblingConsent', 'Automatic'][index] + ').await;'}
                                  for index, suffix in enumerate(STRESS_NAMES)], 'exact-three-original-scenario-wrappers')
        result = result.replace(STRESS_ANCHOR, STRESS_BLOCK + STRESS_ANCHOR, 1)
    ensure(digest(result) == entry['after_sha256'], 'reviewed-whole-adapted-file-hash')
    return result


def source_guard(requested_mode):
    source = subprocess.check_output(['git', 'rev-parse', 'HEAD'], text=True).strip()
    ensure(os.environ.get('GITHUB_ACTIONS') == 'true' and os.environ.get('GITHUB_REPOSITORY') == 'dyKiU/mdk'
           and os.environ.get('GITHUB_EVENT_NAME') == 'workflow_dispatch' and source == os.environ.get('GITHUB_SHA')
           and os.environ.get('GITHUB_REF') == REF
           and os.environ.get('GITHUB_WORKFLOW_REF') == 'dyKiU/mdk/' + WORKFLOW + '@' + REF
           and os.environ.get('UPSTREAM_RUNTIME_ALIGNMENT_BASELINE') == BASE, 'exact-reviewed-remote-source-and-workflow')
    ensure(os.environ.get('CARGO_INCREMENTAL') == '1' and os.environ.get('CARGO_BUILD_JOBS') == '2'
           and os.environ.get('RUST_MIN_STACK') == '4194304', 'fixed-runtime-capacity')
    ensure(all(os.environ.get(key) == '0' for key in ['CARGO_PROFILE_DEV_DEBUG', 'CARGO_PROFILE_TEST_DEBUG']), 'fixed-debug-profile')
    ensure(all(not os.environ.get(key) for key in ['RUSTFLAGS', 'CARGO_ENCODED_RUSTFLAGS', 'RUSTC_BOOTSTRAP',
               'CARGO_PROFILE_DEV_OPT_LEVEL', 'CARGO_PROFILE_TEST_OPT_LEVEL']), 'no-compiler-overrides')
    subprocess.run(['git', 'merge-base', '--is-ancestor', BASE, source], check=True)
    ensure(subprocess.run(['git', 'diff', '--quiet', 'HEAD']).returncode == 0, 'initial-pristine-inputs')
    data = Path(MANIFEST).read_bytes()
    ensure(digest(data) == MANIFEST_SHA256 and len(data) < 500_000, 'exact-reviewed-bounded-adaptation-manifest')
    manifest = json.loads(data)
    ensure(manifest['schema_version'] == 1 and manifest['baseline'] == RUST_BASE and manifest['authoring_metadata_head'] == BASE
           and manifest['bare_attribute_changes'] == 176 and manifest['clock_exception_changes'] == 1
           and manifest['new_required_stress_cases'] == 3 and manifest['stress_failure_blocks_promotion'] is True
           and manifest['two_worker_green_does_not_resolve_single_thread_failure'] is True
           and manifest['ignored_or_new_cfg_exclusions'] is False and len(manifest['paths']) == 31, 'reviewed-runtime-only-adaptation-contract')
    changes = [change for entry in manifest['paths'].values() for change in entry['changes']]
    ensure(sum(change['kind'] == 'bare_to_production_multi_thread' for change in changes) == 176
           and sum(change['kind'] == 'existing_multithread_to_required_paused_clock_single_thread' for change in changes) == 1
           and len(changes) == 177, 'exact-attribute-change-inventory')
    baseline = {}
    for entry in subprocess.check_output(['git', 'ls-tree', '-r', '-z', BASE]).split(b'\0'):
        if entry:
            metadata, name = entry.split(b'\t', 1)
            mode, kind, blob = metadata.decode().split()
            ensure(kind == 'blob' and mode in {'100644', '100755', '120000'}, 'ordinary-baseline-tree')
            baseline[os.fsdecode(name)] = (mode, blob)
    current = layout()
    ensure(SELF not in baseline and MANIFEST not in baseline and set(current) == set(baseline) | {SELF, MANIFEST}, 'whole-input-inventory')
    ensure(all(name in baseline and name.startswith('crates/marmot-app/src/') and name.endswith('.rs') for name in manifest['paths']), 'only-reviewed-existing-Rust-paths')
    for name, metadata in current.items():
        mode, blob = baseline.get(name, ('100644', None))
        ensure(metadata['git_mode'] == mode and metadata['symlink'] == (mode == '120000')
               and (metadata['symlink'] or metadata['actual_executable'] == (mode == '100755')), 'whole-input-mode:' + name)
        content = os.fsencode(os.readlink(name)) if metadata['symlink'] else Path(name).read_bytes()
        if name in manifest['paths']:
            original = subprocess.check_output(['git', 'show', BASE + ':' + name])
            ensure(original == subprocess.check_output(['git', 'show', RUST_BASE + ':' + name]), 'baseline-Rust-identical-to-historical-cohort')
            adapted = expected_file(name, original, manifest['paths'][name], manifest)
            ensure(content == (original if requested_mode == 'clock-red' else adapted),
                   'whole-file-exact-unmigrated-clock-RED-or-reviewed-alignment:' + name)
        elif blob is not None:
            if name == WORKFLOW:
                text = content.decode()
                ensure(text.count(BEGIN) == text.count(END) == text.count(OPTIONS) == 1, 'isolated-workflow-overlay')
                before, rest = text.split(BEGIN); _, after = rest.split(END)
                content = (before + after).replace(OPTIONS, 'options: [', 1).encode()
            ensure(hashlib.sha1(b'blob ' + str(len(content)).encode() + b'\0' + content).hexdigest() == blob, 'every-other-original-input-unchanged:' + name)
    ensure(set(subprocess.check_output(['git', 'ls-files', '--others', '--exclude-standard'], text=True).splitlines()) <= {str(OUT / 'result.json')}, 'no-untracked-source-overlays')
    return {'source': source, 'mode': requested_mode, 'runtime_source_unmigrated': requested_mode == 'clock-red', 'baseline': BASE, 'Rust_baseline': RUST_BASE, 'manifest_sha256': MANIFEST_SHA256,
            'all_original_content_modes_and_exact_runtime_adaptations_verified': requested_mode != 'clock-red',
            'all_original_Rust_content_and_modes_baseline_exact': requested_mode == 'clock-red',
            'unmodified_historical_helpers': True, 'original_test_bodies_names_assertions_deadlines_preserved': True,
            'required_production_controls': 8, 'required_serial_stress_controls': 3,
            'required_source_policy_controls': 1, 'required_paused_clock_controls': 1,
            'historical_runtime_evidence_reused': False, 'single_thread_failures_not_erased': True}


def complete_counts(body):
    return (all(type(body.get(key)) is int and body[key] >= 0 for key in ['passed', 'failed', 'ignored', 'executed_nonignored'])
            and body['passed'] + body['failed'] == body['executed_nonignored']
            and body['executed_nonignored'] + body['ignored'] == 1)


def aggregate_counts(rows):
    result = {'unknown_count_cases': [label for label, row in rows.items() if not row.get('actual_counts_complete')],
              'aggregate_exact_numeric_counts_require_every_receipt': True, 'known_partial_counts': {}}
    for field, output in [('executed_nonignored', 'actual_executed_nonignored'), ('passed', 'actual_passed'),
                          ('failed', 'actual_failed'), ('ignored', 'actual_ignored')]:
        values = [row.get('body', {}).get(field) for row in rows.values()]
        observed = [value for value in values if type(value) is int and value >= 0]
        result['known_partial_counts'][output] = sum(observed)
        result[output] = sum(observed) if len(observed) == len(values) else None
    return result


def parse_case(label, raw, code):
    selected = next(item for item in CASES if item[0] == label)
    _, suffix, name, oracle = selected
    if oracle is not None:
        row = historical.parse(oracle, raw, code)
    else:
        clean = re.sub(r'\x1b\[[0-9;]*m', '', raw)
        row = dict(parse_body(clean, suffix), body_exit_code=code,
                   compiler_error_count=len(re.findall(r'^error(?:\[E[0-9]+\])?:', clean, re.M)),
                   executed_case_names=re.findall(r'(?m)^test ([A-Za-z_0-9:]+) \.\.\.', clean),
                   running_counts=[int(value) for value in re.findall(r'(?m)^running ([0-9]{1,3}) tests?$', clean)])
    row['actual_required_name'] = name
    return row


def case_green(label, row):
    _, suffix, name, oracle = next(item for item in CASES if item[0] == label)
    if row.get('executed_case_names') != [name]:
        return False
    if oracle is not None:
        # The new literal stress wrapper calls the identical frozen scenario.
        # Verify its actual new name first; adapt only the expected-name field
        # for the unchanged original scenario oracle, not the persisted row.
        expected = next(old_name for old_label, _, old_name in historical.CASES if old_label == oracle)
        return historical.runtime_green(oracle, dict(row, executed_case_names=[expected]))
    return (all(type(row.get(key)) is int and row[key] == value for key, value in
                {'body_exit_code': 0, 'passed': 1, 'failed': 0, 'ignored': 0, 'executed_nonignored': 1,
                 'compiler_error_count': 0, 'all_panic_header_count': 0}.items())
            and row.get('running_counts') == [1] and not row.get('watchdog_triggered') and not row.get('actual_count_unknown'))


def parser_controls():
    inherited = historical.parser_controls()
    count = 0
    for label, suffix, name, _ in [CASES[0], *CASES[-4:]]:
        markers = ''
        if label.startswith('stress_'):
            markers = ''.join('automatic-enrollment-control stage=' + stage + '\n' for stage in
                              ['third-device-completion', 'third-device-completed', 'fourth-device-completion', 'fourth-device-completed'])
            if label == 'stress_1': markers += 'automatic-enrollment-control stage=sibling-consent-held-before-peer-progress\n'
            if label == 'stress_2': markers += 'automatic-enrollment-control stage=automatic-publication-held-before-completion\n'
        raw = 'running 1 test\ntest ' + name + ' ... ok\n' + markers + 'test result: ok. 1 passed; 0 failed; 0 ignored;\n'
        row = parse_case(label, raw, 0)
        ensure(case_green(label, row), 'new-policy-stress-clock-green-parser-positive')
        for altered in [raw.replace(name, 'foreign::case'), raw.replace('1 passed', '0 passed'), raw.replace('0 ignored', '1 ignored'),
                        raw.replace('running 1 test', 'running 0 tests'), raw + '\nthread unrelated panicked at crates/other.rs:1:1:\n',
                        'error: compile failed\n']:
            ensure(not case_green(label, parse_case(label, altered, 0)), 'new-control-false-green-negative'); count += 1
        for changed in [{'passed': True}, {'body_exit_code': 101}, {'compiler_error_count': 1}, {'watchdog_triggered': True},
                        {'actual_count_unknown': True}, {'executed_case_names': [name, name]}]:
            ensure(not case_green(label, dict(row, **changed)), 'new-control-identity-count-watchdog-negative'); count += 1
        if label.startswith('stress_'):
            ensure(not case_green(label, parse_case(label, raw.replace('automatic-enrollment-control stage=fourth-device-completed\n', ''), 0)), 'stress-original-oracle-not-waived'); count += 1
    observed = {'passed': {'actual_counts_complete': True, 'body': {'passed': 1, 'failed': 0, 'ignored': 0, 'executed_nonignored': 1}},
                'ignored': {'actual_counts_complete': True, 'body': {'passed': 0, 'failed': 0, 'ignored': 1, 'executed_nonignored': 0}}}
    totals = aggregate_counts(observed)
    ensure(totals['actual_passed'] == 1 and totals['actual_ignored'] == 1
           and totals['actual_executed_nonignored'] == 1, 'observed-skips-remain-visible')
    observed['unknown'] = {'actual_counts_complete': False, 'watchdog_triggered': True}
    totals = aggregate_counts(observed)
    ensure(all(totals[key] is None for key in ['actual_passed', 'actual_failed', 'actual_ignored', 'actual_executed_nonignored'])
           and totals['known_partial_counts']['actual_passed'] == totals['known_partial_counts']['actual_ignored'] == 1
           and totals['unknown_count_cases'] == ['unknown'], 'unknown-counts-never-become-exact-partial-totals')
    return {'unchanged_eight_oracles': inherited, 'new_control_positive': 5, 'new_control_negative': count,
            'aggregate_count_controls': 2, 'runtime_bodies': 0}


def clock_pause_line():
    lines = Path(CLOCK_FILE).read_text().splitlines()
    starts = [index for index, line in enumerate(lines) if ('async fn ' + CLOCK_CASE + '(') in line]
    ensure(len(starts) == 1, 'exact-original-paused-clock-function')
    matches = [index + 1 for index in range(starts[0], min(len(lines), starts[0] + 100))
               if lines[index].strip() == 'tokio::time::pause();']
    ensure(len(matches) == 1, 'exact-unchanged-pause-call')
    return matches[0]


def clock_red_parse(raw, code):
    clean = re.sub(r'\x1b\[[0-9;]*m', '', raw)
    row = dict(parse_body(clean, CLOCK_CASE), body_exit_code=code,
               compiler_error_count=len(re.findall(r'^error(?:\[E[0-9]+\])?:', clean, re.M)),
               executed_case_names=re.findall(r'(?m)^test ([A-Za-z_0-9:]+) \.\.\.', clean),
               running_counts=[int(value) for value in re.findall(r'(?m)^running ([0-9]{1,3}) tests?$', clean)])
    row['closed_pause_runtime_panic_count'] = len(re.findall(r'(?m)^' + re.escape(CLOCK_PANIC) + r'$', clean))
    row['panic_code'] = 'TokioPauseRequiresCurrentThread' if row['closed_pause_runtime_panic_count'] == 1 else 'Unknown'
    return row


def clock_red(row):
    locations = row.get('panic_locations', [])
    return (all(type(row.get(key)) is int and row[key] == value for key, value in
                {'body_exit_code': 101, 'passed': 0, 'failed': 1, 'ignored': 0, 'executed_nonignored': 1,
                 'compiler_error_count': 0, 'all_panic_header_count': 1, 'closed_pause_runtime_panic_count': 1}.items())
            and row.get('executed_case_names') == [CLOCK_NAME] and row.get('running_counts') == [1]
            and len(locations) == 1 and locations[0]['file'] == CLOCK_FILE and locations[0]['line'] == clock_pause_line()
            and not row.get('watchdog_triggered') and not row.get('actual_count_unknown'))


def clock_parser_controls():
    raw = ('running 1 test\ntest ' + CLOCK_NAME + ' ... FAILED\nthread case panicked at ' + CLOCK_FILE
           + ':' + str(clock_pause_line()) + ':9:\n' + CLOCK_PANIC + '\ntest result: FAILED. 0 passed; 1 failed; 0 ignored;\n')
    row = clock_red_parse(raw, 101)
    ensure(clock_red(row), 'original-paused-clock-runtime-RED-parser-positive')
    changes = [{'body_exit_code': 0}, {'passed': 1}, {'failed': 0}, {'ignored': 1}, {'executed_nonignored': 0},
               {'compiler_error_count': 1}, {'all_panic_header_count': 2}, {'closed_pause_runtime_panic_count': 0},
               {'executed_case_names': [CLOCK_NAME + '_other']}, {'running_counts': [0]}, {'panic_locations': []},
               {'panic_locations': [{'file': CLOCK_FILE, 'line': clock_pause_line() + 1, 'column': 9}]},
               {'watchdog_triggered': True}, {'actual_count_unknown': True}]
    for change in changes:
        ensure(not clock_red(dict(row, **change)), 'nonruntime-or-unrelated-clock-RED-rejected')
    return {'positive': 1, 'negative': len(changes), 'runtime_bodies': 0}


def static_command(cohort):
    return historical.static_command(cohort)


def main(options):
    os.umask(0o077); OUT.mkdir(exist_ok=True)
    report = {'mode': options.mode, 'qualification_passed': False, 'native_acceptance_claim': False,
              'mutation_eligible_claim': False, 'mutations_executed': False, 'actual_counts_complete': False,
              'production_eight_green': False, 'source_policy_green': False, 'required_serial_stress_green': False,
              'required_paused_clock_green': False, 'all_thirteen_controls_green': False, 'clock_runtime_red_verified': False, 'cases': {}}
    before = None; modes = None
    def save(): (OUT / 'result.json').write_text(json.dumps(report, indent=2) + '\n')
    try:
        report['source_guard'] = source_guard(options.mode); report['parser_controls'] = parser_controls()
        report['clock_parser_controls'] = clock_parser_controls(); save()
        if options.preflight:
            report['preflight_passed'] = True; save(); return
        report['environment'] = environment()
        before, modes = freeze(), layout()
        report['input_manifest_sha256'] = identity(before)
        if options.mode == 'static':
            ensure(options.cohort in {'default', 'experimental'}, 'explicit-static-cohort')
            command = static_command(options.cohort)
            code, raw, seconds = bounded.capture(command, 1800, limit=8 * 1024 * 1024)
            report.update(cohort=options.cohort, command=command, exit_code=code, seconds=seconds,
                          compiler_error_count=len(re.findall(r'^error(?:\[E[0-9]+\])?:', raw, re.M)))
            report['static_passed'] = code == report['compiler_error_count'] == 0; save()
            ensure(report['static_passed'], 'actual-strict-App-static-cohort-required')
            return
        if options.mode == 'clock-red':
            lock = Path('Cargo.lock').read_text()
            ensure(('name = "tokio"\nversion = "' + TOKIO_VERSION + '"') in lock, 'reviewed-locked-Tokio-panic-contract')
            report['tokio_panic_contract'] = {'version': TOKIO_VERSION, 'source': TOKIO_SOURCE,
                                               'panic_code': 'TokioPauseRequiresCurrentThread',
                                               'runtime_execution_required_docs_alone_not_RED': True}
            compilation, cases = compile_cases([CLOCK_CASE])
            report['compilation'] = compilation; save()
            ensure(compilation.get('compile_exit_code') == compilation.get('compiler_error_count') == 0
                   and compilation.get('compiled_fingerprints', {}).get('verified') is True
                   and set(cases) == {CLOCK_CASE} and cases[CLOCK_CASE]['name'] == CLOCK_NAME, 'actual-one-frozen-clock-RED-body')
            report['feature_identity'] = feature_identity(compilation)
            case = cases[CLOCK_CASE]
            ensure(freeze() == before and layout() == modes and digest(Path(case['binary']).read_bytes()) == case['binary_sha256'], 'before-clock-RED-source-modes-binary')
            try:
                code, raw, seconds = bounded.capture([case['binary'], '--exact', CLOCK_NAME, '--nocapture', '--test-threads=1'], 300, limit=8 * 1024 * 1024)
            except bounded.GateFailure as error:
                report['watchdog_triggered'] = str(error) == 'bounded-command-timeout'
                report['output_limit_triggered'] = str(error) == 'bounded-command-output-limit'
                raise ValueError('clock-RED-did-not-execute-completely') from None
            row = clock_red_parse(raw, code)
            report['clock_runtime_red'] = dict(row, seconds=seconds, compiled_binary_sha256=case['binary_sha256'])
            report['actual_counts_complete'] = (all(type(row.get(key)) is int for key in ['passed', 'failed', 'ignored', 'executed_nonignored'])
                                                and row['passed'] + row['failed'] == row['executed_nonignored'] == 1 and row['ignored'] == 0)
            save()
            ensure(clock_red(row), 'sole-original-actual-Tokio-pause-runtime-panic-required')
            report['original_preparation_and_blocked_publication_reached_before_pause'] = True
            report['clock_runtime_red_verified'] = True
            report['positive_native_closure_claim'] = False
            ensure(digest(Path(case['binary']).read_bytes()) == case['binary_sha256'], 'clock-RED-binary-pristine')
            return
        ensure(options.mode == 'controls' and len(CASES) == 13, 'thirteen-required-cases-no-mutation-mode')
        compilation, cases = compile_cases([suffix for _, suffix, _, _ in CASES])
        report['compilation'] = compilation; save()
        ensure(compilation.get('compile_exit_code') == compilation.get('compiler_error_count') == 0
               and compilation.get('compiled_fingerprints', {}).get('verified') is True
               and set(cases) == {suffix for _, suffix, _, _ in CASES}, 'real-feature-verified-thirteen-case-compile')
        ensure(all(cases[suffix]['name'] == name for _, suffix, name, _ in CASES)
               and len({case['binary_sha256'] for case in cases.values()}) == 1, 'exact-full-inventory-one-real-binary')
        report['feature_identity'] = feature_identity(compilation)
        report['compiled_binary_sha256'] = next(iter(cases.values()))['binary_sha256']
        for label, suffix, name, oracle in CASES:
            case = cases[suffix]
            ensure(freeze() == before and layout() == modes and digest(Path(case['binary']).read_bytes()) == case['binary_sha256'], 'before-each-case-pristine-source-modes-binary')
            row = {'actual_counts_complete': False, 'green': False, 'actual_required_name': name,
                   'historical_oracle_label': oracle, 'compiled_binary_sha256': case['binary_sha256']}
            report['cases'][label] = row; save()
            try:
                code, raw, seconds = bounded.capture([case['binary'], '--exact', name, '--nocapture', '--test-threads=1'], 300, limit=8 * 1024 * 1024)
                row['body'] = dict(parse_body(raw, suffix), body_exit_code=code)
                row['seconds'] = seconds
                row['actual_counts_complete'] = complete_counts(row['body']); save()
                row['body'] = parse_case(label, raw, code)
                row['seconds'] = seconds
                body = row['body']
                row['actual_counts_complete'] = complete_counts(body)
                row['green'] = row['actual_counts_complete'] and case_green(label, body)
            except bounded.GateFailure as error:
                row['watchdog_triggered'] = str(error) == 'bounded-command-timeout'
                row['output_limit_triggered'] = str(error) == 'bounded-command-output-limit'
            except ValueError:
                row['parser_rejected'] = True
            ensure(freeze() == before and layout() == modes and digest(Path(case['binary']).read_bytes()) == case['binary_sha256'], 'after-each-case-pristine-source-modes-binary')
            save()
            # Ordinary runtime failures never stop later required stress bodies.
        report['production_eight_green'] = all(report['cases'][label]['green'] for label, _, _ in historical.CASES)
        report['source_policy_green'] = report['cases']['policy']['green']
        report['required_serial_stress_green'] = all(report['cases']['stress_' + str(index)]['green'] for index in range(3))
        report['required_paused_clock_green'] = report['cases']['paused_clock']['green']
        report['actual_counts_complete'] = all(row['actual_counts_complete'] for row in report['cases'].values())
        report.update(aggregate_counts(report['cases']))
        report['all_thirteen_controls_green'] = (report['actual_counts_complete'] and report['actual_executed_nonignored'] == 13
                                                 and all(row['green'] for row in report['cases'].values()))
        save()
        ensure(report['all_thirteen_controls_green'], 'every-production-policy-serial-stress-and-clock-body-required')
    except Exception as error:
        report['exception_type'] = type(error).__name__
        raise
    finally:
        if before is not None:
            report['inputs_pristine'] = freeze() == before and layout() == modes
            report['source_after_sha256'] = identity(freeze())
        save()
        if before is not None: ensure(report['inputs_pristine'], 'final-inputs-pristine')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--preflight', action='store_true')
    parser.add_argument('--mode', choices=['controls', 'static', 'clock-red'], default='controls')
    parser.add_argument('--cohort', choices=['default', 'experimental'])
    main(parser.parse_args())
