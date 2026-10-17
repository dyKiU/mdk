#!/usr/bin/env python3
"""Frozen real ACK-retention controls; no mutation or native/full qualification."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import qualify_upstream_request_retry_candidate as candidate
import qualify_upstream_runtime_alignment as alignment
import qualify_upstream_storage_boundary as bounded
from qualify_upstream_body_negative import freeze, layout, feature_identity
from upstream_completion_ci import compile_cases, digest, ensure, environment, identity, parse_body

# Provisional reviewed parent. Repin ONLY if root supplies a new formatted base.
BASE = '731914e39ecdaa595cd7db46c902ad994fcd98c3'
SELF = 'scripts/qualify_upstream_request_retry_ack.py'
WORKFLOW = '.github/workflows/experimental-sync-ci.yml'
REF = 'refs/heads/ci/upstream-request-retry-20261018'
PROBE = 'crates/marmot-app/src/client/device_linking/sibling_sharing/peer_proof_probe/retry_completion.rs'
FIXTURE = 'crates/marmot-app/src/native_device_linking/tests/request_retry_ack_acceptance.rs'
REGISTRATION = 'crates/marmot-app/src/native_device_linking/tests/automatic_pairing_acceptance.rs'
# Complete reviewed source snapshots, not a blanket test-source exception.
PROBE_SHA256 = 'd2306a26500a56e6bd0212e17187689d7eedd5d4624314d89c2c45713c61707e'
FIXTURE_SHA256 = 'cf772684f16c65c464435cce3602b6fe5d62815ff8a1ef56057afc098b3a41f1'
REGISTER = b'''// REQUEST_RETRY_ACK_TEST_BEGIN
#[cfg(all(test, feature = "test-policy-overrides"))]
#[path = "request_retry_ack_acceptance.rs"]
mod request_retry_ack_acceptance;
// REQUEST_RETRY_ACK_TEST_END
'''
REGISTER_ANCHOR = b'// REQUEST_RETRY_TEST_BEGIN\n'
BEGIN = '  # REQUEST_RETRY_ACK_JOBS_BEGIN\n'
END = '  # REQUEST_RETRY_ACK_JOBS_END\n'
OPTIONS = 'options: [request-retry-ack-preflight, request-retry-ack-full, request-retry-ack-focused, '
OUT = Path('request-retry-ack-evidence')
PREFIX = 'native_device_linking::automatic_pairing_acceptance::request_retry_ack_acceptance::'
NEGATIVE_CASES = [('initial_ack', 'authenticated_consent_cannot_retire_initial_request_ack', 'initial'),
                  ('proof_ack', 'authenticated_peer_proof_cannot_replace_own_proof_ack', 'proof')]
FIELDS = ['exact_request', 'initial_owned', 'real_sdk_ack_held', 'consent_bound', 'phase_prerequisites',
          'protected_window', 'normal_release', 'enrollment_complete', 'public_cancelled', 'guards_released']
CASES = list(candidate.CASES) + [(label, suffix, PREFIX + suffix, None) for label, suffix, _ in NEGATIVE_CASES]


def source_guard():
    ensure(all(re.fullmatch(r'[0-9a-f]{64}', value) for value in [PROBE_SHA256, FIXTURE_SHA256]), 'final-reviewed-test-and-probe-hashes-required')
    source = subprocess.check_output(['git', 'rev-parse', 'HEAD'], text=True).strip()
    ensure(os.environ.get('GITHUB_ACTIONS') == 'true' and os.environ.get('GITHUB_REPOSITORY') == 'dyKiU/mdk'
           and os.environ.get('GITHUB_EVENT_NAME') == 'workflow_dispatch' and source == os.environ.get('GITHUB_SHA')
           and os.environ.get('GITHUB_REF') == REF
           and os.environ.get('GITHUB_WORKFLOW_REF') == 'dyKiU/mdk/' + WORKFLOW + '@' + REF
           and os.environ.get('UPSTREAM_REQUEST_RETRY_ACK_BASELINE') == BASE, 'exact-reviewed-remote-source-and-workflow')
    ensure(os.environ.get('CARGO_INCREMENTAL') == '1' and os.environ.get('CARGO_BUILD_JOBS') == '2'
           and os.environ.get('RUST_MIN_STACK') == '4194304', 'unchanged-capacity')
    ensure(all(os.environ.get(key) == '0' for key in ['CARGO_PROFILE_DEV_DEBUG', 'CARGO_PROFILE_TEST_DEBUG']), 'unchanged-debug-profile')
    ensure(all(not os.environ.get(key) for key in ['RUSTFLAGS', 'CARGO_ENCODED_RUSTFLAGS', 'RUSTC_BOOTSTRAP',
               'CARGO_PROFILE_DEV_OPT_LEVEL', 'CARGO_PROFILE_TEST_OPT_LEVEL']), 'no-profile-overrides')
    subprocess.run(['git', 'merge-base', '--is-ancestor', BASE, source], check=True)
    ensure(subprocess.run(['git', 'diff', '--quiet', 'HEAD']).returncode == 0, 'initial-pristine-source')
    baseline = {}
    for entry in subprocess.check_output(['git', 'ls-tree', '-r', '-z', BASE]).split(b'\0'):
        if entry:
            metadata, name = entry.split(b'\t', 1)
            git_mode, kind, blob = metadata.decode().split()
            ensure(kind == 'blob' and git_mode in {'100644', '100755', '120000'}, 'ordinary-baseline-inputs')
            baseline[os.fsdecode(name)] = (git_mode, blob)
    current = layout()
    ensure(SELF not in baseline and FIXTURE not in baseline and PROBE in baseline
           and set(current) == set(baseline) | {SELF, FIXTURE}, 'whole-inventory-two-new-files-only')
    for name, metadata in current.items():
        git_mode, blob = baseline.get(name, ('100644', None))
        ensure(metadata['git_mode'] == git_mode and metadata['symlink'] == (git_mode == '120000')
               and (metadata['symlink'] or metadata['actual_executable'] == (git_mode == '100755')), 'every-original-mode:' + name)
        data = os.fsencode(os.readlink(name)) if metadata['symlink'] else Path(name).read_bytes()
        if name == PROBE:
            ensure(digest(data) == PROBE_SHA256, 'whole-reviewed-probe-replacement-no-broad-exceptions')
            continue
        if name == FIXTURE:
            ensure(digest(data) == FIXTURE_SHA256, 'whole-reviewed-two-case-fixture')
            continue
        if name == REGISTRATION:
            original = subprocess.check_output(['git', 'show', BASE + ':' + name])
            ensure(original.count(REGISTER_ANCHOR) == 1 and REGISTER not in original, 'one-existing-retry-module-registration-anchor')
            ensure(data == original.replace(REGISTER_ANCHOR, REGISTER + REGISTER_ANCHOR, 1), 'exact-one-marked-test-module-registration-only')
            data = original
        if name == WORKFLOW:
            text = data.decode()
            ensure(text.count(BEGIN) == text.count(END) == text.count(OPTIONS) == 1, 'one-isolated-ACK-workflow-overlay')
            before, rest = text.split(BEGIN); _, after = rest.split(END)
            data = (before + after).replace(OPTIONS, 'options: [', 1).encode()
        if blob is not None:
            ensure(hashlib.sha1(b'blob ' + str(len(data)).encode() + b'\0' + data).hexdigest() == blob, 'all-other-original-bytes-frozen:' + name)
    ensure(set(subprocess.check_output(['git', 'ls-files', '--others', '--exclude-standard'], text=True).splitlines())
           <= {str(OUT / 'result.json')}, 'no-untracked-source-overlay')
    ensure(len(candidate.CASES) == 14 and len(CASES) == len({name for _, _, name, _ in CASES}) == 16, 'exact-fourteen-plus-two-inventory')
    return {'source': source, 'reviewed_baseline': BASE, 'product_and_all_historical_controllers_byte_exact': True,
            'all_original_contents_and_modes_verified_except_exact_reviewed_test_delta': True,
            'probe_replacement_sha256': PROBE_SHA256, 'new_ACK_fixture_sha256': FIXTURE_SHA256,
            'registration_sha256': digest(REGISTER), 'old_retry_fixture_byte_exact': True,
            'historical_runtime_evidence_reused': False, 'no_new_product_fix': True}


def parse_negative(label, raw, code):
    ensure(len(raw.encode()) <= 8 * 1024 * 1024, 'bounded-ACK-runtime-output')
    clean = re.sub(r'\x1b\[[0-9;]*m', '', raw)
    _, suffix, scenario = next(item for item in NEGATIVE_CASES if item[0] == label)
    name = PREFIX + suffix
    actual_names = re.findall(r'(?m)^test ([A-Za-z_0-9:]+) \.\.\.', clean)
    # Preserve actual identity before splitting an exact libtest prefix that
    # shares the already-observed closed marker line.
    clean, prefix_count = re.subn(r'(?m)^(test ' + re.escape(name) + r' \.\.\. )(?=request-retry-ack )', r'\1\n', clean)
    ensure(prefix_count in {0, 1}, 'at-most-one-exact-ACK-shared-header')
    row = dict(parse_body(clean, suffix), body_exit_code=code,
               compiler_error_count=len(re.findall(r'^error(?:\[E[0-9]+\])?:', clean, re.M)),
               executed_case_names=actual_names, running_counts=[int(value) for value in re.findall(r'(?m)^running ([0-9]{1,3}) tests?$', clean)])
    lines = [line for line in clean.splitlines() if line.startswith('request-retry-ack')]
    ensure(len(lines) == 1 and len(lines[0]) < 2048, 'one-bounded-ACK-marker')
    pattern = r'request-retry-ack scenario=(initial|proof) ' + ' '.join(field + r'=(true|false)' for field in FIELDS)
    pattern += r' samples=([0-9]{1,7}) window_elapsed_us=([0-9]{1,12}) runtime_closes=([0-3]) planes_shutdown=([0-3]) relay_closed=(true|false) attempt_completed=(true|false)'
    match = re.fullmatch(pattern, lines[0])
    ensure(match is not None, 'only-closed-enums-booleans-bounded-aggregate-numbers')
    row.update(scenario=match[1], expected_scenario=scenario, marker_header_count=len(lines),
               exact_prefix_normalization_count=prefix_count,
               facts=dict(zip(FIELDS, [value == 'true' for value in match.groups()[1:1 + len(FIELDS)]])))
    samples, elapsed, runtime, planes, relay, attempt = match.groups()[1 + len(FIELDS):]
    row.update(samples=int(samples), window_elapsed_us=int(elapsed), runtime_closes=int(runtime),
               planes_shutdown=int(planes), relay_closed=relay == 'true', attempt_completed=attempt == 'true')
    return row


def negative_green(label, row):
    _, suffix, scenario = next(item for item in NEGATIVE_CASES if item[0] == label)
    return (all(type(row.get(key)) is int and row[key] == value for key, value in
                {'body_exit_code': 0, 'passed': 1, 'failed': 0, 'ignored': 0, 'executed_nonignored': 1,
                 'compiler_error_count': 0, 'all_panic_header_count': 0, 'marker_header_count': 1}.items())
            and row.get('executed_case_names') == [PREFIX + suffix] and row.get('running_counts') == [1]
            and row.get('scenario') == row.get('expected_scenario') == scenario
            and set(row.get('facts', {})) == set(FIELDS) and all(row['facts'][field] is True for field in FIELDS)
            and type(row.get('samples')) is int and 2 <= row['samples'] <= 9_999_999
            and type(row.get('window_elapsed_us')) is int and 15_000_000 <= row['window_elapsed_us'] <= 300_000_000
            and type(row.get('runtime_closes')) is int and type(row.get('planes_shutdown')) is int
            and row['runtime_closes'] == row['planes_shutdown'] == 3
            and row.get('relay_closed') is True and row.get('attempt_completed') is True
            and row.get('panic_locations') == []
            and not row.get('watchdog_triggered') and not row.get('actual_count_unknown'))


def parse_case(label, raw, code):
    return parse_negative(label, raw, code) if label in {'initial_ack', 'proof_ack'} else candidate.parse_case(label, raw, code)


def case_green(label, row):
    return negative_green(label, row) if label in {'initial_ack', 'proof_ack'} else candidate.case_green(label, row)


def parser_controls():
    inherited = candidate.parser_controls()
    negatives = 0
    for label, suffix, scenario in NEGATIVE_CASES:
        name = PREFIX + suffix
        marker = 'request-retry-ack scenario=' + scenario + ' ' + ' '.join(field + '=true' for field in FIELDS)
        marker += ' samples=2 window_elapsed_us=15000000 runtime_closes=3 planes_shutdown=3 relay_closed=true attempt_completed=true'
        raw = 'running 1 test\ntest ' + name + ' ... ok\n' + marker + '\ntest result: ok. 1 passed; 0 failed; 0 ignored;\n'
        row = parse_negative(label, raw, 0)
        ensure(negative_green(label, row), 'real-negative-window-parser-positive')
        ensure(negative_green(label, parse_negative(label, raw.replace(' ... ok\n' + marker, ' ... ' + marker, 1), 0)), 'exact-shared-prefix-positive')
        for field in FIELDS:
            ensure(not negative_green(label, dict(row, facts=dict(row['facts'], **{field: False}))), 'every-negative-window-and-positive-closure-fact-required'); negatives += 1
        for change in [{'passed': True}, {'body_exit_code': 101}, {'passed': 0}, {'failed': 1}, {'ignored': 1},
                       {'executed_nonignored': 0}, {'compiler_error_count': 1}, {'all_panic_header_count': 1},
                       {'executed_case_names': [name, name]}, {'running_counts': [0]}, {'samples': 1}, {'samples': True},
                       {'window_elapsed_us': 14_999_999}, {'window_elapsed_us': 300_000_001},
                       {'runtime_closes': 2}, {'planes_shutdown': 2}, {'relay_closed': False}, {'attempt_completed': False},
                       {'scenario': 'proof' if scenario == 'initial' else 'initial'}, {'watchdog_triggered': True}, {'actual_count_unknown': True}]:
            ensure(not negative_green(label, dict(row, **change)), 'short-foreign-nonruntime-or-unclosed-window-rejected'); negatives += 1
        for changed in [raw + '\n' + marker, raw.replace('protected_window=true', 'protected_window=private'),
                        raw.replace(' samples=2', ' samples=-1'), raw.replace(' window_elapsed_us=15000000', ''),
                        raw.replace(marker, marker + ' private=secret')]:
            try: parse_negative(label, changed, 0)
            except ValueError: negatives += 1; continue
            raise ValueError('nonclosed-or-duplicate-ACK-marker-accepted')
        ensure(not negative_green(label, parse_negative(label, raw.replace(name, name + '_foreign'), 0)), 'foreign-full-name-rejected'); negatives += 1
    return {'unchanged_candidate_parsers': inherited, 'ACK_positive': 4, 'ACK_negative': negatives, 'runtime_bodies': 0}


def main(options):
    os.umask(0o077); OUT.mkdir(exist_ok=True)
    report = {'mode': options.mode, 'qualification_passed': False, 'native_acceptance_claim': False,
              'promotion_eligible': False, 'first_consent_mutation_eligible': False, 'mutations_executed': False,
              'all_sixteen_controls_green': False, 'focused_four_controls_green': False,
              'actual_counts_complete': False, 'cases': {}}
    before = None; modes = None
    def save(): (OUT / 'result.json').write_text(json.dumps(report, indent=2) + '\n')
    try:
        report['source_guard'] = source_guard(); report['parser_controls'] = parser_controls(); save()
        if options.preflight:
            report['preflight_passed'] = True; save(); return
        report['environment'] = environment()
        before, modes = freeze(), layout()
        report['input_manifest_sha256'] = identity(before)
        if options.mode == 'static':
            ensure(options.cohort in {'default', 'experimental'}, 'explicit-static-cohort')
            command = alignment.static_command(options.cohort)
            code, raw, seconds = bounded.capture(command, 1800, limit=8 * 1024 * 1024)
            report.update(cohort=options.cohort, command=command, exit_code=code, seconds=seconds,
                          compiler_error_count=len(re.findall(r'^error(?:\[E[0-9]+\])?:', raw, re.M)))
            report['static_passed'] = code == report['compiler_error_count'] == 0; save()
            ensure(report['static_passed'], 'fresh-strict-App-static-cohort-required')
            return
        ensure(options.mode in {'focused', 'full'}, 'explicit-focused-or-sixteen-case-mode')
        selected = CASES if options.mode == 'full' else [row for row in CASES if row[0] in {'body', 'request_retry', 'initial_ack', 'proof_ack'}]
        ensure(len(selected) == (16 if options.mode == 'full' else 4), 'exact-selected-required-inventory')
        report['required_case_count'] = len(selected)
        report['focused_component_only'] = options.mode == 'focused'
        compilation, cases = compile_cases([suffix for _, suffix, _, _ in selected])
        report['compilation'] = compilation; save()
        ensure(compilation.get('compile_exit_code') == compilation.get('compiler_error_count') == 0
               and compilation.get('compiled_fingerprints', {}).get('verified') is True
               and set(cases) == {suffix for _, suffix, _, _ in selected}, 'actual-feature-verified-case-compile')
        ensure(all(cases[suffix]['name'] == name for _, suffix, name, _ in selected)
               and len({case['binary_sha256'] for case in cases.values()}) == 1, 'exact-full-names-one-real-binary')
        report['feature_identity'] = feature_identity(compilation)
        report['compiled_binary_sha256'] = next(iter(cases.values()))['binary_sha256']
        for label, suffix, name, oracle in selected:
            case = cases[suffix]
            ensure(freeze() == before and layout() == modes and digest(Path(case['binary']).read_bytes()) == case['binary_sha256'], 'before-body-pristine-source-modes-binary')
            row = {'actual_counts_complete': False, 'green': False, 'actual_required_name': name,
                   'historical_oracle_label': oracle, 'compiled_binary_sha256': case['binary_sha256']}
            report['cases'][label] = row; save()
            try:
                code, raw, seconds = bounded.capture([case['binary'], '--exact', name, '--nocapture', '--test-threads=1'], 300, limit=8 * 1024 * 1024)
                row['body'] = dict(parse_body(raw, suffix), body_exit_code=code)
                row['seconds'] = seconds; row['actual_counts_complete'] = alignment.complete_counts(row['body']); save()
                row['body'] = parse_case(label, raw, code)
                row['actual_counts_complete'] = alignment.complete_counts(row['body'])
                row['green'] = row['actual_counts_complete'] and case_green(label, row['body'])
            except bounded.GateFailure as error:
                row['watchdog_triggered'] = str(error) == 'bounded-command-timeout'
                row['output_limit_triggered'] = str(error) == 'bounded-command-output-limit'
            except ValueError:
                row['parser_rejected'] = True
            ensure(freeze() == before and layout() == modes and digest(Path(case['binary']).read_bytes()) == case['binary_sha256'], 'after-body-pristine-source-modes-binary')
            save()
        report['actual_counts_complete'] = all(row['actual_counts_complete'] for row in report['cases'].values())
        report.update(alignment.aggregate_counts(report['cases']))
        report['initial_and_proof_ACK_controls_green'] = all(report['cases'][label]['green'] for label, _, _ in NEGATIVE_CASES)
        all_green = (report['actual_counts_complete'] and report['actual_executed_nonignored'] == len(selected)
                     and all(row['green'] for row in report['cases'].values()))
        report['focused_four_controls_green' if options.mode == 'focused' else 'all_sixteen_controls_green'] = all_green
        save(); ensure(all_green, 'all-selected-real-controls-including-ACK-windows-required')
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
    parser.add_argument('--mode', choices=['focused', 'full', 'static'], default='focused')
    parser.add_argument('--cohort', choices=['default', 'experimental'])
    main(parser.parse_args())
