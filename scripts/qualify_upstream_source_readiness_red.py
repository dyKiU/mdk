#!/usr/bin/env python3
"""Directed fresh Core-ready first-source scheduling RED; not a GREEN/qualification claim."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import qualify_upstream_storage_boundary as bounded
from upstream_completion_ci import compile_cases, digest, ensure, environment, identity, parse_body
from qualify_upstream_body_negative import freeze, layout, feature_identity

BASE = '5d8ee61aa2b5aa6be7933a342c6bebe4f78c15ed'
SELF = 'scripts/qualify_upstream_source_readiness_red.py'
WORKFLOW = '.github/workflows/experimental-sync-ci.yml'
REF = 'refs/heads/ci/upstream-source-readiness-red-20261018'
FIXTURE = 'crates/marmot-app/src/native_device_linking/tests/source_readiness_acceptance.rs'
PROBE = 'crates/marmot-app/src/client/private_enrollment_proposal/source_readiness_probe.rs'
NEW_HASHES = {'crates/marmot-app/src/native_device_linking/tests/source_readiness_acceptance.rs': '5fc27c8a972949686b0b61f3efe214b9d1a37b3eb2849dddc07ec8c49f764dc7', 'crates/marmot-app/src/client/private_enrollment_proposal/source_readiness_probe.rs': '9ffe8f09328ce5e9a6c17f42d746ca7c3a3d4c75918f22f6f5366c60ac56e24a'}
HOOKS = {'crates/marmot-app/src/native_device_linking/tests/automatic_pairing_acceptance.rs': 1, 'crates/marmot-app/src/runtime/test_linking_periodic_gate.rs': 1, 'crates/marmot-app/src/runtime/account_worker.rs': 1, 'crates/marmot-app/src/runtime/mod.rs': 3, 'crates/marmot-app/src/runtime/device_linking/setup.rs': 3, 'crates/marmot-app/src/client/private_enrollment_proposal.rs': 1}
HOOK_HASHES = {'crates/marmot-app/src/native_device_linking/tests/automatic_pairing_acceptance.rs': 'c8bdd643dc4e7e81ea90741fc3a68aebcfd2d47b3fcd16e402ea2fec3ca73731', 'crates/marmot-app/src/runtime/test_linking_periodic_gate.rs': 'a9b3a08ea156ce62a8e9516bb2c630a3e534df8f2e048781d807c9efdf13b5e5', 'crates/marmot-app/src/runtime/account_worker.rs': 'edc8a35f6752c320794785211eff4465c6b918b70e4273fdce2e3b30add8c6eb', 'crates/marmot-app/src/runtime/mod.rs': '697554aa74d63de67038feabf113f6facd62e203698c5395e7691b885d0960ac', 'crates/marmot-app/src/runtime/device_linking/setup.rs': '4dc6aa667e918595d5658488a7cae7fd56cfb4adc2ee0ad2e2d15b12f9098320', 'crates/marmot-app/src/client/private_enrollment_proposal.rs': '515098a30069d6b86299abdfc65d18ba641dc605b02ef7f40eeb9778fcb232ef'}
CASE = 'fresh_completed_source_starts_request_without_sibling_periodic_tick'
NAME = 'native_device_linking::automatic_pairing_acceptance::source_readiness_acceptance::' + CASE
MESSAGE = 'fresh_completed_owned_source_must_start_first_request_without_sibling_periodic_tick'
BEGIN = '  # SOURCE_READINESS_RED_JOBS_BEGIN\n'
END = '  # SOURCE_READINESS_RED_JOBS_END\n'
OPTIONS = 'options: [source-readiness-preflight, source-readiness-red, '
OUT = Path('source-readiness-red-evidence')
FIELDS = ['periodic_observed', 'fresh_core_prerequisites', 'first_request_before_periodic_release',
          'prerequisites_still_fresh', 'periodic_released', 'actual_request_identity',
          'exact_channel_nonce_deadline', 'guards_released', 'enrollment_complete', 'public_cancelled']
STRIP = re.compile(rb'(?m)^[ \t]*// SOURCE_READINESS_TEST_BEGIN\n.*?^[ \t]*// SOURCE_READINESS_TEST_END\n', re.S)


def source_guard():
    source = subprocess.check_output(['git', 'rev-parse', 'HEAD'], text=True).strip()
    ensure(os.environ.get('GITHUB_ACTIONS') == 'true' and os.environ.get('GITHUB_REPOSITORY') == 'dyKiU/mdk'
           and os.environ.get('GITHUB_EVENT_NAME') == 'workflow_dispatch' and source == os.environ.get('GITHUB_SHA')
           and os.environ.get('GITHUB_REF') == REF
           and os.environ.get('GITHUB_WORKFLOW_REF') == 'dyKiU/mdk/' + WORKFLOW + '@' + REF
           and os.environ.get('UPSTREAM_SOURCE_READINESS_BASELINE') == BASE, 'exact-reviewed-owned-remote-source')
    ensure(os.environ.get('CARGO_INCREMENTAL') == '1' and os.environ.get('CARGO_BUILD_JOBS') == '2'
           and os.environ.get('RUST_MIN_STACK') == '4194304', 'unchanged-execution-capacity')
    ensure(all(os.environ.get(key) == '0' for key in ['CARGO_PROFILE_DEV_DEBUG', 'CARGO_PROFILE_TEST_DEBUG']), 'unchanged-debug-profile')
    ensure(all(not os.environ.get(key) for key in ['RUSTFLAGS', 'CARGO_ENCODED_RUSTFLAGS', 'RUSTC_BOOTSTRAP',
               'CARGO_PROFILE_DEV_OPT_LEVEL', 'CARGO_PROFILE_TEST_OPT_LEVEL']), 'no-compiler-profile-override')
    subprocess.run(['git', 'merge-base', '--is-ancestor', BASE, source], check=True)
    ensure(subprocess.run(['git', 'diff', '--quiet', 'HEAD']).returncode == 0, 'initial-pristine-source')
    baseline = {}
    for entry in subprocess.check_output(['git', 'ls-tree', '-r', '-z', BASE]).split(b'\0'):
        if entry:
            metadata, name = entry.split(b'\t', 1)
            mode, kind, blob = metadata.decode().split()
            ensure(kind == 'blob' and mode in {'100644', '100755', '120000'}, 'ordinary-baseline-tree')
            baseline[os.fsdecode(name)] = (mode, blob)
    current = layout()
    ensure(all(name not in baseline for name in [SELF, FIXTURE, PROBE])
           and set(current) == set(baseline) | {SELF, FIXTURE, PROBE}, 'whole-inventory-plus-exact-three-files')
    for name, metadata in current.items():
        mode, blob = baseline.get(name, ('100644', None))
        ensure(metadata['git_mode'] == mode and metadata['symlink'] == (mode == '120000')
               and (metadata['symlink'] or metadata['actual_executable'] == (mode == '100755')), 'whole-original-modes:' + name)
        data = os.fsencode(os.readlink(name)) if metadata['symlink'] else Path(name).read_bytes()
        if name in HOOKS:
            ensure(digest(data) == HOOK_HASHES[name], 'reviewed-full-hook-file:' + name)
            ensure(data.count(b'// SOURCE_READINESS_TEST_BEGIN') == data.count(b'// SOURCE_READINESS_TEST_END') == HOOKS[name], 'exact-test-only-hook-count')
            data, count = STRIP.subn(b'', data)
            ensure(count == HOOKS[name], 'exact-test-only-hook-strip')
        if name == WORKFLOW:
            text = data.decode()
            ensure(text.count(BEGIN) == text.count(END) == text.count(OPTIONS) == 1, 'one-isolated-workflow-overlay')
            before, rest = text.split(BEGIN); _, after = rest.split(END)
            data = (before + after).replace(OPTIONS, 'options: [', 1).encode()
        if blob is not None:
            ensure(hashlib.sha1(b'blob ' + str(len(data)).encode() + b'\0' + data).hexdigest() == blob, 'entire-original-input-reconstructed:' + name)
        if name in NEW_HASHES:
            ensure(digest(data) == NEW_HASHES[name], 'reviewed-new-test-probe-source:' + name)
    ensure(set(subprocess.check_output(['git', 'ls-files', '--others', '--exclude-standard'], text=True).splitlines())
           <= {str(OUT / 'result.json')}, 'no-untracked-source-overlay')
    return {'source': source, 'reviewed_baseline': BASE, 'all_original_contents_modes_reconstructed': True,
            'new_test_probe_hashes': NEW_HASHES, 'test_only_hook_counts': HOOKS,
            'canonical_adapter_routes_and_original_cancel_deadline_select_unchanged': True,
            'broad_primary_tick_and_existing_both_lane_gate_unchanged': True,
            'readiness_probe_is_fresh_read_only_no_scheduling_hint': True,
            'all_existing_harness_bodies_assertions_deadlines_and_controllers_unchanged': True,
            'product_source_scheduling_fix_present': False, 'historical_runtime_evidence_reused': False}


def assertion_line():
    lines = Path(FIXTURE).read_text().splitlines()
    matches = [index for index, line in enumerate(lines) if MESSAGE in line]
    ensure(len(matches) == 1, 'unique-new-intended-oracle')
    return max(index for index in range(matches[0] + 1) if re.search(r'\bassert!\s*\(', lines[index])) + 1


def parse(raw, code):
    ensure(len(raw.encode()) <= 8 * 1024 * 1024, 'bounded-runtime-output')
    raw = re.sub(r'\x1b\[[0-9;]*m', '', raw)
    actual_names = re.findall(r'(?m)^test ([A-Za-z_0-9:]+) \.\.\.', raw)
    raw = re.sub(r'(?m)^test ' + re.escape(NAME) + r' \.\.\. (?=source-readiness )', '', raw)
    row = dict(parse_body(raw, CASE), body_exit_code=code,
               compiler_error_count=len(re.findall(r'^error(?:\[E[0-9]+\])?:', raw, re.M)),
               running_counts=[int(value) for value in re.findall(r'(?m)^running ([0-9]{1,3}) tests?$', raw)])
    # Accept the libtest prefix only for this exact selected case; marker output
    # can share its line. No unrelated marker/panic/body can establish RED.
    row['executed_case_names'] = actual_names
    row['selected_case_observed'] = actual_names == [NAME]
    lines = [line for line in raw.splitlines() if line.startswith('source-readiness')]
    row['marker_header_count'] = len(lines)
    pattern = 'source-readiness ' + ' '.join(field + r'=(true|false)' for field in FIELDS)
    pattern += r' runtime_closes=([0-3]) planes_shutdown=([0-3]) relay_closed=(true|false) attempt_completed=(true|false)'
    ensure(len(lines) == 1 and len(lines[0]) <= 1024, 'one-bounded-closed-result-marker')
    match = re.fullmatch(pattern, lines[0])
    ensure(match is not None, 'closed-typed-result-fields')
    row['facts'] = dict(zip(FIELDS, [value == 'true' for value in match.groups()[:len(FIELDS)]]))
    tail = match.groups()[len(FIELDS):]
    row.update(runtime_closes=int(tail[0]), planes_shutdown=int(tail[1]), relay_closed=tail[2] == 'true',
               attempt_completed=tail[3] == 'true', named_final_assertion_observed=MESSAGE in raw)
    return row


def prerequisite_facts(row):
    return (all(row.get('facts', {}).get(field) is True for field in FIELDS if field not in
                {'first_request_before_periodic_release'})
            and row.get('runtime_closes') == row.get('planes_shutdown') == 3
            and row.get('relay_closed') is True and row.get('attempt_completed') is True)


def intended_red(row):
    locations = row.get('panic_locations', [])
    return (all(type(row.get(key)) is int and row[key] == value for key, value in
                {'body_exit_code': 101, 'passed': 0, 'failed': 1, 'ignored': 0, 'executed_nonignored': 1,
                 'compiler_error_count': 0, 'all_panic_header_count': 1, 'marker_header_count': 1}.items())
            and row.get('running_counts') == [1] and row.get('executed_case_names') == [NAME]
            and row.get('selected_case_observed') is True
            and row.get('named_final_assertion_observed') is True and prerequisite_facts(row)
            and row['facts'].get('first_request_before_periodic_release') is False
            and len(locations) == 1 and locations[0]['file'] == FIXTURE and locations[0]['line'] == assertion_line()
            and not row.get('watchdog_triggered') and not row.get('actual_count_unknown'))


def parser_controls():
    marker = 'source-readiness ' + ' '.join(field + '=' + ('false' if field in
              {'first_request_before_periodic_release'} else 'true') for field in FIELDS)
    marker += ' runtime_closes=3 planes_shutdown=3 relay_closed=true attempt_completed=true'
    raw = ('running 1 test\ntest ' + NAME + ' ... FAILED\n' + marker + '\nthread case panicked at ' + FIXTURE
           + ':' + str(assertion_line()) + ':5:\n' + MESSAGE + '\ntest result: FAILED. 0 passed; 1 failed; 0 ignored;\n')
    row = parse(raw, 101)
    ensure(intended_red(row), 'genuine-final-oracle-parser-positive')
    shared = raw.replace(' ... FAILED\n' + marker, ' ... ' + marker, 1)
    ensure(intended_red(parse(shared, 101)), 'exact-libtest-marker-prefix-positive')
    negatives = 0
    for change in [{'body_exit_code': True}, {'failed': True}, {'ignored': False}, {'body_exit_code': 0}, {'passed': 1}, {'failed': 0}, {'ignored': 1}, {'executed_nonignored': 0},
                   {'compiler_error_count': 1}, {'all_panic_header_count': 2}, {'running_counts': [0]},
                   {'selected_case_observed': False}, {'runtime_closes': 2}, {'planes_shutdown': 2}, {'relay_closed': False},
                   {'attempt_completed': False}, {'named_final_assertion_observed': False}, {'watchdog_triggered': True},
                   {'actual_count_unknown': True}, {'panic_locations': []},
                   {'panic_locations': [{'file': FIXTURE, 'line': assertion_line() + 1, 'column': 5}]},
                   {'panic_locations': [{'file': 'crates/other.rs', 'line': assertion_line(), 'column': 5}]},
                   {'executed_case_names': [NAME, NAME]}]:
        ensure(not intended_red(dict(row, **change)), 'unrelated-nonruntime-or-unclosed-RED-rejected'); negatives += 1
    for field in FIELDS:
        changed = dict(row, facts=dict(row['facts'], **{field: not row['facts'][field]}))
        ensure(not intended_red(changed), 'every-prerequisite-and-baseline-negative-verdict-required'); negatives += 1
    for value in [raw + '\n' + marker, raw.replace('periodic_observed=true', 'periodic_observed=private'),
                  raw.replace(' runtime_closes=3', ' runtime_closes=-1'), raw.replace(' guards_released=true', ''),
                  raw.replace(marker, marker + ' private=secret')]:
        try: parse(value, 101)
        except ValueError: negatives += 1; continue
        raise ValueError('unclosed-private-marker-export-accepted')
    ensure(not intended_red(parse(raw.replace(NAME, NAME + '_other'), 101)), 'foreign-selected-case-rejected'); negatives += 1
    ensure(not intended_red(parse(raw + '\ntest foreign::extra ... FAILED\n', 101)), 'extra-full-name-rejected'); negatives += 1
    return {'positive': 2, 'negative': negatives, 'runtime_bodies': 0}


def main(options):
    os.umask(0o077); OUT.mkdir(exist_ok=True)
    report = {'behavioral_red_verified': False, 'qualification_passed': False, 'green_claim': False,
              'mutation_claim': False, 'actual_counts_complete': False, 'positive_native_acceptance_claim': False}
    before = None; modes = None
    def save(): (OUT / 'result.json').write_text(json.dumps(report, indent=2) + '\n')
    try:
        report['source_guard'] = source_guard(); report['parser_controls'] = parser_controls(); save()
        if options.preflight:
            report['preflight_passed'] = True; save(); return
        report['environment'] = environment()
        before, modes = freeze(), layout()
        report['input_manifest_sha256'] = identity(before)
        compilation, cases = compile_cases([CASE])
        report['compilation'] = compilation; save()
        ensure(compilation.get('compile_exit_code') == compilation.get('compiler_error_count') == 0
               and compilation.get('compiled_fingerprints', {}).get('verified') is True
               and set(cases) == {CASE} and cases[CASE]['name'] == NAME, 'one-actual-feature-verified-readiness-body')
        report['feature_identity'] = feature_identity(compilation)
        case = cases[CASE]
        ensure(freeze() == before and layout() == modes and digest(Path(case['binary']).read_bytes()) == case['binary_sha256'], 'before-runtime-frozen-inputs-binary')
        try:
            code, raw, seconds = bounded.capture([case['binary'], '--exact', NAME, '--nocapture', '--test-threads=1'], 300, limit=8 * 1024 * 1024)
        except bounded.GateFailure as error:
            report['watchdog_triggered'] = str(error) == 'bounded-command-timeout'
            report['output_limit_triggered'] = str(error) == 'bounded-command-output-limit'
            report['actual_count_unknown'] = True
            raise ValueError('bounded-runtime-did-not-complete') from None
        report['actual_runtime'] = dict(parse_body(raw, CASE), body_exit_code=code, seconds=seconds,
                                       compiler_error_count=len(re.findall(r'^error(?:\[E[0-9]+\])?:', raw, re.M)),
                                       compiled_binary_sha256=case['binary_sha256']); save()
        row = parse(raw, code)
        report['actual_runtime'] = dict(row, seconds=seconds, compiled_binary_sha256=case['binary_sha256']); save()
        report['actual_counts_complete'] = (all(type(row.get(key)) is int for key in ['passed', 'failed', 'ignored', 'executed_nonignored'])
                                            and row['passed'] + row['failed'] == row['executed_nonignored'] == 1 and row['ignored'] == 0)
        ensure(report['actual_counts_complete'] and intended_red(row), 'sole-directed-final-oracle-runtime-RED-required')
        ensure(digest(Path(case['binary']).read_bytes()) == case['binary_sha256'], 'after-runtime-binary-pristine')
        report['behavioral_red_verified'] = True
    except Exception as error:
        report['exception_type'] = type(error).__name__
        raise
    finally:
        if before is not None:
            report['inputs_pristine'] = freeze() == before and layout() == modes
            report['source_after_sha256'] = identity(freeze())
            if not report['inputs_pristine']:
                report['behavioral_red_verified'] = False
        save()
        if before is not None: ensure(report['inputs_pristine'], 'final-source-modes-pristine')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--preflight', action='store_true')
    main(parser.parse_args())
