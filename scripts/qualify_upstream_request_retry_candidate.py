#!/usr/bin/env python3
"""Frozen retry component plus fourteen required controls; no mutation/promotion."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import qualify_upstream_runtime_alignment as alignment
import qualify_upstream_request_retry_red as regression
import qualify_upstream_automatic_body as body_protocol
import qualify_upstream_storage_boundary as bounded
from qualify_upstream_body_negative import freeze, layout, feature_identity
from upstream_completion_ci import compile_cases, digest, ensure, environment, identity, parse_body

BASE = '3622c0c2051af7df2f5639016e9777f3dae41e50'
SELF = 'scripts/qualify_upstream_request_retry_candidate.py'
WORKFLOW = '.github/workflows/experimental-sync-ci.yml'
PRODUCT = 'crates/marmot-app/src/client/device_linking/sibling_sharing.rs'
PROBE = 'crates/marmot-app/src/client/device_linking/sibling_sharing/peer_proof_probe/retry_completion.rs'
CAPTURE_BEFORE = b'    pub(crate) fn capture('
CAPTURE_AFTER = b'    pub(in super::super) fn capture('
REF = 'refs/heads/ci/upstream-request-retry-20261018'
BEGIN = '  # REQUEST_RETRY_CANDIDATE_JOBS_BEGIN\n'
END = '  # REQUEST_RETRY_CANDIDATE_JOBS_END\n'
OPTIONS = 'options: [request-retry-candidate-preflight, request-retry-candidate-controls, request-retry-candidate-focused, '
OUT = Path('request-retry-candidate-evidence')
# Proposed literal only. Root must approve/adopt it AFTER actual baseline RED.
# Exactly one insertion inside first_consent, after Core binding succeeded.
ANCHOR = b'''                    if first_consent {
                        // A one-shot scheduling hint, not authority or a retry.
'''
FIX = b'''                        // Keep the initial Request ACK; only its superseded retry is obsolete.
                        if entry.handshake_published
                            && entry
                                .publication
                                .as_ref()
                                .is_some_and(|pending| !pending.proof)
                        {
                            drop(entry.publication.take());
                        }
'''
CASES = list(alignment.CASES) + [('request_retry', regression.CASE, regression.NAME, None)]


def source_guard():
    source = subprocess.check_output(['git', 'rev-parse', 'HEAD'], text=True).strip()
    ensure(os.environ.get('GITHUB_ACTIONS') == 'true' and os.environ.get('GITHUB_REPOSITORY') == 'dyKiU/mdk'
           and os.environ.get('GITHUB_EVENT_NAME') == 'workflow_dispatch' and source == os.environ.get('GITHUB_SHA')
           and os.environ.get('GITHUB_REF') == REF
           and os.environ.get('GITHUB_WORKFLOW_REF') == 'dyKiU/mdk/' + WORKFLOW + '@' + REF
           and os.environ.get('UPSTREAM_REQUEST_RETRY_CANDIDATE_BASELINE') == BASE, 'exact-reviewed-remote-source-workflow')
    ensure(os.environ.get('CARGO_INCREMENTAL') == '1' and os.environ.get('CARGO_BUILD_JOBS') == '2'
           and os.environ.get('RUST_MIN_STACK') == '4194304', 'unchanged-capacity')
    ensure(all(os.environ.get(key) == '0' for key in ['CARGO_PROFILE_DEV_DEBUG', 'CARGO_PROFILE_TEST_DEBUG']), 'unchanged-debug-profile')
    ensure(all(not os.environ.get(key) for key in ['RUSTFLAGS', 'CARGO_ENCODED_RUSTFLAGS', 'RUSTC_BOOTSTRAP',
               'CARGO_PROFILE_DEV_OPT_LEVEL', 'CARGO_PROFILE_TEST_OPT_LEVEL']), 'no-profile-overrides')
    subprocess.run(['git', 'merge-base', '--is-ancestor', BASE, source], check=True)
    ensure(subprocess.run(['git', 'diff', '--quiet', 'HEAD']).returncode == 0, 'initial-pristine-inputs')
    baseline = {}
    for entry in subprocess.check_output(['git', 'ls-tree', '-r', '-z', BASE]).split(b'\0'):
        if entry:
            metadata, name = entry.split(b'\t', 1)
            git_mode, kind, blob = metadata.decode().split()
            ensure(kind == 'blob' and git_mode in {'100644', '100755', '120000'}, 'ordinary-baseline-inputs')
            baseline[os.fsdecode(name)] = (git_mode, blob)
    current = layout()
    ensure(SELF not in baseline and set(current) == set(baseline) | {SELF}, 'whole-inventory-only-one-new-controller')
    for name, metadata in current.items():
        git_mode, blob = baseline.get(name, ('100644', None))
        ensure(metadata['git_mode'] == git_mode and metadata['symlink'] == (git_mode == '120000')
               and (metadata['symlink'] or metadata['actual_executable'] == (git_mode == '100755')), 'exact-input-mode:' + name)
        data = os.fsencode(os.readlink(name)) if metadata['symlink'] else Path(name).read_bytes()
        if name == PRODUCT:
            original = subprocess.check_output(['git', 'show', BASE + ':' + name])
            ensure(original.count(ANCHOR) == 1 and FIX not in original, 'one-original-first-Core-bound-consent-anchor')
            expected = original.replace(ANCHOR, ANCHOR.split(b'\n', 1)[0] + b'\n' + FIX + ANCHOR.split(b'\n', 1)[1], 1)
            ensure(data == expected, 'exact-one-reviewed-retirement-insertion-no-other-product-change')
            data = original
        if name == PROBE:
            original = subprocess.check_output(['git', 'show', BASE + ':' + name])
            ensure(original.count(CAPTURE_BEFORE) == 1 and CAPTURE_AFTER not in original, 'one-reviewed-capture-visibility-anchor')
            ensure(data == original.replace(CAPTURE_BEFORE, CAPTURE_AFTER, 1), 'only-exact-capture-visibility-correction-same-probe-body')
            data = original
        if name == WORKFLOW:
            text = data.decode()
            ensure(text.count(BEGIN) == text.count(END) == text.count(OPTIONS) == 1, 'one-isolated-candidate-workflow-overlay')
            before, rest = text.split(BEGIN); _, after = rest.split(END)
            data = (before + after).replace(OPTIONS, 'options: [', 1).encode()
        if blob is not None:
            ensure(hashlib.sha1(b'blob ' + str(len(data)).encode() + b'\0' + data).hexdigest() == blob, 'every-original-byte-and-mode-frozen:' + name)
    ensure(set(subprocess.check_output(['git', 'ls-files', '--others', '--exclude-standard'], text=True).splitlines())
           <= {str(OUT / 'result.json')}, 'no-untracked-source-overlay')
    ensure(len(alignment.CASES) == 13 and len(CASES) == 14
           and len({name for _, _, name, _ in CASES}) == 14, 'exact-thirteen-plus-one-runtime-inventory')
    return {'source': source, 'reviewed_baseline': BASE, 'all_original_contents_and_modes_verified': True,
            'only_product_delta': 'Exact first Core-bound source Consent retirement of an already-ACKed non-proof Request retry',
            'literal_fix_sha256': digest(FIX), 'fixture_and_historical_controllers_unchanged': True,
            'probe_body_unchanged': True,
            'probe_visibility_correction': {'path': PROBE, 'function': 'Adapter::capture',
                                          'before': 'pub(crate)', 'after': 'pub(in super::super)',
                                          'only_visibility_token_changed': True},
            'original_bodies_assertions_deadlines_and_required_serial_stress_unchanged': True,
            'initial_Request_ACK_recipient_Consent_and_proof_ACK_requirements_unchanged': True,
            'historical_runtime_evidence_reused': False}


def retry_green(row):
    return (all(type(row.get(key)) is int and row[key] == expected for key, expected in
                {'body_exit_code': 0, 'passed': 1, 'failed': 0, 'ignored': 0, 'executed_nonignored': 1,
                 'compiler_error_count': 0, 'all_panic_header_count': 0, 'marker_header_count': 1}.items())
            and row.get('executed_case_names') == [regression.NAME] and row.get('running_counts') == [1]
            and row.get('selected_case_observed') is True and regression.prerequisite_facts(row)
            and set(row.get('facts', {})) == set(regression.FIELDS)
            and all(row['facts'][field] is True for field in regression.FIELDS)
            and row.get('panic_locations') == []
            and not row.get('watchdog_triggered') and not row.get('actual_count_unknown'))


def parse_case(label, raw, code):
    if label == 'request_retry':
        return regression.parse(raw, code)
    if label != 'body':
        return alignment.parse_case(label, raw, code)
    clean = re.sub(r'\x1b\[[0-9;]*m', '', raw)
    actual_names = re.findall(r'(?m)^test ([A-Za-z_0-9:]+) \.\.\.', clean)
    ensure(actual_names == [body_protocol.NAME], 'body-exact-observed-name-before-any-normalization')
    # Preserve the actual header and literal first marker. Only their missing
    # line separator is repaired; no absent marker can be supplied here.
    pattern = (r'(?m)^(test ' + re.escape(body_protocol.NAME) + r' \.\.\. )'
               r'(automatic-body-control stage=bilateral-pair-and-history-ready)$')
    normalized, count = re.subn(pattern, r'\1\n\2', clean)
    ensure(type(count) is int and count in {0, 1}, 'at-most-one-exact-Body-first-stage-shared-line')
    row = alignment.parse_case(label, normalized, code)
    row['body_first_stage_prefix_normalization_count'] = count
    row['body_observed_names_before_normalization'] = actual_names
    return row


def case_green(label, row):
    if label == 'request_retry':
        return retry_green(row)
    if label == 'body':
        if (type(row.get('body_first_stage_prefix_normalization_count')) is not int
                or row['body_first_stage_prefix_normalization_count'] not in {0, 1}
                or row.get('body_observed_names_before_normalization') != [body_protocol.NAME]):
            return False
    return alignment.case_green(label, row)


def body_normalization_controls():
    events = ['automatic-body-control stage=' + stage
              + (' responsive=true' if index == 4 else ' index=' + str(index - 8) if index in {8, 9} else '')
              for index, stage in enumerate(body_protocol.STAGES)]
    header = 'test ' + body_protocol.NAME + ' ... '
    tail = '\ntest result: ok. 1 passed; 0 failed; 0 ignored;\n'
    separate = 'running 1 test\n' + header + 'ok\n' + '\n'.join(events) + tail
    shared = 'running 1 test\n' + header + '\n'.join(events) + tail
    for raw, expected in [(separate, 0), (shared, 1)]:
        row = parse_case('body', raw, 0)
        ensure(case_green('body', row) and row['body_first_stage_prefix_normalization_count'] == expected
               and row['body_observed_names_before_normalization'] == [body_protocol.NAME], 'actual-literal-Body-marker-normalization-positive')
    negatives = [shared.replace(body_protocol.NAME, 'foreign::case', 1),
                 separate.replace(events[0] + '\n', '', 1),
                 shared.replace(events[0], events[1], 1),
                 shared.replace(events[0], events[0] + '\n' + events[0], 1),
                 separate.replace(events[0] + '\n' + events[1], events[1] + '\n' + events[0], 1),
                 separate.replace(events[0], 'test foreign::case ... ' + events[0], 1)]
    for raw in negatives:
        try: row = parse_case('body', raw, 0)
        except ValueError: continue
        ensure(not case_green('body', row), 'foreign-missing-duplicate-or-reordered-first-Body-marker-rejected')
    return {'positive': 2, 'negative': len(negatives), 'runtime_bodies': 0,
            'historical_3bec_Body_evidence_requalified': False}


def parser_controls():
    inherited = {'alignment': alignment.parser_controls(), 'frozen_directed_RED': regression.parser_controls()}
    marker = 'request-retry-completion ' + ' '.join(field + '=true' for field in regression.FIELDS)
    marker += ' runtime_closes=3 planes_shutdown=3 relay_closed=true attempt_completed=true'
    raw = ('running 1 test\ntest ' + regression.NAME + ' ... ok\n' + marker
           + '\ntest result: ok. 1 passed; 0 failed; 0 ignored;\n')
    row = regression.parse(raw, 0)
    ensure(retry_green(row), 'retry-all-positive-runtime-parser-positive')
    ensure(retry_green(regression.parse(raw.replace(' ... ok\n' + marker, ' ... ' + marker, 1), 0)), 'exact-shared-libtest-line-positive')
    negatives = 0
    for field in regression.FIELDS:
        ensure(not retry_green(dict(row, facts=dict(row['facts'], **{field: False}))), 'every-positive-fact-required'); negatives += 1
    for change in [{'body_exit_code': 101}, {'passed': True}, {'passed': 0}, {'failed': 1}, {'ignored': 1},
                   {'executed_nonignored': 0}, {'compiler_error_count': 1}, {'all_panic_header_count': 1},
                   {'marker_header_count': 0}, {'running_counts': [0]}, {'selected_case_observed': False},
                   {'executed_case_names': [regression.NAME, regression.NAME]}, {'runtime_closes': 2},
                   {'planes_shutdown': 2}, {'relay_closed': False}, {'attempt_completed': False},
                   {'panic_locations': [{'file': regression.FIXTURE, 'line': regression.assertion_line(), 'column': 5}]},
                   {'watchdog_triggered': True}, {'actual_count_unknown': True}]:
        ensure(not retry_green(dict(row, **change)), 'nonruntime-foreign-unclosed-or-incomplete-green-rejected'); negatives += 1
    for value in [raw + '\n' + marker, raw.replace('consent_held=true', 'consent_held=private'),
                  raw.replace(' runtime_closes=3', ' runtime_closes=-1'), raw.replace(' guards_released=true', ''),
                  raw.replace(marker, marker + ' private=secret')]:
        try: regression.parse(value, 0)
        except ValueError: negatives += 1; continue
        raise ValueError('nonclosed-marker-accepted')
    ensure(not retry_green(regression.parse(raw.replace(regression.NAME, regression.NAME + '_foreign'), 0)), 'foreign-case-name-rejected'); negatives += 1
    return {'unchanged_historical_parsers': inherited, 'retry_green_positive': 2, 'retry_green_negative': negatives,
            'Body_exact_first_stage_prefix_controls': body_normalization_controls(),
            'runtime_bodies': 0}


def main(options):
    os.umask(0o077); OUT.mkdir(exist_ok=True)
    report = {'mode': options.mode, 'qualification_passed': False, 'native_acceptance_claim': False,
              'promotion_eligible': False, 'first_consent_mutation_eligible': False, 'mutations_executed': False,
              'initial_and_proof_ACK_negative_controls_qualified': False,
              'component_green': False, 'all_fourteen_controls_green': False, 'actual_counts_complete': False, 'cases': {}}
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
            ensure(options.cohort in {'default', 'experimental'}, 'explicit-strict-static-cohort')
            command = alignment.static_command(options.cohort)
            code, raw, seconds = bounded.capture(command, 1800, limit=8 * 1024 * 1024)
            report.update(cohort=options.cohort, command=command, exit_code=code, seconds=seconds,
                          compiler_error_count=len(re.findall(r'^error(?:\[E[0-9]+\])?:', raw, re.M)))
            report['static_passed'] = code == report['compiler_error_count'] == 0; save()
            ensure(report['static_passed'], 'actual-strict-App-static-required')
            return
        ensure(not options.include_body or options.mode == 'focused', 'optional-Body-control-only-on-explicit-focused-mode')
        selected = CASES if options.mode == 'controls' else [item for item in CASES if item[0] in
                    ({'body', 'request_retry'} if options.include_body else {'request_retry'})]
        ensure(options.mode in {'controls', 'focused'} and len(selected) == (14 if options.mode == 'controls' else 2 if options.include_body else 1), 'explicit-full-or-component-only-scope')
        report['required_case_count'] = len(selected)
        report['focused_component_only'] = options.mode == 'focused'
        report['focused_includes_fresh_Body_control'] = options.mode == 'focused' and options.include_body
        compilation, cases = compile_cases([suffix for _, suffix, _, _ in selected])
        report['compilation'] = compilation; save()
        ensure(compilation.get('compile_exit_code') == compilation.get('compiler_error_count') == 0
               and compilation.get('compiled_fingerprints', {}).get('verified') is True
               and set(cases) == {suffix for _, suffix, _, _ in selected}, 'actual-feature-verified-compile-inventory')
        ensure(all(cases[suffix]['name'] == name for _, suffix, name, _ in selected)
               and len({case['binary_sha256'] for case in cases.values()}) == 1, 'exact-real-names-one-feature-verified-binary')
        report['feature_identity'] = feature_identity(compilation)
        report['compiled_binary_sha256'] = next(iter(cases.values()))['binary_sha256']
        for label, suffix, name, oracle in selected:
            case = cases[suffix]
            ensure(freeze() == before and layout() == modes and digest(Path(case['binary']).read_bytes()) == case['binary_sha256'], 'before-body-source-modes-binary-pristine')
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
            ensure(freeze() == before and layout() == modes and digest(Path(case['binary']).read_bytes()) == case['binary_sha256'], 'after-body-source-modes-binary-pristine')
            save()
            # A failing old scenario never hides the later required stress/clock/retry cases.
        report['actual_counts_complete'] = all(row['actual_counts_complete'] for row in report['cases'].values())
        report.update(alignment.aggregate_counts(report['cases']))
        report['component_green'] = report['cases']['request_retry']['green']
        if options.mode == 'controls':
            report['production_eight_green'] = all(report['cases'][label]['green'] for label, _, _ in alignment.historical.CASES)
            report['required_serial_stress_green'] = all(report['cases']['stress_' + str(index)]['green'] for index in range(3))
            report['source_policy_green'] = report['cases']['policy']['green']
            report['required_paused_clock_green'] = report['cases']['paused_clock']['green']
            report['all_fourteen_controls_green'] = (report['actual_counts_complete'] and report['actual_executed_nonignored'] == 14
                                                     and all(row['green'] for row in report['cases'].values()))
            save(); ensure(report['all_fourteen_controls_green'], 'all-fourteen-production-policy-stress-clock-and-retry-bodies-required')
        else:
            report['focused_Body_control_green'] = report['cases'].get('body', {}).get('green') if options.include_body else None
            save(); ensure(report['component_green'] and all(row['green'] for row in report['cases'].values()), 'every-selected-focused-control-required-not-overall-qualification')
    except Exception as error:
        report['exception_type'] = type(error).__name__
        raise
    finally:
        if before is not None:
            report['inputs_pristine'] = freeze() == before and layout() == modes
            report['source_after_sha256'] = identity(freeze())
        save()
        if before is not None: ensure(report['inputs_pristine'], 'final-source-modes-pristine')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--preflight', action='store_true')
    parser.add_argument('--mode', choices=['controls', 'focused', 'static'], default='controls')
    parser.add_argument('--cohort', choices=['default', 'experimental'])
    parser.add_argument('--include-body', action='store_true')
    main(parser.parse_args())
