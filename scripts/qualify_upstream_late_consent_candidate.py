#!/usr/bin/env python3
"""Fresh one-shot Consent progress GREEN; full integration qualification remains separate."""
import argparse
import json
import os
from pathlib import Path
import re
import subprocess
import time
import qualify_upstream_late_consent_red as red
import qualify_upstream_peer_proof as late_proof
from qualify_upstream_peer_proof_candidate import green as proof_green
from upstream_completion_ci import DEFAULT_FEATURES, FEATURES, compile_cases, digest, ensure, environment, headers, identity
from qualify_upstream_body_negative import feature_identity, freeze, layout

BASE = 'dd38298f3e6269c1911224b04c2833da25826dd8'
PRODUCT = 'crates/marmot-app/src/client/device_linking/sibling_sharing.rs'
PRODUCT_SHA256 = '21aee51aeb8f0e972f27a945370704148b6f81ee1f2c4d3ab359c78e0727e763'
SELF = 'scripts/qualify_upstream_late_consent_candidate.py'
WORKFLOW = '.github/workflows/experimental-sync-ci.yml'
OUT = Path('late-consent-candidate-evidence')
CASES = [('late_consent', red.CASE, red.TEST), ('late_proof', late_proof.CASE, late_proof.TEST)]


def consent_green(row):
    counts = {'body_exit_code': 0, 'passed': 1, 'failed': 0, 'ignored': 0,
              'executed_nonignored': 1, 'compiler_error_count': 0, 'all_panic_header_count': 0}
    return (all(type(row.get(name)) is int and row[name] == value for name, value in counts.items())
            and row.get('executed_case_names') == [red.TEST] and row.get('marker_count') == 1
            and row.get('runtime_closes') == row.get('planes_shutdown') == 3
            and row.get('relay_closed') is True and row.get('attempt_completed') is True
            and all(row.get('facts', {}).get(name) is True for name in red.FIELDS)
            and not row.get('watchdog_triggered') and not row.get('actual_count_unknown'))


def parser_controls():
    prior = red.parser_controls()
    marker = 'late-sibling-consent ' + ' '.join(name + '=true' for name in red.FIELDS)
    marker += ' runtime_closes=3 planes_shutdown=3 relay_closed=true attempt_completed=true'
    raw = 'test ' + red.TEST + ' ... ' + marker + '\ntest result: ok. 1 passed; 0 failed; 0 ignored;\n'
    for value in [raw, raw.replace(' ... ' + marker, ' ... \n' + marker)]:
        ensure(consent_green(red.parse(value, 0)), 'positive-late-consent-green-parser')
    negatives = [raw + marker + '\n', raw.replace(red.TEST, 'foreign::case'), raw.replace('1 passed', '0 passed'),
                 raw.replace('runtime_closes=3', 'runtime_closes=2'), raw.replace('planes_shutdown=3', 'planes_shutdown=2'),
                 raw.replace('relay_closed=true', 'relay_closed=false'), raw.replace('attempt_completed=true', 'attempt_completed=false'),
                 raw + '\nthread extra panicked at crates/other.rs:1:1:\n', 'error: compilation failed\n']
    negatives += [raw.replace(name + '=true', name + '=false') for name in red.FIELDS]
    for value in negatives:
        ensure(not consent_green(red.parse(value, 0)), 'missing-prerequisite-or-false-green-rejected')
    ensure(not consent_green(dict(red.parse(raw, 0), passed=True)), 'boolean-not-runtime-count')
    return {'historical_red': prior, 'green_positive': 2, 'green_negative': len(negatives) + 1, 'actual_runtime_bodies': 0}


def source_guard():
    source = subprocess.check_output(['git', 'rev-parse', 'HEAD'], text=True).strip()
    ensure(os.environ.get('GITHUB_ACTIONS') == 'true' and os.environ.get('GITHUB_REPOSITORY') == 'dyKiU/mdk'
           and source == os.environ.get('GITHUB_SHA'), 'approved-exact-remote-source')
    subprocess.run(['git', 'merge-base', '--is-ancestor', BASE, source], check=True)
    ensure(subprocess.run(['git', 'diff', '--quiet', 'HEAD']).returncode == 0, 'initial-pristine-source')
    changed = set(subprocess.check_output(['git', 'diff', '--name-only', BASE, 'HEAD'], text=True).splitlines())
    ensure(changed <= {PRODUCT, SELF, WORKFLOW}, 'only-reviewed-one-shot-consent-product-and-metadata')
    ensure(digest(Path(PRODUCT).read_bytes()) == PRODUCT_SHA256, 'exact-reviewed-full-product-bytes')
    metadata = layout()
    for name in changed:
        ensure(metadata[name]['git_mode'] == '100644' and not metadata[name]['actual_executable'] and not metadata[name]['symlink'], 'reviewed-ordinary-product-metadata-modes')
    exact = [red.FILE, red.PROBE, red.REGISTER, red.SELF, late_proof.FILE, 'scripts/qualify_upstream_peer_proof.py',
             'scripts/qualify_upstream_peer_proof_candidate.py']
    for name in exact:
        ensure(Path(name).read_bytes() == subprocess.check_output(['git', 'show', BASE + ':' + name]), 'exact-unchanged-test-probe-historical-controller:' + name)
    workflow = Path(WORKFLOW).read_text()
    begin, end = '  # LATE_CONSENT_CANDIDATE_JOBS_BEGIN\n', '  # LATE_CONSENT_CANDIDATE_JOBS_END\n'
    ensure(workflow.count(begin) == workflow.count(end) == 1, 'one-isolated-candidate-workflow-addition')
    before, rest = workflow.split(begin)
    _, after = rest.split(end)
    restored = (before + after).replace('options: [late-consent-candidate-preflight, late-consent-candidate-green, ', 'options: [', 1)
    ensure(restored.encode() == subprocess.check_output(['git', 'show', BASE + ':' + WORKFLOW]), 'all-historical-workflow-jobs-and-options-preserved')
    return {'source': source, 'baseline': BASE, 'reviewed_product_sha256': PRODUCT_SHA256,
            'genuine_red_run': 39060926547, 'all_existing_tests_probes_controllers_sdk_deadlines_unchanged': True,
            'four_device_failure_cause_established': False, 'historical_runtime_evidence_reused': False, 'counterfactual_hint_and_wake_omission_pending': True}


def main(options):
    os.umask(0o077); OUT.mkdir(exist_ok=True)
    report = {'mode': options.mode, 'green_passed': False, 'qualification_passed': False, 'phases': {}}
    frozen, metadata = freeze(), layout()
    report['input_manifest_sha256'] = identity(frozen)
    def pristine(): return freeze() == frozen and layout() == metadata
    def save(): (OUT / 'result.json').write_text(json.dumps(report, indent=2) + '\n')
    try:
        report['source_preflight'] = source_guard(); report['source'] = report['source_preflight']['source']
        report['parser_controls'] = parser_controls(); save()
        if options.preflight: return
        report.update(environment())
        if options.mode == 'static':
            ensure(options.cohort in {'default', 'experimental'}, 'explicit-static-feature-cohort')
            command = ['cargo', 'clippy', '--locked', '-p', 'marmot-app', '--all-targets', '--features', FEATURES if options.cohort == 'experimental' else DEFAULT_FEATURES, '--', '-D', 'warnings']
            started = time.monotonic(); result = subprocess.run(command, capture_output=True, text=True, timeout=1800)
            report.update(cohort=options.cohort, command=command, exit_code=result.returncode,
                          seconds=time.monotonic() - started, **headers(result.stderr))
            report['static_passed'] = result.returncode == report['compiler_error_count'] == 0 and pristine()
            ensure(report['static_passed'], 'actual-static-cohort-not-green'); return
        for label, suffix, name in CASES:
            ensure(pristine(), 'before-directed-phase-inputs-exact')
            row = {'actual_counts_complete': False}; report['phases'][label] = row; save()
            compilation, cases = compile_cases([suffix]); row['compilation'] = compilation; save()
            ensure(compilation.get('compile_exit_code') == compilation.get('compiler_error_count') == 0
                   and compilation.get('compiled_fingerprints', {}).get('verified') is True
                   and set(cases) == {suffix} and cases[suffix]['name'] == name, 'actual-sole-nonignored-compiled-feature-cohort')
            features = feature_identity(compilation)
            command = list(features['command']); ensure(command.count('-E') == 1, 'one-exact-directed-filter')
            index = command.index('-E') + 1; ensure(command[index] == 'test(' + suffix + ')', 'actual-exact-directed-filter')
            command[index] = 'test(<verified-directed-case>)'
            features = dict(features, command=command)
            if 'compiled_feature_identity' in report: ensure(features == report['compiled_feature_identity'], 'same-compiled-feature-profile-cohort')
            else: report['compiled_feature_identity'] = features
            case = cases[suffix]; row['compiled_binary_sha256'] = case['binary_sha256']
            ensure(pristine() and digest(Path(case['binary']).read_bytes()) == case['binary_sha256'], 'compiled-source-and-binary-exact')
            if label == 'late_proof': ensure(row['compiled_binary_sha256'] == report['phases']['late_consent']['compiled_binary_sha256'], 'same-directed-app-binary')
            started = time.monotonic()
            try:
                result = subprocess.run([case['binary'], '--exact', name, '--nocapture', '--test-threads=1'], capture_output=True, text=True, timeout=300)
                row['body'] = red.parse(result.stdout + result.stderr, result.returncode) if label == 'late_consent' else late_proof.parse(result.stdout + result.stderr, result.returncode)
            except subprocess.TimeoutExpired:
                row['body'] = {'watchdog_triggered': True, 'actual_count_unknown': True}
            row['body']['seconds'] = time.monotonic() - started
            row['actual_counts_complete'] = all(type(row['body'].get(key)) is int for key in ['passed', 'failed', 'ignored', 'executed_nonignored']) and row['body']['executed_nonignored'] == 1 and not row['body'].get('watchdog_triggered')
            row['green_passed'] = consent_green(row['body']) if label == 'late_consent' else proof_green(row['body'])
            ensure(pristine() and digest(Path(case['binary']).read_bytes()) == case['binary_sha256'], 'actual-runtime-source-binary-unchanged'); save()
            ensure(row['green_passed'], 'unchanged-directed-runtime-not-green')
        report['green_passed'] = all(row['green_passed'] for row in report['phases'].values())
    except Exception as error:
        report['controller_exception'] = type(error).__name__
        raise
    finally:
        report['inputs_pristine'] = pristine() and subprocess.run(['git', 'diff', '--quiet', 'HEAD']).returncode == 0
        phases = list(report['phases'].values())
        report['actual_runtime_bodies'] = sum(row.get('body', {}).get('executed_nonignored', 0) for row in phases)
        report['actual_executed_nonignored'] = report['actual_runtime_bodies']
        for name in ['passed', 'failed', 'ignored']:
            report['actual_' + name] = sum(row.get('body', {}).get(name, 0) for row in phases)
        report['actual_counts_complete'] = all(row.get('actual_counts_complete') is True for row in phases)
        save()
        ensure(report['inputs_pristine'], 'final-source-not-pristine')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--preflight', action='store_true')
    parser.add_argument('--mode', choices=['green', 'static'], default='green')
    parser.add_argument('--cohort', choices=['default', 'experimental'])
    main(parser.parse_args())
