#!/usr/bin/env python3
"""Actual public cancellation and labelled injected validation rejection, not revocation qualification."""
import argparse
import io
import json
import os
from pathlib import Path
import re
import subprocess
import time
import zipfile
from upstream_completion_ci import DEFAULT_FEATURES, FEATURES, compile_cases, digest, ensure, environment, headers, identity, parse_body
from qualify_upstream_body_negative import freeze, layout, feature_identity

BASE = 'bc7bf63f645c1490b6dba7061e0207a9452cff96'
FILE = 'crates/marmot-app/src/native_device_linking/tests/late_peer_proof_negative_acceptance.rs'
PRODUCT = 'crates/marmot-app/src/client/device_linking/sibling_sharing.rs'
SELF = 'scripts/qualify_upstream_peer_proof_negatives.py'
WORKFLOW = '.github/workflows/experimental-sync-ci.yml'
CASES = {'public-cancel': 'late_peer_proof_public_cancel_cannot_complete_original',
         'injected-validation': 'late_peer_proof_injected_validation_rejection_retains_and_recovers'}
PREFIX = 'native_device_linking::automatic_pairing_acceptance::late_peer_proof_negative_acceptance::'
FIELDS = ['held', 'own_harvested', 'periodic_observed', 'fresh_before', 'negative_preserved',
          'recovered_or_retired', 'no_replay', 'ownership_preserved', 'enrollment_complete', 'public_cancelled']
MARKER = 'late-peer-negative mode=(public-cancel|injected-validation) ' + ' '.join(name + '=(true|false)' for name in FIELDS)
MARKER += r' accepted=([0-9]+) validation_rejections=([0-9]+) own_publications=([0-9]+) open_attempts=([0-9]+) routed_after_cancel=([0-9]+) closed_denials=([0-9]+) runtime_closes=([0-9]+) planes_shutdown=([0-9]+) relay_closed=(true|false) attempt_completed=(true|false)'
MESSAGE = 'late_peer_proof_negative_guard_and_positive_cleanup'
MUTANT_OLD = '''                            Err(_) => {
                                tracing::debug!(
'''
MUTANT_NEW = '''                            Err(_) => {
                                Self::complete_sibling_sharing(&entry);
                                tracing::debug!(
'''
HOOKS = {PRODUCT: 7, 'crates/marmot-app/src/client/device_linking/sibling_sharing/peer_proof_probe.rs': 6,
         'crates/marmot-app/src/native_device_linking/tests/automatic_pairing_acceptance.rs': 1}
NEW = {FILE, SELF, 'crates/marmot-app/src/client/device_linking/sibling_sharing/peer_proof_probe/negative.rs'}
OUT = Path('peer-proof-negative-evidence')


def location():
    lines = Path(FILE).read_text().splitlines()
    matches = [index for index, line in enumerate(lines) if MESSAGE in line]
    ensure(len(matches) == 1, 'one-own-negative-final-assertion')
    return {'file': FILE, 'line': max(index for index in range(matches[0]+1) if 'assert!(' in lines[index])+1}


def parse(raw, mode, exit_code):
    raw = re.sub(r'\x1b\[[0-9;]*m', '', raw)
    row = parse_body(raw, CASES[mode])
    row.update(body_exit_code=exit_code, compiler_error_count=headers(raw)['compiler_error_count'])
    row['executed_case_names'] = re.findall(r'(?m)^test ([A-Za-z0-9_:]+) \.\.\.', raw)
    prefix = r'(?:test ' + re.escape(PREFIX + CASES[mode]) + r' \.\.\. )?'
    values = re.findall(r'(?m)^' + prefix + MARKER + '$', raw)
    row['marker_count'] = len(values)
    if len(values) == 1:
        values = values[0]
        row['mode'] = values[0]
        row['facts'] = dict(zip(FIELDS, [value == 'true' for value in values[1:11]]))
        row.update(dict(zip(['accepted', 'validation_rejections', 'own_publications', 'open_attempts', 'routed_after_cancel', 'closed_denials', 'runtime_closes', 'planes_shutdown'], map(int, values[11:19]))))
        row.update(relay_closed=values[19] == 'true', attempt_completed=values[20] == 'true')
    row['intended_assertion_observed'] = MESSAGE in raw
    return row


def prerequisites(row, mode):
    return (row.get('mode') == mode and row.get('marker_count') == 1
            and row.get('runtime_closes') == row.get('planes_shutdown') == 3
            and row.get('relay_closed') is True and row.get('attempt_completed') is True
            and row.get('own_publications') == 0
            and all(row.get('facts', {}).get(name) is True for name in FIELDS if name != 'negative_preserved')
            and ((mode == 'public-cancel' and row.get('routed_after_cancel') == row.get('closed_denials') == 1 and row.get('accepted') == row.get('validation_rejections') == row.get('open_attempts') == 0)
                 or (mode == 'injected-validation' and row.get('routed_after_cancel') == row.get('closed_denials') == 0 and row.get('accepted') == row.get('open_attempts') == 1 and type(row.get('validation_rejections')) is int and row['validation_rejections'] > 0)))


def green(row, mode):
    return (prerequisites(row, mode) and row.get('facts', {}).get('negative_preserved') is True
            and row.get('body_exit_code') == 0 and row.get('passed') == row.get('executed_nonignored') == 1
            and row.get('failed') == row.get('ignored') == row.get('compiler_error_count') == row.get('all_panic_header_count') == 0
            and row.get('executed_case_names') == [PREFIX + CASES[mode]] and not row.get('watchdog_triggered'))


def killed(row):
    own = location(); panics = row.get('panic_locations', [])
    return (prerequisites(row, 'injected-validation') and row.get('facts', {}).get('negative_preserved') is False
            and row.get('body_exit_code') == 101 and row.get('passed') == row.get('ignored') == row.get('compiler_error_count') == 0
            and row.get('failed') == row.get('executed_nonignored') == row.get('all_panic_header_count') == 1
            and row.get('executed_case_names') == [PREFIX + CASES['injected-validation']]
            and row.get('intended_assertion_observed') is True and len(panics) == 1
            and all(panics[0].get(key) == value for key, value in own.items()) and not row.get('watchdog_triggered'))


def parser_preflight():
    positive = negative = 0
    for mode in CASES:
        marker = 'late-peer-negative mode=' + mode + ' ' + ' '.join(name + '=true' for name in FIELDS)
        marker += ' accepted=' + ('1' if mode == 'injected-validation' else '0')
        marker += ' validation_rejections=' + ('1' if mode == 'injected-validation' else '0')
        marker += ' own_publications=0 open_attempts=' + ('1' if mode == 'injected-validation' else '0') + ' routed_after_cancel=' + ('0' if mode == 'injected-validation' else '1') + ' closed_denials=' + ('0' if mode == 'injected-validation' else '1') + ' runtime_closes=3 planes_shutdown=3 relay_closed=true attempt_completed=true'
        raw = 'running 1 test\ntest ' + PREFIX + CASES[mode] + ' ... ' + marker + '\ntest result: ok. 1 passed; 0 failed; 0 ignored;\n'
        for text in [raw, raw.replace(' ... ' + marker, ' ... \n' + marker)]: ensure(green(parse(text, mode, 0), mode), 'green-parser'); positive += 1
        variants = [raw + marker + '\n', raw.replace(PREFIX + CASES[mode], 'foreign::test'), raw.replace('runtime_closes=3', 'runtime_closes=2'), raw.replace('planes_shutdown=3', 'planes_shutdown=2'), raw.replace('own_publications=0', 'own_publications=1'), raw.replace('open_attempts=' + ('1' if mode == 'injected-validation' else '0'), 'open_attempts=2'), raw.replace('relay_closed=true', 'relay_closed=false'), raw.replace('1 passed', '0 passed')]
        for name in ['routed_after_cancel', 'closed_denials']:
            expected = '0' if mode == 'injected-validation' else '1'
            variants += [raw.replace(' ' + name + '=' + expected, ''), raw.replace(name + '=' + expected, name + '=2'), raw.replace(name + '=' + expected, name + '=' + ('1' if expected == '0' else '0')), raw.replace(' ' + name + '=' + expected, ' ' + name + '=' + expected + ' ' + name + '=' + expected)]
        variants += [raw.replace(name + '=true', name + '=false') for name in FIELDS]
        for value in variants: ensure(not green(parse(value, mode, 0), mode), 'adversarial-green-parser'); negative += 1
        if mode == 'injected-validation':
            own = location()
            red = raw.replace('negative_preserved=true', 'negative_preserved=false').replace('test result: ok. 1 passed; 0 failed;', "thread '" + PREFIX + CASES[mode] + "' panicked at " + FILE + ':' + str(own['line']) + ':5:\n' + MESSAGE + '\ntest result: FAILED. 0 passed; 1 failed;')
            ensure(killed(parse(red, mode, 101)), 'sole-own-guard-assertion-red-parser'); positive += 1
            variants = [red.replace('negative_preserved=false', 'negative_preserved=true'), red + marker + '\n', red.replace('accepted=1', 'accepted=2'), red.replace('validation_rejections=1', 'validation_rejections=0'), red.replace(FILE + ':' + str(own['line']), FILE + ':1'), red + '\nthread extra panicked at crates/other.rs:1:1:\n', 'error: compile failure\n']
            for name in ['routed_after_cancel', 'closed_denials']:
                variants += [red.replace(' ' + name + '=0', ''), red.replace(name + '=0', name + '=1')]
            variants += [red.replace(name + '=true', name + '=false') for name in FIELDS if name != 'negative_preserved']
            for value in variants: ensure(not killed(parse(value, mode, 101)), 'adversarial-red-parser'); negative += 1
    return {'positive': positive, 'negative': negative, 'actual_runtime_bodies': 0}


def source_guard():
    source = subprocess.check_output(['git', 'rev-parse', 'HEAD'], text=True).strip()
    ensure(os.environ.get('GITHUB_ACTIONS') == 'true' and os.environ.get('GITHUB_REPOSITORY') == 'dyKiU/mdk' and source == os.environ.get('GITHUB_SHA'), 'approved-exact-remote-source')
    subprocess.run(['git', 'merge-base', '--is-ancestor', BASE, source], check=True)
    ensure(subprocess.run(['git', 'diff', '--quiet', 'HEAD']).returncode == 0, 'pristine')
    changed = set(subprocess.check_output(['git', 'diff', '--name-only', BASE, 'HEAD'], text=True).splitlines())
    ensure(changed <= set(HOOKS) | NEW | {WORKFLOW}, 'only-explicit-test-hook-files-controller-workflow')
    pattern = rb'(?m)^[ \t]*// PEER_NEGATIVE_TEST_BEGIN\n.*?^[ \t]*// PEER_NEGATIVE_TEST_END\n'
    for name, count in HOOKS.items():
        data = Path(name).read_bytes()
        ensure(data.count(b'PEER_NEGATIVE_TEST_BEGIN') == data.count(b'PEER_NEGATIVE_TEST_END') == count, 'bounded-negative-test-hooks')
        ensure(re.sub(pattern, b'', data, flags=re.S) == subprocess.check_output(['git', 'show', BASE + ':' + name]), 'exact-unchanged-production-and-existing-tests-after-strip')
        ensure(subprocess.check_output(['git', 'ls-tree', BASE, name]).split()[0] == subprocess.check_output(['git', 'ls-tree', 'HEAD', name]).split()[0], 'hook-mode-exact')
    return {'source': source, 'baseline': BASE, 'existing_product_tests_sdk_exact_after_strip': True,
            'injection_is_actual_sqlite_fault': False, 'real_stale_parent_revocation_qualified': False}


def previous_control(run_id, report):
    ensure(run_id.isdecimal(), 'exact-prior-negative-control-required')
    repo = os.environ['GITHUB_REPOSITORY']
    def api(path): return subprocess.check_output(['gh', 'api', 'repos/' + repo + '/' + path], timeout=60)
    run = json.loads(api('actions/runs/' + run_id))
    ensure(run['repository']['full_name'] == repo and run['head_sha'] == report['source'] and run['status'] == 'completed' and run['conclusion'] == 'success' and run['event'] == 'workflow_dispatch' and run['path'] == WORKFLOW, 'prior-source-workflow-status')
    artifacts = json.loads(api('actions/runs/' + run_id + '/artifacts?per_page=100'))['artifacts']
    rows = [row for row in artifacts if row['name'] == 'peer-proof-negative-controls' and not row['expired']]
    ensure(len(rows) == 1 and 0 < rows[0]['size_in_bytes'] < 1000000, 'bounded-prior-negative-artifact')
    artifact = rows[0]; data = api('actions/artifacts/' + str(artifact['id']) + '/zip')
    ensure(len(data) == artifact['size_in_bytes'] and len(data) < 1000000 and artifact.get('digest') == 'sha256:' + digest(data), 'actual-prior-negative-digest')
    with zipfile.ZipFile(io.BytesIO(data)) as archive:
        files = [entry for entry in archive.infolist() if Path(entry.filename).name == 'result.json']
        ensure(len(files) == 1 and files[0].file_size < 1000000, 'one-prior-negative-result')
        old = json.loads(archive.read(files[0]))
    ensure(old['source'] == report['source'] and old['mode'] == 'controls' and old['controls_passed'] and old['inputs_pristine'] and old['actual_counts_complete'] and old['actual_executed_nonignored'] == 2 and old['input_manifest_sha256'] == report['input_manifest_sha256'] and old['toolchain'] == report['toolchain'] and old['environment'] == report['environment'], 'prior-two-real-controls-exact')
    for mode in CASES: ensure(green(old['phases'][mode]['body'], mode), 'prior-real-own-negative-control')
    static_receipts = []
    for cohort in ['default', 'experimental']:
        rows = [row for row in artifacts if row['name'] == 'peer-proof-negative-static-' + cohort and not row['expired']]
        ensure(len(rows) == 1 and 0 < rows[0]['size_in_bytes'] < 1000000, 'one-bounded-prior-static-artifact')
        entry = rows[0]; content = api('actions/artifacts/' + str(entry['id']) + '/zip')
        ensure(len(content) == entry['size_in_bytes'] and len(content) < 1000000 and entry.get('digest') == 'sha256:' + digest(content), 'actual-prior-static-digest')
        with zipfile.ZipFile(io.BytesIO(content)) as archive:
            files = [item for item in archive.infolist() if Path(item.filename).name == 'result.json']
            ensure(len(files) == 1 and files[0].file_size < 1000000, 'one-prior-static-result')
            proof = json.loads(archive.read(files[0]))
        ensure(proof['source'] == report['source'] and proof['mode'] == 'static' and proof['cohort'] == cohort
               and proof['static_passed'] and proof['inputs_pristine'] and proof['actual_counts_complete']
               and proof['actual_executed_nonignored'] == proof['actual_runtime_bodies'] == proof['exit_code'] == proof['compiler_error_count'] == 0
               and proof['input_manifest_sha256'] == report['input_manifest_sha256']
               and proof['toolchain'] == report['toolchain'] and proof['environment'] == report['environment'], 'actual-prior-both-static-cohorts')
        static_receipts.append({'cohort': cohort, 'id': entry['id'], 'digest': entry['digest'], 'download_digest_verified': True})
    return {'run_id': int(run_id), 'artifact_id': artifact['id'], 'digest': artifact['digest'],
            'compiled_feature_identity': old['compiled_feature_identity'], 'static_artifacts': static_receipts}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--mode', choices=['controls', 'mutation', 'static'], default='controls')
    parser.add_argument('--cohort', choices=['default', 'experimental'])
    parser.add_argument('--preflight', action='store_true')
    args = parser.parse_args(); os.umask(0o077); OUT.mkdir(exist_ok=True)
    report = {'mode': args.mode, 'qualification_passed': False, 'controls_passed': False, 'mutation_chain_passed': False, 'phases': {}}
    def save(): (OUT / 'result.json').write_text(json.dumps(report, indent=2) + '\n')
    original = Path(PRODUCT).read_bytes(); frozen, metadata = freeze(), layout()
    report['input_manifest_sha256'] = identity(frozen)
    def pristine(expected=frozen): return freeze() == expected and layout() == metadata
    def phase(label, mode, expected=frozen):
        ensure(pristine(expected), 'phase-source-exact')
        compilation, cases = compile_cases([CASES[mode]])
        row = {'compilation': compilation, 'actual_counts_complete': False}; report['phases'][label] = row; save()
        ensure(compilation.get('compile_exit_code') == compilation.get('compiler_error_count') == 0 and compilation.get('compiled_fingerprints', {}).get('verified') is True and set(cases) == {CASES[mode]} and cases[CASES[mode]]['name'] == PREFIX + CASES[mode], 'actual-one-compiled-case')
        features = feature_identity(compilation)
        # Freeze every compile argument except the independently checked exact case selector.
        common_command = list(features['command'])
        ensure(common_command.count('-E') == 1, 'one-exact-case-filter-argument')
        selection = common_command.index('-E') + 1
        ensure(common_command[selection] == 'test(' + CASES[mode] + ')', 'actual-exact-case-filter')
        common_command[selection] = 'test(<exact-case-recorded-per-phase>)'
        feature_cohort = dict(features, command=common_command)
        if 'compiled_feature_identity' in report: ensure(feature_cohort == report['compiled_feature_identity'], 'same-feature-cohort')
        else: report['compiled_feature_identity'] = feature_cohort
        case = cases[CASES[mode]]; row['compiled_binary_sha256'] = case['binary_sha256']
        ensure(pristine(expected) and digest(Path(case['binary']).read_bytes()) == case['binary_sha256'], 'compiled-source-and-binary-exact')
        started = time.monotonic()
        try:
            command = [case['binary'], '--exact', PREFIX + CASES[mode], '--nocapture', '--test-threads=1']
            result = subprocess.run(command, capture_output=True, text=True, timeout=300)
            row['body'] = parse(result.stdout + result.stderr, mode, result.returncode)
        except subprocess.TimeoutExpired: row['body'] = {'watchdog_triggered': True}
        row['body']['seconds'] = time.monotonic() - started
        body = row['body']
        row['actual_counts_complete'] = all(type(body.get(key)) is int and body[key] >= 0 for key in ['passed','failed','ignored','executed_nonignored']) and body['executed_nonignored'] == body['passed'] + body['failed'] and not body.get('watchdog_triggered')
        ensure(pristine(expected) and digest(Path(case['binary']).read_bytes()) == case['binary_sha256'], 'runtime-source-and-binary-exact'); save()
        return body
    try:
        report['source_preflight'] = source_guard(); report['source'] = report['source_preflight']['source']; report['parser_controls'] = parser_preflight(); save()
        if args.preflight: return
        report.update(environment())
        if args.mode == 'static':
            ensure(args.cohort is not None, 'static-cohort-required')
            command = ['cargo','clippy','--locked','-p','marmot-app','--all-targets','--features',FEATURES if args.cohort == 'experimental' else DEFAULT_FEATURES,'--','-D','warnings']
            result = subprocess.run(command, capture_output=True, text=True, timeout=1800)
            report.update(cohort=args.cohort, exit_code=result.returncode, command=command, actual_runtime_bodies=0, **headers(result.stderr))
            report['static_passed'] = result.returncode == report['compiler_error_count'] == 0 and pristine()
            ensure(report['static_passed'], 'actual-negative-static-cohort'); return
        if args.mode == 'controls':
            for mode in CASES: ensure(green(phase(mode, mode), mode), 'actual-public-cancel-and-injected-recovery-controls')
            report['controls_passed'] = True
        else:
            report['prior_control'] = previous_control(os.environ.get('PEER_PROOF_NEGATIVE_CONTROL_RUN_ID', ''), report)
            ensure(green(phase('baseline', 'injected-validation'), 'injected-validation'), 'actual-baseline-green')
            ensure(report['compiled_feature_identity'] == report['prior_control']['compiled_feature_identity'], 'same-prior-feature-cohort')
            text = original.decode(); ensure(text.count(MUTANT_OLD) == 1, 'one-validation-error-grant-anchor')
            changed = text.replace(MUTANT_OLD, MUTANT_NEW, 1).encode(); mutation_error = None
            try:
                Path(PRODUCT).write_bytes(changed); expected = freeze()
                ensure(layout() == metadata and set(expected) == set(frozen) and {name for name in frozen if frozen[name] != expected[name]} == {PRODUCT}, 'sole-improper-error-grant-mutant')
                report['runtime_mutant_killed'] = killed(phase('error-grant', 'injected-validation', expected))
            except Exception as error: mutation_error = type(error).__name__; report['mutation_exception'] = mutation_error
            finally: Path(PRODUCT).write_bytes(original); report['source_restored'] = pristine(); save()
            ensure(report['source_restored'], 'exact-restoration')
            restored = phase('restored', 'injected-validation')
            report['restored_binary_identical'] = report['phases']['baseline']['compiled_binary_sha256'] == report['phases']['restored']['compiled_binary_sha256']
            report['mutation_chain_passed'] = bool(mutation_error is None and report.get('runtime_mutant_killed') and green(restored, 'injected-validation') and report['restored_binary_identical'])
            ensure(report['mutation_chain_passed'], 'sole-own-runtime-kill-and-restored-control')
    except Exception as error: report['controller_exception'] = type(error).__name__; raise
    finally:
        Path(PRODUCT).write_bytes(original); report['inputs_pristine'] = pristine() and subprocess.run(['git','diff','--quiet','HEAD']).returncode == 0
        rows = list(report['phases'].values()); report['actual_counts_complete'] = all(row.get('actual_counts_complete') is True for row in rows)
        report['actual_executed_nonignored'] = sum(row.get('body', {}).get('executed_nonignored', 0) for row in rows if type(row.get('body', {}).get('executed_nonignored')) is int)
        save(); ensure(report['inputs_pristine'] and report['actual_counts_complete'], 'exact-final-source-and-counts')


if __name__ == '__main__': main()
