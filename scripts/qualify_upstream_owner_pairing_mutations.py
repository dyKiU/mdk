#!/usr/bin/env python3
"""Remote-only exact-source owner pairing mutation chains; no native qualification."""
import argparse
import json
import os
from pathlib import Path
import re
import subprocess
import time
from upstream_completion_ci import compile_cases, digest, ensure, headers, parse_body
from upstream_extraction_cohort import reviewed_cohort
from qualify_upstream_body_negative import freeze, layout, feature_identity

APP_FILE = 'crates/marmot-app/src/native_device_linking/tests/automatic_pairing_acceptance.rs'
CORE_FILE = 'crates/cgka-engine/tests/accepted_welcome_receipts/private_batch.rs'
APP_PREFIX = 'native_device_linking::automatic_pairing_acceptance::'
CASES = {
    'readiness': {
        'package': 'marmot-app', 'stack': 4194304,
        'name': APP_PREFIX + 'automatic_pairing_delayed_recipient_approval_does_not_lose_welcome',
        'source': 'crates/marmot-app/src/native_device_linking/enabled/automatic.rs',
        'old': '} else if authorized && (original.inner.new_device || self.peer_recipient_ready) {',
        'new': '} else if authorized {',
        'panic_file': APP_FILE,
        'panic_anchor': 'panic!("automatic pairing did not reach required phase: expected={phase:?} observed={observed:?}")',
        'message': 'automatic pairing did not reach required phase: expected=EnrollmentComplete',
        'claim': 'Bypass recipient readiness; require observed premature Welcome plus the exact final enrollment assertion. A survivor or another failure does not qualify.',
    },
    'unrelated-welcome': {
        'package': 'marmot-app', 'stack': 4194304,
        'name': APP_PREFIX + 'another_installations_private_welcome_cannot_abort_an_approved_recipient',
        'source': 'crates/marmot-app/src/client/device_linking.rs',
        'old': 'Err(ClientLinkingError::Collection(CollectionError::UnrelatedContext)) => {\n                Ok(Some(PrivateWelcomeIngress::Unrelated))\n            }',
        'new': 'Err(ClientLinkingError::Collection(CollectionError::UnrelatedContext)) => {\n                Err(ClientLinkingError::Collection(CollectionError::UnrelatedContext))\n            }',
        'panic_file': APP_FILE,
        'assert_function': 'another_installations_private_welcome_cannot_abort_an_approved_recipient',
        'assert_anchor': 'assert_eq!(\n        current.phase,\n        DeviceLinkingPhase::VerificationCompleteEnrollmentPending\n    );',
        'message': 'assertion `left == right` failed',
        'claim': 'Return unrelated authenticated inbox context as an owner-fatal error; require the exact existing phase-preservation assertion with Failed versus VerificationCompleteEnrollmentPending. Expiry, cancellation and other failures cannot qualify.',
    },
    'historical-policy': {
        'package': 'cgka-engine', 'stack': 16777216,
        'name': 'private_batch::private_batch_unused_birth_retirement_preserves_historical_sharing_policy',
        'source': 'crates/cgka-engine/src/private_linking_join.rs',
        'old': '            .approved_account_sharing_policies()?\n            .is_empty()\n            || self',
        'new': '            .approved_account_sharing_policies()?\n            .is_empty()\n            && false\n            || self',
        'panic_file': CORE_FILE,
        'assert_function': 'private_batch_unused_birth_retirement_preserves_historical_sharing_policy',
        'message': 'Err(cgka_traits::EngineError::LinkingWelcomeDenied(_))',
        'claim': 'Ignore only the historical sharing-policy denial guard, retaining the settlement guard. Real MLS with injected revoked policy proves negative refusal, not human consent.',
    },
    'retirement-omission': {
        'package': 'cgka-engine', 'stack': 16777216,
        'name': 'private_batch::private_batch_join_retires_only_unused_birth_atomically',
        'source': 'crates/cgka-engine/src/group_lifecycle.rs',
        'old': '                    self.retire_unused_genesis_for_private_join()?;\n',
        'new': '',
        'panic_file': CORE_FILE,
        'assert_function': 'private_batch_join_retires_only_unused_birth_atomically',
        'message': 'Err(cgka_traits::EngineError::Storage(_))',
        'claim': 'Omit authenticated unused-birth retirement. Require the exact expected SQL-fault predicate; omission can deny before reaching the trigger. This kill alone is not proof of post-join retirement or fault execution in the mutant.',
    },
}


def location(case):
    text = Path(case['panic_file']).read_text()
    if 'assert_anchor' in case:
        start = text.index('async fn ' + case['assert_function'] + '(')
        end = text.find('\n#[tokio::test', start)
        body = text[start:end if end >= 0 else len(text)]
        ensure(body.count(case['assert_anchor']) == 1, 'one-exact-scoped-phase-assertion')
        offset = start + body.index(case['assert_anchor'])
    elif 'panic_anchor' in case:
        ensure(text.count(case['panic_anchor']) == 1, 'one-exact-own-panic-anchor')
        offset = text.index(case['panic_anchor'])
    else:
        start = text.index('async fn ' + case['assert_function'] + '(')
        end = text.find('\n#[tokio::test', start)
        body = text[start:end if end >= 0 else len(text)]
        anchor = 'assert!(matches!(\n        f.recipient\n            .join_private_linking_welcome_batch'
        ensure(body.count(anchor) == 1 and case['message'] in body, 'one-exact-own-behavioral-predicate')
        offset = start + body.index(anchor)
    return {'file': case['panic_file'], 'line': text[:offset].count('\n') + 1}


def parse(raw, case, exit_code):
    raw = re.sub(r'\x1b\[[0-9;]*m', '', raw)
    row = parse_body(raw, case['name'].rsplit('::', 1)[-1])
    row.update(body_exit_code=exit_code, compiler_error_count=headers(raw)['compiler_error_count'])
    row['executed_case_names'] = re.findall(r'(?m)^test ([A-Za-z0-9_:]+) \.\.\.', raw)
    row['expected_panic'] = location(case)
    row['intended_assertion_observed'] = case['message'] in raw
    prefix = r'(?:test ' + re.escape(case['name']) + r' \.\.\. )?'
    row['early_welcome_observations'] = re.findall(
        r'(?m)^' + prefix + r'automatic-approval-order-control early_welcome_cached=(true|false)$', raw)
    if case is CASES['unrelated-welcome']:
        phases = 'AwaitingSetup|AwaitingPeer|ComparisonAvailable|AwaitingPeerVerification|VerificationCompleteEnrollmentPending|Cancelled|Expired|Failed|EnrollmentComplete'
        matches = re.findall(r'(?m)^assertion `left == right` failed\n[ ]+left: (' + phases + r')\n[ ]+right: (' + phases + r')$', raw)
        row['phase_assertions'] = [{'left': left, 'right': right} for left, right in matches[:2]]
        row['phase_assertion_count'] = len(matches)
        row['phase_assertion_header_count'] = len(re.findall(r'(?m)^assertion `left == right` failed$', raw))
    return row


def exact_numbers(row, values):
    return all(type(row.get(key)) is int and row[key] == value for key, value in values.items())


def green(row, case):
    return (exact_numbers(row, {'body_exit_code': 0, 'passed': 1, 'failed': 0, 'ignored': 0,
                              'executed_nonignored': 1, 'compiler_error_count': 0, 'all_panic_header_count': 0})
            and row.get('executed_case_names') == [case['name']]
            and not row.get('watchdog_triggered') and not row.get('actual_count_unknown')
            and (case is not CASES['readiness'] or row.get('early_welcome_observations') == ['false']))


def killed(row, case):
    locations = row.get('panic_locations', [])
    return (exact_numbers(row, {'body_exit_code': 101, 'passed': 0, 'failed': 1, 'ignored': 0,
                              'executed_nonignored': 1, 'compiler_error_count': 0, 'all_panic_header_count': 1})
            and len(locations) == 1
            and all(locations[0].get(key) == value for key, value in row['expected_panic'].items())
            and row.get('executed_case_names') == [case['name']]
            and row.get('intended_assertion_observed') is True
            and not row.get('watchdog_triggered') and not row.get('actual_count_unknown')
            and (case is not CASES['readiness'] or row.get('early_welcome_observations') == ['true'])
            and (case is not CASES['unrelated-welcome'] or
                 (row.get('phase_assertion_header_count') == 1 and row.get('phase_assertion_count') == 1 and row.get('phase_assertions') == [
                     {'left': 'Failed', 'right': 'VerificationCompleteEnrollmentPending'}])))


def parser_preflight():
    positive = negative = 0
    for case in CASES.values():
        own = location(case)
        marker = 'automatic-approval-order-control early_welcome_cached=false\n' if case is CASES['readiness'] else ''
        raw = 'test ' + case['name'] + ' ... ok\n' + marker + 'test result: ok. 1 passed; 0 failed; 0 ignored;\n'
        control = parse(raw, case, 0)
        ensure(green(control, case) and not killed(control, case), 'parser-green'); positive += 1
        red = raw.replace(' ... ok', ' ... FAILED').replace('false\n', 'true\n').replace('test result: ok. 1 passed; 0 failed;', 'test result: FAILED. 0 passed; 1 failed;')
        red += f"thread case panicked at {own['file']}:{own['line']}:5:\n{case['message']}\n"
        if case is CASES['unrelated-welcome']:
            red += '  left: Failed\n right: VerificationCompleteEnrollmentPending\n'
        mutant = parse(red, case, 101)
        ensure(killed(mutant, case) and not green(mutant, case), 'parser-intended-red'); positive += 1
        for change in [{'body_exit_code': 1}, {'passed': 1}, {'failed': 0}, {'ignored': 1},
                       {'executed_nonignored': 0}, {'compiler_error_count': 1},
                       {'all_panic_header_count': 2}, {'executed_case_names': []},
                       {'watchdog_triggered': True}, {'intended_assertion_observed': False},
                       {'passed': False}, {'failed': True},
                       {'panic_locations': [dict(own, line=own['line'] + 1, column=5)]}]:
            ensure(not killed(dict(mutant, **change), case), 'parser-rejects-nonbehavioral-or-unrelated-red'); negative += 1
        if case is CASES['unrelated-welcome']:
            for left, right in [('Expired', 'VerificationCompleteEnrollmentPending'),
                                ('Cancelled', 'VerificationCompleteEnrollmentPending'),
                                ('EnrollmentComplete', 'VerificationCompleteEnrollmentPending'),
                                ('Failed', 'Failed'), ('Secret', 'VerificationCompleteEnrollmentPending')]:
                changed = red.replace('left: Failed', 'left: ' + left).replace('right: VerificationCompleteEnrollmentPending', 'right: ' + right)
                ensure(not killed(parse(changed, case, 101), case), 'parser-rejects-wrong-or-unknown-phase'); negative += 1
            for changed in [red.replace('  left: Failed\n', ''), red.replace('assertion `left == right` failed', 'unrelated authenticated Welcome must preserve the actual owner'),
                            red + 'assertion `left == right` failed\n  left: Failed\n right: VerificationCompleteEnrollmentPending\n',
                            red + 'assertion `left == right` failed\n  left: Unknown\n right: VerificationCompleteEnrollmentPending\n',
                            red.replace('left: Failed', 'left: Failed private'),
                            red.replace(str(own['line']) + ':5:', str(own['line'] - 1) + ':5:')]:
                ensure(not killed(parse(changed, case, 101), case), 'parser-rejects-missing-duplicate-or-foreign-assertion'); negative += 1
        if case is CASES['readiness']:
            for values in [[], ['false'], ['true', 'true']]:
                ensure(not killed(dict(mutant, early_welcome_observations=values), case), 'parser-requires-premature-publication'); negative += 1
            selected_prefix = 'test ' + case['name'] + ' ... '
            prefixed_control = raw.replace(selected_prefix + 'ok\n' + marker,
                                           selected_prefix + marker + 'ok\n', 1)
            ensure(green(parse(prefixed_control, case, 0), case), 'parser-selected-test-prefix-green'); positive += 1
            red_marker = marker.replace('false', 'true')
            prefixed_red = red.replace(selected_prefix + 'FAILED\n' + red_marker,
                                       selected_prefix + red_marker + 'FAILED\n', 1)
            ensure(killed(parse(prefixed_red, case, 101), case), 'parser-selected-test-prefix-red'); positive += 1
            for invalid_prefix in ['test other_case ... ', selected_prefix + 'extra ', 'partial ']:
                changed = parse(raw.replace(marker, invalid_prefix + marker, 1), case, 0)
                ensure(changed['early_welcome_observations'] == [] and not green(changed, case), 'parser-rejects-foreign-or-partial-marker-prefix'); negative += 1
            duplicate = parse(prefixed_red + selected_prefix + red_marker, case, 101)
            ensure(duplicate['early_welcome_observations'] == ['true', 'true'] and not killed(duplicate, case), 'parser-rejects-duplicate-selected-prefix-marker'); negative += 1
        for change in [{'passed': 0}, {'ignored': 1}, {'executed_case_names': []}, {'all_panic_header_count': 1}]:
            ensure(not green(dict(control, **change), case), 'parser-rejects-false-green'); negative += 1
    return {'positive_controls': positive, 'negative_controls': negative, 'actual_runtime_bodies': 0}


def engine_features(binary):
    directory = binary.parent.parent / '.fingerprint'
    suffix = binary.name.rsplit('-', 1)[-1]
    root = directory / ('cgka-engine-' + suffix) / 'test-integration-test-accepted_welcome_receipts.json'
    wanted = {'cgka_engine', 'cgka_traits', 'storage_sqlite'}
    result = {'verified': False, 'coverage_required': sorted(wanted), 'nodes': {}, 'unresolved': []}
    expected_units = {}
    def read(file, name):
        data = json.loads(file.read_text()); features = data.get('features', [])
        if isinstance(features, str): features = json.loads(features)
        ensure(isinstance(features, list) and all(isinstance(value, str) for value in features), 'fingerprint-feature-schema')
        flags = data.get('rustflags', [])
        result['nodes'][name] = {'features': features, 'profile': data.get('profile'),
            'compile_kind': data.get('compile_kind'), 'rustflags_sha256': digest(json.dumps(flags, sort_keys=True).encode()),
            'rustflags_empty': flags == [], 'fingerprint_json_sha256': digest(file.read_bytes())}
        for dep in data.get('deps', []):
            if len(dep) != 4 or dep[1] not in wanted: continue
            depname, expected = dep[1], dep[3]
            if depname in result['nodes']:
                if expected_units.get(depname) != expected: result['unresolved'].append(depname + '-multiple-units')
                continue
            candidates = []
            if type(expected) is not int:
                result['unresolved'].append(depname); continue
            for candidate in directory.glob(depname.replace('_', '-') + '-*/lib-' + depname + '.json'):
                companion = candidate.with_suffix('')
                if not companion.is_file(): continue
                value = companion.read_text().strip()
                if not re.fullmatch('[0-9a-fA-F]{16}', value): continue
                raw = bytes.fromhex(value)
                if expected in (int.from_bytes(raw, 'little'), int.from_bytes(raw, 'big')): candidates.append(candidate)
            if len(candidates) != 1:
                result['unresolved'].append(depname); continue
            expected_units[depname] = expected
            read(candidates[0], depname)
            result['nodes'][depname]['expected_dependency_fingerprint_u64'] = expected
    if not root.is_file(): return result
    read(root, 'integration_test')
    result['verified'] = (wanted <= set(result['nodes']) and not result['unresolved']
        and all(node['rustflags_empty'] for node in result['nodes'].values())
        and {'experimental-device-sync', 'test-policy-overrides', 'test-crash-hooks'} <= set(result['nodes']['cgka_engine']['features'])
        and 'experimental-device-sync' in result['nodes']['storage_sqlite']['features'])
    return result


def compile_case(case):
    if case['package'] == 'marmot-app':
        row, cases = compile_cases([case['name'].rsplit('::', 1)[-1]])
        row['selected_case_count'] = len(cases)
        if len(cases) != 1: return row, None
        value = next(iter(cases.values()))
        if value['name'] != case['name']:
            row['inventory_exception'] = 'UnexpectedAppCase'; return row, None
        return row, value
    features = 'experimental-device-sync,test-policy-overrides,test-crash-hooks'
    command = ['cargo', 'nextest', 'list', '--locked', '-p', 'cgka-engine', '--test', 'accepted_welcome_receipts',
               '--features', features, '-E', 'test(=' + case['name'] + ')', '--message-format', 'json']
    start = time.monotonic(); result = subprocess.run(command, capture_output=True, text=True, timeout=1800)
    row = {'command': command, 'features_requested': features, 'compile_exit_code': result.returncode,
           'compile_seconds': time.monotonic() - start, **headers(result.stderr)}
    if result.returncode != 0 or row['compiler_error_count'] != 0: return row, None
    try:
        matches = [(name, suite) for suite in json.loads(result.stdout)['rust-suites'].values()
                   for name, value in suite['testcases'].items() if not value['ignored']
                   and value.get('filter-match', {}).get('status') == 'matches']
        row['selected_case_count'] = len(matches)
        ensure(len(matches) == 1 and matches[0][0] == case['name'], 'exact-engine-inventory')
        binary = Path(matches[0][1]['binary-path'])
        row['compiled_fingerprints'] = engine_features(binary)
    except Exception as error:
        row['inventory_exception'] = type(error).__name__; return row, None
    return row, {'name': case['name'], 'binary': str(binary), 'binary_sha256': digest(binary.read_bytes())}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--case', choices=CASES, required=True)
    parser.add_argument('--cohort-baseline', default=os.environ.get('UPSTREAM_EXTRACTION_COHORT_BASELINE'))
    parser.add_argument('--preflight', action='store_true')
    args = parser.parse_args(); case = CASES[args.case]
    ensure(bool(args.cohort_baseline), 'explicit-reviewed-baseline-required')
    cohort = reviewed_cohort(args.cohort_baseline)
    ensure(os.environ.get('CARGO_INCREMENTAL') == '1', 'incremental-cohort')
    ensure(os.environ.get('RUST_MIN_STACK') == str(case['stack']), 'unchanged-case-specific-stack')
    for key in ['RUSTFLAGS', 'CARGO_ENCODED_RUSTFLAGS', 'RUSTC_BOOTSTRAP', 'CARGO_PROFILE_DEV_OPT_LEVEL', 'CARGO_PROFILE_TEST_OPT_LEVEL']:
        ensure(not os.environ.get(key), 'no-compiler-override')
    for key in ['CARGO_PROFILE_DEV_DEBUG', 'CARGO_PROFILE_TEST_DEBUG']:
        ensure(os.environ.get(key) == '0', 'exact-debug-profile')
    out = Path('owner-pairing-mutation-evidence'); out.mkdir(exist_ok=True)
    report = {'source': cohort['source'], 'cohort_baseline': args.cohort_baseline,
              'reviewed_extraction_cohort': cohort, 'case': args.case, 'test': case['name'],
              'scope': case['claim'], 'runtime_budget_bytes': case['stack'], 'retries': 0,
              'phases': {}, 'mutation_chain_passed': False, 'qualification_passed': False,
              'toolchain': subprocess.check_output(['rustc', '-Vv'], text=True),
              'environment': {key: os.environ.get(key) for key in ['CARGO_INCREMENTAL', 'RUST_MIN_STACK', 'CARGO_PROFILE_DEV_DEBUG', 'CARGO_PROFILE_TEST_DEBUG']}}
    def save(): (out / 'result.json').write_text(json.dumps(report, indent=2) + '\n')
    frozen = freeze(); original_layout = layout(); source = Path(case['source']); original = source.read_bytes()
    text = original.decode(); ensure(text.count(case['old']) == 1, 'exact-single-mutation-anchor')
    mutant_bytes = text.replace(case['old'], case['new'], 1).encode()
    report.update(expected_panic=location(case), source_before_sha256=digest(json.dumps(frozen, sort_keys=True).encode()),
                  mutated_path=case['source'], original_file_sha256=digest(original),
                  mutant_file_sha256=digest(mutant_bytes), parser_controls=parser_preflight())
    save()
    if args.preflight: return
    def phase(label, expected):
        row = {}; report['phases'][label] = row; save()
        ensure(freeze() == expected and layout() == original_layout, 'phase-inputs-exact')
        try:
            compilation, selected = compile_case(case)
        except subprocess.TimeoutExpired:
            row['compilation'] = {'watchdog_triggered': True, 'compile_exit_code': None,
                                  'compiler_error_count': None, 'actual_runtime_bodies': 0}
            save(); raise
        row['compilation'] = compilation; save()
        ensure(compilation.get('compile_exit_code') == 0 and compilation.get('compiler_error_count') == 0
               and compilation.get('compiled_fingerprints', {}).get('verified') is True
               and selected is not None, 'compiled-feature-identity-required')
        row['compiled_feature_identity'] = feature_identity(compilation)
        if label != 'baseline':
            ensure(row['compiled_feature_identity'] == report['phases']['baseline']['compiled_feature_identity'], 'same-actual-feature-profile-cohort')
        ensure(freeze() == expected and layout() == original_layout, 'compile-input-drift')
        start = time.monotonic()
        try:
            result = subprocess.run([selected['binary'], '--exact', selected['name'], '--nocapture', '--test-threads=1'],
                                    capture_output=True, text=True, timeout=300)
            row['body'] = parse(result.stdout + result.stderr, case, result.returncode)
        except subprocess.TimeoutExpired:
            row['body'] = {'watchdog_triggered': True, 'actual_count_unknown': True}
        row.update(body_seconds=time.monotonic() - start, binary_sha256=selected['binary_sha256'],
                   exact_inputs_after=freeze() == expected and layout() == original_layout)
        save(); ensure(row['exact_inputs_after'], 'runtime-input-drift')
        return row['body']
    try:
        baseline = phase('baseline', frozen); ensure(green(baseline, case), 'actual-baseline-not-green')
        mutation_error = None
        try:
            source.write_bytes(mutant_bytes)
            expected = freeze()
            ensure(set(expected) == set(frozen) and {name for name in frozen if expected[name] != frozen[name]} == {case['source']}
                   and layout() == original_layout, 'one-exact-mutant-only')
            report['mutant_inputs_sha256'] = digest(json.dumps(expected, sort_keys=True).encode()); save()
            mutant = phase('mutant', expected)
            report['intended_runtime_kill'] = killed(mutant, case)
            ensure(report['intended_runtime_kill'], 'mutant-survived-or-unrelated-failure')
        except Exception as error:
            mutation_error = type(error).__name__; report['mutation_exception'] = mutation_error
        finally:
            source.write_bytes(original)
            ensure(freeze() == frozen and layout() == original_layout, 'exact-source-restoration')
            report['source_restored'] = True; save()
        restored = phase('restored', frozen); ensure(green(restored, case), 'actual-restored-control-not-green')
        ensure(mutation_error is None, 'mutation-chain-not-qualified')
        report['mutation_chain_passed'] = True
    except Exception as error:
        report['controller_exception'] = type(error).__name__
    finally:
        report['inputs_pristine'] = False
        try:
            source.write_bytes(original)
            report['inputs_pristine'] = freeze() == frozen and layout() == original_layout and subprocess.run(['git', 'diff', '--quiet', 'HEAD']).returncode == 0
            report['source_after_sha256'] = digest(json.dumps(freeze(), sort_keys=True).encode())
        except Exception as error:
            report['final_restore_exception'] = type(error).__name__
        report['actual_executed_nonignored'] = sum(value.get('body', {}).get('executed_nonignored', 0) for value in report['phases'].values())
        report['actual_counts_complete'] = (len(report['phases']) == 3 and all(
            value.get('body', {}).get('executed_nonignored') == 1
            and not value.get('body', {}).get('actual_count_unknown') for value in report['phases'].values()))
        save()
    raise SystemExit(0 if report['mutation_chain_passed'] and report['inputs_pristine'] and report['actual_executed_nonignored'] == 3 else 1)


if __name__ == '__main__': main()
