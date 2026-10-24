"""Remote exact hermetic directory-login fixture controls; no full-suite credit."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess

from upstream_current_backend_probe import ANSI, capture
from upstream_extraction_cohort import git, reviewed_cohort
from upstream_replay_controls import compiler, selected_case, summary_counts, unique
from upstream_apple_ci.package_metadata_pfp import HeldSource, snapshot

CASE = 'directory-login-fixtures'
MECHANISM = 'directory-incomplete-indexer'
MECHANISM_SOURCE = 'crates/marmot-uniffi/tests/directory_login.rs'
MECHANISM_TEST = 'directory_discovery_coverage_remains_fail_closed_for_owned_incomplete_indexer'
MECHANISM_SHA = '021031fe60048c1c4d99272cf0629ada964e7f7a99d97f368cde94b843c663a8'
GREEN = '        vec![healthy.to_owned()]\n'
INVERSE = '        { let _ = healthy; vec![incomplete.to_owned()] }\n'
MESSAGE = 'owned complete discovery must permit real login while incomplete discovery stays fail closed'
PREFIX = 'owned-directory-fixture '
VERDICTS = {'positive_login_succeeded', 'positive_typed_incomplete', 'positive_owned_contact'}
PREREQUISITES = {'host_without_tokio', 'host_still_without_tokio', 'endpoints_joined',
    'negative_no_panic', 'negative_typed_incomplete', 'negative_rejected',
    'negative_account_bound', 'negative_owned_contact', 'negative_shutdown_complete',
    'positive_no_panic', 'positive_account_bound', 'positive_shutdown_complete'}
INPUTS = {
    'crates/marmot-c/src/device_linking/tests.rs': 'ada95d54558480632a2b87e9e93f115dbad9a5d4c715e933e2f8ab7176784443',
    'crates/marmot-uniffi/tests/runtime_threads.rs': 'bc5cbe96f86d88eaa99dc5e1917a89888a8d642719185a5d9f0716fd2edbc764',
}
ORDINARY = 'uniffi_exports_run_mdk_work_on_marmotkit_runtime_threads'
CASES = [
    ('c-two', 'marmot-c', 'marmot_c', 'lib',
     'device_linking::tests::actual_c_sessions_continue_original_enrollment_and_close_is_reentrant',
     ['experimental-device-sync', 'alloc-audit']),
    ('c-three', 'marmot-c', 'marmot_c', 'lib',
     'device_linking::tests::actual_c_three_device_enrollment_retains_approval_after_list_free',
     ['experimental-device-sync', 'alloc-audit']),
    ('uniffi-ordinary-default', 'marmot-uniffi', 'runtime_threads', 'test', ORDINARY, []),
    ('uniffi-ordinary-experimental', 'marmot-uniffi', 'runtime_threads', 'test', ORDINARY,
     ['experimental-device-sync']),
    ('uniffi-private-foreign', 'marmot-uniffi', 'runtime_threads', 'test',
     'private_pairing_exports_complete_on_a_foreign_executor_without_tokio', ['experimental-device-sync']),
]
EMPTY_COMPILER = {'codes': [], 'header_count': 0, 'sites': [], 'unknown_or_excess_sites': 0}


def require(value, label):
    if not value:
        raise ValueError(label)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def observed_counts(raw):
    value = summary_counts(raw)
    if value['summary_count'] != 1 or type(value['counts']) is not dict:
        return None
    counts = value['counts']
    if set(counts) != {'executed', 'passed', 'failed', 'skipped'} or any(type(item) is not int or item < 0 for item in counts.values()):
        return None
    if counts['executed'] != counts['passed'] + counts['failed']:
        return None
    return counts


def environment(values, stack):
    denied = ['RUSTFLAGS', 'CARGO_ENCODED_RUSTFLAGS', 'RUSTDOCFLAGS', 'CARGO_ENCODED_RUSTDOCFLAGS',
              'RUSTC', 'RUSTC_WRAPPER', 'RUSTC_WORKSPACE_WRAPPER', 'RUSTC_BOOTSTRAP']
    require((values.get('RUST_MIN_STACK') or None) == stack
            and not any(values.get(key) for key in denied)
            and not any(value for key, value in values.items() if key.startswith('CARGO_TARGET_') and key.endswith('_RUSTFLAGS'))
            and values.get('CARGO_BUILD_JOBS') == '2' and values.get('CARGO_INCREMENTAL') == '1',
            'exact-replay-environment-required')


def runtime(raw, package, binary, kind, test):
    text = ANSI.sub('', raw.decode('utf-8', errors='strict')).replace('\r\n', '\n')
    observed = summary_counts(raw)
    require(observed['summary_count'] == 1 and observed['counts'] is not None, 'one-actual-runtime-summary')
    counts = observed['counts']
    display = package if kind == 'lib' else '(?:' + re.escape(package) + '::)?' + re.escape(binary)
    if kind == 'lib': display = re.escape(display)
    rows = re.findall(r'^\s*(PASS|FAIL)\s+\[[^\]]+\]\s+(?:\([ \t]{0,8}1/1\)[ \t]+)?([^\s]+)\s+([^\s]+)\s*$', text, re.M)
    require(counts['executed'] == 1 and counts['passed'] + counts['failed'] == 1 and len(rows) == 1,
            'exact-one-executed-runtime-body')
    verdict, actual_binary, actual_test = rows[0]
    require(re.fullmatch(display, actual_binary) is not None and actual_test == test
            and (verdict == 'PASS') == (counts['passed'] == 1), 'exact-runtime-binary-test-and-verdict')
    return counts


def controls():
    raw = ('PASS [1s] marmot-uniffi::runtime_threads ' + ORDINARY
           + '\nSummary [1s] 1 test run: 1 passed, 273 skipped\n').encode()
    assert runtime(raw, 'marmot-uniffi', 'runtime_threads', 'test', ORDINARY) == dict(executed=1, passed=1, failed=0, skipped=273)
    bad = [raw + raw, raw.replace(ORDINARY.encode(), b'wrong'), raw.replace(b'1 passed', b'2 passed'),
           raw.replace(b'marmot-uniffi::runtime_threads', b'wrong'), raw.replace(b'PASS', b'FAIL'),
           raw.replace(b'1 test run', b'0 tests run'), raw + b'PASS [1s] wrong extra\n']
    for item in bad:
        try: runtime(item, 'marmot-uniffi', 'runtime_threads', 'test', ORDINARY)
        except ValueError: pass
        else: raise AssertionError('directory-runtime-negative-accepted')
    assert observed_counts(raw.replace(b'marmot-uniffi::runtime_threads', b'wrong')) == dict(executed=1, passed=1, failed=0, skipped=273)
    assert observed_counts(raw.replace(b'1 passed', b'2 passed')) is None
    valid_env = {'CARGO_BUILD_JOBS': '2', 'CARGO_INCREMENTAL': '1'}
    environment(valid_env, None)
    environment(dict(valid_env, RUST_MIN_STACK='4194304'), '4194304')
    denied = ['RUSTFLAGS', 'CARGO_ENCODED_RUSTFLAGS', 'RUSTDOCFLAGS', 'CARGO_ENCODED_RUSTDOCFLAGS',
              'RUSTC', 'RUSTC_WRAPPER', 'RUSTC_WORKSPACE_WRAPPER', 'RUSTC_BOOTSTRAP', 'CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_RUSTFLAGS']
    bad_envs = [dict(valid_env, **{key: 'injected'}) for key in denied]
    bad_envs += [dict(valid_env, CARGO_BUILD_JOBS='3'), dict(valid_env, CARGO_INCREMENTAL='0'), dict(valid_env, RUST_MIN_STACK='1')]
    for item in bad_envs:
        try: environment(item, None)
        except ValueError: pass
        else: raise AssertionError('directory-environment-negative-accepted')
    assert len(CASES) == 5 and len({item[0] for item in CASES}) == 5
    return {'positive': 5, 'negative': len(bad) + len(bad_envs) + 1, 'product_bodies': 0, 'synthetic_metadata_only': True}



def probe(raw):
    require(len(raw) <= 16 * 1024 * 1024, 'bounded-owned-directory-probe')
    text = ANSI.sub('', raw.decode('utf-8', errors='strict')).replace('\r\n', '\n')
    lines = [line for line in text.splitlines() if PREFIX in line]
    require(len(lines) == 1 and text.count(PREFIX) == 1 and len(lines[0]) <= 4096, 'one-bounded-owned-directory-probe')
    match = re.fullmatch(r'[ \t]{0,8}' + re.escape(PREFIX) + r'(\{[^\r\n]*\})[ \t]{0,8}', lines[0])
    require(match is not None, 'owned-directory-probe-envelope')
    value = json.loads(match[1], object_pairs_hook=unique)
    require(type(value) is dict and set(value) == PREREQUISITES | VERDICTS
            and all(type(item) is bool for item in value.values()), 'closed-typed-owned-directory-probe')
    return value


def probe_oracle(value, intentional):
    wanted = dict(positive_login_succeeded=not intentional,
                  positive_typed_incomplete=intentional, positive_owned_contact=intentional)
    require(all(value[key] is True for key in PREREQUISITES), 'actual-negative-control-account-contact-and-cleanup-prerequisites')
    require({key: value[key] for key in VERDICTS} == wanted, 'exact-positive-or-incomplete-indexer-vector')


def own_failure(raw, source):
    text = ANSI.sub('', raw.decode('utf-8', errors='strict')).replace('\r\n', '\n')
    anchor = '    assert!('
    start = source.index('fn ' + MECHANISM_TEST + '() {')
    end = source.index('\n}', start) + 2
    require(source.count(anchor) == 1 and source[start:end].count(anchor) == 1
            and source.count(MESSAGE) == 1, 'sole-source-owned-final-assertion')
    line = source[:source.index(anchor)].count('\n') + 1
    headers = re.findall(r"(?m)^[ \t]{0,8}thread '([^'\r\n]+)'(?: \([0-9]+\))? panicked at ([^\s]+\.rs):([0-9]+):([0-9]+):\n([^\r\n]+)", text)
    require(text.count('panicked at ') == 1 and len(headers) == 1, 'sole-entire-runtime-panic')
    thread, path, actual_line, column, message = headers[0]
    require((thread, path, int(actual_line), int(column))
            == (MECHANISM_TEST, MECHANISM_SOURCE, line, 5)
            and re.fullmatch(r'[ \t]{0,8}' + re.escape(MESSAGE) + r'[ \t]{0,8}', message) is not None,
            'exact-owned-final-assertion-site-and-message')
    return dict(path=path, line=line, column=5, fixed_message=MESSAGE, expected_thread=True)


def mechanism_controls():
    valid = dict.fromkeys(PREREQUISITES, True)
    valid.update(positive_login_succeeded=True, positive_typed_incomplete=False, positive_owned_contact=False)
    def raw(value): return (PREFIX + json.dumps(value) + '\n').encode()
    assert probe(raw(valid)) == valid
    positives, negatives = 1, 0
    for intentional in [False, True]:
        for bits in range(8):
            item = dict(valid)
            for index, name in enumerate(sorted(VERDICTS)): item[name] = bool(bits & (1 << index))
            wanted = dict(positive_login_succeeded=not intentional, positive_typed_incomplete=intentional, positive_owned_contact=intentional)
            if {key: item[key] for key in VERDICTS} == wanted:
                probe_oracle(item, intentional); positives += 1
            else:
                try: probe_oracle(item, intentional)
                except ValueError: negatives += 1
                else: raise AssertionError('owned-indexer-wrong-vector-accepted')
    for key in PREREQUISITES:
        item = dict(valid); item[key] = False
        try: probe_oracle(probe(raw(item)), False)
        except ValueError: negatives += 1
        else: raise AssertionError('owned-indexer-false-prerequisite-accepted')
    bad = [raw(valid) * 2, b'PRIVATE ' + raw(valid), raw(dict(valid, extra=True)),
           raw(dict(valid, negative_owned_contact=1)), raw(valid).replace(b'{', b'{"negative_owned_contact":true,', 1),
           b'x' * (16 * 1024 * 1024 + 1), b' ' * 4097 + raw(valid)]
    for item in bad:
        try: probe(item)
        except (ValueError, UnicodeError): negatives += 1
        else: raise AssertionError('owned-indexer-invalid-probe-accepted')
    source = Path(MECHANISM_SOURCE).read_text()
    anchor = '    assert!('
    line = source[:source.index(anchor)].count('\n') + 1
    panic = ("thread '" + MECHANISM_TEST + "' panicked at " + MECHANISM_SOURCE + ':' + str(line) + ':5:\n' + MESSAGE + '\n').encode()
    own_failure(panic, source); positives += 1
    own_failure(panic.replace(MESSAGE.encode(), b' '*8 + MESSAGE.encode() + b' '*8), source); positives += 1
    for item in [panic * 2, panic.replace(b':5:', b':6:'), panic.replace(MECHANISM_TEST.encode(), b'wrong'),
                 panic.replace(str(line).encode() + b':5:', str(line + 1).encode() + b':5:'),
                 panic.replace(MECHANISM_SOURCE.encode(), b'wrong.rs'), panic.replace(MESSAGE.encode(), b'wrong'),
                 panic.replace(MESSAGE.encode(), b' '*9 + MESSAGE.encode()),
                 panic.replace(MESSAGE.encode(), MESSAGE.encode() + b' '*9)]:
        try: own_failure(item, source)
        except ValueError: negatives += 1
        else: raise AssertionError('owned-indexer-wrong-panic-accepted')
    return {'positive': positives, 'negative': negatives, 'product_bodies': 0, 'synthetic_metadata_only': True}


def mechanism(args, proof, before, save):
    original = Path(MECHANISM_SOURCE).read_bytes()
    source = original.decode()
    require(sha(original) == MECHANISM_SHA and source.count(GREEN) == 1, 'exact-owned-mechanism-input')
    start = source.index('fn discovery(')
    end = source.index('\n}\n', start) + 2
    require(source[start:end].count(GREEN) == 1 and source[start:end].count('if negative_control') == 1,
            'sole-positive-discovery-branch-in-owned-function')
    mutant = source.replace(GREEN, INVERSE, 1).encode()
    require(original.count(b'\n') == mutant.count(b'\n'), 'newline-preserved-owned-endpoint-inverse')
    held = HeldSource(Path(MECHANISM_SOURCE), original)
    proof['mechanism_input_sha256'] = MECHANISM_SHA
    proof['mutant_sha256'] = sha(mutant)
    try:
        for label, intentional in ([('baseline', False), ('incomplete-indexer-mutant', True), ('restored', False)]
                                   if args.stage == 'pfp' else [('positive', False)]):
            wanted = mutant if intentional else original
            if held.current != wanted: held.write(held.current, wanted)
            expected = {**before, 'files': dict(before['files'])}
            if intentional:
                expected['files'][MECHANISM_SOURCE] = [sha(mutant), before['files'][MECHANISM_SOURCE][1]]
                expected['status'] = sha((' M ' + MECHANISM_SOURCE + '\0').encode())
            row = {'label': label, 'intentional_runtime_failure': intentional}
            proof['phases'].append(row); save()
            held.verify(wanted); require(snapshot() == expected, 'whole-source-before-mechanism')
            flags = ['--locked', '-p', 'marmot-uniffi', '--test', 'directory_login', '--profile', 'ci']
            environment(os.environ, None)
            selection = 'package(marmot-uniffi) & binary(=directory_login) & test(=' + MECHANISM_TEST + ')'
            code, raw, elapsed, stderr = capture(['cargo', 'nextest', 'list'] + flags
                + ['--message-format', 'json', '-E', selection], 1800, separate=True)
            row['inventory'] = {'exit_code': code, 'elapsed_seconds': elapsed, 'stdout_sha256': sha(raw),
                                'stderr_sha256': sha(stderr), 'compiler': compiler(stderr, before['files'])}
            save()
            require(code == 0 and row['inventory']['compiler'] == EMPTY_COMPILER, 'mechanism-clean-inventory-compiler')
            inventory = json.loads(raw, object_pairs_hook=unique); selected_case(inventory, MECHANISM_TEST)
            suites = [suite for suite in inventory['rust-suites'].values()
                if any(item['filter-match']['status'] == 'matches' for item in suite['testcases'].values())]
            require(len(suites) == 1 and suites[0]['binary-name'] == 'directory_login' and suites[0]['kind'] == 'test', 'mechanism-exact-binary-kind')
            row['inventory'].update(selected_nonignored=1, selected_ignored=0)
            held.verify(wanted); require(snapshot() == expected, 'whole-source-after-mechanism-inventory')
            row['body_invoked'] = True; save()
            code, raw, elapsed, _ = capture(['cargo', 'nextest', 'run'] + flags
                + ['--retries', '0', '--test-threads', '1', '--status-level', 'pass', '--final-status-level', 'none',
                   '--no-fail-fast', '--success-output', 'immediate', '--failure-output', 'immediate', '-E', selection], 1800)
            row['body'] = {'exit_code': code, 'elapsed_seconds': elapsed, 'raw_sha256': sha(raw), 'raw_bytes': len(raw),
                           'compiler': compiler(raw, before['files']), 'summary': summary_counts(raw)}
            row['observed_counts'] = observed_counts(raw)
            row['counts_identity_validated'] = False; save()
            row['counts'] = runtime(raw, 'marmot-uniffi', 'directory_login', 'test', MECHANISM_TEST)
            row['counts_identity_validated'] = True; save()
            require(row['body']['compiler'] == EMPTY_COMPILER, 'mechanism-entire-compiler-empty')
            row['probe'] = probe(raw); save(); probe_oracle(row['probe'], intentional)
            require(row['counts']['failed'] == int(intentional) and row['counts']['passed'] == int(not intentional)
                    and code == (100 if intentional else 0), 'mechanism-exact-actual-counts-and-exit')
            if intentional: row['owned_failure'] = own_failure(raw, source)
            else: require(b'panicked at ' not in raw, 'mechanism-control-has-no-runtime-panic')
            held.verify(wanted); require(snapshot() == expected, 'whole-source-after-mechanism-body')
            row['source_closure_exact'] = True; save()
    finally:
        try:
            if held.current != original: held.write(held.current, original)
            held.verify(original)
            proof['source_restored'] = snapshot() == before
        finally: held.close()
    require(proof['source_restored'], 'mechanism-exact-source-and-Git-restoration')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--mode', choices=['preflight', 'run'], required=True)
    parser.add_argument('--case', choices=[CASE, MECHANISM], required=True)
    parser.add_argument('--baseline', required=True)
    parser.add_argument('--stage', choices=['positive', 'pfp'], required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    require(args.output.is_absolute() and not args.output.exists()
            and Path.cwd() not in args.output.resolve().parents, 'fresh-result-outside-source-required')
    proof = {'schema': 1, 'passed': False, 'source': git('rev-parse', 'HEAD'),
             'baseline': args.baseline, 'case': args.case, 'stage': args.stage, 'mode': args.mode,
             'historical_evidence_reused': False, 'full_suite_qualification': False,
             'native_acceptance_qualification': False, 'automatic_retries': 0,
             'test_threads': 1, 'phases': []}
    args.output.parent.mkdir(parents=True, exist_ok=True)
    def save(): args.output.write_text(json.dumps(proof, indent=2) + '\n')
    before = None
    try:
        require(os.environ.get('GITHUB_ACTIONS') == 'true' and os.environ.get('RUNNER_OS') == 'Linux', 'remote-Linux-required')
        require(args.baseline == proof['source'], 'explicit-reviewed-self-baseline-required')
        proof['cohort'] = reviewed_cohort(args.baseline)
        before = snapshot()
        require(before['status'] == sha(b''), 'clean-committed-source-required')
        require(all(before['files'][path][0] == digest for path, digest in INPUTS.items()), 'exact-reviewed-fixture-inputs')
        proof['fixture_input_sha256'] = INPUTS
        proof['controls'] = controls()
        require(args.case == MECHANISM or args.stage == 'positive', 'original-fixtures-positive-only')
        if args.case == MECHANISM:
            require(sha(Path(MECHANISM_SOURCE).read_bytes()) == MECHANISM_SHA, 'exact-mechanism-preflight-input')
            if args.mode == 'run': environment(os.environ, None)
            proof['mechanism_controls'] = mechanism_controls()
            if args.mode == 'run': mechanism(args, proof, before, save)
        elif args.mode == 'run':
            environment(os.environ, None)
            for label, package, binary, kind, test, features in CASES:
                profile = 'm5-bounded' if features else 'ci'
                stack = '4194304' if features else None
                if stack is None: os.environ.pop('RUST_MIN_STACK', None)
                else: os.environ['RUST_MIN_STACK'] = stack
                environment(os.environ, stack)
                flags = ['--locked', '-p', package, '--profile', profile]
                flags += ['--lib'] if kind == 'lib' else ['--test', binary]
                if features: flags += ['--features', ','.join(features)]
                selection = 'package(' + package + ') & binary(=' + binary + ') & test(=' + test + ')'
                row = {'label': label, 'package': package, 'binary': binary, 'kind': kind,
                       'test': test, 'features': features, 'profile': profile, 'rust_min_stack': stack}
                proof['phases'].append(row); save()
                require(snapshot() == before, 'whole-source-before-inventory')
                code, raw, elapsed, stderr = capture(['cargo', 'nextest', 'list'] + flags
                    + ['--message-format', 'json', '-E', selection], 1800, separate=True)
                row['inventory'] = {'exit_code': code, 'elapsed_seconds': elapsed,
                    'stdout_sha256': sha(raw), 'stderr_sha256': sha(stderr), 'compiler': compiler(stderr, before['files'])}
                save()
                require(code == 0 and row['inventory']['compiler'] == EMPTY_COMPILER, 'clean-actual-inventory-compilation')
                inventory = json.loads(raw, object_pairs_hook=unique)
                selected_case(inventory, test)
                suites = [suite for suite in inventory['rust-suites'].values()
                    if any(item['filter-match']['status'] == 'matches' for item in suite['testcases'].values())]
                require(len(suites) == 1 and suites[0]['binary-name'] == binary and suites[0]['kind'] == kind, 'exact-selected-binary-kind')
                row['inventory'].update(selected_nonignored=1, selected_ignored=0); save()
                require(snapshot() == before, 'whole-source-after-inventory')
                row['body_invoked'] = True; save()
                command = ['cargo', 'nextest', 'run'] + flags + ['--retries', '0', '--test-threads', '1',
                    '--status-level', 'pass', '--final-status-level', 'none', '--no-fail-fast', '--success-output', 'immediate', '-E', selection]
                code, raw, elapsed, _ = capture(command, 1800)
                row['body'] = {'exit_code': code, 'elapsed_seconds': elapsed, 'raw_sha256': sha(raw),
                    'raw_bytes': len(raw), 'compiler': compiler(raw, before['files']), 'summary': summary_counts(raw)}
                row['observed_counts'] = observed_counts(raw)
                row['counts_identity_validated'] = False
                save()  # Typed actual execution survives all later identity/oracle failures.
                row['counts'] = runtime(raw, package, binary, kind, test)
                row['counts_identity_validated'] = True; save()
                require(code == 0 and row['counts']['passed'] == 1 and row['body']['compiler'] == EMPTY_COMPILER
                        and b'panicked at ' not in raw, 'actual-runtime-positive-with-no-extra-errors')
                require(snapshot() == before, 'whole-source-after-body')
                row['source_closure_exact'] = True; save()
        proof['passed'] = True
    except (ValueError, KeyError, TypeError, OSError, UnicodeError, subprocess.SubprocessError, AssertionError) as error:
        proof['failure_category'] = type(error).__name__
        if isinstance(error, ValueError) and re.fullmatch('[A-Za-z0-9_-]{1,160}', str(error)):
            proof['failure_label'] = str(error)
    finally:
        if before is not None:
            try: proof['source_closure_exact'] = snapshot() == before
            except (OSError, subprocess.SubprocessError): proof['source_closure_exact'] = False
            proof['passed'] = proof['passed'] and proof['source_closure_exact']
        unknown = [row['label'] for row in proof['phases'] if row.get('body_invoked') and row.get('observed_counts') is None]
        known = sum(row['observed_counts']['executed'] for row in proof['phases'] if row.get('observed_counts') is not None)
        proof['known_executed_product_bodies'] = known
        proof['executed_product_bodies'] = None if unknown else known
        proof['invoked_phases_with_unknown_counts'] = unknown
        save()
    return 0 if proof['passed'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
