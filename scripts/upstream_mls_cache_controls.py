"""Remote exact MLS cache-load controls; no full-suite or native credit."""
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
from upstream_directory_login_controls import environment, observed_counts, runtime

CASE = 'engine-mls-group-cache'
SOURCE = 'crates/cgka-engine/src/mls_group_cache.rs'
SOURCE_SHA = '96ecc87f20806e47e78268ee5501d1c8e458f6c0dcc9d024187fd7d51ff496d7'
TEST = 'mls_group_cache::tests::cached_group_is_reused_until_storage_is_written_behind_it'
PREFIX = 'mls-cache-actual-load '
MESSAGE = 'cached sends avoid real MLS loads and rollback forces exactly one reload'
GREEN = '                && cached.generation == generation\n'
INVERSES = {
    'reuse-off': '                && { let _ = cached.generation; false }\n',
    'generation-ignore': '                && { let _ = cached.generation; true }\n',
}
EMPTY_COMPILER = {'codes': [], 'header_count': 0, 'sites': [], 'unknown_or_excess_sites': 0}
COHORTS = [('default', [], 'ci', None),
           ('experimental', ['experimental-device-sync'], 'm5-bounded', '4194304')]


def require(value, label):
    if not value:
        raise ValueError(label)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def probe(raw):
    require(len(raw) <= 16 * 1024 * 1024, 'bounded-cache-output')
    text = ANSI.sub('', raw.decode('utf-8', errors='strict')).replace('\r\n', '\n')
    lines = [line for line in text.splitlines() if PREFIX in line]
    require(len(lines) == 1 and text.count(PREFIX) == 1 and len(lines[0]) <= 4096, 'one-bounded-cache-marker')
    match = re.fullmatch(r'[ \t]{0,8}' + re.escape(PREFIX) + r'(\{[^\r\n]*\})[ \t]{0,8}', lines[0])
    require(match is not None, 'closed-cache-marker-envelope')
    value = json.loads(match[1], object_pairs_hook=unique)
    require(type(value) is dict and set(value) == {'application_sends', 'initial_cached_groups',
            'rollback_changed_generation', 'load_deltas'}, 'closed-cache-marker-fields')
    require(type(value['application_sends']) is list and len(value['application_sends']) == 4
            and all(type(item) is bool for item in value['application_sends'])
            and type(value['initial_cached_groups']) is int and 0 <= value['initial_cached_groups'] <= 32
            and type(value['rollback_changed_generation']) is bool
            and type(value['load_deltas']) is list and len(value['load_deltas']) == 3
            and all(type(item) is int and 0 <= item <= 2**64 - 1 for item in value['load_deltas']),
            'typed-cache-marker-facts')
    return value


def oracle(value, inverse):
    require(all(value['application_sends']) and value['initial_cached_groups'] == 1
            and value['rollback_changed_generation'] is True, 'actual-application-cache-and-rollback-prerequisites')
    deltas = value['load_deltas']
    wanted = deltas == [0, 1, 0] if inverse is None else (
        deltas[0] > 0 and deltas[1] >= 1 and deltas[2] > 0 if inverse == 'reuse-off'
        else deltas == [0, 0, 0] if inverse == 'generation-ignore' else False)
    require(wanted, 'exact-cache-reuse-invalidation-contract')


def final_site(source):
    anchor = '        assert_eq!(\n            load_deltas,\n            [0, 1, 0],\n            "' + MESSAGE + '"\n        );'
    require(source.count(anchor) == 1 and source.count(MESSAGE) == 1
            and source.count('async fn ' + TEST.split('::')[-1] + '()') == 1, 'sole-cache-final-source-owner')
    return source[:source.index(anchor)].count('\n') + 1


def own_failure(raw, source, deltas):
    text = ANSI.sub('', raw.decode('utf-8', errors='strict')).replace('\r\n', '\n')
    line = final_site(source)
    headers = re.findall(r"(?m)^[ \t]{0,8}thread '([^'\r\n]+)'(?: \([0-9]+\))? panicked at ([^\s]+\.rs):([0-9]+):([0-9]+):\n", text)
    require(text.count('panicked at ') == 1 and len(headers) == 1
            and headers[0] == (TEST, SOURCE, str(line), '9'), 'sole-cache-own-runtime-panic-site')
    after = text.split(' panicked at ' + SOURCE + ':' + str(line) + ':9:\n', 1)[1]
    triple = lambda values: r'\[' + r',[ \t]{0,8}'.join(str(item) for item in values) + r'\]'
    pattern = r'[ \t]{0,8}assertion `left == right` failed: ' + re.escape(MESSAGE) + r'[ \t]{0,8}\n' + r'[ \t]{0,8}left: ' + triple(deltas) + r'[ \t]{0,8}\n' + r'[ \t]{0,8}right: ' + triple([0, 1, 0]) + r'[ \t]{0,8}(?:\n|$)'
    require(re.match(pattern, after) is not None, 'sole-cache-final-vector-assertion')
    return {'path': SOURCE, 'line': line, 'column': 9, 'fixed_message': MESSAGE,
            'left': deltas, 'right': [0, 1, 0], 'expected_thread': True}


def controls(source):
    valid = dict(application_sends=[True]*4, initial_cached_groups=1,
                 rollback_changed_generation=True, load_deltas=[0, 1, 0])
    def raw(value): return (PREFIX + json.dumps(value) + '\n').encode()
    positives, negatives = 0, 0
    for inverse, deltas in [(None, [0, 1, 0]), ('reuse-off', [2, 2, 2]), ('generation-ignore', [0, 0, 0])]:
        value = dict(valid, load_deltas=deltas); oracle(probe(raw(value)), inverse); positives += 1
    bad = [raw(valid)*2, b'PRIVATE '+raw(valid), raw(dict(valid, extra=True)),
           raw(dict(valid, load_deltas=[True, 1, 0])), raw(dict(valid, load_deltas=[0, -1, 0])),
           raw(dict(valid, load_deltas=[0, 1])), raw(dict(valid, initial_cached_groups=True)),
           raw(dict(valid, rollback_changed_generation=1)), raw(dict(valid, application_sends=[True]*3)),
           raw(valid).replace(b'{', b'{"initial_cached_groups":1,', 1), b' '*4097+raw(valid), b'\xff'+raw(valid)]
    for item in bad:
        try: probe(item)
        except (ValueError, UnicodeError): negatives += 1
        else: raise AssertionError('invalid-cache-probe-accepted')
    for inverse, value in [(None, dict(valid, application_sends=[True, True, False, True])),
            (None, dict(valid, initial_cached_groups=0)), (None, dict(valid, rollback_changed_generation=False)),
            (None, dict(valid, load_deltas=[0, 0, 0])), ('reuse-off', valid), ('generation-ignore', valid)]:
        try: oracle(value, inverse)
        except ValueError: negatives += 1
        else: raise AssertionError('invalid-cache-contract-accepted')
    line = final_site(source)
    panic = ("thread '" + TEST + "' panicked at " + SOURCE + ':' + str(line) + ':9:\n'
             + 'assertion `left == right` failed: ' + MESSAGE + '\n  left: [0, 0, 0]\n right: [0, 1, 0]\n').encode()
    own_failure(panic, source, [0, 0, 0]); positives += 1
    for item in [panic*2, panic.replace(TEST.encode(), b'wrong'), panic.replace(SOURCE.encode(), b'wrong.rs'),
                 panic.replace(b':9:', b':8:'), panic.replace(MESSAGE.encode(), b'wrong'),
                 panic.replace(b'left: [0, 0, 0]', b'left: [0, 2, 0]'),
                 panic.replace(b'right: [0, 1, 0]', b'right: [0, 0, 0]'),
                 panic.replace(str(line).encode()+b':9:', str(line+1).encode()+b':9:')]:
        try: own_failure(item, source, [0, 0, 0])
        except ValueError: negatives += 1
        else: raise AssertionError('invalid-cache-own-panic-accepted')
    runtime_good = ('PASS [1s] cgka-engine ' + TEST + '\nSummary [1s] 1 test run: 1 passed, 273 skipped\n').encode()
    assert runtime(runtime_good, 'cgka-engine', 'cgka_engine', 'lib', TEST) == dict(executed=1, passed=1, failed=0, skipped=273)
    positives += 1
    for item in [runtime_good * 2, runtime_good.replace(TEST.encode(), b'wrong'),
                 runtime_good.replace(b'cgka-engine', b'wrong'), runtime_good.replace(b'1 passed', b'2 passed'),
                 runtime_good.replace(b'PASS', b'FAIL'), runtime_good + b'PASS [1s] cgka-engine extra\n']:
        try: runtime(item, 'cgka-engine', 'cgka_engine', 'lib', TEST)
        except ValueError: negatives += 1
        else: raise AssertionError('invalid-cache-runtime-accepted')
    require(len(COHORTS) == 2 and set(INVERSES) == {'reuse-off', 'generation-ignore'}, 'closed-cache-configurations')
    return {'positive': positives, 'negative': negatives, 'product_bodies': 0, 'synthetic_metadata_only': True}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--mode', choices=['preflight', 'run'], required=True)
    parser.add_argument('--case', choices=[CASE], required=True)
    parser.add_argument('--baseline', required=True)
    parser.add_argument('--stage', choices=['positive', 'pfp'], required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    require(args.output.is_absolute() and not args.output.exists()
            and Path.cwd() not in args.output.resolve().parents, 'fresh-result-outside-source-required')
    proof = dict(schema=1, passed=False, source=git('rev-parse', 'HEAD'), baseline=args.baseline,
                 case=args.case, stage=args.stage, mode=args.mode, full_suite_qualification=False,
                 native_acceptance_qualification=False, automatic_retries=0, test_threads=1,
                 source_restored=False, phases=[])
    args.output.parent.mkdir(parents=True, exist_ok=True)
    def save(): args.output.write_text(json.dumps(proof, indent=2)+'\n')
    held, before, original = None, None, None
    initial_stack = os.environ.get('RUST_MIN_STACK')
    try:
        require(os.environ.get('GITHUB_ACTIONS') == 'true' and os.environ.get('RUNNER_OS') == 'Linux', 'remote-Linux-required')
        require(args.baseline == proof['source'], 'explicit-reviewed-self-baseline-required')
        proof['cohort'] = reviewed_cohort(args.baseline)
        before = snapshot(); require(before['status'] == sha(b''), 'clean-committed-source-required')
        original = Path(SOURCE).read_bytes(); source = original.decode()
        require(sha(original) == SOURCE_SHA and source.count(GREEN) == 1, 'exact-reviewed-cache-source-required')
        start = source.index('    pub(crate) fn take_mls_group(')
        end = source.index('\n    /// Store `group`', start)
        require(source[start:end].count(GREEN) == 1, 'sole-cache-fast-path-owner')
        mutants = {name: source.replace(GREEN, value, 1).encode() for name, value in INVERSES.items()}
        require(all(value.count(b'\n') == original.count(b'\n') for value in mutants.values()), 'newline-preserved-cache-inverses')
        proof['input_sha256'] = SOURCE_SHA
        proof['mutant_sha256'] = {key: sha(value) for key, value in mutants.items()}
        proof['controls'] = controls(source); save()
        if args.mode == 'run':
            environment(os.environ, None)  # Reject injected initial stack before setting cohort policy.
            held = HeldSource(Path(SOURCE), original)
            for cohort, features, profile, stack in COHORTS:
                if stack is None: os.environ.pop('RUST_MIN_STACK', None)
                else: os.environ['RUST_MIN_STACK'] = stack
                environment(os.environ, stack)
                sequence = [('positive', None)] if args.stage == 'positive' else [
                    ('baseline', None), ('reuse-off', 'reuse-off'), ('reuse-restored', None),
                    ('generation-ignore', 'generation-ignore'), ('generation-restored', None)]
                for phase, inverse in sequence:
                    wanted = mutants[inverse] if inverse else original
                    if held.current != wanted: held.write(held.current, wanted)
                    expected = {**before, 'files': dict(before['files'])}
                    if inverse:
                        expected['files'][SOURCE] = [sha(wanted), before['files'][SOURCE][1]]
                        expected['status'] = sha((' M '+SOURCE+'\0').encode())
                    row = dict(label=cohort+'/'+phase, cohort=cohort, features=features, profile=profile,
                               rust_min_stack=stack, inverse=inverse, intentional_runtime_failure=inverse is not None)
                    proof['phases'].append(row); save()
                    held.verify(wanted); require(snapshot() == expected, 'whole-source-before-cache-inventory')
                    flags = ['--locked', '-p', 'cgka-engine', '--lib', '--profile', profile]
                    if features: flags += ['--features', ','.join(features)]
                    selection = 'package(cgka-engine) & binary(=cgka_engine) & test(='+TEST+')'
                    code, raw, elapsed, stderr = capture(['cargo', 'nextest', 'list']+flags
                        +['--message-format', 'json', '-E', selection], 1800, separate=True)
                    row['inventory'] = dict(exit_code=code, elapsed_seconds=elapsed, stdout_sha256=sha(raw),
                                            stderr_sha256=sha(stderr), compiler=compiler(stderr, before['files']))
                    save(); require(code == 0 and row['inventory']['compiler'] == EMPTY_COMPILER, 'clean-cache-inventory-compiler')
                    inventory = json.loads(raw, object_pairs_hook=unique); selected_case(inventory, TEST)
                    suites = [suite for suite in inventory['rust-suites'].values()
                              if any(item['filter-match']['status'] == 'matches' for item in suite['testcases'].values())]
                    require(len(suites) == 1 and suites[0]['binary-name'] == 'cgka_engine'
                            and suites[0]['kind'] == 'lib', 'exact-one-engine-lib-inventory')
                    row['inventory'].update(selected_nonignored=1, selected_ignored=0); save()
                    held.verify(wanted); require(snapshot() == expected, 'whole-source-after-cache-inventory')
                    row['body_invoked'] = True; save()
                    code, raw, elapsed, _ = capture(['cargo', 'nextest', 'run']+flags+[
                        '--retries', '0', '--test-threads', '1', '--status-level', 'pass', '--final-status-level', 'none',
                        '--no-fail-fast', '--success-output', 'immediate', '--failure-output', 'immediate', '-E', selection], 1800)
                    row['body'] = dict(exit_code=code, elapsed_seconds=elapsed, raw_sha256=sha(raw), raw_bytes=len(raw),
                                       compiler=compiler(raw, before['files']), summary=summary_counts(raw))
                    row['observed_counts'] = observed_counts(raw); row['counts_identity_validated'] = False; save()
                    row['counts'] = runtime(raw, 'cgka-engine', 'cgka_engine', 'lib', TEST)
                    row['counts_identity_validated'] = True; save()
                    require(row['body']['compiler'] == EMPTY_COMPILER, 'full-cache-body-compiler-empty')
                    value = probe(raw); row['probe'] = value; save(); oracle(value, inverse)
                    require(code == (100 if inverse else 0) and row['counts']['failed'] == int(inverse is not None), 'exact-cache-runtime-exit-and-counts')
                    if inverse: row['own_failure'] = own_failure(raw, wanted.decode(), value['load_deltas'])
                    else: require(b'panicked at ' not in raw, 'cache-control-no-runtime-panic')
                    held.verify(wanted); require(snapshot() == expected, 'whole-source-after-cache-body')
                    row['source_closure_exact'] = True; save()
                    if inverse:
                        held.write(wanted, original); require(snapshot() == before, 'exact-immediate-cache-mutant-restoration')
            expected_labels = [cohort+'/'+phase for cohort, _, _, _ in COHORTS
                for phase in (['positive'] if args.stage == 'positive' else
                    ['baseline', 'reuse-off', 'reuse-restored', 'generation-ignore', 'generation-restored'])]
            require([row['label'] for row in proof['phases']] == expected_labels
                    and sum(row['counts']['executed'] for row in proof['phases']) == len(expected_labels),
                    'complete-two-cohort-ordered-runtime-inventory')
            proof['passed'] = True
        else: proof['passed'] = True
    except (ValueError, KeyError, TypeError, OSError, UnicodeError, subprocess.SubprocessError, AssertionError) as error:
        proof['failure_category'] = type(error).__name__
        if isinstance(error, ValueError) and re.fullmatch('[A-Za-z0-9_-]{1,160}', str(error)):
            proof['failure_label'] = str(error)
    finally:
        if held is not None:
            try:
                if held.current != original: held.write(held.current, original)
                held.verify(original)
            except (ValueError, OSError): proof['passed'] = False
            finally: held.close()
        if initial_stack is None: os.environ.pop('RUST_MIN_STACK', None)
        else: os.environ['RUST_MIN_STACK'] = initial_stack
        if before is not None:
            try: proof['source_restored'] = snapshot() == before
            except (OSError, subprocess.SubprocessError): proof['source_restored'] = False
        proof['passed'] = proof['passed'] and proof['source_restored']
        unknown = [row['label'] for row in proof['phases'] if row.get('body_invoked') and row.get('observed_counts') is None]
        known = sum(row['observed_counts']['executed'] for row in proof['phases'] if row.get('observed_counts') is not None)
        proof['known_executed_product_bodies'] = known
        proof['executed_product_bodies'] = None if unknown else known
        proof['invoked_phases_with_unknown_counts'] = unknown
        save()
    return 0 if proof['passed'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
