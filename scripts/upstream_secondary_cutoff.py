"""Remote-only real post-capture arrival cutoff: baseline, sole omission, restore."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess

from upstream_avatar_ready_turn_chain import capture, compiler_diagnostics
from upstream_extraction_cohort import frozen_inputs, git, reviewed_cohort
from upstream_sdk_replay_pfp import (CASES as SDK_CASES, SOURCES as SDK_SOURCES, FIXTURE as SDK_FIXTURE,
    mutate as sdk_mutate, oracle as sdk_oracle, parser_controls as sdk_parser_controls,
    panic_coordinates as sdk_panic_coordinates, partial_counts as sdk_partial_counts)
from upstream_publication_mutation_anchors import ExactCancellationMutation, secondary_prefix_omission

SOURCE = 'crates/marmot-app/src/runtime/account_worker.rs'
FIXTURE = 'crates/marmot-app/src/runtime/account_worker/tests/secondary_retry_scheduler_tests.rs'
CASES = {key: 'runtime::account_worker::tests::secondary_retry_scheduler_tests::captured_'
         + key + '_prefix_drains_before_later_archive_commands' for key in ['deferred', 'buffered']}
ASSERTION = 'captured predecessor prefix must drain before post-cutoff archive commands'
CAPTURE = 'secondary-cutoff-capture '
PRIOR = 'secondary-cutoff-prerequisites '
RESULT = 'secondary-cutoff-result '
PRIOR_KEYS = {'captured_initial_four', 'original_deferred_prefix', 'original_buffered_prefix',
              'no_archive_or_drain_before_cutoff', 'due_retry_owed',
              'later_commands_enqueued_after_cutoff'}
RESULT_KEYS = {'initial_predecessors_before_first_drain', 'later_commands_after_first_drain',
               'all_commands_completed', 'published_send_observed', 'runtime_closed',
               'held_backoff_preserved', 'optional_passes_observed', 'cutoff_rendezvous_completed'}
FEATURES = ('marmot-app/otlp-export,marmot-app/product-analytics-export,'
            'marmot-app/test-policy-overrides,marmot-app/experimental-device-sync,'
            'cgka-engine/test-policy-overrides,cgka-engine/test-crash-hooks')
FAILURES = {'fresh-external-output', 'pristine-inputs', 'source-identity', 'fixture-identity',
            'compiler-environment', 'original-stack', 'pinned-rustc', 'phase-inputs',
            'inventory-compile', 'inventory-one-nonignored', 'baseline-unqualified',
            'assertion-source', 'parser-positive', 'parser-negative', 'unsupported-cargo-test-context'}


def sha(value):
    return hashlib.sha256(value).hexdigest()


FAILURES.update({
    'sdk-private-cohort-only', 'sdk-exact-manual-workflow-source', 'sdk-case',
    'sdk-one-original-anchor', 'sdk-exact-inverse', 'sdk-one-own-label',
    'sdk-one-own-assert', 'sdk-own-condition', 'sdk-parser-positive',
    'sdk-parser-thread-form', 'sdk-parser-negative',
    'unsupported-compiler-source-context', 'mismatched-compiler-source-context',
    'sdk-compiler-source-control', 'sdk-explicit-case-selection',
})


def failure(error):
    if (type(error) is ValueError and len(error.args) == 1
            and type(error.args[0]) is str and error.args[0] in FAILURES):
        return error.args[0]
    return 'unknown'


def assertion_line(fixture):
    lines = fixture.splitlines()
    labels = [index for index, line in enumerate(lines) if ASSERTION in line]
    if len(labels) != 1:
        raise ValueError('assertion-source')
    calls = [index for index in range(max(0, labels[0] - 8), labels[0] + 1)
             if 'assert!(' in lines[index]]
    if not calls:
        raise ValueError('assertion-source')
    body = re.sub(r'\s+', '', ''.join(lines[calls[-1]:labels[0] + 1]))
    if 'assert!(initial_predecessors_before_first_drain&&later_commands_after_first_drain,' not in body:
        raise ValueError('assertion-source')
    return calls[-1] + 1


def runtime_panic_coordinates(raw):
    # Only reviewed public source coordinates; never thread names, messages or
    # unreviewed paths. Export before oracle verdict, including unexpected sites.
    text = re.sub(r'\x1b\[[0-?]*[ -/]*[@-~]', '', raw.decode('utf-8', errors='replace'))
    headers = raw.count(b'panicked at ')
    matches = re.findall(r'panicked at ([^\s\r\n]+\.rs):([0-9]+):([0-9]+):', text)
    positions = set()
    unknown = max(0, headers - len(matches))
    for source, line, column in matches:
        if (source not in {FIXTURE, SOURCE} or len(line) > 7 or len(column) > 7
                or not (1 <= int(line) <= 1_000_000 and 1 <= int(column) <= 1_000_000)):
            unknown += 1
        else:
            positions.add((source, int(line), int(column)))
    ordered = sorted(positions)
    return {'header_count': headers, 'parsed_header_count': len(matches),
            'trusted_source_positions': [dict(source=source, line=line, column=column)
                                         for source, line, column in ordered[:32]],
            'positions_overflow': len(ordered) > 32, 'unreviewed_position_count': unknown}


def oracle(raw, case, fixture, mutant):
    text = re.sub(r'\x1b\[[0-?]*[ -/]*[@-~]', '', raw.decode('utf-8', errors='replace'))
    name = CASES[case]
    summaries = re.findall(r'test result: (ok|FAILED)\. (\d+) passed; (\d+) failed; (\d+) ignored', text)
    named = re.findall(r'^test ' + re.escape(name) + r' \.\.\. (ok|FAILED)\s*$', text, re.M)
    running = re.findall(r'^running (\d+) tests?\s*$', text, re.M)
    counts = None
    if len(summaries) == 1:
        counts = dict(passed=int(summaries[0][1]), failed=int(summaries[0][2]), ignored=int(summaries[0][3]))
    def marker(prefix, keys):
        rows = []
        for line in text.splitlines():
            if prefix.rstrip() not in line:
                continue
            matched = re.fullmatch(re.escape(prefix) + r'(\{[^\r\n]{1,2048}\})', line)
            if matched is None:
                return None
            def unique(pairs):
                value = {}
                for key, item in pairs:
                    if key in value:
                        raise ValueError('duplicate-key')
                    value[key] = item
                return value
            try:
                value = json.loads(matched[1], object_pairs_hook=unique)
            except (TypeError, ValueError):
                return None
            if type(value) is not dict or set(value) != keys or not all(type(v) is bool for v in value.values()):
                return None
            rows.append(value)
        return rows[0] if len(rows) == 1 else None
    capture = marker(CAPTURE, PRIOR_KEYS - {'later_commands_enqueued_after_cutoff'})
    prior = marker(PRIOR, PRIOR_KEYS)
    result = marker(RESULT, RESULT_KEYS)
    expected_prior = {key: True for key in PRIOR_KEYS}
    expected_result = {key: True for key in RESULT_KEYS}
    expected_result['later_commands_after_first_drain'] = not mutant
    site = assertion_line(fixture)
    panic_count = raw.count(b'panicked at ')
    intended = bool(panic_count == 1 and re.search(
        r"thread '" + re.escape(name) + r"'(?: \([0-9]+\))? panicked at " + re.escape(FIXTURE) + ':' + str(site) + r':\d+:\n'
        + re.escape(ASSERTION) + r'\s*(?:\n|$)', text))
    ordered = (capture is not None and prior is not None and result is not None
               and text.index(CAPTURE) < text.index(PRIOR) < text.index(RESULT)
               and (not mutant or intended and text.index(RESULT) < text.index('panicked at ')))
    diagnostics = compiler_diagnostics(raw, cargo_test_context=('marmot-app', '--lib'))
    expected = [('FAILED', '0', '1', '0')] if mutant else [('ok', '1', '0', '0')]
    return {'counts': counts, 'running_one': running == ['1'],
            'actual_named_body': named == ['FAILED' if mutant else 'ok'],
            'prerequisites': prior, 'result': result, 'markers_ordered': bool(ordered),
            'frozen_capture_prerequisites': capture,
            'panic_header_count': panic_count, 'intended_order_assertion': intended,
            'trusted_assertion_line': site, 'compiler_diagnostics': diagnostics,
            'runtime_panic_coordinates': runtime_panic_coordinates(raw),
            'evidence_passed': bool(summaries == expected and running == ['1']
                and named == ['FAILED' if mutant else 'ok'] and ordered
                and capture == {key: True for key in PRIOR_KEYS - {'later_commands_enqueued_after_cutoff'}}
                and prior == expected_prior and result == expected_result
                and (intended if mutant else panic_count == 0)
                and not diagnostics['compiler_codes'] and diagnostics['compiler_header_count'] == 0)}


def parser_controls(fixture):
    site = assertion_line(fixture)
    positives = negatives = 0
    for case, name in CASES.items():
        def stream(mutant):
            result = {key: True for key in RESULT_KEYS}
            result['later_commands_after_first_drain'] = not mutant
            return ('running 1 test\ntest ' + name + (' ... FAILED\n' if mutant else ' ... ok\n')
                + CAPTURE + json.dumps({key: True for key in PRIOR_KEYS - {'later_commands_enqueued_after_cutoff'}}) + '\n'
                + PRIOR + json.dumps({key: True for key in PRIOR_KEYS}) + '\n'
                + RESULT + json.dumps(result) + '\n'
                + ("thread '" + name + "' panicked at " + FIXTURE + ':' + str(site) + ':5:\n' + ASSERTION + '\n' if mutant else '')
                + ('test result: FAILED. 0 passed; 1 failed; 0 ignored\nerror: test failed, to rerun pass `-p marmot-app --lib`\n'
                   if mutant else 'test result: ok. 1 passed; 0 failed; 0 ignored\n')).encode()
        good, killed = stream(False), stream(True)
        if not oracle(good, case, fixture, False)['evidence_passed'] or not oracle(killed, case, fixture, True)['evidence_passed']:
            raise ValueError('parser-positive')
        positions = runtime_panic_coordinates(killed)
        if (positions['trusted_source_positions'] != [dict(source=FIXTURE, line=site, column=5)]
                or positions['header_count'] != 1 or positions['unreviewed_position_count'] != 0):
            raise ValueError('parser-positive')
        private_positions = runtime_panic_coordinates(
            b"thread 'PRIVATE' panicked at /PRIVATE/private.rs:12:4:\nPRIVATE_MESSAGE\n")
        if (private_positions['unreviewed_position_count'] != 1
                or private_positions['trusted_source_positions'] != []
                or 'PRIVATE' in json.dumps(private_positions)):
            raise ValueError('parser-negative')
        positives += 2
        bad = [killed.replace(("thread '" + name + "'").encode(), b"thread 'wrong_thread'"),
               killed.replace(b'"runtime_closed": true', b'"runtime_closed": false'),
               killed.replace(b'"captured_initial_four": true', b'"captured_initial_four": false'),
               killed.replace(b'"later_commands_after_first_drain": false', b'"later_commands_after_first_drain": true'),
               killed.replace(ASSERTION.encode(), b'unknown panic'),
               killed.replace((FIXTURE + ':').encode(), b'private.rs:'),
               killed.replace((':' + str(site) + ':5:').encode(), b':1:5:'),
               killed.replace(name.encode(), b'unknown_case'), killed + killed,
               killed.replace(b'0 ignored', b'1 ignored'),
               killed.replace(b'"runtime_closed": true', b'"runtime_closed": 1'),
               killed.replace(PRIOR.encode(), b'unknown-prefix '),
               killed.replace(CAPTURE.encode(), b'unknown-capture '),
               killed.replace(CAPTURE.encode(), b'secondary-cutoff-capture-PRIVATE '),
               killed.replace(b'\"due_retry_owed\": true', b'\"due_retry_owed\": \"PRIVATE\"'),
               killed + (CAPTURE + json.dumps({key: True for key in PRIOR_KEYS - {'later_commands_enqueued_after_cutoff'}}) + '\n').encode(),
               killed.replace(b'"due_retry_owed": true', b'"due_retry_owed": 1'),
               killed + b'error[E0382]: source-owned synthetic compile error\n']
        if any(oracle(item, case, fixture, True)['evidence_passed'] for item in bad):
            raise ValueError('parser-negative')
        negatives += len(bad)
    return {'positive': positives, 'negative': negatives, 'metadata_only': True, 'product_bodies': 0}


def main():
    os.umask(0o077)
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--case', choices=sorted(set(CASES) | set(SDK_CASES)), required=True)
    parser.add_argument('--source', required=True)
    parser.add_argument('--cohort', choices=['default', 'experimental'], required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--preflight', action='store_true')
    args = parser.parse_args()
    sdk_case = args.case in SDK_CASES
    if sdk_case and args.cohort != 'experimental':
        raise ValueError('sdk-private-cohort-only')
    source_path = SDK_SOURCES[args.case] if sdk_case else SOURCE
    fixture_path = SDK_FIXTURE if sdk_case else FIXTURE
    selected_name = SDK_CASES[args.case] if sdk_case else CASES[args.case]
    package = 'transport-nostr-adapter' if sdk_case else 'marmot-app'
    coordinates = sdk_panic_coordinates if sdk_case else runtime_panic_coordinates
    if sdk_case:
        ref = os.environ.get('GITHUB_REF', '')
        workflow = 'dyKiU/mdk/.github/workflows/upstream-boundary-regressions.yml@' + ref
        if (os.environ.get('GITHUB_EVENT_NAME') != 'workflow_dispatch'
                or not ref.startswith('refs/heads/ci/upstream-develop-dy-')
                or os.environ.get('GITHUB_WORKFLOW_REF') != workflow
                or os.environ.get('GITHUB_WORKFLOW_SHA') != os.environ.get('GITHUB_SHA')
                or args.source != os.environ.get('GITHUB_SHA')):
            raise ValueError('sdk-exact-manual-workflow-source')
        event = json.loads(Path(os.environ['GITHUB_EVENT_PATH']).read_text())
        selector = event.get('inputs', {}).get('sdk_replay_case', 'all')
        if selector not in ('all', 'sdk-epoch', 'sdk-alias') or (selector != 'all' and selector != args.case):
            raise ValueError('sdk-explicit-case-selection')
    root, output = Path.cwd().resolve(), args.output.resolve()
    if output.exists() or output == root or root in output.parents:
        raise ValueError('fresh-external-output')
    output.parent.mkdir(parents=True, exist_ok=True)
    features = FEATURES if args.cohort == 'experimental' else ','.join(
        flag for flag in FEATURES.split(',') if flag != 'marmot-app/experimental-device-sync')
    if sdk_case:
        features = 'sdk,experimental-device-sync,test-policy-overrides'
    proof = {'complete': False, 'case': args.case, 'cohort': args.cohort,
             'runs': [], 'runtime_mutation_qualification': False}
    before = leaf = original = None
    baseline_passed = False
    def save():
        output.write_text(json.dumps(proof, indent=2) + '\n')
    try:
        proof['identity'] = reviewed_cohort(args.source)
        before = frozen_inputs()
        head, index = git('rev-parse', 'HEAD'), git('ls-files', '--stage')
        modes = {name: stat.S_IMODE(Path(name).lstat().st_mode) for name in before}
        if git('diff', '--name-only', 'HEAD') or git('diff', '--cached', '--name-only'):
            raise ValueError('pristine-inputs')
        original, fixture = Path(source_path).read_bytes(), Path(fixture_path).read_text()
        if original != subprocess.check_output(['git', 'show', args.source + ':' + source_path]):
            raise ValueError('source-identity')
        if fixture.encode() != subprocess.check_output(['git', 'show', args.source + ':' + fixture_path]):
            raise ValueError('fixture-identity')
        mutant = (sdk_mutate(args.case, original.decode()) if sdk_case else secondary_prefix_omission(original.decode())).encode()
        proof.update(source=args.source, tooling=head, source_tree=git('rev-parse', args.source + '^{tree}'), tooling_tree=git('rev-parse', 'HEAD^{tree}'),
                     source_sha256=sha(original), mutant_sha256=sha(mutant), fixture_sha256=sha(fixture.encode()),
                     lock_sha256=sha(Path('Cargo.lock').read_bytes()), expected_test=selected_name)
        proof['parser_controls'] = sdk_parser_controls(fixture) if sdk_case else parser_controls(fixture)
        if args.preflight:
            unchanged = (frozen_inputs() == before and git('rev-parse', 'HEAD') == head
                         and git('ls-files', '--stage') == index
                         and all(stat.S_IMODE(Path(name).lstat().st_mode) == value for name, value in modes.items()))
            proof.update(metadata_complete=unchanged, metadata_inputs_unchanged=unchanged, product_bodies=0)
            save()
            return 0 if unchanged else 1
        flags_env = ['RUSTFLAGS', 'CARGO_ENCODED_RUSTFLAGS', 'RUSTDOCFLAGS', 'CARGO_ENCODED_RUSTDOCFLAGS',
                     'RUSTC_WRAPPER', 'RUSTC_WORKSPACE_WRAPPER', 'RUSTC_BOOTSTRAP']
        environment = {'CARGO_INCREMENTAL': '1', 'CARGO_BUILD_JOBS': '2', 'CARGO_PROFILE_DEV_DEBUG': '0',
                       'CARGO_PROFILE_TEST_DEBUG': '0', 'CARGO_TERM_COLOR': 'never'}
        if (any(os.environ.get(key) for key in flags_env) or any(os.environ.get(k) != v for k, v in environment.items())
                or sdk_case and any(value for key,value in os.environ.items()
                                    if key.startswith('CARGO_TARGET_') and key.endswith('_RUSTFLAGS'))):
            raise ValueError('compiler-environment')
        if os.environ.get('RUST_MIN_STACK') != '4194304':
            raise ValueError('original-stack')
        rustc = subprocess.check_output(['rustc', '-Vv'], text=True).strip()
        channel = re.search(r'^channel = "([0-9.]+)"$', Path('rust-toolchain.toml').read_text(), re.M)
        if channel is None or not re.search(r'^release: ' + re.escape(channel[1]) + '$', rustc, re.M):
            raise ValueError('pinned-rustc')
        proof.update(rustc=rustc, cargo=subprocess.check_output(['cargo', '-V'], text=True).strip(),
                     features=features.split(','), compiler_environment=environment,
                     retries=0, test_threads=1, rust_min_stack=4194304)
        leaf = ExactCancellationMutation(Path(source_path))
        def exact(content):
            expected = dict(before)
            expected[source_path] = dict(before[source_path], sha256=sha(content))
            return (frozen_inputs() == expected and git('rev-parse', 'HEAD') == head
                    and git('ls-files', '--stage') == index
                    and all(stat.S_IMODE(Path(name).lstat().st_mode) == value for name, value in modes.items()))
        def execute(phase, content):
            leaf.check()
            if not exact(content):
                raise ValueError('phase-inputs')
            row = {'phase': phase, 'qualified': False, 'source_sha256': sha(content)}
            proof['runs'].append(row)
            save()
            flags = ['--locked', '-p', package, '--lib', '--features', features]
            selection = 'package(' + package + ') & binary(=' + package.replace('-', '_') + ') & test(=' + selected_name + ')'
            code, raw, elapsed, stderr = capture(['cargo', 'nextest', 'list', *flags,
                '--message-format', 'json', '-E', selection], 1800, separate=True)
            row['inventory'] = dict(exit_code=code, elapsed_seconds=elapsed, stdout_sha256=sha(raw),
                stderr_sha256=sha(stderr), compiler_diagnostics=compiler_diagnostics(
                    stderr, compiler_source_context='transport-nostr-adapter' if sdk_case else None))
            save()
            if (code != 0 or row['inventory']['compiler_diagnostics']['compiler_codes']
                    or row['inventory']['compiler_diagnostics']['compiler_header_count'] != 0):
                raise ValueError('inventory-compile')
            inventory = json.loads(raw)
            matched = [(name, case['ignored']) for suite in inventory['rust-suites'].values()
                       for name, case in suite['testcases'].items() if case['filter-match']['status'] == 'matches']
            if (len(matched) != 1 or matched[0][0] != selected_name
                    or matched[0][1] is not False):
                raise ValueError('inventory-one-nonignored')
            row['inventory']['selected_nonignored'] = 1
            save()
            if not exact(content):
                raise ValueError('phase-inputs')
            code, raw, elapsed, _ = capture(['cargo', 'test', *flags, selected_name,
                '--', '--exact', '--test-threads=1', '--show-output'], 1800)
            row['body'] = dict(exit_code=code, elapsed_seconds=elapsed, raw_sha256=sha(raw), raw_bytes=len(raw),
                               compiler_diagnostics=compiler_diagnostics(raw, cargo_test_context=(package, '--lib')),
                               runtime_panic_coordinates=coordinates(raw))
            if sdk_case:
                row['body']['counts'] = sdk_partial_counts(raw)
            save()
            row['body'].update((sdk_oracle if sdk_case else oracle)(raw, args.case, fixture, phase == 'mutant'))
            row['all_inputs_exact'] = exact(content)
            if phase == 'mutant':
                survived = (code == 0 and row['all_inputs_exact']
                            and (sdk_oracle if sdk_case else oracle)(raw, args.case, fixture, False)['evidence_passed'])
                row['counterfactual_outcome'] = ('survived' if survived else
                    'intended-runtime-failure' if code == 101 and row['body']['evidence_passed']
                    else 'unqualified')
            row['qualified'] = (code == (101 if phase == 'mutant' else 0)
                                and row['body']['evidence_passed'] and row['all_inputs_exact'])
            save()
            return row['qualified']
        baseline_passed = execute('baseline', original)
        if not baseline_passed:
            raise ValueError('baseline-unqualified')
        leaf.write(mutant)
        proof['mutant_killed'] = execute('mutant', mutant)
    except Exception as error:
        proof.update(error_category=type(error).__name__, failure_category=failure(error))
    finally:
        try:
            if leaf is not None:
                leaf.check()
                if Path(source_path).read_bytes() != original:
                    leaf.write(original)
                proof['source_restored'] = exact(original)
                if baseline_passed and proof['source_restored']:
                    proof['restored_passed'] = execute('restored-control', original)
                proof['all_inputs_restored'] = (exact(original) and not git('diff', '--name-only', 'HEAD')
                                                 and not git('diff', '--cached', '--name-only'))
                proof['complete'] = bool(baseline_passed and proof.get('mutant_killed')
                                         and proof.get('restored_passed') and proof['all_inputs_restored'])
                proof['runtime_mutation_qualification'] = proof['complete']
        except Exception as error:
            proof.update(complete=False, runtime_mutation_qualification=False,
                         closure_failure_category=failure(error))
        finally:
            if leaf is not None:
                try:
                    leaf.close()
                except OSError:
                    proof.update(complete=False, runtime_mutation_qualification=False,
                                 closure_failure_category='descriptor-close')
            save()
    return 0 if proof['complete'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
