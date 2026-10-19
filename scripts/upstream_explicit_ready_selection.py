"""Remote-only real retained-input one-group selector mutation chain."""
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
from upstream_publication_mutation_anchors import ExactCancellationMutation

SOURCE = 'crates/marmot-app/src/client/sync.rs'
FIXTURE = 'crates/marmot-app/src/client/sync/explicit_ready_turn_tests.rs'
NAME = 'client::sync::explicit_ready_turn_tests::one_ready_turn_advances_only_one_real_retained_group'
ASSERTION = 'one owner turn must not retry the second group'
PRIOR = 'explicit-ready-selection-prerequisites '
PROGRESS = 'explicit-ready-selection-progress '
COMMON = ('marmot-app/otlp-export,marmot-app/product-analytics-export,'
          'marmot-app/test-policy-overrides,cgka-engine/test-policy-overrides,'
          'cgka-engine/test-crash-hooks')


def digest(value):
    return hashlib.sha256(value).hexdigest()


def mutate(source):
    start = source.index('    async fn advance_one_ready_explicit_sync_group(')
    end = source.index('\n    /// Bring the live group subscriptions', start)
    segment = source[start:end]
    anchor = '                    return Ok(());'
    if segment.count(anchor) != 1 or 'ConvergenceScheduleState::Ready => {' not in segment:
        raise ValueError('exact-ready-return-anchor')
    return source[:start] + segment.replace(anchor, '                    continue;') + source[end:]


def assertion_line(fixture):
    lines = fixture.splitlines()
    labels = [i for i, line in enumerate(lines) if ASSERTION in line]
    if len(labels) != 1:
        raise ValueError('exact-second-row-label')
    candidates = [i for i in range(max(0, labels[0] - 5), labels[0] + 1)
                  if 'assert!(' in lines[i]]
    if not candidates:
        raise ValueError('exact-second-row-assertion')
    nearest = candidates[-1]
    body = ''.join(lines[nearest:labels[0] + 1])
    if 'after[1]==before[1]' not in re.sub(r'\s+', '', body):
        raise ValueError('exact-second-row-condition')
    return nearest + 1


def oracle(raw, fixture, expect_failure):
    text = re.sub(r'\x1b\[[0-?]*[ -/]*[@-~]', '', raw.decode('utf-8', errors='replace'))
    summaries = re.findall(r'test result: (ok|FAILED)\. (\d+) passed; (\d+) failed; (\d+) ignored', text)
    named = re.findall(r'^test ' + re.escape(NAME) + r' \.\.\. (ok|FAILED)\s*$', text, re.M)
    running = re.findall(r'^running (\d+) tests?\s*$', text, re.M)
    expected = [('FAILED', '0', '1', '0')] if expect_failure else [('ok', '1', '0', '0')]
    counts = None
    if len(summaries) == 1:
        counts = dict(passed=int(summaries[0][1]), failed=int(summaries[0][2]),
                      ignored=int(summaries[0][3]))
    def marker(prefix, required):
        rows = []
        for line in text.splitlines():
            if prefix in line:
                match = re.fullmatch(re.escape(prefix) + r'(\{[^\r\n]{1,256}\})', line)
                if match is None:
                    return None
                def unique(pairs):
                    result = {}
                    for key, value in pairs:
                        if key in result:
                            raise ValueError('duplicate-marker-key')
                        result[key] = value
                    return result
                try:
                    value = json.loads(match[1], object_pairs_hook=unique)
                except (ValueError, TypeError):
                    return None
                if type(value) is not dict or set(value) != required or not all(v is True for v in value.values()):
                    return None
                rows.append(value)
        return rows[0] if len(rows) == 1 else None
    prior = marker(PRIOR, {'both_ready', 'rows_captured'})
    progress = marker(PROGRESS, {'first_real_attempt'})
    site = assertion_line(fixture)
    panic_count = raw.count(b'panicked at ')
    own = (site is not None and panic_count == 1 and re.search(
        r'panicked at ' + re.escape(FIXTURE) + ':' + str(site) + r':\d+:\n'
        + re.escape(ASSERTION) + r'\s*(?:\n|$)', text) is not None)
    ordered = (prior is not None and progress is not None
               and text.index(PRIOR) < text.index(PROGRESS)
               and (not expect_failure or own and text.index(PROGRESS) < text.index('panicked at ')))
    diagnostics = compiler_diagnostics(raw)
    qualified = (summaries == expected and named == ['FAILED' if expect_failure else 'ok']
                 and running == ['1'] and ordered
                 and not diagnostics['compiler_codes'] and diagnostics['compiler_header_count'] == 0
                 and (own if expect_failure else panic_count == 0))
    return {'counts': counts, 'actual_one_named_body': named == ['FAILED' if expect_failure else 'ok'],
            'running_one': running == ['1'], 'prerequisites': prior, 'first_progress': progress,
            'markers_ordered': bool(ordered), 'panic_header_count': panic_count,
            'intended_second_row_assertion': bool(own), 'trusted_assertion_line': site,
            'compiler_diagnostics': diagnostics, 'oracle_qualified': bool(qualified)}


def parser_controls(fixture):
    site = assertion_line(fixture)
    prefix = ('running 1 test\ntest ' + NAME + ' ... ')
    markers = (PRIOR + '{"both_ready":true,"rows_captured":true}\n'
               + PROGRESS + '{"first_real_attempt":true}\n')
    passed = (prefix + 'ok\n' + markers
              + 'test result: ok. 1 passed; 0 failed; 0 ignored\n').encode()
    failed = (prefix + 'FAILED\n' + markers + "thread 'fixture' panicked at "
              + FIXTURE + ':' + str(site) + ':5:\n' + ASSERTION + '\n'
              + 'test result: FAILED. 0 passed; 1 failed; 0 ignored\n').encode()
    if not oracle(passed, fixture, False)['oracle_qualified'] or not oracle(failed, fixture, True)['oracle_qualified']:
        raise ValueError('oracle-positive-control')
    bad = [failed.replace(b'"both_ready":true', b'"both_ready":false'),
           failed.replace(PROGRESS.encode(), b'unknown-control '),
           failed.replace((FIXTURE + ':').encode(), b'private.rs:'),
           failed.replace((':' + str(site) + ':5:').encode(), b':1:5:'),
           failed.replace(NAME.encode(), b'unknown_case'),
           failed.replace(b'0 passed; 1 failed', b'0 passed; 0 failed'),
           failed + failed,
           failed.replace(ASSERTION.encode(), b'unknown panic')]
    if any(oracle(item, fixture, True)['oracle_qualified'] for item in bad):
        raise ValueError('oracle-negative-control')
    return {'positive': 2, 'negative': len(bad), 'metadata_only': True}


def main():
    os.umask(0o077)
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source', required=True)
    parser.add_argument('--cohort', choices=['default', 'experimental'], required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    output = args.output.resolve()
    root = Path.cwd().resolve()
    if output == root or root in output.parents or output.exists():
        raise ValueError('fresh-external-output-required')
    output.parent.mkdir(parents=True, exist_ok=True)
    report = {'complete': False, 'case': 'explicit-ready-selection-pfp', 'cohort': args.cohort,
              'expected_test': NAME, 'runs': [], 'runtime_mutation_qualification': False}
    before = None
    leaf = None
    baseline_passed = False
    def save():
        output.write_text(json.dumps(report, indent=2) + '\n')
    try:
        report['identity'] = reviewed_cohort(args.source)
        before = frozen_inputs()
        head = git('rev-parse', 'HEAD')
        index = git('ls-files', '--stage')
        modes = {name: stat.S_IMODE(Path(name).lstat().st_mode) for name in before}
        if git('diff', '--name-only', 'HEAD') or git('diff', '--cached', '--name-only'):
            raise ValueError('pristine-input-required')
        if any(os.environ.get(key) for key in ['RUSTFLAGS', 'CARGO_ENCODED_RUSTFLAGS',
                'RUSTDOCFLAGS', 'CARGO_ENCODED_RUSTDOCFLAGS', 'RUSTC_WRAPPER',
                'RUSTC_WORKSPACE_WRAPPER', 'RUSTC_BOOTSTRAP']):
            raise ValueError('unexpected-compiler-flags')
        if os.environ.get('RUST_MIN_STACK') != '4194304':
            raise ValueError('original-stack-required')
        environment = {'CARGO_INCREMENTAL': '1', 'CARGO_BUILD_JOBS': '2',
                       'CARGO_PROFILE_DEV_DEBUG': '0', 'CARGO_PROFILE_TEST_DEBUG': '0',
                       'CARGO_TERM_COLOR': 'never'}
        if any(os.environ.get(name) != value for name, value in environment.items()):
            raise ValueError('fixed-compiler-environment')
        original = Path(SOURCE).read_bytes()
        fixture = Path(FIXTURE).read_text()
        if original != subprocess.check_output(['git', 'show', args.source + ':' + SOURCE]):
            raise ValueError('product-source-identity')
        if fixture.encode() != subprocess.check_output(['git', 'show', args.source + ':' + FIXTURE]):
            raise ValueError('product-fixture-identity')
        mutant = mutate(original.decode()).encode()
        report['parser_controls'] = parser_controls(fixture)
        rustc = subprocess.check_output(['rustc', '-Vv'], text=True).strip()
        channel = re.search(r'^channel = "([0-9.]+)"$', Path('rust-toolchain.toml').read_text(), re.M)
        if channel is None or re.search(r'^release: ' + re.escape(channel[1]) + '$', rustc, re.M) is None:
            raise ValueError('exact-pinned-rustc-release')
        leaf = ExactCancellationMutation(Path(SOURCE))
        report.update(source=args.source, tooling=head,
                      source_tree=git('rev-parse', args.source + '^{tree}'),
                      original_sha256=digest(original), mutant_sha256=digest(mutant),
                      fixture_sha256=digest(fixture.encode()), lock_sha256=digest(Path('Cargo.lock').read_bytes()),
                      compiler_environment=environment, rustc=rustc,
                      cargo=subprocess.check_output(['cargo', '-V'], text=True).strip(),
                      rust_min_stack=4194304, retries=0, test_threads=1)
        features = COMMON + (',marmot-app/experimental-device-sync' if args.cohort == 'experimental' else '')
        flags = ['--locked', '-p', 'marmot-app', '--lib', '--features', features]
        report['features'] = features.split(',')
        save()
        def inputs_exact(content):
            expected = dict(before)
            expected[SOURCE] = dict(before[SOURCE], sha256=digest(content))
            return (frozen_inputs() == expected and git('rev-parse', 'HEAD') == head
                    and git('ls-files', '--stage') == index
                    and all(stat.S_IMODE(Path(name).lstat().st_mode) == mode for name, mode in modes.items()))
        def execute(phase, content):
            leaf.check()
            if not inputs_exact(content):
                raise ValueError('phase-input-identity')
            row = {'phase': phase, 'qualified': False, 'source_sha256': digest(content)}
            report['runs'].append(row)
            save()
            selection = 'package(marmot-app) & binary(=marmot_app) & test(=' + NAME + ')'
            code, raw, elapsed, stderr = capture(['cargo', 'nextest', 'list', *flags,
                '--message-format', 'json', '-E', selection], 1800, separate=True)
            row['inventory'] = {'exit_code': code, 'elapsed_seconds': elapsed,
                                'stdout_sha256': digest(raw), 'stderr_sha256': digest(stderr),
                                'compiler_diagnostics': compiler_diagnostics(stderr)}
            save()
            if code != 0:
                raise ValueError('inventory-compile-failed')
            inventory = json.loads(raw)
            selected = [name for suite in inventory['rust-suites'].values()
                        for name, case in suite['testcases'].items()
                        if case['filter-match']['status'] == 'matches' and not case['ignored']]
            if selected != [NAME]:
                raise ValueError('inventory-one-nonignored')
            row['selected_nonignored'] = 1
            if not inputs_exact(content):
                raise ValueError('post-inventory-input-identity')
            code, raw, elapsed, _ = capture(['cargo', 'test', *flags, NAME,
                '--', '--exact', '--test-threads=1', '--show-output'], 1800)
            row['body'] = {'exit_code': code, 'elapsed_seconds': elapsed,
                           'raw_sha256': digest(raw), 'raw_bytes': len(raw),
                           'compiler_diagnostics': compiler_diagnostics(raw)}
            save()
            row['body'].update(oracle(raw, fixture, phase == 'mutant'))
            row['inputs_exact'] = inputs_exact(content)
            row['qualified'] = (code == (101 if phase == 'mutant' else 0)
                                and row['body']['oracle_qualified'] and row['inputs_exact'])
            save()
            return row['qualified']
        baseline_passed = execute('baseline', original)
        if not baseline_passed:
            raise ValueError('baseline-not-qualified')
        leaf.write(mutant)
        report['mutant_killed'] = execute('mutant', mutant)
    except Exception as error:
        report['error_category'] = type(error).__name__
    finally:
        try:
            if leaf is not None:
                leaf.check()
                if Path(SOURCE).read_bytes() != original:
                    leaf.write(original)
                report['source_restored'] = inputs_exact(original)
                if baseline_passed and report['source_restored']:
                    report['restored_passed'] = execute('restored', original)
                report['all_inputs_restored'] = (inputs_exact(original)
                                                 and not git('diff', '--name-only', 'HEAD')
                                                 and not git('diff', '--cached', '--name-only'))
            report['complete'] = bool(baseline_passed and report.get('mutant_killed')
                                      and report.get('restored_passed') and report.get('all_inputs_restored'))
            report['runtime_mutation_qualification'] = report['complete']
        except Exception as error:
            report['complete'] = False
            report['runtime_mutation_qualification'] = False
            report['closure_error_category'] = type(error).__name__
        finally:
            if leaf is not None:
                try:
                    leaf.close()
                except OSError:
                    report['complete'] = False
                    report['runtime_mutation_qualification'] = False
                    report['closure_error_category'] = 'DescriptorCloseError'
            save()
    return 0 if report['complete'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
