"""Remote-only original avatar regression: control, hook omission, exact restore."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess

from upstream_current_backend_probe import ANSI, capture, parse_core, parse_marker
from upstream_extraction_cohort import frozen_inputs

SOURCE = 'crates/marmot-app/src/client/sync.rs'
TEST = 'crates/cli/tests/cli.rs'
NAME = 'groups_set_avatar_url_round_trips_through_sync_and_show'
TOOLS = {'scripts/upstream_avatar_ready_turn_chain.py',
         '.github/workflows/upstream-avatar-ready-turn.yml',
         '.github/workflows/upstream-boundary-regressions.yml',
         'scripts/upstream_extraction_cohort.py'}
HOOK = '''        if explicit {
            // A directly owned client has no account worker to consume the
            // pending convergence edges produced by the input just ingested.
            // Keep completed work retained across the bounded owner turn.
            self.pending_applied_sync_summary
                .merge(std::mem::take(&mut summary));
            let advanced = self.advance_one_ready_explicit_sync_group().await;
            self.prepend_pending_applied_summary(&mut summary);
            if let Err(error) = advanced {
                return Err(ClassifiedSyncFailure::at_stage(
                    summary,
                    error,
                    SyncFailureStage::Unknown,
                ));
            }
        }
'''


# Only exact literals raised by this source are exported. Arbitrary exception
# messages, identifiers and paths remain unreported, including imported errors.
FAILURE_CATEGORIES = frozenset({
    'physical-source-ancestry', 'original-avatar-assertion-anchor',
    'original-assertion-source-cardinality', 'positive-parser-control',
    'negative-parser-control', 'output-must-be-outside-checkout',
    'fresh-output-required', 'immutable-source-required', 'workflow-head-identity',
    'tool-child-diff-allowlist', 'regular-source-required', 'tracked-product-mode',
    'exact-product-hook-required', 'unchanged-original-test-required',
    'tracked-parent-symlink', 'untracked-source-admission', 'pristine-admission',
    'unexpected-compiler-environment', 'fixed-compiler-environment',
    'exact-pinned-rustc-release', 'inventory-compile-failed',
    'inventory-not-exactly-one-nonignored', 'phase-input-closure',
    'runtime-phase-not-qualified', 'restore-physical-source',
})
COMPILER_SOURCES = frozenset({
    SOURCE, TEST,
    'crates/marmot-app/src/client/sync/explicit_ready_turn_tests.rs',
    'crates/marmot-app/src/client/device_linking.rs',
    'crates/marmot-app/src/runtime/private_commit.rs',
    'crates/marmot-app/src/runtime/account_worker.rs',
    'crates/marmot-app/src/runtime/device_linking.rs',
    'crates/cgka-engine/src/private_roster_settlement_tests.rs',
    'crates/marmot-app/src/tests.rs',
    'crates/cgka-engine/src/private_roster_settlement.rs',
    'crates/cgka-session/src/lib.rs',
})


def failure_category(error):
    if (type(error) is ValueError and len(error.args) == 1
            and type(error.args[0]) is str and error.args[0] in FAILURE_CATEGORIES):
        return error.args[0]
    return 'unknown'


def compiler_diagnostics(raw):
    # Raw capture is already bounded. Export fixed Rust error codes and only
    # reviewed source positions, never diagnostic text or unreviewed paths.
    text = ANSI.sub('', raw.decode('utf-8', errors='replace'))
    codes = sorted(set(re.findall(r'\berror\[(E[0-9]{4})\]', text)))
    headers = [line for line in text.splitlines()
               if re.match(r'^error(?:\[E[0-9]{4}\])?:', line)
               and not re.match(r'^error: test run failed\s*$', line)]
    sites = set()
    unknown = 0
    for path, line, column in re.findall(r'^\s*--> ([^\s]+\.rs):(\d+):(\d+)\s*$', text, re.M):
        if path not in COMPILER_SOURCES or not (1 <= int(line) <= 1_000_000
                                                and 1 <= int(column) <= 1_000_000):
            unknown += 1
        else:
            sites.add((path, int(line), int(column)))
    ordered = sorted(sites)
    return {'compiler_codes': codes, 'compiler_header_count': len(headers),
            'trusted_source_positions': [dict(source=p, line=line, column=column)
                                         for p, line, column in ordered[:32]],
            'trusted_positions_overflow': len(ordered) > 32,
            'unreviewed_position_count': unknown}


def git(*args):
    return subprocess.check_output(['git', *args]).decode().strip()


def sha(data):
    return hashlib.sha256(data).hexdigest()


def physical(path):
    for item in (path, *path.parents):
        if item.is_symlink():
            raise ValueError('physical-source-ancestry')
        if item == Path.cwd():
            break


def modes_for(inputs):
    return {name: stat.S_IMODE(Path(name).lstat().st_mode) for name in inputs}


def closure(before, head, index, modes):
    return (frozen_inputs() == before and git('rev-parse', 'HEAD') == head
            and git('ls-files', '--stage') == index
            and modes_for(before) == modes
            and not git('diff', '--name-only', 'HEAD')
            and not git('diff', '--cached', '--name-only')
            and not git('ls-files', '--others', '--exclude-standard'))


def intended_failure(raw, test_bytes):
    # Restrict the panic to the ORIGINAL final Bob avatar assertion and its
    # exact static boolean mismatch, not an arbitrary warning elsewhere.
    lines = test_bytes.decode().splitlines()
    begin = next(i for i, line in enumerate(lines) if 'fn ' + NAME + '(' in line)
    end = next((i for i in range(begin + 1, len(lines))
                if re.match(r'(?:async )?fn |#\[(?:tokio::)?test', lines[i])), len(lines))
    anchors = [i + 1 for i in range(begin, end)
               if lines[i].strip() == 'assert_eq!(bob_cleared["group"]["avatar_url"]["present"], false);']
    # Source shape is reviewed and immutable. Fail closed if the original
    # assertion differs instead of broadening the accepted panic range.
    if len(anchors) != 1:
        raise ValueError('original-avatar-assertion-anchor')
    # Count headers independently: the contextual body regex can consume a
    # subsequent header. Duplicates or an unrelated panic never qualify.
    if raw.count(b'panicked at ') != 1:
        return False
    text = ANSI.sub('', raw.decode('utf-8', errors='replace'))
    panics = list(re.finditer(r'panicked at ([^\s]+\.rs):(\d+):(\d+):\n([^\n]*(?:\n[^\n]*){0,4})', text))
    if len(panics) != 1:
        return False
    item = panics[0]
    body = item[4]
    return (item[1] == TEST and int(item[2]) == anchors[0]
            and 'assertion `left == right` failed' in body
            and re.search(r'left:\s*Bool\(true\)', body) is not None
            and re.search(r'right:\s*false\b', body) is not None)


def oracle_controls(test_bytes):
    lines = test_bytes.decode().splitlines()
    anchor = 'assert_eq!(bob_cleared["group"]["avatar_url"]["present"], false);'
    sites = [i + 1 for i, line in enumerate(lines) if line.strip() == anchor]
    if len(sites) != 1:
        raise ValueError('original-assertion-source-cardinality')
    good = ("thread 'fixture' panicked at " + TEST + ':' + str(sites[0])
            + ':5:\nassertion `left == right` failed\n  left: Bool(true)\n right: false\n').encode()
    if not intended_failure(good, test_bytes):
        raise ValueError('positive-parser-control')
    bad = [good.replace(b'Bool(true)', b'Bool(false)'),
           good.replace(b'right: false', b'right: true'),
           good.replace((TEST + ':').encode(), b'private.rs:'),
           good.replace((':' + str(sites[0]) + ':5:').encode(), b':1:5:'),
           good + good,
           good.replace(b'assertion `left == right` failed', b'unrelated panic')]
    if any(intended_failure(item, test_bytes) for item in bad):
        raise ValueError('negative-parser-control')
    return {'positive': 1, 'negative': len(bad), 'synthetic_metadata_only': True}


def main():
    os.umask(0o077)
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source', required=True)
    parser.add_argument('--mode', choices=['identity', 'chain'], required=True)
    parser.add_argument('--output', required=True)
    args = parser.parse_args()
    output = Path(args.output).resolve()
    root = Path.cwd().resolve()
    if root in output.parents or output == root:
        raise ValueError('output-must-be-outside-checkout')
    output.parent.mkdir(parents=True, exist_ok=True)
    if output.exists():
        raise ValueError('fresh-output-required')
    report = {'complete': False, 'metadata_only': args.mode == 'identity',
              'source': args.source, 'phases': [], 'mutant': 'omit-explicit-ready-turn-only',
              'expected_test': NAME, 'cohort': 'default-test-policy-overrides',
              'automatic_retries': 0}
    before = None
    original = None
    mode = None
    path = root / SOURCE
    def save():
        output.write_text(json.dumps(report, indent=2) + '\n')
    try:
        if not re.fullmatch('[0-9a-f]{40}', args.source):
            raise ValueError('immutable-source-required')
        head = git('rev-parse', 'HEAD')
        if os.environ.get('GITHUB_SHA') != head or os.environ.get('GITHUB_REPOSITORY') != 'dyKiU/mdk':
            raise ValueError('workflow-head-identity')
        subprocess.run(['git', 'merge-base', '--is-ancestor', args.source, head], check=True)
        changed = set(git('diff', '--name-only', args.source, head).splitlines())
        if not changed <= TOOLS:
            raise ValueError('tool-child-diff-allowlist')
        physical(path)
        if not stat.S_ISREG(path.lstat().st_mode):
            raise ValueError('regular-source-required')
        original = path.read_bytes()
        mode = stat.S_IMODE(path.stat().st_mode)
        if mode != 0o644:
            raise ValueError('tracked-product-mode')
        source_original = subprocess.check_output(['git', 'show', args.source + ':' + SOURCE])
        if original != source_original or original.count(HOOK.encode()) != 1:
            raise ValueError('exact-product-hook-required')
        test_bytes = subprocess.check_output(['git', 'show', args.source + ':' + TEST])
        if (root / TEST).read_bytes() != test_bytes:
            raise ValueError('unchanged-original-test-required')
        report['oracle_parser_controls'] = oracle_controls(test_bytes)
        before = frozen_inputs()
        original_modes = modes_for(before)
        for tracked in before:
            for parent in (root / tracked).parents:
                if parent.is_symlink():
                    raise ValueError('tracked-parent-symlink')
                if parent == root:
                    break
        if git('ls-files', '--others', '--exclude-standard'):
            raise ValueError('untracked-source-admission')
        index = git('ls-files', '--stage')
        if not closure(before, head, index, original_modes):
            raise ValueError('pristine-admission')
        forbidden = ['RUSTFLAGS', 'CARGO_ENCODED_RUSTFLAGS', 'RUSTDOCFLAGS',
                     'CARGO_ENCODED_RUSTDOCFLAGS', 'RUSTC_WRAPPER', 'RUSTC_WORKSPACE_WRAPPER',
                     'RUSTC_BOOTSTRAP', 'RUST_MIN_STACK']
        if any(os.environ.get(name) for name in forbidden):
            raise ValueError('unexpected-compiler-environment')
        environment = {'CARGO_INCREMENTAL': '1', 'CARGO_BUILD_JOBS': '2',
                       'CARGO_PROFILE_DEV_DEBUG': '0', 'CARGO_PROFILE_TEST_DEBUG': '0',
                       'CARGO_TERM_COLOR': 'never'}
        if any(os.environ.get(key) != value for key, value in environment.items()):
            raise ValueError('fixed-compiler-environment')
        rustc = git_version(['rustc', '-Vv'])
        channel = re.fullmatch(r'[\s\S]*?^channel = "([0-9.]+)"[\s\S]*',
                              (root / 'rust-toolchain.toml').read_text(), re.M)
        if channel is None or re.search(r'^release: ' + re.escape(channel[1]) + '$', rustc, re.M) is None:
            raise ValueError('exact-pinned-rustc-release')
        report.update(tooling=head, source_tree=git('rev-parse', args.source + '^{tree}'),
                      original_sha256=sha(original), original_mode=mode,
                      test_sha256=sha(test_bytes), lock_sha256=sha((root / 'Cargo.lock').read_bytes()),
                      compiler_environment=environment, rustc_version=rustc,
                      cargo_version=git_version(['cargo', '-V']))
        save()
        if args.mode == 'chain':
            flags = ['-p', 'wn-cli', '--test', 'cli', '--features', 'test-policy-overrides',
                     '--locked', '--profile', 'ci']
            selection = 'package(wn-cli) & binary(=cli) & test(=' + NAME + ')'
            for phase in ['baseline', 'mutant', 'restored']:
                physical(path)
                expected = original.replace(HOOK.encode(), b'') if phase == 'mutant' else original
                if path.read_bytes() != expected:
                    path.write_bytes(expected)
                    path.chmod(mode)
                row = {'phase': phase, 'source_sha256': sha(expected), 'qualified': False}
                report['phases'].append(row)
                save()
                code, raw, elapsed, stderr = capture(['cargo', 'nextest', 'list', *flags,
                    '--message-format', 'json', '-E', selection], 1200, separate=True)
                row['inventory'] = {'exit_code': code, 'elapsed_seconds': elapsed,
                                    'stdout_sha256': sha(raw), 'stderr_sha256': sha(stderr),
                                    'compiler_codes': sorted({item.decode('ascii') for item in
                                        re.findall(rb'error\[(E[0-9]{4})\]', stderr)})}
                row['inventory']['compiler_diagnostics'] = compiler_diagnostics(stderr)
                save()
                if code != 0:
                    raise ValueError('inventory-compile-failed')
                inventory = json.loads(raw)
                selected = [name for suite in inventory['rust-suites'].values()
                            for name, case in suite['testcases'].items()
                            if case['filter-match']['status'] == 'matches' and not case['ignored']]
                if selected != [NAME]:
                    raise ValueError('inventory-not-exactly-one-nonignored')
                expected_inputs = dict(before)
                expected_inputs[SOURCE] = dict(before[SOURCE], sha256=sha(expected))
                if (frozen_inputs() != expected_inputs or git('ls-files', '--stage') != index
                        or modes_for(before) != original_modes):
                    raise ValueError('phase-input-closure')
                code, raw, elapsed, _ = capture(['cargo', 'nextest', 'run', *flags,
                    '--retries', '0', '--test-threads', '1', '--status-level', 'pass',
                    '--final-status-level', 'none', '--no-fail-fast', '--success-output', 'immediate',
                    '-E', selection], 1200)
                row['body'] = {'exit_code': code, 'elapsed_seconds': elapsed,
                               'raw_sha256': sha(raw), 'raw_bytes': len(raw)}
                row['body']['compiler_diagnostics'] = compiler_diagnostics(raw)
                save()
                row['body'].update(parse_core('avatar', raw))
                save()
                row['body']['observation'] = parse_marker('avatar', raw)
                body = row['body']
                counts = body['counts']
                clean = not body['compiler_codes'] and body['compiler_header_count'] == 0
                if phase == 'mutant':
                    row['intended_original_assertion'] = intended_failure(raw, test_bytes)
                    row['qualified'] = (code == 100 and counts['failed'] == 1
                                        and counts['passed'] == 0 and clean
                                        and row['intended_original_assertion']
                                        and body['observation']['sender_clear_present'] is False
                                        and body['observation']['receiver_present'] is True)
                else:
                    row['qualified'] = (code == 0 and counts['passed'] == 1
                                        and counts['failed'] == 0 and clean
                                        and not body['expected_source_panic_sites']
                                        and body['observation']['sender_clear_present'] is False
                                        and body['observation']['receiver_present'] is False)
                row['inputs_exact'] = (frozen_inputs() == expected_inputs
                                       and modes_for(before) == original_modes
                                       and git('ls-files', '--stage') == index
                                       and git('rev-parse', 'HEAD') == head)
                save()
                if not row['qualified'] or not row['inputs_exact']:
                    raise ValueError('runtime-phase-not-qualified')
        report['complete'] = True
    except Exception as error:
        report['exception_class'] = type(error).__name__
        report['failure_category'] = failure_category(error)
    finally:
        try:
            if original is not None:
                physical(path)
                if not path.is_file() or path.is_symlink():
                    raise ValueError('restore-physical-source')
                if path.read_bytes() != original:
                    path.write_bytes(original)
                if stat.S_IMODE(path.stat().st_mode) != mode:
                    path.chmod(mode)
                report['restored_source_exact'] = (path.read_bytes() == original
                                                    and stat.S_IMODE(path.stat().st_mode) == mode)
            report['all_tracked_inputs_exact'] = (before is not None
                                                and closure(before, head, index, original_modes))
            if not report.get('restored_source_exact') or not report['all_tracked_inputs_exact']:
                report['complete'] = False
        except Exception as error:
            report['complete'] = False
            report['closure_exception_class'] = type(error).__name__
            report['closure_failure_category'] = failure_category(error)
        save()
    return 0 if report['complete'] else 1


def git_version(command):
    return subprocess.check_output(command, text=True).strip()


if __name__ == '__main__':
    raise SystemExit(main())
