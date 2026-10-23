"""One pristine trusted upstream offline body. Source S differs from tooling T."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess

from upstream_current_backend_probe import capture
from upstream_extraction_cohort import frozen_inputs, git
from upstream_offline_fingerprints import controls as fingerprint_controls, snapshot as fingerprint_snapshot
from upstream_replay_controls import compiler, counts, panic_facts, selected_case, summary_counts, unique

SOURCE = 'd274dd228a3ac8d624073d8f5835e06c7cd7b30d'
TREE = 'c9f89a790b4814dd91720b4e9d6703ad007558d9'
LOCK = '774e61b60710708cc4c2ea1328c60d1926a9bce62e159ebed42f776934dc1af6'
TOOLCHAIN = '8361e9b4c8a61651c37999ddd893cbb6d793b946da904174f7fd02474df1b935'
FIXTURE = 'crates/marmot-app/tests/relay_runtime/offline_replay.rs'
FIXTURE_SHA = 'ed803adbc13bb2a562ee10fd202d018871c1fca577e9e7104c9c662d4a158375'
TEST = 'offline_replay::offline_replay_crosses_queue'
SCOPE = 'upstream-offline-control'


def digest(data):
    return hashlib.sha256(data).hexdigest()


def snapshot():
    inputs = frozen_inputs()
    for name, row in inputs.items():
        for parent in Path(name).parents:
            if parent != Path('.') and parent.is_symlink():
                raise ValueError('tracked-parent-symlink')
        if row['mode'] in {'100644', '100755'} and row['actual_executable'] != (row['mode'] == '100755'):
            raise ValueError('tracked-mode')
    return {'head': git('rev-parse', 'HEAD'), 'tree': git('rev-parse', 'HEAD^{tree}'),
            'index': digest(subprocess.check_output(['git', 'ls-files', '--stage', '-z'])),
            'inputs': inputs, 'tracked_clean': not git('diff', 'HEAD', '--name-only')}


def controls():
    passed = ('PASS [ 1s] marmot-app::relay_runtime ' + TEST
              + '\nSummary [ 1s] 1 test run: 1 passed, 12 skipped\n').encode()
    failed = passed.replace(b'PASS [', b'FAIL [').replace(b'1 passed, 12 skipped', b'0 passed, 1 failed, 12 skipped')
    assert counts(passed, 'offline')['passed'] == 1
    assert counts(failed, 'offline')['failed'] == 1
    negatives = 0
    for raw in [passed + passed, passed.replace(TEST.encode(), b'PRIVATE'),
                passed.replace(b'1 test run', b'0 test run'), passed.replace(b'1 passed', b'0 passed')]:
        try:
            counts(raw, 'offline')
        except ValueError:
            negatives += 1
        else:
            raise AssertionError('trusted-runtime-negative-accepted')
    assert compiler(b'error[E0308]: PRIVATE\n', {})['codes'] == ['E0308']
    assert panic_facts(b"thread 'PRIVATE' panicked at PRIVATE.rs:1:2:\nPRIVATE\n", 'offline')['unknown_or_excess_headers'] == 1
    return {'positive': 4, 'negative': negatives, 'synthetic_metadata_only': True, 'product_bodies': 0}


def main():
    os.umask(0o077)
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--mode', choices=['preflight', 'run'], required=True)
    parser.add_argument('--output', required=True)
    args = parser.parse_args()
    tooling_root = Path(__file__).resolve().parents[1]
    os.chdir(tooling_root)
    output = Path(args.output).absolute()
    output.parent.mkdir(parents=True, exist_ok=True)
    report = {'scope': SCOPE, 'source': SOURCE, 'source_tree': TREE, 'tooling': git('rev-parse', 'HEAD'),
              'expected_test': TEST, 'features': ['test-policy-overrides'], 'profile': 'ci',
              'automatic_retries': 0, 'test_threads': 1, 'rust_min_stack': os.environ.get('RUST_MIN_STACK'),
              'qualification_passed': False, 'scoped_original_control_passed': False,
              'original_marker_expected': False, 'source_is_private_candidate': False}
    tooling_before, source_before, source_path = None, None, None
    stage, result = 'tooling-admission', 1
    def save():
        temp = output.with_suffix('.pending')
        temp.write_text(json.dumps(report, sort_keys=True, indent=2) + '\n')
        temp.replace(output)
    try:
        ref = os.environ.get('GITHUB_REF', '')
        if (os.environ.get('GITHUB_ACTIONS') != 'true' or os.environ.get('GITHUB_REPOSITORY') != 'dyKiU/mdk'
                or os.environ.get('GITHUB_EVENT_NAME') != 'workflow_dispatch'
                or not re.fullmatch('[0-9a-f]{40}', report['tooling'])
                or os.environ.get('GITHUB_SHA') != report['tooling']
                or os.environ.get('GITHUB_WORKFLOW_SHA') != report['tooling']
                or not ref.startswith('refs/heads/ci/upstream-develop-dy-')
                or os.environ.get('GITHUB_WORKFLOW_REF') != 'dyKiU/mdk/.github/workflows/upstream-backend-probes.yml@' + ref):
            raise ValueError('tooling-workflow-identity')
        event = json.loads(Path(os.environ['GITHUB_EVENT_PATH']).read_text(), object_pairs_hook=unique)
        if event['inputs'].get('scope') != SCOPE:
            raise ValueError('tooling-event-scope')
        tooling_before = snapshot()
        if not tooling_before['tracked_clean']:
            raise ValueError('tooling-dirty')
        if git('rev-parse', SOURCE + '^{commit}') != SOURCE or git('rev-parse', SOURCE + '^{tree}') != TREE:
            raise ValueError('source-object')
        for path, expected in [('Cargo.lock', LOCK), ('rust-toolchain.toml', TOOLCHAIN), (FIXTURE, FIXTURE_SHA)]:
            if digest(subprocess.check_output(['git', 'show', SOURCE + ':' + path])) != expected:
                raise ValueError('source-file-object')
        report['tooling_tree'] = tooling_before['tree']
        report['tooling_inputs_sha256'] = digest(json.dumps(tooling_before['inputs'], sort_keys=True).encode())
        report['parser_controls'] = controls()
        report['fingerprint_parser_controls'] = fingerprint_controls()
        if args.mode == 'preflight':
            result = 0
        else:
            stage = 'environment'
            denied = ['RUST_MIN_STACK', 'RUSTFLAGS', 'CARGO_ENCODED_RUSTFLAGS', 'RUSTDOCFLAGS',
                      'CARGO_ENCODED_RUSTDOCFLAGS', 'RUSTC', 'RUSTC_WRAPPER', 'RUSTC_WORKSPACE_WRAPPER', 'RUSTC_BOOTSTRAP']
            if (any(os.environ.get(key) for key in denied)
                    or any(value for key, value in os.environ.items() if key.startswith('CARGO_TARGET_') and key.endswith('_RUSTFLAGS'))
                    or os.environ.get('CARGO_BUILD_JOBS') != '2' or os.environ.get('CARGO_INCREMENTAL') != '1'
                    or Path(os.environ.get('CARGO_TARGET_DIR', '')).resolve() != tooling_root / 'target'):
                raise ValueError('source-launch-environment')
            stage = 'source-admission'
            source_path = Path(os.environ['RUNNER_TEMP']) / 'trusted-upstream-offline-source'
            if source_path.is_symlink() or not source_path.is_dir():
                raise ValueError('source-layout')
            os.chdir(source_path)
            if Path(git('rev-parse', '--show-toplevel')).resolve() != source_path.resolve():
                raise ValueError('source-worktree-root')
            source_before = snapshot()
            if (source_before['head'] != SOURCE or source_before['tree'] != TREE or not source_before['tracked_clean']
                    or git('status', '--porcelain', '--untracked-files=all')):
                raise ValueError('source-pristine-identity')
            for path, expected in [('Cargo.lock', LOCK), ('rust-toolchain.toml', TOOLCHAIN), (FIXTURE, FIXTURE_SHA)]:
                if source_before['inputs'][path]['sha256'] != expected:
                    raise ValueError('source-pristine-inputs')
            report['source_inputs_sha256'] = digest(json.dumps(source_before['inputs'], sort_keys=True).encode())
            report['source_lock_sha256'] = LOCK
            report['source_fixture_sha256'] = FIXTURE_SHA
            report['source_toolchain_sha256'] = TOOLCHAIN
            code, raw, elapsed, _ = capture(['rustc', '--version'], 30)
            if code != 0 or re.fullmatch(rb'rustc 1\.97\.1 \([0-9a-f]+ [0-9-]+\)\s*', raw) is None:
                raise ValueError('source-rustc-release')
            report['rustc_release'] = '1.97.1'
            flags = ['-p', 'marmot-app', '--test', 'relay_runtime', '--features', 'test-policy-overrides', '--locked', '--profile', 'ci']
            selection = 'package(marmot-app) & binary(=relay_runtime) & test(=' + TEST + ')'
            stage = 'inventory-command'
            code, raw, elapsed, stderr = capture(['cargo', 'nextest', 'list'] + flags + ['--message-format', 'json', '-E', selection], 1800, separate=True)
            report['inventory'] = {'exit_code': code, 'elapsed_seconds': elapsed, 'stdout_bytes': len(raw),
                                   'stdout_sha256': digest(raw), 'stderr_bytes': len(stderr),
                                   'stderr_sha256': digest(stderr), 'compiler': compiler(stderr, source_before['inputs'])}
            save()
            if code != 0:
                raise ValueError('inventory-command')
            stage = 'inventory-shape'
            inventory = json.loads(raw, object_pairs_hook=unique)
            selected_case(inventory, TEST)
            report['compiled_fingerprints'] = fingerprint_snapshot(
                inventory, TEST, os.environ.get('CARGO_TARGET_DIR', 'target'))
            report['inventory'].update(selected_nonignored=1, selected_ignored=0)
            save()
            if snapshot() != source_before:
                raise ValueError('inventory-source-closure')
            stage = 'body-command'
            report['body_attempted'] = True
            save()
            code, raw, elapsed, _ = capture(['cargo', 'nextest', 'run'] + flags + ['--retries', '0', '--test-threads', '1',
                                          '--status-level', 'pass', '--final-status-level', 'none', '--no-fail-fast',
                                          '--success-output', 'immediate', '-E', selection], 1800)
            report['body'] = {'exit_code': code, 'elapsed_seconds': elapsed, 'raw_bytes': len(raw), 'raw_sha256': digest(raw),
                              'runtime_summary': summary_counts(raw), 'compiler': compiler(raw, source_before['inputs']),
                              'panic': panic_facts(raw, 'offline')}
            save()
            stage = 'runtime-shape'
            report['body']['counts'] = counts(raw, 'offline')
            save()
            # Pristine upstream has no later private diagnostic marker. The
            # original authenticated-text/60s/storage/cleanup assertions decide.
            report['scoped_original_control_passed'] = (code == 0 and report['body']['counts']['passed'] == 1
                and not report['body']['compiler']['codes'] and report['body']['compiler']['header_count'] == 0
                and report['body']['panic'] == {'sites': [], 'unknown_or_excess_headers': 0})
            result = 0 if report['scoped_original_control_passed'] else 1
            if result:
                report['failure_category'] = 'original-body-not-passed'
    except Exception:
        report['failure_category'] = stage
    finally:
        try:
            if source_before is not None:
                os.chdir(source_path)
                report['source_closure_exact'] = snapshot() == source_before and not git('status', '--porcelain', '--untracked-files=all')
            else:
                report['source_closure_exact'] = args.mode == 'preflight'
        except Exception:
            report['source_closure_exact'] = False
        os.chdir(tooling_root)
        try:
            report['tooling_closure_exact'] = tooling_before is not None and snapshot() == tooling_before
        except Exception:
            report['tooling_closure_exact'] = False
        if not report['source_closure_exact'] or not report['tooling_closure_exact']:
            report['scoped_original_control_passed'] = False
            result = 1
        report['preflight_passed'] = args.mode == 'preflight' and result == 0
        save()
    return result


if __name__ == '__main__':
    raise SystemExit(main())
