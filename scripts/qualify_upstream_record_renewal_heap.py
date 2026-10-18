#!/usr/bin/env python3
"""Exact renewal journey and incoming runtime-policy controls, component only."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import qualify_upstream_storage_app_handles as common
from upstream_extraction_cohort import frozen_inputs
from upstream_completion_ci import feature_metadata
old = common.old
ensure = old.ensure
# Root pins the actual remote-formatted pure heap-pin source before execution.
BASE = '9591d2590c8f7866dbc3ef573e46494ec6e3775d'
RENEWAL_SHA256 = '656dad128570b07071ebfa4a3a906f0e23e570f274b1299f3a89d503b05e43ec'
APP_FIXTURE_SHA256 = '4df7d3b3a5ff83fa4df4c822665ad98e3abf61ff510e3010d053e6f481e0fb80'
PROPOSED_PURE_SOURCE = '9591d2590c8f7866dbc3ef573e46494ec6e3775d'
SELF = 'scripts/qualify_upstream_record_renewal_heap.py'
WORKFLOW = '.github/workflows/experimental-sync-ci.yml'
REF = 'refs/heads/ci/upstream-record-renewal-heap-pin-20261018'
BEGIN = '  # RECORD_RENEWAL_HEAP_JOBS_BEGIN\n'
END = '  # RECORD_RENEWAL_HEAP_JOBS_END\n\n'
OPTIONS = 'options: [record-renewal-preflight, record-renewal-green, '
OUT = Path('record-renewal-heap-evidence')
LEAF = 'crates/marmot-app/src/native_device_linking/automatic_record_renewal_acceptance.rs'
SHARED = 'crates/marmot-app/src/native_device_linking/tests.rs'
RENEWAL = ('native_device_linking::tests::automatic_record_renewal_acceptance::'
           'automatic_records_remain_visible_after_acknowledged_ab_batch_and_broad_abc_renewal')
POLICY = 'runtime::tests::async_suites_choose_their_tokio_flavor'
CASES = (RENEWAL, POLICY)
FEATURES = ['marmot-app/otlp-export', 'marmot-app/product-analytics-export',
            'marmot-app/test-policy-overrides', 'marmot-app/experimental-device-sync',
            'cgka-engine/test-policy-overrides', 'cgka-engine/test-crash-hooks']
APP_FEATURES = ['default', 'experimental-device-sync', 'otlp-export', 'product-analytics-export', 'test-policy-overrides']


def source_guard():
    ensure(isinstance(BASE, str) and re.fullmatch('[0-9a-f]{40}', BASE)
           and isinstance(RENEWAL_SHA256, str) and re.fullmatch('[0-9a-f]{64}', RENEWAL_SHA256), 'reviewed-formatted-source-unpinned')
    head = old.git('rev-parse', 'HEAD')
    ensure(os.environ.get('GITHUB_ACTIONS') == 'true' and os.environ.get('GITHUB_REPOSITORY') == 'dyKiU/mdk'
           and os.environ.get('GITHUB_EVENT_NAME') == 'workflow_dispatch' and os.environ.get('GITHUB_SHA') == head
           and os.environ.get('GITHUB_REF') == REF
           and os.environ.get('GITHUB_WORKFLOW_REF') == 'dyKiU/mdk/' + WORKFLOW + '@' + REF
           and os.environ.get('RECORD_RENEWAL_HEAP_BASELINE') == BASE, 'exact-owned-manual-source')
    ensure(os.environ.get('CARGO_INCREMENTAL') == '1' and os.environ.get('CARGO_BUILD_JOBS') == '2'
           and os.environ.get('RUST_MIN_STACK') == '4194304'
           and all(os.environ.get(k) == '0' for k in ['CARGO_PROFILE_DEV_DEBUG', 'CARGO_PROFILE_TEST_DEBUG'])
           and all(not os.environ.get(k) for k in ['RUSTFLAGS', 'CARGO_ENCODED_RUSTFLAGS', 'RUSTC_BOOTSTRAP',
               'CARGO_PROFILE_DEV_OPT_LEVEL', 'CARGO_PROFILE_TEST_OPT_LEVEL']), 'fixed-four-MiB-cohort-no-overrides')
    subprocess.run(['git', 'merge-base', '--is-ancestor', BASE, head], check=True)
    ensure(subprocess.run(['git', 'diff', '--quiet', 'HEAD']).returncode == 0, 'tracked-pristine')
    baseline = {}
    for entry in subprocess.check_output(['git', 'ls-tree', '-r', '-z', BASE]).split(b'\0'):
        if entry:
            metadata, path = entry.split(b'\t', 1)
            mode, kind, blob = metadata.decode().split()
            ensure(kind == 'blob' and mode in {'100644', '100755', '120000'}, 'ordinary-baseline-modes')
            baseline[os.fsdecode(path)] = (mode, blob)
    current = frozen_inputs()
    ensure(SELF not in baseline and set(current) == set(baseline) | {SELF}, 'whole-source-inventory')
    for path, record in current.items():
        mode, blob = baseline.get(path, ('100644', None))
        ensure(record['mode'] == mode and (mode == '120000' or record['actual_executable'] == (mode == '100755')), 'whole-source-modes')
        if path == SELF:
            continue
        data = os.fsencode(os.readlink(path)) if mode == '120000' else Path(path).read_bytes()
        if path == WORKFLOW:
            text = data.decode()
            ensure(text.count(BEGIN) == text.count(END) == text.count(OPTIONS) == 1, 'exact-one-owned-overlay')
            before, rest = text.split(BEGIN)
            _, after = rest.split(END)
            data = (before + after).replace(OPTIONS, 'options: [', 1).encode()
        ensure(hashlib.sha1(b'blob ' + str(len(data)).encode() + b'\0' + data).hexdigest() == blob, 'exact-baseline:' + path)
    for path in [SELF, WORKFLOW]:
        ensure(Path(path).read_bytes() == subprocess.check_output(['git', 'show', 'HEAD:' + path]), 'metadata-exact-signed-HEAD')
    others = set(subprocess.check_output(['git', 'ls-files', '--others', '--exclude-standard'], text=True).splitlines())
    ensure(others <= {str(OUT / 'result.json')}, 'no-unreviewed-untracked-inputs')
    leaf = Path(LEAF).read_bytes()
    ensure(old.digest(leaf) == RENEWAL_SHA256, 'exact-reviewed-renewal-body')
    ensure(old.digest(Path('crates/marmot-app/src/tests.rs').read_bytes()) == APP_FIXTURE_SHA256,
           'exact-reviewed-App-fixtures')
    ensure(leaf.count(b'#[tokio::test(flavor = "multi_thread", worker_threads = 2)]') == 1
           and leaf.count(b'Box::pin(actual::run_native_public_three_device_enrollment(') == 1
           and leaf.count(b'actual::ApprovalScenario::AutomaticRecordGenerationRenewal,') == 1, 'exact-two-worker-real-scenario-call')
    ensure(b'assert_ne!(' in leaf and b'generation, self.initial_generation' in leaf
           and b'Self::wait_record(&runtimes[2]' in leaf
           and b'probe.committed.load(Ordering::Acquire) == 0' in leaf, 'original-AB-ACK-ABC-generation-and-C-delivery-oracles-frozen')
    shared = Path(SHARED).read_bytes()
    ensure(shared.count(b'if let Some(witness) = record_renewal {') == 1
           and shared.count(b'witness.after_abc(&apps, &runtimes).await;') == 1, 'original-renewal-full-journey-not-setup-only')
    return {'source': head, 'baseline': BASE, 'whole_source_and_modes_exact': True,
            'renewal_sha256': RENEWAL_SHA256, 'two_workers': True, 'stack_bytes': 4194304,
            'historical_SIGABRT_retained': {'source': '1d3ea08a3cbfb3d852891f56bc26b8bff237f5f3', 'run': 39115097731, 'job': 117642598564},
            'historical_runtime_evidence_reused_as_GREEN': False}


def parser_controls():
    result = common.parser_controls()
    for name in CASES:
        good = ('running 1 test\ntest ' + name + ' ... ok\n'
                'test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 10 filtered out; finished in 0.1s\n')
        ensure(common.parse_body(good, 0, name)['passed_gate'], 'one-required-body-positive')
        for raw, code in [(good, 101), (good + good, 0), (good.replace(name, name + '_foreign'), 0),
                          (good.replace('1 passed', '0 passed'), 0), (good.replace('0 ignored', '1 ignored'), 0),
                          (good + "thread 'other' panicked at crates/foreign.rs:1:1:\n", 0),
                          (good + 'error[E0000]: rejected\n', 0), ('', -6)]:
            ensure(not common.parse_body(raw, code, name)['passed_gate'], 'no-abort-or-unrelated-false-GREEN')
    return {'preserved': result, 'exact_two_case_positive': 2, 'exact_two_case_negative': 16, 'runtime_bodies': 0}


def compile_app(frozen, report, save):
    command = ['cargo', 'test', '--locked', '-p', 'marmot-app', '--lib', '--no-run', '--message-format=json', '--features', ','.join(FEATURES)]
    code, raw, seconds = old.capture(command, 1800, limit=8 * 1024 * 1024)
    events = [json.loads(line) for line in raw.splitlines() if line.startswith('{')]
    errors = [v for v in events if v.get('reason') == 'compiler-message' and v.get('message', {}).get('level') == 'error']
    artifacts = [v for v in events if v.get('reason') == 'compiler-artifact']
    selected = [v for v in artifacts if v['target']['name'] == 'marmot_app' and v['target']['kind'] == ['lib'] and v['profile']['test'] and v.get('executable')]
    report['compilation'] = {'command': command, 'exit_code': code, 'wall_seconds': seconds, 'compiler_error_count': len(errors),
        'safe_errors': [old.safe_compiler_diagnostic(v, frozen) for v in errors[:16]], 'errors_truncated': len(errors) > 16,
        'features_requested': FEATURES, 'selected_binary_count': len(selected)}
    save()
    ensure(code == 0 and not errors and len(selected) == 1 and sorted(selected[0]['features']) == APP_FEATURES, 'exact-one-experimental-App-binary')
    binary = Path(selected[0]['executable'])
    ensure(binary.resolve().is_relative_to(Path.cwd().resolve()), 'owned-binary')
    metadata = feature_metadata(binary)
    report['compilation']['compiled_fingerprints'] = metadata
    report['compilation']['artifact_manifest_sha256'] = old.digest(json.dumps(artifacts, sort_keys=True).encode())
    save()
    ensure(metadata.get('verified') is True and len(metadata.get('nodes', {})) == 6, 'actual-six-experimental-fingerprints')
    ensure(frozen_inputs() == frozen, 'compile-source-and-mode-pristine')
    return binary


def run(report, save, frozen):
    binary = compile_app(frozen, report, save)
    binary_sha = old.digest(binary.read_bytes())
    report['binary_sha256'] = binary_sha
    report['inventory'] = {}
    for name in CASES:
        entry = {}
        report['inventory'][name] = entry
        for ignored in [False, True]:
            code, raw, _ = old.capture([str(binary), '--exact', name] + (['--ignored'] if ignored else []) + ['--list', '--format', 'terse'], 60, limit=1024 * 1024)
            row = common.parse_inventory(raw, name, ignored)
            row['exit_code'] = code
            entry['ignored' if ignored else 'normal'] = row
            save()
            ensure(code == 0 and row['passed'], 'exact-one-nonignored-case-inventory')
    for name in CASES:
        row = {'passed': None, 'failed': None, 'ignored': None, 'executed_nonignored': None, 'passed_gate': False}
        report['cases'][name] = row
        save()
        try:
            ensure(frozen_inputs() == frozen and old.digest(binary.read_bytes()) == binary_sha, 'before-body-inputs-pristine')
            code, raw, seconds = old.capture([str(binary), '--exact', name, '--nocapture', '--test-threads=1'], 300, limit=8 * 1024 * 1024)
            row.update(common.parse_body(raw, code, name))
            row.update(wall_seconds=seconds, binary_sha256=binary_sha)
        except Exception as error:
            row['error_kind'] = type(error).__name__
        finally:
            save()
    for field in ['passed', 'failed', 'ignored', 'executed_nonignored']:
        values = [row.get(field) for row in report['cases'].values()]
        report['actual_' + field] = sum(values) if len(values) == len(CASES) and all(type(v) is int for v in values) else None
    report['actual_counts_complete'] = len(report['cases']) == 2 and all(row.get('actual_counts_complete') is True for row in report['cases'].values())
    report['component_controls_passed'] = report['actual_counts_complete'] and all(row.get('passed_gate') is True for row in report['cases'].values())
    ensure(frozen_inputs() == frozen and old.digest(binary.read_bytes()) == binary_sha, 'final-source-modes-and-binary-pristine')
    report['inputs_pristine'] = True
    save()
    ensure(report['component_controls_passed'], 'renewal-and-policy-required-not-all-GREEN')


def main():
    os.umask(0o077)
    args = argparse.ArgumentParser()
    args.add_argument('--mode', choices=['preflight', 'green'], required=True)
    mode = args.parse_args().mode
    OUT.mkdir(exist_ok=True)
    report = {'qualification': False, 'native_qualified': False, 'promotion_eligible': False,
              'component_controls_passed': False, 'cases': {}, 'actual_passed': None, 'actual_failed': None,
              'actual_ignored': None, 'actual_executed_nonignored': None, 'inputs_pristine': False,
              'mutation_necessity_claim': False, 'stack_bytes': 4194304}
    frozen = None
    def save():
        (OUT / 'result.json').write_text(json.dumps(report, sort_keys=True, indent=2) + '\n')
    try:
        report['source_guard'] = source_guard()
        report['parser_controls'] = parser_controls()
        frozen = frozen_inputs()
        save()
        if mode == 'preflight':
            report['preflight_passed'] = True
        else:
            run(report, save, frozen)
    except Exception as error:
        report['error_kind'] = type(error).__name__
        raise
    finally:
        if frozen is not None:
            report['inputs_pristine'] = frozen_inputs() == frozen
        save()
        ensure(frozen is None or report['inputs_pristine'], 'finally-source-modes-changed')


if __name__ == '__main__':
    main()
