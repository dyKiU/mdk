#!/usr/bin/env python3
"""One frozen owner-contract ordinary case; not strict-integration qualification."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import selectors
import shutil
import signal
import stat
import subprocess
import time

BASE = '1611fa4ba239933d41875017e12464fef2f4e0d0'
SELF = 'scripts/qualify_owner_ordinary_1611.py'
WORKFLOW = '.github/workflows/experimental-sync-ci.yml'
REF = 'refs/heads/ci/upstream-owner-ordinary-1611-20261018'
FIXTURE = 'crates/marmot-app/src/native_device_linking/tests/automatic_pairing_acceptance.rs'
SUFFIX = 'third_and_later_device_enrollment_need_no_extra_qr_or_manual_artifacts'
NAME = 'native_device_linking::automatic_pairing_acceptance::' + SUFFIX
OLD = '#[tokio::test]\nasync fn ' + SUFFIX + '() {'
NEW = '#[tokio::test(flavor = "multi_thread", worker_threads = 2)]\nasync fn ' + SUFFIX + '() {'
BEGIN = '  # OWNER_ORDINARY_1611_JOBS_BEGIN\n'
END = '  # OWNER_ORDINARY_1611_JOBS_END\n'
OPTIONS = 'options: [owner-ordinary-preflight, owner-ordinary-baseline, '
FEATURES = 'marmot-app/experimental-device-sync,marmot-app/test-policy-overrides,marmot-app/otlp-export,marmot-app/product-analytics-export'
ROOT_FEATURES = sorted(['default', 'experimental-device-sync', 'test-policy-overrides', 'otlp-export', 'product-analytics-export'])
OUT = Path('owner-ordinary-1611-evidence')


class GateFailure(ValueError):
    pass


def ensure(value, label):
    if not value:
        raise GateFailure(label)


def digest(data):
    return hashlib.sha256(data).hexdigest()


def snapshot():
    result = {}
    for entry in subprocess.check_output(['git', 'ls-files', '--stage', '-z']).split(b'\0'):
        if not entry: continue
        metadata, name = entry.split(b'\t', 1)
        mode, _, stage = metadata.decode().split(); name = os.fsdecode(name)
        ensure(stage == '0' and mode in {'100644', '100755', '120000'}, 'ordinary-tracked-modes')
        p = Path(name); kind = p.lstat().st_mode
        ensure((stat.S_ISREG(kind) or stat.S_ISLNK(kind)) and p.is_symlink() == (mode == '120000'), 'ordinary-files-or-links')
        data = os.fsencode(os.readlink(name)) if p.is_symlink() else p.read_bytes()
        result[name] = {'mode': mode, 'actual_executable': bool(kind & 0o111), 'sha256': digest(data)}
    return result


def source_guard():
    source = subprocess.check_output(['git', 'rev-parse', 'HEAD'], text=True).strip()
    ensure(os.environ.get('GITHUB_ACTIONS') == 'true' and os.environ.get('GITHUB_REPOSITORY') == 'dyKiU/mdk'
           and os.environ.get('GITHUB_EVENT_NAME') == 'workflow_dispatch' and os.environ.get('GITHUB_SHA') == source
           and os.environ.get('GITHUB_REF') == REF
           and os.environ.get('GITHUB_WORKFLOW_REF') == 'dyKiU/mdk/' + WORKFLOW + '@' + REF
           and os.environ.get('OWNER_ORDINARY_BASELINE') == BASE, 'exact-owned-remote-source')
    ensure(os.environ.get('CARGO_INCREMENTAL') == '1' and os.environ.get('CARGO_BUILD_JOBS') == '2'
           and os.environ.get('RUST_MIN_STACK') == '4194304'
           and all(os.environ.get(k) == '0' for k in ['CARGO_PROFILE_DEV_DEBUG', 'CARGO_PROFILE_TEST_DEBUG'])
           and all(not os.environ.get(k) for k in ['RUSTFLAGS', 'CARGO_ENCODED_RUSTFLAGS', 'RUSTC_BOOTSTRAP',
               'CARGO_PROFILE_DEV_OPT_LEVEL', 'CARGO_PROFILE_TEST_OPT_LEVEL']), 'fixed-feature-compiler-launch')
    subprocess.run(['git', 'merge-base', '--is-ancestor', BASE, source], check=True)
    ensure(subprocess.run(['git', 'diff', '--quiet', 'HEAD']).returncode == 0, 'initial-tracked-inputs-pristine')
    baseline = {}
    for entry in subprocess.check_output(['git', 'ls-tree', '-r', '-z', BASE]).split(b'\0'):
        if entry:
            metadata, name = entry.split(b'\t', 1); mode, kind, blob = metadata.decode().split()
            ensure(kind == 'blob' and mode in {'100644', '100755', '120000'}, 'ordinary-baseline-tree')
            baseline[os.fsdecode(name)] = (mode, blob)
    frozen = snapshot()
    ensure(set(frozen) == set(baseline) | {SELF} and SELF not in baseline, 'whole-owner-input-inventory')
    for name, actual in frozen.items():
        mode, blob = baseline.get(name, ('100644', None))
        ensure(actual['mode'] == mode and (mode == '120000' or actual['actual_executable'] == (mode == '100755')), 'whole-owner-mode')
        data = os.fsencode(os.readlink(name)) if mode == '120000' else Path(name).read_bytes()
        if name == FIXTURE:
            text = data.decode(); ensure(text.count(NEW) == 1 and OLD not in text, 'one-reviewed-test-flavor-delta')
            data = text.replace(NEW, OLD, 1).encode()
        if name == WORKFLOW:
            text = data.decode(); ensure(text.count(BEGIN) == text.count(END) == text.count(OPTIONS) == 1, 'one-owned-workflow-overlay')
            before, rest = text.split(BEGIN); _, after = rest.split(END)
            data = (before + after).replace(OPTIONS, 'options: [', 1).encode()
        if blob is not None:
            ensure(hashlib.sha1(b'blob ' + str(len(data)).encode() + b'\0' + data).hexdigest() == blob, 'whole-owner-content:' + name)
    ensure(not subprocess.check_output(['git', 'ls-files', '--others', '--exclude-standard'], text=True).strip(), 'no-untracked-source-overlay')
    return {'source': source, 'baseline': BASE, 'all_owner_contents_and_modes_reconstructed': True,
            'only_Rust_delta': 'selected ordinary wrapper Tokio multi_thread worker_threads=2',
            'owner_EnrollmentComplete_seconds': 90, 'owner_comparison_seconds': 15,
            'all_bodies_assertions_deadlines_lock_and_SDK_inputs_unchanged': True,
            'strict_integration_15s_oracle_adopted': False}


def capture(command, timeout, limit):
    started = time.monotonic(); proc = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, start_new_session=True)
    chunks = []; size = 0
    try:
        with selectors.DefaultSelector() as selected:
            selected.register(proc.stdout, selectors.EVENT_READ)
            while selected.get_map():
                ensure(time.monotonic() - started < timeout, 'bounded-command-timeout')
                for key, _ in selected.select(0.2):
                    block = os.read(key.fd, 65536)
                    if not block: selected.unregister(key.fileobj); continue
                    size += len(block); ensure(size <= limit, 'bounded-command-output-limit'); chunks.append(block)
        return proc.wait(timeout=10), b''.join(chunks).decode(errors='replace'), time.monotonic() - started
    finally:
        if proc.poll() is None: os.killpg(proc.pid, signal.SIGKILL); proc.wait(timeout=10)
        proc.stdout.close()


def compiler_error(item, frozen):
    message = item.get('message', {}); code = message.get('code')
    code = code.get('code') if isinstance(code, dict) else None
    result = {'code': code if isinstance(code, str) and re.fullmatch(r'E[0-9]{4}', code) else None,
              'primary_locations': [], 'unknown_locations': 0, 'truncated': False}
    for span in message.get('spans', []):
        if not isinstance(span, dict) or span.get('is_primary') is not True: continue
        f, line, column = span.get('file_name'), span.get('line_start'), span.get('column_start')
        if isinstance(f, str) and f in frozen and f.endswith('.rs') and type(line) is int and type(column) is int and 0 < line < 2**31 and 0 < column < 2**31:
            if len(result['primary_locations']) < 8: result['primary_locations'].append({'file': f, 'line': line, 'column': column})
            else: result['truncated'] = True
        else: result['unknown_locations'] += 1
    return result


def inventory(raw):
    lines = [v for v in raw.splitlines() if v]
    return lines in [[NAME + ': test'], [NAME + ': test', '1 test, 0 benchmarks']]


def body_receipt(raw, code, frozen):
    clean = re.sub(r'\x1b\[[0-9;]*m', '', raw)
    summaries = re.findall(r'^test result: (ok|FAILED)\. ([0-9]+) passed; ([0-9]+) failed; ([0-9]+) ignored; ([0-9]+) measured; ([0-9]+) filtered out;', clean, re.M)
    names = re.findall(r'^test ([A-Za-z_0-9:]+) \.\.\. ', clean, re.M)
    running = re.findall(r'^running ([0-9]+) test(?:s)?$', clean, re.M)
    panics = re.findall(r"^thread '[^'\n]+'(?: \([0-9]+\))? panicked at ([^\n]+):", clean, re.M)
    result = {'actual_counts_complete': False, 'passed': None, 'failed': None, 'ignored': None,
              'executed_nonignored': None, 'exit_code': code, 'exact_selected_name': names == [NAME],
              'compiler_error_count': len(re.findall(r'^error(?:\[E[0-9]+\])?:', clean, re.M)),
              'panic_count': clean.count('panicked at '), 'safe_panic_locations': [], 'unknown_panic_locations': 0,
              'original_fixture_positive_close_counts': None}
    for location in panics[:8]:
        match = re.fullmatch(r'([A-Za-z_0-9/.-]+\.rs):([0-9]+):([0-9]+)', location)
        if match and match[1] in frozen:
            result['safe_panic_locations'].append({'file': match[1], 'line': int(match[2]), 'column': int(match[3])})
        else: result['unknown_panic_locations'] += 1
    result['panic_locations_truncated'] = len(panics) > 8
    if len(summaries) == 1:
        status, p, f, i, m, _ = summaries[0]; p, f, i, m = map(int, [p, f, i, m])
        complete = names == [NAME] and running == ['1'] and p + f == 1 and i == m == 0 and status == ('FAILED' if f else 'ok')
        result.update(actual_counts_complete=complete, passed=p, failed=f, ignored=i,
                      executed_nonignored=p + f if complete else None)
    allowed = {'initial-two-comparison', 'initial-two-completion', 'initial-two-completed',
               'third-device-completion', 'third-device-completed', 'fourth-device-completion', 'fourth-device-completed'}
    # Only closed known stage atoms survive; storage/account diagnostic lines do not.
    result['original_phase_markers'] = [v for v in re.findall(r'automatic-enrollment-control stage=([a-z0-9-]+)', clean) if v in allowed][:32]
    return result


def parser_controls():
    ensure(inventory(NAME + ': test\n') and inventory(NAME + ': test\n1 test, 0 benchmarks\n'), 'both-exact-inventory-layouts')
    for value in ['', NAME + ': test\n' + NAME + ': test\n', 'foreign::test: test\n', NAME + ': test\n0 tests, 0 benchmarks\n']:
        ensure(not inventory(value), 'foreign-or-incomplete-inventory-rejected')
    raw = 'running 1 test\ntest ' + NAME + ' ... ok\ntest result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 3 filtered out; finished in 0.1s\n'
    ensure(body_receipt(raw, 0, {})['actual_counts_complete'], 'one-actual-positive-body')
    for value in [raw.replace(NAME, 'foreign::test'), raw.replace('1 passed', '0 passed'), raw.replace('0 ignored', '1 ignored'), raw + raw, raw.replace('running 1 test', 'running 0 tests')]:
        ensure(not body_receipt(value, 0, {})['actual_counts_complete'], 'no-zero-foreign-or-ignored-pass')
    error = compiler_error({'message': {'code': {'code': 'E0277'}, 'message': 'PRIVATE_ACCOUNT', 'spans': [
        {'is_primary': True, 'file_name': FIXTURE, 'line_start': 42, 'column_start': 5, 'text': ['PRIVATE_ACCOUNT']},
        {'is_primary': True, 'file_name': '/private/ACCOUNT.rs', 'line_start': 1, 'column_start': 1}]}}, {FIXTURE: {}})
    ensure(error['code'] == 'E0277' and len(error['primary_locations']) == 1 and error['unknown_locations'] == 1
           and 'PRIVATE_ACCOUNT' not in json.dumps(error) and '/private/' not in json.dumps(error), 'closed-private-compiler-metadata')
    return {'inventory_positive': 2, 'inventory_negative': 4, 'body_positive': 1, 'body_negative': 5,
            'safe_compiler_metadata_positive': 1, 'actual_runtime_bodies': 0}


def main(args):
    os.umask(0o077); OUT.mkdir(exist_ok=True)
    report = {'baseline': BASE, 'qualification_passed': False, 'native_acceptance_claim': False,
              'installed_binary_inclusion_known': False, 'strict_integration_15s_qualified': False,
              'owner_contract_component_passed': False, 'actual_counts_complete': False,
              'positive_native_closures': None, 'old_locked_negentropy': '0.5.0 diagnostic baseline only'}
    frozen = None
    def save(): (OUT / 'result.json').write_text(json.dumps(report, indent=2) + '\n')
    try:
        report['source_guard'] = source_guard(); report['parser_controls'] = parser_controls(); save()
        if args.preflight: report['source_parser_preflight_passed'] = True; save(); return
        frozen = snapshot(); report['input_manifest_sha256'] = digest(json.dumps(frozen, sort_keys=True).encode())
        report['toolchain'] = {v: subprocess.check_output([v, '--version'], text=True).strip() for v in ['cargo', 'rustc']}
        report['remote_capacity'] = {'minimum_free_bytes': 8*1024**3, 'free_bytes': shutil.disk_usage('.').free,
                                     'cleanup_performed': False}
        save(); ensure(report['remote_capacity']['free_bytes'] >= report['remote_capacity']['minimum_free_bytes'], 'remote-build-capacity')
        command = ['cargo', 'test', '--locked', '-p', 'marmot-app', '--lib', '--no-run', '--message-format=json', '--features', FEATURES]
        report['active_phase'] = 'compilation'; save()
        code, raw, seconds = capture(command, 1800, 16*1024*1024); artifacts = []; errors = []
        for line in raw.splitlines():
            if not line.startswith('{'): continue
            item = json.loads(line)
            if item.get('reason') == 'compiler-message' and item.get('message', {}).get('level') == 'error':
                errors.append(compiler_error(item, frozen))
            if item.get('reason') == 'compiler-artifact': artifacts.append(item)
        selected = [a for a in artifacts if a['target']['name'] == 'marmot_app' and a['target']['kind'] == ['lib'] and a['profile']['test'] and a.get('executable')]
        report['compilation'] = {'command': command, 'seconds': seconds, 'exit_code': code, 'compiler_error_count': len(errors),
            'safe_errors': errors[:32], 'errors_truncated': len(errors) > 32, 'selected_binary_count': len(selected)}; save()
        ensure(code == 0 and not errors and len(selected) == 1, 'one-actual-old-App-binary')
        artifact = selected[0]; ensure(sorted(artifact['features']) == ROOT_FEATURES, 'exact-compiled-old-App-features')
        binary = Path(artifact['executable']); binary_hash = digest(binary.read_bytes())
        report['compilation'].update(features=sorted(artifact['features']), binary_sha256=binary_hash,
            compiled_feature_manifest_sha256=digest(json.dumps([{'target': a['target']['name'], 'features': sorted(a['features']), 'profile': a['profile']} for a in artifacts], sort_keys=True).encode()))
        ensure(snapshot() == frozen, 'whole-inputs-pristine-after-compile')
        code, raw, _ = capture([str(binary), '--exact', NAME, '--list', '--format', 'terse'], 60, 1024*1024)
        ensure(code == 0 and inventory(raw), 'exact-one-nonignored-inventory')
        code, raw, _ = capture([str(binary), '--exact', NAME, '--ignored', '--list', '--format', 'terse'], 60, 1024*1024)
        ensure(code == 0 and raw.strip() in {'', '0 tests, 0 benchmarks'}, 'selected-body-not-ignored')
        report['inventory'] = {'actual_selected_name': NAME, 'selected_nonignored': 1, 'selected_ignored': 0}; save()
        ensure(snapshot() == frozen and digest(binary.read_bytes()) == binary_hash, 'before-body-source-binary-pristine')
        report['active_phase'] = 'one-runtime-body'; save()
        code, raw, seconds = capture([str(binary), '--exact', NAME, '--nocapture', '--test-threads=1'], 900, 8*1024*1024)
        row = body_receipt(raw, code, frozen); row.update(seconds=seconds, binary_sha256=binary_hash)
        report['body'] = row; report['actual_counts_complete'] = row['actual_counts_complete']; save()
        ensure(row['actual_counts_complete'] and row['compiler_error_count'] == 0 and code in {0, 101}, 'one-real-runtime-body-not-compile-or-watchdog')
        ensure(snapshot() == frozen and digest(binary.read_bytes()) == binary_hash, 'after-body-source-binary-pristine')
        report['owner_contract_component_passed'] = (row['passed'] == 1 and row['failed'] == 0 and code == 0 and row['panic_count'] == 0)
        report['active_phase'] = 'runtime-body-completed'; save()
        ensure(report['owner_contract_component_passed'], 'owner-ordinary-runtime-not-green')
    except Exception as error:
        report['exception_type'] = type(error).__name__
        if isinstance(error, GateFailure): report['failure_gate'] = str(error)
        raise
    finally:
        if frozen is not None: report['inputs_pristine'] = snapshot() == frozen
        save()
        if frozen is not None: ensure(report['inputs_pristine'], 'final-source-modes-pristine')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--preflight', action='store_true')
    main(parser.parse_args())
