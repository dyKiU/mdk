"""Standalone compiler feasibility probe. Never execute the Swift capsule."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import selectors
import signal
import subprocess
import time

SOURCE_SHA = '8268dd25c4d1d830e15af13d6dcfee64ac581a4bf304d7ed0e4707b5725eaecb'
SOURCE = Path(__file__).with_name('CheckedCaptureOwner.swift')
DEVELOPER = Path('/Applications/Xcode_26.6.app/Contents/Developer')
CAP = 256 * 1024


def sha(data):
    return hashlib.sha256(data).hexdigest()


def xcode_identity(data):
    return re.fullmatch(rb'Xcode (26\.6(?:\.0)?)\nBuild version (17F113)\n?', data) is not None


DRIVER_STDERR = b'swift-driver version: 1.148.6 '
DIAGNOSTIC_FACTS = {
    'checked_owner_identifier': b'CheckedCaptureOwner',
    'mutex_identifier': b'Mutex',
    'main_actor_preview_bridge_identifier': b'MainActorPreviewBridge',
    'calayer_identifier': b'CALayer',
    'capture_session_identifier': b'AVCaptureSession',
    'preview_layer_identifier': b'AVCaptureVideoPreviewLayer',
    'protected_session_identifier': b'protectedSession',
    'main_actor_isolated': b'main actor-isolated',
    'nonisolated': b'nonisolated',
    'non_sendable': b'non-Sendable',
    'sendable': b'Sendable',
    'sending': b'sending',
    'data_race': b'data race',
    'actor_boundary': b'actor boundary',
    'cannot_be_sent': b'cannot be sent',
    'task_isolated': b'task-isolated',
}


def validate_identity_streams(label, code, stdout, stderr):
    if (label not in ('xcode-version', 'swift-version', 'simulator-sdk-version', 'simulator-sdk-path')
            or type(code) is not int or code != 0 or type(stdout) is not bytes or not stdout
            or type(stderr) is not bytes):
        raise ValueError('identity-command-failed')
    if stderr and (label != 'swift-version' or stderr != DRIVER_STDERR):
        raise ValueError('identity-command-failed')
    return {'driver_version': '1.148.6' if stderr == DRIVER_STDERR else None}


def diagnostics(stdout, stderr):
    rows = []
    unknown = 0
    for stream, data in [('stdout', stdout), ('stderr', stderr)]:
        for line in data.splitlines():
            match = re.fullmatch(rb'(?:[^\r\n]*[/\\])?CheckedCaptureOwner\.swift:([1-9][0-9]*):([1-9][0-9]*): (error|warning|note): [^\r\n]*', line)
            if match:
                rows.append({'stream': stream, 'file': 'CheckedCaptureOwner.swift',
                             'line': int(match[1]), 'column': int(match[2]),
                             'severity': match[3].decode('ascii'), 'row_sha256': sha(line),
                             'fixed_message_facts': {name: token in line.split(b': ', 2)[-1]
                                                     for name, token in DIAGNOSTIC_FACTS.items()}})
            else:
                unknown += 1
    return {'diagnostic_rows': rows, 'diagnostic_count': len(rows), 'other_line_count': unknown,
            'stdout_bytes': len(stdout), 'stderr_bytes': len(stderr),
            'stdout_sha256': sha(stdout), 'stderr_sha256': sha(stderr)}


def bounded(command, env):
    process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                               env=env, start_new_session=True)
    buffers = {'stdout': bytearray(), 'stderr': bytearray()}
    selector = selectors.DefaultSelector()
    for name, pipe in [('stdout', process.stdout), ('stderr', process.stderr)]:
        os.set_blocking(pipe.fileno(), False)
        selector.register(pipe, selectors.EVENT_READ, name)
    deadline = time.monotonic() + 90
    try:
        while selector.get_map():
            if time.monotonic() >= deadline:
                raise ValueError('compiler-probe-timeout')
            for key, _ in selector.select(timeout=min(0.2, max(0, deadline-time.monotonic()))):
                chunk = os.read(key.fileobj.fileno(), 8192)
                if not chunk:
                    selector.unregister(key.fileobj)
                    continue
                if len(buffers[key.data]) + len(chunk) > CAP:
                    raise ValueError('compiler-probe-output-cap')
                buffers[key.data].extend(chunk)
        code = process.wait(timeout=max(0.1, deadline-time.monotonic()))
        return code, bytes(buffers['stdout']), bytes(buffers['stderr'])
    finally:
        if process.poll() is None:
            os.killpg(process.pid, signal.SIGKILL)
            process.wait(timeout=5)
        selector.close()
        process.stdout.close()
        process.stderr.close()


PHASES = ('typecheck', 'emit_sil')


def compiler_counts(phases):
    unknown = [name for name in PHASES if phases[name]['invoked'] is True
               and phases[name]['actual_invocation_count'] is None]
    known = sum(row['actual_invocation_count'] for row in phases.values()
                if type(row.get('actual_invocation_count')) is int)
    return {'known_completed_invocations': known, 'completed_invocations': None if unknown else known,
            'unknown_phases': unknown}


def final_pass(proof):
    phases = proof.get('compiler_phases')
    if type(phases) is not dict or set(phases) != set(PHASES):
        return False
    for name in PHASES:
        row = phases[name]
        if (type(row) is not dict or row.get('invoked') is not True
                or type(row.get('actual_invocation_count')) is not int or row['actual_invocation_count'] != 1):
            return False
        result = row.get('result')
        if (type(result) is not dict or type(result.get('exit_code')) is not int or result['exit_code'] != 0
                or any(type(result.get(key)) is not int or result[key] != 0
                       for key in ('stdout_bytes', 'stderr_bytes', 'diagnostic_count', 'other_line_count'))
                or result.get('diagnostic_rows') != []
                or result.get('stdout_sha256') != sha(b'') or result.get('stderr_sha256') != sha(b'')):
            return False
    return (proof.get('source_unchanged') is True and proof.get('tools_unchanged') is True
            and 'failure_kind' not in proof
            and compiler_counts(phases) == {'known_completed_invocations': 2,
                'completed_invocations': 2, 'unknown_phases': []})


def main(output):
    proof = {'schema': 1, 'diagnostic_only': True, 'qualification_credit': False,
             'behavioral_credit': False, 'product_tests_executed': 0, 'native_tests_executed': 0,
             'tools_sha': os.environ.get('GITHUB_SHA'), 'passed': False, 'compiler_invoked': False,
             'source_sha256': sha(SOURCE.read_bytes()), 'commands': [], 'typecheck': None, 'emit_sil': None,
             'preview_sendable_claim': False,
             'compiler_phases': {name: {'invoked': False, 'actual_invocation_count': 0, 'result': None}
                                 for name in PHASES}}
    def save():
        proof['compiler_counts'] = compiler_counts(proof['compiler_phases'])
        output.write_text(json.dumps(proof, indent=2)+'\n')
    try:
        if os.environ.get('GITHUB_ACTIONS') != 'true' or os.environ.get('RUNNER_OS') != 'macOS':
            raise ValueError('remote-macos-only')
        if output.exists() or proof['source_sha256'] != SOURCE_SHA or not DEVELOPER.is_dir():
            raise ValueError('exact-source-fresh-output-pinned-Xcode-required')
        head = subprocess.check_output(['/usr/bin/git', 'rev-parse', 'HEAD'], timeout=10).decode().strip()
        if head != proof['tools_sha'] or subprocess.check_output(['/usr/bin/git', 'status', '--porcelain'], timeout=10):
            raise ValueError('exact-clean-tools-checkout')
        temp = Path(os.environ['RUNNER_TEMP']) / 'camera-owner-typeprobe'
        temp.mkdir(mode=0o700)
        home, tmp = temp/'home', temp/'tmp'
        home.mkdir(mode=0o700); tmp.mkdir(mode=0o700)
        env = {'PATH': '/usr/bin:/bin:/usr/sbin:/sbin', 'HOME': str(home), 'TMPDIR': str(tmp),
               'DEVELOPER_DIR': str(DEVELOPER), 'LC_ALL': 'C'}
        def identity(label, command):
            code, stdout, stderr = bounded(command, env)
            proof['commands'].append({'label': label, 'exit_code': code,
                'stdout_bytes': len(stdout), 'stderr_bytes': len(stderr),
                'stdout_sha256': sha(stdout), 'stderr_sha256': sha(stderr)})
            save()
            identity_facts = validate_identity_streams(label, code, stdout, stderr)
            if label == 'swift-version':
                proof['driver_version'] = identity_facts['driver_version']
                save()
            return stdout
        actual_xcode = identity('xcode-version', ['/usr/bin/xcodebuild', '-version'])
        if not xcode_identity(actual_xcode):
            raise ValueError('exact-Xcode-26-6-build-17F113-required')
        proof['xcode_version'] = '26.6'; proof['xcode_build'] = '17F113'
        swift = identity('swift-version', ['/usr/bin/xcrun', 'swiftc', '--version'])
        match = re.search(rb'Apple Swift version ([0-9]+\.[0-9]+(?:\.[0-9]+)?)(?: |\n)', swift)
        if not match:
            raise ValueError('typed-actual-Swift-version-required')
        proof['swift_version'] = match[1].decode('ascii')
        version = identity('simulator-sdk-version', ['/usr/bin/xcrun', '--sdk', 'iphonesimulator', '--show-sdk-version']).strip()
        if not re.fullmatch(rb'[0-9]+(?:\.[0-9]+){1,2}', version):
            raise ValueError('typed-actual-simulator-SDK-version-required')
        proof['sdk_version'] = version.decode('ascii')
        sdk_bytes = identity('simulator-sdk-path', ['/usr/bin/xcrun', '--sdk', 'iphonesimulator', '--show-sdk-path'])
        sdk = Path(sdk_bytes.decode('utf-8', errors='strict').strip()).resolve(strict=True)
        if not sdk.is_dir() or not sdk.is_relative_to((DEVELOPER/'Platforms/iPhoneSimulator.platform/Developer/SDKs').resolve(strict=True)):
            raise ValueError('pinned-Xcode-simulator-SDK-path-required')
        if not re.fullmatch(r'iPhoneSimulator(?:[0-9]+(?:\.[0-9]+)*)?\.sdk', sdk.name):
            raise ValueError('closed-simulator-SDK-directory-name-required')
        proof['sdk_directory_name'] = sdk.name
        common = ['-parse-as-library', '-swift-version', '6', '-strict-concurrency=complete',
                  '-warnings-as-errors', '-default-isolation', 'MainActor', '-sdk', str(sdk),
                  '-target', 'arm64-apple-ios18.0-simulator', str(SOURCE)]
        for name in PHASES:
            if sha(SOURCE.read_bytes()) != SOURCE_SHA or subprocess.check_output(
                    ['/usr/bin/git', 'rev-parse', 'HEAD'], timeout=10).decode().strip() != head or subprocess.check_output(
                    ['/usr/bin/git', 'status', '--porcelain'], timeout=10):
                raise ValueError('same-source-tools-before-each-compiler-phase')
            flags = ['-typecheck'] if name == 'typecheck' else ['-emit-sil', '-o', '/dev/null']
            row = proof['compiler_phases'][name]
            row['invoked'] = True; row['actual_invocation_count'] = None
            proof['compiler_invoked'] = True; save()
            code, stdout, stderr = bounded(['/usr/bin/xcrun', 'swiftc'] + flags + common, env)
            row['actual_invocation_count'] = 1
            row['result'] = {'exit_code': code, **diagnostics(stdout, stderr)}
            proof[name] = row['result']
            save()
    except Exception as error:
        proof['failure_kind'] = type(error).__name__
        if isinstance(error, ValueError) and re.fullmatch('[A-Za-z0-9-]+', str(error)):
            proof['failure_label'] = str(error)
    finally:
        try:
            proof['source_unchanged'] = sha(SOURCE.read_bytes()) == SOURCE_SHA
            proof['tools_unchanged'] = ('head' in locals() and subprocess.check_output(
                ['/usr/bin/git', 'rev-parse', 'HEAD'], timeout=10).decode().strip() == head
                and not subprocess.check_output(['/usr/bin/git', 'status', '--porcelain'], timeout=10))
        except Exception as error:
            proof['closure_error_kind'] = type(error).__name__
            proof['source_unchanged'] = False; proof['tools_unchanged'] = False
        proof['passed'] = final_pass(proof)
        save()
    return 0 if proof['passed'] else 1


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', required=True, type=Path)
    os.umask(0o077)
    raise SystemExit(main(parser.parse_args().output))
