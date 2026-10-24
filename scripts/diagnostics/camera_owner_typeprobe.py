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

SOURCE_SHA = 'f6687c58dab235a237da421ca60129731870bc113d1cf42d4aa09eb112b7e10f'
SOURCE = Path(__file__).with_name('CheckedCaptureOwner.swift')
DEVELOPER = Path('/Applications/Xcode_26.6.app/Contents/Developer')
CAP = 256 * 1024


def sha(data):
    return hashlib.sha256(data).hexdigest()


def xcode_identity(data):
    return re.fullmatch(rb'Xcode (26\.6(?:\.0)?)\nBuild version (17F113)\n?', data) is not None


def diagnostics(stdout, stderr):
    rows = []
    unknown = 0
    for stream, data in [('stdout', stdout), ('stderr', stderr)]:
        for line in data.splitlines():
            match = re.fullmatch(rb'(?:[^\r\n]*[/\\])?CheckedCaptureOwner\.swift:([1-9][0-9]*):([1-9][0-9]*): (error|warning|note): [^\r\n]*', line)
            if match:
                rows.append({'stream': stream, 'file': 'CheckedCaptureOwner.swift',
                             'line': int(match[1]), 'column': int(match[2]),
                             'severity': match[3].decode('ascii'), 'row_sha256': sha(line)})
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


def main(output):
    proof = {'schema': 1, 'diagnostic_only': True, 'qualification_credit': False,
             'behavioral_credit': False, 'product_tests_executed': 0, 'native_tests_executed': 0,
             'tools_sha': os.environ.get('GITHUB_SHA'), 'passed': False, 'compiler_invoked': False,
             'source_sha256': sha(SOURCE.read_bytes()), 'commands': [], 'typecheck': None}
    def save():
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
            if code != 0 or stderr or not stdout:
                raise ValueError('identity-command-failed')
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
        proof['compiler_invoked'] = True; save()
        command = ['/usr/bin/xcrun', 'swiftc', '-typecheck', '-parse-as-library', '-swift-version', '6',
                   '-strict-concurrency=complete', '-warnings-as-errors', '-default-isolation', 'MainActor',
                   '-sdk', str(sdk), '-target', 'arm64-apple-ios18.0-simulator', str(SOURCE)]
        code, stdout, stderr = bounded(command, env)
        proof['typecheck'] = {'exit_code': code, **diagnostics(stdout, stderr)}
        proof['source_unchanged'] = sha(SOURCE.read_bytes()) == SOURCE_SHA
        proof['tools_unchanged'] = subprocess.check_output(['/usr/bin/git', 'rev-parse', 'HEAD'], timeout=10).decode().strip() == head and not subprocess.check_output(['/usr/bin/git', 'status', '--porcelain'], timeout=10)
        proof['passed'] = code == 0 and stdout == stderr == b'' and proof['source_unchanged'] and proof['tools_unchanged']
    except Exception as error:
        proof['failure_kind'] = type(error).__name__
        if isinstance(error, ValueError) and re.fullmatch('[A-Za-z0-9-]+', str(error)):
            proof['failure_label'] = str(error)
    finally:
        save()
    return 0 if proof['passed'] else 1


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', required=True, type=Path)
    os.umask(0o077)
    raise SystemExit(main(parser.parse_args().output))
