"""Remote metadata-only PFP; no SDK packaging, imports or qualification."""
import argparse
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[2]
HELPER = 'scripts/upstream_apple_ci/package_metadata.py'
TEST = 'scripts/upstream_apple_ci/test_package_metadata.py'
MANIFEST = 'crates/marmot-uniffi/Cargo.toml'
INPUTS = {'scripts/upstream_apple_ci/package_metadata.py': '7fa7e6cd1922b519dfd12849792a67c3f98dbc551953e6517a443c983254ae99', 'scripts/upstream_apple_ci/test_package_metadata.py': '15ed3c6bc76608d75c04a762efc0b7b42e4ce76752127d7b9a7943b796c56379', 'crates/marmot-uniffi/Cargo.toml': '033f6f50a1ad46672404e3b312d6cf305ac6af3282d7f45ec180ef4e6fea7f41'}
GREEN = "def uniffi_version(manifest):\n    if type(manifest) is not dict or type(manifest.get('dependencies')) is not dict:\n        raise ValueError('UniFFI dependency manifest requires a dependency table')\n    dependency = manifest['dependencies'].get('uniffi')\n    if type(dependency) is dict:\n        dependency = dependency.get('version')\n    return _checked_version(dependency)\n"
INVERSE = "def uniffi_version(manifest):\n    return _checked_version(manifest['dependencies']['uniffi']['version'])\n\n\n\n\n\n"
MUTANT_SHA256 = '57cac60326602215195fb57f9abbd0bcff7fd8bd4846c6016aecba2dbcf14e39'
FIELDS = {'schema', 'metadata_only', 'product_tests_executed', 'executed', 'passed',
          'failed', 'errors', 'skipped', 'typed_errors', 'failure_tests', 'files'}


def require(value, label):
    if not value:
        raise ValueError(label)


def sha(value):
    return hashlib.sha256(value).hexdigest()


def git(*args):
    return subprocess.check_output(['git', *args], cwd=ROOT)


def snapshot():
    files = {}
    for name in git('ls-files', '-z').decode().split('\0'):
        if not name:
            continue
        path = ROOT / name
        data = os.readlink(path).encode() if path.is_symlink() else path.read_bytes()
        files[name] = [sha(data), stat.S_IMODE(path.lstat().st_mode)]
    return {'head': git('rev-parse', 'HEAD').decode().strip(),
            'index': sha(git('ls-files', '--stage', '-z')),
            'status': sha(git('status', '--porcelain=v1', '-z', '--untracked-files=all')),
            'files': files}


class HeldSource:
    def __init__(self, path, original):
        self.path, self.current = path, original
        self.fd = os.open(path, os.O_RDWR | os.O_NOFOLLOW | os.O_CLOEXEC)
        fcntl.flock(self.fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        info = os.fstat(self.fd)
        require(stat.S_ISREG(info.st_mode) and info.st_uid == os.getuid() and info.st_nlink == 1,
                'one-owned-regular-helper-required')
        self.identity = self.signature(info)
        self.verify(original)

    @staticmethod
    def signature(row):
        return (row.st_dev, row.st_ino, row.st_uid, row.st_nlink, stat.S_IMODE(row.st_mode))

    def verify(self, value):
        require(self.signature(os.fstat(self.fd)) == self.signature(self.path.lstat()) == self.identity
                and not self.path.is_symlink(), 'same-held-helper-inode-mode-required')
        require(os.pread(self.fd, len(value) + 1, 0) == value, 'exact-current-helper-bytes-required')

    def write(self, old, new):
        self.verify(old)
        offset = 0
        while offset < len(new):
            count = os.pwrite(self.fd, new[offset:], offset)
            require(count > 0, 'complete-owned-helper-write-required')
            offset += count
            self.current = new[:offset] + self.current[offset:]
        os.ftruncate(self.fd, len(new))
        self.current = new
        os.fsync(self.fd)
        self.verify(new)

    def close(self):
        fcntl.flock(self.fd, fcntl.LOCK_UN)
        os.close(self.fd)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--result', type=Path, required=True)
    args = parser.parse_args()
    require(os.environ.get('GITHUB_ACTIONS') == 'true' and os.environ.get('RUNNER_OS') == 'Linux',
            'remote-Linux-metadata-only-required')
    require(args.result.is_absolute() and not args.result.exists(), 'fresh-absolute-result-required')
    work = Path(os.environ['RUNNER_TEMP']) / 'package-metadata-pfp'
    work.mkdir(mode=0o700)
    args.result.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    proof = {'schema': 1, 'metadata_only': True, 'product_tests_executed': 0,
             'native_tests_executed': 0, 'SDK_qualification': False,
             'passed': False, 'source_restored': False, 'phases': []}
    held, initial, original = None, None, None
    try:
        initial = snapshot()
        require(re.fullmatch('[0-9a-f]{40}', initial['head']) is not None
                and initial['status'] == sha(b''), 'clean-committed-source-required')
        for path, digest in INPUTS.items():
            require(initial['files'][path][0] == digest, 'exact-reviewed-metadata-inputs-required')
        original = (ROOT / HELPER).read_bytes()
        require(original.decode().count(GREEN) == 1 and original.decode().endswith(GREEN),
                'sole-owned-reader-function-required')
        mutant = original.decode().replace(GREEN, INVERSE, 1).encode()
        require(GREEN.count('\n') == INVERSE.count('\n') and sha(mutant) == MUTANT_SHA256,
                'exact-newline-preserved-legacy-inverse-required')
        held = HeldSource(ROOT / HELPER, original)
        proof['source'] = initial['head']
        proof['input_sha256'] = INPUTS
        proof['source_snapshot_sha256'] = sha(json.dumps(initial, sort_keys=True).encode())

        def phase(label, intentional):
            expected = {**initial, 'files': dict(initial['files'])}
            if intentional:
                expected['files'][HELPER] = [sha(mutant), initial['files'][HELPER][1]]
                expected['status'] = sha((' M ' + HELPER + '\0').encode())
            require(snapshot() == expected, 'whole-source-Git-mode-before-phase-required')
            held.verify(mutant if intentional else original)
            folder = work / label
            folder.mkdir(mode=0o700)
            result_path, log_path = folder / 'result.json', folder / 'private.log'
            row = {'phase': label, 'invoked': True}
            proof['phases'].append(row)
            with log_path.open('x') as output:
                process = subprocess.Popen([sys.executable, str(ROOT / TEST), '--result', str(result_path)],
                    cwd=ROOT, stdout=output, stderr=subprocess.STDOUT)
                try:
                    row['exit_code'] = process.wait(timeout=30)
                finally:
                    if process.poll() is None:
                        process.kill(); process.wait(timeout=10)
            require(log_path.stat().st_size <= 1024 * 1024 and result_path.stat().st_size <= 65536,
                    'bounded-actual-metadata-results-required')
            raw = log_path.read_bytes()
            row['log_sha256'] = sha(raw)
            result_bytes = result_path.read_bytes()
            row['result_sha256'] = sha(result_bytes)
            result = json.loads(result_bytes)
            require(type(result) is dict and set(result) == FIELDS
                    and type(result['schema']) is int and result['schema'] == 1 and result['metadata_only'] is True
                    and type(result['product_tests_executed']) is int and result['product_tests_executed'] == 0,
                    'closed-metadata-only-result-required')
            counts = {key: result[key] for key in ('executed', 'passed', 'failed', 'errors', 'skipped')}
            require(all(type(value) is int and value >= 0 for value in counts.values()),
                    'actual-typed-nonnegative-metadata-counts-required')
            row['counts'] = counts  # Preserve observed counts before an oracle rejection.
            expected_counts = dict(executed=3, passed=2 if intentional else 3,
                                   failed=0, errors=1 if intentional else 0, skipped=0)
            require(all(type(result[key]) is int and result[key] == value
                        for key, value in expected_counts.items()), 'three-actual-metadata-methods-required')
            expected_files = dict(INPUTS)
            if intentional: expected_files[HELPER] = sha(mutant)
            require(result['files'] == expected_files and result['failure_tests'] == [],
                    'exact-actual-metadata-inputs-and-no-assertion-failures-required')
            expected_errors = [{'test': 'test_actual_repository_string_dependency', 'type': 'TypeError'}] if intentional else []
            require(result['typed_errors'] == expected_errors and row['exit_code'] == int(intentional),
                    'sole-real-TypeError-or-three-passes-required')
            row['actual'] = result  # Entire result is closed and matched before export.
            if intentional:
                text = raw.decode('utf-8', errors='strict')
                lookup = "    return _checked_version(manifest['dependencies']['uniffi']['version'])"
                line = mutant.decode()[:mutant.decode().index(lookup)].count('\n') + 1
                site = 'File "' + str(ROOT / HELPER) + '", line ' + str(line) + ', in uniffi_version'
                require(text.count(site) == 1 and text.count("TypeError: string indices must be integers, not 'str'") == 1,
                        'exact-source-owned-legacy-TypeError-required')
                row['owned_error_site'] = {'path': HELPER, 'line': line, 'type': 'TypeError'}
            held.verify(mutant if intentional else original)
            require(snapshot() == expected, 'whole-source-Git-mode-after-phase-required')
            row['source_closure_exact'] = True

        phase('baseline', False)
        held.write(original, mutant)
        try:
            phase('mutant', True)
        finally:
            held.verify(mutant)
            held.write(mutant, original)
        phase('restored', False)
        require([row['phase'] for row in proof['phases']] == ['baseline', 'mutant', 'restored'],
                'three-actual-ordered-phases-required')
        proof['passed'] = True
    except (ValueError, OSError, KeyError, TypeError, UnicodeError, subprocess.SubprocessError) as error:
        proof['failure_category'] = type(error).__name__
        if isinstance(error, ValueError) and re.fullmatch('[A-Za-z0-9_-]{1,160}', str(error)):
            proof['failure_label'] = str(error)
    finally:
        if held is not None:
            try:
                if held.current != original:
                    held.verify(held.current); held.write(held.current, original)
                held.verify(original)
                proof['source_restored'] = snapshot() == initial
            except (ValueError, OSError, subprocess.SubprocessError):
                proof['source_restored'] = False
            finally:
                held.close()
        proof['passed'] = proof['passed'] and proof['source_restored']
        unknown = [row['phase'] for row in proof['phases'] if row.get('invoked') is True and 'counts' not in row]
        known = sum(row['counts']['executed'] for row in proof['phases'] if 'counts' in row)
        proof['known_executed_metadata_methods'] = known
        proof['executed_metadata_methods'] = None if unknown else known
        proof['invoked_phases_with_unknown_counts'] = unknown
        with args.result.open('x') as output: json.dump(proof, output, indent=2); output.write('\n')
    return 0 if proof['passed'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
