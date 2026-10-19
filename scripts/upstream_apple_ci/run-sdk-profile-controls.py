"""REMOTE-only metadata controls and one exact validator mutation, no SDK build."""
import hashlib
import json
import os
from pathlib import Path
import re
import signal
import subprocess
import sys
import tempfile
import time

os.umask(0o077)
HERE = Path(__file__).resolve().parent
ROOT = Path(os.environ['SDK_SOURCE_REPOSITORY']).resolve()
SOURCE = os.environ['PROFILE_CONTROL_SOURCE_SHA']
TEST = 'ProfileMetadataTests.test_per_input_lock_mismatch_rejected'
TARGET = HERE / 'sdk_profiles.py'
ORIGINAL = TARGET.read_bytes()
OUT = Path('sdk-profile-controls-proof')
OUT.mkdir(mode=0o700)
GUARDED = [TARGET, HERE / 'test_sdk_profiles.py', HERE / 'install.py', ROOT / 'Cargo.lock',
           ROOT / '.github/workflows/upstream-experimental-apple.yml']


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


before = {str(p.relative_to(ROOT)): digest(p) for p in GUARDED}
report = {'source': SOURCE, 'fixture': 'synthetic metadata derived from real Git objects; NOT SDK artifacts',
          'final_sdk_qualification': False,
          'sdk_or_product_bodies': 0, 'expected_metadata_suite_bodies': 22,
          'expected_mutation_phase_bodies': 3, 'phases': [], 'passed': False,
          'source_hashes_before': before}


def save():
    (OUT / 'result.json').write_text(json.dumps(report, indent=2) + '\n')


def execute(label, directory, expected_count, expected_failure=False, focused=False):
    command = [sys.executable, '-B', str(HERE / 'test_sdk_profiles.py')]
    if focused:
        command.append(TEST)
    row = {'phase': label, 'command': command, 'runtime_counts_available': False, 'qualified': False}
    report['phases'].append(row)
    log = directory / (label + '.log')
    started = time.monotonic()
    print('SDK metadata control phase start: ' + label, flush=True)
    with log.open('x') as stream:
        result = subprocess.run(command, stdout=stream, stderr=subprocess.STDOUT, timeout=120,
                                env=dict(os.environ, PYTHONPYCACHEPREFIX=str(directory / label), PYTHON_COLORS='0'))
    text = log.read_text(errors='replace')
    row.update(exit_code=result.returncode, seconds=round(time.monotonic() - started, 3))
    counts = re.findall(r'(?m)^Ran (\d+) tests? in ', text)
    cases = re.findall(r'(?m)^(test_[A-Za-z_]+) \(__main__\.ProfileMetadataTests\.test_[A-Za-z_]+\) \.\.\. (ok|FAIL|ERROR|skipped[^\n]*)$', text)
    names = [status for _, status in cases]
    row['case_results'] = [{'name': name, 'status': status.split()[0]} for name, status in cases]
    row['reported_case_lines'] = len(names)
    if len(counts) == 1:
        row.update(runtime_counts_available=True, executed=int(counts[0]))
    row['skipped'] = sum(name.startswith('skipped') for name in names)
    row['errors'] = names.count('ERROR')
    row['failed'] = names.count('FAIL')
    row['passed'] = names.count('ok')
    save()  # Persist closed diagnostics before any validator assertion or private-log deletion.
    assert row.get('executed') == expected_count and len(names) == expected_count, 'runtime body count mismatch'
    assert row['skipped'] == row['errors'] == 0, 'skips/import/setup errors do not qualify'
    if expected_failure:
        intended = 'AssertionError: ValueError not raised' in text
        intended = intended and ('FAIL: test_per_input_lock_mismatch_rejected' in text)
        row['intended_failure'] = intended
        row['failure_category'] = 'required_input_lock_rejection_omitted' if intended else 'unknown'
        assert result.returncode != 0 and row['failed'] == 1 and row['passed'] == 0 and intended, 'not intended validator runtime failure'
        assert re.search(r'(?m)^FAILED \(failures=1\)$', text), 'unexpected failure summary'
    else:
        assert result.returncode == 0 and row['failed'] == 0 and row['passed'] == expected_count, 'positive metadata controls did not pass'
        assert re.search(r'(?m)^OK$', text), 'missing positive summary'
    row['qualified'] = True
    save()


def interrupted(signum, _frame):
    raise InterruptedError(signum)


previous_handlers = {sig: signal.signal(sig, interrupted) for sig in (signal.SIGINT, signal.SIGTERM)}
try:
    assert os.environ['GITHUB_REF'].startswith('refs/heads/ci/upstream-sdk-profile-controls-')
    assert subprocess.check_output(['git', '-C', str(ROOT), 'rev-parse', 'HEAD'], text=True).strip() == SOURCE == os.environ['GITHUB_SHA']
    tracked = subprocess.check_output(['git', '-C', str(ROOT), 'show', SOURCE + ':scripts/upstream_apple_ci/sdk_profiles.py'])
    assert tracked == ORIGINAL, 'validator differs from immutable control source'
    anchor = b" or record['cargo_lock_sha256'] != lock"
    assert ORIGINAL.count(anchor) == 1, 'ambiguous omission mutant'
    with tempfile.TemporaryDirectory(prefix='sdk-profile-private-') as private:
        directory = Path(private)
        execute('metadata-suite', directory, 22)
        execute('baseline-control', directory, 1, focused=True)
        mutation_error = None
        try:
            TARGET.write_bytes(ORIGINAL.replace(anchor, b'', 1))
            report['mutant_sha256'] = digest(TARGET)
            execute('input-lock-omission-mutant', directory, 1, expected_failure=True, focused=True)
        except InterruptedError:
            raise
        except Exception as error:
            mutation_error = error
        finally:
            TARGET.write_bytes(ORIGINAL)
            report['validator_exactly_restored'] = TARGET.read_bytes() == ORIGINAL
            save()
        execute('restored-control', directory, 1, focused=True)
        if mutation_error:
            raise mutation_error
    report['passed'] = True
except Exception as error:
    report['failure_type'] = type(error).__name__
finally:
    TARGET.write_bytes(ORIGINAL)
    report['source_hashes_after'] = {str(p.relative_to(ROOT)): digest(p) for p in GUARDED}
    report['source_restored'] = report['source_hashes_after'] == before
    report['passed'] = report['passed'] and report['source_restored']
    for sig, handler in previous_handlers.items():
        signal.signal(sig, handler)
    save()
    print(json.dumps(report, indent=2), flush=True)
if not report['passed']:
    raise SystemExit(1)
