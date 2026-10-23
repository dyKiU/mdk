"""Remote archive-origin metadata P/F/P only; zero Rust, SDK or product bodies."""
import hashlib
import json
import os
from pathlib import Path
import re
import select
import signal
import stat
import subprocess
import sys
import tempfile
import time

from recover_archive_gaps import source_partition_count

ROOT = Path(__file__).resolve().parents[1]
TARGET = ROOT / 'scripts/recover_archive_gaps.py'
FIXTURE = ROOT / 'scripts/test_recover_archive_gaps.py'
TEST = 'ArchiveGapTests.test_current_partition_extra_duplicate_mixed_and_foreign_roles_refused'
METHOD = TEST.split('.')[1]
FIXTURE_SHA = 'eb15dfd9e87241d37e8157c076f2ebff03add66f6d3f461deb4fc909e2788755'
ANCHOR = b'selected = [job for job in jobs if job["name"].startswith(label + " (")]'
OMISSION = b'selected = [job for job in jobs if job["name"] in expected]'
EIGHT_TEST = 'ArchiveGapTests.test_current_eight_partition_origin_exact_union'
EIGHT_METHOD = EIGHT_TEST.split('.')[1]
EIGHT_ANCHOR = b'expected_partitions not in {5, 7, 8, 12}'
EIGHT_INVERSE = b'expected_partitions not in {5, 7, 12}'
GUARDED = [TARGET, FIXTURE, Path(__file__).resolve(), ROOT / 'scripts/recover_experimental_coverage.py',
    ROOT / '.github/workflows/ci.yml', ROOT / '.github/workflows/experimental-sync-ci.yml', ROOT / 'Cargo.lock']
OUT = ROOT / 'archive-partition-origin-pfp-evidence'
os.umask(0o077)
OUT.mkdir(mode=0o700)


def digest(data):
    return hashlib.sha256(data).hexdigest()


def git(*args):
    return subprocess.check_output(['git', '-C', str(ROOT), *args])


def snapshot():
    result = {}
    for path in GUARDED:
        info = path.lstat()
        assert stat.S_ISREG(info.st_mode) and not path.is_symlink()
        result[str(path.relative_to(ROOT))] = (digest(path.read_bytes()), stat.S_IMODE(info.st_mode))
    return result


ORIGINAL = TARGET.read_bytes()
MODE = stat.S_IMODE(TARGET.lstat().st_mode)
original_head = git('rev-parse', 'HEAD').decode().strip()
original_index_sha256 = digest(git('ls-files', '--stage', '-z'))
before = snapshot()
report = {'passed': False, 'scope': 'Source-bound original archive partition roles; metadata only',
    'rust_product_or_sdk_bodies': 0, 'phases': [], 'source_before': before,
    'Parent_SDK_admission_not_qualified': True,
    'head_before': original_head, 'index_before_sha256': original_index_sha256}


def save():
    (OUT / 'result.json').write_text(json.dumps(report, indent=2) + '\n')


def capture(command):
    # Captures remain RAM-only and bounded even when a child does not terminate.
    child = subprocess.Popen(command, cwd=ROOT, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
        start_new_session=True, env=dict(os.environ, PYTHON_COLORS='0'), bufsize=0)
    chunks, size = [], 0
    deadline = time.monotonic() + 120
    try:
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise RuntimeError('metadata-watchdog')
            if not select.select([child.stdout], [], [], min(remaining, 1))[0]:
                continue
            chunk = os.read(child.stdout.fileno(), 65536)
            if not chunk:
                break
            size += len(chunk)
            if size > 1024 * 1024:
                raise RuntimeError('metadata-output-cap')
            chunks.append(chunk)
        code = child.wait(timeout=max(0.001, deadline - time.monotonic()))
        return code, b''.join(chunks).decode('utf-8', errors='replace')
    finally:
        if child.poll() is None:
            os.killpg(child.pid, signal.SIGKILL)
        child.wait()
        child.stdout.close()


def physical(expected_target):
    assert git('rev-parse', 'HEAD').decode().strip() == original_head, 'metadata-head-drift'
    assert digest(git('ls-files', '--stage', '-z')) == original_index_sha256, 'metadata-index-drift'
    actual = snapshot()
    expected = dict(before)
    expected['scripts/recover_archive_gaps.py'] = (digest(expected_target), MODE)
    assert actual == expected, 'metadata-source-or-mode-changed'
    return actual


def execute(label, expected_target, intended_failure=False, *, selected_test=TEST, reject_eight=False):
    method = selected_test.split('.')[1]
    row = {'phase': label, 'test': selected_test, 'executed': None, 'passed': None, 'failed': None,
        'errors': None, 'skipped': None, 'qualified': False}
    report['phases'].append(row)
    row['source_precheck'] = physical(expected_target)
    save()
    started = time.monotonic()
    try:
        code, raw = capture([sys.executable, '-B', str(FIXTURE), selected_test, '-v'])
        row.update(exit_code=code, seconds=round(time.monotonic() - started, 3))
        totals = re.findall(r'(?m)^Ran (\d+) tests? in ', raw)
        status = re.findall(r'(?m)^' + re.escape(method + ' (__main__.ArchiveGapTests.' + method + ')')
            + r' \.\.\. (ok|FAIL|ERROR|skipped[^\n]*)$', raw)
        if len(totals) == 1:
            row['executed'] = int(totals[0])
        row.update(passed=status.count('ok'), failed=status.count('FAIL'), errors=status.count('ERROR'),
            skipped=sum(value.startswith('skipped') for value in status))
        save()  # Actual counts survive a later physical/strict failure.
    finally:
        row['source_postcheck'] = physical(expected_target)
        save()
    assert row['executed'] == len(status) == 1 and row['skipped'] == 0
    if reject_eight:
        fixture_frames = re.findall(r'File "[^"]*/scripts/test_recover_archive_gaps\.py", line (\d+), in '
            + re.escape(method), raw)
        production_frames = re.findall(r'File "[^"]*/scripts/recover_archive_gaps\.py", line (\d+), in validate_origin', raw)
        headers = re.findall(r'(?m)^ERROR: ([^\n]*)$', raw)
        exceptions = re.findall(r'(?m)^ValueError: [^\n]*$', raw)
        row['intended_production_rejection'] = (
            code == 1 and row['passed'] == row['failed'] == 0 and row['errors'] == 1
            and headers == [method + ' (__main__.ArchiveGapTests.' + method + ')']
            and fixture_frames == [str(eight_call_line)]
            and production_frames == [str(eight_guard_line)]
            and exceptions == ['ValueError: Reviewed partition count required']
            and raw.count('Traceback (most recent call last):') == 1
            and re.search(r'(?m)^FAILED \(errors=1\)$', raw) is not None)
        save()
        assert row['intended_production_rejection'], 'unknown-error-not-eight-admission-inverse'
    elif intended_failure:
        assert row['errors'] == 0
        frames = re.findall(r'File "[^"]*/scripts/test_recover_archive_gaps\.py", line (\d+), in '
            + re.escape(method), raw)
        headers = re.findall(r'(?m)^FAIL: ([^\n]*)$', raw)
        errors = re.findall(r'(?m)^AssertionError: [^\n]*$', raw)
        row['intended_failure'] = (code == 1 and row['passed'] == 0 and row['failed'] == 1
            and headers == [method + ' (__main__.ArchiveGapTests.' + method + ')']
            and frames == [str(assertion_line)] and errors == ['AssertionError: ValueError not raised']
            and raw.count('Traceback (most recent call last):') == 1
            and re.search(r'(?m)^FAILED \(failures=1\)$', raw) is not None)
        save()
        assert row['intended_failure'], 'unknown-failure-not-a-mutant-kill'
    else:
        assert code == 0 and row['passed'] == 1 and row['failed'] == row['errors'] == 0 and re.search(r'(?m)^OK$', raw)
    row['qualified'] = True
    save()


def interrupted(signum, _frame):
    raise InterruptedError(signum)


handlers = {sig: signal.signal(sig, interrupted) for sig in (signal.SIGINT, signal.SIGTERM)}
try:
    source = git('rev-parse', 'HEAD').decode().strip()
    assert re.fullmatch('[0-9a-f]{40}', source) and os.environ['GITHUB_REPOSITORY'] == 'dyKiU/mdk'
    event = json.loads(Path(os.environ['GITHUB_EVENT_PATH']).read_text())
    if os.environ['GITHUB_EVENT_NAME'] == 'pull_request':
        pr = event['pull_request']
        assert pr['head']['sha'] == source
        assert pr['head']['repo']['full_name'] == pr['base']['repo']['full_name'] == 'dyKiU/mdk'
    else:
        assert os.environ['GITHUB_EVENT_NAME'] in {'push', 'workflow_dispatch'} and os.environ['GITHUB_SHA'] == source
        if os.environ['GITHUB_EVENT_NAME'] == 'push':
            assert event['after'] == source
    report.update(source=source, tree=git('rev-parse', 'HEAD^{tree}').decode().strip(), event_sha=os.environ['GITHUB_SHA'])
    for path in GUARDED:
        relative = str(path.relative_to(ROOT))
        assert git('show', source + ':' + relative) == path.read_bytes()
        mode = git('ls-tree', source, '--', relative).decode().split()[0]
        assert mode in {'100644', '100755'}
        assert bool(path.stat().st_mode & 0o111) == (mode == '100755')
    report['original_source_partition_counts'] = {cohort: source_partition_count(source, cohort)
        for cohort in ['default', 'experimental']}
    assert report['original_source_partition_counts'] == {'default': 8, 'experimental': 12}
    assert digest(FIXTURE.read_bytes()) == FIXTURE_SHA and ORIGINAL.count(ANCHOR) == ORIGINAL.count(EIGHT_ANCHOR) == 1
    text = FIXTURE.read_text()
    method_start = text.index('    def ' + METHOD + '(')
    next_method = text.index('\n    def ', method_start + 1)
    method = text[method_start:next_method]
    sites = [i for i, line in enumerate(text.splitlines(), 1)
        if line.strip() == 'with self.assertRaises(ValueError):' and method_start <= sum(len(v) + 1 for v in text.splitlines()[:i-1]) < next_method]
    assert len(sites) == 1
    assertion_line = sites[0]
    report['assertion_site'] = {'file': 'scripts/test_recover_archive_gaps.py', 'line': assertion_line}
    eight_start = text.index('    def ' + EIGHT_METHOD + '(')
    eight_end = text.index('\n    def ', eight_start + 1)
    eight_prefix = text[:eight_start].count('\n')
    eight_calls = [eight_prefix + i for i, line in enumerate(text[eight_start:eight_end].splitlines(), 1)
        if 'self.assertEqual(len(validate_origin(' in line]
    assert len(eight_calls) == 1
    eight_call_line = eight_calls[0]
    production = ORIGINAL.decode()
    guard_start = production.index('def validate_origin(')
    guard_end = production.index('\n\ndef ', guard_start + 1)
    guard_prefix = production[:guard_start].count('\n')
    guard_lines = [guard_prefix + i for i, line in enumerate(production[guard_start:guard_end].splitlines(), 1)
        if line.strip() == 'raise ValueError("Reviewed partition count required")']
    assert len(guard_lines) == 1
    eight_guard_line = guard_lines[0]
    report['eight_admission_sites'] = {'fixture': 'scripts/test_recover_archive_gaps.py',
        'fixture_call_line': eight_call_line, 'production': 'scripts/recover_archive_gaps.py',
        'production_guard_line': eight_guard_line}
    mutant = ORIGINAL.replace(ANCHOR, OMISSION, 1)
    with tempfile.TemporaryDirectory(prefix='archive-origin-private-'):
        execute('baseline', ORIGINAL)
        mutation_error = None
        try:
            physical(ORIGINAL)
            TARGET.write_bytes(mutant)
            report['mutant_sha256'] = digest(mutant)
            execute('extra-role-capture-omission-mutant', mutant, intended_failure=True)
        except InterruptedError:
            raise
        except Exception as error:
            mutation_error = error
        finally:
            assert TARGET.is_file() and not TARGET.is_symlink()
            TARGET.write_bytes(ORIGINAL)
            TARGET.chmod(MODE)
            save()
        execute('restored', ORIGINAL)
        if mutation_error:
            raise mutation_error
        # Preserve the original three role-guard bodies above. This independent
        # inverse removes only the newly admitted eight from production validation.
        execute('eight-admission-baseline', ORIGINAL, selected_test=EIGHT_TEST)
        inverse = ORIGINAL.replace(EIGHT_ANCHOR, EIGHT_INVERSE, 1)
        mutation_error = None
        try:
            physical(ORIGINAL)
            TARGET.write_bytes(inverse)
            report['eight_inverse_sha256'] = digest(inverse)
            execute('eight-admission-production-inverse', inverse,
                selected_test=EIGHT_TEST, reject_eight=True)
        except InterruptedError:
            raise
        except Exception as error:
            mutation_error = error
        finally:
            assert TARGET.is_file() and not TARGET.is_symlink()
            TARGET.write_bytes(ORIGINAL)
            TARGET.chmod(MODE)
            save()
        execute('eight-admission-restored', ORIGINAL, selected_test=EIGHT_TEST)
        if mutation_error:
            raise mutation_error
    report['passed'] = True
except Exception as error:
    report['failure_type'] = type(error).__name__
finally:
    assert TARGET.is_file() and not TARGET.is_symlink()
    TARGET.write_bytes(ORIGINAL)
    TARGET.chmod(MODE)
    report['source_after'] = snapshot()
    report['all_source_and_modes_restored'] = report['source_after'] == before
    try:
        report['head_after'] = git('rev-parse', 'HEAD').decode().strip()
        report['index_after_sha256'] = digest(git('ls-files', '--stage', '-z'))
        report['head_and_index_restored'] = (report['head_after'] == original_head
            and report['index_after_sha256'] == original_index_sha256)
    except Exception as error:
        report['head_and_index_restored'] = False
        report['identity_restoration_error'] = type(error).__name__
    report['passed'] = (report['passed'] and report['all_source_and_modes_restored']
        and report['head_and_index_restored'])
    for sig, handler in handlers.items():
        signal.signal(sig, handler)
    save()
if not report['passed']:
    raise SystemExit(1)
