"""Remote metadata-union P/F/P; no protocol, enrollment or shipping-behavior RED."""
import hashlib
import json
import os
from pathlib import Path
import re
import signal
import stat
import subprocess
import sys
import tempfile
import time

ROOT = Path(__file__).resolve().parents[1]
WORKFLOW = ROOT / '.github/workflows/experimental-sync-ci.yml'
FIXTURE = ROOT / 'scripts/test_checkpoint_dispatch.py'
SELF = Path(__file__).resolve()
TEST = 'CheckpointDispatchTests.test_scope_routes_to_the_focused_job'
METHOD = TEST.split('.')[1]
STACK = 'pairing-stack-regression'
PREDECESSOR = 'native-predecessor-readiness'
FIXTURE_SHA = '31140e77c9f990a44c0a9cdcfe5d6610b95649e19f7cb7c9f515d21633ad41ea'
ASSERTION = 'self.assertIn(scope, routes)'
OUT = ROOT / 'owner64-routing-pfp-evidence'
os.umask(0o077)
OUT.mkdir(mode=0o700)
ORIGINAL = WORKFLOW.read_bytes()
MODE = stat.S_IMODE(WORKFLOW.stat().st_mode)
GUARDED = [WORKFLOW, FIXTURE, SELF, ROOT / 'Cargo.lock',
           ROOT / 'crates/marmot-app/src/native_device_linking/tests.rs']


def sha(data):
    return hashlib.sha256(data).hexdigest()


def git(*args):
    return subprocess.check_output(['git', '-C', str(ROOT), *args])


def snapshot():
    return {str(p.relative_to(ROOT)): {'sha256': sha(p.read_bytes()),
                                     'mode': stat.S_IMODE(p.stat().st_mode)} for p in GUARDED}


before = snapshot()
source = git('rev-parse', 'HEAD').decode().strip()
report = {'source': source, 'tree': git('rev-parse', 'HEAD^{tree}').decode().strip(),
          'purpose': 'Resolved workflow route union metadata mutation; not shipping or enrollment behavior RED',
          'test': TEST, 'expected_phase_bodies': [1, 1, 1], 'phases': [],
          'rust_product_bodies': 0, 'sdk_or_native_bodies': 0,
          'existing_selector_PFP_modified': False, 'source_before': before, 'passed': False}


def save():
    (OUT / 'result.json').write_text(json.dumps(report, indent=2) + '\n')


def interrupted(signum, _frame):
    raise InterruptedError(signum)


def execute(label, private, failure=False):
    command = [sys.executable, '-B', str(FIXTURE), TEST, '-v']
    row = {'phase': label, 'command': command, 'runtime_counts_available': False, 'qualified': False}
    report['phases'].append(row)
    started = time.monotonic()
    print('Owner64 route metadata phase start: ' + label, flush=True)
    result = subprocess.run(command, cwd=ROOT, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                            text=True, timeout=120,
                            env=dict(os.environ, PYTHON_COLORS='0', PYTHONPYCACHEPREFIX=str(private / label)))
    text = result.stdout  # RAM only; never print or persist captured test output.
    row.update(exit_code=result.returncode, seconds=round(time.monotonic() - started, 3))
    summaries = re.findall(r'(?m)^Ran (\d+) tests? in ', text)
    case = re.escape(METHOD + ' (__main__.CheckpointDispatchTests.' + METHOD + ')')
    statuses = re.findall(r'(?m)^' + case + r' \.\.\. (ok|FAIL|ERROR|skipped[^\n]*)$', text)
    row['case_statuses'] = [value.split()[0] for value in statuses]
    if len(summaries) == 1:
        row.update(runtime_counts_available=True, executed=int(summaries[0]))
    row.update(passed=statuses.count('ok'), failed=statuses.count('FAIL'), errors=statuses.count('ERROR'),
               skipped=sum(value.startswith('skipped') for value in statuses))
    frames = re.findall(r'File "[^"]*/scripts/test_checkpoint_dispatch\.py", line (\d+), in ' + re.escape(METHOD), text)
    row['fixture_trace_lines'] = [int(value) for value in frames]
    row['failure_category'] = 'unknown' if failure else None
    save()  # Export closed counts/locations before any assertion or private capture cleanup.
    assert row.get('executed') == len(statuses) == 1, 'exact one runtime body required'
    assert row['errors'] == row['skipped'] == 0, 'compile/import/errors/skips cannot qualify'
    if failure:
        expected_payload = "AssertionError: '" + STACK + "' not found in " + repr(mutant_routes)
        assertions = re.findall(r'(?m)^AssertionError: [^\n]*$', text)
        headers = re.findall(r'(?m)^FAIL: ([^\n]*)$', text)
        intended = (result.returncode == 1 and row['passed'] == 0 and row['failed'] == 1
                    and headers == [METHOD + ' (__main__.CheckpointDispatchTests.' + METHOD + ')']
                    and frames == [str(assertion_line)] and assertions == [expected_payload]
                    and text.count('Traceback (most recent call last):') == 1
                    and text.count('    ' + ASSERTION + '\n') == 1
                    and re.search(r'(?m)^FAILED \(failures=1\)$', text) is not None)
        row['intended_route_assertion'] = intended
        row['failure_category'] = 'stack_scope_missing_only_from_focused_job_route' if intended else 'unknown'
        save()
        assert intended, 'unexpected metadata failure cannot kill mutant'
    else:
        assert result.returncode == 0 and row['passed'] == 1 and row['failed'] == 0, 'positive route control failed'
        assert re.search(r'(?m)^OK$', text), 'missing positive unittest summary'
    row['qualified'] = True
    save()


handlers = {sig: signal.signal(sig, interrupted) for sig in (signal.SIGINT, signal.SIGTERM)}
try:
    assert os.environ['GITHUB_REPOSITORY'] == 'dyKiU/mdk'
    event_sha = os.environ['GITHUB_SHA']
    assert re.fullmatch('[0-9a-f]{40}', source) and re.fullmatch('[0-9a-f]{40}', event_sha)
    event = json.loads(Path(os.environ['GITHUB_EVENT_PATH']).read_text())
    if os.environ['GITHUB_EVENT_NAME'] == 'pull_request':
        pr = event['pull_request']
        assert pr['head']['sha'] == source
        assert pr['head']['repo']['full_name'] == pr['base']['repo']['full_name'] == 'dyKiU/mdk'
        report['PR_head_used_instead_of_synthetic_merge'] = True
    else:
        assert os.environ['GITHUB_EVENT_NAME'] in {'push', 'workflow_dispatch'} and event_sha == source
        if os.environ['GITHUB_EVENT_NAME'] == 'push':
            assert event['after'] == source
        report['PR_head_used_instead_of_synthetic_merge'] = False
    report['event_sha'] = event_sha
    report['git_modes'] = {}
    for path in GUARDED:
        relative = str(path.relative_to(ROOT))
        assert git('show', source + ':' + relative) == path.read_bytes(), 'source differs from immutable merge head'
        git_mode = git('ls-tree', source, '--', relative).decode().split()[0]
        assert git_mode in {'100644', '100755'}
        assert bool(stat.S_IMODE(path.stat().st_mode) & 0o111) == (git_mode == '100755')
        report['git_modes'][relative] = git_mode
    assert sha(FIXTURE.read_bytes()) == FIXTURE_SHA, 'test fixture changed; review oracle first'
    fixture_text = FIXTURE.read_text()
    sites = [index for index, line in enumerate(fixture_text.splitlines(), 1) if line.strip() == ASSERTION]
    assert len(sites) == 1, 'ambiguous original assertion'
    assertion_line = sites[0]
    report['assertion_site'] = {'file': 'scripts/test_checkpoint_dispatch.py', 'line': assertion_line,
                                'literal': ASSERTION, 'fixture_sha256': FIXTURE_SHA}
    workflow = ORIGINAL.decode()
    assert not any(marker in workflow for marker in ['<<<<<<<', '>>>>>>>']), 'unresolved workflow conflict'
    start = workflow.index('  core-regressions:\n')
    end = workflow.index('    name:', start)
    header = workflow[start:end]
    matches = list(re.finditer(r"fromJSON\('([^']+)'\)", header))
    assert len(matches) == 1, 'ambiguous actual focused-job routing JSON'
    match = matches[0]
    routes = json.loads(match[1])
    assert type(routes) is list and all(type(value) is str for value in routes)
    assert len(routes) == len(set(routes)) and STACK in routes and PREDECESSOR in routes
    assert match[1] == json.dumps(routes, separators=(',', ':')), 'noncanonical route requires review'
    mutant_routes = [value for value in routes if value != STACK]
    replacement = json.dumps(mutant_routes, separators=(',', ':'))
    left, right = start + match.start(1), start + match.end(1)
    MUTANT = (workflow[:left] + replacement + workflow[right:]).encode()
    assert PREDECESSOR in mutant_routes and len(mutant_routes) == len(routes) - 1
    assert MUTANT != ORIGINAL and MUTANT.count(STACK.encode()) == ORIGINAL.count(STACK.encode()) - 1
    report.update(original_route_count=len(routes), mutant_route_count=len(mutant_routes),
                  predecessor_preserved=True, dispatch_options_and_other_branches_byte_unchanged=True,
                  mutation='Omit only pairing-stack-regression from core-regressions fromJSON route')
    with tempfile.TemporaryDirectory(prefix='owner64-route-private-') as directory:
        private = Path(directory)
        execute('baseline', private)
        mutation_error = None
        try:
            WORKFLOW.write_bytes(MUTANT)
            assert stat.S_IMODE(WORKFLOW.stat().st_mode) == MODE
            report['mutant_workflow_sha256'] = sha(MUTANT)
            execute('stack-route-omission-mutant', private, failure=True)
        except InterruptedError:
            raise
        except Exception as error:
            mutation_error = error
        finally:
            WORKFLOW.write_bytes(ORIGINAL)
            WORKFLOW.chmod(MODE)
            report['workflow_exactly_restored'] = WORKFLOW.read_bytes() == ORIGINAL and stat.S_IMODE(WORKFLOW.stat().st_mode) == MODE
            save()
        execute('restored', private)
        if mutation_error:
            raise mutation_error
    report['passed'] = True
except Exception as error:
    report['failure_type'] = type(error).__name__
finally:
    WORKFLOW.write_bytes(ORIGINAL)
    WORKFLOW.chmod(MODE)
    report['source_after'] = snapshot()
    report['all_source_and_modes_restored'] = report['source_after'] == before
    report['passed'] = report['passed'] and report['all_source_and_modes_restored']
    for sig, handler in handlers.items():
        signal.signal(sig, handler)
    save()
    print(json.dumps(report, indent=2), flush=True)
if not report['passed']:
    raise SystemExit(1)
