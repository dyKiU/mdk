"""Remote Ubuntu metadata only: two actual inventory-helper P/F/P controls."""
import argparse
import ast
import hashlib
import json
import os
from pathlib import Path
import signal
import stat
import subprocess
import sys
import traceback
import unittest

from factory_semantic_runner import ExactSource, context

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
TEST = 'scripts/upstream_apple_ci/test_compatibility_policy.py'
CASES = {
    'strict': {
        'source': 'scripts/upstream_apple_ci/compatibility_policy_pfp.py', 'owner': 'sdk_state',
        'old': '        frozen[name] = digest\n',
        'new': "        if not name.endswith('/Headers/marmot_uniffiFFI.h'): frozen[name] = digest\n",
        'method': 'test_qualified_header_is_frozen_when_producer_artifacts_list_only_archive',
        'message': 'qualified complete inventory must freeze the compiled header',
    },
    'hosted': {
        'source': 'scripts/upstream_apple_ci/hosted-app-unit.py', 'owner': 'freeze_sdk',
        'old': '        frozen[name] = expected_digest\n',
        'new': "        if not name.endswith('/Headers/marmot_uniffiFFI.h'): frozen[name] = expected_digest\n",
        'method': 'test_hosted_unit_freezes_qualified_header_when_artifacts_list_only_archive',
        'message': 'hosted unit complete inventory must freeze the compiled header',
    },
}
INPUTS = {'scripts/upstream_apple_ci/test_compatibility_policy.py': '2383dbfdace93938253b93099adaf2f412a9e987f0c9bf46c28cbb268c2ce352', 'scripts/upstream_apple_ci/compatibility_policy_pfp.py': 'b4e90b5274302d55c522c720249bf29b7cd1c3a9ab8f794cf167321410c1f938', 'scripts/upstream_apple_ci/hosted-app-unit.py': '0f1504e4e7479ad7a5a855018b1d9885cd70c0fa5ff6b42636ba6ff869a0da7a', 'scripts/upstream_apple_ci/sdk_profiles.py': '15c176c3b049032d857c05c0ff5e86952dbc81cb06efbff81f8dcf3efabfdd7f', 'scripts/upstream_apple_ci/factory_semantic_runner.py': 'b89caaa21f2280d08e56b70facc74804782ca05953a06fd97c4e23e41615dd79', 'scripts/upstream_apple_ci/app-sdk-cohort.py': '60f4e123d2bd2a6bb4e95179b686e2f905e13fff452afcdcdcdac633c7aa32d2', 'scripts/upstream_apple_ci/compatibility_policy.py': 'b97a68b35feeb438cba9659222004680cd0982be6bb5a31fb2b068a0617c0f42'}


def require(value, label):
    if not value:
        raise ValueError(label)


def sha(value):
    return hashlib.sha256(value).hexdigest()


def git(*args):
    return subprocess.check_output(['git', '-C', str(ROOT), *args])


def snapshot():
    names = git('ls-files', '-z').decode().split('\0')
    result = {}
    for name in filter(None, names):
        path = ROOT / name
        info = path.lstat()
        data = os.readlink(path).encode() if stat.S_ISLNK(info.st_mode) else path.read_bytes()
        result[name] = [sha(data), stat.S_IMODE(info.st_mode), stat.S_IFMT(info.st_mode)]
    return result


def site(case):
    source = (ROOT / TEST).read_text()
    tree = ast.parse(source)
    owners = [node for node in ast.walk(tree) if isinstance(node, ast.FunctionDef) and node.name == case['method']]
    require(len(owners) == 1, 'exact-selected-metadata-owner')
    calls = [node for node in ast.walk(owners[0]) if isinstance(node, ast.Call)
             and isinstance(node.func, ast.Attribute) and node.func.attr == 'assertEqual'
             and len(node.args) == 3 and isinstance(node.args[2], ast.Constant)
             and node.args[2].value == case['message']]
    require(len(calls) == 1, 'exact-owned-header-assertion')
    return {'path': TEST, 'line': calls[0].lineno, 'method': case['method']}


def transform(original, case):
    text = original.decode('utf-8', errors='strict')
    owner = [node for node in ast.parse(text).body if isinstance(node, ast.FunctionDef) and node.name == case['owner']]
    require(len(owner) == 1 and text.count(case['old']) == 1, 'exact-owned-header-freeze-line')
    body = ''.join(text.splitlines(keepends=True)[owner[0].lineno - 1:owner[0].end_lineno])
    require(body.count(case['old']) == 1, 'header-inverse-within-helper')
    changed = text.replace(case['old'], case['new'], 1).encode()
    require(original.count(b'\n') == changed.count(b'\n'), 'inverse-line-count-preserved')
    ast.parse(changed)
    return changed


def child(case_id, output):
    case = CASES[case_id]
    expected_site = site(case)
    class Result(unittest.TestResult):
        def __init__(self):
            super().__init__()
            self.owned = []
            self.error_digests = []
        def addFailure(self, test, error):
            super().addFailure(test, error)
            frames = traceback.extract_tb(error[2])
            own = [row for row in frames if Path(row.filename).resolve() == ROOT / TEST]
            message = str(error[1])
            expected = "None != '31620fc89e03a26d954602ac2ccdaa8984f301871ebbc55196b003bb9c8d3601' : " + case['message']
            self.owned.append({'type': type(error[1]).__name__, 'message_sha256': sha(message.encode()),
                'exact_own_failure': type(error[1]) is AssertionError and message == expected
                and len(own) == 1 and own[0].name == case['method'] and own[0].lineno == expected_site['line'],
                'site': expected_site if len(own) == 1 else None})
        def addError(self, test, error):
            super().addError(test, error)
            self.error_digests.append(sha(str(error[1]).encode()))
    selected = 'test_compatibility_policy.InstalledSdkInventoryTests.' + case['method']
    suite = unittest.defaultTestLoader.loadTestsFromName(selected)
    require(suite.countTestCases() == 1, 'one-actual-metadata-selector')
    result = Result()
    suite.run(result)
    counts = {'executed': result.testsRun, 'passed': result.testsRun - len(result.failures) - len(result.errors) - len(result.skipped),
              'failed': len(result.failures), 'errors': len(result.errors), 'skipped': len(result.skipped)}
    report = {'case': case_id, 'selector': selected, 'counts': counts,
              'owned_failures': result.owned, 'error_message_digests': result.error_digests}
    output.write_text(json.dumps(report, indent=2) + '\n')
    return 0 if result.wasSuccessful() else 1


def main(output):
    require(os.environ.get('GITHUB_ACTIONS') == 'true' and os.environ.get('RUNNER_OS') == 'Linux',
            'remote-Ubuntu-metadata-only')
    require(not output.exists(), 'fresh-metadata-PFP-result')
    output.parent.mkdir(parents=True, exist_ok=True)
    original_context = context(ROOT)
    initial = snapshot()
    require(original_context['HEAD'] == os.environ['GITHUB_SHA'] and original_context['status'] == sha(b''),
            'exact-clean-signed-workflow-source')
    require(all(initial[name][0] == digest for name, digest in INPUTS.items()), 'exact-reviewed-PFP-inputs')
    proof = {'source': original_context['HEAD'], 'metadata_only': True, 'SDK_qualification': False,
             'product_tests_executed': 0, 'native_tests_executed': 0, 'passed': False,
             'source_restored': False, 'phases': [], 'input_sha256': INPUTS}
    def save():
        known = [row['counts'] for row in proof['phases'] if row.get('counts') is not None]
        unknown = [row['label'] for row in proof['phases'] if row.get('invoked') and row.get('counts') is None]
        proof['known_executed'] = sum(row['executed'] for row in known)
        proof['executed'] = None if unknown else proof['known_executed']
        proof['unknown_phases'] = unknown
        output.write_text(json.dumps(proof, indent=2) + '\n')
    previous = {}
    def interrupted(signum, frame):
        raise KeyboardInterrupt(signum)
    held = None
    original = None
    try:
        for sig in (signal.SIGINT, signal.SIGTERM): previous[sig] = signal.signal(sig, interrupted)
        save()
        for case_id, case in CASES.items():
            path = ROOT / case['source']
            original = path.read_bytes()
            inverse = transform(original, case)
            held = ExactSource(ROOT, path, original)
            try:
                for phase in ('baseline', 'mutant', 'restored'):
                    wanted = inverse if phase == 'mutant' else original
                    if held.current != wanted: held.write(held.current, wanted)
                    held.verify(wanted)
                    expected = dict(initial)
                    expected[case['source']] = [sha(wanted), *initial[case['source']][1:]]
                    require(snapshot() == expected, 'only-owned-source-bytes-and-modes-before-body')
                    row = {'label': case_id + '/' + phase, 'invoked': False, 'source_sha256': sha(wanted),
                           'counts': None, 'qualified': False}
                    proof['phases'].append(row)
                    result_path = output.parent / (case_id + '-' + phase + '.json')
                    require(not result_path.exists(), 'fresh-phase-metadata-result')
                    row['invoked'] = True
                    save()
                    environment = dict(os.environ, PYTHONDONTWRITEBYTECODE='1')
                    process = subprocess.run([sys.executable, '-B', str(Path(__file__).resolve()), '--child-case', case_id,
                        '--output', str(result_path)], env=environment, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=90)
                    require(result_path.is_file() and result_path.stat().st_size <= 16384, 'bounded-actual-child-result')
                    raw_result = result_path.read_bytes()
                    require(len(raw_result) <= 16384, 'bounded-actual-child-result-bytes')
                    row['child_result_sha256'] = sha(raw_result)
                    save()  # The raw result digest survives malformed JSON or a non-object root.
                    actual = json.loads(raw_result)
                    counts = actual.get('counts') if type(actual) is dict else None
                    if type(counts) is dict and set(counts) == {'executed', 'passed', 'failed', 'errors', 'skipped'}:
                        if all(type(value) is int and value >= 0 for value in counts.values()) and counts['executed'] == sum(counts[key] for key in ('passed', 'failed', 'errors', 'skipped')):
                            row['counts'] = counts
                    save()  # Keep actual counts before identity, own-failure or closure rejection.
                    mutant = phase == 'mutant'
                    require(type(actual) is dict and set(actual) == {'case', 'selector', 'counts', 'owned_failures', 'error_message_digests'}
                            and actual.get('case') == case_id and actual.get('selector') == 'test_compatibility_policy.InstalledSdkInventoryTests.' + case['method'], 'exact-actual-selected-owner')
                    require(row['counts'] == dict(executed=1, passed=int(not mutant), failed=int(mutant), errors=0, skipped=0)
                            and process.returncode == int(mutant), 'one-actual-positive-or-own-failed-body')
                    failures = actual.get('owned_failures')
                    require(actual.get('error_message_digests') == [] and type(failures) is list
                            and len(failures) == int(mutant), 'closed-no-error-own-failure-cardinality')
                    if mutant:
                        expected_message = "None != '31620fc89e03a26d954602ac2ccdaa8984f301871ebbc55196b003bb9c8d3601' : " + case['message']
                        require(set(failures[0]) == {'type', 'message_sha256', 'exact_own_failure', 'site'}
                                and failures[0].get('type') == 'AssertionError'
                                and failures[0].get('message_sha256') == sha(expected_message.encode())
                                and failures[0].get('exact_own_failure') is True and failures[0].get('site') == site(case),
                                'actual-owned-fixed-header-assertion')
                        row['own_failure'] = failures[0]
                    held.verify(wanted)
                    require(snapshot() == expected and context(ROOT)['HEAD'] == original_context['HEAD']
                            and context(ROOT)['index'] == original_context['index'], 'exact-Git-and-source-closure')
                    row.update(held_FD_inode_mode_verified=True, source_closure_exact=True, qualified=True)
                    save()
            finally:
                if held is not None:
                    try:
                        if held.current != original: held.write(held.current, original)
                        held.verify(original)
                    finally:
                        held.close()
                        held = None
        proof['source_restored'] = context(ROOT) == original_context and snapshot() == initial
        proof['passed'] = proof['source_restored'] and len(proof['phases']) == 6 and all(row['qualified'] for row in proof['phases'])
    except (Exception, KeyboardInterrupt) as error:
        proof['failure_category'] = type(error).__name__
        if isinstance(error, ValueError) and str(error).replace('-', '').isalnum(): proof['failure_label'] = str(error)
    finally:
        for sig, handler in previous.items(): signal.signal(sig, handler)
        proof['source_restored'] = context(ROOT) == original_context and snapshot() == initial
        proof['passed'] = proof['passed'] and proof['source_restored']
        save()
    return 0 if proof['passed'] else 1


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--child-case', choices=list(CASES))
    args = parser.parse_args()
    os.umask(0o077)
    require(os.environ.get('GITHUB_ACTIONS') == 'true' and os.environ.get('RUNNER_OS') == 'Linux', 'remote-Ubuntu-metadata-only')
    raise SystemExit(child(args.child_case, args.output) if args.child_case else main(args.output))
