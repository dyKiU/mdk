"""Remote filesystem metadata regressions; no SDK, Xcode or native execution."""
import argparse
import ast
import hashlib
import json
import os
from pathlib import Path
import runpy
import subprocess
import sys
import tempfile
import unittest

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
RUNNER = HERE / 'factory_semantic_runner.py'
ADAPTER = HERE / 'paired-direct-mutations.py'
UI = HERE / 'hosted-app-ui.py'
UNIT = HERE / 'hosted-app-unit.py'
OBSERVED = {}
MESSAGES = {
    'factory-build': "factory build driver capture must remain outside the child's reserved prefix",
    'factory-unit': "factory unit driver capture must remain outside the child's reserved prefix",
    'adapter-build': "adapter build driver capture must remain outside the child's reserved prefix",
}
CHILD = r'''
import ast,json,sys,runpy
from pathlib import Path
from types import SimpleNamespace
here,folder,kind,prefix_name=Path(sys.argv[1]),Path(sys.argv[2]),sys.argv[3],sys.argv[4]
prefix=folder/prefix_name
sys.path.insert(0,str(here))
try:
    if kind=='factory-unit':
        source=here/'hosted-app-unit.py'
        tree=ast.parse(source.read_text())
        guards=[node for node in ast.walk(tree) if isinstance(node,ast.If)
                and len(node.body)==1 and isinstance(node.body[0],ast.Raise)
                and isinstance(node.body[0].exc,ast.Call)
                and isinstance(node.body[0].exc.func,ast.Name) and node.body[0].exc.func.id=='ValueError'
                and len(node.body[0].exc.args)==1 and isinstance(node.body[0].exc.args[0],ast.Constant)
                and node.body[0].exc.args[0].value=='Private environment and fresh outputs required']
        assert len(guards)==1
        args=SimpleNamespace(environment=folder/'environment.json',result_bundle=folder/'unit.xcresult',prefix=prefix)
        # Execute the exact source-owned inline guard, with actual filesystem paths.
        exec(compile(ast.Module(body=guards,type_ignores=[]),str(source),'exec'),{'args':args})
    else:
        runpy.run_path(str(here/'hosted-app-ui.py'),run_name='source_owned_ui')['reserve_paths'](prefix,folder/'build-bridge')
    outcome={'reserved':True,'category':None}
except ValueError as error:
    allowed={'prefix-must-be-fresh','Private environment and fresh outputs required'}
    if str(error) not in allowed: raise
    outcome={'reserved':False,'category':'prefix-collision'}
(folder/'observed.json').write_text(json.dumps(outcome))
raise SystemExit(0 if outcome['reserved'] else 3)
'''


def folder_name(node):
    if not (isinstance(node, ast.BinOp) and isinstance(node.op, ast.Div)
            and isinstance(node.left, ast.Name) and node.left.id == 'folder'
            and isinstance(node.right, ast.Constant) and type(node.right.value) is str
            and '/' not in node.right.value):
        raise ValueError('one-source-owned-folder-basename-required')
    return node.right.value


def layout(case):
    path = ADAPTER if case == 'adapter-build' else RUNNER
    raw = path.read_bytes()
    tree = ast.parse(raw)
    if case == 'adapter-build':
        candidates = [node for node in ast.walk(tree) if isinstance(node, ast.With)
            and len(node.items) == 1 and isinstance(node.items[0].context_expr, ast.Call)
            and isinstance(node.items[0].context_expr.func, ast.Attribute)
            and node.items[0].context_expr.func.attr == 'open'
            and isinstance(node.items[0].context_expr.func.value, ast.BinOp)
            and len(node.body) == 1 and isinstance(node.body[0], ast.Assign)
            and isinstance(node.body[0].value, ast.Call)
            and isinstance(node.body[0].value.func, ast.Attribute)
            and isinstance(node.body[0].value.func.value, ast.Name)
            and node.body[0].value.func.value.id == 'subprocess'
            and node.body[0].value.func.attr == 'run'
            and node.body[0].value.args and isinstance(node.body[0].value.args[0], ast.Name)
            and node.body[0].value.args[0].id == 'build']
        if len(candidates) != 1: raise ValueError('one-actual-adapter-build-capture-required')
        capture = folder_name(candidates[0].items[0].context_expr.func.value)
        assignments = [node for node in ast.walk(tree) if isinstance(node, ast.Assign)
            and len(node.targets) == 1 and isinstance(node.targets[0], ast.Name) and node.targets[0].id == 'prefix']
        if len(assignments) != 1: raise ValueError('one-actual-adapter-build-prefix-required')
        prefix = folder_name(assignments[0].value)
        return prefix, capture, candidates[0]
    command = 'command' if case == 'factory-unit' else 'build'
    calls = [node for node in ast.walk(tree) if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Name) and node.func.id == 'invoke' and len(node.args) == 2
        and isinstance(node.args[0], ast.Name) and node.args[0].id == command]
    if len(calls) != 1: raise ValueError('one-actual-factory-capture-required')
    capture = folder_name(calls[0].args[1])
    if case == 'factory-build':
        assignments = [node for node in ast.walk(tree) if isinstance(node, ast.Assign)
            and len(node.targets) == 1 and isinstance(node.targets[0], ast.Name) and node.targets[0].id == 'build_prefix']
        if len(assignments) != 1: raise ValueError('one-actual-factory-build-prefix-required')
        prefix = folder_name(assignments[0].value)
    else:
        assignments = [node for node in ast.walk(tree) if isinstance(node, ast.Assign)
            and len(node.targets) == 1 and isinstance(node.targets[0], ast.Tuple)
            and [getattr(item, 'id', None) for item in node.targets[0].elts] == ['bundle', 'unit_prefix']]
        if len(assignments) != 1 or not isinstance(assignments[0].value, ast.Tuple):
            raise ValueError('one-actual-factory-unit-prefix-required')
        prefix = folder_name(assignments[0].value.elts[1])
    return prefix, capture, None


def exercise(case, override=None):
    prefix, capture, adapter = layout(case)
    if override is not None: capture = override
    with tempfile.TemporaryDirectory(prefix='native-prefix-metadata-') as temporary:
        folder = Path(temporary)
        environment = folder / 'environment.json'; environment.write_text('{}'); environment.chmod(0o600)
        command = [sys.executable, '-B', '-c', CHILD, str(HERE), str(folder), case, prefix]
        if adapter is None:
            # run_path compiles the actual file, avoiding same-size stale bytecode during PFP.
            invoke = runpy.run_path(str(RUNNER), run_name='source_owned_factory_runner')['invoke']
            code = invoke(command, folder / capture, environment=os.environ.copy(), timeout=10)
        else:
            # The original source-owned open/Popen statement, without its Xcode command.
            statement = ast.parse(ast.unparse(adapter)).body[0]
            statement.items[0].context_expr.func.value = ast.BinOp(
                left=ast.Name(id='folder', ctx=ast.Load()), op=ast.Div(), right=ast.Constant(value=capture))
            ast.fix_missing_locations(statement)
            namespace = {'folder': folder, 'build': command, 'subprocess': subprocess}
            exec(compile(ast.Module(body=[statement], type_ignores=[]), str(ADAPTER), 'exec'), namespace)
            code = namespace['result'].returncode
        observed = json.loads((folder / 'observed.json').read_text())
        if set(observed) != {'reserved', 'category'} or type(observed['reserved']) is not bool:
            raise ValueError('closed-actual-reservation-result-required')
        if observed['category'] not in (None, 'prefix-collision') or code != (0 if observed['reserved'] else 3):
            raise ValueError('exact-actual-child-result-required')
        observed['parent_capture_exists'] = (folder / capture).is_file()
        observed['child_exit_code'] = code
    observed['temporary_removed'] = not folder.exists()
    return observed


class NativePrefixLayoutTests(unittest.TestCase):
    def check_case(self, case):
        prefix, _, _ = layout(case)
        old = prefix + ('-private.log' if case == 'adapter-build' else '-driver-private.log')
        negative = exercise(case, old)
        separated = exercise(case, 'driver-' + prefix + '-private.log')
        actual = exercise(case)
        OBSERVED[case] = {'negative': negative, 'separated': separated, 'actual': actual}
        self.assertFalse(negative['reserved'], 'the actual freshness guard must reject occupied prefixes')
        self.assertTrue(separated['reserved'], 'the actual freshness guard must permit a separate namespace')
        self.assertTrue(all(row['parent_capture_exists'] and row['temporary_removed']
                            for row in (negative, separated, actual)), 'metadata children and cleanup must complete')
        self.assertTrue(actual['reserved'], MESSAGES[case])

    def test_factory_build(self): self.check_case('factory-build')
    def test_factory_unit(self): self.check_case('factory-unit')
    def test_adapter_build(self): self.check_case('adapter-build')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--result', type=Path, required=True)
    args = parser.parse_args()
    if os.environ.get('GITHUB_ACTIONS') != 'true': raise ValueError('remote-metadata-only-required')
    result = unittest.TextTestRunner(verbosity=2).run(unittest.defaultTestLoader.loadTestsFromTestCase(NativePrefixLayoutTests))
    proof = {'schema': 1, 'metadata_only': True, 'product_tests_executed': 0, 'native_tests_executed': 0,
             'executed': result.testsRun, 'passed': result.testsRun-len(result.failures)-len(result.errors)-len(result.skipped),
             'failed': len(result.failures), 'errors': len(result.errors), 'skipped': len(result.skipped),
             'failure_tests': [test._testMethodName for test, _ in result.failures],
             'error_tests': [test._testMethodName for test, _ in result.errors], 'observations': OBSERVED,
             'files': {str(path.relative_to(ROOT)): hashlib.sha256(path.read_bytes()).hexdigest()
                       for path in (Path(__file__).resolve(), RUNNER, ADAPTER, UI, UNIT)}}
    args.result.parent.mkdir(parents=True, exist_ok=True)
    with args.result.open('x') as stream: json.dump(proof, stream, indent=2); stream.write('\n')
    return 0 if result.wasSuccessful() else 1


if __name__ == '__main__':
    raise SystemExit(main())
