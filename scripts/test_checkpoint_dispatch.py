"""Check the default checkpoint diagnostic command without running Rust tests."""
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import textwrap
import unittest


WORKFLOW = Path(__file__).resolve().parents[1] / ".github/workflows/experimental-sync-ci.yml"
SCOPE = "default-checkpoint-diagnostic"
CASE = "runtime::conversation_window::tests::hot_checkpoints_do_not_postpone_not_ready_retry"
FEATURES = "wn-cli/test-policy-overrides,cgka-engine/test-policy-overrides,cgka-engine/test-crash-hooks"


class CheckpointDispatchTests(unittest.TestCase):
    def test_scope_routes_to_the_focused_job(self):
        workflow = WORKFLOW.read_text()
        options = re.search(r"options: \[(.*?)\]", workflow).group(1).split(", ")
        job = workflow.split("  core-regressions:\n", 1)[1].split("    name:", 1)[0]
        routes = json.loads(re.search(r"fromJSON\('([^']+)'\)", job).group(1))
        self.assertIn(SCOPE, options)
        self.assertIn(SCOPE, routes)

    def test_exact_default_features_and_inventory_are_required(self):
        workflow = WORKFLOW.read_text()
        start = workflow.index("      - name: Run selected affected regressions without retries\n")
        step = workflow[start:workflow.index("      - uses:", start)]
        script = textwrap.dedent(step.split("        run: |\n", 1)[1])
        for mode in ("exact", "empty", "extra", "ignored", "wrong-suite"):
            with self.subTest(mode=mode), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                cargo = root / "cargo"
                cargo.write_text("#!" + sys.executable + "\n" + textwrap.dedent('''
                    import json, os, sys
                    from pathlib import Path
                    args = sys.argv[1:]
                    if args[:2] == ['nextest', 'list']:
                        case = {'ignored': os.environ['MODE'] == 'ignored',
                                'filter-match': {'status': 'matches'}}
                        cases = {} if os.environ['MODE'] == 'empty' else {os.environ['CASE']: case}
                        if os.environ['MODE'] == 'extra': cases['extra'] = case
                        suite = 'wrong' if os.environ['MODE'] == 'wrong-suite' else 'marmot-app'
                        print(json.dumps({'rust-suites': {suite: {'testcases': cases}}}))
                    elif args[:2] == ['nextest', 'run']:
                        Path('command.json').write_text(json.dumps(args))
                    else:
                        raise SystemExit('unexpected cargo command')
                '''))
                cargo.chmod(0o700)
                env = dict(os.environ, PATH=str(root) + os.pathsep + os.environ['PATH'],
                           REGRESSION_SCOPE=SCOPE, MODE=mode, CASE=CASE)
                result = subprocess.run(['bash', '-c', script], cwd=root, env=env,
                                        capture_output=True, text=True)
                command = root / 'command.json'
                if mode != 'exact':
                    self.assertNotEqual(result.returncode, 0)
                    self.assertFalse(command.exists())
                    continue
                self.assertEqual(result.returncode, 0, result.stderr)
                args = json.loads(command.read_text())
                self.assertIn('--workspace', args)
                for option, value in (('--exclude', 'cgka-conformance-simulator'),
                                      ('--features', FEATURES), ('--retries', '0'),
                                      ('--test-threads', '6'), ('--profile', 'm5-bounded')):
                    self.assertEqual(args[args.index(option) + 1], value)
                self.assertEqual(args[args.index('-E') + 1], f'package(marmot-app) & test(={CASE})')
                self.assertIn('--locked', args)


if __name__ == '__main__':
    unittest.main()
