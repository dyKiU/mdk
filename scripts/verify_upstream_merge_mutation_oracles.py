#!/usr/bin/env python3
"""Remote-only replay of retained full runtime logs; never execute Cargo."""
import ast
import hashlib
import json
import os
from pathlib import Path
import re
import tempfile
from types import SimpleNamespace

if os.environ.get("GITHUB_ACTIONS") != "true":
    raise SystemExit("Run parser replay only in remote GitHub Actions")
root = Path(__file__).resolve().parents[1]
controller = root / "scripts/verify_upstream_merge_mutations.py"
tree = ast.parse(controller.read_text(), filename=str(controller))
main = next(n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == "main")
start = next(i for i, n in enumerate(main.body) if isinstance(n, ast.Assign)
             and any(isinstance(t, ast.Name) and t.id == "routing_oracle_source" for t in n.targets))
end = next(i for i, n in enumerate(main.body) if isinstance(n, ast.FunctionDef) and n.name == "run")
# Execute only source-oracle validation and the actual parser function. Main,
# mutation construction, source writes, and Cargo execution are never evaluated.
fragment = ast.Module(body=main.body[start:end + 1], type_ignores=[])
context = {"root": root, "hashlib": hashlib, "re": re}
context["routing_tests"] = root / "crates/transport-nostr-adapter/tests/inbound_routing.rs"
context["status"] = root / "crates/marmot-c/src/status.rs"
context["frozen"] = {context["routing_tests"]: context["routing_tests"].read_bytes()}
context["originals"] = {context["status"]: context["status"].read_bytes()}
exec(compile(fragment, str(controller), "exec"), context)
fixtures = root / ".github/fixtures/merge-mutation-oracles"
manifest = json.loads((fixtures / "manifest.json").read_text())
report = {"controller_sha256": hashlib.sha256(controller.read_bytes()).hexdigest(),
          "fixture_source": manifest["source_commit"], "product_commands_executed": 0,
          "source_oracle_preflight_passed": True, "checks": [], "passed": False}


def replay(spec, label, text, code, expected):
    with tempfile.TemporaryDirectory() as directory:
        context["output"] = Path(directory)
        def fake_run(command, *, cwd, stdout, stderr):
            if command != [spec["test"], "--", "--exact", "--test-threads=1"]:
                raise AssertionError("Unexpected parser replay command")
            stdout.write(text)
            return SimpleNamespace(returncode=code)
        context["subprocess"] = SimpleNamespace(run=fake_run, STDOUT=-2)
        result = context["run"](spec["name"] + "-mutant", [], spec["test"])
    row = {"name": spec["name"], "control": label, "expected_behavioral_red": expected,
           "actual_behavioral_red": result["behavioral_red"], "parser_result": result}
    report["checks"].append(row)
    if result["behavioral_red"] != expected:
        raise AssertionError("Parser accepted an unrelated failure or rejected actual evidence")


try:
    for spec in manifest["logs"]:
        data = (fixtures / spec["file"]).read_bytes()
        if hashlib.sha256(data).hexdigest() != spec["sha256"]:
            raise AssertionError("Historical runtime fixture hash mismatch")
        text = data.decode()
        replay(spec, "actual-full-retained-log", text, spec["exit_code"], True)
        message = context["source_oracles"][spec["name"]][1]
        replay(spec, "unrelated-panic", text.replace(message, "unrelated prerequisite failure", 1), 101, False)
        expected_file = context["source_oracles"][spec["name"]][0]
        replay(spec, "wrong-panic-source", text.replace(" panicked at " + expected_file, " panicked at unrelated.rs", 1), 101, False)
        replay(spec, "wrong-panic-thread", text.replace("thread '" + spec["test"] + "'", "thread 'unrelated-worker'", 1), 101, False)
        replay(spec, "exit-one", text, 1, False)
        replay(spec, "surviving-exit-zero", text, 0, False)
        replay(spec, "colored-compiler-diagnostic", text + "\n\x1b[31merror[E0308]\x1b[0m: mismatched types\n", 101, False)
        zero = text.replace("running 1 test", "running 0 tests", 1).replace(
            "FAILED. 0 passed; 1 failed; 0 ignored;", "ok. 0 passed; 0 failed; 0 ignored;", 1)
        replay(spec, "zero-body", zero, 101, False)
    report["passed"] = len(report["checks"]) == 32
finally:
    output = root / "mutation-oracle-parser-proof"
    output.mkdir(exist_ok=True)
    (output / "result.json").write_text(json.dumps(report, indent=2) + "\n")
if not report["passed"]:
    raise SystemExit("Mutation parser replay did not satisfy every control")
