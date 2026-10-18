"""Qualify the real checkpoint actor and its deadline-postponement mutation."""
import argparse
from contextlib import contextmanager
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import time


ACTOR = "crates/marmot-app/src/runtime/conversation_window.rs"
HARNESS = "crates/marmot-app/src/runtime/conversation_window/tests.rs"
CASES = tuple("runtime::conversation_window::tests::hot_checkpoints_do_not_postpone_" + suffix
              for suffix in ("normal_refresh", "not_ready_retry"))
FEATURES = "wn-cli/test-policy-overrides,cgka-engine/test-policy-overrides,cgka-engine/test-crash-hooks"
ORIGINAL = b"else if checkpoint_ready { refresh_at = refresh_at.min(next); }"
MUTATION = b"else if checkpoint_ready { refresh_at = next; }"
READY_FAILURE = "a continuing checkpoint producer must not postpone a ready refresh until quiet"


def digest(data):
    return hashlib.sha256(data).hexdigest()


def identity(path):
    return dict(sha256=digest(path.read_bytes()), mode=stat.S_IMODE(path.lstat().st_mode),
                file_type=stat.S_IFMT(path.lstat().st_mode),
                resolved_mode=stat.S_IMODE(path.stat().st_mode),
                symlink_target=os.readlink(path) if path.is_symlink() else None)


def inputs(root):
    root = root.resolve(strict=True)
    names = subprocess.check_output(["git", "ls-files", "-z"], cwd=root).split(b"\0")
    result = {}
    for name in names:
        if not name:
            continue
        path = root / name.decode()
        if not path.resolve(strict=True).is_relative_to(root):
            raise ValueError("Tracked input resolves outside the physical source checkout")
        result[name.decode()] = identity(path)
    return result


def input_digest(values):
    return digest(json.dumps(values, sort_keys=True, separators=(",", ":")).encode())


def require_inputs(root, expected):
    observed = inputs(root)
    if observed != expected:
        raise ValueError("Source bytes, file modes or links changed unexpectedly")
    if subprocess.check_output(["git", "ls-files", "--others", "--exclude-standard", "-z"], cwd=root):
        raise ValueError("Unexpected untracked source files")
    return dict(sha256=input_digest(observed), files=len(observed))


def binary_identity(path):
    if path.is_symlink() or not path.is_file() or not path.stat().st_mode & 0o111:
        raise ValueError("Actual test binary must be a regular executable")
    return dict(path=str(path.resolve(strict=True)), size=path.stat().st_size, **identity(path))


@contextmanager
def restore_actor(path, original, mutant):
    try:
        yield
    finally:
        if path.read_bytes() not in (original, mutant):
            raise ValueError("Unexpected actor edit; refusing to overwrite it")
        if path.read_bytes() != original:
            path.write_bytes(original)


def check_case(text, case, code, mutant):
    summaries = re.findall(r"test result: (ok|FAILED)\. (\d+) passed; (\d+) failed; (\d+) ignored;", text)
    expected = ("FAILED", "0", "1", "0") if mutant else ("ok", "1", "0", "0")
    if summaries != [expected] or not re.search(r"^running 1 test$", text, re.M):
        raise ValueError("Expected exactly one nonignored test body")
    status = "FAILED" if mutant else "ok"
    if re.findall(r"^test " + re.escape(case) + r" \.\.\. (ok|FAILED)$", text, re.M) != [status]:
        raise ValueError("Wrong or missing actual test case")
    if mutant:
        if code == 0 or READY_FAILURE not in text:
            raise ValueError("Mutation must fail the real ready-refresh deadline")
        if any(message in text for message in (
                "the checkpoint watch stayed hot throughout the observation",
                "the actor must receive NotReady before checkpoint production",
                "the producer must qualify the hot checkpoint scenario",
                "hot checkpoint production must qualify within the original observation")):
            raise ValueError("Setup or hotness failure cannot qualify the mutation")
    elif code != 0:
        raise ValueError("Unmodified actor must pass")
    return dict(passed=int(expected[1]), failed=int(expected[2]), ignored=0,
                oracle="original ready-refresh deadline" if mutant else "original ready/hot/header/send guards")


def compile_app(root, output, phase):
    command = ["cargo", "test", "--workspace", "--exclude", "cgka-conformance-simulator",
               "--features", FEATURES, "--locked", "--no-run", "--message-format=json"]
    with (output / f"{phase}-compile.jsonl").open("wb") as stdout, \
            (output / f"{phase}-compile.log").open("wb") as stderr:
        result = subprocess.run(command, cwd=root, stdout=stdout, stderr=stderr, timeout=1800)
    if result.returncode:
        raise ValueError(f"{phase} compilation failed: {result.returncode}")
    rows = [json.loads(line) for line in (output / f"{phase}-compile.jsonl").read_text().splitlines()]
    artifacts = [row for row in rows if row.get("reason") == "compiler-artifact"
                 and row.get("target", {}).get("name") == "marmot_app"
                 and row.get("profile", {}).get("test") and row.get("executable")]
    if len(artifacts) != 1 or artifacts[0]["fresh"]:
        raise ValueError("One newly compiled actual App test binary required")
    artifact = artifacts[0]
    if set(artifact["features"]) != {"default", "test-policy-overrides"}:
        raise ValueError("Wrong default feature cohort")
    binary = Path(artifact["executable"])
    return binary, dict(command=command, exit_code=result.returncode, features=artifact["features"],
                        binary_identity=binary_identity(binary), fresh=False,
                        stdout_sha256=digest((output / f"{phase}-compile.jsonl").read_bytes()),
                        stderr_sha256=digest((output / f"{phase}-compile.log").read_bytes()))


def qualify(root, output):
    root = root.resolve(strict=True)
    if output.is_relative_to(root):
        raise ValueError("Evidence must remain outside the source checkout")
    output.mkdir(exist_ok=False)
    proof = output / "proof"
    proof.mkdir()
    subprocess.run(["git", "diff", "--exit-code", "HEAD", "--"], cwd=root, check=True)
    if subprocess.check_output(["git", "status", "--porcelain=v1", "--untracked-files=all"], cwd=root):
        raise ValueError("A clean physical source checkout is required")
    if Path(subprocess.check_output(["git", "rev-parse", "--show-toplevel"], cwd=root, text=True).strip()).resolve() != root:
        raise ValueError("Source root does not match its physical Git checkout")
    baseline = inputs(root)
    actor = root / ACTOR
    original = actor.read_bytes()
    if original.count(ORIGINAL) != 1:
        raise ValueError("Exactly one production checkpoint deadline statement required")
    mutant = original.replace(ORIGINAL, MUTATION)
    state = dict(source=subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=root, text=True).strip(),
                 source_tree=subprocess.check_output(["git", "rev-parse", "HEAD^{tree}"], cwd=root, text=True).strip(),
                 schema=1, source_physical_root=str(root), source_clean_before=True,
                 baseline_inputs=baseline, baseline_inputs_sha256=input_digest(baseline),
                 completed=False, phases=[], scope="Actual default-cohort two-case checkpoint PFP; not full CI or SDK admission")
    if os.environ.get("GITHUB_SHA", state["source"]) != state["source"]:
        raise ValueError("Workflow source differs from the actual checkout")

    def save_state():
        (proof / "checkpoint-proof.json").write_text(json.dumps(state, indent=2) + "\n")

    save_state()
    try:
        with restore_actor(actor, original, mutant):
            # The changed fixture must actually compile even with a restored cache.
            (root / HARNESS).touch()
            for phase, changed in (("baseline", False), ("mutant", True), ("restored", False)):
                if phase != "baseline":
                    actor.write_bytes(mutant if changed else original)
                expected = dict(baseline, **{ACTOR: identity(actor)})
                source_before = require_inputs(root, expected)
                binary, compiled = compile_app(root, output, phase)
                row = dict(phase=phase, actor_identity=expected[ACTOR], compile=compiled,
                           source_before=source_before, source_after_compile=require_inputs(root, expected), cases=[])
                state["phases"].append(row)
                save_state()
                for index, case in enumerate(CASES):
                    log = output / f"{phase}-{index}.log"
                    command = [str(binary), "--exact", case, "--show-output", "--test-threads=1"]
                    before_binary = binary_identity(binary)
                    if before_binary != compiled["binary_identity"]:
                        raise ValueError("Test binary changed after compilation")
                    before_source = require_inputs(root, expected)
                    started = time.monotonic()
                    with log.open("wb") as stream:
                        result = subprocess.run(command, cwd=root, stdout=stream,
                                                stderr=subprocess.STDOUT, timeout=120)
                    case_row = dict(case=case, command=command, exit_code=result.returncode,
                                    seconds=time.monotonic() - started, log_sha256=digest(log.read_bytes()),
                                    binary_before=before_binary, binary_after=binary_identity(binary),
                                    source_before=before_source, source_after=require_inputs(root, expected))
                    row["cases"].append(case_row)
                    save_state()
                    if case_row["binary_after"] != before_binary:
                        raise ValueError("Test binary bytes or modes changed during execution")
                    case_row["actual"] = check_case(log.read_text(), case, result.returncode, changed)
                    save_state()
                row["binary_final"] = binary_identity(binary)
                if row["binary_final"] != compiled["binary_identity"]:
                    raise ValueError("Phase binary did not remain unchanged")
                row["source_final"] = require_inputs(root, expected)
                save_state()
        if inputs(root) != baseline:
            raise ValueError("Final source did not restore exactly")
        subprocess.run(["git", "diff", "--exit-code", "HEAD", "--"], cwd=root, check=True)
        require_inputs(root, baseline)
        state["completed"] = True
    except BaseException as error:
        state["error"] = str(error)
        raise
    finally:
        state["actor_restored"] = actor.read_bytes() == original
        state["inputs_restored"] = inputs(root) == baseline
        state["final_inputs_sha256"] = input_digest(inputs(root))
        state["source_clean_after"] = not subprocess.check_output(
            ["git", "status", "--porcelain=v1", "--untracked-files=all"], cwd=root)
        save_state()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--directory", type=Path, required=True)
    args = parser.parse_args()
    qualify(Path.cwd(), args.directory.resolve())
