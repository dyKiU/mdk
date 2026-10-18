"""Qualify the real checkpoint actor and its deadline-postponement mutation."""
import argparse
from contextlib import contextmanager
import hashlib
import json
from pathlib import Path
import re
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


def inputs(root):
    names = subprocess.check_output(["git", "ls-files", "-z"], cwd=root).split(b"\0")
    return {name.decode(): digest((root / name.decode()).read_bytes()) for name in names if name}


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
    if not re.search(r"^test " + re.escape(case) + r" \.\.\. (ok|FAILED)$", text, re.M):
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
    if set(artifact["features"]) & {"experimental-device-sync", "otlp-export", "product-analytics-export"}:
        raise ValueError("Wrong default feature cohort")
    binary = Path(artifact["executable"])
    return binary, dict(command=command, exit_code=result.returncode, features=artifact["features"],
                        binary_sha256=digest(binary.read_bytes()),
                        stdout_sha256=digest((output / f"{phase}-compile.jsonl").read_bytes()),
                        stderr_sha256=digest((output / f"{phase}-compile.log").read_bytes()))


def qualify(root, output):
    output.mkdir(exist_ok=False)
    subprocess.run(["git", "diff", "--exit-code", "HEAD", "--"], cwd=root, check=True)
    baseline = inputs(root)
    actor = root / ACTOR
    original = actor.read_bytes()
    if original.count(ORIGINAL) != 1:
        raise ValueError("Exactly one production checkpoint deadline statement required")
    mutant = original.replace(ORIGINAL, MUTATION)
    (output / "inputs.json").write_text(json.dumps(baseline, indent=2) + "\n")
    state = dict(source=subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=root, text=True).strip(),
                 source_tree=subprocess.check_output(["git", "rev-parse", "HEAD^{tree}"], cwd=root, text=True).strip(),
                 completed=False, phases=[], scope="Actual default-cohort two-case checkpoint PFP; not full CI or SDK admission")

    def save_state():
        (output / "status.json").write_text(json.dumps(state, indent=2) + "\n")

    save_state()
    try:
        with restore_actor(actor, original, mutant):
            # The changed fixture must actually compile even with a restored cache.
            (root / HARNESS).touch()
            for phase, changed in (("baseline", False), ("mutant", True), ("restored", False)):
                if phase != "baseline":
                    actor.write_bytes(mutant if changed else original)
                expected = dict(baseline, **{ACTOR: digest(actor.read_bytes())})
                if inputs(root) != expected:
                    raise ValueError("Unexpected source before compilation")
                binary, compiled = compile_app(root, output, phase)
                row = dict(phase=phase, actor_sha256=expected[ACTOR], compile=compiled, cases=[])
                state["phases"].append(row)
                save_state()
                for index, case in enumerate(CASES):
                    log = output / f"{phase}-{index}.log"
                    command = [str(binary), "--exact", case, "--show-output", "--test-threads=1"]
                    started = time.monotonic()
                    with log.open("wb") as stream:
                        result = subprocess.run(command, cwd=root, stdout=stream,
                                                stderr=subprocess.STDOUT, timeout=120)
                    row["cases"].append(dict(case=case, command=command, exit_code=result.returncode,
                                             seconds=time.monotonic() - started, log_sha256=digest(log.read_bytes())))
                    save_state()
                    check_case(log.read_text(), case, result.returncode, changed)
                    if inputs(root) != expected:
                        raise ValueError("Unexpected source during qualification")
        if inputs(root) != baseline:
            raise ValueError("Final source did not restore exactly")
        subprocess.run(["git", "diff", "--exit-code", "HEAD", "--"], cwd=root, check=True)
        state["completed"] = True
    except BaseException as error:
        state["error"] = str(error)
        raise
    finally:
        state["actor_restored"] = actor.read_bytes() == original
        state["inputs_restored"] = inputs(root) == baseline
        save_state()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--directory", type=Path, required=True)
    args = parser.parse_args()
    qualify(Path.cwd(), args.directory.resolve())
