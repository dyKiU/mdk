#!/usr/bin/env python3
"""Closed exact-source real-worker wiring evidence; no SDK or raw-log exports."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import selectors
import shutil
import signal
import stat
import subprocess
import time

WORKER = "crates/marmot-app/src/runtime/account_worker.rs"
TEST = "crates/marmot-app/src/runtime/account_worker/attachments/tests/legacy_migration.rs"
CASE = "runtime::account_worker::attachments::tests::legacy_migration::real_account_worker_migrates_legacy_body_and_wakes_observers"
HELPER = "scripts/qualify_upstream_legacy_worker.py"
WORKFLOW = ".github/workflows/upstream-legacy-worker.yml"
MESSAGE = "real account worker maintenance must migrate legacy bodies and wake observers"
CALL = re.compile(rb"(?m)^[ \t]*attachments::spawn_legacy_migration\(\s*&client,\s*&shared,\s*&mut attachment_admission,\s*\);")
FEATURES = "marmot-app/otlp-export,marmot-app/product-analytics-export,marmot-app/test-policy-overrides,cgka-engine/test-policy-overrides,cgka-engine/test-crash-hooks"
LIMIT = 32 * 1024 * 1024


def git(*args):
    return subprocess.check_output(["git", *args])


def sha(data):
    return hashlib.sha256(data).hexdigest()


def capture(command, seconds=1800):
    # Finite RAM only, continuously drained even when capped. No raw file/log.
    process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                               start_new_session=True)
    selected = selectors.DefaultSelector()
    selected.register(process.stdout, selectors.EVENT_READ)
    output = bytearray()
    deadline = time.monotonic() + seconds
    overflow = False
    timed_out = False
    try:
        while selected.get_map():
            if time.monotonic() >= deadline:
                timed_out = True
                os.killpg(process.pid, signal.SIGTERM)
                break
            for key, _ in selected.select(min(1.0, max(0.0, deadline-time.monotonic()))):
                chunk = os.read(key.fileobj.fileno(), 65536)
                if not chunk:
                    selected.unregister(key.fileobj)
                    continue
                if len(output) + len(chunk) > LIMIT:
                    overflow = True
                output.extend(chunk[:max(0, LIMIT-len(output))])
        try:
            code = process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            os.killpg(process.pid, signal.SIGKILL)
            code = process.wait(timeout=5)
        return code, output.decode("utf-8", "replace"), overflow, timed_out
    finally:
        selected.close()
        process.stdout.close()
        if process.poll() is None:
            os.killpg(process.pid, signal.SIGKILL)
            process.wait(timeout=5)


def compiler_facts(text):
    codes = sorted(set(re.findall(r"(?m)^error\[(E[0-9]{4})\]", text)))
    sites = []
    for path, line, column in re.findall(r"(?m)^\s*--> ([^\n]+):(\d+):(\d+)\s*$", text):
        if path in {TEST, WORKER}:
            sites.append({"source":path,"line":int(line),"column":int(column)})
    return {"compiler_codes":codes,"known_compiler_sites":sites}


def physical(path):
    current = Path.cwd()
    for part in Path(path).parts:
        current = current/part
        assert not current.is_symlink(), "symlink_input"


def untracked_clean(output):
    names = git("ls-files", "--others", "--exclude-standard", "-z").decode().split("\0")
    return all(not name or name == str(output/"result.json") or
               (name.startswith("scripts/__pycache__/qualify_upstream_legacy_worker.") and name.endswith(".pyc")) for name in names)


def modes():
    return {name:stat.S_IMODE(Path(name).lstat().st_mode)
            for name in git("ls-files", "-z").decode().split("\0") if name}


def worker_fd(expected, writable=False):
    # Walk admitted directories by fd, never follow a replaced parent or leaf.
    parts = Path(WORKER).parts
    fd = os.open(".", os.O_RDONLY | os.O_DIRECTORY)
    try:
        for depth, part in enumerate(parts[:-1], 1):
            following = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
            os.close(fd)
            fd = following
            item = os.fstat(fd)
            assert (item.st_dev,item.st_ino) == expected[depth-1], "worker_parent_changed"
        leaf = os.open(parts[-1], (os.O_RDWR if writable else os.O_RDONLY) | os.O_NOFOLLOW, dir_fd=fd)
    finally:
        os.close(fd)
    item = os.fstat(leaf)
    if (item.st_dev,item.st_ino) != expected[-1] or not stat.S_ISREG(item.st_mode):
        os.close(leaf)
        raise AssertionError("worker_leaf_changed")
    return leaf


def restore_or_write(data, mode, expected):
    fd = worker_fd(expected, writable=True)
    try:
        with os.fdopen(os.dup(fd), "rb") as reader:
            current = reader.read(len(data)+1)
        if current != data:
            os.lseek(fd,0,os.SEEK_SET)
            os.ftruncate(fd,0)
            remaining = memoryview(data)
            while remaining:
                count = os.write(fd,remaining)
                assert count > 0, "worker_write"
                remaining = remaining[count:]
        if stat.S_IMODE(os.fstat(fd).st_mode) != mode:
            os.fchmod(fd,mode)
    finally:
        os.close(fd)


def body(command, intended_line):
    started = time.monotonic()
    code, text, overflow, timed_out = capture(command)
    summaries = re.findall(r"^test result: (ok|FAILED)\. (\d+) passed; (\d+) failed; (\d+) ignored; (\d+) measured; (\d+) filtered out;", text, re.M)
    methods = re.findall(r"^test (\S+) \.\.\. ", text, re.M)
    statuses = re.findall(r"^(?:test \S+ \.\.\. )?(ok|FAILED|ignored)\s*$", text, re.M)
    row = {"exit_code": code, "output_truncated": overflow, "timed_out": timed_out,
           "duration_seconds": round(time.monotonic()-started, 3), "summary": None,
           "exact_one": False, "intended_assertion": False, "panic_category": "unknown"}
    if len(summaries) == 1:
        status, passed, failed, ignored, measured, filtered = summaries[0]
        counts = dict(zip(["passed", "failed", "ignored", "measured", "filtered"], map(int, [passed, failed, ignored, measured, filtered])))
        row["summary"] = counts
        row["exact_one"] = (not overflow and not timed_out and counts["passed"]+counts["failed"] == 1
                            and counts["ignored"] == 0 and counts["measured"] == 0
                            and methods == [CASE]
                            and statuses == ["ok" if counts["passed"] else "FAILED"]
                            and re.findall(r"^running (\d+) test(?:s)?$", text, re.M) == ["1"]
                            and status == ("ok" if counts["passed"] else "FAILED"))
    panics = re.findall(r"(?m)^thread '[^'\n]+'(?: \([^\n]*\))? panicked at ([^\n]+):(\d+):(\d+):\n([^\n]*)", text)
    if len(panics) == 1:
        location, line, column, message = panics[0]
        if location.replace("\\", "/").endswith(TEST) and int(line) == intended_line and message.strip() == MESSAGE:
            row["intended_assertion"] = True
            row["panic_category"] = "missing_worker_migration_or_observer_wake"
            row["panic_line"] = int(line)
    row.update(compiler_facts(text))
    del text
    return row


def passing(row):
    return row["exact_one"] and row["exit_code"] == 0 and row["summary"]["passed"] == 1 and not row["intended_assertion"]


def intended_red(row):
    return row["exact_one"] and row["exit_code"] != 0 and row["summary"]["failed"] == 1 and row["intended_assertion"]


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--source", required=True)
    parser.add_argument("--mode", choices=["preflight", "red", "green", "chain"], required=True)
    parser.add_argument("--cohort", choices=["default", "experimental"], default="default")
    parser.add_argument("--identity-only", action="store_true")
    parser.add_argument("--output", required=True)
    args = parser.parse_args()
    report = {"schema": 1, "source_sha": args.source, "mode": args.mode, "cohort": args.cohort,
              "case": CASE, "complete": False, "product_qualified": False, "phases": [],
              "source_restored": False, "no_sdk_or_native_packaging": True}
    output = Path(args.output)
    assert args.output in {"legacy-worker-runtime", "legacy-worker-preparation"}
    physical(output.parent)
    output.mkdir(parents=True, exist_ok=False)
    original = None
    original_mode = None
    worker_identity = None
    tracked_modes = None
    initial_head = None
    try:
        assert re.fullmatch("[0-9a-f]{40}", args.source), "source_identity"
        head = git("rev-parse", "HEAD").decode().strip()
        assert head == os.environ["GITHUB_SHA"], "tool_identity"
        initial_head = head
        report["tooling_sha"] = head
        subprocess.run(["git", "merge-base", "--is-ancestor", args.source, head], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        changed = set(git("diff", "--name-only", args.source, head).decode().splitlines())
        assert changed <= {HELPER, WORKFLOW}, "source_tool_diff"
        assert not git("status", "--porcelain", "--untracked-files=no").strip(), "dirty_checkout"
        assert untracked_clean(output), "unexpected_untracked"
        tracked_modes = modes()
        report["initial_tracked_modes_sha256"] = sha(json.dumps(tracked_modes,sort_keys=True).encode())
        for name in [HELPER, WORKFLOW]:
            physical(name)
        report["source_tree"] = git("rev-parse", args.source+"^{tree}").decode().strip()
        guards = [WORKER, TEST, "Cargo.lock", "Cargo.toml", "rust-toolchain.toml"]
        report["inputs"] = {}
        for name in guards:
            physical(name)
            data = Path(name).read_bytes()
            assert data == git("show", args.source+":"+name), "physical_source_mismatch"
            git_mode = git("ls-tree", args.source, "--", name).decode().split()[0]
            expected_mode = int(git_mode, 8) & 0o777
            assert stat.S_IMODE(Path(name).stat().st_mode) == expected_mode, "physical_source_mode"
            report["inputs"][name] = {"sha256": sha(data), "mode": expected_mode}
        worker_parts = Path(WORKER).parts
        worker_identity = []
        for depth in range(1,len(worker_parts)+1):
            item = Path(*worker_parts[:depth]).stat()
            worker_identity.append((item.st_dev,item.st_ino))
        original = Path(WORKER).read_bytes()
        original_mode = stat.S_IMODE(Path(WORKER).stat().st_mode)
        test = Path(TEST).read_text()
        site = re.search(r"assert!\(\s*moved\.is_ok\(\),", test)
        assert site and test.count(MESSAGE) == 1, "test_oracle"
        intended_line = test[:site.start()].count("\n")+1
        hooks = len(CALL.findall(original))
        assert hooks == (0 if args.mode == "red" else 1) or args.mode == "preflight", "worker_hook_shape"
        report["hook_count"] = hooks
        report["intended_assertion_line"] = intended_line
        if args.identity_only:
            report["identity_only"] = True
            report["complete"] = True
            return
        assert args.mode != "preflight", "preflight_cannot_execute"
        for name, value in {"CARGO_INCREMENTAL":"1", "CARGO_BUILD_JOBS":"2", "CARGO_PROFILE_DEV_DEBUG":"0", "CARGO_PROFILE_TEST_DEBUG":"0", "RUST_MIN_STACK":"4194304"}.items():
            assert os.environ.get(name) == value, "compiler_environment"
        for name in ["RUSTFLAGS","CARGO_ENCODED_RUSTFLAGS","RUSTDOCFLAGS","CARGO_ENCODED_RUSTDOCFLAGS",
                     "RUSTC_WRAPPER","RUSTC_WORKSPACE_WRAPPER","RUSTC_BOOTSTRAP","RUSTC","RUSTDOC"]:
            assert not os.environ.get(name), "unapproved_compiler_override"
        assert not any(value and name.startswith("CARGO_TARGET_") and name.endswith("_RUSTFLAGS") for name,value in os.environ.items()), "unapproved_target_compiler_flags"
        report["compiler_environment"] = {name:os.environ[name] for name in ["CARGO_INCREMENTAL","CARGO_BUILD_JOBS","CARGO_PROFILE_DEV_DEBUG","CARGO_PROFILE_TEST_DEBUG","RUST_MIN_STACK"]}
        channels = re.findall(r'^channel\s*=\s*"([0-9]+\.[0-9]+\.[0-9]+)"\s*$',Path("rust-toolchain.toml").read_text(),re.M)
        assert len(channels) == 1, "source_toolchain_pin"
        for binary, flags in [("rustc", ["-Vv"]), ("cargo", ["-V"])]:
            code, value, overflow, timed_out = capture([binary]+flags, 30)
            assert code == 0 and not overflow and not timed_out, "toolchain_unavailable"
            report[binary] = value.strip()
            if binary == "rustc":
                assert re.findall(r"^release: (\S+)$",value,re.M) == channels, "actual_toolchain_mismatch"
        target = Path(os.environ.get("CARGO_TARGET_DIR", "target"))
        expected_target = Path.cwd().resolve()/"target"
        assert target.resolve() == expected_target and not target.is_symlink(), "physical_target"
        report["physical_target"] = "target"
        free = shutil.disk_usage(".").free
        report["free_bytes_before"] = free
        assert free >= 8*1024**3, "insufficient_capacity"
        features = FEATURES + (",marmot-app/experimental-device-sync" if args.cohort == "experimental" else "")
        command = ["cargo","test","--locked","-p","marmot-app","--lib","--features",features,CASE,"--","--exact"]
        report["command"] = command + ["--nocapture","--test-threads=1","--format=pretty"]
        code, listing, overflow, timed_out = capture(command+["--list"])
        names = re.findall(r"^(\S+): test$", listing, re.M)
        report["inventory"] = {"exit_code":code,"exact_case_count":len(names),"exact_name_match":names==[CASE],"output_truncated":overflow,"timed_out":timed_out}
        report["inventory"].update(compiler_facts(listing))
        del listing
        assert code == 0 and not overflow and not timed_out and names == [CASE], "exact_inventory"
        first = body(report["command"], intended_line)
        report["phases"].append({"name":"red" if args.mode == "red" else "baseline", **first})
        assert (intended_red(first) if args.mode == "red" else passing(first)), "initial_runtime_verdict"
        if args.mode == "chain":
            mutant, substitutions = CALL.subn(b"", original)
            assert substitutions == 1 and mutant != original, "mutation_shape"
            restore_or_write(mutant,original_mode,worker_identity)
            report["mutant_sha256"] = sha(mutant)
            try:
                mutant_row = body(report["command"], intended_line)
                report["phases"].append({"name":"omit_worker_hook", **mutant_row})
            finally:
                restore_or_write(original,original_mode,worker_identity)
            restored_row = body(report["command"], intended_line)
            report["phases"].append({"name":"restored", **restored_row})
            assert intended_red(mutant_row) and passing(restored_row), "mutation_chain_verdict"
        report["complete"] = True
    except Exception as error:
        # Fixed categories only; never export exception text or command output.
        report["error_category"] = type(error).__name__ if type(error).__name__ in {"AssertionError","CalledProcessError","TimeoutExpired","FileNotFoundError","OSError"} else "unknown"
        raise SystemExit(1)
    finally:
        try:
            if original is not None:
                restore_or_write(original,original_mode,worker_identity)
                report["source_restored"] = Path(WORKER).read_bytes() == original and stat.S_IMODE(Path(WORKER).stat().st_mode) == original_mode
                report["restored_worker_sha256"] = sha(Path(WORKER).read_bytes())
            if report.get("inputs"):
                for name in report["inputs"]:
                    physical(name)
                report["all_guarded_inputs_pristine"] = all(Path(name).read_bytes() == git("show", args.source+":"+name) and stat.S_IMODE(Path(name).stat().st_mode) == item["mode"] for name,item in report["inputs"].items())
                report["whole_checkout_pristine"] = (git("rev-parse","HEAD").decode().strip() == initial_head
                    and subprocess.run(["git","diff","--quiet"],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL).returncode == 0
                    and subprocess.run(["git","diff","--cached","--quiet"],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL).returncode == 0
                    and modes() == tracked_modes and untracked_clean(output))
                if not report["all_guarded_inputs_pristine"] or not report["source_restored"] or not report["whole_checkout_pristine"]:
                    report["complete"] = False
        except Exception:
            report["closure_error"] = "source_restoration_or_identity_unknown"
            report["complete"] = False
        (output/"result.json").write_text(json.dumps(report,indent=2)+"\n")
        print(json.dumps({"complete":report["complete"],"mode":args.mode,"cohort":args.cohort,"actual_bodies":len(report["phases"])}))
        if not report["complete"]:
            raise SystemExit(1)


if __name__ == "__main__":
    main()
