import copy
import hashlib
import json
import os
import re
import subprocess
import sys
import textwrap
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from recover_archive_gaps import (fetch, plan as write_plan, prepare_plan, validate_origin, validate_pr_checkout,
                                  verify_selection, without_failure_recap, workflow_partition_count, source_partition_count)
from test_recover_experimental_coverage import inventory, line


def origin():
    source = "a" * 40
    run = dict(id=7, head_sha=source, run_attempt=1, repository=dict(full_name="dyKiU/mdk"),
               path=".github/workflows/ci.yml", status="completed", event="workflow_dispatch")
    jobs = [dict(id=i, run_id=7, head_sha=source, run_attempt=1, status="completed",
                 name=f"Rust tests ({i}/5)") for i in range(1, 6)]
    artifact = dict(name="rust-test", expired=False, digest="sha256:" + "b" * 64,
                    workflow_run=dict(id=7, head_sha=source))
    return run, jobs, artifact


def pr_origin():
    run, jobs, artifact = origin()
    run.update(event="pull_request", pull_requests=[dict(head=dict(sha=run["head_sha"]))])
    jobs.append(dict(id=9, run_id=7, head_sha=run["head_sha"], run_attempt=1,
                     status="completed", conclusion="success", name="Build workspace tests"))
    return run, jobs, artifact


def simulator_origin():
    run, jobs, artifact = pr_origin()
    jobs = [dict(jobs[i - 1], name=f"Simulator and vectors (smoke-{i})") for i in (1, 2)] + [
        dict(jobs[-1], name="Build simulator tests")]
    artifact["name"] = "simulator-tests"
    return run, jobs, artifact


class ArchiveGapTests(unittest.TestCase):
    def test_real_current_source_workflows_bind_twelve_partitions(self):
        import subprocess
        root = Path(__file__).resolve().parents[1]
        source = subprocess.check_output(["git", "-C", str(root), "rev-parse", "HEAD"], text=True).strip()
        # This draft is for Root's reviewed twelve-partition union, not the
        # owner's historical five-partition checkout. Both objects are real Git.
        for cohort in ("default", "experimental"):
            self.assertEqual(source_partition_count(source, cohort), 12)

    def test_actual_public_cancel_partition_diagnostic_is_manual_and_preserves_full_twelve(self):
        root = Path(__file__).resolve().parents[1]
        text = (root / ".github/workflows/experimental-sync-ci.yml").read_text()
        scope = "public-cancel-partition8-diagnostic"
        options = re.search(r"options: \[(.*?)\]", text).group(1).split(", ")
        self.assertIn(scope, options)
        union = text.split("  workflow-union-preflight:\n", 1)[1].split("    name:", 1)[0]
        routes = json.loads(re.search(r"fromJSON\('([^']+)'\)", union).group(1))
        self.assertIn(scope, routes)
        for job in ("experimental-test-build", "experimental-test"):
            starts = list(re.finditer(r"(?m)^  " + re.escape(job) + r":\n", text))
            self.assertEqual(len(starts), 1)
            start = starts[0].end()
            next_job = re.search(r"(?m)^  [A-Za-z0-9_-]+:\n", text[start:])
            block = text[start:start + next_job.start()] if next_job else text[start:]
            conditions = re.findall(r"(?m)^    if: (.+)$", block)
            self.assertEqual(conditions, ["github.event_name != 'workflow_dispatch' || inputs.scope == 'full' || inputs.scope == '" + scope + "'"])
        for event, selected_scope in (("push", scope), ("pull_request", scope),
                                      ("workflow_dispatch", "full"), ("workflow_dispatch", ""),
                                      ("workflow_dispatch", "public-cancel-snapshot-diagnostic")):
            self.assertEqual(workflow_partition_count(text, "experimental", event=event, scope=selected_scope), 12)
        self.assertEqual(workflow_partition_count(text, "experimental", event="workflow_dispatch", scope=scope), 1)
        # Corrupt actual expression branches/condition; no unknown conditional is admitted.
        expression = re.search(r"(?m)^        partition: (\$\{\{[^\n]+)$", text).group(1)
        for bad in (expression.replace("'[8]'", "'[7]'"),
                    expression.replace("workflow_dispatch", "push"),
                    expression.replace("'[1, 2,", "'[2, 1,"),
                    expression.replace("inputs.scope", "inputs.other_scope")):
            with self.assertRaises((ValueError, json.JSONDecodeError)):
                workflow_partition_count(text.replace(expression, bad, 1), "experimental", event="workflow_dispatch", scope=scope)

    def test_actual_partition_eight_inventory_guard_rejects_count_or_required_case_drift(self):
        root = Path(__file__).resolve().parents[1]
        text = (root / ".github/workflows/experimental-sync-ci.yml").read_text()
        step = text.split("      - name: Require exact original partition-eight diagnostic inventory\n", 1)[1].split("      - name:", 1)[0]
        script = textwrap.dedent(step.split("        run: |\n", 1)[1])
        required = "native_device_linking::automatic_pairing_acceptance::late_peer_proof_negative_acceptance::late_peer_proof_public_cancel_cannot_complete_original"
        for mode in ("exact", "short", "extra", "missing-required", "wrong-suite", "required-ignored", "untyped-ignored"):
            with self.subTest(mode=mode), tempfile.TemporaryDirectory() as directory:
                work = Path(directory)
                cargo = work / "cargo"
                cargo.write_text("#!" + sys.executable + "\n" + textwrap.dedent("""
                    import json, os, sys
                    from pathlib import Path
                    args = sys.argv[1:]
                    Path('invocation.json').write_text(json.dumps(args))
                    count = 719 if os.environ['MODE'] == 'short' else 721 if os.environ['MODE'] == 'extra' else 720
                    case = {'ignored': False, 'filter-match': {'status': 'matches'}}
                    cases = {f'metadata_case_{index}': dict(case) for index in range(count - 1)}
                    name = 'wrong_case' if os.environ['MODE'] == 'missing-required' else os.environ['REQUIRED_CASE']
                    cases[name] = dict(case)
                    if os.environ['MODE'] == 'required-ignored': cases[name]['ignored'] = True
                    if os.environ['MODE'] == 'untyped-ignored': cases[name]['ignored'] = 'false'
                    suite = 'wrong-suite' if os.environ['MODE'] == 'wrong-suite' else 'marmot-app'
                    print(json.dumps({'rust-suites': {suite: {'testcases': cases}}}))
                """))
                cargo.chmod(0o700)
                env = dict(os.environ, PATH=str(work) + os.pathsep + os.environ['PATH'],
                           GITHUB_WORKSPACE=str(work), MODE=mode, REQUIRED_CASE=required)
                result = subprocess.run(['bash', '-c', script], cwd=work, env=env,
                                        capture_output=True, text=True)
                self.assertEqual(result.returncode == 0, mode == "exact")
                args = json.loads((work / 'invocation.json').read_text())
                self.assertEqual(args[:2], ['nextest', 'list'])
                self.assertEqual(args[args.index('--partition') + 1], 'count:8/12')
                self.assertEqual(args[args.index('--archive-file') + 1], 'experimental-tests.tar.zst')
                self.assertEqual(args[args.index('--workspace-remap') + 1], str(work))

    def test_current_twelve_partition_origin_exact_union(self):
        run, jobs, artifact = origin()
        jobs = [dict(jobs[0], id=i, name=f"Rust tests ({i}/12)") for i in range(1, 13)]
        self.assertEqual(len(validate_origin(run, jobs, artifact, "default", 7, "a" * 40,
                                             expected_partitions=12)), 12)
        for count in (True, 0, 7, 13):
            with self.assertRaises(ValueError):
                validate_origin(run, jobs, artifact, "default", 7, "a" * 40,
                                expected_partitions=count)

    def test_current_twelve_partition_omission_is_refused(self):
        run, jobs, artifact = origin()
        jobs = [dict(jobs[0], id=i, name=f"Rust tests ({i}/12)") for i in range(1, 12)]
        with self.assertRaisesRegex(ValueError, "Distinct terminal original cohort partitions"):
            validate_origin(run, jobs, artifact, "default", 7, "a" * 40,
                            expected_partitions=12)

    def test_current_partition_extra_duplicate_mixed_and_foreign_roles_refused(self):
        run, jobs, artifact = origin()
        full = [dict(jobs[0], id=i, name=f"Rust tests ({i}/12)") for i in range(1, 13)]
        variants = [full + [dict(full[0], id=13, name="Rust tests (13/12)")],
                    full + [full[0]], full[:-1] + [dict(full[-1], name="Rust tests (12/5)")],
                    full + [dict(full[0], id=13, name="Rust tests (1/5)")],
                    full + [dict(full[0], id=13, name="Rust tests (foreign)")]]
        for changed in variants:
            with self.assertRaises(ValueError):
                validate_origin(run, changed, artifact, "default", 7, "a" * 40,
                                expected_partitions=12)

    def test_workflow_literal_partition_contract_matches_archive_and_runtime(self):
        def workflow(count):
            return ("jobs:\n  rust-test-build:\n    steps:\n      - run: |\n"
                + f"          bash scripts/check_ci_partitions.sh {count} --locked\n"
                + "  rust-test:\n    name: Rust tests (${{ matrix.partition }}/" + str(count) + ")\n"
                + "    strategy:\n      matrix:\n        partition: "
                + json.dumps(list(range(1, count + 1))) + "\n"
                + "    steps:\n      - run: cargo nextest run --partition count:${{ matrix.partition }}/" + str(count) + "\n")
        for count in (5, 12):
            self.assertEqual(workflow_partition_count(workflow(count), "default"), count)
        good = workflow(12)
        variants = [good.replace("[1, 2,", "[1, 1,"),
                    good.replace(", 12]", "]"), good.replace(", 12]", ", 12, 13]"),
                    good.replace("}/12", "}/5"), good.replace("}/12", "}/120"),
                    good.replace("check_ci_partitions.sh 12", "check_ci_partitions.sh 5"),
                    good + "  rust-test:\n", good.replace("partition: [1,", "partition: [true,"),
                    good.replace("partition: [", "partition: ${{ inputs.parts }} # [")]
        for changed in variants:
            with self.assertRaises((ValueError, json.JSONDecodeError)):
                workflow_partition_count(changed, "default")

    def test_aborted_original_body_is_a_retained_failure_not_missing_work(self):
        summary = "2026-10-18T21:59:35Z Summary [42.2s] 1/2 tests run: 0 passed, 1 failed\n"
        for status in ("SIGABRT", "SIGSEGV", "SIGKILL", "EXECFAIL", "SIGTERM"):
            aborted = line(status=status)
            passed, failures, plan = prepare_plan(inventory(), {"1": aborted + summary + aborted}, 2)
            with self.subTest(status=status):
                self.assertEqual(passed, [])
                self.assertEqual([(r["test"], r["status"]) for r in failures], [("complete", status)])
                self.assertEqual([r["test"] for p in plan for r in p["cases"]], ["missing"])

    def test_later_job_cancellation_cannot_erase_an_earlier_sigterm_failure(self):
        earlier = line(status="SIGTERM")
        marker = "2026-10-19T09:00:00Z The operation was canceled.\n"
        _, failures, selected = prepare_plan(
            inventory(), {"1": earlier + marker}, 2, interrupted_jobs={"1"})
        self.assertEqual([row["status"] for row in failures], ["SIGTERM"])
        self.assertEqual([row["test"] for part in selected for row in part["cases"]], ["missing"])

    def test_ambiguous_sigterm_stays_a_failure_even_in_a_cancelled_job(self):
        marker = "The operation was canceled.\n"
        logs = {"1": line(status="SIGTERM") + marker}
        _, failures, selected = prepare_plan(inventory(), logs, 2, interrupted_jobs={"1"})
        self.assertEqual([row["status"] for row in failures], ["SIGTERM"])
        self.assertEqual({r["test"] for p in selected for r in p["cases"]}, {"missing"})
        self.assertEqual(prepare_plan(inventory(), logs, 2)[1][0]["status"], "SIGTERM")
        for changed, interrupted in (({"1": line(status="SIGTERM")}, {"1"}), (logs, {"2"})):
            with self.assertRaises(ValueError):
                prepare_plan(inventory(), changed, 2, interrupted_jobs=interrupted)
        self.assertEqual(prepare_plan(inventory(), {"1": line(status="SIGABRT") + marker}, 2,
                                      interrupted_jobs={"1"})[1][0]["status"], "SIGABRT")

    def test_plan_reads_original_cancelled_job_metadata_without_erasing_failures(self):
        run, jobs, artifact = origin()
        for job in jobs:
            job["conclusion"] = "cancelled" if job["id"] == 2 else "success"
        logs = {str(job["id"]): "" for job in jobs}
        logs["1"] = line()
        logs["2"] = line("missing", "SIGTERM") + "The operation was canceled.\n"
        provenance = dict(source=run["head_sha"], run=7, cohort="default",
                          original_log_hashes={n: hashlib.sha256(raw.encode()).hexdigest()
                                               for n, raw in logs.items()})
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for name, value in (("original-run", run), ("original-jobs", jobs),
                                ("original-artifact", artifact), ("provenance", provenance),
                                ("inventory", inventory())):
                (root / (name + ".json")).write_text(json.dumps(value))
            for name, raw in logs.items():
                (root / (name + ".log")).write_text(raw)
            args = SimpleNamespace(directory=root, inventory=root / "inventory.json", partitions=2,
                                   github_output=root / "output")
            with patch("recover_archive_gaps.source_partition_count", return_value=5):
                write_plan(args)
            summary = json.loads((root / "summary.json").read_text())
            self.assertEqual((summary["retained_passes"], summary["original_failures"], summary["missing"]), (1, 1, 0))
            self.assertFalse(summary["qualified"])
            jobs[1]["conclusion"] = "failure"
            (root / "original-jobs.json").write_text(json.dumps(jobs))
            with patch("recover_archive_gaps.source_partition_count", return_value=5):
                write_plan(args)
            summary = json.loads((root / "summary.json").read_text())
            self.assertEqual((summary["retained_passes"], summary["original_failures"], summary["missing"]), (1, 1, 0))
            self.assertEqual(json.loads((root / "retained-failures.json").read_text())[0]["status"], "SIGTERM")

    def test_original_nextest_failed_summary_recap_is_one_retained_failure(self):
        failed = line(status="FAIL")
        summary = "2026-10-18T21:59:35Z Summary [10.0s] 1/2 tests run: 0 passed, 1 failed\n"
        passed, failures, plan = prepare_plan(inventory(), {"1": failed + summary + failed}, 2)
        self.assertEqual(passed, [])
        self.assertEqual([(r["test"], r["status"]) for r in failures], [("complete", "FAIL")])
        self.assertEqual([r["test"] for p in plan for r in p["cases"]], ["missing"])

    def test_only_identical_failed_summary_recap_is_allowed(self):
        summary = "2026-10-18T21:59:35Z Summary [10.0s] 1/2 tests run: 0 passed, 1 failed\n"
        for status in ("FAIL", "TIMEOUT", "LEAK", "SIGABRT", "SIGSEGV", "EXECFAIL"):
            failed = line(status=status)
            passed, failures, _ = prepare_plan(inventory(), {"1": failed + summary + failed}, 2)
            self.assertEqual((passed, [r["status"] for r in failures]), ([], [status]))
        failed = line(status="FAIL")
        for changed in (failed + failed, failed + summary + failed + failed,
                        failed + summary + line(), line() + summary + failed,
                        failed + summary + line("unknown", "FAIL"),
                        failed + summary + failed.replace("0.01s", "0.02s"),
                        failed + summary + failed.replace("1/2", "2/2")):
            with self.subTest(log=changed), self.assertRaises(ValueError):
                prepare_plan(inventory(), {"1": changed}, 2)
        with self.assertRaises(ValueError):
            prepare_plan(inventory(), {"1": failed, "2": failed}, 2)
        self.assertEqual(without_failure_recap(line()), line())

    def test_simulator_requires_exact_two_smoke_partitions_and_own_producer(self):
        run, jobs, artifact = simulator_origin()
        self.assertEqual([j["id"] for j in validate_origin(run, jobs, artifact, "simulator", 7, "a" * 40)],
                         [1, 2])
        unrelated = dict(jobs[0], id=10, name="Simulator and vectors (models)")
        self.assertEqual(len(validate_origin(run, jobs + [unrelated], artifact, "simulator", 7,
                                            "a" * 40)), 2)
        variants = [jobs[1:], jobs + [jobs[0]],
                    jobs + [dict(jobs[0], id=10, name="Simulator and vectors (smoke-3)")],
                    [dict(jobs[0], name="Rust tests (1/5)")] + jobs[1:],
                    [dict(jobs[0], head_sha="c" * 40)] + jobs[1:],
                    [dict(jobs[0], run_attempt=2)] + jobs[1:],
                    [dict(jobs[0], status="in_progress")] + jobs[1:],
                    jobs[:-1] + [dict(jobs[-1], name="Build workspace tests")]]
        for changed in variants:
            with self.subTest(jobs=changed), self.assertRaises(ValueError):
                validate_origin(run, changed, artifact, "simulator", 7, "a" * 40)
        with self.assertRaises(ValueError):
            validate_origin(run, jobs, dict(artifact, name="rust-test"), "simulator", 7, "a" * 40)

    def test_pr_origin_requires_exact_head_and_successful_archive_producer(self):
        run, jobs, artifact = pr_origin()
        self.assertEqual(len(validate_origin(run, jobs, artifact, "default", 7, "a" * 40)), 5)
        for heads in ([], [dict(head=dict(sha="c" * 40))],
                      [dict(head=dict(sha="a" * 40)), dict(head=dict(sha="c" * 40))]):
            with self.subTest(heads=heads), self.assertRaises(ValueError):
                validate_origin(dict(run, pull_requests=heads), jobs, artifact, "default", 7, "a" * 40)
        for changed in (jobs[:-1], jobs + [jobs[-1]],
                        jobs[:-1] + [dict(jobs[-1], conclusion="failure")],
                        jobs[:-1] + [dict(jobs[-1], status="in_progress")],
                        jobs[:-1] + [dict(jobs[-1], head_sha="c" * 40)],
                        jobs[:-1] + [dict(jobs[-1], run_attempt=2)],
                        jobs[:-1] + [dict(jobs[-1], run_id=8)],
                        jobs[:-1] + [dict(jobs[-1], id=jobs[0]["id"])]):
            with self.subTest(producer=changed), self.assertRaises(ValueError):
                validate_origin(run, changed, artifact, "default", 7, "a" * 40)

    def test_experimental_pr_uses_its_own_workflow_producer_and_partitions(self):
        run, jobs, artifact = pr_origin()
        run["path"] = ".github/workflows/experimental-sync-ci.yml"
        artifact["name"] = "experimental-sync-tests"
        for job in jobs[:-1]:
            job["name"] = job["name"].replace("Rust tests", "Experimental sync tests")
        with self.assertRaises(ValueError):
            validate_origin(run, jobs, artifact, "experimental", 7, "a" * 40)
        jobs[-1]["name"] = "Build experimental sync tests"
        self.assertEqual(len(validate_origin(run, jobs, artifact, "experimental", 7, "a" * 40)), 5)

    def test_pr_checkout_requires_single_exact_source_and_tree_in_raw_output(self):
        source, tree = "a" * 40, "b" * 40
        plain = f"qualification-source: {source}\nqualification-tree: {tree}\n"
        validate_pr_checkout(plain, source, tree)
        raw = "\n".join("2026-10-18T21:47:49.1234567Z \x1b[32m" + line + "\x1b[0m"
                        for line in plain.splitlines())
        validate_pr_checkout(raw, source, tree)
        for changed in ("", plain.splitlines()[0], plain + plain,
                        plain.replace(source, "c" * 40), plain.replace(tree, "c" * 40),
                        plain + "qualification-source: malformed\n",
                        'echo "qualification-source: ' + source + '"\n' + plain.splitlines()[1]):
            with self.subTest(log=changed), self.assertRaises(ValueError):
                validate_pr_checkout(changed, source, tree)

    def test_pr_fetch_rejects_checkout_mismatch_before_downloading_large_archive(self):
        run, jobs, artifact = pr_origin()
        calls = []

        def execute(command, **kwargs):
            calls.append(command)
            if command[0] == "gh":
                self.assertTrue(command[-1].endswith("/logs"))
                kwargs["stdout"].write(b"qualification-source: " + b"c" * 40 + b"\n"
                                       b"qualification-tree: " + b"b" * 40 + b"\n")

        with tempfile.TemporaryDirectory() as tmp, \
                patch("recover_archive_gaps.gh_json", side_effect=[[run], [dict(jobs=jobs)],
                                                                   [dict(artifacts=[artifact])]]), \
                patch("recover_archive_gaps.subprocess.run", side_effect=execute), \
                patch("recover_archive_gaps.source_partition_count", return_value=5), \
                patch("recover_archive_gaps.subprocess.check_output", return_value="b" * 40 + "\n"):
            args = SimpleNamespace(run=7, source="a" * 40, cohort="default",
                                   directory=Path(tmp) / "fresh")
            with self.assertRaisesRegex(ValueError, "checkout source/tree"):
                fetch(args)
            self.assertFalse((args.directory / "original.zip").exists())
            self.assertFalse((args.directory / "provenance.json").exists())
        self.assertEqual(len(calls), 2)  # ancestry validation and one raw job log, no archive

    def test_origin_requires_exact_repository_source_attempt_and_finished_run(self):
        run, jobs, artifact = origin()
        self.assertEqual(len(validate_origin(run, jobs, artifact, "default", 7, "a" * 40)), 5)
        for field, value in (("head_sha", "c" * 40), ("run_attempt", 2),
                             ("status", "in_progress"), ("path", "other.yml"),
                             ("repository", dict(full_name="other/mdk"))):
            changed = dict(run, **{field: value})
            with self.subTest(field=field), self.assertRaises(ValueError):
                validate_origin(changed, jobs, artifact, "default", 7, "a" * 40)

    def test_artifact_cannot_be_expired_unhashed_or_from_another_run(self):
        run, jobs, artifact = origin()
        for field, value in (("expired", True), ("digest", ""), ("name", "other"),
                             ("workflow_run", dict(id=8, head_sha="a" * 40))):
            with self.subTest(field=field), self.assertRaises(ValueError):
                validate_origin(run, jobs, dict(artifact, **{field: value}), "default", 7, "a" * 40)

    def test_partial_duplicate_or_retried_partition_metadata_is_refused(self):
        run, jobs, artifact = origin()
        variants = [jobs[:-1], jobs + [jobs[0]], [dict(j, run_attempt=2) for j in jobs],
                    [dict(j, head_sha="b" * 40) for j in jobs]]
        for changed in variants:
            with self.assertRaises(ValueError):
                validate_origin(run, changed, artifact, "default", 7, "a" * 40)

    def test_original_failure_is_retained_and_never_scheduled_as_a_retry(self):
        for status in ("FAIL", "TIMEOUT", "LEAK"):
            passed, failures, plan = prepare_plan(inventory(), {"1": line(status=status)}, 2)
            self.assertEqual(passed, [])
            self.assertEqual([(r["test"], r["status"]) for r in failures], [("complete", status)])
            self.assertEqual([r["test"] for p in plan for r in p["cases"]], ["missing"])

    def test_passed_and_ignored_cases_are_not_repeated(self):
        passed, failures, plan = prepare_plan(inventory(), {"1": line()}, 3)
        self.assertEqual([r["test"] for r in passed], ["complete"])
        self.assertEqual(failures, [])
        self.assertEqual([r["test"] for p in plan for r in p["cases"]], ["missing"])

    def test_cli_cases_are_not_replaced_by_legacy_followup_roles(self):
        data = inventory()
        data["rust-suites"]["engine"]["package-name"] = "wn-cli"
        passed, failures, plan = prepare_plan(data, {}, 3)
        self.assertEqual((passed, failures), ([], []))
        self.assertEqual(sum(r["count"] for r in plan), 2)

    def test_an_archive_with_complete_coverage_has_no_matrix_jobs(self):
        passed, failures, plan = prepare_plan(inventory(), {"1": line() + line("missing")}, 8)
        self.assertEqual(len(passed), 2)
        self.assertEqual((failures, plan), ([], []))

    def test_actual_selection_must_equal_nonempty_frozen_plan(self):
        _, _, plan = prepare_plan(inventory(), {}, 1)
        verify_selection(plan[0], inventory())
        data = copy.deepcopy(inventory())
        data["rust-suites"]["engine"]["testcases"]["missing"]["ignored"] = True
        with self.assertRaises(ValueError):
            verify_selection(plan[0], data)
        with self.assertRaises(ValueError):
            verify_selection(dict(count=0, cases=[]), inventory())

    def test_each_missing_body_must_terminate_once_with_pass(self):
        _, _, plan = prepare_plan(inventory(), {}, 1)
        complete = "PASS [ 0.01s] ( 1/2) engine complete\nPASS [ 0.01s] ( 2/2) engine missing\n"
        verify_selection(plan[0], inventory(), complete)
        for bad in ("", complete.splitlines()[0], complete + complete,
                    complete.replace("PASS", "FAIL", 1), complete.replace("missing", "unknown"),
                    complete.replace("PASS", "SIGABRT", 1),
                    complete + "SIGSEGV [ 0.1s] ( 1/2) engine unexpected\n"):
            with self.subTest(log=bad), self.assertRaises(ValueError):
                verify_selection(plan[0], inventory(), bad)


if __name__ == "__main__":
    unittest.main()
