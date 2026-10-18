import copy
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from recover_archive_gaps import (fetch, prepare_plan, validate_origin, validate_pr_checkout,
                                  verify_selection, without_failure_recap)
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
    def test_original_nextest_failed_summary_recap_is_one_retained_failure(self):
        failed = line(status="FAIL")
        summary = "2026-10-18T21:59:35Z Summary [10.0s] 1/2 tests run: 0 passed, 1 failed\n"
        passed, failures, plan = prepare_plan(inventory(), {"1": failed + summary + failed}, 2)
        self.assertEqual(passed, [])
        self.assertEqual([(r["test"], r["status"]) for r in failures], [("complete", "FAIL")])
        self.assertEqual([r["test"] for p in plan for r in p["cases"]], ["missing"])

    def test_only_identical_failed_summary_recap_is_allowed(self):
        summary = "2026-10-18T21:59:35Z Summary [10.0s] 1/2 tests run: 0 passed, 1 failed\n"
        for status in ("FAIL", "TIMEOUT", "LEAK"):
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
                    complete.replace("PASS", "FAIL", 1), complete.replace("missing", "unknown")):
            with self.subTest(log=bad), self.assertRaises(ValueError):
                verify_selection(plan[0], inventory(), bad)


if __name__ == "__main__":
    unittest.main()
