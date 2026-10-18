import copy
import unittest

from recover_archive_gaps import prepare_plan, validate_origin, verify_selection
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


class ArchiveGapTests(unittest.TestCase):
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
