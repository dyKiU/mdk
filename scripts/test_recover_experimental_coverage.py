import unittest

from recover_experimental_coverage import recover


def inventory():
    return {"rust-suites": {"engine": {
        "package-name": "engine", "binary-name": "engine",
        "testcases": {name: {"ignored": ignored, "filter-match": {"status": status}}
                      for name, ignored, status in [
                          ("complete", False, "matches"),
                          ("missing", False, "matches"),
                          ("child", True, "mismatch")]}}}}


def line(name="complete", status="PASS"):
    return f"2026-10-14T04:00:00Z         {status} [ 0.01s] ( 1/2) engine {name}\n"


class CoverageTests(unittest.TestCase):
    def test_reuses_only_clean_passes_and_retains_missing_cases(self):
        passed, remaining = recover(inventory(), {"1": "\x1b[32m" + line() + "\x1b[0m"})
        self.assertEqual([r["test"] for r in passed], ["complete"])
        self.assertEqual([(r["test"], r["status"]) for r in remaining],
                         [("missing", "uncompleted")])

    def test_failures_timeouts_and_leaks_require_execution(self):
        for status in ("FAIL", "TIMEOUT", "LEAK"):
            with self.subTest(status=status):
                passed, remaining = recover(inventory(), {"1": line(status=status)})
                self.assertEqual(passed, [])
                self.assertEqual(remaining[0]["status"], status)

    def test_empty_inventory_refused(self):
        with self.assertRaisesRegex(ValueError, "Empty"):
            recover({"rust-suites": {}}, {})

    def test_unknown_and_ignored_terminal_cases_refused(self):
        for name in ("unknown", "child"):
            with self.subTest(name=name), self.assertRaisesRegex(ValueError, "absent"):
                recover(inventory(), {"1": line(name=name)})

    def test_duplicate_case_cannot_mask_a_failure_or_overlap(self):
        with self.assertRaisesRegex(ValueError, "Duplicate"):
            recover(inventory(), {"1": line(status="FAIL"), "2": line()})


if __name__ == "__main__":
    unittest.main()
