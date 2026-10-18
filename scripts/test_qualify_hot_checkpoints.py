"""Mechanical acceptance for qualification counts, oracle and restoration."""
from pathlib import Path
import re
import tempfile
import unittest

from qualify_hot_checkpoints import CASES, READY_FAILURE, check_case, restore_actor


class CheckpointQualificationTests(unittest.TestCase):
    def output(self, mutant=False):
        return (f"running 1 test\ntest {CASES[0]} ... " + ("FAILED" if mutant else "ok")
                + "\ntest result: " + ("FAILED. 0 passed; 1 failed;" if mutant else "ok. 1 passed; 0 failed;")
                + " 0 ignored; 0 measured; 100 filtered out;\n" + (READY_FAILURE if mutant else ""))

    def test_actual_pass_and_ready_failure_are_accepted(self):
        check_case(self.output(), CASES[0], 0, False)
        check_case(self.output(True), CASES[0], 101, True)

    def test_missing_ignored_duplicate_wrong_case_and_exit_are_refused(self):
        for text, code in (("", 0), (self.output().replace("1 passed", "0 passed"), 0),
                           (self.output().replace("0 ignored", "1 ignored"), 0),
                           (self.output() * 2, 0), (self.output().replace(CASES[0], CASES[1]), 0),
                           (self.output(), 1)):
            with self.subTest(text=text, code=code), self.assertRaises(ValueError):
                check_case(text, CASES[0], code, False)

    def test_wrong_mutation_failure_does_not_qualify(self):
        for text, code in ((self.output(True).replace(READY_FAILURE, "setup failed"), 101),
                           (self.output(True), 0),
                           (self.output(True) + "the checkpoint watch stayed hot throughout the observation", 101),
                           (self.output(True) + "hot checkpoint production must qualify within the original observation", 101)):
            with self.subTest(text=text, code=code), self.assertRaises(ValueError):
                check_case(text, CASES[0], code, True)

    def test_actor_restores_even_when_a_phase_fails(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "actor"
            path.write_bytes(b"original")
            with self.assertRaisesRegex(RuntimeError, "compile failure"):
                with restore_actor(path, b"original", b"mutant"):
                    path.write_bytes(b"mutant")
                    raise RuntimeError("compile failure")
            self.assertEqual(path.read_bytes(), b"original")

    def test_unexpected_actor_edit_is_preserved_and_refused(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "actor"
            path.write_bytes(b"unrelated")
            with self.assertRaises(ValueError):
                with restore_actor(path, b"original", b"mutant"):
                    pass
            self.assertEqual(path.read_bytes(), b"unrelated")

    def test_workflow_offers_only_one_manual_proof_job(self):
        workflow = (Path(__file__).resolve().parents[1] / ".github/workflows/experimental-sync-ci.yml").read_text()
        options = re.search(r"options: \[(.*?)\]", workflow).group(1).split(", ")
        self.assertIn("default-checkpoint-regression", options)
        job = workflow.split("  checkpoint-refresh-proof:\n", 1)[1].split("  core-regressions:\n", 1)[0]
        self.assertIn("github.event_name == 'workflow_dispatch' && inputs.scope == 'default-checkpoint-regression'", job)
        self.assertIn('CARGO_INCREMENTAL: "1"', job)
        self.assertEqual(job.count('run: python3 scripts/qualify_hot_checkpoints.py --directory "$RUNNER_TEMP/checkpoint-proof"'), 1)
        other = workflow.split("  core-regressions:\n", 1)[1].split("    name:", 1)[0]
        self.assertNotIn("default-checkpoint-regression", other)


if __name__ == "__main__":
    unittest.main()
