"""Mechanical acceptance for qualification counts, oracle and restoration."""
from pathlib import Path
import re
import subprocess
import tempfile
import unittest

from qualify_hot_checkpoints import CASES, READY_FAILURE, binary_identity, check_case, inputs, restore_actor


class CheckpointQualificationTests(unittest.TestCase):
    def test_input_identity_detects_mode_only_changes(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            subprocess.run(["git", "init", "-q", str(root)], check=True)
            path = root / "source"
            path.write_text("unchanged bytes")
            path.chmod(0o644)
            subprocess.run(["git", "add", "source"], cwd=root, check=True)
            before = inputs(root)
            path.chmod(0o755)
            self.assertNotEqual(inputs(root), before)

    def test_source_identity_refuses_a_symlink_outside_the_checkout(self):
        with tempfile.TemporaryDirectory() as directory:
            parent = Path(directory)
            root = parent / "repo"
            subprocess.run(["git", "init", "-q", str(root)], check=True)
            (parent / "outside").write_text("synthetic source")
            (root / "source").symlink_to(parent / "outside")
            subprocess.run(["git", "add", "source"], cwd=root, check=True)
            with self.assertRaises(ValueError):
                inputs(root)

    def test_binary_identity_binds_bytes_modes_and_regular_executable(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "binary"
            path.write_bytes(b"synthetic executable")
            path.chmod(0o755)
            before = binary_identity(path)
            path.chmod(0o700)
            self.assertNotEqual(binary_identity(path), before)
            path.write_bytes(b"changed synthetic executable")
            self.assertNotEqual(binary_identity(path)["sha256"], before["sha256"])
            link = path.with_name("link")
            link.symlink_to(path)
            with self.assertRaises(ValueError):
                binary_identity(link)
            path.chmod(0o644)
            with self.assertRaises(ValueError):
                binary_identity(path)

    def test_case_status_must_agree_with_its_summary(self):
        for mutant in (False, True):
            text = self.output(mutant)
            original = " ... FAILED" if mutant else " ... ok"
            replacement = " ... ok" if mutant else " ... FAILED"
            with self.subTest(mutant=mutant), self.assertRaises(ValueError):
                check_case(text.replace(original, replacement), CASES[0], 101 if mutant else 0, mutant)

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
        self.assertIn('path: ${{ runner.temp }}/checkpoint-proof/proof/checkpoint-proof.json', job)
        other = workflow.split("  core-regressions:\n", 1)[1].split("    name:", 1)[0]
        self.assertNotIn("default-checkpoint-regression", other)


if __name__ == "__main__":
    unittest.main()
