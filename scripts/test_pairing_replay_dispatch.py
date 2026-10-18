"""Execute the pairing workflow selector without compiling protocol code."""
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import textwrap
import unittest


WORKFLOW = Path(__file__).resolve().parents[1] / ".github/workflows/experimental-sync-ci.yml"
PREFIX = "native_device_linking::automatic_pairing_acceptance::"
FOURTH = PREFIX + "third_and_later_device_enrollment_need_no_extra_qr_or_manual_artifacts"
CONSENT = PREFIX + "blocked_sibling_consent_does_not_starve_another_approved_peer"
EXPECTED = {
    "pairing-diagnostic": {FOURTH},
    "pairing-consent-fairness": {CONSENT},
    "pairing-restart-diagnostic": {
        "native_device_linking::tests::pending_lower_request_recovers_after_higher_restarts_before_consent"
    },
    "pairing-restart-higher-source": {
        "native_device_linking::tests::pending_restart_higher_source_delivers_catalog_and_record"
    },
    "automatic-body-regression": {
        PREFIX + "body_negative_acceptance::authenticated_negative_sql_failure_retains_owned_body_until_commit_before_disposition",
        PREFIX + "held_automatic_catalog_body_keeps_fresh_account_commands_responsive",
        PREFIX + "body_late_ack_acceptance::authenticated_receipt_retires_final_catalog_body_before_late_backend_ack",
        PREFIX + "body_late_ack_acceptance::unchanged_catalog_context_accepts_the_same_real_backend_ack",
        "native_device_linking::tests::pending_lower_request_recovers_after_higher_restarts_before_consent",
        "native_device_linking::tests::pending_restart_higher_source_delivers_catalog_and_record",
    },
    "pairing-regression": {
        FOURTH,
        CONSENT,
        PREFIX + "automatic_transport_cannot_keep_dropped_original_authority_alive",
        PREFIX + "automatic_sync_does_not_block_foreground_enrollment_completion",
    },
}


def replay_script():
    text = WORKFLOW.read_text()
    start = text.index("      - name: Run actual enrollment and authority retirement bodies without retries\n")
    step = text[start:text.index("      - uses:", start)]
    return textwrap.dedent(step.split("        run: |\n", 1)[1])


class PairingReplayDispatchTests(unittest.TestCase):
    def test_every_scope_is_offered_and_routes_to_pairing_job(self):
        text = WORKFLOW.read_text()
        options = re.search(r"options: \[(.*?)\]", text).group(1).split(", ")
        job = text.split("  pairing-replay:\n", 1)[1].split("    name:", 1)[0]
        routed = json.loads(re.search(r"fromJSON\('([^']+)'\)", job).group(1))
        self.assertTrue(set(EXPECTED) <= set(options))
        self.assertTrue(set(EXPECTED) <= set(routed))

    def test_every_scope_executes_its_exact_inventory_and_bounded_command(self):
        script = replay_script()
        syntax = subprocess.run(["bash", "-n"], input=script, text=True, capture_output=True)
        self.assertEqual(syntax.returncode, 0, syntax.stderr)
        for scope, expected in EXPECTED.items():
            with self.subTest(scope=scope), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                cargo = root / "cargo"
                cargo.write_text("#!" + sys.executable + "\n" + textwrap.dedent(r'''
                    import json, os, re, sys
                    from pathlib import Path
                    args = sys.argv[1:]
                    if args[:2] == ['nextest', 'list']:
                        names = re.findall(r'test\(=([^)]*)\)', args[args.index('-E') + 1])
                        cases = {n: {'ignored': False, 'filter-match': {'status': 'matches'}} for n in names}
                        print(json.dumps({'rust-suites': {'marmot-app': {'testcases': cases}}}))
                    elif args[:2] == ['nextest', 'run']:
                        Path(os.environ['PAIRING_COMMAND']).write_text(json.dumps(args))
                    else:
                        raise SystemExit('unexpected cargo command')
                '''))
                cargo.chmod(0o700)
                command = root / "command.json"
                env = dict(os.environ, PATH=str(root) + os.pathsep + os.environ["PATH"],
                           REPLAY_SCOPE=scope, SLOTS="1" if scope == "automatic-body-regression" else "3", PAIRING_COMMAND=str(command))
                result = subprocess.run(["bash", "-c", script], cwd=root, env=env,
                                        text=True, capture_output=True)
                self.assertEqual(result.returncode, 0, result.stderr)
                args = json.loads(command.read_text())
                selected = set(re.findall(r"test\(=([^)]*)\)", args[args.index("-E") + 1]))
                self.assertEqual(selected, expected)
                for option, value in (("--profile", "m5-bounded"), ("--retries", "0"),
                                      ("--test-threads", env["SLOTS"]), ("--success-output", "immediate")):
                    self.assertEqual(args[args.index(option) + 1], value)
                self.assertIn("qualification-selected-pairing-cases: " + str(len(expected)), result.stdout)


if __name__ == "__main__":
    unittest.main()
