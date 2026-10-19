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

from test_checkpoint_dispatch import EXPERIMENTAL_FEATURES


WORKFLOW = Path(__file__).resolve().parents[1] / ".github/workflows/experimental-sync-ci.yml"
PREFIX = "native_device_linking::automatic_pairing_acceptance::"
FOURTH = PREFIX + "third_and_later_device_enrollment_need_no_extra_qr_or_manual_artifacts"
CONSENT = PREFIX + "blocked_sibling_consent_does_not_starve_another_approved_peer"
EXPECTED = {
    "pairing-diagnostic": {FOURTH},
    "pairing-consent-fairness": {CONSENT},
    "pairing-restart-diagnostic": {
        "native_device_linking::tests::pending_lower_request_recovers_after_higher_restarts_before_consent",
        "native_device_linking::tests::pending_restart_higher_source_delivers_catalog_and_record",
    },
    "pairing-restart-higher-source": {
        "native_device_linking::tests::pending_restart_higher_source_delivers_catalog_and_record"
    },
    "pairing-departure-contention": {
        "native_device_linking::tests::automatic_account_departure_acceptance::account_departure_completes_when_source_branch_wins_same_epoch_race",
        "native_device_linking::tests::actual::automatic_catalog_channel_renewal_reaches_later_entries_without_manual_consent",
    },
    "pairing-departure-middle-signer": {
        "native_device_linking::tests::automatic_account_departure_acceptance::account_departure_source_wins_with_reopened_middle_signer",
    },
    "pairing-departure-arrival-order": {
        "native_device_linking::tests::automatic_account_departure_acceptance::account_departure_completes_when_own_leave_precedes_replayed_proposal",
    },
    "pairing-departure-orders": {
        "native_device_linking::tests::automatic_account_departure_acceptance::account_departure_completes_when_own_leave_precedes_replayed_proposal",
        "native_device_linking::tests::automatic_account_departure_acceptance::account_departure_reproposes_public_leave_after_same_epoch_branch_race",
        "native_device_linking::tests::automatic_account_departure_acceptance::account_departure_completes_when_source_branch_wins_same_epoch_race",
        "native_device_linking::tests::automatic_account_departure_acceptance::account_departure_source_wins_with_reopened_middle_signer",
    },
    "pairing-leave-schedule": {
        "client::sync::queued_outbound_schedule_tests::stale_own_leave_after_input_only_convergence_keeps_worker_wake",
        "client::sync::queued_outbound_schedule_tests::restarted_safe_queued_send_does_not_inherit_secondary_retry_cutoff",
        "client::sync::queued_outbound_schedule_tests::restarted_below_quorum_send_keeps_required_retry_cutoff",
        "client::sync::queued_outbound_schedule_tests::publication_barrier_rejects_unhydrated_inventory",
        "client::sync::queued_outbound_schedule_tests::publication_barrier_keeps_pending_mls_after_quorum",
        "tests::due_peer_leave_preserves_the_outbound_fanout_retry_barrier",
        "tests::removed_device_retires_peer_leave_timer_after_input_only_convergence",
    },
    "automatic-body-regression": {
        "client::account_chat_sharing::automatic::records::source_lookup_tests::record_source_epoch_is_independent_of_catalogue_position",
        PREFIX + "body_negative_acceptance::authenticated_negative_sql_failure_retains_owned_body_until_commit_before_disposition",
        PREFIX + "held_automatic_catalog_body_keeps_fresh_account_commands_responsive",
        PREFIX + "body_late_ack_acceptance::authenticated_receipt_retires_final_catalog_body_before_late_backend_ack",
        PREFIX + "body_late_ack_acceptance::unchanged_catalog_context_accepts_the_same_real_backend_ack",
        "native_device_linking::tests::pending_lower_request_recovers_after_higher_restarts_before_consent",
        "native_device_linking::tests::pending_restart_higher_source_delivers_catalog_and_record",
    },
    "automatic-body-negative": {
        PREFIX + "body_negative_acceptance::authenticated_negative_sql_failure_retains_owned_body_until_commit_before_disposition",
    },
    "pairing-regression": {
        FOURTH,
        CONSENT,
        PREFIX + "automatic_transport_cannot_keep_dropped_original_authority_alive",
        PREFIX + "automatic_sync_does_not_block_foreground_enrollment_completion",
    },
}
EXPECTED["pairing-departure-staggered"] = EXPECTED["pairing-departure-contention"]


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
                    import json, os, re, sys, time
                    from pathlib import Path
                    args = sys.argv[1:]
                    if args[:2] == ['nextest', 'list']:
                        names = re.findall(r'test\(=([^)]*)\)', args[args.index('-E') + 1])
                        cases = {n: {'ignored': False, 'filter-match': {'status': 'matches'}} for n in names}
                        print(json.dumps({'rust-suites': {'marmot-app': {'testcases': cases}}}))
                    elif args[:2] == ['nextest', 'run']:
                        ready_name = os.environ.get('PAIRING_MOCK_SLEEP_READY')
                        if ready_name and 'renewal' in args[args.index('-E') + 1]:
                            deadline = time.monotonic() + 5
                            command = Path(os.environ['PAIRING_COMMAND'])
                            while not Path(ready_name).exists() and not (command.is_file() and command.read_bytes().endswith(b'\n')):
                                if time.monotonic() >= deadline:
                                    raise SystemExit(98)
                                time.sleep(0.001)
                        with Path(os.environ['PAIRING_COMMAND']).open('a') as output:
                            output.write(json.dumps(args) + '\n')
                        if os.environ.get('PAIRING_FAIL_RENEWAL') and 'renewal' in args[args.index('-E') + 1]:
                            raise SystemExit(19)
                    else:
                        raise SystemExit('unexpected cargo command')
                '''))
                cargo.chmod(0o700)
                sleep = root / "sleep"
                sleep.write_text("#!" + sys.executable + "\n" + textwrap.dedent(r'''
                    import os, sys, time
                    from pathlib import Path
                    Path(os.environ['PAIRING_DELAY']).write_text(sys.argv[1] + '\n')
                    Path(os.environ['PAIRING_MOCK_SLEEP_READY']).touch()
                    command = Path(os.environ['PAIRING_COMMAND'])
                    deadline = time.monotonic() + 5
                    while not (command.is_file() and command.read_bytes().endswith(b'\n')):
                        if time.monotonic() >= deadline:
                            raise SystemExit(98)
                        time.sleep(0.001)
                '''))
                sleep.chmod(0o700)
                command = root / "command.json"
                env = dict(os.environ, PATH=str(root) + os.pathsep + os.environ["PATH"],
                           REPLAY_SCOPE=scope, SYNC_FEATURES=EXPERIMENTAL_FEATURES,
                           SLOTS=("6" if scope in ("pairing-departure-contention", "pairing-departure-staggered", "pairing-departure-orders") else
                                  "1" if scope in ("automatic-body-regression", "automatic-body-negative") else "3"),
                           PAIRING_COMMAND=str(command), PAIRING_DELAY=str(root / "delay"))
                ready = root / "mock-sleep-ready"
                env.pop("PAIRING_MOCK_SLEEP_READY", None)
                if scope == "pairing-departure-staggered":
                    env["PAIRING_MOCK_SLEEP_READY"] = str(ready)
                ready.unlink(missing_ok=True)
                result = subprocess.run(["bash", "-c", script], cwd=root, env=env,
                                        text=True, capture_output=True)
                self.assertEqual(result.returncode, 0, result.stderr)
                commands = [json.loads(line) for line in command.read_text().splitlines()]
                selected = {name for args in commands for name in re.findall(r"test\(=([^)]*)\)", args[args.index("-E") + 1])}
                self.assertEqual(selected, expected)
                self.assertEqual(len(commands), 2 if scope == "pairing-departure-staggered" else 1)
                for args in commands:
                    if scope in ("pairing-restart-diagnostic", "pairing-restart-higher-source") or scope.startswith("pairing-departure-"):
                        self.assertIn("--workspace", args)
                        self.assertNotIn("-p", args)
                        self.assertEqual(args[args.index("--features") + 1], EXPERIMENTAL_FEATURES)
                    else:
                        self.assertEqual(args[args.index("-p") + 1], "marmot-app")
                        self.assertIn("--lib", args)
                    for option, value in (("--profile", "m5-bounded"), ("--retries", "0"),
                                          ("--test-threads", "3" if scope == "pairing-departure-staggered" else env["SLOTS"]), ("--success-output", "immediate")):
                        self.assertEqual(args[args.index(option) + 1], value)
                if scope == "pairing-departure-staggered":
                    self.assertEqual((root / "delay").read_text().strip(), "60.625453")
                    self.assertIn("renewal", commands[0][commands[0].index("-E") + 1])
                    command.unlink()
                    ready.unlink(missing_ok=True)
                    failed = subprocess.run(["bash", "-c", script], cwd=root,
                                            env=dict(env, PAIRING_FAIL_RENEWAL="1"),
                                            text=True, capture_output=True)
                    self.assertNotEqual(failed.returncode, 0)
                    self.assertIn("renewal=19 departure=0", failed.stdout)
                    self.assertEqual(len(command.read_text().splitlines()), 2)
                self.assertIn("qualification-selected-pairing-cases: " + str(len(expected)), result.stdout)

    def test_departure_contention_rejects_a_serial_budget_before_cargo(self):
        for scope in ("pairing-departure-contention", "pairing-departure-staggered", "pairing-departure-orders"):
            with self.subTest(scope=scope), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                cargo = root / "cargo"
                cargo.write_text("#!/bin/sh\necho unexpected-cargo >&2\nexit 97\n")
                cargo.chmod(0o700)
                env = dict(os.environ, PATH=str(root) + os.pathsep + os.environ["PATH"],
                           REPLAY_SCOPE=scope, SLOTS="3",
                           SYNC_FEATURES=EXPERIMENTAL_FEATURES)
                result = subprocess.run(["bash", "-c", replay_script()], cwd=root,
                                        env=env, text=True, capture_output=True)
                self.assertNotEqual(result.returncode, 0)
                self.assertIn("departure contention requires six test slots", result.stderr)
                self.assertNotIn("unexpected-cargo", result.stderr)


if __name__ == "__main__":
    unittest.main()
