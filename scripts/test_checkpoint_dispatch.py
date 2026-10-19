"""Check the default checkpoint diagnostic command without running Rust tests."""
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
SCOPE = "default-checkpoint-diagnostic"
CASE = "runtime::conversation_window::tests::hot_checkpoints_do_not_postpone_not_ready_retry"
FEATURES = "wn-cli/test-policy-overrides,cgka-engine/test-policy-overrides,cgka-engine/test-crash-hooks"
DEPARTURE_SCOPE = "experimental-departure-diagnostic"
DEPARTURE_CASE = "native_device_linking::tests::automatic_account_departure_acceptance::account_departure_completes_when_source_branch_wins_same_epoch_race"
PUBLIC_SCOPE = "public-third-device-deployment"
PUBLIC_CASE = "native_device_linking::automatic_pairing_acceptance::public_third_device_enrollment_with_existing_chat"
CHAT_SCOPE = "public-three-device-chat-delivery"
CHAT_CASE = "native_device_linking::automatic_pairing_acceptance::public_chat_delivery_acceptance::public_three_device_automatic_chats_and_messages"
EXPERIMENTAL_FEATURES = (
    "marmot-app/otlp-export,marmot-uniffi/otlp-export,marmot-c/otlp-export,wn-cli/otlp-export,agent-connector/otlp-export,"
    "marmot-app/product-analytics-export,marmot-uniffi/product-analytics-export,marmot-c/product-analytics-export,"
    "wn-cli/product-analytics-export,agent-connector/product-analytics-export,wn-cli/test-policy-overrides,"
    "cgka-engine/test-policy-overrides,cgka-engine/test-crash-hooks,experimental-device-sync"
)

STACK_SCOPE = "pairing-stack-regression"
STACK_FEATURES = "marmot-app/otlp-export,marmot-app/product-analytics-export,marmot-app/test-policy-overrides,marmot-app/experimental-device-sync,cgka-engine/test-policy-overrides,cgka-engine/test-crash-hooks"
STACK_CASES = ["native_device_linking::tests::automatic_forwarding_acceptance::" + name for name in (
    "automatic_forwarding_uses_original_client_token_and_real_ordinary_event",
    "automatic_forwarding_preserves_actual_reply_reference_and_canonical_id",
    "automatic_forwarding_queues_without_members_and_reopens_both_independent_stores",
    "automatic_forwarding_retries_unacknowledged_receipt_after_recipient_sql_rollback",
)] + ["native_device_linking::tests::automatic_held_three_original_acceptance::automatic_held_three_originals_allow_" + direction + "_initiated_discovery" for direction in ("b", "c")]
STACK_CASES += ["native_device_linking::tests::automatic_held_original_acceptance::automatic_held_originals_allow_" + direction + "_initiated_discovery" for direction in ("sponsor", "recipient")]
STACK_CASES += [
    "native_device_linking::tests::automatic_forwarding_non_admin_acceptance::automatic_forwarding_reaches_independent_creator_through_non_admin_member",
    "native_device_linking::tests::automatic_forwarding_non_admin_acceptance::automatic_nonadmin_leave_withdraws_mirrors_without_turning_local_hide_into_departure",
    "native_device_linking::tests::automatic_record_renewal_acceptance::automatic_records_remain_visible_after_acknowledged_ab_batch_and_broad_abc_renewal",
]

QUEUE_SCOPE = "queued-intent-regression"
QUEUE_CASES = ["subject::tests::" + name for name in (
    "regenerated_queued_intent_retries_then_retires_through_outbound_acknowledgement",
    "engine_subject_virtual_time_is_shared_while_participant_wakes_are_selected",
    "scheduled_group_evolution_waits_for_public_outbound_acknowledgement",
    "fixed_point_reports_manual_ack_blocker_then_settles",
)]


class CheckpointDispatchTests(unittest.TestCase):
    def test_scope_routes_to_the_focused_job(self):
        workflow = WORKFLOW.read_text()
        options = re.search(r"options: \[(.*?)\]", workflow).group(1).split(", ")
        job = workflow.split("  core-regressions:\n", 1)[1].split("    name:", 1)[0]
        self.assertIn("github.event_name == 'workflow_dispatch'", job)
        routes = json.loads(re.search(r"fromJSON\('([^']+)'\)", job).group(1))
        for scope in (SCOPE, DEPARTURE_SCOPE, PUBLIC_SCOPE, CHAT_SCOPE, STACK_SCOPE, QUEUE_SCOPE):
            self.assertIn(scope, options)
            self.assertIn(scope, routes)

    def test_departure_scope_preserves_the_full_experimental_feature_union(self):
        self.check_inventory(DEPARTURE_SCOPE, DEPARTURE_CASE, EXPERIMENTAL_FEATURES)

    def test_exact_default_features_and_inventory_are_required(self):
        self.check_inventory(SCOPE, CASE, FEATURES)

    def test_public_scope_executes_only_the_exact_ignored_deployment_case(self):
        self.check_inventory(PUBLIC_SCOPE, PUBLIC_CASE, EXPERIMENTAL_FEATURES, ignored_only=True)

    def test_chat_scope_executes_only_the_exact_ignored_delivery_case(self):
        self.check_inventory(CHAT_SCOPE, CHAT_CASE, EXPERIMENTAL_FEATURES, ignored_only=True)

    def test_stack_scope_keeps_eleven_real_cases_and_original_stack_limit(self):
        self.check_inventory(STACK_SCOPE, STACK_CASES, STACK_FEATURES)
        workflow = WORKFLOW.read_text()
        job = workflow.split("  core-regressions:\n", 1)[1].split("  experimental-inventory:\n", 1)[0]
        self.assertNotIn("RUST_MIN_STACK", job)
        self.assertIn('RUST_MIN_STACK: "4194304"', workflow)

    def test_queue_scope_keeps_four_virtual_time_and_acknowledgement_cases(self):
        self.check_inventory(QUEUE_SCOPE, QUEUE_CASES, STACK_FEATURES)

    def check_inventory(self, scope, required_case, features, ignored_only=False):
        workflow = WORKFLOW.read_text()
        start = workflow.index("      - name: Run selected affected regressions without retries\n")
        step = workflow[start:workflow.index("      - uses:", start)]
        script = textwrap.dedent(step.split("        run: |\n", 1)[1])
        required_cases = required_case if isinstance(required_case, list) else [required_case]
        modes = ("exact", "empty", "extra", "not-ignored" if ignored_only else "ignored", "wrong-suite")
        if len(required_cases) > 1:
            modes += ("missing-one",)
        for mode in modes:
            with self.subTest(mode=mode), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                cargo = root / "cargo"
                cargo.write_text("#!" + sys.executable + "\n" + textwrap.dedent('''
                    import json, os, sys
                    from pathlib import Path
                    args = sys.argv[1:]
                    if args[:2] == ['nextest', 'list']:
                        Path('list-command.json').write_text(json.dumps(args))
                        case = {'ignored': (os.environ['MODE'] != 'not-ignored'
                                            if os.environ['IGNORED_ONLY'] == '1'
                                            else os.environ['MODE'] == 'ignored'),
                                'filter-match': {'status': 'matches'}}
                        cases = {} if os.environ['MODE'] == 'empty' else {name: case for name in json.loads(os.environ['CASES'])}
                        if os.environ['MODE'] == 'missing-one': cases.pop(next(iter(cases)))
                        if os.environ['MODE'] == 'extra': cases['extra'] = case
                        suite = 'wrong' if os.environ['MODE'] == 'wrong-suite' else os.environ['SUITE']
                        print(json.dumps({'rust-suites': {suite: {'testcases': cases}}}))
                    elif args[:2] == ['nextest', 'run']:
                        Path('command.json').write_text(json.dumps(args))
                        Path('relay.json').write_text(json.dumps(os.environ.get('WN_PUBLIC_ENROLLMENT_RELAY')))
                    else:
                        raise SystemExit('unexpected cargo command')
                '''))
                cargo.chmod(0o700)
                env = dict(os.environ, PATH=str(root) + os.pathsep + os.environ['PATH'],
                           REGRESSION_SCOPE=scope, MODE=mode, CASES=json.dumps(required_cases),
                           SYNC_FEATURES=EXPERIMENTAL_FEATURES, IGNORED_ONLY=str(int(ignored_only)),
                           SUITE="cgka-conformance-simulator" if scope == QUEUE_SCOPE else "marmot-app")
                result = subprocess.run(['bash', '-c', script], cwd=root, env=env,
                                        capture_output=True, text=True)
                command = root / 'command.json'
                if mode != 'exact':
                    self.assertNotEqual(result.returncode, 0)
                    self.assertFalse(command.exists())
                    continue
                self.assertEqual(result.returncode, 0, result.stderr)
                args = json.loads(command.read_text())
                listing = json.loads((root / 'list-command.json').read_text())
                if scope in (STACK_SCOPE, QUEUE_SCOPE):
                    self.assertNotIn('--workspace', args)
                    self.assertEqual(args[args.index('-p') + 1],
                                     'cgka-conformance-simulator' if scope == QUEUE_SCOPE else 'marmot-app')
                    self.assertIn('--lib', args)
                else:
                    self.assertIn('--workspace', args)
                if scope == SCOPE:
                    self.assertEqual(args[args.index('--exclude') + 1], 'cgka-conformance-simulator')
                else:
                    self.assertNotIn('--exclude', args)
                for option, value in (('--features', features), ('--retries', '0'),
                                      ('--test-threads', '1' if ignored_only else '6'), ('--profile', 'm5-bounded')):
                    self.assertEqual(args[args.index(option) + 1], value)
                expression = ('package(marmot-app) & (test(native_device_linking::tests::automatic_forwarding_acceptance::automatic_forwarding_) | test(native_device_linking::tests::automatic_held_three_original_acceptance::automatic_held_three_originals_) | test(native_device_linking::tests::automatic_held_original_acceptance::automatic_held_originals_) | test(=native_device_linking::tests::automatic_forwarding_non_admin_acceptance::automatic_forwarding_reaches_independent_creator_through_non_admin_member) | test(=native_device_linking::tests::automatic_forwarding_non_admin_acceptance::automatic_nonadmin_leave_withdraws_mirrors_without_turning_local_hide_into_departure) | test(=native_device_linking::tests::automatic_record_renewal_acceptance::automatic_records_remain_visible_after_acknowledged_ab_batch_and_broad_abc_renewal))'
                              if scope == STACK_SCOPE else f'package(marmot-app) & test(={required_case})')
                if scope == QUEUE_SCOPE:
                    expression = 'package(cgka-conformance-simulator) & (' + ' | '.join(
                        f'test(={name})' for name in QUEUE_CASES) + ')'
                self.assertEqual(args[args.index('-E') + 1], expression)
                self.assertIn('--locked', args)
                self.assertEqual(listing[listing.index('--features') + 1], features)
                self.assertEqual(listing[listing.index('-E') + 1], args[args.index('-E') + 1])
                self.assertEqual(listing[listing.index('--run-ignored') + 1], 'only' if ignored_only else 'default')
                if ignored_only:
                    self.assertEqual(args[args.index('--run-ignored') + 1], 'only')
                    self.assertEqual(json.loads((root / 'relay.json').read_text()), 'wss://relay.eu.whitenoise.chat')


if __name__ == '__main__':
    unittest.main()
