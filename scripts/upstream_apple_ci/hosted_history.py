#!/usr/bin/env python3
"""Hosted native archive/lifecycle scenarios; only aggregate results are exported.

Runs isolated processes on one Apple CI host. It deliberately does not invoke or
relax the cross-host controllers' topology checks, and establishes no app UI,
simulator, physical-device or published-client interoperability claim.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import select
import socket
import subprocess
import sys
import tempfile
import time

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE / "native"))

import automatic_chat as automatic
import cross_host as original
from cross_host import GateFailure, Peer, require
from revocation_probe import device_revocation_probe
from hosted_archive import selected_chat
from hosted_pagination import run as pagination


def verify_helpers() -> None:
    frozen = json.loads((HERE / "native/SOURCE.json").read_text())
    require(frozen["workspace_commit"] == "3048d444ffe681fbae2dc1fb8e4f49d2a1c14372",
            "frozen-native-source-cohort")
    for name, expected in frozen["files"].items():
        require(hashlib.sha256((HERE / "native" / name).read_bytes()).hexdigest() == expected,
                "frozen-native-helper-bytes")
    added = json.loads((HERE / "HOSTED-SOURCE.json").read_text())
    for name, record in added["files"].items():
        require(hashlib.sha256((HERE / name).read_bytes()).hexdigest() == record["sha256"],
                "additional-native-helper-bytes")


class Journey:
    def __init__(self, agent: Path, root: Path, port: int):
        root.mkdir(mode=0o700)
        self.root = root
        self.peers = []
        self.commands = {
            role: ["/usr/bin/env", "NATIVE_ACCEPTANCE_RELAY_PORT=" + str(port),
                   str(agent), "serve", str(root / role)]
            for role in ("source", "recipient", "third", "outsider")
        }

    def open(self, role: str) -> Peer:
        peer = Peer(self.commands[role], self.root / (role + "-private.stderr"))
        self.peers.append(peer)
        return peer

    def close(self) -> dict:
        failed = 0
        for peer in self.peers:
            if not peer.closed_successfully:
                try:
                    peer.close()
                except (GateFailure, OSError, subprocess.SubprocessError):
                    failed += 1
                    # Only this journey's freshly spawned worker may be stopped.
                    # Do not let temporary-store cleanup race a surviving process.
                    if peer.process.poll() is None:
                        peer.process.terminate()
                        try:
                            peer.process.wait(timeout=5)
                        except subprocess.TimeoutExpired:
                            peer.process.kill()
                            peer.process.wait()
        counts = {"workers_created": len(self.peers),
                  "workers_closed": sum(peer.closed_successfully for peer in self.peers),
                  "cleanup_failures": failed}
        require(failed == 0 and counts["workers_created"] == counts["workers_closed"],
                "positive-native-worker-close-required")
        return counts


def archive(journey: Journey) -> dict:
    a, b, c, d = (journey.open(role) for role in journey.commands)
    account = original.first_pair(a, b, c)
    # As in the committed history controller, A's genuine B/C enrollment review
    # supplies B's occupied signer. Never derive recipient authority from packets.
    review = original.third_device(b, a, c)
    previous = selected_chat(a, b, c, d, history=True, account=account)
    query = original.history_recipient_query(a, b, c, review["source"], previous["group"])
    original.history_alias_cancellation(a, b, c, review["source"], previous["group"])
    original.history_final_alias_drop(a, b, c, review["source"], previous["group"])
    counts = {}
    receipt = original.history_transfer(a, b, c, review["source"], previous, diagnostics=counts)
    require(receipt["source_complete"] and receipt["recipient_complete"],
            "history-both-originals-completed")
    require(counts["verified_prejoin_records"] == counts["archive_page_records"] == 1
            and counts["source_records"] == 2 and counts["imported_records"] == 1
            and counts["postjoin_live_record_present"] is True,
            "exact-history-fixture-execution-counts")
    # Receipt contains private record content. Export counts only.
    return {"recipient_query": query, "history_counts": counts,
            "alias_cancel_checks": 1, "final_alias_drop_checks": 1,
            "source_attested_transfer_provenance": True,
            "nonrecipient_archive_empty": True, "tagged_prejoin_bytes": 8192}


def automatic_setup(journey: Journey, incoming_required: bool):
    a, b, c, d = (journey.open(role) for role in journey.commands)
    identity, outsider = a.ask("create"), d.ask("create")
    require(identity["account"] != outsider["account"], "independent-ordinary-outsider")
    del outsider["secret"]
    group = a.ask("create-chat", member=outsider["account"])["group"]
    automatic.accept(d, group)
    seed = "hosted-prepair-native-history"
    event = a.ask("send-text", group=group, text=seed)["message"]
    automatic.eventually(lambda: d.ask("message-seen", group=group, message=event, text=seed),
                         lambda value: value["seen"], "hosted-prepair-ordinary-delivery")
    incoming = None
    if incoming_required:
        incoming_group = d.ask("create-chat", member=identity["account"])["group"]
        require(incoming_group != group, "independent-incoming-group")
        automatic.accept(a, incoming_group)
        text = "hosted-incoming-nonadmin-history"
        incoming_event = d.ask("send-text", group=incoming_group, text=text)["message"]
        automatic.eventually(
            lambda: a.ask("message-seen", group=incoming_group, message=incoming_event, text=text),
            lambda value: value["seen"], "hosted-incoming-member-delivery")
        incoming = (incoming_group, text, incoming_event)
    original.first_pair(a, b, c, automatic=True, identity=identity, retain_completed=True)
    automatic.exact_mirror(b, group, seed, event)
    automatic.require_completed_originals(a, b)
    a.ask("cancel")
    b.ask("cancel")
    original.third_device(a, b, c, automatic=True, retain_completed=True)
    automatic.require_completed_originals(a, b, c)
    for peer in (b, c):
        automatic.exact_mirror(peer, group, seed, event)
    return a, b, c, d, outsider["account"], incoming, (group, seed, event)


def lifecycle(journey: Journey, kind: str) -> dict:
    a, b, c, d, outsider, incoming, witness = automatic_setup(
        journey, incoming_required=kind in ("departure", "withdrawal"))
    if kind == "departure":
        automatic.account_departure_probe(
            a, b, c, d, incoming, witness, journey.commands, journey.root, journey.peers)
        return {"pending_offline_receipt": True, "pending_and_completed_encrypted_reopen": True,
                "ordinary_membership_removed": True, "old_sibling_send_denials": 3,
                "unrelated_live_witness": True, "negative_fence_observation_seconds": 20}
    if kind == "revocation":
        stages = []
        device_revocation_probe(a, b, c, d, outsider, witness, progress=stages.append)
        expected = ["protected-remove-confirmed-survivors-settled", "survivor-fresh-canonical-message",
                    "survivor-ordinary-forward-delivered", "survivor-new-chat-and-message",
                    "revoked-new-disclosure-blocked", "revoked-forwarding-refused"]
        require(stages == expected, "every-revocation-scenario-body-completed")
        return {"executed_stages": stages, "revoked_new_disclosure_observation_seconds": 20}
    if kind == "withdrawal":
        automatic.withdrawal_probe(
            a, b, c, d, incoming, witness, journey.commands, journey.root, journey.peers)
        return {"local_hide_preserves_approved_sibling_history": True,
                "fresh_traffic_recreates_locally_hidden_chat": True,
                "ordinary_nonadmin_leave_withdraws_siblings": True,
                "withdrawal_survives_encrypted_reopen": True}
    raise GateFailure("unsupported-hosted-scenario")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--agent", type=Path, required=True)
    parser.add_argument("--agent-sha256", required=True)
    parser.add_argument("--agent-provenance", type=Path,
                        help="Diagnostic-only derived source hash manifest from prepare-hosted-agent.py")
    parser.add_argument("--relay", type=Path, required=True)
    parser.add_argument("--sdk-source", required=True)
    parser.add_argument("--output", type=Path, required=True,
                        help="Fresh aggregate-only report directory; never contains stores or private logs")
    parser.add_argument("--port", type=int, default=18515)
    parser.add_argument("--scenarios", nargs="+", choices=("archive", "departure", "revocation", "withdrawal", "pagination"),
                        default=["archive", "departure", "revocation", "withdrawal"],
                        help="Run only affected journeys; unselected journeys are not qualified by this report")
    args = parser.parse_args()
    require(len(set(args.scenarios)) == len(args.scenarios), "unique-selected-scenarios")
    require(re.fullmatch("[0-9a-f]{40}", args.sdk_source) is not None, "exact-sdk-source-required")
    require(args.agent.is_absolute() and args.relay.is_absolute(), "absolute-native-executables")
    require(1024 <= args.port <= 65535, "bounded-loopback-port")
    require(hashlib.sha256(args.agent.read_bytes()).hexdigest() == args.agent_sha256,
            "native-agent-sha256-mismatch")
    verify_helpers()
    os.umask(0o077)
    args.output.mkdir(mode=0o700, parents=True, exist_ok=False)
    report = {"sdk_source": args.sdk_source, "agent_sha256": args.agent_sha256,
              "controller_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
              "frozen_helpers_manifest_sha256": hashlib.sha256((HERE / "native/SOURCE.json").read_bytes()).hexdigest(),
              "additional_helpers_manifest_sha256": hashlib.sha256((HERE / "HOSTED-SOURCE.json").read_bytes()).hexdigest(),
              "passed": 0, "failed": 0, "scenarios": [],
              "selected_scenarios": args.scenarios,
              "unselected_scenarios": [name for name in ("archive", "departure", "revocation", "withdrawal", "pagination")
                                       if name not in args.scenarios],
              "scope": "Actual macOS native SDK originals on one hosted CI runner; synthetic independent stores only.",
              "not_established": ["history above the SDK 200-record source snapshot cap (NotReady); no full-history replacement equivalence",
                                  "expiry and retention enforcement",
                                  "message deletion tombstone propagation", "iOS native execution",
                                  "installed application UI", "published-client interoperability", "cross-host operation"]}
    if "pagination" not in args.scenarios:
        report["not_established"].append("recipient cursor pagination is not selected in this run")
    if args.agent_provenance is not None:
        report["agent_source_provenance"] = json.loads(args.agent_provenance.read_text())
    started = time.monotonic()
    with tempfile.TemporaryDirectory(prefix="whitenoise-hosted-native-") as temporary:
        private = Path(temporary)
        relay = None
        try:
            with socket.socket() as probe:
                probe.bind(("127.0.0.1", args.port))
            with (private / "relay-private.stderr").open("xb") as log:
                relay = subprocess.Popen([str(args.relay), "--port", str(args.port)],
                                         stdout=subprocess.PIPE, stderr=log)
                require(bool(select.select([relay.stdout], [], [], 10)[0]), "hosted-relay-ready-timeout")
                require(relay.stdout.readline().decode().strip() == "ws://127.0.0.1:" + str(args.port)
                        and relay.poll() is None, "hosted-relay-ready-endpoint")
                for kind in args.scenarios:
                    row = {"name": kind, "passed": False}
                    journey = Journey(args.agent, private / kind, args.port)
                    began = time.monotonic()
                    try:
                        row["observations"] = (archive(journey) if kind == "archive" else
                                               pagination(journey) if kind == "pagination" else lifecycle(journey, kind))
                        row["passed"] = True
                    except (GateFailure, OSError, ValueError, KeyError, subprocess.SubprocessError) as error:
                        # Fixed stages only: never export arbitrary SDK/IPC exception payloads.
                        stage = str(error) if isinstance(error, GateFailure) else type(error).__name__
                        row["failure_stage"] = stage if re.fullmatch(r"[A-Za-z0-9:_-]{1,180}", stage) and not re.search(r"[0-9a-f]{32}", stage) else "native-scenario-refused"
                    finally:
                        if kind == "pagination" and hasattr(journey, "pagination_progress"):
                            row["phase_observations"] = journey.pagination_progress
                        try:
                            row["cleanup"] = journey.close()
                        except GateFailure:
                            row["passed"] = False
                            row["cleanup_failed"] = True
                        row["elapsed_seconds"] = round(time.monotonic() - began, 3)
                        report["scenarios"].append(row)
        except (GateFailure, OSError, ValueError, subprocess.SubprocessError):
            report["setup_or_relay_failure"] = True
        finally:
            if relay is not None:
                relay.terminate()
                try:
                    relay.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    relay.kill()
                    relay.wait()
                    report["relay_cleanup_failed"] = True
                relay.stdout.close()
    report["passed"] = sum(row["passed"] for row in report["scenarios"])
    report["expected_scenarios"] = len(args.scenarios)
    report["executed_scenarios"] = len(report["scenarios"])
    report["not_run"] = len(args.scenarios) - len(report["scenarios"])
    report["failed"] = len(args.scenarios) - report["passed"]
    if report.get("setup_or_relay_failure") or report.get("relay_cleanup_failed"):
        report["failed"] = max(1, report["failed"])
    report["elapsed_seconds"] = round(time.monotonic() - started, 3)
    (args.output / "result.json").write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps({key: report[key] for key in ("passed", "failed", "sdk_source")}))
    return int(report["failed"] != 0)


if __name__ == "__main__":
    raise SystemExit(main())
