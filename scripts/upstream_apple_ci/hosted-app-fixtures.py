#!/usr/bin/env python3
"""Fresh native counterparts for existing app acceptance; export aggregates only."""
from __future__ import annotations
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import select
import shutil
import signal
import socket
import subprocess
import sys
import time

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE / 'native'))
import automatic_chat as automatic
import cross_host as original
import one_scan
from cross_host import GateFailure, Peer, require
from hosted_archive import selected_chat
from hosted_history import verify_helpers


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def private_json(path, value):
    with os.fdopen(os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), 'w') as stream:
        json.dump(value, stream)
        stream.write('\n')


class Journey:
    def __init__(self, args):
        self.args, self.peers, self.app = args, [], None
        self.roots = {}
        self.target = 'third' if args.scenario == 'automatic-switch' else (
            'source' if args.scenario == 'source-transfer' else 'recipient')
        self.platforms = {role: 'macos' for role in ('source', 'recipient', 'third', 'outsider')}
        self.platforms[self.target] = args.platform
        # The Mac recipient's existing test explicitly exercises an iOS source.
        if args.scenario == 'recipient-transfer' and args.platform == 'macos':
            self.platforms['source'] = 'ios-simulator'
        prefix = 'automatic-host-switch-' if args.scenario == 'automatic-switch' else 'native-'
        for role in self.platforms:
            self.roots[role] = args.base / (prefix + role)
        self.bridge = args.base / 'private-bridge'
        self.bridge.mkdir(mode=0o700)
        self.environment = {
            'GITHUB_ACTIONS': os.environ['GITHUB_ACTIONS'], 'GITHUB_RUN_ID': os.environ['GITHUB_RUN_ID'],
            'WN_NATIVE_ACCEPTANCE_BASE': str(args.base),
            'WN_NATIVE_ACCEPTANCE_SDK_SOURCE': args.sdk_source,
            'WN_NATIVE_ACCEPTANCE_SDK_RUN_ID': args.sdk_run_id,
            'WN_NATIVE_ACCEPTANCE_AGENT_SHA256': args.sim_sha if args.platform == 'ios-simulator' else args.mac_sha,
        }
        self.report = {'sdk_source': args.sdk_source, 'sdk_run_id': args.sdk_run_id,
                       'scenario': args.scenario, 'app_platform': args.platform,
                       'controller_sha256': digest(Path(__file__)),
                       'frozen_sources_sha256': digest(HERE / 'native/SOURCE.json'),
                       'adapted_sources_sha256': digest(HERE / 'HOSTED-SOURCE.json'),
                       'application_command_sha256': digest(args.application_command), 'mac_agent_sha256': args.mac_sha,
                       'simulator_agent_sha256': args.sim_sha, 'phase': 'setup', 'passed': 0,
                       'scope': 'Hosted single-runner original native stores and actual app tests; no physical-device or cross-host claim.'}

    def open(self, role):
        if self.platforms[role] == 'ios-simulator':
            command = ['/usr/bin/env', 'SIMCTL_CHILD_NATIVE_ACCEPTANCE_RELAY_PORT=18181',
                       'xcrun', 'simctl', 'spawn', self.args.simulator, str(self.args.sim_agent),
                       'serve', str(self.roots[role])]
        else:
            command = ['/usr/bin/env', 'NATIVE_ACCEPTANCE_RELAY_PORT=18181',
                       str(self.args.mac_agent), 'serve', str(self.roots[role])]
        peer = Peer(command, self.args.base / (role + '-' + str(len(self.peers)) + '-private.stderr'))
        self.peers.append(peer)
        return peer

    def close_workers(self):
        failures = 0
        for peer in self.peers:
            if not peer.closed_successfully:
                try:
                    peer.close()
                except (GateFailure, OSError, subprocess.SubprocessError):
                    failures += 1
                    if peer.process.poll() is None:
                        peer.process.terminate()
                        try:
                            peer.process.wait(timeout=5)
                        except subprocess.TimeoutExpired:
                            peer.process.kill()
                            peer.process.wait()
        self.report['native_cleanup'] = {
            'workers_created': len(self.peers), 'workers_closed': sum(p.closed_successfully for p in self.peers),
            'cleanup_failures': failures}
        require(failures == 0 and all(p.closed_successfully for p in self.peers), 'positive-native-close-required')

    def mark_closed(self, role, peer):
        require(peer.closed_successfully and peer.process.poll() == 0, 'fixture-requires-positive-original-close')
        root = self.roots[role]
        marker = root / '.native-acceptance'
        require(not marker.is_symlink() and marker.stat().st_uid == os.getuid()
                and marker.read_bytes() == b'native-sdk83-test-only-v1\n', 'owned-original-native-marker-required')
        # Restrict this non-sensitive harness marker independently of the
        # simulator launch daemon's umask; never alter native account files.
        marker.chmod(0o600)
        private_json(root / '.hosted-native-fixture.json', {
            'version': 1, 'sdk_source': self.args.sdk_source, 'sdk_run_id': self.args.sdk_run_id,
            'agent_sha256': self.args.sim_sha if self.platforms[role] == 'ios-simulator' else self.args.mac_sha,
            'platform': self.platforms[role], 'original_worker_closed': True})

    def start_app(self, values):
        self.environment.update(values)
        private_json(self.args.environment, self.environment)
        self.report['private_environment_sha256'] = digest(self.args.environment)
        manifest = json.loads(self.args.application_command.read_text())
        command = manifest.get('argv')
        require(isinstance(command, list) and bool(command) and all(isinstance(v, str) and v for v in command),
                'explicit-app-command-required')
        log = (self.args.base / 'application-private.log').open('x')
        try:
            self.app = subprocess.Popen(command, env=dict(os.environ, **self.environment),
                                        stdout=log, stderr=subprocess.STDOUT, start_new_session=True)
        finally:
            log.close()

    def observe(self, name, seconds=180):
        deadline = time.monotonic() + seconds
        path = self.bridge / name
        while time.monotonic() < deadline:
            require(not (self.bridge / 'failed.json').exists(), 'actual-app-reported-failure')
            if path.exists():
                require(path.stat().st_size <= 32768, 'bounded-private-app-observation')
                return json.loads(path.read_text())
            require(self.app is None or self.app.poll() is None, 'app-exited-before-observation')
            time.sleep(0.05)
        raise GateFailure('actual-app-observation-timeout')

    def verify_app(self):
        require(self.app is not None, 'actual-app-execution-required')
        self.report['app_exit_code'] = self.app.wait(timeout=180)
        require(self.report['app_exit_code'] == 0, 'actual-app-command-failed')
        require(self.args.app_result_bundle.exists(), 'actual-app-xcresult-required')
        raw = json.loads(subprocess.check_output(['xcrun', 'xcresulttool', 'get', 'test-results', 'summary',
                                                  '--path', str(self.args.app_result_bundle)], text=True))
        fields = ('totalTestCount', 'passedTests', 'failedTests', 'skippedTests')
        require(all(type(raw.get(k)) is int and raw[k] >= 0 for k in fields), 'actual-app-count-schema')
        self.report['app_counts'] = {k: raw[k] for k in ('result',) + fields if k in raw}
        require(raw['totalTestCount'] == raw['passedTests'] == 1
                and raw['failedTests'] == raw['skippedTests'] == 0, 'actual-app-one-pass-zero-skips-required')

    def stop_app(self):
        if self.app is not None and self.app.poll() is None:
            # Python runners handle SIGINT through their finally blocks and
            # retire their separately owned xcodebuild process groups.
            os.killpg(self.app.pid, signal.SIGINT)
            try:
                self.app.wait(timeout=30)
            except subprocess.TimeoutExpired:
                os.killpg(self.app.pid, signal.SIGKILL)
                self.app.wait(timeout=10)
            self.report['app_required_termination'] = True


def initial_history(journey):
    a, b, c, d = (journey.open(role) for role in journey.platforms)
    account = original.first_pair(a, b, c)
    review = original.third_device(b, a, c)
    previous = selected_chat(a, b, c, d, history=True, account=account)
    previous['recipient_root'] = str(journey.roots['recipient'])
    original.history_recipient_query(a, b, c, review['source'], previous['group'])
    return a, b, c, d, account, review['source'], previous


def closed_fixture(journey):
    args = journey.args
    descriptor = args.base / 'fixture.json'
    if args.scenario == 'automatic-switch':
        a, b, c, d = (journey.open(role) for role in journey.platforms)
        identity, outside = a.ask('create'), d.ask('create')
        require(identity['account'] != outside['account'], 'independent-ordinary-account')
        del outside['secret']
        group = a.ask('create-chat', member=outside['account'])['group']
        automatic.accept(d, group)
        text = 'hosted-app-switch-real-prepair'
        event = a.ask('send-text', group=group, text=text)['message']
        original.wait_message((d,), group, event, text, 'actual-ordinary-prepair-delivery')
        original.first_pair(a, b, c, automatic=True, identity=identity, retain_completed=True)
        automatic.exact_mirror(b, group, text, event)
        automatic.require_completed_originals(a, b)
        a.ask('cancel'); b.ask('cancel')
        original.third_device(a, b, c, automatic=True, retain_completed=True)
        automatic.require_completed_originals(a, b, c)
        for peer in (b, c):
            automatic.exact_mirror(peer, group, text, event)
        journey.close_workers()
        journey.mark_closed('third', c)
        journey.start_app({'WN_AUTOMATIC_SWITCH_ROOT': str(journey.roots['third'])})
    else:
        a, b, c, d, account, recipient, previous = initial_history(journey)
        receipt = original.history_transfer(a, b, c, recipient, previous)
        eligible = b.ask('history-recipients', group=previous['group'])
        require(len(eligible) == 2 and len({row['device'] for row in eligible}) == 2,
                'actual-source-picker-two-native-recipients')
        journey.close_workers()
        journey.mark_closed('recipient', b)
        if args.scenario == 'imported-reader':
            original.write_ios_reader_handoff(descriptor, b, str(journey.roots['recipient']), account, previous, receipt)
            values = {'WN_IMPORTED_HISTORY_FIXTURE': str(descriptor)}
        else:
            original.write_source_picker_handoff(descriptor, b, str(journey.roots['recipient']), account,
                                                previous['group'], len(eligible))
            values = {'WN_HISTORY_SOURCE_PICKER_FIXTURE': str(descriptor),
                      'WN_SOURCE_PICKER_FIXTURE': str(descriptor),
                      'WN_HISTORY_SOURCE_UI_BRIDGE': str(journey.bridge),
                      'WN_SOURCE_PICKER_BUTTON_BRIDGE': str(journey.bridge)}
        journey.start_app(values)
    journey.verify_app()



def paired_direct(journey):
    # Native A/B are distinct installations of one account; D is an independent
    # ordinary participant. B's exact original store is closed, never copied.
    a, b, d = (journey.open(role) for role in ('source', 'recipient', 'outsider'))
    identity, peer_identity = a.ask('create'), d.ask('create')
    account, peer_account = identity['account'], peer_identity['account']
    require(account != peer_account, 'independent-direct-peer-required')
    del peer_identity['secret']
    group = a.ask('create-direct-chat', member=peer_account)['group']
    automatic.accept(d, group)
    text = 'hosted-app-direct-source-only'
    event = a.ask('send-text', group=group, text=text)['message']
    original.wait_message((d,), group, event, text, 'direct-peer-original-message')
    slot = a.ask('package-observation')
    companion = original.supported_companion(b, identity['secret'])
    require(companion['account'] == account and a.ask('package-observation') == slot,
            'supported-companion-preserves-account-and-public-slot')
    del identity['secret']
    pairing = one_scan.pair(b, a)
    require(all(pairing.values()), 'genuine-comparison-and-bilateral-consent-required')
    automatic.exact_mirror(b, group, text, event)
    observations = []
    one_scan.direct_lookup(b, group, peer_account, 'recipient-before-app', observations)
    require(b.ask('automatic-list')['local_groups'] == [], 'source-only-recipient-has-no-local-mls')
    a.ask('cancel'); b.ask('cancel')
    source_groups = a.ask('automatic-list')['local_groups']
    peer_groups = d.ask('automatic-list')['local_groups']
    require(source_groups == peer_groups == [group], 'one-original-direct-chat-required')
    source_state, peer_state = a.ask('group-state', group=group), d.ask('group-state', group=group)
    require(source_state['members'] == peer_state['members'] == 2, 'two-ordinary-direct-members-required')
    require(a.ask('ordinary-invitations') == d.ask('ordinary-invitations') == [], 'no-pending-original-invitations')
    b.close()
    journey.mark_closed('recipient', b)
    descriptor = journey.args.base / 'paired-direct-fixture.json'
    private_json(descriptor, {'version': 1, 'root': str(journey.roots['recipient']),
                             'account': account, 'peer': peer_account, 'group': group,
                             'bridge': str(journey.bridge)})
    journey.report['paired_direct_fixture'] = {'bilateral_consent': True, 'source_only_recipient': True,
        'independent_peer': True, 'original_recipient_positive_close': True,
        'one_original_peer_conversation': True, 'no_pending_peer_invitation': True}
    journey.start_app({'WN_PAIRED_DIRECT_FIXTURE': str(descriptor)})
    journey.verify_app()
    require(journey.observe('paired-direct-complete.json') == {
        'paired_destination': True, 'same_group': True, 'lookup_count': 3,
        'no_local_membership': True, 'no_new_ordinary_chat': True, 'runtime_closed': True},
        'actual-app-paired-direct-and-positive-close-required')
    # Only after the app's positive close may the original B store reopen.
    reopened = journey.open('recipient')
    require(reopened.ask('resume')['account'] == account, 'same-recipient-store-after-app-close')
    one_scan.direct_lookup(reopened, group, peer_account, 'recipient-after-app', observations)
    require(reopened.ask('automatic-list')['local_groups'] == [], 'app-lookup-never-creates-local-membership')
    require(a.ask('automatic-list')['local_groups'] == source_groups
            and d.ask('automatic-list')['local_groups'] == peer_groups,
            'app-lookup-never-creates-a-second-peer-conversation')
    require(a.ask('group-state', group=group) == source_state
            and d.ask('group-state', group=group) == peer_state,
            'app-lookup-never-mutates-original-membership-or-epoch')
    require(a.ask('ordinary-invitations') == d.ask('ordinary-invitations') == [],
            'app-lookup-never-creates-another-peer-invitation')
    journey.report['paired_direct'] = {'lookups': 3, 'source_only_before_and_after': True,
        'same_original_root': True, 'peer_conversation_set_unchanged': True,
        'peer_membership_unchanged': True, 'no_new_peer_invitation': True,
        'app_runtime_closed_before_native_reopen': True, 'bilateral_consent': True}


def source_transfer(journey):
    a, b, c, d, account, recipient, previous = initial_history(journey)
    a.close()
    journey.mark_closed('source', a)
    original.write_source_picker_handoff(journey.bridge / 'fixture.json', a,
        str(journey.roots['source']), account, previous['group'], 2, expected_recipient=recipient)
    journey.start_app({'WN_SOURCE_TRANSFER_BRIDGE': str(journey.bridge),
                       'WN_IOS_SOURCE_TRANSFER_BRIDGE': str(journey.bridge),
                       'WN_IOS_SOURCE_TRANSFER_PUBLIC_BRIDGE': str(journey.bridge)})
    require(journey.observe('ready.json') == {'ready': True}, 'actual-source-app-ready')
    source = journey.observe('requested.json', 60)
    require(source['group'] == previous['group'] and source['recipient'] == recipient
            and source['records'] == 2 and source['complete'] is False
            and source['explicit_action'] is True, 'actual-source-app-fresh-original')
    deadline = time.monotonic() + 30
    while b.ask('history-pending')['count'] != 1:
        require(time.monotonic() < deadline, 'actual-source-app-consent-arrival')
        time.sleep(0.05)
    consent = b.ask('history-consent-snapshot')
    original.require_matching_history_scope(consent, source)
    require(consent['imported'] == 0 and not consent['complete']
            and b.ask('history-page', group=previous['group'])['records'] == [], 'no-import-before-recipient-consent')
    b.ask('history-approve', revision=consent['revision'])
    private_json(journey.bridge / 'recipient-approved.json', {'approved': True})
    require(journey.observe('completed.json', 60) == {
        'source_complete': True, 'original_retired': True, 'runtime_closed': True}, 'actual-source-app-positive-close')
    receiver = b.ask('history-consent-snapshot')
    original.verify_history_import(b, c, source, receiver, previous)
    journey.verify_app()
    journey.report['original_scope_and_exact_import_verified'] = True


def recipient_transfer(journey):
    a, b, c, d, account, recipient, previous = initial_history(journey)
    require(b.ask('history-pending')['count'] == 0, 'no-original-before-app-reopen')
    b.close()
    journey.mark_closed('recipient', b)
    original.write_ios_approval_handoff(journey.bridge / 'fixture.json', b,
        str(journey.roots['recipient']), account, previous)
    journey.start_app({'WN_HISTORY_APPROVAL_BRIDGE': str(journey.bridge),
                       'WN_MAC_HISTORY_APPROVAL_BRIDGE': str(journey.bridge)})
    require(journey.observe('ready.json') == {'ready': True}, 'actual-recipient-app-ready')
    source = a.ask('history-begin', group=previous['group'], member=recipient)
    if journey.args.platform == 'macos':
        private_json(journey.bridge / 'source-requested.json', dict(source, explicit_action=True))
        reviewed = journey.observe('reviewed.json', 60)
        original.require_matching_history_scope(reviewed, source)
        require(reviewed['explicit_action'] is False and reviewed['imported'] == 0
                and reviewed['complete'] is False, 'actual-recipient-review-is-not-consent')
    approved = journey.observe('approved.json', 60)
    original.require_matching_history_scope(approved, source)
    require(approved['explicit_action'] is True and approved['archive_before'] == 0,
            'actual-recipient-original-explicit-approval')
    original.continue_original_history(a, source)
    require(a.ask('history-snapshot')['complete'], 'source-authenticated-final-receipt')
    if journey.args.platform == 'macos':
        private_json(journey.bridge / 'source-complete.json', {'source_complete': True})
    completed = journey.observe('completed.json', 60)
    require(all(completed.get(k) == v for k, v in {
        'consent_complete': True, 'imported_records': 1, 'reader_verified': True, 'owner_retired': True}.items()),
        'actual-recipient-app-complete-and-retired')
    if journey.args.platform == 'macos':
        require(completed.get('runtime_closed') is True, 'actual-mac-recipient-runtime-closed')
    journey.verify_app()
    reopened = journey.open('recipient')
    actual = reopened.ask('resume')
    require(actual['account'] == account and actual['original_session_restored'] is False,
            'recipient-reopen-does-not-reconstruct-original')
    original.verify_history_import(reopened, c, source, {'complete': True, 'imported': 1}, previous)
    journey.report['original_scope_and_exact_import_verified'] = True


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--scenario', choices=('automatic-switch', 'imported-reader', 'source-picker',
                                             'source-transfer', 'recipient-transfer', 'paired-direct'), required=True)
    parser.add_argument('--platform', choices=('macos', 'ios-simulator'), required=True)
    for name in ('mac-agent', 'sim-agent', 'relay', 'base', 'environment', 'application-command',
                 'app-result-bundle', 'output'):
        parser.add_argument('--' + name, type=Path, required=True)
    for name in ('mac-sha', 'sim-sha', 'simulator', 'sdk-source', 'sdk-run-id'):
        parser.add_argument('--' + name, required=True)
    args = parser.parse_args()
    require(os.environ.get('GITHUB_ACTIONS') == 'true', 'hosted-ci-only')
    require(args.sdk_source == os.environ['SOURCE_SHA'] and args.sdk_run_id == os.environ['SDK_RUN_ID'],
            'workflow-sdk-producer-must-match')
    require(re.fullmatch('[0-9a-f]{40}', args.sdk_source) and args.sdk_run_id.isdigit(), 'exact-sdk-producer-required')
    for agent, sha in ((args.mac_agent, args.mac_sha), (args.sim_agent, args.sim_sha)):
        require(agent.is_absolute() and re.fullmatch('[0-9a-f]{64}', sha) and digest(agent) == sha,
                'exact-native-executable-required')
    require(args.relay.is_absolute() and args.application_command.is_absolute()
            and args.application_command.stat().st_mode & 0o777 == 0o600, 'private-explicit-app-command')
    require(args.output.is_absolute() and args.environment.is_absolute()
            and not args.output.is_relative_to(args.base), 'aggregate-output-outside-private-base')
    require(args.base.is_absolute() and not args.base.exists() and not args.environment.exists()
            and not args.output.exists() and not args.app_result_bundle.exists(), 'fresh-owned-paths-required')
    inventory = json.loads(subprocess.check_output(['xcrun', 'simctl', 'list', 'devices', '--json'], text=True))
    devices = [row for rows in inventory['devices'].values() for row in rows if row['udid'] == args.simulator]
    require(len(devices) == 1 and devices[0]['name'] == 'WN-Upstream-UI-' + os.environ['GITHUB_RUN_ID']
            and devices[0]['state'] == 'Booted', 'fresh-booted-job-owned-simulator-required')
    verify_helpers()
    os.umask(0o077)
    args.base.mkdir(mode=0o700)
    require(args.base == args.base.resolve(), 'canonical-fresh-ci-base-required')
    journey = Journey(args)
    relay = None
    started = time.monotonic()
    try:
        with socket.socket() as probe:
            probe.bind(('127.0.0.1', 18181))
        with (args.base / 'relay-private.stderr').open('x') as log:
            relay = subprocess.Popen([str(args.relay), '--port', '18181'], stdout=subprocess.PIPE, stderr=log)
            require(bool(select.select([relay.stdout], [], [], 10)[0]), 'relay-ready-timeout')
            require(relay.stdout.readline().decode().strip() == 'ws://127.0.0.1:18181', 'exact-owned-loopback-relay')
            journey.report['phase'] = 'native-fixture-and-app'
            if args.scenario == 'paired-direct':
                paired_direct(journey)
            elif args.scenario == 'source-transfer':
                source_transfer(journey)
            elif args.scenario == 'recipient-transfer':
                recipient_transfer(journey)
            else:
                closed_fixture(journey)
            journey.report['passed'] = 1
            journey.report['phase'] = 'completed'
    except (GateFailure, OSError, ValueError, KeyError, subprocess.SubprocessError) as error:
        stage = str(error) if isinstance(error, GateFailure) else type(error).__name__
        journey.report['failure_stage'] = stage if re.fullmatch('[A-Za-z0-9:_-]{1,180}', stage) else 'fixture-refused'
    finally:
        journey.stop_app()
        try:
            journey.close_workers()
        except GateFailure:
            journey.report['passed'] = 0
            journey.report['private_cleanup_deferred_to_ephemeral_runner'] = True
        if relay is not None:
            was_running = relay.poll() is None
            if was_running:
                relay.send_signal(signal.SIGINT)
            try:
                output, _ = relay.communicate(timeout=10)
                receipt = re.fullmatch(rb'admitted_events=([0-9]+)\n', output)
                positive = was_running and relay.returncode == 0 and receipt is not None
                journey.report['relay_cleanup'] = {'passed': int(positive), 'exit_code': relay.returncode,
                    'admitted_events': int(receipt[1]) if receipt else None}
                if not positive:
                    journey.report['passed'] = 0
            except subprocess.TimeoutExpired:
                relay.kill()
                relay.communicate(timeout=10)
                journey.report['relay_required_termination'] = True
                journey.report['relay_cleanup'] = {'passed': 0, 'forced_termination': True}
                journey.report['passed'] = 0
        if journey.report.get('app_required_termination'):
            journey.report['passed'] = 0
            journey.report['private_cleanup_deferred_to_ephemeral_runner'] = True
        journey.report['seconds'] = round(time.monotonic() - started, 3)
        private_json(args.output, journey.report)
        # Only the freshly created private tree is retired, after all workers
        # and owned app runners have stopped. Never upload credential or IPC files.
        if not journey.report.get('private_cleanup_deferred_to_ephemeral_runner'):
            shutil.rmtree(args.base)
            args.environment.unlink(missing_ok=True)
    return 0 if journey.report['passed'] == 1 else 1


if __name__ == '__main__':
    raise SystemExit(main())
