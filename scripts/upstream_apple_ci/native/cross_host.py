#!/usr/bin/env python3
"""Private original-handle controller; stdout contains aggregate results only."""
import argparse
from concurrent.futures import ThreadPoolExecutor
import hashlib
import json
import os
from pathlib import Path
import select
import shlex
import subprocess
import time


class GateFailure(Exception):
    pass


class Peer:
    def __init__(self, command, error_log):
        self.closed_successfully = False
        self.error_log = error_log.open('xb')
        self.process = subprocess.Popen(command, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                        stderr=self.error_log)

    def ask(self, command, **fields):
        payload = json.dumps({'command': command, **fields}, separators=(',', ':')).encode() + b'\n'
        if len(payload) > 65536:
            raise GateFailure('controller-frame-bound')
        self.process.stdin.write(payload)
        self.process.stdin.flush()
        deadline = time.monotonic() + 90
        line = bytearray()
        while not line.endswith(b'\n'):
            remaining = deadline - time.monotonic()
            if remaining <= 0 or not select.select([self.process.stdout], [], [], remaining)[0]:
                raise GateFailure('controller-response-timeout')
            byte = os.read(self.process.stdout.fileno(), 1)
            if not byte or len(line) >= 4 * 1024 * 1024:
                raise GateFailure('controller-output-bound-or-closed')
            line.extend(byte)
        try:
            reply = json.loads(line)
        except (UnicodeDecodeError, json.JSONDecodeError):
            raise GateFailure('controller-invalid-response') from None
        if not reply.get('ok'):
            # Agent emits whitelisted stages/categories, never SDK payloads.
            raise GateFailure('agent-' + reply.get('stage', 'unknown') + '-' + reply.get('category', 'unknown'))
        return reply.get('value')

    def close_pipes(self):
        failed = False
        for pipe in (self.process.stdin, self.process.stdout):
            if pipe is not None:
                try:
                    pipe.close()
                except OSError:
                    failed = True
        if failed:
            raise GateFailure('controller-pipe-cleanup-failed')

    def close(self):
        if self.process.poll() is not None:
            self.close_pipes()
            self.error_log.close()
            if self.closed_successfully and self.process.returncode == 0:
                return
            raise GateFailure('original-agent-exited-before-confirmed-close')
        failure = None
        try:
            self.ask('close')
            self.process.wait(timeout=10)
            if self.process.returncode != 0:
                raise GateFailure('original-agent-nonzero-after-close')
            self.closed_successfully = True
        except (GateFailure, subprocess.TimeoutExpired, BrokenPipeError) as error:
            if isinstance(error, subprocess.TimeoutExpired):
                cause = 'exit-timeout-after-close-ack'
            elif isinstance(error, BrokenPipeError):
                cause = 'closed-input-pipe'
            else:
                # Preserve a useful fixed cause, never arbitrary peer reply fields.
                cause = {
                    'agent-agent-close-sdk': 'sdk-close-refused',
                    'controller-response-timeout': 'close-reply-timeout',
                    'controller-output-bound-or-closed': 'closed-before-close-ack',
                    'controller-invalid-response': 'invalid-close-reply',
                    'original-agent-nonzero-after-close': 'nonzero-after-close-ack',
                }.get(str(error), 'unknown-close-refusal')
            failure = GateFailure('original-agent-cleanup-failed:' + cause)
            self.process.terminate()
            try:
                self.process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self.process.kill()
                self.process.wait()
        self.close_pipes()
        self.error_log.close()
        if failure:
            raise failure


def require(condition, stage):
    if not condition:
        raise GateFailure(stage)


def drain(source, destination):
    for packet in source.ask('packets'):
        destination.ask('receive', packet=packet['packet'])
        source.ask('acknowledge', acknowledgement=packet['acknowledgement'])


def supported_companion(peer, secret):
    """Displayed-revision onboarding; no fresh-publication repair or ready shortcut."""
    value = peer.ask('onboarding-begin', secret=secret)
    deadline = time.monotonic() + 90
    while not value['ready']:
        require(time.monotonic() < deadline, 'supported-companion-onboarding-timeout')
        if value.get('needs_companion_ack'):
            value = peer.ask('onboarding-ack', revision=value['revision'])
        else:
            value = peer.ask('onboarding-run')
        if not value['ready']:
            time.sleep(0.1)
    return value


def first_pair(a, b, c=None, *, automatic=False, identity=None, retain_completed=False):
    identity = a.ask('create') if identity is None else identity
    slots = a.ask('package-observation') if automatic else None
    importer = supported_companion if automatic else lambda peer, secret: peer.ask('import', secret=secret)
    imported = importer(b, identity['secret'])
    require(identity['account'] == imported['account'], 'same-fresh-account')
    if c is not None:
        third = importer(c, identity['secret'])
        require(third['account'] == identity['account'], 'same-fresh-third-account')
    if automatic:
        require(a.ask('package-observation') == slots, 'companion-preserves-public-slot-set')
    del identity['secret']
    request = b.ask('begin')
    challenge = a.ask('approve', packet=request['packet'])
    b.ask('setup', packet=challenge['packet'])
    for _ in range(8):
        drain(a, b)
        drain(b, a)
    av, bv = a.ask('snapshot'), b.ask('snapshot')
    require(av['phase'] == bv['phase'] == 'comparisonAvailable', 'comparison-phase')
    require(av.get('comparison') and av['comparison'] == bv.get('comparison'), 'same-actual-comparison')
    a.ask('confirm', revision=av['revision'])
    b.ask('confirm', revision=bv['revision'])
    for _ in range(8):
        drain(a, b)
        drain(b, a)
    require(a.ask('snapshot')['phase'] == b.ask('snapshot')['phase'] ==
            'verificationCompleteEnrollmentPending', 'verification-complete')
    b.ask('continue-share' if automatic else 'continue', revision=b.ask('snapshot')['revision'])
    a.ask('continue-share' if automatic else 'continue', revision=a.ask('snapshot')['revision'])
    deadline = time.monotonic() + 30
    while time.monotonic() < deadline:
        av, bv = a.ask('snapshot'), b.ask('snapshot')
        if av['phase'] == bv['phase'] == 'enrollmentComplete':
            break
        time.sleep(0.05)
    else:
        raise GateFailure('real-cross-host-enrollment-completion')
    for peer in (a, b):
        targets = peer.ask('targets')
        require(len(targets) == 1 and targets[0]['device_count'] == 2, 'actual-two-device-target')
    if not retain_completed:
        a.ask('cancel')
        b.ask('cancel')
    return identity['account']



def third_device(a, b, c, diagnostics=None, *, automatic=False, retain_completed=False):
    targets = a.ask('targets')
    require(len(targets) == 1 and targets[0]['device_count'] == 2, 'actual-predecessor-two')
    request = c.ask('begin')
    challenge = a.ask('approve', packet=request['packet'], target=targets[0]['selector'])
    c.ask('setup', packet=challenge['packet'])
    for _ in range(8):
        drain(a, c)
        drain(c, a)
    av, cv = a.ask('snapshot'), c.ask('snapshot')
    require(av['phase'] == cv['phase'] == 'comparisonAvailable', 'third-comparison-phase')
    require(av.get('comparison') and av['comparison'] == cv.get('comparison'), 'third-actual-comparison')
    a.ask('confirm', revision=av['revision'])
    c.ask('confirm', revision=cv['revision'])
    for _ in range(8):
        drain(a, c)
        drain(c, a)
    c.ask('continue-share' if automatic else 'continue', revision=c.ask('snapshot')['revision'])
    a.ask('continue-share' if automatic else 'continue', revision=a.ask('snapshot')['revision'])
    deadline = time.monotonic() + 30
    while time.monotonic() < deadline:
        count = b.ask('approval-pending')['count']
        require(count <= 1, 'single-original-approval-required')
        if count == 1:
            break
        time.sleep(0.05)
    else:
        raise GateFailure('real-original-sibling-approval-arrival')
    observed = b.ask('approval-snapshot')
    require(observed['phase'] == 'awaitingApproval', 'original-sibling-awaiting-explicit-action')
    review = b.ask('approval-review', revision=observed['revision'])
    require(review['review_valid'] and len(review['source']) == len(review['joining']) == 64 and
            review['source'] != review['joining'], 'actual-sibling-review')
    # An opaque export must remain denied until B explicitly approves its original action.
    try:
        a.ask('enrollment-packet', revision=a.ask('snapshot')['revision'])
    except GateFailure as error:
        require(str(error) == 'agent-original-enrollment-packet-sdk-not-ready', 'missing-approval-typed-denial')
    else:
        raise GateFailure('missing-sibling-approval-must-deny-export')
    b.ask('approval-share' if automatic else 'approval-explicit', revision=observed['revision'])
    deadline = time.monotonic() + 30
    while time.monotonic() < deadline:
        try:
            packet = a.ask('enrollment-packet', revision=a.ask('snapshot')['revision'])['packet']
            break
        except GateFailure as error:
            require(str(error) == 'agent-original-enrollment-packet-sdk-not-ready', 'all-leaf-export-typed-error')
            time.sleep(0.05)
    else:
        raise GateFailure('real-all-leaf-packet-arrival')
    c.ask('enrollment-receive', revision=c.ask('snapshot')['revision'], packet=packet)
    b.ask('approval-receive', revision=b.ask('approval-snapshot')['revision'], packet=packet)
    a.ask('finalize', revision=a.ask('snapshot')['revision'])
    deadline = time.monotonic() + 30
    transitions = []
    while time.monotonic() < deadline:
        snapshots = {'coordinator': a.ask('snapshot'), 'joining': c.ask('snapshot'),
                     'sibling': b.ask('approval-snapshot')}
        phases = {role: value['phase'] for role, value in snapshots.items()}
        if diagnostics is not None:
            diagnostics['native_three_device_phases'] = phases
            if not transitions or transitions[-1] != snapshots:
                if len(transitions) < 32:
                    transitions.append(snapshots)
                else:
                    diagnostics['native_three_device_transitions_truncated'] = True
            diagnostics['native_three_device_transitions'] = transitions
        if phases['coordinator'] == phases['joining'] == 'enrollmentComplete' and phases['sibling'] == 'settled':
            break
        time.sleep(0.05)
    else:
        raise GateFailure('real-three-device-settlement')
    for peer in (a, b, c):
        actual = peer.ask('targets')
        require(len(actual) == 1 and actual[0]['device_count'] == 3, 'actual-three-device-target')
    if not retain_completed:
        a.ask('cancel')
        c.ask('cancel')
    return review


def selected_chat(a, b, c, d, history=False, account=None):
    ordinary = d.ask('create')
    del ordinary['secret']
    d.ask('publish-key-package')
    chat = a.ask('create-chat', member=ordinary['account'])['group']
    deadline = time.monotonic() + 30
    while time.monotonic() < deadline:
        try:
            if d.ask('group-state', group=chat)['members'] == 2:
                break
        except GateFailure as error:
            require(str(error) == 'agent-actual-chat-membership-sdk', 'ordinary-chat-join-error')
        time.sleep(0.05)
    else:
        raise GateFailure('real-ordinary-recipient-join')
    old_text = ('native-pre-join-' + os.urandom(8).hex()).ljust(8192, 'x') if history else 'native-pre-join-' + os.urandom(8).hex()
    old_tags = [['t', 'native-history']] if history else []
    if history:
        old_id = a.ask('send-history-text', group=chat, text=old_text, tags=old_tags)['message']
    else:
        old_id = a.ask('send-text', group=chat, text=old_text)['message']
    deadline = time.monotonic() + 30
    while time.monotonic() < deadline:
        if d.ask('message-seen', group=chat, message=old_id, text=old_text)['seen']:
            break
        time.sleep(0.05)
    else:
        raise GateFailure('actual-pre-join-ordinary-delivery')
    for peer in (b, c):
        require(not peer.ask('message-seen', group=chat, message=old_id, text=old_text)['seen'],
                'no-chat-history-before-original-consent')
    target = a.ask('targets')
    require(len(target) == 1 and target[0]['device_count'] == 3, 'actual-copy-target-three')
    a.ask('copy-begin', group=chat, target=target[0]['selector'])
    observed = a.ask('copy-snapshot')
    require(observed['siblings'] == 2 and observed['consenting'] == observed['offered'] == 0,
            'original-copy-no-inherited-consent')
    request = a.ask('copy-request', revision=observed['revision'])['packet']
    for peer in (b, c):
        peer.ask('consent-receive', packet=request)
        current = peer.ask('consent-snapshot')
        require(current['phase'] == 'awaitingApproval' and current['selector'] == chat, 'exact-authenticated-chat-review')
        try:
            peer.ask('consent-response', revision=current['revision'])
        except GateFailure as error:
            require(str(error) == 'agent-original-chat-consent-response-sdk', 'original-consent-denial-error')
        else:
            raise GateFailure('chat-consent-required-before-response')
        peer.ask('consent-explicit', revision=current['revision'])
        current = peer.ask('consent-snapshot')
        require(current['phase'] == 'approved', 'original-chat-explicitly-approved')
        response = peer.ask('consent-response', revision=current['revision'])['packet']
        a.ask('copy-response', revision=a.ask('copy-snapshot')['revision'], packet=response)
        offer = peer.ask('consent-offer', revision=current['revision'])['packet']
        require(peer.ask('consent-offer', revision=current['revision'])['packet'] == offer, 'exact-owned-offer-retry')
        a.ask('copy-offer', revision=a.ask('copy-snapshot')['revision'], packet=offer)
    current = a.ask('copy-snapshot')
    require(current['consenting'] == current['offered'] == 2, 'all-original-chat-consents-and-offers')
    a.ask('copy-continue', revision=current['revision'])
    require(a.ask('copy-snapshot')['phase'] == 'inviteConfirmed', 'actual-selected-invite-confirmed')
    deadline = time.monotonic() + 30
    while time.monotonic() < deadline:
        complete = True
        for peer in (a, b, c, d):
            try:
                complete &= peer.ask('group-state', group=chat)['members'] == 4
            except GateFailure as error:
                require(str(error) == 'agent-actual-chat-membership-sdk', 'selected-chat-membership-error')
                complete = False
        if complete:
            break
        time.sleep(0.05)
    else:
        raise GateFailure('real-four-member-selected-chat')
    for peer in (b, c):
        require(not peer.ask('message-seen', group=chat, message=old_id, text=old_text)['seen'],
                'selected-admission-does-not-copy-history')
    text = 'native-cross-host-delivery-' + os.urandom(8).hex()
    sent = b.ask('send-text', group=chat, text=text)['message']
    deadline = time.monotonic() + 30
    while time.monotonic() < deadline:
        if all(peer.ask('message-seen', group=chat, message=sent, text=text)['seen'] for peer in (a, b, c, d)):
            return {'group': chat, 'message': sent, 'text': text, 'old_message': old_id,
                    'old_text': old_text, 'old_tags': old_tags, 'author': account}
        time.sleep(0.05)
    raise GateFailure('real-cross-host-new-message-delivery')


def history_recipient_query(a, b, c, recipient, chat):
    """Verify actual Core observations without creating a request or permission."""
    values = a.ask('history-recipients', group=chat)
    require(isinstance(values, list) and len(values) == 2, 'actual-two-linked-history-recipients')
    devices, leaves = set(), set()
    for value in values:
        require(isinstance(value, dict), 'history-recipient-record')
        device, leaf = value.get('device'), value.get('leaf_index')
        require(isinstance(device, str) and len(device) == 64 and
                all(ch in '0123456789abcdef' for ch in device), 'history-recipient-device')
        require(type(leaf) is int and 0 <= leaf <= 0xffffffff, 'history-recipient-leaf')
        require(device not in devices and leaf not in leaves, 'unique-history-recipient-observations')
        devices.add(device)
        leaves.add(leaf)
    require(recipient in devices, 'authenticated-original-recipient-is-listed')
    for peer in (b, c):
        require(peer.ask('history-pending')['count'] == 0, 'listing-recipients-does-not-create-request')
    return {'eligible_recipients': len(values), 'query_created_requests': 0}


def history_alias_cancellation(a, b, c, recipient, chat):
    observed = a.ask('history-begin', group=chat, member=recipient)
    deadline = time.monotonic() + 30
    while True:
        count = b.ask('history-pending')['count']
        require(count <= 1, 'single-original-history-alias')
        if count == 1:
            break
        require(time.monotonic() < deadline, 'original-history-alias-arrival')
        time.sleep(0.05)
    require(b.ask('history-alias-cancel')['same_owner_cancelled'], 'same-original-history-alias-cancellation')
    a.ask('history-cancel')
    # Cancellation must deny a real method on the retained original, not just
    # clear its display/native reference. The revision comes from the original SDK snapshot.
    try:
        a.ask('history-continue', revision=observed['revision'])
    except GateFailure as error:
        require(str(error) == 'agent-original-history-continue-sdk-history-closed', 'cancelled-original-history-denial')
    else:
        raise GateFailure('cancelled-original-history-must-deny')
    for peer in (b, c):
        require(peer.ask('history-page', group=chat)['records'] == [], 'cancelled-history-does-not-import')
    a.ask('history-reset')
    b.ask('history-reset')


def history_final_alias_drop(a, b, c, recipient, chat):
    original = a.ask('history-begin', group=chat, member=recipient)
    deadline = time.monotonic() + 30
    while True:
        count = b.ask('history-pending')['count']
        require(count <= 1, 'single-original-history-final-alias')
        if count == 1:
            break
        require(time.monotonic() < deadline, 'original-history-final-alias-arrival')
        time.sleep(0.05)
    require(b.ask('history-alias-drop')['remaining_live'], 'one-history-alias-drop-preserves-original')
    # A separate RPC runs after the Swift helper/execute frame has returned.
    # No approval or explicit recipient cancel occurs before this observation.
    require(b.ask('history-pending')['count'] == 0, 'last-history-alias-drop-must-retire-original')
    observed = a.ask('history-snapshot')
    require(observed == original and not observed['complete'], 'last-drop-has-no-source-completion')
    for peer in (b, c):
        require(peer.ask('history-page', group=chat)['records'] == [], 'last-drop-does-not-import-history')
    a.ask('history-reset')


def history_transfer(a, b, c, recipient, previous, wait_seconds=30, diagnostics=None):
    # All values are observations from the retained original owners, never grants.
    chat = previous['group']
    for peer in (b, c):
        require(peer.ask('history-page', group=chat)['records'] == [], 'empty-archive-before-history-consent')
    source = a.ask('history-begin', group=chat, member=recipient)
    require(source['group'] == chat and source['recipient'] == recipient and
            len(source['source']) == 64 and source['records'] > 0 and
            not source['complete'], 'actual-original-history-selection')
    deadline = time.monotonic() + wait_seconds
    while True:
        count = b.ask('history-pending')['count']
        require(count <= 1, 'single-original-history-consent')
        if count == 1:
            break
        require(time.monotonic() < deadline, 'original-history-request-arrival')
        time.sleep(0.05)
    consent = b.ask('history-consent-snapshot')
    for field in ('group', 'source', 'recipient', 'records', 'encoded_bytes', 'fragments', 'ceiling'):
        require(consent[field] == source[field], 'exact-original-history-review')
    require(not consent['complete'] and consent['imported'] == 0, 'no-inherited-history-approval')
    require(b.ask('history-page', group=chat)['records'] == [], 'polling-does-not-import-history')
    b.ask('history-approve', revision=consent['revision'])
    a.ask('history-continue', revision=source['revision'])
    while True:
        sender = a.ask('history-snapshot')
        receiver = b.ask('history-consent-snapshot')
        if sender['complete'] and receiver['complete']:
            break
        require(time.monotonic() < deadline, 'committed-native-history-import')
        time.sleep(0.05)
    receipt = verify_history_import(b, c, source, receiver, previous)
    if diagnostics is not None:
        diagnostics.update(receipt['counts'])
    return {'record': receipt['record'], 'source_complete': sender['complete'],
            'recipient_complete': receiver['complete']}


def verify_history_import(b, c, source, receiver, previous):
    chat = previous['group']
    page = b.ask('history-page', group=chat)
    matching = [record for record in page['records'] if record['message'] == previous['old_message']]
    require(len(matching) == 1, 'exact-prejoin-history-record')
    record = matching[0]
    require(record['content'] == previous['old_text'] and record['tags'] == previous['old_tags'] and
            record['author'] == previous['author'] and record['created_at'] > 0 and
            record['expires_at'] is None and not record['deleted'] and record['media_count'] == 0,
            'actual-bounded-prejoin-history-presentation')
    require(record['source'] == source['source'] and
            all(isinstance(record[field], str) and len(record[field]) == 64 and
                all(ch in '0123456789abcdef' for ch in record[field]) for field in ('transfer', 'manifest')),
            'actual-source-attested-history-provenance')
    require(c.ask('history-page', group=chat)['records'] == [], 'nonrecipient-history-remains-empty')
    live_seen = None
    if 'message' in previous:
        live_seen = b.ask('message-seen', group=chat, message=previous['message'], text=previous['text'])['seen']
    if 'message' in previous:
        # This isolated fixture has exactly the prejoin record plus the known
        # postjoin record already delivered to B. Storage preserves live rows
        # instead of inserting an archive duplicate; no unexplained deficit passes.
        require(live_seen is True and len(page['records']) == len(matching) == 1 and
                receiver['imported'] == len(matching) and source['records'] == receiver['imported'] + 1,
                'exact-history-import-plus-live-precedence')
    else:
        require(receiver['imported'] == source['records'], 'exact-committed-history-record-count')
    return {'record': record, 'counts': {
        'source_records': source['records'], 'imported_records': receiver['imported'],
        'archive_page_records': len(page['records']), 'verified_prejoin_records': len(matching),
        'postjoin_live_record_present': live_seen,
        'source_complete': True, 'recipient_complete': receiver['complete']}}



def wait_message(peers, chat, message, text, stage):
    deadline = time.monotonic() + 30
    while time.monotonic() < deadline:
        if all(peer.ask('message-seen', group=chat, message=message, text=text)['seen'] for peer in peers):
            return
        time.sleep(0.05)
    raise GateFailure(stage)



def write_ios_reader_handoff(path, recipient, root, account, previous, receipt):
    # This is a private read-observation contract, never consent or an SDK owner.
    require(recipient.closed_successfully and recipient.process.poll() == 0,
            'reader-reopen-requires-verified-original-shutdown')
    require(receipt is not None and receipt['source_complete'] and receipt['recipient_complete'],
            'reader-reopen-requires-committed-import')
    record = receipt['record']
    require(record['message'] == previous['old_message'] and record['content'] == previous['old_text'],
            'reader-handoff-requires-exact-verified-record')
    value = {'version': 1, 'root': root, 'account': account, 'group': previous['group'],
             'live_message': previous['message'], 'record': record}
    path = Path(path)
    try:
        descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(descriptor, 'w') as stream:
            json.dump(value, stream, sort_keys=True)
            stream.write('\n')
    except OSError:
        raise GateFailure('private-reader-handoff-write-refused') from None


def write_source_picker_handoff(path, source, root, account, group, recipient_count, expected_recipient=None):
    # Observation-only: the app must query Core again and create its own original.
    require(source.closed_successfully and source.process.poll() == 0,
            'source-picker-reopen-requires-verified-original-shutdown')
    require(recipient_count == 2, 'source-picker-requires-native-eligible-roster')
    value = {'version': 1, 'root': root, 'account': account, 'group': group,
             'recipient_count': recipient_count}
    if expected_recipient is not None:
        require(isinstance(expected_recipient, str) and len(expected_recipient) == 64 and
                all(ch in '0123456789abcdef' for ch in expected_recipient),
                'source-handoff-requires-observed-native-device')
        value.update(version=2, expected_recipient=expected_recipient)
    try:
        descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(descriptor, 'w') as stream:
            json.dump(value, stream, sort_keys=True)
            stream.write('\n')
    except OSError:
        raise GateFailure('private-source-picker-handoff-write-refused') from None


def remote_serve_command(args, state, role):
    if args.simulator_binary and args.simulator_role == role:
        return ['ssh', 'macbook.m5', '/usr/bin/env',
                'DEVELOPER_DIR=/Applications/Xcode.app/Contents/Developer',
                'xcrun', 'simctl', 'spawn', args.simulator_device, args.simulator_binary,
                'serve', state]
    return ['ssh', 'macbook.m5', args.remote_binary, 'serve', state]


def restart_offline(a, b, c, d, peers, args, output, account, previous):
    # Close every exact B owner and its runtime before A sends the offline message.
    b.close()
    peers.remove(b)
    offline_text = 'native-offline-delivery-' + os.urandom(8).hex()
    offline_id = a.ask('send-text', group=previous['group'], text=offline_text)['message']
    wait_message((a, c, d), previous['group'], offline_id, offline_text, 'actual-offline-live-recipient-delivery')
    reopened = Peer(remote_serve_command(args, args.remote_state, 'recipient'),
                    output.with_suffix('.b-reopened-private-stderr'))
    peers.append(reopened)
    actual = reopened.ask('resume')
    require(actual['account'] == account and actual['original_session_restored'] is False,
            'public-original-account-reopen-without-session-reconstruction')
    protected = reopened.ask('targets')
    require(len(protected) == 1 and protected[0]['device_count'] == 3, 'reopened-actual-protected-roster')
    require(reopened.ask('group-state', group=previous['group'])['members'] == 4, 'reopened-actual-selected-membership')
    require(reopened.ask('message-seen', group=previous['group'], message=previous['message'],
                         text=previous['text'])['seen'], 'actual-encrypted-message-persistence')
    wait_message((reopened,), previous['group'], offline_id, offline_text, 'actual-offline-relay-recovery')
    post_text = 'native-reopened-send-' + os.urandom(8).hex()
    post_id = reopened.ask('send-text', group=previous['group'], text=post_text)['message']
    wait_message((a, reopened, c, d), previous['group'], post_id, post_text, 'actual-post-restart-cross-host-delivery')
    return reopened


def simultaneous_messages(peers, chat):
    # One task per peer: no two threads read or write the same private RPC pipe.
    texts = ['native-concurrent-' + os.urandom(8).hex() for _ in peers]
    with ThreadPoolExecutor(max_workers=len(peers)) as executor:
        jobs = [executor.submit(peer.ask, 'send-text', group=chat, text=text)
                for peer, text in zip(peers, texts)]
        ids = [job.result()['message'] for job in jobs]
    require(len(set(ids)) == len(peers), 'independent-actual-concurrent-message-ids')
    for message, text in zip(ids, texts):
        wait_message(peers, chat, message, text, 'actual-concurrent-delivery-all-recipients')

def write_ios_approval_handoff(path, recipient, root, account, previous):
    require(recipient.closed_successfully and recipient.process.poll() == 0,
            'app-approval-requires-closed-original-runtime')
    value = {'version': 2, 'root': root, 'account': account, 'group': previous['group'],
             'live_message': previous['message'], 'old_message': previous['old_message'],
             'old_content': previous['old_text'], 'old_tags': previous['old_tags'],
             'author': previous['author']}
    try:
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, 'w') as stream:
            json.dump(value, stream)
    except FileExistsError:
        raise GateFailure('new-app-approval-handoff-required') from None


def app_bridge_read(directory, name):
    script = ('import pathlib,sys;p=pathlib.Path(sys.argv[1]);'
              'sys.stdout.write(p.read_text() if p.exists() else "null")')
    command = ['ssh', 'macbook.m5',
               'python3 -c ' + shlex.quote(script) + ' ' + shlex.quote(directory + '/' + name)]
    result = subprocess.run(command, capture_output=True, text=True)
    require(result.returncode == 0 and len(result.stdout) <= 32768, 'app-approval-observation-read')
    try:
        return json.loads(result.stdout)
    except ValueError:
        raise GateFailure('app-approval-observation-malformed') from None


def wait_app_bridge(directory, name, timeout=180):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        require(app_bridge_read(directory, 'failed.json') is None, 'app-original-approval-failed')
        value = app_bridge_read(directory, name)
        if value is not None:
            return value
        time.sleep(0.1)
    raise GateFailure('app-original-approval-timeout-' + name.split('.')[0])


def continue_original_history(source_peer, original):
    # Refresh the revision of the retained original; review fields are observations, not grants.
    current = source_peer.ask('history-snapshot')
    for field in ('group', 'source', 'recipient', 'records', 'encoded_bytes', 'fragments', 'ceiling'):
        require(current[field] == original[field], 'actual-source-original-review-unchanged')
    require(current['complete'] is False and type(current['revision']) is int and
            current['revision'] >= original['revision'], 'actual-source-original-current-revision')
    source_peer.ask('history-continue', revision=current['revision'])


def app_history_approval(a, b, c, recipient, account, previous, directory, output):
    # No original approval is serialized. The live app discovers its own pending original.
    b.close()
    handoff = output.with_suffix('.app-approval-handoff.json')
    write_ios_approval_handoff(handoff, b, previous['recipient_root'], account, previous)
    result = subprocess.run(['ssh', 'macbook.m5', 'mkdir', '-m', '700', directory], capture_output=True)
    require(result.returncode == 0, 'new-private-app-bridge-required')
    result = subprocess.run(['scp', str(handoff), 'macbook.m5:' + directory + '/fixture.json'], capture_output=True)
    require(result.returncode == 0, 'private-app-bridge-handoff')
    require(wait_app_bridge(directory, 'ready.json') == {'ready': True}, 'actual-app-recipient-ready')
    source = a.ask('history-begin', group=previous['group'], member=recipient)
    approved = wait_app_bridge(directory, 'approved.json', 60)
    for field in ('group', 'source', 'recipient', 'records', 'encoded_bytes', 'fragments', 'ceiling'):
        require(approved[field] == source[field], 'actual-app-original-review-binding')
    require(approved['explicit_action'] is True and approved['archive_before'] == 0,
            'actual-app-original-explicit-approval')
    continue_original_history(a, source)
    completion = wait_app_bridge(directory, 'completed.json', 60)
    require(completion == {'consent_complete': True, 'imported_records': 1,
                           'reader_verified': True, 'owner_retired': True}, 'actual-app-committed-import')
    require(a.ask('history-snapshot')['complete'], 'actual-source-original-complete')
    require(c.ask('history-page', group=previous['group'])['records'] == [], 'nonrecipient-archive-empty')
    return {'source_complete': True, 'recipient_complete': True, 'app_imported_records': 1}


def source_serve_command(args):
    if args.source_m5_state:
        return remote_serve_command(args, args.source_m5_state, 'source')
    return [args.binary, 'serve', args.local_state]


def app_bridge_write(directory, name, value):
    script = ('import os,json,sys;p=sys.argv[1];t=p+".pending";'
              'fd=os.open(t,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600);'
              'f=os.fdopen(fd,"w");json.dump(json.loads(sys.argv[2]),f);f.close();'
              'os.link(t,p);os.unlink(t)')
    command = ['ssh', 'macbook.m5', 'python3 -c ' + shlex.quote(script) + ' ' +
               shlex.quote(directory + '/' + name) + ' ' + shlex.quote(json.dumps(value))]
    require(subprocess.run(command, capture_output=True).returncode == 0,
            'private-source-app-observation-write')


def start_app_history_source(a, recipient, account, previous, args, output):
    # Stop the original runtime before the app opens the same source root.
    a.close()
    directory = args.ios_history_source_bridge or args.mac_history_source_bridge
    handoff = output.with_suffix('.app-source-handoff.json')
    write_source_picker_handoff(handoff, a, args.source_m5_state, account,
                                previous['group'], 2, expected_recipient=recipient)
    require(subprocess.run(['ssh', 'macbook.m5', 'mkdir', '-m', '700', directory],
                           capture_output=True).returncode == 0, 'new-private-source-app-bridge')
    require(subprocess.run(['scp', str(handoff), 'macbook.m5:' + directory + '/fixture.pending'],
                           capture_output=True).returncode == 0, 'private-source-app-handoff')
    publish = 'import os,sys;os.link(sys.argv[1],sys.argv[2]);os.unlink(sys.argv[1])'
    require(subprocess.run(['ssh', 'macbook.m5', 'python3 -c ' + shlex.quote(publish) + ' ' +
                           shlex.quote(directory + '/fixture.pending') + ' ' +
                           shlex.quote(directory + '/fixture.json')], capture_output=True).returncode == 0,
            'exclusive-atomic-source-handoff-publication')
    require(wait_app_bridge(directory, 'ready.json') == {'ready': True}, 'actual-source-app-ready')
    source = wait_app_bridge(directory, 'requested.json', 60)
    require(source['group'] == previous['group'] and source['recipient'] == recipient and
            source['records'] > 0 and source['complete'] is False and source['explicit_action'] is True,
            'actual-source-app-original-review')
    return directory, source


def app_history_source(a, b, c, recipient, account, previous, args, output):
    directory, source = start_app_history_source(a, recipient, account, previous, args, output)
    deadline = time.monotonic() + 30
    while b.ask('history-pending')['count'] != 1:
        require(time.monotonic() < deadline, 'actual-source-app-consent-arrival')
        time.sleep(0.05)
    consent = b.ask('history-consent-snapshot')
    for field in ('group', 'source', 'recipient', 'records', 'encoded_bytes', 'fragments', 'ceiling'):
        require(consent[field] == source[field], 'actual-source-app-review-consent-binding')
    require(b.ask('history-page', group=previous['group'])['records'] == [] and
            consent['imported'] == 0 and not consent['complete'], 'source-app-request-does-not-import')
    b.ask('history-approve', revision=consent['revision'])
    app_bridge_write(directory, 'recipient-approved.json', {'approved': True})
    complete = wait_app_bridge(directory, 'completed.json', 60)
    require(complete == {'source_complete': True, 'original_retired': True, 'runtime_closed': True},
            'actual-source-app-original-completion-and-close')
    receiver = b.ask('history-consent-snapshot')
    require(receiver['complete'], 'actual-source-app-recipient-complete')
    receipt = verify_history_import(b, c, source, receiver, previous)
    return receipt


def require_matching_history_scope(observed, source):
    for field in ('group', 'source', 'recipient', 'records', 'encoded_bytes', 'fragments', 'ceiling'):
        require(observed[field] == source[field], 'both-app-original-review-binding')


def app_history_both(a, b, c, recipient, account, previous, args, output, peers):
    # Close B before A creates a NEW original: closing a pending B original cancels it.
    require(b.ask('history-pending')['count'] == 0, 'both-app-recipient-no-inherited-original')
    b.close()
    directory = args.mac_history_approval_bridge
    handoff = output.with_suffix('.mac-approval-handoff.json')
    write_ios_approval_handoff(handoff, b, args.remote_state, account, previous)
    require(subprocess.run(['ssh', 'macbook.m5', 'mkdir', '-m', '700', directory],
                           capture_output=True).returncode == 0, 'new-private-mac-recipient-bridge')
    fixture = json.loads(handoff.read_text())
    app_bridge_write(directory, 'fixture.json', fixture)
    require(wait_app_bridge(directory, 'ready.json') == {'ready': True}, 'actual-mac-recipient-ready')
    source_directory, source = start_app_history_source(a, recipient, account, previous, args, output)
    app_bridge_write(directory, 'source-requested.json', source)
    reviewed = wait_app_bridge(directory, 'reviewed.json', 60)
    require_matching_history_scope(reviewed, source)
    require(reviewed['imported'] == 0 and reviewed['complete'] is False and
            reviewed['explicit_action'] is False, 'actual-mac-review-does-not-import')
    approved = wait_app_bridge(directory, 'approved.json', 60)
    require_matching_history_scope(approved, source)
    require(approved['explicit_action'] is True and approved['archive_before'] == 0,
            'actual-mac-original-explicit-approval')
    app_bridge_write(source_directory, 'recipient-approved.json', {'approved': True})
    complete = wait_app_bridge(source_directory, 'completed.json', 60)
    require(complete == {'source_complete': True, 'original_retired': True, 'runtime_closed': True},
            'actual-ios-source-original-completion-and-close')
    # B stays alive for the source's final receipt, even after its local import completes.
    app_bridge_write(directory, 'source-complete.json', {'source_complete': True})
    completed = wait_app_bridge(directory, 'completed.json', 60)
    require(completed == {'consent_complete': True, 'imported_records': 1,
                          'reader_verified': True, 'owner_retired': True, 'runtime_closed': True},
            'actual-mac-recipient-import-and-positive-close')
    reopened = Peer(remote_serve_command(args, args.remote_state, 'recipient'),
                    output.with_suffix('.both-app-reader-private-stderr'))
    peers.append(reopened)
    actual = reopened.ask('resume')
    require(actual['account'] == account and actual['original_session_restored'] is False,
            'both-app-reader-no-original-reconstruction')
    # Completion observations come from the actual app original, never a recreated consent.
    receiver = {'imported': completed['imported_records'], 'complete': completed['consent_complete']}
    return verify_history_import(reopened, c, source, receiver, previous)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--binary', required=True)
    parser.add_argument('--remote-binary', required=True)
    parser.add_argument('--local-state', required=True)
    parser.add_argument('--remote-state', required=True)
    parser.add_argument('--output', required=True)
    parser.add_argument('--third-state')
    parser.add_argument('--chat-state')
    parser.add_argument('--restart-offline', action='store_true')
    parser.add_argument('--concurrent', action='store_true')
    parser.add_argument('--enrollment-diagnostic', action='store_true')
    parser.add_argument('--history', action='store_true')
    parser.add_argument('--recipient-query', action='store_true')
    parser.add_argument('--source-picker-handoff')
    parser.add_argument('--source-m5-state')
    parser.add_argument('--mac-history-source-bridge')
    parser.add_argument('--ios-history-source-bridge')
    parser.add_argument('--sdk-source', default='83f5a82d80c9f53bdcbab602f349544397ba07f6')
    parser.add_argument('--reader-handoff', '--ios-reader-handoff', dest='ios_reader_handoff')
    parser.add_argument('--ios-history-approval-bridge')
    parser.add_argument('--mac-history-approval-bridge')
    parser.add_argument('--simulator-binary')
    parser.add_argument('--simulator-device')
    parser.add_argument('--simulator-role', choices=('third', 'recipient', 'source'), default='third')
    args = parser.parse_args()
    require(len(args.sdk_source) == 40 and all(ch in '0123456789abcdef' for ch in args.sdk_source),
            'exact-sdk-source-required')
    require(not args.history or (args.chat_state and args.third_state and
            args.sdk_source != '83f5a82d80c9f53bdcbab602f349544397ba07f6'),
            'history-requires-matched-new-sdk-and-real-selected-chat')
    require(not args.recipient_query or args.history, 'recipient-query-requires-genuine-history')
    require(not args.enrollment_diagnostic or args.third_state,
            'enrollment-diagnostic-requires-three-originals')
    require(not args.enrollment_diagnostic or not (args.restart_offline or args.concurrent or
            args.source_picker_handoff or args.ios_reader_handoff or args.ios_history_approval_bridge),
            'enrollment-diagnostic-refuses-transfer-and-recovery-handoffs')
    require(not args.source_picker_handoff or (args.recipient_query and not args.ios_history_approval_bridge),
            'source-picker-handoff-requires-qualified-native-query')
    require(not args.simulator_binary or (args.simulator_device and args.third_state),
            'dedicated-simulator-and-third-required')
    require(args.simulator_role == 'third' or args.simulator_binary,
            'simulator-targeted-role-requires-binary')
    require(not (args.ios_history_source_bridge and args.mac_history_source_bridge),
            'one-source-app-platform-required')
    require(not args.ios_history_source_bridge or
            (args.simulator_binary and args.simulator_role == 'source'),
            'ios-source-app-requires-native-simulator-source')
    require(args.simulator_role != 'source' or args.ios_history_source_bridge,
            'simulator-source-requires-ios-source-app-bridge')
    require(not args.ios_reader_handoff or
            args.history,
            'reader-handoff-requires-genuine-recipient-history')
    require(not args.ios_history_approval_bridge or (args.history and args.simulator_role == 'recipient' and
            not args.ios_reader_handoff and not args.restart_offline and not args.concurrent),
            'app-approval-bridge-requires-isolated-ios-history')
    source_app_bridge = args.ios_history_source_bridge or args.mac_history_source_bridge
    require(bool(args.source_m5_state) == bool(source_app_bridge),
            'source-app-requires-explicit-m5-root-and-bridge')
    require(not source_app_bridge or (args.history and args.recipient_query and
            not args.ios_history_approval_bridge and not args.source_picker_handoff and
            not args.ios_reader_handoff and not args.restart_offline and not args.concurrent),
            'source-app-bridge-requires-isolated-genuine-history')
    require(not args.mac_history_approval_bridge or
            (args.ios_history_source_bridge and args.history and args.recipient_query and
             not args.enrollment_diagnostic and not args.ios_history_approval_bridge and
             not args.source_picker_handoff and not args.ios_reader_handoff and
             not args.restart_offline and not args.concurrent),
            'both-app-bridge-requires-isolated-ios-source-and-mac-recipient')
    require(not args.mac_history_approval_bridge or
            args.mac_history_approval_bridge != args.ios_history_source_bridge,
            'both-app-bridges-must-be-distinct')
    os.umask(0o077)
    output = Path(args.output)
    output.parent.mkdir(parents=True, exist_ok=True)
    require(not output.exists(), 'new-result-required')
    peers = []
    failure = None
    observations = {}
    history_receipt = None
    source_recipient_count = None
    started = time.monotonic()
    try:
        a = Peer(source_serve_command(args), output.with_suffix('.m5-source-private-stderr' if args.source_m5_state else '.m1-private-stderr'))
        peers.append(a)
        b = Peer(remote_serve_command(args, args.remote_state, 'recipient'),
                 output.with_suffix('.m5-private-stderr'))
        peers.append(b)
        c = None
        if args.third_state:
            command = remote_serve_command(args, args.third_state, 'third')
            c = Peer(command, output.with_suffix('.c-private-stderr'))
            peers.append(c)
        account = first_pair(a, b, c)
        if c is not None:
            # History needs B's authenticated occupied signer. It comes from A's
            # original sibling review of the actual B/C enrollment, never packet parsing.
            review = third_device(b, a, c, observations) if args.history else third_device(a, b, c)
        if args.chat_state and not args.enrollment_diagnostic:
            require(c is not None, 'chat-requires-real-third-device')
            chat_command = ([args.binary, 'serve', args.chat_state] if args.source_m5_state else
                            ['ssh', 'macbook.m5', args.remote_binary, 'serve', args.chat_state])
            d = Peer(chat_command,
                     output.with_suffix('.d-private-stderr'))
            peers.append(d)
            previous = selected_chat(a, b, c, d, history=args.history, account=account)
            if args.history:
                if args.recipient_query:
                    observations.update(history_recipient_query(a, b, c, review['source'], previous['group']))
                history_alias_cancellation(a, b, c, review['source'], previous['group'])
                history_final_alias_drop(a, b, c, review['source'], previous['group'])
                if args.mac_history_approval_bridge:
                    receipt = app_history_both(a, b, c, review['source'], account, previous,
                                              args, output, peers)
                    observations.update(receipt['counts'])
                    observations['app_source_model_complete'] = True
                    observations['app_recipient_model_complete'] = True
                elif source_app_bridge:
                    receipt = app_history_source(a, b, c, review['source'], account, previous, args, output)
                    observations.update(receipt['counts'])
                    observations['app_source_model_complete'] = True
                elif args.ios_history_approval_bridge:
                    previous['recipient_root'] = args.remote_state
                    history_receipt = app_history_approval(a, b, c, review['source'], account, previous,
                                                         args.ios_history_approval_bridge, output)
                    observations.update(history_receipt)
                else:
                    history_receipt = history_transfer(a, b, c, review['source'], previous, diagnostics=observations)
            if args.source_picker_handoff:
                choices = b.ask('history-recipients', group=previous['group'])
                require(len(choices) == 2 and len({row['device'] for row in choices}) == 2,
                        'source-picker-actual-recipient-roster')
                require(all(len(row['device']) == 64 and
                            all(ch in '0123456789abcdef' for ch in row['device']) for row in choices),
                        'source-picker-valid-native-devices')
                source_recipient_count = len(choices)
            if args.restart_offline:
                b = restart_offline(a, b, c, d, peers, args, output, account, previous)
            if args.concurrent:
                simultaneous_messages((a, b, c, d), previous['group'])
        elif not args.enrollment_diagnostic:
            require(not args.restart_offline and not args.concurrent, 'controls-require-real-selected-chat')
    except (GateFailure, BrokenPipeError) as error:
        failure = str(error) if isinstance(error, GateFailure) else 'controller-pipe-closed'
    finally:
        if args.enrollment_diagnostic:
            observations['native_rosters_before_close'] = []
            for peer in peers:
                try:
                    targets = peer.ask('targets')
                    observations['native_rosters_before_close'].append({
                        'target_count': len(targets),
                        'device_counts': [target['device_count'] for target in targets]})
                except GateFailure:
                    observations['native_rosters_before_close'].append({'query_failed': True})
        cleanup = {'originals': len(peers), 'closed': 0, 'failed': 0}
        for peer in peers:
            try:
                peer.close()
                cleanup['closed'] += 1
            except GateFailure:
                cleanup['failed'] += 1
                if failure is None:
                    failure = 'original-agent-cleanup-failed'
    if failure is None and args.ios_reader_handoff:
        try:
            write_ios_reader_handoff(args.ios_reader_handoff, b, args.remote_state,
                                     account, previous, history_receipt)
        except GateFailure as error:
            failure = str(error)
    if failure is None and args.source_picker_handoff:
        try:
            write_source_picker_handoff(args.source_picker_handoff, b, args.remote_state,
                                        account, previous['group'], source_recipient_count)
        except GateFailure as error:
            failure = str(error)
    result = {'gate': 'native-original-history' if args.history else ('native-simulator-selected-concurrent' if args.simulator_binary else ('native-cross-host-restart-offline' if args.restart_offline else ('native-cross-host-selected-delivery' if args.chat_state else ('native-cross-host-three-device' if args.third_state else 'native-cross-host-first-pair')))), 'passed': 0 if failure else 1,
              'failed': 1 if failure else 0, 'seconds': round(time.monotonic() - started, 2),
              'sdk_source': args.sdk_source,
              'binary_sha256': hashlib.sha256(Path(args.binary).read_bytes()).hexdigest(),
              'scope': 'Real original native SDK sessions on M1+M5; not installed application UI acceptance'}
    if args.simulator_binary:
        result['simulator_device'] = args.simulator_device
        result['simulator_role'] = args.simulator_role
        result['scope'] = 'Actual iOS simulator SDK peer plus M1/M5; not installed application UI acceptance'
    if args.mac_history_source_bridge:
        result['scope'] = 'Actual Mac source model with native recipient originals and M1/M5 relay delivery; not UI buttons or installed navigation'
    if args.ios_history_source_bridge:
        result['scope'] = 'Actual iOS simulator source app model with native recipient originals and M1/M5 relay delivery; not UI buttons or installed navigation'
    if args.mac_history_approval_bridge:
        result['scope'] = 'Actual iOS source app and Mac Session recipient models; independent public UI evidence required; not installed navigation'
    result['native_runtime_cleanup'] = cleanup
    if args.enrollment_diagnostic:
        result['gate'] = 'native-three-device-enrollment-diagnostic'
        result['scope'] = 'Native enrollment originals only; no source app fixture, chat or history transfer exercised'
    if args.history or args.enrollment_diagnostic:
        result['history_counts'] = observations
    if failure:
        result['failure_stage'] = failure
    output.write_text(json.dumps(result, indent=2) + '\n')
    print(json.dumps(result))
    return 1 if failure else 0


if __name__ == '__main__':
    raise SystemExit(main())
