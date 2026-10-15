"""Controller refusal controls only; real Apple SDK acceptance runs separately."""
import unittest
from types import SimpleNamespace
from unittest.mock import patch

import one_scan
from cross_host import GateFailure


class Peer:
    def __init__(self, comparison=(1, 2, 3), premature=None):
        self.comparison = comparison
        self.premature = premature
        self.confirmed = False
        self.shared = False
        self.calls = []
        self.other = None

    def ask(self, command, **fields):
        self.calls.append((command, fields))
        both = self.confirmed and self.other.confirmed
        if command == 'one-scan-begin':
            return {'packet': 'synthetic-bootstrap'}
        if command == 'snapshot':
            phase = ('enrollmentComplete' if self.shared and self.other.shared else
                     'verificationCompleteEnrollmentPending' if both else 'comparisonAvailable')
            return {'phase': phase, 'revision': 9 if both else 7, 'comparison': self.comparison}
        if command == 'confirm':
            self.confirmed = True
        if command == 'one-scan-share':
            if not both:
                if self.premature == 'always' or self.premature == 'after-first' and self.confirmed:
                    return None
                raise GateFailure('agent-one-scan-share-sdk-not-ready')
            self.shared = True
        return None


def peers(**kwargs):
    a, b = Peer(**kwargs), Peer()
    a.other, b.other = b, a
    return a, b


class Controls(unittest.TestCase):
    def test_failure_capture_reads_current_phases_without_approving_or_exporting(self):
        class ReadOnlyPeer:
            diagnostic_role = 'source'

            def __init__(self):
                self.commands = []

            def ask(self, command):
                self.commands.append(command)
                return dict(phase='awaitingSettlement' if command == 'approval-snapshot' else 'enrollmentComplete',
                            packet='private-packet', comparison=[111, 222, 333])

        display, scanner, existing = (ReadOnlyPeer() for _ in range(3))
        one_scan.capture_current_phases(display, scanner, existing)
        self.assertEqual(display.commands, ['snapshot'])
        self.assertEqual(scanner.commands, ['snapshot'])
        self.assertEqual(existing.commands, ['approval-snapshot'])
        self.assertEqual(one_scan.pairing_diagnostics([display, scanner, existing]), [
            dict(role='source', current_phase_at_failure='enrollmentComplete'),
            dict(role='source', current_phase_at_failure='enrollmentComplete'),
            dict(role='source', current_approval_at_failure='awaitingSettlement')])

    def test_local_workers_clear_inherited_public_routing(self):
        args = SimpleNamespace(agent='/test-agent', port=18485, public_chat_relay=None)
        with patch.dict(one_scan.os.environ, {'NATIVE_ACCEPTANCE_PUBLIC_CHAT_RELAY': one_scan.PUBLIC_CHAT_RELAYS[0]}):
            command = one_scan.worker_command(args, '/fresh-store')
        self.assertIn('NATIVE_ACCEPTANCE_PUBLIC_CHAT_RELAY=', command)
        self.assertIn('NATIVE_ACCEPTANCE_RELAY_PORT=18485', command)
        self.assertEqual(command[-3:], ['/test-agent', 'serve', '/fresh-store'])

    def test_public_workers_use_only_explicit_deployment_relays(self):
        for relay in one_scan.PUBLIC_CHAT_RELAYS:
            args = SimpleNamespace(agent='/test-agent', port=18485, public_chat_relay=relay)
            self.assertIn('NATIVE_ACCEPTANCE_PUBLIC_CHAT_RELAY=' + relay,
                          one_scan.worker_command(args, '/fresh-store'))
        for relay in ['ws://127.0.0.1:1234', 'https://example.com', 'wss://relay.eu.whitenoise.chat.evil.test']:
            args.public_chat_relay = relay
            with self.assertRaisesRegex(GateFailure, '^public-relay-not-allowed$'):
                one_scan.worker_command(args, '/fresh-store')

    def test_timeout_retains_only_phase_labels_without_sas_packet_or_identity(self):
        class WaitingPeer:
            diagnostic_role = 'third'

            def ask(self, command):
                return dict(phase='verificationCompleteEnrollmentPending', revision=99,
                            comparison=[111, 222, 333], packet='private-packet', account='private-account')

        peer = WaitingPeer()
        with patch.object(one_scan.time, 'monotonic', side_effect=[0, 0, 91]), \
             patch.object(one_scan.time, 'sleep'), \
             self.assertRaisesRegex(GateFailure, '^pairing-timeout-enrollmentComplete$'):
            one_scan.wait_phase(peer, 'enrollmentComplete')
        self.assertEqual(one_scan.pairing_diagnostics([peer]), [dict(
            role='third', expected_phase='enrollmentComplete',
            last_phase='verificationCompleteEnrollmentPending')])

    def test_diagnostics_refuse_unrecognized_labels_and_extra_fields(self):
        peer = Peer()
        peer.diagnostic_role = 'private-account'
        peer.diagnostic_pairing = dict(expected='enrollmentComplete', last='private-packet', comparison=[111])
        peer.diagnostic_approval_phase = 'private-packet'
        self.assertEqual(one_scan.pairing_diagnostics([peer]), [dict(
            role='test-device', expected_phase='enrollmentComplete', last_phase='unrecognized',
            approval_phase='unrecognized')])

    def test_unobserved_peer_adds_no_diagnostic_and_does_not_query_sdk(self):
        peer = Peer()
        self.assertEqual(one_scan.pairing_diagnostics([peer]), [])
        self.assertEqual(peer.calls, [])

    def test_synced_direct_lookup_must_return_the_same_reusable_conversation(self):
        class LookupPeer:
            def __init__(self, **result):
                self.result = result

            def ask(self, command, **fields):
                if command != 'direct-lookup' or fields != {'group': 'group', 'member': 'peer'}:
                    raise AssertionError('Lookup must not create or invite')
                return self.result

        good = dict(found=True, same_group=True, reusable=True, paired_source=False)
        observations = []
        one_scan.direct_lookup(LookupPeer(**good), 'group', 'peer', 'source', observations)
        self.assertEqual(observations, [dict(role='source', **good)])
        mirror = {**good, 'paired_source': True}
        one_scan.direct_lookup(LookupPeer(**mirror), 'group', 'peer', 'mirror', [])
        for field in ('found', 'same_group', 'reusable'):
            result = {**mirror, field: False}
            with self.subTest(field=field), self.assertRaisesRegex(GateFailure, 'direct-reuse-missing-mirror'):
                one_scan.direct_lookup(LookupPeer(**result), 'group', 'peer', 'mirror', [])
        with self.assertRaisesRegex(GateFailure, 'direct-route-provenance-mismatch-mirror'):
            one_scan.direct_lookup(LookupPeer(**good), 'group', 'peer', 'mirror', [])
        for result in [{**mirror, 'found': 1}, {**mirror, 'unexpected_payload': 'private fixture'}]:
            observations = []
            with self.assertRaisesRegex(GateFailure, 'malformed-direct-lookup'):
                one_scan.direct_lookup(LookupPeer(**result), 'group', 'peer', 'mirror', observations)
            self.assertEqual(observations, [])

    def test_existing_device_review_preserves_stale_revision_refusal(self):
        class Existing:
            def __init__(self, accept_stale=False, valid_review=True):
                self.accept_stale = accept_stale
                self.valid_review = valid_review
                self.approved = []

            def ask(self, command, **fields):
                if command == 'approval-pending':
                    return {'count': 1}
                if command == 'approval-snapshot':
                    return {'revision': 8}
                if command == 'approval-review':
                    return {'review_valid': self.valid_review}
                if command == 'approval-share':
                    if fields['revision'] != 8 and not self.accept_stale:
                        raise GateFailure('agent-original-explicit-broad-sibling-sdk-stale-revision')
                    self.approved.append(fields['revision'])
                    return None
                raise AssertionError('Unexpected manual transport')

        a, b = peers()
        original = Existing()
        one_scan.approve_existing_device(original, a, b)
        self.assertEqual(original.approved, [8])
        for original, failure in [(Existing(accept_stale=True), 'accepted-stale-approval'),
                                  (Existing(valid_review=False), 'review-invalid')]:
            with self.subTest(failure=failure):
                with self.assertRaisesRegex(GateFailure, failure):
                    one_scan.approve_existing_device(original, a, b)

    def test_one_scan_passes_existing_group_selector_unchanged(self):
        a, b = peers()
        one_scan.pair(a, b, target='opaque-existing-group-selector')
        approvals = [fields for command, fields in b.calls if command == 'one-scan-approve']
        self.assertEqual(approvals, [{'packet': 'synthetic-bootstrap',
                                     'target': 'opaque-existing-group-selector'}])

    def test_third_device_cannot_pass_with_ambiguous_or_bypassed_sibling_approval(self):
        class Existing:
            def __init__(self, count):
                self.count = count

            def ask(self, command):
                if command == 'approval-pending':
                    return {'count': self.count}
                raise AssertionError('No review or grant may follow a refused precondition')

        a, b = peers()
        with self.assertRaisesRegex(GateFailure, 'ambiguous-existing-device-approval'):
            one_scan.approve_existing_device(Existing(2), a, b)
        a.confirmed = b.confirmed = a.shared = b.shared = True
        with self.assertRaisesRegex(GateFailure, 'enrolled-before-existing-device-approval'):
            one_scan.approve_existing_device(Existing(1), a, b)

    def test_contacts_require_three_installations_and_live_reads_without_invites(self):
        class ContactPeer:
            def __init__(self, shared):
                self.shared = shared
                self.calls = []

            def ask(self, command, **fields):
                self.calls.append(command)
                if command == 'contact-follow':
                    self.shared[:] = [fields['member']]
                elif command == 'contact-unfollow':
                    self.shared.clear()
                elif command != 'contact-list':
                    raise AssertionError('Unexpected invitation or refresh command')
                return {'accounts': list(self.shared)}

        shared = []
        devices = [ContactPeer(shared) for _ in range(3)]
        with patch.object(one_scan.time, 'sleep'):
            result = one_scan.live_contacts(devices, 'synthetic-public-key')
        self.assertTrue(result['live_add'] and result['live_remove'])
        self.assertFalse(result['peer_invitation_required'])
        self.assertEqual([sum(c != 'contact-list' for c in p.calls) for p in devices], [1, 1, 1])
        with self.assertRaisesRegex(GateFailure, 'three-contact-installations-required'):
            one_scan.live_contacts(devices[:2], 'synthetic-public-key')

    def test_stale_contact_snapshot_cannot_produce_a_pass(self):
        class StalePeer:
            def ask(self, command):
                return {'accounts': []}

        with patch.object(one_scan.time, 'monotonic', side_effect=[0, 0, 31]), \
                patch.object(one_scan.time, 'sleep'):
            with self.assertRaisesRegex(GateFailure, 'live-contact-list-did-not-converge'):
                one_scan.wait_contacts([StalePeer()], ['synthetic-public-key'])

    def test_one_bootstrap_and_no_controller_forwarded_packets(self):
        a, b = peers()
        result = one_scan.pair(a, b)
        self.assertTrue(all(result.values()))
        self.assertTrue(a.shared and b.shared)
        self.assertEqual(sum(c == 'one-scan-begin' for c, _ in a.calls + b.calls), 1)
        self.assertEqual(sum(c == 'one-scan-approve' for c, _ in a.calls + b.calls), 1)
        forbidden = {'packets', 'setup', 'receive', 'acknowledge', 'enrollment-packet',
                     'enrollment-receive', 'finalize'}
        self.assertFalse(forbidden.intersection(c for c, _ in a.calls + b.calls))

    def test_mismatched_independent_numbers_cannot_be_confirmed(self):
        a, b = peers()
        b.comparison = (9, 8, 7)
        with self.assertRaisesRegex(GateFailure, 'independent-comparison-mismatch'):
            one_scan.pair(a, b)
        self.assertFalse(a.confirmed or b.confirmed or a.shared or b.shared)

    def test_missing_sdk_comparison_gate_cannot_produce_a_pass(self):
        for mode in ('always', 'after-first'):
            with self.subTest(mode=mode):
                a, b = peers(premature=mode)
                with self.assertRaisesRegex(GateFailure, 'enrollment-accepted-before-both-human-comparisons'):
                    one_scan.pair(a, b)
                self.assertFalse(a.shared or b.shared)


if __name__ == '__main__':
    unittest.main()
