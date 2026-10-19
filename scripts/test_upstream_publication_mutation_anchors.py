"""Run remotely: source fixtures only, zero Rust compilation/runtime bodies."""
from pathlib import Path
import unittest

from upstream_publication_mutation_anchors import (
    publication_mutant, publication_mutation_anchor,
    publication_runtime_oracle, FIXTURE,
)

CASES = {
    'automatic-publication': 'crates/marmot-app/src/client/account_chat_sharing/automatic.rs',
    'sibling-publication': 'crates/marmot-app/src/client/device_linking/sibling_sharing.rs',
}


class PublicationAnchors(unittest.TestCase):
    def test_actual_owned_source_has_one_exact_insertion_and_restores(self):
        for case, path in CASES.items():
            with self.subTest(case=case):
                source = Path(path).read_text()
                old, new = publication_mutation_anchor(case)
                self.assertEqual(source.count(old), 1)
                mutant = publication_mutant(source, case)
                offset = source.index(old) + len(old)
                addition = new[len(old):]
                self.assertEqual(mutant, source[:offset] + addition + source[offset:])
                self.assertEqual(mutant.replace(new, old, 1), source)
                self.assertEqual(mutant.count(addition), 1)
                self.assertIn('.publication.as_ref().expect(', addition)
                self.assertIn('.task.is_finished()', addition)
                self.assertIn('tokio::task::yield_now().await;', addition)
                # Every original byte remains in its original order; no future,
                # semaphore, retry, deadline, ACK or guard expression is removed.

    def test_automatic_wait_is_handshake_only(self):
        old, new = publication_mutation_anchor('automatic-publication')
        addition = new[len(old):]
        self.assertIn('AccountSharingControl::Request | AccountSharingControl::Consent', addition)
        self.assertNotIn('Body', addition)

    def test_absent_duplicate_format_drift_and_already_mutated_refused(self):
        for case in CASES:
            old, new = publication_mutation_anchor(case)
            for bad in ['', old + '\n' + old, old.replace('outcome: None', 'outcome: Some(())'), new]:
                with self.subTest(case=case, invalid=bad[:30]):
                    with self.assertRaises(ValueError):
                        publication_mutant(bad, case)

    def test_unsupported_case_refused(self):
        with self.assertRaises(ValueError):
            publication_mutation_anchor('worker-spawn-stack')

    def test_named_runtime_assertions_and_unrelated_failure_refusal(self):
        fixture = Path(FIXTURE).read_text()
        for case in CASES:
            test = 'native_device_linking::automatic_pairing_acceptance::' + (
                'automatic_sync_does_not_block_foreground_enrollment_completion'
                if case == 'automatic-publication' else
                'blocked_sibling_consent_does_not_starve_another_approved_peer')
            meta = publication_runtime_oracle('', case, test, fixture)
            line = meta['expected_panic_line']
            marker = 'automatic-enrollment-control stage=' + (
                'automatic-publication-held-before-completion' if case == 'automatic-publication'
                else 'sibling-consent-held-before-peer-progress')
            message = ('automatic pairing did not reach required phase: expected=EnrollmentComplete observed=SharingPending'
                       if case == 'automatic-publication' else
                       'one blocked consent publication must not starve another approved sibling')
            panic = f"thread '{test}' (17) panicked at {FIXTURE}:{line}:9:\n{message}\n"
            raw = marker + '\n' + panic
            self.assertTrue(publication_runtime_oracle(raw, case, test, fixture)['intended_runtime_assertion'])
            negatives = [
                panic, panic + marker, raw + panic, raw + marker,
                raw.replace(test, 'unrelated_test'),
                raw.replace(FIXTURE, 'crates/unrelated.rs'),
                raw.replace(f':{line}:9:', f':{line + 1}:9:'),
                raw.replace(message, 'unrelated runtime assertion'),
                raw + 'error[E0308]: mismatched types\n',
                raw + 'error: could not compile\n',
            ]
            if case == 'automatic-publication':
                negatives.append(raw.replace('expected=EnrollmentComplete', 'expected=Comparison'))
            for bad in negatives:
                with self.subTest(case=case, invalid=bad[:30]):
                    self.assertFalse(publication_runtime_oracle(bad, case, test, fixture)['intended_runtime_assertion'])
            with self.assertRaises(ValueError):
                publication_runtime_oracle(raw, case, test, fixture + '\n' + fixture)


if __name__ == '__main__':
    unittest.main()
