"""Remote synthetic receipt/parser controls ONLY; no SDK or interop qualification."""
import copy
import importlib.util
from pathlib import Path
import unittest

SPEC = importlib.util.spec_from_file_location('profile_interop_evidence', Path(__file__).with_name('profile-interop-evidence.py'))
module = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(module)
F = 'a' * 40  # Synthetic metadata identities, never artifacts or approved F.
HASHES = ['a' * 64, 'b' * 64, 'c' * 64, 'd' * 64]


class ProfileInteropEvidenceTests(unittest.TestCase):
    def pair(self):
        common = dict(source_sha=F, builder_sha=F, source_tree='b' * 40,
                      cargo_lock_sha256='c' * 64, release_profile_sha256='d' * 64,
                      compiler=dict(rustc='SYNTHETIC METADATA', cargo='SYNTHETIC METADATA'))
        return [dict(common, sdk_profile=profile, workflow_run_id=run, features=module.features(profile))
                for profile, run in [('default', '123'), ('experimental', '456')]]

    def observation(self):
        return dict(checks=[dict(sponsor=sponsor, **{flag: True for flag in module.FLAGS})
                            for sponsor in ['published', 'experimental']], passed=2, failed=0,
                    workers_created=8, workers_closed=8, owned_relay_exit_codes=[0],
                    published_sha256=HASHES[0], experimental_sha256=HASHES[1],
                    controller_sha256=HASHES[2], observer_sha256=HASHES[3])

    def test_same_F_distinct_profiles_and_producers_metadata_contract(self):
        default, experimental = self.pair()
        module.pair_gate(default, experimental, F, '123', '456')
        for key, value in [('source_sha', 'f' * 40), ('sdk_profile', 'experimental'),
                           ('features', module.features('experimental')), ('workflow_run_id', '456'),
                           ('source_tree', None), ('cargo_lock_sha256', '')]:
            changed = dict(default, **{key: value})
            with self.subTest(field=key), self.assertRaises(ValueError):
                module.pair_gate(changed, experimental, F, '123', '456')
        with self.assertRaises(ValueError):
            module.pair_gate(default, experimental, F, '456', '456')

    def test_legacy_or_mismatched_profile_provenance_cannot_be_default_pair(self):
        default, experimental = self.pair()
        del default['sdk_profile']
        with self.assertRaises(ValueError):
            module.pair_gate(default, experimental, F, '123', '456')
        default, experimental = self.pair()
        experimental['compiler'] = dict(rustc='OTHER', cargo='SYNTHETIC METADATA')
        with self.assertRaises(ValueError):
            module.pair_gate(default, experimental, F, '123', '456')

    def test_original_fixture_slots_export_honest_default_profile_labels(self):
        checks = module.observation_gate(self.observation(), *HASHES)
        self.assertEqual([row['sponsor'] for row in checks], ['default', 'experimental'])
        self.assertTrue(all(all(row[flag] is True for flag in module.FLAGS) for row in checks))
        self.assertNotIn('published', [row['sponsor'] for row in checks])

    def test_missing_duplicate_or_incomplete_sponsor_directions_fail_closed(self):
        for change in ['duplicate', 'missing', 'false-assertion', 'truthy-not-boolean']:
            value = self.observation()
            if change == 'duplicate':
                value['checks'][1]['sponsor'] = 'published'
            elif change == 'missing':
                value['checks'].pop()
            else:
                value['checks'][0]['offline_invitation'] = False if change == 'false-assertion' else 1
            with self.subTest(change=change), self.assertRaises(ValueError):
                module.observation_gate(value, *HASHES)

    def test_partial_worker_or_forced_relay_cleanup_never_qualifies(self):
        for key, changed in [('passed', 1), ('failed', True), ('workers_closed', 7),
                             ('workers_created', True), ('owned_relay_exit_codes', [-9]),
                             ('owned_relay_exit_codes', [False]), ('owned_relay_exit_codes', [])]:
            value = dict(self.observation(), **{key: changed})
            with self.subTest(field=key), self.assertRaises(ValueError):
                module.observation_gate(value, *HASHES)

    def test_actual_worker_and_source_hashes_are_required(self):
        for key in ['published_sha256', 'experimental_sha256', 'controller_sha256', 'observer_sha256']:
            value = self.observation()
            value[key] = None
            with self.subTest(field=key), self.assertRaises(ValueError):
                module.observation_gate(value, *HASHES)
        with self.assertRaises(ValueError):
            module.observation_gate(self.observation(), None, *HASHES[1:])


if __name__ == '__main__':
    unittest.main(verbosity=2)
