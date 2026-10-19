"""REMOTE metadata controls only: synthetic schema records, real immutable Git source.

No binary/archive is manufactured, downloaded, loaded or executed. Accepted
metadata here is deliberately incomplete for install.verified_package and is
never an SDK qualification receipt.
"""
import ast
import copy
import os
from pathlib import Path
import subprocess
import sys
import unittest

import sdk_profiles as profiles

HERE = Path(__file__).resolve().parent
REPO = Path(os.environ['SDK_SOURCE_REPOSITORY']).resolve()
SOURCE = os.environ['PROFILE_CONTROL_SOURCE_SHA']
RUN = os.environ['GITHUB_RUN_ID']


def git(*args):
    return subprocess.check_output(['git', '-C', str(REPO), *args], text=True).strip()


def fixture(profile='default'):
    """Real F/tree/lock identities; explicitly synthetic compiler/input metadata."""
    tree, lock, release_profile = profiles.trusted_source_identity(SOURCE)
    compiler = {'rustc': 'fixture rustc; NOT AN OBSERVED BUILD',
                'cargo': 'fixture cargo; NOT AN OBSERVED BUILD'}
    feature_set = {'otlp_export': True, 'product_analytics_export': True,
                   'experimental_device_sync': profile == 'experimental'}
    inputs = {part: {'part': part, 'source_sha': SOURCE, 'builder_sha': SOURCE,
                     'workflow_run_id': RUN, 'sdk_profile': profile,
                     'source_tree': tree, 'cargo_lock_sha256': lock,
                     'release_profile_sha256': release_profile,
                     'feature_set': dict(feature_set), **compiler} for part in profiles.PARTS}
    manifest = {'source_sha': SOURCE, 'builder_sha': SOURCE,
                'cargo_lock_sha256': lock, 'features': profiles.features(profile), **compiler}
    return {'synthetic_metadata_fixture_only': True, 'schema_version': 2,
            'source_sha': SOURCE, 'builder_sha': SOURCE, 'workflow_run_id': RUN,
            'source_tree': tree, 'cargo_lock_sha256': lock,
            'release_profile_sha256': release_profile, 'sdk_profile': profile,
            'features': profiles.features(profile), 'compiler': compiler,
            'input_provenance': inputs,
            'platforms': {platform: {'manifest': copy.deepcopy(manifest)}
                          for platform in ['macos', 'ios']}}


class ProfileMetadataTests(unittest.TestCase):
    def accept(self, value, profile='default'):
        profiles.validate_provenance(value, profile, SOURCE, RUN)

    def test_default_metadata_accepts_without_private_feature(self):
        value = fixture()
        self.accept(value)
        self.assertIs(value['input_provenance']['swift']['feature_set']['experimental_device_sync'], False)
        self.assertNotIn('experimental-device-sync', value['features'])

    def test_experimental_metadata_accepts(self):
        self.accept(fixture('experimental'), 'experimental')

    def test_legacy_experimental_metadata_keeps_existing_route(self):
        value = {'source_sha': SOURCE, 'builder_sha': SOURCE, 'workflow_run_id': RUN,
                 'features': profiles.features('experimental')}
        self.accept(value, 'experimental')

    def test_default_refuses_legacy_experimental_metadata(self):
        value = fixture()
        del value['sdk_profile']
        with self.assertRaisesRegex(ValueError, 'explicit profile provenance'):
            self.accept(value)

    def test_default_rejects_experimental_features_or_profile(self):
        with self.assertRaisesRegex(ValueError, 'run/features mismatch'):
            self.accept(fixture('experimental'))
        value = fixture()
        value['sdk_profile'] = 'experimental'
        with self.assertRaisesRegex(ValueError, 'SDK profile mismatch'):
            self.accept(value)

    def test_unknown_profile_rejected(self):
        with self.assertRaisesRegex(ValueError, 'Unknown closed SDK profile'):
            profiles.features('unreviewed')

    def test_consistently_spoofed_json_lock_differs_from_git(self):
        value = fixture()
        value['cargo_lock_sha256'] = 'f' * 64
        for record in value['input_provenance'].values():
            record['cargo_lock_sha256'] = 'f' * 64
        for record in value['platforms'].values():
            record['manifest']['cargo_lock_sha256'] = 'f' * 64
        with self.assertRaisesRegex(ValueError, 'immutable Git F'):
            self.accept(value)

    def test_consistently_spoofed_json_tree_differs_from_git(self):
        value = fixture()
        value['source_tree'] = 'f' * 40
        for record in value['input_provenance'].values():
            record['source_tree'] = 'f' * 40
        with self.assertRaisesRegex(ValueError, 'immutable Git F'):
            self.accept(value)

    def test_per_input_lock_mismatch_rejected(self):
        value = fixture()
        value['input_provenance']['macos']['cargo_lock_sha256'] = 'f' * 64
        with self.assertRaisesRegex(ValueError, 'Apple input provenance differs'):
            self.accept(value)

    def test_integer_cannot_impersonate_feature_boolean(self):
        value = fixture()
        value['input_provenance']['swift']['feature_set']['experimental_device_sync'] = 0
        with self.assertRaisesRegex(ValueError, 'strict booleans'):
            self.accept(value)

    def test_boolean_cannot_impersonate_schema_integer(self):
        value = fixture()
        value['schema_version'] = True
        with self.assertRaisesRegex(ValueError, 'provenance schema'):
            self.accept(value)

    def test_wrong_builder_rejected(self):
        value = fixture()
        value['builder_sha'] = 'f' * 40
        with self.assertRaisesRegex(ValueError, 'source/builder'):
            self.accept(value)

    def test_integer_run_identifier_rejected(self):
        with self.assertRaisesRegex(ValueError, 'String producer run identity'):
            profiles.validate_provenance(fixture(), 'default', SOURCE, int(RUN))

    def test_per_input_compiler_mismatch_rejected(self):
        value = fixture()
        value['input_provenance']['macos']['rustc'] = 'different synthetic compiler'
        with self.assertRaisesRegex(ValueError, 'Apple input provenance differs'):
            self.accept(value)

    def test_manifest_lock_mismatch_rejected(self):
        value = fixture()
        value['platforms']['ios']['manifest']['cargo_lock_sha256'] = 'f' * 64
        with self.assertRaisesRegex(ValueError, 'Packaged lock/features differ'):
            self.accept(value)

    def test_missing_input_rejected(self):
        value = fixture()
        del value['input_provenance']['swift']
        with self.assertRaisesRegex(ValueError, 'Exactly four Apple inputs'):
            self.accept(value)

    def test_missing_git_object_fails_closed(self):
        absent = '0' * 40
        with self.assertRaises(subprocess.CalledProcessError):
            profiles.trusted_source_identity(absent)

    def test_existing_five_argument_installer_api_retained(self):
        source = ast.parse((HERE / 'install.py').read_text())
        method = next(n for n in source.body if isinstance(n, ast.FunctionDef) and n.name == 'verified_package')
        self.assertEqual([n.arg for n in method.args.args],
                         ['packages', 'platform', 'source', 'run_id', 'destination', 'profile'])
        self.assertEqual(ast.literal_eval(method.args.defaults[-1]), 'experimental')

    def test_workflow_stays_nonpublishing_manual_package_only(self):
        text = (REPO / '.github/workflows/upstream-experimental-apple.yml').read_text()
        self.assertIn('options: [experimental, default]', text)
        self.assertIn('default: experimental', text)
        self.assertIn('contents: read', text)
        self.assertNotIn('contents: write', text)
        self.assertNotIn('gh release', text)
        self.assertNotIn('refs/tags/', text)
        self.assertIn('test "$REQUESTED_PACKAGE_ONLY" = true', text)
        self.assertEqual(text.count("if: github.event_name == 'workflow_dispatch' && inputs.package_only"), 2)

    def missing_app_guard(self, platform):
        app = Path(os.environ['PROFILE_CONTROL_' + platform.upper() + '_APP']).resolve()
        expected = os.environ['PROFILE_CONTROL_' + platform.upper() + '_SHA']
        self.assertFalse((app / 'scripts/local-sdk-profile-settings.sh').exists())
        head = subprocess.check_output(['git', '-C', str(app), 'rev-parse', 'HEAD'], text=True).strip()
        self.assertEqual(head, expected)
        def state():
            return subprocess.check_output(['git', '-C', str(app), 'status', '--porcelain'], text=True)
        self.assertEqual(state(), '')
        package = app / ('Vendored/MarmotKit' if platform == 'mac' else 'Packages/MarmotKit')
        overlays = [package / 'Artifacts/MarmotKit.xcframework', package / 'LOCAL_BUILD.json']
        self.assertFalse(any(p.exists() for p in overlays))
        result = subprocess.run([sys.executable, '-B', str(HERE / 'install.py'), '--profile', 'default',
                                 '--packages', str(app / 'NO_ARTIFACT_REQUESTED'), '--source', SOURCE,
                                 '--run-id', RUN, '--platform', 'macos' if platform == 'mac' else 'ios',
                                 '--app', str(app), '--app-sha', expected], capture_output=True, text=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('Default SDK app capability guard is not implemented', result.stderr)
        self.assertNotIn('qualification.json', result.stderr)
        self.assertFalse(any(p.exists() for p in overlays))
        self.assertEqual(state(), '')

    def test_default_mac_missing_guard_refuses_before_artifact_or_writes(self):
        self.missing_app_guard('mac')

    def test_default_ios_missing_guard_refuses_before_artifact_or_writes(self):
        self.missing_app_guard('ios')

    def test_profile_artifact_names_stay_distinct_and_legacy_name_stable(self):
        self.assertEqual(profiles.artifact_name('experimental', SOURCE), 'upstream-experimental-apple-' + SOURCE)
        self.assertEqual(profiles.artifact_name('default', SOURCE), 'upstream-default-apple-' + SOURCE)
        self.assertEqual(profiles.release_id('experimental', SOURCE), 'ci-' + SOURCE)
        self.assertEqual(profiles.release_id('default', SOURCE), 'ci-default-' + SOURCE)


if __name__ == '__main__':
    unittest.main(verbosity=2)
