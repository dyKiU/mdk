"""REMOTE destination preflight controls; no SDK, archive, install or product build."""
from pathlib import Path
import tempfile
import unittest

import install


class InstallDestinationTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        # Resolve the system temporary root only; test symlinks below it stay lexical.
        self.root = Path(self.temp.name).resolve()
        self.app = self.root / 'synthetic-source-tree'
        self.package = self.app / 'Vendored/MarmotKit'
        for name in ['Package.swift', 'MARMOT_VERSION', 'Sources/MarmotKit/MarmotKit.swift',
                     'Sources/MarmotKit/MarmotKitVersion.swift',
                     'Sources/MarmotKit/Resources/PrivacyInfo.xcprivacy']:
            path = self.package / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text('SYNTHETIC DESTINATION CONTROL; NOT SDK SOURCE\n')
        self.outside = self.root / 'owned-outside-sentinel'
        self.outside.mkdir()
        (self.outside / 'sentinel').write_text('DO NOT CHANGE\n')

    def inspect(self):
        return install.check_install_destinations(self.app, 'macos')

    def unchanged_outside(self):
        self.assertEqual([p.name for p in self.outside.iterdir()], ['sentinel'])
        self.assertEqual((self.outside / 'sentinel').read_text(), 'DO NOT CHANGE\n')
        self.assertFalse((self.package / 'LOCAL_BUILD.json').exists())

    def test_clean_source_destination_preflight_is_read_only(self):
        self.assertEqual(self.inspect(), self.package)
        self.assertFalse((self.package / 'Artifacts').exists())
        self.assertFalse((self.package / 'LOCAL_BUILD_INPUTS').exists())
        self.unchanged_outside()

    def test_dangling_original_inputs_symlink_refused_before_writes(self):
        (self.package / 'LOCAL_BUILD_INPUTS').symlink_to(self.outside / 'absent-target')
        with self.assertRaisesRegex(ValueError, 'leaf symlink refused'):
            self.inspect()
        self.assertFalse((self.package / 'Artifacts').exists())
        self.unchanged_outside()

    def test_artifacts_parent_symlink_refused_before_writes(self):
        (self.package / 'Artifacts').symlink_to(self.outside, target_is_directory=True)
        with self.assertRaisesRegex(ValueError, 'ancestor symlink refused'):
            self.inspect()
        self.unchanged_outside()

    def test_sources_parent_symlink_refused_before_writes(self):
        sources = self.package / 'Sources'
        sources.rename(self.package / 'real-synthetic-sources')
        sources.symlink_to(self.outside, target_is_directory=True)
        with self.assertRaisesRegex(ValueError, 'ancestor symlink refused'):
            self.inspect()
        self.unchanged_outside()

    def test_privacy_leaf_symlink_refused_before_writes(self):
        privacy = self.package / 'Sources/MarmotKit/Resources/PrivacyInfo.xcprivacy'
        privacy.unlink()
        privacy.symlink_to(self.outside / 'sentinel')
        with self.assertRaisesRegex(ValueError, 'leaf symlink refused'):
            self.inspect()
        self.unchanged_outside()

    def test_existing_local_receipt_refused_before_writes(self):
        receipt = self.package / 'LOCAL_BUILD.json'
        receipt.write_text('EXISTING SYNTHETIC RECEIPT\n')
        with self.assertRaisesRegex(ValueError, 'Existing local SDK destination refused'):
            self.inspect()
        self.assertEqual(receipt.read_text(), 'EXISTING SYNTHETIC RECEIPT\n')
        self.assertFalse((self.package / 'Artifacts').exists())


if __name__ == '__main__':
    unittest.main(verbosity=2)
