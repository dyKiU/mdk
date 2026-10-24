import unittest
import camera_owner_typeprobe as probe


class CameraOwnerMetadataTests(unittest.TestCase):
    def test_exact_reviewed_capsule_hash(self):
        self.assertEqual(probe.sha(probe.SOURCE.read_bytes()), probe.SOURCE_SHA)

    def test_exact_toolchain_identity(self):
        for value in [b'Xcode 26.6\nBuild version 17F113\n', b'Xcode 26.6.0\nBuild version 17F113\n']:
            self.assertTrue(probe.xcode_identity(value))
        for value in [b'Xcode 26.6\nBuild version 17F112\n', b'Xcode 26.7\nBuild version 17F113\n', b'Xcode 26.6\nBuild version 17F113\nextra']:
            self.assertFalse(probe.xcode_identity(value))

    def test_complete_diagnostic_projection_and_unknown_lines(self):
        line = b'/private/source/CheckedCaptureOwner.swift:9:17: error: synthetic unexported text'
        result = probe.diagnostics(b'', line + b'\n  unexported continuation\n')
        self.assertEqual(result['diagnostic_count'], 1)
        self.assertEqual(result['other_line_count'], 1)
        self.assertEqual(result['diagnostic_rows'][0], dict(stream='stderr', file='CheckedCaptureOwner.swift', line=9, column=17, severity='error', row_sha256=probe.sha(line)))
        self.assertNotIn('synthetic', repr(result))
        empty = probe.diagnostics(b'', b'')
        self.assertEqual(empty['diagnostic_count'], 0)
        self.assertEqual(empty['other_line_count'], 0)
        other = probe.diagnostics(b'foreign.swift:1:1: warning: unexported\n', b'')
        self.assertEqual(other['diagnostic_count'], 0)
        self.assertEqual(other['other_line_count'], 1)
