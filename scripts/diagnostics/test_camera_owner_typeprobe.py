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
        self.assertEqual(result['diagnostic_rows'][0], dict(stream='stderr', file='CheckedCaptureOwner.swift', line=9, column=17, severity='error', row_sha256=probe.sha(line), fixed_message_facts={name: False for name in probe.DIAGNOSTIC_FACTS}))
        known = probe.diagnostics(b'', b'CheckedCaptureOwner.swift:9:17: error: sending non-Sendable AVCaptureSession risks data race\n')
        facts = known['diagnostic_rows'][0]['fixed_message_facts']
        self.assertTrue(facts['sending']); self.assertTrue(facts['non_sendable'])
        self.assertTrue(facts['capture_session_identifier']); self.assertTrue(facts['data_race'])
        self.assertFalse(facts['preview_layer_identifier'])
        self.assertNotIn('synthetic', repr(result))
        empty = probe.diagnostics(b'', b'')
        self.assertEqual(empty['diagnostic_count'], 0)
        self.assertEqual(empty['other_line_count'], 0)
        other = probe.diagnostics(b'foreign.swift:1:1: warning: unexported\n', b'')
        self.assertEqual(other['diagnostic_count'], 0)
        self.assertEqual(other['other_line_count'], 1)

    def test_only_exact_driver_version_stderr_is_identity_output(self):
        swift = b'Apple Swift version 6.3 (swiftlang-example)\n'
        self.assertEqual(probe.validate_identity_streams('swift-version', 0, swift, probe.DRIVER_STDERR),
                         {'driver_version': '1.148.6'})
        for label in ('xcode-version', 'swift-version', 'simulator-sdk-version', 'simulator-sdk-path'):
            self.assertEqual(probe.validate_identity_streams(label, 0, b'nonempty', b''), {'driver_version': None})
        for label, code, stdout, stderr in [
            ('swift-version', 0, swift, probe.DRIVER_STDERR + b' extra'),
            ('swift-version', 0, swift, probe.DRIVER_STDERR + b'\n'),
            ('swift-version', 0, swift, b'swift-driver version: 1.148.7 '),
            ('xcode-version', 0, swift, probe.DRIVER_STDERR),
            ('simulator-sdk-version', 0, swift, probe.DRIVER_STDERR),
            ('simulator-sdk-path', 0, swift, probe.DRIVER_STDERR),
            ('unrecognized', 0, swift, b''), ('swift-version', 1, swift, probe.DRIVER_STDERR),
            ('swift-version', True, swift, probe.DRIVER_STDERR), ('swift-version', 0, b'', probe.DRIVER_STDERR),
            ('swift-version', 0, 'not-bytes', b''), ('swift-version', 0, swift, 'not-bytes')]:
            with self.subTest(label=label, code=code):
                with self.assertRaises(ValueError):
                    probe.validate_identity_streams(label, code, stdout, stderr)

    def test_two_actual_clean_compiler_phases_and_closure_required(self):
        clean = {'exit_code': 0, **probe.diagnostics(b'', b'')}
        phases = {name: dict(invoked=True, actual_invocation_count=1, result=dict(clean)) for name in probe.PHASES}
        proof = dict(source_unchanged=True, tools_unchanged=True, compiler_phases=phases)
        self.assertTrue(probe.final_pass(proof))
        import copy
        for name in probe.PHASES:
            for change in [dict(invoked=False), dict(actual_invocation_count=None),
                           dict(actual_invocation_count=0), dict(actual_invocation_count=True), dict(result=None)]:
                bad = copy.deepcopy(proof); bad['compiler_phases'][name].update(change)
                self.assertFalse(probe.final_pass(bad))
            for change in [dict(exit_code=1), dict(exit_code=True), dict(stdout_bytes=1), dict(stderr_bytes=1),
                           dict(diagnostic_count=1), dict(other_line_count=1), dict(stdout_sha256='wrong')]:
                bad = copy.deepcopy(proof); bad['compiler_phases'][name]['result'].update(change)
                self.assertFalse(probe.final_pass(bad))
            bad = copy.deepcopy(proof); del bad['compiler_phases'][name]
            self.assertFalse(probe.final_pass(bad))
        for field in ('source_unchanged', 'tools_unchanged'):
            self.assertFalse(probe.final_pass(proof | {field: False}))
        self.assertFalse(probe.final_pass(proof | dict(failure_kind='ValueError')))
        pending = copy.deepcopy(phases); pending['emit_sil']['actual_invocation_count'] = None
        self.assertEqual(probe.compiler_counts(pending), dict(known_completed_invocations=1,
                         completed_invocations=None, unknown_phases=['emit_sil']))
