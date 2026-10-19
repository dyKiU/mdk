"""REMOTE synthetic process output controls, no SDK/product execution."""
import os
from pathlib import Path
import sys
import unittest

from bounded_capture import capture, MAX_CAPTURE_BYTES


class BoundedCaptureTests(unittest.TestCase):
    def test_small_synthetic_output_remains_ram_only(self):
        result = capture([sys.executable, '-c', 'print("SYNTHETIC CAPTURE CONTROL")'],
                         cwd=Path.cwd(), env=dict(os.environ), timeout=30)
        self.assertEqual(result.returncode, 0)
        self.assertEqual(result.stdout, 'SYNTHETIC CAPTURE CONTROL\n')
        self.assertEqual(result.stderr, '')

    def test_synthetic_output_beyond_cap_is_rejected(self):
        command = [sys.executable, '-c',
                   'import sys; sys.stdout.buffer.write(b"X" * ' + str(MAX_CAPTURE_BYTES + 1) + ')']
        with self.assertRaisesRegex(ValueError, '^Metadata child output limit exceeded$'):
            capture(command, cwd=Path.cwd(), env=dict(os.environ), timeout=30)


    def test_stdout_and_stderr_remain_independent(self):
        command = [sys.executable, '-c',
                   'import sys; print("SYNTHETIC OUT", flush=True); print("SYNTHETIC ERR", file=sys.stderr, flush=True)']
        result = capture(command, cwd=Path.cwd(), env=dict(os.environ), timeout=30)
        self.assertEqual(result.returncode, 0)
        self.assertEqual(result.stdout, 'SYNTHETIC OUT\n')
        self.assertEqual(result.stderr, 'SYNTHETIC ERR\n')

    def test_cap_is_combined_across_both_streams(self):
        half = MAX_CAPTURE_BYTES // 2 + 1
        command = [sys.executable, '-c',
                   'import sys; sys.stdout.buffer.write(b"X" * ' + str(half)
                   + '); sys.stdout.flush(); sys.stderr.buffer.write(b"Y" * ' + str(half) + ')']
        with self.assertRaisesRegex(ValueError, '^Metadata child output limit exceeded$'):
            capture(command, cwd=Path.cwd(), env=dict(os.environ), timeout=30)


if __name__ == '__main__':
    unittest.main(verbosity=2)
