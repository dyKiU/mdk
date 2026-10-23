"""Remote metadata regressions only; no packaging script import, native build or SDK access."""
import argparse
import hashlib
import json
from pathlib import Path
import sys
import tomllib
import unittest

from package_metadata import uniffi_version

HERE = Path(__file__).resolve().parent
MANIFEST = HERE.parents[1] / 'crates/marmot-uniffi/Cargo.toml'


class PackageMetadataTests(unittest.TestCase):
    def test_actual_repository_string_dependency(self):
        manifest = tomllib.loads(MANIFEST.read_text())
        self.assertIs(type(manifest['dependencies']['uniffi']), str)
        self.assertEqual(manifest['dependencies']['uniffi'], '0.29.4')
        self.assertEqual(uniffi_version(manifest), '0.29.4')

    def test_supported_version_table(self):
        self.assertEqual(uniffi_version(tomllib.loads(
            '[dependencies]\nuniffi = { version = "0.29.4", features = ["cli"] }\n')), '0.29.4')

    def test_malformed_shapes_and_values_are_rejected(self):
        malformed = [None, [], {}, {'dependencies': None}, {'dependencies': []},
            {'dependencies': {}}, {'dependencies': {'uniffi': None}},
            {'dependencies': {'uniffi': []}}, {'dependencies': {'uniffi': {}}},
            {'dependencies': {'uniffi': {'workspace': True}}}]
        malformed += [{'dependencies': {'uniffi': {'version': value}}}
            for value in (None, True, 29, [], {}, '', ' ', ' 0.29.4', '0.29.4 ',
                          '0.29.4\n', '0.29.4\x00', 'x' * 129)]
        for manifest in malformed:
            with self.assertRaises((KeyError, TypeError, ValueError)):
                uniffi_version(manifest)


class RecordedResult(unittest.TextTestResult):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.typed_errors = []

    def addError(self, test, error):
        super().addError(test, error)
        kind = error[0].__name__
        self.typed_errors.append({'test': test._testMethodName,
            'type': kind if kind in {'TypeError', 'KeyError', 'ValueError', 'AssertionError'} else 'other'})


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--result', type=Path)
    args = parser.parse_args()
    suite = unittest.defaultTestLoader.loadTestsFromTestCase(PackageMetadataTests)
    result = unittest.TextTestRunner(verbosity=2, resultclass=RecordedResult).run(suite)
    if args.result is not None:
        args.result.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        proof = {'schema': 1, 'metadata_only': True, 'product_tests_executed': 0,
            'executed': result.testsRun, 'passed': result.testsRun - len(result.failures) - len(result.errors) - len(result.skipped),
            'failed': len(result.failures), 'errors': len(result.errors), 'skipped': len(result.skipped),
            'typed_errors': result.typed_errors,
            'failure_tests': [test._testMethodName for test, _ in result.failures],
            'files': {str(path.relative_to(HERE.parents[1])): hashlib.sha256(path.read_bytes()).hexdigest()
                for path in (Path(__file__).resolve(), HERE / 'package_metadata.py', MANIFEST)}}
        with args.result.open('x') as output:
            json.dump(proof, output, indent=2); output.write('\n')
    return 0 if result.wasSuccessful() else 1


if __name__ == '__main__':
    raise SystemExit(main())
