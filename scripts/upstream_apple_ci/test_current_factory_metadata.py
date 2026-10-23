#!/usr/bin/env python3
"""Remote source-only metadata guards, not native SDK behavior evidence."""
import ast
import builtins
import hashlib
import json
from pathlib import Path
import unittest

HERE = Path(__file__).resolve().parent


def undefined_symbols(source):
    tree = ast.parse(source)
    known = set(dir(builtins)) | {'__file__', '__name__'}
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            known.add(node.name)
        if isinstance(node, ast.arg): known.add(node.arg)
        if isinstance(node, ast.Name) and isinstance(node.ctx, ast.Store): known.add(node.id)
        if isinstance(node, ast.Import):
            known.update(alias.asname or alias.name.split('.')[0] for alias in node.names)
        if isinstance(node, ast.ImportFrom):
            known.update(alias.asname or alias.name for alias in node.names)
        if isinstance(node, ast.ExceptHandler) and node.name: known.add(node.name)
    return {node.id for node in ast.walk(tree)
            if isinstance(node, ast.Name) and isinstance(node.ctx, ast.Load) and node.id not in known}


class CurrentFactoryMetadata(unittest.TestCase):
    def test_current_driver_has_no_unbound_helpers(self):
        source = HERE.joinpath('current_factory_one_scan.py').read_text()
        self.assertEqual(undefined_symbols(source), set())
        # Deliberate metadata mutant: missing imported helper must be detected,
        # without invoking any protocol command or manufacturing permissions.
        self.assertEqual(undefined_symbols(source.replace(', confirmed, accept)', ', confirmed)')), {'accept'})
        exports = ast.parse(HERE.joinpath('native/one_scan.py').read_text())
        available = {node.name for node in exports.body if isinstance(node, (ast.FunctionDef, ast.ClassDef))}
        for node in exports.body:
            if isinstance(node, (ast.Import, ast.ImportFrom)):
                available.update(alias.asname or alias.name for alias in node.names)
        for node in ast.parse(source).body:
            if isinstance(node, ast.ImportFrom) and node.module == 'one_scan':
                self.assertTrue({alias.name for alias in node.names} <= available)

    def test_source_grammar_and_exact_listed_helper_hashes(self):
        names = ('current_factory_one_scan.py', 'public-current-factories.py',
                 'prepare-hosted-agent.py', 'test_current_factory_metadata.py')
        manifest = json.loads(HERE.joinpath('HOSTED-SOURCE.json').read_text())
        for name in names:
            content = HERE.joinpath(name).read_bytes()
            compile(content, name, 'exec')
            if name in manifest['files']:
                self.assertEqual(hashlib.sha256(content).hexdigest(), manifest['files'][name]['sha256'])
        fragment = HERE.joinpath('current-factory-commands.swift.txt').read_bytes()
        self.assertEqual(hashlib.sha256(fragment).hexdigest(), manifest['files']['current-factory-commands.swift.txt']['sha256'])


if __name__ == '__main__':
    unittest.main()
