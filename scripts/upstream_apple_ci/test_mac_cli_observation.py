"""Synthetic observer metadata only; no Xcode/SDK/native execution."""
import unittest
import ast
from pathlib import Path
import mac_cli_observation as observer

class MacCliObservationMetadataTests(unittest.TestCase):
    def test_fixed_actual_message_categories_and_identifier_whitelist(self):
        value = observer.message_facts("Main actor-isolated method cannot satisfy Sendable conformance PRIVATE_SENTINEL", ['Sendable'])
        self.assertEqual(value['observed_categories'], ['actor-isolation', 'sendable-conformance'])
        self.assertEqual(value['known_identifiers'], ['Sendable'])
        self.assertNotIn('PRIVATE_SENTINEL', str(value))
    def test_unknown_and_unapproved_identifier_are_not_exposed(self):
        value = observer.message_facts('PRIVATE_UNKNOWN MarmotProtocol')
        self.assertEqual(value['observed_categories'], ['other-unclassified'])
        self.assertEqual(value['known_identifiers'], [])
        self.assertNotIn('PRIVATE_UNKNOWN', str(value))
    def test_exact_unchanged_unit_flags(self):
        settings = ['-project', '/synthetic/project']
        self.assertEqual(observer.unit_command(settings, {'selector':'Target/Suite/test()'}, Path('/synthetic/result')),
            ['xcodebuild','test-without-building','-project','/synthetic/project','-parallel-testing-enabled','NO',
             '-test-iterations','1','-only-testing:Target/Suite/test()','-resultBundlePath','/synthetic/result'])
    def test_oversized_or_untyped_message_rejected(self):
        for value in (None, 1, 'x' * 8193):
            with self.subTest(value_type=type(value).__name__), self.assertRaises(ValueError):
                observer.message_facts(value)

    def test_additional_warning_classes_and_boundary_negatives(self):
        examples = {
            'never-mutated-variable': 'Variable was never mutated',
            'duplicate-switch-case': 'Case is already handled by previous patterns',
            'captured-variable-concurrency': 'Reference to captured var in concurrently-executing code',
            'protocol-conformance': 'Conformance of a type to protocol is not isolated',
        }
        for category, message in examples.items():
            with self.subTest(category=category):
                self.assertIn(category, observer.message_facts(message)['observed_categories'])
        self.assertEqual(observer.message_facts('PRIVATE_SendableSuffix deprecatedness')['observed_categories'], ['other-unclassified'])
    def test_unit_command_matches_actual_strict_driver_argument_ast(self):
        tree = ast.parse(Path(observer.driver.__file__).read_text())
        calls = [node for node in ast.walk(tree) if isinstance(node, ast.Call)
                 and isinstance(node.func, ast.Name) and node.func.id == 'invoke' and node.args
                 and any(isinstance(part, ast.Constant) and part.value == 'test-without-building'
                         for part in ast.walk(node.args[0]))]
        self.assertEqual(len(calls), 1)
        settings, case, result = ['-project', '/synthetic/project'], {'selector': 'Target/Suite/test()'}, Path('/synthetic/result')
        names = {'command_settings': settings, 'case': case, 'result': result}
        def pure(node):
            if isinstance(node, ast.Constant) and type(node.value) is str: return node.value
            if isinstance(node, ast.List): return [pure(item) for item in node.elts]
            if isinstance(node, ast.Name) and node.id in names: return names[node.id]
            if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add): return pure(node.left) + pure(node.right)
            if isinstance(node, ast.Subscript) and isinstance(node.value, ast.Name) and node.value.id == 'case' \
                    and isinstance(node.slice, ast.Constant) and node.slice.value == 'selector': return case['selector']
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id == 'str' \
                    and len(node.args) == 1 and not node.keywords and isinstance(node.args[0], ast.Name) \
                    and node.args[0].id == 'result': return str(result)
            raise ValueError('Non-whitelisted command AST')
        self.assertEqual(observer.unit_command(settings, case, result), pure(calls[0].args[0]))

if __name__ == '__main__': unittest.main()
