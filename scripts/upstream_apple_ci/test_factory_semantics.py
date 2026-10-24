#!/usr/bin/env python3
"""Hosted metadata tests only; no SDK/runtime/build or native pass claim."""
import copy
import hashlib
import itertools
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import factory_semantic_oracle as oracle
import factory_semantic_mutation as mutation
import factory_xcresult as xcresult
from factory_semantic_runner import execution_counts

HERE = Path(__file__).resolve().parent


def issue(path, *, column='12', message='own'):
    url = path.as_uri() + '#StartingLineNumber=9&EndingLineNumber=9&StartingColumnNumber=' + column + '&EndingColumnNumber=' + column
    return {'issueType': {'_type': {'_name': 'String'}, '_value': 'Assertion Failure'}, 'message': {'_type': {'_name': 'String'}, '_value': message},
            'documentLocationInCreatingWorkspace': {'url': {'_type': {'_name': 'String'}, '_value': url}}}


def inventory(rows):
    return {'_type': {'_name': 'ResultIssueSummaries'},
            'testFailureSummaries': {'_type': {'_name': 'Array'}, '_values': rows}}


class CompleteIssues(unittest.TestCase):
    def test_unknown_failure_type_preserves_observations_before_strict_rejection(self):
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / 'Fixture.swift'
            source.write_text('// metadata only\n' * 9 + '#expect(false)\n')
            own = issue(source, message='Expectation failed: synthetic-private-sentinel')
            own['issueType']['_value'] = 'Issue'
            record = {'issues': inventory([own]), 'actions': [{'issues': inventory([own])}]}
            raw = json.dumps(record).encode()
            audit = {}
            with patch.object(xcresult, 'output', return_value=raw):
                with self.assertRaisesRegex(ValueError, '^actual-assertion-type-required$'):
                    xcresult.read(Path('metadata-only.xcresult'), source=source,
                                  relative='Tests/Fixture.swift', audit=audit)
            observed = audit.get('failure_observations')
            self.assertIsInstance(observed, dict, 'complete safe failure observations must survive strict type rejection')
            self.assertEqual(observed['root_failure_count'], 1)
            self.assertEqual(observed['compiler_count'], 0)
            self.assertEqual(observed['root_failures'][0]['issue_type'], 'Issue')
            self.assertEqual(observed['root_failures'][0]['file'], 'Tests/Fixture.swift')
            self.assertEqual(observed['root_failures'][0]['line'], 10)
            self.assertEqual(observed['root_failures'][0]['column'], 13)
            self.assertEqual(observed['root_failures'][0]['source_line_sha256'],
                             hashlib.sha256(b'#expect(false)').hexdigest())
            self.assertTrue(observed['root_failures'][0]['expectation_failed_prefix'])
            self.assertNotIn('synthetic-private-sentinel', json.dumps(observed))

    def test_complete_failures_columns_and_action_closure(self):
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / 'Fixture.swift'; source.write_text('// metadata only\n')
            own = issue(source)
            root = {'issues': inventory([own]), 'actions': [{ 'issues': inventory([own]) }]}
            compiler, failures = xcresult.normalize(root, source=source, relative='Tests/Fixture.swift')
            self.assertEqual(compiler, [])
            self.assertEqual(failures, [dict(file='Tests/Fixture.swift', line=10, column=13, message='own')])
            duplicate = {'issues': inventory([own, own])}
            self.assertEqual(len(xcresult.normalize(duplicate, source=source, relative='Tests/Fixture.swift')[1]), 2)
            extra = copy.deepcopy(root); extra['actions'][0]['issues'] = inventory([own, issue(source, message='extra')])
            with self.assertRaises(ValueError): xcresult.normalize(extra, source=source, relative='Tests/Fixture.swift')
            for column in ('-1', 'unknown'):
                with self.assertRaises(ValueError):
                    xcresult.normalize({'issues': inventory([issue(source, column=column)])}, source=source, relative='Tests/Fixture.swift')
            unknown = xcresult.normalize({'issues': inventory([issue(source, column='0')])}, source=source, relative='Tests/Fixture.swift')[1]
            self.assertIsNone(unknown[0]['column'])
            omitted = issue(source)
            omitted['documentLocationInCreatingWorkspace']['url']['_value'] = source.as_uri() + '#StartingLineNumber=9&EndingLineNumber=9'
            self.assertIsNone(xcresult.normalize({'issues': inventory([omitted])}, source=source, relative='Tests/Fixture.swift')[1][0]['column'])
            multiline = issue(source)
            multiline['documentLocationInCreatingWorkspace']['url']['_value'] = source.as_uri() + '#StartingLineNumber=9&EndingLineNumber=11&StartingColumnNumber=12&EndingColumnNumber=0'
            self.assertEqual(xcresult.normalize({'issues': inventory([multiline])}, source=source, relative='Tests/Fixture.swift')[1][0]['column'], 13)
            malformed = {'issues': inventory([])}
            malformed['issues']['errorSummaries'] = {'_type': {'_name': 'String'}, '_value': 'not-an-empty-array'}
            with self.assertRaises(ValueError): xcresult.normalize(malformed, source=source, relative='Tests/Fixture.swift')
            other = Path(directory) / 'Other.swift'; other.write_text('// other\n')
            with self.assertRaises(ValueError):
                xcresult.normalize({'issues': inventory([issue(other)])}, source=source, relative='Tests/Fixture.swift')
            missing = issue(source); del missing['documentLocationInCreatingWorkspace']
            with self.assertRaises((ValueError, KeyError)):
                xcresult.normalize({'issues': inventory([missing])}, source=source, relative='Tests/Fixture.swift')
            audit = {}
            raw = json.dumps({'issues': inventory([issue(other)])}).encode()
            with patch.object(xcresult, 'output', return_value=raw):
                with self.assertRaises(ValueError):
                    xcresult.read(Path('metadata-only.xcresult'), source=source, relative='Tests/Fixture.swift', audit=audit)
            self.assertEqual(audit['inventory_sha256'], hashlib.sha256(raw).hexdigest())
            self.assertEqual(audit['issue_inventory_counts'][0]['testFailureSummaries'], 1)
            compile_root = {'issues': inventory([])}
            compile_root['issues']['errorSummaries'] = {'_type': {'_name': 'Array'}, '_values': [{'message': {'_type': {'_name': 'String'}, '_value': 'compiler'}}]}
            self.assertEqual(len(xcresult.normalize(compile_root, source=source, relative='Tests/Fixture.swift')[0]), 1)


class TypedOracle(unittest.TestCase):
    def row(self, stage='begin', cause='ok', bootstrap='wnpair2'):
        return dict(schema=1, stage=stage, cause=cause, bootstrap=bootstrap, **dict.fromkeys(oracle.BOOLS, True))

    def sites(self):
        return {key: dict(path='Tests/Fixture.swift', line=20 + index, column=13,
                         message_token='fixed-' + key, assertion='XCTAssertTrue' if key == 'begin-bootstrap' else 'XCTFail')
                for index, key in enumerate(('begin-not-ready', 'begin-bootstrap', 'scan-invalid-packet'))}

    def validate(self, rows, *, phase='baseline', inverse='scan-legacy', failures=None, **kwargs):
        args = dict(records=rows, counts=dict(zip(oracle.COUNTS, (1,0,1,0) if phase=='mutant' else (1,1,0,0))),
                    failures=[] if failures is None else failures, compiler_inventory=[], compiler_body=[],
                    phase=phase, inverse=inverse, assertion_sites=self.sites())
        args.update(kwargs)
        return oracle.validate(**args)

    def test_controls_and_all_typed_counterfactuals(self):
        controls = [self.row(), self.row('scan'), self.row('complete')]
        self.assertTrue(self.validate(controls)['actual_pass'])
        self.assertTrue(self.validate(controls, phase='restored')['actual_pass'])
        cases = [('begin-legacy',[self.row('begin','not-ready','none')],'begin-not-ready'),
                 ('begin-legacy',[self.row('begin','wrong-bootstrap','wnpair1')],'begin-bootstrap'),
                 ('scan-legacy',[self.row(),self.row('scan','invalid-packet')],'scan-invalid-packet')]
        for inverse, rows, name in cases:
            site = self.sites()[name]; message = site['message_token']
            if site['assertion']=='XCTAssertTrue': message='XCTAssertTrue failed - '+message
            own = dict(file=site['path'],line=site['line'],column=site['column'],message=message)
            self.assertTrue(self.validate(rows,phase='mutant',inverse=inverse,failures=[own])['runtime_detected'])
            unknown = dict(own, column=None)
            self.assertIsNone(self.validate(rows,phase='mutant',inverse=inverse,failures=[unknown])['failure_site']['column'])
            for key in own:
                wrong = dict(own); wrong[key] = 999 if key in ('line','column') else 'other'
                with self.assertRaises(ValueError): self.validate(rows,phase='mutant',inverse=inverse,failures=[wrong])
            for failures in ([],[own,own]):
                with self.assertRaises(ValueError): self.validate(rows,phase='mutant',inverse=inverse,failures=failures)

    def test_all_false_prerequisite_vectors_and_bad_inventory_counts(self):
        green = [self.row(),self.row('scan'),self.row('complete')]
        for bits in itertools.product((False,True),repeat=4):
            if all(bits): continue
            rows=copy.deepcopy(green);rows[1].update(zip(oracle.BOOLS,bits))
            with self.assertRaises(ValueError): self.validate(rows)
        for counts in ((0,0,0,0),(1,0,1,0),(1,0,0,1),(2,2,0,0)):
            with self.assertRaises(ValueError): self.validate(green,counts=dict(zip(oracle.COUNTS,counts)))
        for key in ('compiler_inventory','compiler_body'):
            with self.assertRaises(ValueError): self.validate(green,**{key:[{'message':'compiler'}]})
        for rows in (green[:2],green+[self.row('complete')],list(reversed(green))):
            with self.assertRaises(ValueError): self.validate(rows)

    def test_closed_decoder_rejects_missing_duplicate_extra_and_wrong_types(self):
        encoded = oracle.PREFIX + json.dumps(self.row())
        self.assertEqual(oracle.decode(encoded),[self.row()])
        for key in oracle.BOOLS:
            row=self.row();row[key]='true'
            with self.assertRaises(ValueError): oracle.decode(oracle.PREFIX+json.dumps(row))
        for key in oracle.FIELDS:
            row=self.row();del row[key]
            with self.assertRaises(ValueError): oracle.decode(oracle.PREFIX+json.dumps(row))
        with self.assertRaises(ValueError): oracle.decode(encoded[:-1]+',"roster_ready":false}')
        row=self.row();row['extra']=True
        with self.assertRaises(ValueError): oracle.decode(oracle.PREFIX+json.dumps(row))
        with self.assertRaises(ValueError): oracle.decode(encoded+'\n'+encoded+'\n'+encoded+'\n'+encoded)
        with self.assertRaises(ValueError): oracle.decode('x' * (oracle.MAX_OUTPUT_BYTES + 1))
        with self.assertRaises(ValueError): oracle.decode(oracle.PREFIX + 'x' * oracle.MAX_MARKER_LINE_BYTES)
        # Actual Xcode timestamp/process prefixes remain accepted, never exact-matched to a fabricated log header.
        self.assertEqual(oracle.decode('2026-10-23 TestHost[12:34] ' + encoded), [self.row()])

    def test_owner_source_hash_and_message_cardinality(self):
        source = b'''    func testExistingRosterWNPAIR2RequiresSiblingApprovalAndSharesHistory() async throws {
        XCTFail("factory-semantic-existing-roster-begin-not-ready")
        XCTAssertTrue(String(data: code, encoding: .utf8)?.hasPrefix("WNPAIR2:") == true,
            "factory-semantic-existing-roster-begin-bootstrap")
        XCTFail("factory-semantic-existing-roster-scan-invalid-packet")
    }
'''
        digest=hashlib.sha256(source).hexdigest()
        sites=oracle.source_sites(source,'Tests/Fixture.swift',digest)
        self.assertEqual(sites['begin-not-ready']['line'],2)
        self.assertEqual(sites['begin-not-ready']['column'],9)
        with self.assertRaises(ValueError): oracle.source_sites(source,'Tests/Fixture.swift','0'*64)
        for changed in (source.replace(b'testExistingRosterWNPAIR2RequiresSiblingApprovalAndSharesHistory',b'other'),
                        source+source,source.replace(b'XCTFail("factory-semantic-existing-roster-begin-not-ready")',b'XCTFail("wrong")')):
            with self.assertRaises(ValueError): oracle.source_sites(changed,'Tests/Fixture.swift',hashlib.sha256(changed).hexdigest())

    def test_invoked_unknown_execution_is_never_reported_as_zero(self):
        known = {'phase': 'baseline', 'unit_execution_invoked': True,
                 'counts': dict(zip(oracle.COUNTS, (1,1,0,0)))}
        missing = {'phase': 'begin-legacy-mutant', 'unit_execution_invoked': True}
        self.assertEqual(execution_counts([known]), (1,1,[]))
        self.assertEqual(execution_counts([missing]), (0,None,['begin-legacy-mutant']))
        self.assertEqual(execution_counts([known,missing]), (1,None,['begin-legacy-mutant']))
        self.assertEqual(execution_counts([{'phase':'compile-only'}]), (0,0,[]))

    def test_closed_mutation_modes_and_python_grammar(self):
        self.assertEqual(mutation.MODES,('factory-begin-legacy','factory-scan-legacy'))
        for platform in mutation.DEFINITIONS:
            for mode in mutation.MODES:
                with self.assertRaises(ValueError): mutation.transform(b'unreviewed',platform,mode)
        for name in ('factory_semantic_runner.py','factory_xcresult.py','factory_semantic_oracle.py','factory_semantic_mutation.py'):
            compile(HERE.joinpath(name).read_bytes(),name,'exec')


if __name__ == '__main__':
    unittest.main()
