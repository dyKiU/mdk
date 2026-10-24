"""Closed source-owned compatibility policy PFP contracts; no native actions."""
import hashlib
import json
from pathlib import Path
import re

HERE = Path(__file__).resolve().parent
FIELDS = ('totalTestCount', 'passedTests', 'failedTests', 'skippedTests')


def require(value, label):
    if not value:
        raise ValueError(label)


def sha(value):
    return hashlib.sha256(value).hexdigest()


def bindings():
    return json.loads((HERE / 'compatibility-policy-sources.json').read_text())


def cases(platform):
    value = bindings()
    require(platform in ('macos', 'ios') and type(value['schema']) is int and value['schema'] == 1, 'closed-compatibility-platform')
    return value['apps'][platform]


def transform(original, case):
    require(sha(original) == case['original_sha256'], 'exact-compatibility-source')
    text = original.decode('utf-8', errors='strict')
    require(text.count(case['old']) == 1 and text.count(case['owner_start']) == 1,
            'sole-compatibility-literal-and-owner')
    start = text.index(case['owner_start'])
    end = text.index(case['owner_end'], start)
    require(text[start:end].count(case['old']) == 1, 'literal-inside-exact-owner')
    changed = text.replace(case['old'], case['new'], 1).encode()
    require(sha(changed) == case['mutant_sha256'] and changed.count(b'\n') == original.count(b'\n'),
            'exact-newline-preserved-compatibility-inverse')
    return changed


def source_sites(test_source, case):
    require(sha(test_source) == case['test_source_sha256'], 'exact-compatibility-test-source')
    text = test_source.decode('utf-8', errors='strict')
    require(text.count('func ' + case['method'] + '(') == 1, 'sole-compatibility-test-owner')
    owner = text.index('func ' + case['method'] + '(')
    end = text.index('\n    }', owner)
    body = text[owner:end]
    result = []
    for expected in case['issues']:
        expression = expected['source_expression']
        require(body.count(expression) == 1, 'sole-source-assertion-expression-inside-test-owner')
        at = owner + body.index(expression)
        line = text[:at].count('\n') + 1
        column = at - text.rfind('\n', 0, at)
        require(line == expected['line'] and column == expected['column'], 'reviewed-assertion-coordinates')
        result.append({'file': case['test_source'], 'line': line, 'column': column})
    return result


def counts(value):
    require(type(value) is dict and all(type(value.get(k)) is int and value[k] >= 0 for k in FIELDS),
            'typed-actual-compatibility-counts')
    result = {k: value[k] for k in FIELDS}
    require(result[FIELDS[0]] == sum(result[k] for k in FIELDS[1:]), 'consistent-actual-counts')
    return result


def runtime(case, observed, compiler_build, compiler_body, failures, mutant):
    wanted = dict(totalTestCount=1, passedTests=int(not mutant), failedTests=int(mutant), skippedTests=0)
    require(counts(observed) == wanted, 'exact-one-compatibility-runtime-body')
    require(compiler_build == [] and compiler_body == [], 'entire-compiler-inventories-empty')
    require(type(failures) is list and len(failures) == (len(case['issues']) if mutant else 0),
            'entire-closed-compatibility-failure-multiset')
    accepted, seen = [], set()
    for failure in failures:
        require(type(failure) is dict and set(failure) == {'file', 'line', 'column', 'message'},
                'closed-actual-assertion-row')
        require(failure['file'] == case['test_source'] and type(failure['line']) is int
                and failure['line'] > 0 and failure['line'] not in seen, 'exact-unique-own-source-failure')
        expected = [r for r in case['issues'] if r['line'] == failure['line']]
        require(len(expected) == 1, 'exact-source-owned-assertion-line')
        expected = expected[0]
        require(failure['column'] is None or (type(failure['column']) is int
                and failure['column'] == expected['column']), 'actual-column-or-explicitly-unknown')
        message = failure['message']
        require(type(message) is str and len(message.encode('utf-8')) <= 8192
                and message.startswith('Expectation failed:')
                and all(token in message for token in expected['message_tokens']),
                'bounded-source-expression-expectation-failure')
        seen.add(failure['line'])
        accepted.append({'file': failure['file'], 'line': failure['line'], 'column': failure['column'],
                         'message_sha256': sha(message.encode()), 'expression_id': expected['expression_id']})
    require(seen == ({r['line'] for r in case['issues']} if mutant else set()), 'complete-assertion-multiset')
    return accepted


def totals(phases):
    unknown = [r['label'] for r in phases if r.get('unit_invoked') is True and r.get('counts') is None]
    known = sum(counts(r['counts'])['totalTestCount'] for r in phases if r.get('counts') is not None)
    return {'known_executed': known, 'executed': None if unknown else known, 'unknown_phases': unknown}


def receipt(value, cohort, platform, profile, tools):
    app = cases(platform)
    require(profile in ('default', 'experimental') and type(value) is dict
            and value.get('app_sha') == cohort['app_sha'] == app['commit']
            and value.get('platform') == platform and value.get('profile') == profile
            and value.get('sdk_source') == cohort['sdk_source']
            and value.get('sdk_run_id') == cohort['sdk_run_id']
            and value.get('tools_sha') == cohort['tools_sha'] == tools
            and value.get('bindings_sha256') == sha((HERE / 'compatibility-policy-sources.json').read_bytes()),
            'exact-compatibility-cohort-identity')
    require(value.get('passed') is True and value.get('source_restored') is True
            and value.get('relay_cleanup_passed') is True and value.get('platform_cleanup_passed') is True, 'qualified-compatibility-and-restoration')
    phases = value.get('phases')
    require(type(phases) is list and [r.get('label') for r in phases] == [c['id'] + '/' + p
            for c in app['cases'] for p in ('baseline', 'mutant', 'restored')], 'exact-six-compatibility-phases')
    for case in app['cases']:
        for name in ('baseline', 'mutant', 'restored'):
            row = next(r for r in phases if r['label'] == case['id'] + '/' + name)
            mutant = name == 'mutant'
            require(row.get('source_sha256') == (case['mutant_sha256'] if mutant else case['original_sha256'])
                    and row.get('test_sha256') == case['test_source_sha256']
                    and all(type(row.get(k)) is int for k in ('build_exit_code', 'compiler_build_count',
                                                              'compiler_body_count', 'unit_exit_code'))
                    and row.get('unit_invoked') is True
                    and row.get('build_exit_code') == 0 and row.get('compiler_build_count') == 0
                    and row.get('compiler_body_count') == 0 and row.get('unit_exit_code') == (65 if mutant else 0)
                    and row.get('source_sdk_products_frozen') is True
                    and row.get('source_closure_exact') is True and row.get('qualified') is True
                    and type(row.get('inventory')) is dict
                    and set(row['inventory']) == {'status', 'selected', 'actual_identifier'}
                    and row['inventory'].get('status') == 'complete'
                    and row['inventory'].get('selected') == case['selector']
                    and row['inventory'].get('actual_identifier') in case['identifier_aliases'],
                    'exact-compiled-runtime-and-source-closure')
            require(counts(row['counts']) == dict(totalTestCount=1, passedTests=int(not mutant),
                    failedTests=int(mutant), skippedTests=0), 'exact-phase-actual-counts')
            issues = row.get('issue_evidence')
            require(type(issues) is list and len(issues) == (len(case['issues']) if mutant else 0),
                    'exact-phase-causal-evidence-count')
            expected = {r['expression_id']: r for r in case['issues']}
            require(len({r.get('expression_id') for r in issues}) == len(issues), 'unique-issue-evidence')
            for issue in issues:
                require(type(issue) is dict and set(issue) == {'file', 'line', 'column', 'message_sha256', 'expression_id'},
                        'closed-source-causal-evidence-fields')
                target = expected.get(issue.get('expression_id'))
                require(target is not None and issue.get('file') == case['test_source']
                        and issue.get('line') == target['line']
                        and (issue.get('column') is None or type(issue['column']) is int
                             and issue['column'] == target['column'])
                        and re.fullmatch('[0-9a-f]{64}', issue.get('message_sha256', '')),
                        'exact-closed-source-causal-receipt')
    require(value.get('totals') == totals(phases) == dict(known_executed=6, executed=6, unknown_phases=[]),
            'six-actual-compatibility-bodies')
    return {key: value[key] for key in ('app_sha', 'platform', 'profile', 'sdk_source', 'sdk_run_id',
            'tools_sha', 'bindings_sha256', 'source_restored', 'relay_cleanup_passed', 'platform_cleanup_passed', 'totals')} | {
            'passed': True, 'phases': [{key: row[key] for key in ('label', 'source_sha256', 'test_sha256',
                'build_exit_code', 'compiler_build_count', 'compiler_body_count', 'unit_exit_code',
                'source_sdk_products_frozen', 'source_closure_exact', 'qualified')} | {
                'counts': counts(row['counts']), 'issue_evidence': [{key: issue[key]
                    for key in ('file', 'line', 'column', 'message_sha256', 'expression_id')}
                    for issue in row['issue_evidence']]} for row in phases]}


def observed_execution(value):
    """Counts survive a later identity/oracle rejection; unknown stays unknown."""
    if type(value) is not dict or type(value.get('phases')) is not list or len(value['phases']) > 6:
        return {'known_executed': 0, 'executed': None, 'unknown_phases': ['invalid-inventory']}
    rows = []
    for index, row in enumerate(value['phases']):
        known = None
        if type(row) is dict and row.get('counts') is not None:
            try: known = counts(row['counts'])
            except ValueError: pass
        rows.append({'label': 'phase-' + str(index), 'unit_invoked': type(row) is dict
                     and row.get('unit_invoked') is True, 'counts': known})
    return totals(rows)
