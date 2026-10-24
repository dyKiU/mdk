"""Two original iOS regression bodies, using an existing SDK; never qualification."""
import argparse
import collections
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import shutil
from urllib.parse import unquote, urlsplit

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'upstream_apple_ci'))

import compatibility_policy as policy
from compatibility_policy_pfp import cohort, sdk_state, source_state, invoke
import factory_xcresult as xcresult
from summarize import export_metadata, export_tests, summary_counts, test_inventory

HERE = Path(__file__).resolve().parent


def bindings():
    value = json.loads((HERE / 'ios-runtime-diagnostic-sources.json').read_text())
    policy.require(type(value['schema']) is int and value['schema'] == 1
                   and value['diagnostic_only'] is True and value['profile'] == 'experimental'
                   and set(value['cases']) == {'retired-status', 'suspension-storage'}, 'closed-ios-diagnostic-bindings')
    policy.require(all(type(value[k]) is str and re.fullmatch('[0-9a-f]{40}', value[k])
                       for k in ('app_sha', 'sdk_source'))
                   and type(value['sdk_run_id']) is str and re.fullmatch('[1-9][0-9]*', value['sdk_run_id']),
                   'exact-immutable-diagnostic-identities')
    return value


def selected_cases(value):
    policy.require(type(value) is str and value in ('both', 'retired-status', 'suspension-storage'),
                   'closed-ios-diagnostic-selection')
    return ['retired-status', 'suspension-storage'] if value == 'both' else [value]


def observed_counts(value):
    return summary_counts(value)


def exact_inventory(tree, counts, case):
    result = test_inventory(tree, counts)
    policy.require(result['status'] == 'complete' and result['unknown_nodes'] == 0,
                   'complete-ios-diagnostic-test-inventory')
    pending, identifiers = [tree], []
    while pending:
        item = pending.pop()
        if type(item) is dict:
            if item.get('nodeType') == 'Test Case':
                identifiers.append(item.get('nodeIdentifier', item.get('testIdentifier')))
            pending.extend(item.values())
        elif type(item) is list:
            pending.extend(item)
    policy.require(len(identifiers) == 1 and identifiers[0] in case['identifier_aliases']
                   and counts['totalTestCount'] == 1 and counts['skippedTests'] == 0,
                   'exact-one-original-ios-diagnostic-body')
    return {'complete': True, 'selector': case['selector'], 'identifier': identifiers[0]}


def failure_inventory(record, app, tracked, case):
    """Preserve every root failure; never export arbitrary messages, URLs or names."""
    policy.require(type(record) is dict and 'issues' in record, 'actual-runtime-issue-record')
    sets = xcresult.issue_sets(record)
    policy.require(sets and record['issues'] in sets, 'complete-runtime-issue-sets')
    root = xcresult.raw_groups(record['issues'])
    failures = root.get('testFailureSummaries', [])
    policy.require(len(failures) <= 256, 'bounded-complete-runtime-failure-inventory')
    multiset = collections.Counter(json.dumps(row, sort_keys=True) for row in failures)
    counts = []
    for item in sets:
        groups = xcresult.raw_groups(item)
        counts.append({key: len(rows) for key, rows in groups.items()})
        observed = collections.Counter(json.dumps(row, sort_keys=True)
                                       for row in groups.get('testFailureSummaries', []))
        policy.require(not (observed - multiset), 'root-must-contain-all-action-failures')
    rows = []
    for raw in failures:
        row = {'raw_sha256': policy.sha(json.dumps(raw, sort_keys=True).encode()),
               'kind': 'unknown-test-issue', 'message_category': None, 'message_sha256': None,
               'file': None, 'line': None, 'column': None, 'fixed_source_category': None,
               'source_expression_sha256': None, 'source_test_file_matches': False}
        try:
            kind = xcresult.scalar(raw['issueType'])
            row['kind'] = {'Assertion Failure': 'assertion-failure',
                           'Uncaught Exception': 'uncaught-exception',
                           'Test Failure': 'test-failure'}.get(kind, 'unknown-test-issue')
            message = xcresult.scalar(raw['message'])
            policy.require(len(message.encode()) <= 8192, 'bounded-private-runtime-message')
            row['message_sha256'] = policy.sha(message.encode())
            if message.startswith('Expectation failed:'):
                row['message_category'] = 'swift-expectation-failed'
            elif message.startswith('Caught error:'):
                row['message_category'] = 'caught-test-error'
        except (KeyError, ValueError, TypeError):
            pass  # Unknown remains in the complete inventory, with a digest.
        try:
            url = urlsplit(xcresult.scalar(raw['documentLocationInCreatingWorkspace']['url']))
            path = Path(unquote(url.path)).resolve(strict=True)
            name = path.relative_to(app).as_posix()
            policy.require(name in tracked and url.scheme == 'file' and url.netloc in ('', 'localhost')
                           and not url.query, 'actual-tracked-test-issue-location')
            line, column = xcresult.location(raw, path)
            row.update(file=name, line=line, column=column,
                       source_test_file_matches=name == case['test_source'])
            expected = case['known_assertions'].get(str(line)) if name == case['test_source'] else None
            if expected:
                lines = path.read_text().splitlines()
                actual = policy.sha(lines[line - 1].strip().encode())
                policy.require(actual == expected['source_line_sha256'], 'exact-diagnostic-source-expression')
                row.update(fixed_source_category=expected['category'], source_expression_sha256=actual)
        except (KeyError, ValueError, TypeError, OSError, IndexError):
            pass
        rows.append(row)
    return {'complete': True, 'failure_count': len(rows), 'issue_inventory_counts': counts, 'failures': rows}


def collect(bundle, app, tracked, case, audit):
    raw = xcresult.output(['xcrun', 'xcresulttool', 'get', 'object', '--legacy', '--format', 'json',
                          '--path', str(bundle)])
    audit.update(inventory_sha256=policy.sha(raw), inventory_bytes=len(raw))
    record = json.loads(raw)
    audit['compiler'] = cohort.build_compiler_inventory(record, app, tracked)
    audit['runtime'] = failure_inventory(record, app, tracked, case)
    audit['complete'] = True


def run(args):
    config = bindings()
    case = config['cases'][args.case]
    policy.require(os.environ.get('GITHUB_ACTIONS') == 'true' and os.environ.get('RUNNER_OS') == 'macOS',
                   'remote-only-ios-runtime-diagnostic')
    app = Path('ios').resolve(strict=True)
    admitted = json.loads(args.cohort_evidence.read_text())
    policy.require(admitted['app_sha'] == config['app_sha']
                   and admitted['sdk_source'] == config['sdk_source']
                   and admitted['sdk_run_id'] == config['sdk_run_id']
                   and admitted['profile'] == config['profile'] and admitted['platform'] == 'ios'
                   and admitted['tools_sha'] == os.environ['GITHUB_SHA'], 'exact-focused-diagnostic-cohort')
    policy.require(cohort.physical_tracked_snapshot(app) == admitted['prepared_tracked_snapshot'],
                   'unchanged-prepared-ios-source')
    test = app / case['test_source']
    policy.require(policy.sha(test.read_bytes()) == case['test_sha256'], 'exact-original-ios-regression-test')
    package = app / 'Packages/MarmotKit'
    manifest = json.loads((package / 'LOCAL_BUILD.json').read_text())
    policy.require(manifest['qualification_receipt']['qualification_sha256'] == admitted['qualification_sha256']
                   and manifest['qualification_receipt']['platform'] == 'ios', 'admitted-focused-sdk-anchor')
    sdk = sdk_state(package, manifest)
    source = source_state(app)
    environment = cohort.environment_for(config['profile'], config['sdk_source'], config['sdk_run_id'])
    policy.require(cohort.guard_settings(app, config['profile'], environment) == admitted['validated_build_settings'],
                   'unchanged-focused-sdk-flags')
    folder = Path(os.environ['RUNNER_TEMP']) / ('focused-ios-' + args.case)
    policy.require(not folder.exists() and not args.output.exists(), 'fresh-focused-diagnostic-paths')
    folder.mkdir(mode=0o700)
    build, result = folder / 'build.xcresult', folder / 'unit.xcresult'
    policy.require(shutil.disk_usage(folder).free >= 8 * 1024**3, 'eight-gib-focused-build-reserve')
    shared = Path(os.environ['RUNNER_TEMP']) / 'focused-ios-shared'
    environment.update(WN_TEST_DERIVED_DATA=str(shared / 'derived'), WN_TEST_SOURCE_PACKAGES=str(shared / 'packages'),
                       WN_TEST_RESULT_BUNDLE=str(result), WN_TEST_BUILD_RESULT_BUNDLE=str(build), WN_TEST_JOBS='2')
    proof = {'schema': 1, 'diagnostic_only': True, 'qualification_credit': False,
             'case': args.case, 'selector': case['selector'], 'app_sha': config['app_sha'],
             'tools_sha': os.environ['GITHUB_SHA'],
             'helper_sha256': policy.sha(Path(__file__).read_bytes()),
             'bindings_sha256': policy.sha((HERE / 'ios-runtime-diagnostic-sources.json').read_bytes()),
             'original_script_sha256': {name: policy.sha((app / name).read_bytes())
                 for name in ('scripts/test.sh', 'scripts/test-with-relay.sh')},
             'sdk_source': config['sdk_source'],
             'sdk_run_id': config['sdk_run_id'], 'profile': config['profile'],
             'test_sha256': case['test_sha256'], 'script_invoked': False, 'counts': None,
             'source_restored': False, 'sdk_unchanged': False}
    def save():
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(proof, indent=2) + '\n')
    code = 1
    try:
        save()
        proof['script_invoked'] = True
        save()
        try:
            code = invoke(['bash', str(app / 'scripts/test-with-relay.sh'), '-only-testing:' + case['selector']],
                          folder / 'private.log', environment=environment, timeout=3600)
            proof['script_exit_code'] = code
        finally:
            # Actual observed counts survive every later selector/schema/issue/cleanup rejection.
            if result.exists():
                try:
                    summary = export_metadata(['xcrun', 'xcresulttool', 'get', 'test-results', 'summary',
                                               '--path', str(result)])
                    proof['counts'] = observed_counts(summary)
                    if proof['counts'] is None: proof['summary_error_kind'] = 'SchemaUnknown'
                except Exception as error:
                    proof['summary_error_kind'] = type(error).__name__
            save()  # Summary failure must not suppress independent build/runtime issue collectors.
        policy.require((folder / 'private.log').stat().st_size <= 32 * 1024**2, 'bounded-private-diagnostic-log')
        tracked = source['files']
        for label, bundle in [('build_evidence', build), ('runtime_evidence', result)]:
            if bundle.exists():
                audit = {'complete': False}
                proof[label] = audit
                try: collect(bundle, app, tracked, case, audit)
                except Exception as error: audit['collector_error_kind'] = type(error).__name__
                save()  # Preserve each independent inventory even if its counterpart is malformed.
        if result.exists():
            proof['test_inventory'] = exact_inventory(export_tests(result), proof['counts'], case)
            save()
        else:
            proof['runtime_result_unavailable'] = True
            save()
            policy.require(False, 'runtime-result-not-produced')
        policy.require(code in (0, 65), 'known-original-script-exit')
        policy.require(proof.get('build_evidence', {}).get('complete') is True
                       and proof.get('runtime_evidence', {}).get('complete') is True,
                       'entire-focused-inventories-complete')
        policy.require(proof['build_evidence']['compiler']['compiler_row_count'] == 0
                       and proof['runtime_evidence']['compiler']['compiler_row_count'] == 0,
                       'complete-focused-compiler-inventories-empty')
        wanted = dict(totalTestCount=1, passedTests=int(code == 0), failedTests=int(code == 65), skippedTests=0)
        policy.require(proof['counts'] == wanted, 'actual-focused-result-matches-original-script-exit')
    except (Exception, KeyboardInterrupt) as error:
        proof['collector_error_kind'] = type(error).__name__
        code = 130 if isinstance(error, KeyboardInterrupt) else 1
    finally:
        try:
            proof['source_restored'] = source_state(app) == source
            proof['sdk_unchanged'] = sdk_state(package, manifest) == sdk
        except Exception:
            proof['source_restored'] = proof['sdk_unchanged'] = False
        if not proof['source_restored'] or not proof['sdk_unchanged']:
            code = 1
        save()
    return code


def run_selected(args):
    """Always attempt both selected original cases; a real failure keeps the job red."""
    selected = selected_cases(args.selection)
    policy.require(not args.output.exists()
                   and not (Path(os.environ['RUNNER_TEMP']) / 'focused-ios-shared').exists()
                   and all(not args.output.with_name(args.output.stem + '-' + name + '.json').exists()
                           and not (Path(os.environ['RUNNER_TEMP']) / ('focused-ios-' + name)).exists()
                           for name in selected), 'fresh-aggregate-and-case-diagnostic-output')
    aggregate = {'schema': 1, 'diagnostic_only': True, 'qualification_credit': False,
                 'tools_sha': os.environ['GITHUB_SHA'], 'selected_cases': selected,
                 'cases': [], 'counts': None, 'unknown_cases': selected.copy(),
                 'known_executed': 0, 'executed': None}
    exit_code = 0
    for alias in selected:
        output = args.output.with_name(args.output.stem + '-' + alias + '.json')
        case_args = argparse.Namespace(case=alias, cohort_evidence=args.cohort_evidence, output=output)
        code = 1
        try: code = run(case_args)
        except (Exception, KeyboardInterrupt) as error:
            if isinstance(error, KeyboardInterrupt): code = 130
            if not output.exists():
                output.write_text(json.dumps({'case': alias, 'counts': None, 'diagnostic_only': True,
                    'qualification_credit': False, 'execution_status': 'unknown',
                    'collector_error_kind': type(error).__name__}) + '\n')
        raw = output.read_bytes()
        policy.require(len(raw) <= 2 * 1024**2, 'bounded-complete-case-diagnostic')
        report = json.loads(raw)
        aggregate['cases'].append({'case': alias, 'exit_code': code,
                                   'report_sha256': policy.sha(raw), 'evidence': report})
        if code != 0: exit_code = 1
        observed = [observed_counts(row['evidence'].get('counts')) for row in aggregate['cases']]
        aggregate['known_executed'] = sum(row['totalTestCount'] for row in observed if row is not None)
        complete = len(observed) == len(selected) and all(row is not None for row in observed)
        aggregate['counts'] = {key: sum(row[key] for row in observed) for key in policy.FIELDS} if complete else None
        aggregate['executed'] = aggregate['known_executed'] if complete else None
        known = {row['case'] for row in aggregate['cases']
                 if observed_counts(row['evidence'].get('counts')) is not None}
        aggregate['unknown_cases'] = [name for name in selected if name not in known]
        if code == 130:
            aggregate['interrupted'] = True
        args.output.write_text(json.dumps(aggregate, indent=2) + '\n')
        if code == 130: break  # Cancellation is not an instruction to start the next case.
    return exit_code


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--selection', choices=['both', 'retired-status', 'suspension-storage'], default='both')
    parser.add_argument('--cohort-evidence', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    os.umask(0o077)
    raise SystemExit(run_selected(parser.parse_args()))
