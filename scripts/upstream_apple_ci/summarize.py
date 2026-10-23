#!/usr/bin/env python3
"""Retain native summary and bounded, explicit per-test skip inventory."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import select
import subprocess
import time

COUNT_FIELDS = ('totalTestCount', 'passedTests', 'failedTests', 'skippedTests')
STATUSES = {'Passed': 'passedTests', 'Failed': 'failedTests', 'Skipped': 'skippedTests'}
# Source-style identifiers only: never export dynamic display names or payloads.
IDENTIFIER = re.compile(r'[A-Za-z_][A-Za-z0-9_./]*(?:\((?:[A-Za-z_][A-Za-z0-9_]*:)*\))?')
MAX_EXPORT_BYTES = 8 * 1024 * 1024


def summary_counts(summary):
    if not isinstance(summary, dict) or not all(type(summary.get(key)) is int and summary[key] >= 0 for key in COUNT_FIELDS):
        return None
    if summary['totalTestCount'] != sum(summary[key] for key in COUNT_FIELDS[1:]):
        return None
    return {key: summary[key] for key in COUNT_FIELDS}


def test_inventory(tree, summary):
    counts = summary_counts(summary)
    report = {'status': 'schema_unknown', 'summary_counts': counts,
              'enumerated_counts': None, 'skipped_tests': [],
              'skip_reasons_status': 'unknown', 'unknown_nodes': None}
    if not isinstance(tree, dict) or not isinstance(tree.get('testNodes'), list):
        return report
    rows, seen, unknown = [], set(), 0
    pending = [(tree['testNodes'], 0)]
    visited = 0
    while pending:
        value, depth = pending.pop()
        visited += 1
        if visited > 200000 or depth > 64:
            report['status'] = 'schema_limit_exceeded'
            return report
        if isinstance(value, list):
            pending.extend((item, depth + 1) for item in reversed(value))
        elif isinstance(value, dict):
            if value.get('nodeType') == 'Test Case':
                identifier = value.get('nodeIdentifier', value.get('testIdentifier'))
                status = value.get('result', value.get('status'))
                if (not isinstance(identifier, str) or len(identifier) > 512
                        or IDENTIFIER.fullmatch(identifier) is None
                        or not isinstance(status, str) or status not in STATUSES or identifier in seen):
                    unknown += 1
                else:
                    seen.add(identifier)
                    rows.append({'identifier': identifier, 'status': status})
            elif value.get('nodeType') == 'Test Case Run':
                # Repeated/device-specific runs are not silently counted as cases.
                unknown += 1
            pending.extend((item, depth + 1) for item in reversed(list(value.values())) if isinstance(item, (dict, list)))
    report['unknown_nodes'] = unknown
    report['skipped_tests'] = [{'identifier': row['identifier'], 'reason': None, 'reason_status': 'unknown'}
                               for row in rows if row['status'] == 'Skipped']
    if unknown or counts is None or not rows:
        return report
    enumerated = {key: 0 for key in COUNT_FIELDS}
    enumerated['totalTestCount'] = len(rows)
    for row in rows:
        enumerated[STATUSES[row['status']]] += 1
    report['enumerated_counts'] = enumerated
    report['status'] = 'complete' if enumerated == counts else 'count_mismatch'
    return report


def skip_reason_evidence(tree, inventory, catalog, details=None):
    """Separate closed evidence; unknown reasons never become complete inventory."""
    report = {'status': 'unknown', 'reason_export_complete': False,
              'coverage_inventory_complete': inventory.get('status') == 'complete',
              'summary_counts': inventory.get('summary_counts'),
              'enumerated_counts': inventory.get('enumerated_counts'), 'skips': [],
              'unknown_identifiers': 0, 'unknown_reasons': 0, 'unknown_schema': 0}
    if not isinstance(tree, dict) or not isinstance(tree.get('testNodes'), list):
        report['unknown_schema'] = 1
        return report
    pending, seen, visited = [(tree['testNodes'], 0)], set(), 0
    while pending:
        value, depth = pending.pop()
        visited += 1
        if visited > 200000 or depth > 64:
            report['unknown_schema'] += 1
            return report
        if isinstance(value, list):
            pending.extend((item, depth + 1) for item in reversed(value))
        elif isinstance(value, dict):
            if value.get('nodeType') == 'Test Case' and value.get('result', value.get('status')) == 'Skipped':
                identifier = value.get('nodeIdentifier', value.get('testIdentifier'))
                known = catalog.get(identifier) if isinstance(identifier, str) else None
                if known is None or known['identifier'] in seen or len(report['skips']) >= 64:
                    report['unknown_identifiers'] += 1
                else:
                    seen.add(known['identifier'])
                    reason = value.get('skipReason')
                    exact = isinstance(reason, str) and reason in known['reasons']
                    origin = 'test-case.skipReason' if exact else None
                    detail = (details or {}).get(identifier)
                    # No other details fields or source-literal hints prove a reason.
                    if (not exact and isinstance(detail, dict)
                            and detail.get('testIdentifier') == identifier
                            and detail.get('testResult') == 'Skipped'
                            and isinstance(detail.get('skipReason'), str)
                            and detail['skipReason'] in known['reasons']):
                        reason, exact, origin = detail['skipReason'], True, 'test-details.skipReason'
                    inferred = sorted(set(known['reasons']))
                    row = {'identifier': known['identifier'], 'category': known['category'],
                           'source_sha256': known['source_sha256'], 'reason': reason if exact else None,
                           'actual_reason_origin': origin,
                           'source_inferred_reason': inferred[0] if len(inferred) == 1 else None,
                           'source_inference_status': 'unique_source_fixture_literal' if len(inferred) == 1 else 'unknown',
                           'tree_shape': detail_shape(value, known['reasons']),
                           'reason_status': 'observed_source_literal' if exact else 'unknown',
                           'unknown_reason_sha256': hashlib.sha256(reason.encode()).hexdigest()
                           if isinstance(reason, str) and not exact else None}
                    report['skips'].append(row)
                    report['unknown_reasons'] += int(not exact)
            pending.extend((item, depth + 1) for item in reversed(list(value.values())) if isinstance(item, (dict, list)))
    counts = summary_counts(report['summary_counts'])
    if (inventory.get('status') == 'complete' and inventory.get('unknown_nodes') == 0
            and counts is not None and report['enumerated_counts'] == counts
            and len(report['skips']) == counts['skippedTests']
            and not any(report[key] for key in ['unknown_identifiers', 'unknown_reasons', 'unknown_schema'])):
        report['status'] = 'complete'
        report['reason_export_complete'] = True
    return report


def detail_shape(value, reasons):
    """Only finite field/type facts and source-literal matches, never raw details."""
    reviewed = {'testIdentifier', 'testIdentifierString', 'testResult', 'result', 'status',
                'skipReason', 'reason', 'details', 'failureDetails', 'message', 'children',
                'testRuns', 'activities', 'testDescription', 'testName'}
    kinds = lambda item: ('null' if item is None else 'bool' if type(item) is bool
                         else 'number' if type(item) in (int, float) else 'string' if isinstance(item, str)
                         else 'array' if isinstance(item, list) else 'object' if isinstance(item, dict) else 'unknown')
    top = {key: kinds(item) for key, item in value.items() if key in reviewed} if isinstance(value, dict) else {}
    pending, hits, visited, limited = [(value, [], 0)], [], 0, False
    while pending:
        item, path, depth = pending.pop()
        visited += 1
        if visited > 4096 or depth > 12 or len(hits) >= 16:
            limited = True
            break
        if isinstance(item, str) and item in reasons:
            hits.append({'field_path': path, 'source_literal': item})
        elif isinstance(item, dict):
            for key, child in item.items():
                token = key if key in reviewed else 'unknown-key-sha256:' + hashlib.sha256(str(key).encode()).hexdigest()
                pending.append((child, path + [token], depth + 1))
        elif isinstance(item, list):
            pending.extend((child, path + ['array-item'], depth + 1) for child in item)
    return {'root_type': kinds(value), 'reviewed_field_types': top,
            'other_root_field_count': len(value) - len(top) if isinstance(value, dict) else 0,
            'unattributed_source_literal_hits': hits, 'scan_limited': limited}


def export_skip_details(result, inventory, catalog):
    """Optional metadata only, only for actual source-known skipped identifiers."""
    proof = {'status': 'unknown', 'help_support_confirmed': False, 'queries': []}
    details = {}
    identifiers = [row.get('identifier') for row in inventory.get('skipped_tests', [])
                   if isinstance(row, dict) and row.get('identifier') in catalog]
    if not identifiers:
        return details, proof
    if len(identifiers) > 64 or len(identifiers) != len(set(identifiers)):
        return details, proof
    try:
        help_raw = export_metadata(['xcrun', 'xcresulttool', 'get', 'test-results', 'test-details', '--help'],
                                   raw=True, max_bytes=65536, seconds=20)
        proof.update(help_bytes=len(help_raw), help_sha256=hashlib.sha256(help_raw).hexdigest())
        proof['help_support_confirmed'] = all(token in help_raw for token in [b'test-details', b'--path', b'--test-id'])
        if not proof['help_support_confirmed']:
            return details, proof
        # One fixed total metadata budget, independent of the already-frozen test verdict.
        deadline = time.monotonic() + 120
        for identifier in identifiers:
            row = {'identifier': catalog[identifier]['identifier'], 'status': 'unknown'}
            proof['queries'].append(row)
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                return details, proof
            try:
                raw = export_metadata(['xcrun', 'xcresulttool', 'get', 'test-results', 'test-details',
                                       '--path', str(result), '--test-id', identifier],
                                      raw=True, max_bytes=1024 * 1024, seconds=min(20, remaining))
                value = json.loads(raw)
                row.update(bytes=len(raw), sha256=hashlib.sha256(raw).hexdigest(),
                           shape=detail_shape(value, catalog[identifier]['reasons']))
                details[identifier] = value
                row['status'] = 'exported-not-necessarily-known-schema'
            except (OSError, ValueError, RecursionError, subprocess.SubprocessError):
                pass
        proof['status'] = 'exported' if len(details) == len(identifiers) else 'unknown'
    except (OSError, ValueError, RecursionError, subprocess.SubprocessError):
        pass
    return details, proof


def export_metadata(command, raw=False, max_bytes=MAX_EXPORT_BYTES, seconds=60):
    process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
    data = bytearray()
    deadline = time.monotonic() + seconds
    try:
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise ValueError('export_timeout')
            ready, _, _ = select.select([process.stdout], [], [], min(remaining, 1))
            if not ready:
                continue
            chunk = os.read(process.stdout.fileno(), 65536)
            if not chunk:
                break
            if len(data) + len(chunk) > max_bytes:
                raise ValueError('export_size_limit')
            data.extend(chunk)
        if process.wait(timeout=max(0.01, deadline - time.monotonic())) != 0:
            raise ValueError('export_failed')
        return bytes(data) if raw else json.loads(data)
    finally:
        if process.poll() is None:
            process.kill()
        process.wait()
        process.stdout.close()


def export_tests(result):
    return export_metadata(['xcrun', 'xcresulttool', 'get', 'test-results', 'tests', '--path', str(result)])


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--result', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--app-sha', required=True)
    args = parser.parse_args()
    summary = json.loads(subprocess.check_output(
        ['xcrun', 'xcresulttool', 'get', 'test-results', 'summary', '--path', str(args.result)], text=True))
    proof = {'app_sha': args.app_sha, 'sdk_source': os.environ['SOURCE_SHA'],
             'workflow_run_id': os.environ['GITHUB_RUN_ID'],
             'cohort': 'otlp-export,product-analytics-export,experimental-device-sync', 'xcresult_summary': summary}
    try:
        proof['test_inventory'] = test_inventory(export_tests(args.result), summary)
    except (OSError, ValueError, RecursionError, subprocess.SubprocessError):
        proof['test_inventory'] = {'status': 'export_failed', 'summary_counts': summary_counts(summary),
                                   'enumerated_counts': None, 'skipped_tests': [], 'skip_reasons_status': 'unknown'}
    args.output.write_text(json.dumps(proof, indent=2) + '\n')
    counts = summary_counts(summary)
    if (counts is None or counts['totalTestCount'] < 1 or counts['failedTests'] != 0
            or counts['passedTests'] < 1):
        raise SystemExit('XCResult does not establish an executed passing suite')
    # Inventory completeness is reported separately; preserve the suite's existing
    # pass/failure gate. An unknown inventory cannot supply missing skip evidence.


if __name__ == '__main__':
    main()
