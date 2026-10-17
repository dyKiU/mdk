#!/usr/bin/env python3
"""Retain native summary and bounded, explicit per-test skip inventory."""
import argparse
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
IDENTIFIER = re.compile(r'[A-Za-z_][A-Za-z0-9_./]*(?:\(\))?')
MAX_EXPORT_BYTES = 8 * 1024 * 1024


def summary_counts(summary):
    if not isinstance(summary, dict) or not all(type(summary.get(key)) is int and summary[key] >= 0 for key in COUNT_FIELDS):
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


def export_tests(result):
    command = ['xcrun', 'xcresulttool', 'get', 'test-results', 'tests', '--path', str(result)]
    process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
    data = bytearray()
    deadline = time.monotonic() + 60
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
            if len(data) + len(chunk) > MAX_EXPORT_BYTES:
                raise ValueError('export_size_limit')
            data.extend(chunk)
        if process.wait(timeout=max(0.01, deadline - time.monotonic())) != 0:
            raise ValueError('export_failed')
        return json.loads(data)
    finally:
        if process.poll() is None:
            process.kill()
        process.wait()
        process.stdout.close()


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
