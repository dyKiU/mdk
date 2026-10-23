"""Fail-closed complete XCResult legacy issue inventory; no filtering of failures.

Xcode document-location fragment indices are treated as zero-based. A missing
or zero/unknown column is recorded as None; a supplied column is preserved and
checked against source by the causal oracle. It is never borrowed from source. Runtime receipts retain the raw inventory digest privately.
"""
import collections
import hashlib
import json
from pathlib import Path
import re
import os
import select
import time
import subprocess
from urllib.parse import parse_qs, unquote, urlsplit


def require(value, label):
    if not value:
        raise ValueError(label)


def output(argv, cap=16 * 1024 * 1024):
    process = subprocess.Popen(argv, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
    try:
        chunks, size = [], 0
        deadline = time.monotonic() + 60
        while True:
            require(time.monotonic() < deadline, 'bounded-xcresult-inventory-time-required')
            ready = select.select([process.stdout], [], [], min(0.25, max(0, deadline - time.monotonic())))[0]
            if not ready:
                continue
            chunk = os.read(process.stdout.fileno(), min(65536, cap + 1 - size))
            if not chunk:
                break
            chunks.append(chunk)
            size += len(chunk)
            require(size <= cap, 'bounded-xcresult-inventory-required')
        require(process.wait(timeout=max(0.01, deadline - time.monotonic())) == 0,
                'actual-xcresult-inventory-command-required')
        return b''.join(chunks)
    finally:
        if process.poll() is None:
            process.kill()
            process.wait(timeout=10)
        process.stdout.close()


def scalar(value):
    require(type(value) is dict and set(value) <= {'_type', '_value'}
            and type(value.get('_type')) is dict and value['_type'].get('_name') == 'String'
            and type(value.get('_value')) is str, 'typed-xcresult-scalar-required')
    return value['_value']


def values(value):
    require(type(value) is dict and set(value) <= {'_type', '_values'}
            and type(value.get('_type')) is dict and value['_type'].get('_name') == 'Array',
            'typed-xcresult-array-required')
    result = value.get('_values', [])
    require(type(result) is list, 'actual-xcresult-array-required')
    return result


def issue_sets(record):
    """Retain every typed ResultIssueSummaries object, not merely one action."""
    found = []
    def walk(value):
        if isinstance(value, dict):
            if type(value.get('_type')) is dict and value['_type'].get('_name') == 'ResultIssueSummaries':
                found.append(value)
            for child in value.values(): walk(child)
        elif isinstance(value, list):
            for child in value: walk(child)
    walk(record)
    return found


def raw_groups(issues):
    allowed = {'_type', 'analyzerWarningSummaries', 'errorSummaries', 'testFailureSummaries', 'warningSummaries'}
    require(type(issues) is dict and set(issues) <= allowed, 'closed-entire-xcresult-issue-schema-required')
    groups = {key: values(value) for key, value in issues.items() if key != '_type'}
    return groups


def location(issue, source):
    raw = scalar(issue['documentLocationInCreatingWorkspace']['url'])
    parsed = urlsplit(raw)
    require(parsed.scheme == 'file' and parsed.netloc in ('', 'localhost') and not parsed.query,
            'actual-local-source-location-required')
    # No basename matching or source-derived replacement of missing coordinates.
    require(Path(unquote(parsed.path)).resolve(strict=True) == source.resolve(strict=True),
            'exact-native-assertion-file-required')
    fields = parse_qs(parsed.fragment, strict_parsing=True)
    needed = 'StartingLineNumber'
    require(needed in fields and len(fields[needed]) == 1 and re.fullmatch('[0-9]+', fields[needed][0]),
            'actual-native-source-line-required')
    start_line = int(fields[needed][0])
    if 'EndingLineNumber' in fields:
        require(len(fields['EndingLineNumber']) == 1 and re.fullmatch('[0-9]+', fields['EndingLineNumber'][0])
                and int(fields['EndingLineNumber'][0]) >= start_line, 'valid-actual-source-range-required')
    column = None
    for key in ('StartingColumnNumber', 'EndingColumnNumber'):
        if key in fields:
            require(len(fields[key]) == 1 and re.fullmatch('[0-9]+', fields[key][0]),
                    'closed-provided-column-schema-required')
    if 'StartingColumnNumber' in fields and int(fields['StartingColumnNumber'][0]) > 0:
        column = int(fields['StartingColumnNumber'][0]) + 1
    return start_line + 1, column


def normalize(record, *, source, relative):
    require(type(record) is dict and 'issues' in record, 'actual-root-issue-inventory-required')
    root = raw_groups(record['issues'])
    all_sets = issue_sets(record)
    require(all_sets and record['issues'] in all_sets, 'typed-complete-issue-inventory-required')
    compiler = []
    root_failures = root.get('testFailureSummaries', [])
    root_multiset = collections.Counter(json.dumps(row, sort_keys=True) for row in root_failures)
    for inventory in all_sets:
        groups = raw_groups(inventory)
        for key in ('analyzerWarningSummaries', 'errorSummaries', 'warningSummaries'):
            compiler.extend({'inventory': key, 'raw': row} for row in groups.get(key, []))
        # An aggregate may duplicate action entries. Verify every action's
        # complete multiset is a subset of the root; never discard extra issues.
        observed = collections.Counter(json.dumps(row, sort_keys=True) for row in groups.get('testFailureSummaries', []))
        require(not (observed - root_multiset), 'root-inventory-must-contain-every-action-failure')
    failures = []
    for row in root_failures:
        require(scalar(row['issueType']) == 'Assertion Failure', 'actual-assertion-type-required')
        line, column = location(row, source)
        failures.append({'file': relative, 'line': line, 'column': column, 'message': scalar(row['message'])})
    return compiler, failures


def read(bundle, *, source, relative, audit=None):
    raw = output(['xcrun', 'xcresulttool', 'get', 'object', '--legacy', '--format', 'json', '--path', str(bundle)])
    receipt = {'inventory_sha256': hashlib.sha256(raw).hexdigest(), 'inventory_bytes': len(raw)}
    if audit is not None:
        audit.update(receipt)
    record = json.loads(raw)
    sets = issue_sets(record)
    # Safe complete inventory cardinalities survive a later normalization or
    # causal-oracle rejection. No raw assertion message or URL is exported.
    counts = []
    for inventory in sets:
        groups = raw_groups(inventory)
        counts.append({key: len(rows) for key, rows in groups.items()})
    if audit is not None:
        audit['issue_inventory_counts'] = counts
    compiler, failures = normalize(record, source=source, relative=relative)
    return {**receipt, 'compiler': compiler, 'failures': failures}
