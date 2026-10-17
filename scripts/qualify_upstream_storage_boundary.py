#!/usr/bin/env python3
"""Run only the incoming SQLite ownership assertions; failures never qualify."""
import argparse
import hashlib
import io
import json
import os
from pathlib import Path
import re
import selectors
import signal
import subprocess
import time
import zipfile

from upstream_extraction_cohort import frozen_inputs, workflow_identity

INCOMING = '3aec65433eb84f0882430d000b2d31dabf987c24'
MERGE = 'cbd0e5f09224aae1481c87d69d41c8b0cf033461'
RED = '234c9b064bf6c3702a08898b2ea0ab25aa62265d'
COMPOSED = 'a6642b03bd3bb29a529c0fe94b6e3b73d351517c'
SELF = 'scripts/qualify_upstream_storage_boundary.py'
WORKFLOW = '.github/workflows/upstream-boundary-regressions.yml'
BOUNDARY = [
    'crates/storage-sqlite/src/base/mod.rs',
    'crates/storage-sqlite/src/base/boundary_tests.rs',
    'crates/storage-sqlite/src/base/table_owners.rs',
    'crates/storage-sqlite/src/cross/allow-list.txt',
]
TESTS = sorted('base::boundary_tests::' + name for name in [
    'table_registry_names_every_table', 'storage_boundary_matches_the_allow_list',
    'cfg_predicates_skip_only_test_builds',
])
ADDED_TEST = 'base::boundary_tests::unknown_production_roots_cannot_escape_boundary_scan'
OWNERSHIP_DOC = 'crates/storage-sqlite/src/cross/private-ownership.md'
OUT = Path('storage-boundary-evidence')
BOUNDARY_TEST = 'base::boundary_tests::storage_boundary_matches_the_allow_list'


class GateFailure(ValueError):
    """A fixed, source-owned diagnostic label, never child output."""


def ensure(value, label):
    if not value:
        raise GateFailure(label)


def digest(value):
    return hashlib.sha256(value).hexdigest()


def git(*args):
    return subprocess.check_output(['git', *args], text=True).strip()


def capture(command, timeout, limit=16 * 1024 * 1024, binary=False):
    """Bound raw output in memory, never publish SQL/payload-bearing panic text."""
    started = time.monotonic()
    process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, start_new_session=True)
    chunks, size = [], 0
    try:
        with selectors.DefaultSelector() as selector:
            selector.register(process.stdout, selectors.EVENT_READ)
            while selector.get_map():
                ensure(time.monotonic() - started < timeout, 'bounded-command-timeout')
                for key, _ in selector.select(timeout=0.2):
                    data = os.read(key.fd, 65536)
                    if not data:
                        selector.unregister(key.fileobj)
                        continue
                    size += len(data)
                    ensure(size <= limit, 'bounded-command-output-limit')
                    chunks.append(data)
        code = process.wait(timeout=10)
        output = b''.join(chunks)
        return code, output if binary else output.decode('utf-8', errors='replace'), round(time.monotonic() - started, 3)
    finally:
        if process.poll() is None:
            os.killpg(process.pid, signal.SIGKILL)
            process.wait(timeout=10)
        process.stdout.close()


def parse_body(output, code, name):
    output = re.sub(r'\x1b\[[0-9;]*m', '', output)
    summaries = re.findall(r'^test result: (ok|FAILED)\. (\d+) passed; (\d+) failed; (\d+) ignored; (\d+) measured; (\d+) filtered out;', output, re.M)
    names = re.findall(r'^test (base::boundary_tests::[A-Za-z_]+) \.\.\. ', output, re.M)
    panic_headers = re.findall(r"^thread '([^'\n]+)'(?: \(\d+\))? panicked at ([^\n]+):", output, re.M)
    panics = []
    for owner, location in panic_headers:
        match = re.fullmatch(r'(crates/storage-sqlite/src/base/boundary_tests\.rs):(\d+):(\d+)', location)
        panics.append({'selected_test': owner == name, 'known_source_location': match is not None,
                       'line': int(match[2]) if match else None,
                       'column': int(match[3]) if match else None})
    row = {'exit_code': code, 'actual_counts_complete': False, 'passed': None, 'failed': None,
           'ignored': None, 'executed_nonignored': None, 'exact_selected_name': names == [name],
           'panic_count': output.count('panicked at '), 'safe_panic_locations': panics,
           'compiler_error_count': len(re.findall(r'^error(?:\[E\d+\])?:', output, re.M)),
           'registry_assertion_observed': 'src/base/table_owners.rs must name every table of a fresh database exactly once.' in output,
           'boundary_missing_owner_observed': bool(re.search(r'\bhas no owner\b', output)),
           'boundary_allow_list_assertion_observed': 'crossing(s) between the protocol and app sides are not on' in output}
    if len(summaries) == 1:
        status, passed, failed, ignored, measured, _ = summaries[0]
        passed, failed, ignored = int(passed), int(failed), int(ignored)
        complete = (passed + failed == 1 and ignored == 0 and int(measured) == 0
                    and names == [name] and status == ('FAILED' if failed else 'ok'))
        row.update(actual_counts_complete=complete, passed=passed, failed=failed, ignored=ignored,
                   executed_nonignored=passed + failed if complete else None)
    row['passed_gate'] = (row['actual_counts_complete'] and code == 0 and row['passed'] == 1
                          and row['failed'] == 0 and row['panic_count'] == 0
                          and row['compiler_error_count'] == 0)
    return row


def safe_compiler_diagnostic(value, known_sources):
    """Closed compiler metadata only; messages, snippets and external paths stay private."""
    message = value.get('message')
    if not isinstance(message, dict) or message.get('level') != 'error':
        return None
    raw_code = message.get('code')
    code = raw_code.get('code') if isinstance(raw_code, dict) else None
    code_state = 'known' if isinstance(code, str) and re.fullmatch(r'E[0-9]{4}', code) else ('absent' if raw_code is None else 'unknown')
    row = {'code': code if code_state == 'known' else 'generic', 'code_state': code_state,
           'primary_locations': [], 'unknown_primary_location_count': 0,
           'locations_complete': False, 'locations_truncated': False}
    spans = message.get('spans')
    if not isinstance(spans, list):
        row['unknown_primary_location_count'] = 1
        return row
    primary = [span for span in spans if isinstance(span, dict) and span.get('is_primary') is True]
    row['unknown_primary_location_count'] += sum(not isinstance(span, dict) or type(span.get('is_primary')) is not bool for span in spans)
    row['locations_truncated'] = len(primary) > 8
    for span in primary[:8]:
        name = span.get('file_name')
        line, column = span.get('line_start'), span.get('column_start')
        if (isinstance(name, str) and name in known_sources and name.endswith('.rs')
                and type(line) is int and 0 < line <= 2147483647
                and type(column) is int and 0 < column <= 2147483647):
            row['primary_locations'].append({'file': name, 'line': line, 'column': column})
        else:
            row['unknown_primary_location_count'] += 1
    row['locations_complete'] = bool(primary) and row['unknown_primary_location_count'] == 0 and not row['locations_truncated']
    return row


def diagnostic_parser_preflight():
    name = BOUNDARY[1]
    span = {'file_name': name, 'line_start': 42, 'column_start': 5, 'is_primary': True,
            'text': [{'text': 'PRIVATE_RAW_MESSAGE_ACCOUNT_SQL'}]}
    def event(code, spans):
        return {'reason': 'compiler-message', 'message': {'level': 'error', 'code': code,
                'message': 'PRIVATE_RAW_MESSAGE_ACCOUNT_SQL', 'rendered': 'PRIVATE_RAW_MESSAGE_ACCOUNT_SQL', 'spans': spans}}
    known = safe_compiler_diagnostic(event({'code': 'E0277'}, [span]), {name})
    ensure(known['code'] == 'E0277' and known['locations_complete']
           and known['primary_locations'] == [{'file': name, 'line': 42, 'column': 5}], 'compiler-parser-known-code-and-primary')
    ensure(safe_compiler_diagnostic(event(None, []), {name})['code_state'] == 'absent', 'compiler-parser-generic-error')
    invalid = [dict(span, file_name='/private/account/SECRET.rs'), dict(span, file_name='../SECRET.rs'),
               dict(span, file_name='PRIVATE_RAW_MESSAGE_ACCOUNT_SQL'), dict(span, line_start=True),
               dict(span, line_start=-1), dict(span, column_start='5'), dict(span, is_primary='true'),
               'PRIVATE_RAW_MESSAGE_ACCOUNT_SQL']
    for bad in invalid:
        row = safe_compiler_diagnostic(event({'code': 'PRIVATE_RAW_MESSAGE_ACCOUNT_SQL'}, [bad]), {name})
        ensure(not row['locations_complete'] and not row['primary_locations'] and row['code_state'] == 'unknown'
               and 'PRIVATE_RAW_MESSAGE_ACCOUNT_SQL' not in json.dumps(row), 'compiler-parser-rejects-untrusted-metadata')
    row = safe_compiler_diagnostic(event({'code': 'E0277'}, [span] * 9), {name})
    ensure(row['locations_truncated'] and not row['locations_complete'] and len(row['primary_locations']) == 8, 'compiler-parser-bounded-spans')
    ensure(safe_compiler_diagnostic({'message': {'level': 'warning'}}, {name}) is None, 'compiler-parser-no-warning-as-error')
    return {'positive': 2, 'negative': len(invalid) + 2, 'actual_runtime_bodies': 0}


def parser_preflight():
    name = TESTS[0]
    raw = 'running 1 test\ntest ' + name + ' ... ok\ntest result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 2 filtered out; finished in 0.1s\n'
    ensure(parse_body(raw, 0, name)['passed_gate'], 'parser-positive-exact-body')
    negative = [raw.replace(name, 'foreign::test'), raw.replace('1 passed', '0 passed'),
                raw.replace('0 ignored', '1 ignored'), raw + raw, raw + '\nthread other panicked at foreign.rs:1:1:\n',
                raw + '\nerror[E0001]: compiler failure\n', 'error: failed to compile\n', raw.replace('0 measured', '1 measured')]
    for value in negative:
        ensure(not parse_body(value, 0, name)['passed_gate'], 'parser-rejects-incomplete-or-foreign-body')
    ensure(not parse_body(raw, 101, name)['passed_gate'], 'parser-rejects-nonzero')
    failed = raw.replace(' ... ok', ' ... \nthread \'' + name + "' panicked at crates/storage-sqlite/src/base/boundary_tests.rs:42:5:\nprivate SQL must stay private\nFAILED")
    failed = failed.replace('test result: ok. 1 passed; 0 failed', 'test result: FAILED. 0 passed; 1 failed')
    row = parse_body(failed, 101, name)
    ensure(row['actual_counts_complete'] and row['failed'] == 1 and not row['passed_gate']
           and row['safe_panic_locations'] == [{'selected_test': True, 'known_source_location': True, 'line': 42, 'column': 5}], 'parser-safe-failure-receipt')
    return {'positive': 2, 'negative': len(negative) + 1, 'actual_runtime_bodies': 0}


def rust_function(source, name):
    """Exact top-level source body identity, not a Rust parser or proof oracle."""
    anchor = '\nfn ' + name + '('
    ensure(source.count(anchor) == 1, 'one-frozen-top-level-function')
    start = source.index(anchor) + 1
    end = source.index('\n}\n', start) + 3
    return source[start:end]


def crossing_context(frozen):
    prefix = 'crates/storage-sqlite/src/'
    sources = {}
    for name, expected in frozen.items():
        if name.startswith(prefix) and name.endswith('.rs'):
            body = Path(name).read_bytes()
            ensure(digest(body) == expected['sha256'], 'diagnostic-source-identifiers-exact-frozen-inputs')
            sources[name[len(prefix):]] = body.decode()
    registry = sources['base/table_owners.rs']
    tables = set(re.findall(r'\(\s*"([a-z][a-z0-9_]*)",\s*Side::(?:Base|Protocol|App),?\s*\)', registry))
    ensure(bool(tables), 'owned-registry-identifiers-required-for-diagnostic')
    joined = '\n'.join(sources.values())
    triggers = set(re.findall(r'CREATE TRIGGER(?: IF NOT EXISTS)? ([A-Za-z_][A-Za-z0-9_]*)(?=\s)', joined))
    # These two literal templates generate names from schema-owned identifiers.
    # Nothing supplied by a test failure is interpolated into an accepted name.
    chat = sources['base/migrations/0072_chat_list_pages.rs']
    if 'CREATE TRIGGER chat_list_keys_{table}_{operation}' in chat:
        triggers.update('chat_list_keys_' + table + '_' + operation for table in tables
                        if '"' + table + '"' in chat for operation in ['INSERT', 'UPDATE', 'DELETE'])
    if 'CREATE TRIGGER {name} AFTER INSERT ON {table}' in sources['private_migration_ledger.rs']:
        triggers.update('cgka_experimental_device_sync_activate_' + table for table in tables)
    references = set(re.findall(r'REFERENCES\s+([a-z][a-z0-9_]*)\b', joined))
    listed_bytes = Path(BOUNDARY[3]).read_bytes()
    ensure(digest(listed_bytes) == frozen[BOUNDARY[3]]['sha256'], 'diagnostic-allow-list-exact-frozen-input')
    listed = {' '.join(line.split()) for line in listed_bytes.decode().splitlines()
              if line.strip() and not line.strip().startswith('#')}
    return {'sources': sources, 'tables': tables, 'triggers': triggers, 'references': references, 'listed': listed}


def known_crossing(line, context, section='new'):
    parts = line.split(' ')
    if len(parts) != 3 or ' '.join(parts) != line or len(line) > 512:
        return False
    kind, origin, target = parts
    identifier = r'[A-Za-z_][A-Za-z0-9_]*'
    if section == 'stale':
        # A stale row is, by definition, no longer found in current source or
        # schema. Its authority for privacy-safe export is the exact frozen
        # allow-list, not a fabricated current reference. This grants no allowance.
        if line not in context['listed']:
            return False
        if kind == 'fk':
            return origin in context['tables'] and target in context['tables']
        if kind == 'trigger':
            return origin in context['tables'] and re.fullmatch(identifier, target) is not None
        if (kind not in {'sql', 'path', 'method'} or origin not in context['sources']
                or not re.fullmatch(r'[A-Za-z0-9_/-]+\.rs', origin) or '..' in origin):
            return False
        if kind == 'sql':
            return target in context['tables']
        if kind == 'method':
            return re.fullmatch(identifier, target) is not None
        return re.fullmatch(r'crate(?:::' + identifier + r'){1,3}', target) is not None
    if section != 'new':
        return False
    if kind == 'fk':
        return origin in context['tables'] and target in context['tables'] and target in context['references']
    if kind == 'trigger':
        return origin in context['tables'] and target in context['triggers']
    if (kind not in {'sql', 'path', 'method'} or origin not in context['sources']
            or not re.fullmatch(r'[A-Za-z0-9_/-]+\.rs', origin) or '..' in origin):
        return False
    source = context['sources'][origin]
    if kind == 'sql':
        return target in context['tables'] and re.search(r'(?<![A-Za-z0-9_])' + re.escape(target) + r'(?![A-Za-z0-9_])', source) is not None
    if kind == 'method':
        return (re.fullmatch(identifier, target) is not None
                and re.search(r'\b(?:self\s*\.\s*' + re.escape(target) + r'\s*\(|Self\s*::\s*' + re.escape(target) + r'\b)', source) is not None
                and any(re.search(r'\bfn\s+' + re.escape(target) + r'\b', body) for body in context['sources'].values()))
    if not re.fullmatch(r'crate(?:::' + identifier + r'){1,3}', target):
        return False
    tokens = target.split('::')[1:]
    terminal = tokens[-1]
    location = '/'.join(tokens)
    known_target = (location + '.rs' in context['sources'] or location + '/mod.rs' in context['sources']
                    or (len(tokens) == 1 and re.search(r'\b' + re.escape(terminal) + r'\b', context['sources']['lib.rs']) is not None))
    return known_target and re.search(r'\b' + re.escape(terminal) + r'\b', source) is not None


def source_grounded_rejection(line, section, context):
    """Unqualified diagnostic atoms only; never export a raw rejected row."""
    detail = {'validation': 'unresolved-rejected', 'automatically_allowed': False,
              'section': section if section in {'new', 'stale'} else 'unknown',
              'kind': 'unknown', 'origin': None, 'target_atoms': [],
              'target_atoms_proven_static': False}
    parts = line.split(' ')
    if len(parts) != 3 or ' '.join(parts) != line or len(line) > 512:
        return detail
    kind, origin, target = parts
    if kind not in {'sql', 'path', 'method', 'fk', 'trigger'}:
        return detail
    detail['kind'] = kind
    tracked = (origin in context['sources'] and re.fullmatch(r'[A-Za-z0-9_/-]+\.rs', origin)
               and '..' not in origin)
    owned = origin in context['tables']
    detail['origin_is_tracked_source'] = bool(tracked)
    detail['origin_is_owned_schema_table'] = owned
    if (kind in {'sql', 'path', 'method'} and tracked) or (kind in {'fk', 'trigger'} and owned):
        detail['origin'] = origin
    identifier = r'[A-Za-z_][A-Za-z0-9_]{0,127}'
    atoms = target.split('::') if kind == 'path' else [target]
    if (len(atoms) > 9 or (kind == 'path' and atoms[0] != 'crate')
            or not all(re.fullmatch(identifier, atom) for atom in atoms)):
        return detail
    static = set(re.findall(r'\b[A-Za-z_][A-Za-z0-9_]{0,127}\b', '\n'.join(context['sources'].values())))
    safe = all(atom in static and not re.fullmatch(r'[a-fA-F0-9]{24,}', atom)
               and not re.fullmatch(r'(?:npub|nsec|note|nevent|nprofile|naddr)1[0-9a-z]+', atom)
               for atom in atoms)
    if safe:
        detail['target_atoms'] = atoms
        detail['target_atoms_proven_static'] = True
        detail['target_atom_provenance'] = 'bounded-identifiers-in-exact-frozen-storage-source'
    detail['target_is_owned_table'] = target in context['tables']
    detail['target_is_known_trigger'] = target in context['triggers']
    detail['target_is_known_fk_reference'] = target in context['references']
    if kind == 'path':
        detail['path_identifier_depth'] = len(atoms) - 1
        location = '/'.join(atoms[1:])
        detail['concrete_module_exists'] = location + '.rs' in context['sources'] or location + '/mod.rs' in context['sources']
        detail['terminal_occurs_in_origin'] = bool(tracked and re.search(r'\b' + re.escape(atoms[-1]) + r'\b', context['sources'][origin]))
    if kind == 'method':
        detail['origin_self_call_recognized'] = bool(tracked and re.search(r'\b(?:self\s*\.\s*' + re.escape(target) + r'\s*\(|Self\s*::\s*' + re.escape(target) + r'\b)', context['sources'][origin]))
        detail['target_fn_declaration_recognized'] = any(re.search(r'\bfn\s+' + re.escape(target) + r'\b', body) for body in context['sources'].values())
    return detail


def parse_crossing_diagnostic(output, code, context, panic_line):
    def rejected(reason, detail=None):
        return {'status': 'rejected', 'reason': reason, 'new': [], 'stale': [], 'unqualified_rejection_detail': detail}
    row = parse_body(output, code, BOUNDARY_TEST)
    locations = row['safe_panic_locations']
    if not (row['actual_counts_complete'] and row['passed'] == 0 and row['failed'] == 1
            and code != 0 and row['compiler_error_count'] == 0 and row['panic_count'] == 1
            and len(locations) == 1 and locations[0]['selected_test']
            and locations[0]['known_source_location'] and locations[0]['line'] == panic_line):
        return rejected('not-sole-actual-owned-boundary-panic')
    clean = re.sub(r'\x1b\[[0-9;]*m', '', output)
    header = re.search(r"^thread '" + re.escape(BOUNDARY_TEST) + r"'(?: \(\d+\))? panicked at crates/storage-sqlite/src/base/boundary_tests\.rs:" + str(panic_line) + r':\d+:\n', clean, re.M)
    if not header:
        return rejected('unknown-panic-header')
    patterns = {
        'new': r'([1-9][0-9]{0,2}) crossing\(s\) between the protocol and app sides are not on src/cross/allow-list\.txt\. Move them into cross/, or list them:',
        'stale': r'([1-9][0-9]{0,2}) listed crossing\(s\) no longer occur\. Delete them from src/cross/allow-list\.txt:',
    }
    result, declared, section, seen = {'new': [], 'stale': []}, {}, None, set()
    payload_lines = clean[header.end():].splitlines()
    tail = []
    for index, line in enumerate(payload_lines):
        if not line or line.startswith('note: run with `RUST_BACKTRACE=') or line == 'FAILED':
            tail = payload_lines[index:]
            break
        matches = [(kind, re.fullmatch(pattern, line)) for kind, pattern in patterns.items()]
        matches = [(kind, match) for kind, match in matches if match]
        if matches:
            section, match = matches[0]
            if section in declared:
                return rejected('duplicate-section-header')
            declared[section] = int(match[1])
            if declared[section] > 64:
                return rejected('section-bound-exceeded')
            continue
        if section is None or not known_crossing(line, context, section):
            return rejected('unknown-structural-crossing', source_grounded_rejection(line, section, context))
        if line in seen:
            return rejected('duplicate-crossing-row')
        seen.add(line)
        result[section].append(line)
        if len(result[section]) > declared[section]:
            return rejected('declared-count-exceeded')
    if not declared or any(len(result[kind]) != count for kind, count in declared.items()):
        return rejected('missing-or-truncated-section')
    for line in tail:
        if line in {'', 'FAILED', 'failures:', '    ' + BOUNDARY_TEST}:
            continue
        if re.fullmatch(r'note: run with `RUST_BACKTRACE=1` environment variable to display a backtrace', line):
            continue
        if re.fullmatch(r'test result: FAILED\. 0 passed; 1 failed; 0 ignored; 0 measured; [0-9]+ filtered out; finished in [0-9.]+s', line):
            continue
        return rejected('unknown-trailing-metadata')
    # Reject a second header anywhere, including after an apparent terminator.
    for kind, pattern in patterns.items():
        if len(re.findall('^' + pattern + '$', clean, re.M)) != int(kind in declared):
            return rejected('duplicate-or-trailing-section-header')
    return {'status': 'complete', 'new': result['new'], 'stale': result['stale'],
            'new_count': len(result['new']), 'stale_count': len(result['stale']),
            'automatically_allowed': False, 'requires_source_reason_review': True}


def crossing_parser_preflight():
    context = {'sources': {'lib.rs': 'mod owner;', 'owner.rs': 'fn actual() {} impl X { fn f() { self.actual(); } }',
                           'reader.rs': 'use crate::owner; SELECT app_table;'},
               'tables': {'app_table', 'protocol_table'}, 'triggers': {'known_trigger'}, 'references': {'protocol_table'},
               'listed': {'path reader.rs crate::owner', 'method owner.rs retired_method'}}
    new = '1 crossing(s) between the protocol and app sides are not on src/cross/allow-list.txt. Move them into cross/, or list them:'
    stale = '1 listed crossing(s) no longer occur. Delete them from src/cross/allow-list.txt:'
    start = "running 1 test\ntest " + BOUNDARY_TEST + " ... \nthread '" + BOUNDARY_TEST + "' panicked at crates/storage-sqlite/src/base/boundary_tests.rs:90:5:\n"
    end = '\n\nFAILED\ntest result: FAILED. 0 passed; 1 failed; 0 ignored; 0 measured; 3 filtered out; finished in 0.1s\n'
    raw = start + new + '\nsql reader.rs app_table\n' + stale + '\npath reader.rs crate::owner' + end
    ensure(parse_crossing_diagnostic(raw, 101, context, 90)['status'] == 'complete', 'crossing-parser-known-owned-sections')
    for line in ['method owner.rs actual', 'fk app_table protocol_table', 'trigger app_table known_trigger']:
        ensure(parse_crossing_diagnostic(start + new + '\n' + line + end, 101, context, 90)['status'] == 'complete', 'crossing-parser-known-source-schema-kinds')
    no_reference = dict(context, sources={**context['sources'], 'reader.rs': 'SELECT app_table;'})
    ensure(parse_crossing_diagnostic(start + stale + '\npath reader.rs crate::owner' + end, 101, no_reference, 90)['status'] == 'complete', 'crossing-parser-stale-row-exact-listed-without-current-reference')
    ensure(parse_crossing_diagnostic(start + stale + '\nmethod owner.rs retired_method' + end, 101, context, 90)['status'] == 'complete', 'crossing-parser-stale-method-exact-listed-without-definition')
    ensure(parse_crossing_diagnostic(start + new + '\npath reader.rs crate::owner' + end, 101, no_reference, 90)['status'] == 'rejected', 'crossing-parser-new-still-requires-current-reference')
    ensure(parse_crossing_diagnostic(start + stale + '\nmethod owner.rs actual' + end, 101, context, 90)['status'] == 'rejected', 'crossing-parser-stale-requires-exact-listed-line')
    invalid_list = dict(context, listed={'sql ../private/account.rs app_table'})
    ensure(parse_crossing_diagnostic(start + stale + '\nsql ../private/account.rs app_table' + end, 101, invalid_list, 90)['status'] == 'rejected', 'crossing-parser-list-membership-cannot-bypass-path-bounds')
    semantic = dict(context, sources={**context['sources'], 'reader.rs': 'use crate::owner::StoredRecord;', 'owner.rs': 'pub struct StoredRecord; self.generated_call();'})
    row = parse_crossing_diagnostic(start + new + '\npath reader.rs crate::owner::StoredRecord' + end, 101, semantic, 90)
    detail = row['unqualified_rejection_detail']
    ensure(row['status'] == 'rejected' and row['new'] == row['stale'] == []
           and detail['target_atoms'] == ['crate', 'owner', 'StoredRecord'] and detail['target_atoms_proven_static']
           and not detail['concrete_module_exists'] and detail['validation'] == 'unresolved-rejected', 'crossing-parser-semantic-path-atoms-unqualified')
    row = parse_crossing_diagnostic(start + new + '\nmethod owner.rs generated_call' + end, 101, semantic, 90)
    ensure(row['status'] == 'rejected' and row['unqualified_rejection_detail']['target_atoms'] == ['generated_call']
           and not row['unqualified_rejection_detail']['target_fn_declaration_recognized'], 'crossing-parser-macro-like-method-atoms-unqualified')
    for line in ['path reader.rs crate::PRIVATE_ACCOUNT_SQL', 'sql ../private/account.rs PRIVATE_ACCOUNT_SQL']:
        row = parse_crossing_diagnostic(start + new + '\n' + line + end, 101, context, 90)
        ensure(row['status'] == 'rejected' and row['unqualified_rejection_detail']['target_atoms'] == []
               and 'PRIVATE_ACCOUNT_SQL' not in json.dumps(row) and '../private' not in json.dumps(row), 'crossing-parser-unproven-values-not-exported')
    negatives = [raw.replace('reader.rs', '../private/account.rs'), raw.replace('app_table', 'PRIVATE_ACCOUNT_SQL'),
                 raw.replace('crate::owner', 'crate::PRIVATE_ACCOUNT_SQL'), raw.replace('1 crossing(s)', '2 crossing(s)'),
                 raw.replace('1 crossing(s)', '65 crossing(s)'), raw.replace(stale, new), raw + '\n' + new,
                 raw.replace('sql reader.rs app_table', 'sql reader.rs app_table\nsql reader.rs app_table'),
                 raw.replace('sql reader.rs app_table', 'SELECT private_payload FROM private_account'),
                 raw.replace('sql reader.rs app_table', 'method reader.rs PRIVATE_ACCOUNT_SQL'),
                 raw.replace('sql reader.rs app_table', 'fk app_table PRIVATE_ACCOUNT_SQL'),
                 raw.replace('sql reader.rs app_table', 'trigger app_table PRIVATE_ACCOUNT_SQL'),
                 raw.replace(BOUNDARY_TEST, 'foreign::test'), raw.replace(':90:5:', ':91:5:'),
                 raw.replace('1 failed', '0 failed'), raw + "\nthread 'other' panicked at secret:1:1:\n",
                 raw + '\nPRIVATE_ACCOUNT_SQL\n']
    for bad in negatives:
        row = parse_crossing_diagnostic(bad, 101, context, 90)
        ensure(row['status'] == 'rejected' and 'PRIVATE_ACCOUNT_SQL' not in json.dumps(row), 'crossing-parser-rejects-untrusted-incomplete-or-duplicate-metadata')
    return {'positive': 8, 'negative': len(negatives) + 5, 'actual_runtime_bodies': 0}


def source_guard(baseline, ownership_adaptation):
    ensure(isinstance(baseline, str) and re.fullmatch('[0-9a-f]{40}', baseline), 'explicit-reviewed-full-cohort-required')
    source = git('rev-parse', 'HEAD')
    workflow = workflow_identity(source)
    ensure(os.environ.get('GITHUB_EVENT_NAME') == 'workflow_dispatch', 'isolated-manual-scope-only')
    ensure(not git('diff', 'HEAD', '--name-only'), 'initial-tracked-inputs-pristine')
    for ancestor, target in [(MERGE, baseline), (INCOMING, baseline), (baseline, source)]:
        subprocess.run(['git', 'merge-base', '--is-ancestor', ancestor, target], check=True)
    changed = set(git('diff', '--name-only', baseline, source).splitlines())
    ensure(changed <= {SELF, WORKFLOW}, 'only-reviewed-metadata-overlay')
    adaptation = {}
    if ownership_adaptation:
        subprocess.run(['git', 'merge-base', '--is-ancestor', RED, baseline], check=True)
        subprocess.run(['git', 'merge-base', '--is-ancestor', RED, COMPOSED], check=True)
        subprocess.run(['git', 'merge-base', '--is-ancestor', COMPOSED, baseline], check=True)
        allowed = {SELF, WORKFLOW, OWNERSHIP_DOC, *BOUNDARY[1:]}
        composed_changed = set(git('diff', '--name-only', COMPOSED, source).splitlines())
        ensure(composed_changed <= allowed, 'nonownership-product-inputs-exact-reviewed-composed-source')
        storage_changed = set(git('diff', '--name-only', RED, source, '--', 'crates/storage-sqlite').splitlines())
        ensure(storage_changed <= {OWNERSHIP_DOC, *BOUNDARY[1:]}, 'all-private-storage-providers-migrations-and-fixtures-exact-red')
        ensure(not git('diff', '--name-only', RED, COMPOSED, '--', 'crates/storage-sqlite'), 'composed-storage-inputs-exact-red-before-ownership-adaptation')
        ensure(Path(BOUNDARY[0]).read_bytes() == subprocess.check_output(['git', 'show', INCOMING + ':' + BOUNDARY[0]]), 'incoming-base-module-registration-exact')
        old = subprocess.check_output(['git', 'show', INCOMING + ':' + BOUNDARY[1]]).decode()
        current = Path(BOUNDARY[1]).read_text()
        old_functions = re.findall(r'^fn ([A-Za-z_]+)\(', old, re.M)
        frozen_functions = [name for name in old_functions if name not in {'side_of', 'path_target', 'root_reexports'}]
        for name in frozen_functions:
            ensure(rust_function(old, name) == rust_function(current, name), 'original-assertion-and-scanner-function-exact')
        scan_start, scan_end = "impl<'ast> Visit<'ast> for Scan<'_> {", '\nfn use_paths('
        ensure(current[current.index(scan_start):current.index(scan_end)] == old[old.index(scan_start):old.index(scan_end)], 'original-ast-visitor-protections-exact')
        old_registry = subprocess.check_output(['git', 'show', INCOMING + ':' + BOUNDARY[2]]).decode()
        registry = Path(BOUNDARY[2]).read_text()
        start = registry.index('    // Private ownership inventory:')
        end = registry.index('    // The engine:', start)
        ensure(registry[:start] + registry[end:] == old_registry, 'upstream-table-owner-entries-unmodified')
        ensure(Path(BOUNDARY[3]).read_bytes().startswith(subprocess.check_output(['git', 'show', INCOMING + ':' + BOUNDARY[3]])), 'all-upstream-allow-list-entries-retained')
        adaptation = {'historical_red_source': RED, 'historical_red_run_id': 39055385890,
                      'reviewed_composed_source': COMPOSED,
                      'original_three_test_bodies_exact': True, 'unchanged_scanner_functions': frozen_functions,
                      'all_private_storage_provider_migration_and_fixture_inputs_exact_red': True,
                      'all_nonownership_product_inputs_exact_reviewed_composed_source': True,
                      'reviewed_ownership_paths': sorted(composed_changed - {SELF, WORKFLOW}),
                      'historical_green_or_mutation_results_reused': False}
    else:
        for name in BOUNDARY:
            ensure(Path(name).read_bytes() == subprocess.check_output(['git', 'show', INCOMING + ':' + name]), 'incoming-boundary-source-remains-exact-before-red')
    ensure(all(not os.environ.get(key) for key in ['RUSTFLAGS', 'CARGO_ENCODED_RUSTFLAGS', 'RUSTDOCFLAGS', 'CARGO_ENCODED_RUSTDOCFLAGS']), 'no-unrecorded-rust-flags')
    expected_environment = {'CARGO_INCREMENTAL': '1', 'CARGO_BUILD_JOBS': '2',
                            'CARGO_PROFILE_DEV_DEBUG': '0', 'CARGO_PROFILE_TEST_DEBUG': '0',
                            'RUST_MIN_STACK': '4194304'}
    ensure(all(os.environ.get(key) == value for key, value in expected_environment.items()), 'exact-reviewed-build-environment')
    return {'source': source, 'reviewed_cohort_baseline': baseline, 'baseline_tree': git('rev-parse', baseline + '^{tree}'),
            'workflow_identity': workflow, 'incoming_master': INCOMING, 'incoming_boundary_sources_unchanged': not ownership_adaptation,
            'ownership_adaptation': adaptation, 'overlay_paths': sorted(changed), 'historical_results_reused': False}


def mutation_specs(source):
    """Single reviewed counterfactuals; no test, migration or allowance mutation."""
    return {
        'protocol-root': (BOUNDARY_TEST,
                          '        "accepted_welcome"\n        | "accepted_device_group_anchor"',
                          '        "accepted_device_group_anchor"'),
        'private-path': (BOUNDARY_TEST,
                         'return private_root_side(name)\n                .or_else(|| root.get(name).copied())',
                         'return root.get(name).copied()'),
        'unknown-root': (ADDED_TEST,
                         '.ok_or("unclassified production storage file"),',
                         '.ok_or("unclassified production storage file").or(Ok(None)),'),
        'lexical-alias': (ADDED_TEST, '    let rel = normalized.as_str();', '    let rel = rel;'),
    }


def source_line(source, anchor):
    ensure(source.count(anchor) == 1, 'unique-reviewed-runtime-oracle-location')
    return source[:source.index(anchor)].count('\n') + 1


def mutation_killed(label, output, code, source, frozen):
    name = mutation_specs(source)[label][0]
    row = parse_body(output, code, name)
    anchors = {
        'protocol-root': '    classified_side(rel).unwrap_or_else',
        'private-path': '    panic!("{message}");',
        'unknown-root': '        assert_eq!(\n            classified_side(unregistered),',
        'lexical-alias': '    assert!(\n        histories.iter().all(|file| file.side.is_none()),',
    }
    location = source_line(source, anchors[label])
    panics = row['safe_panic_locations']
    exact = (row['actual_counts_complete'] and row['passed'] == 0 and row['failed'] == 1
             and code == 101 and row['compiler_error_count'] == 0 and row['panic_count'] == 1
             and len(panics) == 1 and panics[0]['selected_test']
             and panics[0]['known_source_location'] and panics[0]['line'] == location)
    header = (r"^thread '" + re.escape(name) + r"'(?: \(\d+\))? panicked at "
              + re.escape(BOUNDARY[1]) + ':' + str(location) + r':\d+:\n')
    match = re.search(header, output, re.M)
    if not exact or match is None:
        return False
    payload = output[match.end():]
    if label == 'protocol-root':
        return payload.startswith('unclassified production storage file: accepted_welcome.rs\n')
    if label == 'private-path':
        crossing = parse_crossing_diagnostic(output, code, crossing_context(frozen), location)
        return (crossing.get('status') == 'complete' and crossing['new'] == []
                and crossing['stale'] == ['path device_linking.rs crate::private_device_invite'])
    if label == 'unknown-root':
        return payload.startswith('assertion `left == right` failed: a new production root must declare its ownership before shipping\n'
                                  '  left: Ok(None)\n right: Err("unclassified production storage file")\n')
    return payload.startswith('declared migration aliases are schema history, never Base-owned SQL\n')


def mutation_parser_preflight(frozen):
    source = Path(BOUNDARY[1]).read_text()
    positive, negative = 0, 0
    payloads = {
        'protocol-root': 'unclassified production storage file: accepted_welcome.rs',
        'private-path': '1 listed crossing(s) no longer occur. Delete them from src/cross/allow-list.txt:\npath device_linking.rs crate::private_device_invite',
        'unknown-root': 'assertion `left == right` failed: a new production root must declare its ownership before shipping\n  left: Ok(None)\n right: Err("unclassified production storage file")',
        'lexical-alias': 'declared migration aliases are schema history, never Base-owned SQL',
    }
    anchors = {'protocol-root': '    classified_side(rel).unwrap_or_else',
               'private-path': '    panic!("{message}");',
               'unknown-root': '        assert_eq!(\n            classified_side(unregistered),',
               'lexical-alias': '    assert!(\n        histories.iter().all(|file| file.side.is_none()),'}
    for label, (name, old, new) in mutation_specs(source).items():
        ensure(source.count(old) == 1 and old != new, 'unique-reviewed-mutant-anchor')
        line = source_line(source, anchors[label])
        raw = ('running 1 test\ntest ' + name + " ... \nthread '" + name
               + "' panicked at " + BOUNDARY[1] + ':' + str(line) + ':5:\n'
               + payloads[label] + '\n\nFAILED\ntest result: FAILED. 0 passed; 1 failed; 0 ignored; 0 measured; 3 filtered out; finished in 0.1s\n')
        ensure(mutation_killed(label, raw, 101, source, frozen), 'mutation-parser-positive-owned-runtime-kill')
        positive += 1
        for bad, status in [(raw, 0), (raw.replace('1 failed', '0 failed'), 101),
                            (raw.replace('0 ignored', '1 ignored'), 101),
                            (raw.replace("thread '" + name, "thread 'foreign"), 101),
                            (raw.replace(':' + str(line) + ':5:', ':' + str(line + 1) + ':5:'), 101),
                            (raw.replace(payloads[label], 'unrelated generic panic'), 101),
                            (raw + "\nthread 'other' panicked at foreign.rs:1:1:\n", 101),
                            ('error[E0001]: compiler failure\n', 101), (raw + raw, 101)]:
            ensure(not mutation_killed(label, bad, status, source, frozen), 'mutation-parser-rejects-unintended-or-incomplete-kill')
            negative += 1
    return {'positive': positive, 'negative': negative, 'actual_runtime_bodies': 0}


def github_metadata(endpoint, archive=False):
    ensure(os.environ.get('GH_TOKEN') and not os.environ.get('GH_HOST'), 'explicit-github-actions-read-token-required')
    code, output, _ = capture(['gh', 'api', '--hostname', 'github.com', endpoint], 120,
                              limit=4 * 1024 * 1024, binary=archive)
    ensure(code == 0, 'bounded-github-evidence-request-succeeded')
    return output if archive else json.loads(output)


def prior_controls(run_id, report):
    """Fresh exact-HEAD controls are a prerequisite, not historical GREEN reuse."""
    ensure(isinstance(run_id, str) and re.fullmatch('[1-9][0-9]{0,15}', run_id), 'explicit-controls-run-id-required')
    prefix = 'repos/dyKiU/mdk/actions/'
    run = github_metadata(prefix + 'runs/' + run_id)
    ensure(run.get('head_sha') == report['source'] and run.get('event') == 'workflow_dispatch'
           and run.get('status') == 'completed' and run.get('conclusion') == 'success'
           and run.get('path') == WORKFLOW
           and run.get('head_repository', {}).get('full_name') == 'dyKiU/mdk', 'same-head-successful-owned-controls-run')
    listing = github_metadata(prefix + 'runs/' + run_id + '/artifacts?per_page=100')
    artifacts = listing.get('artifacts')
    ensure(isinstance(artifacts, list) and listing.get('total_count') == len(artifacts) <= 100, 'complete-bounded-artifact-inventory')
    receipts = {}
    for cohort in ['default', 'experimental', 'preflight']:
        name = ('storage-ownership-preflight-' if cohort == 'preflight' else 'storage-ownership-boundary-' + cohort + '-') + report['source']
        selected = [item for item in artifacts if item.get('name') == name]
        ensure(len(selected) == 1 and selected[0].get('expired') is False, 'one-unexpired-owned-controls-artifact')
        item = selected[0]
        ensure(type(item.get('id')) is int and type(item.get('size_in_bytes')) is int
               and 0 < item['size_in_bytes'] <= 4 * 1024 * 1024, 'bounded-controls-artifact')
        data = github_metadata(prefix + 'artifacts/' + str(item['id']) + '/zip', archive=True)
        checksum = digest(data)
        ensure(item.get('digest') == 'sha256:' + checksum, 'controls-archive-digest-exact-api-provenance')
        with zipfile.ZipFile(io.BytesIO(data)) as bundle:
            files = bundle.infolist()
            ensure(len(files) <= 16 and all(not info.flag_bits & 1 and info.file_size <= 512 * 1024 for info in files), 'bounded-unencrypted-controls-archive-members')
            results = [info for info in files if info.filename in {'result.json', 'storage-boundary-evidence/result.json'}]
            ensure(len(results) == 1, 'one-controls-result-member')
            result_bytes = bundle.read(results[0])
            row = json.loads(result_bytes)
            if cohort == 'preflight':
                patches = [info for info in files if info.filename == 'formatting/formatting.patch']
                ensure(len(patches) == 1 and patches[0].file_size == 0 and bundle.read(patches[0]) == b'', 'controls-formatter-patch-empty')
        ensure(row.get('source') == report['source'] and row.get('inputs_pristine') is True
               and row.get('input_manifest_sha256') == report['input_manifest_sha256']
               and row.get('reviewed_cohort_baseline') == report['reviewed_cohort_baseline']
               and row.get('ownership_adaptation', {}).get('original_three_test_bodies_exact') is True
               and row.get('toolchain') == report['toolchain'] and row.get('environment') == report['environment']
               and not row.get('controller_failure_type'), 'controls-exact-source-input-toolchain-and-environment')
        if cohort == 'preflight':
            ensure(row.get('preflight_passed') is True and row.get('actual_executed_nonignored') == 0, 'controls-preflight-required')
        else:
            bodies = row.get('bodies', {})
            ensure(row.get('cohort') == cohort and row.get('compile_only') is False
                   and row.get('crossing_diagnostics_only') is False and not row.get('mutations_only')
                   and row.get('boundary_controls_passed') is True and row.get('actual_counts_complete') is True
                   and row.get('actual_executed_nonignored') == 4 and sorted(bodies) == sorted(TESTS + [ADDED_TEST])
                   and row.get('inventory', {}).get('selected_nonignored') == 4
                   and row.get('inventory', {}).get('selected_ignored') == 0, 'four-complete-nonignored-owned-controls-per-cohort')
            compilation = row.get('compilation', {})
            ensure(compilation.get('exit_code') == 0 and compilation.get('compiler_error_count') == 0
                   and compilation.get('selected_test_artifact_count') == 1
                   and compilation.get('compiled_features') == ([] if cohort == 'default' else ['experimental-device-sync'])
                   and re.fullmatch('[0-9a-f]{64}', compilation.get('compiler_artifact_feature_manifest_sha256', '')) is not None
                   and re.fullmatch('[0-9a-f]{64}', compilation.get('binary_sha256', '')) is not None, 'controls-compiled-feature-cohort-and-binary')
            for body in bodies.values():
                ensure(body.get('actual_counts_complete') is True and body.get('passed_gate') is True
                       and body.get('passed') == 1 and body.get('failed') == body.get('ignored') == 0
                       and body.get('panic_count') == body.get('compiler_error_count') == 0
                       and body.get('executed_nonignored') == 1 and body.get('binary_sha256') == compilation['binary_sha256'], 'each-prior-control-actually-passed')
        receipts[cohort] = {'artifact_id': item['id'], 'artifact_sha256': checksum,
                            'result_sha256': digest(result_bytes),
                            'actual_executed_nonignored': row['actual_executed_nonignored']}
    return {'run_id': int(run_id), 'source': report['source'], 'actual_controls': 8, 'receipts': receipts}


def compile_mutation_phase(cohort, expected, phase, save):
    ensure(frozen_inputs() == expected, 'phase-inputs-exact-before-compilation')
    command = ['cargo', 'test', '--locked', '-p', 'storage-sqlite', '--lib', '--no-run', '--message-format=json']
    features = [] if cohort == 'default' else ['experimental-device-sync']
    if features:
        command += ['--features', features[0]]
    code, raw, seconds = capture(command, 1800)
    events = [json.loads(line) for line in raw.splitlines() if line.startswith('{')]
    errors = sum(value.get('reason') == 'compiler-message' and value.get('message', {}).get('level') == 'error' for value in events)
    artifacts = [value for value in events if value.get('reason') == 'compiler-artifact']
    selected = [value for value in artifacts if value['target']['name'] == 'storage_sqlite' and value['target']['kind'] == ['lib'] and value['profile']['test'] and value.get('executable')]
    phase['compilation'] = {'exit_code': code, 'compiler_error_count': errors, 'wall_seconds': seconds,
                            'succeeded': False,
                            'selected_test_artifact_count': len(selected), 'command': command}
    save()
    ensure(code == errors == 0 and len(selected) == 1 and sorted(selected[0]['features']) == features, 'mutation-phase-must-compile-in-exact-feature-cohort')
    binary = Path(selected[0]['executable'])
    fingerprints = sorted([{'package': value['package_id'], 'target': value['target']['name'],
                            'kind': value['target']['kind'], 'features': sorted(value['features']), 'profile': value['profile']}
                           for value in artifacts], key=lambda value: json.dumps(value, sort_keys=True))
    phase['compilation'].update(succeeded=True, compiled_features=features, binary_sha256=digest(binary.read_bytes()),
                                compiler_artifact_feature_manifest_sha256=digest(json.dumps(fingerprints, sort_keys=True).encode()))
    ensure(frozen_inputs() == expected, 'phase-inputs-exact-after-compilation')
    return binary


def run_mutations(args, report, frozen, save):
    report['prior_controls'] = prior_controls(args.controls_run_id, report)
    target = Path(BOUNDARY[1])
    original, mode = target.read_bytes(), target.stat().st_mode
    source = original.decode()
    report['mutation_chains'] = {}
    try:
        for label, (name, old, new) in mutation_specs(source).items():
            ensure(source.count(old) == 1, 'single-exact-reviewed-mutant-source-anchor')
            chain = {'selected_test': name, 'phases': {}, 'passed': False}
            report['mutation_chains'][label] = chain
            for phase_name in ['baseline', 'mutant', 'restored']:
                body = source.replace(old, new, 1).encode() if phase_name == 'mutant' else original
                target.write_bytes(body)
                target.chmod(mode)
                expected = {key: dict(value) for key, value in frozen.items()}
                expected[BOUNDARY[1]]['sha256'] = digest(body)
                phase = {'source_manifest_sha256': digest(json.dumps(expected, sort_keys=True, separators=(',', ':')).encode()),
                         'boundary_sha256': digest(body), 'actual_counts_complete': False,
                         'intended_runtime_kill': False, 'runtime_started': False,
                         'runtime_completed': False, 'executed_nonignored': None}
                chain['phases'][phase_name] = phase
                save()
                binary = compile_mutation_phase(args.cohort, expected, phase, save)
                binary_hash = phase['compilation']['binary_sha256']
                code, listed, _ = capture([str(binary), name, '--exact', '--list', '--format', 'terse'], 60)
                listed_lines = [line for line in listed.splitlines() if line]
                ensure(code == 0 and listed_lines.count(name + ': test') == 1
                       and all(line in {name + ': test', '1 test, 0 benchmarks'} for line in listed_lines), 'mutation-phase-one-exact-test-inventory')
                code, ignored, _ = capture([str(binary), name, '--exact', '--ignored', '--list', '--format', 'terse'], 60)
                ensure(code == 0 and ignored.strip() in {'', '0 tests, 0 benchmarks'}, 'mutation-phase-never-ignored')
                ensure(frozen_inputs() == expected and digest(binary.read_bytes()) == binary_hash, 'phase-source-and-binary-exact-before-runtime')
                phase['runtime_started'] = True
                save()
                code, raw, seconds = capture([str(binary), name, '--exact', '--nocapture', '--test-threads=1'], 300)
                phase.update(parse_body(raw, code, name))
                phase.update(runtime_completed=True, wall_seconds=seconds, binary_sha256=binary_hash)
                phase['intended_runtime_kill'] = mutation_killed(label, raw, code, body.decode(), expected) if phase_name == 'mutant' else False
                save()
                ensure(frozen_inputs() == expected and digest(binary.read_bytes()) == binary_hash, 'phase-source-and-binary-exact-after-runtime')
            phases = chain['phases']
            first, mutant, last = (phases[name]['compilation'] for name in ['baseline', 'mutant', 'restored'])
            ensure(first['binary_sha256'] == last['binary_sha256']
                   and first['compiler_artifact_feature_manifest_sha256'] == last['compiler_artifact_feature_manifest_sha256']
                   and first['compiled_features'] == last['compiled_features'], 'baseline-restored-binary-and-features-identical')
            ensure(mutant['binary_sha256'] != first['binary_sha256'], 'counterfactual-must-change-compiled-binary')
            ensure(first['compiler_artifact_feature_manifest_sha256'] == mutant['compiler_artifact_feature_manifest_sha256']
                   and first['compiled_features'] == mutant['compiled_features'], 'mutant-feature-and-profile-manifest-exact-controls')
            chain['binary_and_cohort_proof'] = {
                'mutant_binary_differs_from_baseline': True,
                'baseline_and_restored_binaries_identical': True,
                'all_three_feature_and_profile_manifests_identical': True,
            }
            chain['passed'] = (phases['baseline']['passed_gate'] and phases['mutant']['intended_runtime_kill']
                               and phases['restored']['passed_gate'])
            save()
            ensure(chain['passed'], 'required-intended-runtime-mutation-kill-and-passing-controls')
        report['necessity_mutations_passed'] = True
        return 0
    finally:
        target.write_bytes(original)
        target.chmod(mode)
        phases = [phase for chain in report['mutation_chains'].values() for phase in chain['phases'].values()]
        report['actual_counts_complete'] = len(phases) == 12 and all(phase.get('actual_counts_complete') for phase in phases)
        observed = [phase['executed_nonignored'] for phase in phases if phase.get('actual_counts_complete')]
        report['observed_completed_phase_executions'] = sum(observed)
        report['actual_executed_nonignored'] = sum(observed) if len(observed) == len(phases) else None
        report['mutation_phase_count'] = len(phases)
        report['source_and_modes_restored'] = frozen_inputs() == frozen
        if not report['source_and_modes_restored']:
            report['necessity_mutations_passed'] = False
        save()
        ensure(report['source_and_modes_restored'], 'exact-source-and-mode-restoration-required')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--cohort', choices=['default', 'experimental'], required=True)
    parser.add_argument('--cohort-baseline', default=os.environ.get('UPSTREAM_EXTRACTION_COHORT_BASELINE'))
    parser.add_argument('--preflight', action='store_true')
    parser.add_argument('--compile-only', action='store_true')
    parser.add_argument('--ownership-adaptation', action='store_true')
    parser.add_argument('--crossing-diagnostics', action='store_true')
    parser.add_argument('--mutations', action='store_true')
    parser.add_argument('--controls-run-id')
    args = parser.parse_args()
    os.umask(0o077)
    OUT.mkdir(exist_ok=True)
    report = {'cohort': args.cohort, 'compile_only': args.compile_only, 'crossing_diagnostics_only': args.crossing_diagnostics,
              'mutations_only': args.mutations, 'necessity_mutations_passed': False,
              'qualification_passed': False, 'boundary_controls_passed': False,
              'actual_counts_complete': False, 'actual_executed_nonignored': 0, 'bodies': {}}
    frozen = frozen_inputs()
    report['input_manifest_sha256'] = digest(json.dumps(frozen, sort_keys=True, separators=(',', ':')).encode())
    def save():
        (OUT / 'result.json').write_text(json.dumps(report, indent=2) + '\n')
    try:
        report.update(source_guard(args.cohort_baseline, args.ownership_adaptation))
        report['parser_fixtures'] = parser_preflight()
        report['compiler_parser_fixtures'] = diagnostic_parser_preflight()
        report['crossing_parser_fixtures'] = crossing_parser_preflight()
        if args.ownership_adaptation:
            report['mutation_parser_fixtures'] = mutation_parser_preflight(frozen)
        ensure(not args.compile_only or args.cohort == 'default', 'diagnostic-scope-default-only')
        ensure(not args.crossing_diagnostics or (args.cohort == 'default' and args.ownership_adaptation and not args.compile_only), 'crossing-diagnostic-default-owned-runtime-only')
        ensure(not args.mutations or (args.ownership_adaptation and not args.compile_only and not args.crossing_diagnostics and not args.preflight), 'isolated-owned-mutation-runtime-only')
        report['toolchain'] = {name: subprocess.check_output([name, '--version'], text=True).strip() for name in ['cargo', 'rustc']}
        report['environment'] = {key: os.environ.get(key) for key in ['CARGO_INCREMENTAL', 'CARGO_BUILD_JOBS', 'CARGO_PROFILE_DEV_DEBUG', 'CARGO_PROFILE_TEST_DEBUG', 'RUST_MIN_STACK']}
        save()
        if args.preflight:
            report['preflight_passed'] = True
            return 0
        if args.mutations:
            return run_mutations(args, report, frozen, save)
        selected_tests = sorted(TESTS + ([ADDED_TEST] if args.ownership_adaptation else []))
        if args.crossing_diagnostics:
            selected_tests = [BOUNDARY_TEST]
        expected_count = len(selected_tests)
        command = ['cargo', 'test', '--locked', '-p', 'storage-sqlite', '--lib', '--no-run', '--message-format=json']
        expected_features = []
        if args.cohort == 'experimental':
            command += ['--features', 'experimental-device-sync']
            expected_features = ['experimental-device-sync']
        report['compile_command'] = command
        code, raw, seconds = capture(command, 1800)
        artifacts, errors, diagnostics = [], 0, []
        for line in raw.splitlines():
            if not line.startswith('{'):
                continue
            value = json.loads(line)
            if value.get('reason') == 'compiler-message' and value.get('message', {}).get('level') == 'error':
                errors += 1
                if len(diagnostics) < 16:
                    diagnostics.append(safe_compiler_diagnostic(value, frozen))
            if value.get('reason') == 'compiler-artifact':
                artifacts.append(value)
        selected = [value for value in artifacts if value['target']['name'] == 'storage_sqlite' and value['target']['kind'] == ['lib'] and value['profile']['test'] and value.get('executable')]
        report['compilation'] = {'exit_code': code, 'compiler_error_count': errors, 'wall_seconds': seconds,
                                 'selected_test_artifact_count': len(selected), 'compiled_features': None,
                                 'safe_compiler_diagnostics': diagnostics, 'diagnostics_truncated': errors > 16}
        save()
        ensure(code == 0 and errors == 0 and len(selected) == 1, 'actual-storage-lib-compilation-required')
        artifact = selected[0]
        ensure(sorted(artifact['features']) == expected_features, 'exact-default-or-experimental-storage-feature-cohort')
        binary = Path(artifact['executable'])
        binary_hash = digest(binary.read_bytes())
        report['compilation'].update(compiled_features=sorted(artifact['features']), binary_sha256=binary_hash)
        fingerprints = sorted([{'package': value['package_id'], 'target': value['target']['name'],
                                'kind': value['target']['kind'], 'features': sorted(value['features']), 'profile': value['profile']}
                               for value in artifacts], key=lambda value: json.dumps(value, sort_keys=True))
        report['compilation']['compiler_artifact_feature_manifest_sha256'] = digest(json.dumps(fingerprints, sort_keys=True).encode())
        ensure(frozen_inputs() == frozen, 'inputs-exact-after-compilation')
        if args.compile_only:
            report['compile_only_completed'] = True
            report['compile_only_is_not_runtime_green'] = True
            return 0
        inventory_filter = [BOUNDARY_TEST, '--exact'] if args.crossing_diagnostics else ['base::boundary_tests::']
        code, inventory, _ = capture([str(binary), *inventory_filter, '--list', '--format', 'terse'], 60)
        names = sorted(re.findall(r'^(base::boundary_tests::[A-Za-z_]+): test$', inventory, re.M))
        inventory_lines = [line for line in inventory.splitlines() if line]
        allowed_lines = {name + ': test' for name in selected_tests} | {str(expected_count) + (' test' if expected_count == 1 else ' tests') + ', 0 benchmarks'}
        ensure(code == 0 and names == selected_tests and all(line in allowed_lines for line in inventory_lines), 'exact-reviewed-body-inventory-required')
        code, ignored, _ = capture([str(binary), *inventory_filter, '--ignored', '--list', '--format', 'terse'], 60)
        ensure(code == 0 and ignored.strip() in {'', '0 tests, 0 benchmarks'}, 'no-selected-ignored-bodies')
        report['inventory'] = {'selected_names': names, 'selected_nonignored': expected_count, 'selected_ignored': 0}
        for name in names:
            ensure(frozen_inputs() == frozen and digest(binary.read_bytes()) == binary_hash, 'inputs-and-binary-exact-before-body')
            command = [str(binary), name, '--exact', '--nocapture', '--test-threads=1']
            code, raw, seconds = capture(command, 300)
            row = parse_body(raw, code, name)
            if args.crossing_diagnostics:
                source = Path(BOUNDARY[1]).read_text()
                anchor = '    panic!("{message}");'
                ensure(source.count(anchor) == 1, 'one-original-boundary-panic-anchor')
                panic_line = source[:source.index(anchor)].count('\n') + 1
                row['crossing_diagnostic'] = parse_crossing_diagnostic(raw, code, crossing_context(frozen), panic_line)
            row['wall_seconds'] = seconds
            row['binary_sha256'] = binary_hash
            report['bodies'][name] = row
            known = list(report['bodies'].values())
            report['actual_executed_nonignored'] = sum(item['executed_nonignored'] for item in known) if all(item['actual_counts_complete'] for item in known) else None
            save()
            ensure(frozen_inputs() == frozen and digest(binary.read_bytes()) == binary_hash, 'inputs-and-binary-exact-after-body')
        rows = list(report['bodies'].values())
        report['actual_counts_complete'] = len(rows) == expected_count and all(row['actual_counts_complete'] for row in rows)
        report['actual_executed_nonignored'] = sum(row['executed_nonignored'] for row in rows) if report['actual_counts_complete'] else None
        if args.crossing_diagnostics:
            report['crossing_diagnostic_complete'] = report['actual_counts_complete'] and rows[0].get('crossing_diagnostic', {}).get('status') == 'complete'
            return 1
        report['boundary_controls_passed'] = report['actual_counts_complete'] and all(row['passed_gate'] for row in rows)
        return 0 if report['boundary_controls_passed'] else 1
    except Exception as error:
        report['controller_failure_type'] = type(error).__name__
        report['controller_failure_gate'] = str(error) if isinstance(error, GateFailure) else None
        # No exception payload: a child process can include raw SQL or account data.
        return 1
    finally:
        report['inputs_pristine'] = frozen_inputs() == frozen
        save()
        if not report['inputs_pristine']:
            raise SystemExit(1)


if __name__ == '__main__':
    raise SystemExit(main())
