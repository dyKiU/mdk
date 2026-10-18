#!/usr/bin/env python3
"""Frozen merged ownership-policy RED; never full product qualification."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import qualify_upstream_storage_boundary as old
from upstream_extraction_cohort import frozen_inputs

BASE = 'c6f499b7780b66284e5e088ae7c786500c991143'
SELF = 'scripts/qualify_upstream_storage_handle.py'
WORKFLOW = '.github/workflows/upstream-boundary-regressions.yml'
REF = 'refs/heads/ci/upstream-storage-handle-20261018'
BEGIN = '  # STORAGE_HANDLE_JOBS_BEGIN\n'
END = '  # STORAGE_HANDLE_JOBS_END\n'
OPTIONS = 'options: [storage-handle-preflight, storage-handle-red, '
OUT = Path('storage-handle-evidence')
PREFIX = 'base::boundary_tests::'
CONTROLS = sorted(PREFIX + n for n in ['table_registry_names_every_table',
    'cfg_predicates_skip_only_test_builds', 'unknown_production_roots_cannot_escape_boundary_scan',
    'trait_channel_sees_every_way_to_name_a_trait'])
BOUNDARY = PREFIX + 'storage_boundary_matches_the_allow_list'
TESTS = sorted(CONTROLS + [BOUNDARY])
ensure = old.ensure
digest = old.digest


def source_guard():
    source = subprocess.check_output(['git', 'rev-parse', 'HEAD'], text=True).strip()
    ensure(os.environ.get('GITHUB_ACTIONS') == 'true' and os.environ.get('GITHUB_REPOSITORY') == 'dyKiU/mdk'
           and os.environ.get('GITHUB_EVENT_NAME') == 'workflow_dispatch'
           and os.environ.get('GITHUB_SHA') == source and os.environ.get('GITHUB_REF') == REF
           and os.environ.get('GITHUB_WORKFLOW_REF') == 'dyKiU/mdk/' + WORKFLOW + '@' + REF
           and os.environ.get('UPSTREAM_STORAGE_HANDLE_BASELINE') == BASE, 'exact-owned-source-workflow')
    ensure(os.environ.get('CARGO_INCREMENTAL') == '1' and os.environ.get('CARGO_BUILD_JOBS') == '2'
           and os.environ.get('RUST_MIN_STACK') == '4194304'
           and all(os.environ.get(k) == '0' for k in ['CARGO_PROFILE_DEV_DEBUG', 'CARGO_PROFILE_TEST_DEBUG'])
           and all(not os.environ.get(k) for k in ['RUSTFLAGS', 'CARGO_ENCODED_RUSTFLAGS', 'RUSTC_BOOTSTRAP',
               'CARGO_PROFILE_DEV_OPT_LEVEL', 'CARGO_PROFILE_TEST_OPT_LEVEL']), 'fixed-compiler-cohort')
    subprocess.run(['git', 'merge-base', '--is-ancestor', BASE, source], check=True)
    ensure(subprocess.run(['git', 'diff', '--quiet', 'HEAD']).returncode == 0, 'tracked-inputs-pristine')
    baseline = {}
    for entry in subprocess.check_output(['git', 'ls-tree', '-r', '-z', BASE]).split(b'\0'):
        if entry:
            metadata, name = entry.split(b'\t', 1)
            mode, kind, blob = metadata.decode().split()
            ensure(kind == 'blob' and mode in {'100644', '100755', '120000'}, 'ordinary-baseline-mode')
            baseline[os.fsdecode(name)] = (mode, blob)
    frozen = frozen_inputs()
    ensure(set(frozen) == set(baseline) | {SELF} and SELF not in baseline, 'whole-merged-inventory')
    for name, actual in frozen.items():
        mode, blob = baseline.get(name, ('100644', None))
        ensure(actual['mode'] == mode and (mode == '120000' or actual['actual_executable'] == (mode == '100755')),
               'whole-merged-mode:' + name)
        data = os.fsencode(os.readlink(name)) if mode == '120000' else Path(name).read_bytes()
        if name == WORKFLOW:
            text = data.decode()
            ensure(text.count(BEGIN) == text.count(END) == text.count(OPTIONS) == 1, 'isolated-owned-workflow-overlay')
            before, rest = text.split(BEGIN); _, after = rest.split(END)
            data = (before + after).replace(OPTIONS, 'options: [', 1).encode()
        if blob is not None:
            ensure(hashlib.sha1(b'blob ' + str(len(data)).encode() + b'\0' + data).hexdigest() == blob,
                   'whole-merged-content:' + name)
    ensure(not subprocess.check_output(['git', 'ls-files', '--others', '--exclude-standard'], text=True).strip(),
           'no-untracked-overlay')
    return {'source': source, 'baseline': BASE, 'all_merged_contents_and_modes_exact': True,
            'ledger_registry_allowlist_scanner_and_original_assertions_unchanged': True,
            'no_SQL_or_ownership_adaptation': True, 'historical_runtime_evidence_reused': False}


def known_crossing(line, context, section):
    if old.known_crossing(line, context, section):
        return True
    parts = line.split(' ')
    if len(parts) != 3 or ' '.join(parts) != line or len(line) > 512:
        return False
    kind, origin, target = parts
    if kind != 'trait' or origin not in context['sources'] or '..' in origin:
        return False
    if section == 'stale':
        return line in context['listed'] and (re.fullmatch(r'[A-Za-z_][A-Za-z0-9_]{0,127}', target) is not None
                                            or target == 'cgka_traits::*')
    if section != 'new':
        return False
    source = context['sources'][origin]
    if target == 'cgka_traits::*':
        return bool(re.search(r'\buse\s+cgka_traits\b[^;]*\*\s*;', source))
    protocol = '\n'.join(body for path, body in context['sources'].items() if path.startswith('protocol/'))
    return (re.fullmatch(r'[A-Za-z_][A-Za-z0-9_]{0,127}', target) is not None
            and re.search(r'\b' + re.escape(target) + r'\b', source) is not None
            and re.search(r'\b' + re.escape(target) + r'\b', protocol) is not None)


def crossing_inventory(raw, code, context, line):
    row = old.parse_body(raw, code, BOUNDARY)
    locations = row['safe_panic_locations']
    ensure(row['actual_counts_complete'] and row['failed'] == 1 and code == 101
           and row['compiler_error_count'] == 0 and row['panic_count'] == 1
           and len(locations) == 1 and locations[0]['selected_test']
           and locations[0]['known_source_location'] and locations[0]['line'] == line,
           'sole-original-runtime-boundary-assertion')
    clean = re.sub(r'\x1b\[[0-9;]*m', '', raw)
    header = re.search(r"^thread '" + re.escape(BOUNDARY) + r"'(?: \(\d+\))? panicked at crates/storage-sqlite/src/base/boundary_tests\.rs:"
                       + str(line) + r':\d+:\n', clean, re.M)
    ensure(header is not None, 'exact-original-panic-header')
    patterns = {'new': r'([1-9][0-9]{0,2}) crossing\(s\) between the protocol and app sides are not on src/cross/allow-list\.txt\. Move them into cross/, or list them:',
                'stale': r'([1-9][0-9]{0,2}) listed crossing\(s\) no longer occur\. Delete them from src/cross/allow-list\.txt:'}
    result = {'new': [], 'stale': []}; declared = {}; section = None; seen = set(); tail = []
    payload = clean[header.end():].splitlines()
    for index, value in enumerate(payload):
        if not value or value.startswith('note: run with `RUST_BACKTRACE=') or value == 'FAILED':
            tail = payload[index:]; break
        matches = [(kind, re.fullmatch(pattern, value)) for kind, pattern in patterns.items()]
        matches = [(kind, match) for kind, match in matches if match]
        if matches:
            section, match = matches[0]
            ensure(section not in declared and int(match[1]) <= 64, 'one-bounded-crossing-section')
            declared[section] = int(match[1]); continue
        ensure(section is not None, 'unknown-crossing-row-rejected')
        if not known_crossing(value, context, section):
            # A rejected row is NOT an empty/complete crossing inventory. Export
            # only the historical closed static-source diagnostic, never raw SQL.
            return {'status': 'rejected', 'reason': 'unknown-crossing-row-rejected',
                    'new': [], 'stale': [], 'counts': None,
                    'automatically_allowed': False, 'inventory_complete': False,
                    'unqualified_rejection_detail': old.source_grounded_rejection(value, section, context)}
        ensure(value not in seen, 'unique-crossing-row'); seen.add(value)
        kind, origin, target = value.split(' ')
        result[section].append({'kind': kind, 'origin': origin, 'target': target})
        ensure(len(result[section]) <= declared[section], 'declared-crossing-count')
    ensure(declared and all(len(result[k]) == count for k, count in declared.items()), 'complete-crossing-inventory')
    for value in tail:
        if value in {'', 'FAILED', 'failures:', '    ' + BOUNDARY}:
            continue
        if re.fullmatch(r'note: run with `RUST_BACKTRACE=1` environment variable to display a backtrace', value):
            continue
        ensure(re.fullmatch(r'test result: FAILED\. 0 passed; 1 failed; 0 ignored; 0 measured; [0-9]+ filtered out; finished in [0-9.]+s', value),
               'unknown-trailing-crossing-metadata')
    for k, pattern in patterns.items():
        ensure(len(re.findall('^' + pattern + '$', clean, re.M)) == int(k in declared), 'no-duplicate-section')
    return {'status': 'complete', **result, 'counts': {k: len(v) for k, v in result.items()},
            'automatically_allowed': False, 'inventory_complete': True,
            'diagnostic_static_source_validation_only': True}


def aggregate_counts(bodies):
    """Only actual numeric receipts for all five names establish full counts."""
    complete = (set(bodies) == set(TESTS) and all(
        row.get('actual_counts_complete') is True
        and all(type(row.get(k)) is int for k in ['passed', 'failed', 'ignored', 'executed_nonignored'])
        and row['passed'] >= 0 and row['failed'] >= 0 and row['ignored'] == 0
        and row['executed_nonignored'] == row['passed'] + row['failed'] == 1
        for row in bodies.values()))
    result = {'actual_counts_complete': complete}
    for key in ['passed', 'failed', 'ignored', 'executed_nonignored']:
        result['actual_' + key] = sum(v[key] for v in bodies.values()) if complete else None
    return result


def parser_controls():
    inherited = old.parser_preflight()
    context = {'sources': {'app/test.rs': 'use cgka_traits::storage::GroupStorage; use cgka_traits::storage::*;',
                           'protocol/storage.rs': 'impl GroupStorage for SqliteAccountStorage {}'},
               'tables': set(), 'triggers': set(), 'references': set(), 'listed': {'trait app/test.rs OldTrait'}}
    ensure(known_crossing('trait app/test.rs GroupStorage', context, 'new'), 'real-source-trait-row')
    ensure(known_crossing('trait app/test.rs cgka_traits::*', context, 'new'), 'real-source-trait-glob')
    ensure(known_crossing('trait app/test.rs OldTrait', context, 'stale'), 'stale-exact-allowlist-provenance')
    negatives = ['trait app/test.rs PRIVATE_ACCOUNT', 'trait ../private.rs GroupStorage',
                 'trait app/test.rs GroupStorage private', 'trait app/test.rs nsec1PRIVATE',
                 'unknown app/test.rs GroupStorage']
    for value in negatives:
        ensure(not known_crossing(value, context, 'new'), 'unsafe-trait-row-rejected')
    raw = ('running 1 test\ntest ' + BOUNDARY + ' ... \nthread \'' + BOUNDARY
           + "' panicked at crates/storage-sqlite/src/base/boundary_tests.rs:91:5:\n"
           + '1 crossing(s) between the protocol and app sides are not on src/cross/allow-list.txt. Move them into cross/, or list them:\n'
           + 'trait app/test.rs GroupStorage\n\nFAILED\nfailures:\n    ' + BOUNDARY
           + '\ntest result: FAILED. 0 passed; 1 failed; 0 ignored; 0 measured; 4 filtered out; finished in 0.1s\n')
    ensure(crossing_inventory(raw, 101, context, 91)['counts']['new'] == 1, 'closed-typed-inventory-positive')
    for value in [raw + raw, raw.replace('1 crossing(s)', '2 crossing(s)'), raw.replace('GroupStorage\n\n', 'PRIVATE_ACCOUNT\n\n'),
                  raw.replace(':91:5:', ':92:5:'), raw.replace('0 ignored', '1 ignored'), raw + 'PRIVATE_ACCOUNT\n']:
        try:
            rejected = crossing_inventory(value, 101, context, 91)
        except ValueError:
            continue
        ensure(rejected.get('status') == 'rejected' and rejected.get('inventory_complete') is False
               and rejected.get('counts') is None, 'unsafe-inventory-accepted')
    safe_context = {**context, 'sources': {**context['sources'],
                    'app/test.rs': 'use crate::protocol::StoredRecord; SELECT app_table;',
                    'protocol/storage.rs': 'pub struct StoredRecord;'}}
    # A new source-grounded but unrecognized path yields closed atoms only; it
    # is still rejected, never automatically accepted or an empty inventory.
    safe_raw = raw.replace('trait app/test.rs GroupStorage', 'path app/test.rs crate::protocol::StoredRecord')
    safe = crossing_inventory(safe_raw, 101, safe_context, 91)
    ensure(safe['status'] == 'rejected' and safe['counts'] is None
           and safe['unqualified_rejection_detail']['target_atoms_proven_static'] is True
           and safe['unqualified_rejection_detail']['target_atoms'] == ['crate', 'protocol', 'StoredRecord']
           and safe['automatically_allowed'] is False, 'safe-static-rejection-not-complete')
    private = crossing_inventory(raw.replace('trait app/test.rs GroupStorage',
        'path app/test.rs crate::PRIVATE_ACCOUNT'), 101, context, 91)
    ensure(private['status'] == 'rejected' and private['counts'] is None
           and private['unqualified_rejection_detail']['target_atoms'] == []
           and 'PRIVATE_ACCOUNT' not in json.dumps(private), 'unproven-private-atoms-not-exported')
    complete_rows = {name: {'actual_counts_complete': True, 'passed': 1, 'failed': 0,
                          'ignored': 0, 'executed_nonignored': 1} for name in TESTS}
    ensure(aggregate_counts(complete_rows)['actual_passed'] == 5, 'five-real-receipts-counted')
    for rows in [{}, {name: row for name, row in complete_rows.items() if name != BOUNDARY},
                 {**complete_rows, BOUNDARY: {**complete_rows[BOUNDARY], 'passed': None}},
                 {**complete_rows, BOUNDARY: {**complete_rows[BOUNDARY], 'passed': True}},
                 {**complete_rows, BOUNDARY: {**complete_rows[BOUNDARY], 'actual_counts_complete': False}}]:
        unknown = aggregate_counts(rows)
        ensure(unknown['actual_counts_complete'] is False and all(unknown[k] is None for k in
               ['actual_passed', 'actual_failed', 'actual_ignored', 'actual_executed_nonignored']),
               'incomplete-counts-stay-unknown')
    return {'historical_body_parser': inherited, 'trait_positive': 3, 'trait_negative': len(negatives),
            'inventory_positive': 1, 'inventory_negative': 6, 'safe_rejection_controls': 2,
            'aggregate_positive': 1, 'aggregate_negative': 5, 'runtime_bodies': 0}


def main(args):
    os.umask(0o077); OUT.mkdir(exist_ok=True)
    report = {'source': subprocess.check_output(['git', 'rev-parse', 'HEAD'], text=True).strip(),
              'cohort': args.cohort, 'qualification_passed': False, 'native_acceptance_claim': False,
              'initial_policy_RED_verified': False, 'actual_counts_complete': False, 'bodies': {}}
    frozen = None
    def save(): (OUT / 'result.json').write_text(json.dumps(report, indent=2) + '\n')
    try:
        report['source_guard'] = source_guard(); report['parser_controls'] = parser_controls(); save()
        if args.preflight:
            report['source_parser_preflight_passed'] = True; save(); return
        frozen = frozen_inputs(); report['input_manifest_sha256'] = digest(json.dumps(frozen, sort_keys=True).encode())
        context = old.crossing_context(frozen)
        command = ['cargo', 'test', '--locked', '-p', 'storage-sqlite', '--lib', '--no-run', '--message-format=json']
        features = [] if args.cohort == 'default' else ['experimental-device-sync']
        if features: command += ['--features', ','.join(features)]
        code, raw, seconds = old.capture(command, 1800)
        artifacts = []; errors = []
        for value in raw.splitlines():
            if not value.startswith('{'): continue
            item = json.loads(value)
            if item.get('reason') == 'compiler-message' and item.get('message', {}).get('level') == 'error':
                errors.append(old.safe_compiler_diagnostic(item, frozen))
            if item.get('reason') == 'compiler-artifact': artifacts.append(item)
        selected = [a for a in artifacts if a['target']['name'] == 'storage_sqlite' and a['target']['kind'] == ['lib']
                    and a['profile']['test'] and a.get('executable')]
        report['compilation'] = {'command': command, 'exit_code': code, 'compiler_error_count': len(errors),
                                 'safe_errors': errors[:32], 'errors_truncated': len(errors) > 32, 'seconds': seconds}; save()
        ensure(code == 0 and not errors and len(selected) == 1, 'one-real-storage-test-binary')
        artifact = selected[0]; ensure(sorted(artifact['features']) == features, 'exact-compiled-feature-cohort')
        binary = Path(artifact['executable']); binary_hash = digest(binary.read_bytes())
        report['compilation'].update(binary_sha256=binary_hash, features=features,
            artifact_feature_manifest_sha256=digest(json.dumps([{'package': a['package_id'], 'target': a['target']['name'],
                'features': sorted(a['features']), 'profile': a['profile']} for a in artifacts], sort_keys=True).encode()))
        code, inventory, _ = old.capture([str(binary), 'base::boundary_tests::', '--list', '--format', 'terse'], 60)
        names = sorted(re.findall(r'^(base::boundary_tests::[A-Za-z_]+): test$', inventory, re.M))
        ensure(code == 0 and names == TESTS and all(line in {n + ': test' for n in TESTS} | {'5 tests, 0 benchmarks'}
               for line in inventory.splitlines() if line), 'exact-five-case-inventory')
        code, ignored, _ = old.capture([str(binary), 'base::boundary_tests::', '--ignored', '--list', '--format', 'terse'], 60)
        ensure(code == 0 and ignored.strip() in {'', '0 tests, 0 benchmarks'}, 'no-ignored-selected-tests')
        report['inventory'] = {'selected_names': names, 'nonignored': 5, 'ignored': 0}; save()
        source = Path('crates/storage-sqlite/src/base/boundary_tests.rs').read_text()
        anchor = '    panic!("{message}");'; ensure(source.count(anchor) == 1, 'original-boundary-oracle')
        panic_line = source[:source.index(anchor)].count('\n') + 1
        for name in TESTS:
            ensure(frozen_inputs() == frozen and digest(binary.read_bytes()) == binary_hash, 'before-body-source-binary-pristine')
            code, raw, seconds = old.capture([str(binary), '--exact', name, '--nocapture', '--test-threads=1'], 300, limit=8*1024*1024)
            row = old.parse_body(raw, code, name); row['seconds'] = seconds; row['binary_sha256'] = binary_hash
            report['bodies'][name] = row; save()
            ensure(row['actual_counts_complete'] and row['compiler_error_count'] == 0, 'one-actual-nonignored-body')
            if name == BOUNDARY:
                row['crossing_inventory'] = crossing_inventory(raw, code, context, panic_line); save()
            ensure(frozen_inputs() == frozen and digest(binary.read_bytes()) == binary_hash, 'after-body-source-binary-pristine')
        report.update(aggregate_counts(report['bodies']))
        report['initial_policy_RED_verified'] = (report['actual_counts_complete'] and all(report['bodies'][n]['passed_gate'] for n in CONTROLS)
            and report['bodies'][BOUNDARY]['failed'] == 1 and report['bodies'][BOUNDARY]['crossing_inventory']['status'] == 'complete')
        ensure(report['initial_policy_RED_verified'], 'required-real-boundary-policy-RED-and-four-positive-controls')
    except Exception as error:
        report['exception_type'] = type(error).__name__
        if isinstance(error, old.GateFailure): report['failure_gate'] = str(error)
        raise
    finally:
        if frozen is not None: report['inputs_pristine'] = frozen_inputs() == frozen
        save()
        if frozen is not None: ensure(report['inputs_pristine'], 'final-whole-merged-inputs-pristine')


if __name__ == '__main__':
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--preflight', action='store_true')
    p.add_argument('--cohort', choices=['default', 'experimental'], default='default')
    main(p.parse_args())
