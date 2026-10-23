#!/usr/bin/env python3
"""One incoming runtime-source policy RED; not a behavioral enrollment regression."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import qualify_upstream_storage_boundary as bounded
from upstream_completion_ci import compile_cases, digest, ensure, environment, identity, parse_body
from qualify_upstream_body_negative import freeze, layout, feature_identity

BASE = '4dc7ed5101b2be35bd273ff67ea10bdc684cd617'
CASE = 'async_suites_choose_their_tokio_flavor'
NAME = 'runtime::tests::' + CASE
FILE = 'crates/marmot-app/src/runtime/tests.rs'
SELF = 'scripts/qualify_upstream_runtime_policy_red.py'
WORKFLOW = '.github/workflows/experimental-sync-ci.yml'
REF = 'refs/heads/ci/upstream-runtime-alignment-20261018'
BEGIN = '  # RUNTIME_POLICY_RED_JOBS_BEGIN\n'
END = '  # RUNTIME_POLICY_RED_JOBS_END\n'
OPTIONS = 'options: [runtime-policy-preflight, runtime-policy-red, '
OUT = Path('runtime-policy-red-evidence')
LIST_PREFIX = 'only under a `//` comment saying why: '


def source_guard():
    source = subprocess.check_output(['git', 'rev-parse', 'HEAD'], text=True).strip()
    ensure(os.environ.get('GITHUB_ACTIONS') == 'true' and os.environ.get('GITHUB_REPOSITORY') == 'dyKiU/mdk'
           and os.environ.get('GITHUB_EVENT_NAME') == 'workflow_dispatch' and source == os.environ.get('GITHUB_SHA')
           and os.environ.get('GITHUB_REF') == REF
           and os.environ.get('GITHUB_WORKFLOW_REF') == 'dyKiU/mdk/' + WORKFLOW + '@' + REF
           and os.environ.get('UPSTREAM_RUNTIME_POLICY_BASELINE') == BASE, 'exact-reviewed-manual-source')
    ensure(os.environ.get('CARGO_INCREMENTAL') == '1' and os.environ.get('CARGO_BUILD_JOBS') == '2'
           and os.environ.get('RUST_MIN_STACK') == '4194304', 'unchanged-runtime-capacity')
    ensure(all(os.environ.get(key) == '0' for key in ['CARGO_PROFILE_DEV_DEBUG', 'CARGO_PROFILE_TEST_DEBUG']), 'unchanged-debug-profile')
    ensure(all(not os.environ.get(key) for key in ['RUSTFLAGS', 'CARGO_ENCODED_RUSTFLAGS', 'RUSTC_BOOTSTRAP',
               'CARGO_PROFILE_DEV_OPT_LEVEL', 'CARGO_PROFILE_TEST_OPT_LEVEL']), 'no-compiler-overrides')
    subprocess.run(['git', 'merge-base', '--is-ancestor', BASE, source], check=True)
    ensure(subprocess.run(['git', 'diff', '--quiet', 'HEAD']).returncode == 0, 'initial-pristine-inputs')
    baseline = {}
    for entry in subprocess.check_output(['git', 'ls-tree', '-r', '-z', BASE]).split(b'\0'):
        if entry:
            metadata, name = entry.split(b'\t', 1)
            mode, kind, blob = metadata.decode().split()
            ensure(kind == 'blob' and mode in {'100644', '100755', '120000'}, 'ordinary-reviewed-tree')
            baseline[os.fsdecode(name)] = (mode, blob)
    current = layout()
    ensure(SELF not in baseline and set(current) == set(baseline) | {SELF}, 'whole-original-inventory-plus-one-controller')
    for name, metadata in current.items():
        mode, blob = baseline.get(name, ('100644', None))
        ensure(metadata['git_mode'] == mode and metadata['symlink'] == (mode == '120000')
               and (metadata['symlink'] or metadata['actual_executable'] == (mode == '100755')), 'whole-original-modes:' + name)
        data = os.fsencode(os.readlink(name)) if metadata['symlink'] else Path(name).read_bytes()
        if name == WORKFLOW:
            text = data.decode()
            ensure(text.count(BEGIN) == text.count(END) == text.count(OPTIONS) == 1, 'one-isolated-workflow-overlay')
            before, rest = text.split(BEGIN); _, after = rest.split(END)
            data = (before + after).replace(OPTIONS, 'options: [', 1).encode()
        if blob is not None:
            ensure(hashlib.sha1(b'blob ' + str(len(data)).encode() + b'\0' + data).hexdigest() == blob,
                   'whole-original-content-exact:' + name)
    ensure(set(subprocess.check_output(['git', 'ls-files', '--others', '--exclude-standard'], text=True).splitlines())
           <= {str(OUT / 'result.json')}, 'no-untracked-source-overlay')
    return {'source': source, 'reviewed_baseline': BASE, 'whole_original_content_and_modes_unchanged': True,
            'allowed_metadata': [SELF, WORKFLOW], 'runtime_policy_body_unchanged': True,
            'historical_runtime_evidence_reused': False, 'behavioral_enrollment_red_claim': False}


def source_offenders():
    """Privacy whitelist only; the actual Rust source-policy assertion is run separately."""
    rows = {}
    tracked = subprocess.check_output(['git', 'ls-files'], text=True).splitlines()
    for name in tracked:
        if not name.endswith('.rs') or not name.startswith(('crates/marmot-app/src/', 'crates/marmot-app/tests/')):
            continue
        ensure(re.fullmatch(r'crates/marmot-app/(?:src|tests)/[A-Za-z0-9_./-]+\.rs', name) and '..' not in Path(name).parts,
               'ordinary-tracked-source-path')
        previous = ''
        for number, line in enumerate(Path(name).read_text().splitlines(), 1):
            line = line.strip()
            composed = line
            while composed.startswith('crate::tests::'):
                composed = composed[len('crate::tests::'):]
            pin = (line == '#[tokio::test(flavor = "current_thread")]'
                   or 'Builder::new_current_thread()' in line
                   or composed.startswith('run_composed_app_runtime_test_on_one_thread('))
            kind = None
            if line == '#[tokio::test]':
                kind = 'BareTokioTest'
            elif pin and (not previous.startswith('//') or previous.startswith('///')):
                kind = 'UnexplainedSingleThread'
            if kind:
                rows[(name, number)] = kind
            previous = line
    ensure(0 < len(rows) <= 1024, 'bounded-nonempty-frozen-source-policy-offenders')
    return rows


def assertion_line():
    lines = Path(FILE).read_text().splitlines()
    matches = [index for index, line in enumerate(lines) if line.strip() == 'offenders.is_empty(),']
    ensure(len(matches) == 1, 'unique-original-offender-policy-oracle')
    return max(index for index in range(matches[0]) if lines[index].strip() == 'assert!(') + 1


def parse(raw, code, whitelist):
    ensure(len(raw.encode()) <= 8 * 1024 * 1024, 'bounded-runtime-output')
    raw = re.sub(r'\x1b\[[0-9;]*m', '', raw)
    row = parse_body(raw, CASE)
    row['body_exit_code'] = code
    row['exact_executed_name'] = re.findall(r'(?m)^test ([A-Za-z_0-9:]+) \.\.\.', raw) == [NAME]
    row['offender_inventory_known'] = False
    # No panic text, absolute host paths or runtime values enter the receipt.
    ensure(raw.count(LIST_PREFIX) == 1, 'one-original-source-policy-message')
    match = re.search(re.escape(LIST_PREFIX) + r'\[\n((?:    "[^"\n]+",\n){1,1024})\]', raw)
    ensure(match is not None, 'complete-bounded-pretty-debug-offender-list')
    prefix = str(Path.cwd()) + '/'
    offenders = []
    seen = set()
    for entry in match[1].splitlines():
        value = re.fullmatch(r'    "([^"\n]+):([1-9][0-9]{0,6})",', entry)
        ensure(value is not None and value[1].startswith(prefix), 'exact-owned-workspace-offender-path')
        path, line = value[1][len(prefix):], int(value[2])
        ensure(re.fullmatch(r'crates/marmot-app/(?:src|tests)/[A-Za-z0-9_./-]+\.rs', path)
               and '..' not in Path(path).parts and (path, line) in whitelist and (path, line) not in seen,
               'unique-actual-frozen-source-offender')
        seen.add((path, line))
        offenders.append({'path': path, 'line': line, 'category': whitelist[(path, line)]})
    ensure(seen == set(whitelist), 'complete-actual-Rust-offender-inventory')
    row['offenders'] = sorted(offenders, key=lambda item: (item['path'], item['line']))
    row['offender_count'] = len(offenders)
    row['offender_inventory_known'] = True
    return row


def intended_policy_red(row):
    locations = row.get('panic_locations', [])
    return (row.get('body_exit_code') == 101 and row.get('passed') == 0 and row.get('failed') == 1
            and row.get('ignored') == 0 and row.get('executed_nonignored') == 1
            and row.get('exact_executed_name') is True and row.get('all_panic_header_count') == 1
            and len(locations) == 1 and locations[0]['file'] == FILE and locations[0]['line'] == assertion_line()
            and row.get('offender_inventory_known') is True and type(row.get('offender_count')) is int
            and 0 < row['offender_count'] <= 1024)


def parser_controls(whitelist):
    listing = ''.join('    "' + str(Path.cwd()) + '/' + path + ':' + str(line) + '",\n' for path, line in sorted(whitelist))
    raw = ('test ' + NAME + ' ... FAILED\nthread case panicked at ' + FILE + ':' + str(assertion_line()) + ':5:\n'
           + LIST_PREFIX + '[\n' + listing + ']\ntest result: FAILED. 0 passed; 1 failed; 0 ignored;')
    row = parse(raw, 101, whitelist)
    ensure(intended_policy_red(row), 'actual-source-policy-red-parser-positive')
    negatives = 0
    for change in [{'body_exit_code': 0}, {'passed': 1}, {'failed': 0}, {'ignored': 1},
                   {'executed_nonignored': 0}, {'all_panic_header_count': 2}, {'exact_executed_name': False},
                   {'panic_locations': []}, {'offender_count': 0}, {'offender_inventory_known': False},
                   {'panic_locations': [{'file': FILE, 'line': assertion_line() + 1, 'column': 5}]}]:
        ensure(not intended_policy_red(dict(row, **change)), 'non-policy-or-zero-runtime-negative')
        negatives += 1
    first = next(iter(sorted(whitelist)))
    original = str(Path.cwd()) + '/' + first[0] + ':' + str(first[1])
    malformed = [raw.replace(original, '/private/account-data:1', 1), raw.replace(original, str(Path.cwd()) + '/../private:1', 1),
                 raw.replace(original, str(Path.cwd()) + '/' + first[0] + ':0', 1),
                 raw.replace(original, str(Path.cwd()) + '/crates/marmot-app/src/not_tracked.rs:1', 1),
                 raw.replace(listing.splitlines()[0] + '\n', '', 1), raw.replace(listing, listing + listing, 1),
                 raw + '\n' + LIST_PREFIX + '[]', raw.replace('"' + original + '"', '"private-value"', 1),
                 raw.replace('[\n' + listing + ']', '[\n' + listing, 1)]
    for value in malformed:
        try:
            parse(value, 101, whitelist)
        except ValueError:
            negatives += 1
            continue
        raise ValueError('unsafe-or-incomplete-offender-export-accepted')
    return {'positive': 1, 'negative': negatives, 'runtime_bodies': 0, 'passed': True}


def main(options):
    os.umask(0o077); OUT.mkdir(exist_ok=True)
    report = {'source_policy_red_verified': False, 'behavioral_enrollment_red_claim': False,
              'qualification_passed': False, 'product_green_claim': False, 'actual_counts_complete': False}
    before = None; modes = None
    def save():
        (OUT / 'result.json').write_text(json.dumps(report, indent=2) + '\n')
    try:
        report['source_guard'] = source_guard()
        whitelist = source_offenders()
        report['parser_controls'] = parser_controls(whitelist); save()
        if options.preflight:
            report['preflight_passed'] = True; save(); return
        report['environment'] = environment()
        before, modes = freeze(), layout()
        report['input_manifest_sha256'] = identity(before)
        compilation, cases = compile_cases([CASE])
        report['compilation'] = compilation; save()
        ensure(compilation.get('compile_exit_code') == compilation.get('compiler_error_count') == 0
               and compilation.get('compiled_fingerprints', {}).get('verified') is True
               and set(cases) == {CASE} and cases[CASE]['name'] == NAME, 'actual-one-feature-verified-source-policy-body')
        report['compiler_error_count'] = 0
        report['feature_identity'] = feature_identity(compilation)
        case = cases[CASE]
        ensure(freeze() == before and layout() == modes and digest(Path(case['binary']).read_bytes()) == case['binary_sha256'], 'before-runtime-source-modes-binary')
        try:
            code, raw, seconds = bounded.capture([case['binary'], '--exact', NAME, '--nocapture', '--test-threads=1'], 300, limit=8 * 1024 * 1024)
        except bounded.GateFailure as error:
            report['watchdog_triggered'] = str(error) == 'bounded-command-timeout'
            report['output_limit_triggered'] = str(error) == 'bounded-command-output-limit'
            report['actual_count_unknown'] = True; save()
            raise ValueError('bounded-runtime-did-not-complete') from None
        report['actual_runtime'] = dict(parse_body(raw, CASE), body_exit_code=code, seconds=seconds,
                                       compiled_binary_sha256=case['binary_sha256'])
        basic = report['actual_runtime']
        report['actual_counts_complete'] = (all(type(basic.get(key)) is int for key in ['passed', 'failed', 'ignored', 'executed_nonignored'])
                                            and basic['passed'] + basic['failed'] == basic['executed_nonignored'] == 1
                                            and basic['ignored'] == 0)
        save()
        report['actual_runtime'] = dict(parse(raw, code, whitelist), seconds=seconds,
                                       compiled_binary_sha256=case['binary_sha256']); save()
        row = report['actual_runtime']
        report['actual_counts_complete'] = (all(type(row.get(key)) is int for key in ['passed', 'failed', 'ignored', 'executed_nonignored'])
                                            and row['passed'] + row['failed'] == row['executed_nonignored'] == 1 and row['ignored'] == 0)
        ensure(report['actual_counts_complete'] and intended_policy_red(row), 'sole-original-source-policy-assertion-red-required')
        ensure(freeze() == before and layout() == modes and digest(Path(case['binary']).read_bytes()) == case['binary_sha256'], 'after-runtime-source-modes-binary')
        report['source_policy_red_verified'] = True
    except Exception as error:
        report['exception_type'] = type(error).__name__
        raise
    finally:
        if before is not None:
            report['inputs_pristine'] = freeze() == before and layout() == modes
            report['source_after_sha256'] = identity(freeze())
        save()
        if before is not None:
            ensure(report['inputs_pristine'], 'final-inputs-pristine')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--preflight', action='store_true')
    main(parser.parse_args())
