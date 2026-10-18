#!/usr/bin/env python3
"""Remote std-only tracing audit: source-layout component evidence, never full CI."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import tempfile
import qualify_upstream_storage_boundary as bounded

BASE = '2af025f5613a1d6c070ad12414d28825bc39f68d'
REF = 'refs/heads/ci/upstream-composed-fixture-layout-20261018'
SELF = 'scripts/qualify_upstream_fixture_layout.py'
WORKFLOW = '.github/workflows/experimental-sync-ci.yml'
AUDIT = 'crates/cgka-conformance-simulator/tests/tracing_audit.rs'
BEGIN = '  # FIXTURE_LAYOUT_JOBS_BEGIN\n'
END = '  # FIXTURE_LAYOUT_JOBS_END\n'
OPTIONS = 'options: [fixture-layout-preflight, fixture-layout-pfp, '
OUT = Path('fixture-layout-evidence')
ROOT = 'crates/marmot-app/src/'
MOVES = [
    (ROOT + 'relay_plane/pairing.rs', ROOT + 'relay_plane/tests/pairing.rs'),
    (ROOT + 'relay_plane/pairing/deployment_regressions.rs', ROOT + 'relay_plane/tests/pairing/deployment_regressions.rs'),
    (ROOT + 'native_device_linking/automatic_forwarding_non_admin_acceptance.rs', ROOT + 'native_device_linking/tests/automatic_forwarding_non_admin_acceptance.rs'),
]
EDITS = [
    (ROOT + 'relay_plane/mod.rs', b'#[path = "tests/pairing.rs"]', b'#[path = "pairing.rs"]'),
    (ROOT + 'native_device_linking/tests.rs', b'#[path = "tests/automatic_forwarding_non_admin_acceptance.rs"]', b'#[path = "automatic_forwarding_non_admin_acceptance.rs"]'),
]
NAMES = sorted(['production_tracing_calls_are_structured_and_privacy_safe',
                'production_tracing_calls_do_not_interpolate_raw_errors',
                'production_library_sources_do_not_write_direct_output',
                'parse_workspace_members_reads_multiline_workspace_array'])
RED = 'production_library_sources_do_not_write_direct_output'


def ensure(value, code):
    if not value:
        raise RuntimeError(code)


def sha(data):
    return hashlib.sha256(data).hexdigest()


def git(*args):
    return subprocess.check_output(['git', *args])


def frozen_tree():
    result = {}
    for row in git('ls-tree', '-r', '-z', BASE).split(b'\0'):
        if not row:
            continue
        meta, name = row.split(b'\t', 1)
        mode, kind, blob = meta.decode().split()
        ensure(kind == 'blob', 'no-unreviewed-submodules')
        result[name.decode()] = (mode, git('cat-file', 'blob', blob))
    return result


def strip_workflow(data):
    text = data.decode()
    ensure(text.count(BEGIN) == text.count(END) == 1 and text.count(OPTIONS) == 1, 'exact-overlay')
    start = text.index(BEGIN)
    end = text.index(END, start) + len(END)
    return (text[:start] + text[end:]).replace(OPTIONS, 'options: [', 1).encode()


def source_guard(frozen, inverse=False):
    head = git('rev-parse', 'HEAD').decode().strip()
    ensure(os.environ.get('GITHUB_ACTIONS') == 'true'
           and os.environ.get('GITHUB_REPOSITORY') == 'dyKiU/mdk'
           and os.environ.get('GITHUB_EVENT_NAME') == 'workflow_dispatch'
           and os.environ.get('GITHUB_SHA') == head
           and os.environ.get('GITHUB_REF') == REF
           and os.environ.get('GITHUB_WORKFLOW_REF') == 'dyKiU/mdk/' + WORKFLOW + '@' + REF
           and os.environ.get('UPSTREAM_FIXTURE_LAYOUT_BASELINE') == BASE, 'exact-reviewed-remote-cohort')
    ensure(not os.environ.get('RUSTC_BOOTSTRAP') and not os.environ.get('RUSTFLAGS')
           and not os.environ.get('CARGO_ENCODED_RUSTFLAGS'), 'no-unreviewed-compiler-overrides')
    subprocess.run(['git', 'merge-base', '--is-ancestor', BASE, head], check=True)
    expected = dict(frozen)
    if inverse:
        for old, new in MOVES:
            ensure(old not in expected, 'old-path-absent-baseline')
            expected[old] = expected.pop(new)
        for path, new, old in EDITS:
            mode, data = expected[path]
            ensure(data.count(new) == 1, 'unique-path-declaration')
            expected[path] = (mode, data.replace(new, old, 1))
    tracked = {row.decode() for row in git('ls-tree', '-r', '--name-only', '-z', 'HEAD').split(b'\0') if row}
    ensure(tracked == set(frozen) | {SELF}, 'whole-reviewed-head-inventory')
    ensure(Path(SELF).is_file() and not Path(SELF).is_symlink()
           and not Path(SELF).stat().st_mode & stat.S_IXUSR
           and git('ls-tree', 'HEAD', SELF).split()[0] == b'100644', 'exact-controller-file-mode')
    for path in [SELF, WORKFLOW]:
        ensure(Path(path).read_bytes() == git('show', 'HEAD:' + path), 'metadata-exact-signed-head')
    for path, (mode, data) in expected.items():
        item = Path(path)
        if mode == '120000':
            ensure(item.is_symlink() and os.readlink(item).encode() == data, 'exact-symlink')
            continue
        ensure(item.is_file() and not item.is_symlink(), 'exact-source-file')
        current = item.read_bytes()
        if path == WORKFLOW:
            current = strip_workflow(current)
        ensure(current == data, 'exact-whole-baseline-bytes')
        ensure(bool(item.stat().st_mode & stat.S_IXUSR) == (mode == '100755'), 'exact-whole-file-modes')
    for old, new in MOVES:
        ensure(not Path(new if inverse else old).exists(), 'no-duplicate-layout-file')
    others = {row.decode() for row in git('ls-files', '--others', '--exclude-standard', '-z').split(b'\0') if row}
    permitted = {str(OUT / 'result.json')} | ({old for old, _ in MOVES} if inverse else set())
    ensure(others <= permitted, 'no-unreviewed-untracked-input')
    return {'baseline': BASE, 'head': head, 'input_files': len(expected), 'inverse_layout': inverse,
            'audit_sha256': sha(expected[AUDIT][1]), 'qualification': False}


def parse(raw, code, mutant=False):
    clean = re.sub(r'\x1b\[[0-9;]*m', '', raw)
    names = re.findall(r'^test ([A-Za-z_][A-Za-z0-9_]*) \.\.\. (?:ok|FAILED)$', clean, re.M)
    summary = re.findall(r'^test result: (ok|FAILED)\. (\d+) passed; (\d+) failed; (\d+) ignored; (\d+) measured; (\d+) filtered out;', clean, re.M)
    ensure(len(summary) == 1, 'one-actual-libtest-summary')
    status, passed, failed, ignored, measured, filtered = summary[0]
    counts = dict(zip(['passed', 'failed', 'ignored', 'measured', 'filtered'], map(int, [passed, failed, ignored, measured, filtered])))
    ensure(sorted(names) == ([RED] if mutant else NAMES), 'exact-actual-case-inventory')
    panics = re.findall(r"^thread '([^']+)'(?: \(\d+\))? panicked at ([^\n]+):$", clean, re.M)
    if mutant:
        ensure(code == 101 and status == 'FAILED' and counts == dict(passed=0, failed=1, ignored=0, measured=0, filtered=3), 'exact-one-runtime-failure')
        ensure(panics == [(RED, AUDIT + ':186:5')] and '\ndirect output audit failed:\n' in clean, 'sole-original-audit-panic')
        rows = re.findall(r'^([^\n]+) production library source writes direct output with `([^`]+)`$', clean, re.M)
        ensure(rows and len(rows) <= 64, 'bounded-owned-source-failures')
        allowed = {old for old, _ in MOVES}
        repo = str(Path.cwd()) + '/'
        for origin, macro in rows:
            rel = origin.removeprefix(repo)
            path, line = rel.rsplit(':', 1)
            ensure(path in allowed and line.isdecimal() and 0 < int(line) < 10000
                   and macro in {'println!(', 'eprintln!('}, 'only-relocated-source-failure-atoms')
    else:
        ensure(code == 0 and status == 'ok' and counts == dict(passed=4, failed=0, ignored=0, measured=0, filtered=0) and not panics, 'four-actual-green-no-panics')
    return {'actual_passed': counts['passed'], 'actual_failed': counts['failed'], 'actual_ignored': counts['ignored'],
            'actual_executed': counts['passed'] + counts['failed'], 'filtered': counts['filtered'], 'selected': sorted(names)}


def phase(label, binary, frozen, inverse=False):
    row = {'label': label, 'compiler_error_count': None, 'body_exit': None,
           'actual_passed': None, 'actual_failed': None, 'actual_ignored': None, 'actual_executed': None}
    RESULT['phases'].append(row)
    row['source'] = source_guard(frozen, inverse)
    row['rustc_identity'] = subprocess.check_output(['rustc', '--version', '--verbose'], text=True)
    ensure('\nrelease: 1.97.1\n' in row['rustc_identity'], 'exact-reviewed-toolchain')
    env_before = os.environ.get('CARGO_MANIFEST_DIR')
    os.environ['CARGO_MANIFEST_DIR'] = str(Path.cwd() / 'crates/cgka-conformance-simulator')
    try:
        code, raw, seconds = bounded.capture(['rustc', '--edition=2024', '--test', AUDIT, '-o', str(binary)], 120, limit=1024*1024)
    finally:
        if env_before is None:
            os.environ.pop('CARGO_MANIFEST_DIR', None)
        else:
            os.environ['CARGO_MANIFEST_DIR'] = env_before
    row['compile_seconds'] = seconds
    ensure(code == 0, 'std-audit-compile-must-pass')
    row['compiler_error_count'] = 0
    row['binary_sha256'] = sha(binary.read_bytes())
    cmd = [str(binary), '--test-threads=1'] + ([RED, '--exact'] if inverse else [])
    code, raw, seconds = bounded.capture(cmd, 120, limit=1024*1024)
    row['body_exit'], row['body_seconds'] = code, seconds
    # Preserve typed basic counts before strict assertions reject a phase.
    summaries = re.findall(r'^test result: (?:ok|FAILED)\. (\d+) passed; (\d+) failed; (\d+) ignored;', raw, re.M)
    if len(summaries) == 1:
        p, f, i = map(int, summaries[0])
        row.update(actual_passed=p, actual_failed=f, actual_ignored=i, actual_executed=p+f)
    row.update(parse(raw, code, inverse))
    source_guard(frozen, inverse)


RESULT = {'qualification': False, 'component_only': True, 'cargo_or_app_compile_qualified': False,
          'native_qualified': False, 'phases': [], 'source_restored': False}


def parser_controls():
    green = '\n'.join('test ' + name + ' ... ok' for name in NAMES) + '\ntest result: ok. 4 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out;\n'
    red = ('test ' + RED + ' ... FAILED\n' + "thread '" + RED + "' panicked at " + AUDIT + ':186:5:\n'
           + 'direct output audit failed:\n' + MOVES[0][0] + ':283 production library source writes direct output with `eprintln!(`\n'
           + 'test result: FAILED. 0 passed; 1 failed; 0 ignored; 0 measured; 3 filtered out;\n')
    parse(green, 0)
    parse(red, 101, True)
    bad = [(green, 101, False), (green.replace('4 passed', '0 passed'), 0, False),
           (green.replace('0 ignored', '1 ignored'), 0, False), (green + green, 0, False),
           (green + "thread 'other' panicked at src/other.rs:1:1:\n", 0, False),
           (red.replace(':186:5:', ':1:1:'), 101, True),
           (red.replace(MOVES[0][0], 'src/unknown.rs'), 101, True),
           (red.replace('eprintln!(', 'unknown!('), 101, True),
           (red.replace('1 failed', '0 failed'), 101, True),
           (red.replace('direct output audit failed:', 'different failure:'), 101, True)]
    for raw, code, mutant in bad:
        try:
            parse(raw, code, mutant)
        except RuntimeError:
            continue
        raise RuntimeError('parser-adversary-accepted')
    return {'positive': 2, 'negative': len(bad)}


def main():
    os.umask(0o077)
    parser = argparse.ArgumentParser()
    parser.add_argument('--mode', choices=['preflight', 'pfp'], required=True)
    args = parser.parse_args()
    OUT.mkdir(exist_ok=True)
    frozen = frozen_tree()
    RESULT['source'] = source_guard(frozen)
    RESULT['parser_controls'] = parser_controls()
    if args.mode == 'preflight':
        RESULT['preflight_only'] = True
        return
    paths = [item for pair in MOVES for item in pair] + [path for path, _, _ in EDITS]
    snapshots = {path: (Path(path).read_bytes(), Path(path).stat().st_mode) if Path(path).exists() else None for path in paths}
    try:
        with tempfile.TemporaryDirectory(prefix='fixture-layout-', dir=os.environ['RUNNER_TEMP']) as temporary:
            binary = Path(temporary) / 'tracing-audit'
            phase('baseline', binary, frozen)
            for old, new in MOVES:
                Path(old).parent.mkdir(parents=True, exist_ok=True)
                Path(new).rename(old)
            for path, new, old in EDITS:
                data = Path(path).read_bytes()
                ensure(data.count(new) == 1, 'unique-inverse-declaration')
                Path(path).write_bytes(data.replace(new, old, 1))
            phase('inverse-layout', binary, frozen, True)
            for path, snapshot in snapshots.items():
                if snapshot is None:
                    Path(path).unlink(missing_ok=True)
                else:
                    Path(path).parent.mkdir(parents=True, exist_ok=True)
                    Path(path).write_bytes(snapshot[0])
                    Path(path).chmod(snapshot[1])
            phase('restored', binary, frozen)
            ensure(len({row['binary_sha256'] for row in RESULT['phases']}) == 1, 'same-std-audit-binary-all-phases-source-data-mutation')
            ensure(len({row['rustc_identity'] for row in RESULT['phases']}) == 1, 'same-compiler-all-phases')
            RESULT['component_pfp_passed'] = True
    finally:
        for path, snapshot in snapshots.items():
            if snapshot is None:
                Path(path).unlink(missing_ok=True)
            else:
                Path(path).parent.mkdir(parents=True, exist_ok=True)
                Path(path).write_bytes(snapshot[0])
                Path(path).chmod(snapshot[1])
        source_guard(frozen)
        RESULT['source_restored'] = True


if __name__ == '__main__':
    try:
        main()
    except Exception as error:
        RESULT['error_kind'] = type(error).__name__
        raise
    finally:
        OUT.mkdir(exist_ok=True)
        (OUT / 'result.json').write_text(json.dumps(RESULT, sort_keys=True, indent=2) + '\n')
