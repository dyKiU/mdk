#!/usr/bin/env python3
"""Remote-only, closed affected controls. Draft: no final/native qualification."""
import argparse
import ast
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import time

import qualify_upstream_storage_boundary as bounded
import upstream_completion_ci as cohort
import qualify_upstream_pure_native5 as native
import qualify_upstream_current_enrollment as enrollment
import qualify_upstream_storage_app_handles as body_counts

BASE = '4938026f686dc27a2a623ffafe4c882224aacea8'
BASE_TREE = '2b4310d0598b41ea9b0bf037b4ed39ced5b5ed2f'
SELF = 'scripts/qualify_upstream_merged_affected.py'
WORKFLOW = '.github/workflows/merged-affected-controls.yml'
OWNED = {SELF, WORKFLOW}
FEATURES = 'marmot-app/otlp-export,marmot-uniffi/otlp-export,marmot-c/otlp-export,wn-cli/otlp-export,agent-connector/otlp-export,marmot-app/product-analytics-export,marmot-uniffi/product-analytics-export,marmot-c/product-analytics-export,wn-cli/product-analytics-export,agent-connector/product-analytics-export,wn-cli/test-policy-overrides,cgka-engine/test-policy-overrides,cgka-engine/test-crash-hooks,experimental-device-sync'
GRAPH = {
    'marmot_app': ['default', 'experimental-device-sync', 'otlp-export', 'product-analytics-export', 'test-policy-overrides'],
    'cgka_engine': ['default', 'experimental-device-sync', 'test-conformance-snapshot', 'test-crash-hooks', 'test-policy-overrides'],
    'storage_sqlite': ['experimental-device-sync', 'storage-format-benchmarks', 'test-conformance-replay', 'test-migrated-template', 'test-support'],
    'cgka_session': ['default', 'experimental-device-sync', 'test-policy-overrides'],
    'marmot_account': ['experimental-device-sync'],
    'transport_nostr': ['default', 'experimental-device-sync', 'test-policy-overrides', 'test-support'],
}
GROUPS = {
    'activity': {'bin': 'storage_sqlite', 'file': 'crates/storage-sqlite/src/mirrored_chat_presentation/activity.rs',
        'tests_file': 'crates/storage-sqlite/src/mirrored_chat_presentation/tests.rs',
        'names': ['mirrored_chat_presentation::tests::' + name for name in [
            'mirrored_activity_page_is_bounded_latest_deduplicated_and_read_only',
            'mirrored_activity_preserves_block_expiry_and_global_terminal_fences',
            'mirrored_activity_rejects_invalid_or_closed_inputs_and_omits_retired_sources']],
        'target': 1, 'anchor': '                    record.payload.clear();', 'replacement': '',
        'scope': 'if record.expires_at.is_some_and(|value| value <= now)',
        'assertion': 'assert!(latest.record.deleted && latest.record.payload.is_empty());'},
    'held-scope': {'bin': 'transport_nostr', 'file': 'crates/transport-nostr/src/held_delivery.rs',
        'tests_file': 'crates/transport-nostr/src/tests/held_delivery_tests.rs',
        'names': ['tests::held_delivery_tests::' + name for name in [
            'held_delivery_limits_scope_and_drop_releases_original_packet',
            'held_delivery_retains_cursor_pins_for_every_duplicate_until_real_receipt',
            'held_delivery_cannot_enter_or_unpin_a_replacement_queue',
            'held_delivery_defers_recovery_without_unpinning_or_consuming_original']],
        'target': 3, 'anchor': '            || delivery.source.plane != TransportDeliveryPlane::Group', 'replacement': '',
        'scope': 'pub fn defer_held_recovery_for_test(',
        'assertion': 'assert!(!adapter.defer_held_recovery_for_test(&wrong_source_plane));'},
    'stale-leave': {'bin': 'marmot_app', 'file': 'crates/marmot-app/src/client/sync.rs',
        'tests_file': 'crates/marmot-app/src/client/sync/queued_outbound_schedule_tests.rs',
        'names': ['client::sync::queued_outbound_schedule_tests::' + name for name in [
            'stale_own_leave_after_input_only_convergence_keeps_worker_wake',
            'inline_epoch_change_keeps_stale_own_leave_worker_wake',
            'restarted_safe_queued_send_does_not_inherit_secondary_retry_cutoff',
            'restarted_below_quorum_send_keeps_required_retry_cutoff',
            'publication_barrier_rejects_unhydrated_inventory',
            'publication_barrier_keeps_pending_mls_after_quorum']] + [
            'tests::due_peer_leave_preserves_the_outbound_fanout_retry_barrier',
            'tests::removed_device_retires_peer_leave_timer_after_input_only_convergence'],
        'target': 0, 'anchor': '|| self.stale_own_leave_needs_wake(group_id)?',
        'replacement': '|| (self.stale_own_leave_needs_wake(group_id)? && false)',
        'scope': 'fn convergence_schedule_state(',
        'assertion': 'a stale durable leave must retain a worker wake after input-only convergence'},
}
BASELINE_GROUPS = ('activity', 'held-scope', 'stale-leave')
GROUPS['core-inline-wake'] = {
    'bin': 'marmot_app', 'file': 'crates/cgka-engine/src/distributed_convergence.rs',
    'tests_file': GROUPS['stale-leave']['tests_file'],
    'names': list(GROUPS['stale-leave']['names']), 'target': 1,
    'anchor': '                    self.schedule_pending_convergence_group(group_id);',
    'replacement': '', 'scope': 'fn emit_convergence_events(',
    'assertion': 'inline epoch-change effects must notify the worker about the stale original leave',
}
COMPILE_TIMEOUT = 1800
BODY_TIMEOUT = 300
ensure = bounded.ensure


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def git(*args, raw=False):
    value = subprocess.check_output(['git', *args])
    return value if raw else value.decode().strip()


def layout(ref):
    result = {}
    for entry in git('ls-tree', '-rz', ref, raw=True).split(b'\0'):
        if not entry:
            continue
        head, name = entry.split(b'\t', 1)
        mode, kind, oid = head.decode().split()
        name = name.decode()
        ensure(kind == 'blob' and mode in ['100644', '100755', '120000'], 'tracked-mode')
        ensure(not Path(name).is_absolute() and '..' not in Path(name).parts, 'tracked-containment')
        result[name] = {'mode': mode, 'blob': oid}
    return result


def physical(names):
    result = {}
    root = Path.cwd().resolve()
    for name in sorted(names):
        path = Path(name)
        ensure(all(not parent.is_symlink() for parent in path.parents), 'parent-symlink')
        info = path.lstat()
        if stat.S_ISLNK(info.st_mode):
            raw, mode = os.fsencode(os.readlink(path)), '120000'
        else:
            ensure(stat.S_ISREG(info.st_mode), 'regular-tracked-file')
            ensure(path.resolve().is_relative_to(root), 'physical-containment')
            raw = path.read_bytes()
            mode = '100755' if info.st_mode & 0o111 else '100644'
        oid = hashlib.sha1(b'blob ' + str(len(raw)).encode() + b'\0' + raw).hexdigest()
        result[name] = {'mode': mode, 'blob': oid}
    return result


def identity(values):
    return sha(json.dumps(values, sort_keys=True, separators=(',', ':')).encode())


def source_guard(expected=None, mutant=None):
    head = git('rev-parse', 'HEAD')
    ensure(os.environ.get('GITHUB_ACTIONS') == 'true' and os.environ.get('GITHUB_SHA') == head, 'remote-head')
    ensure(os.environ.get('GITHUB_REPOSITORY') == 'dyKiU/mdk', 'fork-only')
    ensure(os.environ.get('GITHUB_REF', '').startswith('refs/heads/ci/upstream-develop-dy-'), 'allowed-ref')
    ensure(os.environ.get('GITHUB_WORKFLOW_REF') == 'dyKiU/mdk/' + WORKFLOW + '@' + os.environ['GITHUB_REF'], 'actual-workflow-identity')
    ensure(os.environ.get('GITHUB_WORKFLOW_SHA') == head, 'actual-workflow-source')
    ensure(git('rev-parse', '--show-object-format') == 'sha1', 'git-object-format')
    ensure(git('rev-parse', BASE + '^{tree}') == BASE_TREE, 'base-tree')
    ensure(b'\ngpgsig ' in git('cat-file', 'commit', BASE, raw=True), 'reviewed-signed-base-object')
    ensure(subprocess.run(['git', 'merge-base', '--is-ancestor', BASE, head], stdout=subprocess.DEVNULL).returncode == 0, 'base-ancestry')
    base, current = layout(BASE), layout('HEAD')
    ensure(not OWNED & set(base) and set(current) == set(base) | OWNED, 'two-metadata-inventory')
    ensure(all(current[name] == value for name, value in base.items()), 'base-blobs-modes')
    ensure(all(current[name]['mode'] == '100644' for name in OWNED), 'metadata-mode')
    ensure(not git('diff', '--cached', '--name-only'), 'clean-index')
    ensure(not git('ls-files', '--others', '--exclude-standard'), 'untracked-input')
    observed = physical(current)
    wanted = dict(current)
    if mutant:
        name, value = mutant
        ensure(name in base, 'mutant-baseline-path')
        wanted[name] = {'mode': current[name]['mode'], 'blob': value}
    ensure(observed == wanted, 'physical-input-drift')
    if expected is not None:
        ensure(current == expected, 'head-inventory-drift')
    return {'head': head, 'tree': git('rev-parse', 'HEAD^{tree}'), 'base': BASE, 'base_tree': BASE_TREE,
        'base_signature': 'root-reviewed-G; exact signed commit object pinned, not remote trust revalidation',
        'tracked_count': len(current), 'input_manifest_sha256': identity(current),
        'workflow_ref': os.environ['GITHUB_WORKFLOW_REF'], 'workflow_sha': os.environ['GITHUB_WORKFLOW_SHA'],
        'run_id': os.environ.get('GITHUB_RUN_ID'), 'event': os.environ.get('GITHUB_EVENT_NAME'),
        'metadata': {name: current[name] for name in sorted(OWNED)}, 'pristine': mutant is None}, current


def environment():
    wanted = {'CARGO_INCREMENTAL': '1', 'CARGO_BUILD_JOBS': '2', 'RUST_MIN_STACK': '4194304',
        'CARGO_PROFILE_DEV_DEBUG': '0', 'CARGO_PROFILE_TEST_DEBUG': '0'}
    ensure(all(os.environ.get(key) == value for key, value in wanted.items()), 'execution-environment')
    for key in ['RUSTFLAGS', 'CARGO_ENCODED_RUSTFLAGS', 'RUSTC_BOOTSTRAP', 'CARGO_PROFILE_DEV_OPT_LEVEL', 'CARGO_PROFILE_TEST_OPT_LEVEL']:
        ensure(not os.environ.get(key), 'compiler-override')
    target = Path(os.environ['CARGO_TARGET_DIR']).resolve()
    ensure(target.is_relative_to(Path(os.environ['RUNNER_TEMP']).resolve()), 'owned-target-directory')
    free_bytes = os.statvfs(os.environ['RUNNER_TEMP']).f_bavail * os.statvfs(os.environ['RUNNER_TEMP']).f_frsize
    ensure(free_bytes >= 48 * 1024 ** 3, 'minimum-free-capacity')
    return {'variables': wanted, 'capacity_free_bytes_before_compile': free_bytes, 'capacity_minimum_bytes': 48 * 1024 ** 3, 'toolchain': git_tool(['rustc', '--version']),
        'cargo': git_tool(['cargo', '--version']), 'features': FEATURES, 'test_threads': 1,
        'automatic_retries': 0, 'compile_watchdog_seconds': COMPILE_TIMEOUT, 'body_watchdog_seconds': BODY_TIMEOUT}


def git_tool(command):
    return subprocess.check_output(command, text=True).strip()


def expected_site(group):
    item = GROUPS[group]
    text = Path(item['tests_file']).read_text()
    short = item['names'][item['target']].split('::')[-1]
    match = list(re.finditer(r'\b(?:async\s+)?fn\s+' + re.escape(short) + r'\s*\(', text))
    ensure(len(match) == 1, 'sole-test-function')
    start = match[0].start()
    next_fn = re.search(r'\n(?:async\s+)?fn\s+\w+\s*\(', text[match[0].end():])
    end = match[0].end() + next_fn.start() if next_fn else len(text)
    part = text[start:end]
    if group in ['stale-leave', 'core-inline-wake']:
        # The selected original test owns its panic; only its source assertion moved.
        argument = 'true' if group == 'core-inline-wake' else 'false'
        ensure(re.match(r'async fn ' + re.escape(short) + r'\(\)\s*\{\s*assert_stale_own_leave_wake\(' + argument + r'\)\.await;\s*\}', part) is not None, 'exact-original-stale-wrapper')
        helpers = list(re.finditer(r'(?m)^async fn assert_stale_own_leave_wake\(require_inline_ingest_wake: bool\) \{', text))
        ensure(len(helpers) == 1, 'sole-stale-shared-helper')
        start = helpers[0].start()
        next_helper_fn = re.search(r'\n(?:async\s+)?fn\s+\w+\s*\(', text[helpers[0].end():])
        end = helpers[0].end() + next_helper_fn.start() if next_helper_fn else len(text)
        part = text[start:end]
    ensure(part.count(item['assertion']) == 1, 'sole-test-oracle')
    mark = part.index(item['assertion'])
    assertions = list(re.finditer(r'\bassert(?:_eq|_ne)?!\s*\(', part[:mark + len(item['assertion'])]))
    ensure(bool(assertions), 'oracle-assertion-site')
    index = start + assertions[-1].start()
    return {'file': item['tests_file'], 'line': text.count('\n', 0, index) + 1}


def mutation_bytes(group, admitted_raw=None):
    item = GROUPS[group]
    raw = Path(item['file']).read_bytes() if admitted_raw is None else admitted_raw
    text = raw.decode()
    start = text.index(item['scope'])
    # The exact anchor must be unique AFTER this function/branch boundary.
    tail = text[start:]
    if group == 'core-inline-wake':
        end = text.index('\n    pub(crate) fn application_replay_events(', start)
        tail = text[start:end]
        branch = list(re.finditer(r'if request\.last_proposed_epoch != Some\(selected_tip\) \{([^{}]*)\}', tail))
        ensure(len(branch) == 1 and branch[0][1].count(item['anchor']) == 1, 'exact-core-stale-epoch-wake-branch')
    ensure(tail.count(item['anchor']) == 1, 'single-mutation-anchor')
    offset = start + tail.index(item['anchor'])
    changed = (text[:offset] + item['replacement'] + text[offset + len(item['anchor']):]).encode()
    ensure(changed != raw, 'actual-mutation-change')
    oid = hashlib.sha1(b'blob ' + str(len(changed)).encode() + b'\0' + changed).hexdigest()
    return raw, changed, oid


def parse_body(raw, code, name, site):
    raw = re.sub(r'\x1b\[[0-9;]*m', '', raw)
    summary = re.findall(r'^test result: (ok|FAILED)\. (\d+) passed; (\d+) failed; (\d+) ignored; (\d+) measured; (\d+) filtered out;', raw, re.M)
    names = re.findall(r'^test ([A-Za-z0-9_:]+) \.\.\. ', raw, re.M)
    panics = re.findall(r"^thread '([^'\n]+)'(?: \(\d+\))? panicked at (crates/[A-Za-z0-9_./-]+\.rs):(\d+):(\d+):", raw, re.M)
    row = {'test': name, 'exit_code': code, 'summary_complete': len(summary) == 1,
        'exact_selected_name': names == [name], 'compiler_error_count': len(re.findall(r'^error(?:\[E\d+\])?:', raw, re.M)),
        'panic_count': raw.count('panicked at '), 'own_panic_count': sum(owner == name and file == site['file'] and int(line) == site['line'] for owner, file, line, _ in panics),
        'expected_panic': site, 'passed': None, 'failed': None, 'ignored': None, 'executed_nonignored': None}
    if len(summary) == 1:
        status, passed, failed, ignored, measured, _ = summary[0]
        row.update(passed=int(passed), failed=int(failed), ignored=int(ignored), measured=int(measured), executed_nonignored=int(passed) + int(failed))
        row['summary_consistent'] = (status == 'ok' and int(failed) == 0) or (status == 'FAILED' and int(failed) > 0)
    return row


def valid(row, red=False):
    return (row.get('summary_complete') is True and row.get('summary_consistent') is True
        and row.get('exact_selected_name') is True and row.get('compiler_error_count') == 0
        and row.get('executed_nonignored') == 1 and row.get('ignored') == 0 and row.get('measured') == 0
        and not row.get('watchdog') and row.get('exit_code') == (101 if red else 0)
        and row.get('passed') == (0 if red else 1) and row.get('failed') == (1 if red else 0)
        and row.get('panic_count') == (1 if red else 0) and row.get('own_panic_count') == (1 if red else 0))


def parser_preflight():
    positive = negative = 0
    for group, item in GROUPS.items():
        site = expected_site(group)
        name = item['names'][item['target']]
        for red in [False, True]:
            raw = 'test ' + name + ' ... ' + ('FAILED' if red else 'ok') + '\n'
            if red:
                raw += "thread '" + name + "' panicked at " + site['file'] + ':' + str(site['line']) + ':9:\n'
            raw += 'test result: ' + ('FAILED. 0 passed; 1 failed;' if red else 'ok. 1 passed; 0 failed;') + ' 0 ignored; 0 measured; 99 filtered out;\n'
            row = parse_body(raw, 101 if red else 0, name, site)
            ensure(valid(row, red), 'parser-positive')
            positive += 1
            for key, value in [('exit_code', 100), ('compiler_error_count', 1), ('passed', 2), ('ignored', 1),
                    ('executed_nonignored', 0), ('exact_selected_name', False), ('summary_complete', False),
                    ('summary_consistent', False), ('watchdog', True), ('panic_count', 2), ('own_panic_count', 2)]:
                bad = dict(row, **{key: value})
                ensure(not valid(bad, red), 'parser-negative')
                negative += 1
            for altered in [raw + raw, raw.replace(name, 'unrelated::case'), raw.replace('0 ignored;', '1 ignored;'), raw.replace('test result:', 'missing result:')]:
                ensure(not valid(parse_body(altered, 101 if red else 0, name, site), red), 'parser-raw-negative')
                negative += 1
        mutation_bytes(group)
    return {'positive': positive, 'negative': negative, 'rust_bodies': 0}


def closed_error(error):
    for kind in [bounded.GateFailure, FileNotFoundError, PermissionError, OSError, ValueError, KeyError, TypeError]:
        if isinstance(error, kind):
            return kind.__name__
    return 'OtherException'


def directory_chain(path):
    """Open every physical directory without following any symlink; return owned fd."""
    path = Path(path).absolute()
    fd = os.open('/', os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    evidence = []
    try:
        for component in path.parts[1:]:
            child = os.open(component, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
            os.close(fd)
            fd = child
            item = os.fstat(fd)
            evidence.append((item.st_dev, item.st_ino, stat.S_IMODE(item.st_mode)))
        return fd, evidence
    except BaseException:
        os.close(fd)
        raise


class OwnedLeaf:
    """Admitted parent chain and regular leaf. All writes are descriptor-relative."""
    def __init__(self, path, absent=False):
        self.path = Path(path).absolute()
        fd, self.parents = directory_chain(self.path.parent)
        os.close(fd)
        self.expected = None if absent else self.read_identity()
        if absent:
            fd = self.parent_fd()
            try:
                try:
                    os.stat(self.path.name, dir_fd=fd, follow_symlinks=False)
                except FileNotFoundError:
                    pass
                else:
                    ensure(False, 'new-output-leaf-exists')
            finally:
                os.close(fd)

    def parent_fd(self):
        fd, evidence = directory_chain(self.path.parent)
        if evidence != self.parents:
            os.close(fd)
            ensure(False, 'admitted-parent-changed')
        return fd

    def read_identity(self, include_bytes=False):
        parent = self.parent_fd()
        fd = None
        try:
            admitted = os.stat(self.path.name, dir_fd=parent, follow_symlinks=False)
            ensure(stat.S_ISREG(admitted.st_mode), 'admitted-regular-leaf')
            fd = os.open(self.path.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=parent)
            before = os.fstat(fd)
            ensure((before.st_dev, before.st_ino) == (admitted.st_dev, admitted.st_ino), 'leaf-open-race')
            ensure(stat.S_ISREG(before.st_mode), 'admitted-regular-leaf')
            chunks = []
            while True:
                chunk = os.read(fd, 1024 * 1024)
                if not chunk:
                    break
                chunks.append(chunk)
            after = os.fstat(fd)
            ensure((before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns, before.st_mode) ==
                   (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns, after.st_mode), 'leaf-read-race')
            raw = b''.join(chunks)
            result = {'device': after.st_dev, 'inode': after.st_ino, 'mode': stat.S_IMODE(after.st_mode), 'sha256': sha(raw)}
            return (result, raw) if include_bytes else result
        finally:
            if fd is not None:
                os.close(fd)
            os.close(parent)

    def check(self):
        ensure(self.expected is not None and self.read_identity() == self.expected, 'admitted-leaf-drift')
        return {'sha256': self.expected['sha256'], 'mode': oct(self.expected['mode']), 'regular': True,
                'parents_unchanged': True, 'identity_unchanged': True}

    def replace(self, raw, mode, repair=False):
        """Never open the replaced destination; atomic rename replaces a link itself."""
        fallback = False
        try:
            if self.expected is not None:
                self.check()
            else:
                parent = self.parent_fd()
                try:
                    try:
                        os.stat(self.path.name, dir_fd=parent, follow_symlinks=False)
                    except FileNotFoundError:
                        pass
                    else:
                        ensure(False, 'unexpected-new-leaf')
                finally:
                    os.close(parent)
        except Exception:
            ensure(repair, 'unsafe-write-admission')
            fallback = True
        parent = self.parent_fd()  # Changed parent is never repaired or traversed.
        name = '.merged-affected-write-' + str(os.getpid()) + '-' + str(time.monotonic_ns())
        fd = None
        try:
            fd = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, mode, dir_fd=parent)
            view = memoryview(raw)
            while view:
                amount = os.write(fd, view)
                ensure(amount > 0, 'short-owned-write')
                view = view[amount:]
            os.fchmod(fd, mode)
            os.fsync(fd)
            os.close(fd)
            fd = None
            os.replace(name, self.path.name, src_dir_fd=parent, dst_dir_fd=parent)
            os.fsync(parent)
        finally:
            if fd is not None:
                os.close(fd)
            try:
                os.unlink(name, dir_fd=parent)
            except FileNotFoundError:
                pass
            os.close(parent)
        self.expected = self.read_identity()
        ensure(self.expected['sha256'] == sha(raw) and self.expected['mode'] == mode, 'owned-write-postcheck')
        return fallback


class EvidenceOutput:
    def __init__(self):
        self.root = Path(os.environ['RUNNER_TEMP']).absolute()
        ensure(self.root == self.root.resolve(strict=True), 'canonical-output-parent')
        ensure(not self.root.is_relative_to(Path.cwd().resolve()) and not (self.root / 'merged-affected-evidence').is_relative_to(Path.cwd().resolve()), 'output-outside-git')
        fd, _ = directory_chain(self.root)
        try:
            os.mkdir('merged-affected-evidence', mode=0o700, dir_fd=fd)
        finally:
            os.close(fd)
        self.directory = self.root / 'merged-affected-evidence'
        fd, self.parents = directory_chain(self.directory)
        os.close(fd)
        self.leaf = OwnedLeaf(self.directory / 'result.json', absent=True)

    def save(self, report):
        # Safe repair of the result leaf itself is reported and disqualifies.
        raw = (json.dumps(report, sort_keys=True, indent=2) + '\n').encode()
        fallback = self.leaf.replace(raw, 0o600, repair=True)
        if fallback:
            report['output_integrity_repaired'] = True
            report['gate_passed'] = False
            self.leaf.replace((json.dumps(report, sort_keys=True, indent=2) + '\n').encode(), 0o600)

    def keep_binary(self, name, raw, mode):
        leaf = OwnedLeaf(self.directory / ('pristine-' + name), absent=True)
        leaf.replace(raw, mode)
        return leaf


def executable_snapshot(paths):
    target = Path(os.environ['CARGO_TARGET_DIR']).absolute()
    result = {}
    for name, path in paths.items():
        path = Path(path).absolute()
        ensure(path.is_relative_to(target), 'executable-target-containment')
        leaf = OwnedLeaf(path)
        ensure(leaf.expected['mode'] & 0o111, 'executable-mode')
        result[name] = leaf
    return result


def baseline_copy_bytes(leaf, frozen):
    observed, raw = leaf.read_identity(include_bytes=True)
    ensure(observed == leaf.expected, 'baseline-copy-identity-drift')
    ensure(observed['sha256'] == sha(raw) == frozen['sha256'] and observed['mode'] == frozen['mode'], 'baseline-copy-byte-mode-drift')
    return raw


def check_executables(snapshot):
    ensure(snapshot is not None and set(snapshot) == {'storage_sqlite', 'transport_nostr', 'marmot_app'}, 'complete-current-executable-snapshot')
    return {name: leaf.check() for name, leaf in snapshot.items()}


def postchecks(row, inventory, mutant, state, save):
    good = True
    for name, action in [('source_postcheck', lambda: source_guard(inventory, mutant)[0]),
                         ('all_executables_postcheck', lambda: check_executables(state.get('latest')))]:
        try:
            row[name] = {'passed': True, 'evidence': action()}
        except Exception as error:
            row[name] = {'passed': False, 'exception': closed_error(error)}
            good = False
        save()
    return good


def capture_record(command, timeout, row, save, limit):
    started = time.monotonic()
    row.update(capture_status='started', elapsed_seconds=None, watchdog=False, output_limit=False)
    save()
    try:
        code, raw, seconds = bounded.capture(command, timeout, limit=limit)
        row.update(exit_code=code, elapsed_seconds=seconds, capture_status='returned')
        return code, raw, seconds
    except Exception as error:
        reason = str(error) if isinstance(error, bounded.GateFailure) else ''
        row.update(capture_status='incomplete', exception=closed_error(error),
                   watchdog=reason == 'bounded-command-timeout', output_limit=reason == 'bounded-command-output-limit')
        raise
    finally:
        row['elapsed_seconds'] = round(time.monotonic() - started, 3)
        save()


def compiler_diagnostics(events, inventory, read_source=None):
    """Only closed Rust codes and source-validated primary coordinates leave memory."""
    if read_source is None:
        read_source = lambda name: OwnedLeaf(Path(name).absolute()).read_identity(include_bytes=True)[1]
    result = {'records': [], 'error_events': 0, 'unknown_code_count': 0,
        'unknown_primary_count': 0, 'errors_without_known_primary': 0,
        'truncated_error_events': 0, 'truncated_primary_count': 0,
        'messages_labels_rendered_source_exported': False, 'maximum_records': 64, 'maximum_primary_sites': 64}
    admitted_sites = 0
    for event in events:
        if not isinstance(event, dict) or event.get('reason') != 'compiler-message':
            continue
        message = event.get('message')
        if not isinstance(message, dict) or message.get('level') != 'error':
            continue
        result['error_events'] += 1
        if len(result['records']) == 64:
            result['truncated_error_events'] += 1
            continue
        raw_code = message.get('code')
        code = raw_code.get('code') if isinstance(raw_code, dict) else None
        if raw_code is not None and (not isinstance(code, str) or re.fullmatch(r'E[0-9]{4}', code) is None):
            code = None
            result['unknown_code_count'] += 1
        record = {'code': code, 'primary': []}
        spans = message.get('spans')
        if not isinstance(spans, list):
            result['unknown_primary_count'] += 1
            spans = []
        for span in spans:
            if not isinstance(span, dict) or span.get('is_primary') is not True:
                continue
            file = span.get('file_name')
            line, column = span.get('line_start'), span.get('column_start')
            if (not isinstance(file, str) or file not in inventory or not file.endswith('.rs')
                    or type(line) is not int or type(column) is not int or line <= 0 or column <= 0):
                result['unknown_primary_count'] += 1
                continue
            if admitted_sites == 64:
                result['truncated_primary_count'] += 1
                continue
            try:
                raw = read_source(file)
                blob = hashlib.sha1(b'blob ' + str(len(raw)).encode() + b'\0' + raw).hexdigest()
                lines = raw.splitlines()
                if blob != inventory[file]['blob'] or line > len(lines) or column > len(lines[line - 1]) + 1:
                    result['unknown_primary_count'] += 1
                    continue
            except Exception:
                result['unknown_primary_count'] += 1
                continue
            record['primary'].append({'file': file, 'line': line, 'column': column})
            admitted_sites += 1
        if not record['primary']:
            result['errors_without_known_primary'] += 1
        result['records'].append(record)
    return result


def compiler_diagnostic_controls():
    file, raw = 'crates/cgka-engine/src/review_fixture.rs', b'fn fixed() {}\n'
    blob = hashlib.sha1(b'blob ' + str(len(raw)).encode() + b'\0' + raw).hexdigest()
    inventory = {file: {'mode': '100644', 'blob': blob}}
    span = {'is_primary': True, 'file_name': file, 'line_start': 1, 'column_start': 1}
    def event(code, primary):
        return {'reason': 'compiler-message', 'message': {'level': 'error', 'code': code,
            'spans': primary, 'message': 'PRIVATE', 'rendered': 'PRIVATE'}}
    valid_event = event({'code': 'E0308', 'explanation': 'PRIVATE'}, [span])
    read = lambda name: raw
    positive = negative = 0
    for code in [{'code': 'E0308'}, None]:
        value = compiler_diagnostics([event(code, [span])], inventory, read)
        ensure(value['records'] == [{'code': code['code'] if code else None, 'primary': [{'file': file, 'line': 1, 'column': 1}]}], 'compiler-diagnostic-positive')
        ensure('PRIVATE' not in json.dumps(value), 'compiler-no-raw-message')
        positive += 1
    for replacement in [dict(span, file_name='../outside.rs'), dict(span, file_name='/outside.rs'),
            dict(span, line_start=0), dict(span, column_start=0), dict(span, line_start=True),
            dict(span, column_start=True), dict(span, line_start=2), dict(span, column_start=1000)]:
        value = compiler_diagnostics([event(None, [replacement])], inventory, read)
        ensure(value['records'][0]['primary'] == [] and value['unknown_primary_count'] == 1, 'compiler-primary-negative')
        negative += 1
    for code in [{'code': 'PRIVATE'}, {'code': 'E12345'}, {'code': 1234}, 'PRIVATE']:
        value = compiler_diagnostics([event(code, [span])], inventory, read)
        ensure(value['records'][0]['code'] is None and value['unknown_code_count'] == 1 and 'PRIVATE' not in json.dumps(value), 'compiler-code-negative')
        negative += 1
    value = compiler_diagnostics([valid_event], inventory, lambda name: b'different')
    ensure(value['unknown_primary_count'] == 1 and value['records'][0]['primary'] == [], 'compiler-source-drift-negative')
    negative += 1
    value = compiler_diagnostics([valid_event] * 65, inventory, read)
    ensure(len(value['records']) == 64 and value['truncated_error_events'] == 1, 'compiler-error-cap-negative')
    negative += 1
    value = compiler_diagnostics([event(None, [span] * 65)], inventory, read)
    ensure(len(value['records'][0]['primary']) == 64 and value['truncated_primary_count'] == 1, 'compiler-primary-cap-negative')
    negative += 1
    ensure(compiler_diagnostics([{'reason': 'compiler-message', 'message': {'level': 'warning', 'rendered': 'PRIVATE'}}], inventory, read)['records'] == [], 'compiler-nonerror-excluded')
    positive += 1
    return {'positive': positive, 'negative': negative, 'actual_rust_bodies': 0}


def compile_all(report, inventory, mutant, save, state, extra_app_names=()):
    source_guard(inventory, mutant)
    # No package-only rebuild shortcut: exactly the same full workspace cohort.
    command = ['cargo', 'test', '--locked', '--workspace', '--no-run', '--message-format=json', '--features', FEATURES]
    row = {'command': command, 'compiled': False, 'compiler_error_count': None, 'bins': {}, 'full_artifact_manifest': [],
           'capture_status': 'not-started', 'elapsed_seconds': None, 'watchdog': False, 'output_limit': False}
    report.setdefault('compilations', []).append(row)
    save()
    capacity = os.statvfs(os.environ['RUNNER_TEMP'])
    row['capacity_free_bytes_before_compile'] = capacity.f_bavail * capacity.f_frsize
    ensure(row['capacity_free_bytes_before_compile'] >= 48 * 1024 ** 3, 'per-compile-capacity')
    # Cargo may legitimately overwrite any prior test path. Retire that snapshot now.
    state['latest'] = None
    for path in dict.fromkeys(item['tests_file'] for item in GROUPS.values()):
        Path(path).touch()
    try:
        code, raw, seconds = capture_record(command, COMPILE_TIMEOUT, row, save, 32 * 1024 * 1024)
        row.update(exit_code=code, seconds=seconds)
        events, malformed = [], 0
        for line in raw.splitlines():
            if line.startswith('{'):
                try:
                    events.append(json.loads(line))
                except json.JSONDecodeError:
                    malformed += 1
        row['compiler_error_count'] = sum(event.get('reason') == 'compiler-message' and event.get('message', {}).get('level') == 'error' for event in events)
        diagnostic_inventory = dict(inventory)
        if mutant:
            name, oid = mutant
            diagnostic_inventory[name] = dict(diagnostic_inventory[name], blob=oid)
        row['compiler_diagnostics'] = compiler_diagnostics(events, diagnostic_inventory)
        row['malformed_json_count'] = malformed
        save()
        artifacts = [event for event in events if event.get('reason') == 'compiler-artifact']
        manifest = []
        for event in artifacts:
            target = event.get('target', {})
            ensure(re.fullmatch(r'[A-Za-z0-9_.-]+', target.get('name', '')) is not None, 'artifact-static-name')
            ensure(all(re.fullmatch(r'[A-Za-z0-9_./+ -]+', value) for value in event.get('features', [])), 'artifact-feature-schema')
            manifest.append({'target': target['name'], 'kind': target.get('kind'), 'features': sorted(event.get('features', [])),
                'profile': event.get('profile'), 'package_id_sha256': sha(event.get('package_id', '').encode())})
        row['full_artifact_manifest'] = sorted(manifest, key=lambda value: json.dumps(value, sort_keys=True))
        row['full_artifact_manifest_sha256'] = identity(row['full_artifact_manifest'])
        finished = [event for event in events if event.get('reason') == 'build-finished']
        ensure(code == 0 and row['compiler_error_count'] == 0 and malformed == 0 and len(finished) == 1 and finished[0].get('success') is True, 'actual-compile-success')
        binaries = {}
        for bin_name in ['storage_sqlite', 'transport_nostr', 'marmot_app']:
            selected = [event for event in artifacts if event.get('target', {}).get('name') == bin_name and event['target'].get('kind') == ['lib'] and event.get('profile', {}).get('test') is True and event.get('executable')]
            ensure(len(selected) == 1, 'exact-three-unit-binaries')
            event = selected[0]
            binary = Path(event['executable'])
            ensure(binary.is_file() and not binary.is_symlink() and binary.resolve().is_relative_to(Path(os.environ['CARGO_TARGET_DIR']).resolve()), 'binary-containment')
            ensure(re.fullmatch(re.escape(bin_name) + r'-[0-9a-f]{16}', binary.name) is not None, 'binary-name')
            ensure(event.get('fresh') is False and sorted(event.get('features', [])) == GRAPH[bin_name], 'selected-unit-feature-build')
            admitted = OwnedLeaf(binary)
            admitted_evidence = admitted.check()
            row['bins'][bin_name] = {'sha256': admitted_evidence['sha256'], 'mode': admitted_evidence['mode'],
                'features': sorted(event['features']), 'profile': event['profile'], 'fresh': event['fresh']}
            fingerprint = binary.parent.parent / '.fingerprint' / (bin_name.replace('_', '-') + '-' + binary.name.rsplit('-', 1)[1]) / ('test-lib-' + bin_name + '.json')
            ensure(fingerprint.is_file() and fingerprint.with_suffix('').is_file(), 'test-profile-fingerprint-found')
            fingerprint_data = json.loads(fingerprint.read_text())
            fingerprint_features = fingerprint_data.get('features')
            if isinstance(fingerprint_features, str):
                fingerprint_features = json.loads(fingerprint_features)
            ensure(sorted(fingerprint_features) == GRAPH[bin_name] and fingerprint_data.get('rustflags') == [], 'test-profile-fingerprint-cohort')
            row['bins'][bin_name]['test_profile_fingerprint'] = {
                'json_sha256': sha(fingerprint.read_bytes()), 'companion_sha256': sha(fingerprint.with_suffix('').read_bytes()),
                'features': sorted(fingerprint_features), 'profile': fingerprint_data.get('profile'),
                'compile_kind': fingerprint_data.get('compile_kind'), 'rustflags': []}
            binaries[bin_name] = binary
        state['latest'] = executable_snapshot(binaries)
        row['admitted_all_executables'] = check_executables(state['latest'])
        ensure(all(row['bins'][name]['sha256'] == evidence['sha256'] and row['bins'][name]['mode'] == evidence['mode'] for name, evidence in row['admitted_all_executables'].items()), 'compile-admission-binary-drift')
        for bin_name, binary in binaries.items():
            listing_row = {'selected_bin': bin_name}
            row.setdefault('listings', []).append(listing_row)
            listing_row['precheck'] = check_executables(state['latest'])
            try:
                list_code, listing, _ = capture_record([str(binary), '--list', '--format', 'terse'], 60, listing_row, save, 4 * 1024 * 1024)
                available = re.findall(r'^([A-Za-z0-9_:]+): test$', listing, re.M)
                required = list(dict.fromkeys(name for group in GROUPS.values() if group['bin'] == bin_name for name in group['names']))
                if bin_name == 'marmot_app':
                    required = list(dict.fromkeys(required + list(extra_app_names)))
                listing_row['exact_inventory'] = list_code == 0 and all(available.count(name) == 1 for name in required)
                row['bins'][bin_name]['selected_test_inventory'] = required
                save()
            finally:
                listing_row['postchecks_passed'] = postchecks(listing_row, inventory, mutant, state, save)
                save()
            ensure(listing_row.get('exact_inventory') and listing_row['postchecks_passed'], 'compiled-exact-test-inventory')
        metadata = cohort.feature_metadata(binaries['marmot_app'])
        row['app_rooted_six_node_graph'] = metadata
        ensure(metadata.get('verified') is True and set(metadata.get('nodes', {})) == set(GRAPH), 'verified-six-node-graph')
        ensure(all(sorted(metadata['nodes'][name]['features']) == features for name, features in GRAPH.items()), 'exact-dependency-feature-cohort')
        row['compiled'] = True
        return binaries
    except Exception as error:
        row['compile_exception'] = closed_error(error)
        save()
        raise
    finally:
        try:
            row['source_after'], _ = source_guard(inventory, mutant)
            row['source_postcheck_passed'] = True
        except Exception as error:
            row['source_postcheck_passed'] = False
            row['source_postcheck_exception'] = closed_error(error)
        save()
        ensure(row['source_postcheck_passed'], 'compile-source-integrity')


def run_cases(report, label, groups, inventory, save, state, mutant=None, only_target=False):
    selected = [name for group in groups for name in ([GROUPS[group]['names'][GROUPS[group]['target']]] if only_target else GROUPS[group]['names'])]
    ensure(len(selected) == len(set(selected)), 'no-duplicate-case-executions')
    phase = {'label': label, 'rows': [], 'all_green': False}
    report.setdefault('phases', []).append(phase)
    save()
    binaries = compile_all(report, inventory, mutant, save, state)
    for group in groups:
        item = GROUPS[group]
        names = [item['names'][item['target']]] if only_target else item['names']
        for name in names:
            row = {'test': name, 'summary_complete': False, 'source_pristine_or_expected_mutant': False,
                'binary_sha256': state['latest'][item['bin']].expected['sha256'], 'compile_index': len(report['compilations']) - 1}
            phase['rows'].append(row)
            save()
            # Basic counts are saved BEFORE any postcheck or verdict.
            source_guard(inventory, mutant)
            row['all_executables_precheck'] = check_executables(state['latest'])
            try:
                code, raw, seconds = capture_record([str(binaries[item['bin']]), '--exact', name, '--nocapture', '--test-threads=1'], BODY_TIMEOUT, row, save, 4 * 1024 * 1024)
                row.update(parse_body(raw, code, name, state['sites'][group]))
                save()
            except Exception as error:
                row['body_exception'] = closed_error(error)
                row['watchdog_or_capture_invalid'] = True
                save()
            finally:
                row['postchecks_passed'] = postchecks(row, inventory, mutant, state, save)
                save()
            row['source_pristine_or_expected_mutant'] = row['postchecks_passed']
            row['green'] = row['postchecks_passed'] and valid(row)
            row['intended_red'] = row['postchecks_passed'] and only_target and valid(row, True)
            save()
            ensure(row['postchecks_passed'], 'body-integrity-drift')
    phase['all_green'] = all(row.get('green') is True for row in phase['rows'])
    compiled = report['compilations'][-1]
    phase['cohort_signature'] = identity({
        'selected_units': {name: {'features': value['features'], 'profile': value['profile'],
            'fingerprint_profile': value['test_profile_fingerprint']['profile'],
            'compile_kind': value['test_profile_fingerprint']['compile_kind']} for name, value in compiled['bins'].items()},
        'app_dependency_units': {name: {'features': value['features'], 'profile': value['profile'],
            'compile_kind': value['compile_kind'], 'rustflags': value['rustflags']} for name, value in compiled['app_rooted_six_node_graph']['nodes'].items()},
        'full_artifact_manifest_sha256': compiled['full_artifact_manifest_sha256']})
    save()
    return phase


RECIPIENT_RUNTIME_PREFIX = 'enrollment-runtime-timing recipient_after_failed_attempt='
RECIPIENT_RUNTIME_OPS = ['WorkerReceive', 'Ingest', 'IngestEngine', 'IngestEffectPublish', 'ProjectionCheckpoint']
RECIPIENT_RUNTIME_FIELDS = ['started', 'completed', 'in_flight', 'completed_wall_sum_ms', 'oldest_tracked_in_flight_ms', 'untracked_in_flight']


def recipient_runtime_rows(raw, name):
    result = {'available': None, 'schema_known': True, 'rows': None,
        'operations': RECIPIENT_RUNTIME_OPS, 'fields': RECIPIENT_RUNTIME_FIELDS,
        'scope': 'actual fifth runtime cumulative; one account in fixture',
        'independent_nonatomic_snapshot': True, 'completed_wall_not_cpu': True,
        'active_tracking_may_be_incomplete': True, 'absence_or_zero_not_no_work_proof': True,
        'tracked_age_lower_bound_for_oldest_all_active': True, 'counts_not_attributable_to_this_join': True,
        'captured_after_failed_attempt_before_cleanup': True, 'no_before_deadline_or_cause_claim': True}
    prefix = r'(?m)^test ' + re.escape(name) + r' \.\.\. '
    if len(re.findall(prefix, raw)) > 1:
        return dict(result, schema_known=False, closed_schema_rejected=True)
    text = re.sub(prefix, lambda hit: hit[0] + '\n', raw, count=1)
    lines = [line for line in text.splitlines() if 'recipient_after_failed_attempt' in line]
    if not lines:
        return result
    if len(lines) != 1 or len(lines[0].encode()) > 1024:
        return dict(result, schema_known=False, closed_schema_rejected=True)
    decimal = r'(?:0|[1-9][0-9]{0,19})'
    token = r'(?:None|Some\(\[' + decimal + (r', ' + decimal) * 5 + r'\]\))'
    line = lines[0]
    match = re.fullmatch(re.escape(RECIPIENT_RUNTIME_PREFIX) + r'\[(' + token + (r', ' + token) * 4 + r')\]', line)
    if match is None:
        return dict(result, schema_known=False, closed_schema_rejected=True)
    rows = []
    for item in re.finditer(token, match[1]):
        if item[0] == 'None':
            rows.append(None)
        else:
            values = [int(value) for value in re.findall(decimal, item[0])]
            if len(values) != 6 or any(value > 2 ** 64 - 1 for value in values):
                return dict(result, schema_known=False, closed_schema_rejected=True)
            rows.append(values)
    if len(rows) != 5:
        return dict(result, schema_known=False, closed_schema_rejected=True)
    return dict(result, available=True, rows=rows)


def recipient_runtime_controls():
    name = 'source::selected_case'
    some = 'Some([0, 1, 2, 3, 4, 5])'
    line = RECIPIENT_RUNTIME_PREFIX + '[' + ', '.join([some, 'None', some, 'None', some]) + ']'
    maximum = 'Some([' + ', '.join(['18446744073709551615'] * 6) + '])'
    positives = [line, 'test ' + name + ' ... ' + line, RECIPIENT_RUNTIME_PREFIX + '[' + ', '.join([maximum] * 5) + ']', RECIPIENT_RUNTIME_PREFIX + '[' + ', '.join(['None'] * 5) + ']']
    for raw in positives:
        ensure(recipient_runtime_rows(raw, name)['available'] is True, 'recipient-runtime-positive')
    ensure(recipient_runtime_rows('', name)['rows'] is None and recipient_runtime_rows('', name)['available'] is None, 'recipient-runtime-absent-unknown')
    negatives = [line + '\n' + line, line.replace('[0, 1, 2, 3, 4, 5]', '[0, 1, 2, 3, 4]'), line.replace('[0, 1, 2, 3, 4, 5]', '[0, 1, 2, 3, 4, 5, 6]'), line.replace('0, 1', '-1, 1'), line.replace('0, 1', '+1, 1'), line.replace('0, 1', '00, 1'), line.replace('0, 1', '18446744073709551616, 1'), line.replace('0, 1', 'PRIVATE, 1'), 'PRIVATE ' + line, line + ' PRIVATE', line.replace('None', 'Some(None)'), line.replace(', None,', ','), line.replace('None', 'null'), line + ('X' * 1025)]
    for raw in negatives:
        ensure(recipient_runtime_rows(raw, name)['schema_known'] is False, 'recipient-runtime-negative')
    return {'positive': len(positives) + 1, 'negative': len(negatives), 'actual_rust_bodies': 0}


def enrollment_parser_preflight():
    # Pure imported parser/data controls only: no legacy guard/main/global writes.
    ensure(native.NAME == 'native_device_linking::automatic_pairing_acceptance::sequential_installations_acceptance::five_installations_join_with_rotating_existing_sponsors_and_explicit_sharing', 'exact-original-five-name')
    ensure(enrollment.POLICY_NAME == 'runtime::tests::async_suites_choose_their_tokio_flavor', 'exact-original-policy-name')
    return {'recipient_runtime': recipient_runtime_controls(), 'inventory': body_counts.parser_controls(), 'native_original': native.parser_controls(), 'finite_observations': enrollment.observation_controls(),
        'approvals': enrollment.approval_controls(), 'children': enrollment.child_controls(),
        'notification_boundaries': enrollment.boundary_controls(), 'guard_timing': enrollment.guard_timing_controls(),
        'retry_custody': enrollment.retry_custody_controls(), 'inner_receive': enrollment.comprehensive_receive_controls(),
        'old_guards_or_main_called': False, 'old_globals_mutated': False, 'actual_rust_bodies': 0}


def run_enrollment(report, inventory, save, state):
    # Baseline only; original policy then original strict-five, no mutation.
    outer_save = save
    def save():
        attempted = [row for phase in report.get('phases', []) for row in phase['rows'] if row.get('runtime_attempted') is True]
        report['enrollment_runtime_attempts'] = len(attempted)
        report['enrollment_actual_counts'] = {key: (sum(row[key] for row in attempted) if all(type(row.get(key)) is int for row in attempted) else None) for key in ['passed', 'failed', 'ignored', 'executed_nonignored']}
        report['enrollment_known_partial_counts'] = {key: sum(row[key] for row in attempted if type(row.get(key)) is int) for key in ['passed', 'failed', 'ignored', 'executed_nonignored']}
        outer_save()
    class IntegrityFailure(RuntimeError):
        pass
    def integrity(action):
        try:
            return action()
        except Exception as error:
            report['enrollment_integrity_stop'] = True
            report['enrollment_integrity_error'] = closed_error(error)
            save()
            raise IntegrityFailure() from None
    def checked_postchecks(row):
        row['postchecks_passed'] = postchecks(row, inventory, None, state, save)
        save()
        integrity(lambda: ensure(row['postchecks_passed'] is True, 'enrollment-postphysical-hard-stop'))
    names = [enrollment.POLICY_NAME, native.NAME]
    phase = {'label': 'merged-original-enrollment-baseline', 'rows': [], 'all_green': False,
        'native_qualification': False, 'strict_five_join_deadline_seconds': 15}
    report.setdefault('phases', []).append(phase); save()
    binaries = compile_all(report, inventory, None, save, state, tuple(names))
    integrity(lambda: ensure(report['compilations'][-1].get('source_postcheck_passed') is True, 'enrollment-compile-postsource-hard-stop'))
    for name in names:
        five = name == native.NAME
        row = {'test': name, 'cohort': 'strict-five' if five else 'policy', 'runtime_attempted': False,
            'summary_complete': False, 'passed': None, 'failed': None, 'ignored': None, 'executed_nonignored': None,
            'original_oracle_green': False, 'green': False, 'compile_index': len(report['compilations']) - 1}
        phase['rows'].append(row); save()
        try:
            # Positively enumerate selected normal/ignored status under all3-binary closure.
            for ignored in [False, True]:
                integrity(lambda: source_guard(inventory))
                item = {'ignored': ignored, 'all_executables_precheck': integrity(lambda: check_executables(state['latest']))}
                row.setdefault('inventories', []).append(item); save()
                try:
                    code, text, _ = integrity(lambda: capture_record([str(binaries['marmot_app']), '--exact', name] + (['--ignored'] if ignored else []) + ['--list', '--format', 'terse'], 60, item, save, 1024 * 1024))
                    parsed_inventory = integrity(lambda: body_counts.parse_inventory(text, name, ignored))
                    item['passed'] = code == 0 and parsed_inventory.get('passed') is True
                    save()
                finally:
                    checked_postchecks(item)
                integrity(lambda: ensure(item.get('passed') and item['postchecks_passed'], 'exact-selected-normal-nonignored-enrollment-inventory'))
            integrity(lambda: source_guard(inventory))
            row['all_executables_precheck'] = integrity(lambda: check_executables(state['latest']))
            row['runtime_attempted'] = True; save()
            raw = None
            try:
                code, raw, seconds = capture_record([str(binaries['marmot_app']), '--exact', name, '--nocapture', '--test-threads=1'], 900 if five else 300, row, save, 8 * 1024 * 1024)
                # Actual numeric/name evidence before physical/strict diagnostics.
                row.update(parse_body(raw, code, name, {'file': 'crates/marmot-app/src/native_device_linking/tests/automatic_pairing_acceptance.rs', 'line': 0, 'column': 0}))
                row['actual_test_passed'] = valid(row); save()
            finally:
                checked_postchecks(row)
            if raw is not None:
                row['recipient_runtime_after_failed_attempt'] = recipient_runtime_rows(raw, name); save()
                try:
                    row['finite_observations'] = enrollment.finite_observations(raw, name, set(inventory), include_approvals=five)
                except Exception:
                    row['finite_observations'] = {'schema_known': False, 'available': None, 'raw_private_export': False}
                row['panic_locations'] = enrollment.closed_panic_sites(raw, name, set(inventory)); save()
                # Original parse input remains raw; only supplemental function owns normalization.
                if five:
                    parsed = native.parse(raw, code)
                    row['original_oracle'] = enrollment.closed_oracle(parsed); save()
                    approvals = row.get('finite_observations', {}).get('existing_approvals')
                    if type(approvals) is dict:
                        try:
                            row['finite_observations']['existing_approvals'] = enrollment.bind_fifth_approvals(approvals, row['original_oracle'], row['finite_observations'].get('side_aggregates'))
                        except (ValueError, TypeError, KeyError):
                            row['finite_observations']['existing_approvals'] = {'schema_known': False, 'available': None, 'partial_or_unknown': True, 'fixture_installations_by_index': None}
                    row['original_oracle_green'] = native.green(parsed) is True
                else:
                    row['original_oracle_green'] = row.get('actual_test_passed') is True
                row['green'] = row.get('postchecks_passed') is True and row.get('actual_test_passed') is True and row['original_oracle_green']; save()
        except IntegrityFailure:
            row['integrity_failure'] = True; save()
            raise
        except Exception as error:
            row['body_exception'] = closed_error(error); save()
        # Continue to the second original case even if policy/first body fails.
    phase['all_green'] = len(phase['rows']) == 2 and all(row.get('green') is True for row in phase['rows'])
    save(); return phase


def chain_driver(baseline, prepare, mutate, restore):
    admitted = baseline()
    ensure(admitted.get('all_green') is True, 'baseline-not-green-mutant-unattempted')
    # A failing admission never enters this restoration/recompile scope.
    try:
        prepare()
        mutate()
    finally:
        restore()


def ownership_driver_preflight():
    """Remote-only synthetic filesystem/driver tests; zero target/ Rust executions."""
    import tempfile
    positive = negative = 0
    with tempfile.TemporaryDirectory(prefix='merged-affected-owner-', dir=os.environ['RUNNER_TEMP']) as directory:
        root = Path(directory)
        sentinel = root / 'outside-sentinel'
        sentinel.write_bytes(b'untouched')
        parent = root / 'owned'
        parent.mkdir()
        path = parent / 'source'
        path.write_bytes(b'original')
        os.chmod(path, 0o640)
        leaf = OwnedLeaf(path)
        leaf.replace(b'mutant', 0o640)
        ensure(leaf.replace(b'original', 0o640) is False and leaf.expected['mode'] == 0o640, 'fixture-normal-restore')
        positive += 1
        for kind in ['missing', 'symlink', 'wrong-bytes', 'wrong-mode']:
            if kind in ['missing', 'symlink']:
                path.unlink()
            if kind == 'symlink':
                path.symlink_to(sentinel)
            elif kind == 'wrong-bytes':
                path.write_bytes(b'foreign')
            elif kind == 'wrong-mode':
                os.chmod(path, 0o600)
            blocked = False
            try:
                leaf.replace(b'mutant', 0o640)
            except Exception:
                blocked = True
            ensure(blocked, 'fixture-unsafe-mutation-rejected')
            ensure(leaf.replace(b'original', 0o640, repair=True) is True, 'fixture-repair-disqualified')
            ensure(sentinel.read_bytes() == b'untouched' and path.read_bytes() == b'original' and stat.S_IMODE(path.stat().st_mode) == 0o640, 'fixture-outside-bytes-unchanged')
            negative += 1
        # Replacing an admitted parent must never redirect the restore to another directory.
        moved = root / 'moved-owned'
        parent.rename(moved)
        parent.symlink_to(root, target_is_directory=True)
        blocked = False
        try:
            leaf.replace(b'unsafe', 0o640, repair=True)
        except Exception:
            blocked = True
        ensure(blocked and sentinel.read_bytes() == b'untouched' and not (root / 'source').exists(), 'fixture-parent-symlink-blocked')
        parent.unlink()
        moved.rename(parent)
        negative += 1
        # Same-byte symlink and exact-mode changes are not executable identity evidence.
        executable = OwnedLeaf(path)
        for kind in ['symlink', 'mode']:
            original = executable.expected['mode']
            if kind == 'symlink':
                copy = root / 'same-bytes'
                copy.write_bytes(path.read_bytes())
                path.unlink()
                path.symlink_to(copy)
            else:
                os.chmod(path, 0o600)
            blocked = False
            try:
                executable.check()
            except Exception:
                blocked = True
            ensure(blocked, 'fixture-executable-kind-mode')
            executable.replace(b'original', original, repair=True)
            negative += 1
        for kind in ['wrong-bytes', 'same-bytes-new-inode']:
            frozen = {'sha256': executable.expected['sha256'], 'mode': executable.expected['mode']}
            if kind == 'wrong-bytes':
                path.write_bytes(b'changed-after-last-body')
            else:
                replacement = parent / 'new-inode'
                replacement.write_bytes(b'original')
                os.chmod(replacement, frozen['mode'])
                os.replace(replacement, path)
            blocked = False
            try:
                baseline_copy_bytes(executable, frozen)
            except Exception:
                blocked = True
            ensure(blocked, 'fixture-baseline-copy-drift-rejected')
            executable.replace(b'original', frozen['mode'], repair=True)
            negative += 1
    events = []
    def baseline_fail():
        events.append('baseline')
        return {'all_green': False}
    try:
        chain_driver(baseline_fail, lambda: events.append('prepare'), lambda: events.append('mutate'), lambda: events.append('restore'))
    except Exception:
        pass
    ensure(events == ['baseline'], 'fixture-baseline-failure-no-repeat')
    negative += 1
    for failing in ['prepare', 'mutate']:
        events = []
        def baseline_green():
            events.append('baseline')
            return {'all_green': True}
        def prepare():
            events.append('prepare')
            if failing == 'prepare':
                raise ValueError('fixture')
        def mutate():
            events.append('mutate')
            raise ValueError('fixture')
        def restored():
            events.extend(['exact-restore', 'fresh-controls'])
        try:
            chain_driver(baseline_green, prepare, mutate, restored)
        except Exception:
            pass
        ensure(events == (['baseline', 'prepare'] + ([] if failing == 'prepare' else ['mutate']) + ['exact-restore', 'fresh-controls']), 'fixture-partial-always-fresh-restoration')
        positive += 1
    return {'positive': positive, 'negative': negative, 'rust_bodies': 0}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--mode', choices=['preflight', 'baseline', 'mutations', 'enrollment'], required=True)
    parser.add_argument('--chain', choices=list(GROUPS))
    parser.add_argument('--approved-source', default='')
    args = parser.parse_args()
    report = {'cohort_contract': '4938-affected15-four-chain50-leave8-v3', 'mode': args.mode, 'chain': args.chain, 'qualification_passed': False, 'native_qualification': False,
        'collection_complete': False, 'gate_passed': False, 'inputs_pristine': False, 'source_after': None,
        'integrity_or_fallback_disqualified': False,
        'expected_rust_bodies': 0 if args.mode == 'preflight' else (15 if args.mode == 'baseline' else (2 if args.mode == 'enrollment' else (2 * len(GROUPS[args.chain]['names']) + 1 if args.chain else None)))}
    # Output admission precedes even the first save; never follow a pre-existing directory.
    try:
        output = EvidenceOutput()
    except Exception:
        print('merged-affected-output-admission-failed')
        raise SystemExit(1)
    def save():
        output.save(report)
    try:
        save()
    except Exception:
        print('merged-affected-initial-safe-save-failed')
        raise SystemExit(1)
    inventory = None
    state = {'latest': None, 'source_leaf': None, 'original': None, 'original_mode': None,
             'baseline_bins': None, 'baseline_copies': {}}
    failure = False
    try:
        report['source_before'], inventory = source_guard()
        state['sites'] = {group: expected_site(group) for group in GROUPS}
        report['parser_controls'] = parser_preflight()
        report['ownership_driver_controls'] = ownership_driver_preflight()
        report['enrollment_parser_controls'] = enrollment_parser_preflight()
        report['compiler_diagnostic_controls'] = compiler_diagnostic_controls()
        ensure(sum(len(GROUPS[group]['names']) for group in BASELINE_GROUPS) == 15 and len(set(name for group in BASELINE_GROUPS for name in GROUPS[group]['names'])) == 15, 'exact-fifteen-distinct-baseline')
        ensure(sum(2 * len(item['names']) + 1 for item in GROUPS.values()) == 50, 'exact-four-chain-fifty-bodies')
        ast.parse(Path(SELF).read_text())
        if args.mode == 'preflight':
            report.update(collection_complete=True, gate_passed=True)
        else:
            ensure(args.approved_source == report['source_before']['head'], 'explicit-approved-final-source')
            report['environment'] = environment()
            if args.mode == 'enrollment':
                result = run_enrollment(report, inventory, save, state)
                report.update(collection_complete=len(result['rows']) == 2 and all(row.get('summary_complete') for row in result['rows']), gate_passed=result['all_green'])
                report['enrollment_baseline_only'] = True
            elif args.mode == 'baseline':
                baseline = run_cases(report, 'affected-baseline', BASELINE_GROUPS, inventory, save, state)
                report.update(collection_complete=len(baseline['rows']) == 15 and all(row.get('summary_complete') for row in baseline['rows']), gate_passed=baseline['all_green'])
            else:
                ensure(args.chain in GROUPS, 'one-independent-chain')
                group = args.chain
                def baseline_action():
                    result = run_cases(report, 'chain-baseline', [group], inventory, save, state)
                    if result['all_green']:
                        state['baseline_bins'] = {name: {'sha256': leaf.expected['sha256'], 'mode': leaf.expected['mode']} for name, leaf in state['latest'].items()}
                        for name, leaf in state['latest'].items():
                            raw = baseline_copy_bytes(leaf, state['baseline_bins'][name])
                            state['baseline_copies'][name] = output.keep_binary(name, raw, state['baseline_bins'][name]['mode'])
                        report['baseline_copies_policy'] = 'ephemeral retained cleanup copies; never fresh compilation credit; fallback execution not automatic'
                        report['pristine_baseline_binary_copies'] = {name: leaf.check() for name, leaf in state['baseline_copies'].items()}
                        save()
                    return result
                def prepare_action():
                    report['mutation_preparation_attempted'] = True
                    save()
                    leaf = OwnedLeaf(Path(GROUPS[group]['file']).absolute())
                    state['source_leaf'] = leaf
                    _, state['original'] = leaf.read_identity(include_bytes=True)
                    state['original_mode'] = leaf.expected['mode']
                    original, changed, oid = mutation_bytes(group, state['original'])
                    ensure(original == state['original'], 'source-prepare-admission')
                    state['mutant'] = (GROUPS[group]['file'], oid)
                    report['mutation'] = {'path': GROUPS[group]['file'], 'original_sha256': sha(original), 'original_mode': oct(state['original_mode']),
                        'mutant_sha256': sha(changed), 'mutant_git_blob': oid, 'own_oracle': expected_site(group)}
                    leaf.replace(changed, state['original_mode'])
                    source_guard(inventory, state['mutant'])
                    save()
                def mutate_action():
                    mutant = run_cases(report, 'single-mutant', [group], inventory, save, state, state['mutant'], True)
                    report['mutant_killed_at_own_oracle'] = len(mutant['rows']) == 1 and mutant['rows'][0].get('intended_red') is True
                    save()
                def restore_action():
                    report['restoration_attempted'] = True
                    save()
                    try:
                        leaf = state['source_leaf']
                        if leaf is not None and state['original'] is not None:
                            fallback = leaf.replace(state['original'], state['original_mode'], repair=True)
                            report['source_restoration_fallback'] = fallback
                            report['integrity_or_fallback_disqualified'] |= fallback
                            report['restored_source_identity'] = leaf.check()
                        source_guard(inventory)
                        restored = run_cases(report, 'fresh-restored-controls', [group], inventory, save, state)
                        report['restored_all_green'] = restored['all_green']
                        actual = {name: {'sha256': leaf.expected['sha256'], 'mode': leaf.expected['mode']} for name, leaf in state['latest'].items()}
                        report['baseline_restored_binary_equality'] = actual == state['baseline_bins']
                        report['restored_binary_identities'] = actual
                        signatures = [phase['cohort_signature'] for phase in report['phases'] if 'cohort_signature' in phase]
                        report['phase_feature_profile_equivalent'] = len(signatures) == 3 and len(set(signatures)) == 1
                    except Exception as error:
                        report['restoration_exception'] = closed_error(error)
                        report['integrity_or_fallback_disqualified'] = True
                        raise
                    finally:
                        save()
                chain_driver(baseline_action, prepare_action, mutate_action, restore_action)
                report['collection_complete'] = sum(len(phase['rows']) for phase in report.get('phases', [])) == report['expected_rust_bodies'] and all(row.get('summary_complete') for phase in report['phases'] for row in phase['rows'])
                report['gate_passed'] = report.get('mutant_killed_at_own_oracle') is True and report.get('restored_all_green') is True and report.get('baseline_restored_binary_equality') is True and report.get('phase_feature_profile_equivalent') is True and report['collection_complete']
    except Exception as error:
        report['exception'] = closed_error(error)
        failure = True
    finally:
        try:
            report['source_after'], _ = source_guard(inventory)
            report['inputs_pristine'] = True
        except Exception as error:
            report['final_source_exception'] = closed_error(error)
            failure = True
        try:
            if state['latest'] is not None:
                report['final_all_executables'] = check_executables(state['latest'])
            elif args.mode != 'preflight':
                report['final_executable_snapshot_unknown'] = True
                failure = True
            report['final_baseline_copies'] = {name: leaf.check() for name, leaf in state['baseline_copies'].items()}
        except Exception as error:
            report['final_executable_exception'] = closed_error(error)
            failure = True
        report['gate_passed'] &= not failure and report['inputs_pristine'] and not report['integrity_or_fallback_disqualified'] and not report.get('output_integrity_repaired', False)
        try:
            save()
        except Exception:
            # If even the admitted parent changed, following it to emit JSON is unsafe.
            print('merged-affected-final-safe-save-failed')
            report['gate_passed'] = False
    raise SystemExit(0 if report['gate_passed'] else 1)


if __name__ == '__main__':
    main()
