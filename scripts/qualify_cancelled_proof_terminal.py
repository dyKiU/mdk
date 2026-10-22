#!/usr/bin/env python3
"""Manual remote-only terminal-negative proof P3/F1/P3; JSON-only evidence."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import selectors
import signal
import stat
import subprocess
import time

# Existing, source-frozen helper: resolve actual selected binary dependency units.
from upstream_completion_ci import FEATURES, feature_metadata

EXPECTED_FEATURES = ('marmot-app/otlp-export,marmot-app/product-analytics-export,'
                     'marmot-app/test-policy-overrides,marmot-app/experimental-device-sync,'
                     'cgka-engine/test-policy-overrides,cgka-engine/test-crash-hooks')
MINIMUM = '338d91e90009b0052d7ea0ec76afcae039040ce8'
SELF = 'scripts/qualify_cancelled_proof_terminal.py'
WORKFLOW = '.github/workflows/upstream-boundary-regressions.yml'
PRODUCT = 'crates/marmot-app/src/client/device_linking/sibling_sharing.rs'
FIXTURE = 'crates/marmot-app/src/native_device_linking/tests/late_peer_proof_negative_acceptance.rs'
PREFIX = 'native_device_linking::automatic_pairing_acceptance::late_peer_proof_negative_acceptance::'
CASES = [PREFIX + name for name in (
    'late_peer_proof_public_cancel_cannot_complete_original',
    'late_peer_proof_injected_validation_rejection_retains_and_recovers',
    'late_peer_proof_public_cancel_does_not_block_independent_ordinary_delivery')]
MESSAGE = 'cancelled sibling proof must not block independent ordinary receive'
FIELDS = 'held own_harvested periodic_observed fresh_before negative_preserved recovered_or_retired no_replay ownership_preserved enrollment_complete public_cancelled'.split()
ORDINARY = 'independent_ready first_denial_seen original_closed_exact published_once source_packet_app_bound unrelated_group wait_sampled ordinary_projected custody_sampled queue_accepted same_receiver ordered_valid_custody negative_preserved final_receiver_matches'.split()
COUNTS = 'accepted validation_rejections own_publications open_attempts routed_after_cancel closed_denials runtime_closes planes_shutdown'.split()
SAMPLE = 'collected row_present original_closed exact_nonce exact_deadline'.split()
OLD_KEYS = ['mode'] + FIELDS + COUNTS + ['relay_closed', 'attempt_completed']
ORD_KEYS = ORDINARY + ['no_replay'] + COUNTS[:6] + ['original_facts_complete'] + COUNTS[6:] + ['independent_closed', 'independent_plane_shutdown', 'relay_closed', 'attempt_completed']
BOOLS = set(FIELDS + ORDINARY + SAMPLE + ['no_replay', 'original_facts_complete', 'independent_closed', 'independent_plane_shutdown', 'relay_closed', 'attempt_completed'])
NS = {'late-peer-negative': OLD_KEYS, 'late-peer-public-cancel-sample': SAMPLE, 'late-peer-ordinary-progress': ORD_KEYS}
DIAGNOSTIC_NS = 'late-peer-ordinary-frozen'
DIAGNOSTIC_BOOLS = {'collected', 'raw_read', 'timeline_read', 'raw_present', 'timeline_present',
                    'timing_present', 'depth_known', 'dequeue_time_known', 'dequeue_order_known',
                    'dequeue_after_accept', 'dequeue_before_verdict', 'invalid_custody'}
DIAGNOSTIC_COUNTS = {'dequeued', 'depth_before', 'depth_after'}
DIAGNOSTIC_ARRAYS = {'raw_matches': (6, bool), 'timeline_matches': (7, bool),
                     'dispositions': (8, int), 'placements': (6, int)}


def decode_diagnostic(line):
    require(line.startswith(DIAGNOSTIC_NS + ' '), 'diagnostic_envelope')
    def unique(pairs):
        result = {}
        for key, value in pairs:
            require(key not in result, 'diagnostic_duplicate_key')
            result[key] = value
        return result
    value = json.loads(line[len(DIAGNOSTIC_NS) + 1:], object_pairs_hook=unique)
    require(type(value) is dict and set(value) == DIAGNOSTIC_BOOLS | DIAGNOSTIC_COUNTS | set(DIAGNOSTIC_ARRAYS), 'diagnostic_keys')
    for key in DIAGNOSTIC_BOOLS:
        require(type(value[key]) is bool, 'diagnostic_bool')
    for key in DIAGNOSTIC_COUNTS:
        require(type(value[key]) is int and 0 <= value[key] <= 18446744073709551615, 'diagnostic_count')
    for key, (size, kind) in DIAGNOSTIC_ARRAYS.items():
        require(type(value[key]) is list and len(value[key]) == size
                and all(type(item) is kind and (kind is bool or 0 <= item <= 18446744073709551615)
                        for item in value[key]), 'diagnostic_array')
    return value


CAP = 16 * 1024 * 1024
ANCHOR = '''                if !entry.recipient
                    && entry.ready
                    && !entry.state.live()
                    && entry.original.matches(scope)
                    && matches!(entry.original.as_ref(), SiblingOriginal::Existing { original, .. }
                        if Arc::ptr_eq(&entry.state, &original.state))
                    && received.control == AccountSharingControl::Body(0)
                    && received.nonce == scope.nonce
                    && received.source == scope.source
                    && received.recipient == scope.recipient
                    && received.approval_id == scope.approval_id
                    && received.signer == scope.recipient
'''


class Rejected(Exception):
    """Only fixed source-owned failure labels, never raw diagnostic text."""


def require(value, code):
    if not value:
        raise Rejected(code)


def sha(data):
    return hashlib.sha256(data).hexdigest()


def git(*args):
    return subprocess.check_output(['git', *args], stderr=subprocess.DEVNULL, timeout=60)


def capture(command, timeout, merged=False):
    """Finite combined budget/deadline, process-group kill; never write raw output."""
    started = time.monotonic()
    process = subprocess.Popen(command, stdout=subprocess.PIPE,
                               stderr=subprocess.STDOUT if merged else subprocess.PIPE,
                               start_new_session=True)
    streams = selectors.DefaultSelector()
    streams.register(process.stdout, selectors.EVENT_READ, 'stdout')
    if not merged:
        streams.register(process.stderr, selectors.EVENT_READ, 'stderr')
    data = {'stdout': bytearray(), 'stderr': bytearray()}
    hashes = {key: hashlib.sha256() for key in data}
    total = 0
    stopped = None
    try:
        while streams.get_map():
            if time.monotonic() - started >= timeout:
                stopped = 'watchdog'
                break
            for item, _ in streams.select(0.2):
                block = os.read(item.fileobj.fileno(), 65536)
                if not block:
                    streams.unregister(item.fileobj)
                    continue
                total += len(block)
                if total > CAP:
                    stopped = 'output_limit'
                    break
                hashes[item.data].update(block)
                data[item.data].extend(block)
            if stopped:
                break
        if stopped:
            os.killpg(process.pid, signal.SIGKILL)
        try:
            code = process.wait(timeout=max(1, timeout - (time.monotonic() - started)))
        except subprocess.TimeoutExpired:
            stopped = 'watchdog'
            os.killpg(process.pid, signal.SIGKILL)
            code = process.wait(timeout=30)
    except BaseException:
        if process.poll() is None:
            os.killpg(process.pid, signal.SIGKILL)
        process.wait(timeout=30)
        raise
    finally:
        streams.close()
        process.stdout.close()
        if process.stderr is not None:
            process.stderr.close()
    facts = {'exit_code': code, 'seconds': time.monotonic() - started,
             'watchdog': stopped == 'watchdog', 'output_limit': stopped == 'output_limit',
             'capture_complete': stopped is None, 'raw_output_persisted': False,
             'stdout_bytes': len(data['stdout']), 'stderr_bytes': len(data['stderr']),
             'stdout_sha256': hashes['stdout'].hexdigest(), 'stderr_sha256': hashes['stderr'].hexdigest()}
    return facts, bytes(data['stdout']), bytes(data['stderr'])


def tree(commit):
    result = {}
    for row in git('ls-tree', '-rz', commit).split(b'\0'):
        if not row:
            continue
        info, name = row.split(b'\t', 1)
        mode, kind, oid = info.decode().split()
        path = os.fsdecode(name)
        require(kind == 'blob' and mode in ('100644', '100755', '120000')
                and not Path(path).is_absolute() and '..' not in Path(path).parts, 'tree_schema')
        result[path] = (mode, oid)
    return result


def physical(names):
    result = {}
    for name in sorted(names):
        path = Path(name)
        for parent in path.parents:
            if parent == Path('.'):
                break
            require(not parent.is_symlink(), 'symlink_parent')
        info = path.lstat()
        if stat.S_ISLNK(info.st_mode):
            mode, data = '120000', os.fsencode(os.readlink(path))
        else:
            require(stat.S_ISREG(info.st_mode), 'physical_regular')
            descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
            try:
                before = os.fstat(descriptor)
                with os.fdopen(descriptor, 'rb', closefd=False) as stream:
                    data = stream.read()
                after = os.fstat(descriptor)
                require((before.st_ino, before.st_size, before.st_mtime_ns, before.st_mode)
                        == (after.st_ino, after.st_size, after.st_mtime_ns, after.st_mode), 'read_changed')
            finally:
                os.close(descriptor)
            mode = '100755' if info.st_mode & 0o111 else '100644'
        oid = hashlib.sha1(b'blob ' + str(len(data)).encode() + b'\0' + data).hexdigest()
        result[name] = (mode, oid, sha(data))
    return result


def manifest(values):
    return sha(json.dumps(values, sort_keys=True, separators=(',', ':')).encode())


def inverse(data):
    text = data.decode()
    require(text.count(ANCHOR) == 1, 'one_terminal_guard')
    changed = text.replace(ANCHOR, ANCHOR.replace('if !entry.recipient', 'if false && !entry.recipient', 1), 1).encode()
    require(changed != data and changed.replace(b'if false && !entry.recipient', b'if !entry.recipient', 1) == data,
            'only_guard_disable')
    return changed


def location():
    text = Path(FIXTURE).read_text()
    require(text.count(MESSAGE) == 1, 'unique_own_assert')
    label = text.index(MESSAGE)
    start = text.rfind('assert!(', max(0, label - 1200), label)
    require(start >= 0 and 'ordinary_facts.into_iter().all(|value| value)' in text[start:label], 'own_assert_condition')
    return text.count('\n', 0, start) + 1


def compiler(raw):
    # Direct binary execution has no Cargo/nextest wrapper: do not exclude errors.
    return {'compiler_error_count': len(re.findall(r'(?m)^error(?:\[E[0-9]{4}\])?:', raw)),
            'compiler_codes': sorted(set(re.findall(r'\berror\[(E[0-9]{4})\]', raw)))}


def decode_marker(line, namespace):
    keys = NS[namespace]
    tokens = line.split(' ')
    require(tokens[0] == namespace and len(tokens) == len(keys) + 1, 'closed_marker_arity')
    row = {}
    for token, key in zip(tokens[1:], keys):
        require(token.startswith(key + '='), 'closed_marker_keys')
        value = token[len(key) + 1:]
        if key == 'mode':
            require(value in ('public-cancel', 'injected-validation'), 'closed_mode')
            row[key] = value
        elif key in BOOLS:
            require(value in ('true', 'false'), 'closed_bool')
            row[key] = value == 'true'
        else:
            require(re.fullmatch(r'(?:0|[1-9][0-9]{0,8})', value) is not None, 'closed_count')
            row[key] = int(value)
    return row


def parse(raw, name, exit_code):
    text = re.sub(r'\x1b\[[0-9;]*m', '', raw.decode('utf-8', errors='replace'))
    row = {'name': name, 'exit_code': exit_code, **compiler(text)}
    summaries = re.findall(r'(?m)^test result: (ok|FAILED)\. ([0-9]+) passed; ([0-9]+) failed; ([0-9]+) ignored;[^\n]*$', text)
    if len(summaries) == 1:
        status, passed, failed, ignored = summaries[0]
        row.update(passed=int(passed), failed=int(failed), ignored=int(ignored), summary_status=status)
    row['selected_names_exact'] = re.findall(r'(?m)^test ([A-Za-z0-9_:]+) \.\.\. ', text) == [name]
    row['running_one'] = re.findall(r'(?m)^running ([0-9]+) tests?$', text) == ['1']
    row['panic_count'] = len(re.findall('panicked at', text))
    panic_pattern = r"(?m)^thread '([^'\n]{1,512})'(?: \([0-9]{1,12}\))? panicked at ([^\n:]{1,300}):([0-9]{1,7}):([0-9]{1,7}):\n([^\n]{0,1024})$"
    panics = list(re.finditer(panic_pattern, text))
    row['own_assertion'] = (row['panic_count'] == len(panics) == 1
        and panics[0][1] == name and panics[0][2] == FIXTURE
        and int(panics[0][3]) == location() and panics[0][5] == MESSAGE)
    row['own_source_line'] = location()
    row['unknown_panic_count'] = row['panic_count'] - (1 if row['own_assertion'] else 0)
    markers = {}
    marker_end = 0
    try:
        for namespace in NS:
            rows = []
            for match in re.finditer(r'(?m)^.*' + re.escape(namespace) + r'.*$', text):
                line = match[0]
                prefix = 'test ' + name + ' ... '
                if line.startswith(prefix):
                    line = line[len(prefix):]
                require(line.startswith(namespace + ' '), 'marker_envelope')
                rows.append(decode_marker(line, namespace))
                marker_end = max(marker_end, match.end())
            require(len(rows) <= 1, 'duplicate_marker')
            if rows:
                markers[namespace] = rows[0]
        row['markers'] = markers
        row['marker_schema_complete'] = True
        row['markers_before_own_assertion'] = row['own_assertion'] and marker_end < panics[0].start()
    except Rejected:
        row['marker_schema_complete'] = False
    try:
        diagnostic_lines = [line for line in text.splitlines() if DIAGNOSTIC_NS in line]
        require(len(diagnostic_lines) <= 1, 'diagnostic_duplicate_line')
        if diagnostic_lines:
            line = diagnostic_lines[0]
            prefix = 'test ' + name + ' ... '
            if line.startswith(prefix):
                line = line[len(prefix):]
            row['frozen_diagnostic'] = decode_diagnostic(line)
        row['diagnostic_schema_complete'] = True
    except (Rejected, ValueError, TypeError):
        row['diagnostic_schema_complete'] = False
    return row


def common(row, red=False):
    return (row.get('capture_complete') is True and not row.get('watchdog') and not row.get('output_limit')
        and row.get('passed') == (0 if red else 1) and row.get('failed') == (1 if red else 0)
        and row.get('ignored') == 0 and row.get('compiler_error_count') == 0
        and row.get('exit_code') == (101 if red else 0) and row.get('running_one') is True
        and row.get('selected_names_exact') is True and row.get('marker_schema_complete') is True
        and row.get('panic_count') == (1 if red else 0)
        and row.get('summary_status') == ('FAILED' if red else 'ok'))


def oracle(row, red=False):
    if not common(row, red):
        return False
    ordinary = row['name'] == CASES[2]
    injected = row['name'] == CASES[1]
    if red and (not ordinary or not row.get('own_assertion') or not row.get('markers_before_own_assertion')):
        return False
    markers = row['markers']
    expected = {'late-peer-negative'} | (set() if injected else {'late-peer-public-cancel-sample'}) | ({'late-peer-ordinary-progress'} if ordinary else set())
    if set(markers) != expected:
        return False
    old = markers['late-peer-negative']
    if old['mode'] != ('injected-validation' if injected else 'public-cancel'):
        return False
    if not all(old[key] == (False if red and key == 'no_replay' else True) for key in FIELDS):
        return False
    if not (old['runtime_closes'] == old['planes_shutdown'] == 3 and old['relay_closed'] and old['attempt_completed']):
        return False
    if not injected and not all(markers['late-peer-public-cancel-sample'].values()):
        return False
    if injected:
        return (old['accepted'] == old['open_attempts'] == 1 and old['validation_rejections'] > 0
                and old['own_publications'] == old['routed_after_cancel'] == old['closed_denials'] == 0)
    if any(old[key] != 0 for key in COUNTS[:4]):
        return False
    if not (old['routed_after_cancel'] == old['closed_denials'] and old['closed_denials'] >= (2 if red else 1)):
        return False
    if not red and old['closed_denials'] != 1:
        return False
    if not ordinary:
        return True
    obs = markers['late-peer-ordinary-progress']
    # The inverse proves repeated terminal retries, not necessarily blocked
    # ordinary projection. Retain its observed projection boolean either way;
    # all original custody/authority/cleanup evidence remains mandatory.
    return (all(obs[key] is True for key in ORDINARY if key != 'ordinary_projected')
        and (red or obs['ordinary_projected'] is True)
        and obs['no_replay'] == obs['original_facts_complete'] == (not red)
        and all(obs[key] == old[key] for key in COUNTS + ['relay_closed', 'attempt_completed'])
        and obs['independent_closed'] and obs['independent_plane_shutdown'])


def metadata_controls():
    positive = negative = 0
    def synthetic(name, red=False):
        injected = name == CASES[1]
        old = dict.fromkeys(FIELDS, True)
        old.update(mode='injected-validation' if injected else 'public-cancel',
                   accepted=int(injected), validation_rejections=int(injected), own_publications=0,
                   open_attempts=int(injected), routed_after_cancel=0 if injected else (3 if red else 1),
                   closed_denials=0 if injected else (3 if red else 1), runtime_closes=3, planes_shutdown=3,
                   relay_closed=True, attempt_completed=True)
        if red:
            old['no_replay'] = False
        values = {'late-peer-negative': old}
        if not injected:
            values['late-peer-public-cancel-sample'] = dict.fromkeys(SAMPLE, True)
        if name == CASES[2]:
            obs = dict.fromkeys(ORDINARY, True)
            obs.update({key: old[key] for key in COUNTS + ['relay_closed', 'attempt_completed']})
            obs.update(no_replay=not red, original_facts_complete=not red, independent_closed=True, independent_plane_shutdown=True)
            obs['ordinary_projected'] = not red
            values['late-peer-ordinary-progress'] = obs
        def value(item):
            return str(item).lower() if type(item) is bool else str(item)
        lines = [namespace + ' ' + ' '.join(key + '=' + value(row[key]) for key in NS[namespace]) for namespace, row in values.items()]
        out = 'running 1 test\ntest ' + name + ' ... \n' + '\n'.join(lines) + '\n'
        if red:
            out += "thread '" + name + "' (123) panicked at " + FIXTURE + ':' + str(location()) + ':9:\n' + MESSAGE + '\n'
        return (out + ('test result: FAILED. 0 passed; 1 failed; 0 ignored;\n' if red else 'test result: ok. 1 passed; 0 failed; 0 ignored;\n')).encode()
    def decode(raw, name, red=False):
        row = parse(raw, name, 101 if red else 0)
        row['capture_complete'] = True
        return oracle(row, red)
    for name in CASES:
        good = synthetic(name)
        require(decode(good, name), 'metadata_green')
        positive += 1
        variants = [good.replace(b'1 passed', b'0 passed'), good.replace(b'0 ignored', b'1 ignored'),
                    good.replace(name.encode(), b'foreign::PRIVATE'), good + b'error[E0308]: PRIVATE\n',
                    good + b'late-peer-negative PRIVATE\n', good + b'late-peer-public-cancel-samplePRIVATE\n',
                    good.replace(b'runtime_closes=3', b'runtime_closes=2'),
                    good.replace(b'planes_shutdown=3', b'planes_shutdown=2'),
                    good.replace(b'accepted=' + (b'1' if name == CASES[1] else b'0'), b'accepted=2'),
                    good.replace(b'own_publications=0', b'own_publications=1'),
                    good.replace(b'late-peer-negative mode=', b'late-peer-negative	mode='),
                    good + next(line for line in good.splitlines() if line.startswith(b'late-peer-negative ')) + b'\n',
                    b'\n'.join(line for line in good.splitlines() if b'late-peer-negative ' not in line)]
        variants += [good.replace((key + '=true').encode(), (key + '=false').encode()) for key in FIELDS + SAMPLE if (key + '=true').encode() in good]
        if name == CASES[2]:
            variants += [good.replace((key + '=true').encode(), (key + '=false').encode()) for key in ORDINARY + ['independent_closed', 'independent_plane_shutdown', 'original_facts_complete']]
        for value in variants:
            require(not decode(value, name), 'metadata_reject_green')
            negative += 1
    red = synthetic(CASES[2], True)
    require(decode(red, CASES[2], True), 'metadata_red')
    positive += 1
    require(decode(red.replace(b'ordinary_projected=false', b'ordinary_projected=true'), CASES[2], True),
            'metadata_terminal_retries_with_ordinary_projection')
    positive += 1
    require(decode(red.replace(b' (123)', b''), CASES[2], True), 'metadata_thread_without_id')
    positive += 1
    variants = [red.replace(MESSAGE.encode(), b'PRIVATE'), red.replace(FIXTURE.encode(), b'crates/PRIVATE.rs'),
                red.replace((':' + str(location()) + ':9').encode(), b':1:9'),
                red.replace(b' (123)', b' (PRIVATE)'),
                red.replace(b'ordinary_projected=false', b'ordinary_projected=unknown'),
                red.replace(b'closed_denials=3', b'closed_denials=1'),
                red.replace(b'no_replay=false', b'no_replay=true'), red.replace(b'0 passed; 1 failed', b'1 passed; 0 failed'),
                red + b"thread 'PRIVATE' panicked at crates/PRIVATE.rs:1:1:\nPRIVATE\n",
                red + b'late-peer-ordinary-progressPRIVATE\n', red + b'error: PRIVATE\n']
    variants += [red.replace((key + '=true').encode(), (key + '=false').encode()) for key in ORDINARY if key != 'ordinary_projected']
    for value in variants:
        require(not decode(value, CASES[2], True), 'metadata_reject_red')
        negative += 1
    original = Path(PRODUCT).read_bytes()
    changed = inverse(original)
    require(changed != original, 'metadata_inverse_changes')
    positive += 1
    for value in (original.replace(ANCHOR.encode(), b''), original + ANCHOR.encode()):
        try:
            inverse(value)
        except Rejected:
            negative += 1
        else:
            raise Rejected('metadata_inverse_failclosed')
    # Unknown payloads are absent from serialized closed decoder output.
    private = parse(red.replace(MESSAGE.encode(), b'PRIVATE_PAYLOAD_SENTINEL'), CASES[2], 101)
    require('PRIVATE_PAYLOAD_SENTINEL' not in json.dumps(private), 'metadata_privacy')
    positive += 1
    diagnostic = {key: True for key in DIAGNOSTIC_BOOLS}
    diagnostic.update({key: 0 for key in DIAGNOSTIC_COUNTS})
    diagnostic.update({key: [False if kind is bool else 0] * size for key, (size, kind) in DIAGNOSTIC_ARRAYS.items()})
    line = DIAGNOSTIC_NS + ' ' + json.dumps(diagnostic, separators=(',', ':'))
    require(decode_diagnostic(line) == diagnostic, 'metadata_diagnostic_positive')
    positive += 1
    bad = [line.replace('"collected":true', '"collected":1'), line.replace('"dequeued":0', '"dequeued":true'),
           line.replace('"dequeued":0', '"dequeued":-1'), line.replace('"raw_matches":[false,false,false,false,false,false]', '"raw_matches":[false]'),
           line.replace('"collected":true', '"collected":true,"collected":true'),
           line.replace('{', '{"PRIVATE":"PRIVATE",', 1), 'PRIVATE ' + line]
    for value in bad:
        try:
            decode_diagnostic(value)
        except (Rejected, ValueError, TypeError):
            negative += 1
        else:
            raise Rejected('metadata_diagnostic_negative')
    diagnostic_raw = synthetic(CASES[2]) + line.encode() + b'\n'
    require(parse(diagnostic_raw, CASES[2], 0).get('diagnostic_schema_complete') is True, 'metadata_diagnostic_parse')
    positive += 1
    for value in (diagnostic_raw + line.encode() + b'\n', diagnostic_raw + b' PRIVATE late-peer-ordinary-frozen PRIVATE\n'):
        require(parse(value, CASES[2], 0).get('diagnostic_schema_complete') is False, 'metadata_diagnostic_duplicate_or_prefixed')
        negative += 1
    return {'passed': True, 'positive': positive, 'negative': negative, 'actual_rust_bodies': 0}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source', required=True)
    parser.add_argument('--baseline', required=True)
    parser.add_argument('--mode', choices=['preflight', 'pfp', 'ordinary-diagnostic'], required=True)
    parser.add_argument('--output', required=True)
    args = parser.parse_args()
    os.umask(0o077)
    report = {'schema': 1, 'mode': args.mode, 'source': args.source, 'product_baseline': args.baseline,
              'qualification_passed': False, 'metadata_passed': False, 'mutation_attempted': False, 'phases': {}, 'actual_rust_bodies': 0, 'runtime_invocations': 0,
              'raw_output_persisted': False, 'scope': 'terminal-negative-only; not full sync or upstream merge qualification'}
    output = Path(args.output)
    output.parent.mkdir(parents=True, exist_ok=True)
    def save():
        temporary = output.with_name(output.name + '.tmp')
        temporary.write_text(json.dumps(report, indent=2, sort_keys=True) + '\n')
        temporary.replace(output)
    original = None
    frozen = None
    current_tree = None
    index = None
    def pristine(expected):
        return (git('rev-parse', 'HEAD').decode().strip() == args.source
                and git('ls-files', '--stage', '-z') == index
                and physical(current_tree) == expected)
    def compile_phase(label, names, expected):
        require(pristine(expected), 'compile_input_closure')
        expression = ' | '.join('test(=' + name + ')' for name in names)
        command = ['cargo', 'nextest', 'list', '--locked', '--lib', '-p', 'marmot-app', '--features', FEATURES,
                   '-E', expression, '--message-format', 'json']
        row = {'command': command, 'requested_features': FEATURES, 'bodies': [], 'qualified': False}
        report['phases'][label] = row
        save()
        facts, stdout, stderr = capture(command, 1800)
        row['compilation'] = dict(facts, **compiler(stderr.decode('utf-8', errors='replace')))
        save()
        require(facts['capture_complete'] and facts['exit_code'] == 0
                and row['compilation']['compiler_error_count'] == 0 and pristine(expected), 'compilation_failed')
        inventory = json.loads(stdout)
        suites = inventory['rust-suites']
        matches = [(name, case, suite) for suite in suites.values() for name, case in suite['testcases'].items()
                   if case.get('filter-match', {}).get('status') == 'matches']
        require(len(matches) == len(names) and {name for name, _, _ in matches} == set(names)
                and all(case.get('ignored') is False for _, case, _ in matches), 'exact_nonignored_inventory')
        binaries = {suite['binary-path'] for _, _, suite in matches}
        require(len(binaries) == 1, 'single_app_binary')
        binary = Path(binaries.pop())
        require(binary.is_file() and not binary.is_symlink(), 'compiled_binary')
        fingerprints = feature_metadata(binary)
        row['compiled_fingerprints'] = fingerprints
        require(fingerprints.get('verified') is True, 'compiled_feature_graph')
        require({'otlp-export', 'product-analytics-export', 'test-policy-overrides', 'experimental-device-sync'}
                <= set(fingerprints['nodes']['marmot_app']['features']), 'actual_app_features')
        require({'test-crash-hooks', 'test-policy-overrides', 'experimental-device-sync'}
                <= set(fingerprints['nodes']['cgka_engine']['features']), 'actual_core_hooks')
        cohort = {key: {field: value[field] for field in ('features', 'profile', 'compile_kind', 'rustflags')}
                  for key, value in fingerprints['nodes'].items()}
        if 'compiled_cohort' not in report:
            report['compiled_cohort'] = cohort
        require(report['compiled_cohort'] == cohort, 'same_compiled_feature_profile')
        row['inventory'] = [{'name': name, 'ignored': False} for name in names]
        row['binary_sha256'] = fingerprints['root_binary_sha256']
        save()
        for name in names:
            require(pristine(expected) and sha(binary.read_bytes()) == row['binary_sha256'], 'body_input_closure')
            body = {'name': name, 'qualified': False}
            row['bodies'].append(body)
            save()
            facts, raw, _ = capture([str(binary), '--exact', name, '--nocapture', '--test-threads=1'], 300, merged=True)
            body.update(facts)
            report['runtime_invocations'] += 1
            save()  # Keep actual exit/time/hash even when the closed grammar rejects output.
            body.update(parse(raw, name, facts['exit_code']))
            if all(type(body.get(key)) is int for key in ('passed', 'failed', 'ignored')):
                report['actual_rust_bodies'] += body['passed'] + body['failed']
            body['qualified'] = oracle(body, label == 'inverse')
            if label == 'inverse' and body['qualified']:
                body['oracle_mutation_class'] = 'repeated_closed_terminal_retries'
            body['source_closure'] = pristine(expected)
            body['binary_unchanged'] = sha(binary.read_bytes()) == row['binary_sha256']
            save()
        row['qualified'] = all(body['qualified'] and body['source_closure'] and body['binary_unchanged'] for body in row['bodies'])
        save()
        return row['qualified']
    save()
    try:
        require(os.environ.get('GITHUB_ACTIONS') == 'true' and os.environ.get('GITHUB_REPOSITORY') == 'dyKiU/mdk'
                and os.environ.get('GITHUB_EVENT_NAME') == 'workflow_dispatch'
                and os.environ.get('GITHUB_REF_NAME', '').startswith('ci/upstream-develop-dy-')
                and os.environ.get('GITHUB_REF') == 'refs/heads/' + os.environ['GITHUB_REF_NAME'], 'manual_owned_remote')
        event = json.loads(Path(os.environ['GITHUB_EVENT_PATH']).read_text())
        require(event.get('inputs', {}).get('case') in (('cancel-terminal-pfp', 'cancel-terminal-ordinary-diagnostic') if args.mode == 'preflight' else (('cancel-terminal-ordinary-diagnostic',) if args.mode == 'ordinary-diagnostic' else ('cancel-terminal-pfp',)))
                and event['inputs'].get('extraction_cohort_baseline') == args.baseline, 'explicit_case_baseline')
        require(re.fullmatch('[0-9a-f]{40}', args.source) and re.fullmatch('[0-9a-f]{40}', args.baseline)
                and args.source == os.environ.get('GITHUB_SHA') == git('rev-parse', 'HEAD').decode().strip(), 'source_identity')
        require(subprocess.run(['git', 'merge-base', '--is-ancestor', MINIMUM, args.baseline]).returncode == 0
                and subprocess.run(['git', 'merge-base', '--is-ancestor', args.baseline, args.source]).returncode == 0, 'reviewed_baseline_ancestry')
        current_tree, base_tree = tree(args.source), tree(args.baseline)
        difference = {name for name in set(current_tree) | set(base_tree) if current_tree.get(name) != base_tree.get(name)}
        require(difference <= {SELF, WORKFLOW} and SELF in current_tree and WORKFLOW in current_tree, 'only_two_metadata_overlays')
        frozen = physical(current_tree)
        require(all(frozen[name][:2] == value for name, value in current_tree.items()), 'tracked_physical_modes_content')
        index = git('ls-files', '--stage', '-z')
        require(subprocess.run(['git', '-c', 'core.filemode=true', 'diff', '--quiet', '--cached', 'HEAD']).returncode == 0,
                'index_matches_head')
        require(pristine(frozen), 'initial_closure')
        for key, expected in {'CARGO_INCREMENTAL': '1', 'CARGO_BUILD_JOBS': '2', 'RUST_MIN_STACK': '4194304',
                              'CARGO_PROFILE_DEV_DEBUG': '0', 'CARGO_PROFILE_TEST_DEBUG': '0'}.items():
            require(os.environ.get(key) == expected, 'fixed_build_environment')
        for key in ('RUSTFLAGS', 'CARGO_ENCODED_RUSTFLAGS', 'RUSTC_BOOTSTRAP', 'CARGO_PROFILE_DEV_OPT_LEVEL', 'CARGO_PROFILE_TEST_OPT_LEVEL'):
            require(not os.environ.get(key), 'no_compiler_override')
        require(FEATURES == EXPECTED_FEATURES, 'same_six_declared_features')
        original = Path(PRODUCT).read_bytes()
        inverse(original)
        report['source_preflight'] = {'passed': True, 'source': args.source, 'product_baseline': args.baseline,
            'minimum_repair_ancestor': MINIMUM, 'tree': git('rev-parse', 'HEAD^{tree}').decode().strip(),
            'tracked_manifest_sha256': manifest(frozen), 'index_stage_sha256': sha(index),
            'fixture_sha256': frozen[FIXTURE][2], 'product_sha256': frozen[PRODUCT][2],
            'overlay_names': sorted(difference), 'tracked_file_count': len(frozen), 'source_assert_line': location(),
            'original_tests_unchanged_from_explicit_baseline': True}
        report['metadata_controls'] = metadata_controls()
        report['metadata_passed'] = True
        save()
        if args.mode in ('pfp', 'ordinary-diagnostic'):
            version_facts, version, _ = capture(['cargo', 'nextest', '--version'], 60)
            require(version_facts['capture_complete'] and version_facts['exit_code'] == 0
                    and re.match(rb'^cargo-nextest 0\.9\.132(?:\s|$)', version), 'pinned_nextest')
            rust_facts, rust, _ = capture(['rustc', '--version'], 60)
            require(rust_facts['capture_complete'] and rust_facts['exit_code'] == 0
                    and re.fullmatch(rb'rustc [A-Za-z0-9 .()_-]{1,150}\n?', rust), 'source_toolchain_version')
            report['execution'] = {'nextest_version': '0.9.132', 'rustc': rust.decode().strip(),
                'test_threads': 1, 'automatic_retries': 0, 'features': FEATURES,
                'stack_bytes': 4194304, 'cargo_build_jobs': 2, 'incremental': 1,
                'dev_debug': 0, 'test_debug': 0, 'compile_watchdog_seconds': 1800, 'body_watchdog_seconds': 300}
            if args.mode == 'ordinary-diagnostic':
                compile_phase('ordinary-diagnostic', [CASES[2]], frozen)
            else:
                baseline_ok = compile_phase('baseline', CASES, frozen)
                require(baseline_ok, 'baseline_not_green')
                changed = inverse(original)
                Path(PRODUCT).write_bytes(changed)
                report['mutation_attempted'] = True
                save()
                expected = physical(current_tree)
                require({name for name in frozen if frozen[name] != expected[name]} == {PRODUCT}
                        and expected[PRODUCT][0] == frozen[PRODUCT][0], 'sole_mutant_source_mode')
                compile_phase('inverse', [CASES[2]], expected)
    except Exception as error:
        report['exception_type'] = type(error).__name__
        report['failure_reason'] = error.args[0] if type(error) is Rejected else 'unknown'
    finally:
        if original is not None and frozen is not None:
            try:
                if Path(PRODUCT).read_bytes() != original:
                    Path(PRODUCT).write_bytes(original)
                report['restored_before_controls'] = pristine(frozen)
                save()
                if (args.mode == 'pfp' and report['mutation_attempted']
                        and report['phases'].get('baseline', {}).get('qualified') is True
                        and report['restored_before_controls']):
                    try:
                        compile_phase('restored', CASES, frozen)
                    except Exception as error:
                        report['restore_exception_type'] = type(error).__name__
                report['final_closure'] = {'head_exact': git('rev-parse', 'HEAD').decode().strip() == args.source,
                    'index_stage_exact': git('ls-files', '--stage', '-z') == index,
                    'all_tracked_content_modes_exact': physical(current_tree) == frozen,
                    'tracked_manifest_sha256': manifest(physical(current_tree)),
                    'untracked_absence_measured': False, 'fds_held_across_execution': False}
            except Exception as error:
                report['closure_exception_type'] = type(error).__name__
        closure = report.get('final_closure', {})
        complete = all(closure.get(key) is True for key in ('head_exact', 'index_stage_exact', 'all_tracked_content_modes_exact'))
        report['qualification_passed'] = (args.mode == 'pfp' and report['metadata_passed'] and complete
            and 'exception_type' not in report and 'restore_exception_type' not in report
            and report['actual_rust_bodies'] == report['runtime_invocations'] == 7
            and set(report['phases']) == {'baseline', 'inverse', 'restored'}
            and all(row.get('qualified') is True for row in report['phases'].values()))
        diagnostic = report['phases'].get('ordinary-diagnostic', {})
        bodies = diagnostic.get('bodies', [])
        report['diagnostic_complete'] = (args.mode == 'ordinary-diagnostic' and complete
            and report['metadata_passed'] and not report['mutation_attempted']
            and 'exception_type' not in report and report['actual_rust_bodies'] == report['runtime_invocations'] == 1
            and len(bodies) == 1 and bodies[0].get('source_closure') is True
            and bodies[0].get('binary_unchanged') is True and bodies[0].get('capture_complete') is True
            and bodies[0].get('marker_schema_complete') is True
            and set(bodies[0].get('markers', {})) == set(NS)
            and bodies[0].get('diagnostic_schema_complete') is True
            and bodies[0].get('frozen_diagnostic', {}).get('collected') is True
            and bodies[0].get('compiler_error_count') == 0 and bodies[0].get('ignored') == 0
            and bodies[0].get('running_one') is True and bodies[0].get('selected_names_exact') is True
            and ((bodies[0].get('passed') == 1 and bodies[0].get('failed') == 0 and bodies[0].get('exit_code') == 0
                  and bodies[0].get('panic_count') == 0)
                 or (bodies[0].get('passed') == 0 and bodies[0].get('failed') == 1 and bodies[0].get('exit_code') == 101
                     and bodies[0].get('own_assertion') is True)))
        report['diagnostic_body_passed'] = bool(report['diagnostic_complete'] and bodies[0].get('qualified') is True)
        report['preflight_passed'] = args.mode == 'preflight' and report['metadata_passed'] and complete and 'exception_type' not in report
        save()
    return 0 if report['qualification_passed'] or report['preflight_passed'] or report['diagnostic_body_passed'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
