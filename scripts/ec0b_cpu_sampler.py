#!/usr/bin/env python3
"""Hosted-only IP sampler. No files for perf streams, symbols, or target output."""
import os
import json
from pathlib import Path
import re
import resource
import selectors
import select
import signal
import stat
import subprocess
import sys
import time

FREQUENCY = 49
MAX_PERF_BYTES = 64 * 1024 * 1024
MAX_SYMBOL_BYTES = 8 * 1024 * 1024
MAX_TARGET_BYTES = 8 * 1024 * 1024
MAX_STDERR_BYTES = 64 * 1024
MAX_SYMBOL_LINE = 8192
MAX_PIPE_PENDING = 65536
CATEGORIES = (
    'app_account_worker', 'app_sibling_sharing', 'app_other', 'core_engine',
    'core_session', 'storage', 'transport', 'openmls', 'crypto',
    'tokio', 'allocator', 'unknown',
)
# Fixed crate/function prefixes, never arbitrary output names. Order is significant.
PREFIXES = (
    ('marmot_app::runtime::account_worker::', 'app_account_worker'),
    ('marmot_app::client::device_linking::sibling_sharing::', 'app_sibling_sharing'),
    ('marmot_app::', 'app_other'), ('cgka_engine::', 'core_engine'),
    ('cgka_session::', 'core_session'), ('storage_sqlite::', 'storage'),
    ('rusqlite::', 'storage'), ('transport_nostr::', 'transport'),
    ('openmls::', 'openmls'), ('openmls_memory_storage::', 'openmls'),
    ('hpke::', 'crypto'), ('chacha20poly1305::', 'crypto'),
    ('aes_gcm::', 'crypto'), ('curve25519_dalek::', 'crypto'),
    ('ed25519_dalek::', 'crypto'), ('sha2::', 'crypto'),
    ('tokio::', 'tokio'), ('tokio_util::', 'tokio'),
)
ALLOCATOR = {'malloc', 'free', 'calloc', 'realloc', '__rust_alloc', '__rust_dealloc',
             '__rust_realloc', '__rust_alloc_zeroed'}


class SamplerFailure(Exception):
    pass


class IntervalExpired(Exception):
    pass


def no_core_dumps():
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))


def require(value):
    if not value:
        raise SamplerFailure()


class Reducer:
    def __init__(self, cap=MAX_SYMBOL_BYTES, timed=False):
        self.cap = cap
        self.bytes = 0
        self.pending = bytearray()
        self.counts = dict.fromkeys(CATEGORIES, 0)
        self.samples = 0
        self.timed = timed
        self.origin_ns = None
        self.bins = {}
        self.current_bin = None

    def feed(self, chunk):
        self.bytes += len(chunk)
        require(self.bytes <= self.cap)
        for part in chunk.splitlines(keepends=True):
            self.pending.extend(part)
            require(len(self.pending) <= MAX_SYMBOL_LINE)
            if self.pending.endswith(b'\n'):
                self.line(bytes(self.pending[:-1]))
                self.pending.clear()

    def line(self, raw):
        # No addresses, frames, command names, IDs, arguments, or symbols escape.
        # Blank output is not a sample. Unrecognized/mangled symbols are unknown.
        raw = raw.strip()
        if not raw:
            return
        if self.timed:
            match = re.fullmatch(rb'([0-9]{1,12})\.([0-9]{1,9}):\s+(.+)', raw)
            require(match is not None)
            stamp = int(match[1]) * 1_000_000_000 + int(match[2].ljust(9, b'0'))
            if self.origin_ns is None: self.origin_ns = stamp
            require(0 <= stamp - self.origin_ns <= 900 * 1_000_000_000)
            self.current_bin = (stamp - self.origin_ns) // 1_000_000_000
            self.bins.setdefault(self.current_bin, dict.fromkeys(CATEGORIES, 0))
            raw = match[3]
        self.samples += 1
        require(self.samples <= 10_000_000)
        try:
            name = raw.decode('ascii')
        except UnicodeDecodeError:
            self.counts['unknown'] += 1
            if self.timed: self.bins[self.current_bin]['unknown'] += 1
            return
        name = re.sub(r'\+0x[0-9a-fA-F]+$', '', name)
        category = 'unknown'
        if name in ALLOCATOR:
            category = 'allocator'
        elif re.fullmatch(r'[A-Za-z0-9_:<> ,&;\[\]().$#{}!*/=+~-]+', name):
            for prefix, fixed in PREFIXES:
                if name.startswith(prefix):
                    category = fixed
                    break
        self.counts[category] += 1
        if self.timed: self.bins[self.current_bin][category] += 1

    def finish(self):
        # A partial line is discarded and disqualifies complete reduction.
        require(not self.pending)
        return {'categories': dict(self.counts), 'total_symbol_lines': self.samples,
                'unknown_symbol_lines': self.counts['unknown'],
                'symbol_bytes_seen': self.bytes, 'raw_symbols_exported': False,
                'per_thread_attribution': False,
                'one_second_bins': [[key, self.bins[key]] for key in sorted(self.bins)],
                'time_anchor': 'first_perf_sample' if self.timed else None,
                'fifth_choice_phase_alignment_known': False}


def kill_owned_group(process):
    if process is None:
        return
    # All children below are admitted with start_new_session=True; never kill a
    # caller's group or a PID learned from untrusted output.
    try:
        os.killpg(process.pid, signal.SIGKILL)
    except ProcessLookupError:
        pass
    try:
        process.wait(timeout=5)
    except subprocess.TimeoutExpired:
        raise SamplerFailure() from None


LAUNCHER_EXITS = {
    'invalid_arguments': 70, 'output_fd_unavailable': 71,
    'admission_fd_unavailable': 72, 'admission_read_failed': 73,
    'expected_parent_precheck_failed': 74, 'pdeathsig_arm_failed': 75,
    'expected_parent_postcheck_failed': 76, 'dup2_failed': 77,
    'exec_failed': 78, 'launcher_unknown': 79,
}


class LauncherFailure(SamplerFailure):
    def __init__(self, category):
        require(category in LAUNCHER_EXITS)
        self.category = category


def launch_require(value, category):
    if not value: raise LauncherFailure(category)


def harmless_launcher_failure(code):
    # Valid only for the fixed harmless Python probe, which exits0 after exec.
    # Never interpret an arbitrary product exit as a launcher category.
    category = next((name for name, value in LAUNCHER_EXITS.items() if type(code) is int and code == value), None)
    keys = ('output_fd_available', 'admission_fd_available', 'admission_read_valid',
            'expected_parent_precheck', 'pdeathsig_armed', 'expected_parent_postcheck',
            'dup2_succeeded', 'exec_succeeded')
    checks = dict.fromkeys(keys, None)
    boundary = {'output_fd_unavailable': 0, 'admission_fd_unavailable': 1,
                'admission_read_failed': 2, 'expected_parent_precheck_failed': 3,
                'pdeathsig_arm_failed': 4, 'expected_parent_postcheck_failed': 5,
                'dup2_failed': 6, 'exec_failed': 7}.get(category)
    if boundary is not None:
        for index, key in enumerate(keys):
            checks[key] = True if index < boundary else False if index == boundary else None
    return {'category': category, 'source_owned_harmless_exit': category is not None,
            'prior_point_checks_only': checks, 'product_exit_classified': False}


def signal_policy_flags(raw, code):
    if type(code) is not int or code != 0:
        return None
    headers = re.findall(r'^Signal[ \t]+Stop[ \t]+Print[ \t]+Pass to program[ \t]+Description[ \t]*$', raw, re.M)
    rows = re.findall(r'^SIGINT[ \t]+(Yes|No)[ \t]+(Yes|No)[ \t]+(Yes|No)[ \t]+Interrupt[ \t]*$', raw, re.M)
    all_signal_rows = re.findall(r'^SIG[A-Z0-9]+[ \t]+.*$', raw, re.M)
    if len(headers) != 1 or len(rows) != 1 or len(all_signal_rows) != 1:
        return None
    return [value == 'Yes' for value in rows[0]]


def gdb_signal_controls(real=False):
    header = 'Signal Stop Print Pass to program Description\n'
    old = header + 'SIGINT No No No Interrupt\n'
    new = header + 'SIGINT Yes Yes No Interrupt\n'
    if not real:
        positive = negative = 0
        require(signal_policy_flags(old, 0) == [False, False, False]); positive += 1
        require(signal_policy_flags(new, 0) == [True, True, False]); positive += 1
        for raw, code in [(old + old, 0), (new.replace('Yes', 'PRIVATE', 1), 0),
                          (new.replace('SIGINT', 'SIGTERM'), 0), (new[len(header):], 0),
                          (new.replace('Interrupt', 'PRIVATE'), 0), (new, 1), (new, True)]:
            require(signal_policy_flags(raw, code) is None); negative += 1
        require(harmless_launcher_failure(72)['prior_point_checks_only']['admission_fd_available'] is False); positive += 1
        require(harmless_launcher_failure(74)['prior_point_checks_only']['expected_parent_precheck'] is False); positive += 1
        for code in [1, 0, None, True]:
            require(harmless_launcher_failure(code)['category'] is None); negative += 1
        for missing_output, expected in [(True, 'output_fd_unavailable'), (False, 'admission_fd_unavailable')]:
            rd, wr = os.pipe()
            child = None
            try:
                child = subprocess.Popen([sys.executable, str(Path(__file__).absolute()), '--exec-target',
                    '999999' if missing_output else str(wr), '999998', sys.executable, '-c',
                    'print("must-not-execute")'], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                    stdin=subprocess.DEVNULL, pass_fds=(wr,), start_new_session=True)
                os.close(wr); wr = None
                require(child.wait(timeout=5) == LAUNCHER_EXITS[expected])
                require(select.select([rd], [], [], 5)[0] == [rd] and os.read(rd, 128) == b'')
                negative += 1
            finally:
                kill_owned_group(child)
                os.close(rd)
                if wr is not None: os.close(wr)
        return {'positive': positive, 'negative': negative, 'rust_bodies': 0,
                'real_gdb_commands': 0}
    import qualify_upstream_storage_boundary as bounded
    result = {'verified': False, 'rows': [], 'rust_bodies': 0,
              'product_red_claim': False, 'raw_output_export': False}
    for label, policy in [('old', 'stop noprint nopass'), ('corrected', 'stop print nopass')]:
        row = {'policy': label, 'exit': None, 'flags_stop_print_pass': None,
               'error_kind': None, 'elapsed_seconds': None}
        result['rows'].append(row)
        command = ['/usr/bin/gdb', '--quiet', '--nx', '--batch',
            '-ex', 'set pagination off', '-ex', 'set debuginfod enabled off',
            '-ex', 'python gdb.execute(' + repr('handle SIGINT ' + policy) + ', to_string=True)',
            '-ex', 'info signals SIGINT']
        started = time.monotonic()
        try:
            code, raw, _ = bounded.capture(command, 5, limit=65536)
            row['exit'] = code
            row['flags_stop_print_pass'] = signal_policy_flags(raw, code)
        except Exception as error:
            row['error_kind'] = setup_exception_kind(error)
        finally:
            row['elapsed_seconds'] = round(time.monotonic() - started, 3)
    result['old_expected_negative_observed'] = result['rows'][0]['flags_stop_print_pass'] == [False, False, False]
    result['corrected_expected_positive_observed'] = result['rows'][1]['flags_stop_print_pass'] == [True, True, False]
    result['verified'] = result['old_expected_negative_observed'] and result['corrected_expected_positive_observed']
    return result


def publish_parent_admission(process, admission):
    read_fd, write_fd = admission
    # Only the profiler inherits the read end. The controller supplies the exact
    # admitted profiler PID after Popen; it is not obtained from target output.
    try:
        payload = (str(process.pid) + '\n').encode('ascii')
        require(os.write(write_fd, payload) == len(payload))
    finally:
        os.close(read_fd)
        os.close(write_fd)


def admit_expected_parent(fd, *, parent=None, arm=None):
    parent = os.getppid if parent is None else parent
    if arm is None:
        def arm():
            import ctypes
            launch_require(ctypes.CDLL(None, use_errno=True).prctl(1, signal.SIGKILL, 0, 0, 0) == 0, 'pdeathsig_arm_failed')
    available = False
    try:
        try:
            os.fstat(fd)
            available = True
        except OSError:
            raise LauncherFailure('admission_fd_unavailable') from None
        try:
            ready = select.select([fd], [], [], 5)[0] == [fd]
            launch_require(ready, 'admission_read_failed')
            raw = os.read(fd, 32)
        except OSError:
            raise LauncherFailure('admission_read_failed') from None
        launch_require(re.fullmatch(rb'[1-9][0-9]{0,9}\n', raw) is not None, 'admission_read_failed')
        expected = int(raw)
        launch_require(parent() == expected, 'expected_parent_precheck_failed')
        try: arm()
        except Exception:
            raise LauncherFailure('pdeathsig_arm_failed') from None
        launch_require(parent() == expected, 'expected_parent_postcheck_failed')
    finally:
        if available:
            os.close(fd)


def exit_owned_parent_before_drain(process, request_exit):
    # Inferior has already reported a terminal state. GDB can still hold its
    # inherited target-output writer, so it must exit before target EOF is read.
    request_exit()
    require(process.wait(timeout=5) == 0)
    return True


def drain_target_after_parent_exit(fd, target):
    deadline = time.monotonic() + 5
    while time.monotonic() < deadline:
        if not select.select([fd], [], [], min(.1, max(0, deadline - time.monotonic())))[0]:
            continue
        try: chunk = os.read(fd, 65536)
        except BlockingIOError: continue
        if not chunk: return True
        require(len(target) + len(chunk) <= MAX_TARGET_BYTES)
        target.extend(chunk)
    raise SamplerFailure()


def pipeline(producer_argv, reducer_argv, target_fd, timeout, *, limits=None, timed=False, admission=None):
    """All raw streams remain in pipes/RAM. Return only closed stats + target RAM."""
    no_core_dumps()
    caps = {'perf': MAX_PERF_BYTES, 'symbols': MAX_SYMBOL_BYTES,
            'target': MAX_TARGET_BYTES, 'producer_err': MAX_STDERR_BYTES,
            'reducer_err': MAX_STDERR_BYTES}
    if limits is not None:
        require(set(limits) <= set(caps))
        for key, value in limits.items():
            require(type(value) is int and 0 < value <= caps[key])
            caps[key] = value
    started = time.monotonic()
    deadline = started + timeout
    target_read, target_write = target_fd
    producer = reducer = None
    selector = selectors.DefaultSelector()
    counts = dict.fromkeys(caps, 0)
    pending = bytearray()
    target = bytearray()
    symbols = Reducer(caps['symbols'], timed=timed)
    finite = {'completed': False, 'watchdog': False, 'output_limit': False,
              'internal_failure': False, 'producer_exit': None, 'reducer_exit': None,
              'cleanup_complete': False, 'owned_groups_stopped': False,
              'stderr_present': False, 'frequency_hz': FREQUENCY,
              'user_space_only': True, 'callchain_or_stack_capture': False,
              'raw_persistence': False, 'qualification_passed': False}
    try:
        reducer = subprocess.Popen(reducer_argv, stdin=subprocess.PIPE,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, start_new_session=True,
            env=dict(os.environ, PERF_CONFIG='/dev/null', DEBUGINFOD_URLS=''))
        producer = subprocess.Popen(producer_argv, stdout=subprocess.PIPE,
            stderr=subprocess.PIPE, pass_fds=(target_write,) + (() if admission is None else (admission[0],)), start_new_session=True,
            env=dict(os.environ, PERF_CONFIG='/dev/null', DEBUGINFOD_URLS=''))
        if admission is not None:
            owned_admission, admission = admission, None
            publish_parent_admission(producer, owned_admission)
        os.close(target_write)
        target_write = None
        streams = [(producer.stdout, 'perf'), (producer.stderr, 'producer_err'),
                   (reducer.stdout, 'symbols'), (reducer.stderr, 'reducer_err'),
                   (target_read, 'target')]
        for stream, role in streams:
            fd = stream if isinstance(stream, int) else stream.fileno()
            os.set_blocking(fd, False)
            selector.register(fd, selectors.EVENT_READ, role)
        write_fd = reducer.stdin.fileno()
        os.set_blocking(write_fd, False)
        producer_eof = False
        writer_registered = False
        writer_closed = False
        while selector.get_map() or producer.poll() is None or reducer.poll() is None:
            if time.monotonic() >= deadline:
                finite['watchdog'] = True
                raise SamplerFailure()
            if pending and not writer_registered:
                selector.register(write_fd, selectors.EVENT_WRITE, 'pump')
                writer_registered = True
            if not pending and writer_registered:
                selector.unregister(write_fd)
                writer_registered = False
            if producer_eof and not pending and not writer_closed:
                reducer.stdin.close()
                writer_closed = True
            for key, events in selector.select(min(.2, max(0, deadline - time.monotonic()))):
                role = key.data
                if role == 'pump':
                    try:
                        amount = os.write(write_fd, pending)
                    except BlockingIOError:
                        continue
                    require(amount > 0)
                    del pending[:amount]
                    # Re-enable producer reads only after bounded backlog drains.
                    if len(pending) < MAX_PIPE_PENDING and not producer_eof:
                        try:
                            selector.get_key(producer.stdout.fileno())
                        except KeyError:
                            selector.register(producer.stdout.fileno(), selectors.EVENT_READ, 'perf')
                    continue
                allowance = min(65536, MAX_PIPE_PENDING - len(pending)) if role == 'perf' else 65536
                if allowance <= 0:
                    continue
                try:
                    chunk = os.read(key.fd, allowance)
                except BlockingIOError:
                    continue
                if not chunk:
                    selector.unregister(key.fd)
                    if role == 'perf':
                        producer_eof = True
                    continue
                counts[role] += len(chunk)
                if counts[role] > caps[role]:
                    finite['output_limit'] = True
                    raise SamplerFailure()
                if role == 'perf':
                    pending.extend(chunk)
                    if len(pending) == MAX_PIPE_PENDING:
                        selector.unregister(key.fd)
                elif role == 'symbols':
                    symbols.feed(chunk)
                elif role == 'target':
                    target.extend(chunk)
                    if finite.get('failure_marker_capture_elapsed_ms') is None and b'panicked at crates/marmot-app/src/native_device_linking/tests/automatic_pairing_acceptance.rs:1785:9:' in target:
                        finite['failure_marker_capture_elapsed_ms'] = int((time.monotonic() - started) * 1000)
                else:
                    # Actual stderr is dropped immediately, not retained.
                    finite['stderr_present'] = True
        finite['producer_exit'] = producer.wait(timeout=5)
        finite['reducer_exit'] = reducer.wait(timeout=5)
        finite['reduction'] = symbols.finish()
        finite['completed'] = True
    except Exception:
        finite['internal_failure'] = not finite['watchdog'] and not finite['output_limit']
    finally:
        if finite['producer_exit'] is None and producer is not None:
            finite['producer_exit'] = producer.poll()  # Only an observed pre-cleanup exit.
        for process in (producer, reducer):
            kill_owned_group(process)
        if target_write is not None:
            os.close(target_write); target_write = None
        try:
            finite['target_eof_verified'] = drain_target_after_parent_exit(target_read, target)
        except Exception:
            finite['internal_failure'] = True
        finite['owned_groups_stopped'] = all(process is None or process.poll() is not None for process in (producer, reducer))
        selector.close()
        for process in (producer, reducer):
            if process:
                for stream in (process.stdin, process.stdout, process.stderr):
                    if stream:
                        stream.close()
        os.close(target_read)
        if target_write is not None:
            os.close(target_write)
        if admission is not None:
            for fd in admission: os.close(fd)
        finite['cleanup_complete'] = True
        finite['bytes_seen'] = counts
        finite['elapsed_seconds'] = round(time.monotonic() - started, 3)
    return finite, target.decode('utf-8', errors='replace')


def accepted(stats, *, probe=False):
    return (stats.get('completed') is True and stats.get('cleanup_complete') is True
            and stats.get('owned_groups_stopped') is True
            and stats.get('reducer_exit') == 0
            and (not probe or stats.get('producer_exit') == 0)
            and not any(stats.get(key) for key in ('watchdog', 'output_limit', 'internal_failure'))
            and type(stats.get('reduction', {}).get('total_symbol_lines')) is int
            and stats['reduction']['total_symbol_lines'] > 0)


def perf_capture(command, timeout):
    require(Path('/usr/bin/perf').is_file() and not Path('/usr/bin/perf').is_symlink())
    target_fd = os.pipe()
    admission = os.pipe()
    launcher = [sys.executable, str(Path(__file__).absolute()), '--exec-target', str(target_fd[1]), str(admission[0]), *command]
    producer = ['/usr/bin/perf', 'record', '-e', 'cpu-clock:u', '-F', str(FREQUENCY),
                '--no-buildid', '-o', '-', '--', *launcher]
    reducer = ['/usr/bin/perf', 'script', '-i', '-', '-F', 'time,sym']
    return pipeline(producer, reducer, target_fd, timeout, timed=True, admission=admission)


def probe():
    # No Rust/test process before successful real pipeline admission. This exercises
    # descriptor forwarding and available perf permissions without changing them.
    command = [sys.executable, '-c',
        'import time; stop=time.monotonic()+.6\nwhile time.monotonic()<stop: pass\nprint("sampler-synthetic-ok")']
    stats, text = perf_capture(command, 15)
    stats['synthetic_output_verified'] = text == 'sampler-synthetic-ok\n'
    stats['admitted'] = accepted(stats, probe=True) and stats['synthetic_output_verified']
    return stats


def ownership_controls():
    positive = negative = 0
    def admit(raw, values):
        rd, wr = os.pipe()
        os.write(wr, raw); os.close(wr)
        actual = iter(values)
        armed = []
        try:
            admit_expected_parent(rd, parent=lambda: next(actual), arm=lambda: armed.append(True))
        except SamplerFailure:
            return False, armed
        return True, armed
    require(admit(b'7\n', [7, 7]) == (True, [True])); positive += 1
    # Parent already dead/reparented before first observation: never arm or exec.
    require(admit(b'7\n', [1]) == (False, [])); negative += 1
    # Parent dies while arming: reject even if PDEATHSIG did not yet deliver.
    require(admit(b'7\n', [7, 1]) == (False, [True])); negative += 1
    for payload in [b'', b'PRIVATE', b'0\n', b'7\n8\n']:
        require(admit(payload, []) == (False, [])); negative += 1
    for admitted in [True, False]:
        # Real harmless trampoline, not a mirror of its decision logic. A wrong
        # expected parent must prevent the synthetic command from executing.
        rd, wr = os.pipe()
        ar, aw = os.pipe()
        child = None
        try:
            child = subprocess.Popen([sys.executable, str(Path(__file__).absolute()),
                '--exec-target', str(wr), str(ar), sys.executable, '-c',
                'print("synthetic-owned-exec")'],
                stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                pass_fds=(wr, ar), start_new_session=True)
            os.close(wr); wr = None
            os.close(ar); ar = None
            expected = os.getpid() if admitted else os.getpid() + 1
            os.write(aw, (str(expected) + '\n').encode()); os.close(aw); aw = None
            result = child.wait(timeout=5)
            require(select.select([rd], [], [], 5)[0] == [rd])
            text = os.read(rd, 128)
            if admitted:
                require(result == 0 and text == b'synthetic-owned-exec\n'); positive += 1
            else:
                require(result == LAUNCHER_EXITS['expected_parent_precheck_failed'] and text == b''); negative += 1
        finally:
            kill_owned_group(child)
            for fd in [rd, wr, ar, aw]:
                if fd is not None: os.close(fd)
    # Reproduce the actual retained-writer issue with a live parent. EOF MUST NOT
    # occur while this admitted parent retains wr, and MUST occur after shared
    # ordered-exit helper runs. No raw/target data or output-derived PID is used.
    rd, wr = os.pipe()
    holder = None
    try:
        holder = subprocess.Popen([sys.executable, '-c',
            'import os,sys; os.write(int(sys.argv[1]),b"synthetic-writer\\n"); sys.stdin.buffer.readline(); os.write(int(sys.argv[1]),b"synthetic-tail\\n")', str(wr)],
            stdin=subprocess.PIPE, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            pass_fds=(wr,), start_new_session=True)
        os.close(wr); wr = None
        require(select.select([rd], [], [], 5)[0] == [rd])
        require(os.read(rd, 128) == b'synthetic-writer\n')
        require(select.select([rd], [], [], .05)[0] == [] and holder.poll() is None)
        def request_exit():
            holder.stdin.write(b'exit\n'); holder.stdin.flush()
        require(exit_owned_parent_before_drain(holder, request_exit) is True)
        tail = bytearray()
        require(drain_target_after_parent_exit(rd, tail) is True and tail == b'synthetic-tail\n')
        positive += 1
    finally:
        kill_owned_group(holder)
        if holder and holder.stdin: holder.stdin.close()
        os.close(rd)
        if wr is not None: os.close(wr)
    failed = subprocess.Popen([sys.executable, '-c', 'raise SystemExit(23)'],
        stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        start_new_session=True)
    try:
        try: exit_owned_parent_before_drain(failed, lambda: None)
        except SamplerFailure: negative += 1
        else: require(False)
    finally:
        kill_owned_group(failed)
    return {'positive': positive, 'negative': negative, 'rust_bodies': 0,
            'actual_trampoline_and_ordered_exit_helpers': True}


TOOL_PATHS = {'gdb': '/usr/bin/gdb', 'perf': '/usr/bin/perf'}
TOOL_BOOLEAN_FIELDS = (
    'path_exists', 'is_file', 'is_symlink', 'executable',
    'canonical_target_regular', 'canonical_target_root_owned',
    'canonical_target_not_group_world_writable',
)


def inventory_path(path):
    """stat/access only; never execute a tool or expose its resolved path."""
    row = {'inventory_known': False, **dict.fromkeys(TOOL_BOOLEAN_FIELDS, None)}
    try:
        try:
            path.lstat()
        except FileNotFoundError:
            return {'inventory_known': True, **dict.fromkeys(TOOL_BOOLEAN_FIELDS, False)}
        row.update(path_exists=True, is_file=path.is_file(), is_symlink=path.is_symlink(),
                   executable=os.access(path, os.X_OK))
        try:
            canonical = path.resolve(strict=True)
        except FileNotFoundError:
            row.update(canonical_target_regular=False, canonical_target_root_owned=False,
                       canonical_target_not_group_world_writable=False, inventory_known=True)
            return row
        info = canonical.lstat()
        row.update(canonical_target_regular=stat.S_ISREG(info.st_mode),
                   canonical_target_root_owned=info.st_uid == 0,
                   canonical_target_not_group_world_writable=not bool(info.st_mode & 0o022),
                   inventory_known=True)
    except (OSError, RuntimeError, ValueError):
        pass
    return row


def tool_inventory():
    rows = {name: inventory_path(Path(path)) for name, path in TOOL_PATHS.items()}
    return {name: dict(row, admission_category=tool_admission_category(row)) for name, row in rows.items()}


def tool_admission_category(row):
    if (type(row) is not dict or row.get('inventory_known') is not True
            or any(type(row.get(key)) is not bool for key in TOOL_BOOLEAN_FIELDS)):
        return 'tool_inventory_unknown'
    for key, wanted, category in [
        ('path_exists', True, 'tool_missing'),
        ('is_symlink', False, 'tool_symlink_unsupported'),
        ('is_file', True, 'tool_not_regular'),
        ('executable', True, 'tool_not_executable'),
        ('canonical_target_regular', True, 'canonical_target_not_regular'),
        ('canonical_target_root_owned', True, 'canonical_target_not_root_owned'),
        ('canonical_target_not_group_world_writable', True, 'canonical_target_writable'),
    ]:
        if row[key] is not wanted:
            return category
    return 'tool_path_admitted'


def setup_exception_kind(error):
    for kind in (SamplerFailure, FileNotFoundError, PermissionError, OSError, ValueError, TypeError):
        if isinstance(error, kind): return kind.__name__
    return 'OtherException'


def inventory_controls():
    import tempfile
    positive = negative = 0
    good = {'inventory_known': True, **dict.fromkeys(TOOL_BOOLEAN_FIELDS, True)}
    good['is_symlink'] = False
    require(tool_admission_category(good) == 'tool_path_admitted'); positive += 1
    for key, value, expected in [
        ('path_exists', False, 'tool_missing'),
        ('is_symlink', True, 'tool_symlink_unsupported'),
        ('is_file', False, 'tool_not_regular'),
        ('executable', False, 'tool_not_executable'),
        ('canonical_target_regular', False, 'canonical_target_not_regular'),
        ('canonical_target_root_owned', False, 'canonical_target_not_root_owned'),
        ('canonical_target_not_group_world_writable', False, 'canonical_target_writable'),
        ('inventory_known', False, 'tool_inventory_unknown'),
        ('is_file', 1, 'tool_inventory_unknown'),
    ]:
        changed = dict(good); changed[key] = value
        require(tool_admission_category(changed) == expected); negative += 1
    missing = dict(good); missing.pop('executable')
    require(tool_admission_category(missing) == 'tool_inventory_unknown'); negative += 1
    # Actual stat/symlink logic, synthetic owned files only; no tool workload.
    with tempfile.TemporaryDirectory(prefix='sampler-tool-inventory-', dir=os.environ['RUNNER_TEMP']) as directory:
        base = Path(directory)
        require(tool_admission_category(inventory_path(base / 'missing')) == 'tool_missing'); negative += 1
        executable = base / 'owned-synthetic'
        executable.write_bytes(b'synthetic, never executed\n'); executable.chmod(0o700)
        link = base / 'link'; link.symlink_to(executable)
        require(tool_admission_category(inventory_path(link)) == 'tool_symlink_unsupported'); negative += 1
        link.unlink(); link.symlink_to(base / 'missing')
        require(tool_admission_category(inventory_path(link)) == 'tool_symlink_unsupported'); negative += 1
        row = inventory_path(executable)
        require(row['inventory_known'] and row['path_exists'] and row['is_file']
                and row['executable'] and row['canonical_target_regular']
                and row['canonical_target_not_group_world_writable']); positive += 1
    calls = []
    def no_capture(*args):
        calls.append(True)
        raise SamplerFailure('PRIVATE: must not export exception text')
    for changed, expected in [(dict(good, path_exists=False), 'tool_missing'),
                              (dict(good, is_symlink=True), 'tool_symlink_unsupported')]:
        result = mode_probe('gdb', inventory={'gdb': changed}, capture=no_capture)
        require(result['setup_category'] == expected and result['admitted'] is False
                and result['capture_invoked'] is False and calls == []); negative += 1
    result = mode_probe('gdb', inventory={'gdb': good}, capture=no_capture)
    require(result['setup_category'] == 'tool_capture_exception' and result['setup_exception'] == 'SamplerFailure'
            and result['admitted'] is False and 'PRIVATE' not in json.dumps(result)); negative += 1
    unsupported = lambda *args: ({'completed': False, 'internal_failure': True}, '')
    result = mode_probe('gdb', inventory={'gdb': good}, capture=unsupported)
    require(result['setup_category'] == 'tool_probe_unsupported' and result['admitted'] is False); negative += 1
    admitted = {'completed': True, 'cleanup_complete': True, 'target_eof_verified': True,
                'target_exit': 0, 'reduction': {'complete': True, 'frames': 1}}
    result = mode_probe('gdb', inventory={'gdb': good}, capture=lambda *args: (dict(admitted), 'sampler-synthetic-ok\n'))
    require(result['setup_category'] == 'admitted' and result['admitted'] is True); positive += 1
    result = mode_probe('gdb', inventory={'gdb': good}, capture=lambda *args: (dict(admitted), 'PRIVATE_OUTPUT'))
    require(result['setup_category'] == 'synthetic_output_mismatch' and not result['admitted']
            and 'PRIVATE_OUTPUT' not in json.dumps(result)); negative += 1
    return {'positive': positive, 'negative': negative, 'rust_bodies': 0,
            'tool_workloads': 0, 'stat_and_synthetic_only': True}


def controls():
    # Hosted preflight only. Pure reduction plus owned synthetic Python processes;
    # no perf permission dependency, Cargo, Rust bodies, protocol, or account data.
    positive = negative = 0
    r = Reducer()
    r.feed(b'marmot_app::runtime::account_worker::handler+0x12\n')
    r.feed(b'cgka_engine::validate\ntokio::runtime::poll\n[unknown]\n')
    x = r.finish()
    require(x['total_symbol_lines'] == 4 and x['categories']['app_account_worker'] == 1
            and x['categories']['core_engine'] == 1 and x['categories']['tokio'] == 1
            and x['categories']['unknown'] == 1)
    positive += 1
    r = Reducer(); r.feed(b'PRIVATE_ID=secret\n0x12345678\nhttps://private.invalid\n')
    require(r.finish()['categories']['unknown'] == 3)
    positive += 1
    for chunks, cap in [([b'abc'], 20), ([b'x' * (MAX_SYMBOL_LINE + 1)], MAX_SYMBOL_BYTES),
                        ([b'abcdef\n'], 3)]:
        try:
            r = Reducer(cap)
            for chunk in chunks: r.feed(chunk)
            r.finish()
        except SamplerFailure:
            negative += 1
        else:
            require(False)
    def fake(code, producer_exit=0, timeout=3, limits=None):
        fds = os.pipe()
        producer = [sys.executable, '-c', code, str(fds[1]), str(producer_exit)]
        reducer = [sys.executable, '-c', 'import sys; data=sys.stdin.buffer.read(); sys.stdout.buffer.write(data)']
        return pipeline(producer, reducer, fds, timeout, limits=limits)
    ok, text = fake('import os,sys; os.write(int(sys.argv[1]),b"synthetic target\\n"); print("marmot_app::runtime::account_worker::x")')
    require(accepted(ok, probe=True) and text == 'synthetic target\n')
    positive += 1
    unsupported, text = fake('import sys; sys.exit(23)')
    require(not accepted(unsupported, probe=True) and unsupported['producer_exit'] == 23
            and unsupported['cleanup_complete'] and not text)
    negative += 1
    broken, _ = fake('import os,sys; print("tokio::x"); sys.exit(23)')
    require(not accepted(broken, probe=True))
    negative += 1
    overflow, _ = fake('import sys; sys.stdout.write("x"*1000)', limits={'perf': 10})
    require(not accepted(overflow) and overflow['output_limit'] and overflow['owned_groups_stopped'])
    negative += 1
    hung, _ = fake('import time; time.sleep(10)', timeout=.1)
    require(not accepted(hung) and hung['watchdog'] and hung['owned_groups_stopped'])
    negative += 1
    for field, value in [('completed', False), ('cleanup_complete', False), ('owned_groups_stopped', False),
                         ('reducer_exit', 1), ('watchdog', True), ('output_limit', True), ('internal_failure', True)]:
        altered = dict(ok); altered[field] = value
        require(not accepted(altered, probe=True))
        negative += 1
    r = Reducer(timed=True)
    r.feed(b'100.100000: tokio::runtime::x\n101.100000: cgka_engine::validate\n')
    value = r.finish()
    require([bucket[0] for bucket in value['one_second_bins']] == [0, 1])
    positive += 1
    for raw in [b'PRIVATE_TIMESTAMP tokio::x\n', b'100.1: tokio::x\n99.1: tokio::x\n',
                b'100.1: tokio::x\n1001.1: tokio::x\n']:
        try:
            r = Reducer(timed=True); r.feed(raw); r.finish()
        except SamplerFailure: negative += 1
        else: require(False)
    good_gdb = {'completed': True, 'cleanup_complete': True, 'target_eof_verified': True, 'internal_failure': False,
                'watchdog': False, 'target_exit': 0,
                'reduction': {'complete': True, 'frames': 1}}
    require(mode_accepted('gdb', good_gdb, probe=True))
    positive += 1
    for field, value in [('completed', False), ('cleanup_complete', False),
                         ('internal_failure', True), ('watchdog', True), ('target_exit', 23), ('target_eof_verified', False)]:
        altered = dict(good_gdb); altered[field] = value
        require(not mode_accepted('gdb', altered, probe=True))
        negative += 1
    for reduction in [{'complete': False, 'frames': 1}, {'complete': True, 'frames': 0},
                      {'complete': True, 'frames': True}]:
        altered = dict(good_gdb, reduction=reduction)
        require(not mode_accepted('gdb', altered, probe=True))
        negative += 1
    require(not mode_accepted('unrecognized', good_gdb, probe=True))
    negative += 1
    return {'positive': positive, 'negative': negative, 'actual_rust_bodies': 0,
            'raw_private_export': False, 'owned_synthetic_processes_only': True, 'embedded_gdb': gdb_controls(), 'ownership_eof': ownership_controls(), 'tool_inventory': inventory_controls(), 'gdb_signal_policy': gdb_signal_controls()}


STAGE_RULES = (
 ('sibling_maintenance', ('marmot_app',), ('maintain_sibling_sharing',)),
 ('sibling_completion_service', ('marmot_app',), ('service_sibling_publication_completions',)),
 ('automatic_sharing_maintenance', ('marmot_app',), ('maintain_automatic_account_sharing',)),
 ('core_account_sharing_validation', ('cgka_engine','cgka_session'), ('validate_account_sharing_channel',)),
 ('ordinary_receive', ('marmot_app','transport_nostr'), ('receive_next_delivery','receive_account_delivery_or_spill')),
 ('inbound_ingest', ('marmot_app',), ('ingest_observed_received_delivery','ingest_received_delivery_once_observed')),
 ('periodic_maintenance', ('marmot_app',), ('finish_periodic_maintenance_after_recovery','maintain_device_linking')),
 ('runtime_command', ('marmot_app',), ('handle_account_worker_command','account_worker_command_future')),
 ('native_observe', ('marmot_app',), ('linking_native_observation',)),
 ('crypto', ('hpke','openmls','curve25519_dalek','chacha20poly1305','ed25519_dalek','sha2'), ('',)),
 ('sqlite', ('rusqlite','storage_sqlite'), ('',)),
)
def gdb_source():
    # Exact metadata source shared by GDB and hosted fake-frame controls.
    return '''import gdb,json
_categories = %r
_prefixes = %r
_allocators = %r
_counts = dict.fromkeys(_categories,0)
_stops = 0
_frames = 0
_complete = True
_stage_counts = dict.fromkeys(%r,0)
_stage_rules = %r
_truncated_threads = 0
_bins={}
def _closed_sample(bin_index):
 global _stops,_frames,_complete,_truncated_threads
 if type(bin_index) is not int or not 0<=bin_index<=900: raise RuntimeError()
 bucket=_bins.setdefault(bin_index,dict.fromkeys(_stage_counts,0))
 threads=gdb.selected_inferior().threads()
 if len(threads)>64:
  _complete=False
  return
 _stops+=1
 for thread in threads:
  if not thread.is_stopped():
   _complete=False
   continue
  thread.switch()
  frame=gdb.newest_frame()
  depth=0
  seen=set()
  while frame is not None and depth<24:
   try: name=frame.name()
   except gdb.error: name=None
   if isinstance(name,str):
    for stage,crates,methods in _stage_rules:
     if any(crate+'::' in name for crate in crates) and any('::'+method in name for method in methods): seen.add(stage)
   category='unknown'
   if name in _allocators: category='allocator'
   elif isinstance(name,str):
    for prefix,fixed in _prefixes:
     if name.startswith(prefix):
      category=fixed
      break
   _counts[category]+=1
   _frames+=1
   depth+=1
   frame=frame.older()
  if frame is not None: _truncated_threads+=1
  for stage in seen:
   _stage_counts[stage]+=1
   bucket[stage]+=1
 gdb.write('GDB_CLOSED:'+json.dumps({'categories':_counts,'stops':_stops,'frames':_frames,'complete':_complete,'stage_presence':_stage_counts,'truncated_thread_stacks':_truncated_threads,'bin_index':bin_index,'bin_stages':bucket},sort_keys=True)+'\\n')
''' % (CATEGORIES, PREFIXES, sorted(ALLOCATOR), tuple(rule[0] for rule in STAGE_RULES), STAGE_RULES)


def gdb_controls():
    import types
    output = []
    class Frame:
        def __init__(self, name, older=None): self.label, self.previous = name, older
        def name(self): return self.label
        def older(self): return self.previous
    class Thread:
        def is_stopped(self): return True
        def switch(self): pass
    fake = types.ModuleType('gdb')
    fake.error = RuntimeError
    fake.write = output.append
    fake.selected_inferior = lambda: types.SimpleNamespace(threads=lambda: [Thread()])
    names = ['marmot_app::client::AppClient::maintain_sibling_sharing',
             'cgka_engine::Engine::validate_account_sharing_channel', 'sha2::compress']
    frame = None
    for name in reversed(names): frame = Frame(name, frame)
    fake.newest_frame = lambda: frame
    previous = sys.modules.get('gdb')
    try:
        sys.modules['gdb'] = fake
        namespace = {}
        exec(gdb_source(), namespace)
        namespace['_closed_sample'](3)
        require(len(output) == 1 and output[0].endswith('\n'))
        row = json.loads(output.pop()[len('GDB_CLOSED:'):])
        require(row['stage_presence']['sibling_maintenance'] == 1
                and row['stage_presence']['core_account_sharing_validation'] == 1
                and row['stage_presence']['crypto'] == 1
                and row['bin_index'] == 3 and row['frames'] == 3)
        positive, negative = 1, 0
        for index in [-1, 901, 'PRIVATE', True]:
            try: namespace['_closed_sample'](index)
            except RuntimeError: negative += 1
            else: require(False)
        frame = Frame('PRIVATE_ACCOUNT=never-export')
        namespace['_closed_sample'](4)
        row = json.loads(output.pop()[len('GDB_CLOSED:'):])
        require('PRIVATE_ACCOUNT' not in json.dumps(row) and row['categories']['unknown'] >= 1)
        positive += 1
        fake.selected_inferior = lambda: types.SimpleNamespace(threads=lambda: [Thread()] * 65)
        namespace['_closed_sample'](5)
        require(namespace['_complete'] is False and output == [])
        negative += 1
        return {'positive': positive, 'negative': negative, 'fake_frames_only': True}
    finally:
        if previous is None: sys.modules.pop('gdb', None)
        else: sys.modules['gdb'] = previous


def gdb_capture(command, timeout):
    """Explicit alternative: interrupted stack presence, NOT CPU-time samples."""
    require(Path('/usr/bin/gdb').is_file() and not Path('/usr/bin/gdb').is_symlink())
    no_core_dumps()
    rd, wr = os.pipe()
    admission = os.pipe()
    process = None
    selector = selectors.DefaultSelector()
    target = bytearray()
    pending = bytearray()
    error_bytes = total_bytes = 0
    deadline = time.monotonic() + timeout
    started = time.monotonic()
    token = 0
    deferred_stops = []
    finite = {'mode': 'gdb', 'measurement': 'interrupted_all_thread_stack_presence_not_cpu',
              'completed': False, 'watchdog': False, 'output_limit': False,
              'internal_failure': False, 'cleanup_complete': False,
              'raw_persistence': False, 'qualification_passed': False,
              'stops': 0, 'paused_wall_seconds': 0., 'target_exit': None,
              'reduction': None, 'capture_stage': 'gdb_process_spawn',
              'error_kind': None, 'error_category': None, 'interval_seconds': .1, 'time_anchor': 'gdb_exec_run_command',
              'fifth_choice_phase_alignment_known': False, 'stage_counts_overlap': True}
    embedded = gdb_source()
    closed = None
    gdb_bins = {}
    try:
        argv = ['/usr/bin/gdb', '--quiet', '--nx', '--interpreter=mi2', '--args',
                sys.executable, str(Path(__file__).absolute()), '--exec-target', str(wr), str(admission[0]), *command]
        process = subprocess.Popen(argv, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
            stderr=subprocess.PIPE, pass_fds=(wr, admission[0]), start_new_session=True)
        owned_admission, admission = admission, None
        finite['capture_stage'] = 'parent_admission_publish'
        publish_parent_admission(process, owned_admission)
        os.close(wr); wr = None
        for stream, role in [(process.stdout, 'mi'), (process.stderr, 'err'), (rd, 'target')]:
            fd = stream if isinstance(stream, int) else stream.fileno()
            os.set_blocking(fd, False); selector.register(fd, selectors.EVENT_READ, role)
        def receive(until, local_deadline):
            nonlocal error_bytes, total_bytes, closed
            for old in list(deferred_stops):
                found = until(old)
                if found is not None:
                    deferred_stops.remove(old)
                    return found
            while time.monotonic() < min(deadline, local_deadline):
                ready = list(selector.select(.05))
                # Existing complete MI lines are processed even without a new read.
                if b'\n' in pending:
                    ready.insert(0, (type('Pending', (), {'data': 'pending', 'fd': -1})(), 0))
                for key, _ in ready:
                    if key.data == 'pending':
                        chunk = b''
                    else:
                        try: chunk = os.read(key.fd, 65536)
                        except BlockingIOError: continue
                    if not chunk and key.data != 'pending':
                        selector.unregister(key.fd)
                        continue
                    if key.data == 'target':
                        require(len(target) + len(chunk) <= MAX_TARGET_BYTES)
                        target.extend(chunk)
                        if finite.get('failure_marker_capture_elapsed_ms') is None and b'panicked at crates/marmot-app/src/native_device_linking/tests/automatic_pairing_acceptance.rs:1785:9:' in target:
                            finite['failure_marker_capture_elapsed_ms'] = int((time.monotonic() - started) * 1000)
                        continue
                    if key.data == 'err':
                        error_bytes += len(chunk); require(error_bytes <= MAX_STDERR_BYTES)
                        continue
                    total_bytes += len(chunk); require(total_bytes <= 8 * 1024 * 1024)
                    pending.extend(chunk)
                    require(len(pending) <= 65536)
                    while b'\n' in pending:
                        raw, _, tail = pending.partition(b'\n'); pending[:] = tail
                        require(len(raw) <= 16384)
                        line = raw.decode('ascii', 'replace')
                        if line.startswith('~'):
                            try: console = json.loads(line[1:])
                            except (ValueError, TypeError): console = ''
                            if console.startswith('GDB_CLOSED:'):
                                value = json.loads(console[len('GDB_CLOSED:'):])
                                require(set(value) == {'categories', 'stops', 'frames', 'complete', 'stage_presence', 'truncated_thread_stacks', 'bin_index', 'bin_stages'})
                                require(set(value['stage_presence']) == {rule[0] for rule in STAGE_RULES})
                                require(all(type(n) is int and 0 <= n <= 640000 for n in value['stage_presence'].values()))
                                require(type(value['truncated_thread_stacks']) is int and 0 <= value['truncated_thread_stacks'] <= 640000)
                                require(set(value['categories']) == set(CATEGORIES))
                                require(all(type(n) is int and 0 <= n <= 10_000_000 for n in value['categories'].values()))
                                require(type(value['stops']) is int and 0 <= value['stops'] <= 10000)
                                require(type(value['frames']) is int and sum(value['categories'].values()) == value['frames'])
                                require(type(value['complete']) is bool)
                                require(type(value['bin_index']) is int and 0 <= value['bin_index'] <= 900)
                                require(type(value['bin_stages']) is dict and set(value['bin_stages']) == {rule[0] for rule in STAGE_RULES})
                                require(all(type(n) is int and 0 <= n <= 640000 for n in value['bin_stages'].values()))
                                gdb_bins[value['bin_index']] = value['bin_stages']
                                require(len(gdb_bins) <= 901)
                                closed = value
                        found = until(line)
                        if found is not None:
                            return found
                        if line.startswith('*stopped,'):
                            require(len(deferred_stops) < 8)
                            deferred_stops.append(line)
                        # Discard all unmatched MI bytes, including paths/addresses.
                if process.poll() is not None:
                    return 'gdb-exited'
            raise IntervalExpired()
        def send(command):
            nonlocal token
            token += 1
            process.stdin.write((str(token) + command + '\n').encode()); process.stdin.flush()
            return str(token)
        def done(command):
            expected = send(command)
            outcome = receive(lambda line: ('done' if line.startswith(expected + '^done') else
                'error' if line.startswith(expected + '^error') else None), time.monotonic() + 5)
            if outcome != 'done':
                finite['error_category'] = 'mi_command_error' if outcome == 'error' else 'mi_reply_unknown'
            require(outcome == 'done')
        finite['capture_stage'] = 'gdb_configuration'
        for setting in ['-gdb-set auto-load off', '-gdb-set debuginfod enabled off',
                        '-gdb-set disable-randomization off', '-gdb-set startup-with-shell off', '-gdb-set pagination off', '-gdb-set confirm off',
                        '-gdb-set print frame-arguments none', '-gdb-set print address off',
                        '-gdb-set print thread-events off', '-gdb-set mi-async on']:
            done(setting)
        done('-interpreter-exec console "handle SIGINT stop print nopass"')
        finite['capture_stage'] = 'gdb_python_install'
        done('-interpreter-exec console ' + json.dumps('python exec(' + repr(embedded) + ')'))
        finite['capture_stage'] = 'gdb_exec_run'
        launch_started = time.monotonic()
        finite['launch_command_capture_elapsed_ms'] = int((launch_started - started) * 1000)
        run_token = send('-exec-run')
        require(receive(lambda line: 'running' if line.startswith(run_token + '^running') else
            'error' if line.startswith(run_token + '^error') else None, time.monotonic() + 5) == 'running')
        def stopped(line):
            if not line.startswith('*stopped,'):
                return None
            if 'reason="exited-normally"' in line:
                return ('exit', 0)
            match = re.search(r'reason="exited",exit-code="([0-7]{1,4})"', line)
            if match:
                return ('exit', int(match[1], 8))
            if 'reason="signal-received",signal-name="SIGINT"' in line:
                return ('interrupt', None)
            return ('unexpected-stop', None)
        while True:
            finite['capture_stage'] = 'gdb_wait_for_stop'
            # Wait for normal exit during the interval before issuing interrupt.
            try:
                status = receive(stopped, time.monotonic() + .1)
            except IntervalExpired:
                require(time.monotonic() < deadline)
                status = None
            if status is None:
                send('-exec-interrupt --all')
                status = receive(stopped, time.monotonic() + 5)
            require(isinstance(status, tuple))
            if status[0] == 'exit':
                finite['target_exit'] = status[1]
                finite['completed'] = True
                break
            require(status[0] == 'interrupt')
            finite['capture_stage'] = 'gdb_frame_reduce'
            paused = time.monotonic()
            done('-interpreter-exec console "python _closed_sample(' + str(int(time.monotonic() - launch_started)) + ')"')
            finite['stops'] += 1
            finite['capture_stage'] = 'gdb_resume'
            next_token = send('-exec-continue')
            require(receive(lambda line: 'running' if line.startswith(next_token + '^running') else
                'error' if line.startswith(next_token + '^error') else None, time.monotonic() + 5) == 'running')
            finite['paused_wall_seconds'] += time.monotonic() - paused
        finite['capture_stage'] = 'gdb_parent_exit'
        finite['profiler_parent_exited_before_target_eof'] = exit_owned_parent_before_drain(
            process, lambda: send('-gdb-exit'))
        # Parent exit closes its inherited writer. Direct bounded drain also
        # preserves final numeric test output before any sampler verdict.
        finite['capture_stage'] = 'target_eof_drain'
        finite['target_eof_verified'] = drain_target_after_parent_exit(rd, target)
        finite['capture_stage'] = 'gdb_reduction_admission'
        finite['reduction'] = closed
        finite['one_second_stage_bins'] = [[key, gdb_bins[key]] for key in sorted(gdb_bins)]
        require(closed is not None and closed['complete'] is True and closed['frames'] > 0)
        finite['capture_stage'] = 'complete'
    except Exception as error:
        finite['error_kind'] = setup_exception_kind(error)
        if finite['error_category'] is None:
            finite['error_category'] = 'mi_operation_timeout' if isinstance(error, IntervalExpired) else 'closed_capture_failure'
        finite['watchdog'] = time.monotonic() >= deadline
        finite['internal_failure'] = not finite['watchdog']
    finally:
        # Target launcher sets Linux PDEATHSIG before exec. Killing this admitted
        # GDB parent also kills the owned inferior; no output-derived PID is used.
        kill_owned_group(process)
        if wr is not None:
            os.close(wr); wr = None
        try:
            finite['target_eof_verified'] = drain_target_after_parent_exit(rd, target)
        except Exception:
            finite['internal_failure'] = True
        if finite.get('failure_marker_capture_elapsed_ms') is None and b'panicked at crates/marmot-app/src/native_device_linking/tests/automatic_pairing_acceptance.rs:1785:9:' in target:
            finite['failure_marker_capture_elapsed_ms'] = int((time.monotonic() - started) * 1000)
        selector.close()
        if process:
            for stream in (process.stdin, process.stdout, process.stderr):
                if stream: stream.close()
        os.close(rd)
        if wr is not None: os.close(wr)
        if admission is not None:
            for fd in admission: os.close(fd)
        finite['cleanup_complete'] = process is None or process.poll() is not None
        finite['elapsed_seconds'] = round(time.monotonic() - started, 3)
        finite['paused_wall_seconds'] = round(finite['paused_wall_seconds'], 6)
        finite['mi_bytes_discarded'] = total_bytes
        finite['stderr_bytes_discarded'] = error_bytes
    return finite, target.decode('utf-8', 'replace')


def mode_capture(mode, command, timeout):
    require(mode in ('perf', 'gdb'))
    return perf_capture(command, timeout) if mode == 'perf' else gdb_capture(command, timeout)


def mode_accepted(mode, stats, *, probe=False):
    if mode == 'perf':
        return accepted(stats, probe=probe)
    return (mode == 'gdb' and stats.get('completed') is True
            and stats.get('cleanup_complete') is True and stats.get('target_eof_verified') is True and not stats.get('internal_failure')
            and not stats.get('watchdog') and stats.get('reduction', {}).get('complete') is True
            and type(stats.get('reduction', {}).get('frames')) is int
            and stats['reduction']['frames'] > 0
            and (not probe or stats.get('target_exit') == 0))


def mode_probe(mode, *, inventory=None, capture=None):
    result = {'selected_tool': mode if mode in TOOL_PATHS else None,
              'admitted': False, 'capture_invoked': False, 'rust_bodies': 0,
              'setup_category': 'unsupported_selected_tool', 'setup_exception': None}
    if mode not in TOOL_PATHS:
        return result
    try:
        inventory = tool_inventory() if inventory is None else inventory
        row = inventory.get(mode) if type(inventory) is dict else None
        result['tool_inventory'] = {
            key: row.get(key) if type(row) is dict and type(row.get(key)) is bool else None
            for key in ('inventory_known', *TOOL_BOOLEAN_FIELDS)}
        result['setup_category'] = tool_admission_category(row)
        if result['setup_category'] != 'tool_path_admitted':
            return result
        if mode == 'gdb' and capture is None:
            result['signal_policy_control'] = gdb_signal_controls(real=True)
            if result['signal_policy_control']['verified'] is not True:
                result['setup_category'] = 'gdb_signal_policy_control_failed'
                return result
        command = [sys.executable, '-c',
            'import time; stop=time.monotonic()+1\nwhile time.monotonic()<stop: pass\nprint("sampler-synthetic-ok")']
        result['capture_invoked'] = True
        capture = mode_capture if capture is None else capture
        stats, text = capture(mode, command, 15)
        result['capture'] = stats
        if mode == 'gdb':
            result['harmless_launcher_failure'] = harmless_launcher_failure(stats.get('target_exit'))
        result['synthetic_output_verified'] = text == 'sampler-synthetic-ok\n'
        if not mode_accepted(mode, stats, probe=True):
            result['setup_category'] = 'tool_probe_unsupported'
        elif not result['synthetic_output_verified']:
            result['setup_category'] = 'synthetic_output_mismatch'
        else:
            result['setup_category'] = 'admitted'
            result['admitted'] = True
    except Exception as error:
        result['setup_category'] = 'tool_capture_exception'
        result['setup_exception'] = setup_exception_kind(error)
    return result



def launcher_main(args):
    try:
        launch_require(len(args) >= 5 and args[0] == '--exec-target', 'invalid_arguments')
        try: fd, admission = int(args[1]), int(args[2])
        except ValueError: raise LauncherFailure('invalid_arguments') from None
        launch_require(fd > 2 and admission > 2 and fd != admission, 'invalid_arguments')
        try: os.fstat(fd)
        except OSError: raise LauncherFailure('output_fd_unavailable') from None
        no_core_dumps()
        admit_expected_parent(admission)
        try:
            os.dup2(fd, 1); os.dup2(fd, 2); os.close(fd)
        except OSError:
            raise LauncherFailure('dup2_failed') from None
        try: os.execv(args[3], args[3:])
        except OSError: raise LauncherFailure('exec_failed') from None
    except LauncherFailure as error:
        os._exit(LAUNCHER_EXITS[error.category])
    except Exception:
        os._exit(LAUNCHER_EXITS['launcher_unknown'])


if __name__ == '__main__':
    launcher_main(sys.argv[1:])
