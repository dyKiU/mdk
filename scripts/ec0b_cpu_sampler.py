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
            require(ctypes.CDLL(None, use_errno=True).prctl(1, signal.SIGKILL, 0, 0, 0) == 0)
    try:
        require(select.select([fd], [], [], 5)[0] == [fd])
        raw = os.read(fd, 32)
        require(re.fullmatch(rb'[1-9][0-9]{0,9}\n', raw) is not None)
        expected = int(raw)
        require(parent() == expected)  # Reject already reparented targets.
        arm()
        require(parent() == expected)  # Cover death while arming PDEATHSIG.
    finally:
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
                require(result != 0 and text == b''); negative += 1
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
            'raw_private_export': False, 'owned_synthetic_processes_only': True, 'embedded_gdb': gdb_controls(), 'ownership_eof': ownership_controls()}


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
              'reduction': None, 'interval_seconds': .1, 'time_anchor': 'gdb_exec_run_command',
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
            require(outcome == 'done')
        for setting in ['-gdb-set auto-load off', '-gdb-set debuginfod enabled off',
                        '-gdb-set disable-randomization off', '-gdb-set startup-with-shell off', '-gdb-set pagination off', '-gdb-set confirm off',
                        '-gdb-set print frame-arguments none', '-gdb-set print address off',
                        '-gdb-set print thread-events off', '-gdb-set mi-async on']:
            done(setting)
        done('-interpreter-exec console "handle SIGINT stop noprint nopass"')
        done('-interpreter-exec console ' + json.dumps('python exec(' + repr(embedded) + ')'))
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
            paused = time.monotonic()
            done('-interpreter-exec console "python _closed_sample(' + str(int(time.monotonic() - launch_started)) + ')"')
            finite['stops'] += 1
            next_token = send('-exec-continue')
            require(receive(lambda line: 'running' if line.startswith(next_token + '^running') else
                'error' if line.startswith(next_token + '^error') else None, time.monotonic() + 5) == 'running')
            finite['paused_wall_seconds'] += time.monotonic() - paused
        finite['profiler_parent_exited_before_target_eof'] = exit_owned_parent_before_drain(
            process, lambda: send('-gdb-exit'))
        # Parent exit closes its inherited writer. Direct bounded drain also
        # preserves final numeric test output before any sampler verdict.
        finite['target_eof_verified'] = drain_target_after_parent_exit(rd, target)
        finite['reduction'] = closed
        finite['one_second_stage_bins'] = [[key, gdb_bins[key]] for key in sorted(gdb_bins)]
        require(closed is not None and closed['complete'] is True and closed['frames'] > 0)
    except Exception:
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


def mode_probe(mode):
    command = [sys.executable, '-c',
        'import time; stop=time.monotonic()+1\nwhile time.monotonic()<stop: pass\nprint("sampler-synthetic-ok")']
    stats, text = mode_capture(mode, command, 15)
    stats['synthetic_output_verified'] = text == 'sampler-synthetic-ok\n'
    stats['admitted'] = mode_accepted(mode, stats, probe=True) and stats['synthetic_output_verified']
    return stats



if __name__ == '__main__':
    # Only launched behind perf, never shell-evaluated. Keep target output out of
    # the producer's perf-data stdout pipe. No target code is imported here.
    require(sys.argv[1] == '--exec-target' and len(sys.argv) >= 6)
    fd, admission = int(sys.argv[2]), int(sys.argv[3])
    require(fd > 2 and admission > 2 and fd != admission)
    no_core_dumps()
    admit_expected_parent(admission)
    os.dup2(fd, 1); os.dup2(fd, 2); os.close(fd)
    os.execv(sys.argv[4], sys.argv[4:])
