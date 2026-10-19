"""Finite RAM-only child output for remote metadata controls, never product logs."""
import os
import select
import signal
import subprocess
import time

MAX_CAPTURE_BYTES = 4 * 1024 * 1024


def capture(command, *, cwd, env, timeout):
    process = subprocess.Popen(command, cwd=cwd, env=env, stdin=subprocess.DEVNULL,
                               stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                               start_new_session=True)
    output = bytearray()
    deadline = time.monotonic() + timeout
    try:
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise TimeoutError('Metadata child deadline exceeded')
            ready, _, _ = select.select([process.stdout], [], [], min(remaining, 1))
            if not ready:
                continue
            chunk = os.read(process.stdout.fileno(), min(65536, MAX_CAPTURE_BYTES - len(output) + 1))
            if not chunk:
                break
            if len(output) + len(chunk) > MAX_CAPTURE_BYTES:
                raise ValueError('Metadata child output limit exceeded')
            output.extend(chunk)
        code = process.wait(timeout=max(0.01, deadline - time.monotonic()))
        return subprocess.CompletedProcess(command, code, output.decode('utf-8', errors='replace'), '')
    finally:
        if process.poll() is None:
            # Give the mutation child's SIGTERM restoration handler a bounded
            # chance before terminating its entire task-owned process group.
            try:
                os.killpg(process.pid, signal.SIGTERM)
            except ProcessLookupError:
                pass
            try:
                process.wait(timeout=2)
            except subprocess.TimeoutExpired:
                try:
                    os.killpg(process.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                process.wait()
        process.stdout.close()
