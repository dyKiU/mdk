#!/usr/bin/env python3
"""Run the Mac suite against its own pinned iOS relay fixture, then reap that PID."""
import errno
import hashlib
import json
import os
from pathlib import Path
import signal
import socket
import subprocess
import time


def main():
    ios = Path('ios').resolve(strict=True)
    app = Path('mac').resolve(strict=True)
    temp = Path(os.environ['RUNNER_TEMP'])
    report_path = temp / 'final-mac-relay.json'
    log_path = temp / 'final-mac-relay.log'
    binary = ios / 'build/TestRelay/debug/white-noise-sync-test-relay'
    port = 18181  # NativeSecretStoreBoundaryTests uses this isolated endpoint.
    report = {'relay_source_sha': os.environ['IOS_SHA'], 'app_sha': os.environ['MAC_SHA'],
              'sdk_source_sha': os.environ['SOURCE_SHA'], 'sdk_run_id': os.environ['SDK_RUN_ID'],
              'port': port, 'busy_port_refused': False, 'relay_started': False,
              'smoke_passed': False, 'command_exit_code': None, 'cleanup': None}
    relay = None
    code = 1
    stage = 'validate-pinned-fixture'

    def interrupted(signum, _frame):
        raise KeyboardInterrupt(signum)

    previous_handlers = {sig: signal.signal(sig, interrupted)
                         for sig in (signal.SIGINT, signal.SIGTERM)}
    try:
        for path, expected in ((ios, report['relay_source_sha']), (app, report['app_sha'])):
            actual = subprocess.check_output(['git', '-C', str(path), 'rev-parse', 'HEAD'], text=True).strip()
            if actual != expected:
                raise ValueError('Pinned app/relay source mismatch')
        with binary.open('rb') as source:
            report['relay_binary_sha256'] = hashlib.file_digest(source, 'sha256').hexdigest()
        stage = 'reserve-unused-loopback-port'
        try:
            with socket.socket() as listener:
                listener.bind(('127.0.0.1', port))
        except OSError as error:
            report['busy_port_refused'] = error.errno == errno.EADDRINUSE
            raise
        stage = 'start-owned-relay'
        with log_path.open('xb') as log:
            relay = subprocess.Popen([str(binary), '--port', str(port)], stdout=log, stderr=subprocess.STDOUT)
            report.update(relay_started=True, relay_pid=relay.pid)
            deadline = time.monotonic() + 15
            # The fixture prints its URL only after successful bind/run. This
            # prevents a competing listener from satisfying a mere TCP probe.
            while True:
                if relay.poll() is not None:
                    raise RuntimeError('Owned relay exited before readiness')
                with log_path.open('rb') as output:
                    ready = output.read(256).splitlines()
                if ready and ready[0].removesuffix(b'/') == f'ws://127.0.0.1:{port}'.encode():
                    break
                if time.monotonic() >= deadline:
                    raise TimeoutError('Owned relay readiness deadline')
                time.sleep(0.05)
            stage = 'smoke-owned-relay'
            subprocess.run(['python3', str(ios / 'scripts/test-relay/smoke.py'), '--port', str(port)],
                           check=True, timeout=30)
            if relay.poll() is not None:
                raise RuntimeError('Owned relay exited during smoke')
            report['smoke_passed'] = True
            stage = 'run-mac-suite'
            environment = dict(os.environ, TEST_RUNNER_WN_NATIVE_TEST_RELAY_URL=f'ws://127.0.0.1:{port}')
            result = subprocess.run(['bash', 'scripts/test-isolated.sh'], cwd=app, env=environment)
            report['command_exit_code'] = result.returncode
            code = result.returncode if result.returncode >= 0 else 128 - result.returncode
            if relay.poll() is not None:
                report['failure_stage'] = 'owned-relay-lifetime'
                code = code or 1
    except KeyboardInterrupt as error:
        report['failure_stage'] = stage
        code = 128 + (error.args[0] if error.args else signal.SIGINT)
    except (OSError, ValueError, RuntimeError, subprocess.SubprocessError):
        report['failure_stage'] = stage
    finally:
        if relay is not None:
            cleanup = {'pid': relay.pid, 'forced': False, 'reaped': False}
            try:
                if relay.poll() is None:
                    relay.send_signal(signal.SIGINT)
                relay.wait(timeout=10)
                cleanup.update(reaped=True, exit_code=relay.returncode)
                if relay.returncode != 0:
                    code = code or 1
            except subprocess.TimeoutExpired:
                relay.kill()
                relay.wait()
                cleanup.update(forced=True, reaped=True, exit_code=relay.returncode)
                code = code or 1
            report['cleanup'] = cleanup
        for sig, handler in previous_handlers.items():
            signal.signal(sig, handler)
        with report_path.open('x') as output:
            output.write(json.dumps(report, indent=2) + '\n')
    return code


if __name__ == '__main__':
    raise SystemExit(main())
