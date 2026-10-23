"""Manual hosted-only diagnostic of immutable F2 archive; never qualification."""
import argparse
from collections import Counter
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
import zipfile

from upstream_current_backend_probe import capture
from upstream_replay_controls import counts, selected_case, compiler, panic_facts, marker

SOURCE = '7ca6e10bf0c2d0500ed56c118c4eee419f2617bc'
PRODUCER = 39902825786
ARTIFACT = 12480175027
ZIP_SIZE = 86660526
ZIP_SHA = '85c07e87df35e45c328671074e474cdede921d39a65edce98ddaf21917cb21c4'
TEST = 'offline_replay::offline_replay_crosses_queue'
FILTER = 'package(marmot-app) & binary(=relay_runtime) & test(=' + TEST + ')'
# Only fixed source-level function labels leave the runner. All other symbol
# names, DSOs, addresses, process names and raw perf output stay local.
LABELS = ('canonical_event_id', 'validate_app_payload_for_sender', 'decode_received_event',
          'project_received_message', 'record_account_app_event_at', 'process_message',
          'sqlite3_step', 'sqlite3VdbeExec', 'sqlite3PagerCommitPhaseOne',
          'sqlite3PagerCommitPhaseTwo', 'sqlite3OsSync', 'sqlite3WalCheckpoint',
          'EVP_CipherUpdate', 'EVP_EncryptUpdate', 'EVP_DecryptUpdate',
          'SHA256_Update', 'SHA256_Transform', 'serde_json::de::', 'serde_json::ser::')


def sha(path):
    result = hashlib.sha256()
    with path.open('rb') as source:
        for part in iter(lambda: source.read(1024 * 1024), b''):
            result.update(part)
    return result.hexdigest()


def git(root, *args):
    return subprocess.check_output(['git', '-C', str(root), *args], text=True).strip()


class GuardError(ValueError):
    """A fixed controller label, never an external command or response string."""


def need(condition, label):
    if not condition:
        raise GuardError(label)


def api(path):
    return json.loads(subprocess.check_output(['gh', 'api', 'repos/dyKiU/mdk/' + path], timeout=60))


def sample_summary(raw):
    text = raw.decode('utf-8', errors='strict')
    totals, unknown, labels = 0, 0, Counter()
    for row in text.splitlines():
        if not row.strip() or row.lstrip().startswith('#'):
            continue
        totals += 1
        need(totals <= 1000000 and len(row) <= 8192, 'sample-output-bound')
        matches = [label for label in LABELS if label in row]
        if len(matches) == 1:
            labels[matches[0]] += 1
        else:
            unknown += 1
    return {'scope': 'flat_userspace_cpu_clock_whole_nextest_invocation_inherited_children',
            'sample_rows': totals, 'known_rows': totals - unknown, 'unknown_rows': unknown,
            'fixed_function_rows': dict(labels.most_common(20)), 'not_wait_time': True,
            'not_original_60s_subwindow': True, 'not_per_operation_attribution': True,
            'inline_or_missing_symbols_can_be_unknown': True, 'requested_frequency_hz': 49,
            'callchains_stacks_memory_not_requested': True}



def symbol_preflight(binary):
    code, sections, _, _ = capture(['readelf', '--section-headers', '--wide', str(binary)], 15)
    need(code == 0 and b'.symtab' in sections, 'elf-symbol-section')
    # Stream bounded symbol lines, never retain/export a full symbol table.
    proc = subprocess.Popen(['timeout', '30s', 'nm', '--defined-only', '--format=posix', str(binary)],
                            stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
    rows, size, found = 0, 0, set()
    try:
        while True:
            row = proc.stdout.readline(1024 * 1024 + 1)
            if not row:
                break
            rows += 1; size += len(row)
            need(len(row) <= 1024 * 1024 and rows <= 2000000 and size <= 128 * 1024**2, 'symbol-stream-bound')
            found.update(label for label in LABELS if label.encode() in row)
        need(proc.wait(timeout=5) == 0 and rows >= 100 and found, 'insufficient-elf-symbols')
        return {'defined_symbols': rows, 'fixed_labels_present': sorted(found)}
    finally:
        proc.stdout.close()
        if proc.poll() is None:
            proc.kill(); proc.wait(timeout=5)


def script_warnings(raw):
    lines = raw.decode('utf-8', errors='replace').splitlines()
    lost = [line for line in lines if re.search(r'\blost\b|PERF_RECORD_LOST', line, re.I)]
    return {'stderr_nonempty': bool(raw.strip()), 'stderr_lines': len(lines),
            'warning_lines': sum(bool(re.search(r'warning|error', line, re.I)) for line in lines),
            'lost_lines': len(lost), 'lost_event_count': 0 if not lost else None,
            'lost_event_count_unknown': bool(lost)}


def parser_controls():
    known = sample_summary(b'canonical_event_id\nsqlite3_step\n')
    need(known['known_rows'] == 2 and known['unknown_rows'] == 0, 'known-sample-control')
    unknown = sample_summary(b'[unknown]\ncanonical_event_id process_message\n')
    need(unknown['unknown_rows'] == 2 and unknown['known_rows'] == 0, 'unknown-ambiguous-control')
    need(script_warnings(b'')['stderr_nonempty'] is False, 'empty-warning-control')
    warning = script_warnings(b'Warning: lost events\n')
    need(warning['lost_event_count_unknown'] and warning['warning_lines'] == 1, 'lost-warning-control')
    negatives = [b'\xff', b'x' * 8193, b'x\n' * 1000001]
    for raw in negatives:
        try:
            sample_summary(raw)
        except (ValueError, UnicodeError):
            pass
        else:
            raise ValueError('sample-negative-accepted')
    return {'positive': 4, 'negative': 3, 'product_bodies': 0}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--source-root', required=True)
    parser.add_argument('--output', required=True)
    args = parser.parse_args()
    output = Path(args.output).resolve()
    output.parent.mkdir(parents=True, exist_ok=True)
    tooling = Path(__file__).resolve().parents[1]
    source = Path(args.source_root).resolve()
    report = {'schema': 'existing-archive-flat-cpu-v1', 'diagnostic_only': True,
              'qualification_passed': False, 'source': SOURCE, 'producer_run': PRODUCER,
              'artifact_id': ARTIFACT, 'test': TEST, 'product_bodies_started': 0,
              'stage': 'identity', 'collection_complete': False}
    save = lambda: output.write_text(json.dumps(report, indent=2) + '\n')
    old_paranoid, guard = None, Path(os.environ['RUNNER_TEMP']) / 'archive-perf-paranoid-before'
    binary = None
    try:
        need(os.environ.get('GITHUB_ACTIONS') == 'true' and os.environ.get('RUNNER_ENVIRONMENT') == 'github-hosted', 'hosted-only')
        need(os.environ.get('GITHUB_EVENT_NAME') == 'workflow_dispatch' and os.geteuid() != 0, 'manual-nonroot-only')
        need(os.environ.get('GITHUB_REPOSITORY') == 'dyKiU/mdk', 'owned-repository')
        need(os.environ.get('ARCHIVE_CPU_SCOPE') == 'existing-archive-cpu', 'exact-manual-scope')
        ref = os.environ['GITHUB_REF']
        need(ref.startswith('refs/heads/ci/upstream-develop-dy-') and os.environ['GITHUB_WORKFLOW_REF'] ==
             'dyKiU/mdk/.github/workflows/upstream-backend-probes.yml@' + ref, 'exact-tooling-workflow-ref')
        need(git(tooling, 'rev-parse', 'HEAD') == os.environ['GITHUB_SHA'] == os.environ['GITHUB_WORKFLOW_SHA'], 'exact-tooling-head')
        report['parser_controls'] = parser_controls()
        need('RUST_MIN_STACK' not in os.environ, 'no-stack-override')
        need(git(source, 'rev-parse', 'HEAD') == SOURCE and not git(source, 'status', '--porcelain'), 'exact-clean-source')
        need(not git(tooling, 'status', '--porcelain'), 'clean-tooling')
        report.update(tooling=git(tooling, 'rev-parse', 'HEAD'), tooling_tree=git(tooling, 'rev-parse', 'HEAD^{tree}'),
                      source_tree=git(source, 'rev-parse', 'HEAD^{tree}'),
                      source_lock_sha256=sha(source / 'Cargo.lock'),
                      source_nextest_sha256=sha(source / '.config/nextest.toml'),
                      controller_sha256=sha(Path(__file__)))
        run, artifact = api('actions/runs/' + str(PRODUCER)), api('actions/artifacts/' + str(ARTIFACT))
        need(run['head_sha'] == SOURCE and run['path'] == '.github/workflows/ci.yml', 'producer-identity')
        need(artifact['name'] == 'relay-runtime' and not artifact['expired'] and artifact['size_in_bytes'] == ZIP_SIZE
             and artifact['digest'] == 'sha256:' + ZIP_SHA and artifact['workflow_run']['id'] == PRODUCER
             and artifact['workflow_run']['head_sha'] == SOURCE, 'artifact-identity')
        report['artifact_digest_verified'] = False
        save()
        with tempfile.TemporaryDirectory(prefix='archive-cpu-', dir=os.environ['RUNNER_TEMP']) as temporary:
            temporary = Path(temporary)
            archive_zip, archive, perf_data = [temporary / name for name in ('artifact.zip', 'tests.tar.zst', 'perf.data')]
            with archive_zip.open('wb') as stream:
                subprocess.run(['gh', 'api', 'repos/dyKiU/mdk/actions/artifacts/' + str(ARTIFACT) + '/zip'], stdout=stream, stderr=subprocess.DEVNULL, check=True, timeout=120)
            need(archive_zip.stat().st_size == ZIP_SIZE and sha(archive_zip) == ZIP_SHA, 'archive-digest')
            with zipfile.ZipFile(archive_zip) as package:
                need(package.namelist() == ['tests.tar.zst'], 'sole-archive-member')
                info = package.getinfo('tests.tar.zst')
                need(0 < info.file_size <= 1024**3 and info.compress_type in (0, 8), 'archive-member-bound')
                with package.open(info) as member, archive.open('wb') as stream:
                    shutil.copyfileobj(member, stream, 1024 * 1024)
            report.update(artifact_digest_verified=True, archive_sha256=sha(archive), stage='inventory')
            os.chdir(source)
            common = ['--archive-file', str(archive), '--extract-to', str(source), '--workspace-remap', str(source)]
            code, raw, _, inventory_stderr = capture(
                ['cargo', 'nextest', 'list', *common, '--message-format', 'json', '-E', FILTER],
                180, separate=True)
            report['inventory_stdout_bytes'] = len(raw)
            report['inventory_stdout_sha256'] = hashlib.sha256(raw).hexdigest()
            report['inventory_stderr_bytes'] = len(inventory_stderr)
            report['inventory_stderr_sha256'] = hashlib.sha256(inventory_stderr).hexdigest()
            save()
            need(code == 0, 'archive-inventory-command')
            inventory = json.loads(raw)
            report['selected_nonignored'] = selected_case(inventory, TEST)
            suite = [s for s in inventory['rust-suites'].values() if TEST in s['testcases'] and s['testcases'][TEST]['filter-match']['status'] == 'matches']
            need(len(suite) == 1, 'one-suite')
            binary = Path(suite[0]['binary-path']).resolve()
            need(source in binary.parents and binary.is_file(), 'archive-binary-location')
            report['binary_sha256_before'] = sha(binary)
            report['elf_symbols'] = symbol_preflight(binary)
            perf = os.environ['ARCHIVE_PERF_BINARY']
            code, version, _, _ = capture([perf, '--version'], 15)
            need(code == 0 and re.fullmatch(rb'perf version [0-9A-Za-z.+_-]+\s*', version), 'perf-version')
            report['perf_version'] = version.decode().strip()
            code, _, _, _ = capture([perf, 'stat', '-e', 'cpu-clock:u', '--', 'true'], 15)
            if code != 0:
                old_paranoid = int(Path('/proc/sys/kernel/perf_event_paranoid').read_text().strip())
                need(-1 <= old_paranoid <= 10, 'paranoid-bounds')
                guard.write_text(str(old_paranoid))
                subprocess.run(['sudo', '-n', 'sysctl', '-w', 'kernel.perf_event_paranoid=1'], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=True, timeout=15)
                code, _, _, _ = capture([perf, 'stat', '-e', 'cpu-clock:u', '--', 'true'], 15)
            need(code == 0, 'perf-permission-unavailable-zero-bodies')
            report.update(perf_permission_ready=True, stage='body', product_bodies_started=1,
                          original_profile='ci', automatic_retries=0, test_threads=1, stack_override=False,
                          sampling_includes_setup_catchup_teardown=True, sampling_overhead_can_affect_verdict=True)
            save()
            command = [perf, 'record', '--quiet', '-e', 'cpu-clock:u', '-F', '49', '-o', str(perf_data), '--',
                       'cargo', 'nextest', 'run', *common, '--extract-overwrite', '--profile', 'ci', '--retries', '0',
                       '--test-threads', '1', '--no-fail-fast', '--success-output', 'immediate', '-E', FILTER]
            code, raw, seconds, _ = capture(command, 1200)
            report.update(body_exit_code=code, body_wall_seconds=seconds, body_raw_sha256=hashlib.sha256(raw).hexdigest(), body_raw_bytes=len(raw))
            save()  # Actual execution facts survive observer/parser exceptions.
            report['counts'] = counts(raw, 'offline')
            report['compiler'] = compiler(raw, {p.as_posix(): None for p in Path('crates').rglob('*.rs')})
            report['panic'] = panic_facts(raw, 'offline')
            save()
            report['offline_postverdict_observation'] = marker(raw)
            need(report['compiler']['header_count'] == 0, 'no-compiler-headers')
            need(perf_data.is_file() and 0 < perf_data.stat().st_size <= 128 * 1024**2, 'perf-data-bound')
            script_code, flat, _, stderr = capture([perf, 'script', '-i', str(perf_data), '-F', 'sym'], 60, separate=True)
            need(script_code == 0, 'flat-symbol-read')
            report['samples'] = sample_summary(flat)
            report['perf_script_warnings'] = script_warnings(stderr)
            report['sample_read_confident'] = not report['perf_script_warnings']['stderr_nonempty']
            report['collection_complete'] = report['samples']['sample_rows'] > 0 and report['sample_read_confident']
            report['sampled_cpu_is_not_complete_cpu_coverage'] = True
            report['stage'] = 'complete'
    except Exception as error:
        report['collection_error_class'] = type(error).__name__
        if isinstance(error, GuardError):
            report['guard_failure'] = str(error)
        # Exception text and child stdout are deliberately never exported.
    finally:
        if old_paranoid is not None:
            try:
                restored = subprocess.run(['sudo', '-n', 'sysctl', '-w', 'kernel.perf_event_paranoid=' + str(old_paranoid)], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=15).returncode == 0
            except Exception:
                restored = False
            report['perf_permission_restored'] = restored
            if restored:
                guard.unlink(missing_ok=True)
        report['source_tracked_pristine_after'] = git(source, 'rev-parse', 'HEAD') == SOURCE and not git(source, 'status', '--porcelain', '--untracked-files=no')
        report['tooling_pristine_after'] = not git(tooling, 'status', '--porcelain')
        report['binary_unchanged_after'] = binary is not None and binary.is_file() and sha(binary) == report.get('binary_sha256_before')
        save()
    return 0 if report['collection_complete'] and report['source_tracked_pristine_after'] and report['tooling_pristine_after'] and report['binary_unchanged_after'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
