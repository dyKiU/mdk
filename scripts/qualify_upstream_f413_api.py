#!/usr/bin/env python3
"""Fresh remote checks of reviewed f413 App-storage API adaptations; no integration qualification."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import qualify_upstream_639_merge as previous
import qualify_upstream_storage_boundary as storage
from upstream_extraction_cohort import frozen_inputs, workflow_identity

BASE = '1cc0109cb653ac6377f0dba3e4cfb987e84877f9'
UPSTREAM = 'f413e52c489d3500e18be60075524d3254c49b4a'
SELF = 'scripts/qualify_upstream_f413_api.py'
WORKFLOW = '.github/workflows/experimental-sync-ci.yml'
BRANCH = 'refs/heads/ci/upstream-f413-api-checks-20261018'
OUT = Path('f413-api-evidence')
BEGIN = '  # F413_API_JOBS_BEGIN\n'
END = '  # F413_API_JOBS_END\n'
OPTIONS = 'options: [f413-api-preflight, f413-api-controls, '
BOUNDARY = sorted(storage.TESTS + [storage.ADDED_TEST])
PAGING = ['app::account_projection::tests::' + name for name in [
    'app_messages_page_covers_old_history_and_same_second_ties',
    'app_messages_page_retains_raw_tombstones_and_filters_before_limit',
    'app_messages_page_resumes_after_encrypted_reopen_and_terminal_close',
    'app_messages_page_rejects_unbounded_and_invalid_inputs',
]]
PAIRED = ['app::timeline::tests::' + name for name in [
    'paired_ordinary_timeline_preserves_materialization_blocks_and_event_order',
    'paired_ordinary_timeline_hides_expired_payload_and_reply_before_sweep',
]]
ensure, digest, capture = storage.ensure, storage.digest, storage.capture


def untracked_evidence_only():
    names = set(subprocess.check_output(['git', 'ls-files', '--others', '--exclude-standard', '-z']).decode().strip('\0').split('\0')) - {''}
    return names <= {'f413-api-evidence/result.json', 'f413-api-evidence/audit-output.txt'}


def static_checks(cohort, production, report):
    # Extend only the reviewed delegation's package argument. Its strict JSON
    # artifact/feature/production checks otherwise run unchanged.
    original = previous.PACKAGES
    ensure(original == ['marmot-app', 'transport-nostr', 'transport-nostr-adapter', 'storage-sqlite'],
           'exact-historical-static-delegate-package-set')
    try:
        previous.PACKAGES = original + ['cgka-engine']
        previous.static_checks(cohort, production, report)
        report['static']['reviewed_package_extension'] = ['cgka-engine']
        report['static']['historical_strict_checks_preserved'] = True
    finally:
        previous.PACKAGES = original


def source_guard():
    source = subprocess.check_output(['git', 'rev-parse', 'HEAD'], text=True).strip()
    remote = workflow_identity(source)
    ensure(remote.get('event') == 'workflow_dispatch' and os.environ.get('GITHUB_REF') == BRANCH
           and os.environ.get('GITHUB_WORKFLOW_REF') == 'dyKiU/mdk/' + WORKFLOW + '@' + BRANCH,
           'exact-isolated-remote-workflow-and-branch')
    subprocess.run(['git', 'merge-base', '--is-ancestor', BASE, source], check=True)
    subprocess.run(['git', 'merge-base', '--is-ancestor', UPSTREAM, BASE], check=True)
    ensure(subprocess.run(['git', 'diff', '--quiet', 'HEAD']).returncode == 0 and untracked_evidence_only(),
           'initial-tracked-inputs-pristine-and-no-untracked-source-overlay')
    ensure(subprocess.check_output(['git', 'rev-parse', '--show-object-format'], text=True).strip() == 'sha1', 'explicit-blob-format')
    baseline = {}
    for entry in subprocess.check_output(['git', 'ls-tree', '-r', '-z', BASE]).split(b'\0'):
        if not entry:
            continue
        header, name = entry.split(b'\t', 1)
        mode, kind, blob = header.decode().split()
        ensure(kind == 'blob' and mode in {'100644', '100755', '120000'}, 'ordinary-reviewed-input-tree')
        baseline[os.fsdecode(name)] = (mode, blob)
    frozen = frozen_inputs()
    ensure(SELF not in baseline and set(frozen) == set(baseline) | {SELF}, 'whole-tracked-inventory-exact')
    ensure(frozen[SELF]['mode'] == '100644' and frozen[SELF]['actual_executable'] is False
           and not Path(SELF).is_symlink(), 'ordinary-new-controller-mode')
    for name, (mode, blob) in baseline.items():
        row = frozen[name]
        ensure(row['mode'] == mode and (mode == '120000' or row['actual_executable'] == (mode == '100755')),
               'whole-input-layout:' + name)
        data = os.fsencode(os.readlink(name)) if mode == '120000' else Path(name).read_bytes()
        if name == WORKFLOW:
            text = data.decode()
            ensure(text.count(BEGIN) == text.count(END) == text.count(OPTIONS) == 1, 'one-exact-isolated-workflow-overlay')
            before, rest = text.split(BEGIN)
            _, after = rest.split(END)
            data = (before + after).replace(OPTIONS, 'options: [', 1).encode()
        actual = hashlib.sha1(b'blob ' + str(len(data)).encode() + b'\0' + data).hexdigest()
        ensure(actual == blob, 'entire-baseline-inputs-after-explicit-metadata-only-overlay:' + name)
    environment = {'CARGO_INCREMENTAL': '1', 'CARGO_BUILD_JOBS': '2', 'CARGO_PROFILE_DEV_DEBUG': '0',
                   'CARGO_PROFILE_TEST_DEBUG': '0', 'RUST_MIN_STACK': '4194304'}
    ensure(all(os.environ.get(key) == value for key, value in environment.items()), 'exact-remote-build-environment')
    ensure(all(not os.environ.get(key) for key in ['RUSTFLAGS', 'CARGO_ENCODED_RUSTFLAGS', 'RUSTDOCFLAGS',
               'CARGO_ENCODED_RUSTDOCFLAGS', 'RUSTC_BOOTSTRAP', 'CARGO_PROFILE_DEV_OPT_LEVEL',
               'CARGO_PROFILE_TEST_OPT_LEVEL']), 'no-compiler-or-profile-overrides')
    return {'source': source, 'baseline': BASE, 'incoming_upstream': UPSTREAM,
            'workflow_identity': remote, 'whole_baseline_content_and_modes_exact': True,
            'historical_639_controllers_and_jobs_unchanged': True, 'metadata_overlay': [SELF, WORKFLOW],
            'environment': environment, 'historical_archive_or_mutation_evidence_reused': False}


def paired_parser_controls():
    name = PAIRED[0]
    raw = 'running 1 test\ntest ' + name + ' ... ok\ntest result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 5 filtered out; finished in 0.1s\n'
    ensure(previous.parse_runtime(raw, 0, name)['passed_gate'], 'paired-exact-runtime-parser-positive')
    negatives = [raw.replace(name, 'foreign::case'), raw.replace('1 passed', '0 passed'),
                 raw.replace('0 ignored', '1 ignored'), raw.replace('0 measured', '1 measured'),
                 raw + raw, raw + '\nthread child panicked at crates/private.rs:1:1:\n',
                 raw + '\nerror[E0001]: compiler failure\n', 'error: failed to compile\n']
    for value in negatives:
        ensure(not previous.parse_runtime(value, 0, name)['passed_gate'], 'paired-unrelated-or-incomplete-runtime-rejected')
    ensure(not previous.parse_runtime(raw, 101, name)['passed_gate'], 'paired-runtime-nonzero-rejected')
    return {'positive': 1, 'negative': len(negatives) + 1, 'actual_runtime_bodies': 0}


def compile_storage(cohort, frozen, phase, save):
    ensure(frozen_inputs() == frozen, 'exact-inputs-before-storage-compilation')
    command = ['cargo', 'test', '--locked', '-p', 'storage-sqlite', '--lib', '--no-run', '--message-format=json']
    features = [] if cohort == 'default' else ['experimental-device-sync']
    if features:
        command += ['--features', features[0]]
    code, raw, seconds = capture(command, 1800)
    events = [json.loads(line) for line in raw.splitlines() if line.startswith('{')]
    errors = [event for event in events if event.get('reason') == 'compiler-message'
              and event.get('message', {}).get('level') == 'error']
    artifacts = [event for event in events if event.get('reason') == 'compiler-artifact']
    selected = [event for event in artifacts if event['target']['name'] == 'storage_sqlite'
                and event['target']['kind'] == ['lib'] and event['profile']['test'] and event.get('executable')]
    phase['compilation'] = {'exit_code': code, 'compiler_error_count': len(errors), 'wall_seconds': seconds,
                            'succeeded': False, 'command': command, 'selected_test_artifact_count': len(selected),
                            'safe_compiler_diagnostics': [storage.safe_compiler_diagnostic(event, frozen) for event in errors[:64]],
                            'diagnostics_truncated': len(errors) > 64}
    save()
    ensure(code == len(errors) == 0 and len(selected) == 1
           and sorted(selected[0]['features']) == features, 'storage-must-compile-in-exact-feature-cohort')
    binary = Path(selected[0]['executable'])
    fingerprints = sorted([{'package': event['package_id'], 'target': event['target']['name'],
                            'kind': event['target']['kind'], 'features': sorted(event['features']), 'profile': event['profile']}
                           for event in artifacts], key=lambda event: json.dumps(event, sort_keys=True))
    phase['compilation'].update(succeeded=True, compiled_features=features, binary_sha256=digest(binary.read_bytes()),
                                compiler_artifact_feature_manifest_sha256=digest(json.dumps(fingerprints, sort_keys=True).encode()))
    ensure(frozen_inputs() == frozen, 'exact-inputs-after-storage-compilation')
    return binary


def runtime(cohort, report, frozen, save):
    phase = {'bodies': {}}
    report['runtime'] = phase
    binary = compile_storage(cohort, frozen, phase, save)
    sha = phase['compilation']['binary_sha256']
    selected = BOUNDARY + PAGING + (PAIRED if cohort == 'experimental' else [])
    phase['expected_names'] = selected
    phase['paired_cases_cfg_disabled'] = PAIRED if cohort == 'default' else []
    for name in (PAIRED if cohort == 'default' else []):
        code, raw, _ = capture([str(binary), name, '--exact', '--list', '--format', 'terse'], 60)
        ensure(code == 0 and raw.strip() in {'', '0 tests, 0 benchmarks'}, 'paired-tests-absent-only-in-default-feature-cohort')
    for name in selected:
        code, raw, _ = capture([str(binary), name, '--exact', '--list', '--format', 'terse'], 60)
        lines = [line for line in raw.splitlines() if line]
        ensure(code == 0 and lines.count(name + ': test') == 1
               and all(line in {name + ': test', '1 test, 0 benchmarks'} for line in lines), 'one-exact-selected-runtime-case')
        code, raw, _ = capture([str(binary), name, '--exact', '--ignored', '--list', '--format', 'terse'], 60)
        ensure(code == 0 and raw.strip() in {'', '0 tests, 0 benchmarks'}, 'selected-runtime-case-not-ignored')
        ensure(frozen_inputs() == frozen and untracked_evidence_only() and digest(binary.read_bytes()) == sha, 'source-binary-exact-before-runtime')
        code, raw, seconds = capture([str(binary), name, '--exact', '--nocapture', '--test-threads=1'], 300)
        row = storage.parse_body(raw, code, name) if name in BOUNDARY else previous.parse_runtime(raw, code, name)
        phase['bodies'][name] = dict(row, wall_seconds=seconds, binary_sha256=sha)
        save()
        ensure(frozen_inputs() == frozen and untracked_evidence_only() and digest(binary.read_bytes()) == sha, 'source-binary-exact-after-runtime')
    rows = list(phase['bodies'].values())
    phase['actual_counts_complete'] = len(rows) == len(selected) and all(row.get('actual_counts_complete') is True for row in rows)
    phase['all_runtime_passed'] = phase['actual_counts_complete'] and all(row.get('passed_gate') is True for row in rows)
    ensure(phase['all_runtime_passed'], 'fresh-storage-boundaries-and-paired-timeline-cases-required')


def dependency_audit(report, frozen, save):
    command = ['cargo', '--locked', 'audit']
    lock = Path('Cargo.lock').read_bytes()
    config = Path('.cargo/audit.toml').read_bytes()
    ensure(re.findall(rb'(?m)^ignore = (.+)$', config) == [b'["RUSTSEC-2024-0384"]'],
           'unchanged-single-instant-notice-ignore-only')
    code, version, _ = capture(['cargo', 'audit', '--version'], 60, limit=4096)
    ensure(code == 0 and len(version.strip()) < 128 and re.fullmatch(r'[A-Za-z0-9_. -]*0\.22\.1', version.strip()) is not None,
           'actual-pinned-cargo-audit-version')
    report['audit'] = {'command': command, 'tool_version': version.strip(), 'lock_sha256': digest(lock),
                       'config_sha256': digest(config), 'ignored_advisories': ['RUSTSEC-2024-0384'],
                       'audit_passed': False, 'scope': 'entire-locked-dependency-graph'}
    save()
    code, raw, seconds = capture(command, 600, limit=1024 * 1024)
    output = OUT / 'audit-output.txt'
    output.write_text(raw)
    report['audit'].update(exit_code=code, seconds=seconds, output_file=str(output),
                           output_sha256=digest(output.read_bytes()), output_bytes=output.stat().st_size,
                           exact_lock_restored_or_unchanged=Path('Cargo.lock').read_bytes() == lock)
    report['audit']['audit_passed'] = code == 0 and frozen_inputs() == frozen and untracked_evidence_only()
    save(); ensure(report['audit']['audit_passed'], 'actual-locked-dependency-audit-required')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--mode', choices=['preflight', 'runtime', 'static', 'production', 'audit'], required=True)
    parser.add_argument('--cohort', choices=['default', 'experimental'], default='experimental')
    args = parser.parse_args()
    os.umask(0o077); OUT.mkdir(exist_ok=True)
    report = {'mode': args.mode, 'cohort': None if args.mode == 'audit' else args.cohort, 'qualification_passed': False,
              'focused_checks_passed': False, 'mutation_necessity_claim': False, 'native_acceptance_claim': False,
              'delegation': ['qualify_upstream_storage_boundary.safe_compiler_diagnostic',
                             'qualify_upstream_storage_boundary.parse_body',
                             'qualify_upstream_639_merge.parse_runtime', 'qualify_upstream_639_merge.static_checks'],
              'historical_source_guards_invoked_or_weakened': False}
    frozen = frozen_inputs()
    report['input_manifest_sha256'] = digest(json.dumps(frozen, sort_keys=True, separators=(',', ':')).encode())
    def save():
        (OUT / 'result.json').write_text(json.dumps(report, indent=2) + '\n')
    try:
        report['source_guard'] = source_guard()
        report['toolchain'] = {name: subprocess.check_output([name, '--version'], text=True).strip() for name in ['cargo', 'rustc']}
        report['parser_controls'] = {'boundary': storage.parser_preflight(), 'compiler': storage.diagnostic_parser_preflight(),
                                    'paired_timeline': paired_parser_controls()}
        save()
        if args.mode == 'preflight':
            report['preflight_passed'] = True
        elif args.mode == 'runtime':
            runtime(args.cohort, report, frozen, save)
            report['focused_checks_passed'] = True
        elif args.mode == 'audit':
            dependency_audit(report, frozen, save)
            report['focused_checks_passed'] = True
        else:
            static_checks(args.cohort, args.mode == 'production', report)
            report['focused_checks_passed'] = True
    except Exception as error:
        report['failure_type'] = type(error).__name__
        report['failure_gate'] = str(error) if isinstance(error, storage.GateFailure) else None
        raise SystemExit(1)
    finally:
        report['inputs_pristine'] = frozen_inputs() == frozen and untracked_evidence_only() and subprocess.run(['git', 'diff', '--quiet', 'HEAD']).returncode == 0
        rows = list(report.get('runtime', {}).get('bodies', {}).values())
        report['actual_counts_complete'] = bool(rows) and all(row.get('actual_counts_complete') is True for row in rows)
        report['actual_executed_nonignored'] = sum(row['executed_nonignored'] for row in rows) if report['actual_counts_complete'] else None
        for key in ['passed', 'failed', 'ignored']:
            report['actual_' + key] = sum(row[key] for row in rows) if report['actual_counts_complete'] else None
        report['focused_checks_passed'] = bool(report['focused_checks_passed'] and report['inputs_pristine'])
        save()
        ensure(report['inputs_pristine'], 'final-source-and-modes-pristine')


if __name__ == '__main__':
    main()
