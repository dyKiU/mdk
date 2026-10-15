"""Scoped host/component checks; never build or package an Apple/Android SDK."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import tempfile
import time


def require(value, label):
    if not value:
        raise ValueError(label)


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--scope', choices=('default', 'experimental', 'default-remaining', 'experimental-remaining',
                                          'profile', 'static', 'generate', 'verify-generated', 'swift', 'kotlin'), required=True)
    scope = parser.parse_args().scope
    require(os.environ.get('GITHUB_ACTIONS') == 'true', 'remote-ci-only')
    output = Path('peer-projection-proof')
    output.mkdir()
    source = subprocess.check_output(['git', 'rev-parse', 'HEAD'], text=True).strip()
    require(source == os.environ['GITHUB_SHA'], 'exact-source-required')
    report = {'source': source, 'tree': subprocess.check_output(['git', 'rev-parse', 'HEAD^{tree}'], text=True).strip(),
              'scope': scope, 'commands': [], 'runtime': [], 'passed': False,
              'sdk_packaging_executed': False, 'rust_min_stack': os.environ.get('RUST_MIN_STACK')}
    report['compiler_environment'] = {name: os.environ.get(name) for name in (
        'CARGO_INCREMENTAL', 'CARGO_BUILD_JOBS', 'CARGO_PROFILE_DEV_DEBUG', 'CARGO_PROFILE_TEST_DEBUG',
        'CARGO_PROFILE_RELEASE_DEBUG', 'RUSTFLAGS', 'CARGO_ENCODED_RUSTFLAGS', 'RUSTC_BOOTSTRAP')}
    require(os.environ.get('CARGO_INCREMENTAL') == '1' and os.environ.get('RUST_MIN_STACK') == '4194304',
            'original-incremental-and-stack-required')
    require(not any(os.environ.get(name) for name in ('RUSTFLAGS', 'CARGO_ENCODED_RUSTFLAGS', 'RUSTC_BOOTSTRAP')),
            'no-global-compiler-overrides')
    report['rustc'] = subprocess.check_output(['rustc', '-Vv'], text=True).strip()
    report['cargo'] = subprocess.check_output(['cargo', '-V'], text=True).strip()
    report['configuration_hashes'] = {name: sha(name) for name in (
        'Cargo.lock', 'Cargo.toml', 'rust-toolchain.toml', '.cargo/config.toml', '.config/nextest.toml') if Path(name).is_file()}
    generated = {'crates/marmot-c/include/marmot.h', 'crates/marmot-c/API-REFERENCE.md',
                 'crates/marmot-uniffi/API-REFERENCE.md'}
    tracked = subprocess.check_output(['git', 'ls-files', '-z']).decode().split('\0')
    frozen = {name: sha(name) for name in tracked if name and Path(name).is_file()}

    def save():
        (output / 'result.json').write_text(json.dumps(report, indent=2) + '\n')

    def command(name, argv, environment=None, public=False):
        started = time.monotonic()
        with tempfile.TemporaryDirectory(prefix='peer-projection-private-') as private:
            path = Path(private) / 'command.log'
            errors = Path(private) / 'stderr.log'
            with path.open('x') as stream, errors.open('x') as error_stream:
                process = subprocess.run(argv, stdout=stream, stderr=error_stream,
                    timeout=3600, env=dict(os.environ, **(environment or {})))
            stdout, stderr = path.read_bytes(), errors.read_bytes()
            text = stdout.decode(errors='replace') + '\n' + stderr.decode(errors='replace')
        row = {'name': name, 'argv': argv, 'exit_code': process.returncode,
               'compile_and_execution_seconds': round(time.monotonic() - started, 3),
               'stdout_sha256': hashlib.sha256(stdout).hexdigest(),
               'compiler_stderr_sha256': hashlib.sha256(stderr).hexdigest(),
               'rust_error_codes': sorted(set(re.findall(r'error\[(E[0-9]+)\]', text)))}
        if environment:
            row['command_environment_overrides'] = environment
        if process.returncode and not re.search(r'(?m)^running [0-9]+ tests?$', text):
            row['preexecution_category'] = ('rust-compiler-error' if row['rust_error_codes'] else
                'cargo-feature-selection' if 'features' in text and re.search(r'(?m)^error:', text) else
                'cargo-or-tool-preexecution-failure')
        report['commands'].append(row)
        if public:
            print(text[-16000:], flush=True)
        save()
        return row, text

    features = ['marmot-app/test-policy-overrides', 'cgka-engine/test-policy-overrides', 'cgka-engine/test-crash-hooks']

    def test(name, package, selector, extra=()):
        exporter = package if package in ('marmot-app', 'marmot-uniffi', 'marmot-c') else 'marmot-app'
        selected_features = [exporter + '/otlp-export', exporter + '/product-analytics-export']
        # Boundary DTO/deep-free controls do not use App test hooks. Cargo's
        # selected C package has no direct App/Engine dependency feature path.
        if package not in ('marmot-uniffi', 'marmot-c'):
            selected_features += features
        if package == 'marmot-c':
            selected_features.append('marmot-c/alloc-audit')
        if scope.startswith('experimental'):
            selected_features.append(exporter + '/experimental-device-sync')
        row, text = command(name, ['cargo', 'test', '--locked', '-p', package, *extra,
            '--features', ','.join(selected_features), selector, '--', '--nocapture', '--test-threads=1'])
        summaries = re.findall(r'test result: (ok|FAILED)\. (\d+) passed; (\d+) failed; (\d+) ignored;', text)
        names = re.findall(r'(?m)^test ([^\s]+) \.\.\.', text)
        row['actual_case_names'] = names
        require(len(names) == 1 and (names[0] == selector or names[0].endswith('::' + selector)),
                'actual-exact-selected-runtime-case-required')
        require(len(summaries) == 1 and re.search(r'(?m)^running 1 test$', text), 'one-nonignored-runtime-body-required')
        _, passed, failed, ignored = summaries[0]
        row.update(passed_count=int(passed), failed_count=int(failed), ignored_count=int(ignored))
        row['panic_locations'] = re.findall(r'panicked at (crates/[^:\n]+\.rs:\d+:\d+)', text)
        report['runtime'].append(row)
        save()
        require(row['exit_code'] == 0 and (int(passed), int(failed), int(ignored)) == (1, 0, 0), 'actual-runtime-control-failed')

    save()
    try:
        if scope in ('default', 'experimental', 'default-remaining', 'experimental-remaining'):
            if not scope.endswith('-remaining'):
                test('uniffi-peer-redaction', 'marmot-uniffi',
                     'existing_account_direct_conversation_ffi_keeps_paired_provenance_and_redacts_debug', ['--lib'])
            test('c-direct-deep-free', 'marmot-c',
                 'existing_account_direct_conversation_deep_free_preserves_both_route_tags', ['--lib'])
            test('c-window-deep-free', 'marmot-c',
                 'paired_window_snapshot_deep_free_releases_header_rows_and_cursor', ['--lib'])
            if scope.startswith('experimental'):
                test('core-peer-and-legacy-unknown', 'marmot-app',
                     'paired_summary_keeps_source_attested_peer_and_preserves_unknown_legacy_peer', ['--lib'])
                test('genuine-both-directions-direct-reuse', 'marmot-app',
                     'one_scan_direct_contact_reuses_source_chat_without_another_peer_invitation', ['--lib'])
        elif scope == 'profile':
            for selector in ('public_app_08_concurrent_admin_profile_edits_are_never_lost',
                             'public_app_07_two_groups_stay_isolated'):
                test(selector, 'cgka-conformance-simulator', selector, ['--test', 'app_runtime_interaction_journeys'])
        elif scope == 'static':
            checks = [
                ('format', ['cargo', 'fmt', '--all', '--check']),
                ('default-components', ['cargo', 'check', '--locked', '-p', 'marmot-app', '-p', 'marmot-uniffi', '-p', 'marmot-c']),
                ('strict-components', ['cargo', 'clippy', '--locked', '-p', 'marmot-app', '-p', 'marmot-uniffi',
                    '-p', 'marmot-c', '-p', 'cgka-conformance-simulator', '--all-targets', '--features',
                    ','.join(features + ['marmot-c/alloc-audit', 'marmot-c/experimental-device-sync',
                                        'marmot-c/otlp-export', 'marmot-c/product-analytics-export']), '--', '-D', 'warnings']),
            ]
            for name, argv in checks:
                row, _ = command(name, argv, public=True)
                require(row['exit_code'] == 0, 'component-static-failed')
        elif scope in ('generate', 'verify-generated'):
            row, _ = command('generate-current-header', ['cbindgen', '--config', 'crates/marmot-c/cbindgen.toml',
                '--crate', 'marmot-c', '--output', 'crates/marmot-c/include/marmot.h', 'crates/marmot-c'],
                {'RUSTC_BOOTSTRAP': '1'}, public=True)
            require(row['exit_code'] == 0, 'header-generation-failed')
            for name, argv in [('refresh-docs', ['python3', 'scripts/check_binding_docs.py', '--write']),
                ('binding-docs', ['python3', 'scripts/check_binding_docs.py']),
                ('binding-doc-regressions', ['python3', 'scripts/test_check_binding_docs.py']),
                ('binding-parity', ['python3', 'scripts/check_c_binding_parity.py'])]:
                row, _ = command(name, argv, public=True)
                require(row['exit_code'] == 0, 'generated-surface-gate-failed')
            changed = subprocess.check_output(['git', 'diff', '--name-only'], text=True).splitlines()
            require(set(changed) <= generated, 'unexpected-generated-output-path')
            require(not changed if scope == 'verify-generated' else bool(changed), 'generated-output-cleanliness-mismatch')
            patch = subprocess.check_output(['git', 'diff', '--binary', '--', *sorted(generated)])
            (output / 'generated.patch').write_bytes(patch)
            report['generated'] = {'paths': changed, 'patch_sha256': hashlib.sha256(patch).hexdigest(),
                'patch_bytes': len(patch), 'files': {name: sha(name) for name in changed},
                'base_files': {name: frozen[name] for name in changed}}
        else:
            require(not os.environ.get('RUSTFLAGS') and not os.environ.get('CARGO_ENCODED_RUSTFLAGS'), 'no-compiler-override')
            row, version = command('host-compiler-version', ['swiftc', '--version'] if scope == 'swift' else ['kotlinc', '-version'], public=True)
            require(row['exit_code'] == 0, 'host-compiler-unavailable')
            report['host_compiler_version'] = version.strip()
            if scope == 'kotlin':
                dependency_record = Path(os.environ['RUNNER_TEMP']) / 'peer-kotlin/dependencies.json'
                (output / 'host-dependencies.json').write_bytes(dependency_record.read_bytes())
            # The repository recipe builds the exact host library, generates
            # language bindings from it and executes the pinned DTO program.
            row, _ = command(scope + '-host-smoke', ['bash', 'crates/marmot-uniffi/chat-projections-smoke.sh', scope], public=True)
            require(row['exit_code'] == 0, 'actual-language-program-failed')
            suffix = 'dylib' if scope == 'swift' else 'so'
            library = Path('target/debug/libmarmot_uniffi.' + suffix)
            fixture = Path('crates/marmot-uniffi/tests/chat_projections_smoke.' + ('swift' if scope == 'swift' else 'kt'))
            report['host_smoke'] = {'program_executed': True, 'exit_code': 0, 'fixture_sha256': sha(fixture),
                'host_library_sha256': sha(library), 'scope': 'DTO None/Some and paired-header lift/lower; no SDK/device acceptance'}
        report['source_unchanged'] = all(sha(name) == value for name, value in frozen.items()
                                       if scope not in ('generate', 'verify-generated') or name not in generated)
        report['lock_sha256_after'] = sha('Cargo.lock')
        require(report['source_unchanged'], 'unexpected-tracked-source-drift')
        report['passed'] = True
    except (ValueError, OSError, KeyError, subprocess.SubprocessError) as error:
        report['failure_category'] = type(error).__name__
        if isinstance(error, ValueError) and re.fullmatch('[a-z-]+', str(error)):
            report['failure_stage'] = str(error)
    finally:
        save()
    require(report['passed'], 'peer-projection-scope-failed')


if __name__ == '__main__':
    main()
