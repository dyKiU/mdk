#!/usr/bin/env python3
"""Scoped remote-only baseline qualification for reconciled private fixes."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import tempfile
import time

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('--scope', choices=('cli-default-red', 'cli-experimental-red', 'cli-default-green', 'cli-experimental-green', 'revocation-baseline'), required=True)
args = parser.parse_args()
if os.environ.get('GITHUB_ACTIONS') != 'true':
    raise SystemExit('This qualification runs only through remote GitHub Actions')
os.umask(0o077)
output = Path('private-fix-proof')
output.mkdir(mode=0o700)
report = {'source': subprocess.check_output(['git', 'rev-parse', 'HEAD'], text=True).strip(),
          'scope': args.scope, 'executions': [], 'passed': False,
          'rust_min_stack': os.environ.get('RUST_MIN_STACK'), 'retries': 0}
report['required_executions'] = 12 if args.scope.endswith('-green') else (6 if args.scope == 'revocation-baseline' else 1)
report['baseline'] = '87c992d1ffa478c477b6841e33f1680768dfe329'
report['tree'] = subprocess.check_output(['git', 'rev-parse', 'HEAD^{tree}'], text=True).strip()
report['lock_sha256'] = hashlib.sha256(Path('Cargo.lock').read_bytes()).hexdigest()
report['toolchain'] = subprocess.check_output(['rustc', '-Vv'], text=True)
report['config_sha256'] = hashlib.sha256(Path('.config/nextest.toml').read_bytes()).hexdigest()


def source_hashes():
    paths = subprocess.check_output([
        'git', 'ls-files', 'crates/cli/src', 'crates/cli/tests',
        'crates/marmot-app/src/client/private_settlement.rs',
        'crates/marmot-app/src/client/private_transport.rs',
        'crates/marmot-app/src/runtime/account_worker.rs',
        'crates/marmot-app/src/selected_chat_copy/tests.rs',
        'crates/cgka-engine/src/openmls_projection.rs',
        'crates/storage-sqlite/src/connection.rs', 'crates/traits/src/storage.rs',
        'Cargo.lock', 'Cargo.toml', 'rust-toolchain.toml', '.config/nextest.toml',
    ], text=True).splitlines()
    return {name: hashlib.sha256(Path(name).read_bytes()).hexdigest() for name in paths}


FROZEN_SOURCE = source_hashes()
report['frozen_inputs'] = FROZEN_SOURCE


def save():
    (output / 'result.json').write_text(json.dumps(report, indent=2) + '\n')


def execute(test, package, features, expected, unit=False):
    command = ['cargo', 'test', '--locked', '-p', package,
               *(['--lib'] if unit else ['--test', 'cli'])] if package == 'wn-cli' else ['cargo', 'test', '--locked', '-p', package, '--lib']
    command += ['--features', features, test, '--', '--exact', '--nocapture', '--test-threads=1']
    row = {'test': test, 'command': command, 'expected': expected, 'qualified': False}
    report['executions'].append(row)
    save()
    with tempfile.TemporaryFile(mode='w+') as log:
        started = time.monotonic()
        result = subprocess.run(command, stdout=log, stderr=subprocess.STDOUT, timeout=2400)
        row['seconds'] = round(time.monotonic() - started, 3)
        row['exit_code'] = result.returncode
        log.seek(0)
        text = log.read()
    row['panic_locations'] = [{'file': name, 'line': int(line)}
                              for name, line in re.findall(r'panicked at ([^\n]+):(\d+):\d+:', text)]
    row['compiler_error_codes'] = sorted(set(re.findall(r'error\[(E\d+)\]', text)))
    summaries = re.findall(r'test result: (ok|FAILED)\. (\d+) passed; (\d+) failed; (\d+) ignored;', text)
    durations = re.findall(r'test result: (?:ok|FAILED)\.[^\n]*; finished in ([0-9.]+)s', text)
    row['runtime_seconds'] = float(durations[0]) if len(durations) == 1 else None
    row['command_seconds_include_compilation'] = True
    row['runtime_counts_available'] = len(summaries) == 1
    if len(summaries) == 1:
        _, passed, failed, ignored = summaries[0]
        row.update(passed=int(passed), failed=int(failed), ignored=int(ignored))
    one_body = (row.get('passed', 0) + row.get('failed', 0) == 1
                and row.get('ignored') == 0 and re.search(r'^running 1 test$', text, re.M)
                and re.search(r'^test ' + re.escape(test) + r' \.\.\.', text, re.M))
    if expected == 'readiness-budget-red':
        panics = re.findall(r'panicked at ([^\n]+):(\d+):\d+:\n([^\n]*)', text)
        source_lines = Path('crates/cli/src/commands/stream.rs').read_text().splitlines()
        intended = (len(panics) == 1 and panics[0][0] == 'crates/cli/src/commands/stream.rs'
                    and source_lines[int(panics[0][1]) - 1].strip() == 'assert_eq!(calls, 3);'
                    and panics[0][2].startswith('assertion `left == right` failed'))
        row['intended_runtime_failure'] = bool(intended)
        row['qualified'] = bool(one_body and result.returncode == 101 and row.get('failed') == 1 and intended)
    elif expected == 'foreign-author-red':
        panics = re.findall(r'panicked at ([^\n]+):(\d+):\d+:\n([^\n]*)', text)
        intended = (len(panics) == 1 and panics[0][0] == 'crates/cli/tests/cli.rs'
                    and panics[0][2] == 'wn unexpectedly succeeded'
                    and '"foreign publisher"' in text)
        row['intended_runtime_failure'] = bool(intended)
        row['qualified'] = bool(one_body and result.returncode == 101 and row.get('failed') == 1 and intended)
    else:
        row['qualified'] = bool(one_body and result.returncode == 0 and row.get('passed') == 1)
    row['log_sha256'] = hashlib.sha256(text.encode()).hexdigest()
    save()
    print(json.dumps(row, sort_keys=True), flush=True)
    return row['qualified']


try:
    allowed = {'crates/cli/src/commands/stream.rs', 'crates/cli/README.md', 'crates/cli/CHANGELOG.md',
               'crates/cli/tests/cli.rs', '.github/workflows/upstream-private-fix-reconciliation.yml',
               'scripts/qualify_upstream_private_fixes.py'}
    changed = set(subprocess.check_output(['git', 'diff', '--name-only', report['baseline'], 'HEAD'], text=True).splitlines())
    if not changed.issubset(allowed):
        raise ValueError('Baseline source includes unreviewed production or configuration changes')
    if subprocess.check_output(['git', 'diff', 'HEAD', '--name-only'], text=True).strip():
        raise ValueError('Baseline source is not pristine')
    report['changed_paths'] = sorted(changed)
    outcomes = []
    if args.scope.startswith('cli-'):
        features = 'wn-cli/test-policy-overrides'
        if args.scope.startswith('cli-experimental-'):
            features += ',marmot-app/experimental-device-sync'
        integration = 'stream_start_quic_chunks_and_final_payload_verify_through_mls_messages'
        if args.scope.endswith('-red'):
            outcomes.append(execute(integration, 'wn-cli', features, 'foreign-author-red'))
        else:
            for name in (
                integration,
                'stream_send_and_receive_show_quic_text_content',
                'stream_send_insecure_local_rejects_remote_endpoints',
                'stream_send_rejects_non_public_endpoints_without_insecure_local',
            ):
                outcomes.append(execute(name, 'wn-cli', features, 'green'))
            prefix = 'commands::stream::tests::'
            for name in (
                'stream_reads_retry_typed_contention_without_repeating_success',
                'stream_reads_preserve_non_transient_failure_without_retry',
                'stream_reads_return_the_last_busy_error_after_bounded_attempts',
                'stream_reads_recognize_engine_wrapped_storage_contention',
            ):
                outcomes.append(execute(prefix + name, 'wn-cli', features, 'green', unit=True))
            if all(outcomes):
                source = Path('crates/cli/src/commands/stream.rs')
                original = source.read_bytes()
                original_text = original.decode()
                author_guard = '''            if message.sender != account.account_id_hex {
                if explicit {
                    return Err(WnError::NotMessageAuthor {
                        message_id: start_message_id_hex.to_owned(),
                    });
                }
                continue;
            }
'''
                bypass = '''            if message.sender != account.account_id_hex && !explicit {
                continue;
            }
'''
                if original_text.count(author_guard) != 1 or original_text.count('attempt < 2 && stream_storage_is_busy(&error)') != 1:
                    raise ValueError('Mutation anchors are not unique in exact candidate source')
                for label, mutated, test, expected, unit in (
                    ('omit-author-guard', original_text.replace(author_guard, bypass, 1),
                     integration, 'foreign-author-red', False),
                    ('shorten-busy-read-budget', original_text.replace('attempt < 2 && stream_storage_is_busy(&error)',
                     'attempt < 1 && stream_storage_is_busy(&error)', 1),
                     prefix + 'stream_reads_return_the_last_busy_error_after_bounded_attempts',
                     'readiness-budget-red', True),
                ):
                    mutation = {'label': label, 'baseline_sha256': hashlib.sha256(original).hexdigest(),
                                'mutated_sha256': hashlib.sha256(mutated.encode()).hexdigest()}
                    report.setdefault('mutations', []).append(mutation)
                    try:
                        source.write_text(mutated)
                        detected = execute(test, 'wn-cli', features, expected, unit=unit)
                        outcomes.append(detected)
                        mutation['runtime_detected'] = detected
                    finally:
                        source.write_bytes(original)
                        mutation['exact_source_restored'] = source.read_bytes() == original
                        save()
                    restored = execute(test, 'wn-cli', features, 'green', unit=unit)
                    outcomes.append(restored)
                    mutation['restored_control_passed'] = restored
                    save()
                    if not detected or not restored:
                        break
    else:
        features = ','.join(('marmot-app/otlp-export', 'marmot-app/product-analytics-export',
                             'marmot-app/test-policy-overrides', 'marmot-app/experimental-device-sync',
                             'cgka-engine/test-policy-overrides', 'cgka-engine/test-crash-hooks'))
        for name in (
            'device_revocation_original_receipt_survives_incoming_storage_rollback_retry',
            'device_revocation_challenge_published_before_storage_retry_preserves_fresh_authority',
            'device_revocation_challenge_initial_peel_before_storage_retry_preserves_fresh_authority',
            'device_revocation_confirmation_fact_rollback_preserves_owned_successor_authority',
            'device_revocation_survivors_regain_fresh_original_history_authority',
            'device_revocation_retained_remove_cannot_restore_positive_guard_after_encrypted_reopen',
        ):
            outcomes.append(execute('selected_chat_copy::tests::actual::' + name,
                                    'marmot-app', features, 'green-baseline'))
    report['passed'] = all(outcomes) and len(report['executions']) == report['required_executions']
finally:
    report['inputs_restored'] = source_hashes() == FROZEN_SOURCE
    report['tracked_source_pristine'] = subprocess.run(['git', 'diff', '--quiet', 'HEAD']).returncode == 0
    report['passed'] = report['passed'] and report['inputs_restored'] and report['tracked_source_pristine']
    save()
if not report['passed']:
    raise SystemExit('Scoped qualification did not meet its runtime oracle; retain result.json')
