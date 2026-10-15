#!/usr/bin/env python3
"""Exercise real foreign-future and cleanup-isolation failures, restoring exact sources."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import subprocess

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('--case', choices=['departure', 'worker-reap', 'relay-acquisition', 'upload-fixture', 'migration-default', 'migration-experimental'], required=True)
parser.add_argument('--output', type=Path, required=True)
args = parser.parse_args()
if args.case == 'departure':
    source = Path('crates/marmot-uniffi/src/commands/account_chat_departure.rs')
    old, new = '#[uniffi::export(async_runtime = "tokio")]', '#[uniffi::export]'
    command = ['cargo', 'test', '--locked', '-p', 'marmot-uniffi', '--lib', '--features',
               'experimental-device-sync', 'commands::account_chat_departure::tests::',
               '--', '--test-threads=1']
    expected = 2
elif args.case == 'worker-reap':
    source = Path('crates/marmot-app/src/runtime/mod.rs')
    old, new = 'let completed = handle.is_finished();', 'let completed = true;'
    command = ['cargo', 'test', '--locked', '-p', 'marmot-app', '--lib', '--features',
               'cgka-engine/test-policy-overrides,cgka-engine/test-crash-hooks',
               'runtime::tests::stuck_worker_reap_does_not_block_a_healthy_account',
               '--', '--exact', '--test-threads=1']
    expected = 1
elif args.case == 'relay-acquisition':
    source = Path('crates/marmot-app/src/relay_plane/tests.rs')
    old, new = 'let subscription = issued_subscription;', 'let subscription = legacy_subscription.clone();'
    command = ['cargo', 'test', '--locked', '-p', 'marmot-app', '--lib', '--features',
               'experimental-device-sync',
               'relay_plane::tests::enrollment_acquisition_delayed_notification_worker_preserves_clock_and_fifo_eose',
               '--', '--exact', '--test-threads=1']
    expected = 1

elif args.case == 'upload-fixture':
    source = Path('crates/marmot-app/src/client/upload_cleanup_tests.rs')
    old = ("            let mut first_byte = [0u8; 1];\n"
           "            if socket.peek(&mut first_byte).await.unwrap() == 0 {\n"
           "                continue;\n"
           "            }\n")
    new = ''
    command = ['env', '-u', 'RUST_MIN_STACK', 'cargo', 'test', '--locked',
               '-p', 'marmot-app', '--lib',
               'client::upload_cleanup_tests::outgoing_publication_', '--', '--test-threads=1']
    expected = 2
else:
    source = Path('crates/storage-sqlite/src/private_migration_ledger.rs')
    old = ('        applied += 1;\n    }\n'
           '    install_activation_triggers(&tx, schemas.last().unwrap())?;')
    new = old.replace('applied += 1;', 'applied += 0;')
    command = ['env', '-u', 'RUST_MIN_STACK', 'cargo', 'test', '--locked',
               '-p', 'storage-sqlite', '--lib']
    if args.case == 'migration-experimental':
        command.extend(['--features', 'experimental-device-sync'])
    command.extend(['migrations::migration_0108_account_attachment_history::tests::populated_v106_upgrade_preserves_group_pages_and_installs_global_mutation_fences',
                    '--', '--exact', '--test-threads=1'])
    expected = 1

original = source.read_bytes()
text = original.decode()
if text.count(old) != 1:
    raise ValueError('Mutation anchor must match exactly once')
args.output.mkdir(parents=True, exist_ok=False)
proof = {'source_commit': subprocess.check_output(['git', 'rev-parse', 'HEAD'], text=True).strip(),
         'case': args.case, 'source_path': str(source),
         'original_sha256': hashlib.sha256(original).hexdigest(), 'command': command, 'runs': []}


def save():
    (args.output / 'report.json').write_text(json.dumps(proof, indent=2) + '\n')


def execute(phase):
    path = args.output / (phase + '.log')
    with path.open('x') as log:
        result = subprocess.run(command, stdout=log, stderr=subprocess.STDOUT, timeout=1800)
    counts = re.findall(r'test result: (ok|FAILED)\. (\d+) passed; (\d+) failed; (\d+) ignored', path.read_text())
    row = {'phase': phase, 'exit_code': result.returncode, 'counts': counts, 'log': path.name}
    proof['runs'].append(row)
    save()
    return row


def matches(row, passed, failed):
    return len(row['counts']) == 1 and list(row['counts'][0][1:]) == [str(passed), str(failed), '0']


baseline = execute('baseline')
if baseline['exit_code'] != 0 or not matches(baseline, expected, 0):
    raise SystemExit('Baseline did not execute the intended passing regression cohort')
attempt_error = None
try:
    source.write_text(text.replace(old, new))
    mutant = execute('mutant')
    proof['runtime_mutant_killed'] = mutant['exit_code'] != 0 and matches(mutant, 0, expected)
except (OSError, subprocess.SubprocessError) as error:
    attempt_error = type(error).__name__
    proof['mutation_error_category'] = attempt_error
finally:
    source.write_bytes(original)
    proof['source_restored'] = hashlib.sha256(source.read_bytes()).hexdigest() == proof['original_sha256']
    save()
if not proof['source_restored']:
    raise SystemExit('Exact source restoration failed')
control = execute('restored-control')
proof['restored_control_passed'] = control['exit_code'] == 0 and matches(control, expected, 0)
proof['final_source_sha256'] = hashlib.sha256(source.read_bytes()).hexdigest()
proof['completed'] = (proof.get('runtime_mutant_killed', False) and proof['restored_control_passed']
                      and proof['final_source_sha256'] == proof['original_sha256'] and attempt_error is None)
save()
if not proof['completed']:
    raise SystemExit('Runtime mutation/restoration qualification failed; compile or empty runs are not kills')
