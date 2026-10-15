#!/usr/bin/env python3
"""Remote-only exact-test quarantine/privacy mutations; export closed evidence only."""
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import tempfile
import time

SOURCE = '312e8b549321dd93636afe98d4a6fd8c79e0f69d'
TEST = 'client::sync::projection_retry_tests::quarantined_private_group_does_not_retain_or_expose_chat_projection'
FIXTURE = Path('crates/marmot-app/src/client/sync/projection_retry_tests.rs')
SYNC = Path('crates/marmot-app/src/client/sync.rs')
SESSION = Path('crates/cgka-session/src/lib.rs')
FEATURES = ','.join(('marmot-app/otlp-export', 'marmot-app/product-analytics-export',
                     'marmot-app/test-policy-overrides', 'marmot-app/experimental-device-sync',
                     'cgka-engine/test-policy-overrides', 'cgka-engine/test-crash-hooks'))
COMMAND = ['cargo', 'test', '--locked', '-p', 'marmot-app', '--lib', '--features', FEATURES,
           TEST, '--', '--exact', '--nocapture', '--test-threads=1']
OUT = Path('quarantine-mutation-proof')
OUT.mkdir(mode=0o700)
report = {'source': SOURCE, 'tool_sha': subprocess.check_output(['git', 'rev-parse', 'HEAD'], text=True).strip(),
          'command': COMMAND, 'rust_min_stack': 4194304, 'test_threads': 1, 'retries': 0,
          'executions': [], 'passed': False, 'scope': 'Exact private quarantine fixture; no SDK or app execution'}


def sha(data):
    return hashlib.sha256(data).hexdigest()


def require(condition, label):
    if not condition:
        raise ValueError(label)


def save():
    (OUT / 'result.json').write_text(json.dumps(report, indent=2) + '\n')


def execute(label, private, expected):
    log = private / (label + '.log')
    started = time.monotonic()
    with log.open('x') as stream:
        process = subprocess.run(COMMAND, stdout=stream, stderr=subprocess.STDOUT, timeout=1800)
    text = log.read_text(errors='replace')
    summaries = re.findall(r'test result: (ok|FAILED)\. (\d+) passed; (\d+) failed; (\d+) ignored;', text)
    row = {'label': label, 'exit_code': process.returncode,
           'seconds': round(time.monotonic() - started, 3), 'runtime_counts_available': False,
           'intended_assertion': None, 'qualified': False}
    report['executions'].append(row)
    if len(summaries) == 1:
        _, passed, failed, ignored = summaries[0]
        row.update(runtime_counts_available=True, passed=int(passed), failed=int(failed), ignored=int(ignored))
    one_body = (row.get('passed', 0) + row.get('failed', 0) == 1 and row.get('ignored') == 0
                and re.search(r'^running 1 test$', text, re.M) is not None
                and re.search(r'^test ' + re.escape(TEST) + r' \.\.\. (?:ok|FAILED)$', text, re.M) is not None)
    if expected == 'green':
        row['qualified'] = one_body and process.returncode == 0 and row.get('passed') == 1 and row.get('failed') == 0
    else:
        # Inspect raw panic privately; never export dynamic messages, group IDs or payloads.
        sites = re.findall(r'panicked at (crates/marmot-app/src/client/sync/projection_retry_tests\.rs):(\d+):\d+:', text)
        lines = FIXTURE.read_text().splitlines()
        begin = next(index + 1 for index, line in enumerate(lines) if 'async fn quarantined_private_group_does_not_retain_or_expose_chat_projection()' in line)
        sites = [(name, int(line)) for name, line in sites if begin <= int(line) <= len(lines)]
        category = None
        if expected == 'deferral' and ('UnknownGroup' in text or 'assertion failed: !client.has_pending_effect_projections()' in text):
            category = 'quarantined-projection-retained-or-healthy-work-refused'
        if expected == 'privacy' and ('assertion failed: client.state_group_record(&broken).is_none()' in text
                                      or ('assertion failed:' in text and 'group.group_id_hex != private_hex' in text)):
            category = 'private-group-visible-in-chat-projection'
        if len(sites) == 1 and category is not None:
            row['intended_assertion'] = {'source_file': sites[0][0], 'line': sites[0][1], 'category': category}
        row['qualified'] = (one_body and process.returncode == 101 and row.get('passed') == 0
                            and row.get('failed') == 1 and row['intended_assertion'] is not None)
    save()
    require(row['qualified'], 'exact-runtime-evidence-required-' + label)


originals = {}
try:
    require(os.environ.get('GITHUB_ACTIONS') == 'true' and os.environ.get('RUNNER_OS') == 'Linux', 'remote-linux-CI-only')
    require(os.environ.get('RUST_MIN_STACK') == '4194304', 'original-four-MiB-stack-required')
    subprocess.run(['git', 'merge-base', '--is-ancestor', SOURCE, 'HEAD'], check=True)
    for path in (SYNC, SESSION, FIXTURE, Path('Cargo.lock')):
        data = path.read_bytes()
        require(data == subprocess.check_output(['git', 'show', SOURCE + ':' + str(path)]), 'source-or-lock-differs-from-approved-fixture')
        originals[path] = data
    report['original_hashes'] = {str(path): sha(data) for path, data in originals.items()}
    save()
    mutations = [
        ('deferral-disabled', SYNC,
         b'.is_err_and(|error| self.defer_quarantined_group_projection(error, &mut pending))',
         b'.is_err_and(|error| false && self.defer_quarantined_group_projection(error, &mut pending))', 'deferral'),
        ('privacy-filter-bypassed', SESSION,
         b'self.engine.exclude_private_group_from_chat(group)',
         b'self.engine.exclude_private_group_from_chat(group).map(|_| false)', 'privacy'),
    ]
    with tempfile.TemporaryDirectory(prefix='quarantine-private-', dir=os.environ['RUNNER_TEMP']) as private:
        private = Path(private)
        execute('baseline', private, 'green')
        for label, path, before, after, expected in mutations:
            require(originals[path].count(before) == 1, 'unique-mutation-anchor-required')
            failure = None
            try:
                path.write_bytes(originals[path].replace(before, after))
                report.setdefault('mutations', {})[label] = {'path': str(path), 'mutant_sha256': sha(path.read_bytes())}
                save()
                execute(label, private, expected)
            except Exception as error:
                failure = error
            finally:
                path.write_bytes(originals[path])
                require(path.read_bytes() == originals[path], 'exact-source-restoration-required')
                report['mutations'][label]['restored_sha256'] = sha(path.read_bytes())
                save()
            execute(label + '-restored-control', private, 'green')
            if failure is not None:
                raise failure
    require(len(report['executions']) == 5 and all(row['qualified'] for row in report['executions']), 'five-qualified-executions-required')
    report['passed'] = True
except Exception as error:
    report['failure_category'] = str(error) if isinstance(error, ValueError) and re.fullmatch('[a-zA-Z0-9-]+', str(error)) else type(error).__name__
finally:
    for path, data in originals.items():
        if path in (SYNC, SESSION):
            path.write_bytes(data)
    report['restored_hashes'] = {str(path): sha(path.read_bytes()) for path in originals}
    report['all_source_and_lock_restored'] = all(path.read_bytes() == data for path, data in originals.items())
    report['passed'] = report['passed'] and report['all_source_and_lock_restored']
    save()
print(json.dumps({'passed': report['passed'], 'executions': len(report['executions']),
                  'all_source_and_lock_restored': report['all_source_and_lock_restored']}))
raise SystemExit(0 if report['passed'] else 1)
