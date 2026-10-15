"""Run one real directory-cleanup regression; export only a compact verdict."""
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import tempfile
import time

os.umask(0o077)
test = 'sqlcipher::concurrency_tests::delayed_directory_cleanup_preserves_published_encrypted_cache'
features = ','.join(('marmot-app/otlp-export', 'marmot-app/product-analytics-export',
                     'marmot-app/test-policy-overrides', 'marmot-app/experimental-device-sync',
                     'cgka-engine/test-policy-overrides', 'cgka-engine/test-crash-hooks'))
command = ['cargo', 'test', '--locked', '-p', 'marmot-app', '--lib', '--features', features,
           test, '--', '--exact', '--nocapture', '--test-threads=1']
guarded = [Path(name) for name in (
    'crates/marmot-app/src/directory/methods.rs',
    'crates/marmot-app/src/sqlcipher.rs',
    'crates/marmot-app/src/sqlcipher/concurrency_tests.rs', 'Cargo.lock')]
before = {str(path): hashlib.sha256(path.read_bytes()).hexdigest() for path in guarded}
output = Path('directory-cleanup-proof')
output.mkdir(mode=0o700)
report = {'source': subprocess.check_output(['git', 'rev-parse', 'HEAD'], text=True).strip(),
          'tree': subprocess.check_output(['git', 'rev-parse', 'HEAD^{tree}'], text=True).strip(),
          'scope': 'One deterministic real filesystem regression against unchanged cleanup behavior',
          'test': test, 'command': command, 'retries': 0, 'test_threads': 1,
          'rust_min_stack': 4194304, 'source_hashes_before': before,
          'expected': 'one runtime failure at the published-database filesystem oracle',
          'runtime_counts_available': False, 'passed': False}
try:
    assert report['source'] == os.environ['GITHUB_SHA']
    assert os.environ.get('RUST_MIN_STACK') == '4194304'
    for variable in ('RUSTFLAGS', 'CARGO_ENCODED_RUSTFLAGS', 'RUSTC_BOOTSTRAP'):
        assert not os.environ.get(variable), 'unexpected compiler override'
    report['rustc'] = subprocess.check_output(['rustc', '-Vv'], text=True).strip()
    report['cargo'] = subprocess.check_output(['cargo', '-V'], text=True).strip()
    with tempfile.TemporaryDirectory(prefix='directory-cleanup-private-') as private:
        log = Path(private) / 'regression.log'
        started = time.monotonic()
        print('directory regression compilation/execution started', flush=True)
        with log.open('x') as stream:
            process = subprocess.run(command, stdout=stream, stderr=subprocess.STDOUT, timeout=2700)
        text = log.read_text(errors='replace')
        report['seconds'] = round(time.monotonic() - started, 3)
        report['exit_code'] = process.returncode
        summaries = re.findall(r'test result: (ok|FAILED)\. (\d+) passed; (\d+) failed; (\d+) ignored;', text)
        if len(summaries) == 1:
            result, passed, failed, ignored = summaries[0]
            report.update(runtime_counts_available=True, passed_count=int(passed),
                          failed_count=int(failed), ignored_count=int(ignored))
        panics = re.findall(r"thread '[^\n]*' panicked at ([^\n]+):\n([^\n]+)", text)
        report['panics'] = []
        for site, message in panics:
            safe_site = site if re.fullmatch(r'crates/marmot-app/src/sqlcipher/concurrency_tests\.rs:\d+:\d+', site) else 'outside_expected_fixture'
            category = 'other_assertion'
            if message.startswith('called `Result::unwrap()` on an `Err` value:'):
                category = 'unexpected_result_unwrap'
            elif message.startswith('called `Option::unwrap()` on a `None` value'):
                category = 'unexpected_option_unwrap'
            elif message == 'late cleanup removed a published directory database':
                category = 'published_directory_database_removed'
            elif message == 'assertion `left == right` failed: late cleanup replaced a published directory database':
                category = 'published_directory_database_replaced'
            report['panics'].append({'site': safe_site, 'category': category})
        intended = [
            (site, message) for site, message in panics
            if re.fullmatch(r'crates/marmot-app/src/sqlcipher/concurrency_tests\.rs:\d+:\d+', site)
            and message in ('late cleanup removed a published directory database',
                            'assertion `left == right` failed: late cleanup replaced a published directory database')]
        report['intended_filesystem_oracle'] = len(panics) == len(intended) == 1
        if intended:
            report['panic_site'] = intended[0][0]
            report['panic_category'] = 'published_directory_database_removed_or_replaced'
        assert re.search(r'(?m)^running 1 test$', text), 'one runtime body did not start'
        assert re.search(r'(?m)^test ' + re.escape(test) + r' \.\.\. ', text), 'wrong runtime body'
        assert report.get('runtime_counts_available'), 'runtime counts unavailable'
        assert (report['passed_count'], report['failed_count'], report['ignored_count']) == (0, 1, 0), 'unexpected runtime counts'
        assert process.returncode != 0 and report['intended_filesystem_oracle'], 'missing intended runtime filesystem failure'
        report['passed'] = True
except Exception as error:
    report['reporting_error_type'] = type(error).__name__
finally:
    report['source_hashes_after'] = {str(path): hashlib.sha256(path.read_bytes()).hexdigest() for path in guarded}
    report['source_unchanged'] = report['source_hashes_after'] == before
    report['passed'] = report['passed'] and report['source_unchanged']
    (output / 'result.json').write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps(report, indent=2), flush=True)
if not report['passed']:
    raise SystemExit(1)
