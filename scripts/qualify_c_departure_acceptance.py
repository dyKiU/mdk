#!/usr/bin/env python3
"""Explicit remote C acceptance, closed evidence only; never release packaging."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import tempfile

from upstream_current_backend_probe import capture
from upstream_extraction_cohort import frozen_inputs

CONSUMER = 'account_chat_departure_acceptance_tests::genuine_two_source_departure_crosses_real_c_and_uniffi_boundaries'
PRODUCER = 'native_device_linking::tests::account_departure_ffi_fixture::account_departure_ffi_fixture_producer'
WORKFLOW = '.github/workflows/upstream-merge-artifacts.yml'
FIXTURE = 'crates/marmot-c/src/tests/account_chat_departure_acceptance_tests.rs'
SIX = ('marmot-app/otlp-export,marmot-app/product-analytics-export,marmot-app/experimental-device-sync,'
       'marmot-app/test-policy-overrides,cgka-engine/test-policy-overrides,cgka-engine/test-crash-hooks')
MARKERS = ('ffi_fixture_private_handoff_valid=true', 'ffi_fixture_real_native_ordinary_sends_decrypted=true',
           'ffi_fixture_mirrored_initiator_available=true', 'ffi_fixture_offline_pending=true',
           'ffi_fixture_actual_ordinary_removals=true', 'ffi_fixture_receipt_complete=true',
           'ffi_fixture_same_root_reopen_completed=true', 'ffi_fixture_producer_bytes_unchanged=true',
           'ffi_fixture_cleanup_clients_closed=true producer_closed=true',
           'ffi_departure_real_two_sources=true all_clients_closed=true producer_exit_zero=true')
SMOKE = 'history C ABI: statuses=5 preflight=2 factory-gates=3 query-gates=2 no-account-effects=1 experimental='


def git(*args):
    return subprocess.check_output(['git', *args]).decode().strip()


def sha(value):
    return hashlib.sha256(value).hexdigest()


class QualificationFailure(ValueError):
    """A fixed source-owned category, safe for the closed report."""


def require(value, category):
    if not value:
        raise QualificationFailure(category)


def runtime_facts(raw):
    text = raw.decode('utf-8', errors='replace')
    counts = re.findall(r'(?m)^test result: (ok|FAILED)\. (\d+) passed; (\d+) failed; (\d+) ignored;', text)
    rows = re.findall(r'(?m)^test ([A-Za-z0-9_:]+) \.\.\. (ok|FAILED)\s*$', text)
    return dict(counts=[dict(status=s, passed=int(p), failed=int(f), ignored=int(i)) for s,p,f,i in counts],
                exact_named_pass=rows == [(CONSUMER, 'ok')], panic_headers=text.count('panicked at '),
                runtime_panic_coordinates=[dict(file=FIXTURE, line=int(line), column=int(column))
                    for line,column in re.findall(re.escape(FIXTURE) + r':([0-9]+):([0-9]+):', text)],
                required_markers={mark: text.splitlines().count(mark) == 1 for mark in MARKERS})


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--mode', choices=['departure', 'history-smoke'], required=True)
    parser.add_argument('--source', required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    os.umask(0o077)
    output = args.output.absolute()
    require(not output.exists() and Path.cwd() not in output.parents, 'fresh-external-output')
    output.parent.mkdir(parents=True, exist_ok=True)
    report = dict(source=args.source, mode=args.mode, completed=False, runtime_mutation_qualification=False,
                  phases=[], actual_c_departure_bodies=0, actual_history_smoke_executions=0)
    before = None
    def save():
        output.write_text(json.dumps(report, indent=2) + '\n')
    def run(label, command, limit=1800, separate=False):
        row = dict(phase=label)
        report['phases'].append(row)
        save()
        code, raw, elapsed, stderr = capture(command, limit, separate=separate)
        diagnostic = stderr if separate else raw
        row.update(exit_code=code, elapsed_seconds=elapsed, stdout_sha256=sha(raw),
                   stderr_sha256=sha(stderr), stdout_bytes=len(raw), stderr_bytes=len(stderr),
                   compiler_codes=sorted(set(re.findall(rb'error\[(E[0-9]{4})\]', diagnostic))))
        row['compiler_codes'] = [value.decode() for value in row['compiler_codes']]
        save()
        return row, raw
    def artifacts(raw, names):
        found = {name: [] for name in names}
        for line in raw.splitlines():
            item = json.loads(line)
            if item.get('reason') != 'compiler-artifact':
                continue
            name = item['target']['name']
            if name in found and item.get('profile', {}).get('test') is True and item.get('executable'):
                path = Path(item['executable'])
                require(path.is_absolute() and path.is_file() and not path.is_symlink()
                        and stat.S_ISREG(path.lstat().st_mode), 'real-unit-executable')
                found[name].append(path)
        require(all(len(paths) == 1 for paths in found.values()), 'exact-two-unit-artifacts')
        return {name: paths[0] for name,paths in found.items()}
    try:
        ref = os.environ.get('GITHUB_REF', '')
        require(os.environ.get('GITHUB_ACTIONS') == 'true' and os.environ.get('GITHUB_EVENT_NAME') == 'workflow_dispatch'
                and os.environ.get('GITHUB_REPOSITORY') == 'dyKiU/mdk'
                and ref.startswith('refs/heads/ci/upstream-develop-dy-'), 'manual-owned-CI')
        require(re.fullmatch('[0-9a-f]{40}', args.source) and args.source == git('rev-parse','HEAD')
                == os.environ.get('GITHUB_SHA') == os.environ.get('GITHUB_WORKFLOW_SHA')
                and os.environ.get('GITHUB_WORKFLOW_REF') == 'dyKiU/mdk/' + WORKFLOW + '@' + ref, 'exact-workflow-source')
        event = json.loads(Path(os.environ['GITHUB_EVENT_PATH']).read_text())
        require(event['inputs']['c_acceptance_only'] in [args.mode, 'all']
                and event['inputs'].get('generation_only', 'false') == 'false', 'explicit-mode')
        require(not git('diff','--name-only','HEAD') and not git('diff','--cached','--name-only'), 'pristine-source')
        require(not any(os.environ.get(k) for k in ['RUSTFLAGS','CARGO_ENCODED_RUSTFLAGS','RUSTC_BOOTSTRAP',
                    'RUSTC','RUSTC_WRAPPER','RUSTC_WORKSPACE_WRAPPER','RUSTDOCFLAGS','CARGO_ENCODED_RUSTDOCFLAGS'])
                and not any(v for k,v in os.environ.items() if re.fullmatch(r'CARGO_TARGET_.*_RUSTFLAGS', k)), 'compiler-flags')
        channel = re.search(r'^channel = "([0-9.]+)"$', Path('rust-toolchain.toml').read_text(), re.M)
        rustc = subprocess.check_output(['rustc','-Vv'], text=True)
        require(channel and re.search(r'^release: ' + re.escape(channel[1]) + r'$', rustc, re.M), 'pinned-rustc')
        report['rustc'] = rustc
        report['cargo'] = subprocess.check_output(['cargo','-V'], text=True).strip()
        report['lock_sha256'] = sha(Path('Cargo.lock').read_bytes())
        report['toolchain_sha256'] = sha(Path('rust-toolchain.toml').read_bytes())
        good = ('test ' + CONSUMER + ' ... ok\n\ntest result: ok. 1 passed; 0 failed; 0 ignored;\n' + '\n'.join(MARKERS) + '\n').encode()
        require(runtime_facts(good)['exact_named_pass'] and all(runtime_facts(good)['required_markers'].values()), 'metadata-positive')
        require(not runtime_facts(good.replace(CONSUMER.encode(), b'unknown'))['exact_named_pass']
                and not runtime_facts(good + good)['exact_named_pass']
                and not all(runtime_facts(good.replace(MARKERS[0].encode(), b''))['required_markers'].values()), 'metadata-negative')
        report['metadata_controls'] = dict(positive=1, negative=3, product_bodies=0)
        before = frozen_inputs()
        before_modes = {name: stat.S_IMODE(Path(name).lstat().st_mode) for name in before}
        index = git('ls-files','--stage')
        os.environ['MARMOT_ACCEPTANCE_SOURCE_COMMIT'] = args.source
        if args.mode == 'departure':
            require(os.environ.get('RUNNER_OS') == 'Linux', 'departure-runner')
            row, raw = run('compile-same-source-units', ['cargo','test','--locked','--lib','-p','marmot-app','-p','marmot-c',
                '--features', SIX + ',marmot-c/experimental-device-sync,marmot-c/alloc-audit', '--no-run','--message-format=json'], separate=True)
            require(row['exit_code'] == 0 and not row['compiler_codes'], 'unit-compile')
            units = artifacts(raw, ['marmot_app','marmot_c'])
            producer_hash = sha(units['marmot_app'].read_bytes())
            report['producer_sha256'] = producer_hash
            report['consumer_sha256'] = sha(units['marmot_c'].read_bytes())
            with tempfile.TemporaryDirectory(prefix='c-departure-', dir=os.environ['RUNNER_TEMP']) as temporary:
                directory = Path(temporary)
                os.environ['MARMOT_ACCOUNT_DEPARTURE_FIXTURE_EXE'] = str(units['marmot_app'])
                os.environ['MARMOT_ACCOUNT_DEPARTURE_FIXTURE_SHA256'] = producer_hash
                os.environ['MARMOT_ACCOUNT_DEPARTURE_FIXTURE_LOG'] = str(directory/'producer.private.log')
                row, raw = run('actual-ignored-C-departure', [str(units['marmot_c']),CONSUMER,
                    '--exact','--ignored','--test-threads=1','--show-output'])
                row.update(runtime_facts(raw));save()
                log = directory/'producer.private.log'
                require(log.is_file() and not log.is_symlink() and log.stat().st_size <= 8*1024*1024, 'bounded-private-producer-log')
                producer = log.read_bytes()
                row['producer_cleanup_observed'] = producer.splitlines().count(b'ffi_fixture_producer_cleanup_closed=true') == 1
                row['producer_bytes_unchanged'] = sha(units['marmot_app'].read_bytes()) == producer_hash
                save()
                require(row['exit_code'] == 0 and row['counts'] == [dict(status='ok',passed=1,failed=0,ignored=0)]
                        and row['exact_named_pass'] and row['panic_headers'] == 0
                        and all(row['required_markers'].values()) and row['producer_cleanup_observed']
                        and row['producer_bytes_unchanged'], 'actual-departure-not-qualified')
                report['actual_c_departure_bodies'] = 1
        else:
            require(os.environ.get('RUNNER_OS') == 'macOS', 'actual-platform-keystore-runner')
            for experimental in [False, True]:
                flags = ['--features','experimental-device-sync'] if experimental else []
                row, raw = run('compile-C-libraries-' + str(int(experimental)), ['cargo','build','--locked','-p','marmot-c',
                    '--message-format=json',*flags], separate=True)
                require(row['exit_code'] == 0 and not row['compiler_codes'], 'C-library-compile')
                paths = []
                for line in raw.splitlines():
                    item=json.loads(line)
                    if item.get('reason')=='compiler-artifact' and item['target']['name']=='marmot_c':
                        paths.extend(Path(name) for name in item['filenames'] if name.endswith(('.a','.dylib')))
                require(len(paths)==2 and {p.suffix for p in paths}=={'.a','.dylib'} and all(p.is_file() and not p.is_symlink() for p in paths), 'actual-shared-static-libraries')
                directory=paths[0].parent
                with tempfile.TemporaryDirectory(prefix='C-history-', dir=os.environ['RUNNER_TEMP']) as temporary:
                    for linkage in ['shared','static']:
                        binary=Path(temporary)/linkage
                        libs = ['-L'+str(directory),'-lmarmot_c','-Wl,-rpath,'+str(directory)] if linkage=='shared' else [str(next(p for p in paths if p.suffix=='.a')),'-lm','-pthread','-framework','Security','-framework','CoreFoundation','-liconv']
                        row, _ = run('link-'+str(int(experimental))+'-'+linkage, ['clang','-std=c11','-Wall','-Wextra','-Werror',
                            '-Icrates/marmot-c/include','crates/marmot-c/examples/history_transfer_smoke.c',*libs,'-o',str(binary)])
                        require(row['exit_code']==0, 'C-smoke-link')
                        home=Path(temporary)/('home-'+linkage);home.mkdir(mode=0o700)
                        row, raw=run('execute-'+str(int(experimental))+'-'+linkage,[str(binary),str(home),str(int(experimental))],300)
                        row['exact_success_marker'] = raw.splitlines().count((SMOKE+str(int(experimental))).encode())==1
                        save()
                        require(row['exit_code']==0 and row['exact_success_marker'], 'actual-C-smoke-not-qualified')
                        report['actual_history_smoke_executions']+=1
        report['source_restored'] = frozen_inputs()==before and {name: stat.S_IMODE(Path(name).lstat().st_mode) for name in before}==before_modes and git('ls-files','--stage')==index and git('rev-parse','HEAD')==args.source
        require(report['source_restored'], 'final-source-closure')
        report['completed']=True
    except Exception as error:
        report['failure_category'] = str(error) if isinstance(error, QualificationFailure) else type(error).__name__
    finally:
        if before is not None:
            try:
                report['source_restored'] = frozen_inputs()==before and {name: stat.S_IMODE(Path(name).lstat().st_mode) for name in before}==before_modes and git('ls-files','--stage')==index and git('rev-parse','HEAD')==args.source
            except Exception:
                report['source_restored']=False
            report['completed'] &= report['source_restored']
        save()
    return 0 if report['completed'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
