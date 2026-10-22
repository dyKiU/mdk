#!/usr/bin/env python3
"""Two real cross-build storage bodies; no mutation or SDK qualification credit."""
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

WORKFLOW = '.github/workflows/upstream-boundary-regressions.yml'
WRITER = 'feature::encrypted_sql_cannot_delete_replace_or_reactivate_terminal_references'
READER = 'selected_chat_populated_cohort_is_unavailable_by_default'


def git(*args):
    return subprocess.check_output(['git', *args], text=True).strip()


def sha(data):
    return hashlib.sha256(data).hexdigest()


class QualificationFailure(ValueError):
    pass


def require(value, category):
    if not value:
        raise QualificationFailure(category)


def facts(raw, name):
    text = raw.decode('utf-8', errors='replace')
    rows = re.findall(r'(?m)^test ([A-Za-z0-9_:]+) \.\.\. (ok|FAILED|ignored)\s*$', text)
    summaries = re.findall(r'(?m)^test result: (ok|FAILED)\. (\d+) passed; (\d+) failed; (\d+) ignored;', text)
    return dict(exact_named_pass=rows == [(name, 'ok')],
                counts=[dict(status=s, passed=int(p), failed=int(f), ignored=int(i)) for s,p,f,i in summaries],
                panic_headers=text.count('panicked at '))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source', required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    os.umask(0o077)
    output = args.output.absolute()
    require(not output.exists() and Path.cwd() not in output.parents, 'fresh-external-output')
    output.parent.mkdir(parents=True, exist_ok=True)
    report = dict(source=args.source, completed=False, actual_bodies=0,
                  runtime_mutation_qualification=False, phases=[])
    before = None
    def save():
        output.write_text(json.dumps(report, indent=2) + '\n')
    def run(label, command, separate=False):
        row = dict(phase=label, command=command)
        report['phases'].append(row)
        save()
        code, raw, elapsed, stderr = capture(command, 1800, separate=separate)
        codes, coordinates = set(), set()
        if separate:
            for line in raw.splitlines():
                try:
                    item = json.loads(line)
                except json.JSONDecodeError:
                    continue
                if not isinstance(item, dict) or item.get('reason') != 'compiler-message':
                    continue
                message = item.get('message', {})
                value = (message.get('code') or {}).get('code')
                if isinstance(value, str) and re.fullmatch('E[0-9]{4}', value):
                    codes.add(value)
                for span in message.get('spans', []):
                    name, line, column = span.get('file_name'), span.get('line_start'), span.get('column_start')
                    if (span.get('is_primary') is True and name in before and type(line) is int
                            and line > 0 and type(column) is int and column > 0):
                        coordinates.add((name, line, column))
        row.update(exit_code=code, elapsed_seconds=elapsed, stdout_bytes=len(raw), stderr_bytes=len(stderr),
                   stdout_sha256=sha(raw), stderr_sha256=sha(stderr), compiler_codes=sorted(codes),
                   compiler_primary_coordinates=[dict(file=n, line=l, column=c) for n,l,c in sorted(coordinates)[:64]])
        save()
        return row, raw
    try:
        ref = os.environ.get('GITHUB_REF', '')
        require(os.environ.get('GITHUB_ACTIONS') == 'true' and os.environ.get('GITHUB_EVENT_NAME') == 'workflow_dispatch'
                and os.environ.get('GITHUB_REPOSITORY') == 'dyKiU/mdk'
                and ref.startswith('refs/heads/ci/upstream-develop-dy-'), 'manual-owned-CI')
        require(re.fullmatch('[0-9a-f]{40}', args.source) and args.source == git('rev-parse','HEAD')
                == os.environ.get('GITHUB_SHA') == os.environ.get('GITHUB_WORKFLOW_SHA')
                and os.environ.get('GITHUB_WORKFLOW_REF') == 'dyKiU/mdk/' + WORKFLOW + '@' + ref, 'exact-workflow-source')
        event = json.loads(Path(os.environ['GITHUB_EVENT_PATH']).read_text())
        require(event['inputs']['case'] == 'selected-purpose-cross-build'
                and event['inputs']['extraction_cohort_baseline'] == args.source, 'explicit-self-baseline')
        require(not git('diff','--name-only','HEAD') and not git('diff','--cached','--name-only'), 'pristine-source')
        require(not any(os.environ.get(k) for k in ['RUSTFLAGS','CARGO_ENCODED_RUSTFLAGS','RUSTC_BOOTSTRAP','RUSTC',
                    'RUSTC_WRAPPER','RUSTC_WORKSPACE_WRAPPER','RUSTDOCFLAGS','CARGO_ENCODED_RUSTDOCFLAGS'])
                and not any(v for k,v in os.environ.items() if re.fullmatch(r'CARGO_TARGET_.*_RUSTFLAGS', k)), 'compiler-flags')
        require(not any(k.startswith('WN_SELECTED_CHAT_PURPOSE_') for k in os.environ), 'no-inherited-fixture')
        require(os.environ.get('CARGO_INCREMENTAL') == '1', 'explicit-incremental')
        channel = re.search(r'^channel = "([0-9.]+)"$', Path('rust-toolchain.toml').read_text(), re.M)
        rustc = subprocess.check_output(['rustc','-Vv'], text=True)
        require(channel and re.search(r'^release: ' + re.escape(channel[1]) + '$', rustc, re.M), 'pinned-rustc')
        before = frozen_inputs()
        index = git('ls-files','--stage')
        report.update(tree=git('rev-parse','HEAD^{tree}'), rustc=rustc,
                      lock_sha256=sha(Path('Cargo.lock').read_bytes()), tracked_input_count=len(before),
                      input_manifest_sha256=sha(json.dumps(before, sort_keys=True).encode()))
        # Parser controls are synthetic metadata, never product bodies.
        good = ('test ' + WRITER + ' ... ok\n\ntest result: ok. 1 passed; 0 failed; 0 ignored;\n').encode()
        require(facts(good, WRITER)['exact_named_pass'], 'metadata-positive')
        require(not facts(good+good, WRITER)['exact_named_pass']
                and not facts(good.replace(WRITER.encode(), b'unknown'), WRITER)['exact_named_pass'], 'metadata-negative')
        report['metadata_controls'] = dict(positive=1, negative=2, actual_bodies=0)
        with tempfile.TemporaryDirectory(prefix='selected-purpose-', dir=os.environ['RUNNER_TEMP']) as temporary:
            fixture = Path(temporary)/'closed.sqlite'
            os.environ['WN_SELECTED_CHAT_PURPOSE_TEST_FIXTURE'] = str(fixture)
            writer_hash = None
            for experimental, name in [(True, WRITER), (False, READER)]:
                cohort = 'experimental' if experimental else 'default'
                flags = ['--features','experimental-device-sync'] if experimental else []
                row, raw = run('compile-'+cohort, ['cargo','test','--locked','-p','storage-sqlite',
                    '--test','selected_chat_key_package',*flags,'--no-run','--message-format=json'], separate=True)
                require(row['exit_code'] == 0 and not row['compiler_codes'], 'unit-compile')
                units = []
                for line in raw.splitlines():
                    item = json.loads(line)
                    if (item.get('reason') == 'compiler-artifact' and item['target']['name'] == 'selected_chat_key_package'
                            and item.get('profile', {}).get('test') is True and item.get('executable')):
                        require(('experimental-device-sync' in item['features']) == experimental, 'exact-feature-cohort')
                        units.append((Path(item['executable']), sorted(item['features'])))
                require(len(units) == 1, 'exact-unit-artifact')
                unit, features = units[0]
                require(unit.is_absolute() and unit.is_file() and not unit.is_symlink()
                        and stat.S_ISREG(unit.lstat().st_mode), 'real-unit-executable')
                unit_hash = sha(unit.read_bytes())
                row.update(binary_sha256=unit_hash, features=features);save()
                if experimental:
                    writer_hash = unit_hash
                    require(not fixture.exists(), 'fresh-writer-output')
                else:
                    require(unit_hash != writer_hash and fixture.is_file() and not fixture.is_symlink(), 'distinct-default-binary-real-fixture')
                    input_hash = sha(fixture.read_bytes())
                row, raw = run('actual-'+cohort, [str(unit),name,'--exact',*(['--ignored'] if not experimental else []),
                    '--test-threads=1','--show-output'])
                row.update(facts(raw, name));save()
                require(row['exit_code'] == 0 and row['exact_named_pass'] and row['panic_headers'] == 0
                        and row['counts'] == [dict(status='ok',passed=1,failed=0,ignored=0)], 'actual-body-not-qualified')
                require(sha(unit.read_bytes()) == unit_hash, 'unit-bytes-unchanged')
                require(fixture.is_file() and not fixture.is_symlink() and fixture.stat().st_size > 0, 'actual-closed-fixture')
                if not experimental:
                    require(sha(fixture.read_bytes()) == input_hash, 'default-denial-preserves-fixture')
                report['fixture_sha256'] = sha(fixture.read_bytes())
                report['actual_bodies'] += 1;save()
        report['completed'] = True
    except Exception as error:
        report['failure_category'] = str(error) if isinstance(error, QualificationFailure) else type(error).__name__
    finally:
        if before is not None:
            try:
                report['source_unchanged'] = (frozen_inputs() == before and git('ls-files','--stage') == index
                    and git('rev-parse','HEAD') == args.source and not git('diff','--name-only','HEAD')
                    and not git('diff','--cached','--name-only'))
            except Exception:
                report['source_unchanged'] = False
            report['completed'] &= report['source_unchanged']
        save()
    return 0 if report['completed'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
