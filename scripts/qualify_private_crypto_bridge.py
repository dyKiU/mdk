#!/usr/bin/env python3
"""Fresh exact historical writer -> current reader; two actual crypto bodies only."""
import argparse
import json
import os
from pathlib import Path
import re
import shutil
import stat
import subprocess
import tempfile

from qualify_selected_purpose_cross_build import QualificationFailure, facts, git, require, sha
from upstream_current_backend_probe import capture
from upstream_extraction_cohort import frozen_inputs

WORKFLOW = '.github/workflows/upstream-boundary-regressions.yml'
WRITER = '8c7c39a9df530654cd6d2aeff7e4475001011717'
WRITER_TREE = '6a88211bf9f3a8a8b0837db1c6e0c3b97a9ee620'
WRITER_FILE_MAP = 'bfe0c4700984b16db28ff1a31f38dae9e3714e10ff20b0b49fd51a38eabf92b9'
OLD_LOCK = 'e3f7c8374ced78877a13dfed723b2edabb92ed4223e2b62b361baf66836544b2'
CASE = 'private_device_invite::prepare_tests::private_ledger_real_crypto_old_writer_fixture'
FEATURES = 'experimental-device-sync,test-policy-overrides'
FILES = {'legacy-private-unknown.db', 'synthetic-echo.json'}


def profile(root):
    result = {}
    entries = subprocess.check_output(['git','-C',str(root),'ls-files','--stage','-z'])
    for entry in entries.split(b'\0'):
        if not entry:
            continue
        metadata, raw_name = entry.split(b'\t', 1)
        mode, _, stage = metadata.decode().split()
        name = os.fsdecode(raw_name)
        path = root/name
        require(stage == '0' and mode in ['100644','100755'] and path.is_file()
                and not path.is_symlink() and stat.S_ISREG(path.lstat().st_mode), 'physical-writer-input')
        require(path.resolve().is_relative_to(root.resolve()), 'writer-input-containment')
        require(bool(path.lstat().st_mode & 0o111) == (mode == '100755'), 'writer-source-modes')
        result[name] = dict(mode=mode, sha256=sha(path.read_bytes()))
    return result


def fixture_profile(root):
    require({p.name for p in root.iterdir()} == FILES, 'exact-closed-fixture-files')
    result = {}
    for name in sorted(FILES):
        path = root/name
        require(path.is_file() and not path.is_symlink() and path.stat().st_size > 0
                and stat.S_IMODE(path.lstat().st_mode) & 0o077 == 0, 'private-closed-fixture')
        result[name] = sha(path.read_bytes())
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source', required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    os.umask(0o077)
    root = Path.cwd().resolve()
    output = args.output.absolute()
    require(not output.exists() and root not in output.parents, 'fresh-external-output')
    output.parent.mkdir(parents=True, exist_ok=True)
    report = dict(source=args.source, writer_source=WRITER, writer_tree=WRITER_TREE, completed=False,
                  phases=[], actual_bodies=0, runtime_mutation_qualification=False,
                  historical_binary_reused=False, excluded_unrelated_python_caches=7,
                  historical_manifest_files=1779, admitted_writer_source_files=1772)
    before = None
    def save():
        output.write_text(json.dumps(report, indent=2) + '\n')
    def run(label, command, context=None, separate=False):
        row = dict(phase=label)
        report['phases'].append(row);save()
        code, raw, elapsed, stderr = capture(command, 1800, separate=separate)
        codes, positions = set(), set()
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
                    name = span.get('file_name')
                    if not isinstance(name, str):
                        continue
                    if context is not None:
                        prefix = str(context) + '/'
                        name = name[len(prefix):] if name.startswith(prefix) else name
                    line, column = span.get('line_start'), span.get('column_start')
                    admitted = old_profile if context is not None else before
                    if (span.get('is_primary') is True and name in admitted and type(line) is int
                            and line > 0 and type(column) is int and column > 0):
                        positions.add((name, line, column))
        row.update(exit_code=code, elapsed_seconds=elapsed, stdout_sha256=sha(raw), stderr_sha256=sha(stderr),
                   stdout_bytes=len(raw), stderr_bytes=len(stderr), compiler_codes=sorted(codes),
                   compiler_primary_coordinates=[dict(file=n,line=l,column=c) for n,l,c in sorted(positions)[:64]])
        save()
        return row, raw
    def compile_unit(label, manifest, target, toolchain, context=None):
        os.environ['CARGO_TARGET_DIR'] = str(target)
        row, raw = run(label, ['cargo', '+'+toolchain, 'test','--locked','--manifest-path',str(manifest),
            '-p','cgka-engine','--lib','--features',FEATURES,'--no-run','--message-format=json'], context, True)
        require(row['exit_code'] == 0 and not row['compiler_codes'], 'actual-unit-compile')
        units = []
        for line in raw.splitlines():
            item = json.loads(line)
            if (item.get('reason') == 'compiler-artifact' and item['target']['name'] == 'cgka_engine'
                    and item.get('profile', {}).get('test') is True and item.get('executable')):
                require(set(item['features']) == {'default', *FEATURES.split(',')}, 'actual-private-features')
                units.append(Path(item['executable']))
                row['features'] = sorted(item['features'])
        require(len(units) == 1, 'exact-engine-unit')
        unit = units[0]
        require(unit.is_absolute() and unit.is_file() and not unit.is_symlink()
                and unit.resolve().is_relative_to(target.resolve()), 'fresh-unit-executable')
        row['binary_sha256'] = sha(unit.read_bytes());save()
        return unit, row['binary_sha256']
    def body(label, unit):
        row, raw = run(label, [str(unit), CASE, '--exact','--ignored','--test-threads=1','--show-output'])
        row.update(facts(raw, CASE))
        coordinates = re.findall(rb"(?m)^[ \t]{0,8}thread '[^'\n]{1,256}'(?: \([0-9]+\))? panicked at (crates/cgka-engine/src/private_device_invite_prepare_tests\.rs):([0-9]+):([0-9]+):", raw)
        row['runtime_panic_coordinates'] = [dict(file=n.decode(), line=int(l), column=int(c)) for n,l,c in coordinates[:64]]
        row['unknown_panic_headers'] = max(0, row['panic_headers'] - len(coordinates))
        save()
        require(row['exit_code'] == 0 and row['exact_named_pass'] and row['panic_headers'] == 0
                and row['counts'] == [dict(status='ok',passed=1,failed=0,ignored=0)], 'actual-crypto-body-not-qualified')
        report['actual_bodies'] += 1;save()
    previous_target = os.environ.get('CARGO_TARGET_DIR')
    try:
        ref = os.environ.get('GITHUB_REF', '')
        require(os.environ.get('GITHUB_ACTIONS') == 'true' and os.environ.get('GITHUB_EVENT_NAME') == 'workflow_dispatch'
                and os.environ.get('GITHUB_REPOSITORY') == 'dyKiU/mdk'
                and ref.startswith('refs/heads/ci/upstream-develop-dy-'), 'manual-owned-CI')
        require(re.fullmatch('[0-9a-f]{40}', args.source) and args.source == git('rev-parse','HEAD')
                == os.environ.get('GITHUB_SHA') == os.environ.get('GITHUB_WORKFLOW_SHA')
                and os.environ.get('GITHUB_WORKFLOW_REF') == 'dyKiU/mdk/' + WORKFLOW + '@' + ref, 'exact-workflow-source')
        event = json.loads(Path(os.environ['GITHUB_EVENT_PATH']).read_text())
        require(event['inputs']['case'] == 'private-crypto-old-writer'
                and event['inputs']['extraction_cohort_baseline'] == args.source, 'explicit-self-baseline')
        require(not git('diff','--name-only','HEAD') and not git('diff','--cached','--name-only'), 'pristine-source')
        require(not any(os.environ.get(k) for k in ['RUSTFLAGS','CARGO_ENCODED_RUSTFLAGS','RUSTC_BOOTSTRAP','RUSTC',
                    'RUSTC_WRAPPER','RUSTC_WORKSPACE_WRAPPER','RUSTDOCFLAGS','CARGO_ENCODED_RUSTDOCFLAGS'])
                and not any(v for k,v in os.environ.items() if re.fullmatch(r'CARGO_TARGET_.*_RUSTFLAGS', k)), 'compiler-flags')
        require(not any(k.startswith('MDK_PRIVATE_LEDGER_FIXTURE_') for k in os.environ), 'no-inherited-fixture')
        require(os.environ.get('CARGO_INCREMENTAL') == '1', 'explicit-incremental')
        before = frozen_inputs();index = git('ls-files','--stage')
        channel = re.search(r'^channel = "([0-9.]+)"$', Path('rust-toolchain.toml').read_text(), re.M)
        require(channel is not None, 'source-toolchain')
        report.update(tree=git('rev-parse','HEAD^{tree}'), current_toolchain=channel[1],
                      current_lock_sha256=sha(Path('Cargo.lock').read_bytes()), tracked_input_count=len(before),
                      input_manifest_sha256=sha(json.dumps(before,sort_keys=True).encode()))
        with tempfile.TemporaryDirectory(prefix='private-crypto-bridge-', dir=os.environ['RUNNER_TEMP']) as temporary:
            temporary = Path(temporary);old = temporary/'writer';old.mkdir(mode=0o700)
            for label, command in [('initialize-writer',['git','init','--quiet',str(old)]),
                    ('obtain-pinned-source',['git','-C',str(old),'fetch','--no-tags','--depth=1',str(root),WRITER]),
                    ('checkout-pinned-source',['git','-C',str(old),'checkout','--quiet','--detach','FETCH_HEAD'])]:
                row, _ = run(label, command);require(row['exit_code'] == 0, 'pinned-writer-checkout')
            old_git = lambda *a: subprocess.check_output(['git','-C',str(old),*a],text=True).strip()
            require(old_git('rev-parse','HEAD') == WRITER and old_git('rev-parse','HEAD^{tree}') == WRITER_TREE,
                    'exact-admitted-writer-tree')
            old_profile = profile(old)
            require(len(old_profile) == 1772 and not any(n.endswith('.pyc') for n in old_profile), 'exact-writer-source-count')
            require(sha(json.dumps({n:v['sha256'] for n,v in old_profile.items()},sort_keys=True).encode())
                    == WRITER_FILE_MAP and not old_git('diff','--name-only','HEAD')
                    and not old_git('diff','--cached','--name-only'), 'historical-source-content-admission')
            require(sha((old/'Cargo.lock').read_bytes()) == OLD_LOCK
                    and re.search(r'^channel = "1\.97\.1"$', (old/'rust-toolchain.toml').read_text(), re.M), 'old-locked-toolchain')
            report.update(writer_profile_sha256=sha(json.dumps(old_profile,sort_keys=True).encode()), writer_lock_sha256=OLD_LOCK,
                          writer_toolchain='1.97.1', new_binary_identity_required=True)
            old_index = old_git('ls-files','--stage')
            try:
                old_unit, old_hash = compile_unit('compile-actual-historical-writer',old/'Cargo.toml',temporary/'old-target','1.97.1',old)
                original = temporary/'original';original.mkdir(mode=0o700)
                os.environ['MDK_PRIVATE_LEDGER_FIXTURE_DIR'] = str(original)
                os.environ['MDK_PRIVATE_LEDGER_FIXTURE_STAGE'] = 'generate'
                body('actual-old-writer-generation',old_unit)
                original_profile = fixture_profile(original)
                copied = temporary/'current-copy';shutil.copytree(original,copied)
                require(fixture_profile(copied) == original_profile, 'fresh-byte-exact-fixture-copy')
                # Separate old target; current target retains existing compatible runner cache.
                current_target = Path(previous_target).absolute() if previous_target else root/'target'
                current_unit, current_hash = compile_unit('compile-current-verifier',root/'Cargo.toml',current_target,channel[1])
                os.environ['MDK_PRIVATE_LEDGER_FIXTURE_DIR'] = str(copied)
                os.environ['MDK_PRIVATE_LEDGER_FIXTURE_STAGE'] = 'verify'
                body('actual-current-crypto-bridge',current_unit)
                require(fixture_profile(original) == original_profile, 'original-writer-output-unchanged')
                require(sha(old_unit.read_bytes()) == old_hash and sha(current_unit.read_bytes()) == current_hash, 'unit-bytes-unchanged')
                report.update(original_fixture_sha256=original_profile, writer_binary_sha256=old_hash,
                              current_binary_sha256=current_hash, original_fixture_unchanged=True)
            finally:
                try:
                    report['writer_source_unchanged'] = (profile(old) == old_profile
                        and old_git('ls-files','--stage') == old_index and old_git('rev-parse','HEAD') == WRITER
                        and not old_git('diff','--name-only','HEAD') and not old_git('diff','--cached','--name-only'))
                except Exception:
                    report['writer_source_unchanged'] = False
                save()
            require(report['writer_source_unchanged'], 'writer-source-closure')
        report['completed'] = True
    except Exception as error:
        report['failure_category'] = str(error) if isinstance(error, QualificationFailure) else type(error).__name__
    finally:
        for key in ['MDK_PRIVATE_LEDGER_FIXTURE_DIR','MDK_PRIVATE_LEDGER_FIXTURE_STAGE']:
            os.environ.pop(key, None)
        if previous_target is None:
            os.environ.pop('CARGO_TARGET_DIR', None)
        else:
            os.environ['CARGO_TARGET_DIR'] = previous_target
        if before is not None:
            try:
                report['current_source_unchanged'] = (frozen_inputs() == before and git('ls-files','--stage') == index
                    and git('rev-parse','HEAD') == args.source and not git('diff','--name-only','HEAD')
                    and not git('diff','--cached','--name-only'))
            except Exception:
                report['current_source_unchanged'] = False
            report['completed'] &= report['current_source_unchanged']
        save()
    return 0 if report['completed'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
