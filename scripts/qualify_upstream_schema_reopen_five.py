#!/usr/bin/env python3
"""Five exact encrypted-reopen schema compatibility controls; component only."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import qualify_upstream_storage_app_handles as common
from upstream_extraction_cohort import frozen_inputs
old = common.old
ensure = old.ensure
BASE = '07da7dd155cd9c93b63afad5a8d8c4a63afbc209'
SELF = 'scripts/qualify_upstream_schema_reopen_five.py'
WORKFLOW = '.github/workflows/upstream-boundary-regressions.yml'
REF = 'refs/heads/ci/upstream-schema-reopen-five-20261018'
BEGIN = '  # SCHEMA_REOPEN_FIVE_JOBS_BEGIN\n'
END = '  # SCHEMA_REOPEN_FIVE_JOBS_END\n\n'
OPTIONS = 'options: [schema-reopen-five-preflight, schema-reopen-five-green, '
OUT = Path('schema-reopen-five-evidence')
CASES = (
    'approved_account_sharing_policy::tests::sharing_policy_encrypted_restart_retains_sequences_revocation_and_closed_owner',
    'existing_device_group_anchor::tests::existing_anchor_encrypted_reopen_preserves_denial_and_original_bytes',
    'mirrored_chat_catalog::tests::mirrored_catalog_encrypted_reopen_preserves_terminal_fence_and_close_is_final',
    'mirrored_chat_messages::tests::mirrored_messages_encrypted_restart_retains_body_and_terminal_close_is_final',
    'revoked_device_group_anchor::tests::revoked_anchor_encrypted_reopen_and_group_deletion_preserve_terminal_bytes',
)


def source_guard():
    head = old.git('rev-parse', 'HEAD')
    ensure(os.environ.get('GITHUB_ACTIONS') == 'true' and os.environ.get('GITHUB_REPOSITORY') == 'dyKiU/mdk'
        and os.environ.get('GITHUB_EVENT_NAME') == 'workflow_dispatch' and os.environ.get('GITHUB_SHA') == head
        and os.environ.get('GITHUB_REF') == REF
        and os.environ.get('GITHUB_WORKFLOW_REF') == 'dyKiU/mdk/' + WORKFLOW + '@' + REF
        and os.environ.get('SCHEMA_REOPEN_FIVE_BASELINE') == BASE, 'exact-owned-source')
    ensure(os.environ.get('CARGO_INCREMENTAL') == '1' and os.environ.get('CARGO_BUILD_JOBS') == '2'
        and os.environ.get('RUST_MIN_STACK') == '4194304'
        and all(os.environ.get(k) == '0' for k in ['CARGO_PROFILE_DEV_DEBUG','CARGO_PROFILE_TEST_DEBUG'])
        and all(not os.environ.get(k) for k in ['RUSTFLAGS','CARGO_ENCODED_RUSTFLAGS','RUSTC_BOOTSTRAP',
            'CARGO_PROFILE_DEV_OPT_LEVEL','CARGO_PROFILE_TEST_OPT_LEVEL']), 'exact-build-cohort')
    subprocess.run(['git','merge-base','--is-ancestor',BASE,head],check=True)
    ensure(subprocess.run(['git','diff','--quiet','HEAD']).returncode == 0, 'initial-tracked-pristine')
    baseline = {}
    for entry in subprocess.check_output(['git','ls-tree','-r','-z',BASE]).split(b'\0'):
        if entry:
            meta,name = entry.split(b'\t',1); mode,kind,blob = meta.decode().split()
            ensure(kind == 'blob' and mode in {'100644','100755','120000'}, 'baseline-blob-mode')
            baseline[os.fsdecode(name)] = (mode,blob)
    current = frozen_inputs()
    ensure(SELF not in baseline and set(current) == set(baseline) | {SELF}, 'whole-source-inventory')
    for name,record in current.items():
        mode,blob = baseline.get(name,('100644',None))
        ensure(record['mode'] == mode and (mode == '120000' or record['actual_executable'] == (mode == '100755')), 'whole-source-modes')
        if name == SELF:
            continue
        data = os.fsencode(os.readlink(name)) if mode == '120000' else Path(name).read_bytes()
        if name == WORKFLOW:
            text = data.decode()
            ensure(text.count(BEGIN) == text.count(END) == text.count(OPTIONS) == 1, 'one-owned-workflow-overlay')
            left,rest = text.split(BEGIN); _,right = rest.split(END)
            data = (left + right).replace(OPTIONS,'options: [',1).encode()
        ensure(hashlib.sha1(b'blob ' + str(len(data)).encode() + b'\0' + data).hexdigest() == blob, 'exact-baseline:' + name)
    ensure(not subprocess.check_output(['git','ls-files','--others','--exclude-standard'],text=True).strip(), 'no-untracked-source')
    return {'source':head,'baseline':BASE,'whole_source_contents_and_modes_exact':True,
        'historical_guard_invoked':False,'historical_runtime_evidence_reused':False}


def parser_controls():
    controls = common.parser_controls()
    ensure(len(CASES) == len(set(CASES)) == 5, 'exact-five-distinct-cases')
    for name in CASES:
        raw = 'running 1 test\ntest ' + name + ' ... ok\ntest result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 99 filtered out; finished in 0.1s\n'
        ensure(common.parse_body(raw,0,name)['passed_gate'], 'exact-green-positive')
        for text,code in [(raw + raw,0),(raw.replace(name,name + '_foreign'),0),
            (raw.replace('1 passed','0 passed'),0),(raw.replace('0 ignored','1 ignored'),0),
            (raw + 'error[E0000]: omitted\n',0),(raw,124)]:
            ensure(not common.parse_body(text,code,name)['passed_gate'], 'no-false-five-case-green')
    return {'preserved_counts_and_inventory_controls':controls,'five_case_positive':5,
        'five_case_negative':30,'runtime_bodies':0}


def run(report, save, frozen):
    phase = {}; report['phase'] = phase; save()
    binary = common.compile_storage('experimental',frozen,phase,save)
    binary_sha = old.digest(binary.read_bytes())
    report['binary_sha256'] = binary_sha
    report['selected_names'] = list(CASES)
    report['inventory'] = {}; save()
    for name in CASES:
        entry = {}; report['inventory'][name] = entry
        for ignored in [False,True]:
            code,raw,_ = old.capture([str(binary),'--exact',name] + (['--ignored'] if ignored else []) + ['--list','--format','terse'],60)
            row = common.parse_inventory(raw,name,ignored); row['exit_code'] = code
            entry['ignored' if ignored else 'normal'] = row; save()
            ensure(code == 0 and row['passed'], 'exact-one-nonignored-inventory')
    for name in CASES:
        ensure(frozen_inputs() == frozen and old.digest(binary.read_bytes()) == binary_sha, 'before-body-pristine')
        try:
            code,raw,seconds = old.capture([str(binary),'--exact',name,'--nocapture','--test-threads=1'],300,limit=8*1024*1024)
            row = common.parse_body(raw,code,name)
            row.update(wall_seconds=seconds,binary_sha256=binary_sha)
            report['bodies'][name] = row; save()  # Counts persist before optional closed diagnostic extraction.
            sites = re.findall(r'panicked at ([A-Za-z0-9_./-]+\.rs):([0-9]+):([0-9]+):',raw)
            row['safe_panic_locations'] = [{'path':p,'line':int(line),'column':int(col)}
                for p,line,col in sites[:8] if p in frozen and p.startswith('crates/storage-sqlite/')]
            row['panic_locations_truncated'] = len(sites) > 8
            save()
        except old.GateFailure as error:
            report['bodies'][name] = {'actual_counts_complete':False,'passed':None,'failed':None,'ignored':None,
                'executed_nonignored':None,'passed_gate':False,'watchdog_triggered':str(error) == 'bounded-command-timeout',
                'output_limit_triggered':str(error) == 'bounded-command-output-limit'}; save()
        ensure(frozen_inputs() == frozen and old.digest(binary.read_bytes()) == binary_sha, 'after-body-pristine')
    report['binary_pristine'] = old.digest(binary.read_bytes()) == binary_sha; save()
    ensure(set(report['bodies']) == set(CASES) and all(row['passed_gate'] for row in report['bodies'].values()), 'all-five-actual-cases-must-pass')
    report['five_case_component_GREEN'] = True; save()


def main(args):
    os.umask(0o077); OUT.mkdir(exist_ok=True)
    report = {'scope':'five-existing-encrypted-reopen-storage-controls','requested_cohort':'experimental-device-sync',
        'bodies':{},'five_case_component_GREEN':False,'full_qualification':False,'native_acceptance_claim':False,
        'promotion_eligible':False,'security_closure':False,'historical_RED_reattempted':False}
    frozen = None
    def save(): (OUT / 'result.json').write_text(json.dumps(report,indent=2) + '\n')
    try:
        report['source_guard'] = source_guard(); report['parser_controls'] = parser_controls(); save()
        if args.preflight:
            report['preflight_passed'] = True; save(); return
        frozen = frozen_inputs()
        report['source_manifest_sha256'] = old.digest(json.dumps(frozen,sort_keys=True).encode()); save()
        run(report,save,frozen)
    except Exception as error:
        report['error_type'] = type(error).__name__
        report['error_label'] = str(error) if isinstance(error,old.GateFailure) else 'unexpected-controller-failure'
        raise
    finally:
        rows = list(report['bodies'].values())
        complete = set(report['bodies']) == set(CASES) and all(row.get('actual_counts_complete') is True for row in rows)
        report['actual_counts_complete'] = complete
        for key in ['passed','failed','ignored','executed_nonignored']:
            report['known_partial_' + key] = sum(row[key] for row in rows if type(row.get(key)) is int)
            report['actual_' + key] = sum(row[key] for row in rows) if complete and all(type(row.get(key)) is int for row in rows) else None
        report['source_pristine'] = frozen_inputs() == frozen if frozen is not None else None
        report['tracked_worktree_pristine'] = subprocess.run(['git','diff','--quiet','HEAD']).returncode == 0
        if report['source_pristine'] is False or not report['tracked_worktree_pristine']:
            report['five_case_component_GREEN'] = False
        save()
        if sys.exc_info()[0] is None and frozen is not None:
            ensure(report['source_pristine'] and report['binary_pristine'], 'final-source-binary-pristine')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(); parser.add_argument('--preflight',action='store_true'); main(parser.parse_args())
