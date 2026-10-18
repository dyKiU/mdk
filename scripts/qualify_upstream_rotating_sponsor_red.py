#!/usr/bin/env python3
"""Three synthetic Protocol storage regressions; no SDK/native/product qualification."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import qualify_upstream_storage_app_handles as common
from upstream_extraction_cohort import frozen_inputs
old=common.old
ensure=old.ensure
BASE='2b5cca339e5fcfe520d58e275238e5fbac40937d'
SELF='scripts/qualify_upstream_rotating_sponsor_red.py'
WORKFLOW='.github/workflows/upstream-boundary-regressions.yml'
REF='refs/heads/ci/upstream-rotating-sponsor-red-20261018'
TEST='crates/storage-sqlite/src/private_device_invite_tests.rs'
BEGIN='  # ROTATING_SPONSOR_RED_JOBS_BEGIN\n'
END='  # ROTATING_SPONSOR_RED_JOBS_END\n'
OPTIONS='options: [rotating-sponsor-red-preflight, rotating-sponsor-red, '
OUT=Path('rotating-sponsor-red-evidence')
TEST_SHA256='9e131bc25ebaf9918f83b2bf08cfcb8a2e0d1dc5fa37bb014f587565b48ed3e3'
ADDITION='\n// Synthetic storage lineage only. The App regression supplies real SDK/MLS proof.\nfn rotated_sponsor_invite() -> (\n    SqliteAccountStorage,\n    ConfirmedPrivateInviteFact,\n    PrivateInviteFact,\n    u64,\n) {\n    use cgka_traits::MessageId;\n    use cgka_traits::existing_device_group_anchor::ExistingDeviceGroupDraft;\n    use cgka_traits::private_roster_settlement::{PrivateSettlementAnchor, PrivateSettlementFact};\n\n    let storage = store();\n    let previous = confirmed(&storage);\n    let rounds = storage.private_roster_settlement_storage().unwrap();\n    let state = rounds\n        .select_round(&PrivateSettlementAnchor {\n            origin: PrivateInviteOrigin::Confirmed(previous.scope.staging_generation),\n            account: previous.scope.account,\n            local_device: previous.scope.local_device,\n            group_id: previous.binding.group_id.clone(),\n            successor: previous.binding.successor.clone(),\n            roster_commitment: [30; 32],\n            enrollment_nonce: previous.binding.nonce,\n            context_digest: previous.binding.context_digest,\n            coordinator: previous.scope.local_device,\n        })\n        .unwrap();\n    rounds\n        .bind_round_nonce(state.generation, [31; 32], 0)\n        .unwrap();\n    for leaf in &previous.binding.successor.leaves {\n        let fact = PrivateSettlementFact {\n            format_version: 1,\n            generation: state.generation,\n            leaf_index: leaf.leaf_index,\n            signature_public_key: leaf.signature_public_key,\n            message_id: MessageId::new(vec![32 + leaf.leaf_index as u8; 32]),\n        };\n        if leaf.signature_public_key == previous.scope.local_device {\n            rounds.record_local_confirmation(&fact, &[34]).unwrap();\n        } else {\n            rounds.record_remote_confirmation(&fact).unwrap();\n        }\n    }\n    let transition = next_raw(1, &previous);\n    let existing = storage\n        .existing_device_group_anchor_storage()\n        .unwrap()\n        .install_existing_anchor(&ExistingDeviceGroupDraft {\n            account: previous.scope.account,\n            local_device: previous.scope.local_device,\n            group_id: previous.binding.group_id.clone(),\n            predecessor: previous.binding.successor.clone(),\n            predecessor_origin: state.anchor.origin,\n            predecessor_settlement_generation: state.generation,\n            action_binding: [35; 32],\n            nonce: transition.binding.nonce,\n            context_digest: transition.binding.context_digest,\n            coordinator: [3; 32],\n            recipient: transition.binding.recipient,\n            key_package_reference: transition.binding.key_package_reference,\n            key_package_digest: transition.binding.key_package_digest,\n            commit_digest: transition.binding.commit_digest,\n            successor: transition.binding.successor,\n        })\n        .unwrap();\n    let cap = storage.private_device_invite_storage().unwrap();\n    cap.deny_confirmed_private_invite(&previous.scope, &previous.binding.group_id)\n        .unwrap();\n    let mut next = next_raw(verified_attempt(&storage), &previous);\n    next.binding.origin = PrivateInviteOrigin::Existing(existing.generation);\n    next.binding.predecessor = existing.draft.successor;\n    next.binding.recipient = [36; 32];\n    next.binding.successor = next.binding.predecessor.clone();\n    next.binding.successor.epoch.0 += 1;\n    next.binding.successor.epoch_authenticator_digest = [37; 32];\n    next.binding.successor.leaves.push(GenesisLeaf {\n        leaf_index: 3,\n        account: previous.scope.account,\n        signature_public_key: next.binding.recipient,\n    });\n    let pending = cap.stage_private_invite(&next).unwrap();\n    cap.cache_private_invite_transport(&pending.scope, &transport())\n        .unwrap();\n    let pending = cap.mark_private_invite_dispatch(&pending.scope).unwrap();\n    (storage, previous, pending, existing.generation)\n}\n\n#[test]\nfn private_device_invite_rotating_sponsor_confirms_current_existing_origin() {\n    let (storage, previous, pending, _) = rotated_sponsor_invite();\n    let cap = storage.private_device_invite_storage().unwrap();\n    let current = cap\n        .confirm_private_invite(&pending.scope, &pending.raw.binding.successor)\n        .expect("fresh existing-member lineage must allow the sponsor\'s next confirmation");\n    assert!(current.scope == pending.scope && !current.denied);\n    assert!(\n        cap.confirm_private_invite(&previous.scope, &previous.binding.successor)\n            .is_err()\n    );\n    assert!(\n        cap.deny_confirmed_private_invite(&previous.scope, &previous.binding.group_id)\n            .is_err()\n    );\n    assert!(cap.confirmed_private_invite().unwrap() == Some(current));\n}\n\n#[test]\nfn private_device_invite_rotating_sponsor_cannot_revive_denied_existing_origin() {\n    let (storage, previous, pending, existing_generation) = rotated_sponsor_invite();\n    storage\n        .existing_device_group_anchor_storage()\n        .unwrap()\n        .deny_existing_anchor(existing_generation, &pending.raw.binding.group_id)\n        .unwrap();\n    let cap = storage.private_device_invite_storage().unwrap();\n    assert!(\n        cap.confirm_private_invite(&pending.scope, &pending.raw.binding.successor)\n            .is_err()\n    );\n    let retained = cap.confirmed_private_invite().unwrap().unwrap();\n    assert!(retained.scope == previous.scope && retained.denied);\n    assert!(cap.private_invite().unwrap().unwrap() == pending);\n}\n\n#[test]\nfn private_device_invite_rotating_sponsor_confirmation_rolls_back_before_exact_retry() {\n    let (storage, previous, pending, _) = rotated_sponsor_invite();\n    storage.lock().unwrap().execute_batch(\n        "CREATE TRIGGER fail_rotated_confirmation BEFORE UPDATE ON private_device_invite_confirmed BEGIN SELECT RAISE(ABORT, \'isolated confirmation fault\'); END;"\n    ).unwrap();\n    let cap = storage.private_device_invite_storage().unwrap();\n    assert!(matches!(\n        cap.confirm_private_invite(&pending.scope, &pending.raw.binding.successor),\n        Err(PrivateInviteStorageError::Storage(_))\n    ));\n    let retained = cap.confirmed_private_invite().unwrap().unwrap();\n    assert!(retained.scope == previous.scope && retained.denied);\n    assert!(cap.private_invite().unwrap().unwrap() == pending);\n    storage\n        .lock()\n        .unwrap()\n        .execute_batch("DROP TRIGGER fail_rotated_confirmation")\n        .unwrap();\n    assert!(\n        cap.confirm_private_invite(&pending.scope, &pending.raw.binding.successor)\n            .is_ok()\n    );\n}\n'
ASSERTION_LINES={0: 321, 2: 359}

CASES=[
 'private_device_invite_tests::private_device_invite_rotating_sponsor_confirms_current_existing_origin',
 'private_device_invite_tests::private_device_invite_rotating_sponsor_cannot_revive_denied_existing_origin',
 'private_device_invite_tests::private_device_invite_rotating_sponsor_confirmation_rolls_back_before_exact_retry']

def source_guard():
    head=old.git('rev-parse','HEAD')
    ensure(os.environ.get('GITHUB_ACTIONS')=='true' and os.environ.get('GITHUB_REPOSITORY')=='dyKiU/mdk'
        and os.environ.get('GITHUB_EVENT_NAME')=='workflow_dispatch' and os.environ.get('GITHUB_SHA')==head
        and os.environ.get('GITHUB_REF')==REF and os.environ.get('GITHUB_WORKFLOW_REF')=='dyKiU/mdk/'+WORKFLOW+'@'+REF
        and os.environ.get('ROTATING_SPONSOR_BASELINE')==BASE,'exact-owned-source')
    ensure(os.environ.get('CARGO_INCREMENTAL')=='1' and os.environ.get('CARGO_BUILD_JOBS')=='2'
        and os.environ.get('RUST_MIN_STACK')=='4194304'
        and all(os.environ.get(k)=='0' for k in ['CARGO_PROFILE_DEV_DEBUG','CARGO_PROFILE_TEST_DEBUG'])
        and all(not os.environ.get(k) for k in ['RUSTFLAGS','CARGO_ENCODED_RUSTFLAGS','RUSTC_BOOTSTRAP','CARGO_PROFILE_DEV_OPT_LEVEL','CARGO_PROFILE_TEST_OPT_LEVEL']),'exact-build-cohort')
    subprocess.run(['git','merge-base','--is-ancestor',BASE,head],check=True)
    ensure(subprocess.run(['git','diff','--quiet','HEAD']).returncode==0,'pristine-source')
    baseline={}
    for entry in subprocess.check_output(['git','ls-tree','-r','-z',BASE]).split(b'\0'):
        if entry:
            meta,name=entry.split(b'\t',1);mode,kind,blob=meta.decode().split()
            ensure(kind=='blob','baseline-blob');baseline[os.fsdecode(name)]=(mode,blob)
    frozen=frozen_inputs();ensure(SELF not in baseline and set(frozen)==set(baseline)|{SELF},'whole-source-inventory')
    for name,record in frozen.items():
        mode,blob=baseline.get(name,('100644',None))
        ensure(record['mode']==mode and (mode=='120000' or record['actual_executable']==(mode=='100755')),'whole-modes')
        if name==SELF:continue
        data=os.fsencode(os.readlink(name)) if mode=='120000' else Path(name).read_bytes()
        if name==TEST:
            ensure(old.digest(data)==TEST_SHA256 and data.count(ADDITION.encode())==1,'exact-reviewed-test-addition')
            data=data.replace(ADDITION.encode(),b'',1)
        if name==WORKFLOW:
            text=data.decode();ensure(text.count(BEGIN)==text.count(END)==text.count(OPTIONS)==1,'marked-workflow-only')
            left,rest=text.split(BEGIN);_,right=rest.split(END)
            data=(left+right).replace(OPTIONS,'options: [',1).encode()
        ensure(hashlib.sha1(b'blob '+str(len(data)).encode()+b'\0'+data).hexdigest()==blob,'reconstructed-baseline:'+name)
    ensure(not subprocess.check_output(['git','ls-files','--others','--exclude-standard'],text=True).strip(),'no-untracked-source')
    return {'source':head,'baseline':BASE,'only_storage_test_addition':True,'App_fixture_adaptations_exact':True,
        'Protocol_provider_and_product_exact':True,'native_five_fixture_helpers_unchanged':True,'whole_modes_exact':True}

def diagnostic(raw,index,row):
    clean=re.sub(r'\x1b\[[0-9;]*m','',raw)
    locations=re.findall(r"panicked at ([A-Za-z0-9_./-]+\.rs):(\d+):(\d+):",clean)
    safe=[{'file':path,'line':int(line),'column':int(column)} for path,line,column in locations
          if path==TEST and 0<int(line)<=2147483647 and 0<int(column)<=2147483647]
    complete=len(safe)==len(locations)==row['panic_count'] and len(safe)<=1
    expected=ASSERTION_LINES.get(index)
    scope_line="fresh existing-member lineage must allow the sponsor's next confirmation: ScopeMismatch"
    primary_scope_mismatch_count=sum(line==scope_line for line in clean.splitlines())
    red=(index in {0,2} and row['actual_counts_complete'] and row['compiler_error_count']==0
         and row['exit_code']==101 and row['passed']==0 and row['failed']==1 and row['ignored']==0
         and complete and len(safe)==1 and safe[0]['line']==expected
         and (index!=0 or primary_scope_mismatch_count==1))
    control=(index==1 and row['passed_gate'])
    return {'safe_panic_locations':safe[:1],'panic_locations_complete':complete,
        'intended_policy_RED_verified':red,'negative_control_PASS':control,
        'primary_scope_mismatch_literal_count':primary_scope_mismatch_count,
        'primary_scope_mismatch_verified':index==0 and primary_scope_mismatch_count==1,
        'raw_private_error_exported':False}

def parser_controls():
    preserved=common.parser_controls()
    name=CASES[0]
    raw='running 1 test\ntest '+name+' ... FAILED\ntest result: FAILED. 0 passed; 1 failed; 0 ignored; 0 measured; 9 filtered out; finished in 0.1s\n'
    raw+="thread 'closed' panicked at "+TEST+':'+str(ASSERTION_LINES[0])+':9:\n'
    scope_line="fresh existing-member lineage must allow the sponsor's next confirmation: ScopeMismatch"
    raw+=scope_line+'\n'
    row=common.parse_body(raw,101,name)
    ensure(diagnostic(raw,0,row)['intended_policy_RED_verified'],'genuine-target-assertion-positive')
    bad=[raw.replace(TEST,'private.rs'),raw.replace(':'+str(ASSERTION_LINES[0])+':',':1:'),
        raw.replace('0 passed; 1 failed','0 passed; 0 failed'),raw+'error[E0000]: rejected\n',raw+raw,
        raw.replace('confirmation: ScopeMismatch','confirmation: Storage'),
        raw.replace(scope_line+'\n',''),raw+scope_line+'\n']
    for value in bad:
        ensure(not diagnostic(value,0,common.parse_body(value,101,name))['intended_policy_RED_verified'],'no-false-RED')
    ensure(not diagnostic(raw,0,common.parse_body(raw,124,name))['intended_policy_RED_verified'],'watchdog-not-RED')
    return {'preserved_closed_counts_inventory':preserved,'target_positive':1,'target_negative':len(bad)+1,'runtime_bodies':0}

def main(args):
    os.umask(0o077);OUT.mkdir(exist_ok=True)
    report={'baseline':BASE,'scope':'three-experimental-Protocol-storage-tests-only','cases':{},'required_nonignored_cases':3,
        'qualification_passed':False,'promotion_eligible':False,'native_acceptance_claim':False,'installed_binary_claim':False,
        'initial_policy_RED_verified':False,'actual_counts_complete':False,'actual_passed':None,'actual_failed':None,'actual_ignored':None}
    frozen=None
    def save():(OUT/'result.json').write_text(json.dumps(report,indent=2)+'\n')
    try:
        report['source_guard']=source_guard();report['parser_controls']=parser_controls();save()
        if args.preflight:report['source_parser_preflight_passed']=True;save();return
        frozen=frozen_inputs();report['input_manifest_sha256']=old.digest(json.dumps(frozen,sort_keys=True).encode())
        report['toolchain']={tool:subprocess.check_output([tool,'--version'],text=True).strip() for tool in ['cargo','rustc']}
        report['capacity']={'free_bytes':shutil.disk_usage('.').free,'minimum_free_bytes':8*1024**3,'cleanup_performed':False};save()
        ensure(report['capacity']['free_bytes']>=8*1024**3,'remote-reserve')
        phase={};report['storage_compile']=phase;binary=common.compile_storage('experimental',frozen,phase,save)
        binary_hash=old.digest(binary.read_bytes());report['inventory']={}
        for name in CASES:
            code,raw,_=old.capture([str(binary),'--exact',name,'--list','--format','terse'],60)
            selected=common.parse_inventory(raw,name);report['inventory'][name]={'selected':selected};save()
            ensure(code==0 and selected['passed'],'one-selected-case')
            code,raw,_=old.capture([str(binary),'--exact',name,'--ignored','--list','--format','terse'],60)
            ignored=common.parse_inventory(raw,name,True);report['inventory'][name]['ignored']=ignored;save()
            ensure(code==0 and ignored['passed'],'nonignored-case')
        for index,name in enumerate(CASES):
            ensure(frozen_inputs()==frozen and old.digest(binary.read_bytes())==binary_hash,'before-body-pristine')
            report['active_case']=name;save()
            code,raw,seconds=old.capture([str(binary),'--exact',name,'--nocapture','--test-threads=1'],300,limit=8*1024*1024)
            row=common.parse_body(raw,code,name);row.update(wall_seconds=seconds,binary_sha256=binary_hash)
            report['cases'][name]=row;save() # Persist actual counts BEFORE any diagnostic parsing.
            row['diagnostic']=diagnostic(raw,index,row);save()
            ensure(frozen_inputs()==frozen and old.digest(binary.read_bytes())==binary_hash,'after-body-pristine')
            ensure(row['actual_counts_complete'] and row['compiler_error_count']==0 and code in {0,101},'actual-body-not-compile-or-watchdog')
        rows=[report['cases'][name] for name in CASES]
        report['actual_counts_complete']=all(row['actual_counts_complete'] for row in rows)
        if report['actual_counts_complete']:
            report.update(actual_passed=sum(row['passed'] for row in rows),actual_failed=sum(row['failed'] for row in rows),
                          actual_ignored=sum(row['ignored'] for row in rows),actual_executed_nonignored=3)
        report['initial_policy_RED_verified']=(report['actual_counts_complete'] and rows[1]['diagnostic']['negative_control_PASS']
            and rows[0]['diagnostic']['intended_policy_RED_verified'] and rows[2]['diagnostic']['intended_policy_RED_verified'])
        save();ensure(report['initial_policy_RED_verified'],'both-target-runtime-REDs-and-negative-control-required')
    except Exception as error:
        report['exception_type']=type(error).__name__
        if isinstance(error,ValueError):report['failure_gate']=str(error) if re.fullmatch('[A-Za-z0-9_.:/-]{1,140}',str(error)) else 'closed-gate-rejected'
        raise
    finally:
        if frozen is not None:report['inputs_pristine']=frozen_inputs()==frozen
        save()
        if frozen is not None:ensure(report['inputs_pristine'],'final-source-pristine')

if __name__=='__main__':
    parser=argparse.ArgumentParser();parser.add_argument('--preflight',action='store_true');main(parser.parse_args())
