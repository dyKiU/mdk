#!/usr/bin/env python3
"""Scoped synthetic storage GREEN/necessity; never native/full qualification."""
import argparse
import hashlib
import io
import json
import os
from pathlib import Path
import re
import shutil
import stat
import subprocess
import zipfile
import qualify_upstream_rotating_sponsor_red as red
from upstream_extraction_cohort import frozen_inputs
common=red.common
old=common.old
ensure=old.ensure
BASE='58b40563064795d48f018b23bd5b76644978e179'
SELF='scripts/qualify_upstream_rotating_sponsor_candidate.py'
PRODUCT='crates/storage-sqlite/src/private_device_invite.rs'
WORKFLOW=red.WORKFLOW
BEGIN='  # ROTATING_SPONSOR_CANDIDATE_JOBS_BEGIN\n'
END='  # ROTATING_SPONSOR_CANDIDATE_JOBS_END\n'
OPTIONS='options: [rotating-sponsor-candidate-preflight, rotating-sponsor-candidate-green, rotating-sponsor-candidate-mutations, '
PRODUCT_SHA='314c6f409d7048737da17f7ddaaa01186364cbcdbd716e50724261f1d04564af'
# Root fills ONLY after exact remote evidence is independently verified. Unset is closed.
REVIEWED_RED={'run_id':39112670082,'artifact_id':12131555243,'archive_sha256':'a3138940349af13828915ba1cfa438f0db176e572f3d552818c4fb929af7a975','head_sha':BASE}
REVIEWED_GREEN={'run_id':39113517951,'artifact_id':12131751503,'archive_sha256':'e02ce3a98b14b27e4365521b08eafbdc960c58dbe4a8704aff1d81642bb9589d','head_sha':'25ec129257c14818f0eedc38b8115f9997028901'}
OLD='''            } else if old.as_ref().is_some_and(|old| old.binding.group_id==current.raw.binding.group_id) {
                return Err(Error::ScopeMismatch);
'''
NEW='''            } else if let Some(old) = old.as_ref().filter(|old| old.binding.group_id==current.raw.binding.group_id) {
                // check_origin freshly validated the exact existing/removal successor.
                // A denied historical confirmation must not veto this new generation;
                // it still cannot be reused as the current Confirmed origin above.
                if !old.denied || !matches!(current.raw.binding.origin,
                    PrivateInviteOrigin::Existing(_) | PrivateInviteOrigin::Revoked(_)) {
                    return Err(Error::ScopeMismatch);
                }
'''
ORIGIN='''            if pending.phase != PrivateInvitePhase::Confirmed {
                check_origin(storage, &pending.raw.binding)?;
            }
'''
NO_ORIGIN='''            // Owned counterfactual: omit only confirmation-time origin validation.
'''
PREFIX='private_device_invite_tests::'
COMPONENT=[PREFIX+name for name in [
 'private_device_invite_stage_exact_retry_and_undispatched_retirement',
 'private_device_invite_wrong_origin_owner_or_raw_integrity_never_allocates',
 'private_device_invite_rotating_sponsor_confirms_current_existing_origin',
 'private_device_invite_rotating_sponsor_cannot_revive_denied_existing_origin',
 'private_device_invite_rotating_sponsor_confirmation_rolls_back_before_exact_retry',
 'private_device_invite_rotating_sponsor_confirms_current_revoked_origin',
 'private_device_invite_rotating_sponsor_cannot_revive_denied_revoked_origin',
 'private_device_invite_uncertain_publication_cannot_retire_or_replace',
 'private_device_invite_next_retirement_preserves_confirmed_anchor',
 'private_device_invite_confirmation_failure_rolls_back_both_slots',
 'private_device_invite_denied_confirmed_origin_cannot_be_revived_by_pending_confirmation',
 'private_device_invite_denied_genesis_cannot_be_revived_by_pending_confirmation',
 'private_device_invite_group_deletion_preserves_publication_uncertainty',
 'private_device_invite_unresolved_blocks_new_pairing_without_changing_scope',
 'private_device_invite_unresolved_blocks_replacing_denied_genesis',
 'private_device_invite_unresolved_blocks_selecting_an_accepted_group',
 'private_device_invite_accepted_origin_retry_is_read_only_while_outgoing_is_pending',
 'private_device_invite_encrypted_reopen_retains_exact_uncertainty_and_scope',
 'private_invite_transport_duplicate_ids_do_not_freeze_a_draft',
 'private_invite_batch_bounds_and_exact_order_are_atomic',
 'private_invite_full_bound_batch_survives_storage_and_old_singleton_shape_fails_closed']]+['base::migrations::private_device_invite_tests::private_device_invite_schema_preserves_confirmed_anchor_separately',
 'base::migrations::private_device_invite_tests::private_device_invite_schema_retirement_and_deletion_preserve_denied_provenance']
OUT=Path('rotating-sponsor-candidate-evidence')

def source_guard():
    head=old.git('rev-parse','HEAD')
    ensure(os.environ.get('GITHUB_ACTIONS')=='true' and os.environ.get('GITHUB_REPOSITORY')=='dyKiU/mdk'
        and os.environ.get('GITHUB_EVENT_NAME')=='workflow_dispatch' and os.environ.get('GITHUB_SHA')==head
        and os.environ.get('GITHUB_REF')==red.REF and os.environ.get('GITHUB_WORKFLOW_REF')=='dyKiU/mdk/'+WORKFLOW+'@'+red.REF
        and os.environ.get('ROTATING_SPONSOR_CANDIDATE_BASELINE')==BASE,'exact-owned-source')
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
        if name==PRODUCT:
            ensure(old.digest(data)==PRODUCT_SHA and data.count(NEW.encode())==1 and data.count(ORIGIN.encode())==1,'exact-reviewed-product')
            data=data.replace(NEW.encode(),OLD.encode(),1)
        if name==WORKFLOW:
            text=data.decode();ensure(text.count(BEGIN)==text.count(END)==text.count(OPTIONS)==1,'marked-workflow-only')
            left,rest=text.split(BEGIN);_,right=rest.split(END)
            data=(left+right).replace(OPTIONS,'options: [',1).encode()
        ensure(hashlib.sha1(b'blob '+str(len(data)).encode()+b'\0'+data).hexdigest()==blob,'reconstructed-baseline:'+name)
    ensure(not subprocess.check_output(['git','ls-files','--others','--exclude-standard'],text=True).strip(),'no-untracked-source')
    return {'source':head,'baseline':BASE,'exact_e71_production_delta_only':True,
        'frozen_five_tests_and_historical_controllers':True,'whole_tree_modes_exact':True,'native_acceptance':False}

def prior_receipt(kind):
    pin=REVIEWED_RED if kind=='red' else REVIEWED_GREEN
    ensure(type(pin['run_id']) is int and type(pin['artifact_id']) is int
        and isinstance(pin['archive_sha256'],str) and re.fullmatch('[0-9a-f]{64}',pin['archive_sha256'])
        and isinstance(pin['head_sha'],str) and re.fullmatch('[0-9a-f]{40}',pin['head_sha']),'verified-'+kind+'-pin-required')
    def api(path):return json.loads(subprocess.check_output(['gh','api','repos/dyKiU/mdk/'+path],timeout=60))
    run=api('actions/runs/'+str(pin['run_id']))
    ensure(run['head_sha']==pin['head_sha'] and run['event']=='workflow_dispatch' and run['conclusion']=='success'
        and run['head_repository']['full_name']=='dyKiU/mdk','prior-'+kind+'-run-identity')
    subprocess.run(['git','merge-base','--is-ancestor',pin['head_sha'],'HEAD'],check=True)
    artifact=api('actions/artifacts/'+str(pin['artifact_id']))
    ensure(not artifact['expired'] and artifact['workflow_run']['id']==pin['run_id']
        and artifact['size_in_bytes']<=2*1024*1024 and artifact['digest']=='sha256:'+pin['archive_sha256'],'prior-'+kind+'-artifact-identity')
    payload=subprocess.check_output(['gh','api','repos/dyKiU/mdk/actions/artifacts/'+str(pin['artifact_id'])+'/zip'],timeout=60)
    ensure(len(payload)<=2*1024*1024 and old.digest(payload)==pin['archive_sha256'],'prior-'+kind+'-archive-digest')
    with zipfile.ZipFile(io.BytesIO(payload)) as archive:
        infos=archive.infolist()
        ensure(len(infos)==1 and infos[0].filename=='result.json' and infos[0].file_size<=1024*1024,'prior-'+kind+'-single-result')
        receipt=json.loads(archive.read(infos[0]))
    expected=(5,2,3) if kind=='red' else (23,23,0)
    ensure(receipt['source_guard']['source']==pin['head_sha'] and receipt['inputs_pristine'] is True
        and receipt['actual_counts_complete'] is True
        and all(type(receipt[k]) is int for k in ['actual_executed_nonignored','actual_passed','actual_failed','actual_ignored'])
        and (receipt['actual_executed_nonignored'],receipt['actual_passed'],receipt['actual_failed'])==expected
        and receipt['actual_ignored']==0,'prior-'+kind+'-actual-counts')
    ensure(receipt['initial_policy_RED_verified'] is True if kind=='red' else receipt['component_green'] is True,'prior-'+kind+'-verdict')
    compilation=receipt['storage_compile']['compilation'] if kind=='red' else receipt['phases']['controls']['compilation']
    ensure(compilation['succeeded'] is True and type(compilation['compiler_error_count']) is int and compilation['compiler_error_count']==0 and compilation['compiled_features']==['experimental-device-sync'],'prior-'+kind+'-compile-features')
    if kind=='green':
        # Child metadata is transparent: compare every prior tree input except this controller/workflow.
        for entry in subprocess.check_output(['git','ls-tree','-r','-z',pin['head_sha']]).split(b'\0'):
            if not entry:continue
            meta,name=entry.split(b'\t',1);name=os.fsdecode(name)
            if name in {SELF,WORKFLOW}:continue
            mode,_,blob=meta.decode().split();now=old.git('ls-tree','HEAD','--',name).split()
            ensure(now[:3]==[mode,'blob',blob],'prior-green-relevant-tree:'+name)
    return {'run_id':pin['run_id'],'artifact_id':pin['artifact_id'],'archive_sha256':pin['archive_sha256'],
        'compiled_binary_sha256':compilation['binary_sha256'],'feature_profile_manifest_sha256':compilation['compiler_artifact_feature_manifest_sha256'],
        'tested_source':pin['head_sha'],'metadata_child_not_exact_prior_sha':pin['head_sha']!=old.git('rev-parse','HEAD')}

def inventory(binary,names,phase,save):
    code,raw,_=old.capture([str(binary),PREFIX,'--list','--format','terse'],60)
    lines=[line for line in raw.splitlines() if line]
    actual=[line[:-6] for line in lines if line.endswith(': test')]
    remainder=[line for line in lines if not line.endswith(': test')]
    phase['module_inventory']={'names':actual,'unknown_or_summary_lines':len(remainder),'expected_count':23};save()
    ensure(code==0 and sorted(actual)==sorted(COMPONENT) and len(actual)==23
        and remainder in [[],['23 tests, 0 benchmarks']],'exact-full-component-inventory')
    for name in names:
        for ignored in [False,True]:
            command=[str(binary),'--exact',name]+(['--ignored'] if ignored else [])+['--list','--format','terse']
            code,raw,_=old.capture(command,60);parsed=common.parse_inventory(raw,name,ignored)
            phase.setdefault('selected_inventory',{}).setdefault(name,{})['ignored' if ignored else 'normal']=parsed;save()
            ensure(code==0 and parsed['passed'],'selected-nonignored-inventory')

def typed_one(row,passed,failed):
    return all(type(row.get(k)) is int for k in ['exit_code','passed','failed','ignored','executed_nonignored','compiler_error_count','panic_count']) and row['actual_counts_complete'] is True and row['exit_code']==(101 if failed else 0) and row['passed']==passed and row['failed']==failed and row['ignored']==0 and row['executed_nonignored']==1 and row['compiler_error_count']==0 and row['panic_count']==failed

def cause(raw,index,row,chain):
    if chain=='old_veto':return (typed_one(row,0,1) and red.diagnostic(raw,index,row)['intended_policy_RED_verified']) if index in {0,2,3} else (typed_one(row,1,0) and row['passed_gate'])
    if index not in {1,4}:return typed_one(row,1,0) and row['passed_gate']
    clean=re.sub(r'\x1b\[[0-9;]*m','',raw)
    sites=re.findall(r'panicked at ([A-Za-z0-9_./-]+\.rs):(\d+):(\d+):',clean)
    expected=343 if index==1 else 496
    # No raw error or SQL exported. Sole unchanged assert at the post-dispatch denial boundary.
    return typed_one(row,0,1) and len(sites)==1 and sites[0][0]==red.TEST and int(sites[0][1])==expected and int(sites[0][2])>0

def phase(names,frozen,target,save,chain=None):
    target['source_manifest_sha256']=old.digest(json.dumps(frozen,sort_keys=True).encode());save()
    binary=common.compile_storage('experimental',frozen,target,save)
    digest=old.digest(binary.read_bytes());inventory(binary,names,target,save)
    target['cases']={}
    for name in names:
        ensure(frozen_inputs()==frozen and old.digest(binary.read_bytes())==digest,'before-case-pristine')
        code,raw,seconds=old.capture([str(binary),'--exact',name,'--nocapture','--test-threads=1'],300,limit=8*1024*1024)
        row=common.parse_body(raw,code,name);row.update(wall_seconds=seconds,binary_sha256=digest)
        target['cases'][name]=row;save() # Retain actual counts before interpreting an intended counterfactual.
        if chain:
            index=red.CASES.index(name)
            if chain=='old_veto':row['counterfactual_cause']=red.diagnostic(raw,index,row)
            else:
                sites=re.findall(r'panicked at ([A-Za-z0-9_./-]+\.rs):(\d+):(\d+):',raw)
                safe=[{'file':path,'line':int(line),'column':int(column)} for path,line,column in sites if path==red.TEST and 0<int(line)<=2147483647 and 0<int(column)<=2147483647]
                row['counterfactual_cause']={'safe_panic_locations':safe[:1],'locations_complete':len(safe)==len(sites)==row['panic_count'] and len(safe)<=1,'expected_denial_assertion_line':343 if index==1 else 496 if index==4 else None,'raw_error_exported':False}
        row['expected_runtime_outcome']=(cause(raw,red.CASES.index(name),row,chain) if chain else row['passed_gate']);save()
        ensure(frozen_inputs()==frozen and old.digest(binary.read_bytes())==digest,'after-case-pristine')
    rows=list(target['cases'].values())
    complete=len(rows)==len(names) and all(row['actual_counts_complete'] for row in rows)
    for key in ['passed','failed','ignored','executed_nonignored']:
        target['actual_'+key]=sum(row[key] for row in rows) if len(rows)==len(names) and all(type(row.get(key)) is int for row in rows) else None
    target['actual_counts_complete']=complete
    target['expected_runtime_outcomes_complete']=complete and all(row['expected_runtime_outcome'] for row in rows)
    target['inputs_pristine']=frozen_inputs()==frozen;save()
    ensure(target['inputs_pristine'],'phase-source-pristine')
    return target['expected_runtime_outcomes_complete']

def parser_controls():
    controls=red.parser_controls();name=red.CASES[1]
    raw='running 1 test\ntest '+name+' ... FAILED\ntest result: FAILED. 0 passed; 1 failed; 0 ignored; 0 measured; 9 filtered out; finished in 0.1s\n'
    raw+="thread 'closed' panicked at "+red.TEST+':343:5:\nassertion failed: closed\n'
    row=common.parse_body(raw,101,name);ensure(cause(raw,1,row,'no_origin'),'denial-mutant-positive')
    bad=[raw+raw,raw.replace(':343:',':1:'),raw.replace(red.TEST,'other.rs'),raw.replace('0 ignored','1 ignored'),raw.replace('1 failed','0 failed'),raw+'error[E0000]: rejected\n']
    for value in bad:ensure(not cause(value,1,common.parse_body(value,101,name),'no_origin'),'denial-mutant-adversary')
    boolean=dict(row);boolean['failed']=True;ensure(not cause(raw,1,boolean,'no_origin'),'boolean-count-rejected')
    ensure(not cause(raw,1,common.parse_body(raw,124,name),'no_origin'),'watchdog-rejected')
    revoked=raw.replace(name,red.CASES[4]).replace(':343:',':496:')
    ensure(cause(revoked,4,common.parse_body(revoked,101,red.CASES[4]),'no_origin'),'revoked-denial-positive')
    for text in [revoked.replace(':496:',':343:'),revoked+revoked,revoked.replace(red.CASES[4],name)]:
        ensure(not cause(text,4,common.parse_body(text,101,red.CASES[4]),'no_origin'),'revoked-denial-adversary')
    return {'preserved':controls,'denial_positive':2,'denial_negative':len(bad)+5,'runtime_executions':0}

def main(args):
    os.umask(0o077);OUT.mkdir(exist_ok=True)
    report={'baseline':BASE,'mode':args.mode,'qualification_passed':False,'promotion_eligible':False,
        'native_acceptance_claim':False,'component_green':False,'component_mutation_verified':False,'actual_counts_complete':False,
        'actual_passed':None,'actual_failed':None,'actual_ignored':None,'actual_executed_nonignored':None,'phases':{}}
    frozen=None;original=None;original_mode=None
    def save():(OUT/'result.json').write_text(json.dumps(report,indent=2)+'\n')
    try:
        report['source_guard']=source_guard();report['parser_controls']=parser_controls();save()
        if args.mode=='preflight':report['preflight_passed']=True;save();return
        report['reviewed_RED']=prior_receipt('red');save()
        frozen=frozen_inputs();original=Path(PRODUCT).read_bytes();original_mode=stat.S_IMODE(Path(PRODUCT).stat().st_mode)
        report['capacity_free_bytes']=shutil.disk_usage('.').free;save();ensure(report['capacity_free_bytes']>=8*1024**3,'remote-capacity')
        if args.mode=='green':
            target=report['phases']['controls']={};report['component_green']=phase(COMPONENT,frozen,target,save)
            report.update({key:target.get(key) for key in ['actual_passed','actual_failed','actual_ignored','actual_executed_nonignored','actual_counts_complete']});save()
            ensure(report['component_green'],'all23-component-controls-required');return
        report['reviewed_component_GREEN']=prior_receipt('green');save()
        baseline=report['phases']['baseline']={};ensure(phase(red.CASES,frozen,baseline,save),'five-baseline-controls-required')
        ensure(baseline['compilation']['binary_sha256']==report['reviewed_component_GREEN']['compiled_binary_sha256'] and baseline['compilation']['compiler_artifact_feature_manifest_sha256']==report['reviewed_component_GREEN']['feature_profile_manifest_sha256'],'prior-green-binary-and-profile-match')
        changed=original.replace(NEW.encode(),OLD.encode(),1) if args.mode=='old_veto' else original.replace(ORIGIN.encode(),NO_ORIGIN.encode(),1)
        ensure(changed!=original and original.count(NEW.encode())==original.count(ORIGIN.encode())==1,'one-exact-mutant')
        Path(PRODUCT).write_bytes(changed);os.chmod(PRODUCT,original_mode) # Fresh write mtimes; never copy old metadata.
        mutated=frozen_inputs();ensure(set(mutated)==set(frozen) and all(mutated[k]==frozen[k] for k in frozen if k!=PRODUCT),'mutant-only-owned-source')
        mutant=report['phases']['mutant']={}
        try:mutant_ok=phase(red.CASES,mutated,mutant,save,args.mode)
        finally:
            Path(PRODUCT).write_bytes(original);os.chmod(PRODUCT,original_mode)
            report['source_and_modes_restored_after_mutant']=frozen_inputs()==frozen;save()
        restored=report['phases']['restored']={};restored_ok=phase(red.CASES,frozen,restored,save)
        records=[entry['compilation'] for entry in [baseline,mutant,restored]]
        binaries=[entry['binary_sha256'] for entry in records]
        features=[entry['compiler_artifact_feature_manifest_sha256'] for entry in records]
        report['binary_restoration_verified']=binaries[0]==binaries[2] and binaries[0]!=binaries[1]
        report['compiled_feature_profile_identity_same']=features[0]==features[1]==features[2]
        report['actual_counts_complete']=all(entry.get('actual_counts_complete') is True for entry in [baseline,mutant,restored])
        for key in ['passed','failed','ignored','executed_nonignored']:
            values=[entry.get('actual_'+key) for entry in [baseline,mutant,restored]]
            report['actual_'+key]=sum(values) if all(type(value) is int for value in values) else None
        report['component_mutation_verified']=bool(mutant_ok and restored_ok and report['source_and_modes_restored_after_mutant'] and report['binary_restoration_verified'] and report['compiled_feature_profile_identity_same'] and report['actual_counts_complete'])
        save();ensure(report['component_mutation_verified'],'actual-runtime-counterfactual-and-exact-restoration-required')
    except Exception as error:
        report['exception_type']=type(error).__name__
        if isinstance(error,ValueError):report['failure_gate']=str(error) if re.fullmatch('[A-Za-z0-9_.:/-]{1,140}',str(error)) else 'closed-gate-rejected'
        raise
    finally:
        if original is not None:
            Path(PRODUCT).write_bytes(original);os.chmod(PRODUCT,original_mode)
        if frozen is not None:report['inputs_pristine']=frozen_inputs()==frozen
        save()
        if frozen is not None:ensure(report['inputs_pristine'],'final-source-mode-restoration')

if __name__=='__main__':
    parser=argparse.ArgumentParser();parser.add_argument('--mode',choices=['preflight','green','old_veto','no_origin'],required=True);main(parser.parse_args())
