#!/usr/bin/env python3
"""Two deterministic Protocol read-snapshot regressions; no App/native/full claim."""
import argparse
import copy
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import qualify_upstream_storage_app_handles as common
from upstream_extraction_cohort import frozen_inputs
old=common.old
ensure=old.ensure
BASE='c3215b2a5f8a9dfe6c8a0628e99f8ab13a771084' # Root pins the exact reviewed test-bearing RED or subsequent pure FIX baseline.
FIXTURE='crates/storage-sqlite/src/private_roster_settlement/tests.rs'
FIXTURE_SHA='32726730a2ea73101f771e11c5709dc8ff525ae58acbdec7d11762c9e25d8594'
CASES={
    'round':{'name':'private_roster_settlement::tests::private_settlement_read_round_pins_foreign_wal_replacement','line':789,'message':'public settlement round snapshot must preserve coherent committed state and facts'},
    'facts':{'name':'private_roster_settlement::tests::private_settlement_read_facts_pins_foreign_wal_replacement','line':793,'message':'public settlement facts snapshot must preserve coherent committed state and facts'},
    'control':{'name':'private_roster_settlement::tests::private_settlement_snapshot_reads_reject_persisted_foreign_generation_fact'},
} # Root fills exact final assertion locations/payloads after source review.
MUTATIONS={'round': {'path': 'crates/storage-sqlite/src/private_roster_settlement.rs', 'old': '    fn read_round(&self) -> StorageResult<Option<PrivateSettlementState>> {\n        self.connection.with_deferred_read(read)\n    }\n', 'new': '    fn read_round(&self) -> StorageResult<Option<PrivateSettlementState>> {\n        {\n            let conn = self.lock()?;\n            read(&conn)\n        }\n    }\n'}, 'facts': {'path': 'crates/storage-sqlite/src/private_roster_settlement.rs', 'old': '    fn read_facts(&self) -> StorageResult<Vec<PrivateSettlementFact>> {\n        self.connection.with_deferred_read(|conn| match read(conn)? {\n            Some(state) => facts(conn, &state),\n            None => Ok(vec![]),\n        })\n    }\n', 'new': '    fn read_facts(&self) -> StorageResult<Vec<PrivateSettlementFact>> {\n        let conn = self.lock()?;\n        match read(&conn)? {\n            Some(s) => facts(&conn, &s),\n            None => Ok(vec![]),\n        }\n    }\n'}}
SELF='scripts/qualify_upstream_settlement_read_snapshot.py'
WORKFLOW='.github/workflows/upstream-boundary-regressions.yml'
REF='refs/heads/ci/upstream-settlement-read-snapshot-20261018'
BEGIN='  # SNAPSHOT_READ_JOBS_BEGIN\n'
END='  # SNAPSHOT_READ_JOBS_END\n'
OPTIONS='options: [settlement-read-preflight, settlement-read-red, settlement-read-green, settlement-read-mutations, '
OUT=Path('settlement-read-snapshot-evidence')

def source_guard(mutation):
    ensure(isinstance(BASE,str) and re.fullmatch('[0-9a-f]{40}',BASE),'reviewed-full-baseline-required')
    ensure(isinstance(FIXTURE,str) and FIXTURE.startswith('crates/storage-sqlite/') and isinstance(FIXTURE_SHA,str)
        and re.fullmatch('[0-9a-f]{64}',FIXTURE_SHA),'reviewed-fixture-required')
    ensure(isinstance(CASES,dict) and set(CASES)=={'round','facts','control'}
        and len({spec['name'] for spec in CASES.values()})==3,'exact-three-reviewed-cases-required')
    for key,spec in CASES.items():
        if key=='control':
            ensure(re.fullmatch('[A-Za-z_][A-Za-z0-9_:]+',spec['name']),'reviewed-denial-control-required');continue
        ensure(re.fullmatch('[A-Za-z_][A-Za-z0-9_:]+',spec['name']) and type(spec['line']) is int
            and spec['line']>0 and isinstance(spec['message'],str) and 0<len(spec['message'])<=256,'reviewed-runtime-oracle-required')
    head=old.git('rev-parse','HEAD')
    ensure(os.environ.get('GITHUB_ACTIONS')=='true' and os.environ.get('GITHUB_REPOSITORY')=='dyKiU/mdk'
        and os.environ.get('GITHUB_EVENT_NAME')=='workflow_dispatch' and os.environ.get('GITHUB_SHA')==head
        and os.environ.get('GITHUB_REF')==REF and os.environ.get('GITHUB_WORKFLOW_REF')=='dyKiU/mdk/'+WORKFLOW+'@'+REF
        and os.environ.get('SETTLEMENT_READ_BASELINE')==BASE,'exact-owned-source')
    ensure(os.environ.get('CARGO_INCREMENTAL')=='1' and os.environ.get('CARGO_BUILD_JOBS')=='2'
        and os.environ.get('RUST_MIN_STACK')=='4194304'
        and all(os.environ.get(k)=='0' for k in ['CARGO_PROFILE_DEV_DEBUG','CARGO_PROFILE_TEST_DEBUG'])
        and all(not os.environ.get(k) for k in ['RUSTFLAGS','CARGO_ENCODED_RUSTFLAGS','RUSTC_BOOTSTRAP','CARGO_PROFILE_DEV_OPT_LEVEL','CARGO_PROFILE_TEST_OPT_LEVEL']),'exact-build-cohort')
    subprocess.run(['git','merge-base','--is-ancestor',BASE,head],check=True)
    ensure(subprocess.run(['git','diff','--quiet','HEAD']).returncode==0,'initial-tracked-pristine')
    baseline={}
    for entry in subprocess.check_output(['git','ls-tree','-r','-z',BASE]).split(b'\0'):
        if entry:
            meta,name=entry.split(b'\t',1);mode,kind,blob=meta.decode().split()
            ensure(kind=='blob','baseline-blob');baseline[os.fsdecode(name)]=(mode,blob)
    current=frozen_inputs();ensure(SELF not in baseline and FIXTURE in baseline and set(current)==set(baseline)|{SELF},'whole-source-inventory')
    for name,record in current.items():
        mode,blob=baseline.get(name,('100644',None))
        ensure(record['mode']==mode and (mode=='120000' or record['actual_executable']==(mode=='100755')),'whole-source-modes')
        if name==SELF:continue
        data=os.fsencode(os.readlink(name)) if mode=='120000' else Path(name).read_bytes()
        if name==FIXTURE:ensure(old.digest(data)==FIXTURE_SHA,'exact-frozen-fixture')
        if name==WORKFLOW:
            text=data.decode();ensure(text.count(BEGIN)==text.count(END)==text.count(OPTIONS)==1,'one-owned-overlay')
            left,rest=text.split(BEGIN);_,right=rest.split(END)
            data=(left+right).replace(OPTIONS,'options: [',1).encode()
        ensure(hashlib.sha1(b'blob '+str(len(data)).encode()+b'\0'+data).hexdigest()==blob,'exact-baseline:'+name)
    ensure(set(subprocess.check_output(['git','ls-files','--others','--exclude-standard'],text=True).splitlines())<={str(OUT/'result.json')},'no-untracked-source')
    if mutation:
        spec=MUTATIONS[mutation];ensure(isinstance(spec,dict) and set(spec)=={'path','old','new'},'reviewed-independent-mutation-required')
        ensure(spec['path'] in baseline and spec['old']!=spec['new'] and Path(spec['path']).read_text().count(spec['old'])==1
            and spec['new'] not in Path(spec['path']).read_text(),'unique-production-snapshot-omission')
    return {'source':head,'baseline':BASE,'fixture_sha256':FIXTURE_SHA,'whole_contents_and_modes_exact':True,
        'historical_source_guard_invoked':False,'historical_runtime_evidence_reused':False}


MARKER_PREFIX='private_settlement_read_snapshot '
MARKER_PATTERN=(r'private_settlement_read_snapshot mode=(round|facts) boundary_seen=(true|false) writer_committed=(true|false)'
    r' callback_completed=(true|false) independent_handles=(true|false) observed_statements=([12]) coherent_old_view=(true|false)'
    r' fresh_new_view=(true|false) typed_serialization=(true|false) returned_facts=(true|false)')

def marker(raw,key):
    clean=re.sub(r'\x1b\[[0-9;]*m','',raw)
    clean=re.sub(r'(?m)^test '+re.escape(CASES[key]['name'])+r' \.\.\. (?=private_settlement_read_snapshot )','',clean)
    lines=[line for line in clean.splitlines() if line.startswith(MARKER_PREFIX)]
    match=re.fullmatch(MARKER_PATTERN,lines[0]) if len(lines)==1 and len(lines[0])<=512 else None
    if not match or match[1]!=key:return None
    return {'mode':match[1],'boundary_seen':match[2]=='true','writer_committed':match[3]=='true',
        'callback_completed':match[4]=='true','independent_handles':match[5]=='true','observed_statements':int(match[6]),
        'coherent_old_view':match[7]=='true','fresh_new_view':match[8]=='true','typed_serialization':match[9]=='true','returned_facts':match[10]=='true'}

def marker_oracle(value,key,red):
    return (isinstance(value,dict) and all(value[k] is True for k in ['boundary_seen','writer_committed','callback_completed','independent_handles','fresh_new_view'])
        and value['observed_statements']==(1 if key=='round' else 2) and value['coherent_old_view'] is (not red)
        and value['typed_serialization'] is (red and key=='round') and value['returned_facts'] is (key=='facts'))

def intended_red(raw,code,key,row):
    spec=CASES[key];clean=re.sub(r'\x1b\[[0-9;]*m','',raw)
    loc=re.findall(r'panicked at ([A-Za-z0-9_./-]+\.rs):([0-9]+):([0-9]+):',clean)
    target=len(loc)==1 and loc[0][0]==FIXTURE and int(loc[0][1])==spec['line'] and int(loc[0][2])>0
    return (row['actual_counts_complete'] is True and type(row['compiler_error_count']) is int and row['compiler_error_count']==0
        and type(row['panic_count']) is int and row['panic_count']==1 and row['exit_code']==code==101
        and all(type(row.get(k)) is int and row[k]==v for k,v in {'passed':0,'failed':1,'ignored':0,'executed_nonignored':1}.items())
        and target and sum(line==spec['message'] for line in clean.splitlines())==1 and marker_oracle(marker(raw,key),key,True))

def parser_controls():
    preserved=common.parser_controls();count=0
    for key,spec in CASES.items():
        if key=='control':continue
        name=spec['name'];raw='running 1 test\ntest '+name+' ... FAILED\ntest result: FAILED. 0 passed; 1 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.1s\n'
        closed='private_settlement_read_snapshot mode='+key+' boundary_seen=true writer_committed=true callback_completed=true independent_handles=true observed_statements='+('1' if key=='round' else '2')+' coherent_old_view=false fresh_new_view=true typed_serialization='+('true' if key=='round' else 'false')+' returned_facts='+('false' if key=='round' else 'true')
        raw+="thread 'closed' panicked at "+FIXTURE+':'+str(spec['line'])+':5:\n'+spec['message']+'\n'+closed+'\n'
        ensure(intended_red(raw,101,key,common.parse_body(raw,101,name)),'exact-runtime-RED-positive')
        shared=raw.replace(' ... FAILED\n',' ... '+closed+'\nFAILED\n',1).replace(spec['message']+'\n'+closed+'\n',spec['message']+'\n',1)
        ensure(intended_red(shared,101,key,common.parse_body(shared,101,name)),'exact-shared-header-RED-positive')
        bad=[raw+raw,raw.replace(spec['message'],'unexpected'),raw+spec['message']+'\n',raw.replace(FIXTURE,'private.rs'),
            raw.replace(':'+str(spec['line'])+':',':1:'),raw.replace(name,name+'_foreign'),raw+'error[E0000]: hidden\n',raw.replace('0 ignored','1 ignored'),raw.replace('writer_committed=true','writer_committed=false'),
            raw.replace('coherent_old_view=false','coherent_old_view=true'),raw.replace(closed,''),raw+closed+'\n',
            raw.replace('observed_statements='+('1' if key=='round' else '2'),'observed_statements=0')]
        bad += [raw.replace(field+'=true',field+'=false') for field in ['boundary_seen','callback_completed','independent_handles','fresh_new_view']]
        bad += [raw.replace('typed_serialization='+('true' if key=='round' else 'false'),'typed_serialization='+('false' if key=='round' else 'true')),
            raw.replace('returned_facts='+('false' if key=='round' else 'true'),'returned_facts='+('true' if key=='round' else 'false')),
            raw.replace('mode='+key,'mode=unknown')]
        for value in bad:ensure(not intended_red(value,101,key,common.parse_body(value,101,name)),'no-false-runtime-RED');count+=1
        ensure(not intended_red(raw,124,key,common.parse_body(raw,124,name)),'watchdog-not-RED');count+=1
    return {'preserved_closed_counts_inventory':preserved,'positive':4,'negative':count,'runtime_bodies':0}

def run_phase(expected,keys,phase,save):
    ensure(frozen_inputs()==expected,'before-phase-pristine')
    binary=common.compile_storage('experimental',expected,phase,save);sha=old.digest(binary.read_bytes())
    phase['binary_sha256']=sha;phase['source_manifest_sha256']=old.digest(json.dumps(expected,sort_keys=True).encode());phase['cases']={};save()
    for key in keys:
        name=CASES[key]['name'];phase.setdefault('inventory',{})[key]={}
        for ignored in [False,True]:
            code,raw,_=old.capture([str(binary),'--exact',name]+(['--ignored'] if ignored else [])+['--list','--format','terse'],60)
            inv=common.parse_inventory(raw,name,ignored);phase['inventory'][key]['ignored' if ignored else 'normal']=inv;save()
            ensure(code==0 and inv['passed'],'one-selected-nonignored-case')
        ensure(frozen_inputs()==expected and old.digest(binary.read_bytes())==sha,'before-body-pristine')
        try:
            code,raw,seconds=old.capture([str(binary),'--exact',name,'--nocapture','--test-threads=1'],300,limit=8*1024*1024)
            row=common.parse_body(raw,code,name);row['wall_seconds']=seconds;phase['cases'][key]=row;save()
            if key=='control':row['denial_control_PASS']=row['passed_gate']
            else:
                row['closed_snapshot_facts']=marker(raw,key)
                row['intended_runtime_RED']=intended_red(raw,code,key,row)
                row['target_GREEN']=row['passed_gate'] and marker_oracle(row['closed_snapshot_facts'],key,False)
            save()
        except old.GateFailure as error:
            phase['cases'][key]={'actual_counts_complete':False,'watchdog_triggered':str(error)=='bounded-command-timeout',
                'output_limit_triggered':str(error)=='bounded-command-output-limit'};save()
        ensure(frozen_inputs()==expected and old.digest(binary.read_bytes())==sha,'after-body-pristine')
    phase['inputs_pristine']=frozen_inputs()==expected;phase['binary_pristine']=old.digest(binary.read_bytes())==sha;save()


def main(args):
    os.umask(0o077);OUT.mkdir(exist_ok=True)
    report={'scope':'two-deterministic-Protocol-read-snapshot-cases-plus-corruption-denial-control','mode':args.mode,'mutation':args.mutation,'phases':{},
        'initial_behavioral_RED_verified':False,'component_GREEN':False,'component_mutation_qualified':False,
        'full_qualification':False,'native_acceptance_claim':False,'promotion_eligible':False}
    before=None;target=None;original=None;original_mode=None
    def save():(OUT/'result.json').write_text(json.dumps(report,indent=2)+'\n')
    try:
        ensure((args.mode=='mutation')==(args.mutation is not None),'explicit-independent-mutation-mode')
        report['source_guard']=source_guard(args.mutation);report['parser_controls']=parser_controls();save()
        if args.preflight:report['preflight_passed']=True;save();return
        before=frozen_inputs();keys=['round','facts','control']
        if args.mutation:
            spec=MUTATIONS[args.mutation];target=Path(spec['path']);original=target.read_bytes();original_mode=target.stat().st_mode
        for label in (['baseline','mutant','restored'] if args.mutation else [args.mode]):
            expected=copy.deepcopy(before)
            if target is not None:
                content=original.replace(spec['old'].encode(),spec['new'].encode(),1) if label=='mutant' else original
                target.write_bytes(content);target.chmod(original_mode);expected[spec['path']]['sha256']=old.digest(content)
            phase={};report['phases'][label]=phase;run_phase(expected,keys,phase,save)
            ensure(all(row.get('denial_control_PASS') if key=='control' else
                (row.get('intended_runtime_RED') if args.mode=='red' or (label=='mutant' and key==args.mutation) else row.get('target_GREEN'))
                for key,row in phase['cases'].items())
                and set(phase['cases'])==set(keys),'all-specific-runtime-oracles-required')
        if args.mutation:
            a,b,c=[report['phases'][k] for k in ['baseline','mutant','restored']]
            ensure(a['binary_sha256']==c['binary_sha256']!=b['binary_sha256'] and a['source_manifest_sha256']==c['source_manifest_sha256']
                and a['compilation']['compiled_features']==b['compilation']['compiled_features']==c['compilation']['compiled_features']
                and a['compilation']['compiler_artifact_feature_manifest_sha256']==b['compilation']['compiler_artifact_feature_manifest_sha256']==c['compilation']['compiler_artifact_feature_manifest_sha256'],'exact-source-binary-feature-restoration')
            report['component_mutation_qualified']=True
        elif args.mode=='red':report['initial_behavioral_RED_verified']=True
        else:report['component_GREEN']=True
    except Exception as error:
        report['exception_type']=type(error).__name__;raise
    finally:
        active_error=sys.exc_info()[0] is not None
        if target is not None:target.write_bytes(original);target.chmod(original_mode)
        if before is not None:report['inputs_pristine']=frozen_inputs()==before
        rows=[row for phase in report['phases'].values() for row in phase.get('cases',{}).values()]
        required=9 if args.mutation else 3
        complete=len(rows)==required and all(row.get('actual_counts_complete') is True for row in rows)
        report['actual_counts_complete']=complete
        for key in ['passed','failed','ignored','executed_nonignored']:
            report['known_partial_'+key]=sum(row[key] for row in rows if type(row.get(key)) is int)
            report['actual_'+key]=sum(row[key] for row in rows) if complete and all(type(row.get(key)) is int for row in rows) else None
        if report.get('inputs_pristine') is False:report['initial_behavioral_RED_verified']=report['component_GREEN']=report['component_mutation_qualified']=False
        save()
        if not active_error and before is not None:ensure(report['inputs_pristine'],'final-original-source-modes-restored')

if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('--preflight',action='store_true');p.add_argument('--mode',choices=['red','green','mutation'],default='red');p.add_argument('--mutation',choices=['round','facts']);main(p.parse_args())
