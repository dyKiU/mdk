#!/usr/bin/env python3
"""Finite App-handle compile/control qualification; no full/native claim."""
import argparse
import copy
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import qualify_upstream_storage_boundary as old
from upstream_extraction_cohort import frozen_inputs

BASE = 'd5c848ab55860034dbdcf5be5da32d790fd79c95'
SELF = 'scripts/qualify_upstream_storage_app_handles.py'
WORKFLOW = '.github/workflows/upstream-boundary-regressions.yml'
REF = 'refs/heads/ci/upstream-storage-app-handles-20261018'
BEGIN = '  # STORAGE_APP_HANDLES_JOBS_BEGIN\n'
END = '  # STORAGE_APP_HANDLES_JOBS_END\n'
OPTIONS = 'options: [storage-app-handles-preflight, storage-app-handles-controls, storage-app-handles-app-compile, storage-app-handles-mutations, '
OUT = Path('storage-app-handles-evidence')
BOUNDARY = sorted('base::boundary_tests::' + n for n in [
    'table_registry_names_every_table', 'storage_boundary_matches_the_allow_list',
    'cfg_predicates_skip_only_test_builds', 'unknown_production_roots_cannot_escape_boundary_scan',
    'trait_channel_sees_every_way_to_name_a_trait'])
ADDED = sorted('cross::private_app_capabilities::tests::' + n for n in [
    'private_app_capability_keeps_protocol_outer_rollback_and_exact_callbacks',
    'private_app_capability_preserves_tail_refusal_and_terminal_shared_close',
    'private_app_read_snapshot_is_query_only_restores_mode_and_observes_close'])
ensure = old.ensure

def source_guard():
    head = old.git('rev-parse', 'HEAD')
    ensure(os.environ.get('GITHUB_ACTIONS') == 'true' and os.environ.get('GITHUB_REPOSITORY') == 'dyKiU/mdk'
           and os.environ.get('GITHUB_EVENT_NAME') == 'workflow_dispatch'
           and os.environ.get('GITHUB_SHA') == head and os.environ.get('GITHUB_REF') == REF
           and os.environ.get('GITHUB_WORKFLOW_REF') == 'dyKiU/mdk/' + WORKFLOW + '@' + REF
           and os.environ.get('UPSTREAM_STORAGE_APP_HANDLES_BASELINE') == BASE, 'owned-frozen-workflow')
    ensure(os.environ.get('CARGO_INCREMENTAL') == '1' and os.environ.get('CARGO_BUILD_JOBS') == '2'
           and os.environ.get('RUST_MIN_STACK') == '4194304'
           and all(os.environ.get(k) == '0' for k in ['CARGO_PROFILE_DEV_DEBUG','CARGO_PROFILE_TEST_DEBUG'])
           and all(not os.environ.get(k) for k in ['RUSTFLAGS','CARGO_ENCODED_RUSTFLAGS','RUSTC_BOOTSTRAP',
               'CARGO_PROFILE_DEV_OPT_LEVEL','CARGO_PROFILE_TEST_OPT_LEVEL']), 'fixed-build-profile')
    subprocess.run(['git','merge-base','--is-ancestor',BASE,head],check=True)
    ensure(subprocess.run(['git','diff','--quiet','HEAD']).returncode == 0,'tracked-pristine')
    baseline = {}
    for entry in subprocess.check_output(['git','ls-tree','-r','-z',BASE]).split(b'\0'):
        if entry:
            meta,name = entry.split(b'\t',1); mode,kind,blob = meta.decode().split()
            ensure(kind == 'blob' and mode in {'100644','100755','120000'},'baseline-mode')
            baseline[os.fsdecode(name)] = (mode,blob)
    frozen = frozen_inputs()
    ensure(SELF not in baseline and set(frozen) == set(baseline)|{SELF},'whole-input-inventory')
    for name,value in frozen.items():
        mode,blob = baseline.get(name,('100644',None))
        ensure(value['mode'] == mode and (mode == '120000' or value['actual_executable'] == (mode == '100755')),'input-mode')
        data = os.fsencode(os.readlink(name)) if mode == '120000' else Path(name).read_bytes()
        if name == WORKFLOW:
            text = data.decode(); ensure(text.count(BEGIN) == text.count(END) == text.count(OPTIONS) == 1,'workflow-markers')
            before,rest = text.split(BEGIN); _,after = rest.split(END)
            data = (before+after).replace(OPTIONS,'options: [',1).encode()
        if blob is not None:
            ensure(hashlib.sha1(b'blob '+str(len(data)).encode()+b'\0'+data).hexdigest() == blob,'frozen-content:'+name)
    ensure(not subprocess.check_output(['git','ls-files','--others','--exclude-standard'],text=True).strip(),'no-source-overlay')
    return {'source':head,'baseline':BASE,'all_product_tests_modes_exact':True,'historical_evidence_reused':False}

def parse_body(raw,code,name):
    raw = re.sub(r'\x1b\[[0-9;]*m','',raw)
    names = re.findall(r'^test ([A-Za-z_][A-Za-z0-9_:]*) \.\.\. ',raw,re.M)
    summaries = re.findall(r'^test result: (ok|FAILED)\. (\d+) passed; (\d+) failed; (\d+) ignored; (\d+) measured; (\d+) filtered out;',raw,re.M)
    row = {'exit_code':code,'actual_counts_complete':False,'passed':None,'failed':None,'ignored':None,
           'executed_nonignored':None,'panic_count':raw.count('panicked at '),
           'compiler_error_count':len(re.findall(r'^error(?:\[E\d+\])?:',raw,re.M)),'passed_gate':False}
    if len(summaries) == 1:
        status,p,f,i,m,_ = summaries[0]; p,f,i,m = map(int,(p,f,i,m))
        row.update(passed=p,failed=f,ignored=i)
        complete = names == [name] and p+f == 1 and i == m == 0 and status == ('FAILED' if f else 'ok')
        row.update(actual_counts_complete=complete,executed_nonignored=p+f if complete else None)
    row['passed_gate'] = row['actual_counts_complete'] and code == 0 and row['passed'] == 1 and row['panic_count'] == row['compiler_error_count'] == 0
    return row

def parse_inventory(raw, name, ignored=False):
    lines=raw.splitlines()
    selected=sum(line==name+': test' for line in lines)
    summary='0 tests, 0 benchmarks' if ignored else '1 test, 0 benchmarks'
    summaries=sum(line==summary for line in lines)
    blank=sum(not line for line in lines)
    unknown=len(lines)-selected-summaries-blank
    return {'selected_line_count':selected,'summary_line_count':summaries,'blank_line_count':blank,
        'unknown_line_count':unknown,'ignored_inventory':ignored,
        'passed':selected==(0 if ignored else 1) and summaries<=1 and unknown==0}


def parser_controls():
    name = ADDED[0]
    raw = 'running 1 test\ntest '+name+' ... ok\ntest result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 9 filtered out; finished in 0.1s\n'
    ensure(parse_body(raw,0,name)['passed_gate'],'parser-positive')
    bad = [(raw+raw,0),(raw.replace(name,ADDED[1]),0),(raw.replace('1 passed','0 passed'),0),
           (raw.replace('0 ignored','1 ignored'),0),(raw.replace('0 measured','1 measured'),0),
           (raw+'error[E0000]: private\n',0),(raw+"thread 'private' panicked at hidden\n",0),(raw,101)]
    for text,code in bad: ensure(not parse_body(text,code,name)['passed_gate'],'parser-negative')
    failure = raw.replace(' ... ok',' ... FAILED').replace('result: ok. 1 passed; 0 failed','result: FAILED. 0 passed; 1 failed')
    ensure(parse_body(failure,101,name)['actual_counts_complete'] and not parse_body(failure,101,name)['passed_gate'],'typed-runtime-failure')
    inventory_positive=[(name+': test\n',False),(name+': test\n\n1 test, 0 benchmarks\n',False),('',True),('0 tests, 0 benchmarks\n',True)]
    for text,ignored in inventory_positive: ensure(parse_inventory(text,name,ignored)['passed'],'inventory-positive')
    inventory_negative=[('',False),(name+': test\n'+name+': test\n',False),
        (name+': test\n1 test, 0 benchmarks\n1 test, 0 benchmarks\n',False),
        (ADDED[1]+': test\n',False),(name+': test\n1 tests, 0 benchmarks\n',False),
        (name+': test\n0 tests, 0 benchmarks\n',False),(name+': test\nPRIVATE_DATA\n',False),
        (name+': test (ignored)\n',False),(name+': test\n',True),('1 test, 0 benchmarks\n',True),
        ('0 tests, 0 benchmarks\n0 tests, 0 benchmarks\n',True),('PRIVATE_DATA\n',True)]
    for text,ignored in inventory_negative: ensure(not parse_inventory(text,name,ignored)['passed'],'inventory-negative')
    return {'positive':2,'negative':len(bad),'inventory_positive':len(inventory_positive),
        'inventory_negative':len(inventory_negative),'runtime_bodies':0}

def compile_storage(cohort, frozen, phase, save):
    ensure(frozen_inputs()==frozen,'before-storage-compile-pristine')
    features=[] if cohort=='default' else ['experimental-device-sync']
    command=['cargo','test','--locked','-p','storage-sqlite','--lib','--no-run','--message-format=json']
    if features: command += ['--features',','.join(features)]
    code,raw,seconds=old.capture(command,1800)
    events=[json.loads(line) for line in raw.splitlines() if line.startswith('{')]
    errors=[v for v in events if v.get('reason')=='compiler-message' and v.get('message',{}).get('level')=='error']
    artifacts=[v for v in events if v.get('reason')=='compiler-artifact']
    selected=[v for v in artifacts if v['target']['name']=='storage_sqlite' and v['target']['kind']==['lib'] and v['profile']['test'] and v.get('executable')]
    phase['compilation']={'command':command,'exit_code':code,'compiler_error_count':len(errors),'wall_seconds':seconds,
        'safe_errors':[old.safe_compiler_diagnostic(v,frozen) for v in errors[:32]],'errors_truncated':len(errors)>32,
        'succeeded':False,'selected_test_artifact_count':len(selected),'features_requested':features}
    save()
    ensure(code==0 and not errors and len(selected)==1 and sorted(selected[0]['features'])==features,'one-exact-storage-feature-binary')
    binary=Path(selected[0]['executable'])
    fingerprints=sorted([{'package':v['package_id'],'target':v['target']['name'],'kind':v['target']['kind'],
        'features':sorted(v['features']),'profile':v['profile']} for v in artifacts],key=lambda v:json.dumps(v,sort_keys=True))
    phase['compilation'].update(succeeded=True,compiled_features=features,binary_sha256=old.digest(binary.read_bytes()),
        compiler_artifact_feature_manifest_sha256=old.digest(json.dumps(fingerprints,sort_keys=True).encode()))
    ensure(frozen_inputs()==frozen,'after-storage-compile-pristine'); save()
    return binary

def compile_app_only(frozen, report, save):
    requested=['marmot-app/test-policy-overrides','cgka-engine/test-policy-overrides','cgka-engine/test-crash-hooks','experimental-device-sync']
    command=['cargo','test','--locked','-p','marmot-app','--all-targets','--no-run','--message-format=json','--features',','.join(requested)]
    code,raw,seconds=old.capture(command,1800)
    events=[json.loads(line) for line in raw.splitlines() if line.startswith('{')]
    errors=[v for v in events if v.get('reason')=='compiler-message' and v.get('message',{}).get('level')=='error']
    artifacts=[v for v in events if v.get('reason')=='compiler-artifact']
    own=[v for v in artifacts if ('/marmot-app#' in v['package_id'] or v['package_id'].split('#')[-1].startswith('marmot-app@') or v['package_id'].startswith('marmot-app '))]
    row={'package':'marmot-app','command':command,'features_requested':requested,'exit_code':code,
        'compiler_error_count':len(errors),'wall_seconds':seconds,'safe_errors':[old.safe_compiler_diagnostic(v,frozen) for v in errors[:32]],
        'errors_truncated':len(errors)>32,'artifact_count':len(artifacts),'selected_package_artifact_count':len(own),
        'selected_package_features':[sorted(v['features']) for v in own],
        'feature_manifest_sha256':old.digest(json.dumps([{'package':v['package_id'],'target':v['target']['name'],'features':sorted(v['features']),'profile':v['profile']} for v in artifacts],sort_keys=True).encode()),
        'passed':code==0 and not errors and bool(own) and all({'experimental-device-sync','test-policy-overrides'} <= set(v['features']) for v in own)
            and any(v['target']['name']=='cgka_engine' and {'experimental-device-sync','test-policy-overrides','test-crash-hooks'} <= set(v['features']) for v in artifacts)}
    report['all_target_compilations'].append(row); save()
    ensure(frozen_inputs()==frozen,'app-only-inputs-pristine')
    report['app_compile_only_passed']=row['passed']; save()
    ensure(row['passed'],'finite-experimental-App-alltargets-required')

MUTATION_TESTS = 'crates/storage-sqlite/src/cross/private_app_capabilities/tests.rs'
MUTATIONS = {
    'query-only': {
        'path':'crates/storage-sqlite/src/app/handle.rs',
        'old':'.with_transaction_mode(true, || self.connection.with_query_only(|| f(self)))',
        'new':'.with_transaction_mode(true, || f(self))',
        'test':'cross::private_app_capabilities::tests::private_app_read_snapshot_is_query_only_restores_mode_and_observes_close',
        'line':128, 'message':'actual App read snapshots must reject writes'},
    'callback': {
        'path':'crates/storage-sqlite/src/cross/private_app_capabilities.rs',
        'old':'.put_approved_account_sharing_policy(policy, validate_original)',
        'new':'.put_approved_account_sharing_policy(policy, &|| Ok(()))',
        'test':'cross::private_app_capabilities::tests::private_app_capability_keeps_protocol_outer_rollback_and_exact_callbacks',
        'line':62, 'message':'the same callback must run before work and at tail'},
}

def intended_mutant(raw, code, spec):
    row=parse_body(raw,code,spec['test'])
    headers=re.findall(r"^thread '([^'\n]+)'(?: \(\d+\))? panicked at ([^\n]+):\n",raw,re.M)
    location=MUTATION_TESTS+':'+str(spec['line'])+':5'
    if spec['message']=='actual App read snapshots must reject writes':
        payload='\n'+spec['message']+'\n'
    else:
        payload='\nassertion `left == right` failed: '+spec['message']+'\n  left: 0\n right: 2\n'
    return (row['actual_counts_complete'] and row['failed']==1 and row['passed']==row['ignored']==row['compiler_error_count']==0
        and code==101 and row['panic_count']==1 and headers==[(spec['test'],location)]
        and raw.count(payload)==1)

def mutation_parser_controls():
    count=0
    for key,spec in MUTATIONS.items():
        payload=spec['message'] if key=='query-only' else 'assertion `left == right` failed: '+spec['message']+'\n  left: 0\n right: 2'
        raw=('running 1 test\ntest '+spec['test']+" ... \nthread '"+spec['test']+"' panicked at "+MUTATION_TESTS+':'+str(spec['line'])+':5:\n'
             +payload+'\nFAILED\nfailures:\n    '+spec['test']+'\ntest result: FAILED. 0 passed; 1 failed; 0 ignored; 0 measured; 999 filtered out; finished in 1.0s\n')
        ensure(intended_mutant(raw,101,spec),'intended-mutation-parser-positive')
        bad=[(raw,0),(raw+raw,101),(raw.replace(':5:',':6:'),101),
            (raw.replace(payload,'different assertion'),101),(raw.replace('0 ignored','1 ignored'),101),
            (raw.replace('0 passed; 1 failed','0 passed; 0 failed'),101),(raw+'error[E0000]: hidden\n',101),
            (raw.replace("thread '"+spec['test'],"thread 'foreign"),101)]
        if key=='callback': bad += [(raw.replace('left: 0','left: 1'),101),(raw.replace('right: 2','right: 3'),101)]
        for text,code in bad: ensure(not intended_mutant(text,code,spec),'intended-mutation-parser-negative')
        count+=len(bad)
    return {'positive':2,'negative':count,'runtime_bodies':0}

def run_mutation(label, frozen, report, save):
    spec=MUTATIONS[label]; target=Path(spec['path']); original=target.read_bytes(); mode=target.stat().st_mode
    ensure(original.decode().count(spec['old'])==1,'single-reviewed-product-mutant-anchor')
    fixture=Path(MUTATION_TESTS).read_bytes()
    ensure(fixture.decode().splitlines()[spec['line']-1].strip() in {'assert!(','assert_eq!('},'exact-unchanged-assertion-location')
    chain={'label':label,'selected_test':spec['test'],'product_path':spec['path'],'phases':{},'qualified':False}
    report['mutation_chain']=chain; report['runtime_scope']='one selected synthetic persistence control per phase; no Core/native authority claim'
    try:
        for phase_name in ['baseline','mutant','restored']:
            body=original.replace(spec['old'].encode(),spec['new'].encode(),1) if phase_name=='mutant' else original
            target.write_bytes(body); target.chmod(mode)
            expected=copy.deepcopy(frozen); expected[spec['path']]['sha256']=old.digest(body)
            ensure(frozen_inputs()==expected and Path(MUTATION_TESTS).read_bytes()==fixture,'only-exact-reviewed-mutation')
            phase={'actual_counts_complete':False,'intended_runtime_kill':False,'runtime_started':False,
                'source_manifest_sha256':old.digest(json.dumps(expected,sort_keys=True).encode())}
            chain['phases'][phase_name]=phase; save()
            binary=compile_storage('experimental',expected,phase,save); binary_hash=old.digest(binary.read_bytes())
            code,listed,_=old.capture([str(binary),'--exact',spec['test'],'--list','--format','terse'],60)
            phase['inventory']=parse_inventory(listed,spec['test']); phase['inventory']['exit_code']=code; save()
            ensure(code==0 and phase['inventory']['passed'],'exact-mutant-selected-inventory')
            code,ignored,_=old.capture([str(binary),'--exact',spec['test'],'--ignored','--list','--format','terse'],60)
            phase['ignored_inventory']=parse_inventory(ignored,spec['test'],True); phase['ignored_inventory']['exit_code']=code; save()
            ensure(code==0 and phase['ignored_inventory']['passed'],'mutation-case-not-ignored')
            ensure(frozen_inputs()==expected and old.digest(binary.read_bytes())==binary_hash,'before-mutant-body-pristine')
            phase['runtime_started']=True; save()
            code,raw,seconds=old.capture([str(binary),'--exact',spec['test'],'--nocapture','--test-threads=1'],300,limit=8*1024*1024)
            phase['body']=parse_body(raw,code,spec['test']); phase['body']['wall_seconds']=seconds
            phase['actual_counts_complete']=phase['body']['actual_counts_complete']; save()
            phase['source_pristine']=frozen_inputs()==expected and target.stat().st_mode==mode
            phase['binary_pristine']=old.digest(binary.read_bytes())==binary_hash
            phase['intended_runtime_kill']=intended_mutant(raw,code,spec) if phase_name=='mutant' else False
            save()
            ensure(phase['source_pristine'] and phase['binary_pristine'],'mutation-phase-pristine')
            ensure(phase['intended_runtime_kill'] if phase_name=='mutant' else phase['body']['passed_gate'],'runtime-only-specific-mutant-or-positive-control')
        baseline=chain['phases']['baseline']; mutant=chain['phases']['mutant']; restored=chain['phases']['restored']
        def compiled(phase): return phase['compilation']
        ensure(compiled(baseline)['binary_sha256']==compiled(restored)['binary_sha256']
            and compiled(mutant)['binary_sha256']!=compiled(baseline)['binary_sha256']
            and compiled(baseline)['compiler_artifact_feature_manifest_sha256']==compiled(restored)['compiler_artifact_feature_manifest_sha256']==compiled(mutant)['compiler_artifact_feature_manifest_sha256']
            and baseline['source_manifest_sha256']==restored['source_manifest_sha256'],'exact-restored-binary-feature-source-identity')
        chain['qualified']=True
        report.update(component_mutation_qualified=True,qualification_passed=False)
    finally:
        original_error_active=sys.exc_info()[0] is not None
        try:
            target.write_bytes(original); target.chmod(mode)
            chain['exact_source_restored']=target.read_bytes()==original and target.stat().st_mode==mode and frozen_inputs()==frozen
        except Exception as error:
            chain['exact_source_restored']=False; chain['restoration_error_type']=type(error).__name__
        rows=[v['body'] for v in chain['phases'].values() if 'body' in v]
        complete=len(rows)==3 and all(v['actual_counts_complete'] for v in rows)
        report['actual_counts_complete']=complete
        report['known_partial_counts']={key:sum(v[key] for v in rows if type(v.get(key)) is int) for key in ['passed','failed','ignored','executed_nonignored']}
        for key in ['passed','failed','ignored','executed_nonignored']:
            report['actual_'+key]=sum(v[key] for v in rows) if complete else None
        if not chain['exact_source_restored']:
            chain['qualified']=False; report['component_mutation_qualified']=False
        save()
        if not original_error_active: ensure(chain['exact_source_restored'],'mutation-final-source-restoration')

def main(args):
    os.umask(0o077); OUT.mkdir(exist_ok=True)
    report = {'cohort':args.cohort,'qualification_passed':False,'full_MDK_qualified':False,'native_qualified':False,'bodies':{},'all_target_compilations':[]}
    def save(): (OUT/'result.json').write_text(json.dumps(report,indent=2)+'\n')
    frozen=None
    try:
        report['source_guard']=source_guard(); report['parser_controls']=parser_controls(); report['mutation_parser_controls']=mutation_parser_controls(); save()
        if args.preflight: report['preflight_passed']=True; save(); return
        frozen=frozen_inputs(); report['input_manifest_sha256']=old.digest(json.dumps(frozen,sort_keys=True).encode())
        if args.mutation:
            ensure(not args.app_compile_only and args.cohort=='experimental','mutation-scope-experimental-only')
            run_mutation(args.mutation,frozen,report,save); return
        if args.app_compile_only:
            ensure(args.cohort=='experimental','app-only-is-experimental')
            report.update(scope='experimental-App-alltargets-compile-only',actual_counts_complete=True,
                actual_passed=0,actual_failed=0,actual_ignored=0,actual_executed_nonignored=0,
                runtime_bodies=0,qualification_passed=False,prior_runtime_evidence_reused=False)
            save(); compile_app_only(frozen,report,save); return
        phase={}; report['storage_compile']=phase
        binary=compile_storage(args.cohort,frozen,phase,save)
        binary_hash=old.digest(binary.read_bytes())
        names=BOUNDARY+(ADDED if args.cohort == 'experimental' else [])
        report['inventory']={}
        for name in names:
            code,listed,_=old.capture([str(binary),'--exact',name,'--list','--format','terse'],60)
            selected=parse_inventory(listed,name); selected['exit_code']=code
            report['inventory'][name]={'selected':selected}; save()
            ensure(code==0 and selected['passed'],'exact-selected-inventory')
            code,ignored,_=old.capture([str(binary),'--exact',name,'--ignored','--list','--format','terse'],60)
            ignored_row=parse_inventory(ignored,name,True); ignored_row['exit_code']=code
            report['inventory'][name]['ignored']=ignored_row; save()
            ensure(code==0 and ignored_row['passed'],'selected-not-ignored')
        report['selected_names']=names; save()
        for name in names:
            ensure(frozen_inputs()==frozen and old.digest(binary.read_bytes())==binary_hash,'before-body-pristine')
            code,raw,seconds=old.capture([str(binary),'--exact',name,'--nocapture','--test-threads=1'],300,limit=8*1024*1024)
            row=parse_body(raw,code,name); row.update(wall_seconds=seconds,binary_sha256=binary_hash)
            report['bodies'][name]=row; save()
            ensure(frozen_inputs()==frozen and old.digest(binary.read_bytes())==binary_hash,'after-body-pristine')
        for package in ['storage-sqlite','marmot-app','cgka-engine']:
            command=['cargo','test','--locked','-p',package,'--all-targets','--no-run','--message-format=json']
            requested=[]
            if package=='marmot-app': requested=['marmot-app/test-policy-overrides','cgka-engine/test-policy-overrides','cgka-engine/test-crash-hooks']
            elif package=='cgka-engine': requested=['test-policy-overrides','test-crash-hooks']
            if args.cohort=='experimental': requested += ['experimental-device-sync']
            if requested: command += ['--features',','.join(requested)]
            code,raw,seconds=old.capture(command,1800)
            events=[json.loads(line) for line in raw.splitlines() if line.startswith('{')]
            errors=[v for v in events if v.get('reason')=='compiler-message' and v.get('message',{}).get('level')=='error']
            artifacts=[v for v in events if v.get('reason')=='compiler-artifact']
            # Package identity also appears as path+fragment in Cargo's JSON; require actual selected package target artifacts.
            own=[v for v in artifacts if ('/'+package+'#' in v['package_id'] or v['package_id'].split('#')[-1].startswith(package+'@') or v['package_id'].startswith(package+' '))]
            item={'package':package,'command':command,'exit_code':code,'compiler_error_count':len(errors),'wall_seconds':seconds,
                  'safe_errors':[old.safe_compiler_diagnostic(v,frozen) for v in errors[:32]],'errors_truncated':len(errors)>32,
                  'artifact_count':len(artifacts),'selected_package_artifact_count':len(own),
                  'features_requested':requested,
                  'selected_package_features':[sorted(v['features']) for v in own],
                  'feature_manifest_sha256':old.digest(json.dumps([{'package':v['package_id'],'target':v['target']['name'],'features':sorted(v['features']),'profile':v['profile']} for v in artifacts],sort_keys=True).encode()),
                  'passed':code==0 and not errors and bool(own) and all(('experimental-device-sync' in v['features']) == (args.cohort=='experimental') and (package=='storage-sqlite' or 'test-policy-overrides' in v['features']) and (package!='cgka-engine' or 'test-crash-hooks' in v['features']) for v in own) and (package!='marmot-app' or any(v['target']['name']=='cgka_engine' and {'test-policy-overrides','test-crash-hooks'} <= set(v['features']) for v in artifacts))}
            report['all_target_compilations'].append(item); save()
            ensure(frozen_inputs()==frozen and old.digest(binary.read_bytes())==binary_hash,'after-alltargets-pristine')
        rows=list(report['bodies'].values()); complete=len(rows)==len(names) and all(r['actual_counts_complete'] for r in rows)
        report['actual_counts_complete']=complete
        for key in ['passed','failed','ignored','executed_nonignored']:
            report['actual_'+key]=sum(r[key] for r in rows) if complete else None
        report['source_pristine']=frozen_inputs()==frozen
        report['qualification_passed']=complete and report['source_pristine'] and all(r['passed_gate'] for r in rows) and all(r['passed'] for r in report['all_target_compilations']) and len(report['all_target_compilations'])==3
        save(); ensure(report['qualification_passed'],'finite-controls-and-alltargets-required')
    except Exception as error:
        report['error_type']=type(error).__name__; report['error_label']=str(error) if isinstance(error,old.GateFailure) else 'unexpected-controller-failure'; save(); raise
    finally:
        try:
            report['source_pristine']=frozen_inputs()==frozen if frozen is not None else None
            report['tracked_worktree_pristine']=subprocess.run(['git','diff','--quiet','HEAD']).returncode==0
            if report['source_pristine'] is False or not report['tracked_worktree_pristine']:
                report['qualification_passed']=False
        except Exception as error:
            report['source_pristine']=None; report['pristine_probe_error_type']=type(error).__name__; report['qualification_passed']=False
        save()

if __name__=='__main__':
    parser=argparse.ArgumentParser(); parser.add_argument('--preflight',action='store_true'); parser.add_argument('--mutation',choices=sorted(MUTATIONS)); parser.add_argument('--app-compile-only',action='store_true'); parser.add_argument('--cohort',choices=['default','experimental'],default='experimental'); main(parser.parse_args())
