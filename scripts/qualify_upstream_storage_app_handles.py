#!/usr/bin/env python3
"""Finite App-handle compile/control qualification; no full/native claim."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import qualify_upstream_storage_boundary as old
from upstream_extraction_cohort import frozen_inputs

BASE = '3f06a0a8d1cff74142dd6c1570f733f09f990ca0'
SELF = 'scripts/qualify_upstream_storage_app_handles.py'
WORKFLOW = '.github/workflows/upstream-boundary-regressions.yml'
REF = 'refs/heads/ci/upstream-storage-app-handles-20261018'
BEGIN = '  # STORAGE_APP_HANDLES_JOBS_BEGIN\n'
END = '  # STORAGE_APP_HANDLES_JOBS_END\n'
OPTIONS = 'options: [storage-app-handles-preflight, storage-app-handles-controls, '
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
    return {'positive':2,'negative':len(bad),'runtime_bodies':0}

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

def main(args):
    os.umask(0o077); OUT.mkdir(exist_ok=True)
    report = {'cohort':args.cohort,'qualification_passed':False,'full_MDK_qualified':False,'native_qualified':False,'bodies':{},'all_target_compilations':[]}
    def save(): (OUT/'result.json').write_text(json.dumps(report,indent=2)+'\n')
    frozen=None
    try:
        report['source_guard']=source_guard(); report['parser_controls']=parser_controls(); save()
        if args.preflight: report['preflight_passed']=True; save(); return
        frozen=frozen_inputs(); report['input_manifest_sha256']=old.digest(json.dumps(frozen,sort_keys=True).encode())
        phase={}; report['storage_compile']=phase
        binary=compile_storage(args.cohort,frozen,phase,save)
        binary_hash=old.digest(binary.read_bytes())
        names=BOUNDARY+(ADDED if args.cohort == 'experimental' else [])
        for name in names:
            code,listed,_=old.capture([str(binary),'--exact',name,'--list','--format','terse'],60)
            ensure(code == 0 and [line for line in listed.splitlines() if line] == [name+': test', '1 test, 0 benchmarks'],'exact-selected-inventory')
            code,ignored,_=old.capture([str(binary),'--exact',name,'--ignored','--list','--format','terse'],60)
            ensure(code == 0 and ignored.strip() in {'','0 tests, 0 benchmarks'},'selected-not-ignored')
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
    parser=argparse.ArgumentParser(); parser.add_argument('--preflight',action='store_true'); parser.add_argument('--cohort',choices=['default','experimental'],default='experimental'); main(parser.parse_args())
