#!/usr/bin/env python3
"""One real client-replacement body; independent omission with exact restoration."""
import argparse
import copy
import json
import os
from pathlib import Path
import re
import subprocess
import tempfile
from upstream_completion_ci import NEW,compile_cases,parse_body,environment,freeze,identity,digest,ensure,green,intended_red
BASE='ac3db2d82bdca105d249b7ddfba73734b4e153e9'
TEST='sibling_completion_service_rebinds_after_actual_client_replacement'
WORKER='crates/marmot-app/src/runtime/account_worker.rs'
STAGES=['old-original-retired','actual-client-replaced','old-signal-fired-before-fresh-enrollment']
def rebind_anchor(text):
    matches=re.findall(r'sibling_completions = client\.sibling_publication_completions\(\);\s*sibling_completions_open = true;',text)
    ensure(len(matches)==1,'sole-replacement-rebind-block')
    return matches[0]
def lifecycle(raw):
    stages=re.findall(r'completion-rebind-control stage=([a-z-]+)',raw)
    values=re.findall(r'completion-rebind-control result fresh_owner=(true|false) old_receivers=([0-9]+) old_send_failed=(true|false)',raw)
    row={'lifecycle_stages':stages,'lifecycle_result_count':len(values)}
    if len(values)==1:row.update(fresh_owner=values[0][0]=='true',old_receivers=int(values[0][1]),old_send_failed=values[0][2]=='true')
    return row
def lifecycle_prerequisites(row):return row.get('lifecycle_stages')==STAGES and row.get('lifecycle_result_count')==1 and row.get('fresh_owner') is True
def lifecycle_green(row):return green(row) and lifecycle_prerequisites(row) and row.get('old_receivers')==0 and row.get('old_send_failed') is True
def parser_preflight_rebind():
    raw='\n'.join('completion-rebind-control stage='+stage for stage in STAGES)+'\ncompletion-rebind-control result fresh_owner=true old_receivers=0 old_send_failed=true'
    row=lifecycle(raw);ensure(lifecycle_prerequisites(row),'lifecycle-parser-positive')
    negatives=[]
    for stage in STAGES:
        changed=copy.deepcopy(row);changed['lifecycle_stages'].remove(stage);negatives.append(changed)
    for key,value in [('fresh_owner',False),('lifecycle_result_count',2)]:
        changed=copy.deepcopy(row);changed[key]=value;negatives.append(changed)
    ensure(all(not lifecycle_prerequisites(value) for value in negatives),'lifecycle-parser-negatives')
    return {'positive':1,'negative':len(negatives),'actual_product_bodies':0}
def verify_green_run(run_id):
    ensure(run_id.isdecimal(),'prior-lifecycle-green-run-required')
    repo=os.environ['GITHUB_REPOSITORY'];source=os.environ['GITHUB_SHA']
    def api(path):return json.loads(subprocess.check_output(['gh','api',path],text=True))
    run=api('repos/'+repo+'/actions/runs/'+run_id)
    ensure(run['head_sha']==source and run['repository']['full_name']==repo and run['path']=='.github/workflows/experimental-sync-ci.yml' and run['event']=='workflow_dispatch' and run['status']=='completed' and run['conclusion']=='success','prior-lifecycle-run-identity')
    artifacts=api('repos/'+repo+'/actions/runs/'+run_id+'/artifacts?per_page=100')['artifacts'];proof=[]
    with tempfile.TemporaryDirectory(prefix='completion-rebind-green-') as directory:
        for name in ['completion-rebind-controls','completion-rebind-static-default','completion-rebind-static-experimental']:
            matches=[entry for entry in artifacts if entry['name']==name and not entry['expired']]
            ensure(len(matches)==1 and matches[0]['size_in_bytes']<2_000_000 and matches[0].get('digest','').startswith('sha256:'),'prior-lifecycle-artifact')
            destination=Path(directory)/name
            subprocess.run(['gh','run','download',run_id,'--repo',repo,'--name',name,'--dir',str(destination)],check=True)
            files=list(destination.rglob('result.json'));ensure(len(files)==1,'one-prior-lifecycle-result');row=json.loads(files[0].read_text())
            ensure(row['source']==source and row['inputs_pristine'] is True,'prior-lifecycle-source')
            if name=='completion-rebind-controls':
                phase=row['controls'];compilation=phase['compilation']
                ensure(compilation['compile_exit_code']==0 and compilation['compiler_error_count']==0 and compilation['compiled_fingerprints']['verified'] is True,'prior-lifecycle-compiled-cohort')
                ensure(row['controls_passed'] is True and len(phase['bodies'])==1 and phase['bodies'][0]['actual_suffix']==TEST and lifecycle_green(phase['bodies'][0]),'prior-lifecycle-real-body')
            else:ensure(row['static_passed'] is True and row['exit_code']==0 and row['compiler_error_count']==0 and row['actual_runtime_bodies']==0 and row['cohort']==name.rsplit('-',1)[-1],'prior-lifecycle-static')
            proof.append({'id':matches[0]['id'],'name':name,'digest':matches[0]['digest']})
    Path('completion-rebind-prior-green.json').write_text(json.dumps({'run_id':int(run_id),'source':source,'artifacts':proof},indent=2)+'\n')
def main():
    parser=argparse.ArgumentParser();parser.add_argument('--mode',choices=['controls','mutation','verify-green'],required=True);args=parser.parse_args()
    if args.mode=='verify-green':verify_green_run(os.environ.get('COMPLETION_CONTROL_RUN_ID',''));return
    os.umask(0o077);out=Path('completion-rebind-evidence');out.mkdir(exist_ok=True)
    report={'mode':args.mode,'source':os.environ.get('GITHUB_SHA'),'qualification_passed':False,'scope':'real continuing-worker client replacement, not full sync acceptance'}
    def save():(out/'result.json').write_text(json.dumps(report,indent=2)+'\n')
    save();report.update(environment());report['baseline_test_source']=BASE;frozen=freeze();report['source_before_sha256']=identity(frozen)
    report['frozen_config_sha256']={name:frozen[name] for name in ['Cargo.lock','Cargo.toml','.cargo/config.toml','.config/nextest.toml']}
    report['old_signal_inert_scope']='no old watch consumer at checkpoint before fresh enrollment, not time-window absence of protocol effects';save()
    def pristine():return freeze()==frozen and subprocess.run(['git','diff','--quiet','HEAD']).returncode==0
    def run(label,expected):
        ensure(freeze()==expected,'lifecycle-before-compile-inputs')
        compilation,cases=compile_cases([TEST]);report[label]={'compilation':compilation,'bodies':[]};save()
        ensure(freeze()==expected,'lifecycle-after-compile-inputs')
        if compilation.get('compile_exit_code')!=0 or compilation.get('compiler_error_count')!=0 or not cases:return False
        ensure(compilation.get('compiled_fingerprints',{}).get('verified'),'lifecycle-actual-features')
        # Reuse the frozen direct-binary parser without changing its production API.
        # The small extra closed lifecycle lines are parsed in the same one call.
        case=cases[TEST]
        import time
        started=time.monotonic();row={'test':case['name'],'suffix':NEW,'actual_suffix':TEST,'binary_sha256':case['binary_sha256']}
        try:
            body=subprocess.run([case['binary'],'--exact',case['name'],'--nocapture','--test-threads=1'],capture_output=True,text=True,timeout=300)
            raw=body.stdout+body.stderr;row.update(parse_body(raw,NEW));row.update(lifecycle(raw));row.update(body_exit_code=body.returncode,body_seconds=time.monotonic()-started)
        except subprocess.TimeoutExpired:row.update(watchdog_triggered=True,actual_count_unknown=True)
        report[label]['bodies'].append(row);save();ensure(freeze()==expected,'lifecycle-body-inputs')
        return lifecycle_green(row)
    if args.mode=='controls':
        try:report['controls_passed']=run('controls',frozen)
        except Exception as error:report['controller_exception']=type(error).__name__
        report['inputs_pristine']=pristine();report['controls_passed']=report.get('controls_passed',False) and report['inputs_pristine'];save();raise SystemExit(0 if report['controls_passed'] else 1)
    original=Path(WORKER).read_bytes();baseline=False;killed=False;restored=False
    try:
        baseline=run('baseline',frozen);ensure(baseline,'lifecycle-baseline-not-green')
        before=rebind_anchor(original.decode());mutant=original.decode().replace(before,'// mutation: omit only continuing-worker completion subscription rebind',1).encode()
        expected=dict(frozen);expected[WORKER]=digest(mutant);report['mutation']={'path':WORKER,'before_sha256':digest(original),'expected_mutant_sha256':digest(mutant)};save();Path(WORKER).write_bytes(mutant)
        run('mutant',expected);phase=report.get('mutant',{});compilation=phase.get('compilation',{});rows=phase.get('bodies',[])
        killed=compilation.get('compile_exit_code')==0 and compilation.get('compiler_error_count')==0 and len(rows)==1 and intended_red(rows[0]) and lifecycle_prerequisites(rows[0]);report['mutant_runtime_killed']=bool(killed)
    except Exception as error:report['mutation_or_controller_exception']=type(error).__name__
    finally:
        Path(WORKER).write_bytes(original);report['exact_source_restored_before_control']=pristine();save()
        try:
            ensure(pristine(),'lifecycle-source-not-restored')
            result=subprocess.run(['python3','scripts/verify_upstream_completion_rebind_source.py']);report['restored_source_guard_exit_code']=result.returncode
            restored=run('restored',frozen)
        except Exception as error:report['restored_control_exception']=type(error).__name__
        report.update(baseline_passed=baseline,restored_control_passed=restored,inputs_pristine=pristine(),source_after_sha256=identity(freeze()))
        report['mutation_qualified']=bool(baseline and killed and restored and report.get('restored_source_guard_exit_code')==0 and report['inputs_pristine']);save()
    raise SystemExit(0 if report['mutation_qualified'] else 1)
if __name__=='__main__':main()
