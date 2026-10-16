#!/usr/bin/env python3
"""Real relay-error cadence body and independently restored guard omission."""
import argparse
import copy
import json
import os
from pathlib import Path
import re
import subprocess
import time
from upstream_completion_ci import environment,freeze,identity,digest,ensure,compile_cases,parse_body,FILE
BASE='ac3db2d82bdca105d249b7ddfba73734b4e153e9'
TEST='another_sibling_success_preserves_failed_consent_periodic_retry_cadence'
SOURCE='crates/marmot-app/src/client/device_linking/sibling_sharing.rs'
MESSAGE='another sibling success must not consume a failed consent before its periodic turn'
STAGES=['primary-round-ready','two-real-consents-held','periodic-arm-gated','actual-error-queued','other-real-success-serviced','fresh-actor-progress','first-periodic-turn-completed','second-periodic-turn-completed','actual-later-retry-ack','periodic-arm-released','normal-completion-and-positive-cleanup']
def mutation_anchor(text):
    matches=re.findall(r'pending\.outcome\.as_ref\(\)\.is_some_and\(Result::is_err\)\s*\|\|\s*self\.validate_sibling_publication\(entry\)\.is_err\(\)',text)
    ensure(len(matches)==1,'sole-initial-error-retention-guard')
    return matches[0]
def parse(raw):
    row=parse_body(raw,TEST)
    row['cadence_stages']=re.findall(r'completion-cadence-control stage=([a-z-]+)',raw)
    values=re.findall(r'completion-cadence-control result before=(\[[0-9, ]+\]) first=(\[[0-9, ]+\]) second=(\[[0-9, ]+\]) acknowledged=(\[[0-9, ]+\]) turns=([0-9]+)/([0-9]+) wire_rejections=([0-9]+)',raw)
    row['cadence_result_count']=len(values)
    if len(values)==1:
        for key,value in zip(['before','first','second','acknowledged'],values[0][:4]):row[key]=json.loads(value)
        row['turns']=list(map(int,values[0][4:6]));row['wire_rejections']=int(values[0][6])
    row['named_assertion_observed']=MESSAGE in raw
    return row
def prerequisites(row):
    arrays=[row.get(key,[]) for key in ['before','first','second','acknowledged']]
    return row.get('cadence_stages')==STAGES and row.get('cadence_result_count')==1 and all(len(value)==6 and all(type(number) is int and 0<=number<=4096 for number in value) for value in arrays) and row.get('turns')==[1,2] and row.get('wire_rejections',0)>0 and row['before'][0]==1 and row['before'][1]==1 and row['second'][0]>=2 and row['acknowledged'][2]>=1 and row.get('original_phase_markers')==['fourth-device-completion','fourth-device-completed']
def good(row):return row.get('body_exit_code')==0 and row.get('passed')==1 and row.get('failed')==0 and row.get('ignored')==0 and row.get('executed_nonignored')==1 and row.get('all_panic_header_count')==0 and not row.get('watchdog_triggered') and prerequisites(row) and row['before'][3]>0 and row['before'][4]==0 and row['first'][0]==1 and row['first'][5]==1 and row['second'][0]==2
def own_assertion():
    lines=Path(FILE).read_text().splitlines();matches=[index for index,line in enumerate(lines) if MESSAGE in line];ensure(len(matches)==1,'one-own-cadence-assertion')
    line=max(index for index in range(matches[0]+1) if re.search(r'\bassert!\s*\(',lines[index]))+1
    return {'file':FILE,'line':line}
def intended_red(row):
    row['expected_panic']=own_assertion()
    return row.get('body_exit_code')==101 and row.get('passed')==0 and row.get('failed')==1 and row.get('ignored')==0 and row.get('executed_nonignored')==1 and row.get('all_panic_header_count')==1 and len(row.get('panic_locations',[]))==1 and all(row['panic_locations'][0][key]==value for key,value in row['expected_panic'].items()) and row.get('named_assertion_observed') is True and not row.get('watchdog_triggered') and prerequisites(row) and row['before'][4]==1 and row['first'][0]>=2

def parser_preflight():
    raw='\n'.join('completion-cadence-control stage='+stage for stage in STAGES)
    raw+='\nautomatic-enrollment-control stage=fourth-device-completion\nautomatic-enrollment-control stage=fourth-device-completed'
    raw+='\ncompletion-cadence-control result before=[1, 1, 0, 1, 0, 0] first=[1, 1, 0, 1, 0, 1] second=[2, 1, 0, 1, 0, 1] acknowledged=[2, 1, 1, 1, 0, 1] turns=1/2 wire_rejections=1\ntest result: ok. 1 passed; 0 failed; 0 ignored;'
    row=dict(parse(raw),body_exit_code=0);ensure(good(row),'cadence-parser-positive')
    negatives=[]
    for stage in STAGES:
        changed=copy.deepcopy(row);changed['cadence_stages'].remove(stage);negatives.append(changed)
    for key,value in [('cadence_result_count',2),('turns',[0,1]),('wire_rejections',0),('all_panic_header_count',1),('ignored',1)]:
        changed=copy.deepcopy(row);changed[key]=value;negatives.append(changed)
    changed=copy.deepcopy(row);changed['first'][0]=2;negatives.append(changed)
    changed=copy.deepcopy(row);changed['acknowledged'][2]=0;negatives.append(changed)
    ensure(all(not good(value) for value in negatives),'cadence-parser-negatives')
    red_raw=raw.replace('before=[1, 1, 0, 1, 0, 0] first=[1, 1, 0, 1, 0, 1] second=[2, 1, 0, 1, 0, 1]', 'before=[1, 1, 0, 0, 1, 0] first=[2, 1, 0, 0, 1, 0] second=[2, 1, 1, 0, 1, 0]').replace('acknowledged=[2, 1, 1, 1, 0, 1]', 'acknowledged=[2, 1, 1, 0, 1, 0]').replace('test result: ok. 1 passed; 0 failed; 0 ignored;', 'test result: FAILED. 0 passed; 1 failed; 0 ignored;')
    red_raw+='\nthread test panicked at '+FILE+':'+str(own_assertion()['line'])+':9:\n'+MESSAGE
    red=dict(parse(red_raw),body_exit_code=101);ensure(intended_red(red),'cadence-parser-intended-red-positive')
    bad=[]
    for key,value in [('all_panic_header_count',2),('ignored',1),('watchdog_triggered',True),('named_assertion_observed',False)]:
        changed=copy.deepcopy(red);changed[key]=value;bad.append(changed)
    changed=copy.deepcopy(red);changed['panic_locations'][0]['line']+=1;bad.append(changed)
    changed=copy.deepcopy(red);changed['before'][4]=0;bad.append(changed)
    changed=copy.deepcopy(red);changed['first'][0]=1;bad.append(changed)
    changed=copy.deepcopy(red);changed['acknowledged'][2]=0;bad.append(changed)
    ensure(all(not intended_red(value) for value in bad),'cadence-parser-invalid-red-negatives')
    return {'positive':2,'negative':len(negatives)+len(bad),'actual_product_bodies':0}
def main():
    parser=argparse.ArgumentParser();parser.add_argument('--mode',choices=['controls','mutation'],required=True);args=parser.parse_args()
    os.umask(0o077);out=Path('consent-cadence-evidence');out.mkdir(exist_ok=True)
    report={'mode':args.mode,'source':os.environ.get('GITHUB_SHA'),'qualification_passed':False,'scope':'queued transport Err cadence only, not wrap/policy errors'}
    def save():(out/'result.json').write_text(json.dumps(report,indent=2)+'\n')
    save();report.update(environment());report['baseline_test_source']=BASE;frozen=freeze();report['source_before_sha256']=identity(frozen);save()
    def pristine():return freeze()==frozen and subprocess.run(['git','diff','--quiet','HEAD']).returncode==0
    def run(label,expected):
        ensure(freeze()==expected,'cadence-before-compile-inputs');compilation,cases=compile_cases([TEST]);report[label]={'compilation':compilation,'bodies':[]};save();ensure(freeze()==expected,'cadence-compile-inputs')
        if compilation.get('compile_exit_code')!=0 or compilation.get('compiler_error_count')!=0 or not cases:return False
        ensure(compilation.get('compiled_fingerprints',{}).get('verified'),'cadence-compiled-features')
        case=cases[TEST];started=time.monotonic();row={'test':case['name'],'suffix':TEST,'binary_sha256':case['binary_sha256']}
        try:
            body=subprocess.run([case['binary'],'--exact',case['name'],'--nocapture','--test-threads=1'],capture_output=True,text=True,timeout=300)
            row.update(body_exit_code=body.returncode,body_seconds=time.monotonic()-started)
            report[label]['bodies'].append(row);save()
            try:row.update(parse(body.stdout+body.stderr))
            except Exception as error:row['parser_exception']=type(error).__name__
        except subprocess.TimeoutExpired:row.update(watchdog_triggered=True,actual_count_unknown=True);report[label]['bodies'].append(row)
        save();ensure(freeze()==expected,'cadence-body-inputs');return good(row)
    if args.mode=='controls':
        try:report['controls_passed']=run('controls',frozen)
        except Exception as error:report['controller_exception']=type(error).__name__
        report['inputs_pristine']=pristine();report['controls_passed']=report.get('controls_passed',False) and report['inputs_pristine'];save();raise SystemExit(0 if report['controls_passed'] else 1)
    original=Path(SOURCE).read_bytes();baseline=False;killed=False;restored=False
    try:
        baseline=run('baseline',frozen);ensure(baseline,'cadence-baseline-not-green')
        before=mutation_anchor(original.decode());mutant=original.decode().replace(before,'self.validate_sibling_publication(entry).is_err()',1).encode();expected=dict(frozen);expected[SOURCE]=digest(mutant)
        report['mutation']={'path':SOURCE,'before_sha256':digest(original),'expected_mutant_sha256':digest(mutant)};save();Path(SOURCE).write_bytes(mutant)
        run('mutant',expected);phase=report.get('mutant',{});rows=phase.get('bodies',[]);compilation=phase.get('compilation',{})
        killed=compilation.get('compile_exit_code')==0 and compilation.get('compiler_error_count')==0 and len(rows)==1 and intended_red(rows[0]);report['mutant_runtime_killed']=bool(killed)
    except Exception as error:report['mutation_or_controller_exception']=type(error).__name__
    finally:
        Path(SOURCE).write_bytes(original);report['exact_source_restored_before_control']=pristine();save()
        try:
            ensure(pristine(),'cadence-not-restored');guard=subprocess.run(['python3','scripts/verify_upstream_consent_cadence_source.py']);report['restored_source_guard_exit_code']=guard.returncode;restored=run('restored',frozen)
        except Exception as error:report['restored_control_exception']=type(error).__name__
        report.update(baseline_passed=baseline,restored_control_passed=restored,inputs_pristine=pristine(),source_after_sha256=identity(freeze()));report['mutation_qualified']=bool(baseline and killed and restored and report.get('restored_source_guard_exit_code')==0 and report['inputs_pristine']);save()
    raise SystemExit(0 if report['mutation_qualified'] else 1)
if __name__=='__main__':main()
