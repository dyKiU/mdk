#!/usr/bin/env python3
"""Remote exact-input controls and independent runtime omission chains."""
import argparse
import json
import os
from pathlib import Path
import subprocess
from upstream_completion_ci import BASE,FEATURES,DEFAULT_FEATURES,NEW,ORIGINALS,environment,freeze,identity,digest,ensure,compile_cases,execute,green,intended_red,headers
from upstream_completion_mutations import SPECS,verify_anchors,anchor
p=argparse.ArgumentParser();p.add_argument('--mode',choices=['controls','signal','wiring','static'],required=True);p.add_argument('--cohort',choices=['default','experimental']);args=p.parse_args()
os.umask(0o077)
OUT=Path('completion-candidate-evidence');OUT.mkdir(exist_ok=True)
r={'mode':args.mode,'source':os.environ.get('GITHUB_SHA'),'qualification_passed':False,'controls_passed':False,'mutation_qualified':False,'restoration_control_attempted':False,'scope':'focused App completion service, not full SDK/native/chat-sync acceptance'}
def save():(OUT/'result.json').write_text(json.dumps(r,indent=2)+'\n')
save();r.update(environment());frozen=freeze();r['source_before_sha256']=identity(frozen)
r['lock_sha256']=frozen['Cargo.lock'];r['cargo_config_sha256']=frozen['.cargo/config.toml'];r['nextest_config_sha256']=frozen['.config/nextest.toml'];save()
def pristine():return freeze()==frozen and subprocess.run(['git','diff','--quiet','HEAD']).returncode==0
def run_phase(label,suffixes,expected=frozen):
    ensure(freeze()==expected,'before-compile-input-drift')
    compilation,cases=compile_cases(suffixes);r[label]={'compilation':compilation,'bodies':[],'source_before_sha256':identity(expected)};save()
    ensure(freeze()==expected,'compile-input-drift')
    if compilation.get('compile_exit_code')!=0 or compilation.get('compiler_error_count')!=0 or not cases:return False
    ensure(compilation.get('compiled_fingerprints',{}).get('verified'),'actual-compiled-feature-fingerprint-unverified')
    for suffix in suffixes:
        ensure(freeze()==expected,'before-body-input-drift')
        row=execute(cases[suffix],suffix);r[label]['bodies'].append(row);save()
        ensure(freeze()==expected,'body-input-drift')
    r[label]['source_after_sha256']=identity(freeze());save()
    r[label]['actual_executed_nonignored']=sum(row.get('executed_nonignored',0) for row in r[label]['bodies']);save()
    return len(r[label]['bodies'])==len(suffixes) and all(green(row) for row in r[label]['bodies'])
if args.mode=='static':
    import time
    ensure(args.cohort is not None,'static-cohort-required')
    features=FEATURES if args.cohort=='experimental' else DEFAULT_FEATURES
    command=['cargo','clippy','--locked','-p','marmot-app','--all-targets','--features',features,'--','-D','warnings']
    r.update(cohort=args.cohort,command=command,actual_runtime_bodies=0)
    started=time.monotonic()
    try:
        result=subprocess.run(command,capture_output=True,text=True,timeout=1800)
        r.update(exit_code=result.returncode,seconds=time.monotonic()-started,**headers(result.stderr))
    except subprocess.TimeoutExpired:r.update(watchdog_triggered=True,seconds=time.monotonic()-started)
    r['inputs_pristine']=pristine();r['static_passed']=r.get('exit_code')==0 and r.get('compiler_error_count')==0 and r['inputs_pristine'];save();raise SystemExit(0 if r['static_passed'] else 1)
if args.mode=='controls':
    try:r['controls_passed']=run_phase('controls',[NEW]+ORIGINALS)
    except Exception as error:r['controller_exception']=type(error).__name__
    r['inputs_pristine']=pristine();r['controls_passed'] &= r['inputs_pristine'];save();raise SystemExit(0 if r['controls_passed'] else 1)
# Every chain starts/ends on the complete frozen source, regardless of oracle failure.
source_path=None;original=None;baseline_ok=False;mutant_ok=False;restored_ok=False
try:
    verify_anchors()
    baseline_ok=run_phase('baseline',[NEW]);r['baseline_passed']=baseline_ok;save()
    ensure(baseline_ok,'baseline-not-green')
    spec=SPECS[args.mode];source_path=Path(spec['path']);original=source_path.read_bytes();text=original.decode();before=anchor(text,spec)
    mutant=text.replace(before,spec['after'],1).encode();expected=dict(frozen);expected[spec['path']]=digest(mutant)
    r['mutation']={'path':spec['path'],'before_sha256':digest(original),'expected_mutant_sha256':digest(mutant),'allowed_changed_paths':[spec['path']]};save()
    source_path.write_bytes(mutant);ensure(freeze()==expected,'exact-mutant-inputs')
    run_phase('mutant',[NEW],expected)
    result=r.get('mutant',{});compile_row=result.get('compilation',{});bodies=result.get('bodies',[])
    mutant_ok=compile_row.get('compile_exit_code')==0 and compile_row.get('compiler_error_count')==0 and len(bodies)==1 and intended_red(bodies[0]);r['mutant_runtime_killed']=bool(mutant_ok);save()
except Exception as error:r['mutation_or_controller_exception']=type(error).__name__
finally:
    if source_path is not None and original is not None:source_path.write_bytes(original)
    r['exact_source_restored_before_control']=pristine();r['restoration_control_attempted']=True;save()
    try:
        ensure(pristine(),'source-not-restored')
        guard=subprocess.run(['python3','scripts/verify_upstream_completion_candidate_source.py'])
        r['restored_source_guard_exit_code']=guard.returncode;save()
        # An invalid anchor/guard never suppresses the actual restored control.
        restored_ok=run_phase('restored',[NEW]);r['restored_control_passed']=restored_ok
    except Exception as error:r['restored_control_exception']=type(error).__name__
    r['inputs_pristine']=pristine();r['source_after_sha256']=identity(freeze());r['mutation_qualified']=bool(baseline_ok and mutant_ok and restored_ok and r.get('restored_source_guard_exit_code')==0 and r['inputs_pristine']);save()
raise SystemExit(0 if r['mutation_qualified'] else 1)
