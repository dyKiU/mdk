#!/usr/bin/env python3
"""One frozen directed readiness GREEN or scoped P/F/P; no full/native claim."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import qualify_upstream_source_readiness_red as red

BASE = 'c0303bcc28640c0854f34b03cd573fa4779c1b3d'
SELF = 'scripts/qualify_upstream_source_readiness_candidate.py'
WORKFLOW = '.github/workflows/experimental-sync-ci.yml'
REF = 'refs/heads/ci/upstream-source-readiness-green-20261018'
BEGIN = '  # SOURCE_READINESS_GREEN_JOBS_BEGIN\n'
END = '  # SOURCE_READINESS_GREEN_JOBS_END\n'
OPTIONS = 'options: [source-readiness-green-preflight, source-readiness-green, source-readiness-mutations, '
OUT = Path('source-readiness-candidate-evidence')
MUTATIONS = {
    'consume': {'path':'crates/marmot-app/src/client/device_linking/sibling_sharing.rs','old':'match self.recheck_owned_sibling_source_readiness() {','new':'match Ok::<Option<Arc<crate::client::private_enrollment_proposal::OriginalSiblingSharingApproval>>, ClientLinkingError>(None) {'},
    'permit': {'path':'crates/marmot-app/src/client/device_linking/sibling_sharing.rs','old':'(harvested_success || entry.recipient || entry.initial_source_due)','new':'(harvested_success || entry.recipient)'},
}
ensure = red.ensure

def source_guard():
    ensure(re.fullmatch('[0-9a-f]{40}',BASE) is not None,'reviewed-pure-F-required')
    head=subprocess.check_output(['git','rev-parse','HEAD'],text=True).strip()
    ensure(os.environ.get('GITHUB_ACTIONS')=='true' and os.environ.get('GITHUB_REPOSITORY')=='dyKiU/mdk'
        and os.environ.get('GITHUB_EVENT_NAME')=='workflow_dispatch' and os.environ.get('GITHUB_SHA')==head
        and os.environ.get('GITHUB_REF')==REF and os.environ.get('GITHUB_WORKFLOW_REF')=='dyKiU/mdk/'+WORKFLOW+'@'+REF
        and os.environ.get('UPSTREAM_SOURCE_READINESS_GREEN_BASELINE')==BASE,'owned-F-workflow')
    ensure(os.environ.get('CARGO_INCREMENTAL')=='1' and os.environ.get('CARGO_BUILD_JOBS')=='2'
        and os.environ.get('RUST_MIN_STACK')=='4194304'
        and all(os.environ.get(k)=='0' for k in ['CARGO_PROFILE_DEV_DEBUG','CARGO_PROFILE_TEST_DEBUG'])
        and all(not os.environ.get(k) for k in ['RUSTFLAGS','CARGO_ENCODED_RUSTFLAGS','RUSTC_BOOTSTRAP','CARGO_PROFILE_DEV_OPT_LEVEL','CARGO_PROFILE_TEST_OPT_LEVEL']),'unchanged-build-cohort')
    subprocess.run(['git','merge-base','--is-ancestor',BASE,head],check=True)
    ensure(subprocess.run(['git','diff','--quiet','HEAD']).returncode==0,'initial-tracked-pristine')
    baseline={}
    for entry in subprocess.check_output(['git','ls-tree','-r','-z',BASE]).split(b'\0'):
        if entry:
            metadata,name=entry.split(b'\t',1);mode,kind,blob=metadata.decode().split()
            ensure(kind=='blob' and mode in {'100644','100755','120000'},'ordinary-F-layout')
            baseline[os.fsdecode(name)]=(mode,blob)
    current=red.layout();ensure(SELF not in baseline and set(current)==set(baseline)|{SELF},'whole-F-inventory')
    for name,value in current.items():
        mode,blob=baseline.get(name,('100644',None))
        ensure(value['git_mode']==mode and value['symlink']==(mode=='120000')
            and (value['symlink'] or value['actual_executable']==(mode=='100755')),'whole-F-mode')
        data=os.fsencode(os.readlink(name)) if value['symlink'] else Path(name).read_bytes()
        if name==WORKFLOW:
            text=data.decode();ensure(text.count(BEGIN)==text.count(END)==text.count(OPTIONS)==1,'one-isolated-workflow-overlay')
            before,rest=text.split(BEGIN);_,after=rest.split(END)
            data=(before+after).replace(OPTIONS,'options: [',1).encode()
        if blob is not None: ensure(hashlib.sha1(b'blob '+str(len(data)).encode()+b'\0'+data).hexdigest()==blob,'exact-F-content:'+name)
    ensure(set(subprocess.check_output(['git','ls-files','--others','--exclude-standard'],text=True).splitlines()) <= {str(OUT/'result.json')},'no-source-overlays')
    ensure(red.assertion_line()==220,'unchanged-directed-fixture-oracle')
    ensure(all(red.digest(Path(name).read_bytes())==value for name,value in red.NEW_HASHES.items()),'unchanged-reviewed-RED-fixture-and-probe')
    for spec in MUTATIONS.values():
        ensure(not any('UNPINNED' in spec[k] for k in ['path','old','new']),'reviewed-two-product-anchors-required')
        ensure(spec['old']!=spec['new'] and Path(spec['path']).read_text().count(spec['old'])==1,'unique-exact-product-omission')
    return {'source':head,'pure_FIX_baseline':BASE,'all_F_contents_and_modes_exact':True,'historical_runtime_evidence_reused':False}

def complete(row):
    return all(type(row.get(k)) is int for k in ['passed','failed','ignored','executed_nonignored']) and row['passed']+row['failed']==row['executed_nonignored']==1 and row['ignored']==0

def green(row):
    return (complete(row) and all(type(row.get(k)) is int and row[k]==v for k,v in
        {'body_exit_code':0,'passed':1,'failed':0,'ignored':0,'compiler_error_count':0,'all_panic_header_count':0,'marker_header_count':1}.items())
        and row.get('running_counts')==[1] and row.get('executed_case_names')==[red.NAME]
        and row.get('selected_case_observed') is True and red.prerequisite_facts(row)
        and all(row.get('facts',{}).get(k) is True for k in red.FIELDS)
        and not row.get('watchdog_triggered') and not row.get('actual_count_unknown'))

def parser_controls():
    inherited=red.parser_controls()
    marker='source-readiness '+' '.join(k+'=true' for k in red.FIELDS)+' runtime_closes=3 planes_shutdown=3 relay_closed=true attempt_completed=true'
    raw='running 1 test\ntest '+red.NAME+' ... '+marker+'\nok\ntest result: ok. 1 passed; 0 failed; 0 ignored;\n'
    row=red.parse(raw,0);ensure(green(row),'all-ten-facts-GREEN-parser-positive')
    negatives=0
    for delta in [{'passed':True},{'failed':False},{'ignored':False},{'body_exit_code':True},{'body_exit_code':101},
        {'passed':0},{'failed':1},{'ignored':1},{'compiler_error_count':1},{'all_panic_header_count':1},
        {'running_counts':[0]},{'executed_case_names':[red.NAME,red.NAME]},{'selected_case_observed':False},
        {'runtime_closes':2},{'planes_shutdown':2},{'relay_closed':False},{'attempt_completed':False}]:
        ensure(not green(dict(row,**delta)),'non-GREEN-or-unclosed-control-rejected');negatives+=1
    for field in red.FIELDS:
        ensure(not green(dict(row,facts=dict(row['facts'],**{field:False}))),'each-positive-fact-required');negatives+=1
    return {'historical_RED_parser':inherited,'GREEN_positive':1,'GREEN_negative':negatives,'runtime_bodies':0}

def run_phase(expected,modes,phase,save):
    ensure(red.freeze()==expected and red.layout()==modes,'before-compile-source-modes')
    compilation,cases=red.compile_cases([red.CASE]);phase['compilation']=compilation;save()
    ensure(compilation.get('compile_exit_code')==compilation.get('compiler_error_count')==0
        and compilation.get('compiled_fingerprints',{}).get('verified') is True
        and set(cases)=={red.CASE} and cases[red.CASE]['name']==red.NAME,'one-actual-feature-verified-readiness-case')
    phase['feature_identity']=red.feature_identity(compilation);case=cases[red.CASE]
    phase['binary_sha256']=case['binary_sha256'];phase['source_manifest_sha256']=red.identity(expected)
    ensure(red.freeze()==expected and red.layout()==modes and red.digest(Path(case['binary']).read_bytes())==case['binary_sha256'],'before-runtime-pristine')
    phase['runtime_started']=True;save()
    code,raw,seconds=red.bounded.capture([case['binary'],'--exact',red.NAME,'--nocapture','--test-threads=1'],300,limit=8*1024*1024)
    phase['body']=dict(red.parse_body(raw,red.CASE),body_exit_code=code);phase['seconds']=seconds;save()
    phase['body']=red.parse(raw,code);phase['actual_counts_complete']=complete(phase['body'])
    phase['green']=green(phase['body']);phase['intended_runtime_RED']=red.intended_red(phase['body'])
    phase['inputs_pristine']=red.freeze()==expected and red.layout()==modes
    phase['binary_pristine']=red.digest(Path(case['binary']).read_bytes())==case['binary_sha256'];save()
    ensure(phase['inputs_pristine'] and phase['binary_pristine'],'after-runtime-pristine')

def main(args):
    os.umask(0o077);OUT.mkdir(exist_ok=True)
    report={'directed_GREEN':False,'component_mutation_qualified':False,'full_qualification':False,'native_acceptance_claim':False,'promotion_eligible':False,'phases':{}}
    before=None;modes=None;target=None;original=None;original_mode=None
    def save(): (OUT/'result.json').write_text(json.dumps(report,indent=2)+'\n')
    try:
        report['source_guard']=source_guard();report['parser_controls']=parser_controls();save()
        if args.preflight: report['preflight_passed']=True;save();return
        report['environment']=red.environment();before,modes=red.freeze(),red.layout()
        phases=['baseline','mutant','restored'] if args.mutation else ['green']
        if args.mutation:
            spec=MUTATIONS[args.mutation];target=Path(spec['path']);original=target.read_bytes();original_mode=target.stat().st_mode
        for label in phases:
            expected=dict(before)
            if target is not None:
                content=original.replace(spec['old'].encode(),spec['new'].encode(),1) if label=='mutant' else original
                target.write_bytes(content);target.chmod(original_mode);expected[spec['path']]=red.digest(json.dumps({'content_sha256':red.digest(content),**modes[spec['path']]},sort_keys=True).encode())
            phase={};report['phases'][label]=phase;run_phase(expected,modes,phase,save)
            ensure(phase['intended_runtime_RED'] if label=='mutant' else phase['green'],'sole-runtime-oracle-or-positive-control-required')
        if args.mutation:
            baseline,mutant,restored=[report['phases'][k] for k in ['baseline','mutant','restored']]
            ensure(baseline['binary_sha256']==restored['binary_sha256']!=mutant['binary_sha256']
                and baseline['feature_identity']==mutant['feature_identity']==restored['feature_identity']
                and baseline['source_manifest_sha256']==restored['source_manifest_sha256'],'exact-restored-source-binary-feature-identity')
            report['component_mutation_qualified']=True
        else: report['directed_GREEN']=True
    except Exception as error:
        report['exception_type']=type(error).__name__;raise
    finally:
        original_error_active=sys.exc_info()[0] is not None
        try:
            if target is not None: target.write_bytes(original);target.chmod(original_mode)
            report['inputs_pristine']=red.freeze()==before and red.layout()==modes if before is not None else None
        except Exception as error: report['inputs_pristine']=False;report['restoration_error_type']=type(error).__name__
        if report['inputs_pristine'] is False: report['directed_GREEN']=report['component_mutation_qualified']=False
        rows=[v['body'] for v in report['phases'].values() if 'body' in v]
        complete_rows=len(rows)==(3 if args.mutation else 1) and all(complete(row) for row in rows)
        report['actual_counts_complete']=complete_rows
        report['known_partial_counts']={k:sum(row[k] for row in rows if type(row.get(k)) is int) for k in ['passed','failed','ignored','executed_nonignored']}
        for k in ['passed','failed','ignored','executed_nonignored']: report['actual_'+k]=sum(row[k] for row in rows) if complete_rows else None
        save()
        if not original_error_active and before is not None: ensure(report['inputs_pristine'],'final-source-modes-restored')

if __name__=='__main__':
    parser=argparse.ArgumentParser();parser.add_argument('--preflight',action='store_true');parser.add_argument('--mutation',choices=sorted(MUTATIONS));main(parser.parse_args())
