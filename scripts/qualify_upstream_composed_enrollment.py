#!/usr/bin/env python3
"""Frozen reconciled composed product cohort over unchanged sixteen-case ACK qualification."""
import argparse
import json
import shutil
import hashlib
import os
import re
from pathlib import Path
import subprocess
import qualify_upstream_request_retry_ack as ack
import qualify_upstream_source_readiness_candidate as readiness
import qualify_upstream_storage_boundary as bounded
import qualify_upstream_storage_app_handles as counts
from upstream_completion_ci import compile_cases, digest
from qualify_upstream_body_negative import feature_identity
from upstream_extraction_cohort import frozen_inputs

BASE = 'f994bc0fb5e54e25653986db89a4a2fc6d001a9b' # Root pins the exact reviewed formatted COMPOSED full baseline.
SELF = 'scripts/qualify_upstream_composed_enrollment.py'
WORKFLOW = '.github/workflows/experimental-sync-ci.yml'
REF = 'refs/heads/ci/upstream-composed-enrollment-final-20261018'
BEGIN = '  # COMPOSED_ENROLLMENT_JOBS_BEGIN\n'
END = '  # COMPOSED_ENROLLMENT_JOBS_END\n'
OPTIONS = 'options: [composed-final-preflight, composed-final-controls, composed-final-native-five, composed-enrollment-mutations, '
OUT = Path('composed-enrollment-evidence')
ensure = ack.ensure
FIXTURE='crates/marmot-app/src/native_device_linking/tests/sequential_installations_acceptance.rs'
PARENT='crates/marmot-app/src/native_device_linking/tests/automatic_pairing_acceptance.rs'
FIXTURE_SHA='a81cc692c9864d9cdf2ff7fe8d533d3115c7eb7958fa7a22df783850fea520ca' # Root pins the exact reviewed formatted fixture in BASE.
OWNER_SHA='d6b092b39cb41b4d2d6a1c4927a1fdd07fd6fe1d1bb20241b98e881fe6922f6f'
STRICT_HELPER_SHA='a059addf027097d91c672ccfe36e613f99cfb93f889ab2087b872a84c7a58ff2' # Root pins the exact unchanged strict15 helper in BASE.
OWNER_COMMENT='// Reuse the OWNER1611 helper:90s enrollment,15s earlier phases;'
CURRENT_COMMENT='// Reuse the integration helper:15s for every phase;'
REGISTRATION='\n#[path = "sequential_installations_acceptance.rs"]\nmod sequential_installations_acceptance;\n'
SUFFIX='sequential_installations_acceptance::five_installations_join_with_rotating_existing_sponsors_and_explicit_sharing'
NAME='native_device_linking::automatic_pairing_acceptance::'+SUFFIX
NODES={'marmot_app','cgka_engine','storage_sqlite','cgka_session','marmot_account','transport_nostr'}
MARKER='sequential-installations completed_steps=4 final_device_count=5 final_roster_and_policies=true public_cancels=14 runtime_closes=5 storages_closed=true plane_shutdown_returns=5 listener_closed=true attempt_completed=true'



def source_guard():
    ensure(isinstance(BASE,str) and re.fullmatch('[0-9a-f]{40}',BASE),'reviewed-composed-full-baseline-required')
    ensure(all(isinstance(pin,str) and re.fullmatch('[0-9a-f]{64}',pin) for pin in [FIXTURE_SHA,STRICT_HELPER_SHA]),'reviewed-composed-fixture-and-helper-pins-required')
    head=subprocess.check_output(['git','rev-parse','HEAD'],text=True).strip()
    ensure(os.environ.get('GITHUB_ACTIONS')=='true' and os.environ.get('GITHUB_REPOSITORY')=='dyKiU/mdk'
        and os.environ.get('GITHUB_EVENT_NAME')=='workflow_dispatch' and os.environ.get('GITHUB_SHA')==head
        and os.environ.get('GITHUB_REF')==REF and os.environ.get('GITHUB_WORKFLOW_REF')=='dyKiU/mdk/'+WORKFLOW+'@'+REF
        and os.environ.get('UPSTREAM_COMPOSED_ENROLLMENT_BASELINE')==BASE,'exact-owned-final-cohort-workflow')
    ensure(os.environ.get('CARGO_INCREMENTAL')=='1' and os.environ.get('CARGO_BUILD_JOBS')=='2'
        and os.environ.get('RUST_MIN_STACK')=='4194304'
        and all(os.environ.get(k)=='0' for k in ['CARGO_PROFILE_DEV_DEBUG','CARGO_PROFILE_TEST_DEBUG'])
        and all(not os.environ.get(k) for k in ['RUSTFLAGS','CARGO_ENCODED_RUSTFLAGS','RUSTC_BOOTSTRAP','CARGO_PROFILE_DEV_OPT_LEVEL','CARGO_PROFILE_TEST_OPT_LEVEL']),'exact-final-build-cohort')
    subprocess.run(['git','merge-base','--is-ancestor',BASE,head],check=True)
    ensure(subprocess.run(['git','diff','--quiet','HEAD']).returncode==0,'initial-tracked-pristine')
    baseline={}
    for entry in subprocess.check_output(['git','ls-tree','-r','-z',BASE]).split(b'\0'):
        if entry:
            metadata,name=entry.split(b'\t',1);mode,kind,blob=metadata.decode().split()
            ensure(kind=='blob' and mode in {'100644','100755','120000'},'ordinary-final-baseline-layout')
            baseline[os.fsdecode(name)]=(mode,blob)
    current=ack.layout()
    ensure(SELF not in baseline and FIXTURE in baseline and PARENT in baseline and set(current)==set(baseline)|{SELF},'whole-final-cohort-inventory')
    for name,value in current.items():
        mode,blob=baseline.get(name,('100644',None))
        ensure(value['git_mode']==mode and value['symlink']==(mode=='120000')
            and (value['symlink'] or value['actual_executable']==(mode=='100755')),'whole-final-cohort-mode')
        data=os.fsencode(os.readlink(name)) if value['symlink'] else Path(name).read_bytes()
        if name==FIXTURE:
            ensure(digest(data)==FIXTURE_SHA and data.count(CURRENT_COMMENT.encode())==1 and OWNER_COMMENT.encode() not in data,'exact-reviewed-formatted-composed-fixture')
        if name==PARENT:
            text=data.decode();ensure(text.count(REGISTRATION)==1,'one-existing-registration-only')
            start=text.index('async fn wait_for_automatic_phase_with_approvals(')
            end=text.index('\n}\n',start)+3
            ensure(digest(text[start:end].encode())==STRICT_HELPER_SHA,'unchanged-strict15-helper')
        if name==WORKFLOW:
            text=data.decode();ensure(text.count(BEGIN)==text.count(END)==text.count(OPTIONS)==1,'one-isolated-final-workflow-overlay')
            before,rest=text.split(BEGIN);_,after=rest.split(END)
            data=(before+after).replace(OPTIONS,'options: [',1).encode()
        if blob is not None: ensure(hashlib.sha1(b'blob '+str(len(data)).encode()+b'\0'+data).hexdigest()==blob,'exact-final-source:'+name)
    ensure(set(subprocess.check_output(['git','ls-files','--others','--exclude-standard'],text=True).splitlines()) <= {str(OUT/'result.json')},'no-untracked-source-overlay')
    ensure(len(ack.CASES)==16 and len({row[0] for row in ack.CASES})==16,'unchanged-sixteen-case-definition')
    ensure(readiness.red.assertion_line()==220,'unchanged-readiness-runtime-oracle')
    ensure(all(readiness.red.digest(Path(name).read_bytes())==value for name,value in readiness.red.NEW_HASHES.items()),'unchanged-reviewed-readiness-fixture-and-probe')
    for spec in readiness.MUTATIONS.values():
        ensure(spec['old']!=spec['new'] and Path(spec['path']).read_text().count(spec['old'])==1 and spec['new'] not in Path(spec['path']).read_text(),'unique-reviewed-readiness-omission')
    return {'source':head,'reviewed_final_baseline':BASE,'all_product_tests_helpers_contents_and_modes_exact':True,
        'historical_ACK_controller_preserved':True,'historical_ACK_source_guard_invoked':False,
        'explicit_wrapper_guard_substitution':True,'historical_runtime_evidence_reused':False,
        'storage_rotating_sponsor_GREEN_is_separate_required_evidence':True,'original_sixteen_including_three_required_serial_stress_cases_preserved':True,'five_device_fixture_already_in_baseline':True,'fixture_sha256':FIXTURE_SHA,'strict_helper_sha256':STRICT_HELPER_SHA,'new_composed_runtime_evidence_required':True,'native_parser_controls':parser_controls(),'readiness_parser_controls':readiness.parser_controls(),'readiness_historical_guard_invoked':False,'readiness_fresh_PFP_required':True}


def parse(raw,code):
    # Exact-name/count parser is unchanged shared infrastructure. Preserve original libtest prefix.
    row=counts.parse_body(raw,code,NAME)
    clean=re.sub(r'\x1b\[[0-9;]*m','',raw)
    marker_text=re.sub(r'(?m)^test '+re.escape(NAME)+r' \.\.\. (?=sequential-installations )','',clean)
    lines=[line for line in marker_text.splitlines() if line.startswith('sequential-installations')]
    row['marker_count']=len(lines);row['facts']=None
    pattern=(r'sequential-installations completed_steps=([0-4]) final_device_count=([0-5]) final_roster_and_policies=(true|false)'
        r' public_cancels=([0-9]{1,2}) runtime_closes=([0-5]) storages_closed=(true|false) plane_shutdown_returns=([0-5])'
        r' listener_closed=(true|false) attempt_completed=(true|false)')
    match=re.fullmatch(pattern,lines[0]) if len(lines)==1 and len(lines[0])<=512 else None
    if match and int(match[4])<=14:
        row['facts']={'completed_steps':int(match[1]),'final_device_count':int(match[2]),'final_roster_and_policies':match[3]=='true',
            'public_cancels':int(match[4]),'runtime_closes':int(match[5]),'storages_closed':match[6]=='true',
            'plane_shutdown_returns':int(match[7]),'listener_closed':match[8]=='true','attempt_completed':match[9]=='true'}
    return row

def green(row):
    facts=row.get('facts')
    return (row.get('actual_counts_complete') is True and row.get('passed_gate') is True
        and all(type(row.get(k)) is int and row[k]==v for k,v in {'passed':1,'failed':0,'ignored':0,'executed_nonignored':1,'exit_code':0,'compiler_error_count':0,'panic_count':0,'marker_count':1}.items())
        and isinstance(facts,dict) and all(type(facts.get(k)) is int and facts[k]==v for k,v in
            {'completed_steps':4,'final_device_count':5,'public_cancels':14,'runtime_closes':5,'plane_shutdown_returns':5}.items())
        and all(facts.get(k) is True for k in ['final_roster_and_policies','storages_closed','listener_closed','attempt_completed']))

def parser_controls():
    inherited=counts.parser_controls()
    raw='running 1 test\ntest '+NAME+' ... ok\n'+MARKER+'\ntest result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 2 filtered out; finished in 1.0s\n'
    ensure(green(parse(raw,0)),'closed-five-positive')
    shared=raw.replace(' ... ok\n'+MARKER,' ... '+MARKER+'\nok')
    ensure(green(parse(shared,0)),'exact-libtest-shared-marker-positive')
    bad=[raw.replace('completed_steps=4','completed_steps=3'),raw.replace('final_device_count=5','final_device_count=4'),
        raw.replace('final_roster_and_policies=true','final_roster_and_policies=false'),raw.replace('public_cancels=14','public_cancels=13'),
        raw.replace('runtime_closes=5','runtime_closes=4'),raw.replace('storages_closed=true','storages_closed=false'),
        raw.replace('plane_shutdown_returns=5','plane_shutdown_returns=4'),raw.replace('listener_closed=true','listener_closed=false'),
        raw.replace('attempt_completed=true','attempt_completed=false'),raw+'\n'+MARKER,raw.replace(MARKER,''),
        raw.replace(NAME,NAME+'_foreign'),raw.replace('0 ignored','1 ignored'),raw.replace('1 passed','0 passed'),
        raw.replace(MARKER,MARKER+' private=hidden'),raw.replace('public_cancels=14','public_cancels=99'),raw.replace('storages_closed=true','storages_closed=hidden'),
        raw+raw,raw+'error[E0000]: rejected\n',raw+"thread 'closed' panicked at crates/closed.rs:1:1:\n"]
    for text in bad:ensure(not green(parse(text,0)),'closed-five-adversary')
    ensure(not green(parse(raw,124)),'watchdog-not-pass')
    row=parse(raw,0)
    for key in ['passed','failed','ignored','executed_nonignored','exit_code','compiler_error_count','panic_count','marker_count']:
        ensure(not green({**row,key:True}),'bool-not-body-count')
    return {'shared_count_inventory_controls':inherited,'positive':2,'negative':len(bad)+9,'actual_runtime_executions':0}

def native_five_main(args):
    os.umask(0o077);OUT.mkdir(exist_ok=True)
    report={'baseline':BASE,'scope':'one-local-real-SDK-five-installation-journey-inherited-strict15s',
        'qualification_passed':False,'promotion_eligible':False,'native_acceptance_claim':False,'installed_binary_claim':False,
        'journey_passed':False,'runtime_execution_attempted':False,'actual_counts_complete':False,
        'actual_executed_nonignored':None,'actual_passed':None,'actual_failed':None,'actual_ignored':None}
    frozen=None;compiled_binary=None;compiled_binary_sha=None
    def save():(OUT/'result.json').write_text(json.dumps(report,indent=2)+'\n')
    try:
        report['source_guard']=source_guard();report['parser_controls']=parser_controls();save()
        if args.preflight:report['preflight_passed']=True;save();return
        frozen=frozen_inputs();report['source_manifest_sha256']=digest(json.dumps(frozen,sort_keys=True).encode())
        report['capacity']={'free_bytes':shutil.disk_usage('.').free,'minimum_free_bytes':8*1024**3};save()
        ensure(report['capacity']['free_bytes']>=8*1024**3,'remote-capacity')
        compilation,cases=compile_cases([SUFFIX])
        compilation.pop('compiler_headers',None) # Never persist raw diagnostic message text.
        report['compilation']=compilation;save()
        ensure(compilation.get('compile_exit_code')==0 and compilation.get('compiler_error_count')==0
            and compilation.get('compiled_fingerprints',{}).get('verified') is True and set(cases)=={SUFFIX},'actual-one-compiled-case')
        case=cases[SUFFIX];ensure(case['name']==NAME,'exact-native-five-fullname')
        compiled_binary=Path(case['binary']);compiled_binary_sha=case['binary_sha256']
        report['feature_identity']=feature_identity(compilation)
        ensure(set(report['feature_identity']['nodes'])==NODES,'six-real-App-dependency-fingerprints')
        for ignored in [False,True]:
            command=[case['binary'],'--exact',NAME]+(['--ignored'] if ignored else [])+['--list','--format','terse']
            code,raw,_=bounded.capture(command,60,limit=1024*1024)
            inventory=counts.parse_inventory(raw,NAME,ignored)
            report.setdefault('inventory',{})['ignored' if ignored else 'normal']=inventory;save()
            ensure(code==0 and inventory['passed'],'one-selected-nonignored-body')
        ensure(frozen_inputs()==frozen and digest(Path(case['binary']).read_bytes())==case['binary_sha256'],'before-runtime-pristine')
        report['runtime_execution_attempted']=True;save()
        try:
            code,raw,seconds=bounded.capture([case['binary'],'--exact',NAME,'--nocapture','--test-threads=1'],900,limit=8*1024*1024)
            basic=counts.parse_body(raw,code,NAME);report['body']=basic;report['body_seconds']=seconds;save()
            report['body']=parse(raw,code);report['journey_passed']=green(report['body'])
            body=report['body'];report['actual_counts_complete']=body['actual_counts_complete']
            for target,key in [('actual_executed_nonignored','executed_nonignored'),('actual_passed','passed'),('actual_failed','failed'),('actual_ignored','ignored')]:
                report[target]=body.get(key)
            report['plane_shutdown_semantics']='returned shutdown calls, not internal task quiescence';save()
        except bounded.GateFailure as error:
            report['watchdog_triggered']=str(error)=='bounded-command-timeout'
            report['output_limit_triggered']=str(error)=='bounded-command-output-limit';save();raise
        ensure(frozen_inputs()==frozen and digest(Path(case['binary']).read_bytes())==case['binary_sha256'],'after-runtime-pristine')
        ensure(report['journey_passed'],'actual-journey-and-all-positive-closures-required')
    except Exception as error:
        report['exception_type']=type(error).__name__
        if isinstance(error,ValueError):report['failure_gate']=str(error) if re.fullmatch('[A-Za-z0-9_.:/-]{1,140}',str(error)) else 'closed-gate-rejected'
        raise
    finally:
        if frozen is not None:
            report['inputs_pristine']=frozen_inputs()==frozen
            if not report['runtime_execution_attempted']:
                report['actual_executed_nonignored']=0 # Compilation/inventory/setup ran no Rust test body.
        if compiled_binary is not None:
            report['binary_pristine']=compiled_binary.is_file() and digest(compiled_binary.read_bytes())==compiled_binary_sha
        if report.get('inputs_pristine') is False or report.get('binary_pristine') is False:
            report['observed_body_journey_pass']=report['journey_passed'];report['journey_passed']=False
        save()
        if frozen is not None:ensure(report['inputs_pristine'],'final-inputs-pristine')
        if compiled_binary is not None:ensure(report['binary_pristine'],'final-binary-pristine')


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--preflight',action='store_true')
    parser.add_argument('--mode',choices=['full','static','native-five','readiness'],default='full')
    parser.add_argument('--cohort',choices=['default','experimental'])
    parser.add_argument('--mutation',choices=['consume','permit'])
    args=parser.parse_args()
    ensure(args.mutation is None or args.mode=='readiness','mutation-only-in-readiness-mode')
    ensure(args.mode!='static' or args.cohort in {'default','experimental'},'explicit-static-cohort')
    # These are the only substitutions. Historical case/parser/compile/runtime,
    # feature, count, binary, closure and finally-pristine functions stay intact.
    ack.source_guard=source_guard
    ack.OUT=OUT
    if args.mode=='readiness' and not args.preflight:
        readiness.source_guard=source_guard
        readiness.OUT=OUT
        readiness.main(args)
    elif args.mode=='native-five' and not args.preflight:
        native_five_main(args)
    else:
        ack.main(args)


if __name__=='__main__':
    main()
