#!/usr/bin/env python3
"""One diagnostic-only post-watch native5 body on the exact full observer tree."""
import argparse,hashlib,json,os,re,shutil,subprocess
from pathlib import Path
import diagnose_upstream_post_offer_native5 as previous
frozen=previous.frozen
ensure=previous.ensure
digest=previous.digest
BASE='64dbf00220c6aac5bd19c17628a85a640cddf42e' # Root freezes d4 diagnostic + exactly three watch inserts, then pins full SHA.
DIAGNOSTIC_PARENT='d4cb1dfa6df1c7751a02b35b3dd67f6ea283ee24'
SELF='scripts/diagnose_upstream_post_watch_native5.py'
WORKFLOW='.github/workflows/experimental-sync-ci.yml'
REF='refs/heads/ci/upstream-post-watch-native5-diagnostic-20261018'
BEGIN='  # POST_WATCH_NATIVE5_JOBS_BEGIN\n'
END='  # POST_WATCH_NATIVE5_JOBS_END\n'
OPTIONS='options: [post-watch-native5-preflight, post-watch-native5-diagnostic, '
OUT=Path('post-watch-native5-evidence')


def source_guard():
    ensure(type(BASE) is str and re.fullmatch('[0-9a-f]{40}',BASE),'root-frozen-post-watch-diagnostic-BASE-required')
    head=subprocess.check_output(['git','rev-parse','HEAD'],text=True).strip()
    ensure(os.environ.get('GITHUB_ACTIONS')=='true' and os.environ.get('GITHUB_REPOSITORY')=='dyKiU/mdk'
        and os.environ.get('GITHUB_EVENT_NAME')=='workflow_dispatch' and os.environ.get('GITHUB_SHA')==head
        and os.environ.get('GITHUB_REF')==REF and os.environ.get('GITHUB_WORKFLOW_REF')=='dyKiU/mdk/'+WORKFLOW+'@'+REF
        and os.environ.get('UPSTREAM_POST_WATCH_NATIVE5_BASELINE')==BASE,'exact-owned-post-watch-workflow')
    ensure(os.environ.get('CARGO_INCREMENTAL')=='1' and os.environ.get('CARGO_BUILD_JOBS')=='2'
        and os.environ.get('RUST_MIN_STACK')=='4194304'
        and all(os.environ.get(k)=='0' for k in ['CARGO_PROFILE_DEV_DEBUG','CARGO_PROFILE_TEST_DEBUG'])
        and all(not os.environ.get(k) for k in ['RUSTFLAGS','CARGO_ENCODED_RUSTFLAGS','RUSTC_BOOTSTRAP','CARGO_PROFILE_DEV_OPT_LEVEL','CARGO_PROFILE_TEST_OPT_LEVEL']),'unchanged-observer-build-cohort')
    subprocess.run(['git','merge-base','--is-ancestor',DIAGNOSTIC_PARENT,BASE],check=True)
    subprocess.run(['git','merge-base','--is-ancestor',BASE,head],check=True)
    ensure(subprocess.run(['git','diff','--quiet','HEAD']).returncode==0,'initial-whole-HEAD-pristine')
    baseline={}
    for item in subprocess.check_output(['git','ls-tree','-r','-z',BASE]).split(b'\0'):
        if item:
            metadata,name=item.split(b'\t',1);mode,kind,sha=metadata.decode().split()
            ensure(kind=='blob' and mode in {'100644','100755','120000'},'ordinary-diagnostic-baseline-layout')
            baseline[os.fsdecode(name)]=(mode,sha)
    current=frozen.ack.layout()
    ensure(SELF not in baseline and set(current)==set(baseline)|{SELF},'whole-post-watch-inventory-one-new-SELF')
    for path,row in current.items():
        mode,sha=baseline.get(path,('100644',None))
        ensure(row['git_mode']==mode and row['symlink']==(mode=='120000')
            and (row['symlink'] or row['actual_executable']==(mode=='100755')),'whole-post-watch-source-modes')
        data=os.fsencode(os.readlink(path)) if row['symlink'] else Path(path).read_bytes()
        if path==WORKFLOW:
            text=data.decode();ensure(text.count(BEGIN)==text.count(END)==text.count(OPTIONS)==1,'one-new-post-watch-overlay')
            before,rest=text.split(BEGIN);_,after=rest.split(END)
            data=(before+after).replace(OPTIONS,'options: [',1).encode()
        if sha is not None:ensure(hashlib.sha1(b'blob '+str(len(data)).encode()+b'\0'+data).hexdigest()==sha,'whole-post-watch-content-no-Rust-exceptions:'+path)
    allowed={str(OUT/'result.json'),str(OUT/'formatting.patch')}
    ensure(set(subprocess.check_output(['git','ls-files','--others','--exclude-standard'],text=True).splitlines())<=allowed,'no-untracked-source-overlay')
    return {'source':head,'baseline':BASE,'all_existing_source_modes_exact':True,'Rust_exceptions':[],
        'old_post_offer_wrapper_and_jobs_are_ordinary_BASE_source':True,'old_source_guards_called':False,
        'old_main_called':False,'old_module_globals_mutated':False,'runtime_evidence_reused':False}


def controls():
    return previous.controls() # Data/parsers only; no legacy guard or main.


def compile_one(report,save):
    return previous.compile_one(report,save) # Guard-free exact one-case compile/inventory helper.


def main(args):
    os.umask(0o077);OUT.mkdir(exist_ok=True)
    report={'baseline':BASE,'scope':'one-original-post-watch-native5-passive-diagnostic','qualification_passed':False,
        'native_qualification':False,'promotion_eligible':False,'runtime_execution_attempted':False,
        'actual_counts_complete':False,'actual_passed':None,'actual_failed':None,'actual_ignored':None,
        'actual_executed_nonignored':None,'actual_native5_pass':False,'diagnostic_completed':False,'automatic_retries':0,
        'source_composition':{'pre_watch_diagnostic_parent':DIAGNOSTIC_PARENT,'command_offer_retained':True,
            'experimental_watch_offer_added':True,'all_existing_passive_observations_retained':True,
            'final_pure_source_closure_equal':False,'current_pure_owner_and_test_support_not_same_whole_tree':True},
        'interpretation':{'worker_selected_masks':{'9':'completion service','17':'claimed delivery ingest','65':'command'},
            'mixed_mask_not_exclusive_arm_attribution':True,'poll_and_stage_durations_are_wall_not_CPU':True,
            'suspended_gap_not_proven_ready_queue_residence':True,'native_ACK_to_same_sealed_wire_route_focus':True,
            'first_outer_delivery_is_separate_identity_observation':True}}

    before=None;binary=None;binary_sha=None
    def save():(OUT/'result.json').write_text(json.dumps(report,indent=2)+'\n')
    try:
        report['source_guard']=source_guard();report['parser_controls']=controls();save()
        if args.preflight:
            code,raw,seconds=frozen.bounded.capture(['cargo','fmt','--all'],180,limit=8*1024*1024)
            patch=subprocess.check_output(['git','diff','--binary'])
            report['format']={'exit_code':code,'seconds':seconds,'patch_bytes':len(patch),'patch_sha256':digest(patch)}
            if patch:(OUT/'formatting.patch').write_bytes(patch)
            save();ensure(code==0 and not patch,'hosted-format-required');report['preflight_passed']=True;save();return
        before=frozen.frozen_inputs();report['source_before_sha256']=digest(json.dumps(before,sort_keys=True).encode())
        case=compile_one(report,save);binary=Path(case['binary']);binary_sha=case['binary_sha256']
        report['binary_before_sha256']=binary_sha
        ensure(frozen.frozen_inputs()==before and binary.is_file() and digest(binary.read_bytes())==binary_sha,'before-body-source-binary-pristine')
        report['runtime_execution_attempted']=True;save()
        code,raw,seconds=frozen.bounded.capture([str(binary),'--exact',frozen.NAME,'--nocapture','--test-threads=1'],900,limit=8*1024*1024)
        row=frozen.counts.parse_body(raw,code,frozen.NAME)
        report['body']=row;report['body_seconds']=seconds;report['body_exit_code']=code
        report['actual_counts_complete']=row.get('actual_counts_complete') is True
        for dest,key in [('actual_passed','passed'),('actual_failed','failed'),('actual_ignored','ignored'),('actual_executed_nonignored','executed_nonignored')]:report[dest]=row.get(key)
        report['source_after_body_sha256']=digest(json.dumps(frozen.frozen_inputs(),sort_keys=True).encode())
        report['inputs_after_body_pristine']=frozen.frozen_inputs()==before
        report['binary_after_body_sha256']=digest(binary.read_bytes()) if binary.is_file() else None
        report['binary_after_body_pristine']=report['binary_after_body_sha256']==binary_sha;save()
        report['body']=frozen.parse(raw,code);report['actual_native5_pass']=frozen.green(report['body'])
        report['panic_observations']=frozen.safe_panic_locations(raw,before);save()
        if code!=0:
            report['closed_failure_observations']=frozen.closed_failure_observations(raw,(report['body'].get('facts') or {}).get('completed_steps'));save()
        report['timing_windows']=frozen.timing_parser.timing_windows(raw,frozen.NAME);save()
        windows=report['timing_windows']['windows']
        def known_window(window):
            timing=window['timing'];wait=timing.get('wait')
            return (timing['known'] is True and isinstance(wait,dict)
                and all(type(wait.get(k)) is int for k in ['constructed_before_us','constructed_after_us','observed_us'])
                and type(wait.get('outcome_ok')) is bool)
        report['native_windows_completed']=bool(windows) and all(known_window(w) for w in windows)
        report['notification_schemas_complete']=bool(windows) and all(w['notification_dispositions'].get('observed') is True and w['notification_dispositions'].get('schema_complete') is True for w in windows)
        report['intake_schemas_complete']=bool(windows) and all(w['intake_dispositions'].get('observed') is True and w['intake_dispositions'].get('schema_complete') is True for w in windows)
        report['actual_named_body_observed']=(row.get('actual_counts_complete') is True
            and all(type(row.get(k)) is int and row[k]==v for k,v in {'executed_nonignored':1,'ignored':0,'compiler_error_count':0}.items())
            and type(code) is int and code in {0,101})
        report['diagnostic_completed']=all(report[k] is True for k in ['actual_named_body_observed','native_windows_completed','notification_schemas_complete','intake_schemas_complete'])
        report['SDK_worker_intake_known_are_independent']=True
        report['missing_fifth_is_not_zero_or_pass']=True
        report['plane_shutdown_semantics']='returned shutdown calls; internal task quiescence not established';save()
        ensure(row['actual_counts_complete'] is True and type(row.get('executed_nonignored')) is int and row['executed_nonignored']==1
            and type(row.get('ignored')) is int and row['ignored']==0 and type(row.get('compiler_error_count')) is int and row['compiler_error_count']==0,'one-actual-native5-body-required')
        ensure(report['inputs_after_body_pristine'] and report['binary_after_body_pristine'],'after-body-source-binary-pristine')
        ensure(report['diagnostic_completed'],'closed-known-native-windows-and-supplemental-schemas-required')
    except frozen.bounded.GateFailure as error:
        report['watchdog_triggered']=str(error)=='bounded-command-timeout';report['output_limit_triggered']=str(error)=='bounded-command-output-limit'
        report['exception_type']=type(error).__name__
        if re.fullmatch('[A-Za-z0-9_.:/-]{1,140}',str(error)):report['failure_gate']=str(error)
        save();raise
    except Exception as error:
        report['exception_type']=type(error).__name__
        if isinstance(error,ValueError):report['failure_gate']=str(error) if re.fullmatch('[A-Za-z0-9_.:/-]{1,140}',str(error)) else 'closed-gate-rejected'
        save();raise
    finally:
        if before is not None:
            report['inputs_pristine']=frozen.frozen_inputs()==before
            report['source_final_sha256']=digest(json.dumps(frozen.frozen_inputs(),sort_keys=True).encode())
            if not report['runtime_execution_attempted']:report['actual_executed_nonignored']=0
        if binary is not None:
            report['binary_final_sha256']=digest(binary.read_bytes()) if binary.is_file() else None
            report['binary_pristine']=report['binary_final_sha256']==binary_sha
        if report.get('inputs_pristine') is False or report.get('binary_pristine') is False:
            report['observed_native5_pass']=report['actual_native5_pass'];report['actual_native5_pass']=False;report['diagnostic_completed']=False
        save()
        if before is not None:ensure(report['inputs_pristine'],'final-source-modes-pristine')
        if binary is not None:ensure(report['binary_pristine'],'final-binary-pristine')

if __name__=='__main__':
    ap=argparse.ArgumentParser();ap.add_argument('--preflight',action='store_true');main(ap.parse_args())
