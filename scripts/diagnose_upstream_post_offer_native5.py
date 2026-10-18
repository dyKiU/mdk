#!/usr/bin/env python3
"""One unchanged post-offer native5 diagnostic. Actual FAIL never becomes native PASS."""
import argparse,hashlib,json,os,re,shutil,subprocess
from pathlib import Path
import diagnose_upstream_native5_consent as frozen
BASE='a9c99b7025f1b4d4a948a041b2d6d0e0ed9ddd55'
SELF='scripts/diagnose_upstream_post_offer_native5.py'
MANIFEST='scripts/post_offer_native5_source_manifest.json'
MANIFEST_SHA='0edeefa915adf7a8eed3bdaccd5305e8c3c07b4d20c0149e4c7dc379b321c2a8' # Root pins exact reviewed metadata; no inference from current HEAD.
WORKFLOW='.github/workflows/experimental-sync-ci.yml'
REF='refs/heads/ci/upstream-private-command-backlog-red-20261018'
BEGIN='  # POST_OFFER_NATIVE5_JOBS_BEGIN\n'
END='  # POST_OFFER_NATIVE5_JOBS_END\n'
OPTIONS='options: [post-offer-native5-preflight, post-offer-native5-diagnostic, '
OUT=Path('post-offer-native5-evidence')
DEPS={'scripts/diagnose_upstream_native5_consent.py': '056089f004cc6c0846e80fc35a57f08704a9e43b89f9ec029bd61653dcbeaa68', 'scripts/native5_timing_parser.py': '83ea7f40544138cd87500a3a087a03218a4191c4d808c85bcc563b754c9d6211', 'scripts/upstream_completion_ci.py': '653ee721447382753e7a69a16762b1981e70188ca029886dfa72026231550b7b', 'crates/marmot-app/src/native_device_linking/tests/sequential_installations_acceptance.rs': '75998408ac1d0b1ab8fab0174ba4391594bc1e24f4f6fde3e76595fdba8b214f', 'crates/marmot-app/src/native_device_linking/tests/automatic_pairing_acceptance.rs': '516b123d21c218a185e92f854559f965d3f003d0417ca5c44a4193ac49cd7286', 'crates/marmot-app/src/runtime/account_worker.rs': 'dc35d1d24a21fb0ac85ab9353217272bdd9797fb780fcab23afbbae24d1cf767'}
ensure=frozen.ensure
digest=frozen.digest


def source_guard():
    ensure(type(MANIFEST_SHA) is str and re.fullmatch('[0-9a-f]{64}',MANIFEST_SHA),'reviewed-post-offer-manifest-required')
    ensure(digest(Path(MANIFEST).read_bytes())==MANIFEST_SHA,'exact-post-offer-manifest')
    manifest=json.loads(Path(MANIFEST).read_text())
    ensure(manifest['baseline']==BASE and manifest['immutable_dependencies']==DEPS and manifest['Rust_exceptions']==[],'exact-post-offer-baseline-no-Rust-exceptions')
    head=subprocess.check_output(['git','rev-parse','HEAD'],text=True).strip()
    ensure(os.environ.get('GITHUB_ACTIONS')=='true' and os.environ.get('GITHUB_REPOSITORY')=='dyKiU/mdk'
        and os.environ.get('GITHUB_EVENT_NAME')=='workflow_dispatch' and os.environ.get('GITHUB_SHA')==head
        and os.environ.get('GITHUB_REF')==REF and os.environ.get('GITHUB_WORKFLOW_REF')=='dyKiU/mdk/'+WORKFLOW+'@'+REF
        and os.environ.get('UPSTREAM_POST_OFFER_NATIVE5_BASELINE')==BASE,'exact-owned-post-offer-workflow')
    ensure(os.environ.get('CARGO_INCREMENTAL')=='1' and os.environ.get('CARGO_BUILD_JOBS')=='2'
        and os.environ.get('RUST_MIN_STACK')=='4194304'
        and all(os.environ.get(k)=='0' for k in ['CARGO_PROFILE_DEV_DEBUG','CARGO_PROFILE_TEST_DEBUG'])
        and all(not os.environ.get(k) for k in ['RUSTFLAGS','CARGO_ENCODED_RUSTFLAGS','RUSTC_BOOTSTRAP','CARGO_PROFILE_DEV_OPT_LEVEL','CARGO_PROFILE_TEST_OPT_LEVEL']),'unchanged-build-cohort')
    subprocess.run(['git','merge-base','--is-ancestor',BASE,head],check=True)
    ensure(subprocess.run(['git','diff','--quiet','HEAD']).returncode==0,'initial-whole-HEAD-pristine')
    baseline={}
    for item in subprocess.check_output(['git','ls-tree','-r','-z',BASE]).split(b'\0'):
        if item:
            metadata,name=item.split(b'\t',1);mode,kind,sha=metadata.decode().split()
            ensure(kind=='blob' and mode in {'100644','100755','120000'},'ordinary-baseline-layout')
            baseline[os.fsdecode(name)]=(mode,sha)
    current=frozen.ack.layout();new={SELF,MANIFEST}
    ensure(not new.intersection(baseline) and set(current)==set(baseline)|new,'exact-post-offer-source-inventory')
    for path,row in current.items():
        mode,sha=baseline.get(path,('100644',None))
        ensure(row['git_mode']==mode and row['symlink']==(mode=='120000')
            and (row['symlink'] or row['actual_executable']==(mode=='100755')),'whole-source-modes')
        data=os.fsencode(os.readlink(path)) if row['symlink'] else Path(path).read_bytes()
        if path in DEPS:ensure(digest(data)==DEPS[path],'immutable-existing-dependency:'+path)
        if path==WORKFLOW:
            text=data.decode();ensure(text.count(BEGIN)==text.count(END)==text.count(OPTIONS)==1,'one-new-owned-diagnostic-overlay')
            before,rest=text.split(BEGIN);_,after=rest.split(END)
            data=(before+after).replace(OPTIONS,'options: [',1).encode()
        if sha is not None:ensure(hashlib.sha1(b'blob '+str(len(data)).encode()+b'\0'+data).hexdigest()==sha,'exact-a9-content-no-Rust-exceptions:'+path)
    allowed={str(OUT/'result.json'),str(OUT/'formatting.patch')}
    ensure(set(subprocess.check_output(['git','ls-files','--others','--exclude-standard'],text=True).splitlines())<=allowed,'no-untracked-source-overlay')
    return {'source':head,'baseline':BASE,'manifest_sha256':MANIFEST_SHA,'all_existing_source_modes_exact':True,
        'Rust_exceptions':[],'old_source_guards_called':False,'old_main_called':False,'runtime_evidence_reused':False}


def controls():
    return {name:call() for name,call in [
        ('native5',frozen.parser_controls),('timing',frozen.timing_parser.parser_controls),
        ('notification',frozen.timing_parser.notification_parser_controls),('intake',frozen.timing_parser.intake_parser_controls),
        ('SDK',frozen.timing_parser.sdk_parser_controls),('windows',frozen.timing_parser.window_parser_controls),
        ('rich',frozen.rich.diagnostic_parser_controls),('native5_rich',frozen.native5_rich_parser_controls),
        ('panic_locations',frozen.panic_location_parser_controls)]}


def compile_one(report,save):
    ensure(shutil.disk_usage('.').free>=8*1024**3,'remote-capacity')
    compilation,cases=frozen.compile_cases([frozen.SUFFIX])
    headers=compilation.pop('compiler_headers',[])
    compilation['closed_error_codes']=sorted(set(code for line in headers for code in re.findall(r'^error\[(E[0-9]{4})\]:',line)))
    compilation['closed_source_locations']=[{'path':match[1],'line':int(match[2]),'column':int(match[3])}
        for line in headers if (match:=re.fullmatch(r'\s*--> (crates/[A-Za-z0-9_./-]+\.rs):([0-9]+):([0-9]+)',line))]
    compilation['missing_nextest_header_observed']=any(line=="error: no such command: `nextest`" for line in headers)
    report['compilation']=compilation;save()
    ensure(type(compilation.get('compile_exit_code')) is int and compilation['compile_exit_code']==0
        and type(compilation.get('compiler_error_count')) is int and compilation['compiler_error_count']==0
        and compilation.get('compiled_fingerprints',{}).get('verified') is True and set(cases)=={frozen.SUFFIX},'one-compiled-native5-six-feature-case')
    case=cases[frozen.SUFFIX];ensure(case['name']==frozen.NAME,'exact-native5-name')
    report['feature_identity']=frozen.feature_identity(compilation)
    ensure(set(report['feature_identity']['nodes'])==frozen.NODES,'six-real-dependency-identities')
    for ignored in [False,True]:
        code,raw,_=frozen.bounded.capture([case['binary'],'--exact',frozen.NAME]+(['--ignored'] if ignored else [])+['--list','--format','terse'],60,limit=1024*1024)
        inventory=frozen.counts.parse_inventory(raw,frozen.NAME,ignored)
        report.setdefault('inventory',{})['ignored' if ignored else 'normal']=inventory;save()
        ensure(code==0 and inventory['passed'],'one-required-not-ignored-native5-case')
    return case


def main(args):
    os.umask(0o077);OUT.mkdir(exist_ok=True)
    report={'baseline':BASE,'scope':'one-original-post-offer-native5-passive-diagnostic','qualification_passed':False,
        'native_qualification':False,'promotion_eligible':False,'runtime_execution_attempted':False,
        'actual_counts_complete':False,'actual_passed':None,'actual_failed':None,'actual_ignored':None,
        'actual_executed_nonignored':None,'actual_native5_pass':False,'diagnostic_completed':False,'automatic_retries':0}
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
