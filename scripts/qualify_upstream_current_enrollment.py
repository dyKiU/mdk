#!/usr/bin/env python3
"""Current original strict five or original sixteen enrollment cases; no mutation."""
import argparse, hashlib, json, os, re, shutil, stat, subprocess, time, sys
from pathlib import Path
import qualify_upstream_storage_boundary as bounded
import qualify_upstream_storage_app_handles as counts
import upstream_completion_ci as completion
import qualify_upstream_pure_native5 as native
import qualify_upstream_request_retry_ack as ack
ensure=bounded.ensure
BASE='c5a5c10ce0792a41c7feecc81bcd2efab2a8adda'
PURE_PRODUCT_BASE='68c93c7b147fdce1911bb857f1b5b2982477ece9'
PFP_METADATA={'.github/workflows/native-predecessor-readiness-pfp.yml','scripts/qualify_upstream_native_predecessor_readiness.py'}
WORKFLOW_SHA='25c0ea3871f9622ee9e169aec1fd8a93532c130e8e6791aeb571ab0ea11a163b'
SELF='scripts/qualify_upstream_current_enrollment.py'
WORKFLOW='.github/workflows/current-enrollment.yml'
REF='refs/heads/ci/upstream-current-enrollment-20261019'
FEATURES='marmot-app/otlp-export,marmot-uniffi/otlp-export,marmot-c/otlp-export,wn-cli/otlp-export,agent-connector/otlp-export,marmot-app/product-analytics-export,marmot-uniffi/product-analytics-export,marmot-c/product-analytics-export,wn-cli/product-analytics-export,agent-connector/product-analytics-export,wn-cli/test-policy-overrides,cgka-engine/test-policy-overrides,cgka-engine/test-crash-hooks,experimental-device-sync'
EXPECTED_GRAPH={'marmot_app': ['default', 'experimental-device-sync', 'otlp-export', 'product-analytics-export', 'test-policy-overrides'], 'cgka_engine': ['default', 'experimental-device-sync', 'test-conformance-snapshot', 'test-crash-hooks', 'test-policy-overrides'], 'storage_sqlite': ['experimental-device-sync', 'storage-format-benchmarks', 'test-conformance-replay', 'test-migrated-template', 'test-support'], 'cgka_session': ['default', 'experimental-device-sync', 'test-policy-overrides'], 'marmot_account': ['experimental-device-sync'], 'transport_nostr': ['default', 'experimental-device-sync', 'test-policy-overrides', 'test-support']}
OUT=Path(os.environ.get('RUNNER_TEMP','/tmp'))/'current-enrollment-evidence'
FIXTURE='crates/marmot-app/src/native_device_linking/tests/sequential_installations_acceptance.rs'
PARENT='crates/marmot-app/src/native_device_linking/tests/automatic_pairing_acceptance.rs'
FIXTURE_SHA='a81cc692c9864d9cdf2ff7fe8d533d3115c7eb7958fa7a22df783850fea520ca'
PARENT_SHA='674912b2606b11ab735b947fdab2b8f9e28597f07f406ab8cff8b6e7c8733fe9'
STRICT_HELPER_SHA='a059addf027097d91c672ccfe36e613f99cfb93f889ab2087b872a84c7a58ff2'
ORACLE_SHA='88417f89d6d6b3b9a8037d408be60c54d8b86451085cff9d254cb6cc74537e72'
NATIVE_HELPER='scripts/qualify_upstream_pure_native5.py'
ACK_HELPER='scripts/qualify_upstream_request_retry_ack.py'
HELPER_PINS={'scripts/qualify_upstream_pure_native5.py': 'e850003b806b321444ec53bac9e3a5b8d1d22e5e0661b09a0f7456f1c985aa2b', 'scripts/qualify_upstream_request_retry_ack.py': 'd413d577d2a6097b94870a9fb662f4ab3dd047ef8cc218861cba51dc0cbd8008'}
def closed_exception(error):
    name=type(error).__name__
    return name if name in {'GateFailure','ValueError','TypeError','KeyError','OSError','FileNotFoundError','RuntimeError','JSONDecodeError','OverflowError','PermissionError'} else 'OtherControllerFailure'

def digest(data):return hashlib.sha256(data).hexdigest()
def git(*args):return subprocess.check_output(['git',*args])
_OUTPUT_GIT_ROOT=None
def save(report):
    global _OUTPUT_GIT_ROOT
    if _OUTPUT_GIT_ROOT is None:_OUTPUT_GIT_ROOT=Path(git('rev-parse','--show-toplevel').decode().strip()).resolve()
    ensure(not within(OUT,_OUTPUT_GIT_ROOT),'output-must-resolve-outside-checkout')
    OUT.mkdir(mode=0o700,exist_ok=True);(OUT/'result.json').write_text(json.dumps(report,indent=2)+'\n')
def within(path,root):return path.resolve().is_relative_to(root.resolve())
def git_closure():
    quiet=subprocess.run(['git','diff','--quiet','HEAD']).returncode==0
    index=subprocess.run(['git','diff','--cached','--quiet']).returncode==0
    n=len(git('ls-files','--others','--exclude-standard').splitlines())
    return {'HEAD_pristine':quiet,'index_pristine':index,'nonignored_untracked_count':n,'verified':quiet and index and n==0}
def source_matches(expected):
    try:return physical()==expected and git_closure()['verified']
    except (OSError,ValueError):return False
def binary_identity(binary,parent):
    regular=binary is not None and binary.parent.resolve()==parent and binary.is_file() and not binary.is_symlink()
    return {'regular_approved_parent':bool(regular),'sha256':digest(binary.read_bytes()) if regular else None,'mode':stat.S_IMODE(binary.stat().st_mode) if regular else None}
def layout(ref):
    result={}
    for item in git('ls-tree','-r','-z',ref).split(b'\0'):
        if item:
            meta,path=item.split(b'\t',1);mode,kind,sha=meta.decode().split()
            ensure(kind=='blob' and mode in {'100644','100755','120000'},'ordinary-whole-source-layout')
            result[os.fsdecode(path)]=(mode,sha)
    return result

def physical():
    rows={}
    for path,(mode,_) in layout('HEAD').items():
        p=Path(path);ensure(within(p,Path.cwd()),'every-tracked-path-within-checkout');s=p.lstat();link=stat.S_ISLNK(s.st_mode)
        ensure(link==(mode=='120000') and (link or stat.S_ISREG(s.st_mode)),'physical-kind')
        data=os.fsencode(os.readlink(p)) if link else p.read_bytes()
        rows[path]=(mode,stat.S_IMODE(s.st_mode),digest(data))
    return rows

def source_guard(preflight=False):
    ensure(type(BASE) is str and re.fullmatch('[0-9a-f]{40}',BASE) and type(WORKFLOW_SHA) is str and re.fullmatch('[0-9a-f]{64}',WORKFLOW_SHA),'root-source-pins-required')
    ensure(Path.cwd().resolve()==Path(git('rev-parse','--show-toplevel').decode().strip()).resolve(),'physical-Git-root')
    ensure(bool(os.environ.get('RUNNER_TEMP')) and Path(os.environ['RUNNER_TEMP']).is_dir() and not within(OUT,Path.cwd()),'outside-hosted-output')
    head=git('rev-parse','HEAD').decode().strip()
    ensure(os.environ.get('GITHUB_ACTIONS')=='true' and os.environ.get('GITHUB_REPOSITORY')=='dyKiU/mdk'
        and (os.environ.get('GITHUB_EVENT_NAME')=='workflow_dispatch' or (preflight and os.environ.get('GITHUB_EVENT_NAME')=='push'))
        and os.environ.get('GITHUB_SHA')==head and os.environ.get('GITHUB_REF')==REF
        and os.environ.get('GITHUB_WORKFLOW_REF')=='dyKiU/mdk/'+WORKFLOW+'@'+REF
        and os.environ.get('UPSTREAM_CURRENT_ENROLLMENT_BASELINE')==BASE,'exact-hosted-ref-source')
    ensure(os.environ.get('CARGO_INCREMENTAL')=='1' and os.environ.get('CARGO_BUILD_JOBS')=='2' and os.environ.get('RUST_MIN_STACK')=='4194304'
        and all(os.environ.get(k)=='0' for k in ['CARGO_PROFILE_DEV_DEBUG','CARGO_PROFILE_TEST_DEBUG'])
        and all(not os.environ.get(k) for k in ['RUSTFLAGS','CARGO_ENCODED_RUSTFLAGS','RUSTC_BOOTSTRAP','CARGO_PROFILE_DEV_OPT_LEVEL','CARGO_PROFILE_TEST_OPT_LEVEL']),'exact-build-cohort')
    ensure(subprocess.run(['git','merge-base','--is-ancestor',BASE,head]).returncode==0,'BASE-ancestor')
    ensure(set(git('diff','--name-only',PURE_PRODUCT_BASE,BASE).decode().splitlines())==PFP_METADATA,'pure-product-plus-existing-PFP-metadata-only')
    baseline=layout(BASE);current=layout('HEAD')
    ensure(SELF not in baseline and WORKFLOW not in baseline and set(current)==set(baseline)|{SELF,WORKFLOW},'only-two-owned-metadata')
    ensure(subprocess.run(['git','diff','--quiet','HEAD']).returncode==0,'HEAD-pristine')
    for path,(mode,oid) in current.items():
        p=Path(path);ensure(within(p,Path.cwd()),'every-tracked-path-within-checkout');s=p.lstat();link=stat.S_ISLNK(s.st_mode);expected=baseline.get(path,('100644',None))
        ensure(mode==expected[0] and link==(mode=='120000') and (link or stat.S_ISREG(s.st_mode))
            and (link or bool(s.st_mode&0o111)==(mode=='100755')),'whole-source-modes')
        data=os.fsencode(os.readlink(p)) if link else p.read_bytes()
        actual=hashlib.sha1(b'blob '+str(len(data)).encode()+b'\0'+data).hexdigest()
        ensure(actual==oid and (expected[1] is None or actual==expected[1]),'whole-BASE-and-HEAD-content')
    ensure(digest(Path(WORKFLOW).read_bytes())==WORKFLOW_SHA,'exact-owned-workflow')
    ensure(digest(Path(FIXTURE).read_bytes())==FIXTURE_SHA and digest(Path(PARENT).read_bytes())==PARENT_SHA,'immutable-original-five-fixture-parent')
    parent=Path(PARENT).read_text();start=parent.index('async fn wait_for_automatic_phase_with_approvals(');end=parent.index('\n}\n',start)+3
    ensure(digest(parent[start:end].encode())==STRICT_HELPER_SHA,'original-strict15-helper')
    for path,sha in HELPER_PINS.items():ensure(digest(Path(path).read_bytes())==sha,'immutable-oracle-helper-blob')
    text=Path(NATIVE_HELPER).read_text();begin='# NATIVE5_IMMUTABLE_ORACLE_BEGIN\n';endmark='# NATIVE5_IMMUTABLE_ORACLE_END\n'
    ensure(text.count(begin)==text.count(endmark)==1 and digest(text.split(begin,1)[1].split(endmark,1)[0].encode())==ORACLE_SHA,'immutable-five-oracle-region')
    ensure(git_closure()['verified'],'tracked-index-untracked-admission-closure')
    return {'head':head,'baseline':BASE,'whole_source_modes_verified':True,'Rust_exceptions':[],
        'old_guards_or_main_called':False,'old_module_globals_mutated':False,'historical_runtime_reused':False,'pure_product_source':PURE_PRODUCT_BASE,'BASE_additions_are_existing_PFP_metadata_only':True,
        'new_native_HEAD_metadata_difference':[SELF,WORKFLOW],'readiness_PFP_rerun_on_this_HEAD_claimed':False}

def compile_app(report,cohort,tracked,save_report):
    features=['otlp-export','product-analytics-export','test-policy-overrides','experimental-device-sync']
    command=['cargo','test','--locked','--workspace','--no-run','--message-format=json']
    if features:command+=['--features',FEATURES]
    report['compilation']={'command':command,'compile_attempted':True,'exit_code':None,'compiler_error_count':None,
        'build_finished_success':None,'malformed_JSON_lines':None,'selected_test_artifact_count':None,
        'watchdog_triggered':False,'output_limit_triggered':False,'runtime_bodies':0};save_report()
    started=time.monotonic()
    try:code,raw,seconds=bounded.capture(command,3600,limit=8*1024*1024)
    except bounded.GateFailure as error:
        report['compilation'].update(seconds=time.monotonic()-started,controller_failure_type=closed_exception(error),
            watchdog_triggered=str(error)=='bounded-command-timeout',output_limit_triggered=str(error)=='bounded-command-output-limit')
        save_report();raise
    events=[];malformed=0
    for line in raw.splitlines():
        if line.startswith('{'):
            try:events.append(json.loads(line))
            except ValueError:malformed+=1
    finished=[v for v in events if v.get('reason')=='build-finished']
    complete=len(finished)==1 and finished[0].get('success') is True and malformed==0
    errors=[v for v in events if v.get('reason')=='compiler-message' and v.get('message',{}).get('level')=='error']
    artifacts=[v for v in events if v.get('reason')=='compiler-artifact']
    selected=[v for v in artifacts if v.get('target',{}).get('name')=='marmot_app' and v['target'].get('kind')==['lib'] and v.get('profile',{}).get('test') is True and v.get('executable')]
    codes=sorted({v.get('message',{}).get('code',{}).get('code') for v in errors if type(v.get('message',{}).get('code')) is dict and re.fullmatch(r'E[0-9]{4}',v['message']['code'].get('code',''))})
    sites=[{'file':s['file_name'],'line':s['line_start'],'column':s['column_start']} for v in errors for s in v.get('message',{}).get('spans',[]) if s.get('file_name') in tracked and s.get('is_primary') is True]
    report['compilation']={'command':command,'compile_attempted':True,'watchdog_triggered':False,'output_limit_triggered':False,'runtime_bodies':0,'exit_code':code,'seconds':seconds,'compiler_error_count':len(errors) if finished else None,'build_finished_success':complete,'malformed_JSON_lines':malformed,'compiler_codes':codes[:32],
        'compiler_sites':sites[:32],'closed_diagnostics_truncated':len(codes)>32 or len(sites)>32,'selected_test_artifact_count':len(selected),'features_requested':features};save_report()
    ensure(type(code) is int and code==0 and complete and not errors and len(selected)==1,'one-successful-App-lib-compilation')
    artifact=selected[0];observed=artifact.get('features')
    ensure(type(observed) is list and all(type(v) is str for v in observed) and len(observed)==len(set(observed)) and set(observed)==set(features)|{'default'} and artifact.get('fresh') is False,'actual-App-unit-feature-cohort')
    binary=Path(artifact['executable']);ensure(binary.is_file() and not binary.is_symlink() and re.fullmatch(r'marmot_app-[0-9a-f]{16}',binary.name) and binary.resolve().is_relative_to(Path(os.environ.get('CARGO_TARGET_DIR','target')).resolve()),'regular-App-test-binary')
    report['compiled_features']={'observed_own_unit_features':sorted(observed),'actual_test_profile':True,'fresh_App_artifact_required':True,'observed_App_artifact_fresh':artifact.get('fresh'),'all_Cargo_artifact_feature_manifest_sha256':digest(json.dumps(sorted([{'package':v['package_id'],'target':v['target']['name'],'kind':v['target']['kind'],'features':sorted(v['features']),'profile':v['profile']} for v in artifacts],key=lambda v:json.dumps(v,sort_keys=True)),sort_keys=True).encode()),'all_emitted_compiler_artifact_feature_cohort_recorded':True,'all_dependencies_freshly_built_claimed':False};save_report()
    graph=completion.feature_metadata(binary)
    report['dependency_fingerprints']=graph;save_report()
    ensure(graph.get('verified') is True and {k:sorted(v['features']) for k,v in graph.get('nodes',{}).items()}=={k:sorted(v) for k,v in EXPECTED_GRAPH.items()},'actual-exact-reviewed-six-node-feature-graph')
    return binary

def aggregate(cases,expected_count):
    result={'actual_case_rows':len(cases),'expected_case_rows':expected_count,'unknown_count_cases':sum(any(type(row.get('basic_counts',{}).get(k)) is not int for k in ['passed','failed','ignored','executed_nonignored']) for row in cases),'nonqualifying_count_shape_cases':sum(row.get('basic_counts',{}).get('actual_counts_complete') is not True for row in cases),'missing_case_rows':max(0,expected_count-len(cases))}
    for key in ['passed','failed','ignored','executed_nonignored']:
        values=[row.get('basic_counts',{}).get(key) for row in cases]
        known=[v for v in values if type(v) is int and v>=0]
        result['actual_'+key]=sum(values) if len(cases)==expected_count and len(known)==len(values) else None
        result['known_partial_'+key]=sum(known) if known else None
    return result


def selected_cases(mode):
    if mode=='five':return [('five',native.SUFFIX,native.NAME,None)]
    rows=list(ack.CASES)
    ensure(len(rows)==16 and all(type(row) in (list,tuple) and len(row)==4 for row in rows)
        and all(len({row[i] for row in rows})==16 for i in [0,1,2])
        and {'policy','stress_0','stress_1','stress_2','paused_clock'}<={row[0] for row in rows},'original-exact-sixteen-inventory')
    ensure(all(type(label) is str and type(suffix) is str and type(name) is str and name.endswith(suffix) for label,suffix,name,_ in rows),'exact-source-case-names')
    return rows

# Only fixed-field numeric/boolean projections leave memory. Strict original oracles
# still consume the complete ephemeral parser result; no raw compiler/panic text exports.
COUNT_KEYS=['passed','failed','ignored','executed_nonignored','exit_code','compiler_error_count','panic_count','actual_counts_complete','passed_gate','watchdog_triggered','output_limit_triggered']
SCALAR_KEYS=COUNT_KEYS+['body_exit_code','all_panic_header_count','samples','window_elapsed_us','runtime_closes','planes_shutdown','relay_closed','attempt_completed','marker_count','actual_count_unknown']
def closed_counts(row):
    return {key:row[key] for key in COUNT_KEYS if key in row and (row[key] is None or type(row[key]) in (bool,int,float))}
def closed_oracle(row):
    result={key:row[key] for key in SCALAR_KEYS if key in row and (row[key] is None or type(row[key]) in (bool,int,float))}
    for key in ['facts','observations']:
        value=row.get(key)
        if value is None:result[key]=None
        elif type(value) is dict:
            result[key]={field:item for field,item in value.items() if type(field) is str and re.fullmatch('[A-Za-z_][A-Za-z0-9_]{0,79}',field) and (item is None or type(item) in (bool,int))}
    return result

def closed_panic_sites(raw,name,tracked,read_bytes=None):
    # Only immutable tracked Rust paths and source-valid byte coordinates leave
    # memory. A foreign thread name or the panic payload is never exported.
    read_bytes=read_bytes or (lambda path:Path(path).read_bytes())
    raw=re.sub(r'\x1b\[[0-?]*[ -/]*[@-~]','',raw)
    found=[]
    for match in re.finditer(r"(?m)^thread '([^'\n]{0,512})'(?: \([0-9]{1,10}\))? panicked at ([^:\n]{1,512}):([0-9]{1,10}):([0-9]{1,10}):$",raw):
        thread,path,line,column=match.groups();line=int(line);column=int(column)
        if path not in tracked or not path.endswith('.rs') or not (line>0 and column>0):continue
        source=read_bytes(path).splitlines()
        if line>len(source) or column>len(source[line-1])+1:continue
        found.append({'file':path,'line':line,'column':column,'thread_fullname':name if thread==name else None})
    return {'sites':found[:32],'truncated':len(found)>32,'source_valid_location_count':len(found),
        'other_panic_headers_unknown':max(0,raw.count('panicked at ')-len(found)),'panic_payloads_exported':False}

def execute_case(report,row,binary,before,mode,parent,inputs,label,name,five):
    row.update(label=label,name=name,runtime_attempted=False,actual_executed_nonignored=0,oracle_green=False)
    save(report)
    for ignored in [False,True]:
        code,raw,seconds=bounded.capture([str(binary),'--exact',name]+(['--ignored'] if ignored else [])+['--list','--format','terse'],60,limit=1024*1024)
        parsed=counts.parse_inventory(raw,name,ignored)
        row.setdefault('inventory',{})['ignored' if ignored else 'normal']={'exit_code':code,'seconds':seconds,'passed':parsed.get('passed') is True}
        save(report);ensure(code==0 and parsed.get('passed') is True,'one-normal-zero-ignored-exact-case')
    ensure(source_matches(inputs) and binary_identity(binary,parent)=={'regular_approved_parent':True,'sha256':before,'mode':mode},'prebody-source-binary-mode')
    row.update(runtime_attempted=True,actual_executed_nonignored=None);save(report)
    try:code,raw,seconds=bounded.capture([str(binary),'--exact',name,'--nocapture','--test-threads=1'],900 if five else 300,limit=8*1024*1024)
    except bounded.GateFailure as error:
        row['watchdog_triggered']=str(error)=='bounded-command-timeout';row['output_limit_triggered']=str(error)=='bounded-command-output-limit';save(report);raise
    identity=binary_identity(binary,parent)
    row.update(body_exit_code=code,body_seconds=seconds,source_after_body_pristine=source_matches(inputs),
        binary_after_sha256=identity['sha256'],binary_after_mode=identity['mode'],binary_after_regular_parent=identity['regular_approved_parent'])
    save(report)
    basic=counts.parse_body(raw,code,name);row['basic_counts']=closed_counts(basic)
    for dest,key in [('actual_passed','passed'),('actual_failed','failed'),('actual_ignored','ignored'),('actual_executed_nonignored','executed_nonignored')]:row[dest]=basic.get(key)
    row['actual_test_passed']=basic.get('passed_gate') is True;save(report)
    row['panic_locations']=closed_panic_sites(raw,name,set(inputs));save(report)
    ensure(row['source_after_body_pristine'] and row['binary_after_regular_parent'] and row['binary_after_sha256']==before and row['binary_after_mode']==mode,'postbody-source-binary-mode')
    parsed=native.parse(raw,code) if five else ack.parse_case(label,raw,code)
    row['original_oracle']=closed_oracle(parsed)
    row['oracle_green']=row['actual_test_passed'] and (native.green(parsed) if five else ack.case_green(label,parsed)) is True
    save(report)

def parser_controls(mode):
    inherited=native.parser_controls() if mode=='five' else ack.parser_controls()
    names=selected_cases(mode)
    ensure(len(names)==(1 if mode=='five' else 16),'exact-selected-case-count')
    ensure(closed_oracle({'facts':{'closed':True},'compiler_headers':['PRIVATE'],'message':'PRIVATE'})=={'facts':{'closed':True},'observations':None},'closed-projection-no-private-strings')
    ensure(not within(Path.cwd().parent,Path.cwd()) and within(Path.cwd()/'ordinary',Path.cwd()),'containment-direction-controls')
    complete={'basic_counts':{'passed':1,'failed':0,'ignored':0,'executed_nonignored':1,'actual_counts_complete':True}}
    observed_ignored={'basic_counts':{'passed':0,'failed':0,'ignored':1,'executed_nonignored':0,'actual_counts_complete':False}}
    ensure(aggregate([complete,observed_ignored],2)['actual_ignored']==1,'known-failed-shape-counts-retained')
    ensure(aggregate([complete,{}],2)['actual_passed'] is None and aggregate([complete,{}],2)['known_partial_passed']==1,'unknown-counts-not-zero')
    ensure(aggregate([complete],2)['actual_passed'] is None,'missing-case-not-complete')
    ensure(aggregate([{'basic_counts':{'passed':True}}],1)['actual_passed'] is None,'bool-not-actual-count')
    path='crates/closed.rs';name='source::known_case'
    header="thread '"+name+"' panicked at "+path+":2:3:\nPRIVATE payload\n"
    read=lambda _:b'first\n    assert!(false);\n'
    valid=closed_panic_sites(header,name,{path},read)
    ensure(valid['sites']==[{'file':path,'line':2,'column':3,'thread_fullname':name}] and 'PRIVATE' not in json.dumps(valid),'closed-source-site-positive')
    pid=closed_panic_sites(header.replace("' panicked","' (123) panicked"),name,{path},read)
    ensure(pid['sites']==valid['sites'],'numeric-Rust-thread-PID-discarded')
    foreign=closed_panic_sites(header.replace(name,'PRIVATE-thread'),name,{path},read)
    ensure(foreign['sites'][0]['thread_fullname'] is None and 'PRIVATE' not in json.dumps(foreign),'foreign-thread-not-exported')
    for text in [header.replace(path,'private/foreign.rs'),header.replace(':2:3:',':0:3:'),header.replace(':2:3:',':3:3:'),header.replace(':2:3:',':2:999:'),header.replace('panicked at ','panicked elsewhere '),header.replace(':2:3:',':2:3: suffix'),header.replace("' panicked","' (PRIVATE) panicked"),header.replace("' panicked","' (123 panicked")]:
        ensure(not closed_panic_sites(text,name,{path},read)['sites'],'unknown-or-out-of-source-site-not-exported')
    many=closed_panic_sites(header*33,name,{path},read)
    ensure(len(many['sites'])==32 and many['truncated'] is True,'bounded-source-sites')
    return {'original_oracle_controls':inherited,'wrapper_controls':5,'panic_site_positive':4,'panic_site_negative':8,'actual_runtime_bodies':0}

def main(args):
    os.umask(0o077)
    report={'expected_case_mode':args.mode,'preflight_only':args.preflight,'actual_test_qualification':False,'global_qualification':False,
        'old_guards_or_main_called':False,'old_module_globals_mutated':False,'automatic_retries':0,'raw_runtime_output_exported':False,
        'requested_features':FEATURES,'environment_stack_bytes':4194304,'Tokio_workers':2 if args.mode=='five' else None,
        'runtime_flavor': 'original-five-two-worker' if args.mode=='five' else 'original-source-defined-mixed-sixteen',
        'actual_runtime_attempts':0,'actual_executed_nonignored':0,'strict_five_join_deadline_seconds':15 if args.mode=='five' else None,'body_watchdog_seconds':900 if args.mode=='five' else 300,'output_limit_bytes':8*1024*1024,'cases':[]}
    save(report);inputs=None;binary=None;before=None;mode=None;parent=None
    try:
        report['controller_stage']='source_guard';save(report)
        report['source']=source_guard(args.preflight);inputs=physical();save(report)
        report['controller_stage']='parser_controls';save(report)
        report['parser_controls']=parser_controls(args.mode);save(report)
        if args.preflight:
            report['actual_executed_nonignored']=0;report['preflight_passed']=True;save(report);return
        report['controller_stage']='compile_admission';save(report)
        report['free_bytes_before_compile']=shutil.disk_usage('.').free
        report['capacity_reserve_satisfied']=report['free_bytes_before_compile']>=8*1024**3
        if not report['capacity_reserve_satisfied']:report['compile_admission_failure']='insufficient_disk_reserve'
        save(report);ensure(report['capacity_reserve_satisfied'],'eight-GiB-free-before-compilation')
        selected=selected_cases(args.mode)
        report['fresh_App_source_mtimes']=[]
        for refresh in [Path(FIXTURE),Path(PARENT)]:
            ensure(source_matches(inputs) and refresh.is_file() and not refresh.is_symlink() and refresh.parent.resolve()==Path.cwd().resolve()/refresh.parent,'fresh-App-source-identity')
            old=refresh.stat().st_mtime_ns;stamp=max(time.time_ns(),old+2_000_000_000);os.utime(refresh,ns=(stamp,stamp))
            after=refresh.stat().st_mtime_ns
            report['fresh_App_source_mtimes'].append({'path':str(refresh),'before_ns':old,'requested_ns':stamp,'actual_after_ns':after});save(report)
            ensure(after>old,'actual-source-mtime-advanced')
        report['controller_stage']='compilation';save(report)
        binary=compile_app(report,'experimental',set(inputs),lambda:save(report))
        parent=binary.parent.resolve();identity=binary_identity(binary,parent)
        ensure(identity['regular_approved_parent'],'admitted-regular-binary')
        before=identity['sha256'];mode=identity['mode']
        report['binary_before']={'sha256':before,'mode':mode,'kind':'regular-test-executable'};save(report)
        ensure(source_matches(inputs),'after-compile-whole-source-pristine')
        report['controller_stage']='original_bodies';save(report)
        for label,suffix,name,_ in selected:
            row={};report['cases'].append(row);save(report)
            try:execute_case(report,row,binary,before,mode,parent,inputs,label,name,args.mode=='five')
            except Exception as error:row['controller_failure_type']=closed_exception(error);save(report)
        report['controller_stage']='aggregate_original_oracles'
        report.update(aggregate(report['cases'],len(selected)));save(report)
        report['all_original_cases_green']=len(report['cases'])==len(selected) and all(row.get('oracle_green') is True for row in report['cases'])
        report['git_closure_before_qualification']=git_closure()
        report['actual_test_qualification']=report['all_original_cases_green'] and source_matches(inputs) and report['git_closure_before_qualification']['verified']
        save(report);ensure(report['actual_test_qualification'],'original-current-enrollment-cases-not-all-GREEN')
    except Exception as error:
        report['controller_failure_type']=closed_exception(error);save(report);raise
    finally:
        report['actual_runtime_attempts']=sum(row.get('runtime_attempted') is True for row in report['cases'])
        if not args.preflight:
            report.update(aggregate(report['cases'],1 if args.mode=='five' else 16))
            if report['actual_runtime_attempts']==0:report['actual_executed_nonignored']=0
        report['final_git_closure']=git_closure()
        report['final_source_pristine']=inputs is not None and source_matches(inputs)
        identity=binary_identity(binary,parent)
        report['final_binary_sha256']=identity['sha256'];report['final_binary_mode']=identity['mode']
        report['final_binary_pristine']=None if binary is None else identity=={'regular_approved_parent':True,'sha256':before,'mode':mode}
        if not report['final_source_pristine'] or not report['final_git_closure']['verified'] or report['final_binary_pristine'] is False:report['actual_test_qualification']=False
        save(report)
        ensure(report['final_source_pristine'] and report['final_git_closure']['verified'] and report['final_binary_pristine'] is not False,'final-source-binary-mode-closure')
    ensure(report['actual_test_qualification'],'actual-current-native-qualification-required')

if __name__=='__main__':
    parser=argparse.ArgumentParser();parser.add_argument('--preflight',action='store_true');parser.add_argument('--mode',choices=['five','sixteen'],default='five')
    main(parser.parse_args())
