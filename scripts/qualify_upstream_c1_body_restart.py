#!/usr/bin/env python3
"""Exact current C1 five-case GREEN and optional positive-receipt omission PFP."""
import argparse, hashlib, json, os, re, shutil, stat, subprocess, time, sys
from pathlib import Path
import qualify_upstream_storage_boundary as bounded
import qualify_upstream_storage_app_handles as counts
import qualify_upstream_automatic_body as held
import qualify_upstream_body_late_ack as late
import upstream_completion_ci as completion
ensure=bounded.ensure
BASE='a098e72bc4071faac524babedb93dd1fb34ac1ca'
WORKFLOW_SHA='f15f1d5e5389aed4ff02d7c392867334e992de88136602971323c0a8ab6ec4d3'
SELF='scripts/qualify_upstream_c1_body_restart.py'
WORKFLOW='.github/workflows/c1-body-restart.yml'
REF='refs/heads/ci/upstream-c1-body-restart-20261018'
PRODUCT='crates/marmot-app/src/client/account_chat_sharing/automatic.rs'
PRODUCT_SHA='0fde8d14ceea74cd2dd998cd4bfd4e516d61f3704e682931fc42f2460b95d117'
OMISSION='                    self.collect_finished_automatic_publication(&mut entry);\n                    if entry.publication.as_ref().is_some_and(|publication| {\n                        publication.body_context.is_some()\n                            && publication.outcome.as_ref().is_some_and(Result::is_ok)\n                    }) && self.harvest_automatic_publication(&mut entry)?\n                    {\n                        self.finish_automatic_body_effects(&mut entry)?;\n                    }\n'
MUTANT_SHA='75a669e0c5935535ae859291cc108decb68fe077ec7d805cba1be7d19e3ef9d7'
RESTART_HELPER='crates/marmot-app/src/client/account_chat_sharing/automatic/tests/pending_restart_acceptance.rs'
COMPOSED_HELPER='crates/marmot-app/src/tests.rs'
MESSAGE='actual restarted peers must deliver genuine ordinary catalog and canonical record within the unchanged recovery deadline'
OUT=Path('c1-body-restart-evidence')
NAMES=[held.NAME,late.PREFIX+late.CASES[0],late.PREFIX+late.CASES[1],
 'native_device_linking::tests::pending_lower_request_recovers_after_higher_restarts_before_consent',
 'native_device_linking::tests::pending_restart_higher_source_delivers_catalog_and_record']
FEATURES='marmot-app/otlp-export,marmot-app/product-analytics-export,marmot-app/test-policy-overrides,marmot-app/experimental-device-sync,cgka-engine/test-policy-overrides,cgka-engine/test-crash-hooks'
def digest(data):return hashlib.sha256(data).hexdigest()
def git(*args):return subprocess.check_output(['git',*args])
def save(report):
    OUT.mkdir(mode=0o700,exist_ok=True);(OUT/'result.json').write_text(json.dumps(report,indent=2)+'\n')
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
        p=Path(path);s=p.lstat();link=stat.S_ISLNK(s.st_mode)
        ensure(link==(mode=='120000') and (link or stat.S_ISREG(s.st_mode)),'physical-kind')
        data=os.fsencode(os.readlink(p)) if link else p.read_bytes()
        rows[path]=(mode,stat.S_IMODE(s.st_mode),digest(data))
    return rows

def source_guard(preflight=False):
    ensure(type(BASE) is str and re.fullmatch('[0-9a-f]{40}',BASE) and type(WORKFLOW_SHA) is str and re.fullmatch('[0-9a-f]{64}',WORKFLOW_SHA),'root-source-pins-required')
    head=git('rev-parse','HEAD').decode().strip()
    ensure(os.environ.get('GITHUB_ACTIONS')=='true' and os.environ.get('GITHUB_REPOSITORY')=='dyKiU/mdk'
        and (os.environ.get('GITHUB_EVENT_NAME')=='workflow_dispatch' or (preflight and os.environ.get('GITHUB_EVENT_NAME')=='push'))
        and os.environ.get('GITHUB_SHA')==head and os.environ.get('GITHUB_REF')==REF
        and os.environ.get('GITHUB_WORKFLOW_REF')=='dyKiU/mdk/'+WORKFLOW+'@'+REF
        and os.environ.get('UPSTREAM_C1_BODY_BASELINE')==BASE,'exact-hosted-ref-source')
    ensure(os.environ.get('CARGO_INCREMENTAL')=='1' and os.environ.get('CARGO_BUILD_JOBS')=='2' and os.environ.get('RUST_MIN_STACK')=='4194304'
        and all(os.environ.get(k)=='0' for k in ['CARGO_PROFILE_DEV_DEBUG','CARGO_PROFILE_TEST_DEBUG'])
        and all(not os.environ.get(k) for k in ['RUSTFLAGS','CARGO_ENCODED_RUSTFLAGS','RUSTC_BOOTSTRAP','CARGO_PROFILE_DEV_OPT_LEVEL','CARGO_PROFILE_TEST_OPT_LEVEL']),'exact-build-cohort')
    ensure(subprocess.run(['git','merge-base','--is-ancestor',BASE,head]).returncode==0,'BASE-ancestor')
    baseline=layout(BASE);current=layout('HEAD')
    ensure(SELF not in baseline and WORKFLOW not in baseline and set(current)==set(baseline)|{SELF,WORKFLOW},'only-two-owned-metadata')
    ensure(subprocess.run(['git','diff','--quiet','HEAD']).returncode==0,'HEAD-pristine')
    for path,(mode,oid) in current.items():
        p=Path(path);s=p.lstat();link=stat.S_ISLNK(s.st_mode);expected=baseline.get(path,('100644',None))
        ensure(mode==expected[0] and link==(mode=='120000') and (link or stat.S_ISREG(s.st_mode))
            and (link or bool(s.st_mode&0o111)==(mode=='100755')),'whole-source-modes')
        data=os.fsencode(os.readlink(p)) if link else p.read_bytes()
        actual=hashlib.sha1(b'blob '+str(len(data)).encode()+b'\0'+data).hexdigest()
        ensure(actual==oid and (expected[1] is None or actual==expected[1]),'whole-BASE-and-HEAD-content')
    ensure(digest(Path(WORKFLOW).read_bytes())==WORKFLOW_SHA and digest(Path(PRODUCT).read_bytes())==PRODUCT_SHA
        and Path(PRODUCT).read_bytes().count(OMISSION.encode())==1,'exact-workflow-and-product-witness')
    ensure(set(git('ls-files','--others','--exclude-standard').decode().splitlines())<={str(OUT/'result.json')},'untracked-closure')
    return {'head':head,'baseline':BASE,'whole_source_modes_verified':True,'Rust_exceptions':[],
        'old_guards_or_main_called':False,'old_module_globals_mutated':False,'historical_runtime_reused':False}

def clean(raw):return re.sub(r'\x1b\[[0-9;]*m','',raw)
def exact_record(text,prefix,pattern):
    lines=[line for line in text.splitlines() if prefix in line]
    ensure(len(lines)==1 and len(lines[0])<=4096,'one-closed-'+prefix)
    # Libtest may prefix its in-progress exact case on the first stderr line.
    line=re.sub(r'^test [A-Za-z0-9_:]+ \.\.\. ','',lines[0])
    match=re.fullmatch(pattern,line);ensure(match is not None,'closed-'+prefix);return match

def restart_sites(helper,composed):
    lines=helper.splitlines();hits=[i for i,line in enumerate(lines) if MESSAGE in line]
    ensure(len(hits)==1,'unique-unchanged-recovery-expect')
    i=hits[0];j=max(k for k in range(i+1) if '.expect(' in lines[k])
    ensure('delivery.expect(' in lines[j] and 'Duration::from_secs(30)' in helper,'original-delivery-expect-and-deadline')
    a={'file':RESTART_HELPER,'line':j+1,'column':lines[j].index('expect(')+1}
    rows=composed.splitlines();hits=[i for i,line in enumerate(rows) if 'test_thread.join().unwrap();' in line]
    ensure(len(hits)==1 and 'const COMPOSED_APP_RUNTIME_STACK_BYTES: usize = 8 * 1024 * 1024;' in composed,'exact-composed-driver')
    i=hits[0];b={'file':COMPOSED_HELPER,'line':i+1,'column':rows[i].index('unwrap()')+1}
    return a,b

def restart(raw,name,basic,code,expected,helper,composed):
    text=clean(raw);higher=name==NAMES[4]
    role=exact_record(text,'pending_restart_required_higher_source=',r'pending_restart_required_higher_source=(true|false) source_is_lower=(true|false)')
    first=exact_record(text,'pending_restart_first_higher_positive_close=',r'pending_restart_first_higher_positive_close=(true|false)')
    auth=exact_record(text,'pending_restart_authenticated_y_retained_exact_live_x=',r'pending_restart_authenticated_y_retained_exact_live_x=(true|false)')
    closes=exact_record(text,'pending_restart_final_positive_closes=',r'pending_restart_final_positive_closes=(true|false)')
    outer=exact_record(text,'delayed_request_cleanup_d_closed=',r'delayed_request_cleanup_d_closed=(true|false) abc_closed=(true|false)')
    n=r'(?:0|[1-9][0-9]{0,38})';pair=r'\['+n+', '+n+r'\]'
    obs=exact_record(text,'pending_restart_delivery_observation ',r'pending_restart_delivery_observation recovered=(true|false) source_is_lower=(true|false) elapsed_millis=('+n+') completed_syncs='+pair+' sync_millis='+pair+' completed_ticks='+pair+' tick_millis='+pair+r' waiting_at=\([01], "(?:sync|automatic_tick|projection|inter_turn_sleep|before_delivery)"\) waiting_millis='+n)
    prereq=(role[1]==str(higher).lower() and (not higher or role[2]=='false') and obs[2]==role[2]
        and first[1]==auth[1]==closes[1]==outer[1]==outer[2]=='true')
    complete=(basic.get('actual_counts_complete') is True and basic.get('executed_nonignored')==1 and basic.get('ignored')==0 and basic.get('compiler_error_count')==0)
    headers=re.findall(r"thread '([^'\n]+)'(?: \([1-9][0-9]*\))? panicked at ([A-Za-z0-9_./-]+):([0-9]+):([0-9]+):\n([^\n]*)",text)
    all_headers=len(re.findall(r'(?m)^thread .* panicked at ',text))
    a,b=restart_sites(helper,composed)
    valid_panics=(all_headers==len(headers)==2 and headers[0]==('pending-restart-higher-source',a['file'],str(a['line']),str(a['column']),MESSAGE+': Elapsed(())')
        and headers[1]==(name,b['file'],str(b['line']),str(b['column']),'called `Result::unwrap()` on an `Err` value: Any { .. }'))
    progress=r'(?:None|Some\(\((?:true|false), '+n+r', (?:true|false), (?:true|false), (?:true|false), (?:true|false)\)\))'
    timeout_lines=[line for line in text.splitlines() if 'pending_restart_post_timeout_catalog_record=' in line]
    timeout_ok=(len(timeout_lines)==1 and re.fullmatch(r'pending_restart_post_timeout_catalog_record=Some\(\(Some\(true\), Some\(false\)\)\) lower_pending_bodies_catalog_records_sent_renew=\['+progress+', '+progress+r'\]',timeout_lines[0]) is not None)
    functional=text.count('pending_restart_functional_catalog_and_new_record_delivered=true')==1
    source_success=re.findall(r'(?m)^pending_restart_source_scoped_catalog_and_exact_record=true local_ordinary_present=(true|false)$',text)
    green=complete and basic.get('passed_gate') is True and prereq and obs[1]=='true' and functional and len(source_success)==1 and not timeout_lines and all_headers==0
    red=(higher and complete and type(code) is int and code==101 and basic.get('passed')==0 and basic.get('failed')==1 and basic.get('panic_count')==2
        and prereq and obs[1]=='false' and int(obs[3])>=30000 and timeout_ok and valid_panics and not functional and not source_success)
    return {'closed_prerequisites':prereq,'required_higher_source':higher,'source_is_lower':role[2]=='true','recovered':obs[1]=='true',
        'observation_elapsed_millis':int(obs[3]),'inner_positive_closes':closes[1]=='true','outer_D_ABC_positive_closes':outer[1]==outer[2]=='true',
        'catalog_present_Record_absent_after_timeout':timeout_ok,'exact_helper_and_composed_join_panics':valid_panics,'expected_panic_sites':[a,b],
        'focused_GREEN':green,'genuine_behavioral_RED':red,'expected_outcome_verified':red if expected=='red' else green}

def verdict(raw,code,basic,name,expected):
    if name in NAMES[3:]:return restart(raw,name,basic,code,expected,Path(RESTART_HELPER).read_text(),Path(COMPOSED_HELPER).read_text())
    ensure(expected=='green','mutant-only-higher-restart')
    if name==NAMES[0]:
        parsed=held.parse(raw);parsed['body_exit_code']=code;ok=held.body_green(parsed)
        result={k:parsed.get(k) for k in ['responsive_while_held','all_prerequisites_and_two_positive_closes','all_panic_header_count']}
    else:
        case=name.rsplit('::',1)[1];parsed=late.parse(raw,case,code);ok=late.green(parsed,case)
        result={k:parsed.get(k) for k in ['observed','cleanup_diagnostics','all_panic_header_count']}
    return dict(result,expected_outcome_verified=bool(ok and basic.get('passed_gate') is True))

def compile_app(report,cohort,tracked,save_report):
    features=['otlp-export','product-analytics-export','test-policy-overrides','experimental-device-sync']
    command=['cargo','test','--locked','-p','marmot-app','--lib','--no-run','--message-format=json']
    if features:command+=['--features',FEATURES]
    code,raw,seconds=bounded.capture(command,1800,limit=8*1024*1024)
    events=[]
    for line in raw.splitlines():
        if line.startswith('{'):
            try:events.append(json.loads(line))
            except ValueError:continue
    errors=[v for v in events if v.get('reason')=='compiler-message' and v.get('message',{}).get('level')=='error']
    artifacts=[v for v in events if v.get('reason')=='compiler-artifact']
    selected=[v for v in artifacts if v.get('target',{}).get('name')=='marmot_app' and v['target'].get('kind')==['lib'] and v.get('profile',{}).get('test') is True and v.get('executable')]
    codes=sorted({v.get('message',{}).get('code',{}).get('code') for v in errors if type(v.get('message',{}).get('code')) is dict and re.fullmatch(r'E[0-9]{4}',v['message']['code'].get('code',''))})
    sites=[{'file':s['file_name'],'line':s['line_start'],'column':s['column_start']} for v in errors for s in v.get('message',{}).get('spans',[]) if s.get('file_name') in tracked and s.get('is_primary') is True]
    report['compilation']={'command':command,'exit_code':code,'seconds':seconds,'compiler_error_count':len(errors),'compiler_codes':codes[:32],
        'compiler_sites':sites[:32],'closed_diagnostics_truncated':len(codes)>32 or len(sites)>32,'selected_test_artifact_count':len(selected),'features_requested':features};save_report()
    ensure(type(code) is int and code==0 and not errors and len(selected)==1,'one-successful-App-lib-compilation')
    artifact=selected[0];observed=artifact.get('features')
    ensure(type(observed) is list and all(type(v) is str for v in observed) and len(observed)==len(set(observed)) and set(observed)-{'default'}==set(features),'actual-App-unit-feature-cohort')
    binary=Path(artifact['executable']);ensure(binary.is_file() and not binary.is_symlink() and re.fullmatch(r'marmot_app-[0-9a-f]{16}',binary.name) and binary.resolve().is_relative_to(Path(os.environ.get('CARGO_TARGET_DIR','target')).resolve()),'regular-App-test-binary')
    report['compiled_features']={'observed_own_unit_features':sorted(observed),'actual_test_profile':True,'all_Cargo_artifact_feature_manifest_sha256':digest(json.dumps([{'target':v['target']['name'],'features':v['features'],'profile':v['profile']} for v in artifacts],sort_keys=True).encode()),'full_dependency_feature_parity_claimed':False};save_report()
    graph=completion.feature_metadata(binary)
    report['dependency_fingerprints']=graph;save_report()
    ensure(graph.get('verified') is True and {'marmot_app','cgka_engine','storage_sqlite','cgka_session','marmot_account','transport_nostr'}<=set(graph.get('nodes',{}))
        and 'test-crash-hooks' in graph['nodes']['cgka_engine']['features'],'actual-six-node-feature-graph')
    return binary

def aggregate(cases,expected_count):
    result={'actual_case_rows':len(cases),'expected_case_rows':expected_count,'unknown_count_cases':sum(any(type(row.get('basic_counts',{}).get(k)) is not int for k in ['passed','failed','ignored','executed_nonignored']) for row in cases),'nonqualifying_count_shape_cases':sum(row.get('basic_counts',{}).get('actual_counts_complete') is not True for row in cases),'missing_case_rows':max(0,expected_count-len(cases))}
    for key in ['passed','failed','ignored','executed_nonignored']:
        values=[row.get('basic_counts',{}).get(key) for row in cases]
        known=[v for v in values if type(v) is int and v>=0]
        result['actual_'+key]=sum(values) if len(cases)==expected_count and len(known)==len(values) else None
        result['known_partial_'+key]=sum(known) if known else None
    return result

def execute_case(root,row,binary,before,mode,expected_inputs,name,expected):
    row.update(name=name,expected=expected,runtime_attempted=False,actual_executed_nonignored=0,expected_outcome_verified=False)
    save(root)
    for ignored in [False,True]:
        code,text,_=bounded.capture([str(binary),'--exact',name]+(['--ignored'] if ignored else [])+['--list','--format','terse'],60,limit=1024*1024)
        item=counts.parse_inventory(text,name,ignored);row.setdefault('inventory',{})['ignored' if ignored else 'normal']=item;save(root)
        ensure(code==0 and item['passed'],'one-normal-zero-ignored-exact-case')
    ensure(physical()==expected_inputs and digest(binary.read_bytes())==before and stat.S_IMODE(binary.stat().st_mode)==mode,'prebody-source-binary-mode')
    row.update(runtime_attempted=True,actual_executed_nonignored=None);save(root)
    try:code,raw,seconds=bounded.capture([str(binary),'--exact',name,'--nocapture','--test-threads=1'],300,limit=8*1024*1024)
    except bounded.GateFailure as error:
        row['watchdog_triggered']=str(error)=='bounded-command-timeout';row['output_limit_triggered']=str(error)=='bounded-command-output-limit';save(root);raise
    row.update(body_exit_code=code,body_seconds=seconds,source_after_body_pristine=physical()==expected_inputs,
        binary_after_sha256=digest(binary.read_bytes()) if binary.is_file() and not binary.is_symlink() else None,
        binary_after_mode=stat.S_IMODE(binary.stat().st_mode) if binary.is_file() and not binary.is_symlink() else None);save(root)
    basic=counts.parse_body(raw,code,name);row['basic_counts']=basic
    for dest,key in [('actual_passed','passed'),('actual_failed','failed'),('actual_ignored','ignored'),('actual_executed_nonignored','executed_nonignored')]:row[dest]=basic.get(key)
    row['actual_test_passed']=basic.get('passed_gate') is True;save(root)
    ensure(row['source_after_body_pristine'] and row['binary_after_sha256']==before and row['binary_after_mode']==mode,'postbody-source-binary-mode')
    row['outcome']=verdict(raw,code,basic,name,expected)
    row['expected_outcome_verified']=row['outcome']['expected_outcome_verified'];save(root)

def phase(root,label,cohort,expected_inputs,specs,different_from=None):
    row={'cases':[],'phase_passed':False,'expected_case_count':len(specs)};root.setdefault('phases',{})[label]=row;save(root)
    ensure(physical()==expected_inputs,'phase-before-compile-pristine')
    binary=compile_app(row,cohort,set(expected_inputs),lambda:save(root))
    before=digest(binary.read_bytes());mode=stat.S_IMODE(binary.stat().st_mode);row['binary_before']={'sha256':before,'mode':mode};save(root)
    ensure(physical()==expected_inputs,'phase-after-compile-pristine')
    if different_from is not None:ensure(before!=different_from,'mutant-binary-must-differ-before-runtime')
    for name,expected in specs:
        case={};row['cases'].append(case);save(root)
        try:execute_case(root,case,binary,before,mode,expected_inputs,name,expected)
        except Exception as error:case['controller_failure_type']=type(error).__name__;save(root)
    row.update(aggregate(row['cases'],len(specs)))
    row['source_after_phase_pristine']=physical()==expected_inputs
    row['binary_after_phase_pristine']=binary.is_file() and not binary.is_symlink() and digest(binary.read_bytes())==before and stat.S_IMODE(binary.stat().st_mode)==mode
    row['phase_passed']=row['source_after_phase_pristine'] and row['binary_after_phase_pristine'] and len(row['cases'])==len(specs) and all(case.get('expected_outcome_verified') is True for case in row['cases'])
    save(root);return binary,before,mode

def write_fresh(path,data,mode):
    previous=path.stat().st_mtime_ns if path.exists() else 0
    path.write_bytes(data);path.chmod(mode)
    timestamp=max(time.time_ns(),previous+2_000_000_000);os.utime(path,ns=(timestamp,timestamp))

def restore_owned(path,data,mode):
    if path.is_symlink():path.unlink()
    ensure(not path.exists() or path.is_file(),'owned-restore-file-kind')
    write_fresh(path,data,mode)

def runtime(report,cohort,expected):
    frozen=physical();product=Path(PRODUCT);original=product.read_bytes();product_mode=stat.S_IMODE(product.stat().st_mode)
    baseline_binary=None;baseline_bytes=None;baseline_mode=None;baseline_hash=None;mutation_attempted=False
    report.update(runtime_attempted=False,mutation_attempted=False,component_PFP_verified=False,fallback_source_restore_used=False,fallback_binary_copy_used=False)
    try:
        free=shutil.disk_usage('.').free;report['free_bytes']=free;save(report);ensure(free>=8*1024**3,'remote-disk-reserve')
        specs=[(name,'green') for name in NAMES]
        baseline_binary,baseline_hash,baseline_mode=phase(report,'baseline',cohort,frozen,specs)
        baseline_bytes=baseline_binary.read_bytes();report['runtime_attempted']=any(row.get('runtime_attempted') for row in report['phases']['baseline']['cases'])
        if expected=='green':
            report['expected_outcome_verified']=report['phases']['baseline']['phase_passed'];save(report)
            ensure(report['expected_outcome_verified'],'required-baseline-outcome-not-established');return
        # Admission is before mutation/finally: an unqualified baseline is not retried as restoration.
        if report['phases']['baseline']['phase_passed'] is not True:
            report['skipped_mutant_and_restored_reason']='baseline_unqualified_no_mutation_attempted';save(report)
            raise ValueError('PFP-baseline-must-qualify-before-mutation')
        ensure(digest(original)==PRODUCT_SHA and original.count(OMISSION.encode())==1,'exact-fixed-product-before-mutation')
        mutant=original.replace(OMISSION.encode(),b'',1)
        ensure(digest(mutant)==MUTANT_SHA,'exact-reviewed-positive-receipt-only-omission')
        expected_mutant=dict(frozen);expected_mutant[PRODUCT]=(frozen[PRODUCT][0],product_mode,digest(mutant))
        try:
            mutation_attempted=True;report['mutation_attempted']=True;save(report)
            write_fresh(product,mutant,product_mode)
            ensure(physical()==expected_mutant,'only-owned-receipt-omission-source-and-mode')
            phase(report,'mutant',cohort,expected_mutant,[(NAMES[4],'red')],different_from=baseline_hash)
        except Exception as error:report['mutant_controller_failure_type']=type(error).__name__;save(report)
        finally:
            restore_owned(product,original,product_mode)
            report['source_restored_before_fresh_compile']=physical()==frozen;save(report)
            ensure(report['source_restored_before_fresh_compile'],'exact-source-restore-before-compile')
            try:phase(report,'restored',cohort,frozen,[(name,'green') for name in NAMES])
            except Exception as error:report['restored_controller_failure_type']=type(error).__name__;save(report)
        rows=[case for label in ['baseline','mutant','restored'] for case in report.get('phases',{}).get(label,{}).get('cases',[])]
        report['aggregate']=aggregate(rows,11)
        restored=report.get('phases',{}).get('restored',{});mutant_row=report.get('phases',{}).get('mutant',{})
        report['baseline_restored_binary_equal']=restored.get('binary_before')==report['phases']['baseline']['binary_before']
        signatures=[{name:node['features'] for name,node in report['phases'].get(label,{}).get('dependency_fingerprints',{}).get('nodes',{}).items()} for label in ['baseline','mutant','restored']]
        report['same_observed_dependency_feature_cohort']=bool(signatures[0] and signatures[0]==signatures[1]==signatures[2])
        report['component_PFP_verified']=(all(report.get('phases',{}).get(label,{}).get('phase_passed') is True for label in ['baseline','mutant','restored'])
            and report['aggregate'].get('actual_passed')==10 and report['aggregate'].get('actual_failed')==1 and report['aggregate'].get('actual_ignored')==0
            and report['aggregate'].get('actual_executed_nonignored')==11 and report['baseline_restored_binary_equal'] and report['same_observed_dependency_feature_cohort']
            and mutant_row.get('binary_before',{}).get('sha256')!=baseline_hash)
        report['expected_outcome_verified']=report['component_PFP_verified'];save(report);ensure(report['component_PFP_verified'],'fresh-eleven-body-PFP-required')
    finally:
        if product.is_symlink() or not product.is_file() or product.read_bytes()!=original or stat.S_IMODE(product.stat().st_mode)!=product_mode:
            report['fallback_source_restore_used']=True;report['component_PFP_verified']=False;report['expected_outcome_verified']=False
            restore_owned(product,original,product_mode)
        report['source_final_pristine']=physical()==frozen
        if baseline_binary is not None and baseline_bytes is not None:
            good=baseline_binary.is_file() and not baseline_binary.is_symlink() and digest(baseline_binary.read_bytes())==baseline_hash and stat.S_IMODE(baseline_binary.stat().st_mode)==baseline_mode
            if not good:
                report['fallback_binary_copy_used']=True;report['component_PFP_verified']=False;report['expected_outcome_verified']=False
                restore_owned(baseline_binary,baseline_bytes,baseline_mode)
            report['baseline_binary_final_pristine']=baseline_binary.is_file() and not baseline_binary.is_symlink() and digest(baseline_binary.read_bytes())==baseline_hash and stat.S_IMODE(baseline_binary.stat().st_mode)==baseline_mode
        if not report['source_final_pristine'] or report.get('baseline_binary_final_pristine') is False:
            report['component_PFP_verified']=False;report['expected_outcome_verified']=False
        allcases=[case for row in report.get('phases',{}).values() for case in row.get('cases',[])]
        report['runtime_attempted']=any(case.get('runtime_attempted') for case in allcases)
        report['actual_body_counts']=aggregate(allcases,11 if expected=='pfp' and mutation_attempted else 5)
        for key in ['passed','failed','ignored','executed_nonignored']:report['actual_'+key]=report['actual_body_counts']['actual_'+key]
        if not report['runtime_attempted']:report['actual_executed_nonignored']=0
        report['qualification_passed']=False;save(report)
        ensure(report['source_final_pristine'] and report.get('baseline_binary_final_pristine',True),'final-source-binary-mode')
        if sys.exc_info()[0] is None:
            ensure(report.get('expected_outcome_verified') is True and not report['fallback_source_restore_used'] and not report['fallback_binary_copy_used'],'final-outcome-without-fallback-required')
            if expected=='pfp':ensure(report['component_PFP_verified'],'final-PFP-must-remain-qualified')

def controls():
    helper=Path(RESTART_HELPER).read_text();composed=Path(COMPOSED_HELPER).read_text();a,b=restart_sites(helper,composed)
    marker='pending_restart_required_higher_source=true source_is_lower=false\npending_restart_first_higher_positive_close=true\npending_restart_authenticated_y_retained_exact_live_x=true\npending_restart_delivery_observation recovered=false source_is_lower=false elapsed_millis=30001 completed_syncs=[1, 2] sync_millis=[1, 2] completed_ticks=[1, 2] tick_millis=[1, 2] waiting_at=(1, "sync") waiting_millis=1\npending_restart_post_timeout_catalog_record=Some((Some(true), Some(false))) lower_pending_bodies_catalog_records_sent_renew=[None, Some((false, 1, false, true, true, false))]\npending_restart_final_positive_closes=true\ndelayed_request_cleanup_d_closed=true abc_closed=true\n'
    panic=lambda thread,site,message:"thread '"+thread+"' panicked at "+site['file']+':'+str(site['line'])+':'+str(site['column'])+':\n'+message+'\n'
    raw='running 1 test\ntest '+NAMES[4]+' ... '+marker+panic('pending-restart-higher-source',a,MESSAGE+': Elapsed(())')+panic(NAMES[4],b,'called `Result::unwrap()` on an `Err` value: Any { .. }')+'FAILED\ntest result: FAILED. 0 passed; 1 failed; 0 ignored; 0 measured; 0 filtered out; finished in 31s\n'
    check=lambda data:restart(data,NAMES[4],counts.parse_body(data,101,NAMES[4]),101,'red',helper,composed)['expected_outcome_verified']
    ensure(check(raw),'source-shaped-two-panic-RED-positive')
    for data in [raw.replace('elapsed_millis=30001','elapsed_millis=29999'),raw.replace('Some(false))) lower_pending','Some(true))) lower_pending'),raw.replace('final_positive_closes=true','final_positive_closes=false'),raw.replace('abc_closed=true','abc_closed=false'),raw.replace('exact_live_x=true','exact_live_x=false'),raw.replace('higher_positive_close=true','higher_positive_close=false'),raw.replace(MESSAGE+': Elapsed(())','unexpected panic'),raw.replace('0 ignored','1 ignored'),raw.replace("thread 'pending-restart-higher-source'","thread 'other'")]:
        ensure(not check(data),'closed-RED-negative')
    green=raw.split("thread '",1)[0].replace('recovered=false','recovered=true')
    green='\n'.join(line for line in green.splitlines() if not line.startswith('pending_restart_post_timeout_catalog_record='))+'\npending_restart_source_scoped_catalog_and_exact_record=true local_ordinary_present=false\npending_restart_functional_catalog_and_new_record_delivered=true\nok\ntest result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 1s\n'
    ensure(restart(green,NAMES[4],counts.parse_body(green,0,NAMES[4]),0,'green',helper,composed)['expected_outcome_verified'],'source-shaped-GREEN-positive')
    lower=green.replace(NAMES[4],NAMES[3]).replace('required_higher_source=true','required_higher_source=false').replace('source_is_lower=false','source_is_lower=true')
    ensure(restart(lower,NAMES[3],counts.parse_body(lower,0,NAMES[3]),0,'green',helper,composed)['expected_outcome_verified'],'lower-source-existing-GREEN-positive')
    malformed=[raw.replace('recovered=false','recovered=unknown'),raw+marker,raw.replace('elapsed_millis=30001','elapsed_millis=-1')]
    for data in malformed:
        try:accepted=check(data)
        except ValueError:accepted=False
        ensure(not accepted,'closed-malformed-or-duplicate-negative')
    for data in [raw.replace(panic(NAMES[4],b,'called `Result::unwrap()` on an `Err` value: Any { .. }'),''),raw+panic('foreign',a,'foreign'),raw.replace('0 passed; 1 failed','0 passed; 0 failed')]:
        ensure(not check(data),'missing-extra-panic-or-zero-body-negative')
    return {'restart_positive':3,'restart_negative':15,'counts':counts.parser_controls(),'held':held.parser_preflight(extraction=True),'late_ACK':late.parser_controls(),'runtime_bodies':0}

def main():
    p=argparse.ArgumentParser();p.add_argument('--preflight',action='store_true');p.add_argument('--expected',choices=['green','pfp'],default='green');args=p.parse_args()
    report={'scope':'C1 positive-receipt ordering and five unchanged existing controls','preflight':args.preflight,'expected':args.expected,'runtime_attempted':False,
        'actual_executed_nonignored':0,'qualification_passed':False,'native_global_qualification':False,'automatic_retries':0,'environment_RUST_MIN_STACK':4194304,
        'restart_composed_driver_and_worker_stack_bytes':8388608,'Tokio_workers':2,'raw_output_retained':False}
    try:
        report['source_guard']=source_guard(args.preflight);save(report);report['parser_controls']=controls();save(report)
        if not args.preflight:runtime(report,'experimental',args.expected)
        report['controller_completed']=True;save(report)
    except Exception as error:report['controller_failure_type']=type(error).__name__;save(report);raise
    finally:report['final_HEAD_git_pristine']=subprocess.run(['git','diff','--quiet','HEAD']).returncode==0;save(report)
if __name__=='__main__':main()
