#!/usr/bin/env python3
"""One current genuine SQL-negative Body control; exact force-renew PFP only."""
import argparse, hashlib, json, os, re, shutil, stat, subprocess, time, sys
from pathlib import Path
import qualify_upstream_storage_boundary as bounded
import qualify_upstream_storage_app_handles as counts
import upstream_completion_ci as completion
ensure=bounded.ensure
BASE='288544fe2d9dc3323cb1df3b99f35cc017375e13'
WORKFLOW_SHA='6fd5f2ce227f8eedad1e769e1251cbf27f4d3ea315f54891c7a9a56c48204218'
SELF='scripts/qualify_upstream_current_body_negative.py'
WORKFLOW='.github/workflows/current-body-negative.yml'
REF='refs/heads/ci/upstream-current-body-negative-20261018'
PRODUCT='crates/marmot-app/src/client/account_chat_sharing/automatic.rs'
PRODUCT_SHA='0fde8d14ceea74cd2dd998cd4bfd4e516d61f3704e682931fc42f2460b95d117'
FIXTURE='crates/marmot-app/src/native_device_linking/tests/automatic_body_negative_acceptance.rs'
FIXTURE_SHA='0e23e1e5666814d1bd55b43b456e06780fedeb4e4265ea7a2ed6f22dd647a870'
ANCHOR='            // Retain the owned slot as a barrier until this authenticated\n            // negative assembly commits. Renewal would discard its retry.\n            if let Some(publication) = entry.publication.as_ref() {'
REPLACEMENT='            // Retain the owned slot as a barrier until this authenticated\n            // negative assembly commits. Renewal would discard its retry.\n            entry.renew = true;\n            if let Some(publication) = entry.publication.as_ref() {'
MUTANT_SHA='135d6053e690f096f9870b496bdec4230c6c4d3ac68f8805990516bafb6ec02b'
MESSAGE='authenticated negative SQL rollback must retain the same owned Body until negative commit precedes owned-task harvest or channel retirement without old Body effects'
NAME='native_device_linking::automatic_pairing_acceptance::body_negative_acceptance::authenticated_negative_sql_failure_retains_owned_body_until_commit_before_disposition'
FEATURES='marmot-app/otlp-export,marmot-app/product-analytics-export,marmot-app/test-policy-overrides,marmot-app/experimental-device-sync,cgka-engine/test-policy-overrides,cgka-engine/test-crash-hooks'
OUT=Path('current-body-negative-evidence')
NAMES=[NAME]
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
        and os.environ.get('UPSTREAM_CURRENT_BODY_NEGATIVE_BASELINE')==BASE,'exact-hosted-ref-source')
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
        and digest(Path(FIXTURE).read_bytes())==FIXTURE_SHA
        and Path(PRODUCT).read_bytes().count(ANCHOR.encode())==1,'exact-workflow-and-product-witness')
    ensure(set(git('ls-files','--others','--exclude-standard').decode().splitlines())<={str(OUT/'result.json')},'untracked-closure')
    return {'head':head,'baseline':BASE,'whole_source_modes_verified':True,'Rust_exceptions':[],
        'old_guards_or_main_called':False,'old_module_globals_mutated':False,'historical_runtime_reused':False}

def clean(raw):return re.sub(r'\x1b\[[0-?]*[ -/]*[@-~]','',raw)
STAGES=['initial-record-receipt-committed','actual-peer-intent-held','actual-owned-body-held','actual-same-channel-binding-verified','actual-peer-intent-released','actual-authenticated-negative-sql-failure','persistent-sql-fault-removed']
FLAGS=['retained','commit_before_disposition','no_old_body_effects','actor_progress']
NUMBERS=['sql_failures','associated_sql_failures','barrier_observations','commit_at','harvest_at','retirement_at','body_effects']
def expected_site():
    source=Path(FIXTURE).read_text();ensure(source.count(MESSAGE)==1,'unique-final-negative-oracle')
    start=source.rfind('assert!(',0,source.index(MESSAGE));ensure(start>=0,'source-owned-final-assertion')
    return {'file':FIXTURE,'line':source[:start].count('\n')+1,'column':len(source[:start].rsplit('\n',1)[-1])+1}

def verdict(raw,code,basic,expected):
    text=clean(raw);header=r'(?m)^test '+re.escape(NAME)+r' \.\.\. '
    ensure(len(re.findall(header,text))==1,'one-genuine-exact-libtest-header')
    text=re.sub(header,lambda hit:hit[0]+'\n',text,count=1)
    lines=[line for line in text.splitlines() if 'body-negative-control' in line]
    ensure(len(lines)==10 and sum(len(line.encode()) for line in lines)<=4096,'exact-ten-closed-negative-lines')
    stages=['body-negative-control stage='+stage for stage in STAGES]+['body-negative-control stage=positive-runtime-close index='+str(i) for i in range(2)]
    ensure(lines[:9]==stages,'all-real-prerequisites-receipt-and-two-positive-closes-in-order')
    num=r'(?:0|[1-9][0-9]{0,19})';boolean=r'(true|false)'
    pattern='body-negative-control '+' '.join(key+'='+boolean for key in FLAGS)+' '+' '.join(key+'=('+num+')' for key in NUMBERS)+' harvested_cancelled='+boolean+' retired_task_finished='+boolean
    match=re.fullmatch(pattern,lines[9]);ensure(match is not None,'exact-negative-summary-grammar')
    flags={key:value=='true' for key,value in zip(FLAGS,match.groups()[:4])}
    numbers=dict(zip(NUMBERS,map(int,match.groups()[4:11])))
    ensure(all(value<1<<64 for value in numbers.values()),'actual-u64-probe-widths')
    outcomes=dict(zip(['harvested_cancelled','retired_task_finished'],[value=='true' for value in match.groups()[11:]]))
    sql=numbers['sql_failures'];associated=numbers['associated_sql_failures']
    prerequisites=(sql>0 and 0<associated<=sql and numbers['barrier_observations']>0 and flags['actor_progress'] and flags['no_old_body_effects'] and numbers['body_effects']==0)
    disposition=min((numbers[key] for key in ['harvest_at','retirement_at'] if numbers[key]>0),default=None)
    ordered=disposition is not None and 0<numbers['commit_at']<disposition
    site=expected_site()
    panics=re.findall(r"(?m)^thread '([^'\n]+)'(?: \([1-9][0-9]*\))? panicked at ([A-Za-z0-9_./-]+):([0-9]+):([0-9]+):\n([^\n]*)",text)
    sole=(len(panics)==1 and text.count('panicked at ')==1 and panics[0]==(NAME,site['file'],str(site['line']),str(site['column']),MESSAGE))
    complete=(basic.get('actual_counts_complete') is True and basic.get('executed_nonignored')==1 and basic.get('ignored')==0 and basic.get('compiler_error_count')==0)
    green=(complete and basic.get('passed_gate') is True and prerequisites and flags['retained'] and flags['commit_before_disposition'] and ordered and not panics)
    red=(complete and type(code)is int and code==101 and basic.get('passed')==0 and basic.get('failed')==1 and basic.get('panic_count')==1 and prerequisites and sole and (not flags['retained'] or not flags['commit_before_disposition']))
    return {'stages':STAGES,'positive_runtime_closes':[0,1],'observed':dict(flags,**numbers,**outcomes),'all_genuine_prerequisites':prerequisites,
        'actual_commit_before_first_disposition':ordered,'expected_panic_site':site,'sole_final_named_assertion':sole,'focused_GREEN':bool(green),'genuine_behavioral_RED':bool(red),
        'expected_outcome_verified':bool(red if expected=='red' else green),'raw_identity_or_error_exported':False}

def compile_app(report,cohort,tracked,save_report):
    features=['otlp-export','product-analytics-export','test-policy-overrides','experimental-device-sync']
    command=['cargo','test','--locked','-p','marmot-app','--lib','--no-run','--message-format=json']
    if features:command+=['--features',FEATURES]
    code,raw,seconds=bounded.capture(command,1800,limit=8*1024*1024)
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
    report['compilation']={'command':command,'exit_code':code,'seconds':seconds,'compiler_error_count':len(errors) if finished else None,'build_finished_success':complete,'malformed_JSON_lines':malformed,'compiler_codes':codes[:32],
        'compiler_sites':sites[:32],'closed_diagnostics_truncated':len(codes)>32 or len(sites)>32,'selected_test_artifact_count':len(selected),'features_requested':features};save_report()
    ensure(type(code) is int and code==0 and complete and not errors and len(selected)==1,'one-successful-App-lib-compilation')
    artifact=selected[0];observed=artifact.get('features')
    ensure(type(observed) is list and all(type(v) is str for v in observed) and len(observed)==len(set(observed)) and set(observed)-{'default'}==set(features),'actual-App-unit-feature-cohort')
    binary=Path(artifact['executable']);ensure(binary.is_file() and not binary.is_symlink() and re.fullmatch(r'marmot_app-[0-9a-f]{16}',binary.name) and binary.resolve().is_relative_to(Path(os.environ.get('CARGO_TARGET_DIR','target')).resolve()),'regular-App-test-binary')
    report['compiled_features']={'observed_own_unit_features':sorted(observed),'actual_test_profile':True,'all_Cargo_artifact_feature_manifest_sha256':digest(json.dumps([{'target':v['target']['name'],'features':v['features'],'profile':v['profile']} for v in artifacts],sort_keys=True).encode()),'full_dependency_feature_parity_claimed':False};save_report()
    graph=completion.feature_metadata(binary)
    report['dependency_fingerprints']=graph;save_report()
    ensure(graph.get('verified') is True and {'marmot_app','cgka_engine','storage_sqlite','cgka_session','marmot_account','transport_nostr'}<=set(graph.get('nodes',{}))
        and {'experimental-device-sync','test-policy-overrides','test-crash-hooks'}<=set(graph['nodes']['cgka_engine']['features']),'actual-six-node-feature-graph')
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
    ensure(physical()==expected_inputs and binary.is_file() and not binary.is_symlink() and digest(binary.read_bytes())==before and stat.S_IMODE(binary.stat().st_mode)==mode,'prebody-source-binary-mode')
    row.update(runtime_attempted=True,actual_executed_nonignored=None);save(root)
    try:code,raw,seconds=bounded.capture([str(binary),'--exact',name,'--nocapture','--test-threads=1'],240,limit=8*1024*1024)
    except bounded.GateFailure as error:
        row['watchdog_triggered']=str(error)=='bounded-command-timeout';row['output_limit_triggered']=str(error)=='bounded-command-output-limit';save(root);raise
    row.update(body_exit_code=code,body_seconds=seconds,source_after_body_pristine=physical()==expected_inputs,
        binary_after_sha256=digest(binary.read_bytes()) if binary.is_file() and not binary.is_symlink() else None,
        binary_after_mode=stat.S_IMODE(binary.stat().st_mode) if binary.is_file() and not binary.is_symlink() else None);save(root)
    basic=counts.parse_body(raw,code,name);row['basic_counts']=basic
    for dest,key in [('actual_passed','passed'),('actual_failed','failed'),('actual_ignored','ignored'),('actual_executed_nonignored','executed_nonignored')]:row[dest]=basic.get(key)
    row['actual_test_passed']=basic.get('passed_gate') is True;save(root)
    ensure(row['source_after_body_pristine'] and row['binary_after_sha256']==before and row['binary_after_mode']==mode,'postbody-source-binary-mode')
    row['outcome']=verdict(raw,code,basic,expected);row['expected_outcome_verified']=row['outcome']['expected_outcome_verified'];save(root)

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
        ensure(digest(original)==PRODUCT_SHA and original.count(ANCHOR.encode())==1,'exact-fixed-product-before-mutation')
        mutant=original.replace(ANCHOR.encode(),REPLACEMENT.encode(),1)
        ensure(digest(mutant)==MUTANT_SHA,'exact-reviewed-force-renew-only-mutant')
        expected_mutant=dict(frozen);expected_mutant[PRODUCT]=(frozen[PRODUCT][0],product_mode,digest(mutant))
        try:
            mutation_attempted=True;report['mutation_attempted']=True;save(report)
            write_fresh(product,mutant,product_mode)
            ensure(physical()==expected_mutant,'only-owned-force-renew-source-and-mode')
            phase(report,'mutant',cohort,expected_mutant,[(NAME,'red')],different_from=baseline_hash)
        except Exception as error:report['mutant_controller_failure_type']=type(error).__name__;save(report)
        finally:
            restore_owned(product,original,product_mode)
            report['source_restored_before_fresh_compile']=physical()==frozen;save(report)
            ensure(report['source_restored_before_fresh_compile'],'exact-source-restore-before-compile')
            try:phase(report,'restored',cohort,frozen,[(name,'green') for name in NAMES])
            except Exception as error:report['restored_controller_failure_type']=type(error).__name__;save(report)
        rows=[case for label in ['baseline','mutant','restored'] for case in report.get('phases',{}).get(label,{}).get('cases',[])]
        report['aggregate']=aggregate(rows,3)
        restored=report.get('phases',{}).get('restored',{});mutant_row=report.get('phases',{}).get('mutant',{})
        report['baseline_restored_binary_equal']=restored.get('binary_before')==report['phases']['baseline']['binary_before']
        signatures=[{name:node['features'] for name,node in report['phases'].get(label,{}).get('dependency_fingerprints',{}).get('nodes',{}).items()} for label in ['baseline','mutant','restored']]
        report['same_observed_dependency_feature_cohort']=bool(signatures[0] and signatures[0]==signatures[1]==signatures[2])
        report['component_PFP_verified']=(all(report.get('phases',{}).get(label,{}).get('phase_passed') is True for label in ['baseline','mutant','restored'])
            and report['aggregate'].get('actual_passed')==2 and report['aggregate'].get('actual_failed')==1 and report['aggregate'].get('actual_ignored')==0
            and report['aggregate'].get('actual_executed_nonignored')==3 and report['baseline_restored_binary_equal'] and report['same_observed_dependency_feature_cohort']
            and mutant_row.get('binary_before',{}).get('sha256')!=baseline_hash)
        report['expected_outcome_verified']=report['component_PFP_verified'];save(report);ensure(report['component_PFP_verified'],'fresh-three-body-PFP-required')
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
        report['actual_body_counts']=aggregate(allcases,3 if expected=='pfp' and mutation_attempted else 1)
        for key in ['passed','failed','ignored','executed_nonignored']:report['actual_'+key]=report['actual_body_counts']['actual_'+key]
        if not report['runtime_attempted']:report['actual_executed_nonignored']=0
        report['qualification_passed']=False;save(report)
        ensure(report['source_final_pristine'] and report.get('baseline_binary_final_pristine',True),'final-source-binary-mode')
        if sys.exc_info()[0] is None:
            ensure(report.get('expected_outcome_verified') is True and not report['fallback_source_restore_used'] and not report['fallback_binary_copy_used'],'final-outcome-without-fallback-required')
            if expected=='pfp':ensure(report['component_PFP_verified'],'final-PFP-must-remain-qualified')

def controls():
    site=expected_site();stages='\n'.join('body-negative-control stage='+stage for stage in STAGES)+'\n'+'\n'.join('body-negative-control stage=positive-runtime-close index='+str(i) for i in range(2))+'\n'
    record='body-negative-control retained=true commit_before_disposition=true no_old_body_effects=true actor_progress=true sql_failures=8 associated_sql_failures=8 barrier_observations=1 commit_at=1 harvest_at=0 retirement_at=2 body_effects=0 harvested_cancelled=false retired_task_finished=true\n'
    prefix='running 1 test\ntest '+NAME+' ... '
    summary='test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 1s\n'
    green=prefix+stages+record+'ok\n'+summary
    def check(raw,code,expected):return verdict(raw,code,counts.parse_body(raw,code,NAME),expected)['expected_outcome_verified']
    ensure(check(green,0,'green'),'actual-shaped-receipt-settled-GREEN')
    ensure(check(green.replace('harvest_at=0 retirement_at=2','harvest_at=2 retirement_at=0').replace('harvested_cancelled=false retired_task_finished=true','harvested_cancelled=true retired_task_finished=false'),0,'green'),'actual-harvest-alternative-GREEN')
    panic="thread '"+NAME+"' panicked at "+FIXTURE+':'+str(site['line'])+':'+str(site['column'])+':\n'+MESSAGE+'\n'
    red=prefix+stages+record.replace('retained=true','retained=false').replace('commit_before_disposition=true','commit_before_disposition=false')+panic+'FAILED\n'+summary.replace('result: ok. 1 passed; 0 failed','result: FAILED. 0 passed; 1 failed')
    ensure(check(red,101,'red'),'real-force-renew-shaped-RED')
    ensure(check(red.replace('commit_before_disposition=false','commit_before_disposition=true'),101,'red'),'retention-only-final-assertion-RED')
    ensure(check(red.replace('retained=false','retained=true'),101,'red'),'order-only-final-assertion-RED')
    ensure(check(red.replace('sql_failures=8 associated_sql_failures=8','sql_failures=3 associated_sql_failures=2'),101,'red'),'variable-positive-associated-real-SQL')
    negatives=[red.replace('actor_progress=true','actor_progress=false'),red.replace('no_old_body_effects=true','no_old_body_effects=false'),red.replace('body_effects=0','body_effects=1'),red.replace('sql_failures=8','sql_failures=0'),red.replace('associated_sql_failures=8','associated_sql_failures=0'),red.replace('associated_sql_failures=8','associated_sql_failures=9'),red.replace('retained=false commit_before_disposition=false','retained=true commit_before_disposition=true'),red.replace(MESSAGE,'foreign assertion'),red.replace(panic,''),red+panic,red.replace('0 ignored','1 ignored'),red.replace('0 passed; 1 failed','0 passed; 0 failed'),red.replace('sql_failures=8','sql_failures=18446744073709551616')]
    negatives += [red.replace('body-negative-control stage='+stage+'\n','') for stage in STAGES]
    negatives += [red.replace('body-negative-control stage=positive-runtime-close index='+str(i)+'\n','') for i in range(2)]
    negatives += [red+stages,red.replace('initial-record-receipt-committed','initial-record-receipt-PRIVATE'),red+'error[E0000]: private\n']
    for raw in negatives:
        try:accepted=check(raw,101,'red')
        except (ValueError,TypeError,OverflowError):accepted=False
        ensure(not accepted,'setup-identity-cleanup-or-foreign-failure-never-intended-RED')
    for raw in [green.replace('commit_at=1','commit_at=2'),green.replace('retirement_at=2','retirement_at=0'),green.replace('retained=true','retained=false')]:
        ensure(not check(raw,0,'green'),'retention-and-strict-commit-order-GREEN-required')
    ensure('PRIVATE' not in json.dumps(verdict(red,101,counts.parse_body(red,101,NAME),'red')),'no-private-text-exported')
    return {'positive':6,'negative':len(negatives)+3,'body_count_controls':counts.parser_controls(),'runtime_bodies':0,'historical_SQL_8_8_not_forced':True}

def main():
    parser=argparse.ArgumentParser();parser.add_argument('--preflight',action='store_true');parser.add_argument('--expected',choices=['green','pfp'],default='pfp');args=parser.parse_args()
    report={'scope':'one current genuine SQL-negative Body; force-renew PFP','preflight':args.preflight,'expected':args.expected,'runtime_attempted':False,
        'actual_executed_nonignored':0,'qualification_passed':False,'native_global_qualification':False,'automatic_retries':0,'fixture_Tokio_flavor':'current_thread','RUST_MIN_STACK':4194304,
        'original_outer_body_seconds':240,'raw_output_retained':False,'initial_real_RecordReceipt_required':True}
    try:
        report['source_guard']=source_guard(args.preflight);save(report);report['parser_controls']=controls();save(report)
        if not args.preflight:runtime(report,'experimental',args.expected)
        report['controller_completed']=True;save(report)
    except Exception as error:report['controller_failure_type']=type(error).__name__;save(report);raise
    finally:report['final_HEAD_git_pristine']=subprocess.run(['git','diff','--quiet','HEAD']).returncode==0;save(report)
if __name__=='__main__':main()
