#!/usr/bin/env python3
"""Real ownership controls and optional exact filter PFP; no native qualification."""
import argparse, hashlib, json, os, re, shutil, stat, subprocess, time, sys
from pathlib import Path
import qualify_upstream_storage_boundary as bounded
import qualify_upstream_storage_app_handles as counts
ensure=bounded.ensure
BASE='ff76aaba0eeffc0c84a1b9b59923ac165400c8fc'
CANONICAL_TEST='1b5628e6e4d83f6ce1e24d3b5115d2ba288c8e41'
RAW_PRODUCT='ff76aaba0eeffc0c84a1b9b59923ac165400c8fc'
PRODUCT='crates/marmot-app/src/runtime/mod.rs'
PRODUCT_BEFORE_SHA='9b783b85368bac715855782f86ecab67f8af640cdaa4cbb837c3e8e3f78c9a21'
RAW_PRODUCT_SHA='1051628fc165c481344ab59f3c6ecdb0f82c13725d3909614da54e031bea8cec'
PRODUCT_SHA='1051628fc165c481344ab59f3c6ecdb0f82c13725d3909614da54e031bea8cec'
FILTER_INSERTION='                .filter(|account| {\n                    target_account_id\n                        .is_none_or(|target| account.account_id_hex == target)\n                })\n'
RAW_FILTER_INSERTION='                .filter(|account| {\n                    target_account_id\n                        .is_none_or(|target| account.account_id_hex == target)\n                })\n'
PRIOR_RED_SOURCE='ce112f33fcf5b263a44a17eebd8c8ebcc193c72c'
PRIOR_RED_RUN=39164409153
PRIOR_RED_ARTIFACT=12150052154
PRIOR_RED_ZIP_SHA='e41f2a7b8dc8e3b2a014128db9babdf7cb5e9ae4955367b19c4c10d2c5ffebcd'
BATCH_NAME='runtime::tests::explicit_batch_reconcile_still_owns_all_eligible_accounts'
PARENT='a839cabf5a401f81bba53f22344e62346d6c4070'
REVIEWED_SOURCE='ebc97baf97d54e1162c6271e0862beb680febae0'
REVIEWED_FIXTURE_SHA='4d6da976cbf61415af5c299376b83a735bfc4decbe06e44f6f48927ed61e29e1'
WORKFLOW_SHA='ac3844a8632663ffa8516dcf7fd43446d535947d694fe8afaafdc77686bdc52b'
FIXTURE_SHA='5a9a0d629c7bb54264a526a8d5001c1aaf82465ed1842e2896f5e1148f8e861e'
SELF='scripts/qualify_upstream_account_isolation.py'
WORKFLOW='.github/workflows/account-isolation.yml'
REF='refs/heads/ci/upstream-account-isolation-20261018'
FIXTURE='crates/marmot-app/src/runtime/tests.rs'
NAME='runtime::tests::cold_selected_group_read_leaves_foreign_account_available_to_another_runtime'
MESSAGE='selected account cold read must not claim foreign account session'
OUT=Path('account-isolation-evidence')

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
    ensure(type(BASE) is str and re.fullmatch('[0-9a-f]{40}',BASE) and type(WORKFLOW_SHA) is str and re.fullmatch('[0-9a-f]{64}',WORKFLOW_SHA)
        and type(FIXTURE_SHA) is str and re.fullmatch('[0-9a-f]{64}',FIXTURE_SHA),'root-pinned-source-required')
    head=git('rev-parse','HEAD').decode().strip()
    ensure(os.environ.get('GITHUB_ACTIONS')=='true' and os.environ.get('GITHUB_REPOSITORY')=='dyKiU/mdk'
        and (os.environ.get('GITHUB_EVENT_NAME')=='workflow_dispatch' or (preflight and os.environ.get('GITHUB_EVENT_NAME')=='push')) and os.environ.get('GITHUB_SHA')==head
        and os.environ.get('GITHUB_REF')==REF and os.environ.get('GITHUB_WORKFLOW_REF')=='dyKiU/mdk/'+WORKFLOW+'@'+REF
        and os.environ.get('UPSTREAM_ACCOUNT_ISOLATION_BASELINE')==BASE,'exact-manual-source')
    ensure(os.environ.get('CARGO_INCREMENTAL')=='1' and os.environ.get('CARGO_BUILD_JOBS')=='2' and os.environ.get('RUST_MIN_STACK')=='4194304'
        and all(os.environ.get(k)=='0' for k in ['CARGO_PROFILE_DEV_DEBUG','CARGO_PROFILE_TEST_DEBUG'])
        and all(not os.environ.get(k) for k in ['RUSTFLAGS','CARGO_ENCODED_RUSTFLAGS','RUSTC_BOOTSTRAP','CARGO_PROFILE_DEV_OPT_LEVEL','CARGO_PROFILE_TEST_OPT_LEVEL']),'exact-App-build-cohort')
    ensure(subprocess.run(['git','merge-base','--is-ancestor',BASE,head]).returncode==0,'BASE-ancestor')
    for a,b in [(PARENT,REVIEWED_SOURCE),(REVIEWED_SOURCE,CANONICAL_TEST),(CANONICAL_TEST,RAW_PRODUCT),(RAW_PRODUCT,BASE)]:
        ensure(subprocess.run(['git','merge-base','--is-ancestor',a,b]).returncode==0,'reviewed-test-and-product-ancestry')
    changes=lambda a,b:set(git('diff','--name-only',a,b).decode().splitlines())
    ensure(changes(PARENT,REVIEWED_SOURCE)=={FIXTURE} and changes(PARENT,CANONICAL_TEST)=={FIXTURE}
        and changes(CANONICAL_TEST,RAW_PRODUCT)=={PRODUCT} and changes(RAW_PRODUCT,BASE)<={PRODUCT}
        and changes(PARENT,BASE)=={FIXTURE,PRODUCT},'exact-reviewed-two-path-provenance')
    ensure(layout(REVIEWED_SOURCE)[FIXTURE][0]=='100644' and digest(git('show',REVIEWED_SOURCE+':'+FIXTURE))==REVIEWED_FIXTURE_SHA
        and digest(git('show',CANONICAL_TEST+':'+FIXTURE))==FIXTURE_SHA and digest(git('show',RAW_PRODUCT+':'+FIXTURE))==FIXTURE_SHA,'exact-raw-and-canonical-test')
    before=git('show',CANONICAL_TEST+':'+PRODUCT);raw=git('show',RAW_PRODUCT+':'+PRODUCT);current_product=git('show',BASE+':'+PRODUCT)
    ensure(all(layout(ref)[PRODUCT][0]=='100644' for ref in [CANONICAL_TEST,RAW_PRODUCT,BASE])
        and digest(before)==PRODUCT_BEFORE_SHA and digest(raw)==RAW_PRODUCT_SHA and digest(current_product)==PRODUCT_SHA
        and raw.count(RAW_FILTER_INSERTION.encode())==1 and raw.replace(RAW_FILTER_INSERTION.encode(),b'',1)==before
        and current_product.count(FILTER_INSERTION.encode())==1 and current_product.replace(FILTER_INSERTION.encode(),b'',1)==before,'only-exact-filter-insertion-with-full-blob-inverse')
    ensure(git('show',PRIOR_RED_SOURCE+':'+PRODUCT)==before and digest(git('show',PRIOR_RED_SOURCE+':'+FIXTURE))==FIXTURE_SHA,'prior-genuine-RED-inputs-exact-not-runtime-reuse')
    baseline=layout(BASE);current=layout('HEAD')
    ensure(SELF not in baseline and WORKFLOW not in baseline and set(current)==set(baseline)|{SELF,WORKFLOW},'only-two-new-owned-metadata')
    ensure(subprocess.run(['git','diff','--quiet','HEAD']).returncode==0,'whole-HEAD-pristine')
    for path,(mode,_) in current.items():
        expected=baseline.get(path,('100644',None));p=Path(path);s=p.lstat();link=stat.S_ISLNK(s.st_mode)
        ensure(mode==expected[0] and link==(mode=='120000') and (link or stat.S_ISREG(s.st_mode))
            and (link or bool(s.st_mode&0o111)==(mode=='100755')),'whole-source-modes')
        data=os.fsencode(os.readlink(p)) if link else p.read_bytes()
        if expected[1] is not None:ensure(hashlib.sha1(b'blob '+str(len(data)).encode()+b'\0'+data).hexdigest()==expected[1],'whole-BASE-content')
    ensure(digest(Path(WORKFLOW).read_bytes())==WORKFLOW_SHA and digest(Path(FIXTURE).read_bytes())==FIXTURE_SHA
        and baseline[FIXTURE][0]=='100644','exact-workflow-and-fixture')
    ensure(set(git('ls-files','--others','--exclude-standard').decode().splitlines())<={str(OUT/'result.json')},'no-unowned-untracked')
    return {'head':head,'baseline':BASE,'whole_source_modes_verified':True,'Rust_exceptions':[],
        'old_guards_or_main_called':False,'old_module_globals_mutated':False,'historical_runtime_reused':False,'reviewed_product':RAW_PRODUCT,'prior_genuine_RED_run':PRIOR_RED_RUN,'prior_genuine_RED_source':PRIOR_RED_SOURCE,'prior_genuine_RED_artifact':PRIOR_RED_ARTIFACT,'prior_genuine_RED_ZIP_sha256':PRIOR_RED_ZIP_SHA}

def expected_site(source):
    lines=source.splitlines();hits=[i for i,line in enumerate(lines) if MESSAGE in line]
    ensure(len(hits)==1,'unique-fixed-assertion')
    index=hits[0]
    start=max(i for i in range(index+1) if re.search(r'\bassert!\s*\(',lines[i]))
    end=index if ');' in lines[index] else next(i for i in range(index+1,min(index+4,len(lines))) if re.fullmatch(r'\s*\);\s*',lines[i]))
    ensure(re.fullmatch(r'assert!\(\s*bob_ok,\s*'+re.escape('"'+MESSAGE+'"')+r'\s*,?\s*\);', '\n'.join(line.strip() for line in lines[start:end+1])) is not None,'exact-original-assertion-shape')
    return {'file':FIXTURE,'line':start+1,'column':lines[start].index('assert!')+1}

def observations(raw):
    text=re.sub(r'\x1b\[[0-9;]*m','',raw)
    text=re.sub(r'(?m)^test '+re.escape(NAME)+r' \.\.\. (?=\[account-isolation\] )','',text)
    rows=[line for line in text.splitlines() if '[account-isolation]' in line]
    ensure(len(rows)==1 and len(rows[0].encode())<=256,'one-closed-account-isolation-row')
    match=re.fullmatch(r'\[account-isolation\] selected_read=(true|false) foreign_read=(true|false) foreign_session_busy=(true|false) shutdown_returns=([012]) terminal_close_ok=(true|false) storage_closed=(true|false)',rows[0])
    ensure(match is not None,'exact-account-isolation-grammar')
    return {'selected_read':match[1]=='true','foreign_read':match[2]=='true','foreign_session_busy':match[3]=='true','shutdown_returns':int(match[4]),'terminal_close_ok':match[5]=='true','storage_closed':match[6]=='true'}

def verdict(raw,code,basic,source,expected):
    row=observations(raw);text=re.sub(r'\x1b\[[0-9;]*m','',raw)
    site=expected_site(source)
    headers=re.findall(r"thread '"+re.escape(NAME)+r"'(?: \([1-9][0-9]*\))? panicked at ([A-Za-z0-9_./-]+):([0-9]+):([0-9]+):\n([^\n]*)",text)
    sole=(len(headers)==1 and headers[0][0]==site['file'] and int(headers[0][1])==site['line'] and int(headers[0][2])==site['column'] and headers[0][3].strip()==MESSAGE)
    complete=(basic.get('actual_counts_complete') is True and basic.get('executed_nonignored')==1 and basic.get('ignored')==0 and basic.get('compiler_error_count')==0)
    red=(complete and type(code) is int and code==101 and basic.get('passed')==0 and basic.get('failed')==1 and basic.get('panic_count')==1 and sole
        and row=={'selected_read':True,'foreign_read':False,'foreign_session_busy':True,'shutdown_returns':2,'terminal_close_ok':True,'storage_closed':True})
    green=(complete and basic.get('passed_gate') is True and row=={'selected_read':True,'foreign_read':True,'foreign_session_busy':False,'shutdown_returns':2,'terminal_close_ok':True,'storage_closed':True})
    return {'facts':row,'expected_assertion':site,'sole_named_assertion_observed':sole,'genuine_behavioral_RED':red,'focused_GREEN':green,
        'expected_outcome':expected,'expected_outcome_verified':red if expected=='red' else green,'actual_storage_closed_observed':row['storage_closed']}

def controls():
    source='    assert!(bob_ok, "'+MESSAGE+'");\n';marker='[account-isolation] selected_read=true foreign_read=false foreign_session_busy=true shutdown_returns=2 terminal_close_ok=true storage_closed=true\n'
    body='running 1 test\ntest '+NAME+' ... '+marker+"thread '"+NAME+"' panicked at "+FIXTURE+':1:5:\n'+MESSAGE+'\nFAILED\ntest result: FAILED. 0 passed; 1 failed; 0 ignored; 0 measured; 0 filtered out; finished in 1s\n'
    b=counts.parse_body(body,101,NAME);ensure(verdict(body,101,b,source,'red')['expected_outcome_verified'],'positive-genuine-RED')
    green='running 1 test\ntest '+NAME+' ... '+marker.replace('foreign_read=false foreign_session_busy=true','foreign_read=true foreign_session_busy=false')+'ok\ntest result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 1s\n'
    ensure(verdict(green,0,counts.parse_body(green,0,NAME),source,'green')['expected_outcome_verified'],'positive-real-GREEN')
    bad=[body.replace('selected_read=true','selected_read=false'),body.replace('foreign_session_busy=true','foreign_session_busy=false'),body.replace('terminal_close_ok=true','terminal_close_ok=false'),body.replace('storage_closed=true','storage_closed=false'),body.replace(MESSAGE+'\n','other assertion\n'),body.replace(FIXTURE+':1:',FIXTURE+':2:'),body.replace('0 ignored','1 ignored'),body.replace('0 passed; 1 failed','0 passed; 0 failed')]
    for text in bad:ensure(not verdict(text,101,counts.parse_body(text,101,NAME),source,'red')['expected_outcome_verified'],'negative-not-genuine-RED')
    for text in [body+marker,body.replace('[account-isolation]','[account-isolation] private'),body.replace('selected_read=true','selected_read=1')]:
        try:observations(text)
        except ValueError:continue
        raise ValueError('malformed-marker-accepted')
    return {'positive':2,'negative':11,'shared_counts':counts.parser_controls(),'runtime_bodies':0}

def compile_app(report,cohort,tracked,save_report):
    features=[] if cohort=='default' else ['experimental-device-sync']
    command=['cargo','test','--locked','-p','marmot-app','--lib','--no-run','--message-format=json']
    if features:command+=['--features',','.join(features)]
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
    return binary

def pfp_metadata_controls():
    def case(p,f,i,n,shape=True):return {'basic_counts':{'passed':p,'failed':f,'ignored':i,'executed_nonignored':n,'actual_counts_complete':shape}}
    row=aggregate([case(1,0,0,1),case(0,1,0,1)],2)
    ensure(row['actual_passed']==row['actual_failed']==1 and row['actual_executed_nonignored']==2,'typed-PFP-aggregate-positive')
    row=aggregate([case(0,0,1,0,False)],1)
    ensure(row['actual_ignored']==1 and row['actual_executed_nonignored']==0 and row['unknown_count_cases']==0,'observed-ignored-not-unknown-or-GREEN')
    row=aggregate([case(1,0,0,1)],2)
    ensure(row['actual_passed'] is None and row['known_partial_passed']==1 and row['missing_case_rows']==1,'missing-body-not-invented')
    row=aggregate([case(True,0,0,1)],1)
    ensure(row['actual_passed'] is None and row['unknown_count_cases']==1,'boolean-count-rejected')
    return {'positive':2,'unknown_or_type_controls':2,'runtime_bodies':0}

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
    try:code,raw,seconds=bounded.capture([str(binary),'--exact',name,'--nocapture','--test-threads=1'],900,limit=8*1024*1024)
    except bounded.GateFailure as error:
        row['watchdog_triggered']=str(error)=='bounded-command-timeout';row['output_limit_triggered']=str(error)=='bounded-command-output-limit';save(root);raise
    row.update(body_exit_code=code,body_seconds=seconds,source_after_body_pristine=physical()==expected_inputs,
        binary_after_sha256=digest(binary.read_bytes()) if binary.is_file() and not binary.is_symlink() else None,
        binary_after_mode=stat.S_IMODE(binary.stat().st_mode) if binary.is_file() and not binary.is_symlink() else None);save(root)
    basic=counts.parse_body(raw,code,name);row['basic_counts']=basic
    for dest,key in [('actual_passed','passed'),('actual_failed','failed'),('actual_ignored','ignored'),('actual_executed_nonignored','executed_nonignored')]:row[dest]=basic.get(key)
    row['actual_test_passed']=basic.get('passed_gate') is True;save(root)
    ensure(row['source_after_body_pristine'] and row['binary_after_sha256']==before and row['binary_after_mode']==mode,'postbody-source-binary-mode')
    if name==NAME:
        row['outcome']=verdict(raw,code,basic,Path(FIXTURE).read_text(),expected)
        row['expected_outcome_verified']=row['outcome']['expected_outcome_verified']
    else:
        ensure(name==BATCH_NAME and expected=='green','fixed-batch-control-only')
        row['expected_outcome_verified']=basic.get('passed_gate') is True
        row['batch_control_has_source_pinned_real_owner_and_terminal_cleanup_assertions']=True
        row['separate_cleanup_marker_observed']=False
    save(root)

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
        specs=[(NAME,'red')] if expected=='red' else [(NAME,'green'),(BATCH_NAME,'green')]
        baseline_binary,baseline_hash,baseline_mode=phase(report,'baseline',cohort,frozen,specs)
        baseline_bytes=baseline_binary.read_bytes();report['runtime_attempted']=any(row.get('runtime_attempted') for row in report['phases']['baseline']['cases'])
        if expected!='pfp':
            report['expected_outcome_verified']=report['phases']['baseline']['phase_passed'];save(report)
            ensure(report['expected_outcome_verified'],'required-baseline-outcome-not-established');return
        # Admission is before mutation/finally: an unqualified baseline is not retried as restoration.
        if report['phases']['baseline']['phase_passed'] is not True:
            report['skipped_mutant_and_restored_reason']='baseline_unqualified_no_mutation_attempted';save(report)
            raise ValueError('PFP-baseline-must-qualify-before-mutation')
        ensure(digest(original)==PRODUCT_SHA and original.count(FILTER_INSERTION.encode())==1,'exact-fixed-product-before-mutation')
        mutant=original.replace(FILTER_INSERTION.encode(),b'',1)
        ensure(digest(mutant)==PRODUCT_BEFORE_SHA and mutant==git('show',CANONICAL_TEST+':'+PRODUCT),'full-mutant-blob-equals-original-genuine-RED-product')
        expected_mutant=dict(frozen);expected_mutant[PRODUCT]=(frozen[PRODUCT][0],product_mode,digest(mutant))
        try:
            mutation_attempted=True;report['mutation_attempted']=True;save(report)
            write_fresh(product,mutant,product_mode)
            ensure(physical()==expected_mutant,'only-owned-filter-omission-source-and-mode')
            phase(report,'mutant',cohort,expected_mutant,[(NAME,'red')],different_from=baseline_hash)
        except Exception as error:report['mutant_controller_failure_type']=type(error).__name__;save(report)
        finally:
            restore_owned(product,original,product_mode)
            report['source_restored_before_fresh_compile']=physical()==frozen;save(report)
            ensure(report['source_restored_before_fresh_compile'],'exact-source-restore-before-compile')
            try:phase(report,'restored',cohort,frozen,[(NAME,'green'),(BATCH_NAME,'green')])
            except Exception as error:report['restored_controller_failure_type']=type(error).__name__;save(report)
        rows=[case for label in ['baseline','mutant','restored'] for case in report.get('phases',{}).get(label,{}).get('cases',[])]
        report['aggregate']=aggregate(rows,5)
        restored=report.get('phases',{}).get('restored',{});mutant_row=report.get('phases',{}).get('mutant',{})
        report['baseline_restored_binary_equal']=restored.get('binary_before')==report['phases']['baseline']['binary_before']
        report['component_PFP_verified']=(all(report.get('phases',{}).get(label,{}).get('phase_passed') is True for label in ['baseline','mutant','restored'])
            and report['aggregate'].get('actual_passed')==4 and report['aggregate'].get('actual_failed')==1 and report['aggregate'].get('actual_ignored')==0
            and report['aggregate'].get('actual_executed_nonignored')==5 and report['baseline_restored_binary_equal']
            and mutant_row.get('binary_before',{}).get('sha256')!=baseline_hash)
        report['expected_outcome_verified']=report['component_PFP_verified'];save(report);ensure(report['component_PFP_verified'],'fresh-five-body-PFP-required')
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
        report['actual_body_counts']=aggregate(allcases,5 if expected=='pfp' and mutation_attempted else (1 if expected=='red' else 2))
        for key in ['passed','failed','ignored','executed_nonignored']:report['actual_'+key]=report['actual_body_counts']['actual_'+key]
        if not report['runtime_attempted']:report['actual_executed_nonignored']=0
        report['qualification_passed']=False;save(report)
        ensure(report['source_final_pristine'] and report.get('baseline_binary_final_pristine',True),'final-source-binary-mode')
        if sys.exc_info()[0] is None:
            ensure(report.get('expected_outcome_verified') is True and not report['fallback_source_restore_used'] and not report['fallback_binary_copy_used'],'final-outcome-without-fallback-required')
            if expected=='pfp':ensure(report['component_PFP_verified'],'final-PFP-must-remain-qualified')

def main():
    p=argparse.ArgumentParser();p.add_argument('--preflight',action='store_true');p.add_argument('--cohort',choices=['default','experimental'],default='default');p.add_argument('--expected',choices=['red','green','pfp'],default='green');args=p.parse_args()
    report={'scope':'focused target-account ownership and explicit batch; optional five-body filter PFP','preflight':args.preflight,'cohort':args.cohort,'expected':args.expected,'runtime_attempted':False,'actual_executed_nonignored':0,
        'qualification_passed':False,'native_global_qualification':False,'automatic_retries':0,'stack_bytes':4194304,'Tokio_workers':2,'raw_output_retained':False}
    try:
        report['source_guard']=source_guard(args.preflight);save(report);report['parser_controls']=controls();report['PFP_metadata_controls']=pfp_metadata_controls();save(report)
        if not args.preflight:runtime(report,args.cohort,args.expected)
        report['controller_completed']=True;save(report)
    except Exception as error:report['controller_failure_type']=type(error).__name__;save(report);raise
    finally:report['final_HEAD_git_pristine']=subprocess.run(['git','diff','--quiet','HEAD']).returncode==0;save(report)
if __name__=='__main__':main()
