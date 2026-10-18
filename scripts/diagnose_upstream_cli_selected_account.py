#!/usr/bin/env python3
"""One unchanged CLI integration case per cohort; no retry or global qualification."""
import argparse, hashlib, json, os, re, shutil, stat, subprocess
from pathlib import Path
import qualify_upstream_storage_boundary as bounded
import qualify_upstream_storage_app_handles as counts
ensure=bounded.ensure
BASE='3c40ff3cfefcd225062cc4e3c9dea789c9ffa190'
REF='refs/heads/ci/upstream-cli-selected-account-20261018'
SELF='scripts/diagnose_upstream_cli_selected_account.py'
WORKFLOW='.github/workflows/cli-selected-account.yml'
WORKFLOW_SHA='fcc9a35d7afca9403019b2b95727fb906b5d6d208ddcefe211b2c1a8464048e8'
FIXTURE='crates/cli/tests/cli.rs'
NAME='stream_start_quic_chunks_and_final_payload_verify_through_mls_messages'
SUITE='wn-cli::cli'
OUT=Path('cli-selected-account-evidence')
DEFAULT_FEATURES='wn-cli/test-policy-overrides'
EXPERIMENTAL_FEATURES='wn-cli/otlp-export,wn-cli/product-analytics-export,wn-cli/test-policy-overrides,marmot-app/experimental-device-sync,cgka-engine/test-policy-overrides,cgka-engine/test-crash-hooks'

def digest(data):return hashlib.sha256(data).hexdigest()
def git(*args):return subprocess.check_output(['git',*args])
def save(row):
    OUT.mkdir(mode=0o700,exist_ok=True);(OUT/'result.json').write_text(json.dumps(row,indent=2)+'\n')
def layout(ref):
    result={}
    for item in git('ls-tree','-r','-z',ref).split(b'\0'):
        if not item:continue
        meta,path=item.split(b'\t',1);mode,kind,sha=meta.decode().split()
        ensure(kind=='blob' and mode in {'100644','100755','120000'},'ordinary-source-layout')
        result[os.fsdecode(path)]=(mode,sha)
    return result

def physical():
    result={}
    for path,(mode,_) in layout('HEAD').items():
        p=Path(path);bits=p.lstat().st_mode;link=stat.S_ISLNK(bits)
        ensure(link==(mode=='120000') and (link or stat.S_ISREG(bits)),'physical-source-kind')
        result[path]=(mode,stat.S_IMODE(bits),digest(os.fsencode(os.readlink(p)) if link else p.read_bytes()))
    return result

def source_guard(preflight):
    head=git('rev-parse','HEAD').decode().strip()
    ensure(os.environ.get('GITHUB_ACTIONS')=='true' and os.environ.get('GITHUB_REPOSITORY')=='dyKiU/mdk'
        and os.environ.get('GITHUB_SHA')==head and os.environ.get('GITHUB_REF')==REF
        and os.environ.get('GITHUB_WORKFLOW_REF')=='dyKiU/mdk/'+WORKFLOW+'@'+REF
        and (os.environ.get('GITHUB_EVENT_NAME')=='workflow_dispatch' or (preflight and os.environ.get('GITHUB_EVENT_NAME')=='push'))
        and os.environ.get('UPSTREAM_CLI_SELECTED_ACCOUNT_BASELINE')==BASE,'exact-hosted-source-event')
    ensure(os.environ.get('CARGO_INCREMENTAL')=='1' and os.environ.get('CARGO_BUILD_JOBS')=='2'
        and os.environ.get('RUST_MIN_STACK')=='4194304'
        and all(os.environ.get(k)=='0' for k in ['CARGO_PROFILE_DEV_DEBUG','CARGO_PROFILE_TEST_DEBUG'])
        and all(not os.environ.get(k) for k in ['RUSTFLAGS','CARGO_ENCODED_RUSTFLAGS','RUSTC_BOOTSTRAP','CARGO_PROFILE_DEV_OPT_LEVEL','CARGO_PROFILE_TEST_OPT_LEVEL']),'fixed-build-cohort')
    ensure(type(WORKFLOW_SHA)is str and re.fullmatch('[0-9a-f]{64}',WORKFLOW_SHA)
        and subprocess.run(['git','merge-base','--is-ancestor',BASE,head]).returncode==0,'pinned-workflow-and-BASE-ancestor')
    baseline=layout(BASE);current=layout('HEAD')
    ensure(SELF not in baseline and WORKFLOW not in baseline and set(current)==set(baseline)|{SELF,WORKFLOW},'only-two-owned-metadata')
    ensure(subprocess.run(['git','diff','--quiet','HEAD']).returncode==0,'HEAD-pristine')
    for path,(mode,_) in current.items():
        expected=baseline.get(path,('100644',None));p=Path(path);bits=p.lstat().st_mode;link=stat.S_ISLNK(bits)
        ensure(mode==expected[0] and link==(mode=='120000') and (link or stat.S_ISREG(bits))
            and (link or bool(bits&0o111)==(mode=='100755')),'whole-source-modes')
        data=os.fsencode(os.readlink(p)) if link else p.read_bytes()
        if expected[1]is not None:ensure(hashlib.sha1(b'blob '+str(len(data)).encode()+b'\0'+data).hexdigest()==expected[1],'whole-BASE-content')
    ensure(digest(Path(WORKFLOW).read_bytes())==WORKFLOW_SHA,'exact-owned-workflow')
    ensure(set(git('ls-files','--others','--exclude-standard').decode().splitlines())<={str(OUT/'result.json')},'no-foreign-untracked')
    return {'head':head,'baseline':BASE,'whole_source_and_modes':True,'Rust_exceptions':[],
        'fixture_sha256':digest(Path(FIXTURE).read_bytes()),'old_guards_main_or_globals_used':False}

def version_record(raw,code):
    if type(code)is not int or code!=0:return False
    short='cargo-nextest 0.9.132'
    public='cargo-nextest 0.9.132 (6e4a9d6f2 2026-03-20)\nrelease: 0.9.132\ncommit-hash: 6e4a9d6f2c4964f30ff54a8cd5466f8869267daa\ncommit-date: 2026-03-20\nhost: x86_64-unknown-linux-gnu'
    return raw in {short,short+'\n',public,public+'\n',public.split('\n')[0],public.split('\n')[0]+'\n'}

def features(cohort):return DEFAULT_FEATURES if cohort=='default' else EXPERIMENTAL_FEATURES

def cargo_args(cohort):
    # Feature matching is against selected members and their direct dependencies.
    # --test cli is one aggregate named-target filter, not one target per package.
    return ['--locked','-p','wn-cli']+(['-p','marmot-app'] if cohort=='experimental' else [])+['--test','cli','--features',features(cohort)]

def cargo_setup_diagnostics(raw):
    text=re.sub(r'\x1b\[[0-?]*[ -/]*[@-~]','',raw)
    # Pinned Cargo source-owned prefixes only; never retain feature/package suffixes.
    patterns={
        'selected_wn_cli_missing_features':r"(?m)^error: the package 'wn-cli' does not contain (?:this feature|these features): [^\n]+$",
        'selected_packages_missing_features':r'(?m)^error: none of the selected packages contains (?:this feature|these features): [^\n]+$',
        'named_cli_test_target_missing':r'(?m)^error: no test target named `cli`(?: in `[^`\n]+`(?:, \.\.\.)? packages?)?[^\n]*$',
        'features_outside_workspace':r'(?m)^error: cannot specify features for packages outside of workspace[^\n]*$',
    }
    return {'fixed_error_families':{name:bool(re.search(pattern,text)) for name,pattern in patterns.items()},
        'captured_bytes':len(raw.encode()),'raw_text_or_dynamic_suffix_exported':False,
        'unmatched_setup_cause_is_unknown':True}

def inventory_json(raw):
    decoder=json.JSONDecoder();objects=[]
    for match in re.finditer(r'(?m)^\{',raw):
        try:value,_=decoder.raw_decode(raw[match.start():])
        except ValueError:continue
        objects.append(value)
    ensure(len(objects)==1 and type(objects[0])is dict and type(objects[0].get('rust-suites'))is dict,'one-nextest-inventory-root')
    return objects[0]

def suite_inventory(value):
    ensure(type(value)is dict and type(value.get('rust-suites'))is dict,'nextest-inventory-root')
    selected=[]
    for suite in value['rust-suites'].values():
        for name,case in suite.get('testcases',{}).items():
            if case.get('filter-match',{}).get('status')=='matches':selected.append((suite,name,case))
    ensure(len(selected)==1,'exact-one-selected-integration-case')
    suite,name,case=selected[0]
    ensure(name==NAME and suite.get('package-name')=='wn-cli' and suite.get('binary-name')=='cli'
        and suite.get('binary-id')==SUITE and suite.get('kind')=='test' and case.get('ignored')is False,'exact-CLI-suite-name-kind')
    return suite

def summary(raw,code):
    text=re.sub(r'\x1b\[[0-?]*[ -/]*[@-~]','',raw)
    lines=re.findall(r'(?m)^\s*Summary\s*\[[^\]\n]{1,40}\]\s*([0-9]+) tests? run: ([0-9]+) passed(?: \(([0-9]+) slow\))?(?:, ([0-9]+) failed)?, ([0-9]+) skipped\s*$',text)
    # Pinned nextest places optional progress counter AFTER duration, BEFORE suite.
    # This exact one-case/retries0 run permits only the actual (1/1) counter.
    events=re.findall(r'(?m)^\s*(PASS|FAIL|TIMEOUT|LEAK|EXECFAIL)\s*\[[^\]\n]{1,40}\]\s*(?:\(1/1\)\s+)?'+re.escape(SUITE)+r'\s+'+re.escape(NAME)+r'\s*$',text)
    plain=re.findall(r'(?m)^\s*(?:PASS|FAIL|TIMEOUT|LEAK|EXECFAIL)\s*\[[^\]\n]{1,40}\]\s*'+re.escape(SUITE)+r'\s+'+re.escape(NAME)+r'\s*$',text)
    counted=re.findall(r'(?m)^\s*(?:PASS|FAIL|TIMEOUT|LEAK|EXECFAIL)\s*\[[^\]\n]{1,40}\]\s*\(1/1\)\s+'+re.escape(SUITE)+r'\s+'+re.escape(NAME)+r'\s*$',text)
    named_candidates=re.findall(r'(?m)^\s*(?:PASS|FAIL|TIMEOUT|LEAK|EXECFAIL)\s+[^\n]*\s'+re.escape(SUITE)+r'\s+'+re.escape(NAME)+r'\s*$',text)
    p=f=i=n=slow=None
    if len(lines)==1:
        n,p,slow,f,i=(int(v or '0') for v in lines[0])
        if n!=p+f or slow>p:n=p=f=i=None
    actual={'actual_counts_complete':n is not None,'passed':p,'failed':f,'skipped':i,'executed_nonignored':n,
        'passed_slow':slow,'runner_skips_are_not_selected_ignored':True,'selected_name_status_count':len(events),'selected_name_status':events[0] if len(events)==1 else None,'exit_code':code}
    actual['summary_one_body_passed']=(type(code)is int and code==0 and n==1 and p==1 and f==0)
    actual['named_status_layout']={'plain_count':len(plain),'one_of_one_counter_count':len(counted),
        'fixed_status_exact_name_candidate_count':len(named_candidates),'unrecognized_layout_is_unknown':True,'raw_line_exported':False}
    actual['original_case_passed']=actual['summary_one_body_passed'] and events==['PASS'] and len(named_candidates)==1
    return actual

def skip_count_matches_inventory(basic,expected):
    return type(expected)is int and expected>=0 and type(basic.get('skipped'))is int and basic['skipped']==expected

def closed_failure(raw,tracked):
    text=re.sub(r'\x1b\[[0-?]*[ -/]*[@-~]','',raw)
    sites=[]
    for path,line,column in re.findall(r'(?m)^thread [^\n]{1,240} panicked at ([A-Za-z0-9_./-]+):([0-9]+):([0-9]+):$',text):
        if path in tracked:sites.append({'file':path,'line':int(line),'column':int(column)})
    # Exact original watcher assertion only; arbitrary command summaries remain uninspected.
    blocks=re.findall(r"thread '[^\n]{1,240}'(?: \([1-9][0-9]*\))? panicked at crates/cli/tests/cli.rs:4036:5:\nstream watcher failed\n(.*?)(?=\n\s*stderr=)",text,re.S)
    code=category=stage=None
    if len(blocks)==1 and len(blocks[0].encode())<=65536:
        found=re.search(r'(?m)^stdout=(.*)$',blocks[0])
        if found:
            try:
                value=json.loads(found[1]);error=value.get('error') if type(value)is dict and value.get('ok')is False else None
                if type(error)is dict and error.get('code')=='command_failed':
                    code='command_failed';message=error.get('message')
                    if message=='blocking app task failed: account worker startup retry deferred by backoff':category='startup_retry_deferred'
                    for token in ['spawned','open_queued','account_state','session_open','client_restore','ready_handoff']:
                        if message=='blocking app task failed: account worker startup timed out at '+token:category='account_startup_timed_out';stage=token
            except (ValueError,TypeError):pass
    return {'tracked_panic_sites':sites[:16],'sites_truncated':len(sites)>16,'watcher_error_code':code,'watcher_static_category':category,
        'startup_stage':stage,'missing_cause_is_unknown':True,'raw_messages_or_suffixes_exported':False}

def controls():
    ensure(cargo_args('default')==['--locked','-p','wn-cli','--test','cli','--features',DEFAULT_FEATURES],'default-selection-unchanged')
    ensure(cargo_args('experimental')==['--locked','-p','wn-cli','-p','marmot-app','--test','cli','--features',EXPERIMENTAL_FEATURES],'experimental-selected-App-keeps-six-features')
    private_cargo="\x1b[31merror: the package 'wn-cli' does not contain these features: PRIVATE_SENTINEL\x1b[0m\n"
    diagnostic=cargo_setup_diagnostics(private_cargo)
    ensure(diagnostic['fixed_error_families']['selected_wn_cli_missing_features'] and 'PRIVATE_SENTINEL' not in json.dumps(diagnostic),'closed-Cargo-prefix-privacy')
    for text,key in [('error: none of the selected packages contains this feature: PRIVATE\n','selected_packages_missing_features'),('error: no test target named `cli` in `wn-cli`, ... packages\n','named_cli_test_target_missing'),('error: cannot specify features for packages outside of workspace\n','features_outside_workspace')]:
        ensure(cargo_setup_diagnostics(text)['fixed_error_families'][key],'closed-Cargo-family-positive')
    for text in ['PRIVATE_SENTINEL','error: the package \'foreign\' does not contain this feature: private','note: the package \'wn-cli\' does not contain this feature: private','error: no test target named `foreign`']:
        ensure(not any(cargo_setup_diagnostics(text)['fixed_error_families'].values()),'foreign-Cargo-family-unknown')
    good='PASS [ 1.000s] '+SUITE+' '+NAME+'\nSummary [ 1.001s] 1 test run: 1 passed, 0 skipped\n'
    counter=good.replace(SUITE+' '+NAME,'(1/1) '+SUITE+' '+NAME)
    ensure(summary(counter,0)['original_case_passed'],'one-of-one-counter-positive')
    ensure(summary(counter.replace('0 skipped','103 skipped').replace('1 passed','1 passed (1 slow)'),0)['original_case_passed'],'counter-slow-filtered-positive')
    ensure(summary(counter,0)['named_status_layout']['one_of_one_counter_count']==1,'closed-counter-layout-positive')
    for text in [counter.replace('(1/1)','(0/1)'),counter.replace('(1/1)','(1/2)'),counter.replace('(1/1)','(2/1)'),counter.replace('(1/1)','(1 /1)'),counter.replace('(1/1)','PRIVATE'),counter+counter]:
        ensure(not summary(text,0)['original_case_passed'],'non-one-case-layout-negative')
    ensure(not summary(good+'PASS [ 1.000s] (1/2) '+SUITE+' '+NAME+'\n',0)['original_case_passed'],'mixed-valid-and-unknown-exact-name-status-negative')
    unknown_layout=summary(counter.replace('(1/1)','PRIVATE_SENTINEL'),0)
    ensure(unknown_layout['summary_one_body_passed'] and not unknown_layout['original_case_passed'] and 'PRIVATE_SENTINEL' not in json.dumps(unknown_layout),'actual-summary-pass-retained-layout-unknown-private')
    ensure(summary(good.replace('0 skipped','23 skipped'),0)['original_case_passed'],'normal-filtered-skips-positive')
    ensure(summary(good.replace('1 passed','1 passed (1 slow)'),0)['original_case_passed'],'passed-slow-positive')
    filtered=summary(good.replace('0 skipped','23 skipped'),0)
    ensure(skip_count_matches_inventory(filtered,23) and not skip_count_matches_inventory(filtered,22),'exact-filtered-skip-inventory-controls')
    ensure(not summary(good.replace('1 passed','1 passed (2 slow)'),0)['original_case_passed'],'impossible-slow-negative')
    bad=good.replace('PASS [','FAIL [').replace('1 passed, 0 skipped','0 passed, 1 failed, 0 skipped')
    ensure(summary(good,0)['original_case_passed'] and summary(bad,100)['failed']==1,'summary-positive')
    for text,code in [(good,100),(good+good,0),(good.replace(NAME,'foreign'),0),(good.replace('1 test run','0 tests run'),0),('',0)]:
        ensure(not summary(text,code)['original_case_passed'],'summary-negative')
    suite={'package-name':'wn-cli','binary-name':'cli','binary-id':SUITE,'kind':'test','testcases':{NAME:{'ignored':False,'filter-match':{'status':'matches'}}}}
    ensure(suite_inventory(inventory_json('Finished normal build\n'+json.dumps({'rust-suites':{'one':suite}})))==suite,'inventory-positive')
    try:inventory_json(json.dumps({'rust-suites':{}})+'\n'+json.dumps({'foreign':{}}))
    except ValueError:pass
    else:raise ValueError('extra-inventory-root-accepted')
    for replacement in [{'package-name':'foreign'},{'kind':'lib'},{'binary-id':'foreign'}]:
        wrong=dict(suite,**replacement)
        try:suite_inventory({'rust-suites':{'one':wrong}})
        except ValueError:continue
        raise ValueError('foreign-suite-accepted')
    private="thread '"+NAME+"' panicked at crates/cli/tests/cli.rs:4036:5:\nstream watcher failed\nstdout="+json.dumps({'ok':False,'error':{'code':'command_failed','message':'blocking app task failed: PRIVATE_SENTINEL'}})+'\nstderr=\n'
    ensure('PRIVATE_SENTINEL' not in json.dumps(closed_failure(private,{FIXTURE})),'private-suffix-not-exported')
    ensure(version_record('cargo-nextest 0.9.132\n',0) and not version_record('cargo-nextest 0.9.132\nPRIVATE',0) and not version_record('cargo-nextest 0.9.131\n',0),'version-controls')
    return {'status_counter_positive':3,'status_counter_negative':7,'status_layout_unknown_privacy':1,'Cargo_argument_controls':2,'Cargo_setup_family_positive':4,'Cargo_setup_family_negative':4,'Cargo_setup_privacy':1,'version_positive':1,'version_negative':2,'summary_positive':4,'summary_negative':6,'inventory_skip_match_positive':1,'inventory_skip_match_negative':1,'inventory_positive':1,'inventory_negative':3,'privacy':1,'count_helpers':counts.parser_controls(),'runtime_bodies':0}

def compile_case(row,cohort,tracked):
    args=cargo_args(cohort)
    command=['cargo','test',*args[:-2],'--no-run','--message-format=json',*args[-2:]]
    code,raw,seconds=bounded.capture(command,1800,limit=8*1024*1024)
    events=[];bad_json=0
    for line in raw.splitlines():
        if not line.startswith('{'):continue
        try:events.append(json.loads(line))
        except ValueError:bad_json+=1
    errors=[v for v in events if v.get('reason')=='compiler-message' and v.get('message',{}).get('level')=='error']
    complete=any(v.get('reason')=='build-finished' for v in events) and bad_json==0
    codes=sorted({v['message']['code']['code'] for v in errors if type(v.get('message',{}).get('code'))is dict and re.fullmatch('E[0-9]{4}',v['message']['code'].get('code',''))})
    sites=[{'file':s['file_name'],'line':s['line_start'],'column':s['column_start']} for v in errors for s in v.get('message',{}).get('spans',[]) if s.get('file_name')in tracked and s.get('is_primary')is True]
    row['compilation']={'command':command,'exit_code':code,'seconds':seconds,'compiler_error_count':len(errors) if complete else None,'compiler_codes':codes[:32],'compiler_sites':sites[:32],'closed_sites_truncated':len(sites)>32,'raw_output_retained':False,'build_finished_observed':any(v.get('reason')=='build-finished' for v in events),'malformed_JSON_lines':bad_json,'setup_diagnostics':cargo_setup_diagnostics(raw)};save(row)
    ensure(type(code)is int and code==0 and complete and not errors,'successful-complete-compile-JSON')
    artifacts=[v for v in events if v.get('reason')=='compiler-artifact']
    required={'test':lambda v:v.get('target',{}).get('name')=='cli' and v['target'].get('kind')==['test'] and v.get('profile',{}).get('test')is True,
        'wn':lambda v:v.get('target',{}).get('name')=='wn' and v['target'].get('kind')==['bin'] and v.get('profile',{}).get('test')is False}
    result={};expected={'test-policy-overrides'}|({'otlp-export','product-analytics-export'} if cohort=='experimental' else set())
    target=Path(os.environ.get('CARGO_TARGET_DIR','target')).resolve()
    for label,predicate in required.items():
        found=[v for v in artifacts if predicate(v) and v.get('executable')]
        ensure(len(found)==1,'one-integration-and-normal-child-artifact');value=found[0];binary=Path(value['executable'])
        observed=value.get('features');ensure(type(observed)is list and all(type(v)is str for v in observed) and set(observed)-{'default'}==expected,'actual-own-artifact-features')
        ensure(binary.is_file() and not binary.is_symlink() and binary.resolve().is_relative_to(target),'regular-target-owned-binary')
        result[label]=binary
    for name in ['marmot_app','cgka_engine']:
        choices=[v for v in artifacts if v.get('target',{}).get('name')==name and v['target'].get('kind')==['lib']]
        ensure(choices and all('test-policy-overrides'in v.get('features',[]) for v in choices),'actual-dependency-policy-feature')
        if name=='marmot_app':ensure(all(('experimental-device-sync'in v.get('features',[]))==(cohort=='experimental') for v in choices),'actual-App-experimental-feature')
        if name=='cgka_engine' and cohort=='experimental':ensure(all('test-crash-hooks'in v.get('features',[]) for v in choices),'actual-engine-crash-feature')
    row['artifact_features']={'own_expected':sorted(expected),'test_and_wn_observed':True,'App_experimental':cohort=='experimental','engine_crash_required':cohort=='experimental','all_artifact_features_digest':digest(json.dumps([{'target':v['target']['name'],'features':v['features']} for v in artifacts],sort_keys=True).encode()),'unmeasured_full_workspace_parity':True};save(row)
    return result

def binary_state(binaries):
    return {name:{'path':str(p),'sha256':digest(p.read_bytes()),'mode':stat.S_IMODE(p.stat().st_mode)} for name,p in binaries.items() if p.is_file() and not p.is_symlink()}

def runtime(row,cohort):
    frozen=physical();binaries={};before=None
    try:
        ensure(shutil.disk_usage('.').free>=8*1024**3,'remote-disk-reserve')
        version_code,version,_=bounded.capture(['cargo-nextest','nextest','--version'],30,limit=4096)
        row['runner_version']={'exit_code':version_code,'captured_bytes':len(version.encode()),'closed_record_valid':version_record(version,version_code)};save(row)
        ensure(row['runner_version']['closed_record_valid'],'pinned-nextest-version')
        binaries=compile_case(row,cohort,set(frozen));before=binary_state(binaries);row['binaries_before']=before;save(row)
        for ignored in [False,True]:
            code,text,_=bounded.capture([str(binaries['test']),'--exact',NAME]+(['--ignored'] if ignored else [])+['--list','--format','terse'],60,limit=1024*1024)
            item=counts.parse_inventory(text,NAME,ignored);row.setdefault('libtest_inventory',{})['ignored' if ignored else 'normal']=item;save(row);ensure(code==0 and item['passed'],'normal-one-ignored-zero')
        args=cargo_args(cohort)
        filterset='package(wn-cli) & binary(cli) & test(='+NAME+')'
        code,raw,_=bounded.capture(['cargo-nextest','nextest','list',*args,'-E',filterset,'--message-format','json'],600,limit=8*1024*1024)
        ensure(code==0,'nextest-list-success');inventory=inventory_json(raw);suite=suite_inventory(inventory)
        all_cases=sum(len(item.get('testcases',{})) for item in inventory['rust-suites'].values());expected_skipped=all_cases-1
        ensure(expected_skipped>=0,'positive-inventory-population')
        ensure(Path(suite['binary-path']).resolve()==binaries['test'].resolve(),'same-actual-selected-binary')
        row['nextest_inventory']={'package':'wn-cli','binary_id':SUITE,'binary_name':'cli','kind':'test','name':NAME,'selected_nonignored':1,'selected_ignored':0,'all_enumerated_cases':all_cases,'expected_unselected_runner_skips':expected_skipped};save(row)
        ensure(physical()==frozen and binary_state(binaries)==before,'prebody-source-both-binaries-pristine')
        profile='ci' if cohort=='default' else 'm5-bounded'
        command=['cargo-nextest','nextest','run',*args,'-E',filterset,'--profile',profile,'--retries','0','--test-threads','1','--success-output','immediate','--failure-output','immediate']
        row.update(runtime_attempted=True,actual_executed_nonignored=None,nextest_profile=profile,body_command=command);save(row)
        try:code,raw,seconds=bounded.capture(command,900,limit=8*1024*1024)
        except bounded.GateFailure as error:
            row['watchdog_triggered']=str(error)=='bounded-command-timeout';row['output_limit_triggered']=str(error)=='bounded-command-output-limit';save(row);raise
        row.update(body_exit_code=code,body_seconds=seconds,source_after_body_pristine=physical()==frozen,binaries_after=binary_state(binaries));save(row)
        basic=summary(raw,code);row['basic_counts']=basic
        for key in ['passed','failed','executed_nonignored']:row['actual_'+key]=basic[key]
        row['actual_runner_filtered_skipped']=basic['skipped'];row['selected_ignored_from_inventory']=0
        row['actual_summary_case_passed']=basic['summary_one_body_passed'];row['actual_original_case_passed']=basic['original_case_passed'];save(row)
        row['closed_failure']=closed_failure(raw,set(frozen));save(row)
        ensure(row['source_after_body_pristine'] and row['binaries_after']==before,'postbody-source-both-binaries')
        row['runner_skips_match_inventory']=skip_count_matches_inventory(basic,expected_skipped)
        row['focused_component_verified']=basic['original_case_passed'] and row['runner_skips_match_inventory'];save(row);ensure(row['focused_component_verified'],'original-full-CLI-case-must-pass')
    finally:
        row['source_final_pristine']=physical()==frozen
        row['binaries_final_pristine']=binary_state(binaries)==before if before is not None else None
        if not row['source_final_pristine'] or row['binaries_final_pristine']is False:row['focused_component_verified']=False
        save(row);ensure(row['source_final_pristine'] and row['binaries_final_pristine']is not False,'final-source-both-binaries')

def main():
    parser=argparse.ArgumentParser();parser.add_argument('--preflight',action='store_true');parser.add_argument('--cohort',choices=['default','experimental'],default='default');args=parser.parse_args()
    row={'scope':'one unchanged full original CLI watcher case','cohort':args.cohort,'runtime_attempted':False,'actual_executed_nonignored':0,'focused_component_verified':False,'native_global_qualification':False,'qualification_passed':False,'raw_protocol_output_retained':False,'automatic_retries':0,'CLI_causal_relation_claimed':False,'global_ignored_count':None}
    try:
        row['source_guard']=source_guard(args.preflight);save(row);row['controls']=controls();save(row)
        if not args.preflight:runtime(row,args.cohort)
        row['controller_completed']=True;save(row)
    except Exception as error:row['controller_failure_type']=type(error).__name__;save(row);raise
    finally:row['final_HEAD_pristine']=subprocess.run(['git','diff','--quiet','HEAD']).returncode==0;save(row)
if __name__=='__main__':main()
