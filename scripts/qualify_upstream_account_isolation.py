#!/usr/bin/env python3
"""One real account-ownership regression; no retry, mutation or native qualification."""
import argparse, hashlib, json, os, re, shutil, stat, subprocess
from pathlib import Path
import qualify_upstream_storage_boundary as bounded
import qualify_upstream_storage_app_handles as counts
ensure=bounded.ensure
BASE='ebc97baf97d54e1162c6271e0862beb680febae0'
PARENT='a839cabf5a401f81bba53f22344e62346d6c4070'
REVIEWED_SOURCE='ebc97baf97d54e1162c6271e0862beb680febae0'
REVIEWED_FIXTURE_SHA='4d6da976cbf61415af5c299376b83a735bfc4decbe06e44f6f48927ed61e29e1'
WORKFLOW_SHA='38a141781e7ad6730af08c07c863dbfb9a14ae82ae025ed75fa7965c4133c445'
FIXTURE_SHA='4d6da976cbf61415af5c299376b83a735bfc4decbe06e44f6f48927ed61e29e1'
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
    for a,b in [(PARENT,REVIEWED_SOURCE),(REVIEWED_SOURCE,BASE)]:
        ensure(subprocess.run(['git','merge-base','--is-ancestor',a,b]).returncode==0,'reviewed-test-ancestry')
    ensure(set(git('diff','--name-only',PARENT,REVIEWED_SOURCE).decode().splitlines())=={FIXTURE}
        and set(git('diff','--name-only',PARENT,BASE).decode().splitlines())=={FIXTURE}
        and layout(REVIEWED_SOURCE)[FIXTURE][0]=='100644' and digest(git('show',REVIEWED_SOURCE+':'+FIXTURE))==REVIEWED_FIXTURE_SHA,'only-reviewed-test-source-before-hostformat')
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
        'old_guards_or_main_called':False,'old_module_globals_mutated':False,'historical_runtime_reused':False}

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

def compile_app(report,cohort,tracked):
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
        'compiler_sites':sites[:32],'closed_diagnostics_truncated':len(codes)>32 or len(sites)>32,'selected_test_artifact_count':len(selected),'features_requested':features};save(report)
    ensure(type(code) is int and code==0 and not errors and len(selected)==1,'one-successful-App-lib-compilation')
    artifact=selected[0];observed=artifact.get('features')
    ensure(type(observed) is list and all(type(v) is str for v in observed) and len(observed)==len(set(observed)) and set(observed)-{'default'}==set(features),'actual-App-unit-feature-cohort')
    binary=Path(artifact['executable']);ensure(binary.is_file() and not binary.is_symlink() and re.fullmatch(r'marmot_app-[0-9a-f]{16}',binary.name),'regular-App-test-binary')
    report['compiled_features']={'observed_own_unit_features':sorted(observed),'actual_test_profile':True,'all_Cargo_artifact_feature_manifest_sha256':digest(json.dumps([{'target':v['target']['name'],'features':v['features'],'profile':v['profile']} for v in artifacts],sort_keys=True).encode()),'full_dependency_feature_parity_claimed':False};save(report)
    return binary

def runtime(report,cohort,expected):
    frozen=physical();binary=None;before=None;mode=None
    try:
        free=shutil.disk_usage('.').free;report['free_bytes']=free;save(report);ensure(free>=8*1024**3,'remote-disk-reserve')
        binary=compile_app(report,cohort,set(frozen));before=digest(binary.read_bytes());mode=stat.S_IMODE(binary.stat().st_mode)
        report['binary_before']={'sha256':before,'mode':mode};save(report)
        for ignored in [False,True]:
            code,text,_=bounded.capture([str(binary),'--exact',NAME]+(['--ignored'] if ignored else [])+['--list','--format','terse'],60,limit=1024*1024)
            row=counts.parse_inventory(text,NAME,ignored);report.setdefault('inventory',{})['ignored' if ignored else 'normal']=row;save(report)
            ensure(code==0 and row['passed'],'one-normal-zero-ignored-exact-case')
        ensure(physical()==frozen and digest(binary.read_bytes())==before and stat.S_IMODE(binary.stat().st_mode)==mode,'prebody-source-binary-mode')
        report.update(runtime_attempted=True,actual_executed_nonignored=None);save(report)
        try:code,raw,seconds=bounded.capture([str(binary),'--exact',NAME,'--nocapture','--test-threads=1'],900,limit=8*1024*1024)
        except bounded.GateFailure as error:
            report['watchdog_triggered']=str(error)=='bounded-command-timeout';report['output_limit_triggered']=str(error)=='bounded-command-output-limit';save(report);raise
        report.update(body_exit_code=code,body_seconds=seconds,source_after_body_pristine=physical()==frozen,
            binary_after_sha256=digest(binary.read_bytes()) if binary.is_file() and not binary.is_symlink() else None,
            binary_after_mode=stat.S_IMODE(binary.stat().st_mode) if binary.is_file() and not binary.is_symlink() else None);save(report)
        basic=counts.parse_body(raw,code,NAME);report['basic_counts']=basic
        for dest,key in [('actual_passed','passed'),('actual_failed','failed'),('actual_ignored','ignored'),('actual_executed_nonignored','executed_nonignored')]:report[dest]=basic.get(key)
        report['actual_test_passed']=basic.get('passed_gate') is True;save(report)
        ensure(report['source_after_body_pristine'] and report['binary_after_sha256']==before and report['binary_after_mode']==mode,'postbody-source-binary-mode')
        report['outcome']=verdict(raw,code,basic,Path(FIXTURE).read_text(),expected);save(report)
        ensure(report['outcome']['expected_outcome_verified'],'actual-required-outcome-not-established')
    finally:
        report['source_final_pristine']=physical()==frozen
        if binary is not None:report['binary_final_pristine']=binary.is_file() and not binary.is_symlink() and digest(binary.read_bytes())==before and stat.S_IMODE(binary.stat().st_mode)==mode
        if not report['source_final_pristine'] or report.get('binary_final_pristine') is False:
            report['outcome_verified_before_pristine_failure']=report.get('outcome',{}).get('expected_outcome_verified');report.setdefault('outcome',{})['expected_outcome_verified']=False
        save(report);ensure(report['source_final_pristine'] and report.get('binary_final_pristine',True),'final-source-binary-mode')

def main():
    p=argparse.ArgumentParser();p.add_argument('--preflight',action='store_true');p.add_argument('--cohort',choices=['default','experimental'],default='default');p.add_argument('--expected',choices=['red','green'],default='red');args=p.parse_args()
    report={'scope':'one real target-account ownership regression','preflight':args.preflight,'cohort':args.cohort,'expected':args.expected,'runtime_attempted':False,'actual_executed_nonignored':0,
        'qualification_passed':False,'native_global_qualification':False,'automatic_retries':0,'stack_bytes':4194304,'Tokio_workers':2,'raw_output_retained':False}
    try:
        report['source_guard']=source_guard(args.preflight);save(report);report['parser_controls']=controls();save(report)
        if not args.preflight:runtime(report,args.cohort,args.expected)
        report['controller_completed']=True;save(report)
    except Exception as error:report['controller_failure_type']=type(error).__name__;save(report);raise
    finally:report['final_HEAD_git_pristine']=subprocess.run(['git','diff','--quiet','HEAD']).returncode==0;save(report)
if __name__=='__main__':main()
