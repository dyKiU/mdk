#!/usr/bin/env python3
"""One existing SDK history test; loss observations are diagnostic, never qualification."""
import argparse,hashlib,json,os,re,shutil,stat,subprocess
from pathlib import Path
import qualify_upstream_storage_boundary as bounded
import qualify_upstream_storage_app_handles as counts
ensure=bounded.ensure
def digest(data):return hashlib.sha256(data).hexdigest()
BASE='ccb839af8771b759daa7cd446d2bf8f9a68a36ee'
MANIFEST_SHA='854e158179c7904b0d9d91273d854c8ea804389d2981b1c98697735ed7b1198a'
SELF='scripts/diagnose_upstream_history_paging_loss.py'
MANIFEST='scripts/history_paging_loss_source_manifest.json'
WORKFLOW='.github/workflows/experimental-sync-ci.yml'
REF='refs/heads/ci/upstream-history-paging-loss-20261018'
BEGIN='  # HISTORY_PAGING_LOSS_JOBS_BEGIN\n';END='  # HISTORY_PAGING_LOSS_JOBS_END\n'
OPTIONS='options: [history-paging-loss-preflight, history-paging-loss-runtime, '
OUT=Path('history-paging-loss-evidence')
NAME='stored_replay_beyond_500_is_paged_before_counting_complete'
PACKAGE='transport-nostr-adapter';UNIT='relay_limit_subscriptions'
U64=2**64-1;N=r'(?:0|[1-9][0-9]{0,19})'

def git(*args):return subprocess.check_output(['git',*args])
def save(report):
    OUT.mkdir(exist_ok=True);(OUT/'result.json').write_text(json.dumps(report,indent=2)+'\n')
def layout(ref):
    result={}
    for item in git('ls-tree','-r','-z',ref).split(b'\0'):
        if item:
            meta,path=item.split(b'\t',1);mode,kind,sha=meta.decode().split();name=os.fsdecode(path)
            ensure(kind=='blob' and mode in {'100644','100755','120000'},'ordinary-whole-source-layout')
            result[name]=(mode,sha)
    return result

def physical():
    rows={}
    for path,(mode,_) in layout('HEAD').items():
        p=Path(path);s=p.lstat();link=stat.S_ISLNK(s.st_mode)
        ensure(link==(mode=='120000') and (link or stat.S_ISREG(s.st_mode)),'physical-file-kind')
        data=os.fsencode(os.readlink(p)) if link else p.read_bytes()
        rows[path]=(mode,stat.S_IMODE(s.st_mode),digest(data))
    return rows

def changed(a,b):return set(git('diff','--name-only',a,b).decode().splitlines())
def source_guard():
    head=git('rev-parse','HEAD').decode().strip()
    ensure(os.environ.get('GITHUB_ACTIONS')=='true' and os.environ.get('GITHUB_REPOSITORY')=='dyKiU/mdk'
        and os.environ.get('GITHUB_EVENT_NAME')=='workflow_dispatch' and os.environ.get('GITHUB_SHA')==head
        and os.environ.get('GITHUB_REF')==REF and os.environ.get('GITHUB_WORKFLOW_REF')=='dyKiU/mdk/'+WORKFLOW+'@'+REF
        and os.environ.get('UPSTREAM_HISTORY_PAGING_LOSS_BASELINE')==BASE,'exact-history-paging-loss-remote-source')
    ensure(os.environ.get('CARGO_INCREMENTAL')=='1' and os.environ.get('CARGO_BUILD_JOBS')=='2' and 'RUST_MIN_STACK' not in os.environ
        and all(os.environ.get(k)=='0' for k in ['CARGO_PROFILE_DEV_DEBUG','CARGO_PROFILE_TEST_DEBUG'])
        and all(not os.environ.get(k) for k in ['RUSTFLAGS','CARGO_ENCODED_RUSTFLAGS','RUSTC_BOOTSTRAP','CARGO_PROFILE_DEV_OPT_LEVEL','CARGO_PROFILE_TEST_OPT_LEVEL']),'exact-build-cohort')
    ensure(type(MANIFEST_SHA) is str and re.fullmatch('[0-9a-f]{64}',MANIFEST_SHA) and digest(Path(MANIFEST).read_bytes())==MANIFEST_SHA,'reviewed-manifest-required')
    manifest=json.loads(Path(MANIFEST).read_text());ensure(manifest['baseline']==BASE,'manifest-BASE')
    for a,b in [(manifest['parent'],manifest['reviewed_source']),(manifest['reviewed_source'],BASE),(BASE,head)]:
        ensure(subprocess.run(['git','merge-base','--is-ancestor',a,b]).returncode==0,'source-ancestry')
    pins=manifest['paths'];ensure(len(pins)==1 and changed(manifest['parent'],manifest['reviewed_source'])==set(pins)
        and changed(manifest['parent'],BASE)==set(pins),'only-one-reviewed-passive-path')
    for path,pin in pins.items():
        for ref,key in [(manifest['parent'],'before'),(manifest['reviewed_source'],'reviewed_after'),(BASE,'baseline_after')]:
            entries=layout(ref)
            if pin[key] is None:ensure(path not in entries,'new-leaf-was-absent')
            else:ensure(entries.get(path,(None,None))[0]=='100644' and digest(git('show',ref+':'+path))==pin[key],'exact-reviewed-raw-source-blob')
    baseline=layout(BASE);current=layout('HEAD')
    ensure(SELF not in baseline and MANIFEST not in baseline and set(current)==set(baseline)|{SELF,MANIFEST},'whole-source-only-two-owned-metadata')
    ensure(subprocess.run(['git','diff','--quiet','HEAD']).returncode==0,'whole-HEAD-pristine')
    for path,(mode,sha) in current.items():
        expected=baseline.get(path,('100644',None));p=Path(path);link=p.is_symlink()
        ensure(mode==expected[0] and link==(mode=='120000') and (link or (bool(p.stat().st_mode&0o111)==(mode=='100755'))),'whole-source-modes')
        data=os.fsencode(os.readlink(p)) if link else p.read_bytes()
        if path==WORKFLOW:
            text=data.decode();ensure(text.count(BEGIN)==text.count(END)==text.count(OPTIONS)==1,'one-owned-workflow-overlay')
            before,rest=text.split(BEGIN);_,after=rest.split(END)
            data=(before+after).replace(OPTIONS,'options: [',1).encode()
        if expected[1] is not None:ensure(hashlib.sha1(b'blob '+str(len(data)).encode()+b'\0'+data).hexdigest()==expected[1],'whole-BASE-content')
    allowed={str(OUT/'result.json'),str(OUT/'formatting.patch')}
    ensure(set(git('ls-files','--others','--exclude-standard').decode().splitlines())<=allowed,'no-unowned-untracked-source')
    return {'head':head,'baseline':BASE,'reviewed_source':manifest['reviewed_source'],'whole_source_modes_verified':True,'Rust_exceptions':[],
        'old_guards_or_main_called':False,'old_module_globals_mutated':False,'historical_runtime_reused':False}


def number(text):
    value=int(text);ensure(value<=U64,'bounded-u64');return value

def replay_rows(raw):
    text=re.sub(r'\x1b\[[0-9;]*m','',raw)
    text=re.sub(r'(?m)^test '+re.escape(NAME)+r' \.\.\. (?=\[h(?:-loss)?\] )','',text)
    original=[line for line in text.splitlines() if line.startswith('[h]')]
    loss_lines=[line for line in text.splitlines() if '[h-loss]' in line]
    ensure(len(original)<=2 and len(loss_lines)==len(original),'at-most-two-corresponding-cohorts')
    rows=[]
    for index,(line,lossline) in enumerate(zip(original,loss_lines)):
        expected='None' if index==0 else 'Some(500)'
        m=re.match(r'^\[h\] clamp=(None|Some\(500\)) stored=1200 delivered=('+N+r') complete=(true|false) reqs=',line)
        ensure(m is not None and m[1]==expected and number(m[2])<=1200,'original-closed-history-prefix')
        k=re.fullmatch(r'\[h-loss\] clamp=(None|Some\(500\)) stored=1200 loss=(None|Some\(None\)|Some\(Some\(\(('+N+r'), ('+N+r')\)\)\)) forwarder_finished=(true|false)',lossline)
        ensure(k is not None and k[1]==expected and len(lossline.encode())<=256,'matching-closed-loss-row')
        observation=None
        if k[2]=='Some(None)':observation={'getter_available':True,'recorded_gap':False,'no_gap_is_not_complete_delivery':True}
        elif k[2]!='None':
            generation,skipped=number(k[3]),number(k[4]);ensure(skipped>0,'recorded-loss-has-positive-count')
            observation={'getter_available':True,'recorded_gap':True,'receiver_generation':generation,'cumulative_skipped':skipped}
        rows.append({'clamp':None if index==0 else 500,'stored':1200,'actual_distinct_delivered':int(m[2]),'coverage_complete':m[3]=='true',
            'loss_observation':observation,'getter_unavailable_is_unknown':True,'forwarder_finished':k[5]=='true',
            'independent_snapshots':True,'loss_scope_identifiers_exported':False,'relay_stats_suffix_not_exported_or_classified':True})
    return {'schema_complete':True,'observed':bool(rows),'cohorts':rows,'unreached_clamped_cohort_is_unknown':True,'cause_proven':False}

def rows_fixture(clamp='None',loss='Some(None)',delivered=1200,complete='true',finished='false'):
    return f'[h] clamp={clamp} stored=1200 delivered={delivered} complete={complete} reqs=2\n[h-loss] clamp={clamp} stored=1200 loss={loss} forwarder_finished={finished}\n'

def select_inventory(raw):
    text=re.sub(r'\x1b\[[0-9;]*m','',raw);decoder=json.JSONDecoder();objects=[]
    for m in re.finditer(r'(?m)^\{',text):
        try:obj,_=decoder.raw_decode(text[m.start():])
        except (ValueError,TypeError):continue
        if type(obj) is dict and type(obj.get('rust-suites')) is dict:objects.append(obj)
    ensure(len(objects)==1,'one-valid-compile-inventory-JSON-object')
    return objects[0]

def compiler(raw,tracked):
    text=re.sub(r'\x1b\[[0-9;]*m','',raw)
    codes=sorted(set(re.findall(r'(?m)^error\[(E[0-9]{4})\]',text)))
    sites=[{'file':p,'line':int(l),'column':int(c)} for p,l,c in re.findall(r'(?m)^\s*--> (crates/[A-Za-z0-9_./-]+\.rs):([0-9]{1,7}):([0-9]{1,7})',text) if p in tracked]
    return {'compiler_error_count':len(re.findall(r'(?m)^error(?:\[E[0-9]{4}\])?:',text)),'compiler_codes':codes[:32],
        'compiler_code_distinct_count':len(codes),'compiler_codes_truncated':len(codes)>32,'compiler_sites':sites[:32],
        'compiler_site_count':len(sites),'compiler_sites_truncated':len(sites)>32,'raw_headers_retained':False}

def own_features(binary):
    match=re.fullmatch(re.escape(UNIT)+r'-([0-9a-f]{16})',binary.name);ensure(match is not None,'actual-integration-binary-suffix')
    path=binary.parent.parent/'.fingerprint'/(PACKAGE+'-'+match[1])/('test-integration-test-'+UNIT+'.json')
    ensure(path.is_file() and not path.is_symlink(),'actual-unit-fingerprint')
    data=path.read_bytes();value=json.loads(data);features=json.loads(value['features'])
    ensure(type(features) is list and all(type(v) is str for v in features) and len(features)==len(set(features))
        and set(features)-{'default'}=={'sdk','test-policy-overrides'},'actual-own-feature-cohort')
    return {'unit_json':str(path.relative_to(Path.cwd())) if path.is_absolute() else str(path),'sha256':digest(data),'features':sorted(features),
        'empty_default_marker_present':'default' in features,'full_workspace_dependency_feature_parity_verified':False,'producer_binary_reused':False}

def controls():
    raw=rows_fixture();bad=[raw+raw,raw.replace('stored=1200','stored=1199'),rows_fixture('Some(500)'),raw.replace('delivered=1200','delivered=1201'),
        raw.replace('loss=Some(None)','loss=Some(Some((0, 0)))'),raw.replace('loss=Some(None)','loss=Some(Some((0, 18446744073709551616)))'),
        raw.replace('forwarder_finished=false','forwarder_finished=private'),raw.replace('loss=Some(None)','loss=secret'),raw.replace('[h-loss]','[h-loss] private'),
        raw.replace('[h-loss] clamp=None','[h-loss] clamp=Some(500)'),raw+'[h-loss] private\n']
    positives=[raw,raw+rows_fixture('Some(500)'),rows_fixture(loss='None',delivered=901,complete='false'),rows_fixture(loss='Some(Some((0, 299)))',delivered=901,complete='false',finished='true'),'']
    for item in positives:ensure(replay_rows(item)['schema_complete'],'closed-history-positive')
    for item in bad:
        try:replay_rows(item)
        except (ValueError,OverflowError):continue
        raise ValueError('closed-history-negative-accepted')
    inventory='{"rust-suites":{}}'
    ensure(select_inventory('Compiling fixed\n'+inventory)['rust-suites']=={},'compile-JSON-with-progress-positive')
    for item in ['',inventory+'\n'+inventory,'{"foreign":{}}']:
        try:select_inventory(item)
        except ValueError:continue
        raise ValueError('compile-JSON-negative-accepted')
    maximum=rows_fixture(loss='Some(Some((18446744073709551615, 18446744073709551615)))',finished='true')
    ensure(replay_rows(maximum)['schema_complete'],'maximum-loss-record-positive')
    return {'history_positive':len(positives)+1,'history_negative':len(bad),'compile_JSON_positive':1,'compile_JSON_negative':3,
        'maximum_loss_line_bytes':max(len(line.encode()) for line in maximum.splitlines() if line.startswith('[h-loss]')),'runtime_bodies':0,
        'shared_counts':counts.parser_controls()}

def runtime(report):
    frozen=physical();binary=None;before=None;mode=None
    report.update(runtime_attempted=False,actual_executed_nonignored=0,actual_passed=None,actual_failed=None,actual_ignored=None,actual_test_passed=False)
    try:
        free=shutil.disk_usage('.').free;report['free_bytes']=free;save(report);ensure(free>=8*1024**3,'remote-capacity')
        code,version,_=bounded.capture(['cargo-nextest','nextest','--version'],30,limit=4096)
        ensure(type(code) is int and code==0 and re.match(r'^cargo-nextest 0\.9\.132(?: |\n|$)',version),'actual-nextest-version');report['nextest_version']='0.9.132'
        command=['cargo','nextest','list','-p',PACKAGE,'--test',UNIT,'--features','sdk,test-policy-overrides','--locked','-E','test(='+NAME+')','--message-format=json']
        code,raw,seconds=bounded.capture(command,1200,limit=8*1024*1024)
        report['compilation']={'command':command,'exit_code':code,'seconds':seconds,**compiler(raw,frozen)};save(report)
        ensure(type(code) is int and code==0 and report['compilation']['compiler_error_count']==0,'compile-success-before-runtime')
        inventory=select_inventory(raw);selected=[]
        for suite in inventory['rust-suites'].values():
            for name,case in suite.get('testcases',{}).items():
                if case.get('filter-match',{}).get('status')=='matches':selected.append((suite,name,case))
        ensure(len(selected)==1 and selected[0][1]==NAME and selected[0][2].get('ignored') is False,'one-exact-nonignored-integration-case')
        suite=selected[0][0];ensure(suite.get('package-name')==PACKAGE and suite.get('binary-id')==PACKAGE+'::'+UNIT and suite.get('binary-name')==UNIT and suite.get('kind')=='test','exact-integration-suite')
        binary=Path(suite['binary-path']);ensure(binary.is_file() and not binary.is_symlink(),'actual-regular-binary')
        before=digest(binary.read_bytes());mode=stat.S_IMODE(binary.stat().st_mode);report['binary_before']={'sha256':before,'mode':mode}
        report['features']=own_features(binary);save(report)
        for ignored in [False,True]:
            c,text,_=bounded.capture([str(binary),'--exact',NAME]+(['--ignored'] if ignored else [])+['--list','--format','terse'],60,limit=1024*1024)
            row=counts.parse_inventory(text,NAME,ignored);report.setdefault('inventory',{})['ignored' if ignored else 'normal']=row;save(report)
            ensure(c==0 and row['passed'],'normal-one-ignored-zero-inventory')
        ensure(physical()==frozen and digest(binary.read_bytes())==before and stat.S_IMODE(binary.stat().st_mode)==mode,'before-runtime-source-binary-modes')
        report['runtime_attempted']=True;report['actual_executed_nonignored']=None;save(report)
        try:c,raw,seconds=bounded.capture([str(binary),'--exact',NAME,'--nocapture','--test-threads=1'],900,limit=8*1024*1024)
        except bounded.GateFailure as error:
            report['watchdog_triggered']=str(error)=='bounded-command-timeout';report['output_limit_triggered']=str(error)=='bounded-command-output-limit';save(report);raise
        report.update(body_exit_code=c,body_seconds=seconds,source_after_body_pristine=physical()==frozen,
            binary_after_sha256=digest(binary.read_bytes()) if binary.is_file() and not binary.is_symlink() else None,
            binary_after_mode=stat.S_IMODE(binary.stat().st_mode) if binary.is_file() and not binary.is_symlink() else None);save(report)
        basic=counts.parse_body(raw,c,NAME);report['basic_counts']=basic;report['actual_test_passed']=basic.get('passed_gate') is True
        for dest,key in [('actual_passed','passed'),('actual_failed','failed'),('actual_ignored','ignored'),('actual_executed_nonignored','executed_nonignored')]:report[dest]=basic.get(key)
        save(report);ensure(report['source_after_body_pristine'] and report['binary_after_sha256']==before and report['binary_after_mode']==mode,'postbody-source-binary-modes')
        report['history']=replay_rows(raw);save(report)
        ensure(report['actual_test_passed'],'original-history-failure-remains-failure')
        ensure(len(report['history']['cohorts'])==2 and all(row['actual_distinct_delivered']==1200 and row['coverage_complete'] for row in report['history']['cohorts']),'both-original-history-cohorts-required')
    finally:
        report['source_final_pristine']=physical()==frozen
        if binary is not None:report['binary_final_pristine']=binary.is_file() and not binary.is_symlink() and digest(binary.read_bytes())==before and stat.S_IMODE(binary.stat().st_mode)==mode
        if not report['source_final_pristine'] or report.get('binary_final_pristine') is False:
            report['observed_test_passed']=report['actual_test_passed'];report['actual_test_passed']=False
        report['qualification_passed']=False;save(report)
        ensure(report['source_final_pristine'] and report.get('binary_final_pristine',True),'final-source-binary-modes')

def main():
    parser=argparse.ArgumentParser();parser.add_argument('--preflight',action='store_true');args=parser.parse_args()
    report={'scope':'one existing integration history test with passive loss watermark','preflight':args.preflight,'runtime_attempted':False,'actual_executed_nonignored':0,
        'qualification_passed':False,'native_whole_qualification':False,'Tokio_workers':4,'RUST_MIN_STACK_unset':True,'automatic_retries':0,'raw_output_retained':False}
    try:
        report['source_guard']=source_guard();save(report);report['parser_controls']=controls();save(report)
        if not args.preflight:runtime(report)
        report['controller_completed']=True;save(report)
    except Exception as error:report['controller_failure_type']=type(error).__name__;save(report);raise
    finally:report['final_HEAD_git_pristine']=subprocess.run(['git','diff','--quiet','HEAD']).returncode==0;report['qualification_passed']=False;save(report)
if __name__=='__main__':main()
