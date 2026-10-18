#!/usr/bin/env python3
"""One strict native5 body; passive receive frontier is diagnostic, never qualification."""
import argparse, hashlib, json, os, re, shutil, stat, subprocess
from pathlib import Path
import qualify_upstream_pure_native5 as native
import qualify_upstream_storage_boundary as bounded
import qualify_upstream_storage_app_handles as counts
from upstream_completion_ci import compile_cases, ensure, digest
from qualify_upstream_body_negative import feature_identity
BASE='23cdbf7211cb4faeff3105b05bb06a0700963623'
MANIFEST_SHA='8cc4b96336bbe0b7ab3f8d94cc72797b14f94297e41550151991c07ee30ba2d9'
SELF='scripts/diagnose_upstream_receive_frontier.py'
MANIFEST='scripts/receive_frontier_source_manifest.json'
WORKFLOW='.github/workflows/experimental-sync-ci.yml'
REF='refs/heads/ci/upstream-receive-frontier-20261018'
BEGIN='  # RECEIVE_FRONTIER_JOBS_BEGIN\n';END='  # RECEIVE_FRONTIER_JOBS_END\n'
OPTIONS='options: [receive-frontier-preflight, receive-frontier-runtime, '
OUT=Path('receive-frontier-evidence')
U64=2**64-1;N=r'(?:0|[1-9][0-9]{0,19})';B=r'(?:true|false)'
ON=r'(?:None|Some\('+N+r'\))';OB=r'(?:None|Some\('+B+r'\))'

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
        and os.environ.get('UPSTREAM_RECEIVE_FRONTIER_BASELINE')==BASE,'exact-receive-frontier-remote-source')
    ensure(os.environ.get('CARGO_INCREMENTAL')=='1' and os.environ.get('CARGO_BUILD_JOBS')=='2' and os.environ.get('RUST_MIN_STACK')=='4194304'
        and all(os.environ.get(k)=='0' for k in ['CARGO_PROFILE_DEV_DEBUG','CARGO_PROFILE_TEST_DEBUG'])
        and all(not os.environ.get(k) for k in ['RUSTFLAGS','CARGO_ENCODED_RUSTFLAGS','RUSTC_BOOTSTRAP','CARGO_PROFILE_DEV_OPT_LEVEL','CARGO_PROFILE_TEST_OPT_LEVEL']),'exact-build-cohort')
    ensure(type(MANIFEST_SHA) is str and re.fullmatch('[0-9a-f]{64}',MANIFEST_SHA) and digest(Path(MANIFEST).read_bytes())==MANIFEST_SHA,'reviewed-manifest-required')
    manifest=json.loads(Path(MANIFEST).read_text());ensure(manifest['baseline']==BASE,'manifest-BASE')
    for a,b in [(manifest['parent'],manifest['reviewed_source']),(manifest['reviewed_source'],BASE),(BASE,head)]:
        ensure(subprocess.run(['git','merge-base','--is-ancestor',a,b]).returncode==0,'source-ancestry')
    pins=manifest['paths'];ensure(len(pins)==8 and changed(manifest['parent'],manifest['reviewed_source'])==set(pins)
        and changed(manifest['parent'],BASE)==set(pins),'only-eight-reviewed-passive-paths')
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

def number(text,maximum=U64):
    value=int(text);ensure(value<=maximum,'bounded-numeric-field');return value
def opt(text):return None if text=='None' else number(text[5:-1],U64-1)
def boolean(text):return text=='true'
def frontier(raw):
    clean=re.sub(r'\x1b\[[0-9;]*m','',raw)
    clean=re.sub(r'(?m)^test '+re.escape(native.NAME)+r' \.\.\. (?=native5-receive-frontier )','',clean)
    lines=[line for line in clean.splitlines() if 'native5-receive-frontier' in line]
    ensure(len(lines)<=2 and sum(len(line.encode())+1 for line in lines)<=1024 and all(len(line.encode())<=512 for line in lines),'bounded-two-frontier-lines')
    rows=[]
    pattern=r'Some\(\(('+B+'), ('+N+'), ('+N+'), ('+B+'), (None|Some\(\(('+N+'), ('+B+')\)\)), ('+ON+'), \[('+ON+'), ('+ON+'), ('+ON+')\], ('+OB+')\)\)'
    for line in lines:
        header=re.fullmatch(r'native5-receive-frontier join=([45]) observation=(.*)',line);ensure(header is not None,'exact-frontier-header')
        ordinal=int(header[1]);ensure(ordinal==4+len(rows),'frontier-four-then-five')
        if header[2]=='None':rows.append({'actual_join_ordinal':ordinal,'observed':False,'missing_is_unknown':True});continue
        m=re.fullmatch(pattern,header[2]);ensure(m is not None,'closed-frontier-tuple')
        stable=boolean(m[1]);loss=number(m[2],3);inflight=number(m[3],2**32-1)
        ensure(stable==(loss==0 and inflight==0),'stable-is-only-loss-and-inflight-sample')
        gate=None if m[5]=='None' else {'observed_us':number(m[6],2**63-2),'receive_enabled':boolean(m[7])}
        receive=opt(m[8]);before,after,observed=[opt(m[i]) for i in [9,10,11]]
        outcome=None if m[12]=='None' else boolean(m[12][5:-1])
        ensure(before is None or after is None or before<=after,'wait-construction-order')
        ensure(after is None or observed is None or after<=observed,'wait-observation-order')
        if stable:
            ensure((observed is None)==(outcome is None) and (after is None or before is not None)
                and (observed is None or after is not None),'quiescent-source-field-coherence')
        rows.append({'actual_join_ordinal':ordinal,'observed':True,'snapshot_stable':stable,'loss_mask':loss,'inflight_at_freeze':inflight,
            'owner_allocation_present':boolean(m[4]),'owner_live_permission_claimed':False,'last_receive_guard':gate,
            'last_before_actual_receive_next_delivery_us':receive,'wait_constructed_before_us':before,'wait_constructed_after_us':after,
            'wait_result_observed_us':observed,'wait_result_ok':outcome,'deadline_lower_us':None if before is None or before>U64-15000000 else before+15000000,
            'deadline_upper_us':None if after is None or after>U64-15000000 else after+15000000,'exact_deadline_known':False,'joint_product_snapshot':False})
    return {'schema_complete':True,'observed':bool(rows),'rows':rows,'unobserved_join_ordinals_are_unknown':True,'runtime_qualification':False}

def fixture(ordinal=4,payload='Some((true, 0, 0, true, Some((10, true)), Some(11), [Some(1), Some(2), Some(20)], Some(false)))'):
    return 'native5-receive-frontier join='+str(ordinal)+' observation='+payload+'\n'
def frontier_controls():
    positive=[fixture(),fixture()+fixture(5),fixture(payload='None'),'',fixture(payload='Some((false, 1, 0, false, None, None, [None, None, None], None))'),
        fixture(payload='Some((false, 0, 1, true, Some((0, false)), None, [Some(0), Some(0), Some(1)], None))'),
        fixture(payload='Some((true, 0, 0, false, Some((30, false)), Some(0), [Some(1), Some(2), Some(20)], Some(true)))')]
    maximum=fixture(payload='Some((false, 3, 4294967295, false, Some((9223372036854775806, false)), Some(18446744073709551614), [Some(18446744073709551614), Some(18446744073709551614), Some(18446744073709551614)], Some(false)))')
    positive.append(maximum+maximum.replace('join=4','join=5'))
    for text in positive:ensure(frontier(text)['schema_complete'],'frontier-positive')
    negative=[fixture(5),fixture()+fixture(),fixture()+fixture(5)+fixture(5),fixture().replace('join=4','join=6'),fixture().replace('observation=','private='),
        fixture().replace('Some((10, true))','Some((9223372036854775807, true))'),fixture().replace('Some(11)','Some(18446744073709551616)'),
        fixture().replace('true, 0, 0, true','true, 1, 0, true'),fixture().replace('true, 0, 0, true','false, 0, 0, true'),
        fixture().replace('Some(1), Some(2)','Some(3), Some(2)'),fixture().replace('Some(20)','Some(1)'),fixture().replace('Some(false)))','None))'),
        fixture().replace('Some(20)','None'),fixture().replace('Some(1), Some(2)','None, Some(2)'),fixture().replace('Some(1), Some(2)','Some(1), None'),fixture()+'native5-receive-frontier private\n',fixture().rstrip()+' secret\n']
    for text in negative:
        try:frontier(text)
        except (ValueError,OverflowError):continue
        raise ValueError('frontier-negative-accepted')
    return {'positive':len(positive),'negative':len(negative),'maximum_two_line_bytes':len(positive[-1].encode()),'cap_bytes':1024,'actual_runtime_executions':0}

def compiler(row,tracked):
    headers=row.pop('compiler_headers',[])
    codes=sorted({c for line in headers for c in re.findall(r'\berror\[(E[0-9]{4})\]',line)})
    row['compiler_codes']=codes[:32];row['compiler_code_distinct_count']=len(codes);row['compiler_codes_truncated']=len(codes)>32
    sites=[]
    for line in headers:
        m=re.fullmatch(r'\s*--> (crates/[A-Za-z0-9_./-]+\.rs):([0-9]{1,7}):([0-9]{1,7})',line)
        if m and m[1] in tracked:sites.append({'file':m[1],'line':int(m[2]),'column':int(m[3])})
    row['compiler_sites']=sites[:32];row['compiler_sites_truncated']=len(sites)>32
    return row

def runtime(report):
    frozen=physical();binary=None;before=None;mode=None
    report.update(runtime_attempted=False,actual_counts_complete=False,actual_passed=None,actual_failed=None,actual_ignored=None,actual_executed_nonignored=0,native_component_control_passed=False)
    try:
        free=shutil.disk_usage('.').free;report['capacity']={'free_bytes':free,'minimum_free_bytes':8*1024**3};save(report);ensure(free>=8*1024**3,'remote-capacity')
        version_code,version,_=bounded.capture(['cargo','nextest','--version'],30,limit=4096)
        ensure(version_code==0 and re.match(r'^cargo-nextest 0\.9\.132(?: |\n|$)',version),'actual-pinned-nextest-version')
        report['nextest_version']='0.9.132'
        compilation,cases=compile_cases([native.SUFFIX]);report['compilation']=compiler(compilation,frozen);save(report)
        ensure(type(compilation.get('compile_exit_code')) is int and compilation['compile_exit_code']==0 and type(compilation.get('compiler_error_count')) is int and compilation['compiler_error_count']==0
            and compilation.get('compiled_fingerprints',{}).get('verified') is True and set(cases)=={native.SUFFIX},'one-compiled-real-native5-case')
        case=cases[native.SUFFIX];ensure(case['name']==native.NAME,'exact-native5-fullname')
        binary=Path(case['binary']);ensure(binary.is_file() and not binary.is_symlink(),'regular-actual-binary')
        before=digest(binary.read_bytes());mode=stat.S_IMODE(binary.stat().st_mode);ensure(before==case['binary_sha256'],'actual-compiled-binary-hash')
        report['binary_before']={'sha256':before,'mode':mode};report['feature_identity']=feature_identity(compilation)
        ensure(set(report['feature_identity']['nodes'])==native.NODES,'six-actual-feature-nodes');save(report)
        for ignored in [False,True]:
            code,text,_=bounded.capture([str(binary),'--exact',native.NAME]+(['--ignored'] if ignored else [])+['--list','--format','terse'],60,limit=1024*1024)
            row=counts.parse_inventory(text,native.NAME,ignored);report.setdefault('inventory',{})['ignored' if ignored else 'normal']=row;save(report)
            ensure(code==0 and row['passed'],'exact-one-nonignored-inventory')
        ensure(physical()==frozen and digest(binary.read_bytes())==before and stat.S_IMODE(binary.stat().st_mode)==mode,'prebody-source-binary-modes')
        report['runtime_attempted']=True;report['actual_executed_nonignored']=None;save(report)
        try:
            code,raw,seconds=bounded.capture([str(binary),'--exact',native.NAME,'--nocapture','--test-threads=1'],900,limit=8*1024*1024)
        except bounded.GateFailure as error:
            report['watchdog_triggered']=str(error)=='bounded-command-timeout'
            report['output_limit_triggered']=str(error)=='bounded-command-output-limit';save(report);raise
        report.update(body_exit_code=code,body_seconds=seconds,source_after_body_pristine=physical()==frozen,
            binary_after_body_sha256=digest(binary.read_bytes()) if binary.is_file() and not binary.is_symlink() else None,
            binary_after_body_mode=stat.S_IMODE(binary.stat().st_mode) if binary.is_file() and not binary.is_symlink() else None);save(report)
        basic=counts.parse_body(raw,code,native.NAME);report['basic_counts']=basic;report['actual_counts_complete']=basic.get('actual_counts_complete') is True
        for target,key in [('actual_passed','passed'),('actual_failed','failed'),('actual_ignored','ignored'),('actual_executed_nonignored','executed_nonignored')]:report[target]=basic.get(key)
        save(report)
        ensure(report['source_after_body_pristine'] and report['binary_after_body_sha256']==before and report['binary_after_body_mode']==mode,'postbody-source-binary-modes')
        try:report['frontier']=frontier(raw)
        except (ValueError,OverflowError) as error:report['frontier']={'schema_complete':False,'failure_type':type(error).__name__}
        save(report)
        try:
            report['native_body']=native.parse(raw,code);report['native_component_control_passed']=native.green(report['native_body'])
        except (ValueError,OverflowError) as error:report['native_parser_failure_type']=type(error).__name__
        save(report)
        ensure(report['frontier']['schema_complete'],'closed-frontier-schema-required')
        ensure(report['native_component_control_passed'],'actual-native5-failure-remains-failure')
    finally:
        report['source_final_pristine']=physical()==frozen
        if binary is not None:
            report['binary_final_pristine']=binary.is_file() and not binary.is_symlink() and digest(binary.read_bytes())==before and stat.S_IMODE(binary.stat().st_mode)==mode
        if not report['source_final_pristine'] or report.get('binary_final_pristine') is False:
            report['observed_native_body_passed']=report['native_component_control_passed'];report['native_component_control_passed']=False
        report['qualification_passed']=False;save(report)
        ensure(report['source_final_pristine'] and report.get('binary_final_pristine',True),'final-source-binary-modes')

def main():
    parser=argparse.ArgumentParser();parser.add_argument('--preflight',action='store_true');args=parser.parse_args()
    report={'scope':'strict native5 plus passive current-source receive frontier','preflight':args.preflight,'native_global_qualification':False,'qualification_passed':False,
        'Tokio_workers':2,'stack_bytes':4194304,'automatic_retries':0,'raw_output_retained':False,'runtime_attempted':False,'actual_executed_nonignored':0}
    try:
        report['source_guard']=source_guard();save(report)
        report['parser_controls']={'native':native.parser_controls(),'frontier':frontier_controls()};save(report)
        if not args.preflight:runtime(report)
        report['controller_completed']=True;save(report)
    except Exception as error:
        report['controller_failure_type']=type(error).__name__;save(report);raise
    finally:
        report['final_HEAD_git_pristine']=subprocess.run(['git','diff','--quiet','HEAD']).returncode==0
        report['qualification_passed']=False;save(report)
if __name__=='__main__':main()
