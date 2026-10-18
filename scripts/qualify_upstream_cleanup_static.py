#!/usr/bin/env python3
"""Exact metadata unit tests and real unchanged standalone Rust source-audit PFP."""
import argparse, hashlib, json, os, re, stat, subprocess, sys, time
from pathlib import Path
import qualify_upstream_storage_boundary as bounded
ensure=bounded.ensure
BASE='11eb96f4f72d17d0b40136bdfb6749acf6b676c4'
OLD='288544fe2d9dc3323cb1df3b99f35cc017375e13'
SELF='scripts/qualify_upstream_cleanup_static.py'
WORKFLOW='.github/workflows/cleanup-static.yml'
WORKFLOW_SHA='407e2c4374a240db3f7ed98597bf647bb79652fb848a4d802a12cca29f201bb4'
REF='refs/heads/ci/upstream-cleanup-static-20261018'
PROBE='crates/marmot-app/src/client/account_chat_sharing/automatic/body_negative_probe.rs'
AUDIT='crates/cgka-conformance-simulator/tests/tracing_audit.rs'
PROBE_SHA='652ab7123f12a6091daed1249fa1c16529ada7bc5fda367d0ac4cada3982047b'
OLD_SHA='7bfe03a775976c6209da164cf9b93f14470ffe5f2d4ab62ca235acb8c8da4a4a'
AUDIT_SHA='30b7784c118a2ece5418fe7de029adc13f3173c1405b417cbdd7742910d4066e'
AUDIT_NAMES=['production_tracing_calls_are_structured_and_privacy_safe', 'production_tracing_calls_do_not_interpolate_raw_errors', 'production_library_sources_do_not_write_direct_output', 'parse_workspace_members_reads_multiline_workspace_array']
UNIT_IDS=['test_recover_archive_gaps.ArchiveGapTests.test_original_nextest_failed_summary_recap_is_one_retained_failure', 'test_recover_archive_gaps.ArchiveGapTests.test_only_identical_failed_summary_recap_is_allowed', 'test_recover_archive_gaps.ArchiveGapTests.test_simulator_requires_exact_two_smoke_partitions_and_own_producer', 'test_recover_archive_gaps.ArchiveGapTests.test_pr_origin_requires_exact_head_and_successful_archive_producer', 'test_recover_archive_gaps.ArchiveGapTests.test_experimental_pr_uses_its_own_workflow_producer_and_partitions', 'test_recover_archive_gaps.ArchiveGapTests.test_pr_checkout_requires_single_exact_source_and_tree_in_raw_output', 'test_recover_archive_gaps.ArchiveGapTests.test_pr_fetch_rejects_checkout_mismatch_before_downloading_large_archive', 'test_recover_archive_gaps.ArchiveGapTests.test_origin_requires_exact_repository_source_attempt_and_finished_run', 'test_recover_archive_gaps.ArchiveGapTests.test_artifact_cannot_be_expired_unhashed_or_from_another_run', 'test_recover_archive_gaps.ArchiveGapTests.test_partial_duplicate_or_retried_partition_metadata_is_refused', 'test_recover_archive_gaps.ArchiveGapTests.test_original_failure_is_retained_and_never_scheduled_as_a_retry', 'test_recover_archive_gaps.ArchiveGapTests.test_passed_and_ignored_cases_are_not_repeated', 'test_recover_archive_gaps.ArchiveGapTests.test_cli_cases_are_not_replaced_by_legacy_followup_roles', 'test_recover_archive_gaps.ArchiveGapTests.test_an_archive_with_complete_coverage_has_no_matrix_jobs', 'test_recover_archive_gaps.ArchiveGapTests.test_actual_selection_must_equal_nonempty_frozen_plan', 'test_recover_archive_gaps.ArchiveGapTests.test_each_missing_body_must_terminate_once_with_pass', 'test_recover_experimental_coverage.CoverageTests.test_reuses_only_clean_passes_and_retains_missing_cases', 'test_recover_experimental_coverage.CoverageTests.test_failures_timeouts_and_leaks_require_execution', 'test_recover_experimental_coverage.CoverageTests.test_empty_inventory_refused', 'test_recover_experimental_coverage.CoverageTests.test_unknown_and_ignored_terminal_cases_refused', 'test_recover_experimental_coverage.CoverageTests.test_duplicate_case_cannot_mask_a_failure_or_overlap', 'test_recover_experimental_coverage.CoverageTests.test_plan_is_complete_disjoint_and_deterministic', 'test_recover_experimental_coverage.CoverageTests.test_replaced_cases_require_evidence_and_are_never_passing', 'test_recover_experimental_coverage.CoverageTests.test_plan_rejects_duplicate_or_unsafe_identifiers', 'test_pairing_replay_dispatch.PairingReplayDispatchTests.test_explicit_replay_alias_preserves_the_existing_one_case_scope', 'test_pairing_replay_dispatch.PairingReplayDispatchTests.test_every_scope_is_offered_and_routes_to_pairing_job', 'test_pairing_replay_dispatch.PairingReplayDispatchTests.test_every_scope_executes_its_exact_inventory_and_bounded_command']
MODULES=['test_recover_archive_gaps','test_recover_experimental_coverage','test_pairing_replay_dispatch']
OUT=Path('cleanup-static-evidence')
def digest(data):return hashlib.sha256(data).hexdigest()
def git(*args):return subprocess.check_output(['git',*args])
def save(report):
    OUT.mkdir(mode=0o700,exist_ok=True);(OUT/'result.json').write_text(json.dumps(report,indent=2)+'\n')
def layout(ref):
    result={}
    for item in git('ls-tree','-r','-z',ref).split(b'\0'):
        if item:
            meta,path=item.split(b'\t',1);mode,kind,oid=meta.decode().split()
            ensure(kind=='blob' and mode in {'100644','100755','120000'},'ordinary-whole-layout')
            result[os.fsdecode(path)]=(mode,oid)
    return result

def physical():
    result={}
    for path,(mode,_) in layout('HEAD').items():
        p=Path(path);s=p.lstat();link=stat.S_ISLNK(s.st_mode)
        ensure(link==(mode=='120000') and (link or stat.S_ISREG(s.st_mode)),'tracked-physical-kind')
        result[path]=(mode,stat.S_IMODE(s.st_mode),digest(os.fsencode(os.readlink(p)) if link else p.read_bytes()))
    return result

def source_guard(preflight):
    head=git('rev-parse','HEAD').decode().strip()
    ensure(os.environ.get('GITHUB_ACTIONS')=='true' and os.environ.get('GITHUB_REPOSITORY')=='dyKiU/mdk'
        and os.environ.get('GITHUB_SHA')==head and os.environ.get('GITHUB_REF')==REF
        and os.environ.get('GITHUB_WORKFLOW_REF')=='dyKiU/mdk/'+WORKFLOW+'@'+REF
        and (os.environ.get('GITHUB_EVENT_NAME')=='workflow_dispatch' or (preflight and os.environ.get('GITHUB_EVENT_NAME')=='push')),'hosted-event-head-ref')
    ensure('channel = "1.97.1"' in Path('rust-toolchain.toml').read_text() and all(not os.environ.get(k) for k in ['RUSTFLAGS','CARGO_ENCODED_RUSTFLAGS','RUSTC_BOOTSTRAP']),'exact-source-toolchain-no-overrides')
    ensure(subprocess.run(['git','merge-base','--is-ancestor',BASE,head]).returncode==0,'BASE-ancestor')
    before=layout(BASE);current=layout('HEAD')
    ensure(SELF not in before and WORKFLOW not in before and set(current)==set(before)|{SELF,WORKFLOW},'wholeBASE-plus-two-owned-metadata')
    ensure(subprocess.run(['git','diff','--quiet','HEAD']).returncode==0,'HEAD-pristine')
    for path,(mode,oid) in current.items():
        p=Path(path);s=p.lstat();link=stat.S_ISLNK(s.st_mode);expected=before.get(path,('100644',None))
        ensure(mode==expected[0] and link==(mode=='120000') and (link or stat.S_ISREG(s.st_mode))
            and (link or bool(s.st_mode&0o111)==(mode=='100755')),'whole-source-modes')
        data=os.fsencode(os.readlink(p)) if link else p.read_bytes()
        actual=hashlib.sha1(b'blob '+str(len(data)).encode()+b'\0'+data).hexdigest()
        ensure(actual==oid and (expected[1] is None or actual==expected[1]),'wholeBASE-and-HEAD-content')
    ensure(digest(Path(WORKFLOW).read_bytes())==WORKFLOW_SHA and digest(Path(PROBE).read_bytes())==PROBE_SHA
        and digest(Path(AUDIT).read_bytes())==AUDIT_SHA and digest(git('show',OLD+':'+PROBE))==OLD_SHA,'workflow-audit-old-current-probe-pins')
    ensure(before[PROBE][0]==layout(OLD)[PROBE][0]=='100644','unchanged-probe-git-mode')
    ensure(set(git('ls-files','--others','--exclude-standard').decode().splitlines())<={str(OUT/'result.json')},'no-untracked-source-overlays')
    return {'head':head,'BASE':BASE,'whole_source_modes':True,'Rust_exceptions':[],'protocol_or_SDK_runtime_qualified':False}

# The child owns its real unittest TestResult. Tracebacks stay only in child RAM;
# only exact source-frozen test IDs and numeric result counts are serialized.
UNIT_CHILD=r'''import json,sys,unittest
sys.path.insert(0,'scripts')
modules=MODULE_VALUES
class ClosedResult(unittest.TestResult):
    def __init__(self):super().__init__();self.ids=[];self.parents={}
    def startTest(self,test):self.ids.append(test.id());super().startTest(test)
    def addSubTest(self,test,subtest,error):
        self.parents[id(subtest)]=test.id();super().addSubTest(test,subtest,error)
    def closed_id(self,test):return self.parents.get(id(test),test.id())
r=ClosedResult();unittest.defaultTestLoader.loadTestsFromNames(modules).run(r)
print(json.dumps({'testsRun':r.testsRun,'ids':r.ids,'errors':[r.closed_id(t) for t,_ in r.errors],'failures':[r.closed_id(t) for t,_ in r.failures],'skips':[t.id() for t,_ in r.skipped],'expected_failures':[t.id() for t,_ in r.expectedFailures],'unexpected_successes':[t.id() for t in r.unexpectedSuccesses]}))
sys.exit(0 if r.wasSuccessful() and not r.skipped and not r.expectedFailures else 1)
'''.replace('MODULE_VALUES',repr(MODULES))

def unit_record(raw,code):
    value=json.loads(raw)
    ensure(type(value)is dict and set(value)=={'testsRun','ids','errors','failures','skips','expected_failures','unexpected_successes'},'closed-unit-fields')
    ensure(type(value['testsRun'])is int and value['testsRun']==27,'actual-27-unittest-methods')
    for key in ['ids','errors','failures','skips','expected_failures','unexpected_successes']:
        ensure(type(value[key])is list and len(value[key])<=27 and all(type(v)is str and v in UNIT_IDS for v in value[key]),'closed-unit-ID-allowlist')
    ensure(len(value['ids'])==27 and len(set(value['ids']))==27 and set(value['ids'])==set(UNIT_IDS),'actual-exact-27-unit-IDs')
    return {'testsRun':27,'executed_test_IDs':value['ids'],'error_test_IDs':value['errors'],'failure_test_IDs':value['failures'],'skip_test_IDs':value['skips'],
        'errors':len(value['errors']),'failures':len(value['failures']),'failure_events':len(value['failures']),'error_events':len(value['errors']),'unique_failed_method_count':len(set(value['failures'])),'unique_error_method_count':len(set(value['errors'])),'counts_are_result_events_not_unique_methods':True,'skips':len(value['skips']),'expected_failures':len(value['expected_failures']),'unexpected_successes':len(value['unexpected_successes']),
        'passed':type(code)is int and code==0 and not any(value[k] for k in ['errors','failures','skips','expected_failures','unexpected_successes'])}

def audit_inventory(raw,ignored):
    lines=[line for line in raw.splitlines() if line.strip()]
    matches=re.findall(r'^([A-Za-z0-9_]+): test$',raw,re.M)
    count=0 if ignored else 4;summary=str(count)+' tests, 0 benchmarks'
    allowed={name+': test' for name in AUDIT_NAMES}|{summary}
    return (all(line in allowed for line in lines) and lines.count(summary)<=1
        and sorted(matches)==([] if ignored else sorted(AUDIT_NAMES)) and len(matches)==count)

def old_print_expectation():
    audit=Path(AUDIT).read_bytes()
    ensure(digest(audit)==AUDIT_SHA,'unchanged-audit-macro-semantics')
    declarations=re.findall(r'const DIRECT_OUTPUT_MACROS: &\[&str\] = &\[([^\]\n]+)\];',audit.decode())
    ensure(len(declarations)==1,'one-source-owned-direct-output-macro-list')
    macros=re.findall(r'"([^"\n]+)"',declarations[0])
    ensure(macros==['println!(', 'eprintln!(', 'dbg!('],'exact-three-original-output-macros')
    original=git('show',OLD+':'+PROBE);ensure(digest(original)==OLD_SHA,'exact-old-probe-for-audit-expectation')
    lines=original.decode().splitlines()
    source_lines=[index+1 for index,line in enumerate(lines) if 'eprintln!(' in line]
    # Mirror the unchanged audit's for-each-macro line.contains semantics:
    # eprintln!( also contains println!(, so two source prints yield four rows.
    wanted=[str(Path(PROBE).resolve())+':'+str(index+1)+' production library source writes direct output with `'+macro+'`'
        for index,line in enumerate(lines) for macro in macros if macro in line]
    ensure(len(source_lines)==2 and len(wanted)==4,'two-source-eprintln-lines-four-macro-violations')
    return wanted,source_lines

def audit_record(raw,code,expected):
    text=re.sub(r'\x1b\[[0-?]*[ -/]*[@-~]','',raw)
    summaries=re.findall(r'^test result: (ok|FAILED)\. ([0-9]+) passed; ([0-9]+) failed; ([0-9]+) ignored; ([0-9]+) measured; ([0-9]+) filtered out; finished in [0-9.]+s$',text,re.M)
    ensure(len(summaries)==1,'one-real-audit-summary')
    status,p,f,i,m,filtered=summaries[0];p,f,i,m,filtered=map(int,[p,f,i,m,filtered])
    events=re.findall(r'^test ([A-Za-z0-9_]+) \.\.\. (ok|FAILED|ignored)$',text,re.M)
    ensure(len(events)==4 and len({name for name,_ in events})==4 and {name for name,_ in events}==set(AUDIT_NAMES),'four-exact-audit-outcomes')
    failed=[name for name,value in events if value=='FAILED'];passed=[name for name,value in events if value=='ok']
    ensure(p==len(passed) and f==len(failed) and p+f==4 and i==m==filtered==0,'audit-summary-event-coherence')
    result={'passed':p,'failed':f,'ignored':i,'executed_nonignored':p+f,'exit_code':code,'failed_test_names':failed,'expected_outcome_verified':False}
    if expected=='green':result['expected_outcome_verified']=type(code)is int and code==0 and status=='ok' and p==4 and not failed
    else:
        target='production_library_sources_do_not_write_direct_output'
        # Attribute only the exact unchanged scanner's four macro diagnostics
        # for the two source-owned old eprintln lines; no unrelated audit failure.
        violations=[line for line in text.splitlines() if ' production library source writes direct output with ' in line]
        wanted,source_lines=old_print_expectation()
        result.update(old_eprintln_source_line_count=len(source_lines),expected_macro_violation_count=len(wanted),observed_macro_violation_count=len(violations))
        result['exact_old_print_violations']=sorted(violations)==sorted(wanted)
        result['expected_outcome_verified']=(type(code)is int and code==101 and status=='FAILED' and p==3 and failed==[target]
            and text.count('direct output audit failed:')==1 and result['exact_old_print_violations'])
    return result

def write_owned(path,data,mode):
    ensure(not path.is_symlink() and (not path.exists() or path.is_file()),'owned-write-kind')
    prior=path.stat().st_mtime_ns if path.exists() else 0;path.write_bytes(data);path.chmod(mode)
    stamp=max(time.time_ns(),prior+2_000_000_000);os.utime(path,ns=(stamp,stamp))

def binary_record(binary):
    ensure(binary.is_file() and not binary.is_symlink(),'regular-audit-binary')
    return {'sha256':digest(binary.read_bytes()),'mode':stat.S_IMODE(binary.stat().st_mode)}

def audit_body(report,label,binary,identity,inputs,expected):
    row={'runtime_attempted':False,'actual_executed_nonignored':0};report.setdefault('phases',{})[label]=row;save(report)
    ensure(physical()==inputs and binary_record(binary)==identity,'audit-prebody-source-binary-mode')
    row.update(runtime_attempted=True,actual_executed_nonignored=None);save(report)
    code,raw,seconds=bounded.capture([str(binary),'--test-threads=1'],120,limit=2*1024*1024)
    row.update(body_exit_code=code,seconds=seconds,source_after_body_pristine=physical()==inputs,binary_after=binary_record(binary));save(report)
    # Numeric evidence is saved before strict named/RED-payload classification.
    basic=re.findall(r'^test result: (?:ok|FAILED)\. ([0-9]+) passed; ([0-9]+) failed; ([0-9]+) ignored;',raw,re.M)
    if len(basic)==1:
        p,f,i=map(int,basic[0]);row.update(actual_passed=p,actual_failed=f,actual_ignored=i,actual_executed_nonignored=p+f);save(report)
    ensure(row['source_after_body_pristine'] and row['binary_after']==identity,'audit-postbody-source-binary-mode')
    row['outcome']=audit_record(raw,code,expected);row['expected_outcome_verified']=row['outcome']['expected_outcome_verified'];save(report)
    return row['expected_outcome_verified']

def observed_audit_counts(rows):
    attempted=[row for row in rows if row.get('runtime_attempted')is True]
    return {key:sum(row[key] for row in attempted) if all(type(row.get(key))is int for row in attempted) else None
        for key in ['actual_passed','actual_failed','actual_ignored','actual_executed_nonignored']}

def runtime(report):
    inputs=physical();probe=Path(PROBE);original=probe.read_bytes();mode=stat.S_IMODE(probe.stat().st_mode);binary=None;identity=None;attempted=False
    try:
        code,raw,seconds=bounded.capture([sys.executable,'-c',UNIT_CHILD],120,limit=2*1024*1024)
        report['units_capture']={'exit_code':code,'seconds':seconds,'bytes':len(raw.encode()),'source_after_units_pristine':physical()==inputs};save(report)
        observed=json.loads(raw)
        report['unit_observed_counts']={'testsRun':observed.get('testsRun') if type(observed.get('testsRun'))is int else None,
            **{('failure_events' if key=='failures' else 'error_events' if key=='errors' else key):len(observed[key]) if type(observed.get(key))is list else None for key in ['errors','failures','skips','expected_failures','unexpected_successes']}}
        save(report)
        report['units']=unit_record(raw,code);save(report)
        ensure(report['units']['passed'] and report['units_capture']['source_after_units_pristine'],'actual-27-units-no-errors-failures-skips')
        binary=Path(os.environ['RUNNER_TEMP'])/'cleanup-tracing-audit'
        ensure(not binary.exists() and not binary.is_symlink(),'fresh-owned-audit-output')
        command=['env','CARGO_MANIFEST_DIR='+str(Path('crates/cgka-conformance-simulator').resolve()),'rustup','run','1.97.1','rustc','--test','--edition=2024','--error-format=json','-C','debuginfo=0',AUDIT,'-o',str(binary)]
        # No Cargo, SDK build, alternate profile or protocol test invocation.
        code,raw,seconds=bounded.capture(command,120,limit=2*1024*1024)
        diagnostics=[]
        for line in raw.splitlines():
            if line.startswith('{'):
                try:value=json.loads(line)
                except ValueError:continue
                if value.get('level')=='error':diagnostics.append(value)
        report['compilation']={'toolchain':'1.97.1','edition':'2024','standalone_rustc_test':True,'manifest_dir_current_conformance_crate':True,'exit_code':code,'seconds':seconds,'compiler_error_count':len(diagnostics),'codes':sorted({v.get('code',{}).get('code') for v in diagnostics if type(v.get('code'))is dict and re.fullmatch(r'E[0-9]{4}',v['code'].get('code',''))})[:32]};save(report)
        ensure(code==0 and not diagnostics and physical()==inputs,'standalone-audit-compile-no-errors')
        identity=binary_record(binary);report['binary_before']=identity;save(report)
        for ignored in [False,True]:
            code,raw,_=bounded.capture([str(binary)]+(['--ignored'] if ignored else [])+['--list','--format','terse'],30,limit=65536)
            valid=audit_inventory(raw,ignored)
            report.setdefault('audit_inventory',{})['ignored' if ignored else 'normal']={'exit_code':code,'valid':valid,'exact_test_names':[] if ignored else AUDIT_NAMES,'actual_test_count':len(re.findall(r'^([A-Za-z0-9_]+): test$',raw,re.M))};save(report)
            ensure(code==0 and valid,'four-normal-zero-ignored-audit-inventory')
        ensure(audit_body(report,'baseline',binary,identity,inputs,'green'),'baseline-four-audits-must-pass-before-mutation')
        old=git('show',OLD+':'+PROBE);ensure(digest(old)==OLD_SHA and digest(original)==PROBE_SHA,'exact-old-and-current-probe')
        expected=dict(inputs);expected[PROBE]=(inputs[PROBE][0],mode,digest(old))
        try:
            attempted=True;report['mutation_attempted']=True;save(report)
            write_owned(probe,old,mode);ensure(physical()==expected,'only-two-original-prints-restored-exact-source')
            audit_body(report,'mutant',binary,identity,expected,'red')
        except Exception as error:report['mutant_failure_type']=type(error).__name__;save(report)
        finally:
            if probe.is_symlink():probe.unlink()
            write_owned(probe,original,mode);ensure(physical()==inputs,'exact-source-restore')
            # Audit executes against actual current source; reuse exact original
            # immutable audit binary, with a fresh real four-test invocation.
            audit_body(report,'restored',binary,identity,inputs,'green')
        rows=list(report.get('phases',{}).values())
        totals=observed_audit_counts(rows)
        report['actual_audit_counts']=totals
        report['static_audit_PFP_verified']=(len(rows)==3 and all(report['phases'].get(label,{}).get('expected_outcome_verified')is True for label in ['baseline','mutant','restored'])
            and totals=={'actual_passed':11,'actual_failed':1,'actual_ignored':0,'actual_executed_nonignored':12})
        save(report);ensure(report['static_audit_PFP_verified'],'twelve-real-audits-eleven-pass-one-intended-failure')
    finally:
        report['mutation_attempted']=attempted
        rows=list(report.get('phases',{}).values())
        report['actual_audit_counts']=observed_audit_counts(rows)
        report['actual_audit_attempts']=sum(row.get('runtime_attempted')is True for row in rows)
        if not report['actual_audit_attempts']:report['actual_audit_counts']['actual_executed_nonignored']=0
        if probe.is_symlink() or not probe.is_file() or probe.read_bytes()!=original or stat.S_IMODE(probe.stat().st_mode)!=mode:
            report['fallback_source_restore_used']=True;report['static_audit_PFP_verified']=False
            if probe.is_symlink():probe.unlink()
            write_owned(probe,original,mode)
        report['source_final_pristine']=physical()==inputs
        report['binary_final']=None if binary is None or identity is None or binary.is_symlink() or not binary.is_file() else binary_record(binary)
        report['binary_final_pristine']=None if identity is None else report['binary_final']==identity
        if not report['source_final_pristine'] or report['binary_final_pristine']is False:report['static_audit_PFP_verified']=False
        save(report);ensure(report['source_final_pristine'] and report['binary_final_pristine']is not False,'final-source-binary-mode')
        if sys.exc_info()[0]is None:ensure(report.get('static_audit_PFP_verified')is True and not report.get('fallback_source_restore_used',False),'no-fallback-qualification')

def controls():
    good={'testsRun':27,'ids':UNIT_IDS,'errors':[],'failures':[],'skips':[],'expected_failures':[],'unexpected_successes':[]}
    ensure(unit_record(json.dumps(good),0)['passed'],'closed-unit-positive')
    for change in [dict(good,testsRun=0),dict(good,testsRun=True),dict(good,ids=UNIT_IDS[:-1]),dict(good,ids=UNIT_IDS[:-1]+['PRIVATE']),dict(good,skips=[UNIT_IDS[0]])]:
        try:accepted=unit_record(json.dumps(change),0)['passed']
        except (ValueError,TypeError):accepted=False
        ensure(not accepted,'closed-unit-zero-skip-private-rejected')
    ensure(audit_inventory('\n'.join(name+': test' for name in AUDIT_NAMES),False) and audit_inventory('',True),'fixed-audit-inventory-positive')
    ensure(not audit_inventory(AUDIT_NAMES[0]+': test',False),'zero-or-partial-audit-not-green')
    ensure(not audit_inventory('\n'.join(name+': test' for name in AUDIT_NAMES)+'\nPRIVATE',False),'unknown-inventory-line-rejected')
    green='running 4 tests\n'+'\n'.join('test '+name+' ... ok' for name in AUDIT_NAMES)+'\ntest result: ok. 4 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.01s\n'
    ensure(audit_record(green,0,'green')['expected_outcome_verified'],'real-four-audit-GREEN-shape')
    for bad in [green.replace('4 passed','0 passed'),green.replace('0 ignored','1 ignored'),green.replace(' ... ok',' ... ignored',1),green+'\n'+green]:
        try:accepted=audit_record(bad,0,'green')['expected_outcome_verified']
        except ValueError:accepted=False
        ensure(not accepted,'audit-zero-ignored-duplicate-not-green')
    target='production_library_sources_do_not_write_direct_output'
    wanted,source_lines=old_print_expectation()
    violations='\n'.join(wanted)
    red=green.replace('test '+target+' ... ok','test '+target+' ... FAILED').replace('test result: ok. 4 passed; 0 failed','test result: FAILED. 3 passed; 1 failed')+'direct output audit failed:\n'+violations+'\n'
    ensure(audit_record(red,101,'red')['expected_outcome_verified'],'actual-two-source-prints-four-macro-RED-shape')
    for bad in [red.replace('direct output audit failed:','foreign'),red.replace(violations,''),red.replace('3 passed; 1 failed','2 passed; 2 failed')]:
        try:accepted=audit_record(bad,101,'red')['expected_outcome_verified']
        except ValueError:accepted=False
        ensure(not accepted,'unrelated-or-incomplete-RED-rejected')
    eprintln_only='\n'.join(line for line in wanted if line.endswith('`eprintln!(`'))
    changed_line=red.replace(str(Path(PROBE).resolve())+':'+str(source_lines[0])+' ',str(Path(PROBE).resolve())+':'+str(source_lines[0]+1)+' ')
    extra_macro=red+wanted[0].replace('`println!(`','`dbg!(`')+'\n'
    for bad in [red.replace(violations,eprintln_only),changed_line,extra_macro]:
        ensure(not audit_record(bad,101,'red')['expected_outcome_verified'],'two-only-changed-line-or-extra-macro-not-intended-RED')
    partial={'runtime_attempted':True,'actual_passed':4,'actual_failed':0,'actual_ignored':0,'actual_executed_nonignored':4}
    ensure(observed_audit_counts([partial])['actual_passed']==4,'baseline-failure-known-count-retained')
    ensure(observed_audit_counts([])['actual_executed_nonignored']==0,'no-audit-attempt-zero-count')
    ensure(observed_audit_counts([partial,{'runtime_attempted':True}])['actual_passed']is None,'attempted-unknown-not-zero')
    return {'positive':6,'negative':18,'runtime_bodies':0}

def main():
    args=argparse.ArgumentParser();args.add_argument('--preflight',action='store_true');args=args.parse_args()
    os.umask(0o077);report={'preflight_only':args.preflight,'Python_units_requested':27,'audit_tests_per_phase':4,'static_audit_PFP_verified':False,
        'protocol_runtime_bodies':0,'SDK_runtime_bodies':0,'global_qualification':False,'raw_logs_exported':False,'automatic_retries':0,'mutation_attempted':False}
    try:
        report['source']=source_guard(args.preflight);report['controls']=controls();save(report)
        if not args.preflight:runtime(report)
        report['controller_completed']=True;save(report)
    except Exception as error:report['controller_failure_type']=type(error).__name__;save(report);raise
    finally:report['final_HEAD_pristine']=subprocess.run(['git','diff','--quiet','HEAD']).returncode==0;save(report)
if __name__=='__main__':main()
