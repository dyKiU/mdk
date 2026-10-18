#!/usr/bin/env python3
"""Current exact-source lookup: three real controls and optional App-only PFP."""
import argparse, hashlib, json, os, re, shutil, stat, subprocess, time, sys
from pathlib import Path
import qualify_upstream_storage_boundary as bounded
import qualify_upstream_storage_app_handles as counts
import upstream_completion_ci as completion
ensure=bounded.ensure
BASE='df0e2177230fbe17cbd1d193e05c463efea37df9'
WORKFLOW_SHA='858bf92cd06c6f7e374e202692a4b556a65896d4724c5ad65d6748c6eae3ce84'
SELF='scripts/qualify_upstream_record_source_lookup.py'
WORKFLOW='.github/workflows/record-source-lookup.yml'
REF='refs/heads/ci/upstream-record-source-lookup-20261018'
PRODUCT='crates/marmot-app/src/client/account_chat_sharing/automatic/records.rs'
PRODUCT_SHA='f433c23c32115850168fac6ee682992aa359da145655facec08e20a833c9b6d8'
FIXED_LOOKUP='        let source = self\n            .runtime\n            .session()\n            .account_chat_catalog_entry(&entry.policy.protected_group, group)\n            .map_err(|_| AccountSharingError::Closed)?;\n        Ok(source.map(|source| source.epoch))\n'
CURSOR_LOOKUP='        let page = self\n            .runtime\n            .session()\n            .account_chat_catalog(\n                &entry.policy.protected_group,\n                entry.records.group_after.as_ref(),\n                1,\n            )\n            .map_err(|_| AccountSharingError::Closed)?;\n        Ok(page\n            .entries\n            .first()\n            .filter(|source| &source.group_id == group)\n            .map(|source| source.epoch))\n'
MUTANT_SHA='27a520673527218fdc8df0a6b7926f3eb3c3049f70752fa4a482d095610a8608'
FIXTURE='crates/marmot-app/src/client/account_chat_sharing/automatic/tests/record_source_lookup.rs'
MESSAGE='an actual requested source must remain valid independently of its discovery-page position'
OUT=Path('record-source-lookup-evidence')
APP_NAME='client::account_chat_sharing::automatic::records::source_lookup_tests::record_source_epoch_is_independent_of_catalogue_position'
CORE_NAMES=['history_transfer::tests::account_chat_catalog_discovers_actual_nonadmin_membership_without_grant','history_transfer::tests::account_chat_catalog_pages_same_title_chats_by_canonical_identity']
NAMES=CORE_NAMES+[APP_NAME]
FEATURES='marmot-app/otlp-export,marmot-app/product-analytics-export,marmot-app/test-policy-overrides,marmot-app/experimental-device-sync,cgka-engine/test-policy-overrides,cgka-engine/test-crash-hooks'
CORE_FEATURES=['experimental-device-sync','test-policy-overrides','test-crash-hooks']
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
        and os.environ.get('UPSTREAM_RECORD_SOURCE_BASELINE')==BASE,'exact-hosted-ref-source')
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
        and Path(PRODUCT).read_bytes().count(FIXED_LOOKUP.encode())==1,'exact-workflow-and-product-witness')
    ensure(set(git('ls-files','--others','--exclude-standard').decode().splitlines())<={str(OUT/'result.json')},'untracked-closure')
    return {'head':head,'baseline':BASE,'whole_source_modes_verified':True,'Rust_exceptions':[],
        'old_guards_or_main_called':False,'old_module_globals_mutated':False,'historical_runtime_reused':False}

def clean(raw):return re.sub(r'\x1b\[[0-9;]*m','',raw)
def expected_site(source):
    lines=source.splitlines();hits=[i for i,line in enumerate(lines) if MESSAGE in line]
    ensure(len(hits)==1,'unique-source-lookup-assertion')
    i=hits[0];j=max(k for k in range(i+1) if 'assert_eq!(' in lines[k])
    ensure('actual' in '\n'.join(lines[j:i+1]) and 'Some(later.epoch)' in '\n'.join(lines[j:i+1]),'actual-later-source-oracle')
    return {'file':FIXTURE,'line':j+1,'column':lines[j].index('assert_eq!')+1}

def app_verdict(raw,code,basic,expected,source):
    text=clean(raw)
    lines=[re.sub(r'^test '+re.escape(APP_NAME)+r' \.\.\. ','',line) for line in text.splitlines() if 'record-source-control' in line]
    ensure(len(lines)==4 and sum(len(line.encode()) for line in lines)<=1024,'four-closed-source-control-markers')
    patterns=[r'record-source-control actual_pair_and_two_runtime_closes=(true|false)',
        r'record-source-control two_actual_catalog_sources=(true|false) later_local_leaf_active=(true|false) first_source_lookup=(true|false)',
        r'record-source-control later_source_lookup=(true|false)',
        r'record-source-control runtime_closes=([012]) reopened_storage_closed=(true|false)']
    values=[re.fullmatch(pattern,line) for pattern,line in zip(patterns,lines)]
    ensure(all(value is not None for value in values),'exact-source-control-grammar-and-order')
    pair,groups,later,close=values
    prerequisites=pair[1]==groups[1]==groups[2]==groups[3]==close[2]=='true' and close[1]=='2'
    site=expected_site(source)
    headers=re.findall(r"(?m)^thread '([^'\n]+)'(?: \([1-9][0-9]*\))? panicked at ([A-Za-z0-9_./-]+):([0-9]+):([0-9]+):\n([^\n]*)",text)
    total=len(re.findall(r'(?m)^thread .* panicked at ',text))
    sole=(len(headers)==total==1 and headers[0]==(APP_NAME,site['file'],str(site['line']),str(site['column']),'assertion `left == right` failed: '+MESSAGE)
        and re.search(r'(?m)^  left: None\n right: Some\((?:0|[1-9][0-9]{0,19})\)\s*$',text) is not None)
    complete=basic.get('actual_counts_complete') is True and basic.get('executed_nonignored')==1 and basic.get('ignored')==0 and basic.get('compiler_error_count')==0
    green=complete and basic.get('passed_gate') is True and prerequisites and later[1]=='true' and total==0
    red=complete and type(code)is int and code==101 and basic.get('passed')==0 and basic.get('failed')==1 and basic.get('panic_count')==1 and prerequisites and later[1]=='false' and sole
    return {'positive_pair_and_initial_closes':pair[1]=='true','two_real_sources_current_later_membership_first_lookup':groups[1]==groups[2]==groups[3]=='true',
        'later_source_lookup':later[1]=='true','initial_runtime_closes_observed':int(close[1]),'reopened_storage_closed':close[2]=='true',
        'all_positive_prerequisites':prerequisites,'expected_panic_site':site,'sole_later_source_assertion':sole,'focused_GREEN':green,'genuine_behavioral_RED':red,
        'expected_outcome_verified':red if expected=='red' else green}

def verdict(raw,code,basic,name,expected):
    if name==APP_NAME:return app_verdict(raw,code,basic,expected,Path(FIXTURE).read_text())
    ensure(name in CORE_NAMES and expected=='green','only-two-source-pinned-Core-controls')
    return {'expected_outcome_verified':basic.get('passed_gate') is True,'source_pinned_real_Core_filter_and_freshness_assertions':True,'separate_cleanup_marker_observed':False}

def compile_unit(root,row,label,tracked):
    package='cgka-engine' if label=='core' else 'marmot-app'
    target_name='cgka_engine' if label=='core' else 'marmot_app'
    own_features=CORE_FEATURES if label=='core' else ['otlp-export','product-analytics-export','test-policy-overrides','experimental-device-sync']
    flags=','.join(CORE_FEATURES) if label=='core' else FEATURES
    command=['cargo','test','--locked','-p',package,'--lib','--no-run','--message-format=json','--features',flags]
    code,raw,seconds=bounded.capture(command,1800,limit=8*1024*1024)
    events=[];malformed=0
    for line in raw.splitlines():
        if not line.startswith('{'):continue
        try:events.append(json.loads(line))
        except ValueError:malformed+=1
    errors=[v for v in events if v.get('reason')=='compiler-message' and v.get('message',{}).get('level')=='error']
    finished=[v for v in events if v.get('reason')=='build-finished']
    complete=len(finished)==1 and finished[0].get('success') is True and malformed==0
    artifacts=[v for v in events if v.get('reason')=='compiler-artifact']
    selected=[v for v in artifacts if v.get('target',{}).get('name')==target_name and v['target'].get('kind')==['lib'] and v.get('profile',{}).get('test') is True and v.get('executable')]
    codes=sorted({v['message']['code']['code'] for v in errors if type(v.get('message',{}).get('code'))is dict and re.fullmatch('E[0-9]{4}',v['message']['code'].get('code',''))})
    sites=[{'file':s['file_name'],'line':s['line_start'],'column':s['column_start']} for v in errors for s in v.get('message',{}).get('spans',[]) if s.get('file_name') in tracked and s.get('is_primary') is True]
    row.update(command=command,exit_code=code,seconds=seconds,compiler_error_count=len(errors) if finished else None,
        compiler_codes=codes[:32],compiler_sites=sites[:32],diagnostics_truncated=len(codes)>32 or len(sites)>32,
        build_finished_success=complete,malformed_JSON_lines=malformed,selected_test_artifact_count=len(selected),features_requested=flags);save(root)
    ensure(type(code)is int and code==0 and complete and not errors and len(selected)==1,'one-successful-exact-unit-compile')
    artifact=selected[0];observed=artifact.get('features')
    ensure(type(observed)is list and all(type(v)is str for v in observed) and len(observed)==len(set(observed)) and set(observed)-{'default'}==set(own_features),'actual-own-unit-cohort')
    binary=Path(artifact['executable']);target=Path(os.environ.get('CARGO_TARGET_DIR','target')).resolve()
    ensure(binary.is_file() and not binary.is_symlink() and binary.resolve().is_relative_to(target) and re.fullmatch(target_name+'-[0-9a-f]{16}',binary.name),'regular-owned-test-binary')
    row['own_observed_features']=sorted(observed)
    row['all_artifact_feature_manifest_sha256']=digest(json.dumps([{'target':v['target']['name'],'features':v['features'],'profile':v['profile']} for v in artifacts],sort_keys=True).encode())
    if label=='app':
        graph=completion.feature_metadata(binary);row['dependency_fingerprints']=graph;save(root)
        ensure(graph.get('verified') is True and {'marmot_app','cgka_engine','storage_sqlite','cgka_session','marmot_account','transport_nostr'}<=set(graph.get('nodes',{}))
            and {'experimental-device-sync','test-policy-overrides','test-crash-hooks'}<=set(graph['nodes']['cgka_engine']['features']),'actual-App-six-node-dependency-cohort')
    save(root);return binary

def aggregate(cases,expected_count):
    result={'actual_case_rows':len(cases),'expected_case_rows':expected_count,'unknown_count_cases':sum(any(type(row.get('basic_counts',{}).get(k)) is not int for k in ['passed','failed','ignored','executed_nonignored']) for row in cases),'nonqualifying_count_shape_cases':sum(row.get('basic_counts',{}).get('actual_counts_complete') is not True for row in cases),'missing_case_rows':max(0,expected_count-len(cases))}
    for key in ['passed','failed','ignored','executed_nonignored']:
        values=[row.get('basic_counts',{}).get(key) for row in cases]
        known=[v for v in values if type(v) is int and v>=0]
        result['actual_'+key]=sum(values) if len(cases)==expected_count and len(known)==len(values) else None
        result['known_partial_'+key]=sum(known) if known else None
    return result

def execute_case(root,row,binary,before,mode,expected_inputs,name,expected,binaries,all_before):
    row.update(name=name,expected=expected,runtime_attempted=False,actual_executed_nonignored=0,expected_outcome_verified=False)
    save(root)
    for ignored in [False,True]:
        code,text,_=bounded.capture([str(binary),'--exact',name]+(['--ignored'] if ignored else [])+['--list','--format','terse'],60,limit=1024*1024)
        item=counts.parse_inventory(text,name,ignored);row.setdefault('inventory',{})['ignored' if ignored else 'normal']=item;save(root)
        ensure(code==0 and item['passed'],'one-normal-zero-ignored-exact-case')
    ensure(physical()==expected_inputs and binary_states(binaries)==all_before,'prebody-source-binary-mode')
    row.update(runtime_attempted=True,actual_executed_nonignored=None);save(root)
    try:code,raw,seconds=bounded.capture([str(binary),'--exact',name,'--nocapture','--test-threads=1'],300,limit=8*1024*1024)
    except bounded.GateFailure as error:
        row['watchdog_triggered']=str(error)=='bounded-command-timeout';row['output_limit_triggered']=str(error)=='bounded-command-output-limit';save(root);raise
    row.update(body_exit_code=code,body_seconds=seconds,source_after_body_pristine=physical()==expected_inputs,
        binary_after_sha256=digest(binary.read_bytes()) if binary.is_file() and not binary.is_symlink() else None,
        binary_after_mode=stat.S_IMODE(binary.stat().st_mode) if binary.is_file() and not binary.is_symlink() else None,both_binaries_after=binary_states(binaries));save(root)
    basic=counts.parse_body(raw,code,name);row['basic_counts']=basic
    for dest,key in [('actual_passed','passed'),('actual_failed','failed'),('actual_ignored','ignored'),('actual_executed_nonignored','executed_nonignored')]:row[dest]=basic.get(key)
    row['actual_test_passed']=basic.get('passed_gate') is True;save(root)
    ensure(row['source_after_body_pristine'] and row['binary_after_sha256']==before and row['binary_after_mode']==mode and row['both_binaries_after']==all_before,'postbody-source-binary-mode')
    row['outcome']=verdict(raw,code,basic,name,expected)
    row['expected_outcome_verified']=row['outcome']['expected_outcome_verified'];save(root)

def binary_states(binaries):
    return {key:{'path':str(path),'sha256':digest(path.read_bytes()),'mode':stat.S_IMODE(path.stat().st_mode)} for key,path in binaries.items() if path.is_file() and not path.is_symlink()}

def phase(root,label,cohort,expected_inputs,specs,different_from=None):
    row={'cases':[],'phase_passed':False,'expected_case_count':len(specs),'compilation':{}};root.setdefault('phases',{})[label]=row;save(root)
    ensure(physical()==expected_inputs,'phase-before-compile-pristine')
    binaries={}
    for unit in ['core','app']:
        row['compilation'][unit]={};save(root)
        binaries[unit]=compile_unit(root,row['compilation'][unit],unit,set(expected_inputs))
    before=binary_states(binaries);row['binaries_before']=before;save(root)
    ensure(set(before)=={'core','app'} and physical()==expected_inputs,'phase-after-compile-pristine')
    if different_from is not None:
        ensure(before['app']['sha256']!=different_from['app']['sha256'] and before['core']==different_from['core'],'only-App-mutant-binary-diff-Core-unchanged')
    for name,expected in specs:
        case={};row['cases'].append(case);save(root);unit='app' if name==APP_NAME else 'core';binary=binaries[unit]
        try:execute_case(root,case,binary,before[unit]['sha256'],before[unit]['mode'],expected_inputs,name,expected,binaries,before)
        except Exception as error:case['controller_failure_type']=type(error).__name__;save(root)
    row.update(aggregate(row['cases'],len(specs)));row['source_after_phase_pristine']=physical()==expected_inputs
    row['both_binaries_after_phase_pristine']=binary_states(binaries)==before
    row['phase_passed']=row['source_after_phase_pristine'] and row['both_binaries_after_phase_pristine'] and len(row['cases'])==len(specs) and all(case.get('expected_outcome_verified') is True for case in row['cases'])
    save(root);return binaries,before

def write_fresh(path,data,mode):
    previous=path.stat().st_mtime_ns if path.exists() else 0
    path.write_bytes(data);path.chmod(mode)
    timestamp=max(time.time_ns(),previous+2_000_000_000);os.utime(path,ns=(timestamp,timestamp))

def restore_owned(path,data,mode):
    if path.is_symlink():path.unlink()
    ensure(not path.exists() or path.is_file(),'owned-restore-file-kind')
    write_fresh(path,data,mode)

def runtime(report,expected):
    frozen=physical();product=Path(PRODUCT);original=product.read_bytes();product_mode=stat.S_IMODE(product.stat().st_mode)
    binaries={};before=None;baseline_bytes={};mutation_attempted=False
    report.update(runtime_attempted=False,mutation_attempted=False,component_PFP_verified=False,fallback_source_restore_used=False,fallback_binary_copy_used=False)
    specs=[(name,'green') for name in NAMES]
    try:
        report['free_bytes']=shutil.disk_usage('.').free;save(report);ensure(report['free_bytes']>=8*1024**3,'remote-disk-reserve')
        binaries,before=phase(report,'baseline','experimental',frozen,specs)
        baseline_bytes={key:path.read_bytes() for key,path in binaries.items()}
        if expected=='green':
            report['expected_outcome_verified']=report['phases']['baseline']['phase_passed'];save(report);ensure(report['expected_outcome_verified'],'baseline-three-GREEN-required');return
        if report['phases']['baseline']['phase_passed'] is not True:
            report['skipped_mutant_and_restored_reason']='baseline_unqualified_no_mutation_attempted';save(report);raise ValueError('baseline-admission-required')
        ensure(digest(original)==PRODUCT_SHA and original.count(FIXED_LOOKUP.encode())==1,'exact-fixed-lookup-source')
        mutant=original.replace(FIXED_LOOKUP.encode(),CURSOR_LOOKUP.encode(),1);ensure(digest(mutant)==MUTANT_SHA,'full-reviewed-cursor-mutant-blob')
        expected_mutant=dict(frozen);expected_mutant[PRODUCT]=(frozen[PRODUCT][0],product_mode,digest(mutant))
        try:
            mutation_attempted=True;report['mutation_attempted']=True;save(report);write_fresh(product,mutant,product_mode)
            ensure(physical()==expected_mutant,'only-App-source-lookup-mutation')
            phase(report,'mutant','experimental',expected_mutant,[(APP_NAME,'red')],different_from=before)
        except Exception as error:report['mutant_controller_failure_type']=type(error).__name__;save(report)
        finally:
            restore_owned(product,original,product_mode);report['source_restored_before_fresh_compile']=physical()==frozen;save(report)
            ensure(report['source_restored_before_fresh_compile'],'exact-source-restoration')
            try:phase(report,'restored','experimental',frozen,specs)
            except Exception as error:report['restored_controller_failure_type']=type(error).__name__;save(report)
        rows=[case for label in ['baseline','mutant','restored'] for case in report['phases'].get(label,{}).get('cases',[])]
        report['aggregate']=aggregate(rows,7)
        report['baseline_restored_binaries_equal']=report['phases'].get('restored',{}).get('binaries_before')==before
        signatures=[{unit:{'own':phase_row.get('compilation',{}).get(unit,{}).get('own_observed_features'),
            'dependencies':{name:node['features'] for name,node in phase_row.get('compilation',{}).get(unit,{}).get('dependency_fingerprints',{}).get('nodes',{}).items()}} for unit in ['core','app']} for phase_row in [report['phases'].get(label,{}) for label in ['baseline','mutant','restored']]]
        report['same_observed_feature_cohort']=signatures[0]==signatures[1]==signatures[2]
        report['component_PFP_verified']=(all(report['phases'].get(label,{}).get('phase_passed') is True for label in ['baseline','mutant','restored'])
            and report['aggregate'].get('actual_passed')==6 and report['aggregate'].get('actual_failed')==1 and report['aggregate'].get('actual_ignored')==0
            and report['aggregate'].get('actual_executed_nonignored')==7 and report['baseline_restored_binaries_equal'] and report['same_observed_feature_cohort'])
        report['expected_outcome_verified']=report['component_PFP_verified'];save(report);ensure(report['component_PFP_verified'],'seven-actual-body-PFP-required')
    finally:
        if product.is_symlink() or not product.is_file() or product.read_bytes()!=original or stat.S_IMODE(product.stat().st_mode)!=product_mode:
            report['fallback_source_restore_used']=True;report['component_PFP_verified']=False;report['expected_outcome_verified']=False;restore_owned(product,original,product_mode)
        report['source_final_pristine']=physical()==frozen
        if before is not None:
            if binary_states(binaries)!=before:
                report['fallback_binary_copy_used']=True;report['component_PFP_verified']=False;report['expected_outcome_verified']=False
                for key,path in binaries.items():restore_owned(path,baseline_bytes[key],before[key]['mode'])
            report['both_binaries_final_pristine']=binary_states(binaries)==before
        if not report['source_final_pristine'] or report.get('both_binaries_final_pristine') is False:report['component_PFP_verified']=False;report['expected_outcome_verified']=False
        cases=[case for row in report.get('phases',{}).values() for case in row.get('cases',[])]
        report['runtime_attempted']=any(case.get('runtime_attempted') for case in cases)
        report['actual_body_counts']=aggregate(cases,7 if expected=='pfp' and mutation_attempted else 3)
        for key in ['passed','failed','ignored','executed_nonignored']:report['actual_'+key]=report['actual_body_counts']['actual_'+key]
        if not report['runtime_attempted']:report['actual_executed_nonignored']=0
        save(report);ensure(report['source_final_pristine'] and report.get('both_binaries_final_pristine',True),'final-source-both-binaries')
        if sys.exc_info()[0] is None:
            ensure(report.get('expected_outcome_verified') is True and not report['fallback_source_restore_used'] and not report['fallback_binary_copy_used'],'final-outcome-without-fallback')
            if expected=='pfp':ensure(report['component_PFP_verified'],'final-PFP-qualified')

def controls():
    fixture=Path(FIXTURE).read_text();site=expected_site(fixture)
    markers='record-source-control actual_pair_and_two_runtime_closes=true\nrecord-source-control two_actual_catalog_sources=true later_local_leaf_active=true first_source_lookup=true\nrecord-source-control later_source_lookup=false\nrecord-source-control runtime_closes=2 reopened_storage_closed=true\n'
    panic="thread '"+APP_NAME+"' panicked at "+FIXTURE+':'+str(site['line'])+':'+str(site['column'])+':\nassertion `left == right` failed: '+MESSAGE+'\n  left: None\n right: Some(7)\n'
    red='running 1 test\ntest '+APP_NAME+' ... '+markers+panic+'FAILED\ntest result: FAILED. 0 passed; 1 failed; 0 ignored; 0 measured; 0 filtered out; finished in 1s\n'
    check=lambda raw:app_verdict(raw,101,counts.parse_body(raw,101,APP_NAME),'red',fixture)['expected_outcome_verified']
    ensure(check(red),'source-shaped-actual-later-source-RED')
    green='running 1 test\ntest '+APP_NAME+' ... '+markers.replace('later_source_lookup=false','later_source_lookup=true')+'ok\ntest result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 1s\n'
    ensure(app_verdict(green,0,counts.parse_body(green,0,APP_NAME),'green',fixture)['expected_outcome_verified'],'source-shaped-actual-source-GREEN')
    negatives=[red.replace('two_runtime_closes=true','two_runtime_closes=false'),red.replace('two_actual_catalog_sources=true','two_actual_catalog_sources=false'),red.replace('later_local_leaf_active=true','later_local_leaf_active=false'),red.replace('first_source_lookup=true','first_source_lookup=false'),red.replace('runtime_closes=2','runtime_closes=1'),red.replace('reopened_storage_closed=true','reopened_storage_closed=false'),red.replace(MESSAGE,'foreign oracle'),red.replace('  left: None','  left: Some(7)'),red.replace('0 ignored','1 ignored'),red.replace('0 passed; 1 failed','0 passed; 0 failed'),red.replace(panic,''),red+panic]
    for raw in negatives:ensure(not check(raw),'prerequisite-or-unrelated-failure-negative')
    for raw in [red+markers,red.replace('later_source_lookup=false','later_source_lookup=unknown')]:
        try:accepted=check(raw)
        except ValueError:accepted=False
        ensure(not accepted,'malformed-marker-negative')
    return {'App_positive':2,'App_negative':14,'counts':counts.parser_controls(),'runtime_bodies':0}

def main():
    parser=argparse.ArgumentParser();parser.add_argument('--preflight',action='store_true');parser.add_argument('--expected',choices=['green','pfp'],default='pfp');args=parser.parse_args()
    report={'scope':'exact current source lookup three real controls; App-only cursor mutation','preflight':args.preflight,'expected':args.expected,'runtime_attempted':False,
        'actual_executed_nonignored':0,'qualification_passed':False,'native_global_qualification':False,'automatic_retries':0,'RUST_MIN_STACK':4194304,
        'App_fixture_Tokio_flavor':'current_thread','Core_fixture_Tokio_flavor':'source-defined','original_App_pair_deadline_seconds':90,'outer_body_seconds':300,'raw_output_retained':False}
    try:
        report['source_guard']=source_guard(args.preflight);save(report);report['parser_controls']=controls();save(report)
        if not args.preflight:runtime(report,args.expected)
        report['controller_completed']=True;save(report)
    except Exception as error:report['controller_failure_type']=type(error).__name__;save(report);raise
    finally:report['final_HEAD_git_pristine']=subprocess.run(['git','diff','--quiet','HEAD']).returncode==0;save(report)
if __name__=='__main__':main()
