#!/usr/bin/env python3
"""One strict real SDK five-installation component control; no global qualification."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import qualify_upstream_pure_command_offer as offer
import qualify_upstream_request_retry_ack as ack
import qualify_upstream_storage_boundary as bounded
import qualify_upstream_storage_app_handles as counts
from upstream_completion_ci import compile_cases, digest, ensure, parse_body as basic_parse_body
from qualify_upstream_body_negative import feature_identity
from upstream_extraction_cohort import frozen_inputs
BASE='d2f9b701b98ed30be04e46acdcedfed931a1c8e5'
MANIFEST_SHA='6c4b9bc09b21c96533f2bb123122c9b934bc4012103a8db9610b603be647c4e2'
SELF='scripts/qualify_upstream_pure_native5.py'
MANIFEST='scripts/pure_command_offer_source_manifest.json'
REF='refs/heads/ci/upstream-command-offer-pure-20261018'
OUT=Path('pure-native5-evidence')
FIXTURE='crates/marmot-app/src/native_device_linking/tests/sequential_installations_acceptance.rs'
PARENT='crates/marmot-app/src/native_device_linking/tests/automatic_pairing_acceptance.rs'
FIXTURE_SHA='a81cc692c9864d9cdf2ff7fe8d533d3115c7eb7958fa7a22df783850fea520ca'
STRICT_HELPER_SHA='a059addf027097d91c672ccfe36e613f99cfb93f889ab2087b872a84c7a58ff2'
ORACLE_SHA='88417f89d6d6b3b9a8037d408be60c54d8b86451085cff9d254cb6cc74537e72'
SUFFIX='sequential_installations_acceptance::five_installations_join_with_rotating_existing_sponsors_and_explicit_sharing'
NAME='native_device_linking::automatic_pairing_acceptance::'+SUFFIX
NODES={'marmot_app','cgka_engine','storage_sqlite','cgka_session','marmot_account','transport_nostr'}
MARKER='sequential-installations completed_steps=4 final_device_count=5 final_roster_and_policies=true public_cancels=14 runtime_closes=5 storages_closed=true plane_shutdown_returns=5 listener_closed=true attempt_completed=true'


def source_guard():
    ensure(type(BASE) is str and re.fullmatch('[0-9a-f]{40}',BASE),'final-pure-native5-BASE-required')
    ensure(type(MANIFEST_SHA) is str and re.fullmatch('[0-9a-f]{64}',MANIFEST_SHA),'final-shared-native5-manifest-required')
    ensure(BASE==offer.BASE and MANIFEST_SHA==offer.MANIFEST_SHA and REF==offer.REF and MANIFEST==offer.MANIFEST,'shared-configuration-equality')
    ensure(digest(Path(MANIFEST).read_bytes())==MANIFEST_SHA,'native5-shared-manifest-pin')
    manifest,row=offer.source_guard() # Only the new shared guard; never another controller main.
    pins=manifest['native5']
    ensure(pins['fixture']==FIXTURE and pins['fixture_sha256']==FIXTURE_SHA
        and pins['parent']==PARENT and re.fullmatch('[0-9a-f]{64}',pins['parent_sha256'])
        and pins['strict_helper_sha256']==STRICT_HELPER_SHA and pins['oracle_region_sha256']==ORACLE_SHA,'explicit-native5-source-pins')
    ensure(digest(Path(FIXTURE).read_bytes())==FIXTURE_SHA and digest(Path(PARENT).read_bytes())==pins['parent_sha256'],'exact-final-native5-fixture-parent')
    parent=Path(PARENT).read_text();start=parent.index('async fn wait_for_automatic_phase_with_approvals(')
    end=parent.index('\n}\n',start)+3
    ensure(digest(parent[start:end].encode())==STRICT_HELPER_SHA,'unchanged-strict15-helper')
    text=Path(SELF).read_text();begin='# NATIVE5_IMMUTABLE_ORACLE_BEGIN\n';endmark='# NATIVE5_IMMUTABLE_ORACLE_END\n'
    ensure(text.count(begin)==text.count(endmark)==1,'one-immutable-native5-oracle')
    oracle=text.split(begin,1)[1].split(endmark,1)[0]
    ensure(digest(oracle.encode())==ORACLE_SHA,'verbatim-reviewed-native5-oracle')
    return row

# NATIVE5_IMMUTABLE_ORACLE_BEGIN
def parse(raw,code):
    # Exact-name/count parser is unchanged shared infrastructure. Preserve original libtest prefix.
    row=counts.parse_body(raw,code,NAME)
    clean=re.sub(r'\x1b\[[0-9;]*m','',raw)
    marker_text=re.sub(r'(?m)^test '+re.escape(NAME)+r' \.\.\. (?=sequential-installations )','',clean)
    lines=[line for line in marker_text.splitlines() if line.startswith('sequential-installations')]
    row['marker_count']=len(lines);row['facts']=None
    pattern=(r'sequential-installations completed_steps=([0-4]) final_device_count=([0-5]) final_roster_and_policies=(true|false)'
        r' public_cancels=([0-9]{1,2}) runtime_closes=([0-5]) storages_closed=(true|false) plane_shutdown_returns=([0-5])'
        r' listener_closed=(true|false) attempt_completed=(true|false)')
    match=re.fullmatch(pattern,lines[0]) if len(lines)==1 and len(lines[0])<=512 else None
    if match and int(match[4])<=14:
        row['facts']={'completed_steps':int(match[1]),'final_device_count':int(match[2]),'final_roster_and_policies':match[3]=='true',
            'public_cancels':int(match[4]),'runtime_closes':int(match[5]),'storages_closed':match[6]=='true',
            'plane_shutdown_returns':int(match[7]),'listener_closed':match[8]=='true','attempt_completed':match[9]=='true'}
    return row

def green(row):
    facts=row.get('facts')
    return (row.get('actual_counts_complete') is True and row.get('passed_gate') is True
        and all(type(row.get(k)) is int and row[k]==v for k,v in {'passed':1,'failed':0,'ignored':0,'executed_nonignored':1,'exit_code':0,'compiler_error_count':0,'panic_count':0,'marker_count':1}.items())
        and isinstance(facts,dict) and all(type(facts.get(k)) is int and facts[k]==v for k,v in
            {'completed_steps':4,'final_device_count':5,'public_cancels':14,'runtime_closes':5,'plane_shutdown_returns':5}.items())
        and all(facts.get(k) is True for k in ['final_roster_and_policies','storages_closed','listener_closed','attempt_completed']))

def parser_controls():
    inherited=counts.parser_controls()
    raw='running 1 test\ntest '+NAME+' ... ok\n'+MARKER+'\ntest result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 2 filtered out; finished in 1.0s\n'
    ensure(green(parse(raw,0)),'closed-five-positive')
    shared=raw.replace(' ... ok\n'+MARKER,' ... '+MARKER+'\nok')
    ensure(green(parse(shared,0)),'exact-libtest-shared-marker-positive')
    bad=[raw.replace('completed_steps=4','completed_steps=3'),raw.replace('final_device_count=5','final_device_count=4'),
        raw.replace('final_roster_and_policies=true','final_roster_and_policies=false'),raw.replace('public_cancels=14','public_cancels=13'),
        raw.replace('runtime_closes=5','runtime_closes=4'),raw.replace('storages_closed=true','storages_closed=false'),
        raw.replace('plane_shutdown_returns=5','plane_shutdown_returns=4'),raw.replace('listener_closed=true','listener_closed=false'),
        raw.replace('attempt_completed=true','attempt_completed=false'),raw+'\n'+MARKER,raw.replace(MARKER,''),
        raw.replace(NAME,NAME+'_foreign'),raw.replace('0 ignored','1 ignored'),raw.replace('1 passed','0 passed'),
        raw.replace(MARKER,MARKER+' private=hidden'),raw.replace('public_cancels=14','public_cancels=99'),raw.replace('storages_closed=true','storages_closed=hidden'),
        raw+raw,raw+'error[E0000]: rejected\n',raw+"thread 'closed' panicked at crates/closed.rs:1:1:\n"]
    for text in bad:ensure(not green(parse(text,0)),'closed-five-adversary')
    ensure(not green(parse(raw,124)),'watchdog-not-pass')
    row=parse(raw,0)
    for key in ['passed','failed','ignored','executed_nonignored','exit_code','compiler_error_count','panic_count','marker_count']:
        ensure(not green({**row,key:True}),'bool-not-body-count')
    return {'shared_count_inventory_controls':inherited,'positive':2,'negative':len(bad)+9,'actual_runtime_executions':0}

# NATIVE5_IMMUTABLE_ORACLE_END


def safe_compilation(row):
    # Preserve closed compiler codes and source sites, never private diagnostic text.
    raw=row.pop('compiler_headers',[])
    row['compiler_codes']=sorted(set(code for line in raw for code in re.findall(r'\berror\[(E[0-9]{4})\]',line)))
    row['compiler_sites']=[{'file':match[1],'line':int(match[2]),'column':int(match[3])}
        for line in raw if (match:=re.fullmatch(r'\s*--> (crates/[A-Za-z0-9_./-]+\.rs):([0-9]{1,7}):([0-9]{1,7})',line))]
    return row


def execute_one(report,save):
    """Reusable one-case body runner; caller owns source guard and global qualification."""
    frozen=frozen_inputs();binary=None;before_sha=None
    report.update(runtime_execution_attempted=False,actual_counts_complete=False,actual_passed=None,
        actual_failed=None,actual_ignored=None,actual_executed_nonignored=None,native5_component_control_passed=False)
    report['source_manifest_sha256']=digest(json.dumps(frozen,sort_keys=True).encode());save()
    try:
        report['capacity']={'free_bytes':shutil.disk_usage('.').free,'minimum_free_bytes':8*1024**3};save()
        ensure(report['capacity']['free_bytes']>=8*1024**3,'remote-capacity')
        compilation,cases=compile_cases([SUFFIX]);report['compilation']=safe_compilation(compilation);save()
        ensure(type(compilation.get('compile_exit_code')) is int and compilation['compile_exit_code']==0
            and type(compilation.get('compiler_error_count')) is int and compilation['compiler_error_count']==0
            and compilation.get('compiled_fingerprints',{}).get('verified') is True and set(cases)=={SUFFIX},'one-actual-compiled-native5-case')
        case=cases[SUFFIX];ensure(case['name']==NAME,'exact-native5-fullname')
        binary=Path(case['binary']);before_sha=case['binary_sha256']
        report['binary_before_sha256']=before_sha;report['feature_identity']=feature_identity(compilation);save()
        ensure(set(report['feature_identity']['nodes'])==NODES,'six-real-feature-fingerprints')
        for ignored in [False,True]:
            command=[case['binary'],'--exact',NAME]+(['--ignored'] if ignored else [])+['--list','--format','terse']
            code,raw,_=bounded.capture(command,60,limit=1024*1024)
            row=counts.parse_inventory(raw,NAME,ignored)
            report.setdefault('inventory',{})['ignored' if ignored else 'normal']=row;save()
            ensure(code==0 and row['passed'],'exact-one-nonignored-native5-inventory')
        ensure(frozen_inputs()==frozen and binary.is_file() and digest(binary.read_bytes())==before_sha,'before-native5-inputs-binary-pristine')
        report['runtime_execution_attempted']=True;save()
        try:
            code,raw,seconds=bounded.capture([case['binary'],'--exact',NAME,'--nocapture','--test-threads=1'],900,limit=8*1024*1024)
            # Save observed counts and physical post-body checks before strict marker classification.
            report['body_seconds']=seconds;report['body_exit_code']=code
            basic=counts.parse_body(raw,code,NAME);report['body']=basic
            report['actual_counts_complete']=basic.get('actual_counts_complete') is True
            for target,key in [('actual_passed','passed'),('actual_failed','failed'),('actual_ignored','ignored'),('actual_executed_nonignored','executed_nonignored')]:
                report[target]=basic.get(key)
            report['binary_after_sha256']=digest(binary.read_bytes()) if binary.is_file() else None
            report['inputs_after_body_pristine']=frozen_inputs()==frozen
            report['binary_after_body_pristine']=report['binary_after_sha256']==before_sha;save()
            report['body']=parse(raw,code)
            report['native5_component_control_passed']=green(report['body'])
            report['plane_shutdown_semantics']='five returned shutdown calls; internal task quiescence not established';save()
        except bounded.GateFailure as error:
            report['watchdog_triggered']=str(error)=='bounded-command-timeout'
            report['output_limit_triggered']=str(error)=='bounded-command-output-limit';save();raise
        ensure(report['inputs_after_body_pristine'] and report['binary_after_body_pristine'],'after-native5-inputs-binary-pristine')
        ensure(report['native5_component_control_passed'],'actual-native5-all-four-joins-and-cleanup-required')
    finally:
        report['inputs_pristine']=frozen_inputs()==frozen
        if not report['runtime_execution_attempted']:report['actual_executed_nonignored']=0
        if binary is not None:
            report['binary_final_sha256']=digest(binary.read_bytes()) if binary.is_file() else None
            report['binary_pristine']=report['binary_final_sha256']==before_sha
        if report['inputs_pristine'] is not True or report.get('binary_pristine') is False:
            report['observed_body_control_passed']=report['native5_component_control_passed']
            report['native5_component_control_passed']=False
        save()
        ensure(report['inputs_pristine'],'final-native5-inputs-pristine')
        if binary is not None:ensure(report['binary_pristine'],'final-native5-binary-pristine')


def full16_cases():
    selected=list(ack.CASES)
    ensure(len(selected)==16 and all(isinstance(row,(list,tuple)) and len(row)==4 for row in selected)
        and all(len({row[i] for row in selected})==16 for i in [0,1,2])
        and {'policy','stress_0','stress_1','stress_2','paused_clock'}<={row[0] for row in selected},'frozen-exact-sixteen-required-cases')
    return selected


def full16_totals(report):
    report.update(ack.alignment.aggregate_counts(report['cases']))
    report['actual_counts_complete']=all(row.get('actual_counts_complete') is True for row in report['cases'].values())


def execute_full16(report,save):
    selected=full16_cases();frozen=frozen_inputs();binary=None;before_sha=None
    report.update(scope='sixteen-original-composed-controls',full16_qualification=False,runtime_execution_attempted=False,
        required_case_count=16,cases={label:{'actual_counts_complete':False,'green':False,'actual_required_name':name,
            'suffix':suffix,'historical_oracle_label':oracle} for label,suffix,name,oracle in selected})
    report['input_manifest_sha256']=digest(json.dumps(frozen,sort_keys=True).encode());full16_totals(report);save()
    try:
        ensure(shutil.disk_usage('.').free>=8*1024**3,'remote-capacity')
        compilation,cases=compile_cases([suffix for _,suffix,_,_ in selected]);report['compilation']=safe_compilation(compilation);save()
        ensure(all(type(compilation.get(k)) is int and compilation[k]==0 for k in ['compile_exit_code','compiler_error_count'])
            and compilation.get('compiled_fingerprints',{}).get('verified') is True
            and set(cases)=={suffix for _,suffix,_,_ in selected}
            and all(cases[suffix]['name']==name for _,suffix,name,_ in selected)
            and len({case['binary_sha256'] for case in cases.values()})==1,'actual-sixteen-exact-fullnames-one-binary')
        binary=Path(next(iter(cases.values()))['binary']);before_sha=next(iter(cases.values()))['binary_sha256']
        report['binary_before_sha256']=before_sha;report['feature_identity']=feature_identity(compilation)
        ensure(set(report['feature_identity']['nodes'])==NODES,'six-actual-full16-feature-fingerprints');save()
        for label,suffix,name,_ in selected:
            row=report['cases'][label]
            for ignored in [False,True]:
                command=[str(binary),'--exact',name]+(['--ignored'] if ignored else [])+['--list','--format','terse']
                code,raw,_=bounded.capture(command,60,limit=1024*1024)
                inventory=counts.parse_inventory(raw,name,ignored)
                row.setdefault('inventory',{})['ignored' if ignored else 'normal']=inventory;save()
                ensure(code==0 and inventory['passed'],'each-full16-normal-one-ignored-zero-inventory')
        ensure(frozen_inputs()==frozen and digest(binary.read_bytes())==before_sha,'full16-after-compile-pristine')
        for label,suffix,name,_ in selected:
            row=report['cases'][label];row['runtime_started']=False;save()
            try:
                ensure(frozen_inputs()==frozen and binary.is_file() and not binary.is_symlink()
                    and digest(binary.read_bytes())==before_sha,'full16-before-body-pristine')
                row['runtime_started']=True;report['runtime_execution_attempted']=True;save()
                code,raw,seconds=bounded.capture([str(binary),'--exact',name,'--nocapture','--test-threads=1'],300,limit=8*1024*1024)
                row['body']=dict(basic_parse_body(raw,suffix),body_exit_code=code,
                    compiler_error_count=len(re.findall(r'^error(?:\[E[0-9]+\])?:',raw,re.M)))
                row['seconds']=seconds;row['actual_counts_complete']=ack.alignment.complete_counts(row['body'])
                row['binary_after_body_sha256']=digest(binary.read_bytes()) if binary.is_file() and not binary.is_symlink() else None
                row['inputs_after_body_pristine']=frozen_inputs()==frozen
                row['binary_after_body_pristine']=row['binary_after_body_sha256']==before_sha
                full16_totals(report);save() # Preserve actual counts and physical checks before strict classification.
                parsed=ack.parse_case(label,raw,code)
                row['body']=parsed;row['actual_counts_complete']=ack.alignment.complete_counts(parsed)
                row['green']=(row['actual_counts_complete'] and ack.case_green(label,parsed)
                    and type(parsed.get('compiler_error_count')) is int and parsed['compiler_error_count']==0
                    and type(parsed.get('all_panic_header_count')) is int and parsed['all_panic_header_count']==0)
            except bounded.GateFailure as error:
                row['watchdog_triggered']=str(error)=='bounded-command-timeout'
                row['output_limit_triggered']=str(error)=='bounded-command-output-limit';row['exception_type']=type(error).__name__
            except Exception as error:
                row['exception_type']=type(error).__name__;row['parser_or_case_gate_rejected']=True
            finally:
                row['inputs_pristine']=frozen_inputs()==frozen
                row['binary_final_sha256']=digest(binary.read_bytes()) if binary.is_file() and not binary.is_symlink() else None
                row['binary_pristine']=row['binary_final_sha256']==before_sha
                if not row['inputs_pristine'] or not row['binary_pristine']:row['green']=False
                full16_totals(report);save()
        report['full16_qualification']=(report['actual_counts_complete'] and all(row.get('green') is True for row in report['cases'].values())
            and all(type(report.get(k)) is int and report[k]==v for k,v in {
                'actual_passed':16,'actual_failed':0,'actual_ignored':0,'actual_executed_nonignored':16}.items()))
        save();ensure(report['full16_qualification'],'all-sixteen-original-controls-required')
    finally:
        report['inputs_pristine']=frozen_inputs()==frozen
        report['source_after_sha256']=digest(json.dumps(frozen_inputs(),sort_keys=True).encode())
        if binary is not None:
            report['binary_final_sha256']=digest(binary.read_bytes()) if binary.is_file() and not binary.is_symlink() else None
            report['binary_pristine']=report['binary_final_sha256']==before_sha
        if not report['inputs_pristine'] or (binary is not None and not report['binary_pristine']):report['full16_qualification']=False
        full16_totals(report);save()
        ensure(report['inputs_pristine'],'final-full16-source-modes-pristine')
        if binary is not None:ensure(report['binary_pristine'],'final-full16-binary-pristine')


def static_diagnostics(raw,tracked):
    raw=re.sub(r'\x1b\[[0-9;]*m','',raw)
    errors=re.findall(r'^error(?:\[E[0-9]+\])?:',raw,re.M)
    codes=sorted(set(re.findall(r'\berror\[(E[0-9]{4})\]',raw)))
    # Export only bounded identifier tokens, never the surrounding diagnostic or URL.
    lint_id=r'([a-z][a-z0-9_]{0,79})(?![A-Za-z0-9_:/.-])'
    lints=sorted(set(re.findall(r'(?<![A-Za-z0-9_:/.-])clippy::'+lint_id,raw)
        +re.findall(r'(?<![A-Za-z0-9_:/.-])https://rust-lang\.github\.io/rust-clippy/(?:master|stable|beta|nightly|rust-[0-9.]{1,20})/index\.html#'+lint_id,raw)))
    sites=[{'file':file,'line':int(line),'column':int(column)}
        for file,line,column in re.findall(r'(?m)^\s*--> (crates/[A-Za-z0-9_./-]+\.rs):([0-9]{1,7}):([0-9]{1,7})\s*$',raw) if file in tracked]
    return {'compiler_error_count':len(errors),'compiler_codes':codes[:32],'compiler_code_count':len(codes),
        'compiler_sites':sites[:32],'compiler_site_count':len(sites),
        'clippy_lint_identifiers':lints[:32],'clippy_lint_identifier_count':len(lints),
        'clippy_lint_identifiers_truncated':len(lints)>32,
        'closed_diagnostics_truncated':len(codes)>32 or len(sites)>32 or len(lints)>32,'raw_diagnostics_retained':False}


def static_unit_candidate(path):
    return any(re.fullmatch(re.escape(node.replace('_','-'))+r'-[0-9a-f]{16}',path.parent.name)
        and path.name in {'lib-'+node+'.json','test-lib-'+node+'.json'} for node in NODES)


def static_artifact_features():
    # Cargo cache candidates are observations, not an identified runtime binary
    # or proof that every listed unit was rebuilt by this invocation.
    root=Path(os.environ.get('CARGO_TARGET_DIR','target'))/'debug'/'.fingerprint'
    paths=sorted(path for path in root.glob('*/*.json') if static_unit_candidate(path))
    rows=[];rejected=0
    for path in paths[:256]:
        try:
            ensure(path.is_file() and not path.is_symlink() and path.stat().st_size<=128*1024,'bounded-unit-fingerprint')
            raw=path.read_bytes();data=json.loads(raw);features=data.get('features')
            if isinstance(features,str):features=json.loads(features)
            ensure(isinstance(features,list) and len(features)<=128 and all(isinstance(value,str) and re.fullmatch('[A-Za-z0-9_./:-]{1,100}',value) for value in features),'closed-unit-features')
            rows.append({'path':str(path.relative_to(root)),'sha256':digest(raw),'observed_features':sorted(features)})
        except Exception:rejected+=1
    return {'observed_unit_candidates':rows,'candidate_count':len(paths),'bounded_candidate_count':len(rows),
        'rejected_candidate_count':rejected,'candidate_list_truncated':len(paths)>256,
        'bound_to_current_command':False,'runtime_six_node_feature_verification':False,'cache_reuse_possible':True}


def static_parser_controls():
    row=static_diagnostics('error[E0001]: private is discarded\n --> crates/closed.rs:1:2\n',{'crates/closed.rs'})
    ensure(row['compiler_error_count']==1 and row['compiler_codes']==['E0001'] and row['compiler_sites']==[{'file':'crates/closed.rs','line':1,'column':2}],'static-closed-error-positive')
    ensure(static_diagnostics('error: hidden\n --> /private/path.rs:1:2\n',set())['compiler_sites']==[],'static-private-location-omitted')
    ensure(static_diagnostics('',set())['compiler_error_count']==0,'static-zero-error-positive')
    colored=static_diagnostics('\x1b[31merror[E0001]\x1b[0m: discarded\n\x1b[34m --> crates/closed.rs:1:2\x1b[0m\n',{'crates/closed.rs'})
    ensure(colored['compiler_error_count']==1 and colored['compiler_codes']==['E0001'] and colored['compiler_sites']==[{'file':'crates/closed.rs','line':1,'column':2}],'static-colored-header-and-site-positive')
    many=static_diagnostics(''.join('error[E'+str(1000+i)+']: discarded\n --> crates/closed.rs:'+str(i+1)+':1\n' for i in range(40)),{'crates/closed.rs'})
    ensure(many['closed_diagnostics_truncated'] and len(many['compiler_codes'])==len(many['compiler_sites'])==32,'static-closed-truncation')
    ensure(static_unit_candidate(Path('marmot-app-0123456789abcdef/lib-marmot_app.json')),'static-allowlisted-unit-path-positive')
    for value in ['marmot-app-PRIVATE0123456789/lib-marmot_app.json','marmot-app-0123456789abcdef/lib-private.json',
        'marmot-app-private-0123456789abcdef/lib-marmot_app.json','marmot-app-0123456789abcde/lib-marmot_app.json']:
        ensure(not static_unit_candidate(Path(value)),'static-unbound-label-not-exported')
    lint=static_diagnostics('\x1b[31mnote: clippy::collapsible_if\x1b[0m PRIVATE_SENTINEL\nhelp: https://rust-lang.github.io/rust-clippy/master/index.html#type_complexity\nclippy::collapsible_if\n',set())
    ensure(lint['clippy_lint_identifiers']==['collapsible_if','type_complexity'] and lint['clippy_lint_identifier_count']==2
        and not lint['clippy_lint_identifiers_truncated'] and 'PRIVATE_SENTINEL' not in json.dumps(lint),'static-closed-lint-identifiers-positive-and-private-text-omitted')
    private=static_diagnostics('https://private.example/index.html#private_secret clippy::UPPER clippy::bad/path xclippy::hidden https://rust-lang.github.io.evil/rust-clippy/master/index.html#secret clippy::'+('a'*81),set())
    ensure(private['clippy_lint_identifiers']==[] and private['clippy_lint_identifier_count']==0,'static-unofficial-or-open-identifier-rejected')
    many_lints=static_diagnostics(' '.join('clippy::lint_'+str(i) for i in range(40)),set())
    ensure(many_lints['clippy_lint_identifier_count']==40 and len(many_lints['clippy_lint_identifiers'])==32
        and many_lints['clippy_lint_identifiers_truncated'] and many_lints['closed_diagnostics_truncated'],'static-lint-identifier-truncation')
    return {'positive':5,'privacy_or_bounds_controls':8,'actual_runtime_bodies':0}


def execute_static(report,save,cohort):
    ensure(cohort in {'default','experimental'},'allowlisted-strict-static-cohort')
    frozen=frozen_inputs();report.update(scope='strict-App-all-targets-static',static_cohort=cohort,static_passed=False,
        runtime_execution_attempted=False,actual_passed=0,actual_failed=0,actual_ignored=0,actual_executed_nonignored=0)
    command=ack.alignment.static_command(cohort)
    report['command']=command;report['requested_features']=command[command.index('--features')+1].split(',')
    report['artifact_features_before']=static_artifact_features();save()
    try:
        code,raw,seconds=bounded.capture(command,1800,limit=8*1024*1024)
        report.update(exit_code=code,seconds=seconds,**static_diagnostics(raw,set(frozen)))
        report['artifact_features_after']=static_artifact_features();save()
        report['static_passed']=(type(code) is int and code==0 and type(report['compiler_error_count']) is int and report['compiler_error_count']==0)
        save();ensure(report['static_passed'],'strict-App-all-targets-clippy-required')
    except bounded.GateFailure as error:
        report['watchdog_triggered']=str(error)=='bounded-command-timeout';report['output_limit_triggered']=str(error)=='bounded-command-output-limit';save();raise
    finally:
        report['inputs_pristine']=frozen_inputs()==frozen
        report['source_after_sha256']=digest(json.dumps(frozen_inputs(),sort_keys=True).encode())
        if not report['inputs_pristine']:report['static_passed']=False
        save();ensure(report['inputs_pristine'],'final-static-source-modes-pristine')


def main(args):
    os.umask(0o077);OUT.mkdir(exist_ok=True)
    report={'baseline':BASE,'scope':'one-strict-real-SDK-five-installation-component','qualification_passed':False,
        'promotion_eligible':False,'SDK_native_UI_qualification':False,'full16_qualification':False,
        'native5_component_control_passed':False,'automatic_retries':0,'stack_bytes':4194304,'Tokio_workers':2}
    def save():(OUT/'result.json').write_text(json.dumps(report,indent=2)+'\n')
    try:
        report['source_guard']=source_guard();report['parser_controls']=parser_controls()
        report['requested_mode']='sixteen' if args.full16 else ('static' if args.static_cohort else 'five')
        if args.full16:
            report['scope']='sixteen-original-composed-controls'
            report['Tokio_workers']=None;report['runtime_flavor_semantics']='unchanged source-defined mixed cases, including three current-thread stress cases and paused clock; policy is synchronous'
            report['full16_parser_controls']=ack.parser_controls()
            report['required_case_inventory']=[{'label':label,'suffix':suffix,'name':name,'oracle':oracle} for label,suffix,name,oracle in full16_cases()]
        elif args.static_cohort:
            report['scope']='strict-App-all-targets-static'
            report['Tokio_workers']=None;report['runtime_flavor_semantics']='zero runtime executions; no Tokio worker count asserted'
            report['static_parser_controls']=static_parser_controls();report['static_cohort']=args.static_cohort
        save()
        if args.preflight:report['preflight_passed']=True;save();return
        if args.full16:execute_full16(report,save)
        elif args.static_cohort:execute_static(report,save,args.static_cohort)
        else:execute_one(report,save)
    except Exception as error:
        report['exception_type']=type(error).__name__
        if isinstance(error,ValueError):report['failure_gate']=str(error) if re.fullmatch('[A-Za-z0-9_.:/-]{1,140}',str(error)) else 'closed-gate-rejected'
        save();raise

if __name__=='__main__':
    parser=argparse.ArgumentParser();parser.add_argument('--preflight',action='store_true');mode=parser.add_mutually_exclusive_group();mode.add_argument('--full16',action='store_true');mode.add_argument('--static-cohort',choices=['default','experimental']);main(parser.parse_args())
