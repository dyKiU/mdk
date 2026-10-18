#!/usr/bin/env python3
"""ONE unchanged native5 case with passive weak-owned publication/RPC observations."""
import argparse,hashlib,json,os,re,shutil,subprocess
from pathlib import Path
import qualify_upstream_request_retry_ack as ack
import qualify_upstream_storage_app_handles as counts
import qualify_upstream_storage_boundary as bounded
from upstream_completion_ci import compile_cases,digest
from qualify_upstream_body_negative import feature_identity
from upstream_extraction_cohort import frozen_inputs
import native5_timing_parser as timing_parser
import qualify_upstream_composed_enrollment as rich
BASE='77caba679ab5986df88fd7296b5446004fba8bb7' # Root MUST pin a reviewed pure, formatted product baseline before adoption.
MANIFEST_SHA='528a9f9ab7407e2b49938eb6541f65835aa02094604340696fe104cf1e234598' # Root MUST pin exact reviewed/reformatted reversal manifest.
PARSER_SHA='08eb7fe9bed96cd54be363817eccaf7f21be276a444cd062d40c14e2de5d0390' # Root MUST pin exact reviewed closed parser.
SELF='scripts/diagnose_upstream_native5_consent.py'
MANIFEST='scripts/native5_consent_source_manifest.json'
PARSER='scripts/native5_timing_parser.py'
WORKFLOW='.github/workflows/experimental-sync-ci.yml'
REF='refs/heads/ci/upstream-native-five-consent-diagnostic-20261018'
BEGIN='  # NATIVE5_CONSENT_DIAGNOSTIC_JOBS_BEGIN\n'
END='  # NATIVE5_CONSENT_DIAGNOSTIC_JOBS_END\n'
OPTIONS='options: [native5-consent-preflight, native5-consent-diagnostic, '
OUT=Path('native5-consent-diagnostic-evidence')
SUFFIX='sequential_installations_acceptance::five_installations_join_with_rotating_existing_sponsors_and_explicit_sharing'
NAME='native_device_linking::automatic_pairing_acceptance::'+SUFFIX
MARKER='sequential-installations completed_steps=4 final_device_count=5 final_roster_and_policies=true public_cancels=14 runtime_closes=5 storages_closed=true plane_shutdown_returns=5 listener_closed=true attempt_completed=true'
NODES={'marmot_app','cgka_engine','storage_sqlite','cgka_session','marmot_account','transport_nostr'}
ensure=ack.ensure

def source_guard():
    ensure(isinstance(BASE,str) and re.fullmatch('[a-f0-9]{40}',BASE),'reviewed-pure-formatted-baseline-required')
    ensure(all(isinstance(pin,str) and re.fullmatch('[a-f0-9]{64}',pin) for pin in [MANIFEST_SHA,PARSER_SHA]),'reviewed-metadata-pins-required')
    ensure(digest(Path(MANIFEST).read_bytes())==MANIFEST_SHA and digest(Path(PARSER).read_bytes())==PARSER_SHA,'exact-passive-manifest-parser')
    manifest=json.loads(Path(MANIFEST).read_text());ensure(manifest['reviewed_source']==BASE,'manifest-baseline-identity')
    head=subprocess.check_output(['git','rev-parse','HEAD'],text=True).strip()
    ensure(os.environ.get('GITHUB_ACTIONS')=='true' and os.environ.get('GITHUB_REPOSITORY')=='dyKiU/mdk'
        and os.environ.get('GITHUB_EVENT_NAME')=='workflow_dispatch' and os.environ.get('GITHUB_SHA')==head
        and os.environ.get('GITHUB_REF')==REF and os.environ.get('GITHUB_WORKFLOW_REF')=='dyKiU/mdk/'+WORKFLOW+'@'+REF
        and os.environ.get('UPSTREAM_NATIVE5_CONSENT_BASELINE')==BASE,'exact-one-owned-workflow')
    ensure(os.environ.get('CARGO_INCREMENTAL')=='1' and os.environ.get('CARGO_BUILD_JOBS')=='2' and os.environ.get('RUST_MIN_STACK')=='4194304'
        and all(os.environ.get(k)=='0' for k in ['CARGO_PROFILE_DEV_DEBUG','CARGO_PROFILE_TEST_DEBUG'])
        and all(not os.environ.get(k) for k in ['RUSTFLAGS','CARGO_ENCODED_RUSTFLAGS','RUSTC_BOOTSTRAP','CARGO_PROFILE_DEV_OPT_LEVEL','CARGO_PROFILE_TEST_OPT_LEVEL']),'exact-build-profile')
    subprocess.run(['git','merge-base','--is-ancestor',BASE,head],check=True)
    ensure(subprocess.run(['git','diff','--quiet','HEAD']).returncode==0,'initial-tracked-pristine')
    baseline={}
    for entry in subprocess.check_output(['git','ls-tree','-r','-z',BASE]).split(b'\0'):
        if entry:
            metadata,path=entry.split(b'\t',1);mode,kind,blob=metadata.decode().split();ensure(kind=='blob','ordinary-blob');baseline[os.fsdecode(path)]=(mode,blob)
    current=ack.layout();new=set(manifest['new_modules'])|{SELF,MANIFEST,PARSER}
    ensure(not(new&set(baseline)) and set(current)==set(baseline)|new,'whole-source-inventory')
    ensure(set(manifest['paths'])<=set(baseline),'exact-reversible-paths')
    for path,entry in current.items():
        mode,blob=baseline.get(path,('100644',None))
        ensure(entry['git_mode']==mode and entry['symlink']==(mode=='120000') and (entry['symlink'] or entry['actual_executable']==(mode=='100755')),'exact-modes')
        data=os.fsencode(os.readlink(path)) if entry['symlink'] else Path(path).read_bytes()
        if path in manifest['new_modules']:
            pin=manifest['new_modules'][path];ensure(mode==pin['mode'] and digest(data)==pin['sha256'],'exact-new-test-only-leaf');continue
        if path in manifest['paths']:
            pin=manifest['paths'][path];ensure(mode==pin['mode'] and digest(data)==pin['after_sha256'],'exact-passive-source')
            text=data.decode()
            for change in reversed(pin['exact_substitutions']):
                ensure(text.count(change['after'])==1,'unique-reversible-hook');text=text.replace(change['after'],change['before'],1)
            data=text.encode();ensure(digest(data)==pin['before_sha256'],'byte-exact-old-source-after-reversal')
        if path==WORKFLOW:
            text=data.decode();ensure(text.count(BEGIN)==text.count(END)==text.count(OPTIONS)==1,'one-owned-workflow')
            before,rest=text.split(BEGIN);_,after=rest.split(END);data=(before+after).replace(OPTIONS,'options: [',1).encode()
        if blob is not None:ensure(hashlib.sha1(b'blob '+str(len(data)).encode()+b'\0'+data).hexdigest()==blob,'whole-baseline-byte-equality:'+path)
    ensure(not subprocess.check_output(['git','ls-files','--others','--exclude-standard'],text=True).strip(),'no-untracked-overlays')
    return {'source':head,'baseline':BASE,'manifest_sha256':MANIFEST_SHA,'parser_sha256':PARSER_SHA,'whole_source_modes_reconstructed':True,'extra_polls_waits_or_authority':False,'only_one_native5_case':True,'passive_target_join_ordinal':4,'first_Body0_proof_and_authenticated_peer_completion_trace':True,'later_proof_attempts_not_merged':True,'full_five_installation_scenario_retained':True,'original_strict15_duration_preserved':True,'exact_deadline_known':False}

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


def safe_panic_locations(raw,known_sources):
    values=re.findall(r'panicked at ([A-Za-z0-9_./-]+\.rs):([0-9]+):([0-9]+):',raw)
    safe=[{'path':path,'line':int(line),'column':int(column)} for path,line,column in values
        if path in known_sources and 0<int(line)<=2147483647 and 0<int(column)<=2147483647]
    headers=raw.count('panicked at ')
    return {'all_panic_header_count':headers,'safe_locations':safe[:16],
        'unknown_location_count':len(values)-len(safe),'unparsed_header_count':max(0,headers-len(values)),
        'locations_truncated':len(safe)>16,'raw_payloads_exported':False}

def panic_location_parser_controls():
    path='crates/marmot-app/src/native_device_linking/tests/automatic_pairing_acceptance.rs'
    safe="thread 'exact' (123) panicked at "+path+':1720:9:\nprivate payload must not survive'
    row=safe_panic_locations(safe,{path})
    ensure(row['all_panic_header_count']==1 and row['safe_locations']==[{'path':path,'line':1720,'column':9}] and row['unknown_location_count']==0,'one-safe-tracked-panic')
    for location in ['/private/untracked.rs:1:1','crates/../../untracked.rs:1:1',path+':0:1',path+':1:0',path+':2147483648:1']:
        row=safe_panic_locations('panicked at '+location+':',{path});ensure(row['safe_locations']==[] and row['unknown_location_count']==1,'unknown-or-invalid-panic-location-not-exported')
    row=safe_panic_locations(safe*17,{path});ensure(len(row['safe_locations'])==16 and row['locations_truncated'] is True and row['all_panic_header_count']==17,'bounded-panic-export-all-counts')
    return {'positive':2,'negative':5,'actual_runtime_bodies':0}

def closed_failure_observations(raw):
    clean=re.sub(r'\x1b\[[0-9;]*m','',raw)
    clean,normalized=re.subn(r'(?m)^test '+re.escape(NAME)+r' \.\.\. (?=automatic-enrollment-control )','',clean)
    try:
        return {'closed_schema_accepted':True,'exact_prefix_normalizations':normalized,
            'observations':rich.diagnostics(clean),'at_deadline_state_known':False,
            'observation_timing':'existing post-failure output only; not original deadline state'}
    except ValueError:
        return {'closed_schema_accepted':False,'exact_prefix_normalizations':normalized,
            'observations':None,'failure_category':'ClosedSchemaRejected','at_deadline_state_known':False}

def main():
    ap=argparse.ArgumentParser();ap.add_argument('--preflight',action='store_true');args=ap.parse_args()
    os.umask(0o077);OUT.mkdir(exist_ok=True)
    report={'scope':'one-native5-scenario-fourth-join-passive-consent-proof-and-same-operation-RPC-diagnostic','qualification_passed':False,'native_acceptance_claim':False,'promotion_eligible':False,'runtime_execution_attempted':False,'actual_counts_complete':False,'actual_passed':None,'actual_failed':None,'actual_ignored':None,'actual_executed_nonignored':None,'diagnostic_completed':False,'journey_passed':False}
    frozen=None;binary=None;binary_sha=None
    def save():(OUT/'result.json').write_text(json.dumps(report,indent=2)+'\n')
    try:
        report['source_guard']=source_guard();report['parser_controls']=parser_controls();report['timing_parser_controls']=timing_parser.parser_controls();report['sdk_parser_controls']=timing_parser.sdk_parser_controls();report['rich_parser_controls']=rich.diagnostic_parser_controls();report['panic_location_parser_controls']=panic_location_parser_controls();save()
        if args.preflight:
            code,raw,wall=bounded.capture(['cargo','fmt','--all'],180,limit=8*1024*1024)
            report['format']={'exit_code':code,'wall_seconds':wall};patch=subprocess.check_output(['git','diff','--binary'])
            if patch:(OUT/'formatting.patch').write_bytes(patch)
            report['format']['patch_bytes']=len(patch);report['format']['patch_sha256']=digest(patch);save()
            ensure(code==0 and not patch,'remote-formatting-required');report['preflight_passed']=True;save();return
        frozen=frozen_inputs();report['source_manifest_sha256']=digest(json.dumps(frozen,sort_keys=True).encode())
        ensure(shutil.disk_usage('.').free>=8*1024**3,'remote-capacity')
        compilation,cases=compile_cases([SUFFIX])
        # Preserve closed compiler codes/sites only; never raw compiler payloads.
        compiler_headers=compilation.pop('compiler_headers',[])
        compilation['closed_error_codes']=sorted(set(code for line in compiler_headers for code in re.findall(r'^error\[(E[0-9]{4})\]:',line)))
        compilation['closed_source_locations']=[{'path':match[1],'line':int(match[2]),'column':int(match[3])}
            for line in compiler_headers if (match:=re.fullmatch(r'\s*--> (crates/[A-Za-z0-9_./-]+\.rs):([0-9]+):([0-9]+)',line))]
        compilation['missing_nextest_header_observed']=any(line=="error: no such command: `nextest`" for line in compiler_headers)
        report['compilation']=compilation;save()
        ensure(compilation.get('compile_exit_code')==0 and compilation.get('compiler_error_count')==0 and compilation.get('compiled_fingerprints',{}).get('verified') is True and set(cases)=={SUFFIX},'one-compiled-case-feature-verified')
        case=cases[SUFFIX];ensure(case['name']==NAME,'exact-one-native-five-fullname');binary=Path(case['binary']);binary_sha=case['binary_sha256']
        report['feature_identity']=feature_identity(compilation);ensure(set(report['feature_identity']['nodes'])==NODES,'six-real-dependency-fingerprints')
        for ignored in [False,True]:
            code,raw,_=bounded.capture([str(binary),'--exact',NAME]+(['--ignored'] if ignored else [])+['--list','--format','terse'],60,limit=1024*1024)
            inventory=counts.parse_inventory(raw,NAME,ignored);report.setdefault('inventory',{})['ignored' if ignored else 'normal']=inventory;save();ensure(code==0 and inventory['passed'],'one-nonignored-exact-case')
        ensure(frozen_inputs()==frozen and digest(binary.read_bytes())==binary_sha,'before-runtime-pristine')
        report['runtime_execution_attempted']=True;save()
        code,raw,wall=bounded.capture([str(binary),'--exact',NAME,'--nocapture','--test-threads=1'],900,limit=8*1024*1024)
        # Preserve actual body evidence BEFORE any richer diagnostic parser can reject.
        row=counts.parse_body(raw,code,NAME);report['body']=row;report['body_seconds']=wall
        report['actual_counts_complete']=row['actual_counts_complete']
        for dest,key in [('actual_passed','passed'),('actual_failed','failed'),('actual_ignored','ignored'),('actual_executed_nonignored','executed_nonignored')]:report[dest]=row.get(key)
        save();report['body']=parse(raw,code);report['journey_passed']=green(report['body']);report['panic_observations']=safe_panic_locations(raw,frozen);save()
        if code!=0:
            report['closed_failure_observations']=closed_failure_observations(raw);save()
        report['timing']=timing_parser.timing(raw,NAME)
        wait=report['timing'].get('wait')
        report['diagnostic_completed']=(report['timing']['known'] is True and isinstance(wait,dict) and all(type(wait.get(k)) is int for k in ['constructed_before_us','constructed_after_us','observed_us']) and type(wait.get('outcome_ok')) is bool);save()
        # A valid observed FAIL remains an actual FAIL. Missing later milestones
        # do not reject useful observations or become invented false/zero facts.
        ensure(row['actual_counts_complete'] is True and row.get('executed_nonignored')==1 and row.get('ignored')==0 and row.get('compiler_error_count')==0,'one-actual-body-no-ignore-or-compiler-error')
        ensure(report['diagnostic_completed'],'known-lossless-passive-observations-required')
    except Exception as error:
        report['exception_type']=type(error).__name__
        if isinstance(error,ValueError):report['failure_gate']=str(error) if re.fullmatch('[A-Za-z0-9_.:/-]{1,140}',str(error)) else 'closed-gate-rejected'
        raise
    finally:
        if frozen is not None:
            report['inputs_pristine']=frozen_inputs()==frozen
            if not report['runtime_execution_attempted']:report['actual_executed_nonignored']=0
        if binary is not None:report['binary_pristine']=binary.is_file() and digest(binary.read_bytes())==binary_sha
        save()
        if frozen is not None:ensure(report['inputs_pristine'],'final-source-pristine')
        if binary is not None:ensure(report['binary_pristine'],'final-binary-pristine')
if __name__=='__main__':main()
