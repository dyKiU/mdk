#!/usr/bin/env python3
"""One unchanged higher-source restart body with passive explicit-sync frontier."""
import argparse, hashlib, json, os, re, shutil, stat, subprocess
from pathlib import Path
import qualify_upstream_storage_boundary as bounded
import qualify_upstream_storage_app_handles as counts
import upstream_completion_ci as completion
ensure=bounded.ensure
BASE='adef3a12b6a8ffa3ed8db16cdd8851e14e57abf8'
RAW_SOURCE='b3123a46986ba4f37ea7200158dd880b814c4cf7'
SOURCE_PARENT='288544fe2d9dc3323cb1df3b99f35cc017375e13'
SOURCE_PATHS={'crates/marmot-app/src/client/account_chat_sharing/automatic/tests/pending_restart_acceptance.rs': {'before': 'b69632ce6c94e18e7ebf02b518d2eaed50c83bd1c87be15ab12ea7ca90ed8c0c', 'raw': '0b58fde3834d61a21f22afb34f4a9ac23fadf8c42a1b0a0fdca520ff9718068c', 'canonical': '0b58fde3834d61a21f22afb34f4a9ac23fadf8c42a1b0a0fdca520ff9718068c', 'mode': '100644'}, 'crates/marmot-app/src/client/explicit_sync_frontier.rs': {'before': None, 'raw': '168303579bfacc4af6dd445f351dd59901b0c736d9797f27aadb9a35c1ed6a43', 'canonical': 'f4a73ac1995134480f6398006ad3af4ddeb2f4a48cce37109df4b18356349dd7', 'mode': '100644'}, 'crates/marmot-app/src/client/mod.rs': {'before': '434a971bf57ed402253cad7cf58c76f5be66ba46f28892bcf5a6456a978c5e7e', 'raw': 'dd85885526ecd336b7edf543108108d094e8a9d2af94cda5a1d42c1e06d4e9f9', 'canonical': '3eb116d2771a0aa8827dd78f44ac4d4ab806eb397265748cd83192d353836686', 'mode': '100644'}, 'crates/marmot-app/src/client/sync.rs': {'before': '2491c5c9a56de4034bf88de33083cebb13e65e05147ae6aff2a102d5f0a2dc96', 'raw': 'cf3860bd3de4f06d27418880c11ee613c63116c94e6dbccb05c75865b9ad4969', 'canonical': '04b5c0360ff97151ee7882100d0b9eae6d10951916cd6907672347f23f1907ce', 'mode': '100644'}, 'crates/marmot-app/src/client/sync/comparison_job.rs': {'before': '44a286cd7e1721ba3483c44742161a8cbe24c0063bcad02b632330e3e6e564bd', 'raw': 'e99ce8660c45a26efb515107606ebe4b8d040ec4924c1ab17fe5b933bbf6e6b9', 'canonical': 'e99ce8660c45a26efb515107606ebe4b8d040ec4924c1ab17fe5b933bbf6e6b9', 'mode': '100644'}, 'crates/marmot-app/src/lib.rs': {'before': '37b1567aec1b88e484b2093108ff420e16afe326126f460be4a52d67dff35113', 'raw': 'c68c15414ccdfffd9f5576f5334a876f8b01af19dae193ff844f41cccb2f221c', 'canonical': 'c68c15414ccdfffd9f5576f5334a876f8b01af19dae193ff844f41cccb2f221c', 'mode': '100644'}}
WORKFLOW_SHA='088680e353e7c6df5b25ebf37bc5cde2afd59193267c5de95e2ddfa05dc5c4a9'
SELF='scripts/diagnose_upstream_restart_sync_frontier.py'
WORKFLOW='.github/workflows/restart-sync-frontier.yml'
REF='refs/heads/ci/upstream-restart-sync-diagnostic-20261018'
RESTART_HELPER='crates/marmot-app/src/client/account_chat_sharing/automatic/tests/pending_restart_acceptance.rs'
COMPOSED_HELPER='crates/marmot-app/src/tests.rs'
MESSAGE='actual restarted peers must deliver genuine ordinary catalog and canonical record within the unchanged recovery deadline'
NAME='native_device_linking::tests::pending_restart_higher_source_delivers_catalog_and_record'
NAMES=[None, None, None, 'native_device_linking::tests::pending_lower_request_recovers_after_higher_restarts_before_consent', 'native_device_linking::tests::pending_restart_higher_source_delivers_catalog_and_record']
FEATURES='marmot-app/otlp-export,marmot-app/product-analytics-export,marmot-app/test-policy-overrides,marmot-app/experimental-device-sync,cgka-engine/test-policy-overrides,cgka-engine/test-crash-hooks'
OUT=Path('restart-sync-frontier-evidence')
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

def source_guard(preflight):
    head=git('rev-parse','HEAD').decode().strip()
    ensure(type(BASE)is str and re.fullmatch('[0-9a-f]{40}',BASE) and type(WORKFLOW_SHA)is str and re.fullmatch('[0-9a-f]{64}',WORKFLOW_SHA),'root-canonical-pins-required')
    ensure(os.environ.get('GITHUB_ACTIONS')=='true' and os.environ.get('GITHUB_REPOSITORY')=='dyKiU/mdk'
        and os.environ.get('GITHUB_SHA')==head and os.environ.get('GITHUB_REF')==REF
        and os.environ.get('GITHUB_WORKFLOW_REF')=='dyKiU/mdk/'+WORKFLOW+'@'+REF
        and (os.environ.get('GITHUB_EVENT_NAME')=='workflow_dispatch' or (preflight and os.environ.get('GITHUB_EVENT_NAME')=='push'))
        and os.environ.get('UPSTREAM_RESTART_SYNC_BASELINE')==BASE,'exact-hosted-event-source')
    ensure(os.environ.get('CARGO_INCREMENTAL')=='1' and os.environ.get('CARGO_BUILD_JOBS')=='2' and os.environ.get('RUST_MIN_STACK')=='4194304'
        and all(os.environ.get(k)=='0' for k in ['CARGO_PROFILE_DEV_DEBUG','CARGO_PROFILE_TEST_DEBUG'])
        and all(not os.environ.get(k) for k in ['RUSTFLAGS','CARGO_ENCODED_RUSTFLAGS','RUSTC_BOOTSTRAP','CARGO_PROFILE_DEV_OPT_LEVEL','CARGO_PROFILE_TEST_OPT_LEVEL']),'fixed-build-cohort')
    ensure(all(subprocess.run(['git','merge-base','--is-ancestor',a,b]).returncode==0 for a,b in [(SOURCE_PARENT,RAW_SOURCE),(RAW_SOURCE,BASE),(BASE,head)]),'reviewed-source-ancestry')
    ensure(set(git('diff','--name-only',SOURCE_PARENT,RAW_SOURCE).decode().splitlines())==set(SOURCE_PATHS)
        and set(git('diff','--name-only',RAW_SOURCE,BASE).decode().splitlines())<=set(SOURCE_PATHS),'exact-six-reviewed-paths-then-format-only-owned-paths')
    parent=layout(SOURCE_PARENT);raw=layout(RAW_SOURCE);baseline=layout(BASE);current=layout('HEAD')
    for path,pin in SOURCE_PATHS.items():
        ensure(raw[path][0]==baseline[path][0]==pin['mode']=='100644' and digest(git('show',RAW_SOURCE+':'+path))==pin['raw']
            and digest(git('show',BASE+':'+path))==pin['canonical'],'raw-and-canonical-source-pins')
        ensure((path not in parent and pin['before'] is None) or (path in parent and parent[path][0]=='100644' and digest(git('show',SOURCE_PARENT+':'+path))==pin['before']),'reviewed-before-source-pins')
    ensure(SELF not in baseline and WORKFLOW not in baseline and set(current)==set(baseline)|{SELF,WORKFLOW},'only-two-owned-metadata')
    ensure(subprocess.run(['git','diff','--quiet','HEAD']).returncode==0,'HEAD-pristine')
    for path,(mode,oid) in current.items():
        expected=baseline.get(path,('100644',None));p=Path(path);s=p.lstat();link=stat.S_ISLNK(s.st_mode)
        ensure(mode==expected[0] and link==(mode=='120000') and (link or stat.S_ISREG(s.st_mode)) and (link or bool(s.st_mode&0o111)==(mode=='100755')),'whole-source-modes')
        data=os.fsencode(os.readlink(p)) if link else p.read_bytes();actual=hashlib.sha1(b'blob '+str(len(data)).encode()+b'\0'+data).hexdigest()
        ensure(actual==oid and (expected[1] is None or actual==expected[1]),'whole-BASE-and-HEAD-content')
    ensure(digest(Path(WORKFLOW).read_bytes())==WORKFLOW_SHA,'exact-owned-workflow')
    ensure(set(git('ls-files','--others','--exclude-standard').decode().splitlines())<={str(OUT/'result.json')},'no-foreign-untracked')
    restart_sites(Path(RESTART_HELPER).read_text(),Path(COMPOSED_HELPER).read_text())
    return {'head':head,'baseline':BASE,'raw_source':RAW_SOURCE,'source_parent':SOURCE_PARENT,'whole_source_modes_verified':True,'reviewed_six_path_provenance':True,'Rust_exceptions':[],'old_guards_or_main_called':False,'old_globals_mutated':False}

def clean(raw):return re.sub(r'\x1b\[[0-9;]*m','',raw)
def normalize_parser_prefix(raw,name):
    text=clean(raw);pattern=r'(?m)^test '+re.escape(name)+r' \.\.\. '
    hits=list(re.finditer(pattern,text));ensure(len(hits)<=1,'unique-exact-libtest-prefix')
    # Keep the genuine header/name for inherited inventory parsers, split only
    # its attached first stderr record onto a new line. Never invent a header.
    return re.sub(pattern,lambda match:match[0]+'\n',text,count=1) if hits else text

def exact_record(text,prefix,pattern):
    lines=[line for line in text.splitlines() if prefix in line]
    ensure(len(lines)==1 and len(lines[0])<=4096,'one-closed-'+prefix)
    # Libtest may prefix its in-progress exact case on the first stderr line.
    line=re.sub(r'^test [A-Za-z0-9_:]+ \.\.\. ','',lines[0])
    match=re.fullmatch(pattern,line);ensure(match is not None,'closed-'+prefix);return match

def restart_sites(helper,composed):
    lines=helper.splitlines();hits=[i for i,line in enumerate(lines) if MESSAGE in line]
    ensure(len(hits)==1,'unique-unchanged-recovery-expect')
    i=hits[0];j=max(k for k in range(i+1) if '.expect(' in lines[k])
    ensure('delivery.expect(' in lines[j] and 'Duration::from_secs(30)' in helper,'original-delivery-expect-and-deadline')
    a={'file':RESTART_HELPER,'line':j+1,'column':lines[j].index('expect(')+1}
    rows=composed.splitlines();hits=[i for i,line in enumerate(rows) if 'test_thread.join().unwrap();' in line]
    ensure(len(hits)==1 and 'const COMPOSED_APP_RUNTIME_STACK_BYTES: usize = 8 * 1024 * 1024;' in composed,'exact-composed-driver')
    i=hits[0];b={'file':COMPOSED_HELPER,'line':i+1,'column':rows[i].index('unwrap()')+1}
    return a,b

def restart(raw,name,basic,code,expected,helper,composed):
    text=clean(raw);higher=name==NAMES[4]
    role=exact_record(text,'pending_restart_required_higher_source=',r'pending_restart_required_higher_source=(true|false) source_is_lower=(true|false)')
    first=exact_record(text,'pending_restart_first_higher_positive_close=',r'pending_restart_first_higher_positive_close=(true|false)')
    auth=exact_record(text,'pending_restart_authenticated_y_retained_exact_live_x=',r'pending_restart_authenticated_y_retained_exact_live_x=(true|false)')
    closes=exact_record(text,'pending_restart_final_positive_closes=',r'pending_restart_final_positive_closes=(true|false)')
    outer=exact_record(text,'delayed_request_cleanup_d_closed=',r'delayed_request_cleanup_d_closed=(true|false) abc_closed=(true|false)')
    n=r'(?:0|[1-9][0-9]{0,38})';pair=r'\['+n+', '+n+r'\]'
    obs=exact_record(text,'pending_restart_delivery_observation ',r'pending_restart_delivery_observation recovered=(true|false) source_is_lower=(true|false) elapsed_millis=('+n+') completed_syncs='+pair+' sync_millis='+pair+' completed_ticks='+pair+' tick_millis='+pair+r' waiting_at=\([01], "(?:sync|automatic_tick|projection|inter_turn_sleep|before_delivery)"\) waiting_millis='+n)
    prereq=(role[1]==str(higher).lower() and (not higher or role[2]=='false') and obs[2]==role[2]
        and first[1]==auth[1]==closes[1]==outer[1]==outer[2]=='true')
    complete=(basic.get('actual_counts_complete') is True and basic.get('executed_nonignored')==1 and basic.get('ignored')==0 and basic.get('compiler_error_count')==0)
    headers=re.findall(r"thread '([^'\n]+)'(?: \([1-9][0-9]*\))? panicked at ([A-Za-z0-9_./-]+):([0-9]+):([0-9]+):\n([^\n]*)",text)
    all_headers=len(re.findall(r'(?m)^thread .* panicked at ',text))
    a,b=restart_sites(helper,composed)
    valid_panics=(all_headers==len(headers)==2 and headers[0]==('pending-restart-higher-source',a['file'],str(a['line']),str(a['column']),MESSAGE+': Elapsed(())')
        and headers[1]==(name,b['file'],str(b['line']),str(b['column']),'called `Result::unwrap()` on an `Err` value: Any { .. }'))
    progress=r'(?:None|Some\(\((?:true|false), '+n+r', (?:true|false), (?:true|false), (?:true|false), (?:true|false)\)\))'
    timeout_lines=[line for line in text.splitlines() if 'pending_restart_post_timeout_catalog_record=' in line]
    timeout_ok=(len(timeout_lines)==1 and re.fullmatch(r'pending_restart_post_timeout_catalog_record=Some\(\(Some\(true\), Some\(false\)\)\) lower_pending_bodies_catalog_records_sent_renew=\['+progress+', '+progress+r'\]',timeout_lines[0]) is not None)
    functional=text.count('pending_restart_functional_catalog_and_new_record_delivered=true')==1
    source_success=re.findall(r'(?m)^pending_restart_source_scoped_catalog_and_exact_record=true local_ordinary_present=(true|false)$',text)
    green=complete and basic.get('passed_gate') is True and prereq and obs[1]=='true' and functional and len(source_success)==1 and not timeout_lines and all_headers==0
    red=(higher and complete and type(code) is int and code==101 and basic.get('passed')==0 and basic.get('failed')==1 and basic.get('panic_count')==2
        and prereq and obs[1]=='false' and int(obs[3])>=30000 and timeout_ok and valid_panics and not functional and not source_success)
    return {'closed_prerequisites':prereq,'required_higher_source':higher,'source_is_lower':role[2]=='true','recovered':obs[1]=='true',
        'observation_elapsed_millis':int(obs[3]),'inner_positive_closes':closes[1]=='true','outer_D_ABC_positive_closes':outer[1]==outer[2]=='true',
        'catalog_present_Record_absent_after_timeout':timeout_ok,'exact_helper_and_composed_join_panics':valid_panics,'expected_panic_sites':[a,b],
        'focused_GREEN':green,'genuine_behavioral_RED':red,'expected_outcome_verified':red if expected=='red' else green}

def unsigned(value,bits):
    ensure(re.fullmatch(r'(?:0|[1-9][0-9]{0,38})',value) is not None,'closed-unsigned')
    number=int(value);ensure(number<(1<<bits),'unsigned-width');return number

def optional_uint(value,bits):
    if value=='None':return None
    match=re.fullmatch(r'Some\(((?:0|[1-9][0-9]{0,38}))\)',value);ensure(match is not None,'optional-unsigned')
    return unsigned(match[1],bits)

def optional_bool(value):
    ensure(value in {'None','Some(true)','Some(false)'},'optional-boolean')
    return None if value=='None' else value=='Some(true)'

def paired_uints(value,bits):
    match=re.fullmatch(r'\[((?:0|[1-9][0-9]{0,38})), ((?:0|[1-9][0-9]{0,38}))\]',value)
    ensure(match is not None,'fixed-two-unsigneds');return [unsigned(match[1],bits),unsigned(match[2],bits)]

def option_pair(value,pattern,parse):
    match=re.fullmatch(r'\[('+pattern+'), ('+pattern+r')\]',value);ensure(match is not None,'fixed-two-optional-rows')
    return [None if part=='None' else parse(part) for part in match.groups()]

def restart_ledgers(raw):
    text=clean(raw);num=r'(?:0|[1-9][0-9]{0,38})';pair=r'\['+num+', '+num+r'\]';opt=r'(?:None|Some\('+num+r'\))';boolean=r'(?:true|false)'
    delivery=exact_record(text,'pending_restart_delivery_observation ',r'pending_restart_delivery_observation recovered=(true|false) source_is_lower=(true|false) elapsed_millis=('+num+') completed_syncs=('+pair+') sync_millis=('+pair+') completed_ticks=('+pair+') tick_millis=('+pair+r') waiting_at=\(([01]), "(sync|automatic_tick|projection|inter_turn_sleep|before_delivery)"\) waiting_millis=('+num+')')
    probe=exact_record(text,'pending_restart_predeadline_sql_observation ',r'pending_restart_predeadline_sql_observation catalog_first_millis=('+opt+') record_first_millis=('+opt+r') scope_unchanged=(None|Some\(true\)|Some\(false\)) sample_count=('+num+') read_millis=('+num+')')
    ready_pattern=r'(?:None|Some\(\('+', '.join([boolean]*5)+r'\)\))'
    ready=exact_record(text,'pending_restart_ready_role_original_nonce_live_core_valid=',r'pending_restart_ready_role_original_nonce_live_core_valid=(\[(?:'+ready_pattern+'), (?:'+ready_pattern+r')\]) same_nonce=(None|Some\(true\)|Some\(false\))')
    ready_values=option_pair(ready[1],ready_pattern,lambda value:[part=='true' for part in value[6:-2].split(', ')])
    first=[optional_uint(probe[i],128) for i in [1,2]]
    ensure(all(value is None or value<30000 for value in first),'actual-predeadline-observation-range')
    result={'schema_known':True,'joint_snapshot_claimed':False,'completed_call_wall_not_CPU':True,
        'completed_syncs':paired_uints(delivery[4],32),'sync_wall_millis':paired_uints(delivery[5],128),
        'completed_ticks':paired_uints(delivery[6],32),'tick_wall_millis':paired_uints(delivery[7],128),
        'waiting_slot':int(delivery[8]),'waiting_stage':delivery[9],'waiting_wall_millis':unsigned(delivery[10],128),
        'delivery_observation_elapsed_millis':unsigned(delivery[3],128),
        'predeadline_SQL':{'catalog_first_millis':first[0],'record_first_millis':first[1],'scope_unchanged':optional_bool(probe[3]),'sample_count':unsigned(probe[4],32),'read_wall_millis':unsigned(probe[5],128),'observation_not_success_or_authority':True},
        'ready_role_original_match_live_Core_valid_by_lower_higher_slot':ready_values,'both_channel_nonce_equal':optional_bool(ready[2]),'actual_nonce_exported':False,
        'post_timeout_progress':None,'post_timeout_body_queue':None}
    if delivery[1]=='false':
        progress_pattern=r'(?:None|Some\(\('+boolean+', '+num+', '+', '.join([boolean]*4)+r'\)\))'
        progress=exact_record(text,'pending_restart_post_timeout_catalog_record=',r'pending_restart_post_timeout_catalog_record=(None|Some\(\((?:None|Some\((?:true|false)\)), (?:None|Some\((?:true|false)\))\)\)) lower_pending_bodies_catalog_records_sent_renew=(\['+progress_pattern+', '+progress_pattern+r'\])')
        def progress_value(value):
            parts=value[6:-2].split(', ')
            return {'local_is_lower':parts[0]=='true','pending_body_count':unsigned(parts[1],64),'pending_catalog':parts[2]=='true','pending_records':parts[3]=='true','ordinary_sent':parts[4]=='true','renew':parts[5]=='true'}
        result['post_timeout_progress']=option_pair(progress[2],progress_pattern,progress_value)
        projection=progress[1]
        if projection=='None':result['post_timeout_catalog_record']=None
        else:
            m=re.fullmatch(r'Some\(\((None|Some\(true\)|Some\(false\)), (None|Some\(true\)|Some\(false\))\)\)',projection)
            result['post_timeout_catalog_record']=[optional_bool(m[1]),optional_bool(m[2])]
        kinds='Catalog|CatalogReceipt|PairPolicyCommitted|Records|RecordReceipt|SendIntent|SendReceipt|DepartureIntent|DepartureReceipt'
        kind_option=r'(?:None|Some\((?:'+kinds+r')\))'
        body_pattern=r'(?:None|Some\(\('+num+', '+kind_option+', '+kind_option+', '+boolean+r'\)\))'
        bodies=exact_record(text,'pending_restart_post_timeout_next_body_front_back_handshake_task=',r'pending_restart_post_timeout_next_body_front_back_handshake_task=(\['+body_pattern+', '+body_pattern+r'\])')
        def body_value(value):
            m=re.fullmatch(r'Some\(\(('+num+'), ('+kind_option+'), ('+kind_option+'), ('+boolean+r')\)\)',value)
            return {'next_body':unsigned(m[1],64),'front_kind':None if m[2]=='None' else m[2][5:-1],'back_kind':None if m[3]=='None' else m[3][5:-1],'handshake_publication_task':m[4]=='true'}
        result['post_timeout_body_queue']=option_pair(bodies[1],body_pattern,body_value)
    return result

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

def phase_rows(raw,timeout):
    lines=[line for line in clean(raw).splitlines() if 'pending_restart_sync_frontier' in line]
    ensure(len(lines)==(2 if timeout else 0) and sum(len(line.encode())+1 for line in lines)<=1024,'two-fixed-timeout-only-frontier-lines')
    result=[]
    for slot,line in enumerate(lines):
        number=r'(?:0|[1-9][0-9]{0,19})'
        match=re.fullmatch('pending_restart_sync_frontier slot='+str(slot)+r' row=\[('+', '.join([number]*15)+r')\]',line)
        ensure(match is not None,'exact-slot-15-u64-frontier')
        values=list(map(int,match[1].split(', ')));ensure(all(value<1<<64 for value in values),'u64-frontier-width')
        calls,status,stage,start,phase_start,end,drain,physical,ingested,skipped,refused,last_receive,last_wait,invalid,snapshot=values
        ensure(status in range(5) and stage in range(11) and invalid in (0,1),'closed-phase-status-enums')
        # Zero clock is UNKNOWN, never a zero elapsed duration or missing work proof.
        if not invalid:
            ensure(snapshot>0,'observed-snapshot-clock')
            if calls==0:ensure(values[:13]==[0]*13,'unentered-fields-none')
            else:
                ensure(status>0 and stage>0 and start>0 and phase_start>=start,'observed-call-phase-clock')
                ensure(phase_start<=snapshot and (end==0 or start<=end<=snapshot),'same-call-bounds')
                ensure((status==1 and end==0) or (status!=1 and end>0),'completed-or-uncompleted-drop-end')
                ensure(all(value==0 or start<=value<=snapshot for value in [last_receive,last_wait]),'current-call-receive-wait-bounds')
                ensure(physical>0 or last_receive==0,'no-invented-first-receive')
                ensure(drain>0 or all(value==0 for value in [physical,ingested,skipped,refused,last_receive,last_wait]),'no-invented-drain')
        result.append({'slot':slot,'numeric_fields':values,'zero_clock_is_unknown':True,'invalid_clock_or_counter':bool(invalid),'joint_snapshot':False,'completed_wall_not_CPU':True})
    return {'rows':result,'field_order':['calls','status','phase','call_start_plus1_us','phase_start_plus1_us','call_end_plus1_us','drain_ordinal','physical_Delivery_receives','ingested','skipped','refused','last_receive_plus1_us','last_outer_wait_plus1_us','invalid','snapshot_plus1_us'],'timeout_only':True,'schema_known':True,'enum_order':['unobserved','setup','first_drain','credit','second_drain','recovery_job','network','admission','subscription_refresh','finalization','returned'],
        'status4_is_early_error_or_cancel_unknown':True,'current_call_last_drain_only':True,'physical_Delivery_not_overflow':True,'wait_is_outer_receive_not_EOSE_poll':True}

def runtime(report):
    inputs=physical();binary=None;before=None;mode=None
    try:
        ensure(shutil.disk_usage('.').free>=8*1024**3,'remote-disk-reserve')
        binary=compile_app(report,'experimental',set(inputs),lambda:save(report));before=digest(binary.read_bytes());mode=stat.S_IMODE(binary.stat().st_mode)
        report['binary_before']={'sha256':before,'mode':mode};save(report)
        for ignored in [False,True]:
            code,text,_=bounded.capture([str(binary),'--exact',NAME]+(['--ignored'] if ignored else [])+['--list','--format','terse'],60,limit=1024*1024)
            item=counts.parse_inventory(text,NAME,ignored);report.setdefault('inventory',{})['ignored' if ignored else 'normal']=item;save(report);ensure(code==0 and item['passed'],'normal-one-ignored-zero')
        ensure(physical()==inputs and binary.is_file() and not binary.is_symlink() and digest(binary.read_bytes())==before and stat.S_IMODE(binary.stat().st_mode)==mode,'prebody-source-binary-mode')
        report.update(runtime_attempted=True,actual_executed_nonignored=None);save(report)
        try:code,raw,seconds=bounded.capture([str(binary),'--exact',NAME,'--nocapture','--test-threads=1'],300,limit=8*1024*1024)
        except bounded.GateFailure as error:
            report['watchdog_triggered']=str(error)=='bounded-command-timeout';report['output_limit_triggered']=str(error)=='bounded-command-output-limit';save(report);raise
        regular=binary.is_file() and not binary.is_symlink()
        report.update(body_exit_code=code,body_seconds=seconds,source_after_body_pristine=physical()==inputs,binary_after_sha256=digest(binary.read_bytes()) if regular else None,binary_after_mode=stat.S_IMODE(binary.stat().st_mode) if regular else None);save(report)
        basic=counts.parse_body(raw,code,NAME);report['basic_counts']=basic
        for key in ['passed','failed','ignored','executed_nonignored']:report['actual_'+key]=basic.get(key)
        report['actual_original_case_passed']=basic.get('passed_gate') is True;save(report)
        ensure(report['source_after_body_pristine'] and report['binary_after_sha256']==before and report['binary_after_mode']==mode,'postbody-source-binary-mode')
        # Independent failures retain all other closed observations, never raw text.
        for key,parse in [('restart_ledgers',lambda:restart_ledgers(raw)),('original_outcome',lambda:restart(raw,NAME,basic,code,'green',Path(RESTART_HELPER).read_text(),Path(COMPOSED_HELPER).read_text()))]:
            try:report[key]=parse()
            except (ValueError,TypeError,OverflowError) as error:report[key]={'schema_known':False,'closed_parser_failure_type':type(error).__name__}
            save(report)
        timeout=(report.get('original_outcome',{}).get('recovered') is False)
        try:report['sync_frontier']=phase_rows(raw,timeout)
        except (ValueError,TypeError,OverflowError) as error:report['sync_frontier']={'schema_known':False,'closed_parser_failure_type':type(error).__name__}
        report['diagnostic_schema_complete']=(basic.get('actual_counts_complete') is True and report.get('original_outcome',{}).get('closed_prerequisites') is True and report.get('restart_ledgers',{}).get('schema_known') is True and 'recovered' in report.get('original_outcome',{}) and report.get('sync_frontier',{}).get('schema_known') is True)
        report['original_component_passed']=(report['actual_original_case_passed'] and report.get('original_outcome',{}).get('focused_GREEN') is True);save(report)
        ensure(report['diagnostic_schema_complete'] and report['original_component_passed'],'original-case-failure-remains-nonzero')
    finally:
        report['source_final_pristine']=physical()==inputs
        regular=binary is not None and binary.is_file() and not binary.is_symlink()
        report['binary_final_pristine']=None if binary is None else regular and digest(binary.read_bytes())==before and stat.S_IMODE(binary.stat().st_mode)==mode
        if not report['source_final_pristine'] or report['binary_final_pristine'] is False:report['original_component_passed']=False
        save(report);ensure(report['source_final_pristine'] and report['binary_final_pristine'] is not False,'final-source-binary-mode')

def original_controls():
    helper=Path(RESTART_HELPER).read_text();composed=Path(COMPOSED_HELPER).read_text();a,b=restart_sites(helper,composed)
    marker='pending_restart_required_higher_source=true source_is_lower=false\npending_restart_first_higher_positive_close=true\npending_restart_authenticated_y_retained_exact_live_x=true\npending_restart_delivery_observation recovered=false source_is_lower=false elapsed_millis=30001 completed_syncs=[1, 2] sync_millis=[1, 2] completed_ticks=[1, 2] tick_millis=[1, 2] waiting_at=(1, "sync") waiting_millis=1\npending_restart_post_timeout_catalog_record=Some((Some(true), Some(false))) lower_pending_bodies_catalog_records_sent_renew=[None, Some((false, 1, false, true, true, false))]\npending_restart_final_positive_closes=true\ndelayed_request_cleanup_d_closed=true abc_closed=true\n'
    panic=lambda thread,site,message:"thread '"+thread+"' panicked at "+site['file']+':'+str(site['line'])+':'+str(site['column'])+':\n'+message+'\n'
    raw='running 1 test\ntest '+NAMES[4]+' ... '+marker+panic('pending-restart-higher-source',a,MESSAGE+': Elapsed(())')+panic(NAMES[4],b,'called `Result::unwrap()` on an `Err` value: Any { .. }')+'FAILED\ntest result: FAILED. 0 passed; 1 failed; 0 ignored; 0 measured; 0 filtered out; finished in 31s\n'
    check=lambda data:restart(data,NAMES[4],counts.parse_body(data,101,NAMES[4]),101,'red',helper,composed)['expected_outcome_verified']
    ensure(check(raw),'source-shaped-two-panic-RED-positive')
    for data in [raw.replace('elapsed_millis=30001','elapsed_millis=29999'),raw.replace('Some(false))) lower_pending','Some(true))) lower_pending'),raw.replace('final_positive_closes=true','final_positive_closes=false'),raw.replace('abc_closed=true','abc_closed=false'),raw.replace('exact_live_x=true','exact_live_x=false'),raw.replace('higher_positive_close=true','higher_positive_close=false'),raw.replace(MESSAGE+': Elapsed(())','unexpected panic'),raw.replace('0 ignored','1 ignored'),raw.replace("thread 'pending-restart-higher-source'","thread 'other'")]:
        ensure(not check(data),'closed-RED-negative')
    green=raw.split("thread '",1)[0].replace('recovered=false','recovered=true')
    green='\n'.join(line for line in green.splitlines() if not line.startswith('pending_restart_post_timeout_catalog_record='))+'\npending_restart_source_scoped_catalog_and_exact_record=true local_ordinary_present=false\npending_restart_functional_catalog_and_new_record_delivered=true\nok\ntest result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 1s\n'
    ensure(restart(green,NAMES[4],counts.parse_body(green,0,NAMES[4]),0,'green',helper,composed)['expected_outcome_verified'],'source-shaped-GREEN-positive')
    lower=green.replace(NAMES[4],NAMES[3]).replace('required_higher_source=true','required_higher_source=false').replace('source_is_lower=false','source_is_lower=true')
    ensure(restart(lower,NAMES[3],counts.parse_body(lower,0,NAMES[3]),0,'green',helper,composed)['expected_outcome_verified'],'lower-source-existing-GREEN-positive')
    malformed=[raw.replace('recovered=false','recovered=unknown'),raw+marker,raw.replace('elapsed_millis=30001','elapsed_millis=-1')]
    for data in malformed:
        try:accepted=check(data)
        except ValueError:accepted=False
        ensure(not accepted,'closed-malformed-or-duplicate-negative')
    for data in [raw.replace(panic(NAMES[4],b,'called `Result::unwrap()` on an `Err` value: Any { .. }'),''),raw+panic('foreign',a,'foreign'),raw.replace('0 passed; 1 failed','0 passed; 0 failed')]:
        ensure(not check(data),'missing-extra-panic-or-zero-body-negative')
    return {'restart_positive':3,'restart_negative':15,'counts':counts.parser_controls(),'runtime_bodies':0}

def controls():
    inherited=original_controls()
    line=lambda slot,row:'pending_restart_sync_frontier slot='+str(slot)+' row='+str(row)+'\n'
    # status4 preserves pending first drain when original future is dropped.
    current=[1,4,2,1,3,101,1,2,1,1,0,51,81,0,110]
    other=[1,2,10,1,90,91,1,0,0,0,0,0,2,0,110]
    good=line(0,current)+line(1,other)
    ensure(phase_rows(good,True)['schema_known'],'closed-timeout-phase-positive')
    ensure(phase_rows('',False)['schema_known'],'original-GREEN-no-appendix-positive')
    none=[0]*14+[110];ensure(phase_rows(line(0,none)+line(1,other),True)['rows'][0]['numeric_fields'][0]==0,'unentered-not-fabricated-zero-work-positive')
    invalid=[1,4,2,0,0,0,1,1,0,0,0,0,0,1,0]
    ensure(phase_rows(line(0,invalid)+line(1,other),True)['schema_known'],'invalid-clock-stays-unknown-positive')
    for data,timeout in [(good,False),(line(0,current),True),(good+good,True),(good.replace('slot=1','slot=2'),True),(good.replace('row=[1, 4, 2','row=[1, 5, 2'),True),(good.replace('row=[1, 4, 2','row=[1, 4, 11'),True),(good.replace('row=[1, 4, 2','row=[18446744073709551616, 4, 2'),True),(good.replace('row=[1, 4, 2','row=[PRIVATE, 4, 2'),True),(line(0,current[:-1])+line(1,other),True),(line(0,[1,4,2,1,0,101,1,2,1,1,0,51,81,0,110])+line(1,other),True)]:
        try:accepted=phase_rows(data,timeout)['schema_known']
        except (ValueError,TypeError,OverflowError):accepted=False
        ensure(not accepted,'closed-phase-malformed-bounds-or-privacy-negative')
    maximum=line(0,[(1<<64)-1]*15)+line(1,[(1<<64)-1]*15)
    ensure(len(maximum.encode())==744 and len(maximum.encode())<=1024,'fixed-shape-source-output-bound')
    return {'original_restart_controls':inherited,'phase_positive':4,'phase_negative':10,'maximum_two_lines_bytes':744,'actual_runtime_bodies':0}

def main():
    parser=argparse.ArgumentParser();parser.add_argument('--preflight',action='store_true');args=parser.parse_args()
    report={'scope':'one higher-source restart explicit-sync diagnostic','runtime_attempted':False,'actual_executed_nonignored':0,'qualification_passed':False,'global_qualification':False,'original_component_passed':False,'diagnostic_schema_complete':False,'automatic_retries':0,'raw_output_retained':False,'fixture_current_thread':False,'composed_driver_stack_bytes':8388608,'environment_stack_bytes':4194304,'original_delivery_deadline_seconds':30,'body_watchdog_seconds':300}
    try:
        report['source_guard']=source_guard(args.preflight);save(report);report['parser_controls']=controls();save(report)
        if not args.preflight:runtime(report)
        report['controller_completed']=True;save(report)
    except Exception as error:report['controller_failure_type']=type(error).__name__;save(report);raise
    finally:report['final_HEAD_pristine']=subprocess.run(['git','diff','--quiet','HEAD']).returncode==0;save(report)
if __name__=='__main__':main()
