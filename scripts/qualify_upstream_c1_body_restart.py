#!/usr/bin/env python3
"""Exact current C1 five-case GREEN and optional positive-receipt omission PFP."""
import argparse, hashlib, json, os, re, shutil, stat, subprocess, time, sys
from pathlib import Path
import qualify_upstream_storage_boundary as bounded
import qualify_upstream_storage_app_handles as counts
import qualify_upstream_automatic_body as held
import qualify_upstream_body_late_ack as late
import upstream_completion_ci as completion
ensure=bounded.ensure
BASE='4408cfd961567059ac313350fc1ab76cd8ddfc88'
OWNER_SOURCE='11eb96f4f72d17d0b40136bdfb6749acf6b676c4'
FRONTIER_PARENT='288544fe2d9dc3323cb1df3b99f35cc017375e13'
FRONTIER_SOURCE='adef3a12b6a8ffa3ed8db16cdd8851e14e57abf8'
PRE_BODY_SOURCE='79d04efe4957ec2db2f3f02ef9ce6f97292ef869'
RAW_SOURCE='4408cfd961567059ac313350fc1ab76cd8ddfc88'
FRONTIER_PATHS={'crates/marmot-app/src/client/account_chat_sharing/automatic/tests/pending_restart_acceptance.rs': {'before': 'b69632ce6c94e18e7ebf02b518d2eaed50c83bd1c87be15ab12ea7ca90ed8c0c', 'after': '0b58fde3834d61a21f22afb34f4a9ac23fadf8c42a1b0a0fdca520ff9718068c', 'mode': '100644'}, 'crates/marmot-app/src/client/explicit_sync_frontier.rs': {'before': None, 'after': 'f4a73ac1995134480f6398006ad3af4ddeb2f4a48cce37109df4b18356349dd7', 'mode': '100644'}, 'crates/marmot-app/src/client/mod.rs': {'before': '434a971bf57ed402253cad7cf58c76f5be66ba46f28892bcf5a6456a978c5e7e', 'after': '3eb116d2771a0aa8827dd78f44ac4d4ab806eb397265748cd83192d353836686', 'mode': '100644'}, 'crates/marmot-app/src/client/sync.rs': {'before': '2491c5c9a56de4034bf88de33083cebb13e65e05147ae6aff2a102d5f0a2dc96', 'after': '04b5c0360ff97151ee7882100d0b9eae6d10951916cd6907672347f23f1907ce', 'mode': '100644'}, 'crates/marmot-app/src/client/sync/comparison_job.rs': {'before': '44a286cd7e1721ba3483c44742161a8cbe24c0063bcad02b632330e3e6e564bd', 'after': 'e99ce8660c45a26efb515107606ebe4b8d040ec4924c1ab17fe5b933bbf6e6b9', 'mode': '100644'}, 'crates/marmot-app/src/lib.rs': {'before': '37b1567aec1b88e484b2093108ff420e16afe326126f460be4a52d67dff35113', 'after': 'c68c15414ccdfffd9f5576f5334a876f8b01af19dae193ff844f41cccb2f221c', 'mode': '100644'}}
BODY_STATE_PATHS={'crates/marmot-app/src/client/account_chat_sharing/automatic/records.rs': {'before': 'f433c23c32115850168fac6ee682992aa359da145655facec08e20a833c9b6d8', 'raw': 'acf29d2b57289ce1f4b4a486e9a7e415333cb86c3d266bffc01c4c5140171578', 'canonical': 'acf29d2b57289ce1f4b4a486e9a7e415333cb86c3d266bffc01c4c5140171578', 'mode': '100644'}, 'crates/marmot-app/src/client/account_chat_sharing/automatic/tests/pending_restart_acceptance.rs': {'before': '0b58fde3834d61a21f22afb34f4a9ac23fadf8c42a1b0a0fdca520ff9718068c', 'raw': 'fbe456a032b4c8ff7fe5b83af0d97b24e5adaa089b4e7dd2b3be598edee4ba0b', 'canonical': 'fbe456a032b4c8ff7fe5b83af0d97b24e5adaa089b4e7dd2b3be598edee4ba0b', 'mode': '100644'}}
WORKFLOW_SHA='0954c3a35a338c1c0936c97cf9f3cb139ed5da90f411585c71d2e5d317689ae8'
SELF='scripts/qualify_upstream_c1_body_restart.py'
WORKFLOW='.github/workflows/c1-body-restart.yml'
REF='refs/heads/ci/upstream-c1-body-restart-20261018'
SYNC_FRONTIER_PARSER_SOURCE='aa6c24ff73b43622b4094915e5a1b4d28028b759'
SYNC_FRONTIER_SOURCE_PINS={'crates/marmot-app/src/client/explicit_sync_frontier.rs': 'f4a73ac1995134480f6398006ad3af4ddeb2f4a48cce37109df4b18356349dd7', 'crates/marmot-app/src/client/account_chat_sharing/automatic/tests/pending_restart_acceptance.rs': 'fbe456a032b4c8ff7fe5b83af0d97b24e5adaa089b4e7dd2b3be598edee4ba0b'}
PRODUCT='crates/marmot-app/src/client/account_chat_sharing/automatic.rs'
PRODUCT_SHA='0fde8d14ceea74cd2dd998cd4bfd4e516d61f3704e682931fc42f2460b95d117'
OMISSION='                    self.collect_finished_automatic_publication(&mut entry);\n                    if entry.publication.as_ref().is_some_and(|publication| {\n                        publication.body_context.is_some()\n                            && publication.outcome.as_ref().is_some_and(Result::is_ok)\n                    }) && self.harvest_automatic_publication(&mut entry)?\n                    {\n                        self.finish_automatic_body_effects(&mut entry)?;\n                    }\n'
MUTANT_SHA='75a669e0c5935535ae859291cc108decb68fe077ec7d805cba1be7d19e3ef9d7'
RESTART_HELPER='crates/marmot-app/src/client/account_chat_sharing/automatic/tests/pending_restart_acceptance.rs'
COMPOSED_HELPER='crates/marmot-app/src/tests.rs'
MESSAGE='actual restarted peers must deliver genuine ordinary catalog and canonical record within the unchanged recovery deadline'
OUT=Path('c1-body-restart-evidence')
NAMES=[held.NAME,late.PREFIX+late.CASES[0],late.PREFIX+late.CASES[1],
 'native_device_linking::tests::pending_lower_request_recovers_after_higher_restarts_before_consent',
 'native_device_linking::tests::pending_restart_higher_source_delivers_catalog_and_record']
FEATURES='marmot-app/otlp-export,marmot-app/product-analytics-export,marmot-app/test-policy-overrides,marmot-app/experimental-device-sync,cgka-engine/test-policy-overrides,cgka-engine/test-crash-hooks'
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
        and os.environ.get('UPSTREAM_C1_BODY_BASELINE')==BASE,'exact-hosted-ref-source')
    ensure(os.environ.get('CARGO_INCREMENTAL')=='1' and os.environ.get('CARGO_BUILD_JOBS')=='2' and os.environ.get('RUST_MIN_STACK')=='4194304'
        and all(os.environ.get(k)=='0' for k in ['CARGO_PROFILE_DEV_DEBUG','CARGO_PROFILE_TEST_DEBUG'])
        and all(not os.environ.get(k) for k in ['RUSTFLAGS','CARGO_ENCODED_RUSTFLAGS','RUSTC_BOOTSTRAP','CARGO_PROFILE_DEV_OPT_LEVEL','CARGO_PROFILE_TEST_OPT_LEVEL']),'exact-build-cohort')
    ensure(subprocess.run(['git','merge-base','--is-ancestor',BASE,head]).returncode==0,'BASE-ancestor')
    for value in [PRE_BODY_SOURCE,RAW_SOURCE]:
        ensure(type(value)is str and re.fullmatch('[0-9a-f]{40}',value),'root-reviewed-body-source-required')
    links=[(FRONTIER_PARENT,OWNER_SOURCE),(FRONTIER_PARENT,FRONTIER_SOURCE),(OWNER_SOURCE,PRE_BODY_SOURCE),(FRONTIER_SOURCE,PRE_BODY_SOURCE),(PRE_BODY_SOURCE,RAW_SOURCE),(RAW_SOURCE,BASE)]
    ensure(all(subprocess.run(['git','merge-base','--is-ancestor',a,b]).returncode==0 for a,b in links),'reviewed-owner-frontier-body-source-ancestry')
    ensure(set(git('diff','--name-only',FRONTIER_PARENT,FRONTIER_SOURCE).decode().splitlines())==set(FRONTIER_PATHS),'exact-reviewed-six-frontier-paths')
    owner=layout(OWNER_SOURCE);frontier=layout(FRONTIER_SOURCE);expected_merge=dict(owner)
    for path,pins in FRONTIER_PATHS.items():
        for commit,key in [(FRONTIER_PARENT,'before'),(FRONTIER_SOURCE,'after')]:
            if pins[key] is None:ensure(path not in layout(commit),'reviewed-new-frontier-path-absent')
            else:ensure(layout(commit)[path][0]==pins['mode'] and digest(git('show',commit+':'+path))==pins[key],'reviewed-six-frontier-full-source-mode')
        expected_merge[path]=frontier[path]
    ensure(layout(PRE_BODY_SOURCE)==expected_merge,'exact-owner-with-six-reviewed-frontier-blobs-no-other-change')
    ensure(set(git('diff','--name-only',PRE_BODY_SOURCE,RAW_SOURCE).decode().splitlines())==set(BODY_STATE_PATHS)
        and set(git('diff','--name-only',RAW_SOURCE,BASE).decode().splitlines())<=set(BODY_STATE_PATHS),'exact-two-body-snapshot-paths-then-hosted-format-only')
    for path,pins in BODY_STATE_PATHS.items():
        for commit,key in [(PRE_BODY_SOURCE,'before'),(RAW_SOURCE,'raw'),(BASE,'canonical')]:
            ensure(layout(commit)[path][0]==pins['mode'] and digest(git('show',commit+':'+path))==pins[key],'reviewed-body-snapshot-full-source-mode')
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
        and Path(PRODUCT).read_bytes().count(OMISSION.encode())==1,'exact-workflow-and-product-witness')
    ensure(all(digest(Path(path).read_bytes())==value for path,value in SYNC_FRONTIER_SOURCE_PINS.items()),'exact-canonical-passive-sync-frontier-source')
    ensure(set(git('ls-files','--others','--exclude-standard').decode().splitlines())<={str(OUT/'result.json')},'untracked-closure')
    return {'head':head,'baseline':BASE,'whole_source_modes_verified':True,'Rust_exceptions':[],
        'old_guards_or_main_called':False,'old_module_globals_mutated':False,'historical_runtime_reused':False}

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
    result={'delivery_recovered':delivery[1]=='true','schema_known':True,'joint_snapshot_claimed':False,'completed_call_wall_not_CPU':True,
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

def verdict(raw,code,basic,name,expected):
    if name in NAMES[3:]:return restart(raw,name,basic,code,expected,Path(RESTART_HELPER).read_text(),Path(COMPOSED_HELPER).read_text())
    parser_raw=normalize_parser_prefix(raw,name)
    ensure(expected=='green','mutant-only-higher-restart')
    if name==NAMES[0]:
        parsed=held.parse(parser_raw);parsed['body_exit_code']=code;ok=held.body_green(parsed)
        result={k:parsed.get(k) for k in ['responsive_while_held','all_prerequisites_and_two_positive_closes','all_panic_header_count']}
    else:
        case=name.rsplit('::',1)[1];parsed=late.parse(parser_raw,case,code);ok=late.green(parsed,case) and parsed.get('cleanup_diagnostics',{}).get('valid') is True
        result={k:parsed.get(k) for k in ['observed','cleanup_diagnostics','all_panic_header_count']}
    return dict(result,expected_outcome_verified=bool(ok and basic.get('passed_gate') is True))

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

def sync_frontier_controls():
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
    return {'phase_positive':4,'phase_negative':10,'maximum_two_lines_bytes':744,'actual_runtime_bodies':0}

def compile_app(report,cohort,tracked,save_report):
    features=['otlp-export','product-analytics-export','test-policy-overrides','experimental-device-sync']
    command=['cargo','test','--locked','-p','marmot-app','--lib','--no-run','--message-format=json']
    if features:command+=['--features',FEATURES]
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
    graph=completion.feature_metadata(binary)
    report['dependency_fingerprints']=graph;save_report()
    ensure(graph.get('verified') is True and {'marmot_app','cgka_engine','storage_sqlite','cgka_session','marmot_account','transport_nostr'}<=set(graph.get('nodes',{}))
        and 'test-crash-hooks' in graph['nodes']['cgka_engine']['features'],'actual-six-node-feature-graph')
    return binary

def aggregate(cases,expected_count):
    result={'actual_case_rows':len(cases),'expected_case_rows':expected_count,'unknown_count_cases':sum(any(type(row.get('basic_counts',{}).get(k)) is not int for k in ['passed','failed','ignored','executed_nonignored']) for row in cases),'nonqualifying_count_shape_cases':sum(row.get('basic_counts',{}).get('actual_counts_complete') is not True for row in cases),'missing_case_rows':max(0,expected_count-len(cases))}
    for key in ['passed','failed','ignored','executed_nonignored']:
        values=[row.get('basic_counts',{}).get(key) for row in cases]
        known=[v for v in values if type(v) is int and v>=0]
        result['actual_'+key]=sum(values) if len(cases)==expected_count and len(known)==len(values) else None
        result['known_partial_'+key]=sum(known) if known else None
    return result


def body_state_rows(raw,needed):
    lines=[line for line in clean(raw).splitlines() if 'pending_restart_body_state' in line]
    result={'schema_known':False,'records':[],'post_timeout_current_policy_channel':True,'joint_with_earlier_ledgers':False,'task_polled':False,'current_original_X_identity_proven':False}
    if not needed:
        ensure(not lines,'no-body-state-on-success');result['schema_known']=True;return result
    ensure(len(lines)==2 and sum(len(line)+1 for line in lines)<=1024,'exact-two-bounded-body-state-rows')
    boolean=r'(?:true|false)';publication=r'(?:None|Some\(\([123], '+boolean+', '+boolean+r', [012]\)\))'
    clock=r'(?:None|Some\('+boolean+r'\))';number=r'(?:0|[1-9][0-9]{0,2})';assembly=r'(?:None|Some\(\('+number+', '+number+r'\)\))'
    for slot,line in enumerate(lines):
        header=re.fullmatch(r'pending_restart_body_state slot=([01]) row=(.*)',line)
        ensure(header is not None and int(header[1])==slot,'ordered-body-state-slot')
        if header[2]=='None':result['records'].append({'slot':slot,'channel_observed':False,'publication':None,'record_clock':None,'assembly':None});continue
        row=re.fullmatch(r'Some\(\(('+publication+'), ('+clock+'), ('+assembly+r')\)\)',header[2]);ensure(row is not None,'closed-body-state-tuple')
        pub=None
        if row[1]!='None':
            match=re.fullmatch(r'Some\(\(([123]), (true|false), (true|false), ([012])\)\)',row[1]);ensure(match is not None,'closed-publication-tuple')
            kind=int(match[1]);context=match[2]=='true';ensure(context==(kind==3),'publication-kind-context-consistency')
            pub={'kind':{1:'Request',2:'Consent',3:'Body'}[kind],'body_context_present':context,'task_is_finished':match[3]=='true','retained_outcome':{0:'Uncollected',1:'Ok',2:'Err'}[int(match[4])]}
        parts=None
        if row[3]!='None':
            match=re.fullmatch(r'Some\(\(('+number+'), ('+number+r')\)\)',row[3]);ensure(match is not None,'closed-assembly-tuple')
            expected,present=(unsigned(match[i],64) for i in [1,2]);ensure(1<=expected<=128 and present<=expected,'bounded-current-assembly-counts')
            parts={'expected':expected,'present':present,'count_equality_is_not_commit':True}
        result['records'].append({'slot':slot,'channel_observed':True,'publication':pub,'record_clock':optional_bool(row[2]),'assembly':parts})
    result['schema_known']=True;return result

def body_state_controls():
    pair=lambda a,b:'pending_restart_body_state slot=0 row='+a+'\npending_restart_body_state slot=1 row='+b+'\n'
    pending='Some((Some((3, true, false, 0)), Some(false), Some((8, 6))))'
    empty='Some((None, None, None))';good=pair(pending,empty)
    row=body_state_rows(good,True);ensure(row['records'][0]['publication']['retained_outcome']=='Uncollected' and row['records'][0]['assembly']['present']==6,'source-shaped-pending-body-state')
    ensure(body_state_rows(pair('None',empty),True)['records'][0]['channel_observed'] is False,'missing-channel-is-unknown')
    for kind,context in [(1,'false'),(2,'false'),(3,'true')]:
        for outcome in [0,1,2]:
            item='Some((Some(('+str(kind)+', '+context+', true, '+str(outcome)+')), Some(true), Some((128, 128))))'
            ensure(body_state_rows(pair(item,empty),True)['schema_known'],'finite-kind-outcome-complete-assembly')
    ensure(body_state_rows(pair(pending.replace('false, 0','true, 0'),empty),True)['schema_known'],'finished-uncollected-result-unknown')
    ensure(body_state_rows('',False)['schema_known'],'no-timeout-no-supplement')
    bad=[good.replace('slot=1 row='+empty,'slot=1 row='+empty+' PRIVATE'),good+good,good.splitlines()[0],good.replace('slot=1','slot=0'),good.replace('slot=1','slot=2'),good.replace('Some((3,','Some(3,'),good.replace('Some((8, 6))','Some((0, 0))'),good.replace('Some((8, 6))','Some((129, 6))'),good.replace('Some((8, 6))','Some((8, 9))'),good.replace('true, false, 0','false, false, 0'),good.replace('3, true','4, true'),good.replace('false, 0','false, 3'),good.replace('Some(false)','Some(PRIVATE)'),good.replace('Some((8, 6))','Some((-1, 0))'),good.replace('row=Some','foreign row=Some',1)]
    for text in bad:
        try:body_state_rows(text,True)
        except (ValueError,TypeError,OverflowError):continue
        raise ValueError('invalid-body-state-accepted')
    try:body_state_rows(good,False)
    except ValueError:pass
    else:raise ValueError('unexpected-success-body-state-accepted')
    ensure('PRIVATE' not in json.dumps(row),'no-private-body-state-export')
    return {'positive':13,'negative':len(bad)+1,'runtime_bodies':0}

def execute_case(root,row,binary,before,mode,expected_inputs,name,expected):
    row.update(name=name,expected=expected,runtime_attempted=False,actual_executed_nonignored=0,expected_outcome_verified=False)
    save(root)
    for ignored in [False,True]:
        code,text,_=bounded.capture([str(binary),'--exact',name]+(['--ignored'] if ignored else [])+['--list','--format','terse'],60,limit=1024*1024)
        item=counts.parse_inventory(text,name,ignored);row.setdefault('inventory',{})['ignored' if ignored else 'normal']=item;save(root)
        ensure(code==0 and item['passed'],'one-normal-zero-ignored-exact-case')
    ensure(physical()==expected_inputs and digest(binary.read_bytes())==before and stat.S_IMODE(binary.stat().st_mode)==mode,'prebody-source-binary-mode')
    row.update(runtime_attempted=True,actual_executed_nonignored=None);save(root)
    try:code,raw,seconds=bounded.capture([str(binary),'--exact',name,'--nocapture','--test-threads=1'],300,limit=8*1024*1024)
    except bounded.GateFailure as error:
        row['watchdog_triggered']=str(error)=='bounded-command-timeout';row['output_limit_triggered']=str(error)=='bounded-command-output-limit';save(root);raise
    row.update(body_exit_code=code,body_seconds=seconds,source_after_body_pristine=physical()==expected_inputs,
        binary_after_sha256=digest(binary.read_bytes()) if binary.is_file() and not binary.is_symlink() else None,
        binary_after_mode=stat.S_IMODE(binary.stat().st_mode) if binary.is_file() and not binary.is_symlink() else None);save(root)
    basic=counts.parse_body(raw,code,name);row['basic_counts']=basic
    for dest,key in [('actual_passed','passed'),('actual_failed','failed'),('actual_ignored','ignored'),('actual_executed_nonignored','executed_nonignored')]:row[dest]=basic.get(key)
    row['actual_test_passed']=basic.get('passed_gate') is True;save(root)
    ensure(row['source_after_body_pristine'] and row['binary_after_sha256']==before and row['binary_after_mode']==mode,'postbody-source-binary-mode')
    if name in NAMES[3:]:
        try:row['restart_ledgers']=restart_ledgers(raw)
        except (ValueError,TypeError,OverflowError) as error:
            row['restart_ledgers']={'schema_known':False,'closed_parser_failure_type':type(error).__name__}
        save(root)
    if name==NAMES[4]:
        # Preserve the passive frontier before the original outcome parser. No
        # successful SQL/phase state can waive the original 30s recovery oracle.
        recovered=row.get('restart_ledgers',{}).get('delivery_recovered')
        try:
            ensure(type(recovered) is bool,'higher-original-timeout-mode-known')
            row['sync_frontier']=phase_rows(raw,not recovered)
        except (ValueError,TypeError,OverflowError) as error:
            row['sync_frontier']={'schema_known':False,'closed_parser_failure_type':type(error).__name__}
        save(root)
        try:
            ensure(type(recovered)is bool,'higher-body-state-timeout-mode-known')
            row['body_state']=body_state_rows(raw,not recovered)
        except (ValueError,TypeError,OverflowError) as error:
            row['body_state']={'schema_known':False,'closed_parser_failure_type':type(error).__name__}
        save(root)
    row['outcome']=verdict(raw,code,basic,name,expected)
    row['expected_outcome_verified']=row['outcome']['expected_outcome_verified'] and (name not in NAMES[3:] or row['restart_ledgers'].get('schema_known') is True) and (name!=NAMES[4] or (row['sync_frontier'].get('schema_known') is True and row['body_state'].get('schema_known') is True));save(root)

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
        specs=[(name,'green') for name in NAMES]
        baseline_binary,baseline_hash,baseline_mode=phase(report,'baseline',cohort,frozen,specs)
        baseline_bytes=baseline_binary.read_bytes();report['runtime_attempted']=any(row.get('runtime_attempted') for row in report['phases']['baseline']['cases'])
        if expected=='green':
            report['expected_outcome_verified']=report['phases']['baseline']['phase_passed'];save(report)
            ensure(report['expected_outcome_verified'],'required-baseline-outcome-not-established');return
        # Admission is before mutation/finally: an unqualified baseline is not retried as restoration.
        if report['phases']['baseline']['phase_passed'] is not True:
            report['skipped_mutant_and_restored_reason']='baseline_unqualified_no_mutation_attempted';save(report)
            raise ValueError('PFP-baseline-must-qualify-before-mutation')
        ensure(digest(original)==PRODUCT_SHA and original.count(OMISSION.encode())==1,'exact-fixed-product-before-mutation')
        mutant=original.replace(OMISSION.encode(),b'',1)
        ensure(digest(mutant)==MUTANT_SHA,'exact-reviewed-positive-receipt-only-omission')
        expected_mutant=dict(frozen);expected_mutant[PRODUCT]=(frozen[PRODUCT][0],product_mode,digest(mutant))
        try:
            mutation_attempted=True;report['mutation_attempted']=True;save(report)
            write_fresh(product,mutant,product_mode)
            ensure(physical()==expected_mutant,'only-owned-receipt-omission-source-and-mode')
            phase(report,'mutant',cohort,expected_mutant,[(NAMES[4],'red')],different_from=baseline_hash)
        except Exception as error:report['mutant_controller_failure_type']=type(error).__name__;save(report)
        finally:
            restore_owned(product,original,product_mode)
            report['source_restored_before_fresh_compile']=physical()==frozen;save(report)
            ensure(report['source_restored_before_fresh_compile'],'exact-source-restore-before-compile')
            try:phase(report,'restored',cohort,frozen,[(name,'green') for name in NAMES])
            except Exception as error:report['restored_controller_failure_type']=type(error).__name__;save(report)
        rows=[case for label in ['baseline','mutant','restored'] for case in report.get('phases',{}).get(label,{}).get('cases',[])]
        report['aggregate']=aggregate(rows,11)
        restored=report.get('phases',{}).get('restored',{});mutant_row=report.get('phases',{}).get('mutant',{})
        report['baseline_restored_binary_equal']=restored.get('binary_before')==report['phases']['baseline']['binary_before']
        signatures=[{name:node['features'] for name,node in report['phases'].get(label,{}).get('dependency_fingerprints',{}).get('nodes',{}).items()} for label in ['baseline','mutant','restored']]
        report['same_observed_dependency_feature_cohort']=bool(signatures[0] and signatures[0]==signatures[1]==signatures[2])
        report['component_PFP_verified']=(all(report.get('phases',{}).get(label,{}).get('phase_passed') is True for label in ['baseline','mutant','restored'])
            and report['aggregate'].get('actual_passed')==10 and report['aggregate'].get('actual_failed')==1 and report['aggregate'].get('actual_ignored')==0
            and report['aggregate'].get('actual_executed_nonignored')==11 and report['baseline_restored_binary_equal'] and report['same_observed_dependency_feature_cohort']
            and mutant_row.get('binary_before',{}).get('sha256')!=baseline_hash)
        report['expected_outcome_verified']=report['component_PFP_verified'];save(report);ensure(report['component_PFP_verified'],'fresh-eleven-body-PFP-required')
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
        report['actual_body_counts']=aggregate(allcases,11 if expected=='pfp' and mutation_attempted else 5)
        for key in ['passed','failed','ignored','executed_nonignored']:report['actual_'+key]=report['actual_body_counts']['actual_'+key]
        if not report['runtime_attempted']:report['actual_executed_nonignored']=0
        report['qualification_passed']=False;save(report)
        ensure(report['source_final_pristine'] and report.get('baseline_binary_final_pristine',True),'final-source-binary-mode')
        if sys.exc_info()[0] is None:
            ensure(report.get('expected_outcome_verified') is True and not report['fallback_source_restore_used'] and not report['fallback_binary_copy_used'],'final-outcome-without-fallback-required')
            if expected=='pfp':ensure(report['component_PFP_verified'],'final-PFP-must-remain-qualified')

def higher_diagnostic(report):
    frozen=physical();binary=None;before=None;mode=None
    report.update(runtime_attempted=False,mutation_attempted=False,component_PFP_verified=False,qualification_passed=False,higher_diagnostic_completed=False)
    try:
        report['free_bytes']=shutil.disk_usage('.').free;save(report);ensure(report['free_bytes']>=8*1024**3,'remote-disk-reserve')
        binary,before,mode=phase(report,'higher_diagnostic','experimental',frozen,[(NAMES[4],'green')])
    finally:
        cases=report.get('phases',{}).get('higher_diagnostic',{}).get('cases',[])
        report['runtime_attempted']=any(case.get('runtime_attempted') is True for case in cases)
        report['actual_body_counts']=aggregate(cases,1)
        for key in ['passed','failed','ignored','executed_nonignored']:report['actual_'+key]=report['actual_body_counts']['actual_'+key]
        if not report['runtime_attempted']:report['actual_executed_nonignored']=0
        report['source_final_pristine']=physical()==frozen
        report['baseline_binary_final_pristine']=None if binary is None else binary.is_file() and not binary.is_symlink() and digest(binary.read_bytes())==before and stat.S_IMODE(binary.stat().st_mode)==mode
        case=cases[0] if len(cases)==1 else {};basic=case.get('basic_counts',{})
        report['higher_diagnostic_completed']=(len(cases)==1 and basic.get('actual_counts_complete') is True and type(basic.get('executed_nonignored'))is int and basic['executed_nonignored']==1
            and basic.get('ignored')==0 and basic.get('compiler_error_count')==0 and case.get('outcome',{}).get('closed_prerequisites') is True
            and case.get('restart_ledgers',{}).get('schema_known') is True and case.get('sync_frontier',{}).get('schema_known') is True and case.get('body_state',{}).get('schema_known') is True
            and report['source_final_pristine'] and report['baseline_binary_final_pristine'] is True)
        report['component_PFP_verified']=False;report['qualification_passed']=False;save(report)
        ensure(report['source_final_pristine'] and report['baseline_binary_final_pristine'] is not False,'diagnostic-final-source-binary-mode')
    ensure(report['higher_diagnostic_completed'],'one-original-higher-closed-diagnostic-required')
    ensure(case.get('expected_outcome_verified') is True,'original-higher-runtime-failure-remains-failure')

def controls():
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
    return {'restart_positive':3,'restart_negative':15,'counts':counts.parser_controls(),'held':held.parser_preflight(extraction=True),'late_ACK':late.parser_controls(),'runtime_bodies':0}

def prefix_and_ledger_controls():
    header='test '+NAMES[0]+' ... '
    events=['automatic-body-control stage='+stage+(' responsive=true' if i==4 else ' index='+str(i-8) if i in [8,9] else '') for i,stage in enumerate(held.STAGES)]
    body='running 1 test\n'+header+'\n'.join(events)+'\nok\ntest result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 1s\n'
    normalized=normalize_parser_prefix(body,NAMES[0]);ensure(counts.parse_body(body,0,NAMES[0])['passed_gate'] and held.body_green(dict(held.parse(normalized),body_exit_code=0)),'attached-held-first-marker-positive')
    ensure(not held.body_green(dict(held.parse(body),body_exit_code=0)),'old-attached-marker-is-not-claimed-retro-green')
    for case in late.CASES:
        name=late.PREFIX+case;hold=case==late.CASES[1]
        cleanup='body-late-ack-cleanup runtime1=true runtime2=true relay_planes=2 connections=2 closed_connections=2 invalid=false task_outcome=1 child_outcomes=[1, 1, 0, 0] io_categories='+json.dumps([[0]*14 for _ in range(8)])+' close_handshakes='+json.dumps([[0]*8 for _ in range(2)])
        record='body-late-ack-control hold_receipt='+str(hold).lower()+' prerequisites=true cleanup=true followup=true old_body_effects='+str(int(hold))+' sdk_success=1 successful_harvest=1 context_rejected=0 future_dropped=1 retired=1'
        raw='running 1 test\ntest '+name+' ... '+cleanup+'\n'+record+'\nok\ntest result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 1s\n'
        parsed=late.parse(normalize_parser_prefix(raw,name),case,0)
        ensure(late.green(parsed,case) and parsed['cleanup_diagnostics']['valid'],'attached-late-cleanup-positive')
        ensure(not late.parse(raw,case,0)['cleanup_diagnostics']['valid'],'old-raw-cleanup-prefix-unparsed-not-retro-evidence')
        ensure(verdict(raw,0,counts.parse_body(raw,0,name),name,'green')['expected_outcome_verified'],'new-late-wrapper-valid-cleanup-positive')
        for bad in [raw.replace(cleanup,''),raw.replace(cleanup,cleanup+' private')]:
            old=late.parse(normalize_parser_prefix(bad,name),case,0)
            ensure(late.green(old,case) and not old['cleanup_diagnostics']['valid'],'isolated-legacy-green-missing-or-malformed-cleanup')
            ensure(not verdict(bad,0,counts.parse_body(bad,0,name),name,'green')['expected_outcome_verified'],'current-wrapper-rejects-unqualified-cleanup')
    ensure(normalize_parser_prefix('foreign '+header+'automatic-body-control',NAMES[0])=='foreign '+header+'automatic-body-control','not-line-start-prefix-untouched')
    ensure(normalize_parser_prefix('test other ... automatic-body-control',NAMES[0])=='test other ... automatic-body-control','foreign-case-prefix-untouched')
    try:normalize_parser_prefix(body+'\n'+header,NAMES[0])
    except ValueError:pass
    else:raise ValueError('duplicate-current-header-accepted')
    broken=body.replace(events[0],events[0]+' private')
    ensure(not held.body_green(dict(held.parse(normalize_parser_prefix(broken,NAMES[0])),body_exit_code=0)),'normalization-does-not-repair-malformed-marker')
    ensure(not held.body_green(dict(held.parse(normalize_parser_prefix(body.replace(events[4],'automatic-body-control stage='+held.STAGES[4]+' responsive=false'),NAMES[0])),body_exit_code=0)),'normalization-preserves-failed-responsive-control')
    numeric='pending_restart_delivery_observation recovered=false source_is_lower=false elapsed_millis=30001 completed_syncs=[1, 2] sync_millis=[3, 4] completed_ticks=[5, 6] tick_millis=[7, 8] waiting_at=(1, "automatic_tick") waiting_millis=9\npending_restart_predeadline_sql_observation catalog_first_millis=Some(29) record_first_millis=None scope_unchanged=Some(true) sample_count=7 read_millis=3\npending_restart_ready_role_original_nonce_live_core_valid=[Some((true, false, true, true, true)), None] same_nonce=None\npending_restart_post_timeout_catalog_record=Some((Some(true), Some(false))) lower_pending_bodies_catalog_records_sent_renew=[None, Some((false, 1, false, true, true, false))]\npending_restart_post_timeout_next_body_front_back_handshake_task=[Some((7, Some(Records), None, false)), None]\n'
    row=restart_ledgers(numeric);ensure(row['completed_syncs']==[1,2] and row['waiting_stage']=='automatic_tick' and row['post_timeout_body_queue'][0]['front_kind']=='Records' and row['actual_nonce_exported'] is False,'closed-restart-ledgers-positive')
    for bad in [numeric.replace('sample_count=7','sample_count=4294967296'),numeric.replace('Some(29)','Some(30000)'),numeric.replace('Some(Records)','Some(PRIVATE)'),numeric.replace('same_nonce=None','same_nonce=actual_secret'),numeric.replace('completed_syncs=[1, 2]','completed_syncs=[1, 2, 3]'),numeric+numeric]:
        try:restart_ledgers(bad)
        except ValueError:continue
        raise ValueError('invalid-restart-ledger-accepted')
    maximum=numeric.replace('sync_millis=[3, 4]','sync_millis=['+str((1<<128)-1)+', '+str((1<<128)-1)+']')
    ensure(restart_ledgers(maximum)['sync_wall_millis']==[(1<<128)-1]*2,'u128-actual-wall-bound-positive')
    try:restart_ledgers(numeric.replace('sync_millis=[3, 4]','sync_millis=['+str(1<<128)+', 4]'))
    except ValueError:pass
    else:raise ValueError('u128-overflow-accepted')
    empty=numeric.replace('recovered=false','recovered=true').replace('catalog_first_millis=Some(29)','catalog_first_millis=None').replace('scope_unchanged=Some(true)','scope_unchanged=None')
    empty='\n'.join(line for line in empty.splitlines() if not line.startswith('pending_restart_post_timeout_'))+'\n'
    ensure(restart_ledgers(empty)['predeadline_SQL']['catalog_first_millis'] is None and restart_ledgers(empty)['post_timeout_progress'] is None,'safe-unknown-SQL-and-no-timeout-green-positive')
    return {'attached_marker_positive':3,'prefix_closed_negative':9,'ledger_positive':3,'ledger_negative':7,'runtime_bodies':0,'old_receipt_reclassified':False}

def main():
    p=argparse.ArgumentParser();p.add_argument('--preflight',action='store_true');p.add_argument('--expected',choices=['green','pfp'],default='green');p.add_argument('--higher-diagnostic',action='store_true');args=p.parse_args();ensure(not args.higher_diagnostic or args.expected=='green','diagnostic-cannot-request-PFP')
    report={'scope':'one original higher restart diagnostic; no mutation' if args.higher_diagnostic else 'C1 positive-receipt ordering and five unchanged existing controls','preflight':args.preflight,'expected':args.expected,'higher_diagnostic':args.higher_diagnostic,'runtime_attempted':False,
        'actual_executed_nonignored':0,'qualification_passed':False,'native_global_qualification':False,'automatic_retries':0,'environment_RUST_MIN_STACK':4194304,
        'restart_composed_driver_and_worker_stack_bytes':8388608,'Tokio_workers':2,'raw_output_retained':False}
    try:
        report['source_guard']=source_guard(args.preflight);save(report);report['parser_controls']=controls();report['prefix_and_restart_ledger_controls']=prefix_and_ledger_controls();report['sync_frontier_controls']=sync_frontier_controls();report['body_state_controls']=body_state_controls();save(report)
        if not args.preflight:
            if args.higher_diagnostic:higher_diagnostic(report)
            else:runtime(report,'experimental',args.expected)
        report['controller_completed']=True;save(report)
    except Exception as error:report['controller_failure_type']=type(error).__name__;save(report);raise
    finally:report['final_HEAD_git_pristine']=subprocess.run(['git','diff','--quiet','HEAD']).returncode==0;save(report)
if __name__=='__main__':main()
