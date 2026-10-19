#!/usr/bin/env python3
"""Exact current C1 five-case GREEN and optional positive-receipt omission PFP."""
import argparse, hashlib, json, os, re, shutil, stat, subprocess, time, sys, tempfile
from pathlib import Path
import qualify_upstream_storage_boundary as bounded
import qualify_upstream_storage_app_handles as counts
import qualify_upstream_automatic_body as held
import qualify_upstream_body_late_ack as late
import upstream_completion_ci as completion
ensure=bounded.ensure
BASE='b1dd1b659a1e410a1d66b4a77225acc1c6cf3df5'
WORKFLOW_SHA='bf7b9e4aab090f34067721fe0340d4a9e0e82963a449234534895a565e2512a2'
SELF='scripts/qualify_upstream_c1_body_restart.py'
WORKFLOW='.github/workflows/c1-body-restart.yml'
REF='refs/heads/ci/upstream-c1-body-ordering-20261019'
PRODUCT='crates/marmot-app/src/client/account_chat_sharing/automatic.rs'
PRODUCT_SHA='0fde8d14ceea74cd2dd998cd4bfd4e516d61f3704e682931fc42f2460b95d117'
OMISSION='                    self.collect_finished_automatic_publication(&mut entry);\n                    if entry.publication.as_ref().is_some_and(|publication| {\n                        publication.body_context.is_some()\n                            && publication.outcome.as_ref().is_some_and(Result::is_ok)\n                    }) && self.harvest_automatic_publication(&mut entry)?\n                    {\n                        self.finish_automatic_body_effects(&mut entry)?;\n                    }\n'
MUTANT_SHA='75a669e0c5935535ae859291cc108decb68fe077ec7d805cba1be7d19e3ef9d7'
RESTART_HELPER='crates/marmot-app/src/client/account_chat_sharing/automatic/tests/pending_restart_acceptance.rs'
COMPOSED_HELPER='crates/marmot-app/src/tests.rs'
MESSAGE='actual restarted peers must deliver genuine ordinary catalog and canonical record within the unchanged recovery deadline'
NAMES=[held.NAME,late.PREFIX+late.CASES[0],late.PREFIX+late.CASES[1],
 'native_device_linking::tests::pending_lower_request_recovers_after_higher_restarts_before_consent',
 'native_device_linking::tests::pending_restart_higher_source_delivers_catalog_and_record']
FEATURES='marmot-app/otlp-export,marmot-uniffi/otlp-export,marmot-c/otlp-export,wn-cli/otlp-export,agent-connector/otlp-export,marmot-app/product-analytics-export,marmot-uniffi/product-analytics-export,marmot-c/product-analytics-export,wn-cli/product-analytics-export,agent-connector/product-analytics-export,wn-cli/test-policy-overrides,cgka-engine/test-policy-overrides,cgka-engine/test-crash-hooks,experimental-device-sync'
EXPECTED_GRAPH={'marmot_app': ['default', 'experimental-device-sync', 'otlp-export', 'product-analytics-export', 'test-policy-overrides'], 'cgka_engine': ['default', 'experimental-device-sync', 'test-conformance-snapshot', 'test-crash-hooks', 'test-policy-overrides'], 'storage_sqlite': ['experimental-device-sync', 'storage-format-benchmarks', 'test-conformance-replay', 'test-migrated-template', 'test-support'], 'cgka_session': ['default', 'experimental-device-sync', 'test-policy-overrides'], 'marmot_account': ['experimental-device-sync'], 'transport_nostr': ['default', 'experimental-device-sync', 'test-policy-overrides', 'test-support']}
OUT=Path(os.environ.get('RUNNER_TEMP','/tmp'))/'c1-body-restart-evidence'
FIXTURE=RESTART_HELPER
GATE=OMISSION
SOURCE_PINS={'crates/marmot-app/src/client/account_chat_sharing/automatic/tests/pending_restart_acceptance.rs': 'cba8721421d2b3a679cfc3cad71b603a5fcaa17b53cf9fdd618da6ae3d557770', 'crates/marmot-app/src/native_device_linking/tests/automatic_pairing_acceptance.rs': '674912b2606b11ab735b947fdab2b8f9e28597f07f406ab8cff8b6e7c8733fe9', 'crates/marmot-app/src/tests.rs': '1c496a3a19b6078437a3d214868373a6dc69a156438f24b47fffdb652598978e', 'scripts/qualify_upstream_automatic_body.py': 'fd7d5e4d94353c37a0038e8c1b7561215c4ffa15ca7799f5d8aa36aa1e3f8c57', 'scripts/qualify_upstream_body_late_ack.py': 'a7347322e902c47c5a91b1b76f3f1069dbeda07b97af19f773d30d2c938e30e6', 'scripts/upstream_completion_ci.py': '653ee721447382753e7a69a16762b1981e70188ca029886dfa72026231550b7b', 'scripts/qualify_upstream_storage_boundary.py': 'b74d67df35d4cd612efdc3b2b42ed9380e543a821dc639b172e9be5770aa5265', 'scripts/qualify_upstream_storage_app_handles.py': 'c72879e29cb657292799bf8f9ef5c6edbf3907e662c315273041da9ca9884d2a'}
def closed_exception(error):
    name=type(error).__name__
    return name if name in {'GateFailure','ValueError','TypeError','KeyError','OSError','FileNotFoundError','RuntimeError','JSONDecodeError','OverflowError','PermissionError'} else 'OtherControllerFailure'

def digest(data):return hashlib.sha256(data).hexdigest()
def git(*args):return subprocess.check_output(['git',*args])
_OUTPUT_GIT_ROOT=None
def save(report):
    global _OUTPUT_GIT_ROOT
    if _OUTPUT_GIT_ROOT is None:_OUTPUT_GIT_ROOT=Path(git('rev-parse','--show-toplevel').decode().strip()).resolve()
    ensure(not within(OUT,_OUTPUT_GIT_ROOT),'output-must-resolve-outside-checkout')
    OUT.mkdir(mode=0o700,exist_ok=True);(OUT/'result.json').write_text(json.dumps(report,indent=2)+'\n')
def within(path,root):return path.resolve().is_relative_to(root.resolve())
def git_closure(mutant=False):
    changed=git('diff','--name-only','HEAD').decode().splitlines()
    untracked=git('ls-files','--others','--exclude-standard').splitlines()
    index_clean=subprocess.run(['git','diff','--cached','--quiet']).returncode==0
    quiet=subprocess.run(['git','diff','--quiet','HEAD']).returncode==0
    return {'tracked_HEAD_pristine':quiet,'index_pristine':index_clean,'nonignored_untracked_count':len(untracked),
        'expected_tracked_change_only':set(changed)==({PRODUCT} if mutant else set()),
        'verified':index_clean and not untracked and (set(changed)=={PRODUCT} if mutant else quiet)}

def source_matches(expected):return physical()==expected and git_closure(expected[PRODUCT][2]!=PRODUCT_SHA)['verified']

def without_fallback(report):return not report.get('fallback_source_restore_used',False) and not report.get('fallback_binary_copy_used',False)

def admitted_mutation_sequence(qualified,attempt,restore,fresh_restored):
    ensure(qualified is True,'PFP-baseline-must-qualify-before-mutation')
    try:attempt()
    finally:
        restore()
        fresh_restored()

def binary_identity(binary,parent):
    regular=binary is not None and binary.parent.resolve()==parent and binary.is_file() and not binary.is_symlink()
    return {'regular_approved_parent':bool(regular),'sha256':digest(binary.read_bytes()) if regular else None,'mode':stat.S_IMODE(binary.stat().st_mode) if regular else None}
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
        p=Path(path);ensure(within(p,Path.cwd()),'every-tracked-path-within-checkout');s=p.lstat();link=stat.S_ISLNK(s.st_mode)
        ensure(link==(mode=='120000') and (link or stat.S_ISREG(s.st_mode)),'physical-kind')
        data=os.fsencode(os.readlink(p)) if link else p.read_bytes()
        rows[path]=(mode,stat.S_IMODE(s.st_mode),digest(data))
    return rows

def source_guard(preflight=False):
    ensure(type(BASE) is str and re.fullmatch('[0-9a-f]{40}',BASE) and type(WORKFLOW_SHA) is str and re.fullmatch('[0-9a-f]{64}',WORKFLOW_SHA),'root-source-pins-required')
    ensure(Path.cwd().resolve()==Path(git('rev-parse','--show-toplevel').decode().strip()).resolve(),'physical-Git-root')
    ensure(bool(os.environ.get('RUNNER_TEMP')) and Path(os.environ['RUNNER_TEMP']).is_dir() and not within(OUT,Path.cwd()),'outside-hosted-output')
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
    baseline=layout(BASE);current=layout('HEAD')
    ensure(SELF not in baseline and WORKFLOW not in baseline and set(current)==set(baseline)|{SELF,WORKFLOW},'only-two-owned-metadata')
    ensure(subprocess.run(['git','diff','--quiet','HEAD']).returncode==0,'HEAD-pristine')
    for path,(mode,oid) in current.items():
        p=Path(path);ensure(within(p,Path.cwd()),'every-tracked-path-within-checkout');s=p.lstat();link=stat.S_ISLNK(s.st_mode);expected=baseline.get(path,('100644',None))
        ensure(mode==expected[0] and link==(mode=='120000') and (link or stat.S_ISREG(s.st_mode))
            and (link or bool(s.st_mode&0o111)==(mode=='100755')),'whole-source-modes')
        data=os.fsencode(os.readlink(p)) if link else p.read_bytes()
        actual=hashlib.sha1(b'blob '+str(len(data)).encode()+b'\0'+data).hexdigest()
        ensure(actual==oid and (expected[1] is None or actual==expected[1]),'whole-BASE-and-HEAD-content')
    ensure(digest(Path(WORKFLOW).read_bytes())==WORKFLOW_SHA,'exact-owned-workflow')
    for path,sha in SOURCE_PINS.items():ensure(digest(Path(path).read_bytes())==sha,'exact-current-fixtures-and-pure-helper-blobs')
    product=Path(PRODUCT).read_bytes()
    ensure(digest(product)==PRODUCT_SHA and product.count(OMISSION.encode())==1 and digest(product.replace(OMISSION.encode(),b'',1))==MUTANT_SHA,'exact-eight-line-positive-receipt-omission-witness')
    ensure(git_closure()['verified'],'tracked-index-untracked-admission-closure')
    return {'head':head,'baseline':BASE,'whole_source_modes_verified':True,'Rust_exceptions':[], 'old_guards_or_main_called':False,'old_module_globals_mutated':False,'historical_runtime_reused':False,'metadata_HEAD_difference':[SELF,WORKFLOW],'original_30s_functional_oracles_unchanged':True}
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

def compile_app(report,cohort,tracked,save_report):
    features=['otlp-export','product-analytics-export','test-policy-overrides','experimental-device-sync']
    command=['cargo','test','--locked','--workspace','--no-run','--message-format=json']
    if features:command+=['--features',FEATURES]
    report['compilation']={'command':command,'compile_attempted':True,'exit_code':None,'compiler_error_count':None,
        'build_finished_success':None,'malformed_JSON_lines':None,'selected_test_artifact_count':None,
        'watchdog_triggered':False,'output_limit_triggered':False,'runtime_bodies':0};save_report()
    started=time.monotonic()
    try:code,raw,seconds=bounded.capture(command,3600,limit=8*1024*1024)
    except bounded.GateFailure as error:
        report['compilation'].update(seconds=time.monotonic()-started,controller_failure_type=closed_exception(error),
            watchdog_triggered=str(error)=='bounded-command-timeout',output_limit_triggered=str(error)=='bounded-command-output-limit')
        save_report();raise
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
    report['compilation']={'command':command,'compile_attempted':True,'watchdog_triggered':False,'output_limit_triggered':False,'runtime_bodies':0,'exit_code':code,'seconds':seconds,'compiler_error_count':len(errors) if finished else None,'build_finished_success':complete,'malformed_JSON_lines':malformed,'compiler_codes':codes[:32],
        'compiler_sites':sites[:32],'closed_diagnostics_truncated':len(codes)>32 or len(sites)>32,'selected_test_artifact_count':len(selected),'features_requested':features};save_report()
    ensure(type(code) is int and code==0 and complete and not errors and len(selected)==1,'one-successful-App-lib-compilation')
    artifact=selected[0];observed=artifact.get('features')
    ensure(type(observed) is list and all(type(v) is str for v in observed) and len(observed)==len(set(observed)) and set(observed)==set(features)|{'default'} and artifact.get('fresh') is False,'actual-App-unit-feature-cohort')
    binary=Path(artifact['executable']);ensure(binary.is_file() and not binary.is_symlink() and re.fullmatch(r'marmot_app-[0-9a-f]{16}',binary.name) and binary.resolve().is_relative_to(Path(os.environ.get('CARGO_TARGET_DIR','target')).resolve()),'regular-App-test-binary')
    report['compiled_features']={'observed_own_unit_features':sorted(observed),'actual_test_profile':True,'fresh_App_artifact_required':True,'observed_App_artifact_fresh':artifact.get('fresh'),'all_Cargo_artifact_feature_manifest_sha256':digest(json.dumps(sorted([{'package':v['package_id'],'target':v['target']['name'],'kind':v['target']['kind'],'features':sorted(v['features']),'profile':v['profile']} for v in artifacts],key=lambda v:json.dumps(v,sort_keys=True)),sort_keys=True).encode()),'all_emitted_compiler_artifact_feature_cohort_recorded':True,'all_dependencies_freshly_built_claimed':False};save_report()
    graph=completion.feature_metadata(binary)
    report['dependency_fingerprints']=graph;save_report()
    ensure(graph.get('verified') is True and {k:sorted(v['features']) for k,v in graph.get('nodes',{}).items()}=={k:sorted(v) for k,v in EXPECTED_GRAPH.items()},'actual-exact-reviewed-six-node-feature-graph')
    return binary

def aggregate(cases,expected_count):
    result={'actual_case_rows':len(cases),'expected_case_rows':expected_count,'unknown_count_cases':sum(any(type(row.get('basic_counts',{}).get(k)) is not int for k in ['passed','failed','ignored','executed_nonignored']) for row in cases),'nonqualifying_count_shape_cases':sum(row.get('basic_counts',{}).get('actual_counts_complete') is not True for row in cases),'missing_case_rows':max(0,expected_count-len(cases))}
    for key in ['passed','failed','ignored','executed_nonignored']:
        values=[row.get('basic_counts',{}).get(key) for row in cases]
        known=[v for v in values if type(v) is int and v>=0]
        result['actual_'+key]=sum(values) if len(cases)==expected_count and len(known)==len(values) else None
        result['known_partial_'+key]=sum(known) if known else None
    return result


COUNT_KEYS=['passed','failed','ignored','executed_nonignored','exit_code','compiler_error_count','panic_count','actual_counts_complete','passed_gate','watchdog_triggered','output_limit_triggered']
def closed_counts(row):
    return {key:row[key] for key in COUNT_KEYS if key in row and (row[key] is None or type(row[key]) in (bool,int,float))}
def execute_case(root,row,binary,before,mode,parent,expected_inputs,name,expected):
    row.update(name=name,expected=expected,runtime_attempted=False,actual_executed_nonignored=0,expected_outcome_verified=False)
    save(root)
    for ignored in [False,True]:
        code,text,_=bounded.capture([str(binary),'--exact',name]+(['--ignored'] if ignored else [])+['--list','--format','terse'],60,limit=1024*1024)
        item=counts.parse_inventory(text,name,ignored);row.setdefault('inventory',{})['ignored' if ignored else 'normal']=item;save(root)
        ensure(code==0 and item['passed'],'one-normal-zero-ignored-exact-case')
    ensure(source_matches(expected_inputs) and binary.parent.resolve()==parent and binary.is_file() and not binary.is_symlink() and digest(binary.read_bytes())==before and stat.S_IMODE(binary.stat().st_mode)==mode,'prebody-source-binary-mode')
    row.update(runtime_attempted=True,actual_executed_nonignored=None);save(root)
    try:code,raw,seconds=bounded.capture([str(binary),'--exact',name,'--nocapture','--test-threads=1'],300,limit=8*1024*1024)
    except bounded.GateFailure as error:
        row['watchdog_triggered']=str(error)=='bounded-command-timeout';row['output_limit_triggered']=str(error)=='bounded-command-output-limit';save(root);raise
    row.update(body_exit_code=code,body_seconds=seconds,source_after_body_pristine=source_matches(expected_inputs),
        binary_after_sha256=digest(binary.read_bytes()) if binary.parent.resolve()==parent and binary.is_file() and not binary.is_symlink() else None,
        binary_after_mode=stat.S_IMODE(binary.stat().st_mode) if binary.parent.resolve()==parent and binary.is_file() and not binary.is_symlink() else None);save(root)
    basic=counts.parse_body(raw,code,name);row['basic_counts']=closed_counts(basic)
    for dest,key in [('actual_passed','passed'),('actual_failed','failed'),('actual_ignored','ignored'),('actual_executed_nonignored','executed_nonignored')]:row[dest]=basic.get(key)
    row['actual_test_passed']=basic.get('passed_gate') is True;save(root)
    ensure(row['source_after_body_pristine'] and row['binary_after_sha256']==before and row['binary_after_mode']==mode,'postbody-source-binary-mode')
    if name in NAMES[3:]:
        try:row['restart_ledgers']=restart_ledgers(raw)
        except Exception as error:row['restart_ledgers']={'schema_known':False,'closed_parser_failure_type':closed_exception(error)}
        save(root)
    row['outcome']=verdict(raw,code,basic,name,expected)
    row['expected_outcome_verified']=row['outcome']['expected_outcome_verified'] and (name not in NAMES[3:] or row['restart_ledgers'].get('schema_known') is True);save(root)

def phase(root,label,cohort,expected_inputs,specs,different_from=None):
    row={'cases':[],'phase_passed':False,'expected_case_count':len(specs)};root.setdefault('phases',{})[label]=row;save(root)
    ensure(source_matches(expected_inputs),'phase-before-compile-pristine')
    row['free_bytes_before_compile']=shutil.disk_usage('.').free
    row['capacity_reserve_satisfied']=row['free_bytes_before_compile']>=8*1024**3
    if not row['capacity_reserve_satisfied']:row['compile_admission_failure']='insufficient_disk_reserve'
    save(root);ensure(row['capacity_reserve_satisfied'],'phase-disk-reserve-before-build')
    row['fresh_App_source_mtimes']=[]
    for refresh in [Path(PRODUCT),Path(FIXTURE)]:
        ensure(refresh.is_file() and not refresh.is_symlink(),'fresh-compile-source-kind')
        approved_parent(refresh,Path.cwd().resolve()/refresh.parent)
        old=refresh.stat().st_mtime_ns;stamp=max(time.time_ns(),old+2_000_000_000);os.utime(refresh,ns=(stamp,stamp))
        after=refresh.stat().st_mtime_ns
        row['fresh_App_source_mtimes'].append({'path':str(refresh),'before_ns':old,'requested_ns':stamp,'actual_after_ns':after});save(root)
        ensure(after>old,'actual-source-mtime-advanced')
    row['fresh_App_method']='mtime-only-reviewed-product-and-fixture';save(root)
    binary=compile_app(row,cohort,set(expected_inputs),lambda:save(root))
    parent=binary.parent.resolve();before=digest(binary.read_bytes());mode=stat.S_IMODE(binary.stat().st_mode);row['binary_before']={'sha256':before,'mode':mode};save(root)
    ensure(source_matches(expected_inputs),'phase-after-compile-pristine')
    if different_from is not None:ensure(before!=different_from,'mutant-binary-must-differ-before-runtime')
    for name,expected in specs:
        case={};row['cases'].append(case);save(root)
        try:execute_case(root,case,binary,before,mode,parent,expected_inputs,name,expected)
        except Exception as error:case['controller_failure_type']=closed_exception(error);save(root)
    row.update(aggregate(row['cases'],len(specs)))
    row['source_after_phase_pristine']=source_matches(expected_inputs)
    row['binary_after_phase_pristine']=binary.parent.resolve()==parent and binary.is_file() and not binary.is_symlink() and digest(binary.read_bytes())==before and stat.S_IMODE(binary.stat().st_mode)==mode
    row['phase_passed']=row['source_after_phase_pristine'] and row['binary_after_phase_pristine'] and len(row['cases'])==len(specs) and all(case.get('expected_outcome_verified') is True for case in row['cases'])
    save(root);return binary,before,mode,parent

def omitted_gate(data,gate,wanted):
    ensure(type(gate) is str and gate and data.count(gate.encode())==1,'unique-only-waiting-return-block')
    result=data.replace(gate.encode(),b'',1)
    ensure(digest(result)==wanted,'full-omission-product-hash')
    return result

def approved_parent(path,parent):
    ensure(isinstance(parent,Path),'approved-original-parent-required')
    ensure(path.parent.resolve()==parent and path.parent.is_dir(),'owned-parent-resolution-unchanged')

def write_fresh(path,data,mode,parent):
    approved_parent(path,parent)
    ensure(not path.is_symlink(),'owned-write-refuses-leaf-symlink')
    previous=path.stat().st_mtime_ns if path.exists() else 0
    path.write_bytes(data);path.chmod(mode)
    timestamp=max(time.time_ns(),previous+2_000_000_000);os.utime(path,ns=(timestamp,timestamp))

def restore_owned(path,data,mode,parent):
    approved_parent(path,parent)
    if path.is_symlink():path.unlink()
    ensure(not path.exists() or path.is_file(),'owned-restore-file-kind')
    write_fresh(path,data,mode,parent)

def runtime(report,cohort,expected):
    frozen=physical();product=Path(PRODUCT);original=product.read_bytes();product_mode=stat.S_IMODE(product.stat().st_mode)
    product_parent=Path.cwd().resolve()/product.parent
    approved_parent(product,product_parent);ensure(within(product,Path.cwd()),'owned-product-in-checkout')
    baseline_binary=None;baseline_bytes=None;baseline_mode=None;baseline_hash=None;baseline_parent=None;mutation_attempted=False
    report.update(runtime_attempted=False,mutation_attempted=False,component_PFP_verified=False,fallback_source_restore_used=False,fallback_binary_copy_used=False)
    try:
        free=shutil.disk_usage('.').free;report['free_bytes']=free;save(report);ensure(free>=8*1024**3,'remote-disk-reserve')
        specs=[(name,'green') for name in NAMES]
        baseline_binary,baseline_hash,baseline_mode,baseline_parent=phase(report,'baseline',cohort,frozen,specs)
        ensure(baseline_binary.parent.resolve()==baseline_parent and baseline_binary.is_file() and not baseline_binary.is_symlink()
            and digest(baseline_binary.read_bytes())==baseline_hash and stat.S_IMODE(baseline_binary.stat().st_mode)==baseline_mode,'baseline-backup-only-admitted-regular-binary')
        baseline_bytes=baseline_binary.read_bytes();report['runtime_attempted']=any(row.get('runtime_attempted') for row in report['phases']['baseline']['cases'])
        if expected=='green':
            report['expected_outcome_verified']=report['phases']['baseline']['phase_passed'];save(report)
            ensure(report['expected_outcome_verified'],'required-baseline-outcome-not-established');return
        # Admission is before mutation/finally: an unqualified baseline is not retried as restoration.
        if report['phases']['baseline']['phase_passed'] is not True:
            report['skipped_mutant_and_restored_reason']='baseline_unqualified_no_mutation_attempted';save(report)
            raise ValueError('PFP-baseline-must-qualify-before-mutation')
        ensure(digest(original)==PRODUCT_SHA and type(GATE) is str and original.count(GATE.encode())==1,'exact-fixed-product-before-mutation')
        mutant=omitted_gate(original,GATE,MUTANT_SHA)
        ensure(digest(mutant)==MUTANT_SHA,'exact-reviewed-positive-receipt-only-mutant')
        expected_mutant=dict(frozen);expected_mutant[PRODUCT]=(frozen[PRODUCT][0],product_mode,digest(mutant))
        def attempt():
            nonlocal mutation_attempted
            try:
                mutation_attempted=True;report['mutation_attempted']=True;save(report)
                write_fresh(product,mutant,product_mode,product_parent)
                ensure(source_matches(expected_mutant),'only-owned-positive-receipt-source-and-mode')
                phase(report,'mutant',cohort,expected_mutant,[(NAMES[4],'red')],different_from=baseline_hash)
            except Exception as error:report['mutant_controller_failure_type']=closed_exception(error);save(report)
        def restore():
            restore_owned(product,original,product_mode,product_parent)
            report['source_restored_before_fresh_compile']=source_matches(frozen);save(report)
            ensure(report['source_restored_before_fresh_compile'],'exact-source-restore-before-compile')
        def fresh_restored():
            try:phase(report,'restored',cohort,frozen,[(name,'green') for name in NAMES])
            except Exception as error:report['restored_controller_failure_type']=closed_exception(error);save(report)
        admitted_mutation_sequence(report['phases']['baseline']['phase_passed'],attempt,restore,fresh_restored)
        rows=[case for label in ['baseline','mutant','restored'] for case in report.get('phases',{}).get(label,{}).get('cases',[])]
        report['aggregate']=aggregate(rows,11)
        restored=report.get('phases',{}).get('restored',{});mutant_row=report.get('phases',{}).get('mutant',{})
        report['baseline_restored_binary_equal']=restored.get('binary_before')==report['phases']['baseline']['binary_before']
        signatures=[{name:node['features'] for name,node in report['phases'].get(label,{}).get('dependency_fingerprints',{}).get('nodes',{}).items()} for label in ['baseline','mutant','restored']]
        report['same_observed_dependency_feature_cohort']=bool(signatures[0] and signatures[0]==signatures[1]==signatures[2])
        allfeatures=[report['phases'].get(label,{}).get('compiled_features',{}).get('all_Cargo_artifact_feature_manifest_sha256') for label in ['baseline','mutant','restored']]
        report['same_all_emitted_compiler_artifact_features']=bool(allfeatures[0] and allfeatures[0]==allfeatures[1]==allfeatures[2])
        report['git_closure_before_PFP']=git_closure();save(report)
        report['component_PFP_verified']=(report['git_closure_before_PFP']['verified'] and without_fallback(report) and all(report.get('phases',{}).get(label,{}).get('phase_passed') is True for label in ['baseline','mutant','restored'])
            and report['aggregate'].get('actual_passed')==10 and report['aggregate'].get('actual_failed')==1 and report['aggregate'].get('actual_ignored')==0
            and report['aggregate'].get('actual_executed_nonignored')==11 and report['baseline_restored_binary_equal'] and report['same_observed_dependency_feature_cohort'] and report['same_all_emitted_compiler_artifact_features']
            and mutant_row.get('binary_before',{}).get('sha256')!=baseline_hash)
        report['expected_outcome_verified']=report['component_PFP_verified'];save(report);ensure(report['component_PFP_verified'],'fresh-eleven-body-ordering-PFP-required')
    finally:
        if product.is_symlink() or not product.is_file() or product.read_bytes()!=original or stat.S_IMODE(product.stat().st_mode)!=product_mode:
            report['fallback_source_restore_used']=True;report['component_PFP_verified']=False;report['expected_outcome_verified']=False
            restore_owned(product,original,product_mode,product_parent)
        report['final_git_closure']=git_closure()
        report['final_HEAD_git_pristine']=report['final_git_closure']['tracked_HEAD_pristine']
        report['source_final_pristine']=physical()==frozen and report['final_git_closure']['verified']
        if baseline_binary is not None and baseline_bytes is not None:
            good=baseline_binary.parent.resolve()==baseline_parent and baseline_binary.is_file() and not baseline_binary.is_symlink() and digest(baseline_binary.read_bytes())==baseline_hash and stat.S_IMODE(baseline_binary.stat().st_mode)==baseline_mode
            if not good:
                report['fallback_binary_copy_used']=True;report['component_PFP_verified']=False;report['expected_outcome_verified']=False
                restore_owned(baseline_binary,baseline_bytes,baseline_mode,baseline_parent)
            report['baseline_binary_final_pristine']=baseline_binary.parent.resolve()==baseline_parent and baseline_binary.is_file() and not baseline_binary.is_symlink() and digest(baseline_binary.read_bytes())==baseline_hash and stat.S_IMODE(baseline_binary.stat().st_mode)==baseline_mode
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
            ensure(report.get('expected_outcome_verified') is True and without_fallback(report),'final-outcome-without-fallback-required')
            if expected=='pfp':ensure(report['component_PFP_verified'],'final-PFP-must-remain-qualified')

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

def filesystem_and_sequence_controls():
    # Remote synthetic fixtures only: no Cargo, binary, SDK or protocol process.
    events=[]
    def attempt():events.append('mutant')
    def restore():events.append('restore-exact-source')
    def fresh():events.append('fresh-compile-and-restored-body')
    try:admitted_mutation_sequence(False,attempt,restore,fresh)
    except ValueError:pass
    ensure(events==[],'unqualified-baseline-starts-neither-mutation-nor-restoration')
    def failed():events.append('mutant');raise ValueError('synthetic')
    try:admitted_mutation_sequence(True,failed,restore,fresh)
    except ValueError:pass
    ensure(events==['mutant','restore-exact-source','fresh-compile-and-restored-body'],'mutant-failure-still-fresh-restored-sequence')
    with tempfile.TemporaryDirectory(prefix='predecessor-controls-',dir=os.environ['RUNNER_TEMP']) as directory:
        root=Path(directory)/'checkout';outside=Path(directory)/'outside';root.mkdir();outside.mkdir()
        target=outside/'file';target.write_bytes(b'outside-unchanged')
        (root/'parent').symlink_to(outside,target_is_directory=True)
        ensure(not within(root/'parent'/'file',root),'regular-leaf-through-parent-symlink-escape-rejected')
        ensure(not within(outside,root) and within(root/'ordinary',root),'output-outside-and-contained-path-control')
        owned=root/'owned';data=b'exact-original';mode=0o640
        for condition in ['missing','symlink','wrong-mode']:
            if owned.is_symlink() or owned.exists():owned.unlink()
            if condition=='symlink':owned.symlink_to(target)
            if condition=='wrong-mode':owned.write_bytes(b'mutant');owned.chmod(0o755)
            restore_owned(owned,data,mode,root.resolve())
            ensure(owned.is_file() and not owned.is_symlink() and owned.read_bytes()==data and stat.S_IMODE(owned.stat().st_mode)==mode,'synthetic-owned-source-exact-restoration')
        ensure(target.read_bytes()==b'outside-unchanged','symlink-restore-never-writes-outside-target')
        original_parent=root/'replaced-parent';original_parent.mkdir();approved=original_parent.resolve();original_parent.rmdir()
        outside_owned=outside/'owned';outside_owned.write_bytes(b'outside-owned-unchanged');original_parent.symlink_to(outside,target_is_directory=True)
        for operation in [write_fresh,restore_owned]:
            try:operation(original_parent/'owned',data,mode,approved);accepted=True
            except ValueError:accepted=False
            ensure(not accepted and outside_owned.read_bytes()==b'outside-owned-unchanged','actual-owned-write-and-restore-reject-parent-escape-before-writing')
    for flag in ['fallback_source_restore_used','fallback_binary_copy_used']:
        ensure(not without_fallback({flag:True}),'any-fallback-disqualifies')
    ensure(without_fallback({}),'no-fallback-positive')
    return {'baseline_failure_no_mutation_or_restore':True,'mutant_failure_fresh_restore_required':True,'parent_symlink_escape_rejected':True,'actual_write_and_restore_parent_escape_rejected':True,
        'restore_conditions':['missing','symlink','wrong-mode'],'fallback_disqualifies':True,'actual_target_processes':0}

def main():
    os.umask(0o077)
    p=argparse.ArgumentParser();p.add_argument('--preflight',action='store_true');p.add_argument('--expected',choices=['green','pfp'],default='pfp');args=p.parse_args()
    report={'scope':'five original C1 controls and authenticated positive-receipt ordering omission','preflight':args.preflight,'expected':args.expected,
        'runtime_attempted':False,'actual_executed_nonignored':0,'component_PFP_verified':False,'qualification_passed':False,'native_global_qualification':False,
        'automatic_retries':0,'environment_RUST_MIN_STACK':4194304,'restart_composed_driver_and_worker_stack_bytes':8388608,'Tokio_workers':2,
        'original_recovery_deadline_seconds':30,'outer_body_watchdog_seconds':300,'raw_output_retained':False,'requested_features':FEATURES}
    try:
        report['controller_stage']='source_guard';report['source_guard']=source_guard(args.preflight);save(report)
        report['controller_stage']='parser_controls';save(report)
        report['parser_controls']=controls();report['prefix_and_restart_ledger_controls']=prefix_and_ledger_controls()
        report['filesystem_and_orchestration_controls']=filesystem_and_sequence_controls();save(report)
        if not args.preflight:
            report['controller_stage']='C1_runtime_PFP';save(report);runtime(report,'experimental',args.expected)
        report['controller_completed']=True;save(report)
    except Exception as error:
        report['controller_failure_type']=closed_exception(error);save(report);raise
    finally:
        report['final_git_closure']=git_closure();report['final_HEAD_git_pristine']=report['final_git_closure']['tracked_HEAD_pristine']
        if not report['final_git_closure']['verified']:report['component_PFP_verified']=False;report['expected_outcome_verified']=False
        save(report);ensure(report['final_git_closure']['verified'],'final-tracked-index-untracked-Git-closure')
if __name__=='__main__':main()
