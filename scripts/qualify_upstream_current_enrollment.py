#!/usr/bin/env python3
"""Current original strict five or original sixteen enrollment cases; no mutation."""
import argparse, hashlib, json, os, re, shutil, stat, subprocess, time, sys
from pathlib import Path
import qualify_upstream_storage_boundary as bounded
import qualify_upstream_storage_app_handles as counts
import upstream_completion_ci as completion
import qualify_upstream_pure_native5 as native
import qualify_upstream_request_retry_ack as ack
ensure=bounded.ensure
BASE='ff9d0aad36daebb37d74f33c189566e39e1bcbf7'
SOURCE_PARENT='2565b3e5e8860678e1f4c8dce33119c1a4599c2b'
RAW_SOURCE='4d48ddd9648535e906029884695f07d9abf4f366'
RESULT_SOURCE_PATHS={'crates/marmot-app/src/client/device_linking/native_enrollment.rs': {'before': 'af418979f8ab87c002890b5426600cd20cfff9028bb452548ec60f22820d5387', 'raw': 'bd99b26a259f65a7f4bda44cf814034e2d5c446f2f433ca7634ac28d45771919', 'canonical': 'bd99b26a259f65a7f4bda44cf814034e2d5c446f2f433ca7634ac28d45771919', 'mode': '100644'}, 'crates/marmot-app/src/client/device_linking/sibling_sharing.rs': {'before': 'a0d487a6a653a61de16d3fa44eec9f787a5181658011fb75c6c09e157905c215', 'raw': 'cd54cc5d1b81e350e3789f77cef2258a3ffcd9b818a8dc261144ad3a859e51d5', 'canonical': '54ae78e686702be2783fc040d58e453078566c333b51bfdd82fc4b01d47b7da6', 'mode': '100644'}}
FAILURE_LABELS=('original_2','stress_0','stress_1','stress_2')
HANDOFF_LABELS=('original_2','stress_1')
WORKFLOW_SHA='4bafb5969d33c4fa6bab98f721ac6f0e65af06eb2b3aea56af6bc0b69c4e2bb9'
SELF='scripts/qualify_upstream_current_enrollment.py'
WORKFLOW='.github/workflows/current-enrollment.yml'
REF='refs/heads/ci/upstream-current-enrollment-20261018'
FEATURES='marmot-app/otlp-export,marmot-app/product-analytics-export,marmot-app/test-policy-overrides,marmot-app/experimental-device-sync,cgka-engine/test-policy-overrides,cgka-engine/test-crash-hooks'
OUT=Path('current-enrollment-evidence')
FIXTURE='crates/marmot-app/src/native_device_linking/tests/sequential_installations_acceptance.rs'
PARENT='crates/marmot-app/src/native_device_linking/tests/automatic_pairing_acceptance.rs'
FIXTURE_SHA='a81cc692c9864d9cdf2ff7fe8d533d3115c7eb7958fa7a22df783850fea520ca'
PARENT_SHA='bd3d6fc39f5578d3f1eeec05dc6238e30bb74217f7cfd8e9ee840577599669ad'
STRICT_HELPER_SHA='aca824bd363e1e5de3da7536aaf20df89b70b3dc5fffd8ab6f40580a06aa2a9e'
ORACLE_SHA='88417f89d6d6b3b9a8037d408be60c54d8b86451085cff9d254cb6cc74537e72'
NATIVE_HELPER='scripts/qualify_upstream_pure_native5.py'
ACK_HELPER='scripts/qualify_upstream_request_retry_ack.py'
HELPER_PINS={'scripts/qualify_upstream_pure_native5.py': 'e850003b806b321444ec53bac9e3a5b8d1d22e5e0661b09a0f7456f1c985aa2b', 'scripts/qualify_upstream_request_retry_ack.py': 'd413d577d2a6097b94870a9fb662f4ab3dd047ef8cc218861cba51dc0cbd8008'}
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
        and os.environ.get('UPSTREAM_CURRENT_ENROLLMENT_BASELINE')==BASE,'exact-hosted-ref-source')
    ensure(os.environ.get('CARGO_INCREMENTAL')=='1' and os.environ.get('CARGO_BUILD_JOBS')=='2' and os.environ.get('RUST_MIN_STACK')=='4194304'
        and all(os.environ.get(k)=='0' for k in ['CARGO_PROFILE_DEV_DEBUG','CARGO_PROFILE_TEST_DEBUG'])
        and all(not os.environ.get(k) for k in ['RUSTFLAGS','CARGO_ENCODED_RUSTFLAGS','RUSTC_BOOTSTRAP','CARGO_PROFILE_DEV_OPT_LEVEL','CARGO_PROFILE_TEST_OPT_LEVEL']),'exact-build-cohort')
    ensure(subprocess.run(['git','merge-base','--is-ancestor',BASE,head]).returncode==0,'BASE-ancestor')
    ensure(type(RAW_SOURCE)is str and re.fullmatch('[0-9a-f]{40}',RAW_SOURCE),'root-reviewed-raw-result-source-required')
    ensure(all(subprocess.run(['git','merge-base','--is-ancestor',a,b]).returncode==0 for a,b in [(SOURCE_PARENT,RAW_SOURCE),(RAW_SOURCE,BASE)]),'latest-owner-then-result-source-ancestry')
    ensure(set(git('diff','--name-only',SOURCE_PARENT,RAW_SOURCE).decode().splitlines())==set(RESULT_SOURCE_PATHS)
        and set(git('diff','--name-only',RAW_SOURCE,BASE).decode().splitlines())<=set(RESULT_SOURCE_PATHS),'exact-two-classifier-paths-then-format-only')
    for path,pins in RESULT_SOURCE_PATHS.items():
        for ref,key in [(SOURCE_PARENT,'before'),(RAW_SOURCE,'raw'),(BASE,'canonical')]:
            ensure(layout(ref)[path][0]==pins['mode'] and digest(git('show',ref+':'+path))==pins[key],'reviewed-result-path-full-source-and-mode')
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
    ensure(digest(Path(WORKFLOW).read_bytes())==WORKFLOW_SHA,'exact-owned-workflow')
    ensure(digest(Path(FIXTURE).read_bytes())==FIXTURE_SHA and digest(Path(PARENT).read_bytes())==PARENT_SHA,'immutable-original-five-fixture-parent')
    parent=Path(PARENT).read_text();start=parent.index('async fn wait_for_automatic_phase_with_approvals(');end=parent.index('\n}\n',start)+3
    ensure(digest(parent[start:end].encode())==STRICT_HELPER_SHA,'original-strict15-helper')
    for path,sha in HELPER_PINS.items():ensure(digest(Path(path).read_bytes())==sha,'immutable-oracle-helper-blob')
    text=Path(NATIVE_HELPER).read_text();begin='# NATIVE5_IMMUTABLE_ORACLE_BEGIN\n';endmark='# NATIVE5_IMMUTABLE_ORACLE_END\n'
    ensure(text.count(begin)==text.count(endmark)==1 and digest(text.split(begin,1)[1].split(endmark,1)[0].encode())==ORACLE_SHA,'immutable-five-oracle-region')
    ensure(set(git('ls-files','--others','--exclude-standard').decode().splitlines())<={str(OUT/'result.json')},'untracked-closure')
    return {'head':head,'baseline':BASE,'whole_source_modes_verified':True,'Rust_exceptions':[],
        'old_guards_or_main_called':False,'old_module_globals_mutated':False,'historical_runtime_reused':False}

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

def aggregate(cases,expected_count):
    result={'actual_case_rows':len(cases),'expected_case_rows':expected_count,'unknown_count_cases':sum(any(type(row.get('basic_counts',{}).get(k)) is not int for k in ['passed','failed','ignored','executed_nonignored']) for row in cases),'nonqualifying_count_shape_cases':sum(row.get('basic_counts',{}).get('actual_counts_complete') is not True for row in cases),'missing_case_rows':max(0,expected_count-len(cases))}
    for key in ['passed','failed','ignored','executed_nonignored']:
        values=[row.get('basic_counts',{}).get(key) for row in cases]
        known=[v for v in values if type(v) is int and v>=0]
        result['actual_'+key]=sum(values) if len(cases)==expected_count and len(known)==len(values) else None
        result['known_partial_'+key]=sum(known) if known else None
    return result


def selected_cases(mode):
    if mode=='five':return [('five',native.SUFFIX,native.NAME,None)]
    rows=list(ack.CASES)
    ensure(len(rows)==16 and all(type(row) in (list,tuple) and len(row)==4 for row in rows)
        and all(len({row[i] for row in rows})==16 for i in [0,1,2])
        and {'policy','stress_0','stress_1','stress_2','paused_clock'}<={row[0] for row in rows},'original-exact-sixteen-inventory')
    ensure(all(type(label) is str and type(suffix) is str and type(name) is str and name.endswith(suffix) for label,suffix,name,_ in rows),'exact-source-case-names')
    if mode in ('failures','handoff-diagnostic'):
        labels=HANDOFF_LABELS if mode=='handoff-diagnostic' else FAILURE_LABELS
        selected=[next(row for row in rows if row[0]==label) for label in labels]
        ensure(tuple(row[0] for row in selected)==labels,'exact-original-diagnostic-labels')
        return selected
    return rows

# Only fixed-field numeric/boolean projections leave memory. Strict original oracles
# still consume the complete ephemeral parser result; no raw compiler/panic text exports.
COUNT_KEYS=['passed','failed','ignored','executed_nonignored','exit_code','compiler_error_count','panic_count','actual_counts_complete','passed_gate','watchdog_triggered','output_limit_triggered']
SCALAR_KEYS=COUNT_KEYS+['body_exit_code','all_panic_header_count','samples','window_elapsed_us','runtime_closes','planes_shutdown','relay_closed','attempt_completed','marker_count','actual_count_unknown']
def closed_counts(row):
    return {key:row[key] for key in COUNT_KEYS if key in row and (row[key] is None or type(row[key]) in (bool,int,float))}
def closed_oracle(row):
    result={key:row[key] for key in SCALAR_KEYS if key in row and (row[key] is None or type(row[key]) in (bool,int,float))}
    for key in ['facts','observations']:
        value=row.get(key)
        if value is None:result[key]=None
        elif type(value) is dict:
            result[key]={field:item for field,item in value.items() if type(field) is str and re.fullmatch('[A-Za-z_][A-Za-z0-9_]{0,79}',field) and (item is None or type(item) in (bool,int))}
    return result

def closed_panic_sites(raw,name,tracked,read_bytes=None):
    # Only immutable tracked Rust paths and source-valid byte coordinates leave
    # memory. A foreign thread name or the panic payload is never exported.
    read_bytes=read_bytes or (lambda path:Path(path).read_bytes())
    raw=re.sub(r'\x1b\[[0-?]*[ -/]*[@-~]','',raw)
    found=[]
    for match in re.finditer(r"(?m)^thread '([^'\n]{0,512})'(?: \([0-9]{1,10}\))? panicked at ([^:\n]{1,512}):([0-9]{1,10}):([0-9]{1,10}):$",raw):
        thread,path,line,column=match.groups();line=int(line);column=int(column)
        if path not in tracked or not path.endswith('.rs') or not (line>0 and column>0):continue
        source=read_bytes(path).splitlines()
        if line>len(source) or column>len(source[line-1])+1:continue
        found.append({'file':path,'line':line,'column':column,'thread_fullname':name if thread==name else None})
    return {'sites':found[:32],'truncated':len(found)>32,'source_valid_location_count':len(found),
        'other_panic_headers_unknown':max(0,raw.count('panicked at ')-len(found)),'panic_payloads_exported':False}

# DeviceLinkingPhase is a source-frozen payload-free unit enum. No Debug
# snapshot, decimals, revision, packet or arbitrary panic message is exported.
PHASES=('AwaitingSetup','AwaitingPeer','ComparisonAvailable','AwaitingPeerVerification','VerificationCompleteEnrollmentPending','Cancelled','Expired','Failed','EnrollmentComplete')
def phase_timeout_site():
    lines=Path(PARENT).read_text().splitlines()
    literal='panic!("automatic pairing did not reach required phase: expected={phase:?} observed={observed:?}")'
    hits=[i for i,line in enumerate(lines) if literal in line]
    ensure(len(hits)==1,'unique-original-phase-timeout-site')
    index=hits[0];return index+1,lines[index].index('panic!')+1

def closed_phase_timeout(raw,name):
    text=re.sub(r'\x1b\[[0-?]*[ -/]*[@-~]','',raw)
    line,column=phase_timeout_site();phase='(?:'+'|'.join(PHASES)+')'
    header=r"(?m)^thread '([^'\n]{0,512})'(?: \([0-9]{1,10}\))? panicked at "+re.escape(PARENT)+':'+str(line)+':'+str(column)+':$'
    payload=r'automatic pairing did not reach required phase: expected=('+phase+r') observed=(None|Some\(\(('+phase+'), ('+phase+r')\)\))'
    headers=list(re.finditer(header,text));matches=list(re.finditer(header+r'\n'+payload+r'$',text))
    result={'source_site_header_count':len(headers),'closed_payload_count':len(matches),'closed_phase_record_available':False,
        'expected_phase':None,'last_completed_serial_pair':None,'observed_pair_available':None,'thread_matches_selected':None,
        'source_site':{'file':PARENT,'line':line,'column':column},'last_sample_timestamp_unknown':True,
        'fresh_deadline_snapshot':False,'blocking_side_identified':False,'raw_message_or_thread_ID_exported':False}
    if len(headers)==len(matches)==1:
        match=matches[0];result.update(closed_phase_record_available=True,thread_matches_selected=match[1]==name,
            expected_phase=match[2],observed_pair_available=match[3]!='None',last_completed_serial_pair=None if match[3]=='None' else [match[4],match[5]])
    return result

# These existing timeout records are post-wait, independently sampled and
# cumulative per sharing choice. Background refresh shares the RPC counters.
# No common wait clock, helper-call attribution or deadline snapshot is claimed.
PROGRESS_REASONS=('VerifierFallback','NoRound','GuardInvalid','NoSettledRoster','SharingPending','Complete')
PROGRESS_UINT=r'(?:0|[1-9][0-9]{0,19})'
def closed_timeout_progress(raw):
    text=re.sub(r'\x1b\[[0-?]*[ -/]*[@-~]','',raw)
    n=PROGRESS_UINT
    opt=lambda value:r'(?:None|Some\('+value+r'\))'
    arr=lambda width:r'\['+', '.join([n]*width)+r'\]'
    aggregate=opt(r'\((true|false), (None|Some\('+n+r'\)), ('+n+'), ('+n+r')\)')
    # Discard the other source-owned numeric arrays; never export their values.
    aggregate_line=r'primary/expected/children/completed=('+aggregate+r') intake='+opt(arr(8))+r' rejections='+opt(arr(4))+r' context_rejections='+opt(arr(9))+r' projection='+opt(arr(4))
    rpc_line=r'native_rpc_counts/elapsed_ms/branch=('+opt(r'\(('+arr(6)+'), ('+arr(6)+'), (None|Some\(\(('+'|'.join(PROGRESS_REASONS)+'), ('+n+r')\)\))\)')+')'
    rows={side:{'completion':{'record_available':False,'value':None},'native_rpc':{'record_available':False,'value':None}} for side in ('left','right')}
    for side in rows:
        prefix='automatic-enrollment-control side='+side+' '
        for category,tag,pattern in [('completion','primary/expected/children/completed=',aggregate_line),('native_rpc','native_rpc_counts/elapsed_ms/branch=',rpc_line)]:
            candidates=[line[len(prefix):] for line in text.splitlines() if line.startswith(prefix+tag)]
            row=rows[side][category];row['candidate_count']=len(candidates)
            if len(candidates)!=1 or len(candidates[0])>4096:continue
            match=re.fullmatch(pattern,candidates[0])
            if match is None:continue
            # Every numeric field, including discarded source arrays, must fit u64.
            if any(int(value)>2**64-1 for value in re.findall(r'(?<![A-Za-z_])[0-9]+',candidates[0])):continue
            row['record_available']=True
            if match[1]=='None':continue
            if category=='completion':
                row['value']={'primary_committed':match[2]=='true','expected_children':None if match[3]=='None' else int(match[3][5:-1]),'children':int(match[4]),'completed_children':int(match[5])}
            else:
                row['value']={'counts':[int(value) for value in match[2][1:-1].split(', ')],'last_elapsed_ms':[int(value) for value in match[3][1:-1].split(', ')],'last_reason':None if match[4]=='None' else {'reason':match[5],'elapsed_ms':int(match[6])}}
    return {'sides':rows,'rpc_stage_order':['DispatchStarted','WorkerStarted','WorkerReturned','FacadeReturned','AutomaticEntered','AutomaticExited'],
        'cumulative_per_original':True,'post_timeout_independent_samples':True,'common_wait_clock':False,'helper_call_attribution':False,'fresh_deadline_snapshot':False,'blocking_side_identified':False}

def timeout_progress_controls():
    prefix='automatic-enrollment-control side=left '
    completion=prefix+'primary/expected/children/completed=Some((true, Some(3), 3, 2)) intake=Some([0, 1, 2, 3, 4, 5, 6, 7]) rejections=None context_rejections=None projection=None'
    rpc=prefix+'native_rpc_counts/elapsed_ms/branch=Some(([1, 2, 3, 4, 5, 6], [0, 1, 2, 3, 4, 18446744073709551615], Some((SharingPending, 12))))'
    rows=closed_timeout_progress(completion+'\n'+rpc)['sides']
    ensure(rows['left']['completion']['value']=={'primary_committed':True,'expected_children':3,'children':3,'completed_children':2} and rows['left']['native_rpc']['value']['counts']==[1,2,3,4,5,6] and rows['right']['completion']['record_available'] is False,'closed-progress-real-widths')
    none=closed_timeout_progress(prefix+'native_rpc_counts/elapsed_ms/branch=None')['sides']['left']['native_rpc']
    ensure(none['record_available'] and none['value'] is None,'closed-progress-source-None')
    reason_none=closed_timeout_progress(rpc.replace('Some((SharingPending, 12))','None'))['sides']['left']['native_rpc']
    ensure(reason_none['record_available'] and reason_none['value']['last_reason'] is None and reason_none['value']['counts']==[1,2,3,4,5,6],'closed-progress-reason-None')
    # Additional existing_index=2/child rows cannot impose an inherited eight-row limit.
    extra='\n'.join(['automatic-enrollment-control existing_index=2 child_channel=None']*9)
    ensure(closed_timeout_progress(completion+'\n'+rpc+'\n'+extra)['sides']==rows,'fifth-extra-rows-not-a-limit')
    for line in [completion.replace('Some(3)','Some(-3)'),completion.replace('3, 2','3, 18446744073709551616'),completion+' PRIVATE',completion+'\n'+completion]:
        result=closed_timeout_progress(line)
        ensure(not result['sides']['left']['completion']['record_available'] and 'PRIVATE' not in json.dumps(result),'closed-progress-invalid-completion')
    for line in [rpc.replace('1, 2, 3, 4, 5, 6','1, 2, 3, 4, 5'),rpc.replace('SharingPending','PRIVATE'),rpc.replace('18446744073709551615','18446744073709551616'),rpc+'\n'+rpc,rpc.replace('Some((SharingPending, 12))','Some((SharingPending, -1))'),rpc.replace('Some((SharingPending, 12))','Some(SharingPending, 12)')]:
        result=closed_timeout_progress(line)
        ensure(not result['sides']['left']['native_rpc']['record_available'] and 'PRIVATE' not in json.dumps(result),'closed-progress-invalid-rpc')
    return {'positive':4,'negative':10,'actual_runtime_bodies':0}

def closed_hold_timeout(raw):
    text=re.sub(r'\x1b\[[0-?]*[ -/]*[@-~]','',raw)
    n=PROGRESS_UINT;opt=lambda value:r'(?:None|Some\('+value+r'\))'
    arr=lambda width:r'\['+', '.join([n]*width)+r'\]'
    completion=opt(r'\((true|false), (None|Some\('+n+r'\)), ('+n+'), ('+n+r')\)')
    rpc=opt(r'\(('+arr(6)+'), ('+arr(6)+'), (None|Some\(\(('+'|'.join(PROGRESS_REASONS)+'), ('+n+r')\)\))\)')
    pattern=r'automatic-hold-timeout stage=(AutomaticPublicationHold|SiblingConsentPeerProgress) side=(source|recipient) completion=('+completion+r') native_rpc=('+rpc+r')'
    lines=[line for line in text.splitlines() if line.startswith('automatic-hold-timeout')]
    result={'schema_known':True,'records':[],'candidate_count':len(lines),'post_timeout_independent_samples':True,'common_wait_clock':False,'helper_call_attribution':False,'fresh_deadline_snapshot':False,'blocking_side_identified':False}
    seen=set();stages=set()
    if len(lines)>2:result['schema_known']=False;return result
    for line in lines:
        match=re.fullmatch(pattern,line) if len(line)<=2048 else None
        if match is None or any(int(value)>2**64-1 for value in re.findall(r'(?<![A-Za-z_])[0-9]+',line)):
            result['schema_known']=False;continue
        stage,side=match[1],match[2];key=(stage,side)
        if key in seen:result['schema_known']=False;continue
        seen.add(key);stages.add(stage)
        aggregate=None if match[3]=='None' else {'primary_committed':match[4]=='true','expected_children':None if match[5]=='None' else int(match[5][5:-1]),'children':int(match[6]),'completed_children':int(match[7])}
        rpc_value=None if match[8]=='None' else {'counts':[int(value) for value in match[9][1:-1].split(', ')],'last_elapsed_ms':[int(value) for value in match[10][1:-1].split(', ')],'last_reason':None if match[11]=='None' else {'reason':match[12],'elapsed_ms':int(match[13])}}
        result['records'].append({'stage':stage,'side':side,'completion':aggregate,'native_rpc':rpc_value})
    if lines and (len(stages)!=1 or len(seen)!=2):result['schema_known']=False
    return result

def hold_timeout_controls():
    make=lambda side:'automatic-hold-timeout stage=AutomaticPublicationHold side='+side+' completion=Some((true, Some(2), 2, 1)) native_rpc=Some(([1, 2, 3, 4, 5, 6], [0, 1, 2, 3, 4, 5], Some((SharingPending, 12))))'
    good=make('source')+'\n'+make('recipient')
    row=closed_hold_timeout(good)
    ensure(row['schema_known'] and row['records'][0]['completion']['children']==2 and row['records'][1]['native_rpc']['last_reason']['reason']=='SharingPending','direct-hold-source-grammar')
    ensure(closed_hold_timeout('')['schema_known'] and not closed_hold_timeout('')['records'],'no-timeout-observation-none')
    none=good.replace('Some((true, Some(2), 2, 1))','None').replace('Some((SharingPending, 12))','None')
    ensure(closed_hold_timeout(none)['schema_known'] and closed_hold_timeout(none)['records'][0]['completion'] is None,'source-None-unknown')
    ensure(closed_hold_timeout(good.replace('AutomaticPublicationHold','SiblingConsentPeerProgress'))['schema_known'],'second-fixed-stage')
    for text in [make('source'),good+'\n'+make('source'),good.replace('side=recipient','side=source'),good.replace('SharingPending','PRIVATE'),good.replace('Some((SharingPending, 12))','Some(SharingPending, 12)'),good.replace('Some(2)','Some(-2)'),good.replace('1, 2, 3, 4, 5, 6','1, 2, 3, 4, 5'),good.replace('SharingPending, 12','SharingPending, 18446744073709551616'),good+' PRIVATE',good.replace('side=recipient','side=PRIVATE'),make('source')+'\n'+make('recipient').replace('AutomaticPublicationHold','SiblingConsentPeerProgress')]:
        bad=closed_hold_timeout(text);ensure(not bad['schema_known'] and 'PRIVATE' not in json.dumps(bad),'closed-hold-invalid-or-privacy')
    return {'positive':4,'negative':11,'runtime_bodies':0}

RESULT_ORDER=('RosterNone','RosterSome','RosterErr','NativePersistErr','MaintenancePersistErr','AutomaticOk','AutomaticErr')
def closed_native_results(raw):
    text=re.sub(r'\x1b\[[0-?]*[ -/]*[@-~]','',raw)
    lines=[line for line in text.splitlines() if line.startswith('native-result-counts')]
    n=PROGRESS_UINT;array=r'\['+', '.join([n]*7)+r'\]'
    pattern=r'native-result-counts stage=(PhaseWait|AutomaticPublicationHold|SiblingConsentPeerProgress) side=(left|right|source|recipient) counts_overflow=(None|Some\(\(('+array+r'), (true|false)\)\))'
    result={'schema_known':True,'records':[],'candidate_count':len(lines),'counter_order':list(RESULT_ORDER),'cumulative_per_original':True,'post_timeout_independent_samples':True,'per_pass_or_helper_attribution':False,'all_zero_is_no_recorded_result_not_no_errors':True,'automatic_only_entered_calls':True,'no_current_authority_claim':True}
    seen=set();stages=set()
    if len(lines)>2:result['schema_known']=False;return result
    for line in lines:
        match=re.fullmatch(pattern,line) if len(line)<=1024 else None
        if match is None:result['schema_known']=False;continue
        stage,side=match[1],match[2]
        if side not in (('left','right') if stage=='PhaseWait' else ('source','recipient')) or (stage,side) in seen:
            result['schema_known']=False;continue
        counts=None if match[3]=='None' else [int(value) for value in match[4][1:-1].split(', ')]
        if counts is not None and any(value>2**64-1 for value in counts):result['schema_known']=False;continue
        seen.add((stage,side));stages.add(stage)
        overflow=None if counts is None else match[5]=='true'
        result['records'].append({'stage':stage,'side':side,'counts':counts,'overflow':overflow,'any_result_recorded':None if counts is None else any(counts),'counts_not_saturated':None if counts is None else not overflow})
    if lines and (len(stages)!=1 or len(seen)!=2):result['schema_known']=False
    return result

def native_result_controls():
    line=lambda side,counts:'native-result-counts stage=PhaseWait side='+side+' counts_overflow='+counts
    observed='Some(([1, 2, 3, 4, 5, 6, 7], false))'
    good=line('left',observed)+'\n'+line('right','None')
    row=closed_native_results(good)
    ensure(row['schema_known'] and row['records'][0]['counts']==[1,2,3,4,5,6,7] and row['records'][1]['counts']is None,'actual-seven-result-counts-and-None')
    zero=good.replace('[1, 2, 3, 4, 5, 6, 7]','[0, 0, 0, 0, 0, 0, 0]')
    ensure(closed_native_results(zero)['schema_known'] and not closed_native_results(zero)['records'][0]['any_result_recorded'],'allzero-no-recorded-result-only')
    overflow=good.replace('7], false','18446744073709551615], true')
    ensure(closed_native_results(overflow)['schema_known'] and not closed_native_results(overflow)['records'][0]['counts_not_saturated'],'overflow-retained-not-complete')
    ensure(closed_native_results('')['schema_known'] and not closed_native_results('')['records'],'no-timeout-records-unknown')
    for text in [good+'\n'+good,line('left',observed),good.replace('side=right','side=left'),good.replace('1, 2, 3, 4, 5, 6, 7','1, 2, 3, 4, 5, 6'),good.replace('7], false','18446744073709551616], false'),good.replace('1, 2','-1, 2'),good.replace('false','PRIVATE'),good+' PRIVATE',good.replace('side=right','side=recipient'),good.replace('stage=PhaseWait','stage=PRIVATE')]:
        bad=closed_native_results(text);ensure(not bad['schema_known'] and 'PRIVATE' not in json.dumps(bad),'closed-result-schema-privacy-bound')
    return {'positive':4,'negative':10,'runtime_bodies':0}

PERSIST_SITES=('InitialCoreRoster','LocalRole','ContextDigest','AccountStorage','LegacyCapture','PolicyCommit')
ENGINE_KINDS=('unknown_group','group_not_hydrated','unknown_pending','not_a_member','not_group_admin','unknown_member','invalid_credential_identity','admin_cannot_self_remove','leave_already_requested','admin_depletion','missing_required_capabilities','disbanding_unsupported_members','disbanding_not_enabled','unsupported_ciphersuite','invalid_app_message_payload','invalid_account_identity_proof','invalid_key_package_lifetime','invalid_key_package_capabilities','app_message_epoch_mismatch','app_message_epoch_unsettled','forked_epoch','queued_outbound_at_capacity','group_unrecoverable_repair_required','invalid_transition','storage','peeler','serialize','invalid_welcome','linking_welcome_denied','selected_chat_welcome_denied','missing_welcome_key_package','welcome_already_processed','private_enrollment_intake_at_capacity','backend','other')
STORAGE_KINDS=('storage_not_found','storage_already_exists','storage_record_denied_by_departure','storage_snapshot_missing','storage_timeline_cursor_expired','storage_busy','storage_corruption','storage_capacity','storage_closed','storage_unsupported_schema_version','storage_invalid_attachment_body','storage_backend')
POLICY_SERIALIZATION_KINDS=('storage_serialization_original_unavailable', 'storage_serialization_settlement_store_missing', 'storage_serialization_round_read_err', 'storage_serialization_round_missing', 'storage_serialization_guard_anchor', 'storage_serialization_fresh_core_err', 'storage_serialization_fresh_core_none', 'storage_serialization_roster_changed', 'storage_serialization_legacy_unavailable', 'storage_serialization_invalid_policy', 'storage_serialization_unknown')
def closed_persist_errors(raw):
    text=re.sub(r'\x1b\[[0-?]*[ -/]*[@-~]','',raw)
    lines=[line for line in text.splitlines() if line.startswith('native-persist-errors')]
    n=PROGRESS_UINT;array=r'\['+', '.join([n]*6)+r'\]'
    kinds='|'.join(ENGINE_KINDS+STORAGE_KINDS+POLICY_SERIALIZATION_KINDS)
    last=r'(None|Some\(\(('+'|'.join(PERSIST_SITES)+r'), (None|Some\("('+kinds+r')"\))\)\))'
    pattern=r'native-persist-errors stage=(PhaseWait|AutomaticPublicationHold|SiblingConsentPeerProgress) side=(left|right|source|recipient) snapshot=(None|Some\(\(('+array+r'), (true|false), '+last+r'\)\))'
    result={'schema_known':True,'records':[],'candidate_count':len(lines),'counter_order':list(PERSIST_SITES),'cumulative_per_original':True,'last_error_only_no_history':True,'per_pass_or_deadline_attribution':False,'all_zero_means_no_recorded_error_only':True,'missing_or_None_is_unknown':True,'raw_errors_exported':False}
    seen=set();stages=set()
    if len(lines)>2 or sum(len(line.encode())+1 for line in lines)>1024:result['schema_known']=False;return result
    for line in lines:
        match=re.fullmatch(pattern,line)
        if match is None:result['schema_known']=False;continue
        stage,side=match[1],match[2]
        if side not in (('left','right') if stage=='PhaseWait' else ('source','recipient')) or (stage,side) in seen:
            result['schema_known']=False;continue
        values=None if match[3]=='None' else [int(v) for v in match[4][1:-1].split(', ')]
        last_value=None if values is None or match[6]=='None' else {'stage':match[7],'kind':None if match[8]=='None' else match[9]}
        if values is not None:
            if any(v>2**64-1 for v in values) or (match[5]=='true' and 2**64-1 not in values) or ((last_value is None)!= (not any(values))):result['schema_known']=False;continue
            if last_value is not None:
                site=last_value['stage'];kind=last_value['kind']
                valid_kind=(kind in ENGINE_KINDS if site=='InitialCoreRoster' else kind in STORAGE_KINDS+POLICY_SERIALIZATION_KINDS if site=='PolicyCommit' else kind is None)
                if not valid_kind or values[PERSIST_SITES.index(site)]==0:result['schema_known']=False;continue
        seen.add((stage,side));stages.add(stage)
        result['records'].append({'stage':stage,'side':side,'counts':values,'overflow':None if values is None else match[5]=='true','last_error':last_value,'any_recorded_error':None if values is None else any(values)})
    if lines and (len(stages)!=1 or len(seen)!=2):result['schema_known']=False
    return result

def persist_error_controls():
    pair=lambda value:'native-persist-errors stage=PhaseWait side=left snapshot='+value+'\n'+'native-persist-errors stage=PhaseWait side=right snapshot=None'
    zero='Some(([0, 0, 0, 0, 0, 0], false, None))'
    engine='Some(([1, 0, 0, 0, 0, 0], false, Some((InitialCoreRoster, Some("backend")))))'
    policy='Some(([0, 0, 0, 0, 0, 1], false, Some((PolicyCommit, Some("storage_busy")))))'
    positives=[pair(zero),pair(engine),pair(policy),pair('Some(([0, 1, 0, 0, 0, 0], false, Some((LocalRole, None))))'),pair(engine.replace('[1,','[18446744073709551615,').replace('false','true')),pair('None'),'']
    for text in positives:ensure(closed_persist_errors(text)['schema_known'],'persist-closed-actual-shape-positive')
    ensure(closed_persist_errors(pair(zero))['records'][0]['any_recorded_error']is False and closed_persist_errors(pair('None'))['records'][0]['counts']is None,'persist-zero-not-unavailable')
    bad=[pair(engine.replace('false','true')),pair(engine.replace('backend','PRIVATE')),pair(engine.replace('Some("backend")','None')),pair(policy.replace('storage_busy','backend')),pair(engine.replace('[1,','[0,')),pair(zero.replace('false, None','false, Some((LocalRole, None))')),pair(engine.replace('18446744073709551615','18446744073709551616').replace('[1,','[18446744073709551616,')),pair(engine.replace('[1,','[-1,')),pair(engine.replace('Some((InitialCoreRoster','Some(InitialCoreRoster')),pair(engine)+' PRIVATE',pair(engine)+'\n'+pair(engine),pair(engine).split('\n')[0],pair(engine).replace('side=right','side=left'),pair(engine).replace('side=right','side=recipient'),pair(engine).replace('stage=PhaseWait','stage=PRIVATE'),pair(engine.replace('[1, 0, 0, 0, 0, 0]','[1, 0, 0, 0, 0]')),pair('Some(([0, 1, 0, 0, 0, 0], false, Some((LocalRole, Some("backend")))))')]
    for text in bad:
        row=closed_persist_errors(text);ensure(not row['schema_known'] and 'PRIVATE' not in json.dumps(row),'persist-malformed-private-or-incoherent-rejected')
    # Exact source-owned static classifier labels only; no free-form Serialization payload.
    classifier_positives=[]
    classifier_negatives=[]
    for kind in POLICY_SERIALIZATION_KINDS:
        observed='Some(([0, 0, 0, 0, 0, 1], false, Some((PolicyCommit, Some("'+kind+'")))))'
        classifier_positives.append(pair(observed))
        classifier_negatives.extend([
            pair('Some(([1, 0, 0, 0, 0, 0], false, Some((InitialCoreRoster, Some("'+kind+'")))))'),
            pair('Some(([0, 1, 0, 0, 0, 0], false, Some((LocalRole, Some("'+kind+'")))))'),
            pair(observed.replace('[0, 0, 0, 0, 0, 1]', '[0, 0, 0, 0, 0, 0]')),
        ])
    maximum='18446744073709551615'
    longest=max(POLICY_SERIALIZATION_KINDS,key=len)
    max_snapshot='Some((['+', '.join([maximum]*6)+'], true, Some((PolicyCommit, Some("'+longest+'")))))'
    max_pair='native-persist-errors stage=SiblingConsentPeerProgress side=source snapshot='+max_snapshot+'\n'+'native-persist-errors stage=SiblingConsentPeerProgress side=recipient snapshot='+max_snapshot
    ensure(sum(len(line.encode())+1 for line in max_pair.splitlines())<=1024,'classifier-max-width-existing-pair-cap')
    classifier_positives.append(max_pair)
    for text in classifier_positives:
        parsed=closed_persist_errors(text)
        ensure(parsed['schema_known'] and all(row['last_error'] is None or row['last_error']['kind'] in POLICY_SERIALIZATION_KINDS for row in parsed['records']),'classifier-static-policy-kind-positive')
    for kind in ['storage_serialization','storage_serialization_unrecognized','storage_serialization_unknown_suffix','storage_serialization_PRIVATE', 'x'*1024]:
        classifier_negatives.append(pair('Some(([0, 0, 0, 0, 0, 1], false, Some((PolicyCommit, Some("'+kind+'")))))'))
    for text in classifier_negatives:
        parsed=closed_persist_errors(text)
        ensure(not parsed['schema_known'] and 'PRIVATE' not in json.dumps(parsed),'classifier-unknown-wrong-site-zero-count-or-private-rejected')
    ensure(len(classifier_positives)==12 and len(classifier_negatives)==38,'classifier-authored-control-inventory')
    return {'positive':19,'negative':55,'runtime_bodies':0,'inherited_positive':7,'inherited_negative':17,'classifier_positive':12,'classifier_negative':38,'max_width_pair_bytes':sum(len(line.encode())+1 for line in max_pair.splitlines()),'existing_pair_cap_bytes':1024}

def execute_case(report,row,binary,before,mode,inputs,label,name,five):
    row.update(label=label,name=name,runtime_attempted=False,actual_executed_nonignored=0,oracle_green=False)
    save(report)
    for ignored in [False,True]:
        code,raw,seconds=bounded.capture([str(binary),'--exact',name]+(['--ignored'] if ignored else [])+['--list','--format','terse'],60,limit=1024*1024)
        parsed=counts.parse_inventory(raw,name,ignored)
        row.setdefault('inventory',{})['ignored' if ignored else 'normal']={'exit_code':code,'seconds':seconds,'passed':parsed.get('passed') is True}
        save(report);ensure(code==0 and parsed.get('passed') is True,'one-normal-zero-ignored-exact-case')
    ensure(physical()==inputs and binary.is_file() and not binary.is_symlink() and digest(binary.read_bytes())==before and stat.S_IMODE(binary.stat().st_mode)==mode,'prebody-source-binary-mode')
    row.update(runtime_attempted=True,actual_executed_nonignored=None);save(report)
    try:code,raw,seconds=bounded.capture([str(binary),'--exact',name,'--nocapture','--test-threads=1'],900 if five else 300,limit=8*1024*1024)
    except bounded.GateFailure as error:
        row['watchdog_triggered']=str(error)=='bounded-command-timeout';row['output_limit_triggered']=str(error)=='bounded-command-output-limit';save(report);raise
    regular=binary.is_file() and not binary.is_symlink()
    row.update(body_exit_code=code,body_seconds=seconds,source_after_body_pristine=physical()==inputs,
        binary_after_sha256=digest(binary.read_bytes()) if regular else None,binary_after_mode=stat.S_IMODE(binary.stat().st_mode) if regular else None)
    save(report)
    basic=counts.parse_body(raw,code,name);row['basic_counts']=closed_counts(basic)
    for dest,key in [('actual_passed','passed'),('actual_failed','failed'),('actual_ignored','ignored'),('actual_executed_nonignored','executed_nonignored')]:row[dest]=basic.get(key)
    row['actual_test_passed']=basic.get('passed_gate') is True;save(report)
    row['panic_locations']=closed_panic_sites(raw,name,set(inputs));save(report)
    if five or label in FAILURE_LABELS:
        row['phase_timeout']=closed_phase_timeout(raw,name);save(report)
        row['timeout_progress']=closed_timeout_progress(raw);save(report)
        if label in FAILURE_LABELS:row['hold_timeout']=closed_hold_timeout(raw);save(report)
        row['native_results']=closed_native_results(raw);save(report)
        row['persist_errors']=closed_persist_errors(raw);save(report)
    ensure(row['source_after_body_pristine'] and row['binary_after_sha256']==before and row['binary_after_mode']==mode,'postbody-source-binary-mode')
    parsed=native.parse(raw,code) if five else ack.parse_case(label,raw,code)
    row['original_oracle']=closed_oracle(parsed)
    row['oracle_green']=row['actual_test_passed'] and (native.green(parsed) if five else ack.case_green(label,parsed)) is True
    save(report)

def parser_controls(mode):
    inherited=native.parser_controls() if mode=='five' else ack.parser_controls()
    names=selected_cases(mode)
    ensure(len(names)==(1 if mode=='five' else 2 if mode=='handoff-diagnostic' else 4 if mode=='failures' else 16),'exact-selected-case-count')
    ensure(closed_oracle({'facts':{'closed':True},'compiler_headers':['PRIVATE'],'message':'PRIVATE'})=={'facts':{'closed':True},'observations':None},'closed-projection-no-private-strings')
    complete={'basic_counts':{'passed':1,'failed':0,'ignored':0,'executed_nonignored':1,'actual_counts_complete':True}}
    observed_ignored={'basic_counts':{'passed':0,'failed':0,'ignored':1,'executed_nonignored':0,'actual_counts_complete':False}}
    ensure(aggregate([complete,observed_ignored],2)['actual_ignored']==1,'known-failed-shape-counts-retained')
    ensure(aggregate([complete,{}],2)['actual_passed'] is None and aggregate([complete,{}],2)['known_partial_passed']==1,'unknown-counts-not-zero')
    ensure(aggregate([complete],2)['actual_passed'] is None,'missing-case-not-complete')
    ensure(aggregate([{'basic_counts':{'passed':True}}],1)['actual_passed'] is None,'bool-not-actual-count')
    path='crates/closed.rs';name='source::known_case'
    header="thread '"+name+"' panicked at "+path+":2:3:\nPRIVATE payload\n"
    read=lambda _:b'first\n    assert!(false);\n'
    valid=closed_panic_sites(header,name,{path},read)
    ensure(valid['sites']==[{'file':path,'line':2,'column':3,'thread_fullname':name}] and 'PRIVATE' not in json.dumps(valid),'closed-source-site-positive')
    pid=closed_panic_sites(header.replace("' panicked","' (123) panicked"),name,{path},read)
    ensure(pid['sites']==valid['sites'],'numeric-Rust-thread-PID-discarded')
    foreign=closed_panic_sites(header.replace(name,'PRIVATE-thread'),name,{path},read)
    ensure(foreign['sites'][0]['thread_fullname'] is None and 'PRIVATE' not in json.dumps(foreign),'foreign-thread-not-exported')
    for text in [header.replace(path,'private/foreign.rs'),header.replace(':2:3:',':0:3:'),header.replace(':2:3:',':3:3:'),header.replace(':2:3:',':2:999:'),header.replace('panicked at ','panicked elsewhere '),header.replace(':2:3:',':2:3: suffix'),header.replace("' panicked","' (PRIVATE) panicked"),header.replace("' panicked","' (123 panicked")]:
        ensure(not closed_panic_sites(text,name,{path},read)['sites'],'unknown-or-out-of-source-site-not-exported')
    many=closed_panic_sites(header*33,name,{path},read)
    ensure(len(many['sites'])==32 and many['truncated'] is True,'bounded-source-sites')
    phase_source=Path('crates/marmot-app/src/native_device_linking.rs').read_text()
    match=re.search(r'pub enum DeviceLinkingPhase \{([^}]+)\}',phase_source)
    ensure(match is not None and tuple(part.strip() for part in match[1].split(',') if part.strip())==PHASES,'exact-nine-source-unit-phases')
    phase_line,phase_column=phase_timeout_site()
    phase_header="thread '"+native.NAME+"' (123) panicked at "+PARENT+':'+str(phase_line)+':'+str(phase_column)+':\n'
    phase_payload='automatic pairing did not reach required phase: expected=EnrollmentComplete observed=Some((EnrollmentComplete, VerificationCompleteEnrollmentPending))'
    closed=closed_phase_timeout(phase_header+phase_payload+'\n',native.NAME)
    ensure(closed['closed_phase_record_available'] and closed['last_completed_serial_pair']==['EnrollmentComplete','VerificationCompleteEnrollmentPending'],'exact-cached-closed-pair-positive')
    none=closed_phase_timeout(phase_header+phase_payload.replace('Some((EnrollmentComplete, VerificationCompleteEnrollmentPending))','None')+'\n',native.NAME)
    ensure(none['closed_phase_record_available'] and none['observed_pair_available'] is False and none['last_completed_serial_pair'] is None,'no-completed-pair-is-unknown-positive')
    for text in [phase_header+phase_payload+' PRIVATE',phase_header+phase_payload.replace('VerificationCompleteEnrollmentPending','PRIVATE'),phase_header.replace(':'+str(phase_column)+':',':999:')+phase_payload,(phase_header+phase_payload+'\n')*2,phase_payload+'\n',phase_header+phase_payload.replace('Some((', '('),phase_header.replace('(123)','(PRIVATE)')+phase_payload]:
        row=closed_phase_timeout(text,native.NAME)
        ensure(not row['closed_phase_record_available'] and 'PRIVATE' not in json.dumps(row),'no-foreign-or-malformed-phase-payload-export')
    return {'persist_error_controls':persist_error_controls(),'native_result_controls':native_result_controls(),'hold_timeout_controls':hold_timeout_controls(),'timeout_progress_controls':timeout_progress_controls(),'original_oracle_controls':inherited,'wrapper_controls':5,'panic_site_positive':4,'panic_site_negative':8,'phase_positive':2,'phase_negative':7,'actual_runtime_bodies':0}

def main(args):
    os.umask(0o077)
    report={'expected_case_mode':args.mode,'preflight_only':args.preflight,'actual_test_qualification':False,'global_qualification':False,
        'old_guards_or_main_called':False,'old_module_globals_mutated':False,'automatic_retries':0,'raw_runtime_output_exported':False,
        'requested_features':FEATURES,'environment_stack_bytes':4194304,'Tokio_workers':2 if args.mode=='five' else None,
        'runtime_flavor': 'original-five-two-worker' if args.mode=='five' else 'original-two-handoff-frontiers-diagnostic-only' if args.mode=='handoff-diagnostic' else 'original-source-defined-four-failures' if args.mode=='failures' else 'original-source-defined-mixed-sixteen',
        'actual_runtime_attempts':0,'actual_executed_nonignored':0,'original_join_deadline_seconds':15,'body_watchdog_seconds':900 if args.mode=='five' else 300,'output_limit_bytes':8*1024*1024,'cases':[]}
    save(report);inputs=None;binary=None;before=None;mode=None
    try:
        report['source']=source_guard(args.preflight);inputs=physical();save(report)
        report['parser_controls']=parser_controls(args.mode);save(report)
        if args.preflight:
            report['actual_executed_nonignored']=0;report['preflight_passed']=True;save(report);return
        ensure(shutil.disk_usage('.').free>=8*1024**3,'eight-GiB-free-before-compilation')
        selected=selected_cases(args.mode)
        binary=compile_app(report,'experimental',set(inputs),lambda:save(report))
        before=digest(binary.read_bytes());mode=stat.S_IMODE(binary.stat().st_mode)
        report['binary_before']={'sha256':before,'mode':mode,'kind':'regular-test-executable'};save(report)
        ensure(physical()==inputs,'after-compile-whole-source-pristine')
        for label,suffix,name,_ in selected:
            row={};report['cases'].append(row);save(report)
            try:execute_case(report,row,binary,before,mode,inputs,label,name,args.mode=='five')
            except Exception as error:row['controller_failure_type']=type(error).__name__;save(report)
        report.update(aggregate(report['cases'],len(selected)));save(report)
        report['all_original_cases_green']=len(report['cases'])==len(selected) and all(row.get('oracle_green') is True for row in report['cases'])
        report['actual_test_qualification']=report['all_original_cases_green'] and args.mode!='handoff-diagnostic'
        report['handoff_diagnostic_completed']=args.mode=='handoff-diagnostic' and report['all_original_cases_green'] and all(row.get('persist_errors',{}).get('schema_known')is True for row in report['cases'])
        save(report);ensure(report['handoff_diagnostic_completed'] if args.mode=='handoff-diagnostic' else report['actual_test_qualification'],'original-current-enrollment-cases-not-all-GREEN')
    finally:
        report['actual_runtime_attempts']=sum(row.get('runtime_attempted') is True for row in report['cases'])
        if not args.preflight:
            report.update(aggregate(report['cases'],1 if args.mode=='five' else 2 if args.mode=='handoff-diagnostic' else 4 if args.mode=='failures' else 16))
            if report['actual_runtime_attempts']==0:report['actual_executed_nonignored']=0
        report['final_source_pristine']=inputs is not None and physical()==inputs
        regular=binary is not None and binary.is_file() and not binary.is_symlink()
        report['final_binary_sha256']=digest(binary.read_bytes()) if regular else None
        report['final_binary_mode']=stat.S_IMODE(binary.stat().st_mode) if regular else None
        report['final_binary_pristine']=None if binary is None else regular and report['final_binary_sha256']==before and report['final_binary_mode']==mode
        if not report['final_source_pristine'] or report['final_binary_pristine'] is False:
            report['actual_test_qualification']=False;report['handoff_diagnostic_completed']=False
        save(report)
        ensure(report['final_source_pristine'] and report['final_binary_pristine'] is not False,'final-source-binary-mode-closure')
    ensure(report.get('handoff_diagnostic_completed')is True if args.mode=='handoff-diagnostic' else report['actual_test_qualification'],'actual-current-native-qualification-required')

if __name__=='__main__':
    parser=argparse.ArgumentParser();parser.add_argument('--preflight',action='store_true');parser.add_argument('--mode',choices=['five','sixteen','failures','handoff-diagnostic'],default='five')
    main(parser.parse_args())
