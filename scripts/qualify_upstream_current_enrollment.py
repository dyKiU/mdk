#!/usr/bin/env python3
"""Original enrollment modes and a closed four-case observation mode; no mutation."""
import argparse, hashlib, json, os, re, shutil, stat, subprocess, time, sys
from pathlib import Path
import qualify_upstream_storage_boundary as bounded
import qualify_upstream_storage_app_handles as counts
import upstream_completion_ci as completion
import qualify_upstream_pure_native5 as native
import qualify_upstream_request_retry_ack as ack
ensure=bounded.ensure
BASE='0b1481fe25ee68fb201ff1a3beb95f73dcc4e52f'
RAW_SOURCE='0b1481fe25ee68fb201ff1a3beb95f73dcc4e52f'
SOURCE_PARENT='0cae96b7a44858b213a2ae1e2703893ff998a945'
DIAGNOSTIC_SOURCE_PINS={'crates/marmot-app/src/client/private_enrollment_proposal.rs': {'before_sha256': 'caf4a6946bf91094db597f4c326df4fc497813b6bdf6a3f358752e0eb9b290e8', 'raw_sha256': '478f08af1f1e22904593af295d40d629e8940a6232260d323f28f7b30bd189fa', 'canonical_sha256': '478f08af1f1e22904593af295d40d629e8940a6232260d323f28f7b30bd189fa', 'mode': '100644'}, 'crates/marmot-app/src/native_device_linking/enabled.rs': {'before_sha256': 'e41d1015ef565db7d79df7438ffa92d83a888f45a98dc0b73641c69dd3a3db0d', 'raw_sha256': 'eb45c461ae251e545a982a53db5d298e650ea7b51cf7776e1b16f9cf118c0893', 'canonical_sha256': 'eb45c461ae251e545a982a53db5d298e650ea7b51cf7776e1b16f9cf118c0893', 'mode': '100644'}, 'crates/marmot-app/src/native_device_linking/tests/automatic_pairing_acceptance.rs': {'before_sha256': '674912b2606b11ab735b947fdab2b8f9e28597f07f406ab8cff8b6e7c8733fe9', 'raw_sha256': 'b77d8e7d945b851f2749e6e7a72a8785647e17a7d78100fbcb8ea825819570e5', 'canonical_sha256': 'b77d8e7d945b851f2749e6e7a72a8785647e17a7d78100fbcb8ea825819570e5', 'mode': '100644'}, 'crates/marmot-app/src/native_device_linking/tests/sequential_installations_acceptance.rs': {'before_sha256': '88431d9c40c8c91ad5cdf6eb59e9155e6aed0a366640044e96c4944930cda0b5', 'raw_sha256': '9f3ca5baf9013ddcf6e754759f87c5e6a9060e3db42de86aabbe4f0c5a694fd7', 'canonical_sha256': '9f3ca5baf9013ddcf6e754759f87c5e6a9060e3db42de86aabbe4f0c5a694fd7', 'mode': '100644'}}
PURE_PRODUCT_BASE='68c93c7b147fdce1911bb857f1b5b2982477ece9'
REVIEWED_PRODUCT_METADATA={'scripts/qualify_upstream_c1_body_restart.py', 'scripts/qualify_upstream_current_enrollment.py', 'scripts/test_pairing_replay_dispatch.py', '.github/workflows/native-predecessor-readiness-pfp.yml', '.github/workflows/experimental-sync-ci.yml', 'scripts/qualify_upstream_native_predecessor_readiness.py', '.github/workflows/c1-body-restart.yml', '.github/workflows/current-enrollment.yml', 'scripts/qualify_pairing_replay_dispatch_pfp.py'}
APPROVED_BASE_TEST_DELTAS={'crates/marmot-app/src/native_device_linking/tests.rs': {'before': 'b50bb5dc83643286212e4edee84b91e0cf0ae3a210818bf07cf39617833a31a4', 'after': 'ef450d4a6e6de0d2989cce96ad87f550529282e433590629270bae25e0000168', 'mode': '100644'}, 'crates/marmot-app/src/native_device_linking/tests/automatic_account_departure_acceptance.rs': {'before': '1eeb59aff6dea7791d9970c68ef1227da9de678d05664fda4fc238a50c25e7e0', 'after': 'a6da36ab13def9b3c443bc3a55facd536fede8c3cdea4875d32d2888542d47ec', 'mode': '100644'}, 'crates/marmot-app/src/native_device_linking/tests/public_chat_delivery_acceptance.rs': {'before': '5a89b3cc3e70cb608b78546c993e332f30feb6ab59576195e6656323f161582c', 'after': '8706544aa426d6a945e880089c95d5a5ab6b4ef3d55ef9dbf7dc2d2487e2c1c5', 'mode': '100644'}, 'crates/marmot-app/src/native_device_linking/tests/sequential_installations_acceptance.rs': {'before': 'a81cc692c9864d9cdf2ff7fe8d533d3115c7eb7958fa7a22df783850fea520ca', 'after': '88431d9c40c8c91ad5cdf6eb59e9155e6aed0a366640044e96c4944930cda0b5', 'mode': '100644'}}
WORKFLOW_SHA='93734757b76eb15d87576a4d90b24403fda0ebde50f92f191b07564655023943'
SELF='scripts/qualify_upstream_current_enrollment.py'
WORKFLOW='.github/workflows/current-enrollment.yml'
REF='refs/heads/ci/upstream-current-enrollment-20261019'
FEATURES='marmot-app/otlp-export,marmot-uniffi/otlp-export,marmot-c/otlp-export,wn-cli/otlp-export,agent-connector/otlp-export,marmot-app/product-analytics-export,marmot-uniffi/product-analytics-export,marmot-c/product-analytics-export,wn-cli/product-analytics-export,agent-connector/product-analytics-export,wn-cli/test-policy-overrides,cgka-engine/test-policy-overrides,cgka-engine/test-crash-hooks,experimental-device-sync'
EXPECTED_GRAPH={'marmot_app': ['default', 'experimental-device-sync', 'otlp-export', 'product-analytics-export', 'test-policy-overrides'], 'cgka_engine': ['default', 'experimental-device-sync', 'test-conformance-snapshot', 'test-crash-hooks', 'test-policy-overrides'], 'storage_sqlite': ['experimental-device-sync', 'storage-format-benchmarks', 'test-conformance-replay', 'test-migrated-template', 'test-support'], 'cgka_session': ['default', 'experimental-device-sync', 'test-policy-overrides'], 'marmot_account': ['experimental-device-sync'], 'transport_nostr': ['default', 'experimental-device-sync', 'test-policy-overrides', 'test-support']}
OUT=Path(os.environ.get('RUNNER_TEMP','/tmp'))/'current-enrollment-evidence'
FIXTURE='crates/marmot-app/src/native_device_linking/tests/sequential_installations_acceptance.rs'
PARENT='crates/marmot-app/src/native_device_linking/tests/automatic_pairing_acceptance.rs'
FIXTURE_SHA='9f3ca5baf9013ddcf6e754759f87c5e6a9060e3db42de86aabbe4f0c5a694fd7'
PARENT_SHA='b77d8e7d945b851f2749e6e7a72a8785647e17a7d78100fbcb8ea825819570e5'
STRICT_WAIT_LOOP_SHA='29255c02115551856e1c5f84bf9203e79818211564ac41cb1bb9804cc082e5ca'
STRICT_HELPER_SHA='8b1635d8c4230ace397374462dbdd504110dc032ccc1e6dd89541a33b8d1eb93'
ORACLE_SHA='88417f89d6d6b3b9a8037d408be60c54d8b86451085cff9d254cb6cc74537e72'
NATIVE_HELPER='scripts/qualify_upstream_pure_native5.py'
ACK_HELPER='scripts/qualify_upstream_request_retry_ack.py'
HELPER_PINS={'scripts/qualify_upstream_pure_native5.py': 'e850003b806b321444ec53bac9e3a5b8d1d22e5e0661b09a0f7456f1c985aa2b', 'scripts/qualify_upstream_request_retry_ack.py': 'd413d577d2a6097b94870a9fb662f4ab3dd047ef8cc218861cba51dc0cbd8008'}
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
def git_closure():
    quiet=subprocess.run(['git','diff','--quiet','HEAD']).returncode==0
    index=subprocess.run(['git','diff','--cached','--quiet']).returncode==0
    n=len(git('ls-files','--others','--exclude-standard').splitlines())
    return {'HEAD_pristine':quiet,'index_pristine':index,'nonignored_untracked_count':n,'verified':quiet and index and n==0}
def source_matches(expected):
    try:return physical()==expected and git_closure()['verified']
    except (OSError,ValueError):return False
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
    ensure(type(RAW_SOURCE) is str and re.fullmatch('[0-9a-f]{40}',RAW_SOURCE),'root-raw-source-pin-required')
    ensure(type(BASE) is str and re.fullmatch('[0-9a-f]{40}',BASE) and type(WORKFLOW_SHA) is str and re.fullmatch('[0-9a-f]{64}',WORKFLOW_SHA),'root-source-pins-required')
    ensure(Path.cwd().resolve()==Path(git('rev-parse','--show-toplevel').decode().strip()).resolve(),'physical-Git-root')
    ensure(bool(os.environ.get('RUNNER_TEMP')) and Path(os.environ['RUNNER_TEMP']).is_dir() and not within(OUT,Path.cwd()),'outside-hosted-output')
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
    pure=layout(PURE_PRODUCT_BASE);prior=layout(SOURCE_PARENT);raw_source=layout(RAW_SOURCE);baseline=layout(BASE);current=layout('HEAD')
    differences={path for path in set(pure)|set(prior) if pure.get(path)!=prior.get(path)}
    ensure(differences==REVIEWED_PRODUCT_METADATA|set(APPROVED_BASE_TEST_DELTAS),'pure-to-source-parent-nine-metadata-four-reviewed-tests')
    for path,pin in APPROVED_BASE_TEST_DELTAS.items():
        ensure(pure[path][0]==prior[path][0]==pin['mode']=='100644' and digest(git('show',PURE_PRODUCT_BASE+':'+path))==pin['before'] and digest(git('show',SOURCE_PARENT+':'+path))==pin['after'],'exact-approved-source-parent-test-before-after-modes')
    for ancestor,descendant in [(SOURCE_PARENT,RAW_SOURCE),(RAW_SOURCE,BASE)]:
        ensure(subprocess.run(['git','merge-base','--is-ancestor',ancestor,descendant]).returncode==0,'reviewed-diagnostic-source-ancestry')
    ensure(set(prior)==set(raw_source)==set(baseline),'diagnostic-source-inventory-fixed')
    ensure({p for p in prior if prior[p]!=raw_source[p]}==set(DIAGNOSTIC_SOURCE_PINS),'exact-four-raw-diagnostic-source-paths')
    ensure({p for p in raw_source if raw_source[p]!=baseline[p]}<=set(DIAGNOSTIC_SOURCE_PINS),'canonical-format-only-owned-four-source-paths')
    for path,pin in DIAGNOSTIC_SOURCE_PINS.items():
        ensure(prior[path][0]==raw_source[path][0]==baseline[path][0]==pin['mode']=='100644'
            and digest(git('show',SOURCE_PARENT+':'+path))==pin['before_sha256']
            and digest(git('show',RAW_SOURCE+':'+path))==pin['raw_sha256']
            and digest(git('show',BASE+':'+path))==pin['canonical_sha256'],'reviewed-four-full-before-raw-canonical-source-hashes')
    full_differences={path for path in set(pure)|set(baseline) if pure.get(path)!=baseline.get(path)}
    reviewed_Rust=set(APPROVED_BASE_TEST_DELTAS)|set(DIAGNOSTIC_SOURCE_PINS)
    ensure(len(reviewed_Rust)==7 and full_differences==REVIEWED_PRODUCT_METADATA|reviewed_Rust,'pure-to-BASE-nine-metadata-seven-reviewed-Rust-deltas')
    ensure(SELF in baseline and WORKFLOW in baseline and set(current)==set(baseline),'exact-BASE-inventory-two-existing-owned-metadata')
    ensure(all(baseline[path][0]=='100644' for path in [SELF,WORKFLOW]),'owned-existing-regular-metadata-modes')
    ensure(subprocess.run(['git','diff','--quiet','HEAD']).returncode==0,'HEAD-pristine')
    for path,(mode,oid) in current.items():
        p=Path(path);ensure(within(p,Path.cwd()),'every-tracked-path-within-checkout');s=p.lstat();link=stat.S_ISLNK(s.st_mode);expected=baseline.get(path,('100644',None))
        ensure(mode==expected[0] and link==(mode=='120000') and (link or stat.S_ISREG(s.st_mode))
            and (link or bool(s.st_mode&0o111)==(mode=='100755')),'whole-source-modes')
        data=os.fsencode(os.readlink(p)) if link else p.read_bytes()
        actual=hashlib.sha1(b'blob '+str(len(data)).encode()+b'\0'+data).hexdigest()
        ensure(actual==oid and (path in {SELF,WORKFLOW} or actual==expected[1]),'whole-BASE-and-HEAD-content')
    ensure(digest(Path(WORKFLOW).read_bytes())==WORKFLOW_SHA,'exact-owned-workflow')
    ensure(digest(Path(FIXTURE).read_bytes())==FIXTURE_SHA and digest(Path(PARENT).read_bytes())==PARENT_SHA,'immutable-original-five-fixture-parent')
    parent=Path(PARENT).read_text();start=parent.index('async fn wait_for_automatic_phase_with_approvals(');end=parent.index('\n}\n',start)+3
    ensure(digest(parent[start:end].encode())==STRICT_HELPER_SHA,'reviewed-helper-with-timeout-only-diagnostics')
    wait_end=parent.index('    .unwrap_or_else(|_| {',start)
    ensure(digest(parent[start:wait_end].encode())==STRICT_WAIT_LOOP_SHA,'byte-original-15s-positive-wait-loop')
    for path,sha in HELPER_PINS.items():ensure(digest(Path(path).read_bytes())==sha,'immutable-oracle-helper-blob')
    text=Path(NATIVE_HELPER).read_text();begin='# NATIVE5_IMMUTABLE_ORACLE_BEGIN\n';endmark='# NATIVE5_IMMUTABLE_ORACLE_END\n'
    ensure(text.count(begin)==text.count(endmark)==1 and digest(text.split(begin,1)[1].split(endmark,1)[0].encode())==ORACLE_SHA,'immutable-five-oracle-region')
    ensure(git_closure()['verified'],'tracked-index-untracked-admission-closure')
    return {'head':head,'baseline':BASE,'whole_source_modes_verified':True,'Rust_exceptions':[],
        'old_guards_or_main_called':False,'old_module_globals_mutated':False,'historical_runtime_reused':False,'pure_product_source':PURE_PRODUCT_BASE,'pure_to_BASE_reviewed_metadata_test_and_diagnostic_union_verified':True,'reviewed_product_metadata_paths':sorted(REVIEWED_PRODUCT_METADATA),'approved_immutable_source_parent_test_deltas':APPROVED_BASE_TEST_DELTAS,'diagnostic_source_parent':SOURCE_PARENT,'raw_source':RAW_SOURCE,'diagnostic_source_lineage_verified':True,'original_positive_wait_loop_sha256':STRICT_WAIT_LOOP_SHA,'diagnostic_observation_overhead_present':True,'existing_optional_trace_SQL_reads_possible':True,'new_Core_queries_or_product_fix_claimed':False,'all_HEAD_Rust_exact_BASE':True,
        'owned_existing_metadata_content_bound_to_HEAD':[SELF,WORKFLOW],'readiness_PFP_rerun_on_this_HEAD_claimed':False}

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


def required_count(mode):return {'five':1,'sixteen':16,'both':17,'observations':4,'observations-five':2}[mode]

def selected_cases(mode):
    five=[('five',native.SUFFIX,native.NAME,None)]
    if mode=='five':return five
    rows=list(ack.CASES)
    ensure(len(rows)==16 and all(type(row) in (list,tuple) and len(row)==4 for row in rows)
        and all(len({row[i] for row in rows})==16 for i in [0,1,2])
        and {'policy','stress_0','stress_1','stress_2','paused_clock'}<={row[0] for row in rows},'original-exact-sixteen-inventory')
    ensure(all(type(label) is str and type(suffix) is str and type(name) is str and name.endswith(suffix) for label,suffix,name,_ in rows),'exact-source-case-names')
    if mode in OBSERVATION_MODES:
        indexed={row[0]:row for row in five+rows}
        labels=OBSERVATION_FIVE_LABELS if mode=='observations-five' else OBSERVATION_LABELS
        result=[indexed[label] for label in labels]
        ensure(len(result)==required_count(mode) and len({row[2] for row in result})==required_count(mode),'exact-selected-original-observation-cases')
        return result
    if mode=='both':
        result=five+rows
        ensure(len(result)==17 and len({row[0] for row in result})==17 and len({row[2] for row in result})==17
            and result[0]==five[0] and result[1:]==rows,'strict-five-first-plus-all-sixteen-distinct-once')
        return result
    return rows

def cohort_totals(cases,mode):
    result={}
    for cohort,size in [('five',1),('sixteen',16)]:
        expected=(1 if cohort=='five' or mode=='observations-five' else 3) if mode in OBSERVATION_MODES else (size if mode in (cohort,'both') else 0)
        rows=[row for row in cases if row.get('cohort')==cohort]
        result[cohort]=aggregate(rows,expected)
        result[cohort]['required']=expected>0
        if mode in OBSERVATION_MODES:result[cohort]['selected_subset_not_full_sixteen']=cohort=='sixteen'
        result[cohort]['all_original_cases_green']=None if expected==0 else len(rows)==expected and all(row.get('oracle_green') is True for row in rows)
    return result

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

# Fixed source-owned observations only. They never authorize an original PASS.
OBSERVATION_LABELS=('policy','five','original_2','stress_1')
OBSERVATION_FIVE_LABELS=('policy','five')
OBSERVATION_MODES=('observations','observations-five')
PHASES=('AwaitingSetup','AwaitingPeer','ComparisonAvailable','AwaitingPeerVerification','VerificationCompleteEnrollmentPending','Cancelled','Expired','Failed','EnrollmentComplete')
REASONS=('VerifierFallback','NoRound','GuardInvalid','NoSettledRoster','SharingPending','Complete')
RPC_STAGES=('DispatchStarted','WorkerStarted','WorkerReturned','FacadeReturned','AutomaticEntered','AutomaticExited')
STAGES=('initial-two-comparison','initial-two-completion','initial-two-completed','initial-chat-mirrored','third-device-comparison','third-device-completion','third-device-completed','fourth-device-comparison','sibling-consent-held-before-peer-progress','automatic-publication-held-before-completion','fourth-device-completion','fourth-device-completed')
NUM=r'(?:0|[1-9][0-9]{0,19})'
POLICY_FILE='crates/marmot-app/src/runtime/tests.rs'
POLICY_NAME='runtime::tests::async_suites_choose_their_tokio_flavor'
POLICY_PREFIX='use #[tokio::test(flavor = "multi_thread", worker_threads = 2)], run_composed_app_runtime_test, or a multi-thread runtime builder; pin one thread (a current_thread flavor, the one-thread composed runner, or a current-thread builder) only under a `//` comment saying why: '

def observation_uint(value):
    ensure(re.fullmatch(NUM,value) is not None and int(value)<1<<64,'observation-u64');return int(value)
def observation_array(value,size):
    ensure(re.fullmatch(r'\['+', '.join([NUM]*size)+r'\]',value) is not None,'fixed-observation-array')
    return [observation_uint(item) for item in value[1:-1].split(', ')]
def observation_option_array(value,size):
    if value=='None':return None
    ensure(value.startswith('Some(') and value.endswith(')'),'optional-observation-array')
    return observation_array(value[5:-1],size)
def observation_completion(value):
    if value=='None':return None
    m=re.fullmatch(r'Some\(\((true|false), (None|Some\('+NUM+r'\)), ('+NUM+'), ('+NUM+r')\)\)',value)
    ensure(m is not None,'fixed-completion-tuple')
    ensure(observation_uint(m[4])<=observation_uint(m[3]),'completed-subset-of-child-count')
    return {'primary_committed':m[1]=='true','expected':None if m[2]=='None' else observation_uint(m[2][5:-1]),'children':observation_uint(m[3]),'completed':observation_uint(m[4])}
def observation_rpc(value):
    if value=='None':return None
    arr=r'\['+', '.join([NUM]*6)+r'\]'
    m=re.fullmatch(r'Some\(\(('+arr+'), ('+arr+r'), (None|Some\(\(('+'|'.join(REASONS)+'), ('+NUM+r')\)\))\)\)',value)
    ensure(m is not None,'fixed-native-RPC-tuple')
    return {'counts':observation_array(m[1],6),'last_elapsed_millis':observation_array(m[2],6),'last_reason':None if m[3]=='None' else m[4],'last_reason_elapsed_millis':None if m[3]=='None' else observation_uint(m[5]),'stage_order':list(RPC_STAGES),'per_original_clock_not_common_join_clock':True,'AutomaticExited_is_not_result_success':True}
def observed_stage(raw):
    lines=[line for line in raw.splitlines() if 'automatic-enrollment-control stage=' in line]
    ensure(len(lines)<=128,'bounded-source-stage-observations');values=[]
    for line in lines:
        m=re.fullmatch(r'automatic-enrollment-control stage=('+'|'.join(STAGES)+')',line)
        ensure(m is not None,'finite-source-stage');values.append(m[1])
    return {'available':bool(values),'last':values[-1] if values else None,'record_count':len(values),'names_are_fixture_progress_not_worker_timestamps':True}
def observed_phase(raw,name):
    needle='automatic pairing did not reach required phase:'
    lines=[line for line in raw.splitlines() if needle in line]
    if not lines:return {'available':False,'expected':None,'observed_pair':None}
    ensure(len(lines)==1 and len(lines[0])<=1024,'one-finite-phase-failure')
    phases='|'.join(PHASES)
    m=re.fullmatch(re.escape(needle)+r' expected=('+phases+r') observed=(None|Some\(\(('+phases+'), ('+phases+r')\)\))',lines[0])
    ensure(m is not None,'closed-phase-expected-observed')
    source=Path(PARENT).read_text().splitlines();hits=[i+1 for i,line in enumerate(source) if 'panic!("automatic pairing did not reach required phase:' in line]
    ensure(len(hits)==1,'unique-source-phase-panic')
    header=r"(?m)^thread '"+re.escape(name)+r"'(?: \([1-9][0-9]{0,9}\))? panicked at "+re.escape(PARENT)+':'+str(hits[0])+r':9:\n'+re.escape(lines[0])+r'$'
    ensure(len(re.findall(header,raw))==1,'phase-payload-bound-to-selected-source-panic')
    return {'available':True,'expected':m[1],'observed_pair':None if m[2]=='None' else [m[3],m[4]],'observed_None_is_unknown':m[2]=='None','after_timeout_not_joint_predicate_at_deadline':True}
def observed_sides(raw):
    aggregate=[line for line in raw.splitlines() if 'automatic-enrollment-control side=' in line and ' primary/expected/children/completed=' in line]
    rpc=[line for line in raw.splitlines() if 'automatic-enrollment-control side=' in line and ' native_rpc_counts/elapsed_ms/branch=' in line]
    ensure(len(aggregate) in (0,2) and len(rpc) in (0,2),'zero-or-two-source-side-records')
    result=[]
    for index,side in enumerate(('left','right')):
        row={'side':side,'completion':None,'native_RPC':None,'aggregate_record_present':bool(aggregate),'RPC_record_present':bool(rpc)}
        if aggregate:
            ensure(len(aggregate[index].encode())<=4096,'bounded-aggregate-record')
            m=re.fullmatch('automatic-enrollment-control side='+side+r' primary/expected/children/completed=(.+) intake=(.+) rejections=(.+) context_rejections=(.+) projection=(.+)',aggregate[index])
            ensure(m is not None,'ordered-source-side-aggregate')
            row['completion']=observation_completion(m[1]);row['intake']=observation_option_array(m[2],8);row['rejections']=observation_option_array(m[3],4);row['context_rejections']=observation_option_array(m[4],9);row['projection']=observation_option_array(m[5],4)
        if rpc:
            prefix='automatic-enrollment-control side='+side+' native_rpc_counts/elapsed_ms/branch='
            ensure(rpc[index].startswith(prefix) and len(rpc[index].encode())<=2048,'ordered-bounded-source-RPC')
            row['native_RPC']=observation_rpc(rpc[index][len(prefix):])
        result.append(row)
    return {'available':bool(aggregate or rpc),'rows':result,'independent_getters_not_joint_snapshot':True,'post_timeout_only':True,'missing_None_never_zero_work':True,'child_channel_Debug_exported':False}
def source_policy_offender(path,line,read_source):
    source=read_source(path).splitlines();ensure(0<line<=len(source),'tracked-policy-line')
    text=source[line-1].strip();previous=source[line-2].strip() if line>1 else ''
    pinned=text=='#[tokio::test(flavor = "current_thread")]' or 'Builder::new_current_thread()' in text or text.removeprefix('crate::tests::').startswith('run_composed_app_runtime_test_on_one_thread(')
    ensure(text=='#[tokio::test]' or (pinned and (not previous.startswith('//') or previous.startswith('///'))),'actual-source-policy-offender')

def source_function(path,line,read_source):
    source=read_source(path).splitlines();ensure(0<line<=len(source),'tracked-source-line')
    fn=r'\s*(?:pub(?:\([^)]*\))?\s+)?(?:async\s+)?fn\s+([A-Za-z_][A-Za-z0-9_]*)\b'
    if source[line-1].strip().startswith('#['):
        for text in source[line:min(line+8,len(source))]:
            m=re.match(fn,text)
            if m:return m[1]
    for text in reversed(source[:line]):
        m=re.match(fn,text)
        if m:return m[1]
    return None

def observed_policy(raw,name,tracked,read_source=None,root=None):
    read_source=read_source or (lambda path:Path(path).read_text());root=root or str(Path.cwd().resolve())
    if POLICY_PREFIX not in raw:return {'available':False,'offenders':None}
    ensure(name==POLICY_NAME and raw.count(POLICY_PREFIX)==1,'policy-case-and-unique-static-payload')
    source=read_source(POLICY_FILE).splitlines();sites=[i+1 for i,line in enumerate(source) if line.strip()=='offenders.is_empty(),'];ensure(len(sites)==1,'unique-policy-assertion')
    assert_line=sites[0]-1
    m=re.search(r"(?m)^thread '"+re.escape(name)+r"'(?: \([1-9][0-9]{0,9}\))? panicked at "+re.escape(POLICY_FILE)+':'+str(assert_line)+r':5:\n'+re.escape(POLICY_PREFIX)+r'\[\n((?:[^\n]*\n){1,64})\]',raw)
    ensure(m is not None,'source-owned-policy-panic-and-closed-array')
    rows=[]
    for text in m[1].splitlines():
        item=re.fullmatch(r'    "([A-Za-z0-9_./-]+):([1-9][0-9]{0,6})",',text);ensure(item is not None,'policy-source-path-line-only')
        path=item[1];path=path[len(root)+1:] if path.startswith(root+'/') else path
        ensure(path in tracked and path.endswith('.rs') and path.startswith(('crates/marmot-app/src/','crates/marmot-app/tests/')),'policy-tracked-known-Rust-path')
        line=int(item[2]);source_policy_offender(path,line,read_source);function=source_function(path,line,read_source);ensure(function is not None,'policy-known-source-function')
        rows.append({'file':path,'line':line,'function':function})
    ensure(0<len(rows)<=64 and len({(row['file'],row['line']) for row in rows})==len(rows),'bounded-distinct-source-offenders')
    return {'available':True,'offenders':rows,'source_owned_assertion_site':{'file':POLICY_FILE,'line':assert_line,'column':5},'raw_panic_payload_exported':False}
# This existing diagnostic type is a five-field numeric/finite-enum snapshot,
# not the State/Channel Debug representation. Periodic masks may be stale.
MAINTENANCE_FAILURES=('Owner','Collection','Runtime','Engine','Genesis','Gate','PrivateInvite')
PUBLICATION_STAGES=('BeforeCoreWrap','AfterCoreWrap','BeforeRelayPublication','AfterRelayPublication')

def approval_snapshot(value):
    if value=='None':return None
    failure='|'.join(MAINTENANCE_FAILURES);stage='|'.join(PUBLICATION_STAGES)
    m=re.fullmatch(r'Some\(\(('+NUM+'), ('+NUM+'), ('+NUM+r'), (None|Some\(('+failure+r')\)), (None|Some\(('+stage+r')\))\)\)',value)
    ensure(m is not None,'closed-five-field-approval-snapshot')
    bits=observation_uint(m[1]);visits=observation_uint(m[2]);failures=observation_uint(m[3])
    ensure(bits<=255 and failures<=visits,'approval-mask-width-and-visit-failure-coherence')
    return {'last_periodic_mask':bits,'periodic_visits':visits,'periodic_failures':failures,
        'last_failure':None if m[4]=='None' else m[5],'publication_stage':None if m[6]=='None' else m[7]}

def observed_approvals(raw):
    lines=[line for line in raw.splitlines() if 'automatic-enrollment-control existing_index=' in line]
    ensure(len(lines)<=128,'bounded-existing-approval-rows');rows=[]
    for line in lines:
        ensure(len(line.encode())<=512,'bounded-existing-approval-line')
        m=re.fullmatch(r'automatic-enrollment-control existing_index=('+NUM+r') child_channel=(.+)',line)
        ensure(m is not None,'exact-existing-approval-record')
        index=observation_uint(m[1]);ensure(index<128,'bounded-existing-approval-index')
        rows.append({'index':index,'snapshot':approval_snapshot(m[2])})
    ensure([row['index'] for row in rows]==list(range(len(rows))),'unique-ordered-complete-prefix-approval-indices')
    return {'schema_known':True,'available':bool(rows),'record_count':len(rows),'rows':rows,
        'fifth_join_evidence_known':None,'all_three_actual_snapshots_present':None,'fifth_A_C_D_mapping_available':False,'partial_or_unknown':True,'fixture_installations_by_index':None,
        'periodic_mask_not_current_state':True,'publication_stage_not_result_success':True,
        'separate_getters_not_joint_snapshot':True,'raw_State_or_Channel_Debug_exported':False}

def bind_fifth_approvals(parsed,original,side_result):
    # The immutable fixture's final join is B->E; its ascending non-sponsor
    # existing approvals are A,C,D. Never apply that mapping to an earlier join.
    facts=original.get('facts') if type(original) is dict else None
    sides=side_result.get('rows') if type(side_result) is dict else None
    right=(sides[1].get('completion') if type(sides) is list and len(sides)==2 and sides[1].get('side')=='right' else None)
    fifth=type(facts) is dict and type(facts.get('completed_steps')) is int and facts['completed_steps']==3 and type(right) is dict and type(right.get('expected')) is int and right['expected']==3
    complete=parsed.get('schema_known') is True and parsed.get('record_count')==3 and [row.get('index') for row in parsed.get('rows',[])]==[0,1,2] and all(row.get('snapshot') is not None for row in parsed.get('rows',[]))
    parsed['fifth_join_evidence_known']=bool(fifth)
    parsed['all_three_actual_snapshots_present']=bool(complete)
    parsed['fifth_A_C_D_mapping_available']=bool(fifth and complete)
    parsed['partial_or_unknown']=not (fifth and complete)
    parsed['fixture_installations_by_index']=['A','C','D'] if fifth and complete else None
    return parsed

def approval_controls():
    value='Some((255, 3, 1, Some(Engine), Some(AfterRelayPublication)))'
    ensure(approval_snapshot(value)['last_failure']=='Engine','approval-known-finite-positive')
    ensure(approval_snapshot('Some((0, 0, 0, None, None))')['publication_stage'] is None,'approval-default-unknown-positive')
    ensure(approval_snapshot('None') is None,'approval-unavailable-positive')
    raw='\n'.join('automatic-enrollment-control existing_index='+str(i)+' child_channel='+value for i in range(3))
    original={'facts':{'completed_steps':3}};sides={'rows':[{'side':'left','completion':None},{'side':'right','completion':{'expected':3}}]}
    bound=bind_fifth_approvals(observed_approvals(raw),original,sides)
    ensure(bound['fifth_A_C_D_mapping_available'] is True and bound['fixture_installations_by_index']==['A','C','D'],'actual-fifth-complete-binding-positive')
    none=raw.replace('existing_index=1 child_channel='+value,'existing_index=1 child_channel=None')
    ensure(bind_fifth_approvals(observed_approvals(none),original,sides)['fixture_installations_by_index'] is None,'None-snapshot-not-role-bound-positive')
    ensure(bind_fifth_approvals(observed_approvals(raw),{'facts':{'completed_steps':2}},sides)['fixture_installations_by_index'] is None,'earlier-failure-not-fifth-role-bound-positive')
    ensure(bind_fifth_approvals(observed_approvals(raw),original,{'rows':[]})['fixture_installations_by_index'] is None,'missing-right-expected-not-role-bound-positive')
    ensure(bind_fifth_approvals(observed_approvals('\n'.join(raw.splitlines()[:2])),original,sides)['fixture_installations_by_index'] is None,'partial-rows-not-role-bound-positive')
    ensure(bind_fifth_approvals(observed_approvals(''),original,sides)['partial_or_unknown'] is True,'missing-rows-unknown-positive')
    maximum='Some((255, 18446744073709551615, 18446744073709551615, Some(PrivateInvite), Some(BeforeCoreWrap)))'
    ensure(approval_snapshot(maximum)['periodic_visits']==(1<<64)-1,'approval-width-maximum-positive')
    invalid=[value.replace('255','256'),value.replace('3, 1','1, 2'),value.replace('Some(Engine)','Some(PRIVATE)'),value.replace('Some(AfterRelayPublication)','Some(PRIVATE)'),value.replace('Some((255','Some(255'),value.replace('3, 1','18446744073709551616, 1'),value.replace('255','-1'),value.replace('255','true'),value+' PRIVATE',value.replace(', 3, 1',', 3')]
    for bad in invalid:
        try:approval_snapshot(bad);accepted=True
        except (ValueError,TypeError,OverflowError):accepted=False
        ensure(not accepted,'invalid-approval-schema-not-exported')
    bad_rows=[raw+'\n'+raw.splitlines()[0],raw.replace('existing_index=1','existing_index=0'),raw.replace('existing_index=1','existing_index=3'),raw.replace('existing_index=2','existing_index=128'),raw.replace(' child_channel=',' account=PRIVATE child_channel='),raw.replace(value,'PRIVATE'),raw+' PRIVATE']
    for bad in bad_rows:
        try:observed_approvals(bad);accepted=True
        except (ValueError,TypeError,OverflowError):accepted=False
        ensure(not accepted,'invalid-approval-records-not-exported')
    for facts,sample in [({'facts':{'completed_steps':True}},sides),(original,{'rows':[{'side':'left'},{'side':'right','completion':{'expected':True}}]})]:
        ensure(bind_fifth_approvals(observed_approvals(raw),facts,sample)['fixture_installations_by_index'] is None,'bool-not-fifth-count')
    return {'positive':10,'negative':len(invalid)+len(bad_rows)+2,'runtime_bodies':0,'raw_private_export':False}

# Exact already-printed Option<Vec<SiblingMaintenanceSnapshot>> only.
# Vector iteration order is not a source-peer identity or transport FIFO.
def child_snapshots(value):
    ensure(len(value.encode())<=32768,'bounded-child-vector-Debug-value')
    if value=='None':return None
    failure='|'.join(MAINTENANCE_FAILURES);stage='|'.join(PUBLICATION_STAGES)
    item=r'\('+NUM+', '+NUM+', '+NUM+r', (?:None|Some\((?:'+failure+r')\)), (?:None|Some\((?:'+stage+r')\))\)'
    ensure(re.fullmatch(r'Some\(\[(?:'+item+r'(?:, '+item+r')*)?\]\)',value) is not None,'exact-optional-vector-of-five-field-tuples')
    inner=value[6:-2];tuples=list(re.finditer(item,inner))
    ensure(len(tuples)<=128,'maximum-128-child-snapshots')
    return [{'vector_index':index,**approval_snapshot('Some('+match[0]+')')} for index,match in enumerate(tuples)]

def observed_children(raw):
    lines=[line for line in raw.splitlines() if 'automatic-enrollment-control side=' in line and ' child_channels=' in line]
    ensure(len(lines) in (0,2),'zero-or-exactly-two-child-vector-records')
    rows=[]
    for index,side in enumerate(('left','right')):
        snapshots=None
        if lines:
            prefix='automatic-enrollment-control side='+side+' child_channels='
            ensure(lines[index].startswith(prefix) and len(lines[index].encode())<=32896,'ordered-bounded-child-vector-record')
            snapshots=child_snapshots(lines[index][len(prefix):])
        rows.append({'side':side,'record_present':bool(lines),'snapshots':snapshots,'snapshot_count':None if snapshots is None else len(snapshots)})
    return {'schema_known':True,'available':bool(lines),'rows':rows,
        'vector_order_is_not_peer_identity_or_transport_FIFO':True,
        'peer_labels_available':False,'last_periodic_masks_not_current_state':True,
        'publication_stage_not_result_success':True,'independent_from_side_aggregate_and_other_getters':True,
        'after_timeout_not_before_deadline_proof':True,'raw_State_or_Channel_Debug_exported':False}

def child_controls():
    item='(11, 4, 0, None, Some(AfterRelayPublication))'
    vector=lambda values:'Some(['+', '.join(values)+'])'
    ensure(child_snapshots('None') is None,'child-outer-None-unknown-positive')
    ensure(child_snapshots('Some([])')==[],'actual-empty-child-vector-positive')
    ensure(child_snapshots(vector([item]))[0]['last_periodic_mask']==11,'one-actual-child-tuple-positive')
    ensure([v['vector_index'] for v in child_snapshots(vector([item]*3))]==[0,1,2],'three-unlabeled-child-tuples-positive')
    maximum='(255, 18446744073709551615, 18446744073709551615, Some(PrivateInvite), Some(BeforeRelayPublication))'
    cap=vector([maximum]*128)
    ensure(len(child_snapshots(cap))==128 and len(cap.encode())<=32768,'128-maxwidth-child-tuples-positive')
    pair='automatic-enrollment-control side=left child_channels=Some([])\nautomatic-enrollment-control side=right child_channels='+vector([item]*3)
    result=observed_children(pair)
    ensure(result['rows'][0]['snapshot_count']==0 and result['rows'][1]['snapshot_count']==3 and result['peer_labels_available'] is False,'ordered-two-source-side-vectors-positive')
    unavailable=observed_children(pair.replace('Some([])','None'))
    ensure(unavailable['rows'][0]['snapshot_count'] is None and unavailable['rows'][1]['snapshot_count']==3,'None-side-keeps-other-side-positive')
    ensure(observed_children('')['available'] is False,'absent-records-unknown-positive')
    ensure('PRIVATE' not in json.dumps(result) and not result['peer_labels_available'],'closed-unlabeled-child-output-positive')
    bad_values=[vector([maximum]*129),vector([item.replace('11','256')]),vector([item.replace('4, 0','0, 1')]),vector([item.replace('4, 0','18446744073709551616, 0')]),vector([item.replace('AfterRelayPublication','PRIVATE')]),vector([item.replace('None','Some(PRIVATE)')]),vector(['None']),vector(['Some('+item+')']),vector([item])+', PRIVATE',vector([item])+')',vector([item]).replace(', None',', None, None'),vector([item]).replace('11','-1'),vector([item]).replace('11','true'),'Some([PRIVATE])','Some([[11, 4, 0, None, None]])','Some(['+item+',])','Some(['+item+' '+item+'])']
    for value in bad_values:
        try:child_snapshots(value);accepted=True
        except (ValueError,TypeError,OverflowError):accepted=False
        ensure(not accepted,'private-malformed-overbound-child-vector-rejected')
    bad_rows=[pair+'\n'+pair.splitlines()[0],pair.splitlines()[0],pair.replace('side=right','side=left'),pair.replace('side=right','side=PRIVATE'),pair.replace(' child_channels=',' scope=PRIVATE child_channels='),pair+' PRIVATE','\n'.join(reversed(pair.splitlines()))]
    for raw in bad_rows:
        try:observed_children(raw);accepted=True
        except (ValueError,TypeError,OverflowError):accepted=False
        ensure(not accepted,'foreign-duplicate-partial-trailing-child-record-rejected')
    ensure(child_snapshots('None') is None and child_snapshots('Some([])') is not None,'outerNone-not-empty-vector')
    return {'positive':10,'negative':len(bad_values)+len(bad_rows),'runtime_bodies':0,'raw_private_export':False,'max_vector_entries':128,'max_value_bytes':32768}

# Existing observer projection only: never exports its MessageId or Instants.
def notification_entry(value):
    if value=='None':return None
    arr8=r'\['+', '.join([NUM]*8)+r'\]';arr6=r'\['+', '.join([NUM]*6)+r'\]'
    m=re.fullmatch(r'Some\(\(('+arr8+'), ('+arr6+r'), (None|Some\(\(('+NUM+'), ('+NUM+r')\)\)), ('+NUM+r'), (true|false), (true|false)\)\)',value)
    ensure(m is not None,'closed-existing-notification-entry')
    dispatch=observation_array(m[1],8);placement=observation_array(m[2],6)
    depth=None if m[3]=='None' else [observation_uint(m[4]),observation_uint(m[5])]
    dequeued=observation_uint(m[6]);first=m[7]=='true';invalid=m[8]=='true'
    ensure(depth is None or (max(depth)<=1025 and placement[0]>0),'source-queue-depth-bounds-and-actual-acceptance')
    ensure(first==(dequeued>0),'actual-dequeue-and-first-callback-presence')
    return {'dispatch_counts':dispatch,'placement_counts':placement,'first_accepted_depths':depth,'Delivery_dequeue_callbacks':dequeued,'first_dequeue_present':first,'invalid':invalid}

def observed_notifications(raw):
    lines=[line for line in raw.splitlines() if 'automatic-enrollment-control existing_index=' in line and ' latest_prepared_id_available=' in line]
    ensure(len(lines)<=128,'bounded-existing-source-notification-rows');rows=[]
    for line in lines:
        ensure(len(line.encode())<=2048,'bounded-existing-source-notification-line')
        m=re.fullmatch(r'automatic-enrollment-control existing_index=('+NUM+r') latest_prepared_id_available=(true|false) recipient_notification=(.+)',line)
        ensure(m is not None,'exact-existing-source-notification-line')
        index=observation_uint(m[1]);ensure(index<128,'bounded-source-notification-index')
        entry=notification_entry(m[3]);available=m[2]=='true'
        ensure(available or entry is None,'no-entry-without-captured-publication-key')
        rows.append({'index':index,'publication_id_available':available,'entry':entry})
    ensure([v['index'] for v in rows]==list(range(len(rows))),'source-notification-ordered-unique-indices')
    return {'schema_known':True,'available':bool(rows),'rows':rows,'publication_kind':'UNKNOWN',
        'captured_latest_prepared_key_not_current_publication':True,'separate_source_and_receiver_getters':True,
        'None_is_unknown_cap_512_or_missing_not_absence':True,'full_queue_or_protocol_history_claimed':False,
        'depths_not_atomic_FIFO_position':True,'dequeue_before_App_owner_Core_filters':True,'IDs_and_Instants_exported':False}

TRACE_CATEGORIES={'outer_authentication':('unsupported','not_ready','closed','stale_revision','runtime_unavailable'),
    'sibling_dispatch':('consumed','not_consumed','unsupported','not_ready','closed','stale_revision','runtime_unavailable'),
    'automatic_dispatch_result':('consumed','not_consumed','unsupported','not_ready','closed','stale_revision','runtime_unavailable')}
def observed_ingress_trace(raw):
    prefix='rejoin boundary diagnostic: stage=';records=[];other=0
    lines=[line for line in raw.splitlines() if line.startswith(prefix)]
    ensure(len(lines)<=1024,'bounded-existing-trace-boundary-lines')
    for line in lines:
        stage=line[len(prefix):].split(', ',1)[0]
        if stage not in TRACE_CATEGORIES:other+=1;continue
        ensure(len(line)<=256,'bounded-selected-trace-line')
        m=re.fullmatch(re.escape(prefix+stage)+r', category=('+'|'.join(TRACE_CATEGORIES[stage])+r'), owner=recipient',line)
        ensure(m is not None,'selected-trace-finite-category-exact-owner')
        records.append({'stage':stage,'category':m[1],'owner':'recipient'})
    ensure(len(records)<=19 and len({(v['stage'],v['category']) for v in records})==len(records),'deduplicated-finite-selected-boundaries')
    return {'schema_known':True,'available':bool(records),'records':records,'selected_record_count':len(records),
        'other_boundary_lines_not_exported':other,'root_armed_only_for_fifth_join':True,
        'records_are_deduplicated_categories_not_attempt_or_message_counts':True,
        'capture_complete':False,'missing_records_not_no_ingest_proof':True,
        'existing_optional_catalog_SQL_diagnostics_may_run':True,'new_Core_queries':False,'raw_output_exported':False}

def boundary_controls():
    value='Some(([0, 0, 0, 0, 0, 1, 0, 1], [1, 0, 0, 0, 0, 0], Some((0, 1)), 1, true, false))'
    ensure(notification_entry(value)['Delivery_dequeue_callbacks']==1,'existing-notification-positive')
    ensure(notification_entry('None') is None,'missing-entry-unknown-positive')
    zero='Some(([0, 0, 0, 0, 0, 0, 0, 0], [0, 0, 0, 0, 0, 0], None, 0, false, false))'
    ensure(notification_entry(zero)['Delivery_dequeue_callbacks']==0,'typed-zero-entry-not-missing-positive')
    none='automatic-enrollment-control existing_index=0 latest_prepared_id_available=false recipient_notification=None'
    true_none=none.replace('=false','=true')
    ensure(not observed_notifications(none)['rows'][0]['publication_id_available'],'missing-key-distinct-positive')
    ensure(observed_notifications(true_none)['rows'][0]['entry'] is None,'captured-key-missing-entry-unknown-positive')
    row=none.replace('=false','=true').replace('notification=None','notification='+value)
    ensure(observed_notifications(row)['rows'][0]['entry']['first_accepted_depths']==[0,1],'captured-key-real-entry-positive')
    max_array=lambda n:'['+', '.join(['18446744073709551615']*n)+']'
    maximum='Some(('+max_array(8)+', '+max_array(6)+', Some((1025, 1025)), 18446744073709551615, true, true))'
    ensure(notification_entry(maximum)['invalid'] is True and len(row.replace(value,maximum).encode())<=2048,'maxwidth-closed-notification-positive')
    bad_values=[value+' PRIVATE',value.replace('Some((0, 1))','Some(0, 1)'),value.replace('Some((0, 1))','Some((0, 1026))'),value.replace('[1, 0, 0, 0, 0, 0]','[0, 0, 0, 0, 0, 0]'),value.replace('1, true, false))','0, true, false))'),value.replace('1, true, false))','1, false, false))'),value.replace('1, true, false))','18446744073709551616, true, false))'),value.replace('true','True'),value.replace('[1, 0, 0, 0, 0, 0]','[1, 0]')]
    for bad in bad_values:
        try:notification_entry(bad);accepted=True
        except (ValueError,TypeError,OverflowError):accepted=False
        ensure(not accepted,'invalid-existing-notification-rejected')
    many='\n'.join(row.replace('existing_index=0','existing_index='+str(i)) for i in range(128))
    ensure(len(observed_notifications(many)['rows'])==128,'128-source-row-bound-positive')
    bad_rows=[many+'\n'+row.replace('existing_index=0','existing_index=128'),row.replace('available=true','available=false'),row+'\n'+row,row.replace('existing_index=0','existing_index=1'),row.replace('existing_index=0','existing_index=128'),row+' PRIVATE']
    for bad in bad_rows:
        try:observed_notifications(bad);accepted=True
        except (ValueError,TypeError,OverflowError):accepted=False
        ensure(not accepted,'invalid-source-notification-row-rejected')
    trace='rejoin boundary diagnostic: stage=sibling_dispatch, category=consumed, owner=recipient'
    ensure(observed_ingress_trace(trace)['records']==[{'stage':'sibling_dispatch','category':'consumed','owner':'recipient'}],'existing-ingress-category-positive')
    ensure(observed_ingress_trace('')['available'] is False,'missing-ingress-unknown-positive')
    other='rejoin boundary diagnostic: stage=catalog_sql, category=PRIVATE, owner=recipient'
    ensure('PRIVATE' not in json.dumps(observed_ingress_trace(other)),'unselected-trace-not-exported-positive')
    bad_trace=[trace.replace('consumed','PRIVATE'),trace.replace('recipient','PRIVATE'),trace+' PRIVATE',trace+'\n'+trace,trace.replace('sibling_dispatch','outer_authentication'),trace.replace('category=consumed','category=consumed, peer=PRIVATE')]
    for bad in bad_trace:
        try:observed_ingress_trace(bad);accepted=True
        except (ValueError,TypeError,OverflowError):accepted=False
        ensure(not accepted,'private-or-incoherent-selected-trace-rejected')
    return {'positive':11,'negative':len(bad_values)+len(bad_rows)+len(bad_trace),'runtime_bodies':0,'raw_private_export':False}

def finite_observations(raw,name,tracked,include_approvals=False):
    text=re.sub(r'\x1b\[[0-?]*[ -/]*[@-~]','',raw)
    prefix=r'(?m)^test '+re.escape(name)+r' \.\.\. '
    if len(re.findall(prefix,text))>1:return {'schema_known':False,'available':None,'duplicate_selected_prefix':True,'raw_private_export':False}
    text=re.sub(prefix,lambda hit:hit[0]+'\n',text,count=1)
    result={'separate_from_original_verdict':True,'no_authority_or_before_deadline_claim':True,'SourcePolicyCommit':{'available':False,'count':None,'last_kind':None,'reason':'not_printed_by_current_frozen_Rust'},'child_channel_Debug_exported':False}
    for key,extract in [('fixture_stage',lambda:observed_stage(text)),('phase_timeout',lambda:observed_phase(text,name)),('side_aggregates',lambda:observed_sides(text)),('policy_offenders',lambda:observed_policy(text,name,tracked))]:
        try:result[key]=dict(schema_known=True,**extract())
        except (ValueError,TypeError,OverflowError,OSError):result[key]={'schema_known':False,'available':None,'values':None,'closed_schema_rejected':True}
    if include_approvals:
        try:result['existing_approvals']=observed_approvals(text)
        except (ValueError,TypeError,OverflowError):result['existing_approvals']={'schema_known':False,'available':None,'rows':None,'closed_schema_rejected':True}
        try:result['recipient_child_snapshots']=observed_children(text)
        except (ValueError,TypeError,OverflowError):result['recipient_child_snapshots']={'schema_known':False,'available':None,'rows':None,'closed_schema_rejected':True,'peer_labels_available':False}
        try:result['source_publication_notifications']=observed_notifications(text)
        except (ValueError,TypeError,OverflowError):result['source_publication_notifications']={'schema_known':False,'available':None,'rows':None,'closed_schema_rejected':True}
        try:result['recipient_ingress_trace']=observed_ingress_trace(text)
        except (ValueError,TypeError,OverflowError):result['recipient_ingress_trace']={'schema_known':False,'available':None,'records':None,'closed_schema_rejected':True}
    return result

def observation_controls():
    ensure(observation_completion('Some((true, Some(2), 2, 1))')['expected']==2,'completion-positive')
    ensure(observation_completion('None') is None,'completion-None-unknown')
    rpc='Some(([1, 2, 3, 4, 5, 6], [7, 8, 9, 10, 11, 12], Some((SharingPending, 13))))'
    ensure(observation_rpc(rpc)['last_reason']=='SharingPending','actual-nested-RPC-Some-positive')
    ensure(observation_rpc(rpc.replace('Some((SharingPending, 13))','None'))['last_reason'] is None,'actual-nested-RPC-reason-None-positive')
    ensure(observation_rpc('None') is None,'unavailable-RPC-positive')
    aggregate=lambda side:'automatic-enrollment-control side='+side+' primary/expected/children/completed=Some((true, Some(2), 2, 1)) intake=Some([0, 1, 2, 3, 4, 5, 6, 7]) rejections=Some([0, 1, 2, 3]) context_rejections=Some([0, 1, 2, 3, 4, 5, 6, 7, 8]) projection=Some([1, 2, 3, 4])'
    sample='\n'.join([aggregate(side) for side in ('left','right')]+['automatic-enrollment-control side='+side+' native_rpc_counts/elapsed_ms/branch='+rpc for side in ('left','right')])
    ensure(observed_sides(sample)['rows'][1]['native_RPC']['counts']==[1,2,3,4,5,6],'two-side-full-source-positive')
    ensure(not observed_sides('')['available'],'no-timeout-print-unknown-positive')
    ensure(observed_stage('automatic-enrollment-control stage=fourth-device-comparison')['last']=='fourth-device-comparison','known-last-stage-positive')
    path='crates/marmot-app/src/native_device_linking/tests/public_chat_delivery_acceptance.rs'
    read=lambda p:('line\n    assert!(\n        offenders.is_empty(),\n' if p==POLICY_FILE else '\n\n\n\n#[tokio::test]\n#[ignore = "known"]\nasync fn public_three_device_automatic_chats_and_messages() {}\n')
    policy="thread '"+POLICY_NAME+"' (123) panicked at "+POLICY_FILE+':2:5:\n'+POLICY_PREFIX+'[\n    "/public/'+path+':5",\n]\n'
    known={POLICY_FILE,path}
    ensure(observed_policy(policy,POLICY_NAME,known,read,'/public')['offenders']==[{'file':path,'line':5,'function':'public_three_device_automatic_chats_and_messages'}],'policy-known-source-projection-positive')
    phase_source=Path(PARENT).read_text().splitlines();phase_line=[i+1 for i,line in enumerate(phase_source) if 'panic!("automatic pairing did not reach required phase:' in line]
    ensure(len(phase_line)==1,'control-source-phase-site')
    phase_payload='automatic pairing did not reach required phase: expected=EnrollmentComplete observed=Some((EnrollmentComplete, VerificationCompleteEnrollmentPending))'
    phase_header="thread 'source::case' (123) panicked at "+PARENT+':'+str(phase_line[0])+':9:\n'
    phase_raw=phase_header+phase_payload+'\n'
    ensure(observed_phase(phase_raw,'source::case')['observed_pair']==['EnrollmentComplete','VerificationCompleteEnrollmentPending'],'source-shaped-phase-positive')
    ensure(observed_phase(phase_raw.replace('Some((EnrollmentComplete, VerificationCompleteEnrollmentPending))','None'),'source::case')['observed_pair'] is None,'phase-None-unknown-positive')
    ensure(not observed_phase('','source::case')['available'],'missing-phase-unknown-positive')
    negatives=[lambda:observation_completion('Some((true, Some(2), 1, 2))'),lambda:observed_phase(phase_raw.replace('VerificationCompleteEnrollmentPending','PRIVATE'),'source::case'),lambda:observed_phase(phase_raw,'foreign::case'),lambda:observed_phase(phase_raw+phase_raw,'source::case'),lambda:observed_phase(phase_raw.replace(':9:',':8:'),'source::case'),lambda:observed_phase(phase_raw.replace('(123)','(PRIVATE)'),'source::case'),lambda:observation_completion('Some((true, Some(18446744073709551616), 2, 1))'),lambda:observation_completion('Some((true, None, 2))'),lambda:observation_rpc(rpc.replace('Some((SharingPending, 13))','Some(SharingPending, 13)')),lambda:observation_rpc(rpc.replace('SharingPending','PRIVATE')),lambda:observation_rpc(rpc.replace('[1, 2, 3, 4, 5, 6]','[1, 2]')),lambda:observation_rpc(rpc.replace('13))))','18446744073709551616))))')),lambda:observed_sides(sample.replace('side=right','side=foreign')),lambda:observed_sides(sample+'\n'+aggregate('left')),lambda:observed_sides(sample.replace('Some([1, 2, 3, 4])','Some([1, PRIVATE, 3, 4])')),lambda:observed_stage('automatic-enrollment-control stage=PRIVATE'),lambda:observed_policy(policy.replace(path,'private/foreign.rs'),POLICY_NAME,known,read,'/public'),lambda:observed_policy(policy.replace(':5",',':999999",'),POLICY_NAME,known,read,'/public'),lambda:observed_policy(policy.replace(':5",',':0",'),POLICY_NAME,known,read,'/public'),lambda:observed_policy(policy+policy,POLICY_NAME,known,read,'/public')]
    for operation in negatives:
        try:operation();accepted=True
        except (ValueError,TypeError,OverflowError,OSError):accepted=False
        ensure(not accepted,'finite-observation-unknown-schema-width-or-path-rejected')
    unknown=finite_observations('automatic-enrollment-control stage=PRIVATE','source::case',set())
    ensure(unknown['fixture_stage']['schema_known'] is False and 'PRIVATE' not in json.dumps(unknown),'unknown-observation-never-exports-raw-token')
    return {'positive':12,'negative':len(negatives)+1,'raw_private_export':False,'runtime_bodies':0,'unexecuted_until_hosted_preflight':True}

def execute_case(report,row,binary,before,mode,parent,inputs,label,name,five):
    row.update(label=label,name=name,cohort='five' if five else 'sixteen',runtime_attempted=False,actual_executed_nonignored=0,oracle_green=False)
    save(report)
    for ignored in [False,True]:
        code,raw,seconds=bounded.capture([str(binary),'--exact',name]+(['--ignored'] if ignored else [])+['--list','--format','terse'],60,limit=1024*1024)
        parsed=counts.parse_inventory(raw,name,ignored)
        row.setdefault('inventory',{})['ignored' if ignored else 'normal']={'exit_code':code,'seconds':seconds,'passed':parsed.get('passed') is True}
        save(report);ensure(code==0 and parsed.get('passed') is True,'one-normal-zero-ignored-exact-case')
    ensure(source_matches(inputs) and binary_identity(binary,parent)=={'regular_approved_parent':True,'sha256':before,'mode':mode},'prebody-source-binary-mode')
    row.update(runtime_attempted=True,actual_executed_nonignored=None);save(report)
    try:code,raw,seconds=bounded.capture([str(binary),'--exact',name,'--nocapture','--test-threads=1'],900 if five else 300,limit=8*1024*1024)
    except bounded.GateFailure as error:
        row['watchdog_triggered']=str(error)=='bounded-command-timeout';row['output_limit_triggered']=str(error)=='bounded-command-output-limit';save(report);raise
    identity=binary_identity(binary,parent)
    row.update(body_exit_code=code,body_seconds=seconds,source_after_body_pristine=source_matches(inputs),
        binary_after_sha256=identity['sha256'],binary_after_mode=identity['mode'],binary_after_regular_parent=identity['regular_approved_parent'])
    save(report)
    basic=counts.parse_body(raw,code,name);row['basic_counts']=closed_counts(basic)
    for dest,key in [('actual_passed','passed'),('actual_failed','failed'),('actual_ignored','ignored'),('actual_executed_nonignored','executed_nonignored')]:row[dest]=basic.get(key)
    row['actual_test_passed']=basic.get('passed_gate') is True;save(report)
    if report['expected_case_mode'] in OBSERVATION_MODES:
        try:row['finite_observations']=finite_observations(raw,name,set(inputs),include_approvals=report['expected_case_mode']=='observations-five' and five)
        except Exception:row['finite_observations']={'schema_known':False,'available':None,'raw_private_export':False}
        save(report)
    row['panic_locations']=closed_panic_sites(raw,name,set(inputs));save(report)
    ensure(row['source_after_body_pristine'] and row['binary_after_regular_parent'] and row['binary_after_sha256']==before and row['binary_after_mode']==mode,'postbody-source-binary-mode')
    parsed=native.parse(raw,code) if five else ack.parse_case(label,raw,code)
    row['original_oracle']=closed_oracle(parsed)
    if five and report['expected_case_mode']=='observations-five':
        observations=row.get('finite_observations',{})
        approvals=observations.get('existing_approvals')
        if type(approvals) is dict:
            try:observations['existing_approvals']=bind_fifth_approvals(approvals,row['original_oracle'],observations.get('side_aggregates'))
            except (ValueError,TypeError,KeyError):observations['existing_approvals']={'schema_known':False,'available':None,'partial_or_unknown':True,'fixture_installations_by_index':None}
        save(report)
    row['oracle_green']=row['actual_test_passed'] and (native.green(parsed) if five else ack.case_green(label,parsed)) is True
    save(report)

def parser_controls(mode):
    inherited=({'five':native.parser_controls(),'sixteen':ack.parser_controls()} if mode in ('both','observations','observations-five') else
        (native.parser_controls() if mode=='five' else ack.parser_controls()))
    names=selected_cases(mode);supplemental_controls=None
    if mode in OBSERVATION_MODES:
        labels=OBSERVATION_FIVE_LABELS if mode=='observations-five' else OBSERVATION_LABELS
        ensure(tuple(row[0] for row in names)==labels,'fixed-original-observation-order')
        supplemental_controls=observation_controls()
        if mode=='observations-five':supplemental_controls={'existing_observations':supplemental_controls,'approval_rows':approval_controls(),'child_vectors':child_controls(),'recipient_boundaries':boundary_controls()}
    ensure(len(names)==required_count(mode),'exact-selected-case-count')
    if mode=='both':ensure(names[0][2]==native.NAME and names[1:]==list(ack.CASES) and len({row[2] for row in names})==17,'both-exact-order-no-duplicate-controls')
    ensure(closed_oracle({'facts':{'closed':True},'compiler_headers':['PRIVATE'],'message':'PRIVATE'})=={'facts':{'closed':True},'observations':None},'closed-projection-no-private-strings')
    ensure(not within(Path.cwd().parent,Path.cwd()) and within(Path.cwd()/'ordinary',Path.cwd()),'containment-direction-controls')
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
    synthetic=[{'cohort':'five' if label=='five' else 'sixteen','oracle_green':True,'basic_counts':dict(complete['basic_counts'])} for label,_,_,_ in names]
    totals=cohort_totals(synthetic,mode)
    ensure(sum(row['basic_counts']['executed_nonignored'] for row in synthetic)==required_count(mode),'all-selected-observed-counts-control')
    if mode=='both':
        ensure(totals['five']['actual_executed_nonignored']==1 and totals['sixteen']['actual_executed_nonignored']==16,'distinct-1-and-16-cohort-counts')
        synthetic[-1]['oracle_green']=False
        changed=cohort_totals(synthetic,mode)
        ensure(changed['five']['all_original_cases_green'] is True and changed['sixteen']['all_original_cases_green'] is False,'sixteen-failure-never-overrides-five-or-qualifies-both')
    return {'original_oracle_controls':inherited,'wrapper_controls':5,'panic_site_positive':4,'panic_site_negative':8,'actual_runtime_bodies':0,'finite_observation_controls':supplemental_controls}

def main(args):
    os.umask(0o077)
    report={'expected_case_mode':args.mode,'preflight_only':args.preflight,'actual_test_qualification':False,'global_qualification':False,
        'old_guards_or_main_called':False,'old_module_globals_mutated':False,'automatic_retries':0,'raw_runtime_output_exported':False,
        'requested_features':FEATURES,'environment_stack_bytes':4194304,'Tokio_workers':2 if args.mode=='five' else None,
        'observation_only':args.mode in OBSERVATION_MODES,'runtime_flavor': 'original-five-two-worker' if args.mode=='five' else ('original-source-defined-mixed-five-plus-sixteen' if args.mode=='both' else ('original-source-defined-four-selected-cases' if args.mode=='observations' else ('original-policy-plus-strict-five' if args.mode=='observations-five' else 'original-source-defined-mixed-sixteen'))),
        'actual_runtime_attempts':0,'actual_executed_nonignored':0,'strict_five_join_deadline_seconds':15 if args.mode in ('five','both','observations','observations-five') else None,'body_watchdog_seconds':None if args.mode in ('both','observations','observations-five') else (900 if args.mode=='five' else 300),'body_watchdog_seconds_by_cohort':{'five':900,'sixteen':300},'output_limit_bytes':8*1024*1024,'cases':[]}
    save(report);inputs=None;binary=None;before=None;mode=None;parent=None
    try:
        report['controller_stage']='source_guard';save(report)
        report['source']=source_guard(args.preflight);inputs=physical();save(report)
        report['controller_stage']='parser_controls';save(report)
        report['parser_controls']=({item:parser_controls(item) for item in ['five','sixteen','both','observations','observations-five']} if args.preflight else parser_controls(args.mode));save(report)
        if args.preflight:
            report['actual_executed_nonignored']=0;report['preflight_passed']=True;save(report);return
        report['controller_stage']='compile_admission';save(report)
        report['free_bytes_before_compile']=shutil.disk_usage('.').free
        report['capacity_reserve_satisfied']=report['free_bytes_before_compile']>=8*1024**3
        if not report['capacity_reserve_satisfied']:report['compile_admission_failure']='insufficient_disk_reserve'
        save(report);ensure(report['capacity_reserve_satisfied'],'eight-GiB-free-before-compilation')
        selected=selected_cases(args.mode)
        report['fresh_App_source_mtimes']=[]
        for refresh in [Path(FIXTURE),Path(PARENT)]:
            ensure(source_matches(inputs) and refresh.is_file() and not refresh.is_symlink() and refresh.parent.resolve()==Path.cwd().resolve()/refresh.parent,'fresh-App-source-identity')
            old=refresh.stat().st_mtime_ns;stamp=max(time.time_ns(),old+2_000_000_000);os.utime(refresh,ns=(stamp,stamp))
            after=refresh.stat().st_mtime_ns
            report['fresh_App_source_mtimes'].append({'path':str(refresh),'before_ns':old,'requested_ns':stamp,'actual_after_ns':after});save(report)
            ensure(after>old,'actual-source-mtime-advanced')
        report['controller_stage']='compilation';save(report)
        binary=compile_app(report,'experimental',set(inputs),lambda:save(report))
        parent=binary.parent.resolve();identity=binary_identity(binary,parent)
        ensure(identity['regular_approved_parent'],'admitted-regular-binary')
        before=identity['sha256'];mode=identity['mode']
        report['binary_before']={'sha256':before,'mode':mode,'kind':'regular-test-executable'};save(report)
        ensure(source_matches(inputs),'after-compile-whole-source-pristine')
        report['controller_stage']='original_bodies';save(report)
        for label,suffix,name,_ in selected:
            row={};report['cases'].append(row);save(report)
            try:execute_case(report,row,binary,before,mode,parent,inputs,label,name,label=='five')
            except Exception as error:row['controller_failure_type']=closed_exception(error);save(report)
        report['controller_stage']='aggregate_original_oracles'
        report.update(aggregate(report['cases'],len(selected)));report['cohorts']=cohort_totals(report['cases'],args.mode);save(report)
        report['all_original_cases_green']=len(report['cases'])==len(selected) and all(row.get('oracle_green') is True for row in report['cases'])
        report['git_closure_before_qualification']=git_closure()
        report['all_selected_originals_and_closure_green']=report['all_original_cases_green'] and source_matches(inputs) and report['git_closure_before_qualification']['verified']
        report['actual_test_qualification']=args.mode not in OBSERVATION_MODES and report['all_selected_originals_and_closure_green']
        save(report);ensure(report['all_selected_originals_and_closure_green'],'original-current-enrollment-cases-not-all-GREEN')
    except Exception as error:
        report['controller_failure_type']=closed_exception(error);save(report);raise
    finally:
        report['actual_runtime_attempts']=sum(row.get('runtime_attempted') is True for row in report['cases'])
        if not args.preflight:
            report.update(aggregate(report['cases'],required_count(args.mode)));report['cohorts']=cohort_totals(report['cases'],args.mode)
            if report['actual_runtime_attempts']==0:report['actual_executed_nonignored']=0
        report['final_git_closure']=git_closure()
        report['final_source_pristine']=inputs is not None and source_matches(inputs)
        identity=binary_identity(binary,parent)
        report['final_binary_sha256']=identity['sha256'];report['final_binary_mode']=identity['mode']
        report['final_binary_pristine']=None if binary is None else identity=={'regular_approved_parent':True,'sha256':before,'mode':mode}
        if not report['final_source_pristine'] or not report['final_git_closure']['verified'] or report['final_binary_pristine'] is False:report['actual_test_qualification']=False
        save(report)
        ensure(report['final_source_pristine'] and report['final_git_closure']['verified'] and report['final_binary_pristine'] is not False,'final-source-binary-mode-closure')
    ensure(report.get('all_selected_originals_and_closure_green') is True if args.mode in OBSERVATION_MODES else report['actual_test_qualification'],'actual-original-case-verdicts-and-closure-required')

if __name__=='__main__':
    parser=argparse.ArgumentParser();parser.add_argument('--preflight',action='store_true');parser.add_argument('--mode',choices=['five','sixteen','both','observations','observations-five'],default='both')
    main(parser.parse_args())
