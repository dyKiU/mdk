"""Bounded CI-only command/evidence helpers. No raw runtime output is persisted."""
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import time
BASE='dad5eed1aafe534dfb4ec7fa3488ad262c6f5e31'
FEATURES='marmot-app/otlp-export,marmot-app/product-analytics-export,marmot-app/test-policy-overrides,marmot-app/experimental-device-sync,cgka-engine/test-policy-overrides,cgka-engine/test-crash-hooks'
DEFAULT_FEATURES='marmot-app/otlp-export,marmot-app/product-analytics-export,marmot-app/test-policy-overrides,cgka-engine/test-policy-overrides,cgka-engine/test-crash-hooks'
NEW='completed_sibling_consent_services_initial_progress_without_periodic_tick'
ORIGINALS=['third_and_later_device_enrollment_need_no_extra_qr_or_manual_artifacts','blocked_sibling_consent_does_not_starve_another_approved_peer','automatic_sync_does_not_block_foreground_enrollment_completion']
FILE='crates/marmot-app/src/native_device_linking/tests/automatic_pairing_acceptance.rs'
MESSAGE='successful sibling consent must persist its real policy and publish its commit proof without a periodic tick'
STAGES=['third-roster-ready','third-originals-retired','primary-round-ready','actual-consent-held','periodic-arm-gated','actual-consent-task-success','foreground-progress','periodic-arm-released','normal-completion','positive-cleanup-completed']
def ensure(ok,reason):
    if not ok:raise ValueError(reason)
def digest(data):return hashlib.sha256(data).hexdigest()
def freeze():
    return {name:digest(os.readlink(name).encode() if Path(name).is_symlink() else Path(name).read_bytes()) for name in subprocess.check_output(['git','ls-files'],text=True).splitlines()}
def identity(values):return digest(b''.join(name.encode()+b'\0'+bytes.fromhex(value) for name,value in sorted(values.items())))
def environment():
    source=subprocess.check_output(['git','rev-parse','HEAD'],text=True).strip()
    ensure(os.environ.get('GITHUB_ACTIONS')=='true' and os.environ.get('GITHUB_SHA')==source,'remote-source-identity')
    ensure(os.environ.get('CARGO_INCREMENTAL')=='1' and os.environ.get('RUST_MIN_STACK')=='4194304','execution-environment')
    for key in ['RUSTFLAGS','CARGO_ENCODED_RUSTFLAGS','RUSTC_BOOTSTRAP','CARGO_PROFILE_DEV_OPT_LEVEL','CARGO_PROFILE_TEST_OPT_LEVEL']:ensure(not os.environ.get(key),'compiler-override')
    for key in ['CARGO_PROFILE_DEV_DEBUG','CARGO_PROFILE_TEST_DEBUG']:ensure(os.environ.get(key)=='0','debug-profile')
    ensure(subprocess.run(['git','diff','--quiet','HEAD']).returncode==0,'initial-source-not-pristine')
    return {'source':source,'tree':subprocess.check_output(['git','rev-parse','HEAD^{tree}'],text=True).strip(),'baseline_test_source':BASE,'environment':{key:os.environ.get(key) for key in ['CARGO_INCREMENTAL','RUST_MIN_STACK','CARGO_PROFILE_DEV_DEBUG','CARGO_PROFILE_TEST_DEBUG','RUSTFLAGS','CARGO_ENCODED_RUSTFLAGS','RUSTC_BOOTSTRAP']},'toolchain':subprocess.check_output(['rustc','--version'],text=True).strip(),'stack_bytes':4194304,'automatic_retries':0,'test_threads':1,'qualification_passed':False}
def headers(raw):
    raw=re.sub(r'\x1b\[[0-9;]*m','',raw)
    return {'compiler_error_count':len(re.findall(r'^error(?:\[E[0-9]+\])?:',raw,re.M)),'compiler_headers':[line[:500] for line in raw.splitlines() if re.match(r'^(?:error(?:\[E[0-9]+\])?:|note:|help:|\s*--> crates/[A-Za-z0-9_./-]+\.rs:[0-9]+:[0-9]+)',line)][:40]}
def compile_cases(suffixes):
    expression=' | '.join('test('+suffix+')' for suffix in suffixes)
    command=['cargo','nextest','list','--locked','--lib','-p','marmot-app','--features',FEATURES,'-E',expression,'--message-format','json']
    started=time.monotonic();row={'command':command,'features_requested':FEATURES,'runtime_bodies':0}
    try:result=subprocess.run(command,capture_output=True,text=True,timeout=1200)
    except subprocess.TimeoutExpired:row.update(watchdog_triggered=True,compile_seconds=time.monotonic()-started);return row,{}
    row.update(compile_exit_code=result.returncode,compile_seconds=time.monotonic()-started,**headers(result.stderr))
    if result.returncode or row['compiler_error_count']:return row,{}
    cases={}
    try:
        suites=json.loads(result.stdout)['rust-suites']
        for suffix in suffixes:
            matches=[(name,suite) for suite in suites.values() for name,case in suite['testcases'].items() if name.endswith('::'+suffix) and not case['ignored'] and case.get('filter-match',{}).get('status')=='matches']
            ensure(len(matches)==1,'exact-nonignored-test-inventory')
            name,suite=matches[0];binary=Path(suite['binary-path'])
            cases[suffix]={'name':name,'binary':str(binary),'binary_sha256':digest(binary.read_bytes())}
    except Exception as error:
        row['inventory_exception']=type(error).__name__
        return row,{}
    if len({case['binary_sha256'] for case in cases.values()})!=1:
        row['inventory_exception']='MultipleCompiledAppBinaries'
        return row,{}
    binary=Path(next(iter(cases.values()))['binary'])
    try:row['compiled_fingerprints']=feature_metadata(binary)
    except Exception as error:row['compiled_fingerprints']={'verified':False,'exception':type(error).__name__}
    row['cases']=[{key:value for key,value in case.items() if key!='binary'} for case in cases.values()]
    return row,cases
def execute(case,suffix):
    started=time.monotonic();row={'test':case['name'],'binary_sha256':case['binary_sha256'],'suffix':suffix}
    try:body=subprocess.run([case['binary'],'--exact',case['name'],'--nocapture','--test-threads=1'],capture_output=True,text=True,timeout=300)
    except subprocess.TimeoutExpired:row.update(watchdog_triggered=True,body_seconds=time.monotonic()-started,actual_count_unknown=True);return row
    row.update(parse_body(body.stdout+body.stderr,suffix))
    row.update(body_exit_code=body.returncode,body_seconds=time.monotonic()-started)
    return row
def parse_body(raw,suffix):
    raw=re.sub(r'\x1b\[[0-9;]*m','',raw)
    row={}
    summaries=re.findall(r'test result: (?:ok|FAILED)\. (\d+) passed; (\d+) failed; (\d+) ignored;',raw)
    if len(summaries)==1:row['passed'],row['failed'],row['ignored']=map(int,summaries[0]);row['executed_nonignored']=row['passed']+row['failed']
    row['stages']=re.findall(r'completion-wake-control stage=([a-z-]+)',raw)
    row['original_phase_markers']=re.findall(r'automatic-enrollment-control stage=((?:third|fourth)-device-complet(?:ion|ed))',raw)
    row['all_panic_header_count']=len(re.findall(r'panicked at',raw))
    row['panic_locations']=[{'file':file,'line':int(line),'column':int(column)} for file,line,column in re.findall(r'panicked at (crates/[A-Za-z0-9_./-]+\.rs):([0-9]+):([0-9]+)',raw)]
    row['hold_markers']=[value for value in ['sibling-consent-held-before-peer-progress','automatic-publication-held-before-completion'] if 'automatic-enrollment-control stage='+value in raw]
    if suffix==NEW:
        values=re.findall(r'completion-wake-control result success=(true|false) foreground=(true|false) progress=(true|false) durable_policy_seen=(true|false) proof_success_seen=(true|false)',raw)
        if len(values)==1:row['observations']=dict(zip(['held_consent_task_success','public_snapshot_responsiveness','durable_policy_and_proof_with_gate','durable_policy_seen','proof_success_seen'],[value=='true' for value in values[0]]))
        row['named_assertion_observed']=MESSAGE in raw
    return row
def phase_prerequisites(row):
    stages=row.get('stages',[])
    return stages.count('fresh-actor-progress')==1 and [stage for stage in stages if stage!='fresh-actor-progress']==STAGES and stages.index('foreground-progress')<stages.index('fresh-actor-progress')<stages.index('periodic-arm-released')
def green(row):
    good=row.get('body_exit_code')==0 and row.get('passed')==1 and row.get('failed')==0 and row.get('ignored')==0 and row.get('executed_nonignored')==1 and row.get('all_panic_header_count')==0 and not row.get('watchdog_triggered')
    if row.get('suffix')==NEW:return good and phase_prerequisites(row) and all(row.get('observations',{}).get(key) is True for key in ['held_consent_task_success','public_snapshot_responsiveness','durable_policy_and_proof_with_gate','durable_policy_seen','proof_success_seen']) and row.get('original_phase_markers')==['fourth-device-completion','fourth-device-completed']
    good &= row.get('original_phase_markers')==['third-device-completion','third-device-completed','fourth-device-completion','fourth-device-completed']
    if row.get('suffix')==ORIGINALS[1]:good &= 'sibling-consent-held-before-peer-progress' in row.get('hold_markers',[])
    if row.get('suffix')==ORIGINALS[2]:good &= 'automatic-publication-held-before-completion' in row.get('hold_markers',[])
    return good
def intended_red(row):
    lines=Path(FILE).read_text().splitlines();matches=[index for index,line in enumerate(lines) if MESSAGE in line];ensure(len(matches)==1,'unique-own-assertion')
    line=max(index for index in range(matches[0]+1) if re.search(r'\bassert!\s*\(',lines[index]))+1
    row['expected_panic']={'file':FILE,'line':line}
    return row.get('body_exit_code')==101 and row.get('passed')==0 and row.get('failed')==1 and row.get('ignored')==0 and row.get('executed_nonignored')==1 and row.get('all_panic_header_count')==1 and len(row.get('panic_locations',[]))==1 and all(row['panic_locations'][0][key]==value for key,value in row['expected_panic'].items()) and row.get('named_assertion_observed') and phase_prerequisites(row) and row.get('observations',{}).get('held_consent_task_success') is True and row.get('observations',{}).get('public_snapshot_responsiveness') is True and row.get('observations',{}).get('durable_policy_and_proof_with_gate') is False and row.get('original_phase_markers')==['fourth-device-completion','fourth-device-completed'] and not row.get('watchdog_triggered')

def feature_metadata(binary, include_native_adapter=False):
    # Cargo's emitted fingerprint companion records must match the dependency
    # hash in the selected binary's own fingerprint. Unknown formats stay unknown.
    directory=binary.parent.parent/'.fingerprint'
    suffix=binary.name.rsplit('-',1)[-1]
    root=directory/('marmot-app-'+suffix)/'test-lib-marmot_app.json'
    result={'root_binary_sha256':digest(binary.read_bytes()),'root_fingerprint_found':root.is_file(),'nodes':{},'unresolved':[],'verified':False}
    if not root.is_file(): return result
    wanted={'marmot_app','cgka_engine','storage_sqlite','cgka_session','marmot_account'}
    # The extracted relay plane is an actual dependency of this App binary.
    # Preserve the original five-node checks and resolve its exact unit too.
    if Path('crates/transport-nostr/Cargo.toml').is_file():wanted.add('transport_nostr')
    if include_native_adapter:
        wanted.add('transport_nostr_adapter')
        result['dependency_edges']=[]
    selected_expected={}
    result['coverage_required']=sorted(wanted)
    def read(path,name):
        data=json.loads(path.read_text()); features=data.get('features',[])
        if isinstance(features,str): features=json.loads(features)
        ensure(isinstance(features,list) and all(isinstance(value,str) and re.fullmatch(r'[A-Za-z0-9_./+-]+',value) for value in features),'feature-schema')
        rustflags=data.get('rustflags',[])
        result['nodes'][name]={'features':features,'fingerprint_json_sha256':digest(path.read_bytes()),'profile':data.get('profile'),'compile_kind':data.get('compile_kind'),'rustflags':[] if rustflags==[] else None,'rustflags_sha256':digest(json.dumps(rustflags,sort_keys=True).encode())}
        for dep in data.get('deps',[]):
            if len(dep)!=4 or dep[1] not in wanted: continue
            depname=dep[1]; expected=dep[3]
            if include_native_adapter:
                result['dependency_edges'].append({'from':name,'to':depname})
            if depname in result['nodes']:
                if selected_expected.get(depname)!=expected: result['unresolved'].append(depname+'-multiple-units')
                continue
            if type(expected) is not int: result['unresolved'].append(depname); continue
            candidates=[]
            for candidate in directory.glob(depname.replace('_','-')+'-*/lib-'+depname+'.json'):
                companion=candidate.with_suffix('')
                if not companion.is_file(): continue
                value=companion.read_text().strip()
                if not re.fullmatch('[0-9a-fA-F]{16}',value): continue
                raw=bytes.fromhex(value)
                if expected in [int.from_bytes(raw,'little'),int.from_bytes(raw,'big')]: candidates.append(candidate)
            if len(candidates)==1:
                selected_expected[depname]=expected
                read(candidates[0],depname)
                result['nodes'][depname]['expected_dependency_fingerprint_u64']=expected
                result['nodes'][depname]['companion_fingerprint_sha256']=digest(candidates[0].with_suffix('').read_bytes())
            else: result['unresolved'].append(depname)
    read(root,'marmot_app')
    result['unresolved']=sorted(set(result['unresolved']))
    required=wanted
    result['verified']=(required<=set(result['nodes']) and not result['unresolved'] and all(node['rustflags']==[] for node in result['nodes'].values()) and {'experimental-device-sync','test-policy-overrides'}<=set(result['nodes']['marmot_app']['features']) and {'experimental-device-sync','test-policy-overrides'}<=set(result['nodes']['cgka_engine']['features']) and 'experimental-device-sync' in result['nodes']['storage_sqlite']['features'])
    if 'transport_nostr' in wanted:
        result['verified'] &= 'experimental-device-sync' in result['nodes'].get('transport_nostr',{}).get('features',[])
    if include_native_adapter:
        edges={(edge['from'],edge['to']) for edge in result['dependency_edges']}
        result['verified'] &= ({'sdk','experimental-device-sync','test-policy-overrides'}
            <= set(result['nodes'].get('transport_nostr_adapter',{}).get('features',[]))
            and {('marmot_app','transport_nostr'),('transport_nostr','transport_nostr_adapter')} <= edges)
    return result

def parser_preflight():
    # Exercises the exact runtime parser/oracles remotely, without executing Rust.
    import copy
    stages=list(STAGES);stages.insert(stages.index('periodic-arm-released'),'fresh-actor-progress')
    text='\n'.join('completion-wake-control stage='+stage for stage in stages)
    text+='\nautomatic-enrollment-control stage=fourth-device-completion\nautomatic-enrollment-control stage=fourth-device-completed'
    text+='\ncompletion-wake-control result success=true foreground=true progress=true durable_policy_seen=true proof_success_seen=true\ntest result: ok. 1 passed; 0 failed; 0 ignored;'
    positive=dict(parse_body(text,NEW),suffix=NEW,body_exit_code=0)
    ensure(green(positive),'parser-positive-green')
    # Exact own-line matching is derived from frozen test source, not a magic line.
    lines=Path(FILE).read_text().splitlines();matches=[index for index,line in enumerate(lines) if MESSAGE in line]
    ensure(len(matches)==1,'parser-one-own-assertion')
    own=max(index for index in range(matches[0]+1) if re.search(r'\bassert!\s*\(',lines[index]))+1
    bad_text=text.replace('progress=true durable_policy_seen=true proof_success_seen=true','progress=false durable_policy_seen=false proof_success_seen=false').replace('test result: ok. 1 passed; 0 failed; 0 ignored;','test result: FAILED. 0 passed; 1 failed; 0 ignored;')
    bad_text+='\nthread test panicked at '+FILE+':'+str(own)+':9:\n'+MESSAGE
    intended=dict(parse_body(bad_text,NEW),suffix=NEW,body_exit_code=101)
    ensure(intended_red(intended),'parser-positive-intended-red')
    negatives=[]
    for field,value in [('body_exit_code',0),('passed',1),('ignored',1),('watchdog_triggered',True),('all_panic_header_count',2),('named_assertion_observed',False)]:
        row=copy.deepcopy(intended);row[field]=value;negatives.append(row)
    for stage in STAGES+['fresh-actor-progress']:
        row=copy.deepcopy(intended);row['stages'].remove(stage);negatives.append(row)
    row=copy.deepcopy(intended);row['stages'].append('fresh-actor-progress');negatives.append(row)
    row=copy.deepcopy(intended);row['panic_locations'][0]['line']+=1;negatives.append(row)
    row=copy.deepcopy(intended);row['original_phase_markers']=['third-device-completion','third-device-completed'];negatives.append(row)
    row=copy.deepcopy(intended);row['observations']['held_consent_task_success']=False;negatives.append(row)
    row=copy.deepcopy(intended);row['observations']['durable_policy_and_proof_with_gate']=True;negatives.append(row)
    ensure(all(not intended_red(row) for row in negatives),'parser-rejects-invalid-red')
    ensure(not green(dict(parse_body('test result: ok. 0 passed; 0 failed; 1 ignored;',NEW),suffix=NEW,body_exit_code=0)),'parser-rejects-zero-body')
    return {'positive_fixtures':2,'negative_fixtures':len(negatives)+1,'actual_product_bodies':0,'parser_preflight_passed':True}
