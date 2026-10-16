#!/usr/bin/env python3
"""One original ordinary body with bounded passive numeric diagnostics only."""
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import time
from upstream_proof_cost_schema import SchemaError, parse_cost, parse_existing, parse_partitions, parse_publications
BASE='21b5cbbf0f806580e75147e6e02e27dc3149031b'
FEATURES='marmot-app/otlp-export,marmot-app/product-analytics-export,marmot-app/test-policy-overrides,marmot-app/experimental-device-sync,cgka-engine/test-policy-overrides,cgka-engine/test-crash-hooks'
SUFFIX='third_and_later_device_enrollment_need_no_extra_qr_or_manual_artifacts'
os.umask(0o077)
OUT=Path('proof-cost-evidence'); OUT.mkdir(exist_ok=True)
report={'source':subprocess.check_output(['git','rev-parse','HEAD'],text=True).strip(),'product_baseline':BASE,'qualification_passed':False,'diagnostic_complete':False,'cpu_usable':False,'stack_bytes':4194304,'test_threads':1,'automatic_retries':0,'features_requested':FEATURES,'snapshot_timestamps_are_last_observations_not_durations':True,'terminal_cached_refresh_can_bypass_stage_counts':True,'nested_cpu_aggregates_are_nonadditive':True}
def save(): (OUT/'result.json').write_text(json.dumps(report,indent=2)+'\n')
def digest(data): return hashlib.sha256(data).hexdigest()
def hashes():
    result={}
    for name in subprocess.check_output(['git','ls-files'],text=True).splitlines():
        path=Path(name); result[name]=digest(os.readlink(path).encode() if path.is_symlink() else path.read_bytes())
    return result
def fingerprint(value): return digest(b''.join(name.encode()+b'\0'+bytes.fromhex(sha) for name,sha in sorted(value.items())))
def ensure(ok,reason):
    if not ok: raise ValueError(reason)
def feature_metadata(binary):
    # Cargo's emitted fingerprint companion records must match the dependency
    # hash in the selected binary's own fingerprint. Unknown formats stay unknown.
    directory=binary.parent.parent/'.fingerprint'
    suffix=binary.name.rsplit('-',1)[-1]
    root=directory/('marmot-app-'+suffix)/'test-lib-marmot_app.json'
    result={'root_binary_sha256':digest(binary.read_bytes()),'root_fingerprint_found':root.is_file(),'nodes':{},'unresolved':[],'verified':False}
    if not root.is_file(): return result
    wanted={'marmot_app','cgka_engine','storage_sqlite','cgka_session','marmot_account'}
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
    result['verified']=(required<=set(result['nodes']) and not result['unresolved'] and all(node['rustflags']==[] for node in result['nodes'].values()) and {'experimental-device-sync','test-policy-overrides'}<=set(result['nodes']['cgka_engine']['features']) and 'experimental-device-sync' in result['nodes']['storage_sqlite']['features'])
    return result
save()
ensure(os.environ.get('GITHUB_ACTIONS')=='true' and report['source']==os.environ.get('GITHUB_SHA'),'remote-source')
ensure(os.environ.get('CARGO_INCREMENTAL')=='1' and os.environ.get('RUST_MIN_STACK')=='4194304','original-environment')
for key in ['RUSTFLAGS','CARGO_ENCODED_RUSTFLAGS','RUSTC_BOOTSTRAP','CARGO_PROFILE_DEV_OPT_LEVEL','CARGO_PROFILE_TEST_OPT_LEVEL']: ensure(not os.environ.get(key),'compiler-override')
for key in ['CARGO_PROFILE_DEV_DEBUG','CARGO_PROFILE_TEST_DEBUG']: ensure(os.environ.get(key)=='0','debug-profile')
report['environment']={key:os.environ.get(key) for key in ['CARGO_INCREMENTAL','RUST_MIN_STACK','CARGO_PROFILE_DEV_DEBUG','CARGO_PROFILE_TEST_DEBUG','RUSTFLAGS','CARGO_ENCODED_RUSTFLAGS','RUSTC_BOOTSTRAP']}
frozen=hashes(); report['source_before_sha256']=fingerprint(frozen)
report['lock_sha256']=frozen['Cargo.lock']; report['nextest_config_sha256']=frozen['.config/nextest.toml']; report['cargo_config_sha256']=frozen['.cargo/config.toml']
report['toolchain']=subprocess.check_output(['rustc','--version'],text=True).strip()
report['tree']=subprocess.check_output(['git','rev-parse','HEAD^{tree}'],text=True).strip()
save()
args=['cargo','nextest','list','--locked','--lib','-p','marmot-app','--features',FEATURES,'-E','test('+SUFFIX+')','--message-format','json']
started=time.monotonic(); listing=subprocess.run(args,capture_output=True,text=True,timeout=1200)
report.update(compile_exit_code=listing.returncode,compile_seconds=time.monotonic()-started)
compiler=re.sub(r'\x1b\[[0-9;]*m','',listing.stderr)
report['compiler_error_count']=len(re.findall(r'^error(?:\[E[0-9]+\])?:',compiler,re.M))
report['compiler_headers']=[line[:500] for line in compiler.splitlines() if re.match(r'^(?:error(?:\[E[0-9]+\])?:|note:|help:|\s*--> crates/[A-Za-z0-9_./-]+\.rs:[0-9]+:[0-9]+)',line)][:40]
save()
if listing.returncode: raise SystemExit(1)
ensure(hashes()==frozen,'compile-changed-inputs')
suites=json.loads(listing.stdout)['rust-suites'].values()
matches=[(name,suite) for suite in suites for name,case in suite['testcases'].items() if name.endswith('::'+SUFFIX) and not case['ignored']]
ensure(len(matches)==1,'exact-one-nonignored-body')
name,suite=matches[0]; binary=Path(suite['binary-path'])
report['test']=name; report['binary_sha256']=digest(binary.read_bytes())
try: report['compiled_fingerprints']=feature_metadata(binary)
except Exception as error: report['compiled_fingerprint_exception']=type(error).__name__; report['compiled_fingerprints']={'verified':False}
save()
ensure(hashes()==frozen,'before-body-inputs')
started=time.monotonic()
try: body=subprocess.run([str(binary),'--exact',name,'--nocapture','--test-threads=1'],capture_output=True,text=True,timeout=300)
except subprocess.TimeoutExpired:
    report['watchdog_triggered']=True; report['body_seconds']=time.monotonic()-started; save(); raise SystemExit(1)
raw=re.sub(r'\x1b\[[0-9;]*m','',body.stdout+body.stderr)
report.update(body_seconds=time.monotonic()-started,body_exit_code=body.returncode)
summary=re.findall(r'test result: (?:ok|FAILED)\. (\d+) passed; (\d+) failed; (\d+) ignored;',raw)
if len(summary)==1:
    passed,failed,ignored=map(int,summary[0]); report.update(passed=passed,failed=failed,ignored=ignored,executed_nonignored=passed+failed)
report['phase_markers']=re.findall(r'automatic-enrollment-control stage=((?:third|fourth)-device-complet(?:ion|ed))',raw)
entries=[stage for stage in report['phase_markers'] if stage.endswith('-completion')]
phase=entries[-1].split('-',1)[0] if entries else None
report['observed_completion_phase']=phase
report['panic_locations']=[{'file':file,'line':int(line),'column':int(column)} for file,line,column in re.findall(r'panicked at (crates/[A-Za-z0-9_./-]+\.rs):([0-9]+):([0-9]+)',raw)]
report['source_after_sha256']=fingerprint(hashes()); report['inputs_pristine']=hashes()==frozen and subprocess.run(['git','diff','--quiet','HEAD']).returncode==0
# Durable actual outcome precedes every optional parser/metadata interpretation.
save()
try:
    report['cost_rows']=parse_cost(raw)
    report['partition_rows']=parse_partitions(raw)
    report['publication_records']=parse_publications(raw)
    report['publication_schema']={'kind':['request','consent','proof'],'outcome':['not-exited','success','error','abort-or-unwind'],'row_fields':['generation','kind','scheduled_us','first_poll_us','body_exit_us','outcome','visits','last_visit_us','last_joinhandle_is_finished','successful_harvest_us','body_exit_age_without_successful_harvest_us'],'time_origin':'same diagnostic monotonic clock as phase_start_us','body_exit_is_not_joinhandle_finished':True,'snapshot_order':'left child list, right child list, then existing source list as existing failure helper reads them','scope_limits':['only outcome1 success with no successful harvest supports completion-service delay','error and JoinError collection can return before successful-harvest hook','start0/outcome0 may mean queued or aborted before first poll','outcome3 means abort-or-unwind without classification']}
    report['protocol_observations']=parse_existing(raw,phase)
    ensure(report['executed_nonignored']==1 and report['ignored']==0,'actual-body-count')
    expected=['third','fourth'] if 'fourth-device-completion' in report['phase_markers'] else ['third'] if 'third-device-completion' in report['phase_markers'] else []
    rows=report['cost_rows']; ensure([row['phase'] for row in rows]==expected and bool(expected),'phase-observer-coverage')
    if report.get('failed')==1: ensure(report['protocol_observations']['failure_snapshots_observed'],'failed-body-observer-missing')
    ensure([row['phase'] for row in report['partition_rows']]==expected,'partition-phase-coverage')
    if report.get('failed')==1:
        expected_records=[]
        protocol=report['protocol_observations']
        ensure(set(protocol['sides'])=={'left','right'},'publication-side-coverage')
        for side in ['left','right']:
            record=protocol['sides'][side]
            ensure(isinstance(record.get('children'),list),'unknown-child-state-count')
            expected_records += [{'role':record['role'],'child_index':index} for index in range(len(record['children']))]
        for source in protocol['existing_sources']:
            ensure(source['channel'] is not None,'unknown-existing-state')
            expected_records.append({'role':source['role'],'existing_index':source['index']})
        publications=report['publication_records']
        ensure(len(publications)==len(expected_records) and bool(publications),'publication-record-count')
        ensure(len({row['state_ordinal'] for row in publications})==len(publications),'duplicate-publication-state')
        report['publication_role_associations']=[dict(role,state_ordinal=row['state_ordinal']) for role,row in zip(expected_records,publications)]
    ensure(all(row['overflow']==0 for row in report['publication_records']),'publication-record-overflow')
    report['diagnostic_complete']=True
    valid=True
    for row in rows:
        global_values=row['global']; records=[entry['counts'] for entry in row['engines']]
        valid &= row['phase_cpu_ns'] is not None and row['phase_cpu_ns']>0 and row['phase_cpu_read_failures']==0 and row['engine_overflow']==0 and row['phase_conflicts']==0 and global_values[0]>0 and global_values[3]>0 and global_values[5:]==[0,0,0]
        valid &= bool(records) and sum(value[0] for value in records)>0 and sum(value[2] for value in records)>0 and sum(value[10] for value in records)>0
        valid &= all(value[0]==value[1]+value[2] and value[2]==value[8]+value[9] and value[12:15]==[0,0,0] for value in records)
        valid &= global_values[0]==global_values[1]+global_values[2] and global_values[0]>=sum(value[2] for value in records)
    valid &= all(all(values[0]>0 and values[3:]==[0,0,0] for values in row['rows']) for row in report['partition_rows'])
    report['cpu_usable']=bool(valid and report['inputs_pristine'] and report['compiled_fingerprints'].get('verified'))
except Exception as error:
    report['parser_or_diagnostic_exception']=type(error).__name__; report['diagnostic_complete']=False; report['cpu_usable']=False
save()
raise SystemExit(0 if report['diagnostic_complete'] and report['cpu_usable'] else 1)
