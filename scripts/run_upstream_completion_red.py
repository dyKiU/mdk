#!/usr/bin/env python3
"""One real scheduled enrollment body. Preserve failure; strict runtime RED oracle."""
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import time
os.umask(0o077)
OUT=Path('completion-red-evidence');OUT.mkdir(exist_ok=True)
FEATURES='marmot-app/otlp-export,marmot-app/product-analytics-export,marmot-app/test-policy-overrides,marmot-app/experimental-device-sync,cgka-engine/test-policy-overrides,cgka-engine/test-crash-hooks'
SUFFIX='completed_sibling_consent_services_initial_progress_without_periodic_tick'
FILE='crates/marmot-app/src/native_device_linking/tests/automatic_pairing_acceptance.rs'
MESSAGE='successful sibling consent must persist its real policy and publish its commit proof without a periodic tick'
r={'source':subprocess.check_output(['git','rev-parse','HEAD'],text=True).strip(),'product_baseline':'3dde689febbe364b70af35ff778e3d74a6bc5622','red_qualified':False,'qualification_passed':False,'setup_claim':'real first-three Completed private roster only; no third-device chat-sharing acceptance claim','original_completion_seconds':15,'gated_initial_progress_seconds':15,'stack_bytes':4194304,'automatic_retries':0,'features_requested':FEATURES}
def save(): (OUT/'result.json').write_text(json.dumps(r,indent=2)+'\n')
def ensure(ok,reason):
    if not ok: raise ValueError(reason)
def sha(data):return hashlib.sha256(data).hexdigest()
def freeze():return {name:sha(Path(name).read_bytes() if not Path(name).is_symlink() else os.readlink(name).encode()) for name in subprocess.check_output(['git','ls-files'],text=True).splitlines()}
def aggregate(values):return sha(b''.join(name.encode()+b'\0'+bytes.fromhex(value) for name,value in sorted(values.items())))
save();ensure(os.environ.get('GITHUB_ACTIONS')=='true' and os.environ.get('GITHUB_SHA')==r['source'],'remote-source')
ensure(os.environ.get('CARGO_INCREMENTAL')=='1' and os.environ.get('RUST_MIN_STACK')=='4194304','environment')
for name in ['RUSTFLAGS','CARGO_ENCODED_RUSTFLAGS','RUSTC_BOOTSTRAP','CARGO_PROFILE_TEST_OPT_LEVEL','CARGO_PROFILE_DEV_OPT_LEVEL']:ensure(not os.environ.get(name),'compiler-override')
for name in ['CARGO_PROFILE_TEST_DEBUG','CARGO_PROFILE_DEV_DEBUG']:ensure(os.environ.get(name)=='0','debug-profile')
r['environment']={name:os.environ.get(name) for name in ['CARGO_INCREMENTAL','RUST_MIN_STACK','CARGO_PROFILE_TEST_DEBUG','CARGO_PROFILE_DEV_DEBUG','RUSTFLAGS','CARGO_ENCODED_RUSTFLAGS','RUSTC_BOOTSTRAP']}
frozen=freeze();r['source_before_sha256']=aggregate(frozen);r['lock_sha256']=frozen['Cargo.lock'];r['nextest_config_sha256']=frozen['.config/nextest.toml'];r['cargo_config_sha256']=frozen['.cargo/config.toml'];r['toolchain']=subprocess.check_output(['rustc','--version'],text=True).strip();r['tree']=subprocess.check_output(['git','rev-parse','HEAD^{tree}'],text=True).strip()
lines=Path(FILE).read_text().splitlines();matches=[i for i,line in enumerate(lines) if MESSAGE in line];ensure(len(matches)==1,'unique-own-assertion')
assertion=max(i for i in range(matches[0]+1) if re.search(r'\bassert!\s*\(',lines[i]));r['expected_panic']={'file':FILE,'line':assertion+1}
save();start=time.monotonic()
compiled=subprocess.run(['cargo','nextest','list','--locked','--lib','-p','marmot-app','--features',FEATURES,'-E','test('+SUFFIX+')','--message-format','json'],capture_output=True,text=True,timeout=1200)
r.update(compile_seconds=time.monotonic()-start,compile_exit_code=compiled.returncode)
errors=re.sub(r'\x1b\[[0-9;]*m','',compiled.stderr);r['compiler_error_count']=len(re.findall(r'^error(?:\[E[0-9]+\])?:',errors,re.M));r['compiler_headers']=[line[:500] for line in errors.splitlines() if re.match(r'^(?:error(?:\[E[0-9]+\])?:|note:|help:|\s*--> crates/[A-Za-z0-9_./-]+\.rs:[0-9]+:[0-9]+)',line)][:40];save()
if compiled.returncode:raise SystemExit(1)
ensure(freeze()==frozen,'compile-source-drift')
cases=[(name,suite) for suite in json.loads(compiled.stdout)['rust-suites'].values() for name,case in suite['testcases'].items() if name.endswith('::'+SUFFIX) and not case['ignored']];ensure(len(cases)==1,'one-real-body')
name,suite=cases[0];binary=Path(suite['binary-path']);r['test']=name;r['binary_sha256']=sha(binary.read_bytes());r['binary_feature_provenance']='exact cargo list package/lib/feature command; no inferred fingerprint linkage';save()
start=time.monotonic()
try:body=subprocess.run([str(binary),'--exact',name,'--nocapture','--test-threads=1'],capture_output=True,text=True,timeout=300)
except subprocess.TimeoutExpired:r.update(watchdog_triggered=True,body_seconds=time.monotonic()-start);save();raise SystemExit(1)
raw=re.sub(r'\x1b\[[0-9;]*m','',body.stdout+body.stderr);r.update(body_seconds=time.monotonic()-start,body_exit_code=body.returncode)
summary=re.findall(r'test result: (?:ok|FAILED)\. (\d+) passed; (\d+) failed; (\d+) ignored;',raw)
if len(summary)==1:r['passed'],r['failed'],r['ignored']=map(int,summary[0]);r['executed_nonignored']=r['passed']+r['failed']
r['stages']=re.findall(r'completion-wake-control stage=([a-z-]+)',raw)
r['original_phase_markers']=re.findall(r'automatic-enrollment-control stage=((?:third|fourth)-device-complet(?:ion|ed))',raw)
r['panic_locations']=[{'file':file,'line':int(line),'column':int(column)} for file,line,column in re.findall(r'panicked at (crates/[A-Za-z0-9_./-]+\.rs):([0-9]+):([0-9]+)',raw)]
r['source_after_sha256']=aggregate(freeze());r['inputs_pristine']=freeze()==frozen and subprocess.run(['git','diff','--quiet','HEAD']).returncode==0;save()
try:
    outcomes=re.findall(r'completion-wake-control result success=(true|false) foreground=(true|false) progress=(true|false) durable_policy_seen=(true|false) proof_success_seen=(true|false)',raw);ensure(len(outcomes)==1,'one-closed-outcome')
    success,foreground,progress,durable,proof=[value=='true' for value in outcomes[0]];r['actual_prerequisites']={'held_consent_task_success':success,'foreground_snapshots':foreground,'durable_policy_and_genuine_proof_with_gate':progress,'durable_policy_seen':durable,'proof_success_seen':proof}
    expected=['third-roster-ready','third-originals-retired','primary-round-ready','actual-consent-held','periodic-arm-gated','actual-consent-task-success','foreground-progress','periodic-arm-released','normal-completion','positive-cleanup-completed'];ensure(r['stages']==expected,'actual-stage-order')
    ensure(r.get('executed_nonignored')==1 and r.get('passed')==0 and r.get('failed')==1 and r.get('ignored')==0 and body.returncode==101 and r['compiler_error_count']==0,'actual-runtime-red')
    ensure(success and foreground and not progress,'intended-liveness-failure')
    ensure(len(r['panic_locations'])==1 and all(r['panic_locations'][0][key]==value for key,value in r['expected_panic'].items()) and MESSAGE in raw,'sole-intended-runtime-assertion')
    ensure(r['inputs_pristine'],'runtime-source-drift');r['red_qualified']=True
except Exception as error:r['oracle_failure']=str(error) if type(error) is ValueError else type(error).__name__
save();raise SystemExit(0 if r['red_qualified'] else 1)
