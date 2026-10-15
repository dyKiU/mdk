#!/usr/bin/env python3
"""One frozen uninfluenced original three-body remote enrollment baseline."""
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import time
assert os.environ.get('GITHUB_ACTIONS')=='true'
assert os.environ.get('CARGO_INCREMENTAL')=='1' and os.environ.get('RUST_MIN_STACK')=='4194304'
assert not any(os.environ.get(k) for k in ['RUSTFLAGS','CARGO_ENCODED_RUSTFLAGS','RUSTC_BOOTSTRAP'])
os.umask(0o077)
BASE='46230f5744139d7f46c1ba266784919361fdcd1d'
source=subprocess.check_output(['git','rev-parse','HEAD'],text=True).strip();assert source==os.environ['GITHUB_SHA']
allowed={'.github/workflows/upstream-latest-original-three.yml','scripts/qualify_latest_original_three.py'}
changed=set(subprocess.check_output(['git','diff','--name-only',BASE,'HEAD'],text=True).splitlines());assert changed==allowed
paths=subprocess.check_output(['git','ls-files','-z'],text=True).split('\0')
def hashes():
 return {p:hashlib.sha256(os.readlink(p).encode() if Path(p).is_symlink() else Path(p).read_bytes()).hexdigest() for p in paths if p}
frozen=hashes();out=Path('latest-original-three-proof');out.mkdir(mode=0o700)
short=['third_and_later_device_enrollment_need_no_extra_qr_or_manual_artifacts','blocked_sibling_consent_does_not_starve_another_approved_peer','automatic_sync_does_not_block_foreground_enrollment_completion']
cases=['native_device_linking::automatic_pairing_acceptance::'+s for s in short]
features='marmot-app/otlp-export,marmot-app/product-analytics-export,marmot-app/test-policy-overrides,marmot-app/experimental-device-sync,cgka-engine/test-policy-overrides,cgka-engine/test-crash-hooks'
report={'source':source,'product_baseline':BASE,'all_product_test_config_inputs_equal_baseline':True,'features':features,'original_bounds_seconds':[15,10],'runtime_flavor':'current_thread','automatic_retries':0,'new_instrumentation':False,'SDK_builds':0,'runs':[],'qualified':False,'input_manifest_sha256':hashlib.sha256(json.dumps(frozen,sort_keys=True).encode()).hexdigest()}
def save():out.joinpath('result.json').write_text(json.dumps(report,indent=2)+'\n')
save()
try:
 start=time.monotonic()
 listing=subprocess.run(['cargo','nextest','list','--locked','-p','marmot-app','--lib','--features',features,'-E',' | '.join('test(='+c+')' for c in cases),'--message-format','json'],capture_output=True,text=True,timeout=1800)
 report.update(compile_seconds=round(time.monotonic()-start,3),compile_exit_code=listing.returncode,compile_error_codes=sorted(set(re.findall(r'error\[(E\d+)\]',listing.stderr))))
 assert listing.returncode==0,'Compile failure is not runtime evidence'
 inventory=json.loads(listing.stdout)
 selected=[(suite,c) for suite in inventory['rust-suites'].values() for c,t in suite['testcases'].items() if c in cases and t['filter-match']['status']=='matches']
 assert len(selected)==3 and {c for _,c in selected}==set(cases)
 assert all(not s['testcases'][c]['ignored'] for s,c in selected)
 binaries={s['binary-path'] for s,c in selected};assert len(binaries)==1
 binary=Path(next(iter(binaries)));binary_hash=hashlib.sha256(binary.read_bytes()).hexdigest();report['binary_sha256']=binary_hash
 report['selected_nonignored']=3;save()
 for case in cases:
  assert hashes()==frozen
  assert hashlib.sha256(binary.read_bytes()).hexdigest()==binary_hash
  start=time.monotonic()
  try:
   completed=subprocess.run([str(binary),'--exact',case,'--nocapture','--test-threads=1'],capture_output=True,text=True,timeout=300)
   raw=completed.stdout+completed.stderr
   counts=re.findall(r'test result: (ok|FAILED)\. (\d+) passed; (\d+) failed; (\d+) ignored;',raw)
   actual=re.findall(r'^test ([\w:]+) \.\.\.',raw,re.M)
   row={'case':case,'exit_code':completed.returncode,'body_seconds':round(time.monotonic()-start,3),'counts':counts,'actual_cases':actual,'panic_locations':re.findall(r'panicked at ([^\s:]+\.rs:\d+:\d+)',raw),'original_phase_assertion':'automatic pairing did not reach required phase:' in raw,'static_control_diagnostics':[line for line in raw.splitlines() if line.startswith('automatic-enrollment-control ')],'phase_oracle_lines':[line for line in raw.splitlines() if re.fullmatch(r'automatic pairing did not reach required phase: expected=[A-Za-z]+ observed=Some\(\([A-Za-z]+, [A-Za-z]+\)\)',line)],'private_log_sha256':hashlib.sha256(raw.encode()).hexdigest()}
   row['qualified']=completed.returncode==0 and counts==[('ok','1','0','0')] and actual==[case] and not row['panic_locations']
  except subprocess.TimeoutExpired:
   row={'case':case,'watchdog_triggered':True,'body_seconds':round(time.monotonic()-start,3),'qualified':False}
  report['runs'].append(row);save();print(json.dumps(row,sort_keys=True),flush=True)
 report['qualified']=len(report['runs'])==3 and all(r['qualified'] for r in report['runs'])
finally:
 report['source_unchanged']=hashes()==frozen
 report['source_pristine']=subprocess.run(['git','diff','--quiet','HEAD']).returncode==0
 report['qualified']=report['qualified'] and report['source_unchanged'] and report['source_pristine'];save()
if not report['qualified']:raise SystemExit('Original three-body enrollment baseline remains unqualified')
