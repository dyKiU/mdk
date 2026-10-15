#!/usr/bin/env python3
"""Remote actual Account companion catch-up predicate qualification, without SDK builds."""
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import tempfile
import time
assert os.environ.get('GITHUB_ACTIONS') == 'true'
assert os.environ.get('CARGO_INCREMENTAL') == '1'
assert not any(os.environ.get(k) for k in ['RUSTFLAGS','CARGO_ENCODED_RUSTFLAGS','RUSTC_BOOTSTRAP'])
os.umask(0o077)
cohort=os.environ['COHORT']; assert cohort in {'default','experimental'}
config=json.loads(Path('scripts/companion_catchup_cohort.json').read_text())
phase=config['phase']; assert phase in {'red','green'}
source=subprocess.check_output(['git','rev-parse','HEAD'],text=True).strip(); assert source==os.environ['GITHUB_SHA']
tracked=subprocess.check_output(['git','ls-files','-z'],text=True).split('\0')
frozen={p:hashlib.sha256(Path(p).read_bytes()).hexdigest() for p in tracked if p and Path(p).is_file()}
assert all(frozen[p]==h for p,h in config['source_sha256'].items())
out=Path('companion-catchup-proof');out.mkdir(mode=0o700)
report={'source':source,'cohort':cohort,'phase':phase,'source_sha256':config['source_sha256'],'automatic_retries':0,'SDK_builds':0,'runs':[],'qualified':False}
case='companion_does_not_publish_or_generate_public_key_packages'
product=Path('crates/marmot-account/src/runtime.rs')
base=['cargo','test','--locked','-p','marmot-account','--test','runtime']
if cohort=='experimental':base+=['--features','marmot-account/experimental-device-sync']

def execute(selector,expect,label):
 command=base+[selector,'--','--exact','--nocapture','--test-threads=1']
 started=time.monotonic()
 with tempfile.TemporaryFile(mode='w+') as log:
  completed=subprocess.run(command,stdout=log,stderr=subprocess.STDOUT,timeout=1800)
  log.seek(0);text=log.read()
 counts=re.findall(r'test result: (ok|FAILED)\. (\d+) passed; (\d+) failed; (\d+) ignored;',text)
 actual=re.findall(r'^test ([\w:]+) \.\.\.',text,re.M)
 errors=sorted(set(re.findall(r'error\[(E\d+)\]',text)))
 oracle='assertion failed: !runtime.key_package_maintenance_requires_catch_up().unwrap()'
 row={'label':label,'selector':selector,'command':command,'actual_cases':actual,'counts':counts,'exit_code':completed.returncode,'compile_and_execution_seconds':round(time.monotonic()-started,3),'named_predicate_assertion':oracle in text,'panic_locations':re.findall(r'panicked at ([^\s:]+\.rs:\d+:\d+)',text),'compiler_error_codes':errors,'private_log_sha256':hashlib.sha256(text.encode()).hexdigest(),'executed_product_sha256':hashlib.sha256(product.read_bytes()).hexdigest()}
 row['qualified']=actual==[selector] and not errors and ((expect=='red' and completed.returncode==101 and counts==[('FAILED','0','1','0')] and row['named_predicate_assertion'] and len(row['panic_locations'])==1) or (expect=='green' and completed.returncode==0 and counts==[('ok','1','0','0')] and not row['panic_locations']))
 report['runs'].append(row)
 out.joinpath('result.json').write_text(json.dumps(report,indent=2)+'\n')
 print(json.dumps(row,sort_keys=True),flush=True)
 return row['qualified']

try:
 if phase=='red':report['qualified']=execute(case,'red','original-companion-regression')
 else:
  passed=[execute(s,'green','baseline-'+s) for s in [case,'companion_hold_fences_retained_public_key_package_fanout_after_reopen','key_package_generation_upgrade_retries_across_restart_and_rotates_only_once']]
  pristine=product.read_bytes()
  anchor=b'    pub fn key_package_maintenance_requires_catch_up(&self) -> AccountResult<bool> {\n        if self.public_key_package_publication_disabled {\n            return Ok(false);\n        }\n'
  replacement=b'    pub fn key_package_maintenance_requires_catch_up(&self) -> AccountResult<bool> {\n'
  assert pristine.count(anchor)==1
  mutant=pristine.replace(anchor,replacement)
  assert hashlib.sha256(mutant).hexdigest()==config['guard_omission_sha256']
  if all(passed):
   try:
    product.write_bytes(mutant)
    assert all(hashlib.sha256(Path(p).read_bytes()).hexdigest()==h for p,h in frozen.items() if p!=str(product))
    passed.append(execute(case,'red','omit-only-companion-catchup-guard'))
   finally:product.write_bytes(pristine)
   passed.append(execute(case,'green','exact-restored'))
  report['qualified']=all(passed) and len(report['runs'])==5
finally:
 report['source_pristine']=subprocess.run(['git','diff','--quiet','HEAD']).returncode==0
 report['source_unchanged']=all(hashlib.sha256(Path(p).read_bytes()).hexdigest()==h for p,h in frozen.items())
 report['qualified']=report['qualified'] and report['source_pristine'] and report['source_unchanged']
 out.joinpath('result.json').write_text(json.dumps(report,indent=2)+'\n')
if not report['qualified']:raise SystemExit('Actual companion predicate qualification incomplete')
