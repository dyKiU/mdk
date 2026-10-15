#!/usr/bin/env python3
"""Count real completed-driver cleanup behavior; compile failures never qualify."""
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import tempfile
import time
assert os.environ.get('GITHUB_ACTIONS') == 'true'
assert os.environ.get('CARGO_INCREMENTAL') == '1' and os.environ.get('RUST_MIN_STACK') == '4194304'
assert not any(os.environ.get(n) for n in ['RUSTFLAGS','CARGO_ENCODED_RUSTFLAGS','RUSTC_BOOTSTRAP'])
os.umask(0o077)
source=subprocess.check_output(['git','rev-parse','HEAD'],text=True).strip()
assert source==os.environ['GITHUB_SHA']
cohort=json.loads(Path('scripts/completed_pairing_cleanup_cohort.json').read_text())
assert cohort['phase']=='red'
paths=subprocess.check_output(['git','ls-files','-z'],text=True).split('\0')
frozen={p:hashlib.sha256(Path(p).read_bytes()).hexdigest() for p in paths if p and Path(p).is_file()}
assert all(frozen[p]==digest for p,digest in cohort['regression_source_sha256'].items())
out=Path('completed-cleanup-proof');out.mkdir(mode=0o700)
case='native_device_linking::automatic_pairing_acceptance::completed_automatic_transport_keeps_public_cleanup_ownership'
features='marmot-app/otlp-export,marmot-app/product-analytics-export,marmot-app/test-policy-overrides,marmot-app/experimental-device-sync,cgka-engine/test-policy-overrides,cgka-engine/test-crash-hooks'
command=['cargo','test','--locked','-p','marmot-app','--lib','--features',features,case,'--','--exact','--nocapture','--test-threads=1']
report={'source':source,'phase':'red','case':case,'command':command,'qualified':False,
 'automatic_retries':0,'SDK_builds':0,'source_sha256':cohort['regression_source_sha256']}
try:
 started=time.monotonic()
 with tempfile.TemporaryFile(mode='w+') as private:
  process=subprocess.run(command,stdout=private,stderr=subprocess.STDOUT,timeout=2400)
  private.seek(0);text=private.read()
 counts=re.findall(r'test result: (ok|FAILED)\. (\d+) passed; (\d+) failed; (\d+) ignored;',text)
 actual=re.findall(r'^test ([\w:]+) \.\.\.',text,re.M)
 witness='completed_driver_cleanup actual_completed=2 natural_closed_exits=2 runtime_closes=2 relay_closed=true'
 oracle='completed_session_public_owner_retains_cleanup'
 report.update(exit_code=process.returncode,compile_and_execution_seconds=round(time.monotonic()-started,3),
  actual_cases=actual,counts=counts,witness=witness in text,named_cleanup_oracle=oracle in text,
  compiler_error_codes=sorted(set(re.findall(r'error\[(E\d+)\]',text))),
  panic_locations=re.findall(r'panicked at ([^\s:]+\.rs:\d+:\d+)',text),
  private_log_sha256=hashlib.sha256(text.encode()).hexdigest())
 report['failure_excerpt']=[line.strip() for line in text.splitlines() if line.strip()==oracle or re.fullmatch(r'error\[E\d+\]: [A-Za-z0-9_ `:<>(),&\[\]\-]+',line.strip())][:10]
 report['qualified']=bool(actual==[case] and counts==[('FAILED','0','1','0')] and process.returncode==101
   and report['witness'] and report['named_cleanup_oracle'] and len(report['panic_locations'])==1)
finally:
 report['source_pristine']=subprocess.run(['git','diff','--quiet','HEAD']).returncode==0
 report['source_unchanged']=all(hashlib.sha256(Path(p).read_bytes()).hexdigest()==digest for p,digest in frozen.items())
 report['qualified']=report['qualified'] and report['source_pristine'] and report['source_unchanged']
 out.joinpath('result.json').write_text(json.dumps(report,indent=2)+'\n')
print(json.dumps(report,sort_keys=True))
if not report['qualified']:raise SystemExit('Genuine completed-session cleanup RED not established')
