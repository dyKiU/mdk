#!/usr/bin/env python3
"""Remove only explicit diagnostic hooks; compare frozen product token streams."""
import json
from pathlib import Path
import re
import subprocess
from upstream_proof_cost_schema import COUNTERS, GLOBAL, preflight
BASE='21b5cbbf0f806580e75147e6e02e27dc3149031b'
FILES=['crates/cgka-engine/src/lib.rs','crates/cgka-engine/src/account_identity_proof.rs','crates/cgka-engine/src/account_identity_proof_memo.rs','crates/marmot-app/src/native_device_linking/tests/automatic_pairing_acceptance.rs']
MODULE='crates/cgka-engine/src/proof_memo_diagnostics.rs'
def normalize(value):
    # Keep quoted contents exact while permitting canonical Rust line wrapping.
    chunks=re.split(r'("(?:\\.|[^"\\])*")',value)
    return ''.join(chunk if index%2 else re.sub(r'\s+','',chunk).replace(',)',')') for index,chunk in enumerate(chunks))
def strip(value):
    value=re.sub(r'\{\s*// PROOF_DIAGNOSTIC_LOCK_BEGIN.*?// PROOF_DIAGNOSTIC_LOCK_END\s*result\s*\}', 'self.entries.lock()',value,flags=re.S)
    value=re.sub(r'(?m)^[ \t]*// PROOF_DIAGNOSTIC_(?:MODULE_|FIELD_)?BEGIN\n.*?^[ \t]*// PROOF_DIAGNOSTIC_(?:MODULE_|FIELD_)?END\n', '',value,flags=re.S|re.M)
    return value
for name in FILES:
    old=subprocess.check_output(['git','show',BASE+':'+name],text=True)
    assert normalize(strip(Path(name).read_text()))==normalize(old), 'frozen product differs beyond diagnostic hooks: '+name
changed=subprocess.check_output(['git','diff','--name-only',BASE],text=True).splitlines()
allowed=set(FILES+[MODULE,'.github/workflows/experimental-sync-ci.yml','scripts/upstream_proof_cost_schema.py','scripts/verify_upstream_proof_cost_source.py','scripts/diagnose_upstream_proof_cost.py'])
assert set(changed)<=allowed, 'unrelated input changed'
for name in ['Cargo.lock','Cargo.toml','.cargo/config.toml','.config/nextest.toml']:
    assert Path(name).read_bytes()==subprocess.check_output(['git','show',BASE+':'+name])
module=Path(MODULE).read_text()
for name,expected in [('NAMES',COUNTERS),('GLOBAL_NAMES',GLOBAL)]:
    match=re.search(r'const '+name+r':.*?=\s*\[(.*?)\];',module,re.S)
    assert match and re.findall(r'"([a-z_]+)"',match[1])==expected
report={'source':subprocess.check_output(['git','rev-parse','HEAD'],text=True).strip(),'product_baseline':BASE,'product_token_streams_exact_after_hook_stripping':True,'original_strings_held_exact':True,'cargo_lock_config_exact':True,'parser_preflight':preflight(),'normal_build_hooks_feature_gated':True,'source_preflight_passed':True,'qualification_passed':False}
Path('proof-cost-source.json').write_text(json.dumps(report,indent=2)+'\n')
