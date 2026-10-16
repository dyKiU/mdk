#!/usr/bin/env python3
"""Test-only scheduling seam must leave the original integration code exact."""
import json
from pathlib import Path
import re
import subprocess
BASE='3dde689febbe364b70af35ff778e3d74a6bc5622'
FILES=['crates/marmot-app/src/account_chat_sharing/enabled.rs','crates/marmot-app/src/client/device_linking/sibling_sharing.rs','crates/marmot-app/src/native_device_linking/enabled.rs','crates/marmot-app/src/native_device_linking/tests/automatic_pairing_acceptance.rs','crates/marmot-app/src/runtime/mod.rs','crates/marmot-app/src/runtime/account_worker.rs']
NEW='crates/marmot-app/src/runtime/test_linking_periodic_gate.rs'
def normalize(value):
    return ''.join(chunk if index%2 else re.sub(r'\s+','',chunk).replace(',)',')').replace(',}','}') for index,chunk in enumerate(re.split(r'("(?:\\.|[^"\\])*")',value)))
for name in FILES:
    old=subprocess.check_output(['git','show',BASE+':'+name],text=True)
    current=re.sub(r'(?m)^[ \t]*// COMPLETION_TEST_BEGIN\n.*?^[ \t]*// COMPLETION_TEST_END\n','',Path(name).read_text(),flags=re.S|re.M)
    assert normalize(current)==normalize(old), 'non-test source changed: '+name
allowed=set(FILES+[NEW,'scripts/verify_upstream_completion_red_source.py','scripts/run_upstream_completion_red.py','.github/workflows/experimental-sync-ci.yml'])
assert set(subprocess.check_output(['git','diff','--name-only',BASE],text=True).splitlines())<=allowed
for name in ['Cargo.lock','Cargo.toml','.cargo/config.toml','.config/nextest.toml']:
    assert Path(name).read_bytes()==subprocess.check_output(['git','show',BASE+':'+name])
Path('completion-red-source.json').write_text(json.dumps({'source':subprocess.check_output(['git','rev-parse','HEAD'],text=True).strip(),'product_baseline':BASE,'original_three_bodies_and_predicates_exact_after_test_hook_stripping':True,'original_product_exact_after_test_hook_stripping':True,'cargo_lock_config_exact':True,'test_gate_only_periodic_arm':True,'source_preflight_passed':True,'actual_bodies':0},indent=2)+'\n')
