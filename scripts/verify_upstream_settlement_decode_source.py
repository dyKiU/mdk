#!/usr/bin/env python3
"""No-compile guard: only raw JSON decoding is memoized, never validation."""
import hashlib
import json
from pathlib import Path
import re
import subprocess
BASE='3dde689febbe364b70af35ff778e3d74a6bc5622'
SQL='crates/storage-sqlite/src/private_roster_settlement.rs'
old=subprocess.check_output(['git','show',BASE+':'+SQL],text=True)
new=Path(SQL).read_text()
old_body=old[old.index('    let row = conn',old.index('fn read(')):old.index('fn write(')]
new_body=new[new.index('    let row = conn',new.index('fn read_decoded(')):new.index('fn write(')]
new_body=new_body.replace('    let state = decode(&bytes)?;','    let state: PrivateSettlementState = serde_json::from_slice(&bytes).map_err(|_| invalid())?;')
assert new_body==old_body, 'query, original validation/index/facts/error order must stay exact'
cold=new[new.index('fn read('):new.index('fn read_memoized(')]
assert 'serde_json::from_slice(bytes)' in cold and 'memo' not in cold
assert new.count('read_memoized(&conn, &self.connection)')==2
for name in ['crates/cgka-engine/src/private_roster_settlement.rs','crates/cgka-engine/src/private_successor.rs','crates/traits/src/private_roster_settlement.rs','crates/marmot-app/src/runtime/device_linking.rs','crates/marmot-app/src/native_device_linking/tests/automatic_pairing_acceptance.rs','Cargo.lock','.cargo/config.toml','.config/nextest.toml','Cargo.toml']:
    assert Path(name).read_bytes()==subprocess.check_output(['git','show',BASE+':'+name]), 'unrelated production/assertion inputs must remain exact'
for name in ['crates/storage-sqlite/src/connection.rs','crates/storage-sqlite/src/storage/groups.rs','crates/storage-sqlite/src/account_projection.rs']:
    assert 'clear_private_settlement_decode()' in Path(name).read_text()
report={'source':subprocess.check_output(['git','rev-parse','HEAD'],text=True).strip(),'baseline':BASE,'fresh_query_and_validation_body_exact':True,'canonical_transition_decoder_uncached':True,'hot_read_paths':2,'original_app_deadlines_and_json_fault_triggers_exact':True,'source_preflight_passed':True,'qualification_passed':False,'fresh_validation_body_sha256':hashlib.sha256(old_body.encode()).hexdigest()}
Path('settlement-decode-source.json').write_text(json.dumps(report,indent=2)+'\n')
