#!/usr/bin/env python3
"""No-compile source equivalence guard for bounded synchronous diagnostics."""
import hashlib
import json
from pathlib import Path
import re
import subprocess
BASE = '3dde689febbe364b70af35ff778e3d74a6bc5622'
FILES = ['crates/cgka-engine/src/lib.rs', 'crates/cgka-engine/src/private_roster_settlement.rs', 'crates/cgka-engine/src/private_successor.rs', 'crates/cgka-engine/src/device_group_snapshot.rs', 'crates/cgka-engine/src/account_chat_sharing.rs', 'crates/marmot-app/src/native_device_linking/tests/automatic_pairing_acceptance.rs']
report = {'source': subprocess.check_output(['git','rev-parse','HEAD'],text=True).strip(), 'baseline':BASE, 'diagnostic_only':True, 'qualification_passed':False, 'stripped_source':{}}
for name in FILES:
    original = subprocess.check_output(['git','show',BASE+':'+name],text=True)
    observed = Path(name).read_text()
    observed = re.sub(r'(?m)^[ \t]*#\[cfg\(feature = "test-policy-overrides"\)\]\n[ \t]*let _sync_cost_[a-z_]+\s*=\s*crate::enrollment_sync_cost::Probe::start\(.*?;\n', '', observed, flags=re.S)
    observed = re.sub(r'(?m)^[ \t]*#\[cfg\(feature = "test-policy-overrides"\)\]\n[ \t]*drop\(_sync_cost_[a-z_]+\);\n', '', observed)
    observed = re.sub(r'(?m)^[ \t]*#\[cfg\(feature = "test-policy-overrides"\)\]\n[ \t]*let sync_cost_phase\s*=\s*cgka_engine::enrollment_sync_cost::PhaseGuard::begin\(.*?;\n', '', observed, flags=re.S)
    observed = re.sub(r'(?m)^[ \t]*#\[cfg\(feature = "test-policy-overrides"\)\]\n[ \t]*drop\(sync_cost_phase\);\n', '', observed)
    observed = observed.replace('\n#[cfg(feature = "test-policy-overrides")]\npub mod enrollment_sync_cost;\n','')
    assert observed == original, 'stripped diagnostic source differs: '+name
    report['stripped_source'][name] = hashlib.sha256(original.encode()).hexdigest()
changed = subprocess.check_output(['git','diff','--name-only',BASE,'HEAD','--','crates'],text=True).splitlines()
assert set(changed)==set(FILES+['crates/cgka-engine/src/enrollment_sync_cost.rs'])
for name in ['Cargo.lock','.cargo/config.toml','.config/nextest.toml','Cargo.toml']:
    assert Path(name).read_bytes()==subprocess.check_output(['git','show',BASE+':'+name])
report['source_equivalence_passed']=True
Path('cost-partition-source.json').write_text(json.dumps(report,indent=2)+'\n')
