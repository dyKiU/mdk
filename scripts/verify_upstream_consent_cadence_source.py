#!/usr/bin/env python3
"""Temporary real transport-Err cadence fixture/source equivalence gate."""
import ast
import json
from pathlib import Path
import re
import subprocess
from upstream_completion_ci import ensure
from verify_upstream_completion_candidate_source import normalize
BASE='ac3db2d82bdca105d249b7ddfba73734b4e153e9'
RUST=['crates/marmot-app/src/account_chat_sharing/enabled.rs','crates/marmot-app/src/client/device_linking/sibling_sharing.rs','crates/marmot-app/src/native_device_linking/enabled.rs','crates/marmot-app/src/native_device_linking/tests/automatic_pairing_acceptance.rs','crates/marmot-app/src/relay_plane/mod.rs','crates/marmot-app/src/runtime/account_worker.rs','crates/marmot-app/src/runtime/test_linking_periodic_gate.rs']
HELPERS=['scripts/verify_upstream_consent_cadence_source.py','scripts/qualify_upstream_consent_cadence.py','.github/workflows/experimental-sync-ci.yml']
def main():
    changed=subprocess.check_output(['git','diff','--name-only',BASE],text=True).splitlines()
    ensure(set(changed)<=set(RUST+HELPERS),'unreviewed-cadence-input')
    for name in RUST:
        current=Path(name).read_text();original=subprocess.check_output(['git','show',BASE+':'+name],text=True)
        ensure('// CADENCE_TEST_BEGIN' in current,'cadence-hooks-marked')
        stripped=re.sub(r'(?m)^[ \t]*// CADENCE_TEST_BEGIN\n.*?^[ \t]*// CADENCE_TEST_END\n','',current,flags=re.S|re.M)
        if name.endswith('automatic_pairing_acceptance.rs'):
            relay='    let relay = nostr_relay_builder::MockRelay::run().await.unwrap();\n    let url = relay.url().await.to_string();\n'
            ensure(stripped.count('// CADENCE_RELAY_BEGIN')==1,'one-reviewed-test-relay-factory')
            stripped=re.sub(r'(?m)^[ \t]*// CADENCE_RELAY_BEGIN\n.*?^[ \t]*// CADENCE_RELAY_END\n',relay,stripped,flags=re.S|re.M)
            stripped=stripped.replace('cadence_roster_setup_for_test(held_publication)','held_publication == HeldPublication::CompletionWake')
        ensure(normalize(stripped)==normalize(original),'frozen-product-and-four-cases-changed:'+name)
    for name in HELPERS:
        if name.endswith('.py'):ast.parse(Path(name).read_text())
    from qualify_upstream_consent_cadence import mutation_anchor,parser_preflight
    mutation_anchor(Path(RUST[1]).read_text())
    report={'source':subprocess.check_output(['git','rev-parse','HEAD'],text=True).strip(),'frozen_candidate':BASE,'all_normal_product_inputs_exact_after_cfg_hook_strip':True,'original_four_preserved_with_reviewed_ordinary_mock_relay_factory_branch':True,'parser':parser_preflight(),'actual_product_bodies':0,'qualification_passed':False}
    Path('consent-cadence-source.json').write_text(json.dumps(report,indent=2)+'\n')
if __name__=='__main__':main()
