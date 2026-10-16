#!/usr/bin/env python3
"""Separate reviewed-product guard; frozen historical RED guard stays unchanged."""
import ast
import json
from pathlib import Path
import re
import subprocess
from upstream_completion_ci import BASE,FILE,ensure,parser_preflight
# Only these reviewed App files may contain the completion-service repair.
PRODUCT=['crates/marmot-app/src/client/device_linking.rs','crates/marmot-app/src/client/device_linking/sibling_sharing.rs','crates/marmot-app/src/runtime/account_worker.rs']
HELPERS=['scripts/upstream_completion_ci.py','scripts/verify_upstream_completion_candidate_source.py','scripts/qualify_upstream_completion.py','scripts/upstream_completion_mutations.py','scripts/verify_upstream_completion_green_run.py','.github/workflows/experimental-sync-ci.yml']
def normalize(value):
    return ''.join(chunk if index%2 else re.sub(r'\s+','',chunk).replace(',)',')').replace(',}','}') for index,chunk in enumerate(re.split(r'("(?:\\.|[^"\\])*")',value)))
def main():
    changed=subprocess.check_output(['git','diff','--name-only',BASE],text=True).splitlines()
    ensure(set(changed)<=set(PRODUCT+HELPERS+[FILE]),'unreviewed-source-or-config-change')
    ensure(bool(set(changed)&set(PRODUCT)),'repair-source-absent')
    current=Path(FILE).read_text();original=subprocess.check_output(['git','show',BASE+':'+FILE],text=True)
    actor=re.findall(r'(?m)^[ \t]*// COMPLETION_ACTOR_CHECK_BEGIN\n(.*?)^[ \t]*// COMPLETION_ACTOR_CHECK_END\n',current,re.S|re.M)
    ensure(len(actor)==1,'one-reviewed-fresh-actor-check')
    ensure('device_linking_targets' in actor[0] and 'fresh-actor-progress' in actor[0] and 'device_count' in actor[0] and '4' in actor[0],'fresh-actor-check-evidence')
    stripped=re.sub(r'(?m)^[ \t]*// COMPLETION_ACTOR_CHECK_BEGIN\n.*?^[ \t]*// COMPLETION_ACTOR_CHECK_END\n','',current,flags=re.S|re.M)
    ensure(normalize(stripped)==normalize(original),'fixture-or-original-three-changed')
    # Test hooks, original source, Cargo and configuration remain exact elsewhere.
    for name in ['Cargo.lock','Cargo.toml','.cargo/config.toml','.config/nextest.toml','scripts/run_upstream_completion_red.py','scripts/verify_upstream_completion_red_source.py','crates/marmot-app/src/account_chat_sharing/enabled.rs','crates/marmot-app/src/native_device_linking/enabled.rs','crates/marmot-app/src/runtime/mod.rs','crates/marmot-app/src/runtime/test_linking_periodic_gate.rs']:
        ensure(Path(name).read_bytes()==subprocess.check_output(['git','show',BASE+':'+name]),'frozen-input-changed:'+name)
    for name in HELPERS:
        if name.endswith('.py'):ast.parse(Path(name).read_text())
    import upstream_completion_mutations as mutations
    anchors=mutations.verify_anchors()
    parser=parser_preflight()
    report={'source':subprocess.check_output(['git','rev-parse','HEAD'],text=True).strip(),'historical_red_source':BASE,'allowed_reviewed_product_paths':PRODUCT,'reviewed_product_differences':sorted(set(changed)&set(PRODUCT)),'all_other_tracked_inputs_frozen_except_named_helpers_and_fresh_actor_check':True,'original_three_and_new_gated_predicates_exact':True,'new_fresh_actor_command_check_present':True,'mutation_anchors':anchors,'parser_preflight':parser,'source_preflight_passed':True,'actual_product_bodies':0,'qualification_passed':False}
    Path('completion-candidate-source.json').write_text(json.dumps(report,indent=2)+'\n')
if __name__=='__main__':main()
