#!/usr/bin/env python3
"""Separate test-only lifecycle guard; frozen completion candidate stays exact."""
import ast
import json
from pathlib import Path
import re
import subprocess
from upstream_completion_ci import ensure,parser_preflight
from verify_upstream_completion_candidate_source import normalize
BASE='80e0eef22d5c19a6edf1ea2f63b43799c43d7bde'
RUST=['crates/marmot-app/src/client/device_linking/sibling_sharing.rs','crates/marmot-app/src/runtime/account_worker.rs','crates/marmot-app/src/runtime/commands.rs','crates/marmot-app/src/native_device_linking/tests/automatic_pairing_acceptance.rs']
HELPERS=['scripts/verify_upstream_completion_rebind_source.py','scripts/qualify_upstream_completion_rebind.py','.github/workflows/experimental-sync-ci.yml']
def main():
    changed=subprocess.check_output(['git','diff','--name-only',BASE],text=True).splitlines()
    ensure(set(changed)<=set(RUST+HELPERS),'unreviewed-lifecycle-input')
    for name in RUST:
        current=Path(name).read_text();original=subprocess.check_output(['git','show',BASE+':'+name],text=True)
        count=len(re.findall(r'(?m)^[ \t]*// REBIND_TEST_BEGIN$',current))
        ensure(count>0,'lifecycle-markers-present')
        stripped=re.sub(r'(?m)^[ \t]*// REBIND_TEST_BEGIN\n.*?^[ \t]*// REBIND_TEST_END\n','',current,flags=re.S|re.M)
        stripped=stripped.replace('completion_wake_for_test(held_publication)','held_publication == HeldPublication::CompletionWake')
        ensure(normalize(stripped)==normalize(original),'frozen-product-and-four-cases-changed:'+name)
    for name in HELPERS:
        if name.endswith('.py'):ast.parse(Path(name).read_text())
    parser=parser_preflight()
    from qualify_upstream_completion_rebind import rebind_anchor,parser_preflight_rebind
    anchor=rebind_anchor(Path(RUST[1]).read_text())
    report={'source':subprocess.check_output(['git','rev-parse','HEAD'],text=True).strip(),'frozen_candidate':BASE,'test_only_rust_paths':RUST,'all_other_product_tests_config_exact':True,'existing_four_cases_exact_after_strip':True,'parser':parser,'lifecycle_parser':parser_preflight_rebind(),'replacement_rebind_anchor_present':bool(anchor),'actual_product_bodies':0,'qualification_passed':False}
    Path('completion-rebind-source.json').write_text(json.dumps(report,indent=2)+'\n')
if __name__=='__main__':main()
