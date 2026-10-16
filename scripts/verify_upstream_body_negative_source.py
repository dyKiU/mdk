#!/usr/bin/env python3
"""Actual source restoration and compact oracle controls; remote CI only."""
import ast
import json
from pathlib import Path
import re
import subprocess
from upstream_completion_ci import ensure
from verify_upstream_completion_candidate_source import normalize
from upstream_body_negative_ci import BASE, PRODUCT, TEST, ANCHOR, MUTANT, parser_preflight
HOOKS=[PRODUCT,'crates/marmot-app/src/client/account_chat_sharing/automatic/departure.rs','crates/marmot-app/src/native_device_linking/tests/automatic_pairing_acceptance.rs']
NEW=[TEST,'crates/marmot-app/src/client/account_chat_sharing/automatic/body_negative_probe.rs','scripts/upstream_body_negative_ci.py','scripts/qualify_upstream_body_negative.py','scripts/verify_upstream_body_negative_source.py','.github/workflows/experimental-sync-ci.yml']
def main():
    changed=subprocess.check_output(['git','diff','--name-only',BASE],text=True).splitlines()
    ensure(set(changed)<=set(HOOKS+NEW),'unreviewed-source-or-config-change')
    counts={}
    for name in HOOKS:
        text=Path(name).read_text();old=subprocess.check_output(['git','show',BASE+':'+name],text=True)
        pattern=r'(?m)^[ \t]*// BODY_NEGATIVE_TEST_BEGIN\n.*?^[ \t]*// BODY_NEGATIVE_TEST_END\n'
        blocks=re.findall(pattern,text,re.S|re.M)
        ensure(blocks and text.count('BODY_NEGATIVE_TEST_BEGIN')==text.count('BODY_NEGATIVE_TEST_END')==len(blocks),'bounded-hooks')
        stripped=re.sub(pattern,'',text,flags=re.S|re.M)
        if name.endswith('/automatic_pairing_acceptance.rs'):
            # The only addition is a trailing child-module registration; preserve
            # the original Body plus four original acceptance functions byte-for-byte.
            ensure(text.startswith(old) and stripped==old+'\n','original-five-fixture-bytes-changed')
        else:ensure(normalize(stripped)==normalize(old),'original-product-tokens-or-strings-changed')
        counts[name]=len(blocks)
    text=Path(PRODUCT).read_text();ensure(text.count(ANCHOR)==1 and MUTANT not in text,'exact-force-renew-only-anchor')
    probe=Path(NEW[1]).read_text()
    ensure('Weak<State>' in probe and 'Weak::ptr_eq' in probe and 'StorageError::Backend' in probe and 'registry.len() < 8' in probe,'probe-ownership-or-bound')
    ensure(not re.search(r'\b(?:unsafe|async|spawn|await|Serialize|Deserialize|Debug)\b',probe),'probe-lifetime-or-export')
    for name in NEW:
        if name.endswith('.py'):ast.parse(Path(name).read_text())
    report={'source':subprocess.check_output(['git','rev-parse','HEAD'],text=True).strip(),'baseline':BASE,'hook_blocks':counts,'original_five_fixture_bytes_exact':True,'stripped_product_tokens_and_strings_exact':True,'parser_controls':parser_preflight(),'actual_runtime_bodies':0,'qualification_passed':False}
    Path('body-negative-source.json').write_text(json.dumps(report,indent=2)+'\n')
if __name__=='__main__':main()
