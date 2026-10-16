#!/usr/bin/env python3
"""Remote-only exact-source guard for the passive ordinary diagnostic."""
import ast
import json
from pathlib import Path
import re
import subprocess
from upstream_completion_ci import ensure
from verify_upstream_completion_candidate_source import normalize
from run_upstream_completion_diagnostic import parser_preflight
BASE='397012abd254cf13a2bfc71780867df4d714f424'
HOOKS=['crates/marmot-app/src/account_chat_sharing/enabled.rs','crates/marmot-app/src/client/device_linking/sibling_sharing.rs','crates/marmot-app/src/client/private_enrollment_proposal.rs','crates/marmot-app/src/client/private_enrollment_proposal/sibling_sharing.rs','crates/cgka-engine/src/account_chat_sharing.rs','crates/marmot-app/src/native_device_linking/tests/automatic_pairing_acceptance.rs']
PROBE='crates/marmot-app/src/account_chat_sharing/completion_diagnostics.rs'
HELPERS=['scripts/run_upstream_completion_diagnostic.py','scripts/verify_upstream_completion_diagnostic_source.py','.github/workflows/experimental-sync-ci.yml']
def main():
    changed=subprocess.check_output(['git','diff','--name-only',BASE],text=True).splitlines()
    ensure(set(changed)<=set(HOOKS+[PROBE]+HELPERS),'unexpected-diagnostic-change')
    counts={}
    for name in HOOKS:
        text=Path(name).read_text(); baseline=subprocess.check_output(['git','show',BASE+':'+name],text=True)
        pattern=r'(?m)^[ \t]*// COMPLETION_DIAGNOSTIC_BEGIN\n.*?^[ \t]*// COMPLETION_DIAGNOSTIC_END\n'
        blocks=re.findall(pattern,text,re.S|re.M); counts[name]=len(blocks)
        ensure(bool(blocks) and text.count('COMPLETION_DIAGNOSTIC_BEGIN')==text.count('COMPLETION_DIAGNOSTIC_END')==len(blocks),'diagnostic-marker-bounds')
        ensure(normalize(re.sub(pattern,'',text,flags=re.S|re.M))==normalize(baseline),'original-product-token-or-string-drift')
    probe=Path(PROBE).read_text()
    ensure(not re.search(r'\b(?:async|unsafe|spawn|notify_one|send_replace|session|sql|adapter|TransportMessage|MessageId)\b',probe),'probe-authority-or-network')
    ensure('self.rows.len() < 32' in probe and 'self.overflow += 1' in probe,'probe-bound-or-overflow')
    for name in HELPERS[:2]: ast.parse(Path(name).read_text(),filename=name)
    report={'source':subprocess.check_output(['git','rev-parse','HEAD'],text=True).strip(),'baseline':BASE,'stripped_original_tokens_and_strings_exact':True,'hook_blocks':counts,'parser_preflight':parser_preflight(),'actual_product_bodies':0,'qualification_passed':False}
    Path('completion-diagnostic-source.json').write_text(json.dumps(report,indent=2)+'\n')
if __name__=='__main__': main()
