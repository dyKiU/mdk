"""Two independently reviewed omission mutations; exact anchors finalized with owner."""
from pathlib import Path
import re
from upstream_completion_ci import ensure,digest
# Product-owner draft anchors; verify against signed/final canonical source before dispatch.
SPECS={
    'signal':{'path':'crates/marmot-app/src/client/device_linking/sibling_sharing.rs','before':'completion.send_replace(());','after':'// mutation: omit success-only completion signal'},
    'wiring':{'path':'crates/marmot-app/src/runtime/account_worker.rs','before_pattern':r'\{\s*sibling_completions_open\s*\}','after':'{ false && sibling_completions_open }'},
}
def anchor(text,spec):
    if 'before_pattern' in spec:
        matches=re.findall(spec['before_pattern'],text)
        ensure(len(matches)==1,'unique-reviewed-cfg-guard-expression')
        return matches[0]
    ensure(text.count(spec['before'])==1,'unique-reviewed-mutation-anchor')
    return spec['before']
def verify_anchors():
    result={}
    for name,spec in SPECS.items():
        text=Path(spec['path']).read_text();before=anchor(text,spec)
        mutant=text.replace(before,spec['after'],1)
        result[name]={'path':spec['path'],'before_sha256':digest(text.encode()),'expected_mutant_sha256':digest(mutant.encode()),'occurrences':1}
    return result
