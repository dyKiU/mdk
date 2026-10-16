"""Two independently reviewed omission mutations; exact anchors finalized with owner."""
from pathlib import Path
from upstream_completion_ci import ensure,digest
# Product-owner draft anchors; verify against signed/final canonical source before dispatch.
SPECS={
    'signal':{'path':'crates/marmot-app/src/client/device_linking/sibling_sharing.rs','before':'completion.send_replace(());','after':'// mutation: omit success-only completion signal'},
    'wiring':{'path':'crates/marmot-app/src/runtime/account_worker.rs','before':'if sibling_completions_open => {','after':'if false && sibling_completions_open => {'},
}
def verify_anchors():
    result={}
    for name,spec in SPECS.items():
        ensure(not spec['before'].startswith('PENDING_'),'product-owner-mutation-anchor-not-reviewed')
        text=Path(spec['path']).read_text();ensure(text.count(spec['before'])==1,'unique-reviewed-mutation-anchor')
        mutant=text.replace(spec['before'],spec['after'],1)
        result[name]={'path':spec['path'],'before_sha256':digest(text.encode()),'expected_mutant_sha256':digest(mutant.encode()),'occurrences':1}
    return result
