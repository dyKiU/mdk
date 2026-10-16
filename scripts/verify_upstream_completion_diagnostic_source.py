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
HOOKS += ['crates/transport-nostr-adapter/src/lib.rs','crates/transport-nostr-adapter/src/sdk_client.rs']
HOOKS += ['crates/marmot-app/src/runtime/account_worker.rs']
PROBE='crates/marmot-app/src/account_chat_sharing/completion_diagnostics.rs'
SDK='crates/transport-nostr-adapter/src/publication_diagnostics.rs'
HELPERS=['scripts/run_upstream_completion_diagnostic.py','scripts/verify_upstream_completion_diagnostic_source.py','scripts/upstream_publication_sdk.py','scripts/upstream_worker_load.py','.github/workflows/experimental-sync-ci.yml']
def main():
    changed=subprocess.check_output(['git','diff','--name-only',BASE],text=True).splitlines()
    ensure(set(changed)<=set(HOOKS+[PROBE,SDK]+HELPERS),'unexpected-diagnostic-change')
    counts={}
    for name in HOOKS:
        text=Path(name).read_text(); baseline=subprocess.check_output(['git','show',BASE+':'+name],text=True)
        worker_wrapper=False
        if name.endswith('/runtime/account_worker.rs'):
            wrapper=r'(?m)^[ \t]*// WORKER_DIAGNOSTIC_SPAWN_BEGIN\n.*?^[ \t]*// WORKER_DIAGNOSTIC_SPAWN_END\n'
            ensure(len(re.findall(wrapper,text,re.S|re.M))==1,'one-reviewed-worker-poll-wrapper')
            original='    tokio::spawn(Box::pin(run_app_runtime_account_worker(\n        runtime,\n        command_tx,\n        commands,\n        ready,\n        startup_progress,\n        shutdown,\n    )))\n'
            ensure(baseline.count(original)==1,'unique-original-worker-pin-context')
            cfg='all(test, feature = "experimental-device-sync", feature = "test-policy-overrides")'
            arguments='runtime,command_tx,commands,ready,startup_progress,shutdown,'
            expected='#[cfg('+cfg+')] { tokio::spawn(crate::account_chat_sharing::enabled::completion_diagnostics::observe_worker(Box::pin(run_app_runtime_account_worker('+arguments+')))) } #[cfg(not('+cfg+'))] { '+original+' }'
            actual=re.findall(wrapper,text,re.S|re.M)[0]
            actual='\n'.join(line for line in actual.splitlines() if '// WORKER_DIAGNOSTIC_SPAWN_' not in line)
            ensure(normalize(actual)==normalize(expected),'reviewed-cfg-original-spawn-or-same-future-wrapper-drift')
            text=re.sub(wrapper,lambda _:original,text,flags=re.S|re.M);worker_wrapper=True
        if name.endswith('/sdk_client.rs'):
            single=r'(?m)^[ \t]*// SDK_CORRELATION_SINGLE_BEGIN\n.*?^[ \t]*// SDK_CORRELATION_SINGLE_END\n'
            ensure(len(re.findall(single,text,re.S|re.M))==1,'one-reviewed-single-publisher-diagnostic')
            text=re.sub(single,'                Ok(request) => vec![self.publish_prepared_single(request).await],\n',text,flags=re.S|re.M)
        marker='SDK_CORRELATION' if '/transport-nostr-adapter/' in name else 'COMPLETION_DIAGNOSTIC'
        pattern=r'(?m)^[ \t]*// '+marker+r'_BEGIN\n.*?^[ \t]*// '+marker+r'_END\n'
        blocks=re.findall(pattern,text,re.S|re.M); counts[name]=len(blocks)
        ensure((bool(blocks) or worker_wrapper) and text.count(marker+'_BEGIN')==text.count(marker+'_END')==len(blocks),'diagnostic-marker-bounds')
        ensure(normalize(re.sub(pattern,'',text,flags=re.S|re.M))==normalize(baseline),'original-product-token-or-string-drift')
    probe=Path(PROBE).read_text()
    ensure(not re.search(r'\b(?:async|unsafe|spawn|notify_one|send_replace|session|sql|adapter|TransportMessage|MessageId)\b',probe),'probe-authority-or-network')
    ensure('self.rows.len() < 32' in probe and 'self.overflow += 1' in probe,'probe-bound-or-overflow')
    for name in HELPERS:
        if name.endswith('.py'): ast.parse(Path(name).read_text(),filename=name)
    sdk=Path(SDK).read_text()
    ensure('const LIMIT: usize = 128;' in sdk and 'identity: String' in sdk and not re.search(r'\b(?:async|unsafe|spawn|await|Serialize|Deserialize|Debug)\b',sdk),'sdk-bound-or-authority')
    from upstream_publication_sdk import parser_preflight as sdk_parser_preflight
    from upstream_worker_load import parser_preflight as load_parser_preflight
    report={'source':subprocess.check_output(['git','rev-parse','HEAD'],text=True).strip(),'baseline':BASE,'stripped_original_tokens_and_strings_exact':True,'hook_blocks':counts,'parser_preflight':parser_preflight(),'actual_product_bodies':0,'qualification_passed':False}
    report['sdk_parser_preflight']=sdk_parser_preflight()
    report['load_parser_preflight']=load_parser_preflight()
    Path('completion-diagnostic-source.json').write_text(json.dumps(report,indent=2)+'\n')
if __name__=='__main__': main()
