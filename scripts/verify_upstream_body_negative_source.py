#!/usr/bin/env python3
"""Actual source restoration and compact oracle controls; remote CI only."""
import ast
import argparse
import json
import os
from pathlib import Path
import re
import subprocess
from upstream_completion_ci import ensure
from verify_upstream_completion_candidate_source import normalize
from upstream_body_negative_ci import BASE, PRODUCT, TEST, ANCHOR, MUTANT, parser_preflight
HOOKS=[PRODUCT,'crates/marmot-app/src/client/account_chat_sharing/automatic/departure.rs','crates/marmot-app/src/native_device_linking/tests/automatic_pairing_acceptance.rs']
NEW=[TEST,'crates/marmot-app/src/client/account_chat_sharing/automatic/body_negative_probe.rs','scripts/upstream_body_negative_ci.py','scripts/qualify_upstream_body_negative.py','scripts/verify_upstream_body_negative_source.py','.github/workflows/experimental-sync-ci.yml']
def main(cohort_baseline=None):
    cohort=None
    if cohort_baseline:
        from upstream_extraction_cohort import reviewed_cohort
        cohort=reviewed_cohort(cohort_baseline)
    changed=subprocess.check_output(['git','diff','--name-only',BASE],text=True).splitlines()
    if not cohort:ensure(set(changed)<=set(HOOKS+NEW),'unreviewed-source-or-config-change')
    counts={}
    for name in HOOKS:
        text=Path(name).read_text();old=subprocess.check_output(['git','show',BASE+':'+name],text=True)
        pattern=r'(?m)^[ \t]*// BODY_NEGATIVE_TEST_BEGIN\n.*?^[ \t]*// BODY_NEGATIVE_TEST_END\n'
        blocks=re.findall(pattern,text,re.S|re.M)
        ensure(blocks and text.count('BODY_NEGATIVE_TEST_BEGIN')==text.count('BODY_NEGATIVE_TEST_END')==len(blocks),'bounded-hooks')
        stripped=re.sub(pattern,'',text,flags=re.S|re.M)
        if cohort:
            # Whole files, including every original owner acceptance function
            # and the retained negative hook, match the reviewed new baseline.
            # The old cb221/a5 stripped-file assertion is historical only.
            ensure(Path(name).read_bytes()==subprocess.check_output(['git','show',cohort_baseline+':'+name]),'reviewed-extraction-fixture-or-product-drift')
        elif name.endswith('/automatic_pairing_acceptance.rs'):
            # The only addition is a trailing child-module registration; preserve
            # the original Body plus four original acceptance functions byte-for-byte.
            ensure(text.startswith(old) and stripped==old+'\n','original-five-fixture-bytes-changed')
            ensure(old==subprocess.check_output(['git','show','a5b1d906134f566580c65a1372211ff751f92eef:'+name],text=True),'composed-original-five-not-exact-a5')
        else:ensure(normalize(stripped)==normalize(old),'original-product-tokens-or-strings-changed')
        counts[name]=len(blocks)
    text=Path(PRODUCT).read_text();ensure(text.count(ANCHOR)==1 and MUTANT not in text,'exact-force-renew-only-anchor')
    destructor=text.index('impl Drop for AutomaticChannel {')
    cancel=text.index('self.original.cancel();',destructor);retire=text.index('self.channel.retire();',cancel)
    observed_retirement=text.index('body_negative_probe::retired(self);',retire)
    ensure(destructor<cancel<retire<observed_retirement and text.count('body_negative_probe::retired(self);')==1,'actual-retirement-observed-after-existing-terminal-operations')
    gate_hooks=[block for block in re.findall(r'(?m)^[ \t]*// BODY_NEGATIVE_TEST_BEGIN\n(.*?)^[ \t]*// BODY_NEGATIVE_TEST_END\n',text,re.S|re.M) if 'gate.wait(' in block]
    expected='#[cfg(all(test, feature = "test-policy-overrides"))] if let Some(gate) = &negative_intent_gate { gate.wait(input_payload_digest).await; }'
    ensure(len(gate_hooks)==1 and normalize(gate_hooks[0])==normalize(expected),'one-cfg-only-original-argument-gate-wait')
    future=text.index('let publication_future = async move {');select=text.index('let report = tokio::select! { biased;',future)
    stopping=text.index('() = &mut stopping =>',select);revoked=text.index('() = &mut revoked =>',select)
    deadline=text.index('() = tokio::time::sleep_until(publication_deadline.into()) =>',select)
    report_arm=text.index('report =',deadline);adapter_future=text.index('async {',report_arm)
    wait=text.index('gate.wait(input_payload_digest).await;',adapter_future);publish=text.index('adapter.publish_automatic_control(request)',wait)
    returned=text.index('=> report.map_err(',publish)
    ensure(select<stopping<revoked<deadline<report_arm<adapter_future<wait<publish<returned,'gate-not-inside-original-cancellable-adapter-select')
    probe=Path(NEW[1]).read_text()
    ensure('Weak<State>' in probe and 'Weak::ptr_eq' in probe and 'StorageError::Backend' in probe and 'registry.len() < 8' in probe,'probe-ownership-or-bound')
    ensure(not re.search(r'\b(?:unsafe|spawn|Serialize|Deserialize|Debug)\b|Arc\s*<\s*State\s*>',probe),'probe-lifetime-or-export')
    ensure(probe.count('async fn wait(')==1 and probe.count('release.changed().await')==1 and 'send_replace(true)' in probe and 'gate.release.receiver_count() > 0' in probe,'one-reviewed-watch-release-gate')
    gate=re.search(r'pub\(super\) struct IntentGate\s*\{(.*?)\n\}',probe,re.S)
    ensure(gate is not None and normalize(gate[1])==normalize('binding: PreparedIntent, prepared_payload_digest: [u8; 32], release: tokio::sync::watch::Sender<bool>, entered: std::sync::atomic::AtomicBool,'),'immutable-binding-watch-only-gate')
    for relation in ['captured.nonce == gate.binding.nonce','captured.account == gate.binding.account','captured.protected_group == gate.binding.protected_group','captured.local_device == gate.binding.peer_device','captured.peer_device == gate.binding.local_device','entry.departures.pending_action_for_test() != Some(binding.action)','binding.nonce != entry.channel.scope().nonce','body.kind == AccountSharedBodyKind::DepartureIntent']:
        ensure(normalize(relation) in normalize(probe),'actual-prepared-peer-binding-and-reversed-roles')
    fixture=Path(TEST).read_text()
    ensure(fixture.index('fs_private::ensure_private_db_files(&path)')<fixture.index('rusqlite::Connection::open(&path)'),'safe-new-upstream-injector-open-order')
    for name in NEW:
        if name.endswith('.py'):ast.parse(Path(name).read_text())
    report={'source':subprocess.check_output(['git','rev-parse','HEAD'],text=True).strip(),'baseline':cohort_baseline or BASE,'historical_baseline':BASE,'hook_blocks':counts,'original_five_fixture_bytes_exact':True,'original_five_comparison_baseline':cohort_baseline or BASE,'stripped_product_tokens_and_strings_exact':True if not cohort else None,'historical_stripped_source_comparison_reused':False if cohort else True,'parser_controls':parser_preflight(),'actual_runtime_bodies':0,'qualification_passed':False}
    if cohort:report['reviewed_extraction_cohort']=cohort
    Path('body-negative-source.json').write_text(json.dumps(report,indent=2)+'\n')
    return report
if __name__=='__main__':
    parser=argparse.ArgumentParser();parser.add_argument('--cohort-baseline',default=os.environ.get('UPSTREAM_EXTRACTION_COHORT_BASELINE'));args=parser.parse_args();main(args.cohort_baseline)
