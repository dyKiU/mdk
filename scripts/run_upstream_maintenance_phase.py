#!/usr/bin/env python3
"""One unchanged ordinary body plus a real CPU-field parser control; no qualification."""
import argparse
import ast
import json
import re
import stat
import subprocess
import time
from pathlib import Path
from upstream_completion_ci import ORIGINALS, compile_cases, ensure, environment, freeze, headers, identity, parse_body
from verify_upstream_completion_candidate_source import normalize
import upstream_maintenance_phase as evidence
import upstream_maintenance_tokens as tokens

BASE='a5b1d906134f566580c65a1372211ff751f92eef'
PREFIX='crates/marmot-app/src/'
FIXTURE=PREFIX+'native_device_linking/tests/automatic_pairing_acceptance.rs'
CLIENT=PREFIX+'client/device_linking.rs'
WORKER=PREFIX+'runtime/account_worker.rs'
LIB=PREFIX+'lib.rs'
MODULE=PREFIX+'maintenance_phase_diagnostics.rs'
SELF='scripts/run_upstream_maintenance_phase.py'
PARSER='scripts/upstream_maintenance_phase.py'
WORKFLOW='.github/workflows/experimental-sync-ci.yml'
TOKENS='scripts/upstream_maintenance_tokens.py'
ALLOWED=[FIXTURE,CLIENT,WORKER,LIB,MODULE,SELF,PARSER,TOKENS,WORKFLOW]
SUBTREE_BASE='b5bc56b69b647c028b1af3af3059d33f07ccb6dc'
SUBTREES={7:{'service_sibling_publication_completions'},8:{'ingest_observed_received_delivery'},9:{'handle_account_worker_command'},10:{'advance_convergence_with_projection_progress_and_yield'},11:{'admit_comparison_turn','finish_comparison_grant','accept_comparison_network','admit_private_echo_recovery','start_pending_recovery_job','finish_pending_welcome_delivery_recovery_best_effort'},12:{'sync_automatically_with_partial_progress','handle_account_worker_catch_up'},13:{'finish_periodic_maintenance_after_recovery'},14:{'finish_receive_after_recovery'},15:{'start_post_join_history_after_visibility'},16:{'publish','publish_revoked_settlement','publish_existing_settlement'}}
SYNC_SUBTREES={17:{'pending_native_private_publication','pending_revoked_settlement','pending_existing_private_settlement','pending_private_settlement','start_private_echo_recovery'}}
CPU_CASE='maintenance_phase_cpu_stat_parser_refuses_unqualified_fields'
ORDINARY=ORIGINALS[0]
CFG='#[cfg(all(test, feature = "experimental-device-sync", feature = "test-policy-overrides"))]'
NOT_CFG='#[cfg(not(all(test, feature = "experimental-device-sync", feature = "test-policy-overrides")))]'
OUT=Path('maintenance-phase-evidence')
CFG_NOT_PATTERN = r'\#\s*\[\s*cfg\s*\(\s*not\s*\(\s*all\s*\(\s*test\s*,\s*feature\s*=\s*"experimental-device-sync"\s*,\s*feature\s*=\s*"test-policy-overrides"\s*,?\s*\)\s*\)\s*\)\s*\]'

def split_cfg_not(content):
    matches=list(re.finditer(CFG_NOT_PATTERN,content))
    ensure(len(matches)==1,'one-production-cfg-attribute')
    match=matches[0];ensure(normalize(match[0])==normalize(NOT_CFG),'production-cfg-identity')
    return [content[:match.start()],content[match.end():]]

def guard_parser_preflight():
    multiline='# [ cfg ( not ( all ( test, feature = "experimental-device-sync", feature = "test-policy-overrides", ) ) ) ]'
    ensure(split_cfg_not('before'+NOT_CFG+'after')==['before','after'],'single-line-cfg-positive')
    ensure(split_cfg_not('before'+multiline+'after')==['before','after'],'formatted-cfg-positive')
    negative=0
    for content in ['',NOT_CFG+NOT_CFG,multiline.replace('test-policy-overrides','other'),multiline.replace('not','any'),multiline.replace('experimental-device-sync','other')]:
        refused=False
        try:split_cfg_not(content)
        except ValueError:refused=True
        ensure(refused,'unreviewed-or-duplicate-cfg-negative');negative+=1
    from unittest.mock import patch
    for error in [OSError('unavailable'),subprocess.TimeoutExpired(['getconf','CLK_TCK'],5)]:
        with patch('subprocess.run',side_effect=error): value=read_hz()
        ensure(value['hz'] is None and value['known'] is False and value.get('exception'),'unknown-clock-command-negative');negative+=1
    return {'positive_controls':2,'negative_controls':negative,'actual_product_bodies':0}

def read_hz():
    try:
        result=subprocess.run(['getconf','CLK_TCK'],capture_output=True,timeout=5)
        value=evidence.clock_hz(result.stdout) if result.returncode==0 else None
        return {'exit_code':result.returncode,'hz':value,'known':value is not None}
    except (OSError,subprocess.TimeoutExpired) as error:
        return {'hz':None,'known':False,'exception':type(error).__name__}

def record_pristine(report,frozen):
    after=freeze();quiet=subprocess.run(['git','diff','--quiet','HEAD']).returncode==0
    report['source_after_sha256']=identity(after)
    report['git_diff_head_quiet']=quiet
    report['inputs_pristine']=frozen==after and quiet
    return report['inputs_pristine']

def original(name): return subprocess.check_output(['git','show',BASE+':'+name],text=True)
def remove_block(text,name):
    pattern=r'(?m)^[ \t]*// '+name+r'_BEGIN\n.*?^[ \t]*// '+name+r'_END\n'
    ensure(len(re.findall(pattern,text,re.S))==1,'exact-one-hook:'+name)
    return re.sub(pattern,'',text,flags=re.S)

def source_preflight():
    changed=set(subprocess.check_output(['git','diff','--name-only',BASE],text=True).splitlines())
    ensure(changed<=set(ALLOWED),'unreviewed-source-or-config')
    for line in subprocess.check_output(['git','diff','--raw',BASE],text=True).splitlines():
        modes=line.split()[:2];ensure(modes[0] in {':100644',':000000'} and modes[1]=='100644','source-mode-changed')
    for name in ALLOWED:
        ensure(stat.S_ISREG(Path(name).lstat().st_mode) and not stat.S_IMODE(Path(name).lstat().st_mode)&0o111,'regular-nonexecutable-source')
    for name in [SELF,PARSER,TOKENS]: ast.parse(Path(name).read_text())
    for name in [FIXTURE,CLIENT,LIB]:
        ensure(Path(name).read_bytes()==subprocess.check_output(['git','show',SUBTREE_BASE+':'+name]),'frozen-b5-fixture-and-call-groups:'+name)
    client=Path(CLIENT).read_text();before=original(CLIENT)
    for phase in range(7):
        pattern=r'(?m)^[ \t]*// MAINTENANCE_PHASE_GROUP_'+str(phase)+r'_BEGIN\n(.*?)^[ \t]*// MAINTENANCE_PHASE_GROUP_'+str(phase)+r'_END'
        matches=list(re.finditer(pattern,client,re.S));ensure(len(matches)==1,'exact-phase-group')
        content=matches[0][1];split=split_cfg_not(content)
        production=split[1].strip();ensure(production.startswith('{') and production.endswith('}'),'production-group-braces');production=production[1:-1]
        expected=CFG+'\ncrate::maintenance_phase_diagnostics::observe_phase('+str(phase)+', Box::pin(async {\n'+production+'\nOk::<(), ClientLinkingError>(())\n})).await?;'
        ensure(normalize(split[0])==normalize(expected),'instrumented-original-group-changed')
        client=client[:matches[0].start()]+production+client[matches[0].end():]
    ensure(normalize(client)==normalize(before),'original-maintenance-or-error-order-changed')
    worker=Path(WORKER).read_text()
    macros=re.findall(r'(?m)^// MAINTENANCE_SUBTREE_MACRO_BEGIN\n(.*?)^// MAINTENANCE_SUBTREE_MACRO_END',worker,re.S)
    ensure(len(macros)==1,'one-reviewed-subtree-macro-block')
    expected_macros = """macro_rules! maintenance_phase_future {
    ($phase:literal, $future:expr $(,)?) => {{
        #[cfg(all(test, feature = "experimental-device-sync", feature = "test-policy-overrides"))]
        { crate::maintenance_phase_diagnostics::observe_phase($phase, Box::pin($future)) }
        #[cfg(not(all(test, feature = "experimental-device-sync", feature = "test-policy-overrides")))]
        { $future }
    }};
}
macro_rules! maintenance_phase_sync {
    ($phase:literal, $expression:expr $(,)?) => {{
        #[cfg(all(test, feature = "experimental-device-sync", feature = "test-policy-overrides"))]
        { crate::maintenance_phase_diagnostics::observe_sync($phase, || $expression) }
        #[cfg(not(all(test, feature = "experimental-device-sync", feature = "test-policy-overrides")))]
        { $expression }
    }};
}
"""
    ensure(normalize(macros[0])==normalize(expected_macros),'macro-same-future-identity')
    worker=remove_block(worker,'MAINTENANCE_SUBTREE_MACRO')
    worker,subtree_counts=tokens.unwrap(worker,SUBTREES)
    worker,sync_counts=tokens.unwrap(worker,SYNC_SUBTREES,'maintenance_phase_sync!')
    subtree_original=subprocess.check_output(['git','show',SUBTREE_BASE+':'+WORKER],text=True)
    ensure(normalize(worker)==normalize(subtree_original),'original-b5-worker-calls-changed')
    pattern=r'(?m)^[ \t]*// MAINTENANCE_PHASE_WORKER_BEGIN\n(.*?)^[ \t]*// MAINTENANCE_PHASE_WORKER_END'
    found=list(re.finditer(pattern,worker,re.S));ensure(len(found)==1,'exact-worker-hook');parts=split_cfg_not(found[0][1])
    production=parts[1].strip();ensure(production.startswith('{') and production.endswith('}'),'worker-braces');production=production[1:-1]
    expected=production.replace('tokio::spawn(Box::pin(', 'tokio::spawn(crate::maintenance_phase_diagnostics::observe_worker(Box::pin(',1)
    at=expected.rfind(')))');ensure(at>=0,'worker-original-spawn');expected=expected[:at]+'))))'+expected[at+3:]
    ensure(normalize(parts[0])==normalize(CFG+'{'+expected+'}'),'worker-context-future-changed')
    ensure(normalize(worker[:found[0].start()]+production+worker[found[0].end():])==normalize(original(WORKER)),'worker-original-changed')
    lib=Path(LIB).read_text();ensure(normalize(remove_block(lib,'MAINTENANCE_PHASE_MODULE'))==normalize(original(LIB)),'original-lib-changed')
    fixture=Path(FIXTURE).read_text();start=re.findall(r'(?m)^[ \t]*// MAINTENANCE_PHASE_BOUNDARY_BEGIN\n(.*?)^[ \t]*// MAINTENANCE_PHASE_BOUNDARY_END',fixture,re.S);end=re.findall(r'(?m)^[ \t]*// MAINTENANCE_PHASE_VERDICT_BEGIN\n(.*?)^[ \t]*// MAINTENANCE_PHASE_VERDICT_END',fixture,re.S)
    ensure(len(start)==len(end)==1,'exact-fixture-hooks')
    ensure(normalize(start[0])==normalize('#[cfg(feature = "test-policy-overrides")] crate::maintenance_phase_diagnostics::boundary(true);'),'start-boundary-only')
    expected='.inspect(|_| { #[cfg(feature = "test-policy-overrides")] crate::maintenance_phase_diagnostics::boundary(false); }).inspect_err(|_| { #[cfg(feature = "test-policy-overrides")] crate::maintenance_phase_diagnostics::boundary(false); })'
    ensure(normalize(end[0])==normalize(expected),'frozen-verdict-only')
    stripped=remove_block(remove_block(fixture,'MAINTENANCE_PHASE_BOUNDARY'),'MAINTENANCE_PHASE_VERDICT')
    ensure(normalize(stripped)==normalize(original(FIXTURE)),'original-five-fixtures-changed')
    marker=fixture.index('// MAINTENANCE_PHASE_BOUNDARY_BEGIN');ensure(marker<fixture.index('stage=fourth-device-completion',marker),'fourth-start-location')
    return {'source':subprocess.check_output(['git','rev-parse','HEAD'],text=True).strip(),'baseline':BASE,'seven_groups_exact_original_tokens':True,'five_fixtures_exact_after_explicit_hook_strip':True,'all_other_tracked_bytes_and_modes_frozen':True,'parser_preflight':evidence.parser_preflight(),'source_parser_preflight':guard_parser_preflight(),'balanced_call_parser':tokens.parser_preflight(),'subtree_baseline':SUBTREE_BASE,'future_subtree_counts':subtree_counts,'sync_selection_counts':sync_counts,'actual_runtime_bodies':0,'qualification_passed':False}

def execute(case,suffix,report,save):
    row={'test':case['name'],'suffix':suffix,'binary_sha256':case['binary_sha256']};report['bodies'].append(row);save();start=time.monotonic()
    try:
        result=subprocess.run([case['binary'],'--exact',case['name'],'--nocapture','--test-threads=1'],capture_output=True,text=True,timeout=300)
        raw=re.sub(r'\x1b\[[0-9;]*m','',result.stdout+result.stderr)
        row.update(body_exit_code=result.returncode,body_seconds=time.monotonic()-start);save()
    except subprocess.TimeoutExpired as error:
        raw=(error.stdout or b'')+(error.stderr or b'') if isinstance(error.stdout or error.stderr,bytes) else (error.stdout or '')+(error.stderr or '')
        if isinstance(raw,bytes):raw=raw.decode('utf-8',errors='replace')
        row.update(watchdog_triggered=True,actual_count_unknown=True,body_seconds=time.monotonic()-start);save()
    try:
        row.update(parse_body(raw,suffix),**headers(raw));row['named_cases']=re.findall(r'(?m)^test ([A-Za-z_0-9:]+) \.\.\.',raw)
        if suffix==CPU_CASE:
            row['parser_controls']=re.findall(r'(?m)^maintenance-phase-cpu-parser positive=([0-9]+) negative=([0-9]+)$',raw)
        else:
            row['measurement']=evidence.collect(raw,report['cpu_clock']['hz'])
    except Exception as error: row['parser_exception']=type(error).__name__
    row['actual_control_passed']=row.get('body_exit_code')==0 and row.get('passed')==1 and row.get('failed')==row.get('ignored')==0 and row.get('executed_nonignored')==1 and row.get('named_cases')==[case['name']] and row.get('all_panic_header_count')==0 and row.get('compiler_error_count')==0 and not row.get('watchdog_triggered') and not row.get('actual_count_unknown')
    if suffix==CPU_CASE: row['actual_control_passed'] &= row.get('parser_controls')==[('2','14')]
    save();return row

def main():
    parser=argparse.ArgumentParser();parser.add_argument('--mode',choices=['preflight','run'],required=True);args=parser.parse_args();OUT.mkdir(exist_ok=True)
    report={'qualification_passed':False,'phase_collection_complete':False,'cpu_known':False,'poll_window_confident':False,'mode':args.mode,'bodies':[],'limits':['Diagnostic only; no merge qualification','Poll wall durations exclude await suspension but include nested synchronous work; not per-operation CPU','Eighteen aggregate categories include nested worker subtrees; inclusive and nonadditive; never sum phases or add to worker totals','Stable-epoch observations exclude boundary straddles; active/unknown/unwind data cannot establish a complete phase inventory','Phase17 measures immediate synchronous invocations; other rows measure future polls','Finite heap allocations and observer metadata locks add diagnostic overhead','Unmeasured gaps include synchronous projection/scheduling/route work outside selected futures and other worker arms','Private publication may serve foreground work internally; category16 is inclusive, not pure publication or transport cost','Exactly two boundary-only thread CPU reads; unsupported/absent data unknown']}
    def save(): (OUT/'result.json').write_text(json.dumps(report,indent=2)+'\n')
    frozen=freeze();report['source_before_sha256']=identity(frozen)
    try:
        report['source_preflight']=source_preflight();save()
        if args.mode=='preflight': return
        report.update(environment());report['baseline_test_source']=BASE;save()
        report['cpu_clock']=read_hz();save()
        compilation,cases=compile_cases([CPU_CASE,ORDINARY]);report['compilation']=compilation;save()
        ensure(compilation.get('compile_exit_code')==0 and compilation.get('compiler_error_count')==0 and compilation.get('compiled_fingerprints',{}).get('verified') and set(cases)=={CPU_CASE,ORDINARY},'compile-or-feature-inventory-failed')
        ensure(record_pristine(report,frozen),'source-changed-after-compile');save()
        cpu=execute(cases[CPU_CASE],CPU_CASE,report,save);ensure(cpu['actual_control_passed'],'real-cpu-parser-control-failed')
        ensure(record_pristine(report,frozen),'source-changed-after-cpu-parser');save()
        ordinary=execute(cases[ORDINARY],ORDINARY,report,save)
        record_pristine(report,frozen);save()
        ensure(report['inputs_pristine'],'source-changed')
        ensure(ordinary.get('executed_nonignored')==1 and ordinary.get('ignored')==0 and not ordinary.get('actual_count_unknown'),'actual-ordinary-count-required')
        measurement=ordinary.get('measurement',{})
        report['phase_collection_complete']=measurement.get('phase_collection_complete',False)
        report['cpu_known']=measurement.get('cpu_known',False)
        report['poll_window_confident']=measurement.get('poll_window_confident',False)
        save()
        ensure(measurement.get('boundary_order_valid') and report['phase_collection_complete'] and report['cpu_known'] and report['poll_window_confident'],'complete-fourth-phase-measurement-required')
        ensure(ordinary['actual_control_passed'],'original-ordinary-failed-diagnostic-retained')
    except Exception as error: report['controller_exception']=type(error).__name__;save();raise
    finally:
        if frozen is not None:
            try:record_pristine(report,frozen)
            except Exception as error:report['inputs_pristine']=False;report['pristine_exception']=type(error).__name__
        save()
if __name__=='__main__':main()
