#!/usr/bin/env python3
"""Remote-only passive ingest attribution; unchanged original ordinary acceptance."""
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
import upstream_ingest_phase as evidence
import upstream_ingest_tokens as tokens
BASE='cb22134ea90cc6ec88fe556cab90717908e67858'
PREFIX='crates/marmot-app/src/'
FIXTURE=PREFIX+'native_device_linking/tests/automatic_pairing_acceptance.rs'
WORKER=PREFIX+'runtime/account_worker.rs'
SYNC=PREFIX+'client/sync.rs'
SHARING=PREFIX+'client/account_chat_sharing.rs'
PRIVATE=PREFIX+'client/private_transport.rs'
LIB=PREFIX+'lib.rs'
MODULE=PREFIX+'maintenance_phase_diagnostics.rs'
SELF='scripts/run_upstream_ingest_phase.py'
PARSER='scripts/upstream_ingest_phase.py'
TOKENS='scripts/upstream_ingest_tokens.py'
WORKFLOW='.github/workflows/experimental-sync-ci.yml'
ALLOWED=[FIXTURE,WORKER,SYNC,SHARING,PRIVATE,LIB,MODULE,SELF,PARSER,TOKENS,WORKFLOW]
CPU_CASE='maintenance_phase_cpu_stat_parser_refuses_unqualified_fields'
ORDINARY=ORIGINALS[0]
CFG='#[cfg(all(test, feature = "experimental-device-sync", feature = "test-policy-overrides"))]'
NOT_CFG='#[cfg(not(all(test, feature = "experimental-device-sync", feature = "test-policy-overrides")))]'
OUT=Path('ingest-phase-evidence')
CFG_NOT_PATTERN=r'\#\s*\[\s*cfg\s*\(\s*not\s*\(\s*all\s*\(\s*test\s*,\s*feature\s*=\s*"experimental-device-sync"\s*,\s*feature\s*=\s*"test-policy-overrides"\s*,?\s*\)\s*\)\s*\)\s*\]'
FUTURES={WORKER:{0:{'client.ingest_observed_received_delivery('}},SYNC:{1:{'client.runtime.ingest_private_enrollment_delivery_with_observer_until(','client.runtime.ingest_delivery_with_observer('},2:{'client.retry_applied_effect_projections('}}}
SYNCHRONOUS={SYNC:{3:{'self.observe_account_sharing_control('},8:{'self.refresh_group_routes('},9:{'self.save_state_with_pending_local_group_deletion_frontier_clears('},10:{'self.transport_receipts(','client.transport_receipts('}},SHARING:{4:{'self.authenticate_sharing_control_intake('},5:{'self.observe_sibling_sharing_control('},6:{'self.observe_automatic_sharing_control('}},PRIVATE:{7:{'self.runtime.session().private_transport_evidence('}}}

def original(name): return subprocess.check_output(['git','show',BASE+':'+name],text=True)
def remove_block(text,name):
    pattern=r'(?m)^[ \t]*// '+name+r'_BEGIN\n.*?^[ \t]*// '+name+r'_END\n'
    ensure(len(re.findall(pattern,text,re.S))==1,'exact-one-hook:'+name)
    return re.sub(pattern,'',text,flags=re.S)

def split_cfg_not(content):
    matches=list(re.finditer(CFG_NOT_PATTERN,content));ensure(len(matches)==1,'one-production-cfg-attribute')
    match=matches[0];ensure(normalize(match[0])==normalize(NOT_CFG),'production-cfg-identity')
    return [content[:match.start()],content[match.end():]]

def read_hz():
    try:
        result=subprocess.run(['getconf','CLK_TCK'],capture_output=True,timeout=5)
        value=evidence.clock_hz(result.stdout) if result.returncode==0 else None
        return {'exit_code':result.returncode,'hz':value,'known':value is not None}
    except (OSError,subprocess.TimeoutExpired) as error:return {'hz':None,'known':False,'exception':type(error).__name__}

def record_pristine(report,frozen):
    after=freeze();quiet=subprocess.run(['git','diff','--quiet','HEAD']).returncode==0
    report['source_after_sha256']=identity(after);report['git_diff_head_quiet']=quiet;report['inputs_pristine']=frozen==after and quiet
    return report['inputs_pristine']

EXPECTED_MACROS='macro_rules! ingest_phase_future {\n    ($phase:literal, $future:expr $(,)?) => {{\n        #[cfg(all(test, feature = "experimental-device-sync", feature = "test-policy-overrides"))]\n        { crate::maintenance_phase_diagnostics::observe_phase($phase, Box::pin($future)) }\n        #[cfg(not(all(test, feature = "experimental-device-sync", feature = "test-policy-overrides")))]\n        { $future }\n    }};\n}\nmacro_rules! ingest_phase_sync {\n    ($phase:literal, $expression:expr $(,)?) => {{\n        #[cfg(all(test, feature = "experimental-device-sync", feature = "test-policy-overrides"))]\n        {\n            let diagnostic = crate::maintenance_phase_diagnostics::SyncObservation::begin($phase);\n            let diagnostic_result = $expression;\n            diagnostic.finish();\n            diagnostic_result\n        }\n        #[cfg(not(all(test, feature = "experimental-device-sync", feature = "test-policy-overrides")))]\n        { $expression }\n    }};\n}\n'

def guard_parser_preflight():
    formatted='# [ cfg ( not ( all ( test, feature = "experimental-device-sync", feature = "test-policy-overrides", ) ) ) ]'
    ensure(split_cfg_not('a'+NOT_CFG+'b')==['a','b'],'cfg-single-positive')
    ensure(split_cfg_not('a'+formatted+'b')==['a','b'],'cfg-formatted-positive');negative=0
    for value in ['',NOT_CFG+NOT_CFG,formatted.replace('test-policy-overrides','other'),formatted.replace('not','any'),formatted.replace('experimental-device-sync','other')]:
        refused=False
        try:split_cfg_not(value)
        except ValueError:refused=True
        ensure(refused,'cfg-negative');negative+=1
    from unittest.mock import patch
    for error in [OSError('unavailable'),subprocess.TimeoutExpired(['getconf','CLK_TCK'],5)]:
        with patch('subprocess.run',side_effect=error):value=read_hz()
        ensure(value['hz'] is None and value['known'] is False and value.get('exception'),'unknown-clock-negative');negative+=1
    return {'positive_controls':2,'negative_controls':negative,'actual_product_bodies':0}

def source_preflight():
    changed=set(subprocess.check_output(['git','diff','--name-only',BASE],text=True).splitlines());ensure(changed<=set(ALLOWED),'unreviewed-source-config-change')
    for line in subprocess.check_output(['git','diff','--raw',BASE],text=True).splitlines():
        modes=line.split()[:2];ensure(modes[0] in {':100644',':000000'} and modes[1]=='100644','source-mode-changed')
    for name in ALLOWED:ensure(stat.S_ISREG(Path(name).lstat().st_mode) and not stat.S_IMODE(Path(name).lstat().st_mode)&0o111,'regular-nonexecutable-source')
    for name in [SELF,PARSER,TOKENS]:ast.parse(Path(name).read_text())
    counts={}
    for name in [WORKER,SYNC,SHARING,PRIVATE]:
        text=Path(name).read_text();row={}
        if name in FUTURES:text,row['future']=tokens.unwrap(text,FUTURES[name],'ingest_phase_future!')
        if name in SYNCHRONOUS:text,row['synchronous']=tokens.unwrap(text,SYNCHRONOUS[name],'ingest_phase_sync!')
        counts[name]=row
        if name==WORKER:
            pattern=r'(?m)^[ \t]*// MAINTENANCE_PHASE_WORKER_BEGIN\n(.*?)^[ \t]*// MAINTENANCE_PHASE_WORKER_END'
            found=list(re.finditer(pattern,text,re.S));ensure(len(found)==1,'exact-worker-hook');parts=split_cfg_not(found[0][1]);production=parts[1].strip()
            ensure(production.startswith('{') and production.endswith('}'),'worker-braces');production=production[1:-1]
            expected=production.replace('tokio::spawn(Box::pin(', 'tokio::spawn(crate::maintenance_phase_diagnostics::observe_worker(Box::pin(',1);at=expected.rfind(')))');ensure(at>=0,'worker-original-spawn');expected=expected[:at]+'))))'+expected[at+3:]
            ensure(normalize(parts[0])==normalize(CFG+'{'+expected+'}'),'same-worker-future-context')
            text=text[:found[0].start()]+production+text[found[0].end():]
        ensure(normalize(text)==normalize(original(name)),'original-expression-error-order-changed:'+name)
    lib=Path(LIB).read_text();macros=re.findall(r'(?m)^// INGEST_ATTRIBUTION_MACRO_BEGIN\n(.*?)^// INGEST_ATTRIBUTION_MACRO_END',lib,re.S)
    ensure(len(macros)==1 and normalize(macros[0])==normalize(EXPECTED_MACROS),'borrow-preserving-identity-macros')
    module=re.findall(r'(?m)^// INGEST_ATTRIBUTION_MODULE_BEGIN\n(.*?)^// INGEST_ATTRIBUTION_MODULE_END',lib,re.S)
    ensure(len(module)==1 and normalize(module[0])==normalize(CFG+'mod maintenance_phase_diagnostics;'),'test-only-module')
    ensure(normalize(remove_block(remove_block(lib,'INGEST_ATTRIBUTION_MACRO'),'INGEST_ATTRIBUTION_MODULE'))==normalize(original(LIB)),'upstream-rootclosers-lib-changed')
    fixture=Path(FIXTURE).read_text();start=re.findall(r'(?m)^[ \t]*// MAINTENANCE_PHASE_BOUNDARY_BEGIN\n(.*?)^[ \t]*// MAINTENANCE_PHASE_BOUNDARY_END',fixture,re.S);end=re.findall(r'(?m)^[ \t]*// MAINTENANCE_PHASE_VERDICT_BEGIN\n(.*?)^[ \t]*// MAINTENANCE_PHASE_VERDICT_END',fixture,re.S)
    ensure(len(start)==len(end)==1,'exact-fixture-hooks')
    ensure(normalize(start[0])==normalize('#[cfg(feature = "test-policy-overrides")] crate::maintenance_phase_diagnostics::boundary(true);'),'start-boundary-only')
    expected='.inspect(|_| { #[cfg(feature = "test-policy-overrides")] crate::maintenance_phase_diagnostics::boundary(false); }).inspect_err(|_| { #[cfg(feature = "test-policy-overrides")] crate::maintenance_phase_diagnostics::boundary(false); })'
    ensure(normalize(end[0])==normalize(expected),'frozen-verdict-only')
    ensure(normalize(remove_block(remove_block(fixture,'MAINTENANCE_PHASE_BOUNDARY'),'MAINTENANCE_PHASE_VERDICT'))==normalize(original(FIXTURE)),'original-five-fixtures-changed')
    return {'source':subprocess.check_output(['git','rev-parse','HEAD'],text=True).strip(),'baseline':BASE,'all_original_source_expressions_and_error_order_restored':True,'five_fixtures_exact_after_explicit_hook_strip':True,'all_other_tracked_bytes_and_modes_frozen':True,'upstream_root_closers_unchanged':True,'call_counts':counts,'parser_preflight':evidence.parser_preflight(),'source_parser_preflight':guard_parser_preflight(),'balanced_call_parser':tokens.parser_preflight(),'actual_runtime_bodies':0,'qualification_passed':False}

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
    report={'qualification_passed':False,'phase_collection_complete':False,'cpu_known':False,'poll_window_confident':False,'mode':args.mode,'bodies':[],'limits':['Diagnostic only; no merge qualification','Poll wall durations exclude await suspension but include nested synchronous work; not per-operation CPU','Eleven aggregate categories are inclusive and NONADDITIVE; account runtime includes Engine plus existing publication; App projection contains nested dispatch','Stable-epoch observations exclude boundary straddles; active/unknown/unwind data cannot establish a complete phase inventory','Categories0..2 measure future polls;3..10 immediate synchronous invocations','Finite heap allocations and observer metadata locks add diagnostic overhead','Unmeasured gaps include private Welcome collection, reconciliation/bookkeeping between measured calls, ingress acquisition checks, and other worker arms','Exactly two boundary-only thread CPU reads; unsupported/absent data unknown']}
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
