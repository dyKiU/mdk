#!/usr/bin/env python3
"""One strict real SDK five-installation component control; no global qualification."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import qualify_upstream_pure_command_offer as offer
import qualify_upstream_storage_boundary as bounded
import qualify_upstream_storage_app_handles as counts
from upstream_completion_ci import compile_cases, digest, ensure
from qualify_upstream_body_negative import feature_identity
from upstream_extraction_cohort import frozen_inputs
BASE='d9cef842e698f274530d0ffd71ec7cc77682e5b3'
MANIFEST_SHA='b3e03ef30c21f296befd201e19c48ddf6bba020bb254278f4a1733e932841e5c'
SELF='scripts/qualify_upstream_pure_native5.py'
MANIFEST='scripts/pure_command_offer_source_manifest.json'
REF='refs/heads/ci/upstream-command-offer-pure-20261018'
OUT=Path('pure-native5-evidence')
FIXTURE='crates/marmot-app/src/native_device_linking/tests/sequential_installations_acceptance.rs'
PARENT='crates/marmot-app/src/native_device_linking/tests/automatic_pairing_acceptance.rs'
FIXTURE_SHA='a81cc692c9864d9cdf2ff7fe8d533d3115c7eb7958fa7a22df783850fea520ca'
STRICT_HELPER_SHA='a059addf027097d91c672ccfe36e613f99cfb93f889ab2087b872a84c7a58ff2'
ORACLE_SHA='88417f89d6d6b3b9a8037d408be60c54d8b86451085cff9d254cb6cc74537e72'
SUFFIX='sequential_installations_acceptance::five_installations_join_with_rotating_existing_sponsors_and_explicit_sharing'
NAME='native_device_linking::automatic_pairing_acceptance::'+SUFFIX
NODES={'marmot_app','cgka_engine','storage_sqlite','cgka_session','marmot_account','transport_nostr'}
MARKER='sequential-installations completed_steps=4 final_device_count=5 final_roster_and_policies=true public_cancels=14 runtime_closes=5 storages_closed=true plane_shutdown_returns=5 listener_closed=true attempt_completed=true'


def source_guard():
    ensure(type(BASE) is str and re.fullmatch('[0-9a-f]{40}',BASE),'final-pure-native5-BASE-required')
    ensure(type(MANIFEST_SHA) is str and re.fullmatch('[0-9a-f]{64}',MANIFEST_SHA),'final-shared-native5-manifest-required')
    ensure(BASE==offer.BASE and MANIFEST_SHA==offer.MANIFEST_SHA and REF==offer.REF and MANIFEST==offer.MANIFEST,'shared-configuration-equality')
    ensure(digest(Path(MANIFEST).read_bytes())==MANIFEST_SHA,'native5-shared-manifest-pin')
    manifest,row=offer.source_guard() # Only the new shared guard; never another controller main.
    pins=manifest['native5']
    ensure(pins['fixture']==FIXTURE and pins['fixture_sha256']==FIXTURE_SHA
        and pins['parent']==PARENT and re.fullmatch('[0-9a-f]{64}',pins['parent_sha256'])
        and pins['strict_helper_sha256']==STRICT_HELPER_SHA and pins['oracle_region_sha256']==ORACLE_SHA,'explicit-native5-source-pins')
    ensure(digest(Path(FIXTURE).read_bytes())==FIXTURE_SHA and digest(Path(PARENT).read_bytes())==pins['parent_sha256'],'exact-final-native5-fixture-parent')
    parent=Path(PARENT).read_text();start=parent.index('async fn wait_for_automatic_phase_with_approvals(')
    end=parent.index('\n}\n',start)+3
    ensure(digest(parent[start:end].encode())==STRICT_HELPER_SHA,'unchanged-strict15-helper')
    text=Path(SELF).read_text();begin='# NATIVE5_IMMUTABLE_ORACLE_BEGIN\n';endmark='# NATIVE5_IMMUTABLE_ORACLE_END\n'
    ensure(text.count(begin)==text.count(endmark)==1,'one-immutable-native5-oracle')
    oracle=text.split(begin,1)[1].split(endmark,1)[0]
    ensure(digest(oracle.encode())==ORACLE_SHA,'verbatim-reviewed-native5-oracle')
    return row

# NATIVE5_IMMUTABLE_ORACLE_BEGIN
def parse(raw,code):
    # Exact-name/count parser is unchanged shared infrastructure. Preserve original libtest prefix.
    row=counts.parse_body(raw,code,NAME)
    clean=re.sub(r'\x1b\[[0-9;]*m','',raw)
    marker_text=re.sub(r'(?m)^test '+re.escape(NAME)+r' \.\.\. (?=sequential-installations )','',clean)
    lines=[line for line in marker_text.splitlines() if line.startswith('sequential-installations')]
    row['marker_count']=len(lines);row['facts']=None
    pattern=(r'sequential-installations completed_steps=([0-4]) final_device_count=([0-5]) final_roster_and_policies=(true|false)'
        r' public_cancels=([0-9]{1,2}) runtime_closes=([0-5]) storages_closed=(true|false) plane_shutdown_returns=([0-5])'
        r' listener_closed=(true|false) attempt_completed=(true|false)')
    match=re.fullmatch(pattern,lines[0]) if len(lines)==1 and len(lines[0])<=512 else None
    if match and int(match[4])<=14:
        row['facts']={'completed_steps':int(match[1]),'final_device_count':int(match[2]),'final_roster_and_policies':match[3]=='true',
            'public_cancels':int(match[4]),'runtime_closes':int(match[5]),'storages_closed':match[6]=='true',
            'plane_shutdown_returns':int(match[7]),'listener_closed':match[8]=='true','attempt_completed':match[9]=='true'}
    return row

def green(row):
    facts=row.get('facts')
    return (row.get('actual_counts_complete') is True and row.get('passed_gate') is True
        and all(type(row.get(k)) is int and row[k]==v for k,v in {'passed':1,'failed':0,'ignored':0,'executed_nonignored':1,'exit_code':0,'compiler_error_count':0,'panic_count':0,'marker_count':1}.items())
        and isinstance(facts,dict) and all(type(facts.get(k)) is int and facts[k]==v for k,v in
            {'completed_steps':4,'final_device_count':5,'public_cancels':14,'runtime_closes':5,'plane_shutdown_returns':5}.items())
        and all(facts.get(k) is True for k in ['final_roster_and_policies','storages_closed','listener_closed','attempt_completed']))

def parser_controls():
    inherited=counts.parser_controls()
    raw='running 1 test\ntest '+NAME+' ... ok\n'+MARKER+'\ntest result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 2 filtered out; finished in 1.0s\n'
    ensure(green(parse(raw,0)),'closed-five-positive')
    shared=raw.replace(' ... ok\n'+MARKER,' ... '+MARKER+'\nok')
    ensure(green(parse(shared,0)),'exact-libtest-shared-marker-positive')
    bad=[raw.replace('completed_steps=4','completed_steps=3'),raw.replace('final_device_count=5','final_device_count=4'),
        raw.replace('final_roster_and_policies=true','final_roster_and_policies=false'),raw.replace('public_cancels=14','public_cancels=13'),
        raw.replace('runtime_closes=5','runtime_closes=4'),raw.replace('storages_closed=true','storages_closed=false'),
        raw.replace('plane_shutdown_returns=5','plane_shutdown_returns=4'),raw.replace('listener_closed=true','listener_closed=false'),
        raw.replace('attempt_completed=true','attempt_completed=false'),raw+'\n'+MARKER,raw.replace(MARKER,''),
        raw.replace(NAME,NAME+'_foreign'),raw.replace('0 ignored','1 ignored'),raw.replace('1 passed','0 passed'),
        raw.replace(MARKER,MARKER+' private=hidden'),raw.replace('public_cancels=14','public_cancels=99'),raw.replace('storages_closed=true','storages_closed=hidden'),
        raw+raw,raw+'error[E0000]: rejected\n',raw+"thread 'closed' panicked at crates/closed.rs:1:1:\n"]
    for text in bad:ensure(not green(parse(text,0)),'closed-five-adversary')
    ensure(not green(parse(raw,124)),'watchdog-not-pass')
    row=parse(raw,0)
    for key in ['passed','failed','ignored','executed_nonignored','exit_code','compiler_error_count','panic_count','marker_count']:
        ensure(not green({**row,key:True}),'bool-not-body-count')
    return {'shared_count_inventory_controls':inherited,'positive':2,'negative':len(bad)+9,'actual_runtime_executions':0}

# NATIVE5_IMMUTABLE_ORACLE_END


def safe_compilation(row):
    # Preserve closed compiler codes and source sites, never private diagnostic text.
    raw=row.pop('compiler_headers',[])
    row['compiler_codes']=sorted(set(code for line in raw for code in re.findall(r'\berror\[(E[0-9]{4})\]',line)))
    row['compiler_sites']=[{'file':match[1],'line':int(match[2]),'column':int(match[3])}
        for line in raw if (match:=re.fullmatch(r'\s*--> (crates/[A-Za-z0-9_./-]+\.rs):([0-9]{1,7}):([0-9]{1,7})',line))]
    return row


def execute_one(report,save):
    """Reusable one-case body runner; caller owns source guard and global qualification."""
    frozen=frozen_inputs();binary=None;before_sha=None
    report.update(runtime_execution_attempted=False,actual_counts_complete=False,actual_passed=None,
        actual_failed=None,actual_ignored=None,actual_executed_nonignored=None,native5_component_control_passed=False)
    report['source_manifest_sha256']=digest(json.dumps(frozen,sort_keys=True).encode());save()
    try:
        report['capacity']={'free_bytes':shutil.disk_usage('.').free,'minimum_free_bytes':8*1024**3};save()
        ensure(report['capacity']['free_bytes']>=8*1024**3,'remote-capacity')
        compilation,cases=compile_cases([SUFFIX]);report['compilation']=safe_compilation(compilation);save()
        ensure(type(compilation.get('compile_exit_code')) is int and compilation['compile_exit_code']==0
            and type(compilation.get('compiler_error_count')) is int and compilation['compiler_error_count']==0
            and compilation.get('compiled_fingerprints',{}).get('verified') is True and set(cases)=={SUFFIX},'one-actual-compiled-native5-case')
        case=cases[SUFFIX];ensure(case['name']==NAME,'exact-native5-fullname')
        binary=Path(case['binary']);before_sha=case['binary_sha256']
        report['binary_before_sha256']=before_sha;report['feature_identity']=feature_identity(compilation);save()
        ensure(set(report['feature_identity']['nodes'])==NODES,'six-real-feature-fingerprints')
        for ignored in [False,True]:
            command=[case['binary'],'--exact',NAME]+(['--ignored'] if ignored else [])+['--list','--format','terse']
            code,raw,_=bounded.capture(command,60,limit=1024*1024)
            row=counts.parse_inventory(raw,NAME,ignored)
            report.setdefault('inventory',{})['ignored' if ignored else 'normal']=row;save()
            ensure(code==0 and row['passed'],'exact-one-nonignored-native5-inventory')
        ensure(frozen_inputs()==frozen and binary.is_file() and digest(binary.read_bytes())==before_sha,'before-native5-inputs-binary-pristine')
        report['runtime_execution_attempted']=True;save()
        try:
            code,raw,seconds=bounded.capture([case['binary'],'--exact',NAME,'--nocapture','--test-threads=1'],900,limit=8*1024*1024)
            # Save observed counts and physical post-body checks before strict marker classification.
            report['body_seconds']=seconds;report['body_exit_code']=code
            basic=counts.parse_body(raw,code,NAME);report['body']=basic
            report['actual_counts_complete']=basic.get('actual_counts_complete') is True
            for target,key in [('actual_passed','passed'),('actual_failed','failed'),('actual_ignored','ignored'),('actual_executed_nonignored','executed_nonignored')]:
                report[target]=basic.get(key)
            report['binary_after_sha256']=digest(binary.read_bytes()) if binary.is_file() else None
            report['inputs_after_body_pristine']=frozen_inputs()==frozen
            report['binary_after_body_pristine']=report['binary_after_sha256']==before_sha;save()
            report['body']=parse(raw,code)
            report['native5_component_control_passed']=green(report['body'])
            report['plane_shutdown_semantics']='five returned shutdown calls; internal task quiescence not established';save()
        except bounded.GateFailure as error:
            report['watchdog_triggered']=str(error)=='bounded-command-timeout'
            report['output_limit_triggered']=str(error)=='bounded-command-output-limit';save();raise
        ensure(report['inputs_after_body_pristine'] and report['binary_after_body_pristine'],'after-native5-inputs-binary-pristine')
        ensure(report['native5_component_control_passed'],'actual-native5-all-four-joins-and-cleanup-required')
    finally:
        report['inputs_pristine']=frozen_inputs()==frozen
        if not report['runtime_execution_attempted']:report['actual_executed_nonignored']=0
        if binary is not None:
            report['binary_final_sha256']=digest(binary.read_bytes()) if binary.is_file() else None
            report['binary_pristine']=report['binary_final_sha256']==before_sha
        if report['inputs_pristine'] is not True or report.get('binary_pristine') is False:
            report['observed_body_control_passed']=report['native5_component_control_passed']
            report['native5_component_control_passed']=False
        save()
        ensure(report['inputs_pristine'],'final-native5-inputs-pristine')
        if binary is not None:ensure(report['binary_pristine'],'final-native5-binary-pristine')


def main(args):
    os.umask(0o077);OUT.mkdir(exist_ok=True)
    report={'baseline':BASE,'scope':'one-strict-real-SDK-five-installation-component','qualification_passed':False,
        'promotion_eligible':False,'SDK_native_UI_qualification':False,'full16_qualification':False,
        'native5_component_control_passed':False,'automatic_retries':0,'stack_bytes':4194304,'Tokio_workers':2}
    def save():(OUT/'result.json').write_text(json.dumps(report,indent=2)+'\n')
    try:
        report['source_guard']=source_guard();report['parser_controls']=parser_controls();save()
        if args.preflight:report['preflight_passed']=True;save();return
        execute_one(report,save)
    except Exception as error:
        report['exception_type']=type(error).__name__
        if isinstance(error,ValueError):report['failure_gate']=str(error) if re.fullmatch('[A-Za-z0-9_.:/-]{1,140}',str(error)) else 'closed-gate-rejected'
        save();raise

if __name__=='__main__':
    parser=argparse.ArgumentParser();parser.add_argument('--preflight',action='store_true');main(parser.parse_args())
