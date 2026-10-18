#!/usr/bin/env python3
"""Two explicitly bounded App cohorts; diagnostic evidence never full qualification."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import qualify_upstream_storage_app_handles as common
from upstream_extraction_cohort import frozen_inputs
old = common.old
ensure = old.ensure
# Root pins only a reviewed, remote-formatted pure test-bearing commit.
BASE = '07da7dd155cd9c93b63afad5a8d8c4a63afbc209'
TEST_SHA256 = '1ecd52987c2d7b89ac4f9a1bffc141ae6c0db0e1d760ac8ae169854dd2aebb0a'
IDENTITY_ASSERTION_LINE = 7105
SELF = 'scripts/qualify_upstream_generated_identity_diagnostic.py'
TEST = 'crates/marmot-app/src/tests.rs'
WORKFLOW = '.github/workflows/upstream-boundary-regressions.yml'
REF = 'refs/heads/ci/upstream-generated-identity-diagnostic-20261018'
BEGIN = '  # GENERATED_IDENTITY_DIAGNOSTIC_JOBS_BEGIN\n'
END = '  # GENERATED_IDENTITY_DIAGNOSTIC_JOBS_END\n\n'
OPTIONS = 'options: [generated-identity-preflight, generated-identity-default-diagnostic, generated-identity-policy-experimental, '
OUT = Path('generated-identity-diagnostic-evidence')
IDENTITY = 'tests::generated_identity_returns_before_bootstrap_publication_unblocks'
POLICY = 'tests::account_worker_is_spawned_as_abortable_async_task'
FEATURES = {
    'default': ['marmot-app/test-policy-overrides', 'cgka-engine/test-policy-overrides', 'cgka-engine/test-crash-hooks'],
    'experimental': ['marmot-app/otlp-export', 'marmot-app/product-analytics-export', 'marmot-app/test-policy-overrides',
                     'marmot-app/experimental-device-sync', 'cgka-engine/test-policy-overrides', 'cgka-engine/test-crash-hooks'],
}
APP_FEATURES = {'default': ['default', 'test-policy-overrides'],
                'experimental': ['default', 'experimental-device-sync', 'otlp-export', 'product-analytics-export', 'test-policy-overrides']}
MARKER = 'generated_identity_blocked_publication'

def source_guard():
    ensure(isinstance(BASE, str) and re.fullmatch('[0-9a-f]{40}', BASE)
           and isinstance(TEST_SHA256, str) and re.fullmatch('[0-9a-f]{64}', TEST_SHA256)
           and isinstance(IDENTITY_ASSERTION_LINE, int) and IDENTITY_ASSERTION_LINE > 0, 'reviewed-fixture-unpinned')
    head = old.git('rev-parse', 'HEAD')
    ensure(os.environ.get('GITHUB_ACTIONS') == 'true' and os.environ.get('GITHUB_REPOSITORY') == 'dyKiU/mdk'
           and os.environ.get('GITHUB_EVENT_NAME') == 'workflow_dispatch' and os.environ.get('GITHUB_SHA') == head
           and os.environ.get('GITHUB_REF') == REF and os.environ.get('GITHUB_WORKFLOW_REF') == 'dyKiU/mdk/' + WORKFLOW + '@' + REF
           and os.environ.get('GENERATED_IDENTITY_BASELINE') == BASE, 'exact-owned-diagnostic-source')
    ensure(os.environ.get('CARGO_INCREMENTAL') == '1' and os.environ.get('CARGO_BUILD_JOBS') == '2'
           and os.environ.get('RUST_MIN_STACK') == '4194304'
           and all(os.environ.get(k) == '0' for k in ['CARGO_PROFILE_DEV_DEBUG', 'CARGO_PROFILE_TEST_DEBUG'])
           and all(not os.environ.get(k) for k in ['RUSTFLAGS','CARGO_ENCODED_RUSTFLAGS','RUSTC_BOOTSTRAP',
               'CARGO_PROFILE_DEV_OPT_LEVEL','CARGO_PROFILE_TEST_OPT_LEVEL']), 'explicit-build-profile')
    subprocess.run(['git','merge-base','--is-ancestor',BASE,head],check=True)
    ensure(subprocess.run(['git','diff','--quiet','HEAD']).returncode == 0, 'tracked-pristine')
    baseline = {}
    for entry in subprocess.check_output(['git','ls-tree','-r','-z',BASE]).split(b'\0'):
        if entry:
            meta,name = entry.split(b'\t',1); mode,kind,blob = meta.decode().split()
            ensure(kind == 'blob' and mode in {'100644','100755','120000'}, 'ordinary-baseline-layout')
            baseline[os.fsdecode(name)] = (mode,blob)
    frozen = frozen_inputs()
    ensure(SELF not in baseline and set(frozen) == set(baseline) | {SELF}, 'whole-frozen-source-inventory')
    for name,value in frozen.items():
        mode,blob = baseline.get(name,('100644',None))
        ensure(value['mode'] == mode and (mode == '120000' or value['actual_executable'] == (mode == '100755')), 'whole-source-mode')
        data = os.fsencode(os.readlink(name)) if mode == '120000' else Path(name).read_bytes()
        if name == TEST: ensure(old.digest(data) == TEST_SHA256, 'exact-formatted-test-fixture')
        if name == WORKFLOW:
            text=data.decode(); ensure(text.count(BEGIN)==text.count(END)==text.count(OPTIONS)==1, 'unique-owned-workflow-overlay')
            before,rest=text.split(BEGIN); _,after=rest.split(END)
            data=(before+after).replace(OPTIONS,'options: [',1).encode()
        if blob is not None:
            ensure(hashlib.sha1(b'blob '+str(len(data)).encode()+b'\0'+data).hexdigest()==blob, 'all-frozen-bytes:'+name)
    ensure(not subprocess.check_output(['git','ls-files','--others','--exclude-standard'],text=True).strip(), 'no-untracked-source')
    return {'source':head,'baseline':BASE,'whole_source_and_modes_exact':True,'test_fixture_sha256':TEST_SHA256,
            'pure_test_baseline_required':True,'historical_source_policy_assertions_preserved':True,
            'production_fix_claim':False,'whole_workspace_equivalence_claim':False}

def identity_marker(raw):
    clean=re.sub(r'\x1b\[[0-9;]*m','',raw)
    # Accept only the exact libtest function-prefix sharing pattern or a standalone marker.
    prefix='test '+IDENTITY+' ... '
    normalized=0
    lines=[]
    for line in clean.splitlines():
        if line.startswith(prefix+MARKER+' '): line=line[len(prefix):]; normalized+=1
        if line.startswith(MARKER): lines.append(line)
    ensure(len(lines)==1 and normalized<=1, 'one-closed-identity-marker')
    match=re.fullmatch(MARKER+r' held_kind_known=(true|false) held_kind=(0|[1-9][0-9]{0,19}) returned_readiness=([0-4]) live_readiness=([0-4])',lines[0])
    ensure(match is not None, 'closed-identity-marker-shape')
    known,kind,returned,live=match.groups(); kind=int(kind)
    ensure(kind<=18446744073709551615 and (known=='true' or kind==0), 'bounded-kind-and-explicit-unknown')
    return {'held_kind_known':known=='true','held_kind':kind if known=='true' else None,
            'returned_readiness':int(returned),'live_readiness':int(live),'exact_prefix_normalizations':normalized}

def diagnostic(raw, row):
    facts=identity_marker(raw)
    clean=re.sub(r'\x1b\[[0-9;]*m','',raw)
    all_locations=re.findall(r'panicked at ([A-Za-z0-9_./-]+\.rs):(\d+):(\d+):',clean)
    safe=[{'file':name,'line':int(line),'column':int(col)} for name,line,col in all_locations if name==TEST]
    complete=len(safe)==len(all_locations)==row['panic_count'] and len(safe)<=1
    observed_failure=(row['actual_counts_complete'] and row['exit_code']==101 and row['passed']==0 and row['failed']==1
        and row['ignored']==0 and row['compiler_error_count']==0 and complete and len(safe)==1
        and safe[0]['line']==IDENTITY_ASSERTION_LINE and facts['held_kind_known']
        and facts['returned_readiness']==1 and facts['live_readiness']==1)
    observed_pass=row['passed_gate'] and facts['held_kind_known'] and facts['returned_readiness']==1 and facts['live_readiness']==2
    return {'facts':facts,'safe_panic_locations':safe,'panic_locations_complete':complete,
            'original_specific_failure_observed':observed_failure,'original_test_PASS':observed_pass,
            'diagnostic_complete':observed_failure or observed_pass,'raw_error_or_event_payload_exported':False,
            'behavioral_fix_or_RED_claim':False}

def parser_controls():
    shared=common.parser_controls()
    marker=MARKER+' held_kind_known=true held_kind=30443 returned_readiness=1 live_readiness=1'
    ensure(identity_marker(marker)['held_kind']==30443, 'marker-positive')
    ensure(identity_marker('test '+IDENTITY+' ... '+marker)['exact_prefix_normalizations']==1, 'exact-prefix-positive')
    bad=[marker+' extra=private',marker+'\n'+marker,marker.replace('30443','18446744073709551616'),
         marker.replace('live_readiness=1','live_readiness=5'),marker.replace('known=true','known=unknown'),
         marker.replace('known=true','known=false'),marker.replace('30443','-1'),marker.replace('30443','030443'),
         marker.replace(' returned_readiness=1',''), 'test foreign ... '+marker]
    for value in bad:
        rejected=False
        try: identity_marker(value)
        except ValueError: rejected=True
        ensure(rejected,'malformed-marker-rejected')
    ensure(identity_marker(marker.replace('known=true held_kind=30443','known=false held_kind=0'))['held_kind'] is None, 'unknown-kind-preserved')
    raw='running 1 test\ntest '+IDENTITY+' ... FAILED\n'+marker+'\n'
    raw+="thread 'closed' panicked at "+TEST+':'+str(IDENTITY_ASSERTION_LINE)+':5:\n'
    raw+='test result: FAILED. 0 passed; 1 failed; 0 ignored; 0 measured; 9 filtered out; finished in 0.1s\n'
    ensure(diagnostic(raw,common.parse_body(raw,101,IDENTITY))['original_specific_failure_observed'],'specific-runtime-failure-positive')
    passed=raw.replace(' ... FAILED',' ... ok').replace('live_readiness=1','live_readiness=2')
    passed=passed.replace("thread 'closed' panicked at "+TEST+':'+str(IDENTITY_ASSERTION_LINE)+':5:\n','')
    passed=passed.replace('result: FAILED. 0 passed; 1 failed','result: ok. 1 passed; 0 failed')
    ensure(diagnostic(passed,common.parse_body(passed,0,IDENTITY))['original_test_PASS'],'actual-test-pass-positive')
    negatives=[(raw,124),(raw.replace(':'+str(IDENTITY_ASSERTION_LINE)+':',':1:'),101),
               (raw.replace('live_readiness=1','live_readiness=3'),101),
               (raw.replace('known=true held_kind=30443','known=false held_kind=0'),101),
               (raw+'error[E0000]: rejected\n',101)]
    for value,code in negatives:
        ensure(not diagnostic(value,common.parse_body(value,code,IDENTITY))['original_specific_failure_observed'],'not-original-failure')
    return {'preserved_counts_inventory':shared,'marker_positive':3,'marker_negative':len(bad),
            'specific_failure_positive':1,'actual_test_pass_positive':1,'specific_failure_negative':len(negatives),'runtime_bodies':0}

def compile_app(cohort, frozen, report, save):
    features=FEATURES[cohort]
    command=['cargo','test','--locked','-p','marmot-app','--lib','--no-run','--message-format=json','--features',','.join(features)]
    code,raw,seconds=old.capture(command,1800,limit=8*1024*1024)
    events=[json.loads(line) for line in raw.splitlines() if line.startswith('{')]
    errors=[event for event in events if event.get('reason')=='compiler-message' and event.get('message',{}).get('level')=='error']
    artifacts=[event for event in events if event.get('reason')=='compiler-artifact']
    selected=[event for event in artifacts if event['target']['name']=='marmot_app' and event['target']['kind']==['lib']
              and event['profile']['test'] and event.get('executable')]
    records=sorted([{'target':event['target']['name'],'kind':event['target']['kind'],'features':sorted(event['features']),
                     'profile':event['profile']} for event in artifacts],key=lambda event:json.dumps(event,sort_keys=True))
    report['compilation']={'command':command,'exit_code':code,'wall_seconds':seconds,'compiler_error_count':len(errors),
        'safe_errors':[old.safe_compiler_diagnostic(event,frozen) for event in errors[:16]],'errors_truncated':len(errors)>16,
        'features_requested':features,'actual_library_artifacts':records,'selected_test_artifact_count':len(selected),
        'whole_workspace_equivalence_claim':False,'succeeded':False}; save()
    ensure(code==0 and not errors and len(selected)==1, 'one-successful-App-library-test-binary')
    ensure(sorted(selected[0]['features'])==APP_FEATURES[cohort], 'exact-selected-App-feature-cohort')
    binary=Path(selected[0]['executable']); ensure(binary.resolve().is_relative_to(Path.cwd().resolve()),'owned-binary-path')
    report['compilation'].update(succeeded=True,actual_App_features=sorted(selected[0]['features']),
        actual_App_profile=selected[0]['profile'],binary_sha256=old.digest(binary.read_bytes()),
        cargo_artifact_manifest_sha256=old.digest(json.dumps(records,sort_keys=True).encode()))
    ensure(frozen_inputs()==frozen,'after-compile-pristine'); save(); return binary

def main(args):
    os.umask(0o077); OUT.mkdir(exist_ok=True)
    report={'cohort':args.cohort,'qualification_passed':False,'promotion_eligible':False,'native_acceptance_claim':False,
        'whole_workspace_equivalence_claim':False,'diagnostic_complete':False,'actual_counts_complete':False,
        'actual_passed':None,'actual_failed':None,'actual_ignored':None,'cases':{}}
    frozen=None
    def save(): (OUT/'result.json').write_text(json.dumps(report,indent=2)+'\n')
    try:
        report['source_guard']=source_guard(); report['parser_controls']=parser_controls(); save()
        if args.preflight: report['preflight_passed']=True; save(); return
        frozen=frozen_inputs(); report['input_manifest_sha256']=old.digest(json.dumps(frozen,sort_keys=True).encode())
        report['toolchain']={name:subprocess.check_output([name,'--version'],text=True).strip() for name in ['cargo','rustc']}
        report['free_bytes']=shutil.disk_usage('.').free; save(); ensure(report['free_bytes']>=8*1024**3,'remote-reserve')
        binary=compile_app(args.cohort,frozen,report,save); digest=old.digest(binary.read_bytes())
        cases=[POLICY,IDENTITY] if args.cohort=='default' else [POLICY]
        report['required_nonignored_cases']=len(cases); report['inventory']={}
        for name in cases:
            report['inventory'][name]={}
            for ignored in [False,True]:
                code,raw,_=old.capture([str(binary),'--exact',name]+(['--ignored'] if ignored else [])+['--list','--format','terse'],60)
                value=common.parse_inventory(raw,name,ignored); report['inventory'][name]['ignored' if ignored else 'normal']=value; save()
                ensure(code==0 and value['passed'],'exact-one-required-nonignored-case')
        for name in cases:
            ensure(frozen_inputs()==frozen and old.digest(binary.read_bytes())==digest,'before-body-pristine')
            report['active_case']=name; save()
            code,raw,seconds=old.capture([str(binary),'--exact',name,'--nocapture','--test-threads=1'],300,limit=8*1024*1024)
            row=common.parse_body(raw,code,name); row.update(wall_seconds=seconds,binary_sha256=digest)
            report['cases'][name]=row; save() # Persist actual counts BEFORE diagnostic parsing.
            if name==IDENTITY: row['diagnostic']=diagnostic(raw,row)
            ensure(frozen_inputs()==frozen and old.digest(binary.read_bytes())==digest,'after-body-pristine'); save()
            ensure(row['actual_counts_complete'] and row['compiler_error_count']==0 and code in {0,101},'actual-body-not-compiler-watchdog')
        rows=list(report['cases'].values()); report['actual_counts_complete']=all(row['actual_counts_complete'] for row in rows)
        if report['actual_counts_complete']:
            report.update(actual_passed=sum(row['passed'] for row in rows),actual_failed=sum(row['failed'] for row in rows),
                          actual_ignored=sum(row['ignored'] for row in rows),actual_executed_nonignored=len(rows))
        report['source_policy_control_PASS']=report['cases'][POLICY]['passed_gate']
        report['diagnostic_complete']=(report['source_policy_control_PASS'] and (args.cohort=='experimental'
            or report['cases'][IDENTITY]['diagnostic']['diagnostic_complete'])); save()
        ensure(report['diagnostic_complete'],'source-policy-PASS-and-known-complete-identity-diagnostic-required')
    except Exception as error:
        report['exception_type']=type(error).__name__
        if isinstance(error,ValueError): report['failure_gate']=str(error) if re.fullmatch('[A-Za-z0-9_.:/-]{1,150}',str(error)) else 'closed-gate-rejected'
        raise
    finally:
        if frozen is not None: report['inputs_pristine']=frozen_inputs()==frozen
        save()
        if frozen is not None: ensure(report['inputs_pristine'],'final-input-pristine')

if __name__=='__main__':
    parser=argparse.ArgumentParser(); parser.add_argument('--preflight',action='store_true')
    parser.add_argument('--cohort',choices=['default','experimental'],required=True); main(parser.parse_args())
