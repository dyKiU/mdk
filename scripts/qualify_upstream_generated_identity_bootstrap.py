#!/usr/bin/env python3
"""Default App bootstrap-fixture GREEN and one exact independent counterfactual."""
import argparse
import copy
import sys
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
BASE = '6bb8802651b7255a83f55743311da263bbde85e8'
TEST_SHA256 = '4df7d3b3a5ff83fa4df4c822665ad98e3abf61ff510e3010d053e6f481e0fb80'
IDENTITY_ASSERTION_LINE = 7121
HELD_ASSERTION_TEXT = '''assert_eq!(
        held_kind,
        Some(0),
        "the held event must be bootstrap metadata"
    );'''
MUTATION_OLD = 'relay.block_next_publish_of_kind(0);'
MUTATION_NEW = 'relay.block_next_publish_of_kind(30443);'
SELF = 'scripts/qualify_upstream_generated_identity_bootstrap.py'
TEST = 'crates/marmot-app/src/tests.rs'
WORKFLOW = '.github/workflows/upstream-boundary-regressions.yml'
REF = 'refs/heads/ci/upstream-generated-identity-bootstrap-fix-20261018'
BEGIN = '  # GENERATED_IDENTITY_BOOTSTRAP_JOBS_BEGIN\n'
END = '  # GENERATED_IDENTITY_BOOTSTRAP_JOBS_END\n\n'
OPTIONS = 'options: [generated-identity-bootstrap-preflight, generated-identity-bootstrap-green, generated-identity-bootstrap-mutations, '
OUT = Path('generated-identity-bootstrap-evidence')
IDENTITY = 'tests::generated_identity_returns_before_bootstrap_publication_unblocks'
POLICY = 'tests::account_worker_is_spawned_as_abortable_async_task'
FEATURES = {'default': ['marmot-app/test-policy-overrides', 'cgka-engine/test-policy-overrides', 'cgka-engine/test-crash-hooks']}
APP_FEATURES = {'default': ['default', 'test-policy-overrides']}
MARKER = 'generated_identity_blocked_publication'

def source_guard():
    ensure(isinstance(BASE, str) and re.fullmatch('[0-9a-f]{40}', BASE)
           and isinstance(TEST_SHA256, str) and re.fullmatch('[0-9a-f]{64}', TEST_SHA256)
           and isinstance(IDENTITY_ASSERTION_LINE, int) and IDENTITY_ASSERTION_LINE > 0, 'reviewed-fixture-unpinned')
    ensure(isinstance(HELD_ASSERTION_TEXT,str) and isinstance(MUTATION_OLD,str) and isinstance(MUTATION_NEW,str)
           and MUTATION_OLD != MUTATION_NEW and '30443' in MUTATION_NEW, 'reviewed-call-only-counterfactual-required')
    fixture = Path(TEST).read_text()
    ensure(fixture.count(MUTATION_OLD) == 1 and MUTATION_NEW not in fixture
           and '\n'.join(fixture.splitlines()[IDENTITY_ASSERTION_LINE-1:IDENTITY_ASSERTION_LINE-1+len(HELD_ASSERTION_TEXT.splitlines())]).strip() == HELD_ASSERTION_TEXT, 'reviewed-held-kind-assertion-and-call')
    head = old.git('rev-parse', 'HEAD')
    ensure(os.environ.get('GITHUB_ACTIONS') == 'true' and os.environ.get('GITHUB_REPOSITORY') == 'dyKiU/mdk'
           and os.environ.get('GITHUB_EVENT_NAME') == 'workflow_dispatch' and os.environ.get('GITHUB_SHA') == head
           and os.environ.get('GITHUB_REF') == REF and os.environ.get('GITHUB_WORKFLOW_REF') == 'dyKiU/mdk/' + WORKFLOW + '@' + REF
           and os.environ.get('GENERATED_IDENTITY_BOOTSTRAP_BASELINE') == BASE, 'exact-owned-bootstrap-source')
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

def identity_oracle(raw,row,mutant):
    facts = identity_marker(raw)
    locations = re.findall(r'panicked at ([A-Za-z0-9_./-]+\.rs):(\d+):(\d+):',raw)
    safe = [{'file':p,'line':int(line),'column':int(col)} for p,line,col in locations if p == TEST]
    failure = (mutant and row['actual_counts_complete'] is True and row['exit_code'] == 101
        and row['passed'] == 0 and row['failed'] == 1 and row['ignored'] == 0
        and row['compiler_error_count'] == 0 and row['panic_count'] == 1 and len(safe) == len(locations) == 1
        and safe[0]['line'] == IDENTITY_ASSERTION_LINE and facts['held_kind_known'] and facts['held_kind'] == 30443
        and facts['returned_readiness'] == 1)
    green = (not mutant and row['passed_gate'] and facts['held_kind_known'] and facts['held_kind'] == 0
        and facts['returned_readiness'] == 1 and facts['live_readiness'] == 2)
    return {'facts':facts,'safe_panic_locations':safe,'sole_exact_held_kind_assertion_failure':failure,
        'fixture_GREEN':green,'raw_error_or_event_payload_exported':False,
        'mutation_live_readiness_is_observed_not_a_relaxed_original_assertion':True}


def parser_controls():
    preserved = common.parser_controls()
    def raw(kind,failed):
        return ('running 1 test\ntest ' + IDENTITY + ' ... ' + ('FAILED' if failed else 'ok') + '\n'
            + MARKER + ' held_kind_known=true held_kind=' + str(kind) + ' returned_readiness=1 live_readiness=' + ('1' if failed else '2') + '\n'
            + ("thread 'closed' panicked at " + TEST + ':' + str(IDENTITY_ASSERTION_LINE) + ':5:\n' if failed else '')
            + 'test result: ' + ('FAILED. 0 passed; 1 failed' if failed else 'ok. 1 passed; 0 failed')
            + '; 0 ignored; 0 measured; 99 filtered out; finished in 0.1s\n')
    green = raw(0,False); red = raw(30443,True)
    ensure(identity_oracle(green,common.parse_body(green,0,IDENTITY),False)['fixture_GREEN'],'real-green-positive')
    ensure(identity_oracle(red,common.parse_body(red,101,IDENTITY),True)['sole_exact_held_kind_assertion_failure'],'exact-mutation-positive')
    shared = green.replace(' ... ok\n' + MARKER,' ... ' + MARKER)
    ensure(identity_oracle(shared,common.parse_body(shared,0,IDENTITY),False)['fixture_GREEN'],'exact-shared-prefix-positive')
    bad = [(red,124),(red.replace('30443','0'),101),(red.replace(':'+str(IDENTITY_ASSERTION_LINE)+':',':1:'),101),
        (red + 'error[E0000]: omitted\n',101),(red.replace('0 ignored','1 ignored'),101),
        (red.replace(IDENTITY,IDENTITY+'_foreign'),101),
        (red.replace('held_kind_known=true held_kind=30443','held_kind_known=false held_kind=0'),101)]
    for text,code in bad:
        ensure(not identity_oracle(text,common.parse_body(text,code,IDENTITY),True)['sole_exact_held_kind_assertion_failure'],'no-false-mutation-kill')
    invalid = [red + red,red + MARKER + ' held_kind_known=true held_kind=30443 returned_readiness=1 live_readiness=1\n',
        red.replace('30443','18446744073709551616'),red.replace('live_readiness=1','live_readiness=5'),
        red.replace('held_kind=30443','held_kind=-1')]
    for text in invalid:
        rejected = False
        try: identity_marker(text)
        except ValueError: rejected = True
        ensure(rejected,'closed-marker-adversary')
    return {'preserved_counts_inventory':preserved,'positive':3,'mutation_negative':len(bad),
        'marker_negative':len(invalid),'runtime_bodies':0}


def phase_run(expected,phase,mutant,save):
    binary = compile_app('default',expected,phase,save)
    digest = old.digest(binary.read_bytes())
    phase['source_manifest_sha256'] = old.digest(json.dumps(expected,sort_keys=True).encode())
    phase['cases'] = {}; phase['inventory'] = {}; save()
    for name in [POLICY,IDENTITY]:
        phase['inventory'][name] = {}
        for ignored in [False,True]:
            code,raw,_ = old.capture([str(binary),'--exact',name] + (['--ignored'] if ignored else []) + ['--list','--format','terse'],60)
            row = common.parse_inventory(raw,name,ignored); row['exit_code'] = code
            phase['inventory'][name]['ignored' if ignored else 'normal'] = row; save()
            ensure(code == 0 and row['passed'],'two-exact-nonignored-controls')
    for name in [POLICY,IDENTITY]:
        ensure(frozen_inputs() == expected and old.digest(binary.read_bytes()) == digest,'before-body-pristine')
        try:
            code,raw,seconds = old.capture([str(binary),'--exact',name,'--nocapture','--test-threads=1'],300,limit=8*1024*1024)
            row = common.parse_body(raw,code,name); row.update(wall_seconds=seconds,binary_sha256=digest)
            phase['cases'][name] = row; save()  # Actual counts persist before closed marker parsing.
            if name == IDENTITY:
                row['identity_oracle'] = identity_oracle(raw,row,mutant)
            save()
        except old.GateFailure as error:
            if name not in phase['cases']:
                phase['cases'][name] = {'actual_counts_complete':False,'passed':None,'failed':None,'ignored':None,
                    'executed_nonignored':None,'passed_gate':False}
            phase['cases'][name]['closed_capture_or_parser_gate_failed'] = True
            phase['cases'][name]['watchdog_triggered'] = str(error) == 'bounded-command-timeout'
            phase['cases'][name]['output_limit_triggered'] = str(error) == 'bounded-command-output-limit'; save()
        ensure(frozen_inputs() == expected and old.digest(binary.read_bytes()) == digest,'after-body-pristine')
    phase['binary_sha256'] = digest
    phase['source_pristine'] = frozen_inputs() == expected
    phase['binary_pristine'] = old.digest(binary.read_bytes()) == digest
    policy = phase['cases'].get(POLICY,{})
    identity = phase['cases'].get(IDENTITY,{}).get('identity_oracle',{})
    phase['required_oracles_passed'] = (policy.get('passed_gate') is True
        and identity.get('sole_exact_held_kind_assertion_failure' if mutant else 'fixture_GREEN') is True)
    save(); ensure(phase['required_oracles_passed'],'two-actual-specific-oracles-required')


def main(args):
    os.umask(0o077); OUT.mkdir(exist_ok=True)
    report = {'mode':args.mode,'cohort':'default-App-policy-overrides','phases':{},'component_GREEN':False,
        'component_mutation_qualified':False,'full_qualification':False,'native_acceptance_claim':False,
        'promotion_eligible':False,'production_fix_claim':False,'whole_workspace_equivalence_claim':False}
    before = None; original = None; mode = None
    def save(): (OUT/'result.json').write_text(json.dumps(report,indent=2)+'\n')
    try:
        report['source_guard'] = source_guard(); report['parser_controls'] = parser_controls(); save()
        if args.preflight:
            report['preflight_passed'] = True; save(); return
        before = frozen_inputs()
        original = Path(TEST).read_bytes(); mode = Path(TEST).stat().st_mode
        for label in (['baseline','mutant','restored'] if args.mode == 'mutation' else ['green']):
            expected = copy.deepcopy(before)
            if label == 'mutant':
                content = original.replace(MUTATION_OLD.encode(),MUTATION_NEW.encode(),1)
                ensure(content != original,'real-call-only-counterfactual')
                Path(TEST).write_bytes(content); Path(TEST).chmod(mode)
                expected[TEST]['sha256'] = old.digest(content)
            else:
                Path(TEST).write_bytes(original); Path(TEST).chmod(mode)
            phase = {}; report['phases'][label] = phase; save()
            phase_run(expected,phase,label == 'mutant',save)
        if args.mode == 'mutation':
            a,b,c = [report['phases'][key] for key in ['baseline','mutant','restored']]
            ensure(a['source_manifest_sha256'] == c['source_manifest_sha256'] != b['source_manifest_sha256']
                and a['binary_sha256'] == c['binary_sha256'] != b['binary_sha256']
                and a['compilation']['actual_App_features'] == b['compilation']['actual_App_features'] == c['compilation']['actual_App_features']
                and a['compilation']['cargo_artifact_manifest_sha256'] == b['compilation']['cargo_artifact_manifest_sha256'] == c['compilation']['cargo_artifact_manifest_sha256'],
                'exact-source-binary-feature-restoration')
            report['component_mutation_qualified'] = True
        else: report['component_GREEN'] = True
    except Exception as error:
        report['exception_type'] = type(error).__name__
        if isinstance(error,ValueError):
            report['failure_gate'] = str(error) if re.fullmatch('[A-Za-z0-9_.:/-]{1,150}',str(error)) else 'closed-gate-rejected'
        raise
    finally:
        active_error = sys.exc_info()[0] is not None
        if original is not None:
            Path(TEST).write_bytes(original); Path(TEST).chmod(mode)
        if before is not None: report['inputs_pristine'] = frozen_inputs() == before
        rows = [row for phase in report['phases'].values() for row in phase.get('cases',{}).values()]
        complete = len(rows) == (6 if args.mode == 'mutation' else 2) and all(row.get('actual_counts_complete') is True for row in rows)
        report['actual_counts_complete'] = complete
        for key in ['passed','failed','ignored','executed_nonignored']:
            report['known_partial_'+key] = sum(row[key] for row in rows if type(row.get(key)) is int)
            report['actual_'+key] = sum(row[key] for row in rows) if complete and all(type(row.get(key)) is int for row in rows) else None
        if report.get('inputs_pristine') is False:
            report['component_GREEN'] = report['component_mutation_qualified'] = False
        save()
        if not active_error and before is not None: ensure(report['inputs_pristine'],'final-source-modes-restored')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(); parser.add_argument('--preflight',action='store_true')
    parser.add_argument('--mode',choices=['green','mutation'],default='green'); main(parser.parse_args())
