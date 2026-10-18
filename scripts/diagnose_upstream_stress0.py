#!/usr/bin/env python3
"""One unchanged required current-thread enrollment case; safe after-timeout observations."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import qualify_upstream_request_retry_ack as ack

BASE='2b5cca339e5fcfe520d58e275238e5fbac40937d'
SELF='scripts/diagnose_upstream_stress0.py'
WORKFLOW='.github/workflows/experimental-sync-ci.yml'
REF='refs/heads/ci/upstream-stress0-diagnostic-20261018'
BEGIN='  # STRESS0_DIAGNOSTIC_JOBS_BEGIN\n'
END='  # STRESS0_DIAGNOSTIC_JOBS_END\n'
OPTIONS='options: [stress0-preflight, stress0-diagnostic, '
OUT=Path('stress0-diagnostic-evidence')
CASE='single_thread_stress_four_device_enrollment'
NAME='native_device_linking::automatic_pairing_acceptance::'+CASE
ensure=ack.ensure

PHASES = 'AwaitingSetup|AwaitingPeer|ComparisonAvailable|AwaitingPeerVerification|VerificationCompleteEnrollmentPending|Cancelled|Expired|Failed|EnrollmentComplete'
NUMBER = r'(?:0|[1-9][0-9]{0,18})'
BOOLEAN = r'(?:true|false)'
FAILURE = r'(?:Owner|Collection|Runtime|Engine|Genesis|Gate|PrivateInvite)'
STAGE = r'(?:BeforeCoreWrap|AfterCoreWrap|BeforeRelayPublication|AfterRelayPublication)'
REASON = r'(?:VerifierFallback|NoRound|GuardInvalid|NoSettledRoster|SharingPending|Complete)'

def option(pattern):
    return r'(?:None|Some\(' + pattern + r'\))'

def sequence(pattern, length, opening=r'\(', closing=r'\)'):
    return opening + ', '.join([pattern] * length) + closing

def array(length):
    return sequence(NUMBER, length, r'\[', r'\]')

CHANNEL = r'\(' + ', '.join([NUMBER] * 3 + [option(FAILURE), option(STAGE)]) + r'\)'
CHILDREN = option(r'\[(?:' + CHANNEL + r'(?:, ' + CHANNEL + r'){0,7})?\]')
AGGREGATES = option(r'\(' + BOOLEAN + ', ' + option(NUMBER) + ', ' + NUMBER + ', ' + NUMBER + r'\)')
RPC = option(r'\(' + array(6) + ', ' + array(6) + ', ' + option(r'\(' + REASON + ', ' + NUMBER + r'\)') + r'\)')
SCHEMAS = [
    ('aggregates', r'side=(left|right) primary/expected/children/completed=(' + AGGREGATES + ') intake=(' + option(array(8)) + ') rejections=(' + option(array(4)) + ') context_rejections=(' + option(array(9)) + ') projection=(' + option(array(4)) + ')'),
    ('child_channels', r'side=(left|right) child_channels=(' + CHILDREN + ')'),
    ('native_rpc', r'side=(left|right) native_rpc_counts/elapsed_ms/branch=(' + RPC + ')'),
    ('existing_child', r'existing_index=([01]) child_channel=(' + option(CHANNEL) + ')'),
]
STAGES = {'initial-two-comparison', 'initial-two-completion', 'initial-two-completed', 'third-device-comparison', 'third-device-completion', 'third-device-completed', 'fourth-device-comparison', 'fourth-device-completion', 'fourth-device-completed', 'sibling-consent-held-before-peer-progress', 'automatic-publication-held-before-completion'}
PREFIX = 'automatic-enrollment-control '
PHASE_LINE = r'automatic pairing did not reach required phase: expected=(' + PHASES + r') observed=(None|Some\(\((' + PHASES + '), (' + PHASES + r')\)\))'


def diagnostics(raw):
    raw=re.sub(r'\x1b\[[0-9;]*m','',raw)
    raw,prefix_count=re.subn(r'(?m)^test '+re.escape(NAME)+r' \.\.\. (?=automatic-enrollment-control )','',raw)
    ensure(prefix_count in {0,1},'at-most-one-exact-shared-diagnostic-header')
    ensure(not re.search(r'(?m)^test [A-Za-z_0-9:]+ \.\.\. automatic-enrollment-control ',raw),'foreign-shared-diagnostic-header')
    ensure(len(raw.encode()) <= 8 * 1024 * 1024, 'bounded-runtime-output')
    # No raw log/panic strings survive this function. Even diagnostic values
    # must match their complete closed tuple schema, without quoted strings.
    rows = []
    stages = []
    phase_rows = []
    seen = set()
    for line in raw.splitlines():
        if line.startswith(PREFIX):
            payload = line[len(PREFIX):]
            ensure(len(payload) <= 4096, 'bounded-diagnostic-line')
            if payload.startswith('stage='):
                stage = payload[6:]
                ensure(stage in STAGES and len(stages) < 16, 'known-bounded-stage')
                stages.append(stage)
                continue
            matched = False
            for category, pattern in SCHEMAS:
                match = re.fullmatch(pattern, payload)
                if not match:
                    continue
                key = (category, match[1])
                ensure(key not in seen and len(rows) < 8, 'unique-bounded-aggregate')
                seen.add(key)
                # Bit flags are the FIRST field; visits and failures follow.
                if category in {'child_channels', 'existing_child'}:
                    flags = re.findall(r'\((' + NUMBER + '), ' + NUMBER + ', ' + NUMBER + r', (?:None|Some\(' + FAILURE + r'\)),', payload)
                    ensure(all(int(value) <= 255 for value in flags), 'known-channel-bitmask')
                rows.append({'category': category, 'side_or_existing_index': match[1], 'closed_schema_values': [None if value=='None' else value for value in match.groups()[1:]]})
                matched = True
                break
            ensure(matched, 'unknown-aggregate-schema')
        elif line.startswith('automatic pairing did not reach required phase:'):
            match = re.fullmatch(PHASE_LINE, line)
            ensure(match is not None and not phase_rows, 'known-unique-phase-schema')
            phase_rows.append({'expected': match[1], 'observed_missing': match[2] == 'None', 'left': match[3], 'right': match[4]})
        elif re.match(r'(?:left|right) expected=', line):
            match = re.fullmatch(r'(left|right) expected=(' + PHASES + r') observed=(' + PHASES + r')', line)
            ensure(match is not None and not phase_rows, 'known-unique-terminal-phase-schema')
            phase_rows.append({'side': match[1], 'expected': match[2], 'observed': match[3]})
    return {'exact_prefix_normalization_count':prefix_count,'aggregates': rows, 'stages': stages, 'phase_failures': phase_rows, 'missing_diagnostics': not rows,
            'observed_only_in_existing_after_timeout_dump': True,
            'missing_required_timeout_rows': sorted({'aggregates:left','aggregates:right','child_channels:left','child_channels:right','native_rpc:left','native_rpc:right','existing_child:0','existing_child:1'} - {category+':'+label for category,label in seen})}


def parser_controls():
    aggregate = PREFIX + 'side=left primary/expected/children/completed=Some((true, Some(2), 2, 0)) intake=Some([0, 1, 2, 3, 4, 5, 6, 7]) rejections=None context_rejections=None projection=None'
    channel = PREFIX + 'side=right child_channels=Some([(255, 2, 1, Some(Genesis), Some(AfterRelayPublication))])'
    rpc = PREFIX + 'side=left native_rpc_counts/elapsed_ms/branch=Some(([1, 2, 3, 4, 5, 6], [0, 0, 1, 2, 3, 4], Some((SharingPending, 12))))'
    existing = PREFIX + 'existing_index=1 child_channel=None'
    phase = 'automatic pairing did not reach required phase: expected=EnrollmentComplete observed=Some((VerificationCompleteEnrollmentPending, AwaitingPeerVerification))'
    complete='\n'.join([aggregate,aggregate.replace('side=left','side=right'),
        channel,channel.replace('side=right','side=left'),rpc,rpc.replace('side=left','side=right'),
        existing,existing.replace('index=1','index=0'),phase])
    shared='test '+NAME+' ... '+PREFIX+'stage=initial-two-comparison\n'+complete
    positives = [aggregate, channel, rpc, existing, phase, 'left expected=EnrollmentComplete observed=Failed', 'private runtime output must be discarded',complete,shared]
    ensure(not diagnostics(complete)['missing_required_timeout_rows'],'all-eight-actual-timeout-schemas-covered')
    ensure(diagnostics(shared)['exact_prefix_normalization_count']==1,'one-exact-shared-prefix-observed')
    ensure(diagnostics(existing)['aggregates'][0]['closed_schema_values']==[None],'missing-is-null-not-zero')
    ensure(len(diagnostics(aggregate)['missing_required_timeout_rows'])==7,'missing-row-remains-unknown')
    for value in positives:
        diagnostics(value)
    negatives = [shared.replace(NAME,NAME+'_foreign'),shared+'\ntest '+NAME+' ... '+PREFIX+'stage=initial-two-comparison',phase.replace('Some((', 'Some(',1),aggregate + ' private', aggregate.replace('side=left', 'side=secret'), aggregate.replace('Some(2)', 'Some(-2)'), aggregate.replace('Some(2)', 'Some(12345678901234567890)'), aggregate.replace('true', 'secret'), channel.replace('255', '256'), channel.replace('Genesis', 'Unknown'), channel.replace('AfterRelayPublication', 'Unknown'), rpc.replace('SharingPending', 'Unknown'), existing.replace('index=1', 'index=2'), phase.replace('AwaitingPeerVerification', 'Unknown'), 'left expected=EnrollmentComplete observed=secret', phase + '\n' + phase, aggregate + '\n' + aggregate, PREFIX + 'private=secret', PREFIX + 'x' * 4097, PREFIX + 'stage=unknown', PREFIX + 'stage=third-device-completion\n' + '\n'.join([PREFIX + 'stage=third-device-completion'] * 16), channel.replace('(255, 2, 1', '("secret", 2, 1')]
    for value in negatives:
        try:
            diagnostics(value)
        except ValueError:
            continue
        raise ValueError('adversarial-parser-control-accepted')
    ensure(diagnostics(phase)['phase_failures'][0]['left'] == 'VerificationCompleteEnrollmentPending', 'phase-projection')
    ensure(not diagnostics('private runtime output')['aggregates'], 'unrelated-raw-output-discarded')
    return {'positive_controls': len(positives), 'negative_controls': len(negatives), 'unchanged_runtime_oracle_controls':ack.parser_controls(), 'passed': True}


def source_guard():
    head=subprocess.check_output(['git','rev-parse','HEAD'],text=True).strip()
    ensure(os.environ.get('GITHUB_ACTIONS')=='true' and os.environ.get('GITHUB_REPOSITORY')=='dyKiU/mdk'
        and os.environ.get('GITHUB_EVENT_NAME')=='workflow_dispatch' and os.environ.get('GITHUB_SHA')==head
        and os.environ.get('GITHUB_REF')==REF and os.environ.get('GITHUB_WORKFLOW_REF')=='dyKiU/mdk/'+WORKFLOW+'@'+REF
        and os.environ.get('UPSTREAM_STRESS0_DIAGNOSTIC_BASELINE')==BASE,'exact-owned-final-cohort-workflow')
    ensure(os.environ.get('CARGO_INCREMENTAL')=='1' and os.environ.get('CARGO_BUILD_JOBS')=='2'
        and os.environ.get('RUST_MIN_STACK')=='4194304'
        and all(os.environ.get(k)=='0' for k in ['CARGO_PROFILE_DEV_DEBUG','CARGO_PROFILE_TEST_DEBUG'])
        and all(not os.environ.get(k) for k in ['RUSTFLAGS','CARGO_ENCODED_RUSTFLAGS','RUSTC_BOOTSTRAP','CARGO_PROFILE_DEV_OPT_LEVEL','CARGO_PROFILE_TEST_OPT_LEVEL']),'exact-final-build-cohort')
    subprocess.run(['git','merge-base','--is-ancestor',BASE,head],check=True)
    ensure(subprocess.run(['git','diff','--quiet','HEAD']).returncode==0,'initial-tracked-pristine')
    baseline={}
    for entry in subprocess.check_output(['git','ls-tree','-r','-z',BASE]).split(b'\0'):
        if entry:
            metadata,name=entry.split(b'\t',1);mode,kind,blob=metadata.decode().split()
            ensure(kind=='blob' and mode in {'100644','100755','120000'},'ordinary-final-baseline-layout')
            baseline[os.fsdecode(name)]=(mode,blob)
    current=ack.layout()
    ensure(SELF not in baseline and set(current)==set(baseline)|{SELF},'whole-final-cohort-inventory')
    for name,value in current.items():
        mode,blob=baseline.get(name,('100644',None))
        ensure(value['git_mode']==mode and value['symlink']==(mode=='120000')
            and (value['symlink'] or value['actual_executable']==(mode=='100755')),'whole-final-cohort-mode')
        data=os.fsencode(os.readlink(name)) if value['symlink'] else Path(name).read_bytes()
        if name==WORKFLOW:
            text=data.decode();ensure(text.count(BEGIN)==text.count(END)==text.count(OPTIONS)==1,'one-isolated-final-workflow-overlay')
            before,rest=text.split(BEGIN);_,after=rest.split(END)
            data=(before+after).replace(OPTIONS,'options: [',1).encode()
        if blob is not None: ensure(hashlib.sha1(b'blob '+str(len(data)).encode()+b'\0'+data).hexdigest()==blob,'exact-final-source:'+name)
    ensure(set(subprocess.check_output(['git','ls-files','--others','--exclude-standard'],text=True).splitlines()) <= {str(OUT/'result.json')},'no-untracked-source-overlay')
    ensure(len([row for row in ack.CASES if row[0]=='stress_0' and row[1]==CASE and row[2]==NAME])==1,'exact-existing-required-serial-case')
    return {'source':head,'reviewed_final_baseline':BASE,'all_product_tests_helpers_contents_and_modes_exact':True,
        'historical_ACK_controller_preserved':True,'historical_ACK_source_guard_invoked':False,
        'explicit_wrapper_guard_substitution':True,'historical_runtime_evidence_reused':False,
        'Rust_fixtures_oracles_runtime_flavors_deadlines_unchanged':True,'one_existing_required_stress_case_only':True}


def main(preflight):
    os.umask(0o077);OUT.mkdir(exist_ok=True)
    report={'diagnostic_only':True,'qualification_passed':False,'native_acceptance_claim':False,'promotion_eligible':False,
        'failure_localization_complete':False,'after_timeout_observations_are_not_deadline_completion':True,
        'original_helper_phase_budget_seconds':15,'actual_counts_complete':False,'actual_passed':None,'actual_failed':None,
        'actual_ignored':None,'actual_executed_nonignored':None}
    before=None;modes=None
    def save(): (OUT/'result.json').write_text(json.dumps(report,indent=2)+'\n')
    try:
        report['source_guard']=source_guard();report['parser_controls']=parser_controls();save()
        if preflight:report['preflight_passed']=True;save();return
        report['environment']=ack.environment();before,modes=ack.freeze(),ack.layout()
        report['input_manifest_sha256']=ack.identity(before)
        compilation,cases=ack.compile_cases([CASE]);report['compilation']=compilation;save()
        ensure(compilation.get('compile_exit_code')==compilation.get('compiler_error_count')==0
            and compilation.get('compiled_fingerprints',{}).get('verified') is True
            and set(cases)=={CASE} and cases[CASE]['name']==NAME,'one-exact-feature-verified-nonignored-stress-case')
        report['feature_identity']=ack.feature_identity(compilation);case=cases[CASE]
        report['compiled_binary_sha256']=case['binary_sha256']
        ensure(ack.freeze()==before and ack.layout()==modes and ack.digest(Path(case['binary']).read_bytes())==case['binary_sha256'],'before-runtime-pristine')
        code,raw,seconds=ack.bounded.capture([case['binary'],'--exact',NAME,'--nocapture','--test-threads=1'],300,limit=8*1024*1024)
        row=dict(ack.parse_body(raw,CASE),body_exit_code=code)
        report['body']=row;report['body_seconds']=seconds;save()
        report['existing_timeout_diagnostics']=diagnostics(raw);save()
        row=ack.parse_case('stress_0',raw,code);report['body']=row
        report['actual_counts_complete']=ack.alignment.complete_counts(row)
        for key in ['passed','failed','ignored','executed_nonignored']:
            report['actual_'+key]=row.get(key) if type(row.get(key)) is int else None
        save()
        data=report['existing_timeout_diagnostics']
        report['failure_observed']=code==101 and row.get('failed')==1
        report['failure_localization_complete']=(report['failure_observed'] and not data['missing_required_timeout_rows'] and len(data['phase_failures'])==1)
        report['test_green']=ack.case_green('stress_0',row)
        report['diagnostic_execution_completed']=report['actual_counts_complete'] and row.get('compiler_error_count')==0 and code in {0,101}
        report['binary_pristine']=ack.digest(Path(case['binary']).read_bytes())==case['binary_sha256'];save()
        ensure(report['diagnostic_execution_completed'] and report['binary_pristine'],'actual-one-case-or-pristine-failure')
        # Preserve the actual product regression, even when its diagnostics were complete.
        ensure(report['test_green'],'unchanged-required-serial-stress-failure-preserved')
    except Exception as error:
        report['exception_type']=type(error).__name__;raise
    finally:
        if before is not None:
            report['inputs_pristine']=ack.freeze()==before and ack.layout()==modes
            report['source_after_sha256']=ack.identity(ack.freeze())
        save()
        if before is not None:ensure(report['inputs_pristine'],'final-source-modes-pristine')

if __name__=='__main__':
    parser=argparse.ArgumentParser();parser.add_argument('--preflight',action='store_true');main(parser.parse_args().preflight)
