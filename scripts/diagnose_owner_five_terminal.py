#!/usr/bin/env python3
"""One passive fifth-session diagnostic; never supplies qualification evidence."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
from types import SimpleNamespace
import qualify_owner_ordinary_1611 as owner

BASE = '4921a48afed8d96b7cbc6cbba2e2bf608af93dcc'
SELF = 'scripts/diagnose_owner_five_terminal.py'
REF = 'refs/heads/ci/upstream-owner-five-diagnostic-20261018'
RUNTIME_DETAILS = {1: 'transport_closed', 2: 'account_worker_response_timed_out', 3: 'runtime_stopping', 4: 'runtime_busy', 5: 'account_worker_busy', 6: 'account_session_busy', 7: 'relay_directory', 8: 'onboarding_required', 9: 'account_setup_recovery_required', 10: 'storage_busy', 11: 'storage_closed', 12: 'storage_backend', 13: 'storage_serialization', 14: 'storage_capacity', 15: 'storage_corruption', 16: 'storage_not_found', 17: 'storage_already_exists', 18: 'storage_unsupported_schema_version', 19: 'sqlite', 20: 'io', 21: 'account_home_secret_not_found', 22: 'account_home_unknown_account'}
WORKFLOW = '.github/workflows/experimental-sync-ci.yml'
BEGIN = '  # OWNER_FIVE_DIAGNOSTIC_JOBS_BEGIN\n'
END = '  # OWNER_FIVE_DIAGNOSTIC_JOBS_END\n'
OPTIONS = 'options: [owner-five-diagnostic-preflight, owner-five-diagnostic, '
OUT = Path('owner-five-terminal-evidence')
PINS = {
    'crates/marmot-app/src/native_device_linking/enabled.rs': 'a1346c0e15ecfcb39899ffefe1c580b29fa4d5a570983274967c6258d9513975',
    'crates/marmot-app/src/native_device_linking/enabled/automatic.rs': '69437cd30b2c435667a5d0d2318dd6f83b44cf82615d151f4751c17e1c122abd',
    'crates/marmot-app/src/native_device_linking/enabled/terminal_diagnostic.rs': 'f0c071f6f4b91d19ec1b54717e3d92d083422ac681701d9bf538ab92f2bc6d60',
    owner.FIVE_FILE: '5b53c21843dfbe8712bdfb5298ba586505adc543c3ae55348adbdbafaa6a4c0a',
}
MANIFEST = 'scripts/owner_five_producer_manifest.json'
MANIFEST_SHA256 = 'e8f71c0ce0c6aaeb186ef05c4df9382715ecbbd77414ec9ca00cfb9b7143dd93'
PROBE = 'crates/marmot-app/src/native_device_linking/enabled/terminal_diagnostic.rs'
PHASES = ['AwaitingSetup','AwaitingPeer','ComparisonAvailable','AwaitingPeerVerification',
          'VerificationCompleteEnrollmentPending','Cancelled','Expired','Failed','EnrollmentComplete']


def source_guard(five):
    head = subprocess.check_output(['git','rev-parse','HEAD'],text=True).strip()
    owner.ensure(five and os.environ.get('GITHUB_ACTIONS') == 'true'
        and os.environ.get('GITHUB_REPOSITORY') == 'dyKiU/mdk'
        and os.environ.get('GITHUB_EVENT_NAME') == 'workflow_dispatch'
        and os.environ.get('GITHUB_SHA') == head and os.environ.get('GITHUB_REF') == REF
        and os.environ.get('GITHUB_WORKFLOW_REF') == 'dyKiU/mdk/'+WORKFLOW+'@'+REF
        and os.environ.get('OWNER_FIVE_DIAGNOSTIC_BASELINE') == BASE, 'exact-owned-diagnostic')
    owner.ensure(os.environ.get('CARGO_INCREMENTAL') == '1' and os.environ.get('CARGO_BUILD_JOBS') == '2'
        and os.environ.get('RUST_MIN_STACK') == '4194304'
        and all(os.environ.get(k) == '0' for k in ['CARGO_PROFILE_DEV_DEBUG','CARGO_PROFILE_TEST_DEBUG'])
        and all(not os.environ.get(k) for k in ['RUSTFLAGS','CARGO_ENCODED_RUSTFLAGS','RUSTC_BOOTSTRAP',
             'CARGO_PROFILE_DEV_OPT_LEVEL','CARGO_PROFILE_TEST_OPT_LEVEL']), 'unchanged-compiler-cohort')
    subprocess.run(['git','merge-base','--is-ancestor',BASE,head],check=True)
    owner.ensure(subprocess.run(['git','diff','--quiet','HEAD']).returncode == 0, 'pristine-inputs')
    manifest_bytes=Path(MANIFEST).read_bytes()
    owner.ensure(owner.digest(manifest_bytes)==MANIFEST_SHA256,'frozen-reversal-manifest')
    manifest=json.loads(manifest_bytes); owner.ensure(manifest['baseline']==BASE,'manifest-parent')
    baseline={}
    for entry in subprocess.check_output(['git','ls-tree','-r','-z',BASE]).split(b'\0'):
        if entry:
            meta,name=entry.split(b'\t',1);mode,kind,blob=meta.decode().split()
            owner.ensure(kind=='blob','ordinary-baseline');baseline[os.fsdecode(name)]=(mode,blob)
    frozen=owner.snapshot()
    owner.ensure(SELF in baseline and MANIFEST not in baseline and set(frozen)==set(baseline)|{MANIFEST},'whole-input-inventory')
    owner.ensure(len(manifest['files'])==7 and all(name.endswith('.rs') for name in manifest['files']),'exact-seven-Rust-paths')
    for name,actual in frozen.items():
        mode,blob=baseline.get(name,('100644',None))
        owner.ensure(actual['mode']==mode and (mode=='120000' or actual['actual_executable']==(mode=='100755')),'whole-modes')
        data=os.fsencode(os.readlink(name)) if mode=='120000' else Path(name).read_bytes()
        if name==SELF: continue  # Reviewed controller metadata; exact immutable commit recorded.
        if name==MANIFEST: continue # Hash-pinned above; no other added path permitted.
        if name in manifest['files']:
            record=manifest['files'][name]
            owner.ensure(owner.digest(data)==record['draft_sha256'],'reviewed-passive-source:'+name)
            lines=data.decode().splitlines(keepends=True)
            for edit in reversed(record['reverse_edits']):
                a,b=edit['after_start'],edit['after_end']
                owner.ensure(type(a) is int and type(b) is int and 0<=a<=b<=len(lines)
                    and lines[a:b]==edit['after'],'exact-reverse-span:'+name)
                lines[a:b]=edit['before']
            data=''.join(lines).encode()
            owner.ensure(owner.digest(data)==record['baseline_sha256'],'reversed-Rust-sha:'+name)
        elif name==WORKFLOW:
            record=manifest['workflow'];text=data.decode()
            owner.ensure(owner.digest(data)==record['draft_sha256'] and text.count(record['after_literal'])==2
                and record['literal_count']==2,'only-two-baseline-literals')
            data=text.replace(record['after_literal'],record['before_literal']).encode()
            owner.ensure(owner.digest(data)==record['baseline_sha256'],'reversed-workflow-sha')
        if blob is not None:
            owner.ensure(hashlib.sha1(b'blob '+str(len(data)).encode()+b'\0'+data).hexdigest()==blob,'exact-parent:'+name)
    owner.ensure(not subprocess.check_output(['git','ls-files','--others','--exclude-standard'],text=True).strip(),'no-untracked-source')
    return {'source':head,'baseline':BASE,'all_seven_Rust_changes_reversed':True,'workflow_two_literals_reversed':True,
        'all_old_helpers_and_other_inputs_exact':True,'manifest_sha256':MANIFEST_SHA256,'parser_controls':parser_controls()}


def option(raw):
    if raw == 'None': return None
    owner.ensure(raw.startswith('Some(') and raw.endswith(')'),'closed-option')
    return json.loads(raw[5:-1])


def parse_terminal(raw):
    clean=re.sub(r'\x1b\[[0-9;]*m','',raw)
    clean=re.sub(r'(?m)^test '+re.escape(owner.FIVE_NAME)+r' \.\.\. (?=owner-five-terminal )','',clean)
    lines=[line for line in clean.splitlines() if 'owner-five-terminal' in line]
    owner.ensure(len(lines)==2,'exact-two-observation-lines')
    result={}
    array=r'(None|Some\(\[[0-9a-z, ]+\]\))'
    pattern=r'owner-five-terminal side=(source|recipient) known=(true|false) pre_arm_unknown=true attempted_error='+array+r' accepted_terminal='+array+r' progress='+array
    for line in lines:
        match=re.fullmatch(pattern,line); owner.ensure(match is not None,'closed-private-free-observation')
        side,known,error,transition,progress=match.groups(); owner.ensure(side not in result,'unique-side')
        error,transition,progress=map(option,[error,transition,progress])
        if error is not None:
            owner.ensure(isinstance(error,list) and len(error)==3 and all(type(x) is int for x in error),'finite-error-shape')
            origin,category,detail=error
            owner.ensure((origin==1 and 1<=category<=7 and (0<=detail<=12 if category==1 else 0<=detail<=22 if category==3 else detail==0))
                or (origin==2 and 1<=category<=6 and detail==0),'finite-error-domain')
        if transition is not None:
            owner.ensure(isinstance(transition,list) and len(transition)==2 and all(type(x) is int for x in transition)
                and 0<=transition[0]<=4 and transition[1] in {5,6,7,8},'actual-accepted-terminal-domain')
        if progress is not None: owner.ensure(isinstance(progress,list) and len(progress)==5 and all(type(x) is bool for x in progress),'closed-progress')
        result[side]={'known':known=='true','pre_arm_unknown':True,'attempted_error':error,'accepted_terminal':transition,'progress':progress}
        runtime=error is not None and error[:2]==[1,3]
        result[side]['runtime_detail_known']=bool(runtime and known=='true' and error[2] in RUNTIME_DETAILS)
        result[side]['runtime_privacy_kind']=RUNTIME_DETAILS.get(error[2]) if runtime else None
        result[side]['runtime_detail_is_not_producer_site']=True
        result[side]['terminal_timeout_source_contradiction']=bool(runtime and error[2]==2)
    phases=[]
    for match in re.finditer(r'\b(left|right) expected=([A-Za-z]+) observed=([A-Za-z]+)',clean):
        side,expected,observed=match.groups(); owner.ensure(expected in PHASES and observed in PHASES,'closed-original-panic-phase')
        phases.append({'side':side,'expected':expected,'observed':observed})
    owner.ensure(len(phases)<=2,'bounded-original-panic-phases')
    return {'sessions':result,'original_wait_terminal_phases':phases,'attempted_error_is_not_accepted_origin_proof':True,
        'error_encoding':{'origin_1':'borrowed_refresh_ClientLinkingError_category_and_verifier_detail','origin_2':'mapped_native_DeviceLinkingError_only_not_raw_Core_cause','refresh_Runtime_detail_codes':RUNTIME_DETAILS,'Runtime_0':'unknown_unclassified_never_NA'},
        'attribution_known':all(row['known'] for row in result.values())}


def terminal_parser_controls():
    row='owner-five-terminal side={} known=true pre_arm_unknown=true attempted_error=Some([1, 1, 6]) accepted_terminal=Some([4, 6]) progress=Some([true, false, true, false, false])'
    good=row.format('source')+'\n'+row.format('recipient')
    owner.ensure(parse_terminal(good)['sessions']['source']['attempted_error']==[1,1,6],'finite-positive')
    owner.ensure(parse_terminal(good.replace(' known=true ',' known=false ').replace('Some([1, 1, 6])','None').replace('Some([4, 6])','None').replace('Some([true, false, true, false, false])','None'))['sessions']['recipient']['known'] is False,'unknown-positive')
    for detail in [0,5,10,21,22]:
        parsed=parse_terminal(good.replace('Some([1, 1, 6])','Some([1, 3, '+str(detail)+'])'))
        owner.ensure(parsed['sessions']['source']['runtime_detail_known']==(detail!=0),'runtime-known-or-explicit-unknown')
    owner.ensure(parse_terminal(good.replace('Some([1, 1, 6])','Some([1, 3, 2])'))['sessions']['source']['terminal_timeout_source_contradiction'],'timeout-is-not-legitimate-terminal-cause')
    bad=['',good+'\n'+row.format('source'),good.replace('side=recipient','side=source'),good.replace('pre_arm_unknown=true','pre_arm_unknown=false'),good.replace('Some([1, 1, 6])','Some([1, 1, 13])'),good.replace('Some([4, 6])','Some([7, 6])'),good.replace('Some([true, false, true, false, false])','Some([1, false, true, false, false])'),good+' private=hidden',good.replace('Some([1, 1, 6])','Some([2, 7, 0])'),good.replace('Some([1, 1, 6])','Some([true, 1, 6])'),good.replace('Some([1, 1, 6])','Some([1, 3, 23])'),good.replace('Some([1, 1, 6])','Some([1, 4, 10])')]
    for raw in bad:
        try: parse_terminal(raw)
        except (ValueError,TypeError): continue
        raise ValueError('invalid-observation-accepted')
    return {'positive':8,'negative':len(bad),'actual_runtime_bodies':0}


def parse(raw):
    clean=re.sub(r'\x1b\[[0-9;]*m','',raw)
    clean=re.sub(r'(?m)^test '+re.escape(owner.FIVE_NAME)+r' \.\.\. (?=owner-five-(?:terminal|producer) )','',clean)
    terminal=parse_terminal(clean) # Preserve old terminal domains and privacy checks.
    lines=[line for line in clean.splitlines() if 'owner-five-producer' in line]
    owner.ensure(len(lines)==2,'exact-two-producer-lines')
    n=r'(?:0|[1-9][0-9]{0,19})'
    pair=r'(None|Some\(\['+n+r', '+n+r'\]\))'
    triple=r'(None|Some\(\['+n+r', '+n+r', '+n+r'\]\))'
    scalar=r'(None|Some\('+n+r'\))'
    pattern=r'owner-five-producer side=(source|recipient) known=(true|false) first_error='+pair+r' receive='+triple+r' terminal_ordinal='+scalar
    dictionary={int(k):v for k,v in json.loads(Path(MANIFEST).read_text())['receive_kind_codes'].items()}
    result={}
    for line in lines:
        match=re.fullmatch(pattern,line);owner.ensure(match is not None,'closed-producer-marker')
        side,known,first,receive,accepted=match.groups();owner.ensure(side not in result,'unique-producer-side')
        first,receive,accepted=map(option,[first,receive,accepted]);original=terminal['sessions'][side]
        error=original['attempted_error'];transition=original['accepted_terminal']
        owner.ensure((first is None)==(error is None) and (accepted is None)==(transition is None),'same-original-record-presence')
        ordinals=[]
        if first is not None:
            code,ordinal=first;owner.ensure(code in {0,1,2,3,4,255} and 1<=ordinal<=3,'closed-first-error-producer')
            closed=error==[1,3,1]
            owner.ensure(closed or code==0,'producer-only-for-same-Runtime-TransportClosed')
            owner.ensure(code!=255 or known=='false','conflicting-producer-is-loss')
            ordinals.append(ordinal)
        if receive is not None:
            shape,kind,ordinal=receive
            owner.ensure(0<=shape<=10 and kind in {0,*dictionary} and 1<=ordinal<=3,'closed-receive-domain')
            ordinals.append(ordinal)
        if accepted is not None:
            owner.ensure(type(accepted) is int and 1<=accepted<=3,'closed-accepted-ordinal');ordinals.append(accepted)
        owner.ensure(len(ordinals)==len(set(ordinals)),'distinct-record-ordinals')
        loss_known=known=='true' and original['known']
        owner.ensure(not loss_known or sorted(ordinals)==list(range(1,len(ordinals)+1)),'known-record-ordinals-contiguous')
        result[side]={'loss_known':loss_known,'first_error':first,'receive_before_reopen':receive,
            'accepted_terminal_ordinal':accepted,'producer_known':bool(loss_known and error==[1,3,1] and first and first[0] in {1,2,3,4}),
            'receive_kind_known':bool(loss_known and receive and receive[1] in dictionary),
            'receive_privacy_kind':dictionary.get(receive[1]) if receive else None,
            'receive_absence_proves_no_reopen':False,'scope_equality_grants_authority':False,
            'ordinals_are_hook_order_not_causality':True,'pre_drop_is_not_drop_completion':True}
    terminal['producer_observations']=result
    terminal['producer_encoding']={0:'unknown',1:'worker_acquisition_TransportClosed',2:'mpsc_send_error',3:'oneshot_dropped',4:'forwarded_inner_Runtime_TransportClosed',255:'conflicting_observation_producers'}
    terminal['receive_kind_dictionary']=dictionary
    terminal['no_product_fix_or_qualification_claim']=True
    return terminal


def parser_controls():
    old=terminal_parser_controls() # Exact preserved original eight-positive/twelve-negative controls.
    a='owner-five-terminal side=source known=true pre_arm_unknown=true attempted_error=Some([1, 3, 1]) accepted_terminal=Some([4, 7]) progress=Some([true, true, true, false, true])'
    b='owner-five-terminal side=recipient known=true pre_arm_unknown=true attempted_error=None accepted_terminal=None progress=Some([true, true, false, true, false])'
    x='owner-five-producer side=source known=true first_error=Some([3, 2]) receive=Some([3, 10, 1]) terminal_ordinal=Some(3)'
    y='owner-five-producer side=recipient known=true first_error=None receive=None terminal_ordinal=None'
    good='\n'.join([a,b,x,y])
    owner.ensure(parse(good)['producer_observations']['source']['producer_known'],'producer-positive')
    unknown=good.replace('receive=Some([3, 10, 1])','receive=Some([3, 0, 1])')
    owner.ensure(not parse(unknown)['producer_observations']['source']['receive_kind_known'],'unclassified-static-kind-unknown')
    owner.ensure(parse(good.replace('[3, 2]','[2, 1]').replace('receive=Some([3, 10, 1])','receive=None').replace('terminal_ordinal=Some(3)','terminal_ordinal=Some(2)'))['producer_observations']['source']['receive_absence_proves_no_reopen'] is False,'absence-unknown')
    owner.ensure(not parse(good.replace('owner-five-producer side=source known=true','owner-five-producer side=source known=false').replace('[3, 2]','[255, 2]'))['producer_observations']['source']['producer_known'],'conflict-loss-positive')
    legacy=good.replace('[1, 3, 1]','[1, 1, 3]').replace('[3, 2]','[0, 2]')
    owner.ensure(not parse(legacy)['producer_observations']['source']['producer_known'],'other-error-not-forged-producer')
    gap=good.replace('first_error=Some([3, 2])','first_error=Some([3, 3])').replace('receive=Some([3, 10, 1])','receive=None').replace('terminal_ordinal=Some(3)','terminal_ordinal=Some(1)')
    owner.ensure(parse(gap.replace('owner-five-producer side=source known=true','owner-five-producer side=source known=false'))['producer_observations']['source']['loss_known'] is False,'unknown-loss-gap-retained')
    bad=[gap,good+'\n'+x,good.replace('owner-five-producer side=recipient','owner-five-producer side=source'),
         good.replace('[3, 2]','[5, 2]'),good.replace('[3, 2]','[255, 2]'),
         good.replace('[3, 10, 1]','[11, 10, 1]'),good.replace('[3, 10, 1]','[3, 255, 1]'),
         good.replace('[3, 2]','[3, 0]'),good.replace('[3, 2]','[3, 1]'),
         good.replace('[3, 2]','[03, 2]'),good.replace('[3, 2]','[-3, 2]'),
         good.replace('[3, 2]','[3, 2, 1]'),good.replace('terminal_ordinal=Some(3)','terminal_ordinal=Some(4)'),
         good.replace('[1, 3, 1]','[2, 3, 0]'),good.replace(' first_error=None',' first_error=Some([3, 1])'),
         good.replace('receive=Some([3, 10, 1])','receive=private_payload'),good.replace(y,'')]
    for raw in bad:
        try:parse(raw)
        except (ValueError,TypeError):continue
        raise ValueError('invalid-producer-observation-accepted')
    return {'preserved_terminal_parser_controls':old,'producer_positive':6,'producer_negative':len(bad),'actual_runtime_bodies':0}


def remote_format_preflight():
    manifest=json.loads(Path(MANIFEST).read_text());paths=sorted(manifest['files'])
    toolchain=re.search(r'^channel = "([^"\r\n]+)"$',Path('rust-toolchain.toml').read_text(),re.M).group(1)
    subprocess.run(['rustup','toolchain','install',toolchain,'--profile','minimal','--component','rustfmt'],check=True)
    subprocess.run(['rustup','run',toolchain,'rustfmt','--edition','2024','--config','skip_children=true',*paths],check=True)
    patch=subprocess.check_output(['git','diff','--binary','--',*paths])
    destination=Path(os.environ['RUNNER_TEMP'])/'owner-five-terminal-format.patch';destination.write_bytes(patch)
    return {'paths':paths,'patch_bytes':len(patch),'patch_sha256':owner.digest(patch),'passed':not patch}


def main(args):
    os.umask(0o077);OUT.mkdir(exist_ok=True);observations={'complete':False};captured=[]
    capture=owner.capture
    def diagnostic_capture(command,*a,**kw):
        code,raw,seconds=capture(command,*a,**kw)
        if list(command[1:3])==['--exact',owner.FIVE_NAME] and '--nocapture' in command:
            captured.append(raw) # Bounded old capture only; never persisted as raw text.
        return code,raw,seconds
    owner.source_guard=source_guard;owner.OUT=OUT;owner.capture=diagnostic_capture
    try:
        owner.main(SimpleNamespace(five=True,preflight=args.preflight))
        if args.preflight:
            formatted=remote_format_preflight()
            path=OUT/'result.json';result=json.loads(path.read_text());result['remote_format_preflight']=formatted
            path.write_text(json.dumps(result,indent=2)+'\n')
            owner.ensure(formatted['passed'],'remote-formatting-patch-requires-review')
    finally:
        path=OUT/'result.json';result=json.loads(path.read_text()) if path.exists() else {}
        # Old body count/oracle/cleanup parsing has already saved its actual receipt.
        result['actual_receipt_saved_before_diagnostic_parser']=bool(result.get('cases'))
        if captured:
            try:
                owner.ensure(len(captured)==1,'exact-one-captured-original-body')
                observations.update(parse(captured[0]),complete=True)
            except (ValueError,TypeError):observations['rejected_closed_observation']=True
        captured.clear()
        result.update(diagnostic_observations=observations,observed_five_device_pass=result.get('five_device_journey_passed',False),
            five_device_journey_passed=False,qualification_passed=False,native_acceptance_claim=False,promotion_eligible=False,closes_prior_fifth_failure=False)
        path.write_text(json.dumps(result,indent=2)+'\n');owner.capture=capture
        if result.get('cases'):owner.ensure(observations['complete'],'closed-terminal-and-producer-observations-required')

if __name__=='__main__':
    parser=argparse.ArgumentParser();parser.add_argument('--preflight',action='store_true');main(parser.parse_args())
