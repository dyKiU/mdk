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

BASE = 'c75d41ce5070f4d99d12e8c933cdc67733eb4aa6'
SELF = 'scripts/diagnose_owner_five_terminal.py'
REF = 'refs/heads/ci/upstream-owner-five-diagnostic-20261018'
WORKFLOW = '.github/workflows/experimental-sync-ci.yml'
BEGIN = '  # OWNER_FIVE_DIAGNOSTIC_JOBS_BEGIN\n'
END = '  # OWNER_FIVE_DIAGNOSTIC_JOBS_END\n'
OPTIONS = 'options: [owner-five-diagnostic-preflight, owner-five-diagnostic, '
OUT = Path('owner-five-terminal-evidence')
PINS = {
    'crates/marmot-app/src/native_device_linking/enabled.rs': 'a1346c0e15ecfcb39899ffefe1c580b29fa4d5a570983274967c6258d9513975',
    'crates/marmot-app/src/native_device_linking/enabled/automatic.rs': '69437cd30b2c435667a5d0d2318dd6f83b44cf82615d151f4751c17e1c122abd',
    'crates/marmot-app/src/native_device_linking/enabled/terminal_diagnostic.rs': 'c41b5b4ce0354e4fba0189568f81c7396ca16c31cdb61619087bd5bd119ba4db',
    owner.FIVE_FILE: '5b53c21843dfbe8712bdfb5298ba586505adc543c3ae55348adbdbafaa6a4c0a',
}
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
    baseline = {}
    for entry in subprocess.check_output(['git','ls-tree','-r','-z',BASE]).split(b'\0'):
        if entry:
            meta,name=entry.split(b'\t',1); mode,kind,blob=meta.decode().split()
            owner.ensure(kind == 'blob','ordinary-baseline'); baseline[os.fsdecode(name)]=(mode,blob)
    frozen=owner.snapshot()
    owner.ensure(set(frozen)==set(baseline)|{SELF,PROBE} and SELF not in baseline and PROBE not in baseline,'whole-input-inventory')
    for name,actual in frozen.items():
        mode,blob=baseline.get(name,('100644',None))
        owner.ensure(actual['mode']==mode and (mode=='120000' or actual['actual_executable']==(mode=='100755')),'whole-modes')
        data=os.fsencode(os.readlink(name)) if mode=='120000' else Path(name).read_bytes()
        if name in PINS:
            owner.ensure(owner.digest(data)==PINS[name],'reviewed-passive-source:'+name)
            if name.endswith('/enabled.rs') or name.endswith('/enabled/automatic.rs'):
                text=data.decode(); count=4 if name.endswith('/enabled.rs') else 1
                pattern=r'(?m)^[ \t]*// OWNER_FIVE_TERMINAL_TEST_BEGIN\n.*?^[ \t]*// OWNER_FIVE_TERMINAL_TEST_END\n'
                data,n=re.subn(pattern,'',text,flags=re.S); owner.ensure(n==count,'exact-passive-hook-count'); data=data.encode()
            else: continue
        if name==WORKFLOW:
            text=data.decode(); owner.ensure(text.count(BEGIN)==text.count(END)==text.count(OPTIONS)==1,'isolated-workflow')
            before,rest=text.split(BEGIN); _,after=rest.split(END); data=(before+after).replace(OPTIONS,'options: [',1).encode()
        if blob is not None:
            owner.ensure(hashlib.sha1(b'blob '+str(len(data)).encode()+b'\0'+data).hexdigest()==blob,'exact-baseline:'+name)
    owner.ensure(not subprocess.check_output(['git','ls-files','--others','--exclude-standard'],text=True).strip(),'no-untracked-source')
    return {'source':head,'baseline':BASE,'test_only_passive_hooks':True,'old_helpers_controllers_exact':True,'parser_controls':parser_controls()}


def option(raw):
    if raw == 'None': return None
    owner.ensure(raw.startswith('Some(') and raw.endswith(')'),'closed-option')
    return json.loads(raw[5:-1])


def parse(raw):
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
            owner.ensure((origin==1 and 1<=category<=7 and (0<=detail<=12 if category==1 else detail==0))
                or (origin==2 and 1<=category<=6 and detail==0),'finite-error-domain')
        if transition is not None:
            owner.ensure(isinstance(transition,list) and len(transition)==2 and all(type(x) is int for x in transition)
                and 0<=transition[0]<=4 and transition[1] in {5,6,7,8},'actual-accepted-terminal-domain')
        if progress is not None: owner.ensure(isinstance(progress,list) and len(progress)==5 and all(type(x) is bool for x in progress),'closed-progress')
        result[side]={'known':known=='true','pre_arm_unknown':True,'attempted_error':error,'accepted_terminal':transition,'progress':progress}
    phases=[]
    for match in re.finditer(r'\b(left|right) expected=([A-Za-z]+) observed=([A-Za-z]+)',clean):
        side,expected,observed=match.groups(); owner.ensure(expected in PHASES and observed in PHASES,'closed-original-panic-phase')
        phases.append({'side':side,'expected':expected,'observed':observed})
    owner.ensure(len(phases)<=2,'bounded-original-panic-phases')
    return {'sessions':result,'original_wait_terminal_phases':phases,'attempted_error_is_not_accepted_origin_proof':True,
        'error_encoding':{'origin_1':'borrowed_refresh_ClientLinkingError_category_and_verifier_detail','origin_2':'mapped_native_DeviceLinkingError_only_not_raw_Core_cause'},
        'attribution_known':all(row['known'] for row in result.values())}


def parser_controls():
    row='owner-five-terminal side={} known=true pre_arm_unknown=true attempted_error=Some([1, 1, 6]) accepted_terminal=Some([4, 6]) progress=Some([true, false, true, false, false])'
    good=row.format('source')+'\n'+row.format('recipient')
    owner.ensure(parse(good)['sessions']['source']['attempted_error']==[1,1,6],'finite-positive')
    owner.ensure(parse(good.replace(' known=true ',' known=false ').replace('Some([1, 1, 6])','None').replace('Some([4, 6])','None').replace('Some([true, false, true, false, false])','None'))['sessions']['recipient']['known'] is False,'unknown-positive')
    bad=['',good+'\n'+row.format('source'),good.replace('side=recipient','side=source'),good.replace('pre_arm_unknown=true','pre_arm_unknown=false'),good.replace('Some([1, 1, 6])','Some([1, 1, 13])'),good.replace('Some([4, 6])','Some([7, 6])'),good.replace('Some([true, false, true, false, false])','Some([1, false, true, false, false])'),good+' private=hidden',good.replace('Some([1, 1, 6])','Some([2, 7, 0])'),good.replace('Some([1, 1, 6])','Some([true, 1, 6])')]
    for raw in bad:
        try: parse(raw)
        except (ValueError,TypeError): continue
        raise ValueError('invalid-observation-accepted')
    return {'positive':2,'negative':len(bad),'actual_runtime_bodies':0}


def main(args):
    os.umask(0o077); OUT.mkdir(exist_ok=True); observations={'complete':False}
    capture=owner.capture
    def diagnostic_capture(command,*a,**kw):
        code,raw,seconds=capture(command,*a,**kw)
        if list(command[1:3])==['--exact',owner.FIVE_NAME] and '--nocapture' in command:
            try: observations.update(parse(raw),complete=True)
            except (ValueError,TypeError): observations['rejected_closed_observation']=True
        return code,raw,seconds
    owner.source_guard=source_guard; owner.OUT=OUT; owner.capture=diagnostic_capture
    try: owner.main(SimpleNamespace(five=True,preflight=args.preflight))
    finally:
        path=OUT/'result.json'; result=json.loads(path.read_text()) if path.exists() else {}
        result.update(diagnostic_observations=observations,observed_five_device_pass=result.get('five_device_journey_passed',False),
            five_device_journey_passed=False,qualification_passed=False,native_acceptance_claim=False,promotion_eligible=False,closes_prior_fifth_failure=False)
        path.write_text(json.dumps(result,indent=2)+'\n'); owner.capture=capture
        if result.get('cases'): owner.ensure(observations['complete'],'closed-terminal-observations-required')

if __name__=='__main__':
    parser=argparse.ArgumentParser(); parser.add_argument('--preflight',action='store_true'); main(parser.parse_args())
