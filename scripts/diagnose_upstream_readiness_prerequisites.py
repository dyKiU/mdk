#!/usr/bin/env python3
"""One-case prerequisite observations; never closes a failed mutation chain."""
import argparse, hashlib, json, os, re, subprocess
from pathlib import Path
from types import SimpleNamespace
import qualify_upstream_source_readiness_candidate as candidate
red = candidate.red
BASE = '86b51bfc8b797d799cad7e23d81fc31ce20affd2'
SELF = 'scripts/diagnose_upstream_readiness_prerequisites.py'
PROBE = 'crates/marmot-app/src/client/private_enrollment_proposal/source_readiness_probe.rs'
PROBE_SHA = 'ef4923aca7189724bccd6c87194826d643074d84b7defd1146939424d48c27f3'
WORKFLOW = '.github/workflows/experimental-sync-ci.yml'
REF = 'refs/heads/ci/upstream-readiness-prerequisites-diagnostic-20261018'
BEGIN = '  # READINESS_PREREQUISITE_JOBS_BEGIN\n'
END = '  # READINESS_PREREQUISITE_JOBS_END\n'
OPTIONS = 'options: [readiness-prerequisites-preflight, readiness-prerequisites-diagnostic, '
OUT = Path('readiness-prerequisites-evidence')
PREFIX = 'source-readiness-prerequisite'

def source_guard():
    head=subprocess.check_output(['git','rev-parse','HEAD'],text=True).strip()
    red.ensure(os.environ.get('GITHUB_ACTIONS')=='true' and os.environ.get('GITHUB_REPOSITORY')=='dyKiU/mdk' and os.environ.get('GITHUB_EVENT_NAME')=='workflow_dispatch' and os.environ.get('GITHUB_SHA')==head and os.environ.get('GITHUB_REF')==REF and os.environ.get('GITHUB_WORKFLOW_REF')=='dyKiU/mdk/'+WORKFLOW+'@'+REF and os.environ.get('UPSTREAM_READINESS_DIAGNOSTIC_BASELINE')==BASE,'owned-reviewed-diagnostic')
    red.ensure(os.environ.get('CARGO_INCREMENTAL')=='1' and os.environ.get('CARGO_BUILD_JOBS')=='2' and os.environ.get('RUST_MIN_STACK')=='4194304' and all(os.environ.get(k)=='0' for k in ['CARGO_PROFILE_DEV_DEBUG','CARGO_PROFILE_TEST_DEBUG']) and all(not os.environ.get(k) for k in ['RUSTFLAGS','CARGO_ENCODED_RUSTFLAGS','RUSTC_BOOTSTRAP','CARGO_PROFILE_DEV_OPT_LEVEL','CARGO_PROFILE_TEST_OPT_LEVEL']),'unchanged-execution-cohort')
    subprocess.run(['git','merge-base','--is-ancestor',BASE,head],check=True)
    red.ensure(subprocess.run(['git','diff','--quiet','HEAD']).returncode==0,'pristine-inputs')
    baseline={}
    for entry in subprocess.check_output(['git','ls-tree','-r','-z',BASE]).split(b'\0'):
        if entry:
            meta,name=entry.split(b'\t',1);mode,kind,blob=meta.decode().split();red.ensure(kind=='blob','baseline-blobs');baseline[os.fsdecode(name)]=(mode,blob)
    current=red.layout();red.ensure(SELF not in baseline and set(current)==set(baseline)|{SELF},'whole-input-inventory')
    for name,meta in current.items():
        mode,blob=baseline.get(name,('100644',None));red.ensure(meta['git_mode']==mode and meta['symlink']==(mode=='120000') and (meta['symlink'] or meta['actual_executable']==(mode=='100755')),'exact-modes')
        data=os.fsencode(os.readlink(name)) if meta['symlink'] else Path(name).read_bytes()
        if name==PROBE:red.ensure(red.digest(data)==PROBE_SHA,'exact-observation-only-probe');continue
        if name==WORKFLOW:
            text=data.decode();red.ensure(text.count(BEGIN)==text.count(END)==text.count(OPTIONS)==1,'isolated-workflow');before,rest=text.split(BEGIN);_,after=rest.split(END);data=(before+after).replace(OPTIONS,'options: [',1).encode()
        if blob is not None:red.ensure(hashlib.sha1(b'blob '+str(len(data)).encode()+b'\0'+data).hexdigest()==blob,'whole-baseline-input:'+name)
    red.ensure(not subprocess.check_output(['git','ls-files','--others','--exclude-standard'],text=True).strip(),'no-untracked-source')
    return {'source':head,'reviewed_baseline':BASE,'all_fixture_product_helpers_modes_exact':True,'only_probe_observation_changed':True,'historical_evidence_reused':False}

def parse_codes(raw):
    clean=re.sub(r'\x1b\[[0-9;]*m','',raw)
    clean=re.sub(r'(?m)^test '+re.escape(red.NAME)+r' \.\.\. (?='+PREFIX+r' )','',clean)
    lines=[line for line in clean.splitlines() if PREFIX in line]
    red.ensure(0<len(lines)<=1024,'bounded-present-code-changes')
    codes=[]
    for line in lines:
        match=re.fullmatch(PREFIX+r' code=(0|[1-9][0-9]{0,2})',line)
        red.ensure(match is not None and int(match[1])<=258,'closed-static-mask-or-none-code');codes.append(int(match[1]))
    red.ensure(all(a!=b for a,b in zip(codes,codes[1:])),'deduplicated-state-changes')
    return codes

def parser_controls():
    red.ensure(parse_codes(PREFIX+' code=0\n'+PREFIX+' code=255\n'+PREFIX+' code=256\n'+PREFIX+' code=258')==[0,255,256,258],'closed-positive')
    red.ensure(parse_codes('test '+red.NAME+' ... '+PREFIX+' code=7')==[7],'exact-prefix-positive')
    for value in ['',PREFIX+' code=259',PREFIX+' code=true',PREFIX+' code=01',PREFIX+' code=7 private=x',PREFIX+' code=7\n'+PREFIX+' code=7','test foreign ... '+PREFIX+' code=7','\n'.join(PREFIX+' code='+str(i%2) for i in range(1025))]:
        try:parse_codes(value)
        except ValueError:continue
        raise ValueError('invalid-private-unbounded-observation-accepted')
    return {'positive':2,'negative':8,'runtime_bodies':0}

def main(args):
    os.umask(0o077);OUT.mkdir(exist_ok=True);observations={'codes':None,'complete':False,'mask_bits':['exact_owner','eligible_original','matching_live_attempt','fresh_round_completed','fresh_guard_valid','validated_roster_some','retained_matching_request','still_live_unchanged_deadline'],'none_codes':{'256':'weak_unavailable','257':'action_unavailable','258':'owner_mismatch'},'timing_attribution':False}
    capture=red.bounded.capture;guard=source_guard
    def diagnostic_guard():return dict(guard(),observation_parser_controls=parser_controls())
    def capture_observations(*a,**kw):
        code,raw,seconds=capture(*a,**kw)
        command=a[0] if a else kw.get('command', [])
        if isinstance(command, (list, tuple)) and list(command[1:3]) == ['--exact', red.NAME]:
            try:observations['codes']=parse_codes(raw);observations['complete']=True
            except ValueError:observations['rejected_closed_observation']=True
        return code,raw,seconds
    candidate.source_guard=diagnostic_guard;candidate.OUT=OUT;red.bounded.capture=capture_observations
    try:candidate.main(SimpleNamespace(preflight=args.preflight,mutation=None))
    finally:
        result=OUT/'result.json';row=json.loads(result.read_text()) if result.exists() else {}
        row['diagnostic_observations']=observations;row['diagnostic_complete']=observations['complete'];row['observed_directed_green']=row.get('directed_GREEN',False)
        row.update(directed_GREEN=False,component_mutation_qualified=False,full_qualification=False,native_acceptance_claim=False,promotion_eligible=False,closes_prior_failed_PFP=False)
        result.write_text(json.dumps(row,indent=2)+'\n');red.bounded.capture=capture
        if any('body' in phase for phase in row.get('phases',{}).values()):red.ensure(observations['complete'],'closed-prerequisite-observations-required')

if __name__=='__main__':
    parser=argparse.ArgumentParser();parser.add_argument('--preflight',action='store_true');main(parser.parse_args())
