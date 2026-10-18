#!/usr/bin/env python3
"""One unchanged thousand-group SDK test; diagnostic completion is not product GREEN."""
import argparse,hashlib,json,os,re,subprocess
from pathlib import Path
import qualify_upstream_storage_app_handles as shared
from upstream_extraction_cohort import frozen_inputs
bounded=shared.old
ensure=bounded.ensure
BASE='77caba679ab5986df88fd7296b5446004fba8bb7'
SELF='scripts/diagnose_upstream_transport_thousand.py'
MANIFEST='scripts/transport_thousand_source_manifest.json'
MANIFEST_SHA='b248468d2a99c28ac837479860b7d26e134dc9cec31ea5a70f829bec97608743'
WORKFLOW='.github/workflows/experimental-sync-ci.yml'
REF='refs/heads/ci/upstream-transport-thousand-diagnostic-20261018'
BEGIN='  # TRANSPORT_THOUSAND_DIAGNOSTIC_JOBS_BEGIN\n'
END='  # TRANSPORT_THOUSAND_DIAGNOSTIC_JOBS_END\n'
OPTIONS='options: [transport-thousand-preflight, transport-thousand-diagnostic, '
OUT=Path('transport-thousand-diagnostic-evidence')
NAME='a_thousand_groups_fit_in_a_few_reqs_and_every_group_delivers'
FIXTURE='crates/transport-nostr-adapter/tests/relay_limit_subscriptions.rs'
FEATURES=['default','experimental-device-sync','sdk','test-policy-overrides']
EXIT_MEANINGS={0:'expected_count_reached',1:'selected_global_deadline_elapsed',2:'selected_idle_deadline_elapsed',3:'receive_none',4:'receive_error'}

def source_guard():
    ensure(isinstance(MANIFEST_SHA,str) and re.fullmatch('[a-f0-9]{64}',MANIFEST_SHA),'reviewed-manifest-required')
    ensure(bounded.digest(Path(MANIFEST).read_bytes())==MANIFEST_SHA,'exact-source-manifest')
    manifest=json.loads(Path(MANIFEST).read_text())
    ensure(manifest['baseline']==BASE and manifest['path']==FIXTURE and manifest['mode']=='100644','one-reviewed-fixture')
    head=subprocess.check_output(['git','rev-parse','HEAD'],text=True).strip()
    ensure(os.environ.get('GITHUB_ACTIONS')=='true' and os.environ.get('GITHUB_REPOSITORY')=='dyKiU/mdk'
        and os.environ.get('GITHUB_EVENT_NAME')=='workflow_dispatch' and os.environ.get('GITHUB_SHA')==head
        and os.environ.get('GITHUB_REF')==REF and os.environ.get('GITHUB_WORKFLOW_REF')=='dyKiU/mdk/'+WORKFLOW+'@'+REF
        and os.environ.get('TRANSPORT_THOUSAND_BASELINE')==BASE,'exact-owned-workflow')
    ensure(os.environ.get('CARGO_INCREMENTAL')=='1' and os.environ.get('CARGO_BUILD_JOBS')=='2'
        and os.environ.get('RUST_MIN_STACK')=='4194304'
        and all(os.environ.get(k)=='0' for k in ['CARGO_PROFILE_DEV_DEBUG','CARGO_PROFILE_TEST_DEBUG'])
        and all(not os.environ.get(k) for k in ['RUSTFLAGS','CARGO_ENCODED_RUSTFLAGS','RUSTC_BOOTSTRAP','CARGO_PROFILE_DEV_OPT_LEVEL','CARGO_PROFILE_TEST_OPT_LEVEL']),'exact-build-cohort')
    subprocess.run(['git','merge-base','--is-ancestor',BASE,head],check=True)
    ensure(subprocess.run(['git','diff','--quiet','HEAD']).returncode==0,'tracked-pristine')
    baseline={}
    for entry in subprocess.check_output(['git','ls-tree','-r','-z',BASE]).split(b'\0'):
        if entry:
            metadata,path=entry.split(b'\t',1);mode,kind,blob=metadata.decode().split()
            ensure(kind=='blob','baseline-blob');baseline[os.fsdecode(path)]=(mode,blob)
    current=frozen_inputs()
    ensure(not({SELF,MANIFEST}&set(baseline)) and set(current)==set(baseline)|{SELF,MANIFEST},'whole-source-inventory')
    for path,row in current.items():
        mode,blob=baseline.get(path,('100644',None))
        ensure(row['mode']==mode and (mode=='120000' or row['actual_executable']==(mode=='100755')),'whole-source-modes')
        data=os.fsencode(os.readlink(path)) if mode=='120000' else Path(path).read_bytes()
        if path==FIXTURE:
            ensure(bounded.digest(data)==manifest['after_sha256'],'exact-observation-source')
            change=manifest['exact_substitution'];text=data.decode()
            ensure(text.count(change['after'])==1,'unique-observation-reversal')
            data=text.replace(change['after'],change['before'],1).encode()
            ensure(bounded.digest(data)==manifest['before_sha256'],'exact-original-helper-after-reversal')
        if path==WORKFLOW:
            text=data.decode();ensure(text.count(BEGIN)==text.count(END)==text.count(OPTIONS)==1,'one-owned-workflow-overlay')
            left,rest=text.split(BEGIN);_,right=rest.split(END);data=(left+right).replace(OPTIONS,'options: [',1).encode()
        if blob is not None:ensure(hashlib.sha1(b'blob '+str(len(data)).encode()+b'\0'+data).hexdigest()==blob,'exact-baseline:'+path)
    ensure(set(subprocess.check_output(['git','ls-files','--others','--exclude-standard'],text=True).splitlines())<={str(OUT/'result.json')},'no-untracked-source')
    ensure('#[tokio::test(flavor = "multi_thread", worker_threads = 4)]\nasync fn '+NAME+'()' in Path(FIXTURE).read_text(),'original-four-workers')
    return {'source':head,'baseline':BASE,'whole_source_modes_reconstructed':True,'fixture_sha256':manifest['after_sha256'],
        'manifest_sha256':MANIFEST_SHA,'original_workers':4,'outer_wait_seconds':20,'idle_milliseconds':1500,
        'historical_runtime_evidence_reused':False}

def diagnostic(raw):
    clean=re.sub(r'\x1b\[[0-9;]*m','',raw)
    clean,normalized=re.subn(r'(?m)^test '+re.escape(NAME)+r' \.\.\. (?=transport-delivery-exit )','',clean)
    ensure(normalized<=1,'one-shared-test-prefix')
    lines=[line for line in clean.splitlines() if line.startswith('transport-delivery-exit')]
    ensure(len(lines)==1 and len(lines[0])<=256,'one-bounded-exit-marker')
    match=re.fullmatch(r'transport-delivery-exit known=(true|false) exit=([0-4]) delivered=([0-9]{1,4}) receives=([0-9]{1,20}) unhinted=([0-9]{1,20}) elapsed_us=([0-9]{1,10})',lines[0])
    ensure(match is not None,'closed-exit-marker')
    known=match[1]=='true';exit_code,delivered,receives,unhinted,elapsed=map(int,[match[i] for i in range(2,7)])
    ensure(delivered<=1000 and unhinted<=receives<=18446744073709551615 and elapsed<=300000000,'bounded-closed-observations')
    ensure(not known or delivered<=receives-unhinted,'actual-hinted-delivery-count')
    ensure(exit_code!=0 or delivered==1000,'count-exit-requires-expected-count')
    return {'known':known,'exit_code':exit_code,'exit_meaning':EXIT_MEANINGS[exit_code],'delivered':delivered,
        'receives':receives,'unhinted':unhinted,'elapsed_us':elapsed,'exact_prefix_normalizations':normalized,
        'selected_deadline_is_not_exact_firing_time':True}

def parser_controls():
    sample='transport-delivery-exit known=true exit=2 delivered=657 receives=660 unhinted=2 elapsed_us=4909000'
    positives=[sample,'test '+NAME+' ... '+sample,sample.replace('known=true','known=false'),sample.replace('exit=2 delivered=657 receives=660','exit=0 delivered=1000 receives=1002')]
    for value in positives:diagnostic(value)
    bad=[sample+'\n'+sample,sample.replace('exit=2','exit=5'),sample.replace('delivered=657','delivered=1001'),
        sample.replace('exit=2','exit=0'),sample.replace('receives=660','receives=1'),sample.replace('known=true','known=unknown'),
        sample.replace('elapsed_us=4909000','elapsed_us=300000001'),sample+' private=hidden',sample.replace('delivered=657','delivered=-1'),
        'test foreign::case ... '+sample,sample.replace('unhinted=2','unhinted=99999999999999999999')]
    for value in bad:
        try:diagnostic(value)
        except (ValueError,bounded.GateFailure):continue
        raise ValueError('invalid-exit-marker-accepted')
    return {'positive':len(positives),'negative':len(bad),'runtime_bodies':0,'shared_counts_inventory':shared.parser_controls()}

def main(args):
    os.umask(0o077);OUT.mkdir(exist_ok=True)
    report={'scope':'one-original-thousand-group-delivery-diagnostic','diagnostic_completed':False,'journey_passed':False,
        'qualification':False,'native_acceptance':False,'promotion_eligible':False,'runtime_execution_attempted':False,
        'actual_counts_complete':False,'actual_passed':None,'actual_failed':None,'actual_ignored':None,'actual_executed_nonignored':None}
    frozen=None;binary=None;sha=None
    def save():(OUT/'result.json').write_text(json.dumps(report,indent=2)+'\n')
    try:
        report['source_guard']=source_guard();report['parser_controls']=parser_controls();save()
        if args.preflight:
            code,_,seconds=bounded.capture(['rustfmt','--edition','2024','--config','skip_children=true',FIXTURE],180,limit=1024*1024)
            patch=subprocess.check_output(['git','diff','--binary','--',FIXTURE]);(OUT/'formatting.patch').write_bytes(patch)
            report['format']={'exit_code':code,'seconds':seconds,'patch_bytes':len(patch),'sha256':bounded.digest(patch)};save()
            ensure(code==0 and not patch,'remote-format-feedback-required');report['preflight_passed']=True;save();return
        frozen=frozen_inputs();report['source_manifest_sha256']=bounded.digest(json.dumps(frozen,sort_keys=True).encode())
        command=['cargo','test','--locked','-p','transport-nostr-adapter','--test','relay_limit_subscriptions','--all-features','--no-run','--message-format=json']
        code,raw,seconds=bounded.capture(command,1800,limit=8*1024*1024)
        events=[json.loads(line) for line in raw.splitlines() if line.startswith('{')]
        errors=[v for v in events if v.get('reason')=='compiler-message' and v.get('message',{}).get('level')=='error']
        artifacts=[v for v in events if v.get('reason')=='compiler-artifact']
        selected=[v for v in artifacts if v['target']['name']=='relay_limit_subscriptions' and v['target']['kind']==['test'] and v.get('executable')]
        manifest=[{'package':v['package_id'],'target':v['target']['name'],'kind':v['target']['kind'],'features':sorted(v['features']),'profile':v['profile']} for v in artifacts]
        report['compilation']={'command':command,'exit_code':code,'compiler_error_count':len(errors),'seconds':seconds,
            'safe_errors':[bounded.safe_compiler_diagnostic(v,frozen) for v in errors[:32]],'errors_truncated':len(errors)>32,
            'artifact_features':manifest,'feature_manifest_sha256':bounded.digest(json.dumps(manifest,sort_keys=True).encode()),'selected_artifact_count':len(selected)};save()
        ensure(code==0 and not errors and len(selected)==1 and sorted(selected[0]['features'])==FEATURES
            and selected[0]['profile']['test'] is True and any(v['target']['name']=='nostr_sdk' and v['target']['kind']==['lib'] for v in artifacts),'actual-sdk-test-compile-required')
        binary=Path(selected[0]['executable']);sha=bounded.digest(binary.read_bytes());report['binary_sha256']=sha;save()
        for ignored in [False,True]:
            code,raw,_=bounded.capture([str(binary),'--exact',NAME]+(['--ignored'] if ignored else [])+['--list','--format','terse'],60,limit=1024*1024)
            inventory=shared.parse_inventory(raw,NAME,ignored);report.setdefault('inventory',{})['ignored' if ignored else 'normal']=inventory;save()
            ensure(code==0 and inventory['passed'],'exact-one-nonignored-original-case')
        ensure(frozen_inputs()==frozen and bounded.digest(binary.read_bytes())==sha,'before-runtime-pristine')
        report['runtime_execution_attempted']=True;save()
        code,raw,seconds=bounded.capture([str(binary),'--exact',NAME,'--nocapture','--test-threads=1'],300,limit=8*1024*1024)
        row=shared.parse_body(raw,code,NAME);report['body']=row;report['body_seconds']=seconds
        locations=re.findall(r'panicked at ([A-Za-z0-9_./-]+\.rs):([0-9]+):([0-9]+):',raw)
        known_locations=[{'path':path,'line':int(line),'column':int(column)} for path,line,column in locations
            if path in frozen and 0<int(line)<=2147483647 and 0<int(column)<=2147483647]
        report['safe_panic_locations']=known_locations[:16]
        report['unknown_panic_location_count']=len(locations)-len(known_locations)
        report['panic_locations_truncated']=len(known_locations)>16
        for destination,key in [('actual_passed','passed'),('actual_failed','failed'),('actual_ignored','ignored'),('actual_executed_nonignored','executed_nonignored')]:report[destination]=row.get(key)
        report['actual_counts_complete']=row['actual_counts_complete'];save()
        report['diagnostic']=diagnostic(raw);report['journey_passed']=row['passed_gate'];save()
        ensure(row['actual_counts_complete'] and row['executed_nonignored']==1 and row['ignored']==0 and row['compiler_error_count']==0,'one-actual-original-runtime-body')
        ensure(report['diagnostic']['known'],'known-exit-diagnostic-required')
        report['diagnostic_completed']=True;save()
        ensure(row['passed_gate'],'original-runtime-failure-retained')
    except Exception as error:
        report['exception_type']=type(error).__name__
        if isinstance(error,(ValueError,bounded.GateFailure)):
            text=str(error);report['failure_gate']=text if re.fullmatch('[A-Za-z0-9_.:/-]{1,120}',text) else 'closed-gate-rejected'
        raise
    finally:
        if frozen is not None:
            report['inputs_pristine']=frozen_inputs()==frozen
            if not report['runtime_execution_attempted']:report['actual_executed_nonignored']=0
        if binary is not None:report['binary_pristine']=binary.is_file() and bounded.digest(binary.read_bytes())==sha
        if report.get('inputs_pristine') is False or report.get('binary_pristine') is False:report['diagnostic_completed']=False
        save()
        if frozen is not None:ensure(report['inputs_pristine'],'final-source-pristine')
        if binary is not None:ensure(report['binary_pristine'],'final-binary-pristine')
if __name__=='__main__':
    parser=argparse.ArgumentParser();parser.add_argument('--preflight',action='store_true');main(parser.parse_args())
