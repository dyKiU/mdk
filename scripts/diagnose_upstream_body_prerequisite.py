#!/usr/bin/env python3
"""One unchanged current-thread Body negative case; passive prerequisite observations only."""
import argparse,hashlib,json,os,re,subprocess
from pathlib import Path
import qualify_upstream_storage_app_handles as shared
from upstream_extraction_cohort import frozen_inputs
bounded=shared.old
ensure=bounded.ensure
BASE='77caba679ab5986df88fd7296b5446004fba8bb7'
SELF='scripts/diagnose_upstream_body_prerequisite.py'
MANIFEST='scripts/body_prerequisite_source_manifest.json'
MANIFEST_SHA='6652586c94fef4111e4c0a1c7660f35579299248d50bb1d6ae1f1917a2399f54'
WORKFLOW='.github/workflows/experimental-sync-ci.yml'
REF='refs/heads/ci/upstream-body-prerequisite-diagnostic-20261018'
BEGIN='  # BODY_PREREQUISITE_DIAGNOSTIC_JOBS_BEGIN\n'
END='  # BODY_PREREQUISITE_DIAGNOSTIC_JOBS_END\n'
OPTIONS='options: [body-prerequisite-preflight, body-prerequisite-diagnostic, '
OUT=Path('body-prerequisite-diagnostic-evidence')
CASE='authenticated_negative_sql_failure_retains_owned_body_until_commit_before_disposition'
NAME='native_device_linking::automatic_pairing_acceptance::body_negative_acceptance::'+CASE
FIXTURE='crates/marmot-app/src/native_device_linking/tests/automatic_body_negative_acceptance.rs'
NODES={'marmot_app','cgka_engine','storage_sqlite','cgka_session','marmot_account','transport_nostr'}
from upstream_completion_ci import compile_cases
from qualify_upstream_body_negative import feature_identity
import upstream_body_negative_ci as rich
BIT_MEANINGS=['captured_present','intent_gate_present','catalog_group','payload','nonce','account','protected_group','local_to_peer_device','peer_to_local_device','intent_gate_entered','release_receiver_present']

def source_guard():
    ensure(isinstance(MANIFEST_SHA,str) and re.fullmatch('[a-f0-9]{64}',MANIFEST_SHA),'reviewed-manifest-required')
    ensure(bounded.digest(Path(MANIFEST).read_bytes())==MANIFEST_SHA,'exact-source-manifest')
    manifest=json.loads(Path(MANIFEST).read_text())
    ensure(manifest['baseline']==BASE and set(manifest['paths'])=={FIXTURE,'crates/marmot-app/src/client/account_chat_sharing/automatic/body_negative_probe.rs'},'one-reviewed-fixture')
    head=subprocess.check_output(['git','rev-parse','HEAD'],text=True).strip()
    ensure(os.environ.get('GITHUB_ACTIONS')=='true' and os.environ.get('GITHUB_REPOSITORY')=='dyKiU/mdk'
        and os.environ.get('GITHUB_EVENT_NAME')=='workflow_dispatch' and os.environ.get('GITHUB_SHA')==head
        and os.environ.get('GITHUB_REF')==REF and os.environ.get('GITHUB_WORKFLOW_REF')=='dyKiU/mdk/'+WORKFLOW+'@'+REF
        and os.environ.get('BODY_PREREQUISITE_BASELINE')==BASE,'exact-owned-workflow')
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
        if path in manifest['paths']:
            pin=manifest['paths'][path];ensure(pin['mode']==mode and bounded.digest(data)==pin['after_sha256'],'exact-observation-source')
            text=data.decode()
            for change in reversed(pin['exact_substitutions']):
                ensure(text.count(change['after'])==1,'unique-observation-reversal')
                text=text.replace(change['after'],change['before'],1)
            data=text.encode();ensure(bounded.digest(data)==pin['before_sha256'],'exact-original-source-after-reversal')
        if path==WORKFLOW:
            text=data.decode();ensure(text.count(BEGIN)==text.count(END)==text.count(OPTIONS)==1,'one-owned-workflow-overlay')
            left,rest=text.split(BEGIN);_,right=rest.split(END);data=(left+right).replace(OPTIONS,'options: [',1).encode()
        if blob is not None:ensure(hashlib.sha1(b'blob '+str(len(data)).encode()+b'\0'+data).hexdigest()==blob,'exact-baseline:'+path)
    ensure(set(subprocess.check_output(['git','ls-files','--others','--exclude-standard'],text=True).splitlines())<={str(OUT/'result.json')},'no-untracked-source')
    ensure('#[tokio::test(flavor = "current_thread")]\nasync fn '+CASE+'()' in Path(FIXTURE).read_text(),'original-current-thread-interleaving')
    return {'source':head,'baseline':BASE,'whole_source_modes_reconstructed':True,'manifest_sha256':MANIFEST_SHA,
        'current_thread_SQL_interleaving_preserved':True,'original_matcher_short_circuit_preserved':True,'no_new_queries_waits_or_authority':True,'historical_runtime_evidence_reused':False}

def diagnostic(raw):
    clean=re.sub(r'\x1b\[[0-9;]*m','',raw)
    clean,normalized=re.subn(r'(?m)^test '+re.escape(NAME)+r' \.\.\. (?=body-prerequisite )','',clean)
    ensure(normalized<=1,'one-shared-test-prefix')
    lines=[line for line in clean.splitlines() if line.startswith('body-prerequisite')]
    ensure(len(lines)==1 and len(lines[0])<=256,'one-bounded-prerequisite-marker')
    number=r'(?:0|[1-9][0-9]{0,19})';option=r'(?:None|Some\('+number+r'\))'
    match=re.fullmatch(r'body-prerequisite known=(true|false) evaluated=('+number+r') matched=('+number+r') capture_ordinal=('+option+r') observation_ordinal=('+option+r')',lines[0])
    ensure(match is not None,'closed-prerequisite-marker')
    known=match[1]=='true';evaluated,matched=int(match[2]),int(match[3])
    ordinal=lambda value: None if value=='None' else int(value[5:-1])
    captured,observed=ordinal(match[4]),ordinal(match[5])
    ensure(evaluated<=2047 and matched<=2047 and matched & ~evaluated==0 and evaluated & 3==3,'closed-evaluated-value-masks')
    ensure(all(value is None or 0<value<=18446744073709551615 for value in [captured,observed]),'positive-or-unknown-ordinals')
    if matched & 3==3:
        compared=evaluated>>2;values=matched>>2
        ensure(compared in [(1<<size)-1 for size in range(1,10)],'original-comparison-prefix')
        size=compared.bit_length()
        ensure(values==(1<<(size-1))-1 or size==9 and values==511,'original-short-circuit-values')
    else:ensure(evaluated==3,'no-comparisons-without-owned-pair')
    if known:
        ensure(observed is not None and (captured is not None)==bool(matched&1),'known-capture-presence-and-observation')
        ensure(captured is None or captured<observed,'capture-before-observation')
    return {'known':known,'evaluated_mask':evaluated,'matched_mask':matched,'capture_ordinal':captured,'observation_ordinal':observed,
        'comparisons':{meaning:(bool(matched&(1<<index)) if evaluated&(1<<index) else None) for index,meaning in enumerate(BIT_MEANINGS)},
        'matcher_result':(evaluated==matched==2047 if known else None),'exact_prefix_normalizations':normalized,'unevaluated_is_unknown':True}

def parser_controls():
    sample='body-prerequisite known=true evaluated=31 matched=15 capture_ordinal=Some(1) observation_ordinal=Some(2)'
    positives=[sample,'test '+NAME+' ... '+sample,sample.replace('evaluated=31 matched=15','evaluated=2047 matched=2047'),
        sample.replace('evaluated=31 matched=15 capture_ordinal=Some(1)','evaluated=3 matched=2 capture_ordinal=None'),
        sample.replace('known=true','known=false').replace('observation_ordinal=Some(2)','observation_ordinal=None')]
    for value in positives:diagnostic(value)
    bad=[sample+'\n'+sample,sample.replace('evaluated=31','evaluated=2048'),sample.replace('matched=15','matched=32'),
        sample.replace('matched=15','matched=31'),sample.replace('evaluated=31','evaluated=23'),sample.replace('matched=15','matched=11'),
        sample.replace('matched=15','matched=14'),sample.replace('capture_ordinal=Some(1)','capture_ordinal=None'),
        sample.replace('observation_ordinal=Some(2)','observation_ordinal=None'),sample.replace('Some(2)','Some(1)'),
        sample.replace('Some(1)','Some(0)'),sample.replace('known=true','known=unknown'),sample+' private=hidden',
        'test foreign::case ... '+sample,sample.replace('evaluated=31','evaluated=-1')]
    for value in bad:
        try:diagnostic(value)
        except (ValueError,bounded.GateFailure):continue
        raise ValueError('invalid-prerequisite-marker-accepted')
    return {'positive':len(positives),'negative':len(bad),'runtime_bodies':0,'shared_counts_inventory':shared.parser_controls(),
        'historical_negative_oracle_controls':rich.parser_preflight()}

def main(args):
    os.umask(0o077);OUT.mkdir(exist_ok=True)
    report={'scope':'one-original-current-thread-Body-prerequisite-diagnostic','diagnostic_completed':False,'journey_passed':False,
        'qualification':False,'native_acceptance':False,'promotion_eligible':False,'runtime_execution_attempted':False,
        'actual_counts_complete':False,'actual_passed':None,'actual_failed':None,'actual_ignored':None,'actual_executed_nonignored':None}
    frozen=None;binary=None;sha=None
    def save():(OUT/'result.json').write_text(json.dumps(report,indent=2)+'\n')
    try:
        report['source_guard']=source_guard();report['parser_controls']=parser_controls();save()
        if args.preflight:
            code,_,seconds=bounded.capture(['rustfmt','--edition','2024','--config','skip_children=true',*json.loads(Path(MANIFEST).read_text())['paths']],180,limit=1024*1024)
            patch=subprocess.check_output(['git','diff','--binary','--',*json.loads(Path(MANIFEST).read_text())['paths']]);(OUT/'formatting.patch').write_bytes(patch)
            report['format']={'exit_code':code,'seconds':seconds,'patch_bytes':len(patch),'sha256':bounded.digest(patch)};save()
            ensure(code==0 and not patch,'remote-format-feedback-required');report['preflight_passed']=True;save();return
        frozen=frozen_inputs();report['source_manifest_sha256']=bounded.digest(json.dumps(frozen,sort_keys=True).encode())
        compilation,cases=compile_cases([CASE])
        headers=compilation.pop('compiler_headers',[])
        codes=sorted(set(code for line in headers for code in re.findall(r'^error\[(E[0-9]{4})\]:',line)))
        locations=[];unknown_locations=0
        for line in headers:
            match=re.fullmatch(r'\s*--> (crates/[A-Za-z0-9_./-]+\.rs):([0-9]+):([0-9]+)',line)
            if match:
                if match[1] in frozen and 0<int(match[2])<=2147483647 and 0<int(match[3])<=2147483647:
                    locations.append({'path':match[1],'line':int(match[2]),'column':int(match[3])})
                else:unknown_locations+=1
            elif line.lstrip().startswith('--> '):unknown_locations+=1
        compilation.update(closed_error_codes=codes[:64],closed_source_locations=locations[:64],
            compiler_metadata_truncated=len(codes)>64 or len(locations)>64,unknown_source_locations=unknown_locations,
            missing_nextest_header_observed=any(line=="error: no such command: `nextest`" for line in headers))
        report['compilation']=compilation;save()
        ensure(compilation.get('compile_exit_code')==0 and compilation.get('compiler_error_count')==0
            and compilation.get('compiled_fingerprints',{}).get('verified') is True and set(cases)=={CASE},'sole-real-experimental-compile')
        report['feature_identity']=feature_identity(compilation);ensure(set(report['feature_identity']['nodes'])==NODES,'six-actual-feature-fingerprints')
        case=cases[CASE];ensure(case['name']==NAME,'exact-original-Body-fullname')
        binary=Path(case['binary']);sha=case['binary_sha256'];report['binary_sha256']=sha;save()
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
        # Preserve the exact existing negative-retention oracle; normalize only
        # the selected libtest prefix while retaining its test-name header.
        normalized=re.sub(r'(?m)^(test '+re.escape(NAME)+r' \.\.\. )(?=body-negative-control )',r'\1\n',raw)
        try:
            report['original_negative_control']=rich.parse(normalized)
            report['original_negative_control']['body_exit_code']=code
            report['journey_passed']=row['passed_gate'] and rich.green(report['original_negative_control'])
            report['original_negative_parser_rejected']=False
        except Exception as error:
            report['original_negative_parser_rejected']=True
            report['original_negative_parser_exception_type']=type(error).__name__
            report['original_negative_parser_rejection']='closed-original-negative-parser-rejected'
            report['journey_passed']=False
        save()
        report['diagnostic']=diagnostic(raw);save()
        ensure(row['actual_counts_complete'] and row['executed_nonignored']==1 and row['ignored']==0 and row['compiler_error_count']==0,'one-actual-original-runtime-body')
        ensure(report['diagnostic']['known'],'known-prerequisite-diagnostic-required')
        report['diagnostic_completed']=True;save()
        ensure(report['journey_passed'],'original-runtime-failure-or-negative-oracle-rejection-retained')
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
