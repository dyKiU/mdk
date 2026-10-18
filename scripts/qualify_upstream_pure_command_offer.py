#!/usr/bin/env python3
"""Fresh bounded-command offer component P/F/P only; all five real bodies required."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import stat
import subprocess
import sys
import tempfile
import time
import qualify_upstream_command_backlog_pair as pair
red=pair.red
ensure=red.ensure
BASE='c2bde1ed27f4bc14a0cc9ec86ba2580f67e383ee'  # Root pins the final pure product+App-pin commit; never the diagnostic overlay.
SELF='scripts/qualify_upstream_pure_command_offer.py'
PEER_SELF='scripts/qualify_upstream_pure_native5.py'
MANIFEST='scripts/pure_command_offer_source_manifest.json'
MANIFEST_SHA='c7d529d9b080d2069b7a617900e3745b55a5c857e80b24ef832eac10e9bfd974'  # Root pins the shared reviewed manifest after final formatting/source freeze.
WORKFLOW='.github/workflows/experimental-sync-ci.yml'
REF='refs/heads/ci/upstream-command-offer-pure-20261018'
OUT=Path('pure-command-offer-evidence')
ORIGINAL_FIELDS=red.FIELDS
HISTORICAL_RED='89326048c400e87671e2f66eb192547109265eae'
HELPERS={'scripts/qualify_upstream_command_backlog_red.py': {'sha256': '7581507845da9e588866d10cbbe59dee98a2dddd878212243c23111a0a47585d', 'mode': '100644', 'source': '89326048c400e87671e2f66eb192547109265eae'}, 'scripts/qualify_upstream_command_backlog_pair.py': {'sha256': '6e6600e422d4930b8c3ad9c9ce6e31bfe6910385335e2a0c32dfdd211dd7d9ec', 'mode': '100644', 'source': '89326048c400e87671e2f66eb192547109265eae'}}
OVERLAYS=[
    {'name':'offer','begin':'  # PURE_COMMAND_OFFER_JOBS_BEGIN\n','end':'  # PURE_COMMAND_OFFER_JOBS_END\n',
     'options':'options: [pure-command-offer-preflight, pure-command-offer-pfp, '},
    {'name':'native5','begin':'  # PURE_NATIVE5_JOBS_BEGIN\n','end':'  # PURE_NATIVE5_JOBS_END\n',
     'options':'options: [pure-native5-preflight, pure-native5-green, '},
]


def strip_owned_workflow(data, required):
    text=data.decode()
    present=[(text.count(item['begin']),text.count(item['end'])) for item in OVERLAYS]
    if not required and all(row==(0,0) for row in present):
        ensure(all(item['options'] not in text for item in OVERLAYS),'no-unowned-option-prefix-without-blocks')
        return data
    ensure(all(row==(1,1) for row in present),'exact-complete-owned-workflow-union')
    for overlay in OVERLAYS:
        before,rest=text.split(overlay['begin']);_,after=rest.split(overlay['end']);text=before+after
    for overlay in OVERLAYS:
        ensure(text.count(overlay['options'])==1,'exact-owned-option-prefix-order')
        text=text.replace(overlay['options'],'options: [',1)
    return text.encode()


def workflow_metadata_controls():
    # Synthetic metadata only: no source reads, builds, protocol bodies or RED claim.
    bare='name: synthetic\noptions: [legacy]\njobs:\n'
    full=bare
    for overlay in reversed(OVERLAYS):full=full.replace('options: [',overlay['options'],1)
    blocks=[item['begin']+'  owned_'+item['name']+': synthetic\n'+item['end'] for item in OVERLAYS]
    full+=''.join(blocks)
    ensure(strip_owned_workflow(bare.encode(),False)==bare.encode(),'workflow-optional-absent-positive')
    ensure(strip_owned_workflow(full.encode(),True)==bare.encode(),'workflow-current-complete-positive')
    ensure(strip_owned_workflow(full.encode(),False)==bare.encode(),'workflow-BASE-complete-positive')
    bad=[(bare,True),
        (full.replace(blocks[0],'',1),False),
        (full+blocks[0],True),
        (full.replace(OVERLAYS[1]['end'],'',1),True),
        (full.replace(OVERLAYS[0]['options']+'pure-native5-preflight, pure-native5-green, ',
            OVERLAYS[1]['options']+'pure-command-offer-preflight, pure-command-offer-pfp, ',1),True),
        (full.replace(''.join(blocks),'',1),False),
        (full.replace(OVERLAYS[0]['options'],'options: [',1),True),
        (full.replace(OVERLAYS[0]['options'],OVERLAYS[0]['options']+'pure-command-offer-preflight, pure-command-offer-pfp, ',1),True)]
    for candidate,required in bad:
        rejected=False
        try:strip_owned_workflow(candidate.encode(),required)
        except ValueError:rejected=True
        ensure(rejected,'malformed-owned-workflow-union-rejected')
    changed_owned=full.replace('owned_offer: synthetic','owned_offer: reviewed-change',1)
    ensure(strip_owned_workflow(changed_owned.encode(),True)==bare.encode(),'only-declared-owned-body-removed')
    foreign=full.replace('name: synthetic','name: foreign',1)
    expected_foreign=bare.replace('name: synthetic','name: foreign',1).encode()
    normalized=strip_owned_workflow(foreign.encode(),True)
    ensure(normalized==expected_foreign and normalized!=strip_owned_workflow(bare.encode(),False),'foreign-outside-bytes-survive-and-mismatch')
    return {'synthetic_metadata_positive':3,'malformed_union_negative':len(bad),
        'owned_body_normalized':1,'foreign_outside_comparison_mismatch':1,'actual_runtime_bodies':0}


def source_guard():
    ensure(isinstance(BASE,str) and re.fullmatch('[0-9a-f]{40}',BASE),'final-pure-BASE-pin-required')
    ensure(isinstance(MANIFEST_SHA,str) and re.fullmatch('[0-9a-f]{64}',MANIFEST_SHA),'final-shared-manifest-pin-required')
    head=subprocess.check_output(['git','rev-parse','HEAD'],text=True).strip()
    ensure(os.environ.get('GITHUB_ACTIONS')=='true' and os.environ.get('GITHUB_REPOSITORY')=='dyKiU/mdk'
        and os.environ.get('GITHUB_EVENT_NAME')=='workflow_dispatch' and os.environ.get('GITHUB_SHA')==head
        and os.environ.get('GITHUB_REF')==REF and os.environ.get('GITHUB_WORKFLOW_REF')=='dyKiU/mdk/'+WORKFLOW+'@'+REF
        and os.environ.get('UPSTREAM_PURE_QUALIFICATION_BASELINE')==BASE,'exact-pure-owned-source-and-workflow')
    ensure(os.environ.get('CARGO_BUILD_JOBS')=='2' and os.environ.get('CARGO_INCREMENTAL')=='1'
        and os.environ.get('RUST_MIN_STACK')=='4194304'
        and all(os.environ.get(k)=='0' for k in ['CARGO_PROFILE_DEV_DEBUG','CARGO_PROFILE_TEST_DEBUG'])
        and all(not os.environ.get(k) for k in ['RUSTFLAGS','CARGO_ENCODED_RUSTFLAGS','RUSTC_BOOTSTRAP',
            'CARGO_PROFILE_DEV_OPT_LEVEL','CARGO_PROFILE_TEST_OPT_LEVEL']),'unchanged-two-worker-four-MiB-cohort')
    subprocess.run(['git','merge-base','--is-ancestor',BASE,head],check=True)
    ensure(subprocess.run(['git','diff','--quiet','HEAD']).returncode==0,'initial-whole-GitHEAD-pristine')
    ensure(red.digest(Path(MANIFEST).read_bytes())==MANIFEST_SHA,'exact-shared-reviewed-manifest')
    manifest=json.loads(Path(MANIFEST).read_text())
    ensure(manifest['baseline']==BASE and manifest['helpers']==HELPERS
        and manifest['owned_metadata']==[SELF,PEER_SELF,MANIFEST]
        and manifest['workflow_overlays']==OVERLAYS,'exact-declared-metadata-union')
    prior=manifest.get('reviewed_paired_RED_control')
    ensure(isinstance(prior,dict) and prior.get('source')==HISTORICAL_RED and prior.get('paired_red_control_verified') is True
        and isinstance(prior.get('run_id'),str) and prior['run_id'].isdigit()
        and isinstance(prior.get('artifact_sha256'),str) and re.fullmatch('[0-9a-f]{64}',prior['artifact_sha256'])
        and all(type(prior.get(k)) is int and prior[k]==v for k,v in {'actual_passed':1,'actual_failed':1,'actual_ignored':0,'actual_executed_nonignored':2}.items()),'reviewed-historical-genuine-RED-control-pin-required')
    baseline={}
    for item in subprocess.check_output(['git','ls-tree','-r','-z',BASE]).split(b'\0'):
        if item:
            meta,name=item.split(b'\t',1);mode,kind,blob=meta.decode().split()
            ensure(kind=='blob' and mode in {'100644','100755','120000'},'ordinary-pure-baseline')
            baseline[os.fsdecode(name)]=(mode,blob)
    owned_metadata={SELF,PEER_SELF,MANIFEST}
    declared=owned_metadata|set(HELPERS)
    current=red.layout()
    ensure(set(current)==set(baseline)|declared,'exact-whole-pure-inventory-and-owned-metadata-union')
    product=manifest['product']
    ensure(product['path']=='crates/marmot-app/src/runtime/account_worker.rs' and product['git_mode']=='100644'
        and len(product['edits'])==3,'exact-three-production-insertions-witness')
    for name,meta in current.items():
        mode,blob=baseline.get(name,('100644',None))
        if name in declared:ensure(mode=='100644','owned-metadata-and-helper-normal-file-mode')
        ensure(meta['git_mode']==mode and meta['symlink']==(mode=='120000')
            and (meta['symlink'] or meta['actual_executable']==(mode=='100755')),'whole-modes-and-executability')
        data=os.fsencode(os.readlink(name)) if meta['symlink'] else Path(name).read_bytes()
        if name in HELPERS:ensure(red.digest(data)==HELPERS[name]['sha256'],'exact-immutable-original-helper:'+name)
        if name==product['path']:
            ensure(mode=='100644' and red.digest(data)==product['after_sha256'],'exact-candidate-worker-witness')
            witness=data.decode()
            for edit in reversed(product['edits']):
                ensure(witness.count(edit['after'])==1,'unique-exact-counterfactual-insertion')
                witness=witness.replace(edit['after'],edit['before'],1)
            ensure(red.digest(witness.encode())==product['before_sha256'],'exact-worker-omission-witness')
            # Do not replace data: the candidate Rust MUST match BASE byte-for-byte.
        if name in owned_metadata:
            # These three reviewed metadata files may already exist in BASE.
            # SELF bytes are bound by signed/pristine GitHEAD==GITHUB_SHA; the
            # manifest additionally has its explicit non-circular SHA pin above.
            continue
        if name==WORKFLOW:
            ensure(blob is not None,'baseline-workflow-required')
            expected=subprocess.check_output(['git','cat-file','blob',blob])
            ensure(strip_owned_workflow(data,True)==strip_owned_workflow(expected,False),'exact-workflow-outside-owned-union')
            continue
        if blob is not None:
            ensure(hashlib.sha1(b'blob '+str(len(data)).encode()+b'\0'+data).hexdigest()==blob,'whole-pure-content-no-Rust-exceptions:'+name)
    allowed={'pure-command-offer-evidence/result.json','pure-native5-evidence/result.json'}
    ensure(set(subprocess.check_output(['git','ls-files','--others','--exclude-standard'],text=True).splitlines())<=allowed,'no-untracked-source-overlay')
    return manifest,{'source':head,'baseline':BASE,'whole_source_modes_reconstructed':True,'no_Rust_exceptions':True,
        'owned_metadata_union':[SELF,PEER_SELF,MANIFEST],'baseline_owned_metadata_present':sorted(owned_metadata.intersection(baseline)),'metadata_controllers_commit_bound_by_GITHUB_SHA_and_pristine_HEAD':True,
        'helper_guards_called':False,'reviewed_prior_control_pins':prior,'prior_control_verified_by_this_controller':False,
        'runtime_evidence_reused':False,'native_qualification_is_separate':True}


def extract_ingress(raw):
    ensure(len(raw.encode())<=8*1024*1024,'ingress-bounded-input')
    clean=re.sub(r'\x1b\[[0-9;]*m','',raw)
    lines=[line for line in clean.splitlines() if line.startswith('command-backlog-ingress')]
    ensure(len(lines)==1 and len(lines[0].encode())<1024,'one-closed-ingress-marker')
    pattern=(r'command-backlog-ingress schedule=(None|Some\(\(\[(true|false), (true|false), (true|false), (true|false)\], '
             r'([01]), (0|[1-9][0-9]?), (0|[1-9][0-9]?), (true|false)\)\))')
    match=re.fullmatch(pattern,lines[0]);ensure(match is not None,'closed-ingress-schedule')
    schedule=None
    if match[1]!='None':
        held,replayed=int(match[7]),int(match[8]);ensure(held<=32 and replayed<=held,'ingress-bounded-held-replayed')
        schedule={'armed':match[2]=='true','valid':match[3]=='true','released':match[4]=='true','flushed':match[5]=='true',
            'target_passes':int(match[6]),'held':held,'replayed':replayed,'overflow':match[9]=='true'}
    row={'schema_complete':True,'schedule':schedule,'controlled_test_arrivals_not_production_FIFO_evidence':True,
        'missing_schedule_is_unknown_not_no_arrival':True,'IDs_or_payloads_exported':False}
    filtered=''.join(line for line in clean.splitlines(keepends=True) if line.rstrip('\r\n')!=lines[0])
    return filtered,row


def ingress_gate(row):
    schedule=row.get('schedule')
    return (row.get('schema_complete') is True and isinstance(schedule,dict)
        and all(schedule.get(key) is True for key in ['armed','valid','released','flushed'])
        and type(schedule.get('target_passes')) is int and schedule['target_passes']==1
        and all(type(schedule.get(key)) is int and 0<=schedule[key]<=32 for key in ['held','replayed'])
        and schedule['held']==schedule['replayed'] and schedule.get('overflow') is False)


def ingress_parser_controls():
    marker='command-backlog-ingress schedule=Some(([true, true, true, true], 1, 2, 2, false))'
    raw='command-backlog facts=UNCHANGED\n'+marker+'\ncommand-backlog-queue UNCHANGED\n'
    filtered,row=extract_ingress(raw)
    ensure(ingress_gate(row) and filtered=='command-backlog facts=UNCHANGED\ncommand-backlog-queue UNCHANGED\n','ingress-only-validated-line-removed')
    for value in [0,32]:
        ensure(ingress_gate(extract_ingress(marker.replace(', 2, 2,',', '+str(value)+', '+str(value)+','))[1]),'ingress-real-bounded-replay-positive')
    unknown=extract_ingress('command-backlog-ingress schedule=None')[1]
    ensure(unknown['schema_complete'] and unknown['schedule'] is None and not ingress_gate(unknown),'unknown-schedule-retained-not-qualified')
    negatives=0
    for key in ['armed','valid','released','flushed']:
        altered={**row,'schedule':{**row['schedule'],key:False}};ensure(not ingress_gate(altered),'ingress-prerequisite-required');negatives+=1
    for delta in [{'target_passes':True},{'target_passes':0},{'held':True},{'replayed':False},{'held':33},
                  {'replayed':1},{'overflow':True}]:
        ensure(not ingress_gate({**row,'schedule':{**row['schedule'],**delta}}),'ingress-invalid-setup-not-qualified');negatives+=1
    # Typed setup failures are useful observations, not schema failures or product RED.
    partial=extract_ingress(marker.replace('[true, true, true, true]','[true, false, true, false]').replace(', false))',', true))'))[1]
    ensure(partial['schema_complete'] and not ingress_gate(partial),'ingress-partial-failure-preserved')
    for bad in ['',marker+'\n'+marker,marker+' private=PAYLOAD',marker.replace(', 1, 2, 2,',', 2, 2, 2,'),
                marker.replace(', 1, 2, 2,',', 1, 33, 2,'),marker.replace(', 1, 2, 2,',', 1, 1, 2,'),
                marker.replace(', 1, 2, 2,',', 1, 02, 2,'),marker.replace('true, true, true, true','1, true, true, true'),
                marker.replace(', 1, 2, 2,',', 1, -1, 2,')]:
        try:extract_ingress(bad)
        except ValueError:negatives+=1;continue
        raise ValueError('ingress-malformed-marker-accepted')
    return {'positive':3,'typed_unknown_or_setup_failure_controls':2,'negative':negatives,'actual_runtime_bodies':0}


def original_green(row):
    return (all(type(row.get(k)) is int and row[k]==v for k,v in {'body_exit_code':0,'passed':1,'failed':0,'ignored':0,
        'executed_nonignored':1,'compiler_error_count':0,'all_panic_header_count':0,'marker_header_count':1,
        'runtime_closes':3,'plane_shutdown_returns':3}.items())
        and row.get('running_counts')==[1] and row.get('executed_case_names')==[red.NAME]
        and all(row.get('facts',{}).get(k) is True for k in ORIGINAL_FIELDS)
        and type(row.get('completed_before')) is int and 0<=row['completed_before']<=1
        and row.get('relay_closed') is True and row.get('attempt_completed') is True
        and not row.get('watchdog_triggered') and not row.get('actual_count_unknown'))


def totals(phases):
    bodies=[case.get('body',{}) for phase in phases for case in phase.get('cases',[])]
    fields=['passed','failed','ignored','executed_nonignored']
    return {'actual_'+key:sum(row[key] for row in bodies) if len(bodies)==5 and all(type(row.get(key)) is int for row in bodies) else None for key in fields} | {
        'known_partial_counts':{key:sum(row[key] for row in bodies if type(row.get(key)) is int) for key in fields},
        'unknown_count_cases':5-sum(all(type(row.get(key)) is int for key in fields) for row in bodies)}


def parser_controls():
    workflow_controls=workflow_metadata_controls()
    ingress_controls=ingress_parser_controls()
    inherited=pair.parser_controls()
    marker='command-backlog facts=['+', '.join(['true']*13)+'] completed_before=Some(1) runtime_closes=3 plane_shutdown_returns=3 relay_closed=true attempt_completed=true'
    raw='running 1 test\ntest '+red.NAME+' ... ok\n'+marker+'\ntest result: ok. 1 passed; 0 failed; 0 ignored;\n'
    row=red.parse(raw,0);ensure(original_green(row),'fresh-original-GREEN-positive')
    ensure(original_green(red.parse(raw.replace(' ... ok\n'+marker,' ... '+marker),0)),'original-shared-prefix-positive')
    negatives=0
    for delta in [{'passed':True},{'failed':False},{'ignored':False},{'body_exit_code':False},{'completed_before':True},
        {'completed_before':2},{'completed_before':None},{'passed':0},{'failed':1},{'ignored':1},{'executed_nonignored':0},
        {'compiler_error_count':1},{'all_panic_header_count':1},{'running_counts':[0]},{'executed_case_names':[red.NAME,red.NAME]},
        {'runtime_closes':2},{'plane_shutdown_returns':2},{'relay_closed':False},{'attempt_completed':False},{'watchdog_triggered':True}]:
        ensure(not original_green(dict(row,**delta)),'non-GREEN-original-rejected');negatives+=1
    for field in ORIGINAL_FIELDS:
        ensure(not original_green(dict(row,facts=dict(row['facts'],**{field:False}))),'all-thirteen-original-facts-required');negatives+=1
    return {'workflow_metadata_controls':workflow_controls,'ingress_controls':ingress_controls,'historical_pair_controls':inherited,'original_GREEN_positive':2,'original_GREEN_negative':negatives,'runtime_bodies':0}


def write_fresh(path,data,mode):
    ensure(not path.is_symlink() and (not path.exists() or path.is_file()),'owned-source-path-before-write')
    previous=path.stat().st_mtime_ns if path.is_file() else 0
    path.write_bytes(data);os.chmod(path,mode)
    # Never copy old mtimes. Force this content to be newer than its predecessor
    # even if the runner clock has equal timestamp resolution.
    now=max(time.time_ns(),previous+1)
    os.utime(path,ns=(now,now))


def run_phase(label,expected,modes,expected_cases,save,report):
    phase={'label':label,'cases':[],'phase_verified':False};report['phases'].append(phase);save()
    try:
        ensure(red.freeze()==expected and red.layout()==modes,'phase-source-and-modes-before-compile')
        compilation,cases=red.compile_cases([red.CASE,pair.COUNTER_CASE])
        headers=compilation.pop('compiler_headers',[])
        compilation['compiler_codes']=sorted(set(re.findall(r'error\[(E[0-9]{4})\]','\n'.join(headers))))
        compilation['compiler_sites']=[{'file':p,'line':int(n),'column':int(c)} for p,n,c in re.findall(r'--> (crates/[A-Za-z0-9_./-]+\.rs):([0-9]+):([0-9]+)','\n'.join(headers))]
        phase['compilation']=compilation;save()
        ensure(compilation.get('compile_exit_code')==compilation.get('compiler_error_count')==0
            and compilation.get('compiled_fingerprints',{}).get('verified') is True
            and set(cases)=={red.CASE,pair.COUNTER_CASE} and cases[red.CASE]['name']==red.NAME
            and cases[pair.COUNTER_CASE]['name']==pair.COUNTER_NAME
            and cases[red.CASE]['binary_sha256']==cases[pair.COUNTER_CASE]['binary_sha256'],'same-two-case-inventory-and-six-features')
        phase['feature_identity']=red.feature_identity(compilation)
        phase['source_manifest_sha256']=red.identity(expected);phase['binary_sha256']=cases[red.CASE]['binary_sha256']
        phase['binary_path']=cases[red.CASE]['binary'];save()
        for suffix in expected_cases:
            name=red.NAME if suffix==red.CASE else pair.COUNTER_NAME
            case_row={'name':name,'runtime_started':False};phase['cases'].append(case_row)
            try:
                ensure(red.freeze()==expected and red.layout()==modes and red.digest(Path(phase['binary_path']).read_bytes())==phase['binary_sha256'],'before-case-source-binary-pristine')
                case_row['runtime_started']=True;save()
                code,raw,seconds=red.bounded.capture([phase['binary_path'],'--exact',name,'--nocapture','--test-threads=1'],300,limit=4*1024*1024)
                case_row['body']=dict(red.parse_body(raw,suffix),body_exit_code=code,seconds=seconds,
                    compiler_error_count=len(re.findall(r'^error(?:\[E[0-9]+\])?:',raw,re.M)));save()
                case_row['post_body_binary_sha256']=red.digest(Path(phase['binary_path']).read_bytes())
                case_row['post_body_binary_pristine']=case_row['post_body_binary_sha256']==phase['binary_sha256'];save()
                ensure(case_row['post_body_binary_pristine'],'actual-post-body-binary-pristine')
                filtered,case_row['ingress_observation']=extract_ingress(raw);save()
                filtered,case_row['queue_observation']=pair.extract_queue(filtered);save()
                parser=red.parse if suffix==red.CASE else pair.parse_counter
                case_row['body']=dict(parser(filtered,code),seconds=seconds)
                gate=red.intended_red if label=='mutant' else (original_green if suffix==red.CASE else pair.counter_green)
                case_row['expected_outcome_verified']=(gate(case_row['body']) and pair.queue_gate(case_row['queue_observation'],suffix==red.CASE)
                    and ingress_gate(case_row['ingress_observation']))
            except red.bounded.GateFailure as error:
                case_row['watchdog_triggered']=str(error)=='bounded-command-timeout';case_row['output_limit_triggered']=str(error)=='bounded-command-output-limit'
                case_row['actual_count_unknown']=True;case_row['exception_type']=type(error).__name__
            except Exception as error:case_row['exception_type']=type(error).__name__
            finally:
                case_row['source_after_sha256']=red.identity(red.freeze())
                case_row['mode_layout_after_sha256']=red.digest(json.dumps(red.layout(),sort_keys=True).encode())
                case_row['final_binary_sha256']=red.digest(Path(phase['binary_path']).read_bytes()) if Path(phase['binary_path']).is_file() else None
                case_row['inputs_pristine']=red.freeze()==expected and red.layout()==modes
                if not case_row['inputs_pristine'] or case_row['final_binary_sha256']!=phase['binary_sha256']:case_row['expected_outcome_verified']=False
                report.update(totals(report['phases']));save()
        phase['phase_verified']=len(phase['cases'])==len(expected_cases) and all(row.get('expected_outcome_verified') is True for row in phase['cases'])
    except Exception as error:phase['exception_type']=type(error).__name__
    finally:
        phase['inputs_pristine']=red.freeze()==expected and red.layout()==modes
        phase['final_binary_sha256']=red.digest(Path(phase['binary_path']).read_bytes()) if phase.get('binary_path') and Path(phase['binary_path']).is_file() else None
        phase['binary_pristine']=phase['final_binary_sha256'] is not None and phase['final_binary_sha256']==phase.get('binary_sha256')
        if not phase['inputs_pristine'] or not phase['binary_pristine']:phase['phase_verified']=False
        save()
    return phase


def main(options):
    os.umask(0o077);OUT.mkdir(exist_ok=True)
    report={'component_PFP_verified':False,'qualification_passed':False,'default_qualified':False,'native_qualified':False,
        'full_enrollment_qualified':False,'original_native_gates_waived':False,'phases':[],'automatic_retries':0,
        'expected_actual_bodies':5,'expected_passed':4,'expected_intended_failed':1}
    report.update(totals([]));before=modes=None;product=None;candidate_bytes=None;candidate_mode=None
    backup_dir=None;backup_path=None;baseline_binary=None;baseline_binary_sha=None;baseline_binary_mode=None
    def save(): (OUT/'result.json').write_text(json.dumps(report,indent=2)+'\n')
    try:
        manifest,report['source_guard']=source_guard();report['parser_controls']=parser_controls();save()
        if options.preflight:report['preflight_passed']=True;save();return
        report['environment']=red.environment();before,modes=red.freeze(),red.layout()
        product=Path(manifest['product']['path']);candidate_bytes=product.read_bytes();candidate_mode=stat.S_IMODE(product.stat().st_mode)
        old=candidate_bytes.decode()
        for edit in reversed(manifest['product']['edits']):
            ensure(old.count(edit['after'])==1,'unique-exact-product-omission');old=old.replace(edit['after'],edit['before'],1)
        old_bytes=old.encode();ensure(red.digest(old_bytes)==manifest['product']['before_sha256'],'mutant-exact-pure-worker-without-three-inserts')
        baseline=run_phase('baseline',before,modes,[red.CASE,pair.COUNTER_CASE],save,report)
        ensure(baseline['phase_verified'],'fresh-two-body-GREEN-before-mutation')
        baseline_binary=Path(baseline['binary_path']);baseline_binary_sha=baseline['binary_sha256']
        baseline_binary_mode=stat.S_IMODE(baseline_binary.stat().st_mode)
        ensure(0<baseline_binary.stat().st_size<=512*1024*1024,'bounded-baseline-binary-backup')
        backup_dir=tempfile.TemporaryDirectory(prefix='command-offer-binary-',dir=os.environ.get('RUNNER_TEMP'))
        backup_path=Path(backup_dir.name)/'baseline-binary';shutil.copyfile(baseline_binary,backup_path)
        ensure(red.digest(backup_path.read_bytes())==baseline_binary_sha,'exact-baseline-backup')
        try:
            write_fresh(product,old_bytes,candidate_mode)
            mutant_expected=red.freeze()
            ensure(red.layout()==modes and product.read_bytes()==old_bytes and set(mutant_expected)==set(before)
                and {name for name in before if mutant_expected[name]!=before[name]}=={str(product)},'exact-worker-only-composite-input-change')
            report['mutant_diff']={'path':str(product),'before_sha256':red.digest(candidate_bytes),'after_sha256':red.digest(old_bytes),
                'exact_three_insertions_omitted':True,'exact_pure_candidate_offer_omission':True};save()
            mutant=run_phase('mutant',mutant_expected,modes,[red.CASE],save,report)
        finally:
            write_fresh(product,candidate_bytes,candidate_mode)
            restored=run_phase('restored',before,modes,[red.CASE,pair.COUNTER_CASE],save,report)
        report['same_feature_identity']=baseline.get('feature_identity')==mutant.get('feature_identity')==restored.get('feature_identity')
        report['baseline_restored_binary_equal']=baseline.get('binary_sha256')==restored.get('binary_sha256')
        report['mutant_binary_differs']=mutant.get('binary_sha256') is not None and mutant['binary_sha256']!=baseline['binary_sha256']
        report['component_PFP_verified']=(all(phase.get('phase_verified') is True for phase in [baseline,mutant,restored])
            and report['same_feature_identity'] and report['baseline_restored_binary_equal'] and report['mutant_binary_differs']
            and all(type(report.get(k)) is int and report[k]==v for k,v in {'actual_passed':4,'actual_failed':1,'actual_ignored':0,'actual_executed_nonignored':5}.items()))
        save();ensure(report['component_PFP_verified'],'all-five-runtime-bodies-and-exact-restoration-required')
    except Exception as error:report['exception_type']=type(error).__name__;raise
    finally:
        exception_in_flight=sys.exc_info()[0] is not None
        if before is not None:
            try:
                if product is not None and candidate_bytes is not None:
                    if product.is_symlink(): product.unlink()
                    ensure(not product.exists() or product.is_file(),'owned-source-restoration-path')
                    if not product.is_file() or product.read_bytes()!=candidate_bytes or stat.S_IMODE(product.stat().st_mode)!=candidate_mode:
                        write_fresh(product,candidate_bytes,candidate_mode)
            except Exception as error:
                report['source_restoration_exception_type']=type(error).__name__;report['component_PFP_verified']=False
            try:
                source_after,layout_after=red.freeze(),red.layout()
                report['source_after_sha256']=red.identity(source_after)
                report['mode_layout_after_sha256']=red.digest(json.dumps(layout_after,sort_keys=True).encode())
                report['inputs_pristine']=source_after==before and layout_after==modes
            except Exception as error:
                report['inputs_pristine']=False;report['source_snapshot_exception_type']=type(error).__name__
            if baseline_binary is not None and baseline_binary_sha is not None:
                report['binary_fallback_restoration_used']=False;report['binary_restored']=False
                try:
                    regular=baseline_binary.is_file() and not baseline_binary.is_symlink()
                    matches=regular and red.digest(baseline_binary.read_bytes())==baseline_binary_sha and stat.S_IMODE(baseline_binary.stat().st_mode)==baseline_binary_mode
                    if not matches and backup_path is not None:
                        if baseline_binary.is_symlink():baseline_binary.unlink()
                        ensure(not baseline_binary.exists() or baseline_binary.is_file(),'owned-binary-restoration-path')
                        shutil.copyfile(backup_path,baseline_binary);os.chmod(baseline_binary,baseline_binary_mode)
                        report['binary_fallback_restoration_used']=True
                    regular=baseline_binary.is_file() and not baseline_binary.is_symlink()
                    report['final_binary_sha256']=red.digest(baseline_binary.read_bytes()) if regular else None
                    report['binary_restored']=regular and report['final_binary_sha256']==baseline_binary_sha and stat.S_IMODE(baseline_binary.stat().st_mode)==baseline_binary_mode
                except Exception as error:report['binary_restoration_exception_type']=type(error).__name__
                if report['binary_fallback_restoration_used'] or not report['binary_restored']:report['component_PFP_verified']=False
            if not report['inputs_pristine']:report['component_PFP_verified']=False
        if backup_dir is not None:
            try:backup_dir.cleanup();report['binary_backup_removed']=True
            except Exception as error:
                report['binary_backup_removed']=False;report['backup_cleanup_exception_type']=type(error).__name__;report['component_PFP_verified']=False
        report.update(totals(report['phases']));save()
        if before is not None and not exception_in_flight:
            ensure(report['inputs_pristine'],'finally-source-modes-pristine')
            ensure(report['component_PFP_verified'],'finally-full-component-PFP-and-binary-restoration-required')

if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--preflight',action='store_true');main(parser.parse_args())
