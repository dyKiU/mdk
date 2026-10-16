#!/usr/bin/env python3
"""One genuine fixture; optional force-renew omission with exact restored control."""
import io
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import time
import zipfile
from upstream_completion_ci import ensure, environment, freeze as content_freeze, identity, compile_cases, digest
from upstream_body_negative_ci import BASE, CASE, PRODUCT, ANCHOR, MUTANT, parse, green, intended_red
OUT=Path('body-negative-evidence')
def layout():
    rows={}
    for entry in subprocess.check_output(['git','ls-files','--stage','-z']).split(b'\0'):
        if not entry:continue
        metadata,path=entry.split(b'\t',1);mode,_,stage=metadata.decode().split();name=os.fsdecode(path)
        ensure(stage=='0' and mode in {'100644','100755','120000'},'ordinary-tracked-source-layout')
        file=Path(name);kind=file.lstat().st_mode
        ensure(stat.S_ISREG(kind) or stat.S_ISLNK(kind),'ordinary-source-file-or-symlink')
        rows[name]={'git_mode':mode,'actual_executable':bool(kind & 0o111),'symlink':file.is_symlink(),'symlink_target':os.readlink(file) if file.is_symlink() else None}
        ensure((mode=='120000')==rows[name]['symlink'],'source-link-type-mismatch')
    return rows
def freeze():
    contents=content_freeze();metadata=layout();ensure(set(contents)==set(metadata),'source-inventory-layout')
    return {name:digest(json.dumps({'content_sha256':value,**metadata[name]},sort_keys=True).encode()) for name,value in contents.items()}
def feature_identity(compilation):
    fingerprints=compilation.get('compiled_fingerprints',{});ensure(fingerprints.get('verified'),'verified-compiled-features-required')
    return {'requested':compilation['features_requested'],'command':compilation['command'],'nodes':{name:{key:node[key] for key in ['features','profile','compile_kind','rustflags_sha256']} for name,node in fingerprints['nodes'].items()}}
def previous_control(run_id,source):
    ensure(run_id.isdigit(),'prior-control-run-required')
    repo=os.environ['GITHUB_REPOSITORY']
    def api(path): return subprocess.check_output(['gh','api','repos/'+repo+'/'+path],timeout=30)
    run=json.loads(api('actions/runs/'+run_id))
    ensure(run['head_sha']==source and run['conclusion']=='success' and run['event']=='workflow_dispatch' and run['path']=='.github/workflows/experimental-sync-ci.yml','prior-control-run-identity')
    artifacts=json.loads(api('actions/runs/'+run_id+'/artifacts'))['artifacts']
    matches=[row for row in artifacts if row['name']=='body-negative-control' and not row['expired']]
    ensure(len(matches)==1 and 0<matches[0]['size_in_bytes']<500_000,'prior-control-artifact')
    data=api('actions/artifacts/'+str(matches[0]['id'])+'/zip');ensure(len(data)<500_000,'bounded-prior-artifact')
    expected_digest=matches[0].get('digest');ensure(isinstance(expected_digest,str) and re.fullmatch(r'sha256:[0-9a-f]{64}',expected_digest) and expected_digest=='sha256:'+digest(data),'actual-prior-artifact-digest')
    ensure(len(data)==matches[0]['size_in_bytes'],'actual-prior-artifact-size')
    with zipfile.ZipFile(io.BytesIO(data)) as archive:
        files=[name for name in archive.namelist() if name.endswith('result.json')]
        ensure(len(files)==1 and archive.getinfo(files[0]).file_size<500_000,'bounded-prior-result')
        prior=json.loads(archive.read(files[0]))
    ensure(prior['source']==source and prior['mode']=='control' and prior['inputs_pristine'] and prior['component_control_passed'] and green(prior['baseline']['body']),'prior-real-control-not-green')
    prior_features=feature_identity(prior['baseline']['compilation'])
    return {'run_id':int(run_id),'artifact_id':matches[0]['id'],'api_digest':expected_digest,'api_size_bytes':matches[0]['size_in_bytes'],'download_sha256':digest(data),'download_bytes':len(data),'source':source,'compiled_feature_identity':prior_features,'toolchain':prior['toolchain'],'environment':prior['environment']}

def main():
    OUT.mkdir(exist_ok=True);report=environment();report.update(mode=os.environ.get('BODY_NEGATIVE_MODE','control'),fixture_baseline=BASE,qualification_passed=False,component_control_passed=False,mutation_chain_passed=False,scope='Real two-device bilateral pairing/history; NEW-chat pre-publication Catalog Body versus OLD mirrored-chat authenticated negative on SAME channel. Persistent SQL trigger until removed. Aborted pre-publication gate release is NOT late ACK; different chat IDs are NOT same-chat withdrawal. Original three enrollment failures and final qualification remain pending.')
    original=freeze();original_layout=layout();original_bytes=Path(PRODUCT).read_bytes();report['source_before_sha256']=identity(original)
    report['source_layout_before_sha256']=digest(json.dumps(original_layout,sort_keys=True).encode())
    def save(): (OUT/'result.json').write_text(json.dumps(report,indent=2)+'\n')
    def phase(label,expected):
        result={};report[label]=result;save()
        compilation,cases=compile_cases([CASE]);result['compilation']=compilation;save()
        ensure(compilation.get('compile_exit_code')==0 and compilation.get('compiler_error_count')==0 and compilation.get('compiled_fingerprints',{}).get('verified') and len(cases)==1,'compile-or-sole-inventory-unqualified')
        ensure(freeze()==expected,'compile-phase-source-drift')
        result['compiled_feature_identity']=feature_identity(compilation)
        prior=report.get('prior_control')
        if prior:ensure(result['compiled_feature_identity']==prior['compiled_feature_identity'] and report['toolchain']==prior['toolchain'] and report['environment']==prior['environment'],'actual-compiled-feature-cohort-differs-from-prior-control')
        if label!='baseline':ensure(result['compiled_feature_identity']==report['baseline']['compiled_feature_identity'],'phase-compiled-feature-cohort-drift')
        case=cases[CASE];row={'test':case['name'],'binary_sha256':case['binary_sha256']};result['body']=row;start=time.monotonic();raw=''
        try:
            body=subprocess.run([case['binary'],'--exact',case['name'],'--nocapture','--test-threads=1'],capture_output=True,text=True,timeout=240)
            row['body_exit_code']=body.returncode;raw=body.stdout+body.stderr
        except subprocess.TimeoutExpired as error:
            def text(value):return value.decode(errors='replace') if isinstance(value,bytes) else value or ''
            raw=text(error.stdout)+text(error.stderr);row.update(watchdog_triggered=True,actual_count_unknown=True)
        row['body_seconds']=time.monotonic()-start;save()
        row.update(parse(raw));result['source_pristine']=freeze()==expected;save()
        ensure(row.get('executed_case_names')==[case['name']],'actual-sole-case-identity')
        ensure(result['source_pristine'],'runtime-phase-source-drift')
        return row
    save()
    try:
        ensure(report['mode'] in {'control','mutation'},'known-mode')
        if report['mode']=='mutation':report['prior_control']=previous_control(os.environ.get('BODY_NEGATIVE_CONTROL_RUN',''),report['source']);save()
        baseline=phase('baseline',original);ensure(green(baseline),'actual-baseline-not-green')
        report['component_control_passed']=True;save()
        if report['mode']=='mutation':
            mutation_error=None
            try:
                text=original_bytes.decode();ensure(text.count(ANCHOR)==1,'one-exact-barrier-anchor')
                changed=text.replace(ANCHOR,MUTANT,1).encode();Path(PRODUCT).write_bytes(changed)
                expected=freeze();ensure(set(expected)==set(original) and {name for name in expected if expected[name]!=original[name]}=={PRODUCT} and content_freeze()[PRODUCT]==digest(changed) and layout()==original_layout,'only-force-renew-product-difference')
                report['mutant_source_sha256']=identity(expected);save()
                mutant=phase('force_renew',expected);ensure(intended_red(mutant),'mutant-not-sole-intended-runtime-red')
            except Exception as error:
                mutation_error=type(error).__name__;report['mutation_exception']=mutation_error;save()
            finally:
                Path(PRODUCT).write_bytes(original_bytes)
                ensure(freeze()==original,'exact-restored-source-map');report['source_restored']=True;save()
            # Always run the actual restored control after mutant/controller errors.
            restored=phase('restored',original);ensure(green(restored),'actual-restored-control-not-green')
            ensure(mutation_error is None,'mutation-chain-unqualified')
            report['mutation_chain_passed']=True
    except Exception as error:report['controller_exception']=type(error).__name__
    finally:
        report['inputs_pristine']=False;report['source_after_sha256']=None;report['source_layout_after_sha256']=None
        try:Path(PRODUCT).write_bytes(original_bytes)
        except Exception as error:report['final_restore_exception']=type(error).__name__
        try:
            final=freeze();final_layout=layout()
            report['source_after_sha256']=identity(final)
            report['source_layout_after_sha256']=digest(json.dumps(final_layout,sort_keys=True).encode())
            report['inputs_pristine']=final==original and final_layout==original_layout and subprocess.run(['git','diff','--quiet','HEAD']).returncode==0
        except Exception as error:report['final_freeze_exception']=type(error).__name__
        save()
    raise SystemExit(0 if report['inputs_pristine'] and not report.get('controller_exception') and (report['mutation_chain_passed'] if report['mode']=='mutation' else report['component_control_passed']) else 1)
if __name__=='__main__':main()
