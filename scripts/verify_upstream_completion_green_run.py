#!/usr/bin/env python3
"""Mutations require prior real controls/static GREEN for this exact source."""
import json
import os
from pathlib import Path
import subprocess
import io
import hashlib
import re
import zipfile
from upstream_completion_ci import NEW,ORIGINALS,ensure,green
cohort_baseline=os.environ.get('UPSTREAM_EXTRACTION_COHORT_BASELINE')
cohort=None
if cohort_baseline:
    from upstream_extraction_cohort import reviewed_cohort
    cohort=reviewed_cohort(cohort_baseline)
run_id=os.environ.get('COMPLETION_CONTROL_RUN_ID','');ensure(run_id.isdecimal(),'prior-green-run-required')
repository=os.environ['GITHUB_REPOSITORY'];source=os.environ['GITHUB_SHA']
def api(path):return json.loads(subprocess.check_output(['gh','api',path],text=True))
run=api('repos/'+repository+'/actions/runs/'+run_id)
ensure(run['repository']['full_name']==repository and run['head_sha']==source and run['event']=='workflow_dispatch' and run['path']=='.github/workflows/experimental-sync-ci.yml' and run['status']=='completed' and run['conclusion']=='success','prior-run-identity-or-status')
artifacts=api('repos/'+repository+'/actions/runs/'+run_id+'/artifacts?per_page=100')['artifacts']
expected=['completion-controls-runtime','completion-controls-static-default','completion-controls-static-experimental']
evidence=[]
for name in expected:
    matching=[entry for entry in artifacts if entry['name']==name and not entry['expired']]
    ensure(len(matching)==1,'exact-prior-artifact')
    artifact=matching[0]
    expected_digest=artifact.get('digest','')
    ensure(0<artifact['size_in_bytes']<2_000_000 and re.fullmatch(r'sha256:[0-9a-f]{64}',expected_digest),'bounded-prior-artifact')
    data=subprocess.check_output(['gh','api','repos/'+repository+'/actions/artifacts/'+str(artifact['id'])+'/zip'],timeout=60)
    ensure(len(data)==artifact['size_in_bytes'] and len(data)<2_000_000,'actual-prior-artifact-size')
    ensure('sha256:'+hashlib.sha256(data).hexdigest()==expected_digest,'actual-prior-artifact-digest')
    with zipfile.ZipFile(io.BytesIO(data)) as archive:
        files=[entry for entry in archive.infolist() if Path(entry.filename).name=='result.json']
        ensure(len(files)==1 and 0<files[0].file_size<2_000_000,'one-bounded-prior-result')
        report=json.loads(archive.read(files[0]))
    ensure(report['source']==source and report['inputs_pristine'] is True,'prior-source-pristine')
    if cohort_baseline:
        proof=report.get('reviewed_extraction_cohort',{})
        ensure(proof.get('baseline')==cohort_baseline and proof.get('source')==source
               and proof.get('input_manifest_sha256')==cohort['input_manifest_sha256']
               and report.get('source_preflight',{}).get('source_preflight_passed') is True,
               'prior-exact-reviewed-extraction-cohort')
    if name=='completion-controls-runtime':
        ensure(report['mode']=='controls' and report['controls_passed'] is True,'actual-prior-controls')
        phase=report['controls'];ensure(phase['compilation']['compile_exit_code']==0 and phase['compilation']['compiler_error_count']==0 and phase['compilation']['compiled_fingerprints']['verified'] is True,'actual-prior-compile-cohort')
        ensure([row['suffix'] for row in phase['bodies']]==[NEW]+ORIGINALS and all(green(row) for row in phase['bodies']),'actual-four-prior-bodies')
    else:
        feature_cohort=name.rsplit('-',1)[-1];ensure(report['mode']=='static' and report['cohort']==feature_cohort and report['static_passed'] is True and report['exit_code']==0 and report['compiler_error_count']==0 and report['actual_runtime_bodies']==0,'actual-prior-static')
    evidence.append({'id':artifact['id'],'name':name,'digest':artifact['digest'],'source':source,'download_digest_verified':True})
Path('completion-prior-green.json').write_text(json.dumps({'run_id':int(run_id),'source':source,'extraction_cohort_baseline':cohort_baseline,'artifacts':evidence,'exact_prior_controls_and_two_static_cohorts_passed':True},indent=2)+'\n')
