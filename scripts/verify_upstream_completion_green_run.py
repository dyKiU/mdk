#!/usr/bin/env python3
"""Mutations require prior real controls/static GREEN for this exact source."""
import json
import os
from pathlib import Path
import subprocess
import tempfile
from upstream_completion_ci import NEW,ORIGINALS,ensure,green
run_id=os.environ.get('COMPLETION_CONTROL_RUN_ID','');ensure(run_id.isdecimal(),'prior-green-run-required')
repository=os.environ['GITHUB_REPOSITORY'];source=os.environ['GITHUB_SHA']
def api(path):return json.loads(subprocess.check_output(['gh','api',path],text=True))
run=api('repos/'+repository+'/actions/runs/'+run_id)
ensure(run['repository']['full_name']==repository and run['head_sha']==source and run['event']=='workflow_dispatch' and run['path']=='.github/workflows/experimental-sync-ci.yml' and run['status']=='completed' and run['conclusion']=='success','prior-run-identity-or-status')
artifacts=api('repos/'+repository+'/actions/runs/'+run_id+'/artifacts?per_page=100')['artifacts']
expected=['completion-controls-runtime','completion-controls-static-default','completion-controls-static-experimental']
evidence=[]
with tempfile.TemporaryDirectory(prefix='completion-prior-green-') as directory:
    root=Path(directory)
    for name in expected:
        matching=[entry for entry in artifacts if entry['name']==name and not entry['expired']]
        ensure(len(matching)==1,'exact-prior-artifact')
        artifact=matching[0];ensure(artifact['size_in_bytes']<2_000_000 and artifact.get('digest','').startswith('sha256:'),'bounded-prior-artifact')
        destination=root/name
        subprocess.run(['gh','run','download',run_id,'--repo',repository,'--name',name,'--dir',str(destination)],check=True)
        files=list(destination.rglob('result.json'));ensure(len(files)==1,'one-prior-result')
        report=json.loads(files[0].read_text());ensure(report['source']==source and report['inputs_pristine'] is True,'prior-source-pristine')
        if name=='completion-controls-runtime':
            ensure(report['mode']=='controls' and report['controls_passed'] is True,'actual-prior-controls')
            phase=report['controls'];ensure(phase['compilation']['compile_exit_code']==0 and phase['compilation']['compiler_error_count']==0 and phase['compilation']['compiled_fingerprints']['verified'] is True,'actual-prior-compile-cohort')
            ensure([row['suffix'] for row in phase['bodies']]==[NEW]+ORIGINALS and all(green(row) for row in phase['bodies']),'actual-four-prior-bodies')
        else:
            cohort=name.rsplit('-',1)[-1];ensure(report['mode']=='static' and report['cohort']==cohort and report['static_passed'] is True and report['exit_code']==0 and report['compiler_error_count']==0 and report['actual_runtime_bodies']==0,'actual-prior-static')
        evidence.append({'id':artifact['id'],'name':name,'digest':artifact['digest'],'source':source})
Path('completion-prior-green.json').write_text(json.dumps({'run_id':int(run_id),'source':source,'artifacts':evidence,'exact_prior_controls_and_two_static_cohorts_passed':True},indent=2)+'\n')
