#!/usr/bin/env python3
"""Wait for an existing exact SDK artifact without launching or rerunning workflows."""
import json
import os
import subprocess
import time
from sdk_profiles import artifact_name


def api(path):
    return json.loads(subprocess.check_output(['gh', 'api', path], text=True))


run_id, source = os.environ['SDK_RUN_ID'], os.environ['SOURCE_SHA']
run_path = 'repos/dyKiU/mdk/actions/runs/' + run_id
profile = os.environ.get('SDK_PROFILE', 'experimental')
expected = artifact_name(profile, source)
deadline = time.monotonic() + 100 * 60
while True:
    run = api(run_path)
    if run['head_sha'] != source or run['path'] != '.github/workflows/upstream-experimental-apple.yml':
        raise SystemExit('SDK producer run identity mismatch')
    artifacts = api(run_path + '/artifacts?per_page=100')['artifacts']
    matching = [a for a in artifacts if a['name'] == expected and not a['expired']]
    if len(matching) == 1:
        print(json.dumps({'sdk_run_id': run_id, 'source_sha': source, 'sdk_profile': profile, 'artifact': expected,
                          'artifact_id': matching[0]['id'], 'producer_status': run['status']}))
        break
    if len(matching) > 1 or run['status'] == 'completed':
        raise SystemExit('Existing SDK producer has no unique available matching artifact')
    if time.monotonic() >= deadline:
        raise SystemExit('SDK artifact still pending; no build was dispatched')
    print('Waiting for existing SDK assembly artifact', flush=True)
    time.sleep(60)
