#!/usr/bin/env python3
"""Resolve one immutable PR or manual qualification cohort before allocating Apple runners."""
import json
import os
from pathlib import Path
import re
import subprocess


def require(value, message):
    if not value:
        raise ValueError(message)


head = subprocess.check_output(['git', 'rev-parse', 'HEAD'], text=True).strip()
require(head == os.environ['WORKFLOW_HEAD_SHA'], 'Checkout differs from workflow head')
if os.environ['GITHUB_EVENT_NAME'] == 'pull_request':
    event = json.loads(Path(os.environ['GITHUB_EVENT_PATH']).read_text())
    pr = event['pull_request']
    require(pr['head']['repo']['full_name'] == os.environ['GITHUB_REPOSITORY'], 'Only same-fork qualification PRs are supported')
    require(pr['head']['ref'].startswith('ci/upstream-develop-dy-'), 'Unexpected qualification branch')
    require(pr['base']['ref'] == 'master', 'Qualification PR must target refreshed fork master')
    require(head == pr['head']['sha'], 'PR head identity differs')
    # The synthetic PR merge must have the same effective source/workflow tree.
    # An ancestor base guarantees that; a newly advanced base needs reconciliation.
    subprocess.run(['git', 'merge-base', '--is-ancestor', pr['base']['sha'], head], check=True)
    cohort = json.loads(Path('scripts/upstream_apple_ci/cohort.json').read_text())
    require(set(cohort) == {'mac_sha', 'ios_sha'}, 'Unexpected cohort configuration')
    cohort['mdk_sha'] = head
else:
    require(os.environ['GITHUB_EVENT_NAME'] == 'workflow_dispatch', 'Unsupported workflow event')
    require(os.environ['GITHUB_REF'].startswith('refs/heads/ci/upstream-develop-dy-'), 'Unexpected dispatch branch')
    cohort = {key: os.environ['REQUESTED_' + key.upper()] for key in ['mdk_sha', 'mac_sha', 'ios_sha']}
    require(cohort['mdk_sha'] == head == os.environ['GITHUB_SHA'], 'Dispatch source must equal workflow commit')
for key, sha in cohort.items():
    require(isinstance(sha, str) and re.fullmatch('[0-9a-f]{40}', sha), 'Full immutable SHA required: ' + key)
with Path(os.environ['GITHUB_OUTPUT']).open('a') as output:
    for key in ['mdk_sha', 'mac_sha', 'ios_sha']:
        output.write(f'{key}={cohort[key]}\n')
print(json.dumps(cohort, sort_keys=True))
