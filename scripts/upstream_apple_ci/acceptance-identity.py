#!/usr/bin/env python3
"""Resolve supplemental test-tool and previously built SDK identities separately."""
import json
import os
from pathlib import Path
import re
import subprocess


def require(value, message):
    if not value:
        raise ValueError(message)


head = subprocess.check_output(['git', 'rev-parse', 'HEAD'], text=True).strip()
require(head == os.environ['WORKFLOW_HEAD_SHA'], 'Unexpected test-tool checkout')
keys = ['sdk_run_id', 'sdk_sha', 'mac_sha', 'ios_sha']
require(os.environ['GITHUB_REF'].startswith('refs/heads/ci/upstream-acceptance-'), 'Dedicated acceptance branch required')
require(head == os.environ['GITHUB_SHA'], 'Workflow source differs from the tested tools')
require(os.environ['GITHUB_EVENT_NAME'] == 'workflow_dispatch', 'Explicit manual qualification required')
cohort = {key: os.environ['REQUESTED_' + key.upper()] for key in keys}
require(set(cohort) == set(keys), 'Unexpected supplemental cohort fields')
for key in ['sdk_sha', 'mac_sha', 'ios_sha']:
    require(isinstance(cohort[key], str) and re.fullmatch('[0-9a-f]{40}', cohort[key]), 'Full immutable SHA required')
require(isinstance(cohort['sdk_run_id'], str) and re.fullmatch('[1-9][0-9]+', cohort['sdk_run_id']), 'Numeric SDK run required')
cohort['tools_sha'] = head
allowed = {'default-interop', 'published-interop', 'hosted-history', 'final-ios', 'final-mac', 'one-scan', 'history-pagination', 'automatic-history'}
selection = os.environ['REQUESTED_LANE']
require(selection == 'all' or selection in allowed, 'Known manual lane required')
lanes = sorted(allowed) if selection == 'all' else [selection]
require(isinstance(lanes, list) and lanes and all(isinstance(lane, str) and lane in allowed for lane in lanes)
        and len(lanes) == len(set(lanes)), 'Explicit nonempty unique known lanes required')
cohort['lanes'] = json.dumps(lanes, separators=(',', ':'))
default_run = os.environ.get('REQUESTED_DEFAULT_SDK_RUN_ID', '')
if 'default-interop' in lanes:
    require(isinstance(default_run, str) and re.fullmatch('[1-9][0-9]*', default_run),
            'Explicit default SDK producer required for default interoperability')
    require(default_run != cohort['sdk_run_id'], 'Default and experimental producers must be distinct')
else:
    require(not default_run, 'Default SDK producer supplied for an unrelated lane')
cohort['default_sdk_run_id'] = default_run
with Path(os.environ['GITHUB_OUTPUT']).open('a') as output:
    for key, value in cohort.items():
        output.write(f'{key}={value}\n')
print(json.dumps(cohort, sort_keys=True))
