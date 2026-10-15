#!/usr/bin/env python3
"""Retain raw XCResult counts and immutable cohort identity; reject empty runs."""
import argparse
import json
import os
from pathlib import Path
import subprocess

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('--result', type=Path, required=True)
parser.add_argument('--output', type=Path, required=True)
parser.add_argument('--app-sha', required=True)
args = parser.parse_args()
summary = json.loads(subprocess.check_output(
    ['xcrun', 'xcresulttool', 'get', 'test-results', 'summary', '--path', str(args.result)], text=True))
proof = {'app_sha': args.app_sha, 'sdk_source': os.environ['SOURCE_SHA'],
         'workflow_run_id': os.environ['GITHUB_RUN_ID'],
         'cohort': 'otlp-export,product-analytics-export,experimental-device-sync', 'xcresult_summary': summary}
args.output.write_text(json.dumps(proof, indent=2) + '\n')
if summary.get('totalTestCount', 0) < 1 or summary.get('failedTests') != 0 or summary.get('passedTests', 0) < 1:
    raise SystemExit('XCResult does not establish an executed passing suite')
# Skips remain visible for gate review, rather than being counted as passes.
