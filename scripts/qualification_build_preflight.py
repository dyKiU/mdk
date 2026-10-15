#!/usr/bin/env python3
"""Read-only capacity and launch-environment guard for remote qualification builds."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('--label', required=True)
parser.add_argument('--output', default='build-capacity-preflight.json')
args = parser.parse_args()
if os.environ.get('GITHUB_ACTIONS') != 'true':
    raise SystemExit('Qualification build preflight requires remote GitHub Actions')
minimum = 8 * 1024**3
paths = [Path.cwd(), Path(os.environ.get('CARGO_TARGET_DIR', 'target')).resolve(),
         Path(os.environ['RUNNER_TEMP']).resolve()]
observations = []
for path in paths:
    while not path.exists():
        path = path.parent
    usage = shutil.disk_usage(path)
    observations.append({'path': str(path), 'free_bytes': usage.free, 'total_bytes': usage.total})
record = {'source_sha': subprocess.check_output(['git', 'rev-parse', 'HEAD'], text=True).strip(),
          'label': args.label, 'minimum_free_bytes': minimum, 'volumes': observations,
          'cargo_incremental': os.environ.get('CARGO_INCREMENTAL'),
          'cargo_lock_sha256': hashlib.sha256(Path('Cargo.lock').read_bytes()).hexdigest(),
          'compiler_launch_environment': {name: os.environ.get(name) for name in (
              'CARGO_BUILD_JOBS', 'CARGO_PROFILE_DEV_DEBUG', 'CARGO_PROFILE_TEST_DEBUG',
              'CARGO_PROFILE_RELEASE_DEBUG', 'RUSTFLAGS', 'CARGO_ENCODED_RUSTFLAGS')},
          'cleanup_performed': False}
record['passed'] = record['cargo_incremental'] == '1' and all(row['free_bytes'] >= minimum for row in observations)
Path(args.output).write_text(json.dumps(record, indent=2) + '\n')
print(json.dumps(record, sort_keys=True), flush=True)
if not record['passed']:
    raise SystemExit('Qualification build requires incremental=1 and eight GiB available on each build volume')
