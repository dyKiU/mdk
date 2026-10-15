#!/usr/bin/env python3
"""Export only checked Apple packages and immutable qualification inputs."""
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import tomllib


def digest(path):
    return hashlib.file_digest(path.open('rb'), 'sha256').hexdigest()


sha = os.environ['SOURCE_SHA']
release = 'ci-' + sha
evidence = {
    'source_sha': sha, 'builder_sha': os.environ['WORKFLOW_HEAD_SHA'],
    'source_tree': subprocess.check_output(['git', 'rev-parse', 'HEAD^{tree}'], text=True).strip(),
    'workflow_run_id': os.environ['GITHUB_RUN_ID'],
    'uniffi_version': tomllib.loads(Path('crates/marmot-uniffi/Cargo.toml').read_text())['dependencies']['uniffi']['version'],
    'features': ['otlp-export', 'product-analytics-export', 'experimental-device-sync'],
    'input_provenance': {part: json.loads(Path('inputs', part, 'build-provenance.json').read_text())
                         for part in ['swift', 'macos', 'ios-device', 'ios-simulator']},
    'platforms': {},
    'scope': 'Apple SDK artifacts and consumer checks; backend and app qualification are separate gates.',
}
for platform in ['macos', 'ios']:
    bundle = Path('dist', f'marmotkit-{platform}-{release}.zip')
    manifest = json.loads(Path('dist', f'marmotkit-{platform}-{release}.manifest.json').read_text())
    if manifest['source_sha'] != sha or manifest['builder_sha'] != sha or manifest['features'] != evidence['features']:
        raise ValueError('Packaged source or feature identity differs')
    output = Path('crates/marmot-uniffi/output')
    if platform == 'macos':
        output /= 'macos'
    inventory = {str(path.relative_to(output)): digest(path)
                 for path in sorted(output.rglob('*')) if path.is_file()
                 and (path.relative_to(output).parts[0] == 'MarmotKit.xcframework'
                      or path.relative_to(output).as_posix() in ['MarmotKit.swift', 'PrivacyInfo.xcprivacy'])}
    shutil.copy2(bundle, Path('packages', bundle.name))
    evidence['platforms'][platform] = {'bundle': bundle.name, 'sha256': digest(bundle),
                                      'files': inventory, 'manifest': manifest}
Path('packages/qualification.json').write_text(json.dumps(evidence, indent=2) + '\n')
