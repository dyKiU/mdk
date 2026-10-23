#!/usr/bin/env python3
"""Export only checked Apple packages and immutable qualification inputs."""
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import tomllib
from package_metadata import uniffi_version
from sdk_profiles import environment_profile, features, release_id, validate_provenance


def digest(path):
    return hashlib.file_digest(path.open('rb'), 'sha256').hexdigest()


sha = os.environ['SOURCE_SHA']
profile = environment_profile()
release = release_id(profile, sha)
evidence = {
    'schema_version': 2,
    'source_sha': sha, 'builder_sha': os.environ['WORKFLOW_HEAD_SHA'],
    'source_tree': subprocess.check_output(['git', 'rev-parse', 'HEAD^{tree}'], text=True).strip(),
    'workflow_run_id': os.environ['GITHUB_RUN_ID'],
    'uniffi_version': uniffi_version(tomllib.loads(Path('crates/marmot-uniffi/Cargo.toml').read_text())),
    'sdk_profile': profile,
    'features': features(profile),
    'cargo_lock_sha256': hashlib.sha256(Path('Cargo.lock').read_bytes()).hexdigest(),
    'release_profile_sha256': hashlib.sha256(Path('crates/marmot-uniffi/marmotkit-release-profile.env').read_bytes()).hexdigest(),
    'input_provenance': {part: json.loads(Path('inputs', part, 'build-provenance.json').read_text())
                         for part in ['swift', 'macos', 'ios-device', 'ios-simulator']},
    'platforms': {},
    'scope': 'Apple SDK artifacts and consumer checks; backend and app qualification are separate gates.',
}
first = evidence['input_provenance']['swift']
evidence['compiler'] = {'rustc': first['rustc'], 'cargo': first['cargo']}
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
validate_provenance(evidence, profile, sha, os.environ['GITHUB_RUN_ID'])
Path('packages/qualification.json').write_text(json.dumps(evidence, indent=2) + '\n')
