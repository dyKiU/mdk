#!/usr/bin/env python3
"""Validate same-run packages and adopt an ephemeral app SDK overlay, without builds."""
import argparse
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import stat
import subprocess
import tempfile
import zipfile


FEATURES = ['otlp-export', 'product-analytics-export', 'experimental-device-sync']


def digest(path):
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def require(value, message):
    if not value:
        raise ValueError(message)


def verified_package(packages, platform, source, run_id, destination):
    proof = json.loads((packages / 'qualification.json').read_text())
    require(proof['source_sha'] == proof['builder_sha'] == source, 'SDK source/builder mismatch')
    require(proof['workflow_run_id'] == run_id and proof['features'] == FEATURES, 'SDK run/cohort mismatch')
    record = proof['platforms'][platform]
    require(record['bundle'] == f'marmotkit-{platform}-ci-{source}.zip', 'Unexpected bundle name')
    bundle = packages / record['bundle']
    require(digest(bundle) == record['sha256'], 'Bundle checksum mismatch')
    root_name = bundle.stem
    seen = set()
    with zipfile.ZipFile(bundle) as archive:
        for item in archive.infolist():
            name = PurePosixPath(item.filename.rstrip('/'))
            require(not name.is_absolute() and '..' not in name.parts and name.parts[0] == root_name,
                    'Unsafe archive member')
            require(str(name) == item.filename.rstrip('/') and item.filename not in seen, 'Duplicate/noncanonical member')
            require(not stat.S_ISLNK(item.external_attr >> 16), 'Archive symlink refused')
            require(len(seen) < 256 and item.file_size < 2 * 1024**3, 'Archive budget exceeded')
            seen.add(item.filename)
        archive.extractall(destination)
    output = destination / root_name
    manifest = json.loads((output / 'manifest.json').read_text())
    require(manifest == record['manifest'], 'Embedded manifest mismatch')
    require(manifest['source_sha'] == manifest['builder_sha'] == source and manifest['features'] == FEATURES,
            'Embedded cohort mismatch')
    actual = {str(path.relative_to(output)): digest(path)
              for path in sorted(output.rglob('*')) if path.is_file() and path.name != 'manifest.json'}
    require(actual == record['files'], 'Expanded native/header/Swift/privacy inventory mismatch')
    for name, value in manifest['artifacts'].items():
        path = output / name
        if name.endswith('.swift'):
            path = output / 'MarmotKit.swift'
        elif name.endswith('.xcprivacy'):
            path = output / 'PrivacyInfo.xcprivacy'
        elif name.endswith('.xcframework.zip'):
            continue  # Standalone distribution ZIP is not part of this complete bundle.
        require(path.is_file() and digest(path) == value['sha256'], 'Manifest artifact mismatch')
    manifest['uniffi_version'] = proof['uniffi_version']
    return output, manifest


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--packages', type=Path, required=True)
    parser.add_argument('--source', required=True)
    parser.add_argument('--run-id', required=True)
    parser.add_argument('--platform', choices=['macos', 'ios'], required=True)
    parser.add_argument('--app', type=Path)
    parser.add_argument('--app-sha')
    parser.add_argument('--output', type=Path)
    args = parser.parse_args()
    require(re.fullmatch('[0-9a-f]{40}', args.source), 'Full source SHA required')
    require(bool(args.app) != bool(args.output), 'Choose app installation or validated output extraction')
    with tempfile.TemporaryDirectory() as temp:
        output, manifest = verified_package(args.packages, args.platform, args.source, args.run_id, Path(temp))
        if args.output:
            require(not args.output.exists(), 'Output already exists')
            shutil.copytree(output, args.output)
            return
        app = args.app.resolve(strict=True)
        require(re.fullmatch('[0-9a-f]{40}', args.app_sha or ''), 'Exact app SHA required')
        head = subprocess.check_output(['git', '-C', str(app), 'rev-parse', 'HEAD'], text=True).strip()
        require(head == args.app_sha, 'App source identity mismatch')
        require(not subprocess.check_output(['git', '-C', str(app), 'status', '--porcelain']), 'App checkout must be pristine')
        package = app / ('Vendored/MarmotKit' if args.platform == 'macos' else 'Packages/MarmotKit')
        artifact = package / 'Artifacts/MarmotKit.xcframework'
        require(not artifact.exists(), 'Existing local SDK overlay refused')
        artifact.parent.mkdir(exist_ok=True)
        shutil.copytree(output / 'MarmotKit.xcframework', artifact)
        swift = package / 'Sources/MarmotKit/MarmotKit.swift'
        swift.write_text('\n'.join(line.rstrip() for line in (output / 'MarmotKit.swift').read_text().splitlines()) + '\n')
        resources = package / 'Sources/MarmotKit/Resources'
        resources.mkdir(exist_ok=True)
        shutil.copy2(output / 'PrivacyInfo.xcprivacy', resources / 'PrivacyInfo.xcprivacy')
        package_file = package / 'Package.swift'
        text, count = re.subn(r'let marmotKitLocalPath: String\? = .*',
                             'let marmotKitLocalPath: String? = "Artifacts/MarmotKit.xcframework"', package_file.read_text())
        require(count == 1, 'Local package override declaration missing/ambiguous')
        require('resources: [.copy("Resources/PrivacyInfo.xcprivacy")]' in text, 'Privacy resource declaration missing')
        package_file.write_text(text)
        manifest['installed_swift_sha256'] = digest(swift)
        manifest['installation'] = 'Ephemeral hosted CI overlay; never commit'
        manifest['workflow_run_id'] = args.run_id
        (package / 'LOCAL_BUILD.json').write_text(json.dumps(manifest, indent=2) + '\n')
        features = ','.join(FEATURES)
        (package / 'MARMOT_VERSION').write_text(f'mdk-sha: {args.source}\nmdk-branch: detached\nmdk-tag: ci-{args.source}\nfeatures: {features}\n')
        (package / 'Sources/MarmotKit/MarmotKitVersion.swift').write_text(
            'import Foundation\npublic enum MarmotKitVersion {\n'
            f'    public static let mdkSHA = "{args.source}"\n'
            f'    public static let mdkTag = "ci-{args.source}"\n'
            '    public static let builtAt = "CI artifact"\n'
            f'    public static let uniffiVersion = "{manifest["uniffi_version"]}"\n'
            f'    public static let features = "{features}"\n' + '}\n')
        # The app's independently maintained guard checks the actual installed bytes.
        subprocess.run(['bash', '-c', 'repo_root=$1; source "$repo_root/scripts/local-device-sync-settings.sh"',
                        'verify-overlay', str(app)], check=True,
                       env=dict(os.environ, WN_EXPERIMENTAL_DEVICE_SYNC='1'))


if __name__ == '__main__':
    main()
