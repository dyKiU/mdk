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
from sdk_profiles import features as profile_features, release_id, validate_provenance


FEATURES = ['otlp-export', 'product-analytics-export', 'experimental-device-sync']


def digest(path):
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def require(value, message):
    if not value:
        raise ValueError(message)


def safe_install_directory(app, directory):
    require(directory.is_absolute() and directory.is_relative_to(app), 'Install destination escaped app')
    require(app.resolve(strict=True) == app and not app.is_symlink(), 'Physical app root required')
    for ancestor in [directory, *directory.parents]:
        require(not ancestor.is_symlink(), 'Install destination ancestor symlink refused')
        if ancestor.exists():
            require(ancestor.is_dir(), 'Install destination parent is not a directory')
        if ancestor == app:
            break


def check_install_destinations(app, platform):
    """Read-only preflight; every destination parent is checked before any write."""
    require(platform in {'macos', 'ios'}, 'Unknown Apple platform')
    package = app / ('Vendored/MarmotKit' if platform == 'macos' else 'Packages/MarmotKit')
    safe_install_directory(app, package)
    absent = [package / 'Artifacts/MarmotKit.xcframework', package / 'LOCAL_BUILD_INPUTS',
              package / 'LOCAL_BUILD.json']
    outputs = [package / name for name in ['Package.swift', 'MARMOT_VERSION',
        'Sources/MarmotKit/MarmotKit.swift', 'Sources/MarmotKit/MarmotKitVersion.swift',
        'Sources/MarmotKit/Resources/PrivacyInfo.xcprivacy']]
    for path in absent + outputs:
        safe_install_directory(app, path.parent)
        require(not path.is_symlink(), 'Install destination leaf symlink refused')
    for path in absent:
        require(not path.exists(), 'Existing local SDK destination refused')
    for path in outputs:
        require(not path.exists() or path.is_file(), 'Install destination is not a regular file')
    return package


def verified_package(packages, platform, source, run_id, destination, profile='experimental'):
    expected_features = profile_features(profile)
    qualification_path = packages / 'qualification.json'
    qualification_bytes = qualification_path.read_bytes()
    proof = json.loads(qualification_bytes)
    validate_provenance(proof, profile, source, run_id)
    require(proof['source_sha'] == proof['builder_sha'] == source, 'SDK source/builder mismatch')
    require(proof['workflow_run_id'] == run_id and proof['features'] == expected_features, 'SDK run/cohort mismatch')
    record = proof['platforms'][platform]
    require(record['bundle'] == f'marmotkit-{platform}-{release_id(profile, source)}.zip', 'Unexpected bundle name')
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
    manifest_bytes = (output / 'manifest.json').read_bytes()
    manifest = json.loads(manifest_bytes)
    require(manifest == record['manifest'], 'Embedded manifest mismatch')
    require(manifest['source_sha'] == manifest['builder_sha'] == source and manifest['features'] == expected_features,
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
    require(qualification_path.read_bytes() == qualification_bytes, 'Qualification changed during verification')
    # Installer-only receipt; never mutate the generated embedded manifest.
    manifest['qualification_receipt'] = {
        'qualification_json': qualification_bytes.decode('utf-8'),
        'qualification_sha256': hashlib.sha256(qualification_bytes).hexdigest(),
        'manifest_json': manifest_bytes.decode('utf-8'),
        'manifest_sha256': hashlib.sha256(manifest_bytes).hexdigest(),
        'platform': platform, 'bundle': record['bundle'], 'bundle_sha256': record['sha256'],
        'original_swift_relative_path': 'LOCAL_BUILD_INPUTS/MarmotKit.swift',
    }
    manifest['uniffi_version'] = proof['uniffi_version']
    manifest['sdk_profile'] = profile
    return output, manifest


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--profile', choices=['default', 'experimental'], default='experimental')
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
    # Default app capability is a prerequisite, not an artifact installation.
    # Refuse an unsupported real app before reading a package or writing an
    # overlay. This negative preflight cannot qualify a synthetic artifact.
    if args.app:
        app = args.app.resolve(strict=True)
        require(re.fullmatch('[0-9a-f]{40}', args.app_sha or ''), 'Exact app SHA required')
        head = subprocess.check_output(['git', '-C', str(app), 'rev-parse', 'HEAD'], text=True).strip()
        require(head == args.app_sha, 'App source identity mismatch')
        require(not subprocess.check_output(['git', '-C', str(app), 'status', '--porcelain']), 'App checkout must be pristine')
        if args.profile == 'default':
            require((app / 'scripts/local-sdk-profile-settings.sh').is_file(),
                    'Default SDK app capability guard is not implemented')
        check_install_destinations(app, args.platform)
    with tempfile.TemporaryDirectory() as temp:
        output, manifest = verified_package(args.packages, args.platform, args.source, args.run_id, Path(temp), args.profile)
        if args.output:
            require(not args.output.exists(), 'Output already exists')
            shutil.copytree(output, args.output)
            return
        app = args.app.resolve(strict=True)
        require(re.fullmatch('[0-9a-f]{40}', args.app_sha or ''), 'Exact app SHA required')
        head = subprocess.check_output(['git', '-C', str(app), 'rev-parse', 'HEAD'], text=True).strip()
        require(head == args.app_sha, 'App source identity mismatch')
        require(not subprocess.check_output(['git', '-C', str(app), 'status', '--porcelain']), 'App checkout must be pristine')
        if args.profile == 'default':
            require((app / 'scripts/local-sdk-profile-settings.sh').is_file(),
                    'Default SDK app capability guard is not implemented')
        package = check_install_destinations(app, args.platform)
        artifact = package / 'Artifacts/MarmotKit.xcframework'
        require(not artifact.exists(), 'Existing local SDK overlay refused')
        original_inputs = package / 'LOCAL_BUILD_INPUTS'
        require(not original_inputs.exists(), 'Existing SDK original inputs refused')
        artifact.parent.mkdir(exist_ok=True)
        shutil.copytree(output / 'MarmotKit.xcframework', artifact)
        swift = package / 'Sources/MarmotKit/MarmotKit.swift'
        original_inputs.mkdir()
        shutil.copy2(output / 'MarmotKit.swift', original_inputs / 'MarmotKit.swift')
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
        features = ','.join(profile_features(args.profile))
        # A verified ephemeral overlay follows the app's local-build convention;
        # the immutable producer identity remains in LOCAL_BUILD.json.
        (package / 'MARMOT_VERSION').write_text(f'mdk-sha: {args.source}\nmdk-branch: detached\nmdk-tag: local-{args.source}\nfeatures: {features}\n')
        (package / 'Sources/MarmotKit/MarmotKitVersion.swift').write_text(
            'import Foundation\npublic enum MarmotKitVersion {\n'
            f'    public static let mdkSHA = "{args.source}"\n'
            f'    public static let mdkTag = "local-{args.source}"\n'
            '    public static let builtAt = "CI artifact"\n'
            f'    public static let uniffiVersion = "{manifest["uniffi_version"]}"\n'
            f'    public static let features = "{features}"\n' + '}\n')
        guard_environment = dict(os.environ, WN_SDK_PROFILE=args.profile,
                                 WN_EXPERIMENTAL_DEVICE_SYNC='0' if args.profile == 'default' else '1',
                                 WN_SDK_SOURCE_SHA=args.source, WN_SDK_RUN_ID=args.run_id,
                                 SDK_SOURCE_REPOSITORY=os.environ.get('SDK_SOURCE_REPOSITORY',
                                                                    str(Path(__file__).resolve().parents[2])))
        guard = app / 'scripts/local-sdk-profile-settings.sh'
        if args.profile == 'default':
            require(guard.is_file(), 'Default SDK app capability guard is not implemented')
            subprocess.run(['bash', '-c',
                            'set -e; repo_root=$1; source "$repo_root/scripts/local-sdk-profile-settings.sh"; '
                            'test "$WN_VERIFIED_SDK_PROFILE" = default; '
                            'test "$WN_CURRENT_SDK_API" = 1; test "$WN_EXPERIMENTAL_DEVICE_SYNC" = 0',
                            'verify-default-overlay', str(app)], check=True, env=guard_environment)
        else:
            # Historical app revisions have only the original stable entry point.
            # Preserve their independently validated experimental installation.
            subprocess.run(['bash', '-c',
                            'set -e; repo_root=$1; source "$repo_root/scripts/local-device-sync-settings.sh"',
                            'verify-overlay', str(app)], check=True, env=guard_environment)



if __name__ == '__main__':
    main()
