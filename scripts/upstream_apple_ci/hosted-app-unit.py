#!/usr/bin/env python3
"""Run exactly one existing fixture test from prebuilt products; never compile."""
import argparse
import paired_direct_mutation
import copy
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re

from sdk_profiles import validate_provenance, release_id, features as profile_features
import plistlib
import signal
import subprocess
import time

ENVIRONMENT_KEYS = {
    'GITHUB_ACTIONS', 'GITHUB_RUN_ID', 'WN_NATIVE_ACCEPTANCE_BASE',
    'WN_NATIVE_ACCEPTANCE_SDK_SOURCE', 'WN_NATIVE_ACCEPTANCE_SDK_RUN_ID',
    'WN_NATIVE_ACCEPTANCE_AGENT_SHA256', 'WN_AUTOMATIC_SWITCH_ROOT', 'WN_IMPORTED_HISTORY_FIXTURE',
    'WN_HISTORY_SOURCE_PICKER_FIXTURE', 'WN_SOURCE_PICKER_FIXTURE', 'WN_HISTORY_SOURCE_UI_BRIDGE',
    'WN_SOURCE_PICKER_BUTTON_BRIDGE', 'WN_SOURCE_TRANSFER_BRIDGE', 'WN_IOS_SOURCE_TRANSFER_BRIDGE',
    'WN_IOS_SOURCE_TRANSFER_PUBLIC_BRIDGE', 'WN_HISTORY_APPROVAL_BRIDGE', 'WN_MAC_HISTORY_APPROVAL_BRIDGE',
    'WN_NATIVE_PAIRING_QR_ACCEPTANCE', 'WN_PAIRED_DIRECT_FIXTURE',
    'WN_AUTOMATIC_HOST_FACTORY_ACCEPTANCE',
}
SELECTORS = {
    'macos': {
        'GenuineAutomaticHostFactoryTests/testExistingRosterWNPAIR2RequiresSiblingApprovalAndSharesHistory',
        'GenuineAutomaticHostFactoryTests/testForwardFactoriesShareBothPreviouslyAbsentChats',
        'GenuineAutomaticHostFactoryTests/testReverseFactoriesShareBothPreviouslyAbsentChats',
        'GenuineAutomaticHostFactoryTests/testActualFactoryCancellationRetiresOriginal',
        'GenuineAutomaticHostFactoryTests/testActualFactoryPlatformShutdownClosesStorageAndRetiresOriginal',
        'GenuineAutomaticHostFactoryTests/testLateBeginFactoryCannotAdoptAcrossAccountReplacement',
        'GenuineAutomaticHostFactoryTests/testLateScanFactoryCannotAdoptAcrossAccountReplacement',
        'GenuinePairedDirectConversationTests/testRealMarmotClientReusesPairedSourceWithoutLocalMembershipOrInvitation',
        'GenuineAutomaticAccountSwitchTests/testActualAccountsReplacePairedOwnersAndRetireBeforeRuntimeClose',
        'GenuineImportedHistoryPaneTests/testRealCommittedImportThroughSessionOwnedReaderAndHostedPane',
        'GenuineHistorySourcePickerTests/testRealRecipientsAndFreshOriginalThroughSessionOwnedModel',
        'GenuineHistorySourceTransferTests/testCompleteFreshSourceOriginalThroughAccountModelAndNativeRecipient',
        'GenuineHistoryRecipientTransferTests/testFreshRecipientOriginalThroughSessionModelAndIOSSource',
    },
    'ios-simulator': {
        'GenuineAutomaticHostFactoryTests/testExistingRosterWNPAIR2RequiresSiblingApprovalAndSharesHistory',
        'GenuineAutomaticHostFactoryTests/testForwardFactoriesShareBothPreviouslyAbsentChats',
        'GenuineAutomaticHostFactoryTests/testReverseFactoriesShareBothPreviouslyAbsentChats',
        'GenuineAutomaticHostFactoryTests/testActualFactoryCancellationRetiresOriginal',
        'GenuineAutomaticHostFactoryTests/testActualFactoryPlatformShutdownClosesStorageAndRetiresOriginal',
        'GenuineAutomaticHostFactoryTests/testLateBeginFactoryCannotAdoptAcrossAccountReplacement',
        'GenuineAutomaticHostFactoryTests/testLateScanFactoryCannotAdoptAcrossAccountReplacement',
        'GenuinePairedDirectConversationTests/testRealMarmotClientReusesPairedSourceWithoutLocalMembershipOrInvitation',
        'NativePairingQRCodeTests/testActualThreeDevicePacketsPassAppCodecAndOriginalSdkAuthentication',
        'GenuineAutomaticAccountSwitchTests/testActualAccountsReplacePairedOwnersAndSceneSuspensionClosesRuntime',
        'GenuineImportedHistoryPaneTests/testRealCommittedImportThroughAccountOwnedReaderAndHostedPane',
        'GenuineHistorySourcePickerTests/testActualNativeChoicesCreateRefreshAndCancelOriginalThroughAccountOwner',
        'GenuineHistorySourceTransferTests/testCompleteFreshSourceOriginalThroughAppStateAndNativeRecipient',
    },
}


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def freeze_source(source, commit, sdk_package, mutation_mode=None):
    if subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=source, text=True).strip() != commit:
        raise ValueError('App source commit changed')
    names = subprocess.check_output(['git', 'ls-files', '-z', '--cached', '--others', '--exclude-standard'],
                                    cwd=source).decode().split('\0')
    frozen = {}
    for name in filter(None, names):
        path = source / name
        if not path.is_file():
            raise ValueError('Tracked or untracked source file is missing')
        if path.is_relative_to(sdk_package):
            continue
        data = os.readlink(path).encode() if path.is_symlink() else path.read_bytes()
        committed = subprocess.check_output(['git', 'show', commit + ':' + name], cwd=source)
        if data != paired_direct_mutation.expected_bytes(name, committed, mutation_mode):
            raise ValueError('Non-SDK source differs from the pinned commit')
        frozen[name] = hashlib.sha256(data).hexdigest()
    return frozen


def freeze_sdk(package, manifest):
    """Freeze authenticated native/header inventory without executing SDK code."""
    def require(value, label):
        if not value:
            raise ValueError(label)

    require(package.is_absolute() and package.resolve(strict=True) == package,
                   'physical-installed-sdk-root')
    def regular(relative):
        path = package / relative
        for item in (path, *path.parents):
            require(not item.is_symlink(), 'installed-sdk-symlink-refused')
            if item == package:
                break
        require(path.is_file(), 'installed-sdk-file-required')
        return path

    require(json.loads(regular('LOCAL_BUILD.json').read_text()) == manifest,
                   'installed-sdk-manifest-unchanged')
    receipt = manifest['qualification_receipt']
    require(type(receipt) is dict and set(receipt) == {
        'qualification_json', 'qualification_sha256', 'manifest_json', 'manifest_sha256',
        'platform', 'bundle', 'bundle_sha256', 'original_swift_relative_path'},
        'closed-installed-qualification-receipt')
    raw_q = receipt['qualification_json'].encode('utf-8')
    raw_manifest = receipt['manifest_json'].encode('utf-8')
    require(len(raw_q) <= 2 * 1024**2 and len(raw_manifest) <= 256 * 1024,
                   'bounded-installed-qualification-receipt')
    require(hashlib.sha256(raw_q).hexdigest() == receipt['qualification_sha256']
                   and hashlib.sha256(raw_manifest).hexdigest() == receipt['manifest_sha256'],
                   'installed-qualification-bytes-authenticated')
    proof = json.loads(raw_q)
    original = json.loads(raw_manifest)
    profile, source, run = manifest['sdk_profile'], manifest['source_sha'], manifest['workflow_run_id']
    validate_provenance(proof, profile, source, run)
    require(proof.get('sdk_profile') == profile and manifest['builder_sha'] == source
                   and manifest['features'] == profile_features(profile), 'exact-installed-sdk-profile')
    platform = receipt['platform']
    require(platform in ('macos', 'ios'), 'closed-installed-sdk-platform')
    record = proof['platforms'][platform]
    require(record['manifest'] == original and original['source_sha'] == original['builder_sha'] == source,
                   'exact-qualified-package-manifest')
    require(receipt['bundle'] == record['bundle']
                   == 'marmotkit-' + platform + '-' + release_id(profile, source) + '.zip'
                   and receipt['bundle_sha256'] == record['sha256'], 'exact-qualified-platform-bundle')
    expected = original | dict(uniffi_version=proof['uniffi_version'], sdk_profile=profile,
        installed_swift_sha256=manifest['installed_swift_sha256'], workflow_run_id=run,
        installation='Ephemeral hosted CI overlay; never commit', qualification_receipt=receipt)
    require(manifest == expected, 'exact-installed-package-metadata')
    files = record['files']
    require(type(files) is dict and 0 < len(files) <= 256 and {
        'MarmotKit.swift', 'PrivacyInfo.xcprivacy', 'MarmotKit.xcframework/Info.plist'} <= set(files),
        'complete-qualified-package-inventory')
    require(receipt['original_swift_relative_path'] == 'LOCAL_BUILD_INPUTS/MarmotKit.swift',
                   'exact-original-sdk-swift-path')
    frozen = {'LOCAL_BUILD.json': digest(regular('LOCAL_BUILD.json'))}
    native = set()
    for name, expected_digest in files.items():
        require(type(name) is str and type(expected_digest) is str and re.fullmatch('[0-9a-f]{64}', expected_digest),
                       'typed-qualified-sdk-file-digest')
        path_name = PurePosixPath(name)
        require(not path_name.is_absolute() and '..' not in path_name.parts and str(path_name) == name,
                       'canonical-qualified-sdk-file-path')
        if name == 'MarmotKit.swift':
            relative = receipt['original_swift_relative_path']
        elif name == 'PrivacyInfo.xcprivacy':
            relative = 'Sources/MarmotKit/Resources/PrivacyInfo.xcprivacy'
        else:
            require(name.startswith('MarmotKit.xcframework/'), 'closed-qualified-sdk-root-member')
            relative = 'Artifacts/' + name
            native.add(name)
        require(digest(regular(relative)) == expected_digest, 'entire-qualified-sdk-file-digest')
        frozen[name] = expected_digest
    framework = package / 'Artifacts/MarmotKit.xcframework'
    actual_native = set()
    for path in framework.rglob('*'):
        require(not path.is_symlink(), 'installed-native-sdk-symlink-refused')
        if path.is_file():
            actual_native.add('MarmotKit.xcframework/' + path.relative_to(framework).as_posix())
    require(actual_native == native, 'complete-installed-native-sdk-inventory')
    slices = ('macos-arm64',) if platform == 'macos' else ('ios-arm64', 'ios-arm64-simulator')
    required = {'MarmotKit.xcframework/' + part + '/' + leaf for part in slices
                for leaf in ('libmarmot_uniffi.a', 'Headers/marmot_uniffiFFI.h', 'Headers/module.modulemap')}
    require(required <= native and len([name for name in native if name.endswith('.a')]) == len(slices),
                   'required-qualified-native-sdk-inputs')
    original_swift = regular(receipt['original_swift_relative_path']).read_text()
    normalized = ('\n'.join(line.rstrip() for line in original_swift.splitlines()) + '\n').encode()
    installed = regular('Sources/MarmotKit/MarmotKit.swift')
    require(installed.read_bytes() == normalized and digest(installed) == manifest['installed_swift_sha256'],
                   'exact-installed-normalized-sdk-swift')
    for name in ('MARMOT_VERSION', 'Package.swift', 'Sources/MarmotKit/MarmotKit.swift',
                 'Sources/MarmotKit/MarmotKitVersion.swift'):
        frozen[name] = digest(regular(name))
    return frozen


def selected_plan(original, target_name, selector, environment):
    plan = copy.deepcopy(original)
    if 'TestConfigurations' in plan:
        for configuration in plan['TestConfigurations']:
            targets = [target for target in configuration['TestTargets']
                       if target.get('BlueprintName') == target_name or target.get('TargetName') == target_name]
            if len(targets) != 1:
                raise ValueError('Exactly one selected unit target required')
            configuration['TestTargets'] = targets
            target = targets[0]
            target['OnlyTestIdentifiers'] = [selector]
            target.pop('SkipTestIdentifiers', None)
            target.setdefault('EnvironmentVariables', {}).update(environment)
    else:
        if target_name not in plan:
            raise ValueError('Expected existing unit test target')
        target = plan[target_name]
        target['OnlyTestIdentifiers'] = [selector]
        target.pop('SkipTestIdentifiers', None)
        target.setdefault('EnvironmentVariables', {}).update(environment)
        plan = {target_name: target, '__xctestrun_metadata__': plan['__xctestrun_metadata__']}
    return plan


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--platform', choices=SELECTORS, required=True)
    parser.add_argument('--paired-direct-mutation', choices=paired_direct_mutation.MODES)
    for name in ('source', 'sdk-package', 'products', 'xctestrun', 'environment', 'prefix', 'result-bundle'):
        parser.add_argument('--' + name, type=Path, required=True)
    for name in ('source-commit', 'sdk-source', 'selector', 'destination', 'developer-dir'):
        parser.add_argument('--' + name, required=True)
    args = parser.parse_args()
    if args.paired_direct_mutation and args.selector != paired_direct_mutation.SELECTOR:
        raise ValueError('Named direct mutation requires exact paired-direct unit selector')
    os.umask(0o077)
    if os.environ.get('GITHUB_ACTIONS') != 'true' or args.selector not in SELECTORS[args.platform]:
        raise ValueError('Exact existing hosted unit test required')
    if (args.environment.stat().st_mode & 0o777 != 0o600 or args.result_bundle.exists()
            or any(args.prefix.parent.glob(args.prefix.name + '-*'))):
        raise ValueError('Private environment and fresh outputs required')
    source = args.source.resolve(strict=True)
    head = subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=source, text=True).strip()
    if head != args.source_commit:
        raise ValueError('Actual app source commit mismatch')
    args.sdk_package = args.sdk_package.resolve(strict=True)
    expected_package = 'Packages/MarmotKit' if args.platform == 'ios-simulator' else 'Vendored/MarmotKit'
    if args.sdk_package != (source / expected_package).resolve(strict=True):
        raise ValueError('Expected the selected app package')
    sdk = json.loads((args.sdk_package / 'LOCAL_BUILD.json').read_text())
    if (sdk['source_sha'] != sdk['builder_sha'] or sdk['source_sha'] != args.sdk_source
            or str(sdk['workflow_run_id']) != os.environ['SDK_RUN_ID']
            or sdk['qualification_receipt']['platform'] != ('ios' if args.platform == 'ios-simulator' else 'macos')
            or sdk['features'] != ['otlp-export', 'product-analytics-export', 'experimental-device-sync']):
        raise ValueError('Matching experimental app SDK required')
    source_inputs = freeze_source(source, head, args.sdk_package, args.paired_direct_mutation)
    sdk_inputs = freeze_sdk(args.sdk_package, sdk)
    environment = json.loads(args.environment.read_text())
    if (set(environment) - ENVIRONMENT_KEYS or any(not isinstance(v, str) for v in environment.values())
            or any(environment.get(key) != os.environ.get(key) for key in ('GITHUB_ACTIONS', 'GITHUB_RUN_ID'))
            or environment.get('WN_NATIVE_ACCEPTANCE_SDK_SOURCE') != args.sdk_source
            or environment.get('WN_NATIVE_ACCEPTANCE_SDK_RUN_ID') != os.environ['SDK_RUN_ID']):
        raise ValueError('Unexpected fixture environment')
    products = args.products.resolve(strict=True)
    original_plan = args.xctestrun.resolve(strict=True)
    original_plan.relative_to(products)
    if args.platform == 'ios-simulator':
        if not args.destination.startswith('platform=iOS Simulator,id='):
            raise ValueError('Explicit simulator destination required')
        device = args.destination.split('id=', 1)[1]
        inventory = json.loads(subprocess.check_output(['xcrun', 'simctl', 'list', 'devices', '--json'], text=True))
        matches = [row for rows in inventory['devices'].values() for row in rows if row['udid'] == device]
        if len(matches) != 1 or matches[0]['name'] != 'WN-Upstream-UI-' + os.environ['GITHUB_RUN_ID']:
            raise ValueError('Fresh job-owned simulator required')
    elif args.destination != 'platform=macOS,arch=arm64':
        raise ValueError('Explicit native Mac destination required')
    target = 'whitenoise-iosTests' if args.platform == 'ios-simulator' else 'whitenoise-macTests'
    plan = selected_plan(plistlib.loads(original_plan.read_bytes()), target, args.selector, environment)
    plan_path = products / (args.prefix.name + '-unit.xctestrun')
    with plan_path.open('xb') as output:
        output.write(plistlib.dumps(plan))
    configuration = 'Debug-Staging-iphonesimulator' if args.platform == 'ios-simulator' else 'Debug'
    slice_name = 'ios-arm64-simulator' if args.platform == 'ios-simulator' else 'macos-arm64'
    compiled = {
        'archive': (products / configuration / 'libmarmot_uniffi.a',
                    'MarmotKit.xcframework/' + slice_name + '/libmarmot_uniffi.a'),
        'header': (products / configuration / 'include/marmot_uniffiFFI.h',
                   'MarmotKit.xcframework/' + slice_name + '/Headers/marmot_uniffiFFI.h'),
    }
    compiled_hashes = {}
    for label, (path, sdk_name) in compiled.items():
        actual = digest(path)
        if actual != sdk_inputs[sdk_name]:
            raise ValueError('Compiled native ' + label + ' differs from the matching SDK')
        compiled_hashes[label] = actual
    # Compilation and its input receipt belong to the calling CI build step.
    # Freeze its prebuilt products here to detect mutation during execution.
    frozen = {str(path.relative_to(products)): digest(path)
              for path in products.rglob('*') if path.is_file()}
    plan_hash = digest(original_plan)
    run_plan_hash = digest(plan_path)
    command = ['xcodebuild', 'test-without-building', '-xctestrun', str(plan_path),
               '-destination', args.destination, '-parallel-testing-enabled', 'NO',
               '-resultBundlePath', str(args.result_bundle)]
    report = {'source_commit': head, 'sdk_source': args.sdk_source, 'sdk_run_id': os.environ['SDK_RUN_ID'],
              'selector': args.selector, 'platform': args.platform,
              'intentional_source_mutation': paired_direct_mutation.identity('ios' if args.platform == 'ios-simulator' else 'macos', args.paired_direct_mutation), 'prebuilt_product_count': len(frozen),
              'original_plan_sha256': plan_hash, 'run_plan_sha256': run_plan_hash,
              'source_inputs_sha256': hashlib.sha256(json.dumps(source_inputs, sort_keys=True).encode()).hexdigest(),
              'sdk_inputs': sdk_inputs, 'compiled_native_inputs': compiled_hashes,
              'passed': 0, 'scope': 'Existing selected app test against prebuilt products; matching compilation receipt remains required.'}
    started = time.monotonic()
    process = None
    try:
        with Path(str(args.prefix) + '-private.log').open('x') as log:
            process = subprocess.Popen(command, cwd=source, env=dict(os.environ, DEVELOPER_DIR=args.developer_dir),
                                       stdout=log, stderr=subprocess.STDOUT, start_new_session=True)
            report['exit_code'] = process.wait(timeout=600)
    except (OSError, subprocess.SubprocessError) as error:
        report['runner_error_category'] = type(error).__name__
    finally:
        if process is not None and process.poll() is None:
            os.killpg(process.pid, signal.SIGTERM)
            try:
                process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                os.killpg(process.pid, signal.SIGKILL)
                process.wait(timeout=10)
            report['runner_error_category'] = 'OwnedRunnerRequiredTermination'
        report['seconds'] = round(time.monotonic() - started, 3)
        try:
            report['source_unchanged'] = freeze_source(source, head, args.sdk_package, args.paired_direct_mutation) == source_inputs
            report['sdk_unchanged'] = freeze_sdk(args.sdk_package, sdk) == sdk_inputs
        except (OSError, ValueError, subprocess.SubprocessError):
            report['source_unchanged'] = report['sdk_unchanged'] = False
        report['products_unchanged'] = frozen == {
            str(path.relative_to(products)): digest(path) for path in products.rglob('*') if path.is_file()}
        report['plans_unchanged'] = digest(original_plan) == plan_hash and digest(plan_path) == run_plan_hash
        if args.result_bundle.exists():
            try:
                raw = json.loads(subprocess.check_output(['xcrun', 'xcresulttool', 'get', 'test-results', 'summary',
                                                          '--path', str(args.result_bundle)], text=True))
                fields = ('totalTestCount', 'passedTests', 'failedTests', 'skippedTests')
                if any(type(raw.get(key)) is not int or raw[key] < 0 for key in fields):
                    raise ValueError('Native count schema unavailable')
                report['summary'] = {key: raw[key] for key in ('result',) + fields if key in raw}
                report['passed'] = int(report.get('exit_code') == 0 and raw['totalTestCount'] == raw['passedTests'] == 1
                    and raw['failedTests'] == raw['skippedTests'] == 0 and report['products_unchanged']
                    and report['plans_unchanged'] and report['source_unchanged'] and report['sdk_unchanged']
                    and 'runner_error_category' not in report)
            except (OSError, ValueError, subprocess.SubprocessError) as error:
                report['runner_error_category'] = type(error).__name__
        with Path(str(args.prefix) + '-result.json').open('x') as output:
            json.dump(report, output, indent=2)
            output.write('\n')
    return 0 if report['passed'] == 1 else 1


if __name__ == '__main__':
    raise SystemExit(main())
