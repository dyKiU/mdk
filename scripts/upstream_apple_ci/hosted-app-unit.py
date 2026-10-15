#!/usr/bin/env python3
"""Run exactly one existing fixture test from prebuilt products; never compile."""
import argparse
import copy
import hashlib
import json
import os
from pathlib import Path
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
}
SELECTORS = {
    'macos': {
        'GenuineAutomaticAccountSwitchTests/testActualAccountsReplacePairedOwnersAndRetireBeforeRuntimeClose',
        'GenuineImportedHistoryPaneTests/testRealCommittedImportThroughSessionOwnedReaderAndHostedPane',
        'GenuineHistorySourcePickerTests/testRealRecipientsAndFreshOriginalThroughSessionOwnedModel',
        'GenuineHistorySourceTransferTests/testCompleteFreshSourceOriginalThroughAccountModelAndNativeRecipient',
        'GenuineHistoryRecipientTransferTests/testFreshRecipientOriginalThroughSessionModelAndIOSSource',
    },
    'ios-simulator': {
        'GenuineAutomaticAccountSwitchTests/testActualAccountsReplacePairedOwnersAndSceneSuspensionClosesRuntime',
        'GenuineImportedHistoryPaneTests/testRealCommittedImportThroughAccountOwnedReaderAndHostedPane',
        'GenuineHistorySourcePickerTests/testActualNativeChoicesCreateRefreshAndCancelOriginalThroughAccountOwner',
        'GenuineHistorySourceTransferTests/testCompleteFreshSourceOriginalThroughAppStateAndNativeRecipient',
    },
}


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def freeze_source(source, commit, sdk_package):
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
        if data != subprocess.check_output(['git', 'show', commit + ':' + name], cwd=source):
            raise ValueError('Non-SDK source differs from the pinned commit')
        frozen[name] = hashlib.sha256(data).hexdigest()
    return frozen


def freeze_sdk(package, manifest):
    if digest(package / 'Sources/MarmotKit/MarmotKit.swift') != manifest['installed_swift_sha256']:
        raise ValueError('Installed generated Swift differs from its verified producer record')
    frozen = {'LOCAL_BUILD.json': digest(package / 'LOCAL_BUILD.json')}
    for name, row in manifest['artifacts'].items():
        if name.startswith('MarmotKit.xcframework/'):
            if digest(package / 'Artifacts' / name) != row['sha256']:
                raise ValueError('App native SDK artifact mismatch')
            frozen[name] = row['sha256']
    for name in ('MARMOT_VERSION', 'Package.swift', 'Sources/MarmotKit/MarmotKit.swift',
                 'Sources/MarmotKit/MarmotKitVersion.swift'):
        frozen[name] = digest(package / name)
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
    for name in ('source', 'sdk-package', 'products', 'xctestrun', 'environment', 'prefix', 'result-bundle'):
        parser.add_argument('--' + name, type=Path, required=True)
    for name in ('source-commit', 'sdk-source', 'selector', 'destination', 'developer-dir'):
        parser.add_argument('--' + name, required=True)
    args = parser.parse_args()
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
            or sdk['features'] != ['otlp-export', 'product-analytics-export', 'experimental-device-sync']):
        raise ValueError('Matching experimental app SDK required')
    source_inputs = freeze_source(source, head, args.sdk_package)
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
              'selector': args.selector, 'platform': args.platform, 'prebuilt_product_count': len(frozen),
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
            report['source_unchanged'] = freeze_source(source, head, args.sdk_package) == source_inputs
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
