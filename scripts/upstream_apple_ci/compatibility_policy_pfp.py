"""Remote current-SDK compatibility P/F/P, using the already installed cohort."""
import argparse
from contextlib import contextmanager
import importlib.util
import hashlib
import shutil
import json
import os
import plistlib
from pathlib import Path, PurePosixPath
import re

from sdk_profiles import validate_provenance, release_id
import signal
import socket
import stat
import subprocess
import sys
import time
from urllib.parse import parse_qs, unquote, urlsplit

import compatibility_policy as policy
import factory_xcresult as xcresult
from factory_semantic_runner import ExactSource, context, invoke
from summarize import export_metadata, export_tests, summary_counts, test_inventory

HERE = Path(__file__).resolve().parent


def load(name, filename):
    spec = importlib.util.spec_from_file_location(name, HERE / filename)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


cohort = load('compatibility_app_cohort', 'app-sdk-cohort.py')
def file_sha(path):
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def sdk_state(package, manifest):
    """Freeze the authenticated full package inventory, not the sparse release artifacts."""
    policy.require(package.is_absolute() and package.resolve(strict=True) == package,
                   'physical-installed-sdk-root')
    def regular(relative):
        path = package / relative
        for item in (path, *path.parents):
            policy.require(not item.is_symlink(), 'installed-sdk-symlink-refused')
            if item == package:
                break
        policy.require(path.is_file(), 'installed-sdk-file-required')
        return path

    policy.require(json.loads(regular('LOCAL_BUILD.json').read_text()) == manifest,
                   'installed-sdk-manifest-unchanged')
    receipt = manifest['qualification_receipt']
    policy.require(type(receipt) is dict and set(receipt) == {
        'qualification_json', 'qualification_sha256', 'manifest_json', 'manifest_sha256',
        'platform', 'bundle', 'bundle_sha256', 'original_swift_relative_path'},
        'closed-installed-qualification-receipt')
    raw_q = receipt['qualification_json'].encode('utf-8')
    raw_manifest = receipt['manifest_json'].encode('utf-8')
    policy.require(len(raw_q) <= 2 * 1024**2 and len(raw_manifest) <= 256 * 1024,
                   'bounded-installed-qualification-receipt')
    policy.require(policy.sha(raw_q) == receipt['qualification_sha256']
                   and policy.sha(raw_manifest) == receipt['manifest_sha256'],
                   'installed-qualification-bytes-authenticated')
    proof = json.loads(raw_q)
    original = json.loads(raw_manifest)
    profile, source, run = manifest['sdk_profile'], manifest['source_sha'], manifest['workflow_run_id']
    validate_provenance(proof, profile, source, run)
    policy.require(proof.get('sdk_profile') == profile and manifest['builder_sha'] == source
                   and manifest['features'] == cohort.FEATURES[profile], 'exact-installed-sdk-profile')
    platform = receipt['platform']
    policy.require(platform in ('macos', 'ios'), 'closed-installed-sdk-platform')
    record = proof['platforms'][platform]
    policy.require(record['manifest'] == original and original['source_sha'] == original['builder_sha'] == source,
                   'exact-qualified-package-manifest')
    policy.require(receipt['bundle'] == record['bundle']
                   == 'marmotkit-' + platform + '-' + release_id(profile, source) + '.zip'
                   and receipt['bundle_sha256'] == record['sha256'], 'exact-qualified-platform-bundle')
    expected = original | dict(uniffi_version=proof['uniffi_version'], sdk_profile=profile,
        installed_swift_sha256=manifest['installed_swift_sha256'], workflow_run_id=run,
        installation='Ephemeral hosted CI overlay; never commit', qualification_receipt=receipt)
    policy.require(manifest == expected, 'exact-installed-package-metadata')
    files = record['files']
    policy.require(type(files) is dict and 0 < len(files) <= 256 and {
        'MarmotKit.swift', 'PrivacyInfo.xcprivacy', 'MarmotKit.xcframework/Info.plist'} <= set(files),
        'complete-qualified-package-inventory')
    policy.require(receipt['original_swift_relative_path'] == 'LOCAL_BUILD_INPUTS/MarmotKit.swift',
                   'exact-original-sdk-swift-path')
    frozen = {'LOCAL_BUILD.json': file_sha(regular('LOCAL_BUILD.json'))}
    native = set()
    for name, digest in files.items():
        policy.require(type(name) is str and type(digest) is str and re.fullmatch('[0-9a-f]{64}', digest),
                       'typed-qualified-sdk-file-digest')
        path_name = PurePosixPath(name)
        policy.require(not path_name.is_absolute() and '..' not in path_name.parts and str(path_name) == name,
                       'canonical-qualified-sdk-file-path')
        if name == 'MarmotKit.swift':
            relative = receipt['original_swift_relative_path']
        elif name == 'PrivacyInfo.xcprivacy':
            relative = 'Sources/MarmotKit/Resources/PrivacyInfo.xcprivacy'
        else:
            policy.require(name.startswith('MarmotKit.xcframework/'), 'closed-qualified-sdk-root-member')
            relative = 'Artifacts/' + name
            native.add(name)
        policy.require(file_sha(regular(relative)) == digest, 'entire-qualified-sdk-file-digest')
        frozen[name] = digest
    framework = package / 'Artifacts/MarmotKit.xcframework'
    actual_native = set()
    for path in framework.rglob('*'):
        policy.require(not path.is_symlink(), 'installed-native-sdk-symlink-refused')
        if path.is_file():
            actual_native.add('MarmotKit.xcframework/' + path.relative_to(framework).as_posix())
    policy.require(actual_native == native, 'complete-installed-native-sdk-inventory')
    slices = ('macos-arm64',) if platform == 'macos' else ('ios-arm64', 'ios-arm64-simulator')
    required = {'MarmotKit.xcframework/' + part + '/' + leaf for part in slices
                for leaf in ('libmarmot_uniffi.a', 'Headers/marmot_uniffiFFI.h', 'Headers/module.modulemap')}
    policy.require(required <= native and len([name for name in native if name.endswith('.a')]) == len(slices),
                   'required-qualified-native-sdk-inputs')
    original_swift = regular(receipt['original_swift_relative_path']).read_text()
    normalized = ('\n'.join(line.rstrip() for line in original_swift.splitlines()) + '\n').encode()
    installed = regular('Sources/MarmotKit/MarmotKit.swift')
    policy.require(installed.read_bytes() == normalized and file_sha(installed) == manifest['installed_swift_sha256'],
                   'exact-installed-normalized-sdk-swift')
    for name in ('MARMOT_VERSION', 'Package.swift', 'Sources/MarmotKit/MarmotKit.swift',
                 'Sources/MarmotKit/MarmotKitVersion.swift'):
        frozen[name] = file_sha(regular(name))
    return frozen


def source_state(app):
    names = cohort.git_output(app, 'ls-files', '-z', '--cached', '--others', '--exclude-standard').decode().split('\0')
    result = {}
    for name in filter(None, names):
        path = app / name
        info = path.lstat()
        digest = policy.sha(os.readlink(path).encode()) if path.is_symlink() else file_sha(path)
        result[name] = [digest, stat.S_IMODE(info.st_mode)]
    return {'HEAD': context(app)['HEAD'], 'index': context(app)['index'], 'files': result}


def products_state(products):
    return {str(p.relative_to(products)): [file_sha(p), stat.S_IMODE(p.lstat().st_mode)]
            for p in products.rglob('*') if p.is_file()}


def compiler_sites(rows, app, tracked):
    policy.require(len(rows) <= 2048, 'bounded-entire-compiler-site-inventory')
    result = []
    known = {'Swift Compiler Error', 'Swift Compiler Warning', 'Semantic Issue', 'Build System Failure'}
    for entry in rows:
        raw = entry['raw']
        row = {'inventory': entry['inventory'], 'raw_sha256': policy.sha(json.dumps(raw, sort_keys=True).encode()),
               'kind': 'unclassified-compiler-issue', 'file': None, 'line': None, 'column': None}
        try:
            kind = xcresult.scalar(raw['issueType'])
            if kind in known: row['kind'] = kind
            url = urlsplit(xcresult.scalar(raw['documentLocationInCreatingWorkspace']['url']))
            path = Path(unquote(url.path)).resolve(strict=True)
            relative = str(path.relative_to(app))
            if url.scheme == 'file' and not url.query and relative in tracked:
                row['line'], row['column'] = xcresult.location(raw, path)
                row['file'] = relative
        except (ValueError, KeyError, TypeError, OSError):
            pass  # Unknown stays unknown; this nonempty compiler row still forbids qualification.
        result.append(row)
    return result


def unit_command_diagnostics(path):
    """Supplemental bounded CLI facts; never export arbitrary error messages."""
    cap = 2 * 1024**2
    report = {'status': 'unavailable', 'classification_credit': False,
              'log_complete': False, 'error_rows': []}
    try:
        with path.open('rb') as stream:
            captured = stream.read(cap + 1)
        complete = len(captured) <= cap
        raw = captured[:cap]
        report.update(log_bytes=path.stat().st_size, captured_bytes=len(raw),
                      captured_sha256=policy.sha(raw), log_complete=complete)
        text = raw.decode('utf-8', errors='strict')
        flags = ('-test-iterations', '-parallel-testing-enabled', '-only-testing', '-testPlan',
                 '-project', '-scheme', '-configuration', '-destination', '-derivedDataPath',
                 '-jobs', '-resultBundlePath', '-retry-tests-on-failure', '-run-tests-until-failure',
                 'OTHER_SWIFT_FLAGS', 'TEST_HOST', 'CODE_SIGNING_ALLOWED', 'test-without-building')
        phrases = {'invalid option': 'invalid-option', 'unknown option': 'unknown-option',
                   'unrecognized option': 'unrecognized-option', 'cannot be used': 'cannot-be-used',
                   'not supported': 'not-supported', 'requires': 'requires', 'must be': 'must-be',
                   'more than once': 'more-than-once', 'does not exist': 'does-not-exist',
                   'does not contain': 'does-not-contain', 'is not a valid': 'not-valid',
                   'repetition': 'repetition', 'iteration': 'iteration',
                   'greater than 1': 'greater-than-one', 'at least 2': 'at-least-two',
                   'greater than zero': 'greater-than-zero'}
        overflow = False
        for line in text.splitlines():
            clean = re.sub(r'\x1b\[[0-9;]*m', '', line)
            match = re.fullmatch(r'[ \t]{0,8}xcodebuild: error: (.{1,4096})', clean)
            if match is None:
                continue
            if len(report['error_rows']) == 16:
                overflow = True
                break
            message = match.group(1)
            present = [flag for flag in flags if re.search(r'(?<![A-Za-z0-9_-])' + re.escape(flag)
                       + r'(?![A-Za-z0-9_-])', message)]
            fragments = sorted(label for phrase, label in phrases.items()
                               if re.search(r'(?<![A-Za-z0-9_])' + re.escape(phrase)
                                            + r'(?![A-Za-z0-9_])', message.lower()))
            # These are observed fixed tokens, not a diagnosis inferred from a flag.
            report['error_rows'].append({'message_sha256': policy.sha(message.encode()),
                'category': 'xcodebuild-error', 'source_owned_tokens': present, 'static_fragments': fragments})
        report.update(status='observed', error_rows_complete=complete and not overflow,
                      error_rows_truncated=overflow)
    except (OSError, UnicodeError):
        report['reason'] = 'private-command-log-unavailable-or-invalid-utf8'
    return report


def selected_identity(tree, case, observed):
    inventory = test_inventory(tree, observed)
    policy.require(inventory['status'] == 'complete' and inventory['unknown_nodes'] == 0,
                   'complete-exact-test-inventory')
    found = []
    def walk(value):
        if type(value) is dict:
            if value.get('nodeType') == 'Test Case':
                found.append(value.get('nodeIdentifier', value.get('testIdentifier')))
            for child in value.values(): walk(child)
        elif type(value) is list:
            for child in value: walk(child)
    walk(tree)
    policy.require(len(found) == 1 and found[0] in case['identifier_aliases'], 'exact-selected-test-owner')
    return {'status': 'complete', 'selected': case['selector'], 'actual_identifier': found[0]}


@contextmanager
def relay(folder, environment, proof):
    ios = Path('ios').resolve(strict=True)
    policy.require(cohort.git_output(ios, 'rev-parse', 'HEAD').decode().strip() == os.environ['IOS_SHA'],
                   'exact-owned-relay-source')
    binary = ios / 'build/TestRelay/debug/white-noise-sync-test-relay'
    proof['relay_binary_sha256'] = file_sha(binary)
    with socket.socket() as listener:
        listener.bind(('127.0.0.1', 18181))
    process = None
    try:
        with (folder / 'relay-private.log').open('xb') as log:
            process = subprocess.Popen([str(binary), '--port', '18181'], stdout=log, stderr=subprocess.STDOUT)
            deadline = time.monotonic() + 15
            while True:
                policy.require(process.poll() is None, 'owned-relay-stays-live')
                with (folder / 'relay-private.log').open('rb') as stream:
                    first = stream.read(256).splitlines()
                if first and first[0].removesuffix(b'/') == b'ws://127.0.0.1:18181': break
                policy.require(time.monotonic() < deadline, 'owned-relay-readiness-deadline')
                time.sleep(0.05)
            code = invoke([sys.executable, str(ios / 'scripts/test-relay/smoke.py'), '--port', '18181'],
                          folder / 'relay-smoke-private.log', environment=environment, timeout=30)
            policy.require(code == 0 and process.poll() is None, 'owned-relay-smoke')
            environment['TEST_RUNNER_WN_NATIVE_TEST_RELAY_URL'] = 'ws://127.0.0.1:18181'
            yield
            policy.require(process.poll() is None, 'owned-relay-lifetime')
    finally:
        if process is not None:
            forced = False
            if process.poll() is None: process.send_signal(signal.SIGINT)
            try: process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                forced = True
                process.kill()
                process.wait(timeout=10)
            proof['relay_cleanup_passed'] = not forced and process.returncode == 0


def settings(app, platform, temp, flags):
    derived = temp / ('final-mac-derived-data' if platform == 'macos' else 'final-ios-derived-data')
    if platform == 'macos':
        host = derived / 'Build/Products/Debug/White Noise Unit Host.app'
        args = ['-project', str(app / 'whitenoise-mac.xcodeproj'), '-scheme', 'whitenoise-mac',
                '-configuration', 'Debug', '-testPlan', 'PR', '-destination', 'platform=macOS,arch=arm64',
                'WN_APP_BUNDLE_IDENTIFIER=dev.ipf.whitenoise.mac.tests',
                'WN_APP_PRODUCT_NAME=White Noise Unit Host', 'WN_APP_DISPLAY_NAME=White Noise Unit Host',
                'WN_APP_URL_SCHEME=marmot-tests', 'TEST_HOST=' + str(host / 'Contents/MacOS/White Noise Unit Host'),
                'CODE_SIGNING_ALLOWED=NO']
    else:
        destination = os.environ['WN_TEST_DESTINATION']
        policy.require(destination.startswith('platform=iOS Simulator,'), 'existing-explicit-ios-destination')
        args = ['-project', str(app / 'whitenoise-ios.xcodeproj'), '-scheme', 'Whitenoise (Staging)',
                '-destination', destination, '-skipPackagePluginValidation', '-skipMacroValidation',
                '-clonedSourcePackagesDirPath', str(temp / 'final-ios-packages'), 'ONLY_ACTIVE_ARCH=YES',
                'CODE_SIGN_STYLE=Manual', 'DEVELOPMENT_TEAM=', 'PROVISIONING_PROFILE_SPECIFIER=',
                'CODE_SIGN_IDENTITY=-', 'CODE_SIGNING_ALLOWED=YES', 'COMPILER_INDEX_STORE_ENABLE=NO']
    return args + ['-derivedDataPath', str(derived), '-jobs', '2'] + flags, derived / 'Build/Products'


def main(args):
    policy.require(os.environ.get('GITHUB_ACTIONS') == 'true' and os.environ.get('RUNNER_OS') == 'macOS'
                   and args.profile in ('default', 'experimental'), 'remote-current-app-cohort-only')
    app = Path('mac' if args.platform == 'macos' else 'ios').resolve(strict=True)
    admitted = json.loads(args.cohort_evidence.read_text())
    binding = policy.cases(args.platform)
    policy.require(admitted['app_sha'] == binding['commit']
                   and admitted['profile'] == args.profile and admitted['platform'] == args.platform
                   and admitted['tools_sha'] == os.environ['GITHUB_SHA'], 'existing-exact-cohort-required')
    policy.require(cohort.physical_tracked_snapshot(app) == admitted['prepared_tracked_snapshot'],
                   'original-prepared-source-modes-required')
    environment = cohort.environment_for(args.profile, admitted['sdk_source'], admitted['sdk_run_id'])
    flags = cohort.guard_settings(app, args.profile, environment)
    policy.require(flags == admitted['validated_build_settings'], 'same-verified-compiler-settings')
    package = app / ('Vendored/MarmotKit' if args.platform == 'macos' else 'Packages/MarmotKit')
    sdk_manifest = json.loads((package / 'LOCAL_BUILD.json').read_text())
    policy.require(sdk_manifest['source_sha'] == sdk_manifest['builder_sha'] == admitted['sdk_source']
                   and str(sdk_manifest['workflow_run_id']) == admitted['sdk_run_id']
                   and sdk_manifest['features'] == cohort.FEATURES[args.profile], 'exact-installed-profile-sdk')
    policy.require(sdk_manifest['qualification_receipt']['qualification_sha256'] == admitted['qualification_sha256']
                   and sdk_manifest['qualification_receipt']['platform'] == args.platform,
                   'admitted-installed-sdk-qualification-anchor')
    sdk = sdk_state(package, sdk_manifest)
    initial = source_state(app)
    temp = Path(os.environ['RUNNER_TEMP'])
    work = temp / ('compatibility-policy-' + args.platform + '-' + args.profile)
    policy.require(not work.exists() and not args.output.exists(), 'fresh-no-rerun-compatibility-output')
    work.mkdir(mode=0o700)
    proof = {'app_sha': binding['commit'], 'platform': args.platform, 'profile': args.profile,
             'sdk_source': admitted['sdk_source'], 'sdk_run_id': admitted['sdk_run_id'],
             'tools_sha': admitted['tools_sha'], 'bindings_sha256': policy.sha((HERE / 'compatibility-policy-sources.json').read_bytes()),
             'passed': False, 'source_restored': False, 'relay_cleanup_passed': False, 'platform_cleanup_passed': args.platform != 'macos', 'phases': []}
    def save():
        proof['totals'] = policy.totals(proof['phases'])
        args.output.write_text(json.dumps(proof, indent=2) + '\n')
    held = None
    original = None
    previous = {}
    def interrupt(signum, frame): raise KeyboardInterrupt(signum)
    try:
        for sig in (signal.SIGINT, signal.SIGTERM): previous[sig] = signal.signal(sig, interrupt)
        save()
        with relay(work, environment, proof):
            command_settings, products = settings(app, args.platform, temp, flags)
            for case in binding['cases']:
                original = cohort.git_output(app, 'show', binding['commit'] + ':' + case['source'])
                mutant = policy.transform(original, case)
                test = app / case['test_source']
                policy.source_sites(test.read_bytes(), case)
                held = ExactSource(app, app / case['source'], original)
                try:
                    for name in ('baseline', 'mutant', 'restored'):
                        intentional = name == 'mutant'
                        wanted = mutant if intentional else original
                        if held.current != wanted: held.write(held.current, wanted)
                        expected = {**initial, 'files': dict(initial['files'])}
                        expected['files'][case['source']] = [policy.sha(wanted), initial['files'][case['source']][1]]
                        held.verify(wanted)
                        policy.require(source_state(app) == expected and sdk_state(package, sdk_manifest) == sdk,
                                       'all-exact-source-and-sdk-before-phase')
                        row = {'label': case['id'] + '/' + name, 'source_sha256': policy.sha(wanted),
                               'test_sha256': policy.sha(test.read_bytes()), 'unit_invoked': False, 'qualified': False}
                        proof['phases'].append(row)
                        folder = work / row['label'].replace('/', '-')
                        folder.mkdir(mode=0o700)
                        build = folder / 'build.xcresult'
                        policy.require(shutil.disk_usage(temp).free >= 8 * 1024**3, 'eight-gib-build-reserve')
                        row['build_exit_code'] = invoke(['xcodebuild', 'build-for-testing'] + command_settings
                            + ['-resultBundlePath', str(build)], folder / 'build-private.log', environment=environment, timeout=1900)
                        save()
                        policy.require((folder / 'build-private.log').stat().st_size <= 32 * 1024**2, 'bounded-private-build-log')
                        build_audit = {}
                        row['build_inventory_audit'] = build_audit
                        build_issues = xcresult.read(build, source=test, relative=case['test_source'], audit=build_audit)
                        row['compiler_build_count'] = len(build_issues['compiler'])
                        row['compiler_build_sites'] = compiler_sites(build_issues['compiler'], app, initial['files'])
                        save()
                        policy.require(row['build_exit_code'] == 0 and not build_issues['compiler']
                                       and not build_issues['failures'], 'entire-compiler-build-must-pass')
                        configuration = 'Debug' if args.platform == 'macos' else 'Debug-Staging-iphonesimulator'
                        sdk_slice = 'macos-arm64' if args.platform == 'macos' else 'ios-arm64-simulator'
                        row['qualified_input_presence'] = {}
                        for label, file, native in [('archive', 'libmarmot_uniffi.a', 'libmarmot_uniffi.a'),
                                ('header', 'include/marmot_uniffiFFI.h', 'Headers/marmot_uniffiFFI.h')]:
                            row['stage'] = 'compiled-' + label
                            key = 'MarmotKit.xcframework/' + sdk_slice + '/' + native
                            row['qualified_input_presence'][label] = key in sdk
                            save()
                            policy.require(key in sdk, 'qualified-compiled-' + label + '-required')
                            policy.require(file_sha(products / configuration / file) == sdk[key],
                                           'compiled-sdk-input-matches')
                        if args.platform == 'macos':
                            host = products / 'Debug/White Noise Unit Host.app'
                            row['stage'] = 'temporary-host-identity'
                            identity = plistlib.loads((host / 'Contents/Info.plist').read_bytes())
                            row['host_identity_key_present'] = 'CFBundleIdentifier' in identity
                            save()
                            policy.require(row['host_identity_key_present'], 'temporary-host-identity-key-required')
                            policy.require(identity['CFBundleIdentifier'] == 'dev.ipf.whitenoise.mac.tests',
                                           'exact-temporary-unit-host-identity')
                        frozen_products = products_state(products)
                        policy.require(frozen_products and len(list(products.glob('*.xctestrun'))) == 1, 'actual-compiled-test-products')
                        result = folder / 'unit.xcresult'
                        row['unit_invoked'] = True
                        save()
                        try:
                            row['unit_exit_code'] = invoke(['xcodebuild', 'test-without-building'] + command_settings
                                + ['-parallel-testing-enabled', 'NO',
                                   '-only-testing:' + case['selector'], '-resultBundlePath', str(result)],
                                folder / 'unit-private.log', environment=environment, timeout=1200)
                        finally:
                            row['unit_command_diagnostics'] = unit_command_diagnostics(folder / 'unit-private.log')
                            save()
                            row['counts'] = None
                            if result.exists():
                                try:
                                    observed = export_metadata(['xcrun', 'xcresulttool', 'get', 'test-results', 'summary', '--path', str(result)])
                                    row['counts'] = summary_counts(observed)
                                except Exception as summary_error:
                                    # Summary rejection must not hide independent legacy issue evidence.
                                    row['summary_error_kind'] = type(summary_error).__name__
                            else:
                                row['summary_error_kind'] = 'ResultBundleUnavailable'
                            save()
                        policy.require((folder / 'unit-private.log').stat().st_size <= 32 * 1024**2, 'bounded-private-unit-log')
                        runtime_audit = {}
                        row['runtime_inventory_audit'] = runtime_audit
                        issues = xcresult.read(result, source=test, relative=case['test_source'], audit=runtime_audit)
                        row['compiler_body_count'] = len(issues['compiler'])
                        row['compiler_body_sites'] = compiler_sites(issues['compiler'], app, initial['files'])
                        save()
                        row['inventory'] = selected_identity(export_tests(result), case, row.get('counts'))
                        row['issue_evidence'] = policy.runtime(case, row.get('counts'), build_issues['compiler'],
                                                             issues['compiler'], issues['failures'], intentional)
                        policy.require(row['unit_exit_code'] == (65 if intentional else 0), 'exact-xcode-runtime-status')
                        held.verify(wanted)
                        policy.require(source_state(app) == expected and products_state(products) == frozen_products
                                       and sdk_state(package, sdk_manifest) == sdk, 'source-sdk-products-unchanged')
                        row.update(source_sdk_products_frozen=True, source_closure_exact=True, qualified=True)
                        save()
                finally:
                    if held is not None:
                        try:
                            if held.current != original: held.write(held.current, original)
                            held.verify(original)
                        finally:
                            held.close()
                            held = None
        proof['source_restored'] = source_state(app) == initial and sdk_state(package, sdk_manifest) == sdk
        proof['passed'] = proof['source_restored'] and proof['relay_cleanup_passed']
        save()
    except (Exception, KeyboardInterrupt) as error:
        proof['passed'] = False
        proof['failure_category'] = type(error).__name__
        if isinstance(error, ValueError) and str(error).replace('-', '').isalnum():
            proof['failure_label'] = str(error)[:160]
    finally:
        for sig, handler in previous.items(): signal.signal(sig, handler)
        try:
            proof['source_restored'] = source_state(app) == initial and sdk_state(package, sdk_manifest) == sdk
        except Exception: proof['source_restored'] = False
        if args.platform == 'macos':
            try:
                host = temp / 'final-mac-derived-data/Build/Products/Debug/White Noise Unit Host.app'
                if host.exists():
                    identity = plistlib.loads((host / 'Contents/Info.plist').read_bytes())
                    policy.require(identity['CFBundleIdentifier'] == 'dev.ipf.whitenoise.mac.tests',
                                   'only-owned-temporary-host-cleanup')
                    result = subprocess.run(['/System/Library/Frameworks/CoreServices.framework/Frameworks/LaunchServices.framework/Support/lsregister', '-u', str(host)],
                                            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=20)
                    proof['platform_cleanup_passed'] = result.returncode == 0
                else:
                    proof['platform_cleanup_passed'] = not any(r.get('unit_invoked') for r in proof['phases'])
            except Exception: proof['platform_cleanup_passed'] = False
        proof['passed'] = proof['passed'] and proof['source_restored'] and proof['relay_cleanup_passed'] and proof['platform_cleanup_passed']
        save()
    if proof['passed']:
        try: policy.receipt(proof, admitted, args.platform, args.profile, admitted['tools_sha'])
        except Exception:
            proof['passed'] = False
            proof['failure_label'] = 'final-closed-compatibility-receipt'
            save()
    return 0 if proof['passed'] else 1


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--platform', choices=['macos', 'ios'], required=True)
    parser.add_argument('--profile', choices=['default', 'experimental'], required=True)
    parser.add_argument('--cohort-evidence', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    os.umask(0o077)
    raise SystemExit(main(parser.parse_args()))
