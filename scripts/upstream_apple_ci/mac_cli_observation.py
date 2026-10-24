"""One current Mac unit command observation; never strict qualification."""
import argparse
import collections
import json
import os
from pathlib import Path
import plistlib
import re
import shutil
import signal
import subprocess

import compatibility_policy_pfp as driver

policy, cohort, xcresult = driver.policy, driver.cohort, driver.xcresult
MAC = 'b8f71a6d17f934a34b5bda2243e31d3623ea7fb4'
SDK = '6b8d9ea18406a6a0f588de91bece0cf6b29ef129'
RUN = '40036892229'
IDS = ('MainActor', 'Sendable', 'Codable', 'MarmotKit', 'MarmotProtocol')


def message_facts(message, identifiers=()):
    policy.require(type(message) is str and len(message.encode()) <= 8192, 'bounded-private-compiler-message')
    lower = message.lower()
    patterns = {
        'unnecessary-await/noasync': ("no 'async' operations occur within 'await' expression",),
        'unnecessary-try/nonthrowing': ("no calls to throwing functions occur within 'try' expression",),
        'deprecated-api': ('deprecated',),
        'actor-isolation': ('actor-isolated', 'actor isolation'),
        'sendable-conformance': ('sendable',),
        'unused-value': ('was never used', 'is unused', 'result of call to'),
        'nonexhaustive-switch': ('switch must be exhaustive', 'switch covers known cases'),
        'never-mutated-variable': ('was never mutated', 'is never mutated'),
        'duplicate-switch-case': ('case is already handled', 'case has already been handled', 'duplicate case'),
        'captured-variable-concurrency': ('reference to captured var', 'mutation of captured var', 'captured var'),
        'protocol-conformance': ('conformance of', 'does not conform to protocol', 'does not conform to the'),
    }
    found = [key for key, phrases in patterns.items()
             if any(re.search(r'(?<![A-Za-z0-9_])' + re.escape(part) + r'(?![A-Za-z0-9_])', lower) for part in phrases)]
    return {'message_sha256': policy.sha(message.encode()), 'observed_categories': found or ['other-unclassified'],
            'known_identifiers': [name for name in IDS if name in identifiers
                and re.search(r'(?<![A-Za-z0-9_])' + re.escape(name) + r'(?![A-Za-z0-9_])', message)]}


def unit_command(settings, case, result):
    return ['xcodebuild', 'test-without-building'] + settings + [
        '-parallel-testing-enabled', 'NO',
        '-only-testing:' + case['selector'], '-resultBundlePath', str(result)]


def collect(bundle, app, tracked, audit):
    raw = xcresult.output(['xcrun', 'xcresulttool', 'get', 'object', '--legacy', '--format', 'json', '--path', str(bundle)])
    audit.update(inventory_sha256=policy.sha(raw), inventory_bytes=len(raw), complete=False)
    record = json.loads(raw)
    sets = xcresult.issue_sets(record)
    policy.require(type(record) is dict and 'issues' in record and sets and record['issues'] in sets,
                   'complete-actual-compiler-inventory')
    groups = [xcresult.raw_groups(value) for value in sets]
    audit['issue_inventory_counts'] = [{name: len(rows) for name, rows in group.items()} for group in groups]
    root_failures = xcresult.raw_groups(record['issues']).get('testFailureSummaries', [])
    audit['root_runtime_failure_count'] = len(root_failures)
    policy.require(len(root_failures) <= 256, 'bounded-complete-runtime-failure-cardinality')
    root_multiset = collections.Counter(json.dumps(row, sort_keys=True) for row in root_failures)
    for group in groups:
        actual = collections.Counter(json.dumps(row, sort_keys=True) for row in group.get('testFailureSummaries', []))
        policy.require(not (actual - root_multiset), 'root-contains-all-runtime-failures')
    audit['failure_multisets_complete'] = True
    rows = [{'inventory': name, 'raw': row} for group in groups
            for name in ('analyzerWarningSummaries', 'errorSummaries', 'warningSummaries') for row in group.get(name, [])]
    audit['compiler_row_count'] = len(rows)
    audit['compiler_sites'] = driver.compiler_sites(rows, app, tracked)
    for item, entry in zip(audit['compiler_sites'], rows):
        item['message_facts_status'] = 'unknown'
        try:
            # Identifiers may be exposed only if present in the actual tracked diagnostic source.
            source = (app / item['file']).read_text() if item['file'] in tracked else ''
            identifiers = [name for name in IDS if re.search(r'(?<![A-Za-z0-9_])' + name + r'(?![A-Za-z0-9_])', source)]
            item.update(message_facts(xcresult.scalar(entry['raw']['message']), identifiers), message_facts_status='observed')
        except (ValueError, KeyError, TypeError, OSError):
            pass
    audit['compiler_error_rows'] = sum(entry['inventory'] == 'errorSummaries' for entry in rows)
    audit['complete'] = True


def main(args):
    policy.require(os.environ.get('GITHUB_ACTIONS') == 'true' and os.environ.get('RUNNER_OS') == 'macOS', 'remote-Mac-observation-only')
    app = Path('mac').resolve(strict=True)
    admitted = json.loads(args.cohort_evidence.read_text())
    binding = policy.cases('macos')
    policy.require(binding['commit'] == MAC and admitted['app_sha'] == MAC
        and admitted['sdk_source'] == SDK and admitted['sdk_run_id'] == RUN
        and admitted['profile'] == 'experimental' and admitted['platform'] == 'macos'
        and admitted['tools_sha'] == os.environ['GITHUB_SHA'], 'exact-pinned-observation-cohort')
    policy.require(cohort.physical_tracked_snapshot(app) == admitted['prepared_tracked_snapshot'], 'exact-prepared-app-source')
    environment = cohort.environment_for('experimental', SDK, RUN)
    flags = cohort.guard_settings(app, 'experimental', environment)
    policy.require(flags == admitted['validated_build_settings'], 'same-verified-compiler-settings')
    package = app / 'Vendored/MarmotKit'
    manifest = json.loads((package / 'LOCAL_BUILD.json').read_text())
    policy.require(manifest['source_sha'] == manifest['builder_sha'] == SDK and manifest['workflow_run_id'] == RUN
        and manifest['sdk_profile'] == 'experimental' and manifest['features'] == cohort.FEATURES['experimental']
        and manifest['qualification_receipt']['qualification_sha256'] == admitted['qualification_sha256']
        and manifest['qualification_receipt']['platform'] == 'macos', 'exact-admitted-installed-sdk')
    sdk, source = driver.sdk_state(package, manifest), driver.source_state(app)
    temp = Path(os.environ['RUNNER_TEMP'])
    work = temp / 'mac-cli-observation'
    policy.require(not work.exists() and not args.output.exists(), 'fresh-observation-paths')
    work.mkdir(mode=0o700)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    case = binding['cases'][0]
    policy.require(case['id'] == 'mac-cleaned-rearm', 'exact-first-original-case')
    policy.source_sites((app / case['test_source']).read_bytes(), case)
    proof = {'diagnostic_only': True, 'qualification_credit': False, 'strict_qualification_passed': False,
             'tools_sha': os.environ['GITHUB_SHA'], 'app_sha': MAC, 'sdk_source': SDK, 'sdk_run_id': RUN,
             'selector': case['selector'], 'mutations_executed': 0, 'unit_invoked': False, 'counts': None,
             'source_restored': False, 'sdk_unchanged': False, 'relay_cleanup_passed': False,
             'platform_cleanup_passed': False, 'observation_complete': False}
    def save(): args.output.write_text(json.dumps(proof, indent=2) + '\n')
    previous = {}
    def interrupt(signum, frame): raise KeyboardInterrupt(signum)
    try:
        for sig in (signal.SIGINT, signal.SIGTERM): previous[sig] = signal.signal(sig, interrupt)
        save()
        with driver.relay(work, environment, proof):
            settings, products = driver.settings(app, 'macos', temp, flags)
            policy.require(shutil.disk_usage(temp).free >= 8 * 1024**3, 'eight-gib-build-reserve')
            build = work / 'build.xcresult'
            proof['build_exit_code'] = driver.invoke(['xcodebuild', 'build-for-testing'] + settings + ['-resultBundlePath', str(build)],
                work / 'build-private.log', environment=environment, timeout=1900)
            save()
            audit = {}; proof['build_inventory'] = audit
            try: collect(build, app, source['files'], audit)
            except Exception as error: audit['collector_error_kind'] = type(error).__name__
            save()
            # No strict gate changes: nonempty warnings remain explicitly unqualified.
            # A successful build without compiler errors permits one CLI observation only.
            policy.require(proof['build_exit_code'] == 0 and audit.get('complete') is True
                and audit['compiler_error_rows'] == 0, 'successful-build-before-CLI-observation')
            configuration = products / 'Debug'
            for label, file, native in [('archive', 'libmarmot_uniffi.a', 'libmarmot_uniffi.a'),
                                       ('header', 'include/marmot_uniffiFFI.h', 'Headers/marmot_uniffiFFI.h')]:
                key = 'MarmotKit.xcframework/macos-arm64/' + native
                policy.require(key in sdk and driver.file_sha(configuration / file) == sdk[key], 'qualified-compiled-sdk-' + label)
            host = configuration / 'White Noise Unit Host.app'
            identity = plistlib.loads((host / 'Contents/Info.plist').read_bytes())
            policy.require(identity['CFBundleIdentifier'] == 'dev.ipf.whitenoise.mac.tests', 'exact-owned-host')
            frozen_products = driver.products_state(products)
            policy.require(frozen_products and len(list(products.glob('*.xctestrun'))) == 1, 'actual-compiled-test-products')
            policy.require(driver.source_state(app) == source and driver.sdk_state(package, manifest) == sdk, 'unchanged-inputs-before-unit')
            result = work / 'unit.xcresult'
            proof['unit_invoked'] = True; save()
            try:
                proof['unit_exit_code'] = driver.invoke(unit_command(settings, case, result), work / 'unit-private.log',
                    environment=environment, timeout=1200)
            finally:
                proof['unit_command_diagnostics'] = driver.unit_command_diagnostics(work / 'unit-private.log'); save()
                if result.exists():
                    try:
                        observed = driver.export_metadata(['xcrun', 'xcresulttool', 'get', 'test-results', 'summary', '--path', str(result)])
                        proof['counts'] = driver.summary_counts(observed)
                    except Exception as error: proof['summary_error_kind'] = type(error).__name__
                else: proof['summary_error_kind'] = 'ResultBundleUnavailable'
                save()
            audit = {}; proof['runtime_inventory'] = audit
            if result.exists():
                try: collect(result, app, source['files'], audit)
                except Exception as error: audit['collector_error_kind'] = type(error).__name__
                save()
                try: proof['selected_inventory'] = driver.selected_identity(driver.export_tests(result), case, proof['counts'])
                except Exception as error: proof['selection_error_kind'] = type(error).__name__
            proof['products_unchanged'] = driver.products_state(products) == frozen_products
            proof['observation_complete'] = True; save()
    except (Exception, KeyboardInterrupt) as error:
        proof['error_kind'] = type(error).__name__
    finally:
        for sig, handler in previous.items(): signal.signal(sig, handler)
        try:
            proof['source_restored'] = driver.source_state(app) == source
            proof['sdk_unchanged'] = driver.sdk_state(package, manifest) == sdk
        except Exception: pass
        try:
            host = temp / 'final-mac-derived-data/Build/Products/Debug/White Noise Unit Host.app'
            if host.exists():
                identity = plistlib.loads((host / 'Contents/Info.plist').read_bytes())
                policy.require(identity['CFBundleIdentifier'] == 'dev.ipf.whitenoise.mac.tests', 'only-owned-host-cleanup')
                code = subprocess.run(['/System/Library/Frameworks/CoreServices.framework/Frameworks/LaunchServices.framework/Support/lsregister', '-u', str(host)],
                    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=20).returncode
                proof['platform_cleanup_passed'] = code == 0
            else: proof['platform_cleanup_passed'] = not proof['unit_invoked']
        except Exception: pass
        save()
    # This observation cannot turn preexisting warnings/exit64 into a passing qualification.
    return 1


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--cohort-evidence', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    os.umask(0o077)
    raise SystemExit(main(parser.parse_args()))
