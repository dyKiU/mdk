#!/usr/bin/env python3
"""Stage exact-cohort hosted app acceptance; only compact aggregate reports leave CI."""
from __future__ import annotations
import argparse
from contextlib import contextmanager
from datetime import datetime, timezone
import hashlib
import fcntl
import importlib.util
import json
import math
import os
from pathlib import Path
import re
import select
import signal
import socket
import subprocess
import sys
import time

HERE = Path(__file__).resolve().parent
FEATURES = ['otlp-export', 'product-analytics-export', 'experimental-device-sync']
EXISTING_ROSTER_SELECTOR = 'GenuineAutomaticHostFactoryTests/testExistingRosterWNPAIR2RequiresSiblingApprovalAndSharesHistory'
HOST_FACTORY_SELECTORS = ('GenuineAutomaticHostFactoryTests/testForwardFactoriesShareBothPreviouslyAbsentChats', 'GenuineAutomaticHostFactoryTests/testReverseFactoriesShareBothPreviouslyAbsentChats', 'GenuineAutomaticHostFactoryTests/testActualFactoryCancellationRetiresOriginal', 'GenuineAutomaticHostFactoryTests/testActualFactoryPlatformShutdownClosesStorageAndRetiresOriginal', 'GenuineAutomaticHostFactoryTests/testLateBeginFactoryCannotAdoptAcrossAccountReplacement', 'GenuineAutomaticHostFactoryTests/testLateScanFactoryCannotAdoptAcrossAccountReplacement') + (EXISTING_ROSTER_SELECTOR,)

MODELS = {
    'macos': [
        ('paired-direct', 'paired-direct', 'GenuinePairedDirectConversationTests/testRealMarmotClientReusesPairedSourceWithoutLocalMembershipOrInvitation'),
        ('switch', 'automatic-switch', 'GenuineAutomaticAccountSwitchTests/testActualAccountsReplacePairedOwnersAndRetireBeforeRuntimeClose'),
        ('reader', 'imported-reader', 'GenuineImportedHistoryPaneTests/testRealCommittedImportThroughSessionOwnedReaderAndHostedPane'),
        ('picker', 'source-picker', 'GenuineHistorySourcePickerTests/testRealRecipientsAndFreshOriginalThroughSessionOwnedModel'),
        ('source', 'source-transfer', 'GenuineHistorySourceTransferTests/testCompleteFreshSourceOriginalThroughAccountModelAndNativeRecipient'),
        ('recipient', 'recipient-transfer', 'GenuineHistoryRecipientTransferTests/testFreshRecipientOriginalThroughSessionModelAndIOSSource'),
    ],
    'ios': [
        ('paired-direct', 'paired-direct', 'GenuinePairedDirectConversationTests/testRealMarmotClientReusesPairedSourceWithoutLocalMembershipOrInvitation'),
        ('switch', 'automatic-switch', 'GenuineAutomaticAccountSwitchTests/testActualAccountsReplacePairedOwnersAndSceneSuspensionClosesRuntime'),
        ('reader', 'imported-reader', 'GenuineImportedHistoryPaneTests/testRealCommittedImportThroughAccountOwnedReaderAndHostedPane'),
        ('picker', 'source-picker', 'GenuineHistorySourcePickerTests/testActualNativeChoicesCreateRefreshAndCancelOriginalThroughAccountOwner'),
        ('source', 'source-transfer', 'GenuineHistorySourceTransferTests/testCompleteFreshSourceOriginalThroughAppStateAndNativeRecipient'),
    ],
}
UI_CASES = {'macos': [('picker-ui', 'source-picker', 'mac-source-picker')],
            'ios': [('picker-ui', 'source-picker', 'source-picker'),
                    ('source-ui', 'source-transfer', 'source-transfer'),
                    ('approval-ui', 'recipient-transfer', 'approval')]}


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def require(condition, label):
    if not condition:
        raise ValueError(label)


def write_private(path, value, exclusive=True):
    mode = 'x' if exclusive else 'w'
    with path.open(mode) as stream:
        json.dump(value, stream, indent=2)
        stream.write('\n')


def one_pass(value):
    fields = ('totalTestCount', 'passedTests', 'failedTests', 'skippedTests')
    return (all(type(value.get(key)) is int for key in fields)
            and value.get('totalTestCount') == value.get('passedTests') == 1
            and value.get('failedTests') == value.get('skippedTests') == 0)


class Runner:
    def __init__(self, args):
        self.args = args
        self.work = args.work.resolve()
        require(args.work.is_absolute() and args.output.is_absolute()
                and not args.output.exists() and not args.output.is_relative_to(self.work), 'fresh-aggregate-output-outside-private-work-required')
        self.work.mkdir(mode=0o700, exist_ok=True)
        require(self.work.stat().st_uid == os.getuid() and self.work.stat().st_mode & 0o777 == 0o700,
                'owned-private-work-directory-required')
        self.lock_path = self.work / '.orchestrator.lock'
        self.lock = self.lock_path.open('a')
        fcntl.flock(self.lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        self.private = self.work / 'private'
        self.private.mkdir(mode=0o700, exist_ok=True)
        self.evidence = args.output.parent
        self.evidence.mkdir(mode=0o700, parents=True, exist_ok=True)
        self.state_path = self.work / 'state.json'
        self.environment = dict(os.environ, SOURCE_SHA=args.sdk_source, SDK_RUN_ID=args.sdk_run_id,
                                SDK_QUALIFICATION_JSON=str(args.packages / 'qualification.json'),
                                DEVELOPER_DIR=args.developer_dir, WN_EXPERIMENTAL_DEVICE_SYNC='1')
        os.environ.update(SOURCE_SHA=args.sdk_source, SDK_RUN_ID=args.sdk_run_id)
        qualification = json.loads((args.packages / 'qualification.json').read_text())
        trees = {platform: subprocess.check_output(['git', 'rev-parse', commit + '^{tree}'], cwd=source, text=True).strip()
                 for platform, source, commit in (('macos', args.mac_source, args.mac_commit), ('ios', args.ios_source, args.ios_commit))}
        self.cohort = {'sdk_source': args.sdk_source, 'sdk_run_id': args.sdk_run_id,
                       'mac_commit': args.mac_commit, 'ios_commit': args.ios_commit, 'app_trees': trees,
                       'sdk_tree': qualification['source_tree'],
                       'sdk_bundle_sha256': {platform: row['sha256'] for platform, row in qualification['platforms'].items()},
                       'simulator': args.simulator, 'developer_dir': args.developer_dir,
                       'github_run_id': os.environ['GITHUB_RUN_ID'], 'runner_name': os.environ['RUNNER_NAME'],
                       'qualification_sha256': digest(args.packages / 'qualification.json'),
                       'tools': {name: digest(HERE / name) for name in (
                           'run-hosted-app-acceptance.py', 'hosted-app-ui.py', 'hosted-app-unit.py',
                           'hosted-app-fixtures.py', 'build-hosted-simulator-agent.sh', 'install.py', 'sdk_profiles.py',
                           'prepare-hosted-agent.py', 'paired_direct_mutation.py', 'paired-direct-mutations.py',
                           'native/SOURCE.json', 'HOSTED-SOURCE.json')}}
        if self.state_path.exists():
            self.state = json.loads(self.state_path.read_text())
            require(self.state['cohort'] == self.cohort, 'existing-staged-cohort-must-remain-identical')
        else:
            require(set(self.work.iterdir()) == {self.private, self.lock_path} and not any(self.private.iterdir()),
                    'fresh-work-or-exact-existing-stage-required')
            self.state = {'cohort': self.cohort, 'steps': {}, 'cases': {}}
            self.save()
        self.report = {'cohort': self.cohort, 'requested_scope': args.scope, 'passed': 0,
                       'qualification_scope': ('Owner-free UI infrastructure setup: one real passing test, then attach-only harness control: one unit and one UI driver; '
                           'no enrollment, history, fixture-agent or changed-SDK behavior qualification.'
                           if args.scope == 'ios-control' else 'Real native app fixtures using the exact SDK cohort.'),
                       'setup': {}, 'cases': {}, 'adapter_mutations': {}, 'stage_timings': [],
                       'limits': ['Hosted single-runner SDK/app acceptance; no physical-device, APNS or production-install claim.',
                                  'No exhaustive full-history, all-user/topology or transferred retention/deletion equivalence.']}
        spec = importlib.util.spec_from_file_location('hosted_app_ui', HERE / 'hosted-app-ui.py')
        self.ui = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(self.ui)

    def save(self):
        temporary = self.work / 'state.pending.json'
        write_private(temporary, self.state, exclusive=not temporary.exists())
        temporary.replace(self.state_path)

    def failed_receipt(self, label):
        """Export native counts/closed categories, never private receipt contents."""
        if label not in ('ios-build', 'macos-build', 'ios-runner-preflight', 'ios-control', 'ios-native-qr'):
            return
        platform = 'macos' if label.startswith('macos-') else 'ios'
        prefix = self.private / label
        path = Path(str(prefix) + ('-result.json' if label == 'ios-native-qr' else '-results.json'))
        compact = {'receipt_status': 'unavailable',
                   'unit': {'counts_status': 'unknown'}, 'driver': {'counts_status': 'unknown'}}
        if path.exists():
            try:
                raw = json.loads(path.read_text())
                require(raw.get('source_commit') == self.commit(platform)
                        and raw.get('sdk_source') == self.args.sdk_source
                        and str(raw.get('sdk_run_id', self.args.sdk_run_id)) == self.args.sdk_run_id,
                        'failure-receipt-identity-mismatch')
                compact['receipt_status'] = 'available'
                for name in ('passed', 'exit_code', 'unit_exit_code', 'driver_exit_code', 'seconds'):
                    value = raw.get(name)
                    if type(value) in (int, float) and math.isfinite(value):
                        compact[name] = value
                for name in ('source_unchanged', 'sdk_unchanged', 'products_unchanged',
                             'plans_unchanged', 'unit_ready_observed', 'unchanged'):
                    if type(raw.get(name)) is bool:
                        compact[name] = raw[name]
                if raw.get('runner_error_category') in (
                    'RuntimeError', 'TimeoutError', 'OSError', 'ValueError', 'KeyError',
                    'InputVerificationFailed', 'OwnedRunnerRequiredTermination', 'FileNotFoundError'):
                    compact['runner_error_category'] = raw['runner_error_category']
                if raw.get('failure_stage') in (
                    'unit-ended-before-ui-ready', 'ui-ready-timeout', 'owned-test-runner-timeout'):
                    compact['failure_stage'] = raw['failure_stage']
                for name in ('unit', 'driver'):
                    counts = raw.get(name if label != 'ios-native-qr' else 'summary')
                    fields = ('totalTestCount', 'passedTests', 'failedTests', 'skippedTests')
                    if isinstance(counts, dict) and all(type(counts.get(k)) is int and counts[k] >= 0 for k in fields):
                        compact[name] = {'counts_status': 'available', **{key: counts[key] for key in fields}}
                    if label == 'ios-native-qr':
                        break
                diagnostic = raw.get('control_diagnostics')
                if label in ('ios-control', 'ios-runner-preflight') and isinstance(diagnostic, dict):
                    categories = {'host-foreground', 'control-button-exists', 'control-button-hittable',
                                  'control-button-tap', 'control-result-visible', 'host-not-running'}
                    keys = {'unit_process_launched_seconds', 'driver_process_launched_seconds', 'unit_ready_observed_seconds'}
                    keys.update(role + suffix for role in ('unit', 'driver') for suffix in (
                        '_method_start_observed_seconds', '_method_end_observed_seconds', '_process_exit_observed_seconds'))
                    closed = {'source_file': 'whitenoise-iosUITests/HostedHistoryApprovalUITests.swift',
                              'source_contract_verified': diagnostic.get('source_contract_verified') is True,
                              'failure_site_status': 'matched' if diagnostic.get('failure_site_status') == 'matched' else 'unavailable',
                              'failure_sites': [], 'observations': {},
                              'timing_scope': 'Monotonic host observations; not CPU or exact XCTest event times'}
                    if isinstance(diagnostic.get('source_sha256'), str) and re.fullmatch('[0-9a-f]{64}', diagnostic['source_sha256']):
                        closed['source_sha256'] = diagnostic['source_sha256']
                    for site in diagnostic.get('failure_sites', []):
                        if not isinstance(site, dict):
                            continue
                        if (site.get('category') in categories and type(site.get('line')) is int and site['line'] > 0
                                and type(site.get('occurrences')) is int and site['occurrences'] > 0):
                            closed['failure_sites'].append({k: site[k] for k in ('line', 'category', 'occurrences')})
                    for key, value in diagnostic.get('observations', {}).items():
                        if key in keys and type(value) in (int, float) and math.isfinite(value) and 0 <= value <= 3600:
                            closed['observations'][key] = value
                    if type(diagnostic.get('unclassified_source_failure_count')) is int:
                        closed['unclassified_source_failure_count'] = diagnostic['unclassified_source_failure_count']
                    compact['control_diagnostics'] = closed
            except (OSError, ValueError, KeyError, TypeError):
                compact['receipt_status'] = 'invalid-or-identity-mismatch'
        if label.endswith('-build'):
            # This log exists only for build-for-testing, before any runtime body.
            log = Path(str(prefix) + '-build.log')
            diagnostics = []
            if log.is_file():
                source = self.source(platform)
                tracked = set(subprocess.check_output(['git', 'ls-files', '*.swift'], cwd=source, text=True).splitlines())
                pattern = re.compile(r'^' + re.escape(str(source)) + r'/([^:\n]+\.swift):([0-9]+)(?::([0-9]+))?: error: (.*)$')
                with log.open(errors='replace') as stream:
                    for line in stream:
                        match = pattern.fullmatch(line.rstrip('\n'))
                        if not match or match[1] not in tracked or match[1].startswith(('Packages/MarmotKit/', 'Vendored/MarmotKit/')):
                            continue
                        if len(diagnostics) == 50:
                            compact['compiler_diagnostics_truncated'] = True
                            break
                        message = match[4]
                        for root in (str(source), os.environ.get('GITHUB_WORKSPACE', ''), os.environ.get('RUNNER_TEMP', '')):
                            if root:
                                message = message.replace(root, '<build-path>')
                        diagnostics.append({'path': match[1], 'line': int(match[2]),
                            'column': int(match[3]) if match[3] else None, 'error': message[:512]})
            compact['compiler_diagnostics'] = diagnostics
        self.report.setdefault('failed_stage_receipts', {})[label] = compact

    def command(self, label, command, kind, timeout=1900):
        previous = self.state['steps'].get(label)
        if previous is not None:
            require(previous['exit_code'] == 0 and previous['command'] == command, 'refuse-blind-retry-or-changed-staged-command')
            self.report['stage_timings'].append({'label': label, 'kind': kind,
                'seconds': previous['seconds'], 'reused_prior_execution': True})
            return previous
        row = {'command': command, 'kind': kind, 'exit_code': None}
        self.state['steps'][label] = row
        self.save()
        started = time.monotonic()
        print(json.dumps({'phase': label, 'event': 'start',
                          'utc': datetime.now(timezone.utc).isoformat(timespec='seconds')}), flush=True)
        process = None
        try:
            # Child helpers reserve every prefix-* sibling for their own fresh
            # artifacts. Wrapper logs must never occupy that namespace.
            logs = self.private / 'command-logs'
            logs.mkdir(mode=0o700, exist_ok=True)
            with (logs / (label + '.log')).open('x') as log:
                process = subprocess.Popen(command, env=self.environment, stdout=log,
                                           stderr=subprocess.STDOUT, start_new_session=True)
                row['exit_code'] = process.wait(timeout=timeout)
        except (OSError, subprocess.SubprocessError) as error:
            row['error_category'] = type(error).__name__
        finally:
            if process is not None and process.poll() is None:
                os.killpg(process.pid, signal.SIGINT)
                try:
                    process.wait(timeout=30)
                except subprocess.TimeoutExpired:
                    os.killpg(process.pid, signal.SIGKILL)
                    process.wait(timeout=10)
                row['required_termination'] = True
            row['seconds'] = round(time.monotonic() - started, 3)
            self.save()
            self.report['stage_timings'].append({'label': label, 'kind': kind, 'seconds': row['seconds']})
            print(json.dumps({'phase': label, 'event': 'end', 'seconds': row['seconds'], 'exit_code': row['exit_code'],
                              'utc': datetime.now(timezone.utc).isoformat(timespec='seconds')}), flush=True)
            if row['exit_code'] != 0 or 'error_category' in row or row.get('required_termination'):
                try:
                    self.failed_receipt(label)
                except (OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError):
                    self.report.setdefault('failed_stage_receipts', {})[label] = {'receipt_status': 'unavailable', 'counts_status': 'unknown'}
        require(row['exit_code'] == 0 and 'error_category' not in row and not row.get('required_termination'),
                'remote-stage-failed-' + label)
        return row

    def source(self, platform):
        return self.args.ios_source if platform == 'ios' else self.args.mac_source

    def commit(self, platform):
        return self.args.ios_commit if platform == 'ios' else self.args.mac_commit

    def package(self, platform):
        return self.source(platform) / ('Packages/MarmotKit' if platform == 'ios' else 'Vendored/MarmotKit')

    def products(self, platform):
        explicit = self.args.ios_products if platform == 'ios' else self.args.mac_products
        return explicit or self.work / (platform + '-derived') / 'Build/Products'

    def ui_arguments(self, platform, prefix, bridge):
        result = [sys.executable, str(HERE / 'hosted-app-ui.py'), '--platform', platform,
                  '--source', str(self.source(platform)), '--source-commit', self.commit(platform),
                  '--products', str(self.products(platform)), '--prefix', str(prefix), '--bridge', str(bridge),
                  '--sdk-package', str(self.package(platform)), '--sdk-source', self.args.sdk_source,
                  '--developer-dir', self.args.developer_dir]
        if platform == 'ios':
            result += ['--simulator', self.args.simulator]
        return result

    def prepare_sdk(self):
        qualification = json.loads((self.args.packages / 'qualification.json').read_text())
        require(qualification['source_sha'] == qualification['builder_sha'] == self.args.sdk_source
                and str(qualification['workflow_run_id']) == self.args.sdk_run_id
                and qualification['features'] == FEATURES, 'matching-new-sdk-producer-required')
        for platform, output in [('ios', self.work / 'sdk'), ('macos', self.work / 'sdk/macos')]:
            record = qualification['platforms'][platform]
            if not output.exists():
                self.command('extract-' + platform, [sys.executable, str(HERE / 'install.py'),
                    '--packages', str(self.args.packages), '--source', self.args.sdk_source,
                    '--run-id', self.args.sdk_run_id, '--platform', platform, '--output', str(output)], 'sdk-extraction')
            require(json.loads((output / 'manifest.json').read_text()) == record['manifest'], 'extracted-sdk-manifest-mismatch')
            actual = {str(path.relative_to(output)): digest(path) for path in output.rglob('*')
                      if path.is_file() and path.name != 'manifest.json'
                      and (platform != 'ios' or path.relative_to(output).parts[0] != 'macos')}
            require(actual == record['files'], 'extracted-sdk-inventory-mismatch')
        for platform in ('ios', 'macos'):
            package = self.package(platform)
            if not (package / 'LOCAL_BUILD.json').exists():
                self.command('install-' + platform, [sys.executable, str(HERE / 'install.py'),
                    '--packages', str(self.args.packages), '--source', self.args.sdk_source,
                    '--run-id', self.args.sdk_run_id, '--platform', platform,
                    '--app', str(self.source(platform)), '--app-sha', self.commit(platform)], 'app-sdk-installation')
            self.ui.freeze_sdk(package, self.args.sdk_source)

    def build(self, platform):
        self.ui.CONFIG = self.ui.CONFIGURATIONS[platform]
        explicit = self.args.ios_build_input if platform == 'ios' else self.args.mac_build_input
        prefix = self.private / (platform + '-build')
        receipt = explicit or Path(str(prefix) + '-input.json')
        if not receipt.exists():
            self.command(platform + '-build', self.ui_arguments(platform, prefix, self.private / (platform + '-build-bridge'))
                         + ['--stage', 'build', '--case', 'control' if platform == 'ios' else 'mac-source-picker'], 'app-compilation')
        frozen = self.ui.freeze_source(self.source(platform), self.commit(platform))
        sdk = self.ui.freeze_sdk(self.package(platform), self.args.sdk_source)
        self.ui.verify_build(receipt, frozen, sdk, self.products(platform))
        return receipt

    def runner_preflight(self):
        # Run before any hosted original exists. This is a real passing UI test,
        # reported separately; the following live-owner pair remains unchanged.
        name = 'ios-runner-preflight'
        prefix = self.private / name
        bridge = self.private / 'runner-preflight-bridge'
        bridge.mkdir(mode=0o700, exist_ok=True)
        build = self.build('ios')
        self.command(name, self.ui_arguments('ios', prefix, bridge)
                     + ['--stage', 'runner-preflight', '--case', 'control', '--build-input', str(build)],
                     'owner-free-ui-runner-setup', timeout=600)
        receipt = json.loads(Path(str(prefix) + '-results.json').read_text())
        require(type(receipt.get('passed')) is int and receipt['passed'] == 1
                and receipt.get('stage') == 'runner-preflight' and one_pass(receipt['driver'])
                and receipt.get('unit_exit_code') is None and 'unit' not in receipt
                and receipt['source_commit'] == self.args.ios_commit
                and receipt['sdk_source'] == self.args.sdk_source
                and str(receipt['sdk_run_id']) == self.args.sdk_run_id,
                'exact-owner-free-runner-preflight-required')
        self.report['setup'][name] = {'passed': 1, 'driver': receipt['driver'],
            'source_commit': self.args.ios_commit, 'sdk_source': self.args.sdk_source,
            'scope': 'Owner-free public UI runner only; no SDK protocol acceptance'}

    def ui_control(self):
        name = 'ios-control'
        prefix = self.private / name
        # reserve_paths rejects any existing sibling beginning with prefix + '-'.
        bridge = self.private / 'control-bridge'
        bridge.mkdir(mode=0o700, exist_ok=True)
        build = self.build('ios')
        self.command(name, self.ui_arguments('ios', prefix, bridge) + ['--stage', 'run', '--case', 'control',
                     '--build-input', str(build)], 'ui-attach-control', timeout=600)
        receipt = json.loads(Path(str(prefix) + '-results.json').read_text())
        require(receipt.get('passed') == 1 and one_pass(receipt['unit']) and one_pass(receipt['driver'])
                and receipt['source_commit'] == self.args.ios_commit and receipt['sdk_source'] == self.args.sdk_source
                and str(receipt['sdk_run_id']) == self.args.sdk_run_id, 'exact-initial-ui-control-required')
        result = {'passed': 1, 'unit': receipt['unit'], 'driver': receipt['driver'],
                  'sdk_source': self.args.sdk_source, 'source_commit': self.args.ios_commit}
        observations = receipt.get('control_diagnostics', {}).get('observations', {})
        result['control_observations'] = {key: value for key, value in observations.items()
            if re.fullmatch(r'(unit|driver)_(process_launched|ready_observed|method_start_observed|method_end_observed|process_exit_observed)_seconds', key)
            and type(value) in (int, float) and math.isfinite(value) and 0 <= value <= 3600}
        self.state['cases'][name] = result
        self.report['cases'][name] = result
        self.save()

    def agents(self):
        derived = self.work / 'derived-native'
        if not derived.exists():
            self.command('derive-agents', [sys.executable, str(HERE / 'prepare-hosted-agent.py'), '--output', str(derived)], 'native-source-preparation')
        provenance = json.loads((derived / 'DERIVED-SOURCE.json').read_text())
        for name, row in provenance['files'].items():
            require(digest(derived / name) == row['derived_sha256'], 'derived-agent-source-changed')
        flags = {name: '1' for name in ('NATIVE_AUTOMATIC_ACCEPTANCE', 'NATIVE_ONE_SCAN_ACCEPTANCE',
                 'NATIVE_HISTORY_ACCEPTANCE', 'NATIVE_HISTORY_RECIPIENT_QUERY',
                 'NATIVE_ACCOUNT_DEPARTURE_ACCEPTANCE', 'NATIVE_DEVICE_REVOCATION_ACCEPTANCE')}
        self.environment.update(flags)
        sdk = self.work / 'sdk'
        require(digest(sdk / 'MarmotKit.swift') == digest(sdk / 'macos/MarmotKit.swift'), 'matching-shared-swift-required')
        inputs = {str(path): digest(path) for path in derived.iterdir() if path.is_file()}
        for relative in ('MarmotKit.swift', 'manifest.json', 'macos/manifest.json',
                         'macos/MarmotKit.xcframework/macos-arm64/libmarmot_uniffi.a',
                         'macos/MarmotKit.xcframework/macos-arm64/Headers/marmot_uniffiFFI.h',
                         'macos/MarmotKit.xcframework/macos-arm64/Headers/module.modulemap'):
            inputs[str(sdk / relative)] = digest(sdk / relative)
        mac = self.work / 'mac-agent'
        simulator = self.work / 'sim-agent'
        if 'agent-builds' not in self.state:
            cache = self.work / 'mac-module-cache'
            cache.mkdir(mode=0o700, exist_ok=True)
            self.environment['NATIVE_MODULE_CACHE_PATH'] = str(cache)
            self.command('mac-agent-build', ['bash', str(derived / 'build.sh'), str(sdk), str(mac)], 'native-agent-compilation')
            require(all(digest(Path(path)) == value for path, value in inputs.items()), 'mac-agent-inputs-changed')
            cache = self.work / 'sim-module-cache'
            cache.mkdir(mode=0o700, exist_ok=True)
            self.environment['NATIVE_MODULE_CACHE_PATH'] = str(cache)
            self.command('sim-agent-build', ['bash', str(HERE / 'build-hosted-simulator-agent.sh'), str(sdk), str(derived), str(simulator)],
                         'native-agent-compilation')
            self.state['agent-builds'] = {'mac_sha': digest(mac), 'sim_sha': digest(simulator), 'mac_inputs': inputs,
                'sim_provenance': json.loads(Path(str(simulator) + '.provenance.json').read_text())}
            self.save()
        proof = self.state['agent-builds']
        require(digest(mac) == proof['mac_sha'] and digest(simulator) == proof['sim_sha']
                and proof['mac_inputs'] == inputs and all(digest(Path(path)) == value for path, value in inputs.items()),
                'exact-existing-agent-inputs-required')
        self.report['native_agent_provenance'] = {
            'mac_sha256': proof['mac_sha'], 'simulator_sha256': proof['sim_sha'],
            'mac_inputs_sha256': hashlib.sha256(json.dumps(proof['mac_inputs'], sort_keys=True).encode()).hexdigest(),
            'simulator_provenance_sha256': digest(Path(str(simulator) + '.provenance.json'))}
        return mac, simulator, proof

    def unit_arguments(self, platform, prefix, environment, selector, bundle):
        self.ui.CONFIG = self.ui.CONFIGURATIONS[platform]
        plans = list(self.products(platform).glob(self.ui.CONFIG['plan_glob']))
        require(len(plans) == 1, 'one-original-compiled-test-plan-required')
        destination = 'platform=macOS,arch=arm64' if platform == 'macos' else 'platform=iOS Simulator,id=' + self.args.simulator
        return [sys.executable, str(HERE / 'hosted-app-unit.py'), '--platform', 'ios-simulator' if platform == 'ios' else 'macos',
                '--source', str(self.source(platform)), '--source-commit', self.commit(platform),
                '--sdk-package', str(self.package(platform)), '--sdk-source', self.args.sdk_source,
                '--products', str(self.products(platform)), '--xctestrun', str(plans[0]), '--selector', selector,
                '--environment', str(environment), '--destination', destination, '--developer-dir', self.args.developer_dir,
                '--prefix', str(prefix), '--result-bundle', str(bundle)]

    @contextmanager
    def relay(self, label):
        relay = None
        try:
            with socket.socket() as probe:
                probe.bind(('127.0.0.1', 18181))
            with (self.private / (label + '-relay-private.stderr')).open('x') as log:
                relay = subprocess.Popen([str(self.args.relay), '--port', '18181'], stdout=subprocess.PIPE,
                                         stderr=log, env=self.environment)
                require(bool(select.select([relay.stdout], [], [], 10)[0]), 'owned-relay-ready-timeout')
                require(relay.stdout.readline().decode().strip() == 'ws://127.0.0.1:18181', 'owned-relay-endpoint-mismatch')
                yield
        finally:
            if relay is not None:
                was_running = relay.poll() is None
                if was_running:
                    relay.send_signal(signal.SIGINT)
                try:
                    output, _ = relay.communicate(timeout=10)
                except subprocess.TimeoutExpired:
                    relay.kill()
                    relay.communicate(timeout=10)
                    self.report['qr_relay_cleanup'] = {'passed': 0, 'forced_termination': True}
                    raise ValueError('owned-relay-required-forced-termination')
                receipt = re.fullmatch(rb'admitted_events=([0-9]+)\n', output)
                positive = was_running and relay.returncode == 0 and receipt is not None
                self.report['qr_relay_cleanup'] = {'passed': int(positive), 'exit_code': relay.returncode,
                    'admitted_events': int(receipt[1]) if receipt else None}
                require(positive, 'owned-relay-positive-shutdown-required')

    def qr(self):
        name = 'ios-native-qr'
        previous = self.state['cases'].get(name)
        if previous is not None:
            require(previous['passed'] == 1, 'no-blind-native-qr-retry')
            self.report['cases'][name] = previous
            return
        environment = self.private / (name + '-environment.json')
        write_private(environment, {'GITHUB_ACTIONS': 'true', 'GITHUB_RUN_ID': os.environ['GITHUB_RUN_ID'],
            'WN_NATIVE_ACCEPTANCE_SDK_SOURCE': self.args.sdk_source,
            'WN_NATIVE_ACCEPTANCE_SDK_RUN_ID': self.args.sdk_run_id, 'WN_NATIVE_PAIRING_QR_ACCEPTANCE': '1'})
        prefix = self.private / name
        bundle = self.private / (name + '.xcresult')
        command = self.unit_arguments('ios', prefix, environment,
            'NativePairingQRCodeTests/testActualThreeDevicePacketsPassAppCodecAndOriginalSdkAuthentication', bundle)
        with self.relay(name):
            self.command(name, command, 'app-native-qr-acceptance', timeout=1200)
        report = json.loads(Path(str(prefix) + '-result.json').read_text())
        require(report['passed'] == 1 and one_pass(report['summary']), 'actual-qr-runtime-pass-required')
        log = Path(str(prefix) + '-private.log').read_text(errors='replace')
        closes = re.findall(r'\{"positive_closes":(\d+),"cleanup_passed":(true|false)\}', log)
        gates = re.findall(r'\{"gate":"native-real-packet-qr",[^\n]+\}', log)
        require(closes == [('3', 'true')] and len(gates) == 1, 'actual-three-runtime-positive-close-receipt-required')
        gate = json.loads(gates[0])
        require(gate['passed'] == 1 and gate['failed'] == 0
                and all(gate.get(key) is True for key in ('request_authenticated', 'challenge_authenticated',
                                                        'third_device_settled', 'enrollment_authenticated')), 'actual-three-device-qr-body-required')
        result = {'passed': 1, 'unit': report['summary'], 'positive_native_closes': 3,
                  'real_request_challenge_enrollment_authenticated': True, 'three_device_settlement': True,
                  'relay_cleanup': self.report['qr_relay_cleanup']}
        self.state['cases'][name] = result
        self.report['cases'][name] = result
        self.save()

    def host_factory(self, platform, selector):
        require(selector in HOST_FACTORY_SELECTORS, 'closed-real-host-factory-selector-required')
        name = platform + '-host-factory-' + selector.split('/', 1)[1]
        previous = self.state['cases'].get(name)
        if previous is not None:
            require(previous['passed'] == 1, 'no-blind-host-factory-retry')
            self.report['cases'][name] = previous
            return
        environment = self.private / (name + '-environment.json')
        write_private(environment, {'GITHUB_ACTIONS': 'true', 'GITHUB_RUN_ID': os.environ['GITHUB_RUN_ID'],
            'WN_NATIVE_ACCEPTANCE_SDK_SOURCE': self.args.sdk_source,
            'WN_NATIVE_ACCEPTANCE_SDK_RUN_ID': self.args.sdk_run_id,
            'WN_AUTOMATIC_HOST_FACTORY_ACCEPTANCE': '1'})
        prefix = self.private / name
        bundle = self.private / (name + '.xcresult')
        command = self.unit_arguments(platform, prefix, environment, selector, bundle)
        with self.relay(name):
            self.command(name, command, 'real-automatic-host-factory-acceptance', timeout=1200)
        result = json.loads(Path(str(prefix) + '-result.json').read_text())
        require(result['passed'] == 1 and one_pass(result['summary']),
                'one-actual-host-factory-body-no-failures-or-skips-required')
        require(self.report['qr_relay_cleanup']['passed'] == 1,
                'host-factory-owned-relay-positive-close-required')
        row = {'passed': 1, 'unit': result['summary'], 'selector': selector,
               'fixture_identity': ('real-automatic-app-owner-existing-roster-WNPAIR2-v1'
                   if selector == EXISTING_ROSTER_SELECTOR else 'real-automatic-app-owner-factories-v1'),
               'relay_cleanup': self.report['qr_relay_cleanup'],
               'app_report_sha256': digest(Path(str(prefix) + '-result.json'))}
        self.state['cases'][name] = row
        self.report['cases'][name] = row
        self.save()

    def fixture(self, platform, name, scenario, selector=None, ui_case=None):
        label = platform + '-' + name
        previous = self.state['cases'].get(label)
        if previous is not None:
            require(previous['passed'] == 1, 'no-blind-fixture-retry')
            self.report['cases'][label] = previous
            return
        directory = self.private / label
        directory.mkdir(mode=0o700)
        base = directory / 'native-base'
        environment = directory / 'environment.json'
        prefix = directory / (label + '-runner')
        if ui_case:
            app = self.ui_arguments(platform, prefix, base / 'private-bridge') + [
                '--stage', 'run', '--case', ui_case, '--environment', str(environment),
                '--build-input', str(self.build(platform))]
            bundle = Path(str(prefix) + '-unit.xcresult')
        else:
            bundle = directory / 'unit.xcresult'
            app = self.unit_arguments(platform, prefix, environment, selector, bundle)
        manifest = directory / 'command.json'
        write_private(manifest, {'argv': app})
        native_result = self.evidence / (label + '-native.json')
        mac, simulator, agents = self.agents()
        self.command(label, [sys.executable, str(HERE / 'hosted-app-fixtures.py'), '--scenario', scenario,
            '--platform', 'ios-simulator' if platform == 'ios' else 'macos', '--mac-agent', str(mac),
            '--mac-sha', agents['mac_sha'], '--sim-agent', str(simulator), '--sim-sha', agents['sim_sha'],
            '--simulator', self.args.simulator, '--relay', str(self.args.relay), '--base', str(base),
            '--environment', str(environment), '--application-command', str(manifest),
            '--app-result-bundle', str(bundle), '--output', str(native_result), '--sdk-source', self.args.sdk_source,
            '--sdk-run-id', self.args.sdk_run_id], 'native-and-app-acceptance', timeout=1200)
        native = json.loads(native_result.read_text())
        cleanup = native['native_cleanup']
        require(native['passed'] == 1 and one_pass(native['app_counts'])
                and cleanup['cleanup_failures'] == 0 and cleanup['workers_created'] == cleanup['workers_closed'] > 0
                and native['relay_cleanup']['passed'] == 1,
                'exact-native-counterpart-and-app-close-required')
        app_report = json.loads(Path(str(prefix) + ('-results.json' if ui_case else '-result.json')).read_text())
        require(app_report['passed'] == 1, 'existing-app-runner-proof-required')
        result = {'passed': 1, 'scenario': scenario, 'unit': native['app_counts'], 'native_cleanup': cleanup,
                  'relay_cleanup': native['relay_cleanup'],
                  'native_result_sha256': digest(native_result), 'app_report_sha256': digest(Path(str(prefix) + ('-results.json' if ui_case else '-result.json')))}
        result['app_input_proof'] = {key: app_report[key] for key in (
            'source_commit', 'sdk_source', 'sdk_run_id', 'source_unchanged', 'sdk_unchanged',
            'products_unchanged', 'plans_unchanged', 'compiled_native_inputs') if key in app_report}
        if scenario == 'paired-direct':
            require(native.get('paired_direct', {}).get('no_new_peer_invitation') is True
                    and native['paired_direct']['source_only_before_and_after'] is True,
                    'paired-direct-fixture-must-prove-peer-and-membership-invariants')
            result['paired_direct'] = native['paired_direct']
        if ui_case:
            require(one_pass(app_report['driver']) and one_pass(app_report['unit']), 'one-public-ui-driver-pass-required')
            result['driver'] = app_report['driver']
        self.state['cases'][label] = result
        self.report['cases'][label] = result
        self.save()

    def paired_direct_mutations(self, platform):
        mac, simulator, agents = self.agents()
        name = platform + '-paired-direct-mutations'
        output = self.args.output.parent / (name + '.json')
        command = [sys.executable, str(HERE / 'paired-direct-mutations.py'), '--platform', platform,
            '--source', str(self.source(platform)), '--source-commit', self.commit(platform),
            '--sdk-package', str(self.package(platform)), '--sdk-source', self.args.sdk_source,
            '--sdk-run-id', self.args.sdk_run_id, '--mac-agent', str(mac), '--mac-sha', agents['mac_sha'],
            '--sim-agent', str(simulator), '--sim-sha', agents['sim_sha'],
            '--simulator', self.args.simulator, '--developer-dir', self.args.developer_dir,
            '--relay', str(self.args.relay), '--work', str(self.private / name), '--output', str(output)]
        # Three existing bounded phases, each with a fresh genuine native fixture.
        # This is additional mutation evidence, separate from the native app bodies.
        self.command(name, command, 'paired-direct-runtime-mutation', timeout=10000)
        proof = json.loads(output.read_text())
        require(proof.get('passed') is True and proof['platform'] == platform
                and proof['app_sha'] == self.commit(platform) and proof['sdk_source'] == self.args.sdk_source
                and str(proof['sdk_run_id']) == self.args.sdk_run_id
                and proof.get('mutant_runtime_detected') is True and proof.get('source_restored') is True,
                'exact-paired-direct-runtime-mutation-required')
        self.report['adapter_mutations'][platform] = {'passed': True, 'mutant_runtime_detected': True,
            'source_restored': True, 'app_sha': self.commit(platform), 'sdk_source': self.args.sdk_source,
            'proof_sha256': digest(output)}

    def expected_cases(self):
        if self.args.scope.startswith('adapter-'):
            return set()
        expected = {'ios-control'}
        if self.args.scope in ('mac', 'all'):
            expected.update('macos-' + name for name in ('switch', 'reader', 'picker', 'source', 'recipient', 'picker-ui', 'paired-direct'))
        if self.args.scope in ('ios', 'all'):
            expected.add('ios-native-qr')
            expected.update('ios-' + name for name in ('switch', 'reader', 'picker', 'source', 'picker-ui', 'source-ui', 'approval-ui', 'paired-direct'))
        for platform in (('macos', 'ios') if self.args.scope == 'all' else
                         ('macos',) if self.args.scope == 'mac' else
                         ('ios',) if self.args.scope == 'ios' else ()):
            expected.update(platform + '-host-factory-' + selector.split('/', 1)[1]
                            for selector in HOST_FACTORY_SELECTORS)
        return expected

    def run(self):
        self.prepare_sdk()
        if self.args.scope.startswith('adapter-'):
            self.paired_direct_mutations('macos' if self.args.scope == 'adapter-macos' else 'ios')
            return
        self.runner_preflight()
        self.ui_control()
        if self.args.scope == 'ios-control':
            return
        platforms = ('macos', 'ios') if self.args.scope == 'all' else (('macos',) if self.args.scope == 'mac' else ('ios',))
        for platform in platforms:
            self.build(platform)
        self.agents()
        if 'ios' in platforms:
            self.qr()
        for platform in platforms:
            for name, scenario, selector in MODELS[platform]:
                self.fixture(platform, name, scenario, selector=selector)
            for name, scenario, ui_case in UI_CASES[platform]:
                self.fixture(platform, name, scenario, ui_case=ui_case)
            for selector in HOST_FACTORY_SELECTORS:
                self.host_factory(platform, selector)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--scope', choices=('ios-control', 'mac', 'ios', 'all', 'adapter-macos', 'adapter-ios'), required=True)
    for name in ('mac-source', 'ios-source', 'packages', 'work', 'output', 'relay'):
        parser.add_argument('--' + name, type=Path, required=True)
    for name in ('mac-products', 'ios-products', 'mac-build-input', 'ios-build-input'):
        parser.add_argument('--' + name, type=Path)
    for name in ('mac-commit', 'ios-commit', 'sdk-source', 'sdk-run-id', 'simulator', 'developer-dir'):
        parser.add_argument('--' + name, required=True)
    args = parser.parse_args()
    require(os.environ.get('GITHUB_ACTIONS') == 'true' and os.environ.get('RUNNER_OS') == 'macOS', 'hosted-ci-only')
    require(all(re.fullmatch('[0-9a-f]{40}', value) for value in (args.mac_commit, args.ios_commit, args.sdk_source))
            and args.sdk_run_id.isdigit(), 'immutable-source-and-sdk-cohort-required')
    require(args.scope == 'ios-control'
            or args.sdk_source != '3f18b2d1acac4f87680b35f39bf8dce67dcf28ec',
            'old-sdk-permitted-only-for-attach-only-harness-control')
    require(Path(args.developer_dir).is_absolute() and Path(args.developer_dir).is_dir(),
            'actual-selected-xcode-developer-directory-required')
    os.umask(0o077)
    for name in ('mac_source', 'ios_source', 'packages', 'relay'):
        path = getattr(args, name)
        require(path.is_absolute(), 'absolute-owned-inputs-required')
        setattr(args, name, path.resolve(strict=True))
    for name in ('mac_products', 'ios_products', 'mac_build_input', 'ios_build_input'):
        path = getattr(args, name)
        if path is not None:
            require(path.is_absolute(), 'absolute-build-receipts-and-products-required')
            setattr(args, name, path.resolve())
    for platform, source, commit in (('macos', args.mac_source, args.mac_commit), ('ios', args.ios_source, args.ios_commit)):
        require(subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=source, text=True).strip() == commit,
                'actual-app-head-must-match-' + platform)
    runner = Runner(args)
    started = time.monotonic()
    try:
        runner.run()
        expected_setup = set() if args.scope.startswith('adapter-') else {'ios-runner-preflight'}
        require(set(runner.report['setup']) == expected_setup
                and all(item['passed'] == 1 for item in runner.report['setup'].values()),
                'actual-owner-free-setup-body-required')
        require(set(runner.report['cases']) == runner.expected_cases()
                and all(case['passed'] == 1 for case in runner.report['cases'].values()),
                'every-requested-native-app-body-required')
        expected_bodies = {'ios-control': 2, 'mac': 17, 'ios': 21, 'all': 36, 'adapter-macos': 0, 'adapter-ios': 0}[args.scope]
        executed_bodies = sum(case['unit']['totalTestCount'] + case.get('driver', {}).get('totalTestCount', 0)
                              for case in runner.report['cases'].values())
        require(executed_bodies == expected_bodies, 'exact-selected-native-app-body-count-required')
        host_expected = {'ios-control': 0, 'mac': 7, 'ios': 7, 'all': 14, 'adapter-macos': 0, 'adapter-ios': 0}[args.scope]
        host_cases = [row for name, row in runner.report['cases'].items() if '-host-factory-' in name]
        require(len(host_cases) == host_expected and all(
            row['fixture_identity'] == ('real-automatic-app-owner-existing-roster-WNPAIR2-v1'
                if row['selector'] == EXISTING_ROSTER_SELECTOR else 'real-automatic-app-owner-factories-v1')
            and row['selector'] in HOST_FACTORY_SELECTORS and one_pass(row['unit'])
            and row['relay_cleanup']['passed'] == 1 for row in host_cases),
            'every-new-real-host-factory-body-and-close-required')
        runner.report['expected_automatic_host_factory_body_count'] = host_expected
        runner.report['executed_automatic_host_factory_body_count'] = len(host_cases)
        roster_expected = {'ios-control': 0, 'mac': 1, 'ios': 1, 'all': 2, 'adapter-macos': 0, 'adapter-ios': 0}[args.scope]
        roster_actual = sum(row['selector'] == EXISTING_ROSTER_SELECTOR for row in host_cases)
        require(roster_actual == roster_expected, 'each-actual-existing-roster-wnpair2-body-required')
        runner.report['expected_existing_roster_wnpair2_body_count'] = roster_expected
        runner.report['executed_existing_roster_wnpair2_body_count'] = roster_actual
        expected_mutations = ({'macos'} if args.scope == 'adapter-macos' else
                              {'ios'} if args.scope == 'adapter-ios' else set())
        require(set(runner.report['adapter_mutations']) == expected_mutations
                and all(proof['passed'] is True for proof in runner.report['adapter_mutations'].values()),
                'each-requested-platform-runtime-mutant-required')
        runner.report['passed'] = 1
    except (ValueError, OSError, KeyError, subprocess.SubprocessError) as error:
        # Only fixed labels/types leave the private runner, never SDK descriptions.
        label = str(error) if isinstance(error, ValueError) else type(error).__name__
        runner.report['failure_stage'] = label if re.fullmatch('[A-Za-z0-9:_-]{1,180}', label) else type(error).__name__
    finally:
        runner.report['expected_app_test_body_count'] = {'ios-control': 2, 'mac': 17, 'ios': 21, 'all': 36, 'adapter-macos': 0, 'adapter-ios': 0}[args.scope]
        # Failed/partial case reports must not mask the original failure in
        # this finally block. The success path above still requires all counts.
        runner.report['execution_count_incomplete_cases'] = sorted(
            name for name, case in runner.report['cases'].items()
            if not isinstance(case.get('unit'), dict)
            or type(case['unit'].get('totalTestCount')) is not int)
        runner.report['executed_app_test_body_count'] = sum(
            counts['totalTestCount'] for case in runner.report['cases'].values()
            for counts in (case.get('unit'), case.get('driver'))
            if isinstance(counts, dict) and type(counts.get('totalTestCount')) is int
            and counts['totalTestCount'] >= 0)
        runner.report['expected_adapter_runtime_mutant_count'] = {'ios-control': 0, 'mac': 0, 'ios': 0, 'all': 0, 'adapter-macos': 1, 'adapter-ios': 1}[args.scope]
        runner.report['completed_adapter_runtime_mutant_count'] = len(runner.report['adapter_mutations'])
        runner.report['expected_setup_test_count'] = 0 if args.scope.startswith('adapter-') else 1
        runner.report['completed_setup_test_count'] = len(runner.report['setup'])
        runner.report['expected_cases'] = sorted(runner.expected_cases())
        runner.report['expected_case_count'] = len(runner.expected_cases())
        runner.report['completed_case_count'] = len(runner.report['cases'])
        runner.report['seconds'] = round(time.monotonic() - started, 3)
        runner.report['successful_state_cases'] = sorted(runner.state['cases'])
        write_private(args.output, runner.report)
    return 0 if runner.report['passed'] == 1 else 1


if __name__ == '__main__':
    raise SystemExit(main())
