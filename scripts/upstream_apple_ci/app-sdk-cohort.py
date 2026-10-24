#!/usr/bin/env python3
"""Remote application SDK cohort setup, guarded builds and closed count evidence."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import stat
import sys

from summarize import summary_counts, test_inventory, export_tests, skip_reason_evidence, export_skip_details

HISTORICAL_SOURCE = '891ab34980ee9dc2ef45bf690733a6e31d3e6778'
HISTORICAL_CHECKSUMS = {'macos': 'a5b74c4ad8b5da6bd00b24173fa6628cc6aba1dfb9a13ee4d5ff0af1d2081366',
                        'ios': '06fa55edf8bb77edf0479452b5ec976eaea0298a5e0d07fe07ca176bdba0459e'}
FEATURES = {'default': ['otlp-export', 'product-analytics-export'],
            'experimental': ['otlp-export', 'product-analytics-export', 'experimental-device-sync'],
            'historical': ['otlp-export', 'product-analytics-export']}
HERE = Path(__file__).resolve().parent

# These source-owned fixture/driver/physical-device bodies remain separate native
# qualification gates. Only these named skips may appear in a compatibility run.
KNOWN_SKIPS = {
    'macos': {
        'GenuineAutomaticHostFactoryTests/testExistingRosterWNPAIR2RequiresSiblingApprovalAndSharesHistory()': ('GenuineAutomaticHostFactoryTests.swift', 'native_fixture'),
        'GenuineAutomaticHostFactoryTests/testForwardFactoriesShareBothPreviouslyAbsentChats()': ('GenuineAutomaticHostFactoryTests.swift', 'native_fixture'),
        'GenuineAutomaticHostFactoryTests/testReverseFactoriesShareBothPreviouslyAbsentChats()': ('GenuineAutomaticHostFactoryTests.swift', 'native_fixture'),
        'GenuineAutomaticHostFactoryTests/testActualFactoryCancellationRetiresOriginal()': ('GenuineAutomaticHostFactoryTests.swift', 'native_fixture'),
        'GenuineAutomaticHostFactoryTests/testActualFactoryPlatformShutdownClosesStorageAndRetiresOriginal()': ('GenuineAutomaticHostFactoryTests.swift', 'native_fixture'),
        'GenuineAutomaticHostFactoryTests/testLateBeginFactoryCannotAdoptAcrossAccountReplacement()': ('GenuineAutomaticHostFactoryTests.swift', 'native_fixture'),
        'GenuineAutomaticHostFactoryTests/testLateScanFactoryCannotAdoptAcrossAccountReplacement()': ('GenuineAutomaticHostFactoryTests.swift', 'native_fixture'),
        'GenuineAutomaticAccountSwitchTests/testActualAccountsReplacePairedOwnersAndRetireBeforeRuntimeClose()': ('GenuineAutomaticAccountSwitchTests.swift', 'native_fixture'),
        'GenuineHistoryRecipientTransferTests/testFreshRecipientOriginalThroughSessionModelAndIOSSource()': ('GenuineHistoryRecipientTransferTests.swift', 'native_fixture'),
        'GenuineImportedHistoryPaneTests/testRealCommittedImportThroughSessionOwnedReaderAndHostedPane()': ('GenuineImportedHistoryPaneTests.swift', 'native_fixture'),
        'GenuineHistorySourceTransferTests/testCompleteFreshSourceOriginalThroughAccountModelAndNativeRecipient()': ('GenuineHistorySourceTransferTests.swift', 'native_fixture'),
        'GenuineHistorySourcePickerTests/testHostedNativePickerButtonsWithExternalDriver()': ('GenuineHistorySourcePickerTests.swift', 'external_ui_driver'),
        'GenuineHistorySourcePickerTests/testRealRecipientsAndFreshOriginalThroughSessionOwnedModel()': ('GenuineHistorySourcePickerTests.swift', 'native_fixture'),
        'GenuinePairedDirectConversationTests/testRealMarmotClientReusesPairedSourceWithoutLocalMembershipOrInvitation()': ('GenuinePairedDirectConversationTests.swift', 'native_fixture'),
    },
    'ios': {
        'GenuineAutomaticHostFactoryTests/testExistingRosterWNPAIR2RequiresSiblingApprovalAndSharesHistory()': ('GenuineAutomaticHostFactoryTests.swift', 'native_fixture'),
        'GenuineAutomaticHostFactoryTests/testForwardFactoriesShareBothPreviouslyAbsentChats()': ('GenuineAutomaticHostFactoryTests.swift', 'native_fixture'),
        'GenuineAutomaticHostFactoryTests/testReverseFactoriesShareBothPreviouslyAbsentChats()': ('GenuineAutomaticHostFactoryTests.swift', 'native_fixture'),
        'GenuineAutomaticHostFactoryTests/testActualFactoryCancellationRetiresOriginal()': ('GenuineAutomaticHostFactoryTests.swift', 'native_fixture'),
        'GenuineAutomaticHostFactoryTests/testActualFactoryPlatformShutdownClosesStorageAndRetiresOriginal()': ('GenuineAutomaticHostFactoryTests.swift', 'native_fixture'),
        'GenuineAutomaticHostFactoryTests/testLateBeginFactoryCannotAdoptAcrossAccountReplacement()': ('GenuineAutomaticHostFactoryTests.swift', 'native_fixture'),
        'GenuineAutomaticHostFactoryTests/testLateScanFactoryCannotAdoptAcrossAccountReplacement()': ('GenuineAutomaticHostFactoryTests.swift', 'native_fixture'),
        'GenuineHistorySourcePickerTests/testHostedNativeChoiceRequestAndCancelThroughPublicDriver()': ('GenuineHistorySourcePickerTests.swift', 'external_ui_driver'),
        'GenuineHistorySourcePickerTests/testActualNativeChoicesCreateRefreshAndCancelOriginalThroughAccountOwner()': ('GenuineHistorySourcePickerTests.swift', 'native_fixture'),
        'NativePairingQRCodeTests/testActualThreeDevicePacketsPassAppCodecAndOriginalSdkAuthentication()': ('NativePairingQRCodeTests.swift', 'isolated_relay'),
        'SignUpDraftStoreTests/submittedDraftAndDirectoryUseCompleteFileProtection()': ('SignUpDraftStoreTests.swift', 'physical_data_protection'),
        'GenuineHistorySourceTransferTests/testCompleteFreshSourceOriginalThroughAppStateAndNativeRecipient()': ('GenuineHistorySourceTransferTests.swift', 'native_fixture'),
        'GenuineHistorySourceTransferTests/testHostedFreshSourceTransferThroughPublicButtons()': ('GenuineHistorySourceTransferTests.swift', 'external_ui_driver'),
        'GenuineAutomaticAccountSwitchTests/testActualAccountsReplacePairedOwnersAndSceneSuspensionClosesRuntime()': ('GenuineAutomaticAccountSwitchTests.swift', 'native_fixture'),
        'ExternalHostedUIControlTests/testExternalDriverAttachesWithoutReplacingHostedApp()': ('ExternalHostedUIControlTests.swift', 'external_ui_driver'),
        'GenuineImportedHistoryPaneTests/testRealCommittedImportThroughAccountOwnedReaderAndHostedPane()': ('GenuineImportedHistoryPaneTests.swift', 'native_fixture'),
        'GenuinePairedDirectConversationTests/testRealMarmotClientReusesPairedSourceWithoutLocalMembershipOrInvitation()': ('GenuinePairedDirectConversationTests.swift', 'native_fixture'),
        'GenuineHistoryApprovalPaneTests/testHostedExplicitOriginalApprovalCommitsRealRelayImport()': ('GenuineHistoryApprovalPaneTests.swift', 'external_ui_driver'),
    },
}
MUTANTS = {
    'macos': [
        ('attachment-storage-mutation', 'retry', 'whitenoise-mac/Views/RetainedSharedMediaViews.swift', 'whitenoise-macTests/AttachmentStorageAdmissionTests/storagePressureKeepsCheckpointRetryAndRemovalAvailable()'),
        ('attachment-storage-rearm-mutation', 'rearm', 'whitenoise-mac/Features/Attachments/AttachmentViewModel.swift', 'whitenoise-macTests/AttachmentStorageAdmissionTests/storagePressureKeepsCheckpointRetryAndRemovalAvailable()'),
        ('missing-key-mutations-macos', 'mac-obsolete-invite', 'whitenoise-mac/Core/ChatCreationFailure.swift', 'whitenoise-macTests/ChatInviteRuleTests/obsoletePublicationUsesGenericErrorWithoutAnInviteOrAccountDisclosure()'),
    ],
    'ios': [
        ('ios-storage-mutations', 'ios-storage-await-policy', 'whitenoise-ios/Core/MarmotClient+Attachments.swift', 'whitenoise-iosTests/Marmot0104BindingTests/terminalAttachmentStatesDoNotWaitOrRetryAutomatically()'),
        ('ios-storage-mutations', 'ios-storage-running-wait', 'whitenoise-ios/Core/MarmotClient+Attachments.swift', 'whitenoise-iosTests/Marmot0104BindingTests/storageBlockedStopsAnAlreadyRunningAttachmentWait()'),
        ('missing-key-mutations-ios', 'ios-obsolete-recipient', 'whitenoise-ios/Recipients/MissingKeyPackageInvitationPresentation.swift', 'whitenoise-iosTests/MissingKeyPackageInvitationPresentationTests/obsoletePublicationDoesNotIdentifySomeoneAsAbsentFromWhiteNoise()'),
        ('missing-key-mutations-ios', 'ios-obsolete-direct-chat', 'whitenoise-ios/Recipients/DirectChatStarter.swift', 'whitenoise-iosTests/DirectChatStarterTests/obsoletePublicationOffersAnErrorInsteadOfSharingTheApp()'),
    ],
}


def selected_platforms(value):
    require(type(value) is str and value in ('both', 'macos', 'ios'), 'Closed app platform selection required')
    return ['macos', 'ios'] if value == 'both' else [value]


def digest_value(value):
    return isinstance(value, str) and re.fullmatch('[0-9a-f]{64}', value) is not None


def suite_inventory_gate(inventory, counts, platform):
    require(isinstance(counts, dict) and summary_counts(counts) == counts and counts['totalTestCount'] > 0,
            'Actual complete suite counts required')
    require(isinstance(inventory, dict) and inventory.get('status') == 'complete'
            and type(inventory.get('unknown_nodes')) is int and inventory['unknown_nodes'] == 0
            and summary_counts(inventory.get('summary_counts')) == counts
            and summary_counts(inventory.get('enumerated_counts')) == counts,
            'Complete case inventory matching summary required')
    skipped = inventory.get('skipped_tests')
    require(isinstance(skipped, list) and len(skipped) == counts['skippedTests'],
            'Every skipped case must be enumerated')
    accepted, seen = [], set()
    modules = ('whitenoise_macTests', 'whitenoise-macTests') if platform == 'macos' else ('whitenoise_iosTests', 'whitenoise-iosTests')
    aliases = {}
    for canonical in KNOWN_SKIPS[platform]:
        aliases[canonical] = canonical
        for module in modules:
            aliases[module + '/' + canonical] = canonical
            aliases[module + '.' + canonical] = canonical
    for row in skipped:
        require(isinstance(row, dict) and isinstance(row.get('identifier'), str),
                'Known source-owned skipped identifier required')
        canonical = aliases.get(row['identifier'])
        require(canonical is not None and canonical not in seen,
                'Unknown or duplicate skipped required body')
        seen.add(canonical)
        file, category = KNOWN_SKIPS[platform][canonical]
        accepted.append({'identifier': canonical, 'source_file': file,
                         'separate_gate': category, 'native_acceptance_waived': False})
    return accepted


def metadata_identity_gate(value, proof, profile, platform, tools):
    require(isinstance(value, dict) and isinstance(proof, dict), 'Mutation identity schema differs')
    require(value.get('app_sha') == proof['app_sha'] and value.get('sdk_sha') == proof['sdk_source']
            and value.get('sdk_run_id') == proof['sdk_run_id'] and value.get('sdk_profile') == profile
            and value.get('workflow_tools_sha') == proof['tools_sha'] == tools
            and value.get('private_flag') == ('0' if profile == 'default' else '1'),
            'Mutation app SDK profile run tools identity differs')
    require(all(isinstance(proof.get(key), str) and re.fullmatch('[0-9a-f]{40}', proof[key])
                for key in ['app_sha', 'sdk_source', 'tools_sha'])
            and isinstance(proof.get('sdk_run_id'), str)
            and re.fullmatch('[1-9][0-9]*', proof['sdk_run_id']) is not None,
            'Immutable mutation identity schema differs')
    if 'platform' in value:
        require(value['platform'] == platform, 'Mutation platform differs')


def row_identity(row):
    return (row.get('name', row.get('case')), row.get('source', row.get('source_path')), row.get('selector'))


def mutation_rows_gate(value, definitions):
    require(isinstance(value, dict), 'Mutation proof mapping required')
    rows = value.get('mutants') if 'mutants' in value else [value]
    require(isinstance(rows, list) and len(rows) == len(definitions)
            and all(isinstance(row, dict) for row in rows), 'Exact mutation row count required')
    expected = {(name, source, selector) for _, name, source, selector in definitions}
    actual = [row_identity(row) for row in rows]
    require(all(all(isinstance(part, str) for part in identity) for identity in actual),
            'String mutation identities required')
    require(len(set(actual)) == len(actual) and set(actual) == expected,
            'Exact unique source selector mutant identities required')
    if 'mutants' in value:
        require(type(value.get('expected_mutants')) is int and value['expected_mutants'] == len(rows),
                'Exact expected mutation count required')
    return {row_identity(row): row for row in rows}


def source_facts_gate(facts, source):
    require(isinstance(facts, dict) and facts.get('path') == source
            and facts.get('canonical_file') is True
            and digest_value(facts.get('git_sha256')) and digest_value(facts.get('physical_sha256'))
            and facts['git_sha256'] == facts['physical_sha256']
            and facts.get('git_mode') in {'100644', '100755'}
            and type(facts.get('physical_mode')) is int and type(facts.get('prepared_mode')) is int
            and 0 <= facts['prepared_mode'] <= 0o777
            and facts['physical_mode'] == facts['prepared_mode']
            and bool(facts['physical_mode'] & 0o111) == (facts['git_mode'] == '100755'),
            'Restored source must match Git bytes and checkout mode')


def mutation_row_gate(row, definition, facts):
    _, name, source, selector = definition
    require(row_identity(row) == (name, source, selector), 'Mutation row identity differs')
    source_facts_gate(facts, source)
    require(all(digest_value(row.get(key)) for key in ['original_sha256', 'mutant_sha256', 'final_source_sha256'])
            and row['original_sha256'] == row['final_source_sha256'] == facts['git_sha256']
            and row['mutant_sha256'] != row['original_sha256'], 'Nonempty distinct mutation hashes required')
    require(all(row.get(key) is True for key in ['mutation_killed', 'source_restored',
                 'restored_control_passed', 'runtime_red_confirmed']), 'Actual runtime kill and source restoration required')
    runs = row.get('runs')
    require(isinstance(runs, list) and len(runs) == 2 and all(isinstance(phase, dict) for phase in runs),
            'Exactly two native mutation phases required')
    expected_counts = [dict(totalTestCount=1, passedTests=0, failedTests=1, skippedTests=0),
                       dict(totalTestCount=1, passedTests=1, failedTests=0, skippedTests=0)]
    phases = []
    for index, phase in enumerate(runs):
        phase_name = ['mutant', 'restored-control'][index]
        code = [65, 0][index]  # xcodebuild TEST_FAILURE and successful restored execution.
        counts = summary_counts(phase.get('summary'))
        require(phase.get('phase') == phase_name and type(phase.get('exit_code')) is int
                and phase['exit_code'] == code and phase.get('runtime_result_present') is True
                and counts == expected_counts[index], 'Exact phase exit code and actual XCTest counts required')
        phases.append({'phase': phase_name, 'exit_code': code, 'counts': counts})
    return {'name': name, 'source_path': source, 'selector': selector, 'accepted': True,
            'phases': phases, 'original_sha256': row['original_sha256'],
            'mutant_sha256': row['mutant_sha256'], 'final_source_sha256': row['final_source_sha256'],
            'source_mode': facts['physical_mode'], 'git_mode': facts['git_mode']}


def git_output(app, *arguments):
    return subprocess.check_output(['git', '-C', str(app), *arguments])


def physical_source_facts(app, relative, commit, prepared_mode=None):
    entry = git_output(app, 'ls-tree', commit, '--', relative).decode().rstrip('\n').split('\t')
    require(len(entry) == 2 and entry[1] == relative, 'Expected tracked product source required')
    mode, kind, oid = entry[0].split(' ')
    path = app / relative
    info = path.lstat()
    return {'path': relative, 'git_sha256': hashlib.sha256(git_output(app, 'show', commit + ':' + relative)).hexdigest(),
            'physical_sha256': sha(path) if stat.S_ISREG(info.st_mode) and not path.is_symlink() else None,
            'git_mode': mode, 'physical_mode': stat.S_IMODE(info.st_mode),
            'prepared_mode': stat.S_IMODE(info.st_mode) if prepared_mode is None else prepared_mode,
            'canonical_file': kind == 'blob' and not path.is_symlink() and path.resolve(strict=True) == path
                              and path.is_file() and path.is_relative_to(app)}


def physical_tracked_snapshot(app):
    rows = []
    for raw in git_output(app, 'ls-files', '--stage', '-z').split(b'\0'):
        if not raw:
            continue
        prefix, name = raw.decode('utf-8').split('\t', 1)
        mode, oid, stage = prefix.split(' ')
        require(stage == '0' and mode in {'100644', '100755', '120000'}, 'Pristine tracked stage schema required')
        path = app / name
        info = path.lstat()
        if mode == '120000':
            require(path.is_symlink(), 'Tracked symlink type changed')
            content = hashlib.sha256(os.readlink(path).encode()).hexdigest()
        else:
            require(stat.S_ISREG(info.st_mode) and not path.is_symlink(), 'Tracked file type changed')
            content = sha(path)
        rows.append([name, mode, oid, stat.S_IMODE(info.st_mode), content])
    require(rows, 'Nonempty tracked source snapshot required')
    return {'sha256': hashlib.sha256(json.dumps(rows, separators=(',', ':')).encode()).hexdigest(),
            'tracked_count': len(rows)}


def skip_reason_catalog(app, platform, commit):
    # The existing source-owned allowlist is unchanged. Literal reasons are
    # internal until an actual skipped node reports the exact same string.
    folder = 'whitenoise-macTests' if platform == 'macos' else 'whitenoise-iosTests'
    modules = ('whitenoise_macTests', 'whitenoise-macTests') if platform == 'macos' else ('whitenoise_iosTests', 'whitenoise-iosTests')
    catalog = {}
    for identifier, (file, category) in KNOWN_SKIPS[platform].items():
        source = git_output(app, 'show', commit + ':' + folder + '/' + file)
        method = identifier.split('/')[1][:-2].encode()
        require(b'func ' + method + b'(' in source, 'Source-owned skipped method required')
        reasons = [value.decode('ascii') for value in re.findall(
            rb'(?:XCTSkip|\.disabled)\("([^"\\\n]{1,256})"\)', source)
                   if value.isascii()]
        row = {'identifier': identifier, 'category': category,
               'source_sha256': hashlib.sha256(source).hexdigest(), 'reasons': reasons}
        for alias in [identifier] + [module + separator + identifier for module in modules for separator in ('/', '.')]:
            catalog[alias] = row
    return catalog


def verify_source_owned_skips(app, platform, skips, commit):
    folder = 'whitenoise-macTests' if platform == 'macos' else 'whitenoise-iosTests'
    result = []
    for row in skips:
        relative = folder + '/' + row['source_file']
        source = git_output(app, 'show', commit + ':' + relative)
        method = row['identifier'].split('/')[1][:-2].encode()
        require(b'func ' + method + b'(' in source
                and (b'XCTSkip(' in source or b'.disabled(' in source),
                'Allowed skip must remain source-owned and explicitly guarded')
        result.append(dict(row, source_sha256=hashlib.sha256(source).hexdigest()))
    return result


def require(value, message):
    if not value:
        raise ValueError(message)


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def guard_settings(app, profile, environment):
    command = ['bash', '-c', 'set -e; repo_root=$1; source "$repo_root/scripts/local-device-sync-settings.sh"; '
               'printf "%s\\n" "$WN_CURRENT_SDK_API" "${WN_VERIFIED_SDK_PROFILE:-}" "${device_sync_settings[*]:-}"',
               'validated-sdk-flags', str(app)]
    values = subprocess.check_output(command, env=environment, text=True).splitlines()
    flags = [] if profile == 'historical' else ['OTHER_SWIFT_FLAGS=$(inherited) -D WN_CURRENT_SDK_API'
                         + (' -D WN_EXPERIMENTAL_DEVICE_SYNC' if profile == 'experimental' else '')]
    require(values == (['0', '', ''] if profile == 'historical' else ['1', profile, flags[0]]),
            'App guard did not establish exact cohort compiler settings')
    return flags


def environment_for(profile, source, run):
    return dict(os.environ, WN_SDK_PROFILE='' if profile == 'historical' else profile,
                WN_CURRENT_SDK_API='0', WN_EXPERIMENTAL_DEVICE_SYNC='1' if profile == 'experimental' else '0',
                WN_SDK_SOURCE_SHA='' if profile == 'historical' else source,
                WN_SDK_RUN_ID='' if profile == 'historical' else run)


def prepare(args):
    app = Path('mac' if args.platform == 'macos' else 'ios').resolve(strict=True)
    head = subprocess.check_output(['git', '-C', str(app), 'rev-parse', 'HEAD'], text=True).strip()
    require(head == args.app_sha, 'Immutable app source differs')
    require(not subprocess.check_output(['git', '-C', str(app), 'status', '--porcelain']), 'Fresh app checkout required')
    package = app / ('Vendored/MarmotKit' if args.platform == 'macos' else 'Packages/MarmotKit')
    environment = environment_for(args.profile, args.sdk_source, args.sdk_run_id)
    requested_platforms = json.loads(os.environ.get('COHORT_PLATFORMS', '["macos","ios"]'))
    require(requested_platforms in (['macos'], ['ios'], ['macos', 'ios'])
            and args.platform in requested_platforms, 'Closed requested app platform matrix required')
    proof = {'scope': 'SDK compatibility full suite, Release/analysis and API adaptation controls ONLY; repository PR/static/coverage/native gates remain separate', 'profile': args.profile, 'platform': args.platform, 'app_sha': head,
             'app_tree': subprocess.check_output(['git', '-C', str(app), 'rev-parse', 'HEAD^{tree}'], text=True).strip(),
             'tools_sha': os.environ['GITHUB_SHA'], 'features': FEATURES[args.profile],
             'requested_platforms': requested_platforms,
             'both_platforms_requested': requested_platforms == ['macos', 'ios'],
             'final_qualification_requires_both_platforms': True,
             'current_api': 0 if args.profile == 'historical' else 1,
             'private_sync': 1 if args.profile == 'experimental' else 0}
    if args.profile == 'historical':
        pin = (package / 'Package.swift').read_text()
        stamp = (package / 'MARMOT_VERSION').read_text()
        require('let marmotKitReleaseID = "0.13.0"' in pin and 'let marmotKitReleaseTag = "marmotkit-v0.13.0"' in pin
                and 'let marmotKitLocalPath: String? = nil' in pin, 'Historical release pin differs')
        require('let marmotKitChecksum = "' + HISTORICAL_CHECKSUMS[args.platform] + '"' in pin,
                'Historical binary checksum differs')
        require(f'mdk-sha: {HISTORICAL_SOURCE}\n' in stamp
                and 'features: otlp-export,product-analytics-export\n' in stamp, 'Historical SDK source differs')
        require(not (package / 'LOCAL_BUILD.json').exists()
                and not (package / 'Artifacts/MarmotKit.xcframework').exists(), 'Historical cohort refuses local SDK overlay')
        proof.update(sdk_source=HISTORICAL_SOURCE, sdk_run_id=None, release='marmotkit-v0.13.0',
                     binary_sha256=HISTORICAL_CHECKSUMS[args.platform],
                     scope='Historical published compatibility ONLY; not a patched default SDK adoption')
        source, run = HISTORICAL_SOURCE, ''
    else:
        require(re.fullmatch('[0-9a-f]{40}', args.sdk_source) and re.fullmatch('[1-9][0-9]*', args.sdk_run_id),
                'Exact F and producer R required')
        subprocess.run([sys.executable, str(HERE / 'install.py'), '--profile', args.profile,
                        '--packages', str(args.packages), '--source', args.sdk_source, '--run-id', args.sdk_run_id,
                        '--platform', args.platform, '--app', str(app), '--app-sha', head],
                       env=environment, check=True)
        local = json.loads((package / 'LOCAL_BUILD.json').read_text())
        receipt = local['qualification_receipt']
        proof.update(sdk_source=args.sdk_source, sdk_run_id=args.sdk_run_id,
                     qualification_sha256=receipt['qualification_sha256'], bundle_sha256=receipt['bundle_sha256'],
                     cargo_lock_sha256=local['cargo_lock_sha256'], rustc=local['rustc'], cargo=local['cargo'],
                     installed_swift_sha256=local['installed_swift_sha256'])
        source, run = args.sdk_source, args.sdk_run_id
    proof['validated_build_settings'] = guard_settings(app, args.profile, environment)
    require(not git_output(app, 'diff', '--cached', '--name-only'), 'Pristine app index required')
    proof['prepared_tracked_snapshot'] = physical_tracked_snapshot(app)
    proof['mutation_original_source_facts'] = {}
    if args.profile != 'historical':
        for relative in dict.fromkeys(item[2] for item in MUTANTS[args.platform]):
            facts = physical_source_facts(app, relative, args.app_sha)
            source_facts_gate(facts, relative)
            proof['mutation_original_source_facts'][relative] = facts
    require(not args.output.exists(), 'Fresh cohort proof required')
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(proof, indent=2) + '\n')
    with open(os.environ['GITHUB_ENV'], 'a') as output:
        for key, value in dict(environment_for(args.profile, source, run), SOURCE_SHA=source, SDK_RUN_ID=run).items():
            if key in {'WN_SDK_PROFILE', 'WN_CURRENT_SDK_API', 'WN_EXPERIMENTAL_DEVICE_SYNC',
                       'WN_SDK_SOURCE_SHA', 'WN_SDK_RUN_ID', 'SOURCE_SHA', 'SDK_RUN_ID'}:
                output.write(key + '=' + value + '\n')


def release(args):
    proof = json.loads(args.output.read_text())
    require(proof['profile'] == args.profile and proof['platform'] == args.platform and proof['app_sha'] == args.app_sha,
            'Release cohort differs')
    app = Path('mac' if args.platform == 'macos' else 'ios').resolve(strict=True)
    environment = environment_for(args.profile, proof['sdk_source'], proof['sdk_run_id'] or '')
    flags = guard_settings(app, args.profile, environment)
    require(flags == proof['validated_build_settings'], 'Release flags differ from full suite')
    temp = Path(os.environ['RUNNER_TEMP'])
    commands = []
    if args.platform == 'macos':
        for action, configuration, directory in [('build', 'Release', 'cohort-release'),
                                                 ('analyze', 'Debug', 'final-mac-derived-data')]:
            commands.append(['xcodebuild', action, '-project', 'whitenoise-mac.xcodeproj', '-scheme', 'whitenoise-mac',
                             '-configuration', configuration, '-destination', 'platform=macOS',
                             '-derivedDataPath', str(temp / directory), 'ARCHS=arm64', 'ONLY_ACTIVE_ARCH=NO',
                             'CODE_SIGNING_ALLOWED=NO', *flags])
    else:
        for flavor in ['Production', 'Staging']:
            commands.append(['xcodebuild', 'build', '-project', 'whitenoise-ios.xcodeproj', '-scheme',
                'Whitenoise (' + flavor + ')', '-configuration', 'Release-' + flavor,
                '-destination', 'generic/platform=iOS', '-derivedDataPath', str(temp / ('release-' + flavor)),
                '-skipPackagePluginValidation', '-skipMacroValidation', 'CODE_SIGNING_ALLOWED=NO', *flags])
        commands.append(['xcodebuild', 'analyze', '-project', 'whitenoise-ios.xcodeproj', '-scheme', 'Whitenoise (Staging)',
            '-configuration', 'Debug-Staging', '-destination', os.environ['WN_TEST_DESTINATION'],
            '-derivedDataPath', str(temp / 'final-ios-derived-data'), '-skipPackagePluginValidation',
            '-skipMacroValidation', 'CODE_SIGNING_ALLOWED=NO', *flags])
    for command in commands:
        subprocess.run(command, cwd=app, env=environment, check=True)
    proof['release_analysis_commands'] = commands
    proof['release_analysis_passed'] = True
    args.output.write_text(json.dumps(proof, indent=2) + '\n')


def summary(args):
    proof = json.loads(args.output.read_text())
    bundle = Path(os.environ['RUNNER_TEMP']) / ('final-mac.xcresult' if args.platform == 'macos' else 'final-ios.xcresult')
    raw = json.loads(subprocess.check_output(['xcrun', 'xcresulttool', 'get', 'test-results', 'summary',
                                             '--path', str(bundle)], text=True))
    counts = summary_counts(raw)
    require(counts is not None and counts['totalTestCount'] > 0, 'Actual nonempty XCTest counts required')
    proof['full_suite_counts'] = counts
    args.output.write_text(json.dumps(proof, indent=2) + '\n')  # Keep actual counts before optional metadata.
    tree = None
    try:
        tree = export_tests(bundle)
        proof['test_inventory'] = test_inventory(tree, raw)
    except (OSError, ValueError, subprocess.SubprocessError):
        proof['test_inventory'] = {'status': 'unknown', 'summary_counts': counts}
    app = Path('mac' if args.platform == 'macos' else 'ios').resolve(strict=True)
    try:
        catalog = skip_reason_catalog(app, args.platform, args.app_sha)
    except (OSError, ValueError, subprocess.SubprocessError):
        catalog = {}
    try:
        proof['skip_evidence'] = skip_reason_evidence(tree, proof['test_inventory'], catalog)
        if proof['skip_evidence']['unknown_reasons']:
            details, details_proof = export_skip_details(bundle, proof['test_inventory'], catalog)
            proof['skip_evidence'] = skip_reason_evidence(tree, proof['test_inventory'], catalog, details)
            proof['skip_evidence']['details_export'] = details_proof
    except (OSError, ValueError, TypeError, KeyError, RecursionError, subprocess.SubprocessError):
        proof['skip_evidence'] = {'status': 'unknown', 'reason_export_complete': False,
                                  'unknown_schema': True}
    proof['skip_evidence'].update(app_sha=args.app_sha, app_tree=proof['app_tree'],
                                  tooling_sha=os.environ['GITHUB_SHA'])
    # Persist actual failure/unknown evidence before rejecting it. Unknown case
    # inventory cannot qualify even if aggregate counts look green.
    proof['inventory_qualified'] = False
    try:
        named = suite_inventory_gate(proof['test_inventory'], counts, args.platform)
        app = Path('mac' if args.platform == 'macos' else 'ios').resolve(strict=True)
        proof['named_separate_skip_gates'] = verify_source_owned_skips(app, args.platform, named, args.app_sha)
        proof['inventory_qualified'] = True
    finally:
        args.output.write_text(json.dumps(proof, indent=2) + '\n')
    require(counts['failedTests'] == 0 and counts['passedTests'] > 0, 'Full suite has runtime failures')


def finalize(args):
    proof = json.loads(args.output.read_text())
    proof['passed_sdk_compatibility_cohort'] = False
    proof['api_mutations'] = []
    app = Path('mac' if args.platform == 'macos' else 'ios').resolve(strict=True)
    try:
        require(proof['profile'] == args.profile and proof['platform'] == args.platform
                and proof['app_sha'] == args.app_sha and proof['tools_sha'] == os.environ['GITHUB_SHA'],
                'Final cohort identity differs')
        require(git_output(app, 'rev-parse', 'HEAD').decode().strip() == args.app_sha
                and git_output(app, 'rev-parse', 'HEAD^{tree}').decode().strip() == proof['app_tree']
                and not git_output(app, 'diff', '--cached', '--name-only'), 'Restored app Git identity/index differs')
        snapshot = physical_tracked_snapshot(app)
        require(snapshot == proof['prepared_tracked_snapshot'], 'Tracked app bytes or modes changed after preparation')
        proof['restored_tracked_snapshot'] = snapshot
        counts = proof.get('full_suite_counts')
        named = suite_inventory_gate(proof.get('test_inventory'), counts, args.platform)
        require(proof.get('inventory_qualified') is True
                and verify_source_owned_skips(app, args.platform, named, args.app_sha)
                    == proof['named_separate_skip_gates'], 'Named separate skip evidence differs')
        environment = environment_for(args.profile, proof['sdk_source'], proof['sdk_run_id'] or '')
        require(guard_settings(app, args.profile, environment) == proof['validated_build_settings'],
                'Final installed SDK guard differs')
        definitions = [] if args.profile == 'historical' else MUTANTS[args.platform]
        for gate in dict.fromkeys(item[0] for item in definitions):
            expected = [item for item in definitions if item[0] == gate]
            value = json.loads((Path(os.environ['RUNNER_TEMP']) / gate / 'result.json').read_text())
            metadata_identity_gate(value, proof, args.profile, args.platform, os.environ['GITHUB_SHA'])
            rows = mutation_rows_gate(value, expected)
            accepted = []
            for definition in expected:
                _, name, relative, selector = definition
                original_facts = proof['mutation_original_source_facts'][relative]
                source_facts_gate(original_facts, relative)
                facts = physical_source_facts(app, relative, args.app_sha, original_facts['prepared_mode'])
                require(facts == original_facts, 'Product source bytes or modes changed from prepared Git source')
                accepted.append(mutation_row_gate(rows[(name, relative, selector)], definition, facts))
            proof['api_mutations'].append({'gate': gate, 'identity_matches': True, 'accepted': True,
                                          'mutants': accepted})
        require(proof.get('release_analysis_passed') is True
                and counts['failedTests'] == 0 and counts['passedTests'] > 0,
                'Suite or Release/analysis remains unqualified')
        proof['passed_sdk_compatibility_cohort'] = True
    finally:
        # No raw exception messages, native summaries, XCResults or private logs.
        args.output.write_text(json.dumps(proof, indent=2) + '\n')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('stage', choices=['prepare', 'release', 'summary', 'finalize'])
    parser.add_argument('--profile', choices=list(FEATURES), required=True)
    parser.add_argument('--platform', choices=['macos', 'ios'], required=True)
    parser.add_argument('--app-sha', required=True)
    parser.add_argument('--sdk-source', default='')
    parser.add_argument('--sdk-run-id', default='')
    parser.add_argument('--packages', type=Path, default=Path('packages'))
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    require(re.fullmatch('[0-9a-f]{40}', args.app_sha), 'Exact app commit required')
    {'prepare': prepare, 'release': release, 'summary': summary, 'finalize': finalize}[args.stage](args)
