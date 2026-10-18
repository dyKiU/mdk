#!/usr/bin/env python3
"""Passive original-case timeline; diagnostic completion never qualifies a product."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import time
import qualify_upstream_storage_boundary as bounded
from upstream_completion_ci import ORIGINALS, FEATURES, compile_cases, digest, ensure, environment, identity, parse_body
from qualify_upstream_body_negative import freeze, layout, feature_identity
from qualify_upstream_composed_enrollment import diagnostics

BASE = '8bab50793e9bf046369cdc5df9c2bae4d074453f'
ROOT = 'crates/marmot-app/src/'
HOOKS = {
    ROOT + 'client/device_linking/sibling_sharing.rs': 28,
    ROOT + 'client/device_linking.rs': 14,
    ROOT + 'client/account_chat_sharing/automatic.rs': 8,
    ROOT + 'native_device_linking/enabled.rs': 2,
    ROOT + 'client/private_enrollment_proposal.rs': 1,
    ROOT + 'client/private_enrollment_proposal/sibling_sharing.rs': 19,
    ROOT + 'native_device_linking/tests/automatic_pairing_acceptance.rs': 13,
}
MODULE = ROOT + 'client/device_linking/sibling_sharing/broad_trace.rs'
SELF = 'scripts/diagnose_upstream_sibling_current.py'
WORKFLOW = '.github/workflows/experimental-sync-ci.yml'
REF = 'refs/heads/ci/upstream-sibling-current-diagnostic-20261018'
OUT = Path('sibling-current-evidence')
BEGIN = '  # SIBLING_CURRENT_JOBS_BEGIN\n'
END = '  # SIBLING_CURRENT_JOBS_END\n'
OPTIONS = 'options: [sibling-current-preflight, sibling-current-diagnostic, '
PREFIX = 'native_device_linking::automatic_pairing_acceptance::'
STAGES = {
    1: 'SelectedEnter', 2: 'SelectedExit', 3: 'RevocationEnter', 4: 'RevocationExit',
    5: 'HistoryEnter', 6: 'HistoryExit', 7: 'ExistingSharingEnter', 8: 'ExistingSharingExit',
    9: 'PersistApprovalEnter', 10: 'PersistApprovalExit', 11: 'AutomaticEnter', 12: 'AutomaticExit',
    13: 'TailEnter', 14: 'TailExit', 15: 'DepartureEnter', 16: 'DepartureExit',
    17: 'AutomaticTickEnter', 18: 'AutomaticTickExit', 19: 'CoreWrapEnter', 20: 'CoreWrapExit',
    21: 'PrepareSendsEnter', 22: 'PrepareSendsExit', 25: 'ObservationDispatch',
    26: 'ObservationWorkerEnter', 27: 'ObservationWorkerExit', 28: 'ObservationFacadeReturn',
    29: 'ObservationResponseTimeout', 30: 'ChannelBecameComplete', 31: 'ChoiceChildAssociation',
    32: 'ExistingOriginalSnapshot', 33: 'RecipientOriginalSnapshot', 34: 'HelperSleepBefore',
    35: 'HelperSleepAfter', 36: 'HelperLeftSnapshotBefore', 37: 'HelperLeftSnapshotAfter',
    38: 'HelperRightSnapshotBefore', 39: 'HelperRightSnapshotAfter', 40: 'FourthDeviceHandoffWindowBegin',
    41: 'WindowEndAtCaseReturnOrUnwind', 42: 'ObservationReason', 43: 'ExistingAutomaticProbeEnter',
    44: 'ExistingAutomaticProbeExit', 45: 'PhaseWaitEnter', 46: 'PhaseWaitExit',
    47: 'HeldConsentWaitEnter', 48: 'HeldConsentWaitExit', 49: 'FreshNativeResponseIsComplete',
    50: 'SourceCoreBeginEnter', 51: 'SourceCoreBeginSucceeded', 52: 'SourceChannelAdmitted',
    53: 'SiblingPublicationEnterKind', 54: 'SiblingFirstParentValidationSucceeded',
    56: 'SiblingCoreWrapEnter', 57: 'SiblingCoreWrapSucceeded',
    58: 'SiblingFinalValidationEnter', 59: 'SiblingFinalValidationSucceeded',
    60: 'SiblingSpawnPrepared', 61: 'SiblingTaskEntered', 62: 'SiblingAdapterEntered',
    63: 'SiblingAdapterReturnedMetAck', 64: 'SiblingTaskOutcomeSuccess',
    65: 'SiblingResultHarvestedKind', 66: 'RecipientNonPrimaryRequestObserved',
    67: 'RecipientRequestAuthenticateEnter', 68: 'RecipientRequestAuthenticateSucceeded',
    69: 'RecipientCoreApproveEnter', 70: 'RecipientCoreApproveSucceeded',
    71: 'RecipientAdmissionWakeSent', 72: 'ObsoleteRequestRetryPublicationRetired',
    73: 'BeginCompletedSiblingSourceEntered', 74: 'NoReceivedEndorsementBypass',
    75: 'NoSharingOriginalBypass', 76: 'OriginalEligibilityEnter',
    77: 'OriginalIneligibleLiveCancelledOrCompleteBypass', 78: 'OriginalEligibilityAccepted',
    79: 'ExistingAttemptMatchEnter', 80: 'ExistingAttemptMismatchOrDeadBypass',
    81: 'ExistingAttemptMatchAccepted', 82: 'ReadRetainedRoundEnter',
    83: 'ReadRetainedRoundResultPhase', 84: 'ValidateExistingGuardEnter',
    85: 'ValidateExistingGuardResult', 86: 'ValidatedSettledRosterEnter',
    87: 'ValidatedSettledRosterResult', 88: 'RetainedRequestLookupEnter',
    89: 'RetainedRequestLookupResult', 90: 'BeginSourceChannelCall',
    91: 'ExistingAccountStorageEnter', 92: 'ExistingAccountStorageResult',
}
HOOK_FILE_HASHES = {'crates/marmot-app/src/client/device_linking/sibling_sharing.rs': '8714f00c456ad57134c45c359a1349c9f4a1c706c2261afbe3c6c05354f622f8', 'crates/marmot-app/src/client/device_linking.rs': '7da356dfaa48bf9ca3dc1e75a8e8f0cd85d8a3538aabd5678c8c252b10670dac', 'crates/marmot-app/src/client/account_chat_sharing/automatic.rs': 'b1051f4d3f222cd6fb1dc8a65d6bfd44610fe5f190a4e43fd81050f4b5e6b1e1', 'crates/marmot-app/src/native_device_linking/enabled.rs': '17383b799ae0505646f6fe33eb9253988376d6592d8198ab230fd33b1ce2207b', 'crates/marmot-app/src/client/private_enrollment_proposal.rs': '8f815fdd6d804d9111e87cd3e44120cb5fda28d27629b3b7681a1b46d93f5941', 'crates/marmot-app/src/native_device_linking/tests/automatic_pairing_acceptance.rs': '1b7e0bd7c60da0fc726c4c9a848f34c60796a9a6c446e8b2f3b7b78daf22d623', 'crates/marmot-app/src/client/private_enrollment_proposal/sibling_sharing.rs': 'ef7adf871b542236cb262b984fa86d959169b1a9d58cfa2e3f51a49732c7db3e'}
MODULE_SHA256 = 'ff5cbb8bf79d5c4d2044a7a21a563687a6af3a5b897efae84ae82727e600cd26'
STRIP = re.compile(rb'(?m)^[ \t]*// BROAD_TRACE_BEGIN\n.*?^[ \t]*// BROAD_TRACE_END\n', re.S)


def source_guard():
    source = subprocess.check_output(['git', 'rev-parse', 'HEAD'], text=True).strip()
    ensure(os.environ.get('GITHUB_ACTIONS') == 'true' and os.environ.get('GITHUB_REPOSITORY') == 'dyKiU/mdk'
           and os.environ.get('GITHUB_EVENT_NAME') == 'workflow_dispatch' and os.environ.get('GITHUB_SHA') == source
           and os.environ.get('GITHUB_REF') == REF
           and os.environ.get('GITHUB_WORKFLOW_REF') == 'dyKiU/mdk/' + WORKFLOW + '@' + REF
           and os.environ.get('UPSTREAM_SIBLING_CURRENT_BASELINE') == BASE, 'exact-reviewed-remote-workflow-source')
    ensure(os.environ.get('CARGO_INCREMENTAL') == '1' and os.environ.get('CARGO_BUILD_JOBS') == '2'
           and os.environ.get('RUST_MIN_STACK') == '4194304', 'fixed-capacity-and-stack')
    ensure(all(os.environ.get(key) == '0' for key in ['CARGO_PROFILE_DEV_DEBUG', 'CARGO_PROFILE_TEST_DEBUG']), 'fixed-debug-profile')
    ensure(all(not os.environ.get(key) for key in ['RUSTFLAGS', 'CARGO_ENCODED_RUSTFLAGS', 'RUSTC_BOOTSTRAP',
           'CARGO_PROFILE_DEV_OPT_LEVEL', 'CARGO_PROFILE_TEST_OPT_LEVEL']), 'no-compiler-profile-overrides')
    subprocess.run(['git', 'merge-base', '--is-ancestor', BASE, source], check=True)
    ensure(subprocess.run(['git', 'diff', '--quiet', 'HEAD']).returncode == 0, 'initial-pristine-inputs')
    baseline = {}
    for entry in subprocess.check_output(['git', 'ls-tree', '-r', '-z', BASE]).split(b'\0'):
        if entry:
            metadata, name = entry.split(b'\t', 1)
            mode, kind, blob = metadata.decode().split()
            ensure(kind == 'blob' and mode in {'100644', '100755', '120000'}, 'ordinary-baseline-tree')
            baseline[os.fsdecode(name)] = (mode, blob)
    current = layout()
    ensure(set(current) == set(baseline) | {SELF, MODULE} and SELF not in baseline and MODULE not in baseline,
           'whole-input-inventory-exact')
    for name, metadata in current.items():
        mode, blob = baseline.get(name, ('100644', None))
        ensure(metadata['git_mode'] == mode and metadata['symlink'] == (mode == '120000')
               and (metadata['symlink'] or metadata['actual_executable'] == (mode == '100755')), 'whole-input-mode:' + name)
        data = os.fsencode(os.readlink(name)) if metadata['symlink'] else Path(name).read_bytes()
        if name == MODULE:
            ensure(digest(data) == MODULE_SHA256, 'reviewed-passive-module-snapshot')
        if name in HOOKS:
            ensure(digest(data) == HOOK_FILE_HASHES[name], 'reviewed-exact-passive-hook-snapshot:' + name)
            ensure(data.count(b'// BROAD_TRACE_BEGIN') == data.count(b'// BROAD_TRACE_END') == HOOKS[name], 'exact-passive-hook-count:' + name)
            data, count = STRIP.subn(b'', data)
            ensure(count == HOOKS[name], 'exact-passive-hook-stripping:' + name)
        if name == WORKFLOW:
            text = data.decode()
            ensure(text.count(BEGIN) == text.count(END) == text.count(OPTIONS) == 1, 'isolated-workflow-overlay')
            before, rest = text.split(BEGIN); _, after = rest.split(END)
            data = (before + after).replace(OPTIONS, 'options: [', 1).encode()
        if blob is not None:
            ensure(hashlib.sha1(b'blob ' + str(len(data)).encode() + b'\0' + data).hexdigest() == blob,
                   'entire-original-source-reconstructed:' + name)
    ensure(set(subprocess.check_output(['git', 'ls-files', '--others', '--exclude-standard'], text=True).splitlines())
           <= {str(OUT / 'result.json')}, 'no-untracked-source-overlay')
    return {'source': source, 'reviewed_baseline': BASE, 'all_original_contents_and_modes_reconstructed': True,
            'historical_helpers_and_original_assertions_deadlines_unchanged': True,
            'allowed_hook_counts': HOOKS, 'new_files': [SELF, MODULE], 'historical_runtime_evidence_reused': False}


def timeline(raw, name):
    ensure(len(raw.encode()) <= 8 * 1024 * 1024, 'bounded-runtime-output')
    clean = re.sub(r'\x1b\[[0-9;]*m', '', raw)
    clean = re.sub(r'(?m)^test ' + re.escape(name) + r' \.\.\. (?=broad-trace )', '', clean)
    summary = None; keys = []; events = []; child_links = set(); completed = set(); unavailable = False
    for line in clean.splitlines():
        if not line.startswith('broad-trace '):
            continue
        ensure(len(line) <= 160, 'bounded-timeline-line')
        if line == 'broad-trace unavailable':
            ensure(summary is None and not keys and not events, 'one-unavailable-snapshot')
            unavailable = True
            summary = {'known': False, 'keys': None, 'events': None}
            continue
        ensure(not unavailable, 'no-data-after-unavailable-snapshot')
        if line.startswith('broad-trace summary '):
            match = re.fullmatch(r'broad-trace summary known=(true|false) keys=([0-9]{1,2}) events=([0-9]{1,4})', line)
            ensure(match is not None and summary is None and not keys and not events, 'one-closed-summary-before-rows')
            summary = {'known': match[1] == 'true', 'keys': int(match[2]), 'events': int(match[3])}
            ensure(summary['keys'] <= 64 and summary['events'] <= 8192, 'closed-timeline-capacity')
        elif line.startswith('broad-trace key='):
            match = re.fullmatch(r'broad-trace key=([1-9][0-9]?) kind=([12])', line)
            ensure(summary is not None and match is not None and not events and len(keys) < summary['keys'], 'closed-key-row')
            ensure(int(match[1]) == len(keys) + 1, 'unique-sequential-key')
            keys.append(int(match[2]))
        else:
            match = re.fullmatch(r'broad-trace event=\[([0-9]{1,12}), ([0-9]{1,2}), ([0-9]{1,2}), ([0-9]{1,2})\]', line)
            ensure(summary is not None and match is not None and len(keys) == summary['keys'] and len(events) < summary['events'], 'closed-event-row')
            stamp, key, stage, value = map(int, match.groups())
            ensure(key <= len(keys) and stage in STAGES and (not events or stamp >= events[-1][0]), 'known-monotonic-event')
            if stage == 31:
                ensure(key > 0 and keys[key - 1] == 1 and 0 < value <= len(keys) and keys[value - 1] == 2, 'actual-choice-child-key-types')
                ensure(value not in child_links, 'one-exact-parent-per-child')
                child_links.add(value)
            elif stage == 30:
                ensure(key > 0 and keys[key - 1] == 2 and value == 1, 'actual-channel-completion-transition')
                ensure(key not in completed, 'one-channel-completion-transition')
                completed.add(key)
            elif stage == 49:
                ensure(key > 0 and keys[key - 1] == 1 and value <= 1, 'closed-fresh-native-response')
            elif stage == 42:
                ensure(key > 0 and keys[key - 1] == 1 and value <= 5, 'closed-observation-reason')
            elif stage in {53, 65}:
                ensure(key > 0 and keys[key - 1] == 2 and value <= 3, 'closed-owned-publication-kind')
            elif stage in {83, 85, 87, 89, 92}:
                maximum = {83: 4, 85: 1, 87: 2, 89: 1, 92: 1}[stage]
                ensure(key > 0 and keys[key - 1] == 2 and value <= maximum, 'closed-source-prerequisite-result')
            elif stage in {63, 64}:
                ensure(key > 0 and keys[key - 1] == 2 and value <= 1, 'closed-actual-publication-outcome')
            else:
                ensure(value == 0, 'no-unreviewed-event-values')
                if stage == 73:
                    pass  # broad_trace_for_test preserves its actual existing attribution.
                elif stage in {74, 75}:
                    ensure(key == 0, 'unattributed-absent-source-original')
                elif stage in {25, 26, 27, 28, 29, 33, 43, 44}:
                    ensure(key > 0 and keys[key - 1] == 1, 'original-choice-observation-key')
                elif stage == 32:
                    ensure(key > 0 and keys[key - 1] == 2, 'existing-original-state-key')
                elif stage in {50, 51, 52, 54, 56, 57, 58, 59, 60, 61, 62, 69, 70, 72, 76, 77, 78, 79, 80, 81, 82, 84, 86, 88, 90, 91}:
                    ensure(key > 0 and keys[key - 1] == 2, 'original-channel-pipeline-key')
                elif stage in {66, 67, 68, 71}:
                    ensure(key > 0 and keys[key - 1] == 1, 'original-recipient-pipeline-key')
                elif stage in {34, 35, 36, 37, 38, 39, 40, 41, 45, 46, 47, 48}:
                    ensure(key == 0, 'unattributed-test-helper-key')
            events.append([stamp, key, stage, value])
    ensure(summary is not None and (unavailable or (len(keys) == summary['keys'] and len(events) == summary['events'])), 'complete-export-inventory')
    if summary['known']:
        ensure(events and events[0][2] == 40 and events[-1][2] == 41
               and sum(event[2] == 40 for event in events) == sum(event[2] == 41 for event in events) == 1,
               'one-owned-fourth-device-handoff-window')
    return {'known': summary['known'], 'window_known': summary['known'],
            'capture_scope': 'fourth-device-handoff-through-case-return-or-unwind',
            'setup_prefix_intentionally_omitted': True, 'prewindow_event_counts': None,
            'prewindow_coverage': 'unknown-not-captured', 'timestamps_relative_to_window_start': True, 'key_kinds': None if unavailable else keys,
            'events_microseconds_key_stage_value': None if unavailable else events,
            'exported_key_count': summary['keys'], 'exported_event_count': summary['events'],
            'stage_names': STAGES, 'unattributed_key_zero_is_not_an_account': True,
            'partial_when_unknown_never_zero_evidence': not summary['known']}


def parser_controls():
    name = PREFIX + ORIGINALS[0]
    valid = 'broad-trace summary known=true keys=2 events=4\nbroad-trace key=1 kind=1\nbroad-trace key=2 kind=2\nbroad-trace event=[0, 0, 40, 0]\nbroad-trace event=[1, 1, 31, 2]\nbroad-trace event=[2, 2, 30, 1]\nbroad-trace event=[3, 0, 41, 0]'
    ensure(timeline(valid, name)['known'], 'closed-timeline-positive')
    ensure(timeline('test ' + name + ' ... ' + valid, name)['known'], 'libtest-prefix-positive')
    unknown = 'broad-trace unavailable'
    ensure(timeline(unknown, name)['known'] is False, 'contention-is-explicit-unknown')
    ensure(timeline(valid.replace('[2, 2, 30, 1]', '[2, 2, 53, 3]'), name)['known'], 'closed-publication-kind-positive')
    ensure(timeline(valid.replace('[2, 2, 30, 1]', '[2, 2, 63, 1]'), name)['known'], 'closed-publication-ack-positive')
    ensure(timeline(valid.replace('[2, 2, 30, 1]', '[2, 2, 72, 0]'), name)['known'], 'closed-actual-retirement-positive')
    ensure(timeline(valid.replace('[2, 2, 30, 1]', '[2, 2, 83, 2]'), name)['known'], 'actual-retained-round-completed-phase-positive')
    ensure(timeline(valid.replace('[2, 2, 30, 1]', '[2, 2, 85, 1]'), name)['known'], 'actual-existing-guard-rejection-positive')
    ensure(timeline(valid.replace('[1, 1, 31, 2]', '[1, 1, 66, 0]'), name)['known'], 'closed-recipient-intake-positive')
    negatives = [valid + '\nbroad-trace private=secret', valid + '\n' + valid,
                 valid.replace('keys=2', 'keys=65'), valid.replace('events=4', 'events=3'),
                 valid.replace('key=2 kind=2', 'key=1 kind=2'), valid.replace('[1, 1, 31, 2]', '[1, 2, 31, 1]'),
                 valid.replace('[2, 2, 30, 1]', '[2, 1, 30, 1]'), valid.replace('[2, 2, 30, 1]', '[2, 2, 30, 0]'),
                 valid.replace('[3, 0, 41, 0]', '[1, 0, 41, 0]'), valid.replace('[1, 1, 31, 2]', '[1, 1, 99, 2]'),
                 valid.replace('[0, 0, 40, 0]', '[0, 0, 40, 9]'), valid.replace('[1, 1, 31, 2]', '[1, 1, 31, 63]'),
                 valid.replace('known=true', 'known=secret'), unknown + '\n' + unknown, unknown + '\n' + valid, valid.replace('[1, 1, 31, 2]', '["private", 1, 31, 2]'),
                 valid.replace('broad-trace event=[1, 1, 31, 2]\n', ''),
                 'test foreign ... ' + valid, valid.replace('[3, 0, 41, 0]', '[3, 0, 40, 0]'),
                 valid.replace('[1, 1, 31, 2]', '[1, 2, 25, 0]'),
                 valid.replace('[2, 2, 30, 1]', '[2, 1, 49, 2]'),
                 valid.replace('[3, 0, 41, 0]', '[3, 1, 41, 0]'),
                 valid.replace('events=4', 'events=5').replace('[2, 2, 30, 1]', '[2, 2, 30, 1]\nbroad-trace event=[2, 2, 30, 1]'),
                 valid.replace('events=4', 'events=5').replace('[1, 1, 31, 2]', '[1, 1, 31, 2]\nbroad-trace event=[1, 1, 31, 2]'),
                 valid.replace('[2, 2, 30, 1]', '[2, 2, 53, 4]'),
                 valid.replace('[2, 2, 30, 1]', '[2, 2, 63, 2]'),
                 valid.replace('[2, 2, 30, 1]', '[2, 1, 69, 0]'),
                 valid.replace('[1, 1, 31, 2]', '[1, 2, 66, 0]'),
                 valid.replace('[2, 2, 30, 1]', '[2, 1, 72, 0]'),
                 valid.replace('[2, 2, 30, 1]', '[2, 2, 72, 1]'),
                 valid.replace('[2, 2, 30, 1]', '[2, 1, 83, 2]'),
                 valid.replace('[2, 2, 30, 1]', '[2, 2, 83, 5]'),
                 valid.replace('[2, 2, 30, 1]', '[2, 2, 85, 2]'),
                 valid.replace('[2, 2, 30, 1]', '[2, 2, 87, 3]'),
                 valid.replace('[2, 2, 30, 1]', '[2, 2, 89, 2]'),
                 valid.replace('[2, 2, 30, 1]', '[2, 2, 92, 2]'),
                 valid.replace('[2, 2, 30, 1]', '[2, 2, 74, 0]')]
    for raw in negatives:
        try:
            timeline(raw, name)
        except ValueError:
            continue
        raise ValueError('unsafe-or-incomplete-timeline-accepted')
    return {'positive': 9, 'negative': len(negatives), 'executed_remotely': True}


def main(options):
    os.umask(0o077); OUT.mkdir(exist_ok=True)
    report = {'qualification_passed': False, 'product_green_claim': False, 'native_closes': 'unknown-original-fixtures',
              'historical_runtime_evidence_reused': False, 'actual_counts_complete': False,
              'trace_scope': 'fourth-device-handoff-through-case-return-or-unwind',
              'diagnostic_extension': 'current-source-prerequisite-attribution-and-owned-pipeline',
              'publication_kind_legend': {'0': 'SourceRequest', '1': 'RecipientConsent',
                                          '2': 'SourceProof', '3': 'RecipientProof'},
              'setup_prefix_intentionally_omitted': True, 'event_capacity_unchanged': 8192, 'cases': {}}
    def save():
        (OUT / 'result.json').write_text(json.dumps(report, indent=2) + '\n')
    before = None; metadata = None
    try:
        report['source_guard'] = source_guard(); report['parser_controls'] = parser_controls(); save()
        if options.preflight:
            report['source_and_parser_preflight_passed'] = True; save(); return
        report['environment'] = environment()
        before, metadata = freeze(), layout()
        report['source_before_sha256'] = identity(before)
        selected = [ORIGINALS[0], ORIGINALS[1]]
        compilation, cases = compile_cases(selected)
        report['compilation'] = compilation; save()
        ensure(compilation.get('compile_exit_code') == compilation.get('compiler_error_count') == 0
               and compilation.get('compiled_fingerprints', {}).get('verified') is True
               and len(compilation['compiled_fingerprints']['nodes']) == 6 and set(cases) == set(selected), 'real-compile-and-exact-two-case-inventory')
        report['feature_identity'] = feature_identity(compilation)
        for index, suffix in enumerate(selected):
            case = cases[suffix]; name = PREFIX + suffix
            ensure(case['name'] == name and freeze() == before and layout() == metadata, 'before-case-exact-source-and-test')
            ensure(digest(Path(case['binary']).read_bytes()) == case['binary_sha256'], 'actual-compiled-binary')
            started = time.monotonic()
            try:
                previous_trace_env = os.environ.get('MDK_UPSTREAM_BROAD_TRACE')
                os.environ['MDK_UPSTREAM_BROAD_TRACE'] = '1'
                try:
                    code, raw, _ = bounded.capture([case['binary'], '--exact', name, '--nocapture', '--test-threads=1'], 300, limit=8 * 1024 * 1024)
                finally:
                    if previous_trace_env is None:
                        os.environ.pop('MDK_UPSTREAM_BROAD_TRACE', None)
                    else:
                        os.environ['MDK_UPSTREAM_BROAD_TRACE'] = previous_trace_env
            except bounded.GateFailure as error:
                report['cases'][suffix] = {'watchdog_triggered': str(error) == 'bounded-command-timeout',
                                          'output_limit_triggered': str(error) == 'bounded-command-output-limit',
                                          'actual_count_unknown': True}; save()
                raise ValueError('bounded-diagnostic-not-completed') from None
            row = parse_body(raw, suffix)
            row.update(body_exit_code=code, seconds=time.monotonic() - started,
                       compiled_binary_sha256=case['binary_sha256'])
            report['cases'][suffix] = row; save()
            row['timeline'] = timeline(raw, name); save()
            clean = re.sub(r'(?m)^test ' + re.escape(name) + r' \.\.\. (?=automatic-enrollment-control )', '', raw)
            row['original_diagnostics'] = diagnostics(clean)
            if index == 1:
                row['actual_held_consent_marker_observed'] = 'sibling-consent-held-before-peer-progress' in row.get('hold_markers', [])
                row['held_marker_classification'] = ('ObservedActualHoldBeforeOtherPeerProgressFailureOrPass'
                    if row['actual_held_consent_marker_observed'] else 'ActualHoldNotObservedInThisExecution')
            save()
            ensure(all(type(row.get(key)) is int for key in ['passed', 'failed', 'ignored', 'executed_nonignored'])
                   and row['executed_nonignored'] == row['passed'] + row['failed'] == 1 and row['ignored'] == 0,
                   'actual-one-nonignored-body-per-case')
            ensure(re.findall(r'(?m)^test ([A-Za-z_0-9:]+) \.\.\.', raw) == [name], 'exact-executed-test-name')
            ensure(code in {0, 101}, 'no-abnormal-process-exit')
            if row['failed']:
                source = Path(ROOT + 'native_device_linking/tests/automatic_pairing_acceptance.rs')
                lines = source.read_text().splitlines()
                message = ('automatic pairing did not reach required phase:' if index == 0 else
                           'one blocked consent publication must not starve another approved sibling')
                matches = [position for position, line in enumerate(lines) if message in line]
                ensure(len(matches) == 1, 'unique-original-failure-oracle')
                line = matches[0] + 1 if index == 0 else max(position for position in range(matches[0]) if 'assert!(' in lines[position]) + 1
                ensure(code == 101 and row['all_panic_header_count'] == 1 and len(row['panic_locations']) == 1
                       and row['panic_locations'][0]['file'] == str(source) and row['panic_locations'][0]['line'] == line,
                       'sole-original-runtime-failure-not-unrelated-panic')
            else:
                ensure(code == 0 and row['passed'] == 1 and row['all_panic_header_count'] == 0, 'actual-runtime-pass')
            ensure(freeze() == before and layout() == metadata and digest(Path(case['binary']).read_bytes()) == case['binary_sha256'], 'after-case-pristine-source-modes-binary')
            ensure(row['timeline']['known'] is True, 'unknown-or-incomplete-timeline-not-completed-diagnosis')
            row['diagnostic_completed'] = True; save()
        report['actual_counts_complete'] = True
        report['actual_executed_nonignored'] = sum(row['executed_nonignored'] for row in report['cases'].values())
        report['actual_passed'] = sum(row['passed'] for row in report['cases'].values())
        report['actual_failed'] = sum(row['failed'] for row in report['cases'].values())
        report['actual_ignored'] = sum(row['ignored'] for row in report['cases'].values())
        report['diagnostic_completed'] = True
    except Exception as error:
        report['exception_type'] = type(error).__name__
        raise
    finally:
        if before is not None:
            report['source_after_sha256'] = identity(freeze())
            report['inputs_pristine'] = freeze() == before and layout() == metadata
        save()
        if before is not None:
            ensure(report['inputs_pristine'], 'final-source-and-modes-pristine')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--preflight', action='store_true')
    main(parser.parse_args())
