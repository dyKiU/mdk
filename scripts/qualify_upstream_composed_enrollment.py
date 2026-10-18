#!/usr/bin/env python3
"""Fresh eight-control qualification of the reviewed f413/enrollment composition."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import qualify_upstream_recipient_admission_candidate as historical
from upstream_completion_ci import ensure
from qualify_upstream_body_negative import layout

BASE = '1cc0109cb653ac6377f0dba3e4cfb987e84877f9'
HELPER_SOURCE = '50c2df29223b94963597325a1572eba4cf8492ae'
HELPER = 'scripts/qualify_upstream_recipient_admission_candidate.py'
HELPER_BLOB = 'a4f3b3b6c2db7df497d617c408419710a3c2d8d0'
SELF = 'scripts/qualify_upstream_composed_enrollment.py'
WORKFLOW = '.github/workflows/experimental-sync-ci.yml'
REF = 'refs/heads/ci/upstream-composed-enrollment-20261018'
OUT = Path('composed-enrollment-evidence')
BEGIN = '  # COMPOSED_ENROLLMENT_JOBS_BEGIN\n'
END = '  # COMPOSED_ENROLLMENT_JOBS_END\n'
OPTIONS = 'options: [composed-enrollment-preflight, composed-enrollment-green, '


def source_guard():
    source = subprocess.check_output(['git', 'rev-parse', 'HEAD'], text=True).strip()
    ensure(os.environ.get('GITHUB_ACTIONS') == 'true' and os.environ.get('GITHUB_REPOSITORY') == 'dyKiU/mdk'
           and os.environ.get('GITHUB_EVENT_NAME') == 'workflow_dispatch' and source == os.environ.get('GITHUB_SHA')
           and os.environ.get('GITHUB_REF') == REF
           and os.environ.get('GITHUB_WORKFLOW_REF') == 'dyKiU/mdk/' + WORKFLOW + '@' + REF
           and os.environ.get('UPSTREAM_COMPOSED_ENROLLMENT_BASELINE') == BASE,
           'exact-owned-reviewed-composition-workflow-source')
    ensure(os.environ.get('CARGO_INCREMENTAL') == '1' and os.environ.get('CARGO_BUILD_JOBS') == '2'
           and os.environ.get('RUST_MIN_STACK') == '4194304', 'fixed-execution-capacity-and-stack')
    for name in ['CARGO_PROFILE_DEV_DEBUG', 'CARGO_PROFILE_TEST_DEBUG']:
        ensure(os.environ.get(name) == '0', 'fixed-debug-profile')
    for name in ['RUSTFLAGS', 'CARGO_ENCODED_RUSTFLAGS', 'RUSTC_BOOTSTRAP',
                 'CARGO_PROFILE_DEV_OPT_LEVEL', 'CARGO_PROFILE_TEST_OPT_LEVEL']:
        ensure(not os.environ.get(name), 'no-compiler-profile-override')
    subprocess.run(['git', 'merge-base', '--is-ancestor', BASE, source], check=True)
    ensure(subprocess.run(['git', 'diff', '--quiet', 'HEAD']).returncode == 0, 'initial-pristine-tracked-inputs')
    baseline = {}
    for entry in subprocess.check_output(['git', 'ls-tree', '-r', '-z', BASE]).split(b'\0'):
        if entry:
            metadata, path = entry.split(b'\t', 1)
            mode, kind, blob = metadata.decode().split()
            ensure(kind == 'blob' and mode in {'100644', '100755', '120000'}, 'ordinary-baseline-tree')
            baseline[os.fsdecode(path)] = (mode, blob)
    current = layout()
    ensure(HELPER not in baseline and SELF not in baseline
           and set(current) == set(baseline) | {HELPER, SELF}, 'entire-tracked-inventory-exact')
    for name, metadata in current.items():
        mode, blob = baseline.get(name, ('100644', None))
        ensure(metadata['git_mode'] == mode and metadata['symlink'] == (mode == '120000')
               and (metadata['symlink'] or metadata['actual_executable'] == (mode == '100755')),
               'entire-tracked-layout:' + name)
        data = os.fsencode(os.readlink(name)) if metadata['symlink'] else Path(name).read_bytes()
        if name == WORKFLOW:
            text = data.decode()
            ensure(text.count(BEGIN) == text.count(END) == text.count(OPTIONS) == 1, 'one-isolated-composition-workflow-overlay')
            before, rest = text.split(BEGIN); _, after = rest.split(END)
            data = (before + after).replace(OPTIONS, 'options: [', 1).encode()
        actual = hashlib.sha1(b'blob ' + str(len(data)).encode() + b'\0' + data).hexdigest()
        if blob is not None:
            ensure(actual == blob, 'entire-original-content-exact:' + name)
        if name == HELPER:
            ensure(actual == HELPER_BLOB and data == subprocess.check_output(['git', 'show', HELPER_SOURCE + ':' + HELPER]),
                   'historical-helper-exact-reviewed-blob')
    ensure(set(subprocess.check_output(['git', 'ls-files', '--others', '--exclude-standard'], text=True).splitlines())
           <= {str(OUT / 'result.json')}, 'no-untracked-source-overlays')
    product = Path(historical.PRODUCT).read_bytes()
    ensure(product.count(historical.NEW_FIRST_SHOT_REGION) == product.count(historical.FULL_WAKE_REGION) == 1,
           'exact-af330-first-consent-two-product-regions')
    ensure(product.count(b'PEER_NEGATIVE_TEST_BEGIN') > 0, 'existing-composed-negative-probes-present')
    return {'source': source, 'baseline': BASE, 'entire_tracked_content_and_modes_verified': True,
            'historical_helper_source': HELPER_SOURCE, 'historical_helper_blob': HELPER_BLOB,
            'all_existing_products_fixtures_deadlines_and_controllers_unchanged': True,
            'first_consent_regions_match_reviewed_af330': True, 'private_negative_probes_preserved': True,
            'historical_runtime_or_archive_evidence_reused': False, 'full_integration_qualified': False}

# Closed aggregate parser retained from the reviewed 6e75 diagnostic helper.
PHASES = 'AwaitingSetup|AwaitingPeer|ComparisonAvailable|AwaitingPeerVerification|VerificationCompleteEnrollmentPending|Cancelled|Expired|Failed|EnrollmentComplete'
NUMBER = r'(?:0|[1-9][0-9]{0,18})'
BOOLEAN = r'(?:true|false)'
FAILURE = r'(?:Owner|Collection|Runtime|Engine|Genesis|Gate|PrivateInvite)'
STAGE = r'(?:BeforeCoreWrap|AfterCoreWrap|BeforeRelayPublication|AfterRelayPublication)'
REASON = r'(?:VerifierFallback|NoRound|GuardInvalid|NoSettledRoster|SharingPending|Complete)'

def option(pattern):
    return r'(?:None|Some\(' + pattern + r'\))'

def sequence(pattern, length, opening=r'\(', closing=r'\)'):
    return opening + ', '.join([pattern] * length) + closing

def array(length):
    return sequence(NUMBER, length, r'\[', r'\]')

CHANNEL = r'\(' + ', '.join([NUMBER] * 3 + [option(FAILURE), option(STAGE)]) + r'\)'
CHILDREN = option(r'\[(?:' + CHANNEL + r'(?:, ' + CHANNEL + r'){0,7})?\]')
AGGREGATES = option(r'\(' + BOOLEAN + ', ' + option(NUMBER) + ', ' + NUMBER + ', ' + NUMBER + r'\)')
RPC = option(r'\(' + array(6) + ', ' + array(6) + ', ' + option(r'\(' + REASON + ', ' + NUMBER + r'\)') + r'\)')
SCHEMAS = [
    ('aggregates', r'side=(left|right) primary/expected/children/completed=(' + AGGREGATES + ') intake=(' + option(array(8)) + ') rejections=(' + option(array(4)) + ') context_rejections=(' + option(array(9)) + ') projection=(' + option(array(4)) + ')'),
    ('child_channels', r'side=(left|right) child_channels=(' + CHILDREN + ')'),
    ('native_rpc', r'side=(left|right) native_rpc_counts/elapsed_ms/branch=(' + RPC + ')'),
    ('existing_child', r'existing_index=([01]) child_channel=(' + option(CHANNEL) + ')'),
]
STAGES = {'initial-two-comparison', 'initial-two-completion', 'initial-two-completed', 'third-device-comparison', 'third-device-completion', 'third-device-completed', 'fourth-device-comparison', 'fourth-device-completion', 'fourth-device-completed', 'sibling-consent-held-before-peer-progress', 'automatic-publication-held-before-completion'}
PREFIX = 'automatic-enrollment-control '
PHASE_LINE = r'automatic pairing did not reach required phase: expected=(' + PHASES + r') observed=(None|Some\(\((' + PHASES + '), (' + PHASES + r')\)\))'


def diagnostics(raw):
    ensure(len(raw.encode()) <= 8 * 1024 * 1024, 'bounded-runtime-output')
    # No raw log/panic strings survive this function. Even diagnostic values
    # must match their complete closed tuple schema, without quoted strings.
    rows = []
    stages = []
    phase_rows = []
    seen = set()
    for line in raw.splitlines():
        if line.startswith(PREFIX):
            payload = line[len(PREFIX):]
            ensure(len(payload) <= 4096, 'bounded-diagnostic-line')
            if payload.startswith('stage='):
                stage = payload[6:]
                ensure(stage in STAGES and len(stages) < 16, 'known-bounded-stage')
                stages.append(stage)
                continue
            matched = False
            for category, pattern in SCHEMAS:
                match = re.fullmatch(pattern, payload)
                if not match:
                    continue
                key = (category, match[1])
                ensure(key not in seen and len(rows) < 8, 'unique-bounded-aggregate')
                seen.add(key)
                # Bit flags are the FIRST field; visits and failures follow.
                if category in {'child_channels', 'existing_child'}:
                    flags = re.findall(r'\((' + NUMBER + '), ' + NUMBER + ', ' + NUMBER + r', (?:None|Some\(' + FAILURE + r'\)),', payload)
                    ensure(all(int(value) <= 255 for value in flags), 'known-channel-bitmask')
                rows.append({'category': category, 'side_or_existing_index': match[1], 'closed_schema_values': list(match.groups()[1:])})
                matched = True
                break
            ensure(matched, 'unknown-aggregate-schema')
        elif line.startswith('automatic pairing did not reach required phase:'):
            match = re.fullmatch(PHASE_LINE, line)
            ensure(match is not None and not phase_rows, 'known-unique-phase-schema')
            phase_rows.append({'expected': match[1], 'observed_missing': match[2] == 'None', 'left': match[3], 'right': match[4]})
        elif re.match(r'(?:left|right) expected=', line):
            match = re.fullmatch(r'(left|right) expected=(' + PHASES + r') observed=(' + PHASES + r')', line)
            ensure(match is not None and not phase_rows, 'known-unique-terminal-phase-schema')
            phase_rows.append({'side': match[1], 'expected': match[2], 'observed': match[3]})
    return {'aggregates': rows, 'stages': stages, 'phase_failures': phase_rows, 'missing_diagnostics': not rows}


def diagnostic_parser_controls():
    aggregate = PREFIX + 'side=left primary/expected/children/completed=Some((true, Some(2), 2, 0)) intake=Some([0, 1, 2, 3, 4, 5, 6, 7]) rejections=None context_rejections=None projection=None'
    channel = PREFIX + 'side=right child_channels=Some([(255, 2, 1, Some(Genesis), Some(AfterRelayPublication))])'
    rpc = PREFIX + 'side=left native_rpc_counts/elapsed_ms/branch=Some(([1, 2, 3, 4, 5, 6], [0, 0, 1, 2, 3, 4], Some((SharingPending, 12))))'
    existing = PREFIX + 'existing_index=1 child_channel=None'
    phase = 'automatic pairing did not reach required phase: expected=EnrollmentComplete observed=Some((VerificationCompleteEnrollmentPending, AwaitingPeerVerification))'
    positives = [aggregate, channel, rpc, existing, phase, 'left expected=EnrollmentComplete observed=Failed', 'private runtime output must be discarded']
    for value in positives:
        diagnostics(value)
    negatives = [aggregate + ' private', aggregate.replace('side=left', 'side=secret'), aggregate.replace('Some(2)', 'Some(-2)'), aggregate.replace('Some(2)', 'Some(12345678901234567890)'), aggregate.replace('true', 'secret'), channel.replace('255', '256'), channel.replace('Genesis', 'Unknown'), channel.replace('AfterRelayPublication', 'Unknown'), rpc.replace('SharingPending', 'Unknown'), existing.replace('index=1', 'index=2'), phase.replace('AwaitingPeerVerification', 'Unknown'), 'left expected=EnrollmentComplete observed=secret', phase + '\n' + phase, aggregate + '\n' + aggregate, PREFIX + 'private=secret', PREFIX + 'x' * 4097, PREFIX + 'stage=unknown', PREFIX + 'stage=third-device-completion\n' + '\n'.join([PREFIX + 'stage=third-device-completion'] * 16), channel.replace('(255, 2, 1', '("secret", 2, 1')]
    for value in negatives:
        try:
            diagnostics(value)
        except ValueError:
            continue
        raise ValueError('adversarial-parser-control-accepted')
    ensure(diagnostics(phase)['phase_failures'][0]['left'] == 'VerificationCompleteEnrollmentPending', 'phase-projection')
    ensure(not diagnostics('private runtime output')['aggregates'], 'unrelated-raw-output-discarded')
    return {'positive_controls': len(positives), 'negative_controls': len(negatives), 'passed': True}



_original_parse = historical.parse
_original_parser_controls = historical.parser_controls


def parse(label, raw, exit_code):
    row = _original_parse(label, raw, exit_code)
    if label.startswith('original_'):
        clean = re.sub(r'\x1b\[[0-9;]*m', '', raw)
        name = next(name for key, _, name in historical.CASES if key == label)
        clean = re.sub(r'(?m)^test ' + re.escape(name) + r' \.\.\. (?=automatic-enrollment-control )', '', clean)
        try:
            row['closed_original_diagnostics'] = diagnostics(clean)
            row['diagnostic_parser_passed'] = True
        except ValueError:
            row['diagnostic_parser_passed'] = False
            row['diagnostic_parser_error'] = 'ClosedSchemaRejected'
    return row


def parser_controls():
    return {'unchanged_eight_control_parsers': _original_parser_controls(),
            'closed_aggregate_parser': diagnostic_parser_controls(), 'actual_runtime_bodies': 0}


def main(options):
    ensure(options.mode in {'green', 'static'}, 'no-mutation-or-archive-mode-in-composition-lane')
    historical.source_guard = source_guard
    historical.OUT = OUT
    historical.parse = parse
    historical.parser_controls = parser_controls
    try:
        historical.main(options)
    finally:
        path = OUT / 'result.json'
        if path.exists():
            report = json.loads(path.read_text())
            if 'baseline_test_source' in report:
                report['historical_helper_baseline_label'] = report.pop('baseline_test_source')
            report.update(reviewed_product_baseline=BASE, baseline_test_source=BASE,
                          helper_source=HELPER_SOURCE, historical_runtime_or_archive_evidence_reused=False,
                          historical_red_is_component_history_only=True,
                          mutations_executed=False, full_integration_qualified=False)
            path.write_text(json.dumps(report, indent=2) + '\n')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--preflight', action='store_true')
    parser.add_argument('--mode', choices=['green', 'static'], default='green')
    parser.add_argument('--cohort', choices=['default', 'experimental'])
    main(parser.parse_args())
