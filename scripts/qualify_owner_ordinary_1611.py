#!/usr/bin/env python3
"""Four frozen owner-contract fairness/recovery cases; no full qualification."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import selectors
import shutil
import signal
import stat
import subprocess
import time

BASE = '1611fa4ba239933d41875017e12464fef2f4e0d0'
SELF = 'scripts/qualify_owner_ordinary_1611.py'
WORKFLOW = '.github/workflows/experimental-sync-ci.yml'
REF = 'refs/heads/ci/upstream-owner-components-1611-20261018'
FIXTURE = 'crates/marmot-app/src/native_device_linking/tests/automatic_pairing_acceptance.rs'
SUFFIX = 'third_and_later_device_enrollment_need_no_extra_qr_or_manual_artifacts'
PREFIX = 'native_device_linking::automatic_pairing_acceptance::'
CASES = [
    'blocked_sibling_consent_does_not_starve_another_approved_peer',
    'automatic_sync_does_not_block_foreground_enrollment_completion',
    'cancelled_setup_can_reverse_roles_after_restart_and_complete_enrollment',
    'interrupted_first_enrollment_same_peer_completes_after_restart',
]
# Retain the already-qualified ordinary wrapper alignment, without rerunning it.
ALIGNED_WRAPPERS = [SUFFIX] + CASES
NAME = PREFIX + CASES[0]
BEGIN = '  # OWNER_COMPONENTS_1611_JOBS_BEGIN\n'
END = '  # OWNER_COMPONENTS_1611_JOBS_END\n'
OPTIONS = 'options: [owner-components-preflight, owner-components-baseline, '
FEATURES = 'marmot-app/experimental-device-sync,marmot-app/test-policy-overrides,marmot-app/otlp-export,marmot-app/product-analytics-export'
ROOT_FEATURES = sorted(['default', 'experimental-device-sync', 'test-policy-overrides', 'otlp-export', 'product-analytics-export'])
OUT = Path('owner-components-1611-evidence')

FIVE_REF = 'refs/heads/ci/upstream-owner-five-1611-20261018'
FIVE_FILE = 'crates/marmot-app/src/native_device_linking/tests/sequential_installations_acceptance.rs'
FIVE_SUFFIX = 'sequential_installations_acceptance::five_installations_join_with_rotating_existing_sponsors_and_explicit_sharing'
FIVE_NAME = PREFIX + FIVE_SUFFIX
FIVE_SHA256 = '97f70b7b61523b95efb1f5e85bc69669d8fefa940f3741d7b340ca41bfbf88d6'
FIVE_BEGIN = '  # OWNER_FIVE_1611_JOBS_BEGIN\n'
FIVE_END = '  # OWNER_FIVE_1611_JOBS_END\n'
FIVE_OPTIONS = 'options: [owner-five-preflight, owner-five-acceptance, '
FIVE_REGISTRATION = '\n// OWNER_FIVE_1611_REGISTRATION_BEGIN\n#[path = "sequential_installations_acceptance.rs"]\nmod sequential_installations_acceptance;\n// OWNER_FIVE_1611_REGISTRATION_END\n'

class GateFailure(ValueError):
    pass


def ensure(value, label):
    if not value:
        raise GateFailure(label)


def digest(data):
    return hashlib.sha256(data).hexdigest()


def snapshot():
    result = {}
    for entry in subprocess.check_output(['git', 'ls-files', '--stage', '-z']).split(b'\0'):
        if not entry: continue
        metadata, name = entry.split(b'\t', 1)
        mode, _, stage = metadata.decode().split(); name = os.fsdecode(name)
        ensure(stage == '0' and mode in {'100644', '100755', '120000'}, 'ordinary-tracked-modes')
        p = Path(name); kind = p.lstat().st_mode
        ensure((stat.S_ISREG(kind) or stat.S_ISLNK(kind)) and p.is_symlink() == (mode == '120000'), 'ordinary-files-or-links')
        data = os.fsencode(os.readlink(name)) if p.is_symlink() else p.read_bytes()
        result[name] = {'mode': mode, 'actual_executable': bool(kind & 0o111), 'sha256': digest(data)}
    return result


def source_guard(five=False):
    source = subprocess.check_output(['git', 'rev-parse', 'HEAD'], text=True).strip()
    ensure(os.environ.get('GITHUB_ACTIONS') == 'true' and os.environ.get('GITHUB_REPOSITORY') == 'dyKiU/mdk'
           and os.environ.get('GITHUB_EVENT_NAME') == 'workflow_dispatch' and os.environ.get('GITHUB_SHA') == source
           and os.environ.get('GITHUB_REF') == (FIVE_REF if five else REF)
           and os.environ.get('GITHUB_WORKFLOW_REF') == 'dyKiU/mdk/' + WORKFLOW + '@' + (FIVE_REF if five else REF)
           and os.environ.get('OWNER_COMPONENTS_BASELINE') == BASE, 'exact-owned-remote-source')
    ensure(os.environ.get('CARGO_INCREMENTAL') == '1' and os.environ.get('CARGO_BUILD_JOBS') == '2'
           and os.environ.get('RUST_MIN_STACK') == '4194304'
           and all(os.environ.get(k) == '0' for k in ['CARGO_PROFILE_DEV_DEBUG', 'CARGO_PROFILE_TEST_DEBUG'])
           and all(not os.environ.get(k) for k in ['RUSTFLAGS', 'CARGO_ENCODED_RUSTFLAGS', 'RUSTC_BOOTSTRAP',
               'CARGO_PROFILE_DEV_OPT_LEVEL', 'CARGO_PROFILE_TEST_OPT_LEVEL']), 'fixed-feature-compiler-launch')
    subprocess.run(['git', 'merge-base', '--is-ancestor', BASE, source], check=True)
    ensure(subprocess.run(['git', 'diff', '--quiet', 'HEAD']).returncode == 0, 'initial-tracked-inputs-pristine')
    baseline = {}
    for entry in subprocess.check_output(['git', 'ls-tree', '-r', '-z', BASE]).split(b'\0'):
        if entry:
            metadata, name = entry.split(b'\t', 1); mode, kind, blob = metadata.decode().split()
            ensure(kind == 'blob' and mode in {'100644', '100755', '120000'}, 'ordinary-baseline-tree')
            baseline[os.fsdecode(name)] = (mode, blob)
    frozen = snapshot()
    ensure(set(frozen) == set(baseline) | ({SELF,FIVE_FILE} if five else {SELF}) and SELF not in baseline and FIVE_FILE not in baseline, 'whole-owner-input-inventory')
    for name, actual in frozen.items():
        mode, blob = baseline.get(name, ('100644', None))
        ensure(actual['mode'] == mode and (mode == '120000' or actual['actual_executable'] == (mode == '100755')), 'whole-owner-mode')
        data = os.fsencode(os.readlink(name)) if mode == '120000' else Path(name).read_bytes()
        if name == FIXTURE:
            text = data.decode()
            for suffix in ALIGNED_WRAPPERS:
                old = '#[tokio::test]\nasync fn ' + suffix + '() {'
                new = '#[tokio::test(flavor = "multi_thread", worker_threads = 2)]\nasync fn ' + suffix + '() {'
                ensure(text.count(new) == 1 and old not in text, 'exact-reviewed-wrapper-flavor')
                text = text.replace(new, old, 1)
            if five:
                ensure(text.count(FIVE_REGISTRATION)==1,'one-exact-new-module-registration')
                text=text.replace(FIVE_REGISTRATION,'',1)
            data = text.encode()
        if five and name == FIVE_FILE:
            ensure(digest(data)==FIVE_SHA256,'exact-reviewed-five-device-module')
        if name == WORKFLOW:
            text = data.decode(); begin,end,options=(FIVE_BEGIN,FIVE_END,FIVE_OPTIONS) if five else (BEGIN,END,OPTIONS)
            ensure(text.count(begin) == text.count(end) == text.count(options) == 1, 'one-owned-workflow-overlay')
            before, rest = text.split(begin); _, after = rest.split(end)
            data = (before + after).replace(options, 'options: [', 1).encode()
        if blob is not None:
            ensure(hashlib.sha1(b'blob ' + str(len(data)).encode() + b'\0' + data).hexdigest() == blob, 'whole-owner-content:' + name)
    ensure(not subprocess.check_output(['git', 'ls-files', '--others', '--exclude-standard'], text=True).strip(), 'no-untracked-source-overlay')
    return {'source': source, 'baseline': BASE, 'all_owner_contents_and_modes_reconstructed': True,
            'only_Rust_delta': 'five wrapper attributes plus exact reviewed new fifth-device module/registration' if five else 'five explicitly listed wrapper attributes Tokio multi_thread worker_threads=2',
            'new_five_fixture_sha256': FIVE_SHA256 if five else None,
            'aligned_wrappers': ALIGNED_WRAPPERS, 'runtime_selected_cases': [FIVE_SUFFIX] if five else CASES,
            'owner_EnrollmentComplete_seconds': 90, 'owner_comparison_seconds': 15,
            'owner_real_held_setup_seconds': 90, 'owner_actual_held_fairness_seconds': 10,
            'all_bodies_assertions_deadlines_lock_and_SDK_inputs_unchanged': True,
            'strict_integration_15s_oracle_adopted': False}


def capture(command, timeout, limit):
    started = time.monotonic(); proc = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, start_new_session=True)
    chunks = []; size = 0
    try:
        with selectors.DefaultSelector() as selected:
            selected.register(proc.stdout, selectors.EVENT_READ)
            while selected.get_map():
                ensure(time.monotonic() - started < timeout, 'bounded-command-timeout')
                for key, _ in selected.select(0.2):
                    block = os.read(key.fd, 65536)
                    if not block: selected.unregister(key.fileobj); continue
                    size += len(block); ensure(size <= limit, 'bounded-command-output-limit'); chunks.append(block)
        return proc.wait(timeout=10), b''.join(chunks).decode(errors='replace'), time.monotonic() - started
    finally:
        if proc.poll() is None: os.killpg(proc.pid, signal.SIGKILL); proc.wait(timeout=10)
        proc.stdout.close()


def compiler_error(item, frozen):
    message = item.get('message', {}); code = message.get('code')
    code = code.get('code') if isinstance(code, dict) else None
    result = {'code': code if isinstance(code, str) and re.fullmatch(r'E[0-9]{4}', code) else None,
              'primary_locations': [], 'unknown_locations': 0, 'truncated': False}
    for span in message.get('spans', []):
        if not isinstance(span, dict) or span.get('is_primary') is not True: continue
        f, line, column = span.get('file_name'), span.get('line_start'), span.get('column_start')
        if isinstance(f, str) and f in frozen and f.endswith('.rs') and type(line) is int and type(column) is int and 0 < line < 2**31 and 0 < column < 2**31:
            if len(result['primary_locations']) < 8: result['primary_locations'].append({'file': f, 'line': line, 'column': column})
            else: result['truncated'] = True
        else: result['unknown_locations'] += 1
    return result


def inventory(raw, name=NAME):
    lines = [v for v in raw.splitlines() if v]
    return lines in [[name + ': test'], [name + ': test', '1 test, 0 benchmarks']]


def body_receipt(raw, code, frozen, name=NAME):
    clean = re.sub(r'\x1b\[[0-9;]*m', '', raw)
    summaries = re.findall(r'^test result: (ok|FAILED)\. ([0-9]+) passed; ([0-9]+) failed; ([0-9]+) ignored; ([0-9]+) measured; ([0-9]+) filtered out;', clean, re.M)
    names = re.findall(r'^test ([A-Za-z_0-9:]+) \.\.\. ', clean, re.M)
    running = re.findall(r'^running ([0-9]+) test(?:s)?$', clean, re.M)
    panics = re.findall(r"^thread '[^'\n]+'(?: \([0-9]+\))? panicked at ([^\n]+):", clean, re.M)
    result = {'actual_counts_complete': False, 'passed': None, 'failed': None, 'ignored': None,
              'executed_nonignored': None, 'exit_code': code, 'exact_selected_name': names == [name],
              'compiler_error_count': len(re.findall(r'^error(?:\[E[0-9]+\])?:', clean, re.M)),
              'panic_count': clean.count('panicked at '), 'safe_panic_locations': [], 'unknown_panic_locations': 0,
              'original_fixture_positive_close_counts': None}
    for location in panics[:8]:
        match = re.fullmatch(r'([A-Za-z_0-9/.-]+\.rs):([0-9]+):([0-9]+)', location)
        if match and match[1] in frozen:
            result['safe_panic_locations'].append({'file': match[1], 'line': int(match[2]), 'column': int(match[3])})
        else: result['unknown_panic_locations'] += 1
    result['panic_locations_truncated'] = len(panics) > 8
    if len(summaries) == 1:
        status, p, f, i, m, _ = summaries[0]; p, f, i, m = map(int, [p, f, i, m])
        complete = names == [name] and running == ['1'] and p + f == 1 and i == m == 0 and status == ('FAILED' if f else 'ok')
        result.update(actual_counts_complete=complete, passed=p, failed=f, ignored=i,
                      executed_nonignored=p + f if complete else None)
    allowed = {'initial-two-comparison', 'initial-two-completion', 'initial-two-completed',
               'third-device-completion', 'third-device-completed', 'fourth-device-completion', 'fourth-device-completed'}
    # Only closed known stage atoms survive; storage/account diagnostic lines do not.
    result['original_phase_markers'] = [v for v in re.findall(r'automatic-enrollment-control stage=([a-z0-9-]+)', clean) if v in allowed][:32]
    clean = re.sub(r'(?m)^test ' + re.escape(name) + r' \.\.\. (?=held-consent-control )', '', clean)
    metrics = re.findall(r'^held-consent-control setup-ms=([0-9]{1,9}) held-progress-ms=([0-9]{1,9}) other-peer-progress=(true|false)$', clean, re.M)
    result['actual_held_metrics'] = ({'setup_ms': int(metrics[0][0]), 'held_progress_ms': int(metrics[0][1]),
        'other_peer_progress': metrics[0][2] == 'true'} if len(metrics) == 1 else None)
    result['actual_held_metric_count'] = len(metrics)
    return result


def aggregate(rows, case_suffixes=CASES):
    complete = set(rows) == {PREFIX + suffix for suffix in case_suffixes} and all(
        row.get('actual_counts_complete') is True and all(type(row.get(k)) is int for k in
        ['passed', 'failed', 'ignored', 'executed_nonignored']) and row['ignored'] == 0
        and row['passed'] >= 0 and row['failed'] >= 0
        and row['passed'] + row['failed'] == row['executed_nonignored'] == 1 for row in rows.values())
    return {'actual_counts_complete': complete, **{'actual_' + k:
        sum(row[k] for row in rows.values()) if complete else None
        for k in ['passed', 'failed', 'ignored', 'executed_nonignored']}}


def parser_controls():
    ensure(inventory(NAME + ': test\n') and inventory(NAME + ': test\n1 test, 0 benchmarks\n'), 'both-exact-inventory-layouts')
    for value in ['', NAME + ': test\n' + NAME + ': test\n', 'foreign::test: test\n', NAME + ': test\n0 tests, 0 benchmarks\n']:
        ensure(not inventory(value), 'foreign-or-incomplete-inventory-rejected')
    raw = 'running 1 test\ntest ' + NAME + ' ... ok\ntest result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 3 filtered out; finished in 0.1s\n'
    ensure(body_receipt(raw, 0, {})['actual_counts_complete'], 'one-actual-positive-body')
    for value in [raw.replace(NAME, 'foreign::test'), raw.replace('1 passed', '0 passed'), raw.replace('0 ignored', '1 ignored'), raw + raw, raw.replace('running 1 test', 'running 0 tests')]:
        ensure(not body_receipt(value, 0, {})['actual_counts_complete'], 'no-zero-foreign-or-ignored-pass')
    error = compiler_error({'message': {'code': {'code': 'E0277'}, 'message': 'PRIVATE_ACCOUNT', 'spans': [
        {'is_primary': True, 'file_name': FIXTURE, 'line_start': 42, 'column_start': 5, 'text': ['PRIVATE_ACCOUNT']},
        {'is_primary': True, 'file_name': '/private/ACCOUNT.rs', 'line_start': 1, 'column_start': 1}]}}, {FIXTURE: {}})
    ensure(error['code'] == 'E0277' and len(error['primary_locations']) == 1 and error['unknown_locations'] == 1
           and 'PRIVATE_ACCOUNT' not in json.dumps(error) and '/private/' not in json.dumps(error), 'closed-private-compiler-metadata')
    held = body_receipt(raw + 'held-consent-control setup-ms=15000 held-progress-ms=4000 other-peer-progress=true\n', 0, {})
    ensure(held['actual_held_metric_count'] == 1 and held['actual_held_metrics']['other_peer_progress'] is True,
           'genuine-held-metrics-closed-positive')
    for tail in ['held-consent-control setup-ms=PRIVATE held-progress-ms=4000 other-peer-progress=true\n',
                 'held-consent-control setup-ms=1 held-progress-ms=2 other-peer-progress=PRIVATE\n']:
        ensure(body_receipt(raw + tail, 0, {})['actual_held_metrics'] is None, 'unclosed-held-metadata-not-accepted')
    rows = {PREFIX + suffix: body_receipt(raw.replace(NAME, PREFIX + suffix), 0, {}, PREFIX + suffix) for suffix in CASES}
    ensure(aggregate(rows)['actual_passed'] == 4, 'four-actual-selected-counts')
    for invalid in [{}, {k: v for k, v in rows.items() if k != NAME},
                    {**rows, NAME: {**rows[NAME], 'passed': None}},
                    {**rows, NAME: {**rows[NAME], 'passed': True}}]:
        incomplete = aggregate(invalid)
        ensure(not incomplete['actual_counts_complete'] and incomplete['actual_passed'] is None,
               'partial-or-untyped-counts-stay-unknown')
    return {'inventory_positive': 2, 'inventory_negative': 4, 'body_positive': 1, 'body_negative': 5,
            'safe_compiler_metadata_positive': 1, 'held_metric_positive': 1, 'held_metric_negative': 2,
            'aggregate_positive': 1, 'aggregate_negative': 4, 'actual_runtime_bodies': 0}


def five_receipt(raw, code, frozen):
    row=body_receipt(raw,code,frozen,FIVE_NAME)
    clean=re.sub(r'\x1b\[[0-9;]*m','',raw)
    clean=re.sub(r'(?m)^test '+re.escape(FIVE_NAME)+r' \.\.\. (?=sequential-installations )','',clean)
    lines=[line for line in clean.splitlines() if line.startswith('sequential-installations')]
    row['five_marker_count']=len(lines)
    pattern=(r'sequential-installations completed_steps=([0-4]) final_device_count=([0-5]) final_roster_and_policies=(true|false)'
        r' public_cancels=([0-9]{1,2}) runtime_closes=([0-5]) storages_closed=(true|false) plane_shutdown_returns=([0-5])'
        r' listener_closed=(true|false) attempt_completed=(true|false)')
    match=re.fullmatch(pattern,lines[0]) if len(lines)==1 and len(lines[0])<=512 else None
    row['five_facts']=None
    if match and int(match[4])<=14:
        row['five_facts']={'completed_steps':int(match[1]),'final_device_count':int(match[2]),'final_roster_and_policies':match[3]=='true',
            'public_cancels':int(match[4]),'runtime_closes':int(match[5]),'storages_closed':match[6]=='true',
            'plane_shutdown_returns':int(match[7]),'listener_closed':match[8]=='true','attempt_completed':match[9]=='true'}
    row['five_device_positive_closures']=({k:row['five_facts'][k] for k in ['runtime_closes','storages_closed','plane_shutdown_returns','listener_closed']}
        if row['five_facts'] else None)
    return row


def five_green(row):
    facts=row.get('five_facts')
    return (row.get('actual_counts_complete') is True and row.get('exact_selected_name') is True
        and all(type(row.get(k)) is int and row[k]==v for k,v in {'passed':1,'failed':0,'ignored':0,'executed_nonignored':1,'exit_code':0,'compiler_error_count':0,'panic_count':0,'five_marker_count':1}.items())
        and isinstance(facts,dict) and all(type(facts.get(k)) is int and facts[k]==v for k,v in
            {'completed_steps':4,'final_device_count':5,'public_cancels':14,'runtime_closes':5,'plane_shutdown_returns':5}.items())
        and all(facts.get(k) is True for k in ['final_roster_and_policies','storages_closed','listener_closed','attempt_completed']))


def five_parser_controls():
    marker='sequential-installations completed_steps=4 final_device_count=5 final_roster_and_policies=true public_cancels=14 runtime_closes=5 storages_closed=true plane_shutdown_returns=5 listener_closed=true attempt_completed=true'
    raw='running 1 test\ntest '+FIVE_NAME+' ... ok\n'+marker+'\ntest result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 2 filtered out; finished in 1.0s\n'
    ensure(five_green(five_receipt(raw,0,{})),'five-device-positive-closed-parser')
    shared=raw.replace(' ... ok\n'+marker,' ... '+marker+'\nok')
    ensure(five_green(five_receipt(shared,0,{})),'exact-five-name-shared-marker-parser')
    bad=[raw.replace('completed_steps=4','completed_steps=3'),raw.replace('final_device_count=5','final_device_count=4'),
        raw.replace('final_roster_and_policies=true','final_roster_and_policies=false'),raw.replace('public_cancels=14','public_cancels=13'),
        raw.replace('runtime_closes=5','runtime_closes=4'),raw.replace('storages_closed=true','storages_closed=false'),
        raw.replace('plane_shutdown_returns=5','plane_shutdown_returns=4'),raw.replace('listener_closed=true','listener_closed=false'),
        raw.replace('attempt_completed=true','attempt_completed=false'),raw+'\n'+marker,raw.replace(marker,''),
        raw.replace(FIVE_NAME,FIVE_NAME+'_foreign'),raw.replace('0 ignored','1 ignored'),raw.replace('1 passed','0 passed'),
        raw.replace(marker,marker+' private=hidden'),raw.replace('public_cancels=14','public_cancels=99'),raw.replace('storages_closed=true','storages_closed=hidden')]
    for text in bad: ensure(not five_green(five_receipt(text,0,{})),'incomplete-unclosed-or-foreign-five-device-rejected')
    row=five_receipt(raw,0,{})
    for k in ['passed','failed','ignored','executed_nonignored','exit_code','compiler_error_count','panic_count','five_marker_count']:
        ensure(not five_green(dict(row,**{k:True})),'bool-is-not-runtime-count')
    return {'positive':2,'negative':len(bad)+8,'actual_runtime_bodies':0}


def main(args):
    os.umask(0o077); OUT.mkdir(exist_ok=True)
    report = {'baseline': BASE, 'qualification_passed': False, 'native_acceptance_claim': False,
              'installed_binary_inclusion_known': False, 'strict_integration_15s_qualified': False,
              'owner_contract_component_passed': False, 'actual_counts_complete': False,
              'positive_native_closures': None, 'old_locked_negentropy': '0.5.0 diagnostic baseline only',
              'required_case_count': 1 if args.five else 4, 'cases': {}, 'one_compile_for_selected_experimental_cohort': True}
    frozen = None
    selected_cases = [FIVE_SUFFIX] if args.five else CASES
    def save(): (OUT / 'result.json').write_text(json.dumps(report, indent=2) + '\n')
    try:
        report['scope']='five-device-journey' if args.five else 'four-owner-components'
        report['source_guard'] = source_guard(args.five); report['parser_controls'] = parser_controls()
        if args.five: report['five_parser_controls']=five_parser_controls()
        save()
        if args.preflight: report['source_parser_preflight_passed'] = True; save(); return
        frozen = snapshot(); report['input_manifest_sha256'] = digest(json.dumps(frozen, sort_keys=True).encode())
        report['toolchain'] = {v: subprocess.check_output([v, '--version'], text=True).strip() for v in ['cargo', 'rustc']}
        report['remote_capacity'] = {'minimum_free_bytes': 8*1024**3, 'free_bytes': shutil.disk_usage('.').free,
                                     'cleanup_performed': False}
        save(); ensure(report['remote_capacity']['free_bytes'] >= report['remote_capacity']['minimum_free_bytes'], 'remote-build-capacity')
        command = ['cargo', 'test', '--locked', '-p', 'marmot-app', '--lib', '--no-run', '--message-format=json', '--features', FEATURES]
        report['active_phase'] = 'compilation'; save()
        code, raw, seconds = capture(command, 1800, 16*1024*1024); artifacts = []; errors = []
        for line in raw.splitlines():
            if not line.startswith('{'): continue
            item = json.loads(line)
            if item.get('reason') == 'compiler-message' and item.get('message', {}).get('level') == 'error':
                errors.append(compiler_error(item, frozen))
            if item.get('reason') == 'compiler-artifact': artifacts.append(item)
        selected = [a for a in artifacts if a['target']['name'] == 'marmot_app' and a['target']['kind'] == ['lib'] and a['profile']['test'] and a.get('executable')]
        report['compilation'] = {'command': command, 'seconds': seconds, 'exit_code': code, 'compiler_error_count': len(errors),
            'safe_errors': errors[:32], 'errors_truncated': len(errors) > 32, 'selected_binary_count': len(selected)}; save()
        ensure(code == 0 and not errors and len(selected) == 1, 'one-actual-old-App-binary')
        artifact = selected[0]; ensure(sorted(artifact['features']) == ROOT_FEATURES, 'exact-compiled-old-App-features')
        binary = Path(artifact['executable']); binary_hash = digest(binary.read_bytes())
        report['compilation'].update(features=sorted(artifact['features']), binary_sha256=binary_hash,
            compiled_feature_manifest_sha256=digest(json.dumps([{'target': a['target']['name'], 'features': sorted(a['features']), 'profile': a['profile']} for a in artifacts], sort_keys=True).encode()))
        ensure(snapshot() == frozen, 'whole-inputs-pristine-after-compile')
        report['inventory'] = {}
        for suffix in selected_cases:
            name = PREFIX + suffix
            code, raw, _ = capture([str(binary), '--exact', name, '--list', '--format', 'terse'], 60, 1024*1024)
            ensure(code == 0 and inventory(raw, name), 'exact-one-nonignored-inventory')
            code, raw, _ = capture([str(binary), '--exact', name, '--ignored', '--list', '--format', 'terse'], 60, 1024*1024)
            ensure(code == 0 and raw.strip() in {'', '0 tests, 0 benchmarks'}, 'selected-body-not-ignored')
            report['inventory'][name] = {'selected_nonignored': 1, 'selected_ignored': 0}
        save()
        for suffix in selected_cases:
            name = PREFIX + suffix
            ensure(snapshot() == frozen and digest(binary.read_bytes()) == binary_hash, 'before-body-source-binary-pristine')
            report['active_phase'] = 'runtime-body'; report['active_case'] = name; save()
            code, raw, seconds = capture([str(binary), '--exact', name, '--nocapture', '--test-threads=1'], 900, 8*1024*1024)
            row = five_receipt(raw,code,frozen) if args.five else body_receipt(raw, code, frozen, name); row.update(seconds=seconds, binary_sha256=binary_hash)
            row['runtime_passed'] = row['passed'] == 1 and row['failed'] == 0 and code == 0 and row['panic_count'] == 0
            report['cases'][name] = row; report.update(aggregate(report['cases'],selected_cases)); save()
            ensure(row['actual_counts_complete'] and row['compiler_error_count'] == 0 and code in {0, 101}, 'one-real-runtime-body-not-compile-or-watchdog')
            ensure(snapshot() == frozen and digest(binary.read_bytes()) == binary_hash, 'after-body-source-binary-pristine')
        if args.five:
            report['five_device_journey_passed']=five_green(report['cases'][FIVE_NAME])
            report['plane_shutdown_returns_are_not_internal_task_quiescence']=True
            report['active_phase']='one-five-device-body-completed';save()
            ensure(report['five_device_journey_passed'],'five-device-real-roster-policies-and-positive-closures-required')
        else:
            held = report['cases'][PREFIX + CASES[0]]
            report['genuine_held_metric_complete'] = (held['actual_held_metric_count'] == 1
                and held['actual_held_metrics']['other_peer_progress'] is True)
            report['owner_contract_component_passed'] = (report['actual_counts_complete']
                and all(row['runtime_passed'] for row in report['cases'].values()) and report['genuine_held_metric_complete'])
            report['active_phase'] = 'all-selected-bodies-completed'; save()
            ensure(report['owner_contract_component_passed'], 'selected-owner-components-not-green')
    except Exception as error:
        report['exception_type'] = type(error).__name__
        if isinstance(error, GateFailure): report['failure_gate'] = str(error)
        raise
    finally:
        if frozen is not None: report['inputs_pristine'] = snapshot() == frozen
        save()
        if frozen is not None: ensure(report['inputs_pristine'], 'final-source-modes-pristine')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--preflight', action='store_true')
    parser.add_argument('--five', action='store_true')
    main(parser.parse_args())
