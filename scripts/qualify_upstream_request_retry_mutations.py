#!/usr/bin/env python3
"""Four independent runtime counterfactuals; never full/native qualification."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import time
import qualify_upstream_request_retry_ack as ack
import qualify_upstream_request_retry_candidate as candidate
import qualify_upstream_request_retry_red as regression
import qualify_upstream_runtime_alignment as alignment
import qualify_upstream_runtime_policy_red as policy
import qualify_upstream_storage_boundary as bounded
from qualify_upstream_body_negative import freeze, layout, feature_identity
from upstream_completion_ci import compile_cases, digest, ensure, environment, identity, parse_body

# FAIL CLOSED: root must pin the reviewed, formatted ACK controls GREEN commit.
BASE = 'd9638302cfd2cb212946600e4fe1d596007eab7f'
# Root must replace this with the verified focused4+both-statics run ID.
REVIEWED_CONTROL_RUN = '39080797679'
SELF = 'scripts/qualify_upstream_request_retry_mutations.py'
WORKFLOW = '.github/workflows/experimental-sync-ci.yml'
REF = 'refs/heads/ci/upstream-request-retry-20261018'
BEGIN = '  # REQUEST_RETRY_MUTATION_JOBS_BEGIN\n'
END = '  # REQUEST_RETRY_MUTATION_JOBS_END\n'
OPTIONS = 'options: [request-retry-mutation-preflight, request-retry-mutations, '
OUT = Path('request-retry-mutation-evidence')
PRESENTATION = 'crates/marmot-app/src/account_chat_presentation/tests.rs'
PRESENTATION_CASE = 'paired_presentation_actual_original_approval_catalog_without_fake_mls_group'
PRESENTATION_NAME = 'account_chat_presentation::tests::' + PRESENTATION_CASE
MULTI = b'#[tokio::test(flavor = "multi_thread", worker_threads = 2)]'
CLOCK = b'#[tokio::test(flavor = "current_thread")]'
ACK_MESSAGE = 'required_initial_or_proof_ack_must_remain_owned_until_real_report_release'
CHAINS = ['omit_retirement', 'omit_initial_ack_guard', 'bare_policy_attribute', 'wrong_clock_flavor']


def source_guard():
    ensure(re.fullmatch(r'[0-9a-f]{40}', BASE) is not None, 'reviewed-final-ACK-GREEN-baseline-not-yet-pinned')
    source = subprocess.check_output(['git', 'rev-parse', 'HEAD'], text=True).strip()
    ensure(os.environ.get('GITHUB_ACTIONS') == 'true' and os.environ.get('GITHUB_REPOSITORY') == 'dyKiU/mdk'
           and os.environ.get('GITHUB_EVENT_NAME') == 'workflow_dispatch' and source == os.environ.get('GITHUB_SHA')
           and os.environ.get('GITHUB_REF') == REF
           and os.environ.get('GITHUB_WORKFLOW_REF') == 'dyKiU/mdk/' + WORKFLOW + '@' + REF
           and os.environ.get('UPSTREAM_REQUEST_RETRY_MUTATION_BASELINE') == BASE, 'exact-reviewed-remote-identity')
    ensure(os.environ.get('CARGO_INCREMENTAL') == '1' and os.environ.get('CARGO_BUILD_JOBS') == '2'
           and os.environ.get('RUST_MIN_STACK') == '4194304', 'unchanged-capacity')
    ensure(all(os.environ.get(key) == '0' for key in ['CARGO_PROFILE_DEV_DEBUG', 'CARGO_PROFILE_TEST_DEBUG']), 'unchanged-profile')
    ensure(all(not os.environ.get(key) for key in ['RUSTFLAGS', 'CARGO_ENCODED_RUSTFLAGS', 'RUSTC_BOOTSTRAP',
               'CARGO_PROFILE_DEV_OPT_LEVEL', 'CARGO_PROFILE_TEST_OPT_LEVEL']), 'no-compiler-overrides')
    subprocess.run(['git', 'merge-base', '--is-ancestor', BASE, source], check=True)
    ensure(subprocess.run(['git', 'diff', '--quiet', 'HEAD']).returncode == 0, 'initial-clean-inputs')
    baseline = {}
    for entry in subprocess.check_output(['git', 'ls-tree', '-r', '-z', BASE]).split(b'\0'):
        if entry:
            metadata, name = entry.split(b'\t', 1)
            git_mode, kind, blob = metadata.decode().split()
            ensure(kind == 'blob' and git_mode in {'100644', '100755', '120000'}, 'ordinary-baseline-input')
            baseline[os.fsdecode(name)] = (git_mode, blob)
    current = layout()
    ensure(SELF not in baseline and set(current) == set(baseline) | {SELF}, 'only-one-added-metadata-controller')
    for name, metadata in current.items():
        git_mode, blob = baseline.get(name, ('100644', None))
        ensure(metadata['git_mode'] == git_mode and metadata['symlink'] == (git_mode == '120000')
               and (metadata['symlink'] or metadata['actual_executable'] == (git_mode == '100755')), 'whole-mode:' + name)
        data = os.fsencode(os.readlink(name)) if metadata['symlink'] else Path(name).read_bytes()
        if name == WORKFLOW:
            text = data.decode()
            ensure(text.count(BEGIN) == text.count(END) == text.count(OPTIONS) == 1, 'one-exact-isolated-workflow-overlay')
            before, rest = text.split(BEGIN); _, after = rest.split(END)
            data = (before + after).replace(OPTIONS, 'options: [', 1).encode()
        if blob is not None:
            ensure(hashlib.sha1(b'blob ' + str(len(data)).encode() + b'\0' + data).hexdigest() == blob, 'whole-reviewed-content:' + name)
    ensure(set(subprocess.check_output(['git', 'ls-files', '--others', '--exclude-standard'], text=True).splitlines())
           <= {str(OUT / 'result.json')}, 'no-untracked-source-overlay')
    return {'source': source, 'reviewed_baseline': BASE, 'whole_original_content_and_modes_frozen': True,
            'all_imported_controllers_product_fixtures_and_generated_inputs_byte_exact': True,
            'prior_runtime_evidence_reused': False}


def reviewed_controls():
    ensure(re.fullmatch(r'[1-9][0-9]{5,19}', REVIEWED_CONTROL_RUN) is not None,
           'verified-focused4-and-both-static-prerequisite-not-yet-pinned')
    def api(endpoint):
        code, raw, _ = bounded.capture(['gh', 'api', 'repos/dyKiU/mdk/actions/' + endpoint], 60, limit=2 * 1024 * 1024)
        ensure(code == 0, 'bounded-read-only-control-run-API')
        return json.loads(raw)
    run = api('runs/' + REVIEWED_CONTROL_RUN)
    ensure(run.get('head_sha') == BASE and run.get('head_branch') == REF.removeprefix('refs/heads/')
           and run.get('event') == 'workflow_dispatch' and run.get('status') == 'completed'
           and run.get('conclusion') == 'success' and run.get('repository', {}).get('full_name') == 'dyKiU/mdk',
           'actual-reviewed-exact-source-prior-run-completed-success')
    jobs = api('runs/' + REVIEWED_CONTROL_RUN + '/jobs?per_page=100')
    ensure(type(jobs.get('total_count')) is int and jobs['total_count'] == len(jobs.get('jobs', [])) <= 100,
           'complete-bounded-prior-job-inventory')
    required = ['request-retry-ack-preflight', 'request-retry-ack-focused',
                'request-retry-ack-static (default)', 'request-retry-ack-static (experimental)']
    for name in required:
        matches = [job for job in jobs['jobs'] if job.get('name') == name]
        ensure(len(matches) == 1 and matches[0].get('status') == 'completed'
               and matches[0].get('conclusion') == 'success', 'each-required-focused-and-static-prerequisite-job')
    return {'run_id': REVIEWED_CONTROL_RUN, 'source': BASE, 'jobs_verified_completed_success': required,
            'actual_four_body_artifact_evidence_requires_root_review_before_pin': True,
            'prior_exact_final_helper_SHA_pass_claim': False,
            'fresh_one_case_P_F_P_required_independently': True}


def one_attribute(data, name, before, after):
    # Exact known immediate attribute/function pair; no function/body edits.
    matches = list(re.finditer(rb'(?m)^([ \t]*)' + re.escape(before) + rb'\n\1async fn ' + re.escape(name.encode()) + rb'\(', data))
    ensure(len(matches) == 1, 'one-frozen-known-function-attribute')
    match = matches[0]; indent = match[1]
    return data[:match.start()] + indent + after + b'\n' + indent + b'async fn ' + name.encode() + b'(' + data[match.end():]


def mutation(chain):
    if chain in {'omit_retirement', 'omit_initial_ack_guard'}:
        name = candidate.PRODUCT; original = Path(name).read_bytes()
        ensure(original.count(candidate.FIX) == 1, 'exact-reviewed-nine-line-fix-once')
        replacement = b''
        if chain == 'omit_initial_ack_guard':
            old = b'if entry.handshake_published\n                            && entry'
            ensure(candidate.FIX.count(old) == 1, 'one-explicit-initial-ACK-predicate')
            replacement = candidate.FIX.replace(old, b'if entry', 1)
        return name, original.replace(candidate.FIX, replacement, 1), 'request_retry' if chain == 'omit_retirement' else 'initial_ack'
    if chain == 'bare_policy_attribute':
        return PRESENTATION, one_attribute(Path(PRESENTATION).read_bytes(), PRESENTATION_CASE, MULTI, b'#[tokio::test]'), 'policy'
    ensure(chain == 'wrong_clock_flavor', 'closed-chain')
    name = alignment.CLOCK_FILE
    return name, one_attribute(Path(name).read_bytes(), alignment.CLOCK_CASE, CLOCK, MULTI), 'paused_clock'


def selected(label):
    return next(row for row in ack.CASES if row[0] == label)


def own_assert_line(name, message):
    lines = Path(name).read_text().splitlines()
    matches = [index for index, line in enumerate(lines) if message in line]
    ensure(len(matches) == 1, 'one-unchanged-final-oracle-message')
    return max(index for index in range(matches[0] + 1) if 'assert!(' in lines[index]) + 1


def parse_case(chain, label, raw, code, mutant):
    if mutant and chain == 'wrong_clock_flavor':
        return alignment.clock_red_parse(raw, code)
    if mutant and chain == 'bare_policy_attribute':
        whitelist = policy.source_offenders()
        expected_line = next(index for index, line in enumerate(Path(PRESENTATION).read_text().splitlines(), 1) if line == '#[tokio::test]')
        ensure(whitelist == {(PRESENTATION, expected_line): 'BareTokioTest'}, 'sole-exact-migrated-attribute-offender')
        row = policy.parse(raw, code, whitelist)
        row.update(compiler_error_count=len(re.findall(r'^error(?:\[E[0-9]+\])?:', raw, re.M)),
                   executed_case_names=re.findall(r'(?m)^test ([A-Za-z_0-9:]+) \.\.\.', raw),
                   running_counts=[int(value) for value in re.findall(r'(?m)^running ([0-9]{1,3}) tests?$', raw)])
        return row
    row = ack.parse_case(label, raw, code)
    if mutant and chain == 'omit_initial_ack_guard':
        row['closed_own_final_assertion_count'] = len(re.findall(r'(?m)^' + re.escape(ACK_MESSAGE) + r'$', raw))
    return row


def intended_red(chain, row):
    if chain == 'omit_retirement':
        return regression.intended_red(row)
    if chain == 'wrong_clock_flavor':
        return alignment.clock_red(row)
    if chain == 'bare_policy_attribute':
        return (all(type(row.get(key)) is int and row[key] == expected for key, expected in
                    {'body_exit_code': 101, 'passed': 0, 'failed': 1, 'ignored': 0, 'executed_nonignored': 1,
                     'compiler_error_count': 0, 'all_panic_header_count': 1}.items())
                and policy.intended_policy_red(row)
                and row.get('executed_case_names') == [alignment.POLICY_NAME] and row.get('running_counts') == [1]
                and row.get('offender_count') == 1 and row.get('offenders', [{}])[0].get('category') == 'BareTokioTest')
    ensure(chain == 'omit_initial_ack_guard', 'closed-runtime-oracle')
    expected = {field: field not in {'protected_window', 'normal_release'} for field in ack.FIELDS}
    locations = row.get('panic_locations', [])
    return (all(type(row.get(key)) is int and row[key] == value for key, value in
                {'body_exit_code': 101, 'passed': 0, 'failed': 1, 'ignored': 0, 'executed_nonignored': 1,
                 'compiler_error_count': 0, 'all_panic_header_count': 1, 'marker_header_count': 1,
                 'closed_own_final_assertion_count': 1}.items())
            and row.get('executed_case_names') == [selected('initial_ack')[2]] and row.get('running_counts') == [1]
            and row.get('scenario') == row.get('expected_scenario') == 'initial' and row.get('facts') == expected
            and type(row.get('samples')) is int and row['samples'] >= 2
            and type(row.get('window_elapsed_us')) is int and 15_000_000 <= row['window_elapsed_us'] <= 300_000_000
            and type(row.get('runtime_closes')) is int and row['runtime_closes'] == 3
            and type(row.get('planes_shutdown')) is int and row['planes_shutdown'] == 3
            and row.get('relay_closed') is True and row.get('attempt_completed') is True
            and len(locations) == 1 and locations[0]['file'] == ack.FIXTURE
            and locations[0]['line'] == own_assert_line(ack.FIXTURE, ACK_MESSAGE)
            and not row.get('watchdog_triggered') and not row.get('actual_count_unknown'))


def write_fresh(path, data):
    # Never copy an old mtime onto a changed/restored source input.
    old = path.stat().st_mtime_ns
    path.write_bytes(data)
    stamp = max(time.time_ns(), old + 1_000_000)
    os.utime(path, ns=(stamp, stamp))


def main(options):
    os.umask(0o077)
    OUT.mkdir(exist_ok=True)
    report = {'chain': options.chain, 'mode': 'preflight' if options.preflight else 'mutation',
              'qualification_passed': False, 'component_mutation_passed': False,
              'scope': 'Only one independent selected runtime counterfactual. Full16/native/other mutation gates remain pending.',
              'automatic_retries': 0, 'phases': {}}
    original = None; original_layout = None; target = None; old_bytes = None; old_mode = None
    def save():
        if report['phases']:
            report['observed_counts'] = alignment.aggregate_counts(report['phases'])
        (OUT / 'result.json').write_text(json.dumps(report, indent=2) + '\n')
    def check(expected):
        ensure(freeze() == expected and layout() == original_layout, 'exact-phase-source-content-and-modes')
    def phase(phase_name, label, expected):
        row = {'actual_counts_complete': False}; report['phases'][phase_name] = row; save()
        check(expected)
        suffixes = [selected(label)[1]]
        if options.chain == 'bare_policy_attribute':
            suffixes.append(PRESENTATION_CASE)
        compilation, cases = compile_cases(suffixes)
        row['compilation'] = compilation; save()
        ensure(compilation.get('compile_exit_code') == 0 and compilation.get('compiler_error_count') == 0
               and compilation.get('compiled_fingerprints', {}).get('verified') is True
               and len(compilation['compiled_fingerprints']['nodes']) == 6
               and set(cases) == set(suffixes), 'actual-selected-inventory-six-fingerprint-compilation-required')
        row['compiled_inventory_count'] = len(suffixes)
        row['required_executed_body_count'] = 1
        if options.chain == 'bare_policy_attribute':
            witness = cases[PRESENTATION_CASE]
            ensure(witness['name'] == PRESENTATION_NAME
                   and witness['binary_sha256'] == cases[selected(label)[1]]['binary_sha256'],
                   'mutated-presentation-function-really-compiled-in-same-policy-binary')
            row['compiled_not_executed_witness'] = {'name': witness['name'], 'binary_sha256': witness['binary_sha256']}
        save()
        case = cases[selected(label)[1]]
        ensure(case['name'] == selected(label)[2], 'exact-compiled-selected-body')
        row['binary_sha256'] = case['binary_sha256']; row['compiled_feature_identity'] = feature_identity(compilation)
        check(expected); ensure(digest(Path(case['binary']).read_bytes()) == case['binary_sha256'], 'compiled-binary-pristine-before-body'); save()
        try:
            code, raw, seconds = bounded.capture([case['binary'], '--exact', case['name'], '--nocapture', '--test-threads=1'], 300, limit=8 * 1024 * 1024)
        except Exception as error:
            row.update(watchdog_triggered=str(error) == 'bounded-command-timeout', output_limit_triggered=str(error) == 'bounded-command-output-limit', actual_count_unknown=True)
            save(); raise
        row['body_seconds'] = seconds
        # Retain actual observed basic counts even if the strict closed marker
        # parser later rejects; never persist raw panic/private runtime output.
        basic = dict(parse_body(raw, selected(label)[1]), body_exit_code=code,
                     compiler_error_count=len(re.findall(r'^error(?:\[E[0-9]+\])?:', raw, re.M)))
        row['body'] = basic
        row['actual_counts_complete'] = alignment.complete_counts(basic)
        save()
        body = parse_case(options.chain, label, raw, code, phase_name == 'mutant')
        row['body'] = body; row['actual_counts_complete'] = alignment.complete_counts(body)
        check(expected); ensure(digest(Path(case['binary']).read_bytes()) == case['binary_sha256'], 'compiled-binary-pristine-after-body'); row['source_pristine'] = True; save()
        ensure(row['actual_counts_complete'] and body['executed_nonignored'] == 1 and body['ignored'] == 0, 'one-actual-nonignored-body')
        ensure(intended_red(options.chain, body) if phase_name == 'mutant' else ack.case_green(label, body), 'exact-selected-runtime-verdict-required')
        row['verdict_verified'] = True; save()
    save()
    try:
        report['source_preflight'] = source_guard(); report.update(environment()); save()
        original = freeze(); original_layout = layout(); report['input_manifest_sha256'] = identity(original)
        if not options.preflight:
            report['prior_focused_controls_and_statics'] = reviewed_controls(); save()
        report['parser_controls'] = parser_controls(); save()
        if options.preflight:
            report['preflight_passed'] = True
        else:
            target_name, changed, label = mutation(options.chain)
            target = Path(target_name); old_bytes = target.read_bytes(); old_mode = stat.S_IMODE(target.stat().st_mode)
            ensure(changed != old_bytes, 'nonempty-exact-counterfactual')
            phase('baseline', label, original)
            mutation_error = None
            try:
                write_fresh(target, changed)
                # Prove exact changed bytes and otherwise unchanged contents/modes.
                expected = freeze()
                ensure(set(expected) == set(original) and {name for name in expected if expected[name] != original[name]} == {target_name}
                       and target.read_bytes() == changed and layout() == original_layout, 'only-exact-mutant-input')
                report['mutant_input_manifest_sha256'] = identity(expected); save()
                phase('mutant', label, expected)
            except Exception as error:
                mutation_error = type(error).__name__; report['mutation_exception'] = mutation_error; save()
            finally:
                write_fresh(target, old_bytes); os.chmod(target, old_mode)
                check(original); report['source_restored'] = True; save()
            # Always retain the restored actual control even after failed mutant evidence.
            phase('restored', label, original)
            first, mutant, restored = [report['phases'].get(name, {}) for name in ['baseline', 'mutant', 'restored']]
            ensure(mutation_error is None and all(item.get('verdict_verified') is True for item in [first, mutant, restored]), 'all-three-runtime-phases-verified')
            ensure(first['binary_sha256'] == restored['binary_sha256'] != mutant['binary_sha256'], 'exact-binary-restoration-and-real-counterfactual-binary')
            ensure(first['compiled_feature_identity'] == mutant['compiled_feature_identity'] == restored['compiled_feature_identity'], 'identical-six-fingerprint-feature-profile-cohort')
            report['actual_counts'] = alignment.aggregate_counts(report['phases'])
            ensure(report['actual_counts']['actual_passed'] == 2 and report['actual_counts']['actual_failed'] == 1
                   and report['actual_counts']['actual_ignored'] == 0 and report['actual_counts']['actual_executed_nonignored'] == 3, 'three-actual-runtime-bodies-two-controls-one-intended-failure')
            report['component_mutation_passed'] = True
    except Exception as error:
        report['controller_exception'] = type(error).__name__
    finally:
        report['inputs_pristine'] = False
        if target is not None and old_bytes is not None:
            try: write_fresh(target, old_bytes); os.chmod(target, old_mode)
            except Exception as error: report['final_restore_exception'] = type(error).__name__
        if original is not None:
            try:
                report['inputs_pristine'] = freeze() == original and layout() == original_layout and subprocess.run(['git', 'diff', '--quiet', 'HEAD']).returncode == 0
            except Exception as error: report['final_freeze_exception'] = type(error).__name__
        save()
    raise SystemExit(0 if report['inputs_pristine'] and not report.get('controller_exception') and (report.get('preflight_passed') if options.preflight else report['component_mutation_passed']) else 1)


# Closed parser adversaries are authored here and must execute REMOTELY only.
def parser_controls():
    lines = Path(PRESENTATION).read_text().splitlines()
    starts = [index for index, line in enumerate(lines) if line.startswith('async fn ' + PRESENTATION_CASE + '(')]
    ensure(len(starts) == 1 and lines[starts[0] - 1] == MULTI.decode(), 'exact-known-policy-mutant-attribute-for-parser-whitelist')
    ensure(lines[starts[0] - 5:starts[0] - 1] == ['#[cfg(all(',
           '    feature = "experimental-device-sync",', '    feature = "test-policy-overrides"', '))]'],
           'reviewed-presentation-witness-feature-gates')
    whitelist = {(PRESENTATION, starts[0]): 'BareTokioTest'}
    return {'inherited_retry_and_ACK_and_clock': ack.parser_controls(),
            'one_offender_policy': policy.parser_controls(whitelist),
            'clock': alignment.clock_parser_controls(),
            'new_mutation_adversaries': mutation_parser_controls()}


def mutation_parser_controls():
    # Synthetic parser fixtures never establish a runtime mutation kill.
    _, suffix, name, _ = selected('initial_ack')
    line = own_assert_line(ack.FIXTURE, ACK_MESSAGE)
    facts = {field: field not in {'protected_window', 'normal_release'} for field in ack.FIELDS}
    marker = 'request-retry-ack scenario=initial ' + ' '.join(key + '=' + str(value).lower() for key, value in facts.items())
    marker += ' samples=2 window_elapsed_us=15000000 runtime_closes=3 planes_shutdown=3 relay_closed=true attempt_completed=true'
    raw = ('running 1 test\ntest ' + name + ' ... FAILED\nthread case panicked at ' + ack.FIXTURE + ':' + str(line)
           + ':5:\n' + ACK_MESSAGE + '\n' + marker + '\ntest result: FAILED. 0 passed; 1 failed; 0 ignored;\n')
    row = parse_case('omit_initial_ack_guard', 'initial_ack', raw, 101, True)
    ensure(intended_red('omit_initial_ack_guard', row), 'initial-ACK-mutant-closed-runtime-parser-positive')
    negative = 0
    for change in [{'body_exit_code': 0}, {'passed': 1}, {'failed': 0}, {'ignored': 1}, {'executed_nonignored': 0},
                   {'compiler_error_count': 1}, {'all_panic_header_count': 2}, {'panic_locations': []},
                   {'closed_own_final_assertion_count': 0}, {'running_counts': [0]}, {'executed_case_names': ['foreign::case']},
                   {'watchdog_triggered': True}, {'actual_count_unknown': True}, {'samples': 1}, {'window_elapsed_us': 1},
                   {'runtime_closes': 2}, {'planes_shutdown': 2}, {'attempt_completed': False}]:
        ensure(not intended_red('omit_initial_ack_guard', dict(row, **change)), 'nonruntime-or-unrelated-initial-ACK-mutant-rejected'); negative += 1
    for field in ack.FIELDS:
        altered = dict(facts); altered[field] = not altered[field]
        ensure(not intended_red('omit_initial_ack_guard', dict(row, facts=altered)), 'every-exact-counterfactual-fact-required'); negative += 1
    policy_path = Path(PRESENTATION)
    policy_line = next(index for index, text in enumerate(policy_path.read_text().splitlines(), 1)
                       if text.startswith('async fn ' + PRESENTATION_CASE + '(')) - 1
    policy_row = {'body_exit_code': 101, 'passed': 0, 'failed': 1, 'ignored': 0, 'executed_nonignored': 1,
                  'compiler_error_count': 0, 'all_panic_header_count': 1, 'exact_executed_name': True,
                  'executed_case_names': [alignment.POLICY_NAME], 'running_counts': [1],
                  'panic_locations': [{'file': policy.FILE, 'line': policy.assertion_line(), 'column': 5}],
                  'offender_inventory_known': True, 'offender_count': 1,
                  'offenders': [{'path': PRESENTATION, 'line': policy_line, 'category': 'BareTokioTest'}]}
    ensure(intended_red('bare_policy_attribute', policy_row), 'typed-single-policy-offender-positive')
    for field in ['body_exit_code', 'passed', 'failed', 'ignored', 'executed_nonignored', 'compiler_error_count', 'all_panic_header_count']:
        ensure(not intended_red('bare_policy_attribute', dict(policy_row, **{field: bool(policy_row[field])})),
               'policy-runtime-counts-must-not-accept-booleans'); negative += 1
    return {'positive': 2, 'negative': negative}


if __name__ == '__main__':
    parser = argparse.ArgumentParser(); parser.add_argument('--preflight', action='store_true')
    parser.add_argument('--chain', choices=CHAINS, default='omit_retirement')
    main(parser.parse_args())
