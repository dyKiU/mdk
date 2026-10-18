#!/usr/bin/env python3
"""Reviewed recipient first-Consent GREEN and independent counterfactuals; not full qualification."""
import argparse
import hashlib
import io
import json
import os
from pathlib import Path
import re
import subprocess
import time
import zipfile
import qualify_upstream_recipient_admission_red as red
import qualify_upstream_late_consent_red as consent
import qualify_upstream_late_consent_candidate as consent_candidate
import qualify_upstream_peer_proof as proof
from qualify_upstream_peer_proof_candidate import green as proof_green
import qualify_upstream_automatic_body as body
from upstream_completion_ci import (NEW, ORIGINALS, DEFAULT_FEATURES, FEATURES, compile_cases,
                                    digest, ensure, environment, headers, identity,
                                    parse_body, green as completion_green)
from qualify_upstream_body_negative import feature_identity, freeze, layout

# Exact reviewed fix following genuine one-body RED run 39071256534.
BASE = 'af33069d6ddfdc71d69c1bd2eb05833d2d70f242'
REGRESSION_BASE = 'ce85f68cff73ac3a24823db7e428b340fd8dbc4a'
WAKE_ANCHOR = b'            self.linking_owner\n                .sibling_publication_completions\n                .send_replace(());\n'
ELIGIBILITY_ANCHOR = b'(harvested_success || entry.recipient)'
ELIGIBILITY_MUTANT = b'harvested_success'
FULL_WAKE_REGION = b'            // Core approved this exact owned channel. Wake its first Consent;\n            // the completion service still freshly validates before publishing.\n            self.linking_owner\n                .sibling_publication_completions\n                .send_replace(());\n'
OLD_FIRST_SHOT_REGION = b'        let mut starts_left = MAX_SIBLING_PUBLICATIONS;\n        if harvested_success {\n            // First shots retain the existing channel order and precede a\n            // successful peer\'s proof. The flag records attempts only; periodic\n            // retry selection and its deadlines do not consult it.\n            for entry in &mut channels {\n                if starts_left == 0 || in_flight >= MAX_SIBLING_PUBLICATIONS {\n                    break;\n                }\n                if entry.publication.is_none()\n                    && !entry.handshake_attempted\n                    && entry.deferred_initial_error.is_none()\n                    && entry.original.live()\n                    && entry.state.live()\n                {\n                    #[cfg(all(test, feature = "test-policy-overrides"))]\n                    match Self::sibling_publication_held_for_test(entry) {\n                        Ok(true) => continue,\n                        Ok(false) => {}\n                        Err(error) => {\n                            starts_left -= 1;\n                            entry.handshake_attempted = true;\n                            entry.deferred_initial_error = Some(error);\n                            continue;\n                        }\n                    }\n                    starts_left -= 1;\n                    entry.handshake_attempted = true;\n                    match self.start_sibling_publication(entry, None).await {\n                        Ok(()) => in_flight += 1,\n                        Err(error) => {\n                            entry.deferred_initial_error = Some(error);\n                        }\n                    }\n                }\n            }\n        }\n'
NEW_FIRST_SHOT_REGION = b'        let mut starts_left = MAX_SIBLING_PUBLICATIONS;\n        // An admitted recipient owns a fresh first Consent attempt. Source\n        // first shots still require a successful harvest. Attempts are consumed\n        // before awaiting; periodic retries keep their existing rules.\n        for entry in &mut channels {\n            if starts_left == 0 || in_flight >= MAX_SIBLING_PUBLICATIONS {\n                break;\n            }\n            if (harvested_success || entry.recipient)\n                && entry.publication.is_none()\n                && !entry.handshake_attempted\n                && entry.deferred_initial_error.is_none()\n                && entry.original.live()\n                && entry.state.live()\n            {\n                #[cfg(all(test, feature = "test-policy-overrides"))]\n                match Self::sibling_publication_held_for_test(entry) {\n                    Ok(true) => continue,\n                    Ok(false) => {}\n                    Err(error) => {\n                        starts_left -= 1;\n                        entry.handshake_attempted = true;\n                        entry.deferred_initial_error = Some(error);\n                        continue;\n                    }\n                }\n                starts_left -= 1;\n                entry.handshake_attempted = true;\n                match self.start_sibling_publication(entry, None).await {\n                    Ok(()) => in_flight += 1,\n                    Err(error) => {\n                        entry.deferred_initial_error = Some(error);\n                    }\n                }\n            }\n        }\n'
PRODUCT = red.PRODUCT
SELF = 'scripts/qualify_upstream_recipient_admission_candidate.py'
WORKFLOW = red.WORKFLOW
OUT = Path('recipient-admission-candidate-evidence')
BEGIN = '  # RECIPIENT_ADMISSION_CANDIDATE_JOBS_BEGIN\n'
END = '  # RECIPIENT_ADMISSION_CANDIDATE_JOBS_END\n'
OPTIONS = 'options: [recipient-admission-candidate-preflight, recipient-admission-candidate-green, recipient-admission-candidate-mutations, '
PREFIX = 'native_device_linking::automatic_pairing_acceptance::'
CASES = [('admission', red.CASE, red.TEST), ('late_consent', consent.CASE, consent.TEST),
         ('late_proof', proof.CASE, proof.TEST), ('body', body.CASE, body.NAME),
         ('completion', NEW, PREFIX + NEW)]
CASES += [('original_' + str(index), suffix, PREFIX + suffix) for index, suffix in enumerate(ORIGINALS)]


def configured():
    ensure(re.fullmatch('[0-9a-f]{40}', REGRESSION_BASE) is not None, 'full-signed-regression-baseline-required')
    ensure(re.fullmatch('[0-9a-f]{40}', BASE) is not None, 'reviewed-signed-product-baseline-not-configured')
    ensure(all(value and b'ROOT_REVIEWED' not in value for value in
               [WAKE_ANCHOR, ELIGIBILITY_ANCHOR, ELIGIBILITY_MUTANT]), 'exact-reviewed-counterfactuals-not-configured')
    ensure(ELIGIBILITY_ANCHOR != ELIGIBILITY_MUTANT, 'nonempty-eligibility-counterfactual')


def restored_workflow(data):
    text = data.decode()
    ensure(text.count(BEGIN) == text.count(END) == text.count(OPTIONS) == 1, 'one-exact-candidate-workflow-overlay')
    before, rest = text.split(BEGIN)
    _, after = rest.split(END)
    return (before + after).replace(OPTIONS, 'options: [', 1).encode()


def source_guard():
    configured()
    source = subprocess.check_output(['git', 'rev-parse', 'HEAD'], text=True).strip()
    ensure(os.environ.get('GITHUB_ACTIONS') == 'true' and os.environ.get('GITHUB_REPOSITORY') == 'dyKiU/mdk'
           and source == os.environ.get('GITHUB_SHA'), 'exact-approved-remote-source')
    subprocess.run(['git', 'merge-base', '--is-ancestor', REGRESSION_BASE, BASE], check=True)
    ensure(set(subprocess.check_output(['git', 'diff', '--name-only', '--no-renames', REGRESSION_BASE, BASE], text=True).splitlines()) == {PRODUCT},
           'reviewed-fix-changes-only-product-and-preserves-regression-cohort')
    subprocess.run(['git', 'merge-base', '--is-ancestor', BASE, source], check=True)
    ensure(subprocess.run(['git', 'diff', '--quiet', 'HEAD']).returncode == 0, 'initial-pristine-inputs')
    ensure(subprocess.check_output(['git', 'rev-parse', '--show-object-format'], text=True).strip() == 'sha1', 'explicit-blob-format')
    baseline = {}
    for entry in subprocess.check_output(['git', 'ls-tree', '-r', '-z', BASE]).split(b'\0'):
        if not entry:
            continue
        metadata, name = entry.split(b'\t', 1)
        mode, kind, blob = metadata.decode().split()
        ensure(kind == 'blob' and mode in {'100644', '100755', '120000'}, 'ordinary-reviewed-tree')
        baseline[os.fsdecode(name)] = (mode, blob)
    current = layout()
    ensure(SELF not in baseline and set(current) == set(baseline) | {SELF}, 'whole-tracked-inventory-exact')
    ensure(current[SELF] == {'git_mode': '100644', 'actual_executable': False,
                             'symlink': False, 'symlink_target': None}, 'ordinary-new-controller')
    for name, (mode, blob) in baseline.items():
        metadata = current[name]
        ensure(metadata['git_mode'] == mode and metadata['symlink'] == (mode == '120000')
               and (mode == '120000' or metadata['actual_executable'] == (mode == '100755')), 'whole-tracked-layout:' + name)
        data = os.fsencode(os.readlink(name)) if mode == '120000' else Path(name).read_bytes()
        if name == WORKFLOW:
            data = restored_workflow(data)
        actual = hashlib.sha1(b'blob ' + str(len(data)).encode() + b'\0' + data).hexdigest()
        ensure(actual == blob, 'whole-tracked-content-after-explicit-metadata-overlays:' + name)
    product = Path(PRODUCT).read_bytes()
    ensure(product.count(WAKE_ANCHOR) == product.count(ELIGIBILITY_ANCHOR) == 1, 'unique-reviewed-independent-mutation-anchors')
    ensure(product.count(FULL_WAKE_REGION) == product.count(NEW_FIRST_SHOT_REGION) == 1,
           'exact-reviewed-two-product-regions')
    restored = product.replace(FULL_WAKE_REGION, b'', 1).replace(NEW_FIRST_SHOT_REGION, OLD_FIRST_SHOT_REGION, 1)
    ensure(restored == subprocess.check_output(['git', 'show', REGRESSION_BASE + ':' + PRODUCT]),
           'entire-product-reconstructs-genuine-red-after-only-two-reviewed-regions')
    return {'source': source, 'baseline': BASE, 'entire_tracked_content_and_modes_verified': True,
            'overlay_paths': [SELF, WORKFLOW], 'historical_controllers_and_all_fixtures_unchanged': True,
            'genuine_red_source': REGRESSION_BASE, 'genuine_red_run': 39071256534,
            'whole_product_exact_after_two_reviewed_region_reversal': True,
            'historical_runtime_evidence_reused': False, 'full_integration_qualified': False}


def parse(label, raw, exit_code):
    raw = re.sub(r'\x1b\[[0-9;]*m', '', raw)
    if label == 'admission':
        row = red.parse(raw, exit_code)
    elif label == 'late_consent':
        row = consent.parse(raw, exit_code)
    elif label == 'late_proof':
        row = proof.parse(raw, exit_code)
    elif label == 'body':
        row = dict(body.parse(raw), body_exit_code=exit_code)
    else:
        suffix = next(suffix for key, suffix, _ in CASES if key == label)
        row = dict(parse_body(raw, suffix), body_exit_code=exit_code, suffix=suffix)
    row['compiler_error_count'] = headers(raw)['compiler_error_count']
    row['executed_case_names'] = re.findall(r'(?m)^test ([A-Za-z0-9_:]+) \.\.\.', raw)
    row['running_counts'] = [int(value) for value in re.findall(r'(?m)^running ([0-9]{1,3}) tests?$', raw)]
    return row


def runtime_green(label, row):
    name = next(name for key, _, name in CASES if key == label)
    counts = {'body_exit_code': 0, 'passed': 1, 'failed': 0, 'ignored': 0,
              'executed_nonignored': 1, 'compiler_error_count': 0, 'all_panic_header_count': 0}
    good = (all(type(row.get(key)) is int and row[key] == value for key, value in counts.items())
            and row.get('executed_case_names') == [name] and row.get('running_counts') == [1]
            and not row.get('watchdog_triggered') and not row.get('actual_count_unknown'))
    if label == 'admission':
        return (good and row.get('marker_count') == row.get('marker_header_count') == 1
                and all(row.get('facts', {}).get(key) is True for key in red.FIELDS)
                and row.get('runtime_closes') == row.get('planes_shutdown') == 3
                and row.get('relay_closed') is True and row.get('attempt_completed') is True)
    if label == 'late_consent':
        return good and consent_candidate.consent_green(row)
    if label == 'late_proof':
        return good and proof_green(row)
    if label == 'body':
        return good and body.body_green(row)
    return good and completion_green(row)


def parser_controls():
    prior = red.parser_controls()
    marker = 'recipient-sibling-admission ' + ' '.join(name + '=true' for name in red.FIELDS)
    marker += ' runtime_closes=3 planes_shutdown=3 relay_closed=true attempt_completed=true'
    raw = 'running 1 test\ntest ' + red.TEST + ' ... ' + marker + '\ntest result: ok. 1 passed; 0 failed; 0 ignored;\n'
    ensure(runtime_green('admission', parse('admission', raw, 0)), 'actual-green-parser-positive')
    negatives = [raw + marker + '\n', raw.replace(red.TEST, 'foreign::case'), raw.replace('1 passed', '0 passed'),
                 raw.replace('running 1 test', 'running 0 tests'), raw.replace('0 ignored', '1 ignored'),
                 raw.replace('runtime_closes=3', 'runtime_closes=2'), raw.replace('planes_shutdown=3', 'planes_shutdown=2'),
                 raw.replace('relay_closed=true', 'relay_closed=false'), raw.replace('attempt_completed=true', 'attempt_completed=false'),
                 raw + '\nthread other panicked at crates/other.rs:1:1:\n', 'error: compile failed\n']
    negatives += [raw.replace(name + '=true', name + '=false') for name in red.FIELDS]
    negatives += [raw.replace(' ' + name + '=true', '') for name in red.FIELDS]
    for value in negatives:
        ensure(not runtime_green('admission', parse('admission', value, 0)), 'false-or-incomplete-green-rejected')
    row = parse('admission', raw, 0)
    changes = [{'passed': True}, {'watchdog_triggered': True}, {'actual_count_unknown': True},
               {'compiler_error_count': 1}, {'body_exit_code': 101}, {'executed_case_names': [red.TEST, red.TEST]}]
    for change in changes:
        ensure(not runtime_green('admission', dict(row, **change)), 'unknown-count-or-identity-rejected')
    receipt = {'source': 'parser-source', 'input_manifest_sha256': 'parser-manifest', 'inputs_pristine': True,
               'source_preflight': {'source': 'parser-source', 'baseline': BASE,
                                    'entire_tracked_content_and_modes_verified': True}}
    ensure(receipt_identity(receipt, 'parser-source', 'parser-manifest'), 'receipt-identity-positive')
    changed = [{'source': 'other'}, {'input_manifest_sha256': 'other'}, {'inputs_pristine': False},
               {'source_preflight': {}}, {'source_preflight': dict(receipt['source_preflight'], baseline='other')},
               {'source_preflight': dict(receipt['source_preflight'], source='other')},
               {'source_preflight': dict(receipt['source_preflight'], entire_tracked_content_and_modes_verified=False)}]
    for change in changed:
        ensure(not receipt_identity(dict(receipt, **change), 'parser-source', 'parser-manifest'), 'receipt-cross-source-manifest-or-layout-rejected')
    return {'historical_red_adversaries': prior, 'receipt_identity_positive': 1,
            'receipt_identity_negative': len(changed), 'green_positive': 1,
            'green_negative': len(negatives) + len(changes), 'actual_runtime_bodies': 0}


def normalized_features(compilation):
    result = feature_identity(compilation)
    command = list(result['command'])
    ensure(command.count('-E') == 1, 'one-exact-compiled-filter')
    command[command.index('-E') + 1] = '<verified-exact-case-set>'
    return dict(result, command=command)


def receipt_identity(receipt, source, manifest):
    return (receipt.get('source') == source and receipt.get('input_manifest_sha256') == manifest
            and receipt.get('inputs_pristine') is True
            and receipt.get('source_preflight', {}).get('source') == source
            and receipt.get('source_preflight', {}).get('baseline') == BASE
            and receipt.get('source_preflight', {}).get('entire_tracked_content_and_modes_verified') is True)


def previous_green(run_id, source, manifest, current_environment):
    ensure(re.fullmatch('[0-9]{1,20}', run_id) is not None, 'preceding-green-run-required')
    def api(path):
        return subprocess.check_output(['gh', 'api', 'repos/dyKiU/mdk/' + path], timeout=30)
    run = json.loads(api('actions/runs/' + run_id))
    ensure(run.get('head_sha') == source and run.get('conclusion') == 'success'
           and run.get('event') == 'workflow_dispatch' and run.get('path') == WORKFLOW, 'preceding-whole-success-exact-source')
    listing = json.loads(api('actions/runs/' + run_id + '/artifacts?per_page=100'))
    artifacts = listing['artifacts']
    ensure(type(listing.get('total_count')) is int and listing['total_count'] == len(artifacts) <= 100, 'bounded-complete-artifact-inventory')
    receipts = {}
    for name in ['recipient-admission-candidate-green', 'recipient-admission-candidate-static-default',
                 'recipient-admission-candidate-static-experimental']:
        matches = [item for item in artifacts if item.get('name') == name and item.get('expired') is False]
        ensure(len(matches) == 1 and type(matches[0].get('size_in_bytes')) is int
               and 0 < matches[0]['size_in_bytes'] < 500_000, 'one-bounded-required-green-artifact')
        item = matches[0]
        ensure(type(item.get('id')) is int and item['id'] > 0, 'actual-artifact-id')
        data = api('actions/artifacts/' + str(item['id']) + '/zip')
        ensure(len(data) == item['size_in_bytes'] < 500_000
               and item.get('digest') == 'sha256:' + digest(data), 'artifact-size-and-api-digest')
        with zipfile.ZipFile(io.BytesIO(data)) as archive:
            entries = archive.infolist()
            ensure(len(entries) == 1 and entries[0].filename == 'result.json' and not entries[0].is_dir()
                   and 0 < entries[0].file_size < 500_000 and entries[0].compress_size < 500_000,
                   'sole-bounded-nontraversing-json-receipt')
            receipt = json.loads(archive.read(entries[0]))
        ensure(receipt_identity(receipt, source, manifest), 'exact-relevant-source-layout-and-product-baseline')
        for key in ['toolchain', 'environment']:
            ensure(receipt.get(key) == current_environment.get(key) and receipt.get(key), 'prior-actual-toolchain-environment')
        receipts[name] = {'artifact_id': item['id'], 'download_sha256': digest(data), 'receipt': receipt}
    green = receipts['recipient-admission-candidate-green']['receipt']
    ensure(all(type(green.get(key)) is int for key in ['actual_runtime_bodies', 'actual_passed', 'actual_failed', 'actual_ignored']),
           'prior-counts-are-actual-integers')
    ensure(green.get('mode') == 'green' and green.get('green_passed') is True
           and green.get('actual_runtime_bodies') == green.get('actual_passed') == 8
           and green.get('actual_failed') == green.get('actual_ignored') == 0
           and green.get('actual_counts_complete') is True
           and list(green.get('phases', {})) == [label for label, _, _ in CASES], 'preceding-eight-real-controls')
    for label, _, _ in CASES:
        row = green['phases'][label]
        ensure(row.get('actual_counts_complete') is True and runtime_green(label, row.get('body', {}))
               and row.get('compiled_binary_sha256') == green.get('baseline_binary_sha256'), 'preceding-exact-case-not-green')
    ensure(green.get('compilation', {}).get('compile_exit_code') == green.get('compilation', {}).get('compiler_error_count') == 0
           and green['compilation'].get('compiled_fingerprints', {}).get('verified') is True, 'preceding-real-feature-verified-compile')
    for cohort in ['default', 'experimental']:
        receipt = receipts['recipient-admission-candidate-static-' + cohort]['receipt']
        ensure(receipt.get('mode') == 'static' and receipt.get('cohort') == cohort
               and receipt.get('static_passed') is True
               and type(receipt.get('exit_code')) is int and receipt['exit_code'] == 0
               and type(receipt.get('compiler_error_count')) is int and receipt['compiler_error_count'] == 0
               and receipt.get('command') == static_command(cohort), 'both-actual-strict-app-static-cohorts')
    return {'run_id': int(run_id), 'source': source, 'artifacts': receipts,
            'compiled_feature_identity': green['compiled_feature_identity'],
            'baseline_binary_sha256': green['baseline_binary_sha256']}


def static_command(cohort):
    return ['cargo', 'clippy', '--locked', '-p', 'marmot-app', '--all-targets', '--features',
            FEATURES if cohort == 'experimental' else DEFAULT_FEATURES, '--', '-D', 'warnings']


def main(options):
    os.umask(0o077); OUT.mkdir(exist_ok=True)
    report = {'mode': options.mode, 'green_passed': False, 'mutation_chain_passed': False,
              'qualification_passed': False, 'phases': {}, 'original_native_closure_counts': 'not_emitted_by_original_fixtures'}
    original = Path(PRODUCT).read_bytes()
    frozen, metadata = freeze(), layout()
    report['input_manifest_sha256'] = identity(frozen)
    def save():
        (OUT / 'result.json').write_text(json.dumps(report, indent=2) + '\n')
    def pristine(expected=frozen):
        return freeze() == expected and layout() == metadata
    def compile_for(selected, expected):
        ensure(pristine(expected), 'before-compile-frozen-inputs')
        compilation, cases = compile_cases([suffix for _, suffix, _ in selected])
        report.setdefault('compilations', []).append(compilation); save()
        ensure(compilation.get('compile_exit_code') == compilation.get('compiler_error_count') == 0
               and compilation.get('compiled_fingerprints', {}).get('verified') is True
               and set(cases) == {suffix for _, suffix, _ in selected}, 'actual-feature-verified-compile-and-inventory')
        for _, suffix, name in selected:
            ensure(cases[suffix]['name'] == name, 'actual-exact-full-case-name')
        features = normalized_features(compilation)
        if 'compiled_feature_identity' in report:
            ensure(features == report['compiled_feature_identity'], 'phase-feature-profile-flags-identity')
        else:
            report['compiled_feature_identity'] = features
        if report.get('prior_green'):
            ensure(features == report['prior_green']['compiled_feature_identity'], 'prior-green-actual-compiled-feature-identity')
        ensure(pristine(expected), 'compiled-source-pristine')
        return compilation, cases
    def execute(label, case, expected, phase_name):
        ensure(pristine(expected) and digest(Path(case['binary']).read_bytes()) == case['binary_sha256'], 'before-runtime-source-and-binary')
        row = {'actual_counts_complete': False, 'compiled_binary_sha256': case['binary_sha256'],
               'phase_input_manifest_sha256': identity(expected)}
        report['phases'][phase_name] = row; save()
        started = time.monotonic()
        try:
            result = subprocess.run([case['binary'], '--exact', case['name'], '--nocapture', '--test-threads=1'],
                                    capture_output=True, text=True, timeout=300)
            row['body'] = parse(label, result.stdout + result.stderr, result.returncode)
        except subprocess.TimeoutExpired:
            row['body'] = {'watchdog_triggered': True, 'actual_count_unknown': True}
        row['body']['seconds'] = time.monotonic() - started
        values = row['body']
        row['actual_counts_complete'] = (all(type(values.get(key)) is int and values[key] >= 0
                                             for key in ['passed', 'failed', 'ignored', 'executed_nonignored'])
                                          and values['passed'] + values['failed'] == values['executed_nonignored'] == 1
                                          and not values.get('watchdog_triggered') and not values.get('actual_count_unknown'))
        row['green_passed'] = runtime_green(label, values)
        ensure(pristine(expected) and digest(Path(case['binary']).read_bytes()) == case['binary_sha256'], 'after-runtime-source-and-binary')
        save(); return row
    try:
        report['source_preflight'] = source_guard(); report['source'] = report['source_preflight']['source']
        report['parser_controls'] = parser_controls(); save()
        if options.preflight:
            return
        report.update(environment())
        if options.mode == 'static':
            ensure(options.cohort in {'default', 'experimental'}, 'explicit-static-cohort')
            command = static_command(options.cohort)
            started = time.monotonic()
            result = subprocess.run(command, capture_output=True, text=True, timeout=1800)
            report.update(cohort=options.cohort, command=command, exit_code=result.returncode,
                          seconds=time.monotonic() - started, **headers(result.stderr))
            report['static_passed'] = result.returncode == report['compiler_error_count'] == 0 and pristine()
            save(); ensure(report['static_passed'], 'required-static-cohort-not-green'); return
        if options.mode == 'green':
            compilation, cases = compile_for(CASES, frozen)
            report['compilation'] = compilation
            report['baseline_binary_sha256'] = cases[red.CASE]['binary_sha256']
            for label, suffix, _ in CASES:
                ensure(cases[suffix]['binary_sha256'] == report['baseline_binary_sha256'], 'all-eight-same-app-binary')
                execute(label, cases[suffix], frozen, label)
            report['green_passed'] = all(row['green_passed'] for row in report['phases'].values())
            save(); ensure(report['green_passed'], 'all-eight-real-runtime-controls-required'); return
        ensure(options.mode == 'mutations', 'explicit-qualification-mode')
        report['prior_green'] = previous_green(options.control_run_id, report['source'], report['input_manifest_sha256'], report)
        _, cases = compile_for(CASES[:1], frozen)
        report['baseline_binary_sha256'] = cases[red.CASE]['binary_sha256']
        ensure(report['baseline_binary_sha256'] == report['prior_green']['baseline_binary_sha256'], 'same-exact-prior-green-binary')
        baseline = execute('admission', cases[red.CASE], frozen, 'baseline_admission')
        ensure(baseline['green_passed'], 'fresh-baseline-admission-green')
        outcomes = []
        for label, anchor, replacement in [('wake_omission', WAKE_ANCHOR, b''),
                                            ('eligibility_omission', ELIGIBILITY_ANCHOR, ELIGIBILITY_MUTANT)]:
            ensure(pristine() and original.count(anchor) == 1, 'one-independent-mutation-from-pristine-baseline')
            mutation_error = None
            killed = False
            try:
                changed = original.replace(anchor, replacement, 1)
                Path(PRODUCT).write_bytes(changed)
                expected = freeze()
                ensure(layout() == metadata and set(expected) == set(frozen)
                       and {name for name in frozen if expected[name] != frozen[name]} == {PRODUCT}, 'only-exact-product-counterfactual')
                compilation, cases = compile_for(CASES[:1], expected)
                mutant = execute('admission', cases[red.CASE], expected, label)
                mutant['compilation'] = compilation
                mutant['mutant_product_sha256'] = digest(changed)
                mutant['runtime_killed'] = red.intended_red(mutant['body'])
                mutant['binary_differs'] = mutant['compiled_binary_sha256'] != report['baseline_binary_sha256']
                killed = mutant['runtime_killed'] and mutant['binary_differs']; save()
            except Exception as error:
                mutation_error = type(error).__name__
                report.setdefault('mutation_exceptions', {})[label] = mutation_error; save()
            finally:
                Path(PRODUCT).write_bytes(original)
                ensure(pristine(), 'exact-whole-source-and-layout-restored')
            compilation, cases = compile_for(CASES[:1], frozen)
            restored = execute('admission', cases[red.CASE], frozen, label + '_restored')
            restored['compilation'] = compilation
            restored['binary_identical_to_baseline'] = restored['compiled_binary_sha256'] == report['baseline_binary_sha256']
            ensure(restored['green_passed'] and restored['binary_identical_to_baseline'], 'restored-actual-green-and-same-binary-required')
            outcomes.append(mutation_error is None and killed); save()
        report['mutation_chain_passed'] = len(outcomes) == 2 and all(outcomes)
        save(); ensure(report['mutation_chain_passed'], 'both-independent-runtime-omissions-must-be-killed')
    except Exception as error:
        report['controller_exception'] = type(error).__name__
        raise
    finally:
        Path(PRODUCT).write_bytes(original)
        report['inputs_pristine'] = pristine() and subprocess.run(['git', 'diff', '--quiet', 'HEAD']).returncode == 0
        rows = list(report['phases'].values())
        for key, output in [('executed_nonignored', 'actual_runtime_bodies'), ('passed', 'actual_passed'),
                            ('failed', 'actual_failed'), ('ignored', 'actual_ignored')]:
            values = [row.get('body', {}).get(key) for row in rows]
            report[output] = sum(values) if all(type(value) is int and value >= 0 for value in values) else None
        report['actual_counts_complete'] = bool(rows) and all(row.get('actual_counts_complete') is True for row in rows)
        report['green_passed'] = bool(report['green_passed'] and report['inputs_pristine'] and report['actual_counts_complete']
                                      and report['actual_runtime_bodies'] == report['actual_passed'] == 8
                                      and report['actual_failed'] == report['actual_ignored'] == 0)
        report['mutation_chain_passed'] = bool(report['mutation_chain_passed'] and report['inputs_pristine']
                                               and report['actual_counts_complete'] and report['actual_runtime_bodies'] == 5
                                               and report['actual_passed'] == 3 and report['actual_failed'] == 2
                                               and report['actual_ignored'] == 0)
        save(); ensure(report['inputs_pristine'], 'final-whole-source-not-pristine')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--preflight', action='store_true')
    parser.add_argument('--mode', choices=['green', 'static', 'mutations'], default='green')
    parser.add_argument('--cohort', choices=['default', 'experimental'])
    parser.add_argument('--control-run-id', default='')
    main(parser.parse_args())
