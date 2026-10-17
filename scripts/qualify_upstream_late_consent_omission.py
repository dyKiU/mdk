#!/usr/bin/env python3
"""Exact Consent hint/wake counterfactual; never full integration qualification."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import time
import qualify_upstream_late_consent_red as red
import qualify_upstream_late_consent_candidate as candidate
import qualify_upstream_peer_proof as proof
from qualify_upstream_peer_proof_candidate import green as proof_green
from upstream_completion_ci import compile_cases, digest, ensure, environment, identity
from qualify_upstream_body_negative import feature_identity, freeze, layout

BASE = 'a302c2194c777bef87ae48aff51a8bc570cbc588'
PRODUCT = candidate.PRODUCT
SELF = 'scripts/qualify_upstream_late_consent_omission.py'
WORKFLOW = '.github/workflows/experimental-sync-ci.yml'
OUT = Path('late-consent-omission-evidence')
BEGIN = '  # LATE_CONSENT_OMISSION_JOBS_BEGIN\n'
END = '  # LATE_CONSENT_OMISSION_JOBS_END\n'
OPTIONS = 'options: [late-consent-omission-preflight, late-consent-omission, '
ANCHOR = (b'                        entry.consent_progress_due = true;\n'
          b'                        self.linking_owner\n'
          b'                            .sibling_publication_completions\n'
          b'                            .send_replace(());\n')


def restored_workflow(data):
    text = data.decode()
    ensure(text.count(BEGIN) == text.count(END) == text.count(OPTIONS) == 1, 'one-exact-isolated-workflow-overlay')
    before, rest = text.split(BEGIN)
    _, after = rest.split(END)
    return (before + after).replace(OPTIONS, 'options: [', 1).encode()


def source_guard():
    source = subprocess.check_output(['git', 'rev-parse', 'HEAD'], text=True).strip()
    ensure(os.environ.get('GITHUB_ACTIONS') == 'true' and os.environ.get('GITHUB_REPOSITORY') == 'dyKiU/mdk'
           and source == os.environ.get('GITHUB_SHA'), 'approved-exact-remote-source')
    subprocess.run(['git', 'merge-base', '--is-ancestor', BASE, source], check=True)
    ensure(subprocess.run(['git', 'diff', '--quiet', 'HEAD']).returncode == 0, 'initial-pristine-source')
    ensure(subprocess.check_output(['git', 'rev-parse', '--show-object-format'], text=True).strip() == 'sha1', 'explicit-git-blob-format')
    entries = subprocess.check_output(['git', 'ls-tree', '-r', '-z', BASE]).split(b'\0')
    baseline = {}
    for entry in entries:
        if not entry: continue
        metadata, name = entry.split(b'\t', 1)
        mode, kind, blob = metadata.decode().split()
        ensure(kind == 'blob' and mode in {'100644', '100755', '120000'}, 'ordinary-reviewed-baseline-tree')
        baseline[os.fsdecode(name)] = (mode, blob)
    current = layout()
    ensure(SELF not in baseline and set(current) == set(baseline) | {SELF}, 'entire-tracked-file-inventory-exact')
    ensure(current[SELF] == {'git_mode': '100644', 'actual_executable': False, 'symlink': False, 'symlink_target': None}, 'ordinary-new-controller-mode')
    for name, (mode, blob) in baseline.items():
        metadata = current[name]
        ensure(metadata['git_mode'] == mode and (mode == '120000' or metadata['actual_executable'] == (mode == '100755'))
               and metadata['symlink'] == (mode == '120000'), 'whole-tracked-layout-exact:' + name)
        data = os.fsencode(os.readlink(name)) if mode == '120000' else Path(name).read_bytes()
        if name == WORKFLOW: data = restored_workflow(data)
        actual = hashlib.sha1(b'blob ' + str(len(data)).encode() + b'\0' + data).hexdigest()
        ensure(actual == blob, 'whole-tracked-content-exact-after-two-metadata-overlays:' + name)
    ensure(Path(PRODUCT).read_bytes().count(ANCHOR) == 1, 'unique-two-statement-hint-wake-anchor')
    return {'source': source, 'baseline': BASE, 'entire_tracked_content_and_modes_verified': True,
            'overlay_paths': [SELF, WORKFLOW], 'historical_red_and_green_controllers_unchanged': True,
            'genuine_red_run': 39060926547, 'historical_runtime_evidence_reused': False,
            'full_integration_qualified': False}


def parser_controls():
    green = candidate.parser_controls()
    ensure(ANCHOR.count(b'entry.consent_progress_due = true;') == 1
           and ANCHOR.count(b'.send_replace(());') == 1, 'exact-two-statement-counterfactual')
    # The unchanged predicates exercise all actual runtime and cleanup prerequisites.
    return {'unchanged_green_and_genuine_red_controls': green, 'actual_runtime_bodies': 0}


def main(preflight):
    os.umask(0o077); OUT.mkdir(exist_ok=True)
    report = {'qualification_passed': False, 'mutation_chain_passed': False, 'phases': {},
              'expected_complete_runtime_bodies': 4, 'component_only': True}
    original = Path(PRODUCT).read_bytes()
    frozen, metadata = freeze(), layout()
    report['input_manifest_sha256'] = identity(frozen)
    def save(): (OUT / 'result.json').write_text(json.dumps(report, indent=2) + '\n')
    def pristine(expected=frozen): return freeze() == expected and layout() == metadata
    def phase(label, expected, suffix=red.CASE, name=red.TEST):
        ensure(pristine(expected), 'phase-inputs-exact')
        row = {'actual_counts_complete': False}; report['phases'][label] = row; save()
        compilation, cases = compile_cases([suffix]); row['compilation'] = compilation; save()
        ensure(compilation.get('compile_exit_code') == compilation.get('compiler_error_count') == 0
               and compilation.get('compiled_fingerprints', {}).get('verified') is True
               and set(cases) == {suffix} and cases[suffix]['name'] == name, 'actual-sole-compiled-feature-case')
        features = feature_identity(compilation)
        command = list(features['command']); ensure(command.count('-E') == 1, 'one-actual-case-filter')
        index = command.index('-E') + 1
        ensure(command[index] == 'test(' + suffix + ')', 'exact-selected-case-filter')
        command[index] = 'test(<verified-directed-case>)'
        features = dict(features, command=command)
        if 'compiled_feature_identity' in report: ensure(features == report['compiled_feature_identity'], 'same-feature-profile-throughout-chain')
        else: report['compiled_feature_identity'] = features
        case = cases[suffix]; row['compiled_binary_sha256'] = case['binary_sha256']
        ensure(pristine(expected) and digest(Path(case['binary']).read_bytes()) == case['binary_sha256'], 'compiled-inputs-and-binary-exact')
        started = time.monotonic()
        try:
            result = subprocess.run([case['binary'], '--exact', name, '--nocapture', '--test-threads=1'], capture_output=True, text=True, timeout=300)
            row['body'] = red.parse(result.stdout + result.stderr, result.returncode) if suffix == red.CASE else proof.parse(result.stdout + result.stderr, result.returncode)
        except subprocess.TimeoutExpired:
            row['body'] = {'watchdog_triggered': True, 'actual_count_unknown': True}
        row['body']['seconds'] = time.monotonic() - started
        body = row['body']
        row['actual_counts_complete'] = (all(type(body.get(key)) is int and body[key] >= 0 for key in ['passed', 'failed', 'ignored', 'executed_nonignored'])
                                         and body['executed_nonignored'] == body['passed'] + body['failed'] == 1
                                         and not body.get('watchdog_triggered') and not body.get('actual_count_unknown'))
        ensure(pristine(expected) and digest(Path(case['binary']).read_bytes()) == case['binary_sha256'], 'runtime-source-and-binary-exact')
        save(); return body
    try:
        report['source_preflight'] = source_guard(); report['source'] = report['source_preflight']['source']
        report['parser_controls'] = parser_controls(); save()
        if preflight: return
        report.update(environment())
        baseline = phase('baseline_consent', frozen)
        report['baseline_control_passed'] = candidate.consent_green(baseline); save()
        ensure(report['baseline_control_passed'], 'fresh-consent-baseline-green-required')
        ensure(original.count(ANCHOR) == 1, 'one-exact-hint-and-wake-omission')
        mutated = original.replace(ANCHOR, b'', 1)
        mutation_error = None
        try:
            Path(PRODUCT).write_bytes(mutated)
            expected = freeze()
            ensure(layout() == metadata and set(expected) == set(frozen)
                   and {name for name in frozen if expected[name] != frozen[name]} == {PRODUCT}, 'sole-two-statement-product-counterfactual')
            report['mutant_product_sha256'] = digest(mutated)
            report['mutant_manifest_sha256'] = identity(expected)
            mutant = phase('omission', expected)
            report['omission_runtime_killed'] = red.intended_red(mutant)
            report['mutant_binary_differs_from_baseline'] = (report['phases']['omission']['compiled_binary_sha256'] != report['phases']['baseline_consent']['compiled_binary_sha256'])
            save()
        except Exception as error:
            mutation_error = type(error).__name__; report['mutation_exception'] = mutation_error; save()
        finally:
            Path(PRODUCT).write_bytes(original)
            report['source_restored'] = pristine(); save()
        ensure(report['source_restored'], 'exact-source-and-layout-restored')
        # Positive restored bodies still run if the mutant survives or fails to compile.
        restored = phase('restored_consent', frozen)
        report['restored_control_passed'] = candidate.consent_green(restored)
        report['restored_binary_identical_to_baseline'] = (report['phases']['restored_consent']['compiled_binary_sha256'] == report['phases']['baseline_consent']['compiled_binary_sha256'])
        late_proof = phase('restored_late_proof', frozen, proof.CASE, proof.TEST)
        report['restored_late_proof_passed'] = proof_green(late_proof)
        report['restored_late_proof_binary_identical'] = (report['phases']['restored_late_proof']['compiled_binary_sha256'] == report['phases']['baseline_consent']['compiled_binary_sha256'])
        report['mutation_chain_passed'] = (mutation_error is None and report.get('omission_runtime_killed') is True
            and report.get('mutant_binary_differs_from_baseline') is True and report['restored_control_passed']
            and report['restored_binary_identical_to_baseline'] and report['restored_late_proof_passed']
            and report['restored_late_proof_binary_identical'] and all(row['actual_counts_complete'] for row in report['phases'].values()))
        save(); ensure(report['mutation_chain_passed'], 'actual-four-body-omission-restoration-chain-required')
    except Exception as error:
        report['controller_exception'] = type(error).__name__
        raise
    finally:
        Path(PRODUCT).write_bytes(original)
        report['inputs_pristine'] = pristine() and subprocess.run(['git', 'diff', '--quiet', 'HEAD']).returncode == 0
        phases = list(report['phases'].values())
        report['runtime_phases_attempted'] = len(phases)
        report['actual_counts_complete'] = all(row.get('actual_counts_complete') is True for row in phases)
        report['actual_runtime_bodies'] = sum(row.get('body', {}).get('executed_nonignored', 0) for row in phases)
        for key in ['passed', 'failed', 'ignored']:
            report['actual_' + key] = sum(row.get('body', {}).get(key, 0) for row in phases)
        report['mutation_chain_passed'] = bool(report['mutation_chain_passed'] and report['inputs_pristine'] and report['actual_counts_complete'] and report['actual_runtime_bodies'] == 4)
        save(); ensure(report['inputs_pristine'], 'final-input-source-pristine')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--preflight', action='store_true')
    main(parser.parse_args().preflight)
