#!/usr/bin/env python3
"""Exact directed late-proof GREEN/static/omission evidence; other gates remain pending."""
import argparse
import io
import json
import os
from pathlib import Path
import re
import subprocess
import time
import zipfile
import qualify_upstream_peer_proof as historical
from upstream_completion_ci import DEFAULT_FEATURES, FEATURES, compile_cases, digest, ensure, environment, headers, identity
from qualify_upstream_body_negative import freeze, layout, feature_identity

RED = '1e4e7b56f038bae38079fdb087f4831c4d3d861f'
PRODUCT = 'crates/marmot-app/src/client/device_linking/sibling_sharing.rs'
SELF = 'scripts/qualify_upstream_peer_proof_candidate.py'
WORKFLOW = '.github/workflows/experimental-sync-ci.yml'
EVENT = '''                    // The peer proof can arrive after our own ACK was harvested.
                    // Keep its authenticated fact on this original if fresh parent
                    // or channel validation fails; periodic maintenance retries
                    // completion without reopening the already-consumed wire.
                    if entry.policy_committed && entry.proof_published {
                        match self.validate_sibling_publication(&entry) {
                            Ok(()) => Self::complete_sibling_sharing(&entry),
                            Err(_) => {
                                tracing::debug!(
                                    target: "marmot_app::device_linking",
                                    method = "sibling_peer_proof_completion",
                                    "authenticated peer proof retained for fresh completion validation"
                                );
                            }
                        }
                    }
'''
PERIODIC_OLD = '''        Self::complete_sibling_sharing(entry);
        Ok(())
    }

    fn complete_sibling_sharing'''
PERIODIC_NEW = '''        if entry.peer_committed {
            self.validate_sibling_publication(entry)?;
            Self::complete_sibling_sharing(entry);
        }
        Ok(())
    }

    fn complete_sibling_sharing'''
OUT = Path('peer-proof-candidate-evidence')


def green(row):
    return (row.get('body_exit_code') == 0 and row.get('passed') == 1 and row.get('failed') == 0
            and row.get('ignored') == 0 and row.get('executed_nonignored') == 1
            and row.get('compiler_error_count') == 0 and row.get('all_panic_header_count') == 0
            and row.get('executed_case_names') == [historical.TEST] and historical.prerequisites(row)
            and row.get('facts', {}).get('gated_complete') is True and not row.get('watchdog_triggered'))


def parser_preflight():
    old = historical.parser_preflight()
    marker = 'late-peer-proof ' + ' '.join(field + '=true' for field in historical.FIELDS)
    marker += ' runtime_closes=3 planes_shutdown=3 relay_closed=true attempt_completed=true'
    raw = 'running 1 test\ntest ' + historical.TEST + ' ... ' + marker + '\ntest result: ok. 1 passed; 0 failed; 0 ignored;\n'
    ensure(green(historical.parse(raw, 0)), 'actual-green-parser-prefix')
    ensure(green(historical.parse(raw.replace(' ... ' + marker, ' ... \n' + marker), 0)), 'actual-green-parser-own-line')
    negatives = [raw + marker + '\n', raw.replace(historical.TEST, 'foreign::test'),
                 raw.replace('1 passed', '0 passed'), raw.replace('0 ignored', '1 ignored'),
                 raw.replace('runtime_closes=3', 'runtime_closes=2'), raw.replace('planes_shutdown=3', 'planes_shutdown=2'),
                 raw.replace('relay_closed=true', 'relay_closed=false'), raw.replace('attempt_completed=true', 'attempt_completed=false'),
                 raw + '\nthread extra panicked at crates/other.rs:1:1:\n', 'error: compilation failed\n']
    negatives += [raw.replace(field + '=true', field + '=false') for field in historical.FIELDS]
    for value in negatives: ensure(not green(historical.parse(value, 0)), 'adversarial-green-parser')
    return {'historical_red': old, 'green_positive': 2, 'green_negative': len(negatives), 'actual_runtime_bodies': 0}


def source_guard():
    source = subprocess.check_output(['git', 'rev-parse', 'HEAD'], text=True).strip()
    ensure(os.environ.get('GITHUB_ACTIONS') == 'true' and os.environ.get('GITHUB_REPOSITORY') == 'dyKiU/mdk'
           and os.environ.get('GITHUB_SHA') == source, 'exact-approved-remote-source')
    subprocess.run(['git', 'merge-base', '--is-ancestor', RED, source], check=True)
    ensure(subprocess.run(['git', 'diff', '--quiet', 'HEAD']).returncode == 0, 'initial-pristine-source')
    changed = set(subprocess.check_output(['git', 'diff', '--name-only', RED, 'HEAD'], text=True).splitlines())
    ensure(changed <= {PRODUCT, SELF, WORKFLOW}, 'only-reviewed-two-completion-edges-controller-workflow')
    original = subprocess.check_output(['git', 'show', RED + ':' + PRODUCT]).decode()
    ensure(original.count('                    entry.peer_committed = true;\n') == 1 and original.count(PERIODIC_OLD) == 1, 'historical-exact-completion-anchors')
    expected = original.replace('                    entry.peer_committed = true;\n', '                    entry.peer_committed = true;\n' + EVENT, 1).replace(PERIODIC_OLD, PERIODIC_NEW, 1)
    ensure(Path(PRODUCT).read_bytes() == expected.encode(), 'only-exact-reviewed-product-repair')
    ensure(subprocess.check_output(['git', 'ls-tree', RED, PRODUCT]).split()[0]
           == subprocess.check_output(['git', 'ls-tree', 'HEAD', PRODUCT]).split()[0] == b'100644'
           and not Path(PRODUCT).is_symlink() and not (Path(PRODUCT).stat().st_mode & 0o111), 'product-source-mode-exact')
    # No tests, probe, original RED controller, Cargo, generated or SDK input may drift.
    ensure(Path('scripts/qualify_upstream_peer_proof.py').read_bytes() == subprocess.check_output(['git', 'show', RED + ':scripts/qualify_upstream_peer_proof.py']), 'historical-red-controller-exact')
    return {'source': source, 'historical_red_source': RED, 'historical_red_run_id': 39052541150,
            'only_product_edges_changed': ['authenticated_peer_proof_completion', 'fresh_periodic_completion'],
            'all_other_source_test_sdk_inputs_exact_red': True,
            'guard_negative_runtime_evidence': 'pending: cancelled/revoked/stale-parent/post-auth validation failure',
            'qualification_passed': False}


def previous_green(run_id, source, manifest, current):
    ensure(run_id.isdecimal(), 'exact-prior-green-run-required')
    repo = os.environ['GITHUB_REPOSITORY']
    def api(path): return subprocess.check_output(['gh', 'api', 'repos/' + repo + '/' + path], timeout=60)
    run = json.loads(api('actions/runs/' + run_id))
    ensure(run['repository']['full_name'] == repo and run['head_sha'] == source and run['status'] == 'completed'
           and run['conclusion'] == 'success' and run['event'] == 'workflow_dispatch' and run['path'] == WORKFLOW, 'prior-source-and-completed-workflow')
    artifacts = json.loads(api('actions/runs/' + run_id + '/artifacts?per_page=100'))['artifacts']
    receipts, control = [], None
    for name in ['peer-proof-candidate-green', 'peer-proof-candidate-static-default', 'peer-proof-candidate-static-experimental']:
        matches = [row for row in artifacts if row['name'] == name and not row['expired']]
        ensure(len(matches) == 1 and 0 < matches[0]['size_in_bytes'] < 1000000, 'one-bounded-prior-artifact')
        artifact = matches[0]
        data = api('actions/artifacts/' + str(artifact['id']) + '/zip')
        ensure(len(data) == artifact['size_in_bytes'] and len(data) < 1000000
               and artifact.get('digest') == 'sha256:' + digest(data), 'actual-prior-artifact-size-and-digest')
        with zipfile.ZipFile(io.BytesIO(data)) as archive:
            files = [entry for entry in archive.infolist() if Path(entry.filename).name == 'result.json']
            ensure(len(files) == 1 and 0 < files[0].file_size < 1000000, 'one-bounded-prior-result')
            report = json.loads(archive.read(files[0]))
        ensure(report['source'] == source and report.get('inputs_pristine') is True
               and report.get('input_manifest_sha256') == manifest
               and report.get('toolchain') == current.get('toolchain')
               and report.get('environment') == current.get('environment'), 'exact-prior-frozen-cohort')
        if name == 'peer-proof-candidate-green':
            ensure(report.get('mode') == 'green' and report.get('green_passed') is True
                   and green(report['phases']['baseline']['body']), 'actual-prior-one-body-green')
            compilation = report['phases']['baseline']['compilation']
            ensure(compilation['compile_exit_code'] == compilation['compiler_error_count'] == 0, 'prior-actual-compile-success')
            control = feature_identity(compilation)
        else:
            cohort = name.rsplit('-', 1)[-1]
            ensure(report.get('mode') == 'static' and report.get('cohort') == cohort
                   and report.get('static_passed') is True and report.get('exit_code') == 0
                   and report.get('compiler_error_count') == 0 and report.get('actual_runtime_bodies') == 0,
                   'actual-prior-both-static-cohorts')
        receipts.append({'name': name, 'id': artifact['id'], 'digest': artifact['digest'], 'download_digest_verified': True})
    return {'run_id': int(run_id), 'source': source, 'artifacts': receipts, 'compiled_feature_identity': control}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--mode', choices=['green', 'static', 'mutation'], default='green')
    parser.add_argument('--cohort', choices=['default', 'experimental'])
    parser.add_argument('--preflight', action='store_true')
    args = parser.parse_args()
    os.umask(0o077); OUT.mkdir(exist_ok=True)
    report = {'mode': args.mode, 'qualification_passed': False, 'green_passed': False, 'mutation_chain_passed': False, 'phases': {}}
    def save(): (OUT / 'result.json').write_text(json.dumps(report, indent=2) + '\n')
    original_bytes = Path(PRODUCT).read_bytes()
    frozen, frozen_layout = freeze(), layout()
    report['input_manifest_sha256'] = identity(frozen)
    def pristine(expected=frozen):
        return freeze() == expected and layout() == frozen_layout
    def phase(label, expected):
        ensure(pristine(expected), 'before-runtime-phase-inputs-exact')
        compilation, cases = compile_cases([historical.CASE])
        row = {'compilation': compilation}; report['phases'][label] = row; save()
        ensure(compilation.get('compile_exit_code') == compilation.get('compiler_error_count') == 0
               and compilation.get('compiled_fingerprints', {}).get('verified') is True
               and set(cases) == {historical.CASE} and cases[historical.CASE]['name'] == historical.TEST,
               'actual-exact-one-body-compiled-feature-cohort')
        features = feature_identity(compilation)
        if 'compiled_feature_identity' in report: ensure(features == report['compiled_feature_identity'], 'same-phase-feature-cohort')
        else: report['compiled_feature_identity'] = features
        ensure(pristine(expected), 'compile-input-drift')
        case = cases[historical.CASE]; started = time.monotonic()
        try:
            result = subprocess.run([case['binary'], '--exact', historical.TEST, '--nocapture', '--test-threads=1], capture_output=True, text=True, timeout=300)
            row['body'] = historical.parse(result.stdout + result.stderr, result.returncode)
        except subprocess.TimeoutExpired: row['body'] = {'watchdog_triggered': True, 'actual_count_unknown': True}
        row['body']['seconds'] = time.monotonic() - started
        ensure(pristine(expected), 'runtime-input-drift'); save()
        return row['body']
    try:
        report['source_preflight'] = source_guard(); report['source'] = report['source_preflight']['source']
        report['parser_controls'] = parser_preflight(); save()
        if args.preflight: return
        report.update(environment())
        if args.mode == 'static':
            ensure(args.cohort is not None, 'static-cohort-required')
            command = ['cargo', 'clippy', '--locked', '-p', 'marmot-app', '--all-targets', '--features', FEATURES if args.cohort == 'experimental' else DEFAULT_FEATURES, '--', '-D', 'warnings']
            started = time.monotonic(); result = subprocess.run(command, capture_output=True, text=True, timeout=1800)
            report.update(cohort=args.cohort, command=command, exit_code=result.returncode, seconds=time.monotonic()-started, actual_runtime_bodies=0, **headers(result.stderr))
            report['static_passed'] = result.returncode == 0 and report['compiler_error_count'] == 0 and pristine()
            ensure(report['static_passed'], 'actual-static-cohort-not-green'); return
        if args.mode == 'mutation':
            report['prior_green'] = previous_green(os.environ.get('PEER_PROOF_CONTROL_RUN_ID', ''), report['source'], report['input_manifest_sha256'], report)
        baseline = phase('baseline', frozen); report['green_passed'] = green(baseline); save()
        ensure(report['green_passed'], 'actual-directed-green-required')
        if args.mode == 'mutation':
            ensure(report['compiled_feature_identity'] == report['prior_green']['compiled_feature_identity'], 'same-prior-compiled-feature-cohort')
            text = original_bytes.decode(); ensure(text.count(EVENT) == 1, 'one-exact-event-edge-omission-anchor')
            mutated = text.replace(EVENT, '', 1).encode()
            mutation_error = None
            try:
                Path(PRODUCT).write_bytes(mutated)
                expected = freeze()
                ensure(layout() == frozen_layout and set(expected) == set(frozen)
                       and {name for name in frozen if expected[name] != frozen[name]} == {PRODUCT}, 'sole-exact-omission-source')
                report['expected_mutant_file_sha256'] = digest(mutated)
                mutant = phase('omission', expected)
                report['omission_runtime_killed'] = historical.intended_red(mutant); save()
            except Exception as error:
                mutation_error = type(error).__name__
                report['mutation_exception'] = mutation_error; save()
            finally:
                Path(PRODUCT).write_bytes(original_bytes)
                report['source_restored'] = pristine(); save()
            ensure(report['source_restored'], 'exact-omission-source-restoration')
            # This runs even when the mutant survives its intended assertion.
            restored = phase('restored', frozen)
            report['restored_control_passed'] = green(restored)
            report['mutation_chain_passed'] = bool(mutation_error is None and report.get('omission_runtime_killed') and report['restored_control_passed'])
            ensure(report['mutation_chain_passed'], 'actual-omission-and-restored-control-required')
    except Exception as error:
        report['controller_exception'] = type(error).__name__
        raise
    finally:
        Path(PRODUCT).write_bytes(original_bytes)
        report['inputs_pristine'] = pristine() and subprocess.run(['git', 'diff', '--quiet', 'HEAD']).returncode == 0
        save()


if __name__ == '__main__': main()
