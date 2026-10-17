#!/usr/bin/env python3
"""Fresh unchanged directed controls for an experimental owner scheduling quantum."""
import argparse
import hashlib
import os
from pathlib import Path
import subprocess
import qualify_upstream_late_consent_candidate as candidate
from qualify_upstream_body_negative import layout
from upstream_completion_ci import ensure

BASE = 'a302c2194c777bef87ae48aff51a8bc570cbc588'
SELF = 'scripts/qualify_upstream_worker_quantum.py'
WORKFLOW = '.github/workflows/experimental-sync-ci.yml'
WORKER = 'crates/marmot-app/src/runtime/account_worker.rs'
OUT = Path('worker-quantum-evidence')
BEGIN = '  # WORKER_QUANTUM_JOBS_BEGIN\n'
END = '  # WORKER_QUANTUM_JOBS_END\n'
OPTIONS = 'options: [worker-quantum-preflight, worker-quantum-green, '
YIELD = (b'        // OWNER_QUANTUM_YIELD_BEGIN\n'
         b'        // Cooperate between experimental owner-loop iterations even when biased\n'
         b'        // selection keeps choosing immediately-ready work; retain timer/debt state.\n'
         b'        #[cfg(feature = "experimental-device-sync")]\n'
         b'        tokio::task::yield_now().await;\n'
         b'        // OWNER_QUANTUM_YIELD_END\n')


def reconstruct_workflow(data):
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
    baseline = {}
    for entry in subprocess.check_output(['git', 'ls-tree', '-r', '-z', BASE]).split(b'\0'):
        if not entry: continue
        metadata, name = entry.split(b'\t', 1)
        mode, kind, blob = metadata.decode().split()
        ensure(kind == 'blob' and mode in {'100644', '100755', '120000'}, 'ordinary-reviewed-baseline-tree')
        baseline[os.fsdecode(name)] = (mode, blob)
    current = layout()
    ensure(SELF not in baseline and set(current) == set(baseline) | {SELF}, 'entire-tracked-inventory-exact')
    ensure(current[SELF] == {'git_mode': '100644', 'actual_executable': False, 'symlink': False, 'symlink_target': None}, 'ordinary-new-controller-mode')
    for name, (mode, blob) in baseline.items():
        metadata = current[name]
        ensure(metadata['git_mode'] == mode and (mode == '120000' or metadata['actual_executable'] == (mode == '100755'))
               and metadata['symlink'] == (mode == '120000'), 'whole-tracked-layout-exact:' + name)
        data = os.fsencode(os.readlink(name)) if mode == '120000' else Path(name).read_bytes()
        if name == WORKFLOW: data = reconstruct_workflow(data)
        if name == WORKER:
            ensure(data.count(YIELD) == data.count(b'OWNER_QUANTUM_YIELD_BEGIN') == data.count(b'OWNER_QUANTUM_YIELD_END') == 1, 'one-exact-experimental-owner-yield')
            ensure(data.count(b"    'worker: loop {\n" + YIELD) == 1, 'yield-at-actual-owner-loop-top-outside-select')
            data = data.replace(YIELD, b'', 1)
        actual = hashlib.sha1(b'blob ' + str(len(data)).encode() + b'\0' + data).hexdigest()
        ensure(actual == blob, 'all-source-exact-after-reviewed-yield-and-metadata:' + name)
    return {'source': source, 'baseline': BASE, 'reviewed_product_paths': [WORKER],
            'exact_single_loop_top_experimental_yield': True,
            'all_tests_oracles_deadlines_guards_timer_cadence_and_debt_unchanged': True,
            'all_existing_controllers_unchanged': True, 'historical_runtime_evidence_reused': False,
            'baseline_original_three_failures_recorded': True,
            'current_five_control_results_recorded_separately': True,
            'scheduling_experiment_not_proven_fix': True}


def main(options):
    # Reuse the unchanged directed runtime/parser and strict static implementation.
    # Only the reviewed full-tree source guard and durable output path differ.
    candidate.source_guard = source_guard
    candidate.OUT = OUT
    candidate.main(options)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--preflight', action='store_true')
    parser.add_argument('--mode', choices=['green', 'static'], default='green')
    parser.add_argument('--cohort', choices=['default', 'experimental'])
    main(parser.parse_args())
