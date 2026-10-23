"""Exact reviewed extraction cohort; historical evidence never qualifies this tree."""
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess

EXTRACTION_ORIGIN = 'f609d91d21e6ab8a2de17b405acf9884c11a135f'
UPSTREAM = '3aec65433eb84f0882430d000b2d31dabf987c24'
OWNER = '1168b00d1ad275eac925965d8ab505e7c05a452e'
REPOSITORY = 'dyKiU/mdk'
OVERLAYS = {
    '.github/workflows/upstream-avatar-ready-turn.yml',
    'scripts/upstream_avatar_ready_turn_chain.py',
    'scripts/upstream_explicit_ready_selection.py',
    'scripts/upstream_secondary_cutoff.py',
    '.github/workflows/upstream-backend-probes.yml',
    'scripts/upstream_current_backend_probe.py',
    'scripts/upstream_extraction_cohort.py',
    'scripts/qualify_upstream_private_fixes.py',
    'scripts/verify_upstream_boundary_mutations.py',
    'scripts/upstream_publication_mutation_anchors.py',
    'scripts/test_upstream_publication_mutation_anchors.py',
    'scripts/qualify_upstream_automatic_body.py',
    'scripts/upstream_completion_ci.py',
    'scripts/verify_upstream_body_negative_source.py',
    'scripts/qualify_upstream_body_negative.py',
    'scripts/upstream_body_negative_ci.py',
    'scripts/qualify_upstream_owner_pairing_mutations.py',
    'scripts/qualify_upstream_body_late_ack.py',
    'scripts/qualify_upstream_peer_proof_candidate.py',
    'scripts/test_upstream_extraction_cohort.py',
    'scripts/verify_upstream_completion_candidate_source.py',
    'scripts/qualify_upstream_completion.py',
    'scripts/verify_upstream_completion_green_run.py',
    '.github/workflows/upstream-private-fix-reconciliation.yml',
    '.github/workflows/upstream-boundary-regressions.yml',
    '.github/workflows/experimental-sync-ci.yml',
}


def git(*arguments):
    return subprocess.check_output(['git', *arguments], text=True).strip()


def frozen_inputs():
    result = {}
    for entry in subprocess.check_output(['git', 'ls-files', '--stage', '-z']).split(b'\0'):
        if not entry:
            continue
        metadata, name = entry.split(b'\t', 1)
        mode, _, stage = metadata.decode().split()
        if stage != '0':
            raise ValueError('Unmerged source cannot establish an extraction cohort')
        name = os.fsdecode(name)
        target = Path(name)
        kind = target.lstat().st_mode
        if mode not in {'100644', '100755', '120000'} or not (stat.S_ISREG(kind) or stat.S_ISLNK(kind)):
            raise ValueError('Unsupported tracked extraction input layout')
        if (mode == '120000') != target.is_symlink():
            raise ValueError('Tracked extraction input symlink mismatch')
        content = os.readlink(target).encode() if target.is_symlink() else target.read_bytes()
        result[name] = {'mode': mode, 'actual_executable': bool(kind & 0o111),
                        'sha256': hashlib.sha256(content).hexdigest()}
    return result


def prove_pr_identity(event, repository, source, workflow_sha, merge_parents,
                      head_tree, merge_tree, base_is_ancestor):
    """Validate only supplied Git/event facts; the caller reads actual objects."""
    if repository != REPOSITORY:
        raise ValueError('Qualification is restricted to the approved user fork')
    pr = event['pull_request']
    head, base = pr['head'], pr['base']
    values = [source, workflow_sha, head['sha'], base['sha'], head_tree, merge_tree]
    if not all(isinstance(value, str) and re.fullmatch('[0-9a-f]{40}', value) for value in values):
        raise ValueError('PR identity requires full immutable commit and tree identities')
    if head['repo']['full_name'] != repository or base['repo']['full_name'] != repository:
        raise ValueError('Both PR endpoints must belong to the same approved fork')
    if head['sha'] != source or base['ref'] != 'master' or base_is_ancestor is not True:
        raise ValueError('PR head checkout must contain its refreshed master baseline')
    if workflow_sha in {head['sha'], base['sha']}:
        raise ValueError('The workflow SHA must identify the actual synthetic merge')
    if merge_parents != [base['sha'], head['sha']] or head_tree != merge_tree:
        raise ValueError('Synthetic merge parents or effective source tree differ')
    return {'event': 'pull_request', 'repository': repository, 'checkout_head': source,
            'base': base['sha'], 'workflow_merge': workflow_sha,
            'merge_parents': merge_parents, 'head_tree': head_tree,
            'merge_tree': merge_tree, 'base_ancestor_of_head': True,
            'synthetic_merge_tree_identical_to_head': True}


def workflow_identity(source):
    if os.environ.get('GITHUB_ACTIONS') != 'true' or os.environ.get('GITHUB_REPOSITORY') != REPOSITORY:
        raise ValueError('Extraction qualification requires the approved remote Actions fork')
    workflow_sha = os.environ.get('GITHUB_SHA', '')
    if not re.fullmatch('[0-9a-f]{40}', workflow_sha):
        raise ValueError('Exact workflow commit SHA required')
    if os.environ.get('GITHUB_EVENT_NAME') != 'pull_request':
        if workflow_sha != source:
            raise ValueError('Actions workflow SHA must equal the actual checkout')
        return {'event': os.environ.get('GITHUB_EVENT_NAME'), 'repository': REPOSITORY,
                'checkout_head': source, 'workflow_sha': workflow_sha}
    event = json.loads(Path(os.environ['GITHUB_EVENT_PATH']).read_text())
    base = event['pull_request']['base']['sha']
    if not isinstance(base, str) or not re.fullmatch('[0-9a-f]{40}', base):
        raise ValueError('Exact PR master SHA required')
    # No fallback to a guessed merge: the workflow must fetch GITHUB_SHA first.
    if git('rev-parse', '--verify', workflow_sha + '^{commit}') != workflow_sha:
        raise ValueError('Workflow synthetic merge commit unavailable')
    parents = git('show', '-s', '--format=%P', workflow_sha).split()
    head_tree = git('rev-parse', source + '^{tree}')
    merge_tree = git('rev-parse', workflow_sha + '^{tree}')
    ancestor = subprocess.run(['git', 'merge-base', '--is-ancestor', base, source]).returncode == 0
    return prove_pr_identity(event, os.environ['GITHUB_REPOSITORY'], source, workflow_sha,
                             parents, head_tree, merge_tree, ancestor)


def reviewed_cohort(baseline):
    # The caller's reviewed workflow must pin this argument to a full commit.
    # It may advance only after separately reviewing a new composed cohort;
    # HEAD, branch names and implicit baseline discovery are never accepted.
    if not re.fullmatch('[0-9a-f]{40}', baseline):
        raise ValueError('Extraction baseline must be an explicit reviewed full commit SHA')
    source = git('rev-parse', 'HEAD')
    workflow = workflow_identity(source)
    if git('diff', 'HEAD', '--name-only'):
        raise ValueError('Extraction source must start pristine')
    for ancestor in (baseline, UPSTREAM, OWNER):
        subprocess.run(['git', 'merge-base', '--is-ancestor', ancestor, source], check=True)
    for ancestor in (EXTRACTION_ORIGIN, UPSTREAM, OWNER):
        subprocess.run(['git', 'merge-base', '--is-ancestor', ancestor, baseline], check=True)
    changed = set(git('diff', '--name-only', baseline, 'HEAD').splitlines())
    if not changed <= OVERLAYS:
        raise ValueError('Unreviewed product, generated source, test, Cargo or configuration drift')
    inputs = frozen_inputs()
    return {
        'source': source, 'baseline': baseline,
        'workflow_identity': workflow,
        'baseline_tree': git('rev-parse', baseline + '^{tree}'),
        'extraction_origin': EXTRACTION_ORIGIN, 'upstream': UPSTREAM, 'owner': OWNER,
        'overlay_paths': sorted(changed),
        'all_non_overlay_inputs_exact_baseline': True,
        'tracked_input_count': len(inputs),
        'input_manifest_sha256': hashlib.sha256(
            json.dumps(inputs, sort_keys=True, separators=(',', ':')).encode()).hexdigest(),
        'historical_results_reused': False,
        'qualification_passed': False,
    }


if __name__ == '__main__':
    import argparse
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--baseline', default=os.environ.get('UPSTREAM_EXTRACTION_COHORT_BASELINE'), required=False)
    args = parser.parse_args()
    if not args.baseline:
        raise SystemExit('An explicit reviewed extraction baseline is required')
    print(json.dumps(reviewed_cohort(args.baseline), indent=2))
