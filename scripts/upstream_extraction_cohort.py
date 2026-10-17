"""Exact reviewed extraction cohort; historical evidence never qualifies this tree."""
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess

EXTRACTION_ORIGIN = 'f609d91d21e6ab8a2de17b405acf9884c11a135f'
UPSTREAM = 'ee56871d7671978d0f060e9665af2ea4220806cf'
OWNER = '1168b00d1ad275eac925965d8ab505e7c05a452e'
OVERLAYS = {
    'scripts/upstream_extraction_cohort.py',
    'scripts/qualify_upstream_private_fixes.py',
    'scripts/verify_upstream_boundary_mutations.py',
    'scripts/qualify_upstream_automatic_body.py',
    'scripts/upstream_completion_ci.py',
    'scripts/verify_upstream_body_negative_source.py',
    'scripts/qualify_upstream_body_negative.py',
    'scripts/upstream_body_negative_ci.py',
    'scripts/qualify_upstream_owner_pairing_mutations.py',
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


def reviewed_cohort(baseline):
    # The caller's reviewed workflow must pin this argument to a full commit.
    # It may advance only after separately reviewing a new composed cohort;
    # HEAD, branch names and implicit baseline discovery are never accepted.
    if not re.fullmatch('[0-9a-f]{40}', baseline):
        raise ValueError('Extraction baseline must be an explicit reviewed full commit SHA')
    source = git('rev-parse', 'HEAD')
    if os.environ.get('GITHUB_ACTIONS') != 'true' or os.environ.get('GITHUB_SHA') != source:
        raise ValueError('Extraction qualification requires exact remote Actions source identity')
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
