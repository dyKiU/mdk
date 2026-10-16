"""Temporary, no-compile source boundary for the two-case diagnostic."""
import hashlib
import json
from pathlib import Path
import subprocess

BASE = 'ac3db2d82bdca105d249b7ddfba73734b4e153e9'
CAPSULE = 'bb69a8ae326844ab8851beb39e4c43b576fb9976'
RELAY = 'crates/cgka-conformance-simulator/src/relay_control.rs'
HELPERS = {
    'scripts/verify_upstream_orchestrator_diagnostic_source.py',
    'scripts/run_upstream_orchestrator_diagnostic.py',
    '.github/workflows/experimental-sync-ci.yml',
}


def verify():
    tracked = subprocess.check_output(['git', 'ls-files'], text=True).splitlines()
    old = subprocess.check_output(['git', 'ls-tree', '-r', '--name-only', BASE], text=True).splitlines()
    expected = set(old) | HELPERS
    if set(tracked) != expected:
        raise ValueError('tracked-source-inventory')
    hashes = {}
    for name in tracked:
        path = Path(name)
        raw = path.read_bytes() if not path.is_symlink() else str(path.readlink()).encode()
        hashes[name] = hashlib.sha256(raw).hexdigest()
        if name == '.github/workflows/experimental-sync-ci.yml':
            text = raw.decode()
            marker = '\n\n  # ORCHESTRATOR_DIAGNOSTIC_JOBS_BEGIN\n'
            if text.count(marker) != 1:
                raise ValueError('workflow-appended-jobs-boundary')
            prefix = text.split(marker)[0] + '\n'
            addition = 'orchestrator-diagnostic-preflight, orchestrator-diagnostic, '
            if prefix.count(addition) != 1:
                raise ValueError('workflow-scope-boundary')
            restored = prefix.replace(addition, '', 1).encode()
            original = subprocess.check_output(['git', 'show', BASE + ':' + name])
            if restored != original:
                raise ValueError('existing-workflow-byte-mismatch')
            continue
        if name in HELPERS:
            continue
        reference = CAPSULE if name == RELAY else BASE
        original = subprocess.check_output(['git', 'show', reference + ':' + name])
        if raw != original:
            raise ValueError('frozen-source-mismatch:' + name)
    return {'baseline': BASE, 'capsule_source': CAPSULE, 'all_other_tracked_inputs_byte_identical': True,
            'tracked_sha256': hashes, 'qualification_passed': False}


if __name__ == '__main__':
    result = verify()
    Path('orchestrator-diagnostic').mkdir(exist_ok=True)
    Path('orchestrator-diagnostic/source.json').write_text(json.dumps(result, indent=2) + '\n')
    print('orchestrator diagnostic source boundary passed; zero runtime bodies')
