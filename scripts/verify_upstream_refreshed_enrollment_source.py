"""Temporary remote-only exact-source boundary for refreshed upstream controls."""
import ast
import hashlib
import json
import os
from pathlib import Path
import stat
import subprocess
from upstream_completion_ci import ensure

BASE = 'cb22134ea90cc6ec88fe556cab90717908e67858'
FIXTURE_BASE = 'a5b1d906134f566580c65a1372211ff751f92eef'
WORKFLOW = '.github/workflows/experimental-sync-ci.yml'
REVIEWED_WORKFLOW_BLOB = '4315a681c17aeb1101add08f6e2827c4bd9090c9'
HELPERS = {'scripts/verify_upstream_refreshed_enrollment_source.py', 'scripts/run_upstream_refreshed_enrollment.py'}
FIXTURES = ['crates/marmot-app/src/native_device_linking/tests/automatic_pairing_acceptance.rs', 'crates/marmot-app/src/relay_plane/mod.rs']

def raw_blob(path):
    p = Path(path)
    info = p.lstat()
    ensure(stat.S_ISLNK(info.st_mode) or stat.S_ISREG(info.st_mode), 'regular-file-or-symlink-required')
    data = os.fsencode(os.readlink(p)) if p.is_symlink() else p.read_bytes()
    mode = '120000' if p.is_symlink() else ('100755' if info.st_mode & 0o111 else '100644')
    return mode, hashlib.sha1(b'blob ' + str(len(data)).encode() + b'\0' + data).hexdigest()

def source_guard():
    ensure(subprocess.check_output(['git', 'rev-parse', '--show-object-format'], text=True).strip() == 'sha1', 'git-object-format')
    records = subprocess.check_output(['git', 'ls-tree', '-r', '-z', BASE]).split(b'\0')
    expected = {}
    for record in records:
        if not record: continue
        header, name = record.split(b'\t', 1)
        mode, kind, blob = header.decode().split()
        ensure(kind == 'blob', 'no-submodule-boundary')
        expected[os.fsdecode(name)] = (mode, blob)
    tracked = set(os.fsdecode(name) for name in subprocess.check_output(['git', 'ls-files', '-z']).split(b'\0') if name)
    ensure(tracked - set(expected) <= HELPERS and set(expected) <= tracked, 'tracked-source-inventory')
    for name, value in expected.items():
        ensure(raw_blob(name) == (('100644', REVIEWED_WORKFLOW_BLOB) if name == WORKFLOW else value), 'frozen-input-blob-or-mode')
    for name in HELPERS:
        ensure(Path(name).is_file() and not Path(name).is_symlink() and raw_blob(name)[0] == '100644', 'helper-mode')
        ast.parse(Path(name).read_text(), filename=name)
    for name in FIXTURES:
        old = subprocess.check_output(['git', 'rev-parse', FIXTURE_BASE + ':' + name], text=True).strip()
        ensure(raw_blob(name)[1] == old, 'original-five-fixture-or-gate-drift')
    return {'baseline': BASE, 'fixture_baseline': FIXTURE_BASE, 'source': subprocess.check_output(['git', 'rev-parse', 'HEAD'], text=True).strip(), 'all_original_tracked_inputs_and_modes_exact': True, 'original_five_fixtures_exact_a5': True, 'tracked_baseline_files': len(expected), 'reviewed_workflow_blob': REVIEWED_WORKFLOW_BLOB, 'helper_exceptions': sorted(HELPERS), 'actual_product_bodies': 0, 'qualification_passed': False}
