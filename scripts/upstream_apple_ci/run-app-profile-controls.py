#!/usr/bin/env python3
"""REMOTE exact-count metadata envelope. No artifacts or Apple/product execution."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
import tempfile

from bounded_capture import capture


def require(value, message):
    if not value:
        raise ValueError(message)


def sha(data):
    return hashlib.sha256(data).hexdigest()


def git(directory, *args):
    return subprocess.check_output(['git', '-C', str(directory), *args], stderr=subprocess.PIPE)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--directory', type=Path, required=True)
    parser.add_argument('--source', required=True)
    parser.add_argument('--kind', choices=['app', 'installer'], required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    require(re.fullmatch('[0-9a-f]{40}', args.source), 'Immutable source required')
    require(not args.output.exists(), 'Fresh closed output required')
    directory = args.directory.resolve(strict=True)
    head = git(directory, 'rev-parse', 'HEAD').decode().strip()
    require(head == args.source, 'Executed source identity differs')
    root = Path(git(directory, 'rev-parse', '--show-toplevel').decode().strip())
    modules, count = (['test_local_sdk_profile'], 28) if args.kind == 'app' else (
        ['test_install_destinations', 'test_bounded_capture'], 8)
    names = ['sdk_profiles.py', 'validate_local_sdk_profile.py', 'local-device-sync-settings.sh',
             'local-sdk-profile-settings.sh', 'test_local_sdk_profile.py', 'qualify_local_sdk_guard_pfp.py',
             'bounded_capture.py'] \
            if args.kind == 'app' else ['sdk_profiles.py', 'install.py', 'test_install_destinations.py',
                                       'run-app-profile-controls.py', 'bounded_capture.py', 'test_bounded_capture.py']
    originals = {}
    modes = {}
    for name in names:
        path = directory / name
        require(not path.is_symlink(), 'Source symlink refused')
        original = git(root, 'show', head + ':' + path.relative_to(root).as_posix())
        require(original == path.read_bytes(), 'Executed helper differs from immutable source')
        originals[name] = original
        mode = git(root, 'ls-files', '--stage', '--', path.relative_to(root).as_posix()).decode().split()[0]
        require(mode in {'100644', '100755'} and bool(path.stat().st_mode & 0o111) == (mode == '100755'),
                'Executed source mode differs from Git')
        modes[name] = stat.S_IMODE(path.stat().st_mode)
    report = {'scope': 'SYNTHETIC METADATA ONLY; no SDK artifact/install or product qualification',
              'source_sha': head, 'source_tree': git(root, 'rev-parse', 'HEAD^{tree}').decode().strip(),
              'sdk_git_source': os.environ['PROFILE_CONTROL_SOURCE_SHA'], 'kind': args.kind,
              'python_version': sys.version.split()[0], 'complete': False}
    try:
        with tempfile.TemporaryDirectory(prefix='app-profile-control-') as temp:
            env = dict(os.environ, PYTHONPYCACHEPREFIX=str(Path(temp) / 'cache'))
            body = capture([sys.executable, '-B', '-m', 'unittest', '-v', *modules],
                                  cwd=directory, env=env, timeout=240)
            raw = body.stdout + body.stderr  # RAM only, never uploaded or emitted.
            summaries = re.findall(r'^Ran (\d+) tests? in [0-9.]+s$', raw, re.M)
            valid = summaries == [str(count)] and body.returncode == 0 and re.search(r'^OK$', raw, re.M)
            report['ordinary'] = {'expected': count, 'executed': count if summaries == [str(count)] else None,
                                  'passed': count if valid else None, 'failures': 0 if valid else None,
                                  'errors': 0 if valid else None, 'skips': 0 if valid else None,
                                  'exit_code': body.returncode}
            require(valid, 'Ordinary metadata controls did not execute the exact passing count')
            if args.kind == 'app':
                proof_path = Path(temp) / 'pfp.json'
                pfp = capture([sys.executable, '-B', 'qualify_local_sdk_guard_pfp.py',
                                      '--output', str(proof_path)], cwd=directory, env=env,
                                     timeout=1200)
                require(proof_path.is_file(), 'PFP aggregate missing')
                proof = json.loads(proof_path.read_text())
                report['pfp'] = proof
                require(pfp.returncode == 0 and proof['complete'] is True
                        and proof['source_restored'] is True and len(proof['chains']) == 3,
                        'PFP metadata qualification incomplete')
                for chain in proof['chains']:
                    require(len(chain['phases']) == 3, 'Three actual PFP phases required')
                    for index, phase in enumerate(chain['phases']):
                        require(type(phase['executed']) is int and type(phase['skipped']) is int
                                and type(phase['passed']) is int and type(phase['intended_failures']) is int
                                and phase['executed'] == 1 and phase['skipped'] == 0
                                and phase['errors_or_unknown'] is False
                                and phase['passed'] == (0 if index == 1 else 1)
                                and phase['intended_failures'] == (1 if index == 1 else 0),
                                'Exact metadata PFP phase counts required')
            report['complete'] = True
    finally:
        report['source_restored_by_envelope'] = False
        if args.kind == 'app':
            for name in ['sdk_profiles.py', 'validate_local_sdk_profile.py']:
                path = directory / name
                if path.read_bytes() != originals[name] or stat.S_IMODE(path.stat().st_mode) != modes[name]:
                    path.write_bytes(originals[name])
                    path.chmod(modes[name])
                    report['source_restored_by_envelope'] = True
        report['source_unchanged'] = all((directory / name).read_bytes() == data
                                        and stat.S_IMODE((directory / name).stat().st_mode) == modes[name]
                                        for name, data in originals.items())
        report['source_modes'] = modes
        report['source_sha256'] = {name: sha(data) for name, data in originals.items()}
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(report, indent=2) + '\n')
    require(report['complete'] and report['source_unchanged'] and not report['source_restored_by_envelope'], 'Incomplete or changed metadata source')


if __name__ == '__main__':
    main()
