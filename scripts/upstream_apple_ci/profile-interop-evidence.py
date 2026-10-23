#!/usr/bin/env python3
"""Closed default F/experimental F evidence for the unchanged real public fixture."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess

from sdk_profiles import features, validate_provenance

FLAGS = ('invitation', 'bidirectional_authenticated_messages', 'receiver_restart',
         'offline_message', 'offline_invitation')


def require(condition, category):
    if not condition:
        raise ValueError(category)


def digest(path):
    value = hashlib.sha256()
    with path.open('rb') as stream:
        while True:
            chunk = stream.read(65536)
            if not chunk:
                break
            value.update(chunk)
    return value.hexdigest()


def pair_gate(default, experimental, source, default_run, experimental_run):
    require(isinstance(source, str) and re.fullmatch('[0-9a-f]{40}', source)
            and isinstance(default_run, str) and re.fullmatch('[1-9][0-9]*', default_run)
            and isinstance(experimental_run, str) and re.fullmatch('[1-9][0-9]*', experimental_run)
            and default_run != experimental_run, 'Explicit same-F distinct-profile producer identities required')
    for profile, value, run in [('default', default, default_run),
                                ('experimental', experimental, experimental_run)]:
        require(isinstance(value, dict) and value.get('sdk_profile') == profile
                and value.get('source_sha') == value.get('builder_sha') == source
                and value.get('workflow_run_id') == run and value.get('features') == features(profile),
                'Exact same-F default and experimental profiles required')
    for value in [default, experimental]:
        require(isinstance(value.get('source_tree'), str) and re.fullmatch('[0-9a-f]{40}', value['source_tree'])
                and all(isinstance(value.get(key), str) and re.fullmatch('[0-9a-f]{64}', value[key])
                        for key in ['cargo_lock_sha256', 'release_profile_sha256'])
                and isinstance(value.get('compiler'), dict) and set(value['compiler']) == {'rustc', 'cargo'}
                and all(isinstance(version, str) and 0 < len(version) <= 512
                        for version in value['compiler'].values()), 'Complete cross-profile provenance required')
    require(all(default[key] == experimental[key] for key in
                ['source_tree', 'cargo_lock_sha256', 'release_profile_sha256', 'compiler']),
            'Cross-profile immutable source or compiler identity differs')


def input_snapshot():
    source, default_run, experimental_run = (os.environ['SOURCE_SHA'], os.environ['DEFAULT_SDK_RUN_ID'],
                                             os.environ['SDK_RUN_ID'])
    temporary = Path(os.environ['RUNNER_TEMP'])
    proofs, closed = {}, {}
    for profile, packages, sdk, run in [
            ('default', Path('packages-default'), temporary / 'interop-default-sdk', default_run),
            ('experimental', Path('packages'), temporary / 'interop-experimental-sdk', experimental_run)]:
        path = packages / 'qualification.json'
        value = json.loads(path.read_text())
        # This performs actual trusted Git F tree/lock/profile validation; it
        # neither manufactures nor qualifies an artifact from synthetic metadata.
        validate_provenance(value, profile, source, run)
        require(value.get('sdk_profile') == profile, 'New default/experimental pair requires explicit modern profiles')
        record = value['platforms']['ios']
        require(sdk.is_dir() and not sdk.is_symlink() and sdk.resolve(strict=True) == sdk,
                'Physical extracted SDK root required')
        require(not any(path.is_symlink() for path in sdk.rglob('*')), 'Extracted SDK symlink refused')
        manifest_path = sdk / 'manifest.json'
        require(json.loads(manifest_path.read_text()) == record['manifest'], 'Extracted SDK manifest differs')
        actual = {str(path.relative_to(sdk)): digest(path) for path in sorted(sdk.rglob('*'))
                  if path.is_file() and path.name != 'manifest.json'}
        require(actual == record['files'], 'Prepared native Swift header privacy inputs changed')
        proofs[profile] = value
        closed[profile] = dict(source_sha=source, builder_sha=value['builder_sha'], sdk_profile=profile,
                               workflow_run_id=run, features=value['features'], source_tree=value['source_tree'],
                               cargo_lock_sha256=value['cargo_lock_sha256'],
                               release_profile_sha256=value['release_profile_sha256'], compiler=value['compiler'],
                               qualification_sha256=digest(path), bundle_sha256=record['sha256'],
                               manifest_sha256=digest(manifest_path), expanded_files=actual)
    pair_gate(proofs['default'], proofs['experimental'], source, default_run, experimental_run)
    source_inputs = {}
    for repository, commit, names in [
            (Path('ios'), os.environ['IOS_SHA'], ['scripts/public-chat-acceptance/controller.py',
                                                'scripts/public-chat-acceptance/build.sh',
                                                'scripts/public-chat-acceptance/Worker.swift']),
            (Path('.'), os.environ['GITHUB_SHA'], ['scripts/upstream_apple_ci/observed-public-interop.py',
                                                 'scripts/upstream_apple_ci/published-interop.sh',
                                                 'scripts/upstream_apple_ci/profile-interop-evidence.py'])]:
        require(subprocess.check_output(['git', '-C', str(repository), 'rev-parse', 'HEAD'],
                                        text=True).strip() == commit, 'Exact immutable fixture/tool source required')
        for relative in names:
            original = subprocess.check_output(['git', '-C', str(repository), 'show', commit + ':' + relative])
            original_hash = hashlib.sha256(original).hexdigest()
            require(digest(repository / relative) == original_hash, 'Fixture/controller/tool source changed')
            source_inputs[str(repository / relative)] = original_hash
    return dict(profiles=closed, source_inputs=source_inputs, ios_sha=os.environ['IOS_SHA'],
                workflow_tools_sha=os.environ['GITHUB_SHA'], historical_peer_replaced=False)


def observation_gate(value, peer_worker, experimental_worker, controller_hash, observer_hash):
    require(isinstance(value, dict), 'Actual controller receipt required')
    require(all(isinstance(value, str) and re.fullmatch('[0-9a-f]{64}', value) for value in
                [peer_worker, experimental_worker, controller_hash, observer_hash]),
            'Complete worker/controller/observer digests required')
    checks = value.get('checks')
    require(isinstance(checks, list) and len(checks) == 2 and all(isinstance(row, dict) for row in checks),
            'Exactly two actual sponsor directions required')
    require([row.get('sponsor') for row in checks] == ['published', 'experimental']
            and all(all(row.get(flag) is True for flag in FLAGS) for row in checks),
            'Original invitation bidirectional reopen and offline assertions required')
    for key, expected in [('passed', 2), ('failed', 0), ('workers_created', 8), ('workers_closed', 8)]:
        require(type(value.get(key)) is int and value[key] == expected, 'Exact actual fixture and worker counts required')
    exits = value.get('owned_relay_exit_codes')
    require(isinstance(exits, list) and len(exits) == 1 and type(exits[0]) is int and exits[0] == 0,
            'Owned relay must positively exit without forced kill')
    require(value.get('published_sha256') == peer_worker
            and value.get('experimental_sha256') == experimental_worker
            and value.get('controller_sha256') == controller_hash
            and value.get('observer_sha256') == observer_hash,
            'Actual worker/controller/observer hashes differ')
    # Original fixed argument/state label "published" is slot0 inside the frozen
    # fixture ONLY. Export honest profile names; never claim this is0.13 evidence.
    return [dict(sponsor='default' if row['sponsor'] == 'published' else 'experimental',
                 **{key: True for key in FLAGS}) for row in checks]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('stage', choices=['prepare', 'finalize'])
    args = parser.parse_args()
    evidence = Path(os.environ['RUNNER_TEMP']) / 'interop-evidence'
    provenance = evidence / 'profile-provenance.json'
    if args.stage == 'prepare':
        require(not provenance.exists(), 'Fresh cross-profile provenance required')
        provenance.write_text(json.dumps(input_snapshot(), indent=2) + '\n')
        return
    baseline = json.loads(provenance.read_text())
    result = dict(gate='ios-independent-account-default-F-experimental-F', peer_profile='default',
                  experimental_profile='experimental', passed_profile_interop=False, actual_sponsor_directions=None,
                  sdk_source=os.environ['SOURCE_SHA'], default_sdk_run_id=os.environ['DEFAULT_SDK_RUN_ID'],
                  experimental_sdk_run_id=os.environ['SDK_RUN_ID'], ios_sha=os.environ['IOS_SHA'],
                  workflow_tools_sha=os.environ['GITHUB_SHA'], historical_013_qualification=False,
                  scope='Real two-profile iOS simulator public-account protocol; no private sync, UI/APNS, shipping adoption or historical0.13 credit')
    try:
        private = Path(os.environ['RUNNER_TEMP']) / 'published-interop-private' / 'result.json'
        raw = json.loads(private.read_text())
        # Preserve numeric partial evidence before validation, never raw messages,
        # account data, payloads, simulator IDs or process output.
        result['actual_counts'] = {key: raw.get(key) if type(raw.get(key)) is int else None
                                  for key in ['passed', 'failed', 'workers_created', 'workers_closed']}
        result['owned_relay_exit_codes'] = raw.get('owned_relay_exit_codes') if (
            isinstance(raw.get('owned_relay_exit_codes'), list)
            and len(raw['owned_relay_exit_codes']) == 1
            and type(raw['owned_relay_exit_codes'][0]) is int) else None
        require(input_snapshot() == baseline, 'Cross-profile SDK or fixture inputs changed after preparation')
        result['inputs_unchanged'] = True
        peer_worker = digest(Path(os.environ['RUNNER_TEMP']) / 'published-worker')
        experimental_worker = digest(Path(os.environ['RUNNER_TEMP']) / 'experimental-worker')
        result['default_worker_sha256'] = peer_worker
        result['experimental_worker_sha256'] = experimental_worker
        checks = observation_gate(raw, peer_worker, experimental_worker,
                                 baseline['source_inputs']['ios/scripts/public-chat-acceptance/controller.py'],
                                 baseline['source_inputs']['scripts/upstream_apple_ci/observed-public-interop.py'])
        result['actual_sponsor_directions'] = checks
        result['passed_profile_interop'] = True
    finally:
        (evidence / 'result.json').write_text(json.dumps(result, indent=2) + '\n')
    require(result['passed_profile_interop'], 'Cross-profile independent-account interoperability remains pending')


if __name__ == '__main__':
    main()
