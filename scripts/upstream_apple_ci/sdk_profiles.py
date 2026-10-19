"""Closed nonpublishing Apple feature profiles and immutable build provenance."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess

PROFILES = {
    'default': ['otlp-export', 'product-analytics-export'],
    'experimental': ['otlp-export', 'product-analytics-export', 'experimental-device-sync'],
}
PARTS = {'swift', 'macos', 'ios-device', 'ios-simulator'}


def features(profile):
    if profile not in PROFILES:
        raise ValueError('Unknown closed SDK profile')
    return list(PROFILES[profile])


def release_id(profile, source):
    features(profile)
    if not re.fullmatch('[0-9a-f]{40}', source):
        raise ValueError('Immutable SDK source required')
    return ('ci-default-' if profile == 'default' else 'ci-') + source


def artifact_name(profile, source):
    release_id(profile, source)
    return 'upstream-' + ('default' if profile == 'default' else 'experimental') + '-apple-' + source


def environment_profile():
    profile = os.environ.get('SDK_PROFILE', 'experimental')
    expected = features(profile)
    actual = [name for variable, name in (
        ('OTLP_EXPORT', 'otlp-export'), ('PRODUCT_ANALYTICS_EXPORT', 'product-analytics-export'),
        ('EXPERIMENTAL_DEVICE_SYNC', 'experimental-device-sync'))
        if os.environ.get(variable, '0') in {'1', 'true'}]
    if actual != expected:
        raise ValueError('SDK profile and selected build features differ')
    if os.environ.get('EXPERIMENTAL_DEVICE_SYNC', '0') not in {'0', 'false', '1', 'true'}:
        raise ValueError('Invalid experimental flag')
    return profile


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def git_value(*arguments):
    return subprocess.check_output(['git', *arguments], text=True, stderr=subprocess.PIPE).strip()


def trusted_source_identity(source):
    # Consumers must provide the immutable F object, either in this MDK tools
    # checkout or a separately checked-out F. Never trust a lock/tree merely
    # because several untrusted JSON records repeat it.
    configured = os.environ.get('SDK_SOURCE_REPOSITORY')
    repository = Path(configured) if configured else Path(__file__).resolve().parents[2]
    commit = git_value('-C', str(repository), 'rev-parse', source + '^{commit}')
    if commit != source:
        raise ValueError('Trusted Git object differs from requested F')
    tree = git_value('-C', str(repository), 'rev-parse', source + '^{tree}')
    lock = subprocess.check_output(['git', '-C', str(repository), 'show', source + ':Cargo.lock'],
                                   stderr=subprocess.PIPE)
    profile = subprocess.check_output(['git', '-C', str(repository), 'show',
                                      source + ':crates/marmot-uniffi/marmotkit-release-profile.env'],
                                     stderr=subprocess.PIPE)
    return tree, hashlib.sha256(lock).hexdigest(), hashlib.sha256(profile).hexdigest()


def record_part(path):
    profile = environment_profile()
    source = os.environ['SOURCE_SHA']
    record = json.loads(path.read_text())
    if not (record['source_sha'] == record['builder_sha'] == git_value('rev-parse', 'HEAD') == source):
        raise ValueError('Input source/builder mismatch')
    record.update(sdk_profile=profile, source_tree=git_value('rev-parse', 'HEAD^{tree}'),
                  cargo_lock_sha256=sha('Cargo.lock'))
    path.write_text(json.dumps(record, indent=2) + '\n')


def validate_provenance(proof, profile, source, run_id):
    expected = features(profile)
    if not isinstance(source, str) or not re.fullmatch('[0-9a-f]{40}', source):
        raise ValueError('Full source identity required')
    if not isinstance(run_id, str) or not re.fullmatch('[1-9][0-9]*', run_id):
        raise ValueError('String producer run identity required')
    if proof['source_sha'] != proof['builder_sha'] or proof['source_sha'] != source:
        raise ValueError('SDK source/builder mismatch')
    if proof['workflow_run_id'] != run_id or proof['features'] != expected:
        raise ValueError('SDK producer run/features mismatch')
    # Historical experimental packages retain their existing validation route;
    # they cannot be selected as a default-profile package.
    if 'sdk_profile' not in proof:
        if profile != 'experimental':
            raise ValueError('Default package requires explicit profile provenance')
        return
    if proof['sdk_profile'] != profile:
        raise ValueError('SDK profile mismatch')
    if type(proof['schema_version']) is not int or proof['schema_version'] != 2:
        raise ValueError('Profile-aware provenance schema required')
    if not re.fullmatch('[0-9a-f]{40}', proof['source_tree']):
        raise ValueError('Invalid source tree identity')
    if not re.fullmatch('[0-9a-f]{64}', proof['release_profile_sha256']):
        raise ValueError('Invalid release profile identity')
    if set(proof['compiler']) != {'rustc', 'cargo'} or set(proof['platforms']) != {'macos', 'ios'}:
        raise ValueError('Exact compiler and Apple platform inventory required')
    trusted_tree, trusted_lock, trusted_profile = trusted_source_identity(source)
    if (proof['source_tree'] != trusted_tree or proof['cargo_lock_sha256'] != trusted_lock
            or proof['release_profile_sha256'] != trusted_profile):
        raise ValueError('Provenance differs from immutable Git F')
    lock = proof['cargo_lock_sha256']
    if not re.fullmatch('[0-9a-f]{64}', lock):
        raise ValueError('Invalid lockfile identity')
    records = proof['input_provenance']
    if set(records) != PARTS:
        raise ValueError('Exactly four Apple inputs required')
    expected_set = {'otlp_export': True, 'product_analytics_export': True,
                    'experimental_device_sync': profile == 'experimental'}
    for part, record in records.items():
        if (set(record['feature_set']) != set(expected_set)
                or any(type(value) is not bool for value in record['feature_set'].values())):
            raise ValueError('Input feature set must contain strict booleans')
        if (record['part'] != part or record['source_sha'] != source or record['builder_sha'] != source
                or record['workflow_run_id'] != run_id or record['sdk_profile'] != profile
                or record['source_tree'] != proof['source_tree'] or record['cargo_lock_sha256'] != lock
                or record['feature_set'] != expected_set
                or record['release_profile_sha256'] != proof['release_profile_sha256']
                or record['rustc'] != proof['compiler']['rustc'] or record['cargo'] != proof['compiler']['cargo']):
            raise ValueError('Apple input provenance differs')
    for compiler in proof['compiler'].values():
        if not isinstance(compiler, str) or not compiler or any(c in compiler for c in '\n\r\0'):
            raise ValueError('Invalid observed compiler identity')
    for record in proof['platforms'].values():
        manifest = record['manifest']
        if manifest['cargo_lock_sha256'] != lock or manifest['features'] != expected:
            raise ValueError('Packaged lock/features differ')
        if manifest['rustc'] != proof['compiler']['rustc'] or manifest['cargo'] != proof['compiler']['cargo']:
            raise ValueError('Packaged compiler differs')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('operation', choices=['record-part', 'release-id'])
    parser.add_argument('value')
    args = parser.parse_args()
    if args.operation == 'record-part':
        record_part(Path(args.value))
    else:
        print(release_id(environment_profile(), args.value))
