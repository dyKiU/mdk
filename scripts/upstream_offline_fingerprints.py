"""Optional read-only Cargo fingerprint evidence; unknown never changes a body verdict."""
import hashlib
import json
import os
from pathlib import Path
import re
import stat

NODES = {'relay_runtime', 'marmot_app', 'cgka_engine', 'cgka_session', 'marmot_account',
         'transport_nostr', 'transport_nostr_adapter', 'storage_sqlite', 'openmls'}
FEATURES = {'marmot_app': ['default', 'experimental-device-sync', 'media-benchmarks', 'otlp-export', 'product-analytics-export', 'test-policy-overrides'], 'cgka_engine': ['default', 'experimental-device-sync', 'test-conformance-snapshot', 'test-crash-hooks', 'test-policy-overrides'], 'cgka_session': ['default', 'experimental-device-sync', 'test-policy-overrides'], 'marmot_account': ['default', 'experimental-device-sync'], 'transport_nostr': ['default', 'experimental-device-sync', 'test-policy-overrides', 'test-support'], 'transport_nostr_adapter': ['default', 'experimental-device-sync', 'sdk', 'test-policy-overrides'], 'storage_sqlite': ['default', 'experimental-device-sync', 'extensions-draft', 'media-store-benchmarks', 'storage-format-benchmarks', 'test-conformance-replay', 'test-migrated-template', 'test-support'], 'openmls': ['0-8-1-storage-format', 'all-ciphersuites', 'backtrace', 'content-debug', 'crypto-debug', 'default', 'draft-ietf-mls-pq-ciphersuites', 'experimental-retained-own-commit', 'extensions-draft', 'extensions-draft-test-dependencies', 'fork-resolution', 'generate-kats', 'js', 'js-test', 'libcrux-provider', 'sqlite-provider', 'targeted-messages-draft', 'test-utils', 'unchecked-conversions', 'virtual-clients-draft', 'virtual-clients-draft-test-dependencies'], 'relay_runtime': ['default', 'experimental-device-sync', 'media-benchmarks', 'otlp-export', 'product-analytics-export', 'test-policy-overrides']}


class Unknown(Exception):
    pass


def unique(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise Unknown('schema')
        result[key] = value
    return result


def opened(path, directory=False):
    # Walk from / using directory FDs: neither parent nor leaf symlinks are followed.
    parts = Path(os.path.abspath(path)).parts
    fd = os.open('/', os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        for index, part in enumerate(parts[1:]):
            flags = os.O_RDONLY | os.O_NOFOLLOW
            if index < len(parts) - 2 or directory:
                flags |= os.O_DIRECTORY
            child = os.open(part, flags, dir_fd=fd)
            os.close(fd)
            fd = child
        return fd
    except BaseException:
        os.close(fd)
        raise


def read(path, maximum, digest_only=False):
    fd = opened(path)
    try:
        before = os.fstat(fd)
        if not stat.S_ISREG(before.st_mode) or before.st_size > maximum:
            raise Unknown('bounds')
        total, chunks, digest = 0, [], hashlib.sha256()
        while True:
            block = os.read(fd, min(65536, maximum + 1 - total))
            if not block:
                break
            total += len(block)
            if total > maximum:
                raise Unknown('bounds')
            digest.update(block)
            if not digest_only:
                chunks.append(block)
        after = os.fstat(fd)
        identity = lambda value: (value.st_dev, value.st_ino, value.st_size, value.st_mtime_ns, value.st_ctime_ns)
        if identity(before) != identity(after) or total != before.st_size:
            raise Unknown('changed')
        return digest.hexdigest() if digest_only else b''.join(chunks)
    finally:
        os.close(fd)


def names(path):
    fd = opened(path, True)
    try:
        values = os.listdir(fd)
        if len(values) > 4096:
            raise Unknown('bounds')
        return sorted(values)
    finally:
        os.close(fd)


def uint(value):
    return type(value) is int and 0 <= value < 2**64


def decode(raw, label):
    value = json.loads(raw, object_pairs_hook=unique)
    features = value.get('features')
    if isinstance(features, str):
        features = json.loads(features, object_pairs_hook=unique)
    if (not isinstance(features, list) or len(features) > 64
            or any(not isinstance(item, str) or item not in FEATURES[label] for item in features)
            or len(features) != len(set(features))):
        raise Unknown('features')
    deps = value.get('deps')
    if not isinstance(deps, list) or len(deps) > 256:
        raise Unknown('schema')
    edges = []
    for item in deps:
        if not isinstance(item, list) or len(item) != 4:
            raise Unknown('schema')
        if item[1] in NODES:
            if not uint(item[3]):
                raise Unknown('schema')
            edges.append((item[1], item[3]))
    row = {'features': sorted(features), 'fingerprint_json_sha256': hashlib.sha256(raw).hexdigest()}
    for key in ['profile', 'target', 'rustc', 'compile_kind']:
        if not uint(value.get(key)):
            raise Unknown('schema')
        row[key + '_opaque_u64'] = value[key]
    flags = value.get('rustflags')
    if not isinstance(flags, list) or len(flags) > 64 or any(not isinstance(v, str) or len(v) > 4096 for v in flags):
        raise Unknown('schema')
    row.update(rustflags_empty=flags == [], rustflags_sha256=hashlib.sha256(json.dumps(flags).encode()).hexdigest())
    return row, edges


def snapshot(inventory, expected_test, target):
    result = {'schema': 'offline-compiled-fingerprints-v1', 'attribution': 'unknown',
              'root_binary_sha256': None, 'nodes': {}, 'edges': [], 'unknown_reason': None,
              'opaque_profile_is_not_optimization_flags': True}
    try:
        suites = [suite for suite in inventory['rust-suites'].values()
                  if expected_test in suite['testcases']
                  and suite['testcases'][expected_test].get('filter-match', {}).get('status') == 'matches']
        if len(suites) != 1 or suites[0]['testcases'][expected_test].get('ignored') is not False:
            raise Unknown('inventory')
        binary = Path(os.path.abspath(suites[0]['binary-path']))
        target = Path(os.path.abspath(target))
        if target not in binary.parents or binary.parent.name != 'deps':
            raise Unknown('inventory')
        match = re.fullmatch(r'relay_runtime-([0-9a-f]{16})', binary.name)
        if match is None:
            raise Unknown('inventory')
        directory = binary.parent.parent / '.fingerprint'
        result['root_binary_sha256'] = read(binary, 2**31, True)
        entries = names(directory)
        root = directory / ('marmot-app-' + match[1]) / 'test-integration-test-relay_runtime.json'
        expected, seen, observed = {}, set(), {}
        def visit(path, label, companion=None):
            if label in seen or len(result['nodes']) >= len(NODES):
                raise Unknown('units')
            seen.add(label)
            metadata_raw = read(path, 65536)
            observed[path] = metadata_raw
            row, dependencies = decode(metadata_raw, label)
            if companion is not None:
                if read(path.with_suffix(''), 32) != companion:
                    raise Unknown('changed')
                observed[path.with_suffix('')] = companion
                row.update(expected_dependency_fingerprint_u64=expected[label],
                           companion_sha256=hashlib.sha256(companion).hexdigest())
            result['nodes'][label] = row
            for dep, fingerprint in dependencies:
                if dep == label or dep == 'relay_runtime':
                    raise Unknown('units')
                result['edges'].append({'from': label, 'to': dep, 'expected_fingerprint_u64': fingerprint})
                if dep in expected and expected[dep] != fingerprint:
                    raise Unknown('units')
                expected[dep] = fingerprint
                if dep in result['nodes']:
                    continue
                matches, candidates = [], 0
                pattern = re.compile(re.escape(dep.replace('_', '-')) + r'-[0-9a-f]{16}')
                for entry in entries:
                    if pattern.fullmatch(entry) is None:
                        continue
                    candidates += 1
                    if candidates > 256:
                        raise Unknown('bounds')
                    candidate = directory / entry / ('lib-' + dep + '.json')
                    try:
                        companion_raw = read(candidate.with_suffix(''), 32)
                    except FileNotFoundError:
                        continue
                    if re.fullmatch(rb'[0-9a-fA-F]{16}\s*', companion_raw) is None:
                        continue
                    raw = bytes.fromhex(companion_raw.decode().strip())
                    if fingerprint in (int.from_bytes(raw, 'little'), int.from_bytes(raw, 'big')):
                        matches.append((candidate, companion_raw))
                if len(matches) != 1:
                    raise Unknown('dependency')
                visit(matches[0][0], dep, matches[0][1])
        visit(root, 'relay_runtime')
        if set(result['nodes']) != NODES:
            raise Unknown('dependency')
        if any(read(path, 65536) != raw for path, raw in observed.items()):
            raise Unknown('changed')
        result['attribution'] = 'cargo-metadata-linked'
    except Unknown as error:
        result['unknown_reason'] = error.args[0]
    except (OSError, ValueError, KeyError, TypeError, UnicodeError, RecursionError):
        result['unknown_reason'] = 'unavailable-or-schema'
    except Exception:
        result['unknown_reason'] = 'internal'
    return result


def controls():
    # Remote preflight only; no Cargo/rustc or product body is invoked.
    base = {'features': [], 'deps': [], 'profile': 1, 'target': 2, 'rustc': 3,
            'compile_kind': 0, 'rustflags': []}
    assert decode(json.dumps(base).encode(), 'openmls')[0]['profile_opaque_u64'] == 1
    negatives = [dict(base, profile=True), dict(base, rustc=-1), dict(base, compile_kind=None),
                 dict(base, features=['PRIVATE']), dict(base, features=['default', 'default']),
                 dict(base, deps=[['PRIVATE']]), dict(base, rustflags=[False])]
    for value in negatives:
        try:
            decode(json.dumps(value).encode(), 'openmls')
        except Unknown:
            pass
        else:
            raise AssertionError('fingerprint-negative')
    try:
        decode(b'{"features":[],"features":[],"deps":[]}', 'openmls')
    except Unknown:
        pass
    else:
        raise AssertionError('fingerprint-duplicate')
    assert snapshot({'rust-suites': {}}, 'fixed', '/no-read') == {
        'schema': 'offline-compiled-fingerprints-v1', 'attribution': 'unknown',
        'root_binary_sha256': None, 'nodes': {}, 'edges': [], 'unknown_reason': 'inventory',
        'opaque_profile_is_not_optimization_flags': True}
    import tempfile
    with tempfile.TemporaryDirectory(prefix='offline-fingerprint-controls-') as temporary:
        target = Path(temporary) / 'target'
        binary = target / 'debug/deps/relay_runtime-0000000000000000'
        binary.parent.mkdir(parents=True)
        binary.write_bytes(b'synthetic-not-an-executable')
        directory = binary.parent.parent / '.fingerprint'
        root = directory / 'marmot-app-0000000000000000/test-integration-test-relay_runtime.json'
        order = ['relay_runtime', 'marmot_app', 'cgka_engine', 'cgka_session', 'marmot_account',
                 'transport_nostr', 'transport_nostr_adapter', 'storage_sqlite', 'openmls']
        fixtures = {}
        for index, label in enumerate(order):
            path = root if index == 0 else directory / (label.replace('_', '-') + '-0000000000000001') / ('lib-' + label + '.json')
            path.parent.mkdir(parents=True, exist_ok=True)
            value = dict(base, deps=[] if index + 1 == len(order) else [[0, order[index + 1], False, 1]])
            path.write_text(json.dumps(value))
            if index:
                path.with_suffix('').write_text('0100000000000000')
            fixtures[label] = path
        inventory = {'rust-suites': {'fixed': {'binary-path': str(binary), 'testcases': {
            'fixed': {'ignored': False, 'filter-match': {'status': 'matches'}}}}}}
        def sample():
            return snapshot(inventory, 'fixed', target)
        assert sample()['attribution'] == 'cargo-metadata-linked'
        saved = root.read_bytes()
        root.write_text(json.dumps(dict(base, profile=True)))
        assert sample()['attribution'] == 'unknown'
        root.write_bytes(saved)
        absent = fixtures['openmls']
        companion = absent.with_suffix('')
        old = companion.read_bytes()
        companion.unlink()
        assert sample()['unknown_reason'] == 'dependency'
        companion.write_bytes(old)
        duplicate = directory / 'openmls-0000000000000002/lib-openmls'
        duplicate.parent.mkdir()
        duplicate.write_bytes(old)
        assert sample()['unknown_reason'] == 'dependency'
        duplicate.unlink()
        duplicate.parent.rmdir()
        saved_binary = binary.read_bytes()
        binary.unlink()
        binary.symlink_to(root)
        assert sample()['attribution'] == 'unknown'
        binary.unlink()
        binary.write_bytes(saved_binary)
        saved_leaf = absent.read_bytes()
        absent.unlink()
        absent.symlink_to(root)
        assert sample()['attribution'] == 'unknown'
        absent.unlink()
        absent.write_bytes(saved_leaf)
        physical = absent.parent.with_name('physical-openmls')
        absent.parent.rename(physical)
        absent.parent.symlink_to(physical, target_is_directory=True)
        assert sample()['attribution'] == 'unknown'
        absent.parent.unlink()
        physical.rename(absent.parent)
        assert sample()['attribution'] == 'cargo-metadata-linked'
    return {'positive': 4, 'negative': len(negatives) + 7, 'synthetic_metadata_only': True,
            'product_bodies': 0, 'cargo_commands': 0}

