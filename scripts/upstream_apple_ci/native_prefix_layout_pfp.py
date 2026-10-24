"""Remote filesystem metadata PFP only; never run Xcode, SDK or native tests."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import signal
import subprocess
import sys

from package_metadata_pfp import HeldSource, snapshot

ROOT = Path(__file__).resolve().parents[2]
HERE = Path(__file__).resolve().parent
TEST = 'scripts/upstream_apple_ci/test_native_prefix_layout.py'
RUNNER = 'scripts/upstream_apple_ci/factory_semantic_runner.py'
ADAPTER = 'scripts/upstream_apple_ci/paired-direct-mutations.py'
INPUTS = {
    TEST: '1d8d46f1ed01ea4cac9b23a428024d0a2225d04a9d5d5a64427e050e90a76b9c',
    RUNNER: 'b89caaa21f2280d08e56b70facc74804782ca05953a06fd97c4e23e41615dd79',
    ADAPTER: '1bfcefcfabb77aea48d58dc9e9ca69a8f23590487661d7a11f8df6187f11f3a1',
    'scripts/upstream_apple_ci/hosted-app-ui.py': '5b13dd5b22670fec484dd498459bfa476ac9b5ee86cc8a6cd0532bda2e166a22',
    'scripts/upstream_apple_ci/hosted-app-unit.py': '0f1504e4e7479ad7a5a855018b1d9885cd70c0fa5ff6b42636ba6ff869a0da7a',
}
MUTATIONS = [
    ('factory-build', RUNNER, "invoke(build, folder / 'driver-build-private.log',", "invoke(build, folder / 'build-driver-private.log',"),
    ('factory-unit', RUNNER, "invoke(command, folder / 'driver-unit-private.log',", "invoke(command, folder / 'unit-driver-private.log',"),
    ('adapter-build', ADAPTER, "with (folder / 'driver-build-private.log').open('x') as log:", "with (folder / 'build-private.log').open('x') as log:"),
]
MESSAGES = {
    'factory-build': "factory build driver capture must remain outside the child's reserved prefix",
    'factory-unit': "factory unit driver capture must remain outside the child's reserved prefix",
    'adapter-build': "adapter build driver capture must remain outside the child's reserved prefix",
}
METHODS = {'factory-build': 'test_factory_build', 'factory-unit': 'test_factory_unit', 'adapter-build': 'test_adapter_build'}
FIELDS = {'schema', 'metadata_only', 'product_tests_executed', 'native_tests_executed', 'executed',
          'passed', 'failed', 'errors', 'skipped', 'failure_tests', 'error_tests', 'observations', 'files'}


def require(value, label):
    if not value: raise ValueError(label)


def sha(raw): return hashlib.sha256(raw).hexdigest()


def unique(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result, 'duplicate-metadata-key')
        result[key] = value
    return result


def totals(phases):
    unknown = [row['label'] for row in phases if row.get('invoked') and row.get('observed_counts') is None]
    known = sum(row['observed_counts']['executed'] for row in phases if row.get('observed_counts') is not None)
    return dict(known_executed_metadata_methods=known, executed_metadata_methods=None if unknown else known,
                invoked_phases_with_unknown_counts=unknown)


def observed_counts(value):
    if type(value) is not dict: return None
    names = ['executed', 'passed', 'failed', 'errors', 'skipped']
    if not all(type(value.get(key)) is int and 0 <= value[key] <= 128 for key in names): return None
    result = {key: value[key] for key in names}
    return result if result['executed'] == sum(result[key] for key in names[1:]) else None


def observations(value, target):
    require(type(value) is dict and set(value) == set(METHODS), 'closed-three-reservation-cases')
    for case, rows in value.items():
        require(type(rows) is dict and set(rows) == {'negative', 'separated', 'actual'}, 'three-actual-guard-probes-per-case')
        for phase, row in rows.items():
            reserved = phase == 'separated' or phase == 'actual' and case != target
            wanted = dict(reserved=reserved, category=None if reserved else 'prefix-collision',
                          parent_capture_exists=True, child_exit_code=0 if reserved else 3, temporary_removed=True)
            require(type(row) is dict and set(row) == set(wanted)
                    and all(type(row[key]) is bool for key in ['reserved', 'parent_capture_exists', 'temporary_removed'])
                    and type(row['child_exit_code']) is int and row == wanted, 'exact-guard-vector-and-real-cleanup')


def own_failure(raw, target, source):
    anchor = "        self.assertTrue(actual['reserved'], MESSAGES[case])"
    require(source.count(anchor) == 1, 'one-source-owned-layout-final-assertion')
    line = source[:source.index(anchor)].count('\n') + 1
    text = raw.decode('utf-8', errors='strict')
    expected = 'AssertionError: False is not true : ' + MESSAGES[target]
    site = 'File "' + str(ROOT / TEST) + '", line ' + str(line) + ', in check_case'
    require(text.count('AssertionError:') == text.count(expected) == text.count(site) == 1,
            'sole-exact-source-owned-layout-assertion')
    return dict(path=TEST, function='check_case', line=line, fixed_message=MESSAGES[target], method=METHODS[target])


def controls(test_source):
    positives, negatives = 0, 0
    def fixture(target):
        value = {}
        for case in METHODS:
            value[case] = {}
            for phase in ['negative', 'separated', 'actual']:
                reserved = phase == 'separated' or phase == 'actual' and case != target
                value[case][phase] = dict(reserved=reserved, category=None if reserved else 'prefix-collision',
                    parent_capture_exists=True, child_exit_code=0 if reserved else 3, temporary_removed=True)
        return value
    for target in [None] + list(METHODS):
        observations(fixture(target), target); positives += 1
    for name, change in [('reserved', False), ('parent_capture_exists', False), ('temporary_removed', False), ('child_exit_code', True)]:
        value = fixture(None); value['factory-build']['actual'][name] = change
        try: observations(value, None)
        except ValueError: negatives += 1
        else: raise AssertionError('malformed-layout-observation-accepted')
    value = fixture(None); value['factory-build']['actual']['private'] = 'PRIVATE'
    try: observations(value, None)
    except ValueError: negatives += 1
    else: raise AssertionError('private-layout-field-accepted')
    try: json.loads('{"executed":3,"executed":0}', object_pairs_hook=unique)
    except ValueError: negatives += 1
    else: raise AssertionError('duplicate-layout-key-accepted')
    assert observed_counts(dict(executed=3, passed=2, failed=1, errors=0, skipped=0)) is not None
    assert observed_counts(dict(executed=3, passed=3, failed=1, errors=0, skipped=0)) is None
    assert totals([dict(label='pending', invoked=True)])['executed_metadata_methods'] is None
    positives += 3
    anchor = "        self.assertTrue(actual['reserved'], MESSAGES[case])"
    require(test_source.count(anchor) == 1, 'one-source-owned-layout-assertion')
    line = test_source[:test_source.index(anchor)].count('\n') + 1
    target = 'factory-build'
    raw = ('File "' + str(ROOT / TEST) + '", line ' + str(line) + ', in check_case\n'
        + 'AssertionError: False is not true : ' + MESSAGES[target] + '\n').encode()
    own_failure(raw, target, test_source); positives += 1
    for wrong in [raw*2, raw.replace(MESSAGES[target].encode(), b'wrong'),
                  raw.replace(('line '+str(line)).encode(), ('line '+str(line+1)).encode()),
                  raw.replace(b'in check_case', b'in setup')]:
        try: own_failure(wrong, target, test_source)
        except ValueError: negatives += 1
        else: raise AssertionError('unowned-layout-failure-accepted')
    return dict(positive=positives, negative=negatives, metadata_only=True, product_tests_executed=0, native_tests_executed=0)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--result', type=Path, required=True)
    args = parser.parse_args()
    require(os.environ.get('GITHUB_ACTIONS') == 'true' and os.environ.get('RUNNER_OS') == 'Linux', 'remote-Linux-metadata-only')
    require(args.result.is_absolute() and not args.result.exists()
            and ROOT not in args.result.resolve().parents, 'fresh-result-outside-source')
    work = Path(os.environ['RUNNER_TEMP']) / 'native-prefix-layout-pfp'
    work.mkdir(mode=0o700)
    args.result.parent.mkdir(parents=True, exist_ok=True)
    proof = dict(schema=1, metadata_only=True, product_tests_executed=0, native_tests_executed=0,
                 passed=False, source_restored=False, phases=[])
    def save():
        proof.update(totals(proof['phases']))
        args.result.write_text(json.dumps(proof, indent=2)+'\n')
    held, originals, before = {}, {}, None
    try:
        before = snapshot(); require(before['status'] == sha(b''), 'clean-committed-source-required')
        require(all(before['files'][path][0] == digest for path, digest in INPUTS.items()), 'exact-reviewed-metadata-inputs')
        manifest = json.loads((HERE / 'HOSTED-SOURCE.json').read_text())
        require(len(manifest['files']) == 31 and manifest['files']['factory_semantic_runner.py']['sha256'] == INPUTS[RUNNER]
                and manifest['files']['paired-direct-mutations.py']['sha256'] == INPUTS[ADAPTER], 'current-versioned-hosted-hashes-required')
        proof.update(source=before['head'], input_sha256=INPUTS,
                     hosted_manifest_sha256=before['files']['scripts/upstream_apple_ci/HOSTED-SOURCE.json'][0])
        for path in (RUNNER, ADAPTER):
            originals[path] = (ROOT / path).read_bytes()
            held[path] = HeldSource(ROOT / path, originals[path])
        test_source = (ROOT / TEST).read_text()
        proof['controls'] = controls(test_source); save()
        variants = {}
        for label, path, old, new in MUTATIONS:
            text = originals[path].decode()
            require(text.count(old) == 1, 'one-owned-layout-callsite')
            mutant = text.replace(old, new, 1).encode()
            require(mutant.count(b'\n') == originals[path].count(b'\n'), 'newline-preserved-filename-inverse')
            variants[label] = (path, mutant)
        proof['mutant_sha256'] = {name: sha(value[1]) for name, value in variants.items()}
        sequence = [('baseline', None)]
        for name, _, _, _ in MUTATIONS: sequence += [(name+'-mutant', name), (name+'-restored', None)]
        for label, target in sequence:
            expected = {**before, 'files': dict(before['files'])}
            if target:
                path, mutant = variants[target]; held[path].write(originals[path], mutant)
                expected['files'][path] = [sha(mutant), before['files'][path][1]]
                expected['status'] = sha((' M '+path+'\0').encode())
            def closure():
                for path, handle in held.items():
                    handle.verify(variants[target][1] if target and variants[target][0] == path else originals[path])
                require(snapshot() == expected, 'exact-held-source-Git-mode-phase-closure')
            closure()
            row = dict(label=label, inverse=target, invoked=True)
            proof['phases'].append(row); save()
            folder = work / label; folder.mkdir(mode=0o700)
            result_path, log_path = folder / 'result.json', folder / 'private.log'
            with log_path.open('x') as output:
                process = subprocess.Popen([sys.executable, '-B', str(ROOT / TEST), '--result', str(result_path)],
                    cwd=ROOT, stdout=output, stderr=subprocess.STDOUT, start_new_session=True)
                try: row['exit_code'] = process.wait(timeout=30)
                finally:
                    if process.poll() is None:
                        os.killpg(process.pid, signal.SIGKILL); process.wait(timeout=10)
            require(log_path.stat().st_size <= 1024*1024 and result_path.stat().st_size <= 65536, 'bounded-metadata-results')
            raw, result_raw = log_path.read_bytes(), result_path.read_bytes()
            row.update(log_sha256=sha(raw), result_sha256=sha(result_raw))
            value = json.loads(result_raw, object_pairs_hook=unique)
            row['observed_counts'] = observed_counts(value); save()
            require(type(value) is dict and set(value) == FIELDS and type(value['schema']) is int and value['schema'] == 1
                    and value['metadata_only'] is True and type(value['product_tests_executed']) is int and value['product_tests_executed'] == 0
                    and type(value['native_tests_executed']) is int and value['native_tests_executed'] == 0, 'closed-metadata-only-result')
            wanted = dict(executed=3, passed=2 if target else 3, failed=1 if target else 0, errors=0, skipped=0)
            require(row['observed_counts'] == wanted and row['exit_code'] == int(target is not None)
                    and value['failure_tests'] == ([METHODS[target]] if target else []) and value['error_tests'] == [],
                    'three-executed-methods-and-exact-planned-failure')
            files = dict(INPUTS)
            if target: files[variants[target][0]] = sha(variants[target][1])
            require(value['files'] == files, 'actual-test-and-helper-inputs-exact')
            observations(value['observations'], target)
            row['observations'] = value['observations']; row['counts'] = wanted; save()
            if target: row['own_failure'] = own_failure(raw, target, test_source)
            else: require(b'AssertionError:' not in raw, 'passing-controls-without-assertion-errors')
            closure(); row['source_closure_exact'] = True
            if target:
                path, mutant = variants[target]; held[path].write(mutant, originals[path])
                require(snapshot() == before, 'immediate-complete-source-restoration')
            save()
        require([row['label'] for row in proof['phases']] == [label for label, _ in sequence], 'seven-ordered-metadata-phases')
        require(sum(row['counts']['executed'] for row in proof['phases']) == 21
                and sum(row['counts']['passed'] for row in proof['phases']) == 18
                and sum(row['counts']['failed'] for row in proof['phases']) == 3, 'exact-twentyone-method-complete-PFP')
        proof['passed'] = True
    except (ValueError, OSError, KeyError, TypeError, UnicodeError, subprocess.SubprocessError, AssertionError) as error:
        proof['failure_category'] = type(error).__name__
        if isinstance(error, ValueError) and re.fullmatch('[A-Za-z0-9_-]{1,160}', str(error)): proof['failure_label'] = str(error)
    finally:
        restored = True
        for path, handle in held.items():
            try:
                if handle.current != originals[path]: handle.write(handle.current, originals[path])
                handle.verify(originals[path])
            except (ValueError, OSError): restored = False
            finally:
                try: handle.close()
                except OSError: restored = False
        if before is not None:
            try: proof['source_restored'] = restored and snapshot() == before
            except (OSError, subprocess.SubprocessError): proof['source_restored'] = False
        proof['passed'] = proof['passed'] and proof['source_restored']
        save()
    return 0 if proof['passed'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
