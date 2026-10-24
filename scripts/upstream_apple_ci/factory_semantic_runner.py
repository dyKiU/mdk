"""Exact-cohort hosted native factory PFP; called only by the existing orchestrator."""
from contextlib import contextmanager
import fcntl
import hashlib
import json
import os
from pathlib import Path
import shutil
import signal
import stat
import subprocess
import sys
import time

import factory_semantic_mutation as mutation
import factory_semantic_oracle as oracle
import factory_xcresult as xcresult

HERE = Path(__file__).resolve().parent


def require(value, label):
    if not value:
        raise ValueError(label)


def sha(data):
    return hashlib.sha256(data).hexdigest()


def git(source, *arguments):
    return subprocess.check_output(['git', *arguments], cwd=source)


def context(source):
    return {'HEAD': git(source, 'rev-parse', 'HEAD').strip().decode(),
            'index': sha(git(source, 'ls-files', '--stage', '-z')),
            'status': sha(git(source, 'status', '--porcelain=v1', '-z', '--untracked-files=all'))}


def modes(source):
    names = git(source, 'ls-files', '-z', '--cached', '--others', '--exclude-standard').decode().split('\0')
    return {name: stat.S_IMODE((source / name).lstat().st_mode) for name in names if name}


class ExactSource:
    """One owned inode/FD; never overwrite an unexpected concurrent edit."""
    def __init__(self, source, path, original):
        self.source, self.path, self.original = source, path, original
        self.fd = os.open(path, os.O_RDWR | os.O_NOFOLLOW | os.O_CLOEXEC)
        fcntl.flock(self.fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        info = os.fstat(self.fd)
        require(stat.S_ISREG(info.st_mode) and info.st_uid == os.getuid() and info.st_nlink == 1,
                'one-owned-regular-adapter-inode-required')
        self.identity = (info.st_dev, info.st_ino, info.st_uid, info.st_nlink, stat.S_IMODE(info.st_mode))
        self.head = context(source)
        self.current = original
        self.verify(original)

    def verify(self, expected):
        fd, path = os.fstat(self.fd), self.path.lstat()
        signature = lambda row: (row.st_dev, row.st_ino, row.st_uid, row.st_nlink, stat.S_IMODE(row.st_mode))
        require(signature(fd) == signature(path) == self.identity and not stat.S_ISLNK(path.st_mode),
                'exact-held-FD-path-inode-owner-mode-required')
        require(os.pread(self.fd, len(expected) + 1, 0) == expected, 'exact-current-adapter-bytes-required')
        require(context(self.source)['HEAD'] == self.head['HEAD']
                and context(self.source)['index'] == self.head['index'], 'HEAD-and-index-must-remain-exact')

    def write(self, expected, replacement):
        self.verify(expected)
        # Mark the permitted recovery bytes before writing, so a short write
        # cannot be mistaken for an unrelated legitimate source update.
        self.current = expected
        offset = 0
        while offset < len(replacement):
            amount = os.pwrite(self.fd, replacement[offset:], offset)
            require(amount > 0, 'complete-owned-FD-write-required')
            offset += amount
            self.current = replacement[:offset] + self.current[offset:]
        os.ftruncate(self.fd, len(replacement))
        self.current = replacement
        os.fsync(self.fd)
        self.verify(replacement)

    def close(self):
        fcntl.flock(self.fd, fcntl.LOCK_UN)
        os.close(self.fd)


def invoke(arguments, path, *, environment, timeout):
    with path.open('x') as log:
        process = subprocess.Popen(arguments, stdout=log, stderr=subprocess.STDOUT,
                                   env=environment, start_new_session=True)
        try:
            return process.wait(timeout=timeout)
        finally:
            if process.poll() is None:
                os.killpg(process.pid, signal.SIGTERM)
                try:
                    process.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    os.killpg(process.pid, signal.SIGKILL)
                    process.wait(timeout=10)


def execution_counts(phases):
    unknown = [row['phase'] for row in phases if row.get('unit_execution_invoked') is True and 'counts' not in row]
    known = sum(row['counts']['totalTestCount'] for row in phases if 'counts' in row)
    return known, None if unknown else known, unknown


def run(runner):
    """Five actual selected bodies per app; original36 runs remain unchanged."""
    args = runner.args
    platform = 'macos' if args.scope == 'native-factory-macos' else 'ios'
    require(args.scope in ('native-factory-macos', 'native-factory-ios')
            and os.environ.get('GITHUB_ACTIONS') == 'true' and os.environ.get('RUNNER_OS') == 'macOS',
            'closed-remote-native-factory-scope-required')
    proof = {'platform': platform, 'app_sha': runner.commit(platform), 'sdk_source': args.sdk_source,
             'sdk_run_id': args.sdk_run_id, 'passed': False, 'source_restored': False,
             'phases': [], 'scope': 'Actual current app WNPAIR2 factory semantics; no SDK rebuild or replacement of native36.'}
    wrapper = runner.report
    wrapper['factory_semantics'] = proof
    started = time.monotonic()
    held = None
    original = None
    initial = None
    initial_modes = None
    initial_context = None
    source = runner.source(platform)
    try:
        require(not (runner.private / 'factory-baseline').exists(), 'no-blind-native-factory-rerun')
        runner.prepare_sdk()
        runner.ui.CONFIG = runner.ui.CONFIGURATIONS[platform]
        bindings_path = HERE / 'factory-semantic-sources.json'
        binding = json.loads(bindings_path.read_text())['apps'][platform]
        require(runner.commit(platform) == binding['commit'], 'exact-reviewed-canonical-app-source-required')
        test_source = source / binding['test_path']
        test_bytes = git(source, 'show', binding['commit'] + ':' + binding['test_path'])
        require(test_source.read_bytes() == test_bytes and sha(test_bytes) == binding['test_sha256'],
                'actual-formatted-native-fixture-required')
        sites = oracle.source_sites(test_bytes, binding['test_path'], binding['test_sha256'])
        require(sites == binding['assertion_sites'], 'independently-derived-exact-assertion-sites-required')
        adapter = source / binding['adapter_path']
        original = git(source, 'show', binding['commit'] + ':' + binding['adapter_path'])
        require(sha(original) == binding['adapter_sha256'], 'reviewed-adapter-source-required')
        initial = runner.ui.freeze_source(source, binding['commit'])
        initial_modes, initial_context = modes(source), context(source)
        sdk = runner.ui.freeze_sdk(runner.package(platform), args.sdk_source)
        held = ExactSource(source, adapter, original)
        proof.update(adapter_original_sha256=sha(original), test_source_sha256=sha(test_bytes),
                     assertion_sites=sites, source_bindings_sha256=sha(bindings_path.read_bytes()),
                     original_modes_sha256=sha(json.dumps(initial_modes, sort_keys=True).encode()),
                     original_context=initial_context)
        cache = {}

        def phase(name, inverse, mutant):
            folder = runner.private / ('factory-' + name)
            folder.mkdir(mode=0o700)
            mode = 'factory-' + inverse if mutant else None
            expected_bytes = mutation.transform(original, platform, mode) if mutant else original
            held.verify(expected_bytes)
            frozen = runner.ui.freeze_source(source, binding['commit'], mode)
            require(modes(source) == initial_modes and runner.ui.freeze_sdk(runner.package(platform), args.sdk_source) == sdk,
                    'exact-source-modes-and-SDK-before-phase-required')
            key = sha(json.dumps(frozen, sort_keys=True).encode())
            products = runner.work / ('factory-derived-' + key) / 'Build/Products'
            row = {'phase': name, 'inverse': inverse, 'intentional_mutation': mode,
                   'adapter_sha256': sha(expected_bytes), 'source_key': key, 'source_sdk_product_plan_frozen': False}
            proof['phases'].append(row)
            build_prefix = folder / 'build'
            if key not in cache:
                require(shutil.disk_usage(runner.work).free >= 8 * 1024**3, 'eight-GiB-build-reserve-required')
                build_bundle = folder / 'compile.xcresult'
                build = [sys.executable, str(HERE / 'hosted-app-ui.py'), '--platform', platform,
                         '--source', str(source), '--source-commit', binding['commit'],
                         '--sdk-package', str(runner.package(platform)), '--sdk-source', args.sdk_source,
                         '--products', str(products), '--prefix', str(build_prefix), '--bridge', str(folder / 'build-bridge'),
                         '--stage', 'build', '--case', 'control' if platform == 'ios' else 'mac-source-picker',
                         '--developer-dir', args.developer_dir, '--compiler-result-bundle', str(build_bundle)]
                if platform == 'ios': build += ['--simulator', args.simulator]
                if mode: build += ['--paired-direct-mutation', mode]
                row['build_exit_code'] = invoke(build, folder / 'driver-build-private.log',
                                                environment=runner.environment, timeout=1900)
                row['build_inventory_audit'] = {}
                if build_bundle.exists():
                    build_issues = xcresult.read(build_bundle, source=test_source, relative=binding['test_path'],
                                                 audit=row['build_inventory_audit'])
                    row['compiler_inventory_count'] = len(build_issues['compiler'])
                    row['build_failure_inventory_count'] = len(build_issues['failures'])
                require(row['build_exit_code'] == 0, 'compilation-is-not-behavioral-RED')
                require(build_bundle.exists(), 'actual-compiler-result-bundle-required')
                require(build_issues['compiler'] == [] and build_issues['failures'] == [], 'entire-build-issue-inventory-empty-required')
                cache[key] = (Path(str(build_prefix) + '-input.json'), build_issues)
                row['reused_matching_compilation'] = False
            else:
                row['reused_matching_compilation'] = True
            receipt, build_issues = cache[key]
            runner.ui.verify_build(receipt, frozen, sdk, products)
            plans = list(products.glob(runner.ui.CONFIG['plan_glob']))
            require(len(plans) == 1, 'one-actual-compiled-native-plan-required')
            environment = folder / 'environment.json'
            environment.write_text(json.dumps({'GITHUB_ACTIONS': 'true', 'GITHUB_RUN_ID': os.environ['GITHUB_RUN_ID'],
                'WN_NATIVE_ACCEPTANCE_SDK_SOURCE': args.sdk_source, 'WN_NATIVE_ACCEPTANCE_SDK_RUN_ID': args.sdk_run_id,
                'WN_AUTOMATIC_HOST_FACTORY_ACCEPTANCE': '1'}) + '\n')
            bundle, unit_prefix = folder / 'unit.xcresult', folder / 'unit'
            command = [sys.executable, str(HERE / 'hosted-app-unit.py'), '--platform',
                       'ios-simulator' if platform == 'ios' else 'macos', '--source', str(source),
                       '--source-commit', binding['commit'], '--sdk-package', str(runner.package(platform)),
                       '--sdk-source', args.sdk_source, '--products', str(products), '--xctestrun', str(plans[0]),
                       '--selector', mutation.SELECTOR, '--environment', str(environment), '--prefix', str(unit_prefix),
                       '--result-bundle', str(bundle), '--developer-dir', args.developer_dir,
                       '--destination', 'platform=iOS Simulator,id=' + args.simulator if platform == 'ios' else 'platform=macOS,arch=arm64']
            if mode: command += ['--paired-direct-mutation', mode]
            with runner.relay('factory-' + name):
                row['unit_execution_invoked'] = True
                try:
                    row['unit_exit_code'] = invoke(command, folder / 'driver-unit-private.log', environment=runner.environment, timeout=1200)
                finally:
                    result_path = Path(str(unit_prefix) + '-result.json')
                    if result_path.exists():
                        result = json.loads(result_path.read_text())
                        counts = {key: result['summary'][key] for key in oracle.COUNTS}
                        require(all(type(value) is int and value >= 0 for value in counts.values()), 'actual-typed-phase-counts-required')
                        row['counts'] = counts
                        row['counts_status'] = 'actual-typed-summary'
                    else:
                        row['counts_status'] = 'unknown-no-terminal-unit-summary'
            row['relay_cleanup'] = dict(runner.report['qr_relay_cleanup'])
            require(row['relay_cleanup']['passed'] == 1, 'positive-owned-relay-close-required')
            require('counts' in row, 'actual-terminal-native-counts-required')
            require(all(result.get(key) is True for key in ('source_unchanged', 'sdk_unchanged', 'products_unchanged', 'plans_unchanged'))
                    and 'runner_error_category' not in result, 'entire-native-input-freeze-required')
            require(result['source_commit'] == binding['commit'] and result['sdk_source'] == args.sdk_source
                    and str(result['sdk_run_id']) == args.sdk_run_id and result['selector'] == mutation.SELECTOR,
                    'actual-exact-native-phase-identity-required')
            row['runtime_inventory_audit'] = {}
            native_issues = xcresult.read(bundle, source=test_source, relative=binding['test_path'],
                                          audit=row['runtime_inventory_audit'])
            row['compiler_body_count'] = len(native_issues['compiler'])
            row['observed_native_failure_inventory_count'] = len(native_issues['failures'])
            with Path(str(unit_prefix) + '-private.log').open('rb') as stream:
                raw_output = stream.read(oracle.MAX_OUTPUT_BYTES + 1)
            require(len(raw_output) <= oracle.MAX_OUTPUT_BYTES, 'bounded-actual-native-output-required')
            records = oracle.decode(raw_output.decode('utf-8', errors='strict'))
            row['records'] = records  # Only fully decoded closed enum/bool fields, even if later rejected.
            verdict = oracle.validate(records, counts, native_issues['failures'], build_issues['compiler'], native_issues['compiler'],
                                      phase='mutant' if mutant else ('baseline' if name == 'baseline' else 'restored'),
                                      inverse=inverse, assertion_sites=sites)
            require(row['unit_exit_code'] == (1 if mutant else 0), 'exact-native-driver-exit-required')
            require(runner.ui.freeze_source(source, binding['commit'], mode) == frozen
                    and runner.ui.freeze_sdk(runner.package(platform), args.sdk_source) == sdk
                    and modes(source) == initial_modes, 'exact-source-SDK-modes-after-phase-required')
            held.verify(expected_bytes)
            row.update(counts=counts, records=records, verdict=verdict,
                       compiler_inventory_count=len(build_issues['compiler']), compiler_body_count=len(native_issues['compiler']),
                       build_inventory_sha256=build_issues['inventory_sha256'], runtime_inventory_sha256=native_issues['inventory_sha256'],
                       complete_actual_failures=native_issues['failures'], compiled_native_inputs=result['compiled_native_inputs'],
                       source_sdk_product_plan_frozen=True, fixture_cleanup_completed=True)
            return row

        phase('baseline', 'begin-legacy', False)
        for inverse in ('begin-legacy', 'scan-legacy'):
            mutant = mutation.transform(original, platform, 'factory-' + inverse)
            held.write(original, mutant)
            try:
                phase(inverse + '-mutant', inverse, True)
            finally:
                held.verify(mutant)
                held.write(mutant, original)
                held.verify(original)
            phase(inverse + '-restored', inverse, False)
        require([row['phase'] for row in proof['phases']] == ['baseline', 'begin-legacy-mutant', 'begin-legacy-restored',
                                                            'scan-legacy-mutant', 'scan-legacy-restored'], 'five-exact-actual-phases-required')
        require(all(row['source_sdk_product_plan_frozen'] for row in proof['phases']), 'every-actual-phase-qualified-required')
        proof['passed'] = True
    except (ValueError, OSError, KeyError, TypeError, UnicodeError, subprocess.SubprocessError) as error:
        # Fixed closed labels only. Never export associated native error text.
        proof['failure_category'] = type(error).__name__
        if isinstance(error, ValueError) and str(error).replace('-', '').replace('_', '').isalnum() and len(str(error)) <= 160:
            proof['failure_label'] = str(error)
    finally:
        if held is not None:
            try:
                if held.current != original:
                    # Recover only bytes last written through our own held FD;
                    # an unexpected concurrent path/byte change is preserved.
                    held.verify(held.current)
                    held.write(held.current, original)
                held.verify(original)
                proof['source_restored'] = (runner.ui.freeze_source(source, runner.commit(platform)) == initial
                    and modes(source) == initial_modes and context(source) == initial_context)
            except (ValueError, OSError, subprocess.SubprocessError):
                proof['source_restored'] = False
            finally:
                held.close()
        proof['passed'] = proof['passed'] and proof['source_restored']
        wrapper['passed'] = int(proof['passed'])
        wrapper['expected_factory_semantic_phase_bodies'] = 5
        known, total, unknown = execution_counts(proof['phases'])
        wrapper['observed_factory_semantic_phase_bodies_with_counts'] = known
        wrapper['executed_factory_semantic_phase_bodies'] = total
        wrapper['invoked_factory_phases_with_unknown_counts'] = unknown
        wrapper['seconds'] = round(time.monotonic() - started, 3)
        args.output.write_text(json.dumps(wrapper, indent=2) + '\n')
    return 0 if proof['passed'] else 1
