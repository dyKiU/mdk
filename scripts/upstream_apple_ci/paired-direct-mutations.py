#!/usr/bin/env python3
"""Fresh genuine native fixture for each app's baseline/old-adapter/restored control."""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import paired_direct_mutation as mutation

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('hosted_ui_build', HERE / 'hosted-app-ui.py')
ui = importlib.util.module_from_spec(spec)
spec.loader.exec_module(ui)


def require(value, category):
    if not value:
        raise ValueError(category)


def write(path, value):
    with path.open('x') as stream:
        json.dump(value, stream, indent=2)
        stream.write('\n')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--platform', choices=mutation.DEFINITIONS, required=True)
    for name in ('source', 'sdk-package', 'mac-agent', 'sim-agent', 'relay', 'work', 'output'):
        parser.add_argument('--' + name, type=Path, required=True)
    for name in ('source-commit', 'sdk-source', 'sdk-run-id', 'mac-sha', 'sim-sha', 'simulator', 'developer-dir'):
        parser.add_argument('--' + name, required=True)
    args = parser.parse_args()
    require(os.environ.get('GITHUB_ACTIONS') == 'true' and os.environ.get('RUNNER_OS') == 'macOS', 'remote-macos-only')
    require(args.sdk_source == os.environ['SOURCE_SHA'] and args.sdk_run_id == os.environ['SDK_RUN_ID']
            and args.sdk_source != '3f18b2d1acac4f87680b35f39bf8dce67dcf28ec', 'qualified-final-sdk-required')
    os.umask(0o077)
    args.source = args.source.resolve(strict=True)
    args.sdk_package = args.sdk_package.resolve(strict=True)
    require(args.work.is_absolute() and not args.work.exists() and args.output.is_absolute()
            and not args.output.exists() and not args.output.is_relative_to(args.work), 'fresh-private-mutation-work-required')
    args.work.mkdir(mode=0o700)
    require(subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=args.source, text=True).strip()
            == args.source_commit, 'exact-app-candidate-required')
    relative, _, _ = mutation.DEFINITIONS[args.platform]
    source = args.source / relative
    original = subprocess.check_output(['git', 'show', args.source_commit + ':' + relative], cwd=args.source)
    require(source.read_bytes() == original, 'original-adapter-must-match-git')
    mutant = mutation.transform(original, args.platform)
    ui.CONFIG = ui.CONFIGURATIONS[args.platform]
    initial_source = ui.freeze_source(args.source, args.source_commit)
    initial_sdk = ui.freeze_sdk(args.sdk_package, args.sdk_source)
    proof = {'platform': args.platform, 'app_sha': args.source_commit, 'sdk_source': args.sdk_source,
             'sdk_run_id': args.sdk_run_id, 'tool_sha': subprocess.check_output(['git', 'rev-parse', 'HEAD'], text=True).strip(),
             'mutation': mutation.identity(args.platform, mutation.MODE), 'phases': [], 'passed': False,
             'scope': 'Actual app adapter and original native stores, fresh fixture per phase; intentional mutant is not qualified app source.'}

    def save():
        args.output.write_text(json.dumps(proof, indent=2) + '\n')

    def phase(name, mode):
        folder = args.work / name
        folder.mkdir(mode=0o700)
        expected_source = ui.freeze_source(args.source, args.source_commit, mode)
        require(ui.freeze_sdk(args.sdk_package, args.sdk_source) == initial_sdk, 'sdk-drift-before-phase')
        # Reuse only same-source compiled products. The old-body mutant has its
        # own derived-data key and cannot populate original/restored products.
        source_hash = hashlib.sha256(source.read_bytes()).hexdigest()
        products = args.work / ('derived-' + source_hash) / 'Build/Products'
        prefix = folder / 'build'
        build = [sys.executable, str(HERE / 'hosted-app-ui.py'), '--platform', args.platform,
                 '--source', str(args.source), '--source-commit', args.source_commit,
                 '--sdk-package', str(args.sdk_package), '--sdk-source', args.sdk_source,
                 '--products', str(products), '--prefix', str(prefix), '--bridge', str(folder / 'build-bridge'),
                 '--stage', 'build', '--case', 'control' if args.platform == 'ios' else 'mac-source-picker',
                 '--developer-dir', args.developer_dir]
        if args.platform == 'ios':
            build += ['--simulator', args.simulator]
        if mode:
            build += ['--paired-direct-mutation', mode]
        row = {'phase': name, 'intentional_source_mutation': mutation.identity(args.platform, mode),
               'source_sha256': source_hash, 'derived_products_key': source_hash}
        proof['phases'].append(row)
        save()
        require(shutil.disk_usage(args.work).free >= 8 * 1024**3, 'eight-gib-build-reserve-required')
        with (folder / 'build-private.log').open('x') as log:
            result = subprocess.run(build, stdout=log, stderr=subprocess.STDOUT, timeout=1900)
        row['build_exit_code'] = result.returncode
        save()
        require(result.returncode == 0, 'compilation-is-not-behavioral-red')
        build_input = Path(str(prefix) + '-input.json')
        ui.verify_build(build_input, expected_source, initial_sdk, products)
        row['compiled_input_receipt_sha256'] = ui.digest(build_input)
        plans = list(products.glob(ui.CONFIG['plan_glob']))
        require(len(plans) == 1, 'exact-built-unit-plan-required')
        base, environment = folder / 'native-base', folder / 'environment.json'
        bundle, unit_prefix = folder / 'unit.xcresult', folder / 'unit'
        target_platform = 'ios-simulator' if args.platform == 'ios' else 'macos'
        destination = 'platform=iOS Simulator,id=' + args.simulator if args.platform == 'ios' else 'platform=macOS,arch=arm64'
        app = [sys.executable, str(HERE / 'hosted-app-unit.py'), '--platform', target_platform,
               '--source', str(args.source), '--source-commit', args.source_commit,
               '--sdk-package', str(args.sdk_package), '--sdk-source', args.sdk_source,
               '--products', str(products), '--xctestrun', str(plans[0]), '--selector', mutation.SELECTOR,
               '--environment', str(environment), '--prefix', str(unit_prefix), '--result-bundle', str(bundle),
               '--destination', destination, '--developer-dir', args.developer_dir]
        if mode:
            app += ['--paired-direct-mutation', mode]
        manifest = folder / 'application-command.json'
        write(manifest, {'argv': app})
        native_output = folder / 'native-result.json'
        command = [sys.executable, str(HERE / 'hosted-app-fixtures.py'), '--scenario', 'paired-direct',
                   '--platform', target_platform, '--mac-agent', str(args.mac_agent), '--sim-agent', str(args.sim_agent),
                   '--mac-sha', args.mac_sha, '--sim-sha', args.sim_sha, '--simulator', args.simulator,
                   '--relay', str(args.relay), '--base', str(base), '--environment', str(environment),
                   '--application-command', str(manifest), '--app-result-bundle', str(bundle),
                   '--output', str(native_output), '--sdk-source', args.sdk_source, '--sdk-run-id', args.sdk_run_id]
        with (folder / 'fixture-private.log').open('x') as log:
            result = subprocess.run(command, stdout=log, stderr=subprocess.STDOUT, timeout=1200)
        row['fixture_exit_code'] = result.returncode
        require(native_output.exists() and bundle.exists(), 'actual-native-fixture-and-xcresult-required')
        native = json.loads(native_output.read_text())
        app_result = json.loads(Path(str(unit_prefix) + '-result.json').read_text())
        summary = json.loads(subprocess.check_output(['xcrun', 'xcresulttool', 'get', 'test-results', 'summary',
                                                     '--path', str(bundle)], text=True))
        fields = ('totalTestCount', 'passedTests', 'failedTests', 'skippedTests')
        require(all(type(summary.get(k)) is int and summary[k] >= 0 for k in fields), 'actual-execution-counts-required')
        row['counts'] = {k: summary[k] for k in fields}
        require(native.get('paired_direct_fixture') == {'bilateral_consent': True, 'source_only_recipient': True,
            'independent_peer': True, 'original_recipient_positive_close': True,
            'one_original_peer_conversation': True, 'no_pending_peer_invitation': True}, 'actual-source-only-original-fixture-required')
        require(native.get('app_runtime_positive_close') is True,
                'actual-app-positive-close-required-even-for-mutant')
        row['app_runtime_positive_close'] = True
        cleanup = native['native_cleanup']
        require(cleanup['workers_created'] == cleanup['workers_closed'] > 0 and cleanup['cleanup_failures'] == 0
                and native['relay_cleanup']['passed'] == 1, 'positive-native-relay-close-required')
        require(all(app_result.get(k) is True for k in ('source_unchanged', 'sdk_unchanged', 'products_unchanged', 'plans_unchanged')),
                'frozen-source-sdk-products-plan-required')
        require(ui.freeze_source(args.source, args.source_commit, mode) == expected_source
                and ui.freeze_sdk(args.sdk_package, args.sdk_source) == initial_sdk, 'phase-input-drift')
        row['native_cleanup'] = cleanup
        row['relay_cleanup'] = native['relay_cleanup']
        row['fixture_preconditions_proved'] = True
        row['compiled_native_inputs'] = app_result['compiled_native_inputs']
        row['source_sdk_product_plan_frozen'] = True
        if mode:
            log = Path(str(unit_prefix) + '-private.log').read_text(errors='replace')
            row['runtime_red'] = (result.returncode != 0 and row['counts'] == dict(zip(fields, (1, 0, 1, 0)))
                                  and 'paired-direct-adapter-destination' in log)
        else:
            row['green'] = (result.returncode == 0 and native['passed'] == 1
                            and row['counts'] == dict(zip(fields, (1, 1, 0, 0)))
                            and native.get('paired_direct', {}).get('no_new_peer_invitation') is True)
        save()
        return row

    save()
    baseline = phase('baseline', None)
    require(baseline['green'], 'baseline-one-runtime-pass-required')
    try:
        source.write_bytes(mutant)
        row = phase('old-adapter-mutant', mutation.MODE)
        proof['mutant_runtime_detected'] = row['runtime_red']
    except (ValueError, OSError, subprocess.SubprocessError, KeyError) as error:
        proof['mutant_runtime_detected'] = False
        proof['mutant_error_category'] = type(error).__name__
    finally:
        source.write_bytes(original)
        proof['source_restored'] = source.read_bytes() == original
        proof['restored_source_sha256'] = hashlib.sha256(source.read_bytes()).hexdigest()
        save()
    require(proof['source_restored'] and ui.freeze_source(args.source, args.source_commit) == initial_source,
            'exact-source-restore-required')
    restored = phase('restored-control', None)
    proof['passed'] = proof['mutant_runtime_detected'] and restored['green']
    save()
    require(proof['passed'], 'whole-old-adapter-runtime-mutant-not-qualified')


if __name__ == '__main__':
    main()
