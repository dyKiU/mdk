"""Remote-only Vision runtime controls; no application or SDK qualification credit."""
import argparse
import copy
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import signal
import sys

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
sys.path.insert(0, str(HERE.parent / 'upstream_apple_ci'))
import compatibility_policy as policy
import factory_xcresult as xcresult
from compatibility_policy_pfp import (cohort, sdk_state, source_state, products_state,
    compiler_sites, selected_identity, settings, relay, invoke, file_sha)
from factory_semantic_runner import ExactSource, context
from summarize import export_metadata, export_tests, summary_counts


def bindings():
    value = json.loads((HERE / 'ios-vision-runtime-sources.json').read_text())
    policy.require(type(value.get('schema')) is int and value['schema'] == 1
                   and value['diagnostic_only'] is True and value['qualification_credit'] is False
                   and value['profile'] == 'experimental'
                   and set(value['cases']) == {'earliest', 'empty', 'pixel'}, 'closed-Vision-bindings')
    for name in ('app_sha', 'sdk_source'):
        policy.require(type(value[name]) is str and re.fullmatch('[0-9a-f]{40}', value[name]), 'exact-Vision-commit')
    policy.require(type(value['sdk_run_id']) is str and re.fullmatch('[1-9][0-9]*', value['sdk_run_id']),
                   'exact-existing-Vision-SDK-run')
    return value


def schedule():
    return [('positive-earliest', 'earliest', False), ('positive-empty', 'empty', False),
            ('positive-pixel', 'pixel', False), ('mutant-earliest', 'earliest', True),
            ('restored-earliest', 'earliest', False), ('mutant-empty', 'empty', True),
            ('restored-empty', 'empty', False)]


def totals(phases):
    known, unknown = [], []
    for row in phases:
        observed = summary_counts(row.get('counts'))
        if observed is not None:
            known.append(observed)
        elif row.get('unit_invoked') is True:
            unknown.append(row['label'])
    return {'known_executed': sum(r['totalTestCount'] for r in known),
            'executed': None if unknown else sum(r['totalTestCount'] for r in known),
            'unknown_phases': unknown,
            'known_counts': {key: sum(r[key] for r in known) for key in policy.FIELDS}}


def expected_source(initial, path, wanted):
    result = copy.deepcopy(initial)
    policy.require(path in result['files'], 'tracked-Vision-mutation-source')
    result['files'][path][0] = policy.sha(wanted)
    return result


def final_pass(proof):
    return (proof.get('source_restored') is True and proof.get('sdk_unchanged') is True
            and proof.get('relay_cleanup_passed') is True and proof.get('tools_unchanged') is True
            and 'failure_category' not in proof and 'restoration_error_kind' not in proof
            and len(proof['phases']) == 7
            and all(row.get('qualified') is True and row.get('source_sdk_products_frozen') is True
                    and row.get('held_FD_inode_mode_verified') is True for row in proof['phases']))


def pinned_helpers(config):
    for name, digest in config['helper_sha256'].items():
        policy.require((ROOT / name).is_file() and file_sha(ROOT / name) == digest,
                       'exact-imported-Vision-helper')


def safe_failures(failures):
    # Entire failure multiset, never a filtered subset or arbitrary diagnostic text.
    return [{key: row[key] for key in ('file', 'line', 'column')} |
            {'message_sha256': policy.sha(row['message'].encode())} for row in failures]


def observed_own_failure_facts(case, failures):
    # Supplemental observations only: never a compiler waiver or runtime verdict.
    # Preserve every row, including off-owner and additional failures.
    result = []
    for failure in failures:
        row = safe_failures([failure])[0]
        expected = [issue for issue in case['issues']
                    if failure['file'] == case['test_source']
                    and type(failure['line']) is int and failure['line'] == issue['line']
                    and (failure['column'] is None or type(failure['column']) is int
                         and failure['column'] == issue['column'])]
        bound = len(expected) == 1
        message = failure['message']
        row.update(exact_bound_own_site=bound,
                   bounded_expectation_prefix=(type(message) is str
                       and len(message.encode('utf-8')) <= 8192
                       and message.startswith('Expectation failed:')),
                   expected_expression_id=expected[0]['expression_id'] if bound else None,
                   fixed_expected_token_matches=([token in message for token in expected[0]['message_tokens']]
                                                if bound else None))
        result.append(row)
    return {'diagnostic_only': True, 'qualification_credit': False,
            'entire_failure_count': len(failures), 'failures': result}


def run(args):
    config = bindings()
    policy.require(os.environ.get('GITHUB_ACTIONS') == 'true' and os.environ.get('RUNNER_OS') == 'macOS',
                   'remote-only-Vision-runtime')
    policy.require(not args.output.exists(), 'fresh-Vision-report')
    pinned_helpers(config)
    tools = context(ROOT)
    policy.require(tools['HEAD'] == os.environ['GITHUB_SHA'], 'exact-Vision-tools-source')
    app = Path('ios').resolve(strict=True)
    admitted = json.loads(args.cohort_evidence.read_text())
    policy.require(admitted['app_sha'] == config['app_sha'] and admitted['sdk_source'] == config['sdk_source']
                   and admitted['sdk_run_id'] == config['sdk_run_id'] and admitted['profile'] == config['profile']
                   and admitted['platform'] == 'ios' and admitted['tools_sha'] == tools['HEAD'],
                   'exact-admitted-Vision-cohort')
    policy.require(cohort.physical_tracked_snapshot(app) == admitted['prepared_tracked_snapshot'],
                   'original-prepared-Vision-source')
    package = app / 'Packages/MarmotKit'
    manifest = json.loads((package / 'LOCAL_BUILD.json').read_text())
    policy.require(manifest['qualification_receipt']['qualification_sha256'] == admitted['qualification_sha256']
                   and manifest['qualification_receipt']['platform'] == 'ios', 'admitted-Vision-SDK-anchor')
    sdk = sdk_state(package, manifest)
    initial = source_state(app)
    environment = cohort.environment_for('experimental', config['sdk_source'], config['sdk_run_id'])
    flags = cohort.guard_settings(app, 'experimental', environment)
    policy.require(flags == admitted['validated_build_settings'], 'same-admitted-Vision-settings')
    work = Path(os.environ['RUNNER_TEMP']) / 'vision-runtime-controls'
    policy.require(not work.exists(), 'fresh-Vision-work')
    work.mkdir(mode=0o700)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    cases = config['cases']
    common = cases['earliest']
    original = (app / common['source']).read_bytes()
    policy.require(policy.sha(original) == common['original_sha256'], 'exact-original-Vision-product')
    for case in cases.values():
        policy.require(case['source'] == common['source'] and case['original_sha256'] == policy.sha(original),
                       'same-original-Vision-product')
        policy.source_sites((app / case['test_source']).read_bytes(), case)
    inverses = {name: policy.transform(original, cases[name]) for name in ('earliest', 'empty')}
    proof = {'schema': 1, 'diagnostic_only': True, 'qualification_credit': False,
             'app_sha': config['app_sha'], 'sdk_source': config['sdk_source'],
             'sdk_run_id': config['sdk_run_id'], 'profile': 'experimental', 'tools_sha': tools['HEAD'],
             'helper_sha256': policy.sha(Path(__file__).read_bytes()),
             'bindings_sha256': policy.sha((HERE / 'ios-vision-runtime-sources.json').read_bytes()),
             'source_restored': False, 'sdk_unchanged': False, 'tools_unchanged': False,
             'relay_cleanup_passed': False, 'passed': False, 'phases': []}
    def save():
        proof['totals'] = totals(proof['phases'])
        args.output.write_text(json.dumps(proof, indent=2) + '\n')
    held, previous = None, {}
    def interrupt(signum, frame):
        raise KeyboardInterrupt(signum)
    try:
        for sig in (signal.SIGINT, signal.SIGTERM):
            previous[sig] = signal.signal(sig, interrupt)
        save()
        held = ExactSource(app, app / common['source'], original)
        command, products = settings(app, 'ios', work, flags)
        built_sha, frozen_products, build_facts, build_issues = None, None, None, None
        with relay(work, environment, proof):
            for label, alias, mutant in schedule():
                case = cases[alias]
                wanted = inverses[alias] if mutant else original
                if label == 'mutant-earliest':
                    policy.require(all(row.get('runtime_positive_observed') is True for row in proof['phases'][:3]),
                                   'three-actual-positive-controls-before-Vision-inverses')
                if held.current != wanted:
                    held.write(held.current, wanted)
                held.verify(wanted)
                expected = expected_source(initial, common['source'], wanted)
                policy.require(source_state(app) == expected and sdk_state(package, manifest) == sdk,
                               'exact-source-and-SDK-before-Vision-phase')
                pinned_helpers(config)
                row = {'label': label, 'case': alias, 'intentional_mutant': mutant,
                       'source_sha256': policy.sha(wanted), 'test_sha256': case['test_source_sha256'],
                       'unit_invoked': False, 'counts': None, 'qualified': False}
                proof['phases'].append(row)
                folder = work / label
                folder.mkdir(mode=0o700)
                test = app / case['test_source']
                save()
                if built_sha != policy.sha(wanted):
                    policy.require(shutil.disk_usage(work).free >= 8 * 1024**3, 'eight-gib-Vision-build-reserve')
                    build = folder / 'build.xcresult'
                    row['build_exit_code'] = invoke(['xcodebuild', 'build-for-testing'] + command
                        + ['-resultBundlePath', str(build)], folder / 'build-private.log', environment=environment, timeout=1900)
                    save()
                    policy.require((folder / 'build-private.log').stat().st_size <= 32 * 1024**2,
                                   'bounded-private-Vision-build-log')
                    row['build_inventory_audit'] = {}
                    build_issues = xcresult.read(build, source=test, relative=case['test_source'],
                                                 audit=row['build_inventory_audit'])
                    row['compiler_build_count'] = len(build_issues['compiler'])
                    row['compiler_build_sites'] = compiler_sites(build_issues['compiler'], app, initial['files'])
                    row['build_failure_inventory'] = safe_failures(build_issues['failures'])
                    save()
                    policy.require(row['build_exit_code'] == 0 and not build_issues['failures'],
                                   'actual-Vision-build-no-compile-failure')
                    for name, compiled in [('libmarmot_uniffi.a', 'libmarmot_uniffi.a'),
                                           ('Headers/marmot_uniffiFFI.h', 'include/marmot_uniffiFFI.h')]:
                        key = 'MarmotKit.xcframework/ios-arm64-simulator/' + name
                        policy.require(key in sdk and file_sha(products / 'Debug-Staging-iphonesimulator' / compiled) == sdk[key],
                                       'compiled-Vision-archive-header-qualified')
                    frozen_products = products_state(products)
                    policy.require(frozen_products and len(list(products.glob('*.xctestrun'))) == 1,
                                   'actual-compiled-Vision-products')
                    built_sha = policy.sha(wanted)
                    build_facts = {k: copy.deepcopy(row[k]) for k in ('build_exit_code', 'build_inventory_audit',
                                   'compiler_build_count', 'compiler_build_sites', 'build_failure_inventory')}
                else:
                    row.update(copy.deepcopy(build_facts))
                    row['shared_original_build'] = True
                row['compiled_products_sha256'] = policy.sha(json.dumps(frozen_products, sort_keys=True).encode())
                row['compiled_archive_header_qualified'] = True
                policy.require(source_state(app) == expected and products_state(products) == frozen_products
                               and sdk_state(package, manifest) == sdk, 'exact-compiled-Vision-inputs-before-body')
                result = folder / 'unit.xcresult'
                row['unit_invoked'] = True
                save()
                try:
                    row['unit_exit_code'] = invoke(['xcodebuild', 'test-without-building'] + command
                        + ['-parallel-testing-enabled', 'NO', '-only-testing:' + case['selector'],
                           '-resultBundlePath', str(result)], folder / 'unit-private.log', environment=environment, timeout=1200)
                finally:
                    if result.exists():
                        try:
                            summary = export_metadata(['xcrun', 'xcresulttool', 'get', 'test-results', 'summary',
                                                       '--path', str(result)])
                            row['counts'] = summary_counts(summary)
                        except Exception as error:
                            row['summary_error_kind'] = type(error).__name__
                    save()  # Actual counts precede every later issue/identity/closure validation.
                policy.require((folder / 'unit-private.log').stat().st_size <= 32 * 1024**2,
                               'bounded-private-Vision-unit-log')
                row['runtime_inventory_audit'] = {}
                issues = xcresult.read(result, source=test, relative=case['test_source'], audit=row['runtime_inventory_audit'])
                row['compiler_body_count'] = len(issues['compiler'])
                row['compiler_body_sites'] = compiler_sites(issues['compiler'], app, initial['files'])
                row['entire_failure_inventory'] = safe_failures(issues['failures'])
                row['observed_own_failure_facts'] = observed_own_failure_facts(case, issues['failures'])
                save()
                row['inventory'] = selected_identity(export_tests(result), case, row['counts'])
                row['runtime_positive_observed'] = (not mutant and row['unit_exit_code'] == 0
                    and row['counts'] == dict(totalTestCount=1, passedTests=1, failedTests=0, skippedTests=0)
                    and not issues['failures'])
                try:
                    row['own_issue_evidence'] = policy.runtime(case, row['counts'], build_issues['compiler'],
                                                               issues['compiler'], issues['failures'], mutant)
                    policy.require(row['unit_exit_code'] == (65 if mutant else 0), 'exact-Vision-runtime-exit')
                    row['qualified'] = True
                except ValueError as error:
                    row['phase_gate_failure'] = str(error) if str(error).replace('-', '').isalnum() else 'closed-oracle-rejection'
                    # Retain compiler warnings and all actual bodies, but never qualify a warning-bearing phase.
                held.verify(wanted)
                policy.require(source_state(app) == expected and products_state(products) == frozen_products
                               and sdk_state(package, manifest) == sdk, 'exact-source-SDK-products-after-Vision-body')
                row['source_sdk_products_frozen'] = True
                row['held_FD_inode_mode_verified'] = True
                save()
    except (Exception, KeyboardInterrupt) as error:
        proof['failure_category'] = type(error).__name__
        if isinstance(error, ValueError) and str(error).replace('-', '').isalnum():
            proof['failure_label'] = str(error)
    finally:
        if held is not None:
            try:
                if held.current != original:
                    held.write(held.current, original)
                held.verify(original)
            except Exception as error:
                proof['restoration_error_kind'] = type(error).__name__
            finally:
                held.close()
        for sig, handler in previous.items():
            signal.signal(sig, handler)
        try:
            proof['source_restored'] = source_state(app) == initial
            proof['sdk_unchanged'] = sdk_state(package, manifest) == sdk
            pinned_helpers(config)
            proof['tools_unchanged'] = context(ROOT) == tools
        except Exception:
            proof['source_restored'] = proof['sdk_unchanged'] = proof['tools_unchanged'] = False
        proof['passed'] = final_pass(proof)
        save()
    return 0 if proof['passed'] else 1


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--cohort-evidence', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    os.umask(0o077)
    raise SystemExit(run(parser.parse_args()))
