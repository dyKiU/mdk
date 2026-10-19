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


APP_METHODS = {
    'test_default_synthetic_metadata_accepts_private_zero',
    'test_ios_synthetic_inventory_accepts_two_slices',
    'test_current_experimental_metadata_accepts_private_one',
    'test_legacy_experimental_original_checks_still_accept',
    'test_default_rejects_private_one',
    'test_consistent_lock_spoof_rejected_against_git',
    'test_modified_header_digest_rejected',
    'test_extra_inventory_file_rejected',
    'test_changed_original_swift_rejected',
    'test_changed_installed_swift_rejected',
    'test_changed_privacy_digest_rejected',
    'test_missing_explicit_source_rejected',
    'test_wrong_producer_run_rejected',
    'test_changed_qualification_bytes_rejected',
    'test_boolean_schema_rejected',
    'test_integer_feature_rejected',
    'test_historical_shell_needs_no_overlay_and_sets_no_flags',
    'test_default_shell_emits_current_only',
    'test_new_experimental_shell_emits_both_flags',
    'test_implicit_private_new_receipt_requires_explicit_source',
    'test_legacy_private_shell_does_not_require_new_receipt',
    'test_current_flag_cannot_enable_without_profile',
    'test_private_compilation_environment_rejected',
    'test_private_compilation_argument_rejected',
    'test_configuration_override_rejected',
    'test_required_root_inventory_members_rejected',
    'test_symlinked_artifact_root_rejected',
    'test_symlinked_package_rejected',
}
CASE_GROUPS = {
    'test_local_sdk_profile.LocalSdkProfileTests': APP_METHODS,
    'test_install_destinations.InstallDestinationTests': {
        'test_clean_source_destination_preflight_is_read_only',
        'test_dangling_original_inputs_symlink_refused_before_writes',
        'test_artifacts_parent_symlink_refused_before_writes',
        'test_sources_parent_symlink_refused_before_writes',
        'test_privacy_leaf_symlink_refused_before_writes',
        'test_existing_local_receipt_refused_before_writes',
    },
    'test_bounded_capture.BoundedCaptureTests': {
        'test_small_synthetic_output_remains_ram_only',
        'test_synthetic_output_beyond_cap_is_rejected',
    },
}
SOURCE_NAMES = {'test_local_sdk_profile.py', 'validate_local_sdk_profile.py', 'sdk_profiles.py',
                'bounded_capture.py', 'run-app-profile-controls.py', 'qualify_local_sdk_guard_pfp.py',
                'test_install_destinations.py', 'test_bounded_capture.py', 'install.py'}
EXCEPTION_CATEGORIES = {'AssertionError', 'ValueError', 'TypeError', 'KeyError', 'OSError',
    'FileNotFoundError', 'ModuleNotFoundError', 'ImportError', 'AttributeError', 'RuntimeError',
    'TimeoutError', 'CalledProcessError', 'JSONDecodeError', 'PermissionError', 'NameError',
    'SyntaxError', 'IndentationError', 'UnboundLocalError', 'IndexError', 'ProcessLookupError',
    'BrokenPipeError', 'UnicodeDecodeError'}


def owned_case(method, label, kind):
    groups = ['test_local_sdk_profile.LocalSdkProfileTests'] if kind == 'app' else [
        'test_install_destinations.InstallDestinationTests', 'test_bounded_capture.BoundedCaptureTests']
    return any(method in CASE_GROUPS[group] and label in {group, group + '.' + method} for group in groups)


def closed_ordinary(raw, code, expected, kind):
    """Never return raw messages, full paths, reprs, payloads or unowned method names."""
    rows, seen, unknown_rows = [], set(), 0
    pattern = r'^(test_[A-Za-z0-9_]+) \(([^\r\n()]+)\) \.\.\. (ok|FAIL|ERROR|skipped[^\r\n]*|expected failure|unexpected success)$'
    for match in re.finditer(pattern, raw, re.M):
        method, label, status = match.groups()
        if not owned_case(method, label, kind) or method in seen:
            unknown_rows += 1
            continue
        seen.add(method)
        fixed = 'skipped' if status.startswith('skipped') else status
        rows.append({'method': method, 'status': fixed})
    counts = {'passed': sum(row['status'] == 'ok' for row in rows),
              'failures': sum(row['status'] == 'FAIL' for row in rows),
              'errors': sum(row['status'] == 'ERROR' for row in rows),
              'skips': sum(row['status'] == 'skipped' for row in rows),
              'expected_failures': sum(row['status'] == 'expected failure' for row in rows),
              'unexpected_successes': sum(row['status'] == 'unexpected success' for row in rows)}
    runs = re.findall(r'^Ran (\d+) tests? in [0-9.]+s$', raw, re.M)
    executed = int(runs[0]) if len(runs) == 1 else None
    terminal = list(re.finditer(r'^(OK(?: \(skipped=\d+\))?|FAILED \([^\r\n)]{1,128}\))$', raw, re.M))
    summary_counts = None
    if len(terminal) == 1:
        line = terminal[0].group()
        values = {'failures': 0, 'errors': 0, 'skips': 0, 'expected_failures': 0, 'unexpected_successes': 0}
        text = line[line.find('(') + 1:-1] if '(' in line else ''
        mapping = {'failures': 'failures', 'errors': 'errors', 'skipped': 'skips',
                   'expected failures': 'expected_failures', 'unexpected successes': 'unexpected_successes'}
        pairs = [] if not text else text.split(', ')
        valid_summary, keys = True, set()
        for pair in pairs:
            item = re.fullmatch(r'([a-z ]+)=(\d+)', pair)
            if item is None or item[1] not in mapping or item[1] in keys:
                valid_summary = False
                break
            keys.add(item[1])
            values[mapping[item[1]]] = int(item[2])
        if valid_summary:
            summary_counts = values
    diagnostics = []
    headings = list(re.finditer(r'^(FAIL|ERROR): (test_[A-Za-z0-9_]+) \(([^\r\n()]+)\)$', raw, re.M))
    for index, heading in enumerate(headings[:64]):
        status, method, label = heading.groups()
        if not owned_case(method, label, kind):
            continue
        end = headings[index + 1].start() if index + 1 < len(headings) else len(raw)
        block = raw[heading.end():end]
        categories, sites, active = [], [], False
        for line in block.splitlines():
            if line == 'Traceback (most recent call last):':
                active = True
                continue
            if not active:
                continue
            frame = re.fullmatch(r'  File "([^"\r\n]+)", line ([1-9][0-9]{0,6}), in [^\r\n]+', line)
            if frame:
                basename = Path(frame[1]).name
                site = {'file': basename, 'line': int(frame[2])}
                if basename in SOURCE_NAMES and site not in sites and len(sites) < 16:
                    sites.append(site)
                continue
            exception = re.match(r'^(?:[A-Za-z_][A-Za-z0-9_]*\.)*([A-Za-z_][A-Za-z0-9_]*)(?::|$)', line)
            if exception:
                category = exception[1]
                categories.append(category if category in EXCEPTION_CATEGORIES else 'unknown')
                active = False
        diagnostics.append({'method': method, 'status': status,
                            'exception_category': categories[-1] if categories else 'unknown',
                            'source_sites': sites})
    reconciled = (executed is not None and executed == len(rows) and unknown_rows == 0
                  and summary_counts is not None
                  and all(counts[key] == summary_counts[key] for key in summary_counts))
    reported = dict(counts)
    scope = 'complete_verbose_and_summary' if reconciled else 'observed_verbose_rows_only'
    if executed is not None and summary_counts is not None:
        reported.update(summary_counts)
        remainder = executed - sum(summary_counts.values())
        reported['passed'] = remainder if remainder >= 0 else None
        if not reconciled:
            scope = 'unittest_summary; verbose_inventory_incomplete'
    report = {'expected': expected, 'executed': executed, **reported, 'exit_code': code,
              'counts_scope': scope, 'observed_case_counts': counts,
              'observed_cases': len(rows), 'unknown_case_rows': unknown_rows,
              'summary_counts': summary_counts, 'cases': rows, 'diagnostics': diagnostics,
              'unreported_cases': max(0, executed - len(rows)) if executed is not None else None}
    valid = (reconciled and executed == expected and code == 0 and counts['passed'] == expected
             and all(counts[key] == 0 for key in counts if key != 'passed'))
    return report, valid


def parser_preflight():
    """Six synthetic reporting controls, not product bodies or runtime RED."""
    method = 'test_default_rejects_private_one'
    label = 'test_local_sdk_profile.LocalSdkProfileTests.' + method
    ok = method + ' (' + label + ') ... ok\n\nRan 1 test in 0.001s\n\nOK\n'
    passed, qualifies = closed_ordinary(ok, 0, 1, 'app')
    require(qualifies and passed['passed'] == 1 and passed['executed'] == 1,
            'Synthetic parser positive control failed')
    fail = (method + ' (' + label + ') ... FAIL\n\n'
            + 'FAIL: ' + method + ' (' + label + ')\n'
            + 'Traceback (most recent call last):\n'
            + '  File "/PRIVATE_PATH_SENTINEL/test_local_sdk_profile.py", line 127, in ' + method + '\n'
            + '    source_owned_assertion()\n'
            + 'AssertionError: PRIVATE_MESSAGE_SENTINEL\n\n'
            + 'Ran 1 test in 0.001s\n\nFAILED (failures=1)\n')
    failed, qualifies = closed_ordinary(fail, 1, 1, 'app')
    require(not qualifies and failed['failures'] == 1 and failed['passed'] == 0
            and failed['diagnostics'] == [{'method': method, 'status': 'FAIL',
                  'exception_category': 'AssertionError',
                  'source_sites': [{'file': 'test_local_sdk_profile.py', 'line': 127}]}],
            'Synthetic parser intended failure projection failed')
    unknown = fail.replace(method, 'test_PRIVATE_METHOD_SENTINEL').replace(
        'test_local_sdk_profile.py', 'PRIVATE_SOURCE_SENTINEL.py')
    private, qualifies = closed_ordinary(unknown, 1, 1, 'app')
    exported = json.dumps([failed, private])
    require(not qualifies and private['unknown_case_rows'] == 1
            and private['cases'] == [] and private['diagnostics'] == []
            and all(value not in exported for value in ['PRIVATE_PATH_SENTINEL', 'PRIVATE_MESSAGE_SENTINEL',
                'PRIVATE_METHOD_SENTINEL', 'PRIVATE_SOURCE_SENTINEL']),
            'Synthetic parser privacy projection failed')
    duplicate, qualifies = closed_ordinary(ok + 'Ran 1 test in 0.002s\nOK\n', 0, 1, 'app')
    require(not qualifies and duplicate['executed'] is None,
            'Synthetic parser duplicate summary qualified')
    contradictory = ok.replace('OK\n', 'FAILED (errors=1)\n')
    mismatch, qualifies = closed_ordinary(contradictory, 1, 1, 'app')
    require(not qualifies and mismatch['errors'] == 1
            and mismatch['observed_case_counts']['passed'] == 1
            and mismatch['counts_scope'] != 'complete_verbose_and_summary',
            'Synthetic parser contradictory summary qualified')
    category, qualifies = closed_ordinary(fail.replace('AssertionError:', 'UnreviewedSdkPrivateError:'), 1, 1, 'app')
    require(not qualifies and category['diagnostics'][0]['exception_category'] == 'unknown'
            and 'UnreviewedSdkPrivateError' not in json.dumps(category),
            'Synthetic parser unknown category exported')
    return {'scope': 'synthetic closed-reporting parser ONLY; no product/runtime RED',
            'executed': 6, 'passed': 6, 'failed': 0}


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
        report['parser_preflight'] = parser_preflight()
        with tempfile.TemporaryDirectory(prefix='app-profile-control-') as temp:
            env = dict(os.environ, PYTHONPYCACHEPREFIX=str(Path(temp) / 'cache'))
            body = capture([sys.executable, '-B', '-m', 'unittest', '-v', *modules],
                                  cwd=directory, env=env, timeout=240)
            raw = body.stdout + body.stderr  # RAM only, never uploaded or emitted.
            report['ordinary'], valid = closed_ordinary(raw, body.returncode, count, args.kind)
            # Retain closed actual case counts/sites before the failure verdict.
            args.output.parent.mkdir(parents=True, exist_ok=True)
            args.output.write_text(json.dumps(report, indent=2) + '\n')
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
