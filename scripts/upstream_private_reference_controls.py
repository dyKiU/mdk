"""Manual exact-source reference parity, ledger controls and experimental denial PFP."""
import argparse
import hashlib
import json
import os
import posixpath
from pathlib import Path
import re
import stat
import subprocess

from upstream_avatar_ready_turn_chain import capture, compiler_diagnostics
from upstream_extraction_cohort import frozen_inputs, git, reviewed_cohort
from upstream_publication_mutation_anchors import ExactCancellationMutation

SOURCE = 'crates/storage-sqlite/src/private_migration_ledger.rs'
FIXTURE = 'crates/storage-sqlite/src/private_migration_ledger_tests.rs'
PREFIX = 'base::migrations::private_migration_ledger_tests::'
PARITY = ('base::migrations::private_migration_ledger::reference_tests::'
          'minimum_core_reference_matches_full_core_at_every_private_revision')
DENIAL = PREFIX + 'private_ledger_missing_denial_trigger_rejected_without_mutation'
LABEL = 'missing permanent-denial trigger must not be accepted'
WORKFLOW = '.github/workflows/upstream-boundary-regressions.yml'


def sha(value):
    return hashlib.sha256(value).hexdigest()


def mutate(source):
    anchor = """    for (name, value) in expected {
        if actual.get(name) != Some(value) {
            return Err(denied());
        }
    }"""
    if source.count(anchor) != 2:
        raise ValueError('expected-two-validation-loops')
    start = source.index('fn validate_schema(')
    end = source.index('\nfn validate_namespace(', start)
    block = source[start:end]
    if block.count(anchor) != 1:
        raise ValueError('expected-private-validation-loop')
    replacement = '    // Mutation: omit only exact expected-object validation.'
    return source[:start] + block.replace(anchor, replacement) + source[end:]


def expected_names(fixture, experimental):
    names = []
    for attrs, name in re.findall(r'((?:#\[[^\n]+\]\n)+)fn ([a-zA-Z0-9_]+)\(', fixture):
        if '#[test]' not in attrs:
            continue
        cfg = re.findall(r'#\[cfg\(([^\n]+)\)\]', attrs)
        if any(value not in {'feature = "experimental-device-sync"',
                              'not(feature = "experimental-device-sync")'} for value in cfg):
            raise ValueError('unknown-fixture-cfg')
        if 'feature = "experimental-device-sync"' in cfg and not experimental:
            continue
        if 'not(feature = "experimental-device-sync")' in cfg and experimental:
            continue
        names.append(PREFIX + name)
    if not names or (experimental and DENIAL not in names) or len(set(names)) != len(names):
        raise ValueError('fixture-inventory-shape')
    return sorted(names)


def assertion_line(fixture):
    lines = fixture.splitlines()
    at = [i for i, line in enumerate(lines) if LABEL in line]
    if len(at) != 1:
        raise ValueError('denial-assertion-label')
    prior = [i for i in range(max(0, at[0] - 4), at[0]) if 'assert!(' in lines[i]]
    if len(prior) != 1 or 'run_all(&mut connection).is_err()' not in ''.join(lines[prior[0]:at[0]]):
        raise ValueError('denial-assertion-shape')
    return prior[0] + 1


def diagnostics(raw):
    text = raw.decode('utf-8', errors='replace')
    lines = text.splitlines(keepends=True)
    wrappers = {'error: test failed, to rerun pass `-p storage-sqlite --lib`',
                'error: test failed, to rerun pass `--lib`'}
    found = [i for i, line in enumerate(lines) if line.strip() in wrappers]
    last = max((i for i, line in enumerate(lines) if line.strip()), default=-1)
    if len(found) == 1 and found[0] == last:
        lines.pop(found[0])
    result = compiler_diagnostics(''.join(lines).encode())
    result['storage_terminal_runtime_wrapper_count'] = len(found)
    return result


def fixture_paths():
    declaration_source = Path('crates/storage-sqlite/src/base/migrations.rs').read_text()
    declared = re.findall(r'#\[path = "([^"]+)"\]\s*mod private_migration_ledger_tests;', declaration_source)
    if declared != ['../private_migration_ledger_tests.rs']:
        raise ValueError('fixture-module-path')
    lexical = 'crates/storage-sqlite/src/base/' + declared[0]
    if posixpath.normpath(lexical) != FIXTURE:
        raise ValueError('fixture-module-path')
    return (FIXTURE, lexical)


def panic_facts(raw, fixture):
    text = re.sub(r'\x1b\[[0-?]*[ -/]*[@-~]', '', raw.decode('utf-8', errors='replace'))
    paths = fixture_paths()
    headers = list(re.finditer(
        r"(?m)^[ \t]{0,8}thread '([^'\r\n]{1,4096})'(?: \(\d+\))? panicked at ([^\r\n]{1,4096}):(\d+):(\d+):\r?\n", text))
    total = text.count('panicked at ')
    facts = []
    unknown = max(0, total - len(headers))
    for header in headers:
        thread, path, line, column = header.groups()
        if path not in paths or not (1 <= int(line) <= 1_000_000 and 1 <= int(column) <= 1_000_000):
            unknown += 1
            continue
        label = re.match(r'(?:\r?\n){0,2}' + re.escape(LABEL) + r'\s*(?:\n|$)', text[header.end():]) is not None
        facts.append(dict(source=path, line=int(line), column=int(column),
            expected_thread=thread == DENIAL, expected_assertion_line=int(line) == assertion_line(fixture),
            label_class='missing-permanent-denial' if label else 'unknown'))
    return dict(header_count=total, known_positions=facts[:8], known_positions_overflow=len(facts) > 8,
                unknown_header_or_position_count=unknown,
                intended_denial_assertion=(total == 1 and unknown == 0 and len(facts) == 1
                    and facts[0]['expected_thread'] and facts[0]['expected_assertion_line']
                    and facts[0]['label_class'] == 'missing-permanent-denial'))


def oracle(raw, names, failure, fixture):
    text = re.sub(r'\x1b\[[0-?]*[ -/]*[@-~]', '', raw.decode('utf-8', errors='replace'))
    summaries = re.findall(r'^test result: (ok|FAILED)\. (\d+) passed; (\d+) failed; (\d+) ignored;[^\n]*$', text, re.M)
    actual = re.findall(r'^test ([a-zA-Z0-9_:]+) \.\.\. (ok|FAILED|ignored)\s*$', text, re.M)
    running = re.findall(r'^running (\d+) tests?\s*$', text, re.M)
    expected = [('FAILED', '0', '1', '0')] if failure else [('ok', str(len(names)), '0', '0')]
    own = panic_facts(raw, fixture)['intended_denial_assertion'] if failure else False
    diag = diagnostics(raw)
    counts = None if len(summaries) != 1 else dict(passed=int(summaries[0][1]),
        failed=int(summaries[0][2]), ignored=int(summaries[0][3]))
    qualified = (summaries == expected and running == [str(len(names))]
        and sorted(actual) == sorted((name, 'FAILED' if failure else 'ok') for name in names)
        and not diag['compiler_codes'] and diag['compiler_header_count'] == 0
        and (own if failure else text.count('panicked at ') == 0))
    return dict(counts=counts, expected_names=names, actual_named_statuses=[row for row in actual if row[0] in names],
                unknown_named_status_count=sum(name not in names for name, _ in actual),
                intended_denial_assertion=own, compiler_diagnostics=diag,
                oracle_qualified=qualified)


def controls(fixture):
    prefix = 'running 1 test\ntest ' + DENIAL + ' ... '
    end = 'test result: FAILED. 0 passed; 1 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.1s\n'
    failure = (prefix + 'FAILED\n' + "thread '" + DENIAL + "' panicked at "
        + FIXTURE + ':' + str(assertion_line(fixture)) + ':5:\n' + LABEL + '\n' + end).encode()
    good = (prefix + 'ok\ntest result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.1s\n').encode()
    threaded = failure.replace(("thread '" + DENIAL + "' panicked at").encode(), ("thread '" + DENIAL + "' (123) panicked at").encode())
    lexical = failure.replace(FIXTURE.encode(), fixture_paths()[1].encode())
    if (not oracle(failure, [DENIAL], True, fixture)['oracle_qualified']
        or not oracle(threaded, [DENIAL], True, fixture)['oracle_qualified']
        or not oracle(lexical, [DENIAL], True, fixture)['oracle_qualified']
        or not oracle(good, [DENIAL], False, fixture)['oracle_qualified']):
        raise ValueError('parser-positive')
    negatives = [failure + failure, failure.replace(LABEL.encode(), b'unknown'),
        failure.replace(FIXTURE.encode(), b'unknown.rs'),
        failure.replace((":" + str(assertion_line(fixture)) + ':5:').encode(), b':1:5:'),
        failure.replace(("thread '" + DENIAL).encode(), b"thread 'unknown"),
        failure.replace(b'0 passed; 1 failed', b'0 passed; 0 failed'),
        failure + b'error[E0382]: synthetic\n', failure + b'error: unknown\n',
        failure + b"thread 'unknown' panicked at unknown.rs:1:1:\nunknown\n",
        failure + b'error: test failed, to rerun pass `-p storage-sqlite --lib`\n' * 2,
        failure.replace(b'running 1 test', b'running 0 tests'),
        failure.replace(b'0 ignored;', b'1 ignored;'),
        failure.replace(("thread '" + DENIAL).encode(), ("PRIVATE_PREFIX thread '" + DENIAL).encode())]
    if any(oracle(raw, [DENIAL], True, fixture)['oracle_qualified'] for raw in negatives):
        raise ValueError('parser-negative')
    return dict(positive=4, negative=len(negatives), metadata_only=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source', required=True)
    parser.add_argument('--cohort', choices=['default', 'experimental'], required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    output = args.output.resolve()
    if output.exists() or output == Path.cwd().resolve() or Path.cwd().resolve() in output.parents:
        raise ValueError('fresh-external-report-required')
    output.parent.mkdir(parents=True, exist_ok=True)
    report = dict(complete=False, source=args.source, cohort=args.cohort, runs=[],
                  runtime_mutation_qualification=False)
    leaf = None
    original = None
    before = None
    baseline = False
    def save():
        output.write_text(json.dumps(report, indent=2) + '\n')
    try:
        if args.source != git('rev-parse', 'HEAD'):
            raise ValueError('self-baseline-required')
        report['identity'] = reviewed_cohort(args.source)
        if (os.environ.get('GITHUB_EVENT_NAME') != 'workflow_dispatch'
            or os.environ.get('GITHUB_WORKFLOW_SHA') != args.source
            or os.environ.get('GITHUB_WORKFLOW_REF') != 'dyKiU/mdk/' + WORKFLOW + '@' + os.environ.get('GITHUB_REF', '')):
            raise ValueError('manual-workflow-identity')
        forbidden = ['RUSTFLAGS', 'CARGO_ENCODED_RUSTFLAGS', 'RUSTDOCFLAGS',
            'CARGO_ENCODED_RUSTDOCFLAGS', 'RUSTC_WRAPPER', 'RUSTC_WORKSPACE_WRAPPER', 'RUSTC_BOOTSTRAP']
        if any(os.environ.get(key) for key in forbidden) or any(value for key, value in os.environ.items() if re.fullmatch(r'CARGO_TARGET_.*_RUSTFLAGS', key)):
            raise ValueError('compiler-environment')
        environment = dict(CARGO_INCREMENTAL='1', CARGO_BUILD_JOBS='2',
            CARGO_PROFILE_DEV_DEBUG='0', CARGO_PROFILE_TEST_DEBUG='0',
            CARGO_TERM_COLOR='never', RUST_MIN_STACK='4194304')
        if any(os.environ.get(key) != value for key, value in environment.items()):
            raise ValueError('compiler-environment')
        rustc = subprocess.check_output(['rustc', '-Vv'], text=True)
        channel = re.search(r'^channel = "([0-9.]+)"$', Path('rust-toolchain.toml').read_text(), re.M)
        if channel is None or re.search(r'^release: ' + re.escape(channel[1]) + '$', rustc, re.M) is None:
            raise ValueError('toolchain-release')
        before = frozen_inputs()
        index = git('ls-files', '--stage')
        modes = {name: stat.S_IMODE(Path(name).lstat().st_mode) for name in before}
        for name in before:
            target = Path(name)
            if any(parent.is_symlink() for parent in target.parents):
                raise ValueError('source-parent-symlink')
        parents = {parent for name in before for parent in Path(name).parents}
        parent_identity = {str(parent): (parent.lstat().st_dev, parent.lstat().st_ino, parent.lstat().st_mode) for parent in parents}
        original = Path(SOURCE).read_bytes()
        fixture = Path(FIXTURE).read_text()
        mutant = mutate(original.decode()).encode()
        leaf = ExactCancellationMutation(Path(SOURCE))
        report.update(parser_controls=controls(fixture), rustc=rustc,
            cargo=subprocess.check_output(['cargo', '-V'], text=True).strip(),
            compiler_environment=environment, lock_sha256=sha(Path('Cargo.lock').read_bytes()),
            source_tree=git('rev-parse', 'HEAD^{tree}'), original_sha256=sha(original),
            mutant_sha256=sha(mutant), fixture_sha256=sha(fixture.encode()), retries=0, test_threads=1)
        flags = ['--locked', '-p', 'storage-sqlite', '--lib']
        if args.cohort == 'experimental':
            flags += ['--features', 'experimental-device-sync']
        report['features'] = [] if args.cohort == 'default' else ['experimental-device-sync']
        def exact(content):
            expected = dict(before)
            expected[SOURCE] = dict(before[SOURCE], sha256=sha(content))
            return (frozen_inputs() == expected and git('rev-parse', 'HEAD') == args.source
                and git('ls-files', '--stage') == index
                and all((parent.lstat().st_dev, parent.lstat().st_ino, parent.lstat().st_mode) == parent_identity[str(parent)] for parent in parents)
                and all(stat.S_IMODE(Path(name).lstat().st_mode) == mode for name, mode in modes.items()))
        def execute(phase, names, content, failure=False):
            leaf.check()
            if not exact(content):
                raise ValueError('phase-source')
            row = dict(phase=phase, qualified=False, source_sha256=sha(content))
            report['runs'].append(row)
            save()
            selection = 'package(storage-sqlite) & binary(=storage_sqlite) & (' + ' | '.join('test(=' + name + ')' for name in names) + ')'
            if phase == 'positive-controls':
                selection = 'package(storage-sqlite) & binary(=storage_sqlite) & (test(' + PREFIX + ') | test(=' + PARITY + '))'
            code, raw, elapsed, stderr = capture(['cargo', 'nextest', 'list', *flags,
                '--message-format', 'json', '-E', selection], 1800, separate=True)
            row['inventory'] = dict(exit_code=code, elapsed_seconds=elapsed,
                compiler_diagnostics=compiler_diagnostics(stderr), stdout_sha256=sha(raw), stderr_sha256=sha(stderr))
            save()
            if code != 0:
                raise ValueError('inventory-compile')
            inventory = json.loads(raw)
            selected = [(name, case['ignored']) for suite in inventory['rust-suites'].values()
                for name, case in suite['testcases'].items() if case['filter-match']['status'] == 'matches']
            if sorted(selected) != sorted((name, False) for name in names):
                raise ValueError('inventory-exact')
            row['selected_nonignored'] = names
            # One exact process per named body prevents any substring-selected hidden body.
            row['bodies'] = []
            for name in names:
                if not exact(content):
                    raise ValueError('body-source')
                code, raw, elapsed, _ = capture(['cargo', 'test', *flags, name,
                    '--', '--exact', '--test-threads=1', '--show-output'], 1800)
                body = dict(name=name, exit_code=code, elapsed_seconds=elapsed,
                    output_sha256=sha(raw), output_bytes=len(raw))
                row['bodies'].append(body)
                save()
                # Preserve finite facts before any supplemental assertion-site parsing.
                summary_rows = re.findall(rb'test result: (?:ok|FAILED)\. (\d+) passed; (\d+) failed; (\d+) ignored', raw)
                body['observed_summary_counts'] = [dict(passed=int(p), failed=int(f), ignored=int(i)) for p, f, i in summary_rows]
                body['compiler_diagnostics'] = diagnostics(raw)
                save()
                body['runtime_panic_facts'] = panic_facts(raw, fixture)
                save()
                body.update(oracle(raw, [name], failure, fixture))
                save()
                if code != (101 if failure else 0) or not body['oracle_qualified']:
                    raise ValueError('body-unqualified')
            row['qualified'] = exact(content)
            save()
            return row['qualified']
        positives = [PARITY] + expected_names(fixture, args.cohort == 'experimental')
        report['positive_names'] = positives
        baseline = execute('positive-controls', positives, original)
        if not baseline:
            raise ValueError('positive-controls')
        if args.cohort == 'experimental':
            leaf.write(mutant)
            report['mutant_killed'] = execute('missing-denial-trigger-mutant', [DENIAL], mutant, True)
    except Exception as error:
        report['error_category'] = type(error).__name__
        report['failure_category'] = (error.args[0] if type(error) is ValueError and len(error.args) == 1
            and error.args[0] in {'expected-two-validation-loops','expected-private-validation-loop',
            'fixture-module-path','unknown-fixture-cfg','fixture-inventory-shape','denial-assertion-label','denial-assertion-shape',
            'parser-positive','parser-negative','self-baseline-required','manual-workflow-identity',
            'compiler-environment','toolchain-release','source-parent-symlink','phase-source',
            'inventory-compile','inventory-exact','body-source','body-unqualified','positive-controls'} else 'unknown')
    finally:
        try:
            if leaf is not None:
                leaf.check()
                if Path(SOURCE).read_bytes() != original:
                    leaf.write(original)
                report['source_restored'] = exact(original)
                if baseline and args.cohort == 'experimental' and report['source_restored']:
                    report['restored_passed'] = execute('exact-restored-denial-control', [DENIAL], original)
                report['all_inputs_restored'] = (exact(original)
                    and not git('diff', '--name-only', 'HEAD') and not git('diff', '--cached', '--name-only'))
            report['complete'] = bool(baseline and report.get('all_inputs_restored')
                and (args.cohort == 'default' or report.get('mutant_killed') and report.get('restored_passed')))
            report['runtime_mutation_qualification'] = bool(report['complete'] and args.cohort == 'experimental')
        except Exception as error:
            report['complete'] = False
            report['closure_error_category'] = type(error).__name__
        finally:
            if leaf is not None:
                try:
                    leaf.close()
                except OSError:
                    report['complete'] = False
                    report['runtime_mutation_qualification'] = False
            save()
    return 0 if report['complete'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
