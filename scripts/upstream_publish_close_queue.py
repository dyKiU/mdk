"""Remote original pass-close fault: one exact default or experimental body; RED stays nonzero."""
import argparse
import json
import os
from pathlib import Path
import re
import subprocess

from upstream_current_backend_probe import ANSI, capture
from upstream_directory_login_controls import EMPTY_COMPILER, environment, observed_counts, require, runtime, sha
from upstream_extraction_cohort import git, reviewed_cohort
from upstream_replay_controls import compiler, selected_case, summary_counts, unique
from upstream_apple_ci.package_metadata_pfp import snapshot

SOURCE = 'crates/cgka-engine/tests/publish_lifecycle.rs'
SOURCE_SHA = 'de87ad2cacc63ca0405ff707b7f5feb310bc79794dbac3904cf299deffd9510e'
PRODUCT = 'crates/cgka-engine/src/message_processor/send.rs'
PRODUCT_SHA = '210ef8a48e71eb354dbb449eba993e3381e3d0bd8eaa8814693c04b7eaf5951f'
TEST = 'an_unreadable_intent_queue_at_pass_close_still_rearms_and_drains'
MESSAGE = 'a failed post-close queue read must not fail a durable convergence apply'
PREFIX = 'pass-close-queue-fault '
FIELDS = ('before_epoch_available', 'after_epoch_available', 'epoch_advanced',
          'before_pass_readable', 'after_pass_readable', 'before_active', 'after_active',
          'fault_consumed', 'result_storage_busy', 'result_settled')
CASES = {'publish-close-queue-default': False, 'publish-close-queue-experimental': True}


def probe(raw):
    require(len(raw) <= 16 * 1024 * 1024, 'bounded-pass-close-output')
    text = ANSI.sub('', raw.decode('utf-8', errors='strict')).replace('\r\n', '\n')
    lines = [line for line in text.splitlines() if PREFIX in line]
    require(len(lines) == 1 and text.count(PREFIX) == 1 and len(lines[0]) <= 2048, 'one-bounded-pass-close-probe')
    pattern = r'[ \t]{0,8}' + re.escape(PREFIX) + ' '.join(re.escape(key) + r'=(true|false)' for key in FIELDS) + r'[ \t]{0,8}'
    match = re.fullmatch(pattern, lines[0])
    require(match is not None, 'closed-ten-boolean-pass-close-probe')
    return dict(zip(FIELDS, (item == 'true' for item in match.groups())))


def vector(value, red):
    expected = dict.fromkeys(FIELDS, True)
    expected.update(epoch_advanced=not red, after_active=red, result_storage_busy=red, result_settled=not red)
    require(value == expected, 'exact-pass-close-stage-and-typed-Busy-vector')


def source_site(text):
    begin = text.index('async fn ' + TEST + '() {')
    end = text.index('\n#[tokio::test]', begin)
    body = text[begin:end]
    require(body.count('queued_intent_list_fault.arm(1);') == 1
            and body.count('clock.advance_ms(1_500);') == 1
            and body.count('.advance_convergence_inputs_until_settled(&group_id, 2_500)') == 1
            and body.count(PREFIX) == 1 and body.count(MESSAGE) == 1, 'original-manual-clock-arm-and-verdict-owned')
    match = list(re.finditer(r'\badvance\s*\.\s*(expect)\(\s*"' + re.escape(MESSAGE) + r'"\s*,?\s*\)', body))
    require(len(match) == 1, 'one-original-owned-expect-site')
    offset = begin + match[0].start(1)
    fault_begin = text.index('impl OutboundIntentStorage for FaultStorage {')
    fault_end = text.index('    fn delete_queued_outbound_intent(', fault_begin)
    owned = text[fault_begin:fault_end]
    busy = re.findall(r'StorageError::Busy\(\s*"([^"\r\n]{1,128})"\.into\(\),?\s*\)', owned)
    require(busy == ['injected retained-intent read lock'], 'one-owned-fixed-Busy-injection')
    fixed = MESSAGE + ': Storage(Busy(' + json.dumps(busy[0]) + '))'
    return {'line': text[:offset].count('\n') + 1,
            'column': offset - text.rfind('\n', 0, offset), 'fixed': fixed}


def own_failure(raw, site):
    text = ANSI.sub('', raw.decode('utf-8', errors='strict')).replace('\r\n', '\n')
    headers = re.findall(r"(?m)^[ \t]{0,8}thread '([^'\r\n]+)'(?: \([0-9]+\))? panicked at ([^\s]+\.rs):([0-9]+):([0-9]+):\n([^\r\n]+)", text)
    require(text.count('panicked at ') == 1 and len(headers) == 1, 'sole-entire-pass-close-runtime-panic')
    thread, path, line, column, message = headers[0]
    require((thread, path, int(line), int(column)) == (TEST, SOURCE, site['line'], site['column'])
            and re.fullmatch(r'[ \t]{0,8}' + re.escape(site['fixed']) + r'[ \t]{0,8}', message) is not None,
            'original-owned-expect-and-fixed-typed-Busy-error')
    return {'path': SOURCE, 'line': site['line'], 'column': site['column'],
            'fixed_message_sha256': sha(site['fixed'].encode()), 'typed_storage_busy': True, 'expected_thread': True}


def controls(site):
    def raw(value): return (PREFIX + ' '.join(key + '=' + str(value[key]).lower() for key in FIELDS) + '\n').encode()
    green = dict.fromkeys(FIELDS, True); green.update(after_active=False, result_storage_busy=False)
    red = dict(green, epoch_advanced=False, after_active=True, result_storage_busy=True, result_settled=False)
    for item, is_red in [(green, False), (red, True)]: vector(probe(raw(item)), is_red)
    negative = 0
    for item, is_red in [(green, False), (red, True)]:
        for key in FIELDS:
            changed = dict(item); changed[key] = not changed[key]
            try: vector(probe(raw(changed)), is_red)
            except ValueError: negative += 1
            else: raise AssertionError('pass-close-wrong-stage-bit-accepted')
    valid = raw(red)
    for item in [valid * 2, b'PRIVATE ' + valid, valid.replace(b'true', b'1', 1),
                 valid + b' extra=true', valid.replace(b'before_active=', b'unknown='), b' '*9 + valid,
                 b'x' * (16 * 1024 * 1024 + 1)]:
        try: probe(item)
        except (ValueError, UnicodeError): negative += 1
        else: raise AssertionError('pass-close-malformed-probe-accepted')
    panic = ("thread '" + TEST + "' panicked at " + SOURCE + ':' + str(site['line']) + ':' + str(site['column']) + ':\n' + site['fixed'] + '\n').encode()
    own_failure(panic, site)
    own_failure(panic.replace(site['fixed'].encode(), b' '*8 + site['fixed'].encode() + b' '*8), site)
    for item in [panic * 2, panic.replace(TEST.encode(), b'wrong'), panic.replace(SOURCE.encode(), b'wrong.rs'),
                 panic.replace(site['fixed'].encode(), b'wrong'), panic.replace(site['fixed'].encode(), b' '*9 + site['fixed'].encode()),
                 panic.replace((':' + str(site['column']) + ':').encode(), (':' + str(site['column'] + 1) + ':').encode()),
                 panic.replace((':' + str(site['line']) + ':').encode(), (':' + str(site['line'] + 1) + ':').encode())]:
        try: own_failure(item, site)
        except ValueError: negative += 1
        else: raise AssertionError('pass-close-wrong-owned-panic-accepted')
    return {'positive': 4, 'negative': negative, 'product_bodies': 0, 'synthetic_metadata_only': True}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--mode', choices=['preflight', 'run'], required=True)
    parser.add_argument('--case', choices=sorted(CASES), required=True)
    parser.add_argument('--stage', choices=['sample', 'positive'], required=True)
    parser.add_argument('--baseline', required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    require(args.output.is_absolute() and not args.output.exists()
            and Path.cwd() not in args.output.resolve().parents, 'fresh-proof-outside-source')
    experimental = CASES[args.case]
    features = ['test-policy-overrides', 'test-crash-hooks'] + (['experimental-device-sync'] if experimental else [])
    profile, stack = ('m5-bounded', '4194304') if experimental else ('ci', None)
    proof = {'schema': 1, 'passed': False, 'qualification_passed': False, 'diagnostic_valid': False,
             'causal_red_verified': False, 'source': git('rev-parse', 'HEAD'), 'baseline': args.baseline,
             'mode': args.mode, 'case': args.case, 'stage': args.stage, 'features': features,
             'profile': profile, 'rust_min_stack': stack, 'test': TEST, 'automatic_retries': 0,
             'test_threads': 1, 'historical_evidence_reused': False, 'full_suite_qualification': False,
             'native_acceptance_qualification': False, 'executed_product_bodies': 0}
    args.output.parent.mkdir(parents=True, exist_ok=True)
    def save(): args.output.write_text(json.dumps(proof, indent=2) + '\n')
    before = None
    try:
        require(os.environ.get('GITHUB_ACTIONS') == 'true' and os.environ.get('RUNNER_OS') == 'Linux', 'remote-Linux-required')
        require(args.baseline == proof['source'], 'explicit-reviewed-self-baseline')
        proof['cohort'] = reviewed_cohort(args.baseline)
        before = snapshot()
        require(before['status'] == sha(b'') and before['files'][SOURCE][0] == SOURCE_SHA
                and before['files'][PRODUCT][0] == PRODUCT_SHA, 'clean-exact-diagnostic-test-and-unfixed-product')
        site = source_site(Path(SOURCE).read_text())
        proof['inputs'] = {SOURCE: SOURCE_SHA, PRODUCT: PRODUCT_SHA}
        proof['metadata_controls'] = controls(site)
        if args.mode == 'preflight':
            proof['passed'] = True
        else:
            environment(os.environ, stack)
            flags = ['--locked', '-p', 'cgka-engine', '--test', 'publish_lifecycle', '--profile', profile,
                     '--features', ','.join(features)]
            selection = 'package(cgka-engine) & binary(=publish_lifecycle) & test(=' + TEST + ')'
            code, raw, elapsed, stderr = capture(['cargo', 'nextest', 'list'] + flags
                + ['--message-format', 'json', '-E', selection], 1800, separate=True)
            proof['inventory'] = {'exit_code': code, 'elapsed_seconds': elapsed, 'stdout_sha256': sha(raw),
                                  'stderr_sha256': sha(stderr), 'compiler': compiler(stderr, before['files'])}; save()
            require(code == 0 and proof['inventory']['compiler'] == EMPTY_COMPILER, 'clean-actual-inventory-compiler')
            inventory = json.loads(raw, object_pairs_hook=unique); selected_case(inventory, TEST)
            suites = [suite for suite in inventory['rust-suites'].values()
                if any(item['filter-match']['status'] == 'matches' for item in suite['testcases'].values())]
            require(len(suites) == 1 and suites[0]['binary-name'] == 'publish_lifecycle' and suites[0]['kind'] == 'test', 'exact-original-integration-binary')
            proof['inventory'].update(selected_nonignored=1, selected_ignored=0); save()
            require(snapshot() == before, 'whole-source-after-inventory')
            proof['body_invoked'] = True; proof['executed_product_bodies'] = None; save()
            code, raw, elapsed, _ = capture(['cargo', 'nextest', 'run'] + flags
                + ['--retries', '0', '--test-threads', '1', '--status-level', 'pass', '--final-status-level', 'none',
                   '--no-fail-fast', '--success-output', 'immediate', '--failure-output', 'immediate', '-E', selection], 1800)
            proof['body'] = {'exit_code': code, 'elapsed_seconds': elapsed, 'raw_sha256': sha(raw), 'raw_bytes': len(raw),
                             'compiler': compiler(raw, before['files']), 'summary': summary_counts(raw)}
            proof['observed_counts'] = observed_counts(raw)
            if proof['observed_counts'] is not None: proof['executed_product_bodies'] = proof['observed_counts']['executed']
            proof['counts_identity_validated'] = False; save()
            proof['counts'] = runtime(raw, 'cgka-engine', 'publish_lifecycle', 'test', TEST)
            proof['counts_identity_validated'] = True; save()
            require(proof['body']['compiler'] == EMPTY_COMPILER, 'entire-runtime-compiler-empty')
            proof['probe'] = probe(raw); save()
            is_red = proof['counts']['failed'] == 1
            vector(proof['probe'], is_red)
            if is_red:
                require(code == 100 and experimental, 'only-experimental-own-runtime-RED')
                proof['owned_failure'] = own_failure(raw, site)
                proof['causal_red_verified'] = True
            else:
                require(code == 0 and proof['counts']['passed'] == 1 and b'panicked at ' not in raw, 'one-original-positive-with-no-panic')
            require(snapshot() == before, 'whole-source-after-original-body')
            proof['diagnostic_valid'] = True
            # Genuine runtime RED remains failed/nonzero, even when causally classified.
            proof['passed'] = not is_red
            proof['qualification_passed'] = not is_red
    except (ValueError, KeyError, TypeError, OSError, UnicodeError, subprocess.SubprocessError, AssertionError) as error:
        proof['failure_category'] = type(error).__name__
        if isinstance(error, ValueError) and re.fullmatch('[A-Za-z0-9_-]{1,160}', str(error)):
            proof['failure_label'] = str(error)
    finally:
        if before is not None:
            try: proof['source_restored_exact'] = snapshot() == before
            except (OSError, subprocess.SubprocessError): proof['source_restored_exact'] = False
            proof['passed'] = proof['passed'] and proof['source_restored_exact']
            proof['qualification_passed'] = proof['qualification_passed'] and proof['source_restored_exact']
            proof['diagnostic_valid'] = proof['diagnostic_valid'] and proof['source_restored_exact']
            proof['causal_red_verified'] = proof['causal_red_verified'] and proof['source_restored_exact']
        save()
    return 0 if proof['passed'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
