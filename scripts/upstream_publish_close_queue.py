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
from upstream_apple_ci.package_metadata_pfp import HeldSource, snapshot

SOURCE = 'crates/cgka-engine/tests/publish_lifecycle.rs'
SOURCE_SHA = 'de87ad2cacc63ca0405ff707b7f5feb310bc79794dbac3904cf299deffd9510e'
PRODUCT = 'crates/cgka-engine/src/message_processor/send.rs'
PRODUCT_SHA = 'dc82f4346b36e172610c8ee50d6df748af8abfa4412dd56b97c059ab30a866fb'
RED_PRODUCT_SHA = '210ef8a48e71eb354dbb449eba993e3381e3d0bd8eaa8814693c04b7eaf5951f'
GREEN = '        let retired = self.storage.with_transaction(|storage| {\n            if !self.with_mls_group(group_id, |group| {\n                crate::device_group_genesis::has_private_component(group)\n            })? {\n                return Ok::<_, EngineError>(Vec::new());\n            }\n            let queued = storage.list_queued_outbound_intents(group_id)?;\n            if !queued.iter().any(|record| {\n                matches!(&record.intent, SendIntent::SelfUpdate { .. })\n                    && !self.queued_outbound_intent_in_flight(group_id, &record.id)\n            }) {\n                return Ok::<_, EngineError>(Vec::new());\n            }\n'
INVERSE = '        let retired = self.storage.with_transaction(|storage| {\n            let queued = storage.list_queued_outbound_intents(group_id)?;\n            if !queued.iter().any(|record| {\n                matches!(&record.intent, SendIntent::SelfUpdate { .. })\n                    && !self.queued_outbound_intent_in_flight(group_id, &record.id)\n            }) {\n                return Ok::<_, EngineError>(Vec::new());\n            }\n            if !self.with_mls_group(group_id, |group| {\n                crate::device_group_genesis::has_private_component(group)\n            })? {\n                return Ok::<_, EngineError>(Vec::new());\n            }\n'
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



def execution_totals(phases):
    unknown = [row['label'] for row in phases if row.get('body_invoked') and row.get('observed_counts') is None]
    known = sum(row['observed_counts']['executed'] for row in phases if row.get('observed_counts') is not None)
    return {'known_executed_product_bodies': known,
            'executed_product_bodies': None if unknown else known,
            'invoked_phases_with_unknown_counts': unknown}


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
                 valid.rstrip(b'\n') + b' extra=true\n', valid.replace(b'before_active=', b'unknown='), b' '*9 + valid,
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
    assert execution_totals([]) == dict(known_executed_product_bodies=0, executed_product_bodies=0, invoked_phases_with_unknown_counts=[])
    pending = {'label': 'pending', 'body_invoked': True}
    assert execution_totals([pending]) == dict(known_executed_product_bodies=0, executed_product_bodies=None, invoked_phases_with_unknown_counts=['pending'])
    completed = {'label': 'completed', 'body_invoked': True, 'observed_counts': dict(executed=1, passed=0, failed=1, skipped=24)}
    assert execution_totals([completed, pending]) == dict(known_executed_product_bodies=1, executed_product_bodies=None, invoked_phases_with_unknown_counts=['pending'])
    assert execution_totals([completed]) == dict(known_executed_product_bodies=1, executed_product_bodies=1, invoked_phases_with_unknown_counts=[])
    return {'positive': 8, 'negative': negative, 'product_bodies': 0, 'synthetic_metadata_only': True}



def execute_phase(proof, save, before, source_closure, site, features, profile, stack, experimental, label, expected_red):
    row = {'label': label, 'expected_runtime_red': expected_red, 'causal_red_verified': False}
    proof['phases'].append(row); save()
    source_closure('whole-source-before-pass-close-phase')
    environment(os.environ, stack)
    flags = ['--locked', '-p', 'cgka-engine', '--test', 'publish_lifecycle', '--profile', profile,
             '--features', ','.join(features)]
    selection = 'package(cgka-engine) & binary(=publish_lifecycle) & test(=' + TEST + ')'
    code, raw, elapsed, stderr = capture(['cargo', 'nextest', 'list'] + flags
        + ['--message-format', 'json', '-E', selection], 1800, separate=True)
    row['inventory'] = {'exit_code': code, 'elapsed_seconds': elapsed, 'stdout_sha256': sha(raw),
                          'stderr_sha256': sha(stderr), 'compiler': compiler(stderr, before['files'])}; save()
    require(code == 0 and row['inventory']['compiler'] == EMPTY_COMPILER, 'clean-actual-inventory-compiler')
    inventory = json.loads(raw, object_pairs_hook=unique); selected_case(inventory, TEST)
    suites = [suite for suite in inventory['rust-suites'].values()
        if any(item['filter-match']['status'] == 'matches' for item in suite['testcases'].values())]
    require(len(suites) == 1 and suites[0]['binary-name'] == 'publish_lifecycle' and suites[0]['kind'] == 'test', 'exact-original-integration-binary')
    row['inventory'].update(selected_nonignored=1, selected_ignored=0); save()
    source_closure('whole-source-after-inventory')
    row['body_invoked'] = True; row['executed_product_bodies'] = None; save()
    code, raw, elapsed, _ = capture(['cargo', 'nextest', 'run'] + flags
        + ['--retries', '0', '--test-threads', '1', '--status-level', 'pass', '--final-status-level', 'none',
           '--no-fail-fast', '--success-output', 'immediate', '--failure-output', 'immediate', '-E', selection], 1800)
    row['body'] = {'exit_code': code, 'elapsed_seconds': elapsed, 'raw_sha256': sha(raw), 'raw_bytes': len(raw),
                     'compiler': compiler(raw, before['files']), 'summary': summary_counts(raw)}
    row['observed_counts'] = observed_counts(raw)
    if row['observed_counts'] is not None: row['executed_product_bodies'] = row['observed_counts']['executed']
    row['counts_identity_validated'] = False; save()
    row['counts'] = runtime(raw, 'cgka-engine', 'publish_lifecycle', 'test', TEST)
    row['counts_identity_validated'] = True; save()
    require(row['body']['compiler'] == EMPTY_COMPILER, 'entire-runtime-compiler-empty')
    row['probe'] = probe(raw); save()
    is_red = row['counts']['failed'] == 1
    vector(row['probe'], is_red)
    if is_red:
        require(code == 100 and experimental, 'only-experimental-own-runtime-RED')
        row['owned_failure'] = own_failure(raw, site)
        row['causal_red_verified'] = True
    else:
        require(code == 0 and row['counts']['passed'] == 1 and b'panicked at ' not in raw, 'one-original-positive-with-no-panic')
    source_closure('whole-source-after-original-body')
    row['diagnostic_valid'] = True
    # This records the actual body verdict; only an explicitly planned PFP phase can qualify an inverse.
    row['actual_body_passed'] = not is_red
    if expected_red is not None:
        require(is_red is expected_red, 'exact-planned-pass-close-phase-verdict')
    row['phase_qualified'] = expected_red is not None and is_red is expected_red

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--mode', choices=['preflight', 'run'], required=True)
    parser.add_argument('--case', choices=sorted(CASES), required=True)
    parser.add_argument('--stage', choices=['sample', 'positive', 'pfp'], required=True)
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
             'native_acceptance_qualification': False, 'executed_product_bodies': 0, 'phases': []}
    args.output.parent.mkdir(parents=True, exist_ok=True)
    def save():
        proof.update(execution_totals(proof['phases']))
        args.output.write_text(json.dumps(proof, indent=2) + '\n')
    before, held, original = None, None, None
    try:
        require(os.environ.get('GITHUB_ACTIONS') == 'true' and os.environ.get('RUNNER_OS') == 'Linux', 'remote-Linux-required')
        require(args.baseline == proof['source'], 'explicit-reviewed-self-baseline')
        proof['cohort'] = reviewed_cohort(args.baseline)
        before = snapshot()
        product_pin = RED_PRODUCT_SHA if args.stage == 'sample' else PRODUCT_SHA
        require(before['status'] == sha(b'') and before['files'][SOURCE][0] == SOURCE_SHA
                and before['files'][PRODUCT][0] == product_pin, 'clean-exact-test-and-reviewed-stage-product')
        site = source_site(Path(SOURCE).read_text())
        proof['inputs'] = {SOURCE: SOURCE_SHA, PRODUCT: product_pin}
        proof['metadata_controls'] = controls(site)
        if args.mode == 'preflight':
            if args.stage == 'pfp':
                source = Path(PRODUCT).read_text()
                begin = source.index('    pub(crate) fn retire_queued_private_maintenance(')
                end = source.index('\n    pub(crate) async fn do_send_ready(', begin)
                require(source.count(GREEN) == 1 and source[begin:end].count(GREEN) == 1
                        and GREEN.count('\n') == INVERSE.count('\n')
                        and sha(source.replace(GREEN, INVERSE, 1).encode()) == RED_PRODUCT_SHA,
                        'exact-source-owned-guard-order-counterfactual')
            proof['passed'] = True
        else:
            environment(os.environ, stack)
            sequence = [('diagnostic', None)] if args.stage == 'sample' else (
                [('positive', False)] if args.stage == 'positive' else
                [('baseline', False), ('guard-order-mutant', experimental), ('restored', False)])
            original = Path(PRODUCT).read_bytes()
            mutant = None
            if args.stage == 'pfp':
                source = original.decode()
                begin = source.index('    pub(crate) fn retire_queued_private_maintenance(')
                end = source.index('\n    pub(crate) async fn do_send_ready(', begin)
                require(source.count(GREEN) == 1 and source[begin:end].count(GREEN) == 1
                        and GREEN.count('\n') == INVERSE.count('\n'), 'one-owned-newline-preserved-guard-order-inverse')
                mutant = source.replace(GREEN, INVERSE, 1).encode()
                require(sha(mutant) == RED_PRODUCT_SHA, 'exact-entire-original-bug-source')
                held = HeldSource(Path(PRODUCT), original)
            for label, expected_red in sequence:
                intentional = label == 'guard-order-mutant'
                wanted = mutant if intentional else original
                if held is not None:
                    if held.current != wanted: held.write(held.current, wanted)
                    held.verify(wanted)
                expected = {**before, 'files': dict(before['files'])}
                if intentional:
                    expected['files'][PRODUCT] = [sha(mutant), before['files'][PRODUCT][1]]
                    expected['status'] = sha((' M ' + PRODUCT + '\0').encode())
                def source_closure(note):
                    if held is not None: held.verify(wanted)
                    require(snapshot() == expected, note)
                execute_phase(proof, save, before, source_closure, site, features, profile, stack, experimental, label, expected_red)
                if held is not None: held.verify(wanted)
                if intentional:
                    held.write(wanted, original)
                    require(snapshot() == before, 'immediate-exact-guard-order-restoration')
            require([row['label'] for row in proof['phases']] == [label for label, _ in sequence],
                    'complete-ordered-pass-close-phase-inventory')
            totals = {key: sum(row['counts'][key] for row in proof['phases']) for key in ['executed', 'passed', 'failed']}
            expected_failed = int(args.stage == 'pfp' and experimental) if args.stage != 'sample' else int(experimental)
            if args.stage != 'sample':
                require(totals == dict(executed=len(sequence), failed=expected_failed,
                                      passed=len(sequence) - expected_failed), 'exact-complete-phase-runtime-totals')
            proof['phase_totals'] = totals
            proof['diagnostic_valid'] = all(row['diagnostic_valid'] for row in proof['phases'])
            proof['causal_red_verified'] = any(row['causal_red_verified'] for row in proof['phases'])
            proof['passed'] = (all(row['actual_body_passed'] for row in proof['phases']) if args.stage == 'sample'
                               else all(row['phase_qualified'] for row in proof['phases']))
            proof['qualification_passed'] = proof['passed'] and args.stage != 'sample'

    except (ValueError, KeyError, TypeError, OSError, UnicodeError, subprocess.SubprocessError, AssertionError) as error:
        proof['failure_category'] = type(error).__name__
        if isinstance(error, ValueError) and re.fullmatch('[A-Za-z0-9_-]{1,160}', str(error)):
            proof['failure_label'] = str(error)
    finally:
        fd_restored = True
        if held is not None:
            try:
                if held.current != original: held.write(held.current, original)
                held.verify(original)
            except (ValueError, OSError):
                fd_restored = False; proof['passed'] = False
            finally:
                try: held.close(); proof['source_fd_closed'] = True
                except OSError:
                    fd_restored = False; proof['passed'] = False; proof['source_fd_closed'] = False
            proof['held_source_restored_exact'] = fd_restored
        if before is not None:
            try: proof['source_restored_exact'] = snapshot() == before and fd_restored
            except (OSError, subprocess.SubprocessError): proof['source_restored_exact'] = False
            proof['passed'] = proof['passed'] and proof['source_restored_exact']
            proof['qualification_passed'] = proof['qualification_passed'] and proof['source_restored_exact'] and proof['passed']
            proof['diagnostic_valid'] = proof['diagnostic_valid'] and proof['source_restored_exact']
            proof['causal_red_verified'] = proof['causal_red_verified'] and proof['source_restored_exact']
        save()
    return 0 if proof['passed'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
