"""Pure source transformations; runtime mutation qualification stays separate."""
import re

FIXTURE = 'crates/marmot-app/src/native_device_linking/tests/automatic_pairing_acceptance.rs'

AUTOMATIC = '''        entry.publication = Some(AutomaticPublication {
            kind,
            deadline: publication_deadline,
            payload_digest: input_payload_digest,
            body_context,
            task,
            outcome: None,
        });'''
SIBLING = '''        entry.publication = Some(SiblingPublication {
            proof,
            result,
            outcome: None,
            task,
        });'''


def publication_mutation_anchor(case):
    if case == 'automatic-publication':
        # The actual transport hold accepts any automatic control kind. Wait
        # AFTER installing that owned task. Keep both bounded permit pools,
        # the exact publication future, cancellation/deadline select, ACK checks
        # and actor harvest unchanged.
        old = AUTOMATIC
        wait = '''
        while !entry.publication.as_ref().expect("owned automatic publication").task.is_finished() {
            tokio::task::yield_now().await;
        }'''
    elif case == 'sibling-publication':
        # Result-before-wake and the receiver stay exactly as constructed. The
        # regression is blocking the worker after registering its owned task.
        old = SIBLING
        wait = '''
        while !entry.publication.as_ref().expect("owned sibling publication").task.is_finished() {
            tokio::task::yield_now().await;
        }'''
    else:
        raise ValueError('Unsupported publication mutation')
    return old, old + wait


def publication_mutant(source, case):
    old, new = publication_mutation_anchor(case)
    if source.count(old) != 1 or new in source:
        raise ValueError('Publication owner anchor must match exactly once')
    return source.replace(old, new, 1)


def closed_panic_facts(panics, test):
    """Export bounded classifications only; never raw panic content/identities."""
    facts = []
    for panic in panics[:4]:
        text = panic[5]
        if any(text == literal or text.startswith(literal + ': ') for literal in (
            'the actual automatic publication must be held before completion',
            'the actual automatic publication must be observed',
            'genuine sibling consent publication',
            'genuine sibling consent publication did not reach its hold',
        )):
            kind = 'hold_precondition'
        elif text == 'one blocked consent publication must not starve another approved sibling':
            kind = 'held_fairness'
        elif re.fullmatch(r'automatic pairing did not reach required phase: expected=EnrollmentComplete observed=[^\n]+', text):
            kind = 'enrollment_complete_timeout'
        else:
            kind = 'other'
        expected_file = panic[2] == FIXTURE
        # Even an attacker-controlled path/line cannot become an exported path
        # or an unbounded integer. Wrong files have no exported source line.
        raw_line = panic[3]
        line = int(raw_line) if expected_file and len(raw_line) <= 7 else None
        if line is not None and not 1 <= line <= 1000000:
            line = None
        facts.append({'expected_fixture_file': expected_file,
                      'expected_test_thread': panic[1] == test,
                      'line': line, 'message_kind': kind})
    return {'actual_panic_facts': facts,
            'actual_panic_facts_truncated': len(panics) > 4}


def publication_runtime_oracle(output, case, test, fixture):
    """Require the real named test's unique original assertion, never just text."""
    if case == 'automatic-publication':
        literal = 'panic!("automatic pairing did not reach required phase: expected={phase:?} observed={observed:?}")'
        matches = list(re.finditer(re.escape(literal), fixture))
        marker = 'automatic-enrollment-control stage=automatic-publication-held-before-completion'
        message = r'automatic pairing did not reach required phase: expected=EnrollmentComplete observed=[^\n]+'
    elif case == 'sibling-publication':
        message = 'one blocked consent publication must not starve another approved sibling'
        expression = r'assert!\(\s*result\.is_ok\(\),\s*"' + re.escape(message) + r'"\s*\);'
        matches = list(re.finditer(expression, fixture))
        marker = 'automatic-enrollment-control stage=sibling-consent-held-before-peer-progress'
        message = re.escape(message)
    else:
        raise ValueError('Unsupported publication runtime oracle')
    if len(matches) != 1:
        raise ValueError('Unique original publication assertion required')
    line = fixture[:matches[0].start()].count('\n') + 1
    panics = list(re.finditer(
        r"(?m)^[ \t]{0,8}thread '([^'\r\n]+)'(?: \(\d+\))? panicked at ([^\r\n]+):(\d+):(\d+):\r?\n[ \t]{0,8}([^\r\n]+)",
        output,
    ))
    compiler = re.findall(r'(?m)^error(?:\[E[0-9]+\])?: (?!test failed(?:,|$)|test run failed\r?$)[^\n]*', output)
    intended = (len(panics) == 1 and output.count('panicked at ') == 1
                and panics[0][1] == test and panics[0][2] == FIXTURE
                and int(panics[0][3]) == line
                and re.fullmatch(message, panics[0][5]) is not None
                and output.count(marker) == 1
                and output.index(marker) < panics[0].start()
                and not compiler)
    return {'intended_runtime_assertion': bool(intended),
            'expected_panic_file': FIXTURE, 'expected_panic_line': line,
            'compiler_error_count': len(compiler),
            'panic_header_count': output.count('panicked at '),
            'parsed_panic_header_count': len(panics),
            'unsupported_panic_format': output.count('panicked at ') != len(panics),
            **closed_panic_facts(panics, test)}


# Separate exact recipient timer-frontier evidence; old publication oracles unchanged.
PRIORITY_FIXTURE = 'crates/marmot-app/src/native_device_linking/tests/recipient_retry_priority_acceptance.rs'
PRIORITY_NAME = 'native_device_linking::automatic_pairing_acceptance::recipient_retry_priority_acceptance::older_recipient_proof_retry_precedes_later_consent_retry'
PRIORITY_MESSAGE = 'older real recipient proof retry must precede a later Consent retry'
PRIORITY_FACT_NAMES = ('source_proof_held', 'real_frontier', 'both_due_unchanged', 'next_real_ack',
              'source_dispatch_ack_after_release', 'exact_peer_proof_authenticated', 'enrollment_complete',
              'source_cancelled', 'recipient_cancelled', 'probe_custody_released')


def retry_priority_oracle(output, phase, fixture, capture_complete=False):
    if phase not in {'baseline', 'mutant', 'restored-control'}:
        raise ValueError('unsupported-phase')
    capture_complete = capture_complete if type(capture_complete) is bool else False
    assertion = list(re.finditer(r'assert!\(\s*selected_proof,\s*"' + re.escape(PRIORITY_MESSAGE) + r'"\s*\);', fixture))
    if len(assertion) != 1 or '#[ignore' in fixture:
        raise ValueError('unique-nonignored-original-ordering-assertion-required')
    line = fixture[:assertion[0].start()].count('\n') + 1
    marker = 'recipient-retry-priority '
    fields = ' '.join(name + r'=(true|false)' for name in PRIORITY_FACT_NAMES)
    grammar = (r'[ \t]{0,8}' + marker + fields + r' selected_proof=(true|false)'
               + r' runtime_closes=([0-9]+) storage_closes=([0-9]+) planes_shutdown=([0-9]+)'
               + r' relay_closed=(true|false) attempt_completed=(true|false)[ \t]{0,8}')
    rows = [text for text in output.splitlines() if marker in text]
    match = re.fullmatch(grammar, rows[0]) if len(rows) == 1 and len(rows[0]) <= 2048 else None
    prerequisites = bool(match and all(match[n] == 'true' for n in range(1, 11))
                         and all(match[n] == '3' for n in range(12, 15)) and match[15] == match[16] == 'true')
    selected = None if not match else match[11] == 'true'
    summaries = re.findall(r'Summary\s+\[[^\]]+\]\s+(\d+)(?:/\d+)?\s+tests? run:\s*([^\r\n]*)', output)
    counts = None
    if len(summaries) == 1:
        tail = summaries[0][1]
        def count(label):
            found = re.findall(r'([0-9]+) ' + label + r'\b', tail)
            if len(found) > 1:
                return None
            if not found:
                return 0
            if len(found[0]) > 20 or (len(found[0]) > 1 and found[0].startswith('0')):
                return None
            value = int(found[0])
            return value if value <= 2**64 - 1 else None
        if summaries[0][0] == '1':
            passed, failed = count('passed'), count('failed')
            if passed is not None and failed is not None and passed <= 1 and failed <= 1 and passed + failed == 1:
                counts = [1, passed, failed]
    panics = list(re.finditer(r"(?m)^[ \t]{0,8}thread '([^'\r\n]+)'(?: \(\d+\))? panicked at ([^\r\n]+):(\d+):(\d+):\r?\n[ \t]{0,8}([^\r\n]+)", output))
    compiler = re.findall(r'(?m)^error(?:\[E[0-9]+\])?: (?!test failed(?:,|$)|test run failed\r?$)[^\n]*', output)
    exact_panic = bool(len(panics) == output.count('panicked at ') == 1
                       and panics[0][1] == PRIORITY_NAME and panics[0][2] == PRIORITY_FIXTURE
                       and panics[0][3] == str(line) and panics[0][5] == PRIORITY_MESSAGE
                       and match and output.index(marker) < panics[0].start())
    named = re.findall(r'(?m)^[ \t]{0,8}(PASS|FAIL)[ \t]+\[[^\]\r\n]+\][ \t]+(?:\([ \t]{0,8}1/1\)[ \t]+)?marmot-app[ \t]+' + re.escape(PRIORITY_NAME) + r'[ \t]{0,8}\r?$', output)
    named_exact = len(named) == 1 and named[0] == ('FAIL' if phase == 'mutant' else 'PASS')
    good = bool(named_exact and capture_complete and prerequisites and not compiler and (
        (phase == 'mutant' and selected is False and counts == [1, 0, 1] and exact_panic)
        or (phase != 'mutant' and selected is True and counts == [1, 1, 0] and not output.count('panicked at '))))
    return {'phase': phase, 'summary_counts': counts, 'prerequisites_and_closure_known': prerequisites,
            'selected_proof': selected, 'exact_intended_panic': exact_panic,
            'expected_file': PRIORITY_FIXTURE, 'expected_line': line, 'compiler_error_count': len(compiler), 'named_case_observed': named_exact,
            'panic_header_count': output.count('panicked at '),
            'parsed_panic_header_count': len(panics),
            'unsupported_panic_format': output.count('panicked at ') != len(panics),
            'evidence_passed': good, 'product_qualification': False}
