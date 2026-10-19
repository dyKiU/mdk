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
        # Block only automatic handshakes AFTER installing their actual owned
        # task. Keep both bounded permit pools, the exact publication future,
        # cancellation/deadline select, ACK checks and actor harvest unchanged.
        old = AUTOMATIC
        wait = '''
        if matches!(
            kind,
            AccountSharingControl::Request | AccountSharingControl::Consent
        ) {
            while !entry.publication.as_ref().expect("owned automatic publication").task.is_finished() {
                tokio::task::yield_now().await;
            }
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
        r"(?m)^thread '([^']+)'(?: \(\d+\))? panicked at ([^\n]+):(\d+):(\d+):\n([^\n]+)",
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
            **closed_panic_facts(panics, test)}
