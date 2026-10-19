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

SECONDARY_FIXTURE = 'crates/marmot-app/src/runtime/account_worker/tests/secondary_retry_scheduler_tests.rs'
SECONDARY_CASES = {
    'secondary-deferred': 'runtime::account_worker::tests::secondary_retry_scheduler_tests::overdue_secondary_groups_service_durable_send_after_deferred_predecessors',
    'secondary-buffered': 'runtime::account_worker::tests::secondary_retry_scheduler_tests::overdue_secondary_groups_service_durable_send_after_buffered_predecessors',
}
SECONDARY_ASSERTION = '.expect("the held admission gate makes the durable drain retry");'
SECONDARY_MARKER = 'secondary-retry-control '
SECONDARY_NUMBERS = {'deferred_count', 'drain_count', 'pass_count', 'turn_count', 'predecessor_command_count'}
SECONDARY_TURN_BOOLEANS = {'yielded', 'due', 'owed', 'retry_ready'}
SECONDARY_TURN_NUMBERS = {'pending', 'buffered'}


def secondary_scheduler_oracle(output, case, fixture, expect_failure):
    import json
    if case not in SECONDARY_CASES or fixture.count(SECONDARY_ASSERTION) != 1:
        raise ValueError('Exact secondary case and original timeout assertion required')
    name = SECONDARY_CASES[case]
    line = fixture[:fixture.index(SECONDARY_ASSERTION)].count('\n') + 1
    counts = re.findall(r'test result: (ok|FAILED)\. (\d+) passed; (\d+) failed; (\d+) ignored', output)
    expected = [('FAILED', '0', '1', '0')] if expect_failure else [('ok', '1', '0', '0')]
    statuses = re.findall(r'^test ' + re.escape(name) + r'\s+\.\.\.\s+(ok|FAILED)\s*$', output, re.M)
    named = statuses == (['FAILED'] if expect_failure else ['ok'])
    compiler = re.findall(r'(?m)^error(?:\[E[0-9]+\])?: (?!test failed(?:,|$)|test run failed\r?$)[^\n]*', output)
    panic_count = output.count('panicked at ')
    panic = re.search(r"(?m)^[ \t]{0,8}thread '" + re.escape(name) + r"'(?: \(\d+\))? panicked at "
                      + re.escape(SECONDARY_FIXTURE) + ':' + str(line) + r':\d+:\r?\n'
                      + r'[ \t]{0,8}the held admission gate makes the durable drain retry(?:: Elapsed\(\(\)\))?[ \t]*\r?$', output)
    own = panic is not None
    markers = []
    valid = True
    def unique(pairs):
        value = {}
        for key, item in pairs:
            if key in value:
                raise ValueError('duplicate-field')
            value[key] = item
        return value
    for raw in output.splitlines():
        if SECONDARY_MARKER not in raw:
            continue
        match = re.fullmatch(r'[ \t]*' + re.escape(SECONDARY_MARKER) + r'(\{[^\r\n]*\})[ \t]*', raw)
        try:
            if match is None or len(raw) > 4096:
                raise ValueError('marker-envelope')
            value = json.loads(match[1], object_pairs_hook=unique)
            if not isinstance(value, dict) or set(value) != SECONDARY_NUMBERS | {'last_turn'}:
                raise ValueError('marker-keys')
            def number(item):
                return type(item) is int and 0 <= item <= 2**64 - 1
            if not all(number(value[key]) for key in SECONDARY_NUMBERS):
                raise ValueError('marker-counts')
            if value['deferred_count'] != (2 if case == 'secondary-deferred' else 0):
                raise ValueError('marker-case')
            turn = value['last_turn']
            if turn is not None:
                if type(turn) is not dict or set(turn) != SECONDARY_TURN_BOOLEANS | SECONDARY_TURN_NUMBERS:
                    raise ValueError('marker-turn-keys')
                if not all(type(turn[key]) is bool for key in SECONDARY_TURN_BOOLEANS):
                    raise ValueError('marker-turn-booleans')
                if not all(number(turn[key]) for key in SECONDARY_TURN_NUMBERS):
                    raise ValueError('marker-turn-numbers')
            if (turn is None) != (value['turn_count'] == 0):
                raise ValueError('marker-turn-presence')
            markers.append(value)
        except (ValueError, TypeError):
            valid = False
    marker_complete = valid and len(markers) == 1
    marker_before_panic = bool(marker_complete and panic and output.index(SECONDARY_MARKER) < panic.start())
    evidence = (counts == expected and named and not compiler
                and ((panic_count == 1 and own and marker_before_panic)
                     if expect_failure else panic_count == 0))
    return {'expected_test': name, 'actual_one_named_body': named, 'compiler_error_count': len(compiler),
            'panic_header_count': panic_count, 'own_timeout_assertion_observed': own,
            'timeout_marker_before_panic': marker_before_panic,
            'trusted_source_line': line, 'timeout_marker_complete': marker_complete,
            'timeout_observation': markers[0] if marker_complete else None,
            'evidence_passed': evidence}

CANCEL_MAINTENANCE_FIXTURE = 'crates/marmot-app/src/runtime/device_linking.rs'
CANCEL_MAINTENANCE_NAME = 'runtime::device_linking::tests::device_linking_original_sdk_cancel_after_real_maintenance_retires_owned_invite'
CANCEL_MAINTENANCE_MARKER = 'cancel-maintenance-control '
CANCEL_MAINTENANCE_FIELDS = {'wrapped_owned', 'same_retired_owned', 'recipient_purpose_unchanged', 'real_maintenance_completed'}
CANCEL_MAINTENANCE_CHAIN = '''                    workers
                        .a
                        .cancel_device_linking("test", &a_scope)
                        .await
                        .unwrap();
                    runtime_c.shutdown_and_close().await.unwrap();'''
CANCEL_MAINTENANCE_MESSAGE = 'called `Result::unwrap()` on an `Err` value: Owner(Verifier(StaleFlow))'


def cancel_maintenance_oracle(output, fixture, expect_failure=True):
    import json
    if fixture.count(CANCEL_MAINTENANCE_MARKER) != 1:
        raise ValueError('Exact negative-maintenance fixture marker required')
    start = fixture.index(CANCEL_MAINTENANCE_MARKER)
    following = fixture[start:]
    if CANCEL_MAINTENANCE_CHAIN not in following:
        raise ValueError('Original manager cancel/unwrap chain must remain unchanged')
    position = start + following.index(CANCEL_MAINTENANCE_CHAIN)
    line = fixture[:position + CANCEL_MAINTENANCE_CHAIN.index('.unwrap();')].count('\n') + 1
    counts = re.findall(r'test result: (ok|FAILED)\. (\d+) passed; (\d+) failed; (\d+) ignored', output)
    statuses = re.findall(r'(?m)^test ' + re.escape(CANCEL_MAINTENANCE_NAME) + r'[ \t]+\.\.\.[ \t]+(ok|FAILED)[ \t]*\r?$', output)
    compiler = re.findall(r'(?m)^error(?:\[E[0-9]+\])?: (?!test failed(?:,|$)|test run failed\r?$)[^\n]*', output)
    panic = re.search(r"(?m)^[ \t]{0,8}thread '" + re.escape(CANCEL_MAINTENANCE_NAME)
                      + r"'(?: \(\d+\))? panicked at " + re.escape(CANCEL_MAINTENANCE_FIXTURE)
                      + ':' + str(line) + r':\d+:\r?\n[ \t]{0,8}'
                      + re.escape(CANCEL_MAINTENANCE_MESSAGE) + r'[ \t]*\r?$', output)
    markers = []
    valid = True
    def unique(pairs):
        value = {}
        for key, item in pairs:
            if key in value:
                raise ValueError('duplicate-field')
            value[key] = item
        return value
    for raw in output.splitlines():
        if CANCEL_MAINTENANCE_MARKER not in raw:
            continue
        match = re.fullmatch(r'[ \t]{0,8}' + re.escape(CANCEL_MAINTENANCE_MARKER) + r'(\{[^\r\n]*\})[ \t]{0,8}', raw)
        try:
            if match is None or len(raw) > 4096:
                raise ValueError('marker-envelope')
            value = json.loads(match[1], object_pairs_hook=unique)
            if type(value) is not dict or set(value) != CANCEL_MAINTENANCE_FIELDS or not all(item is True for item in value.values()):
                raise ValueError('marker-fields')
            markers.append(value)
        except (ValueError, TypeError):
            valid = False
    closed = valid and len(markers) == 1
    named = statuses == ['FAILED' if expect_failure else 'ok']
    own = bool(panic and output.count('panicked at ') == 1)
    prior = bool(closed and panic and output.index(CANCEL_MAINTENANCE_MARKER) < panic.start())
    return {'expected_test': CANCEL_MAINTENANCE_NAME, 'trusted_source_line': line,
            'actual_one_named_body': named, 'compiler_error_count': len(compiler),
            'panic_header_count': output.count('panicked at '),
            'own_cancel_stale_flow_observed': own, 'prerequisite_marker_complete': closed,
            'prerequisites_before_cancel_panic': prior,
            'prerequisite_observation': markers[0] if closed else None,
            'evidence_passed': bool(named and not compiler and closed
                and (counts == [('FAILED', '0', '1', '0')] and own and prior if expect_failure
                     else counts == [('ok', '1', '0', '0')] and output.count('panicked at ') == 0))}


class ExactCancellationMutation:
    """Fixed original inode custody; refuse parent/leaf replacement before writes."""
    def __init__(self, path):
        import os, stat
        from pathlib import Path
        self.os = os
        self.path = Path(path).absolute()
        self.parents = []
        for parent in reversed(self.path.parents):
            value = parent.lstat()
            if not stat.S_ISDIR(value.st_mode) or parent.resolve() != parent:
                raise ValueError('mutation-parent-layout')
            self.parents.append((parent, value.st_dev, value.st_ino))
        self.parent_fd = os.open(self.path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            self.fd = os.open(self.path.name, os.O_RDWR | os.O_NOFOLLOW, dir_fd=self.parent_fd)
            value = os.fstat(self.fd)
            if not stat.S_ISREG(value.st_mode) or value.st_nlink != 1:
                raise ValueError('mutation-leaf-layout')
            self.identity = (value.st_dev, value.st_ino, stat.S_IMODE(value.st_mode))
            self.check()
        except BaseException:
            if hasattr(self, 'fd'): os.close(self.fd)
            os.close(self.parent_fd)
            raise
    def check(self):
        import stat
        for parent, device, inode in self.parents:
            value = parent.lstat()
            if not stat.S_ISDIR(value.st_mode) or (value.st_dev, value.st_ino) != (device, inode):
                raise ValueError('mutation-parent-changed')
        leaf = self.os.stat(self.path.name, dir_fd=self.parent_fd, follow_symlinks=False)
        descriptor = self.os.fstat(self.fd)
        if not stat.S_ISREG(leaf.st_mode) or leaf.st_nlink != 1 or descriptor.st_nlink != 1:
            raise ValueError('mutation-leaf-changed')
        if (leaf.st_dev, leaf.st_ino, stat.S_IMODE(leaf.st_mode)) != self.identity:
            raise ValueError('mutation-leaf-changed')
        if (descriptor.st_dev, descriptor.st_ino, stat.S_IMODE(descriptor.st_mode)) != self.identity:
            raise ValueError('mutation-descriptor-changed')
    def write(self, content):
        self.check()
        self.os.lseek(self.fd, 0, self.os.SEEK_SET)
        view = memoryview(content)
        while view:
            count = self.os.write(self.fd, view)
            if count <= 0: raise OSError('mutation-write')
            view = view[count:]
        self.os.ftruncate(self.fd, len(content))
        self.os.fsync(self.fd)
        self.check()
    def close(self):
        self.os.close(self.fd)
        self.os.close(self.parent_fd)


SECONDARY_PREFIX_INSERT = 'pending.push_back(AccountWorkerCommand::LocalSubmissionFence);'
SECONDARY_PREFIX_OMISSION = '/* finite-predecessor barrier omitted */'


def secondary_prefix_omission(source):
    if source.count(SECONDARY_PREFIX_INSERT) != 1:
        raise ValueError('Exact unique finite-predecessor insertion required')
    if SECONDARY_PREFIX_OMISSION in source:
        raise ValueError('Finite-predecessor omission already present')
    return source.replace(SECONDARY_PREFIX_INSERT, SECONDARY_PREFIX_OMISSION)


REAL_GUARD_NAME = 'runtime::device_linking::tests::device_linking_foreign_guard_cannot_cancel_real_guarded_same_group_admission'
REAL_GUARD_EXPECT = 'foreign negative guard must not revoke the real original guarded admission'
REAL_GUARD_CHECK = """        if admission.anchor.group_id != *group
            || !admission
                .guard
                .as_ref()
                .is_some_and(|guard| Arc::ptr_eq(guard, expected))
        {"""
REAL_GUARD_OMISSION = '        if admission.anchor.group_id != *group {'
REAL_GUARD_FIELDS = {'selected_original', 'current_guard_pointer', 'original_live', 'actual_round_present'}


def real_guard_oracle(output, fixture, expect_failure):
    import json
    if type(expect_failure) is not bool:
        raise ValueError('real-guard-phase')
    if fixture.count('"' + REAL_GUARD_EXPECT + '"') != 1:
        raise ValueError('real-guard-source-expect')
    literal = fixture.index('"' + REAL_GUARD_EXPECT + '"')
    call = fixture.rfind('.expect', 0, literal)
    if call < 0 or literal - call > 256:
        raise ValueError('real-guard-source-call')
    line = fixture[:call].count('\n') + 1
    prefixes = ('cancel-real-guard-control ', 'cancel-real-guard-result ')
    observations = [[], []]
    positions = [[], []]
    invalid = len(output) > 16 * 1024 * 1024
    def unique(pairs):
        value = {}
        for key, item in pairs:
            if key in value: raise ValueError('duplicate-field')
            value[key] = item
        return value
    for ordinal, raw in enumerate(output.splitlines()):
        for index, prefix in enumerate(prefixes):
            if prefix not in raw: continue
            try:
                match = re.fullmatch(r'[ \t]{0,8}' + re.escape(prefix) + r'(\{[^\r\n]*\})[ \t]{0,8}', raw)
                if match is None or len(raw) > 4096: raise ValueError('envelope')
                value = json.loads(match[1], object_pairs_hook=unique)
                expected = REAL_GUARD_FIELDS if index == 0 else {'foreign_cancel_returned_ok'}
                if type(value) is not dict or set(value) != expected or any(type(item) is not bool for item in value.values()):
                    raise ValueError('fields')
                if index == 0 and not all(value.values()): raise ValueError('prerequisites')
                observations[index].append(value); positions[index].append(ordinal)
            except (ValueError, TypeError): invalid = True
    complete = not invalid and all(len(value) == 1 for value in observations)
    ordered = complete and positions[0][0] < positions[1][0]
    expected_result = complete and observations[1][0]['foreign_cancel_returned_ok'] is expect_failure
    counts = re.findall(r'test result: (ok|FAILED)\. (\d+) passed; (\d+) failed; (\d+) ignored', output)
    statuses = re.findall(r'(?m)^test ' + re.escape(REAL_GUARD_NAME) + r'[ \t]+\.\.\.[ \t]+(ok|FAILED)[ \t]*\r?$', output)
    compiler = re.findall(r'(?m)^error(?:\[E[0-9]+\])?: (?!test failed(?:,|$)|test run failed\r?$)[^\n]*', output)
    panic_count = output.count('panicked at ')
    panic = re.search(r"(?m)^[ \t]{0,8}thread '" + re.escape(REAL_GUARD_NAME)
        + r"'(?: \(\d+\))? panicked at " + re.escape(CANCEL_MAINTENANCE_FIXTURE)
        + ':' + str(line) + r':\d+:\r?\n[ \t]{0,8}'
        + re.escape(REAL_GUARD_EXPECT + ': Gate(NoLiveVerifier)') + r'[ \t]*\r?$', output)
    before_panic = bool(ordered and panic and output.index(prefixes[1]) < panic.start())
    own = bool(panic and panic_count == 1)
    named = statuses == ['FAILED' if expect_failure else 'ok']
    expected_counts = [('FAILED', '0', '1', '0')] if expect_failure else [('ok', '1', '0', '0')]
    passed = (ordered and expected_result and named and counts == expected_counts and not compiler
              and (own and before_panic if expect_failure else panic_count == 0))
    return {'expected_test': REAL_GUARD_NAME, 'trusted_source_line': line,
            'actual_one_named_body': named, 'compiler_error_count': len(compiler),
            'panic_header_count': panic_count, 'prerequisite_marker_complete': complete,
            'prerequisites_before_result': bool(ordered),
            'foreign_cancel_returned_ok': observations[1][0]['foreign_cancel_returned_ok'] if complete else None,
            'own_guard_rejection_panic': own, 'markers_before_own_panic': before_panic,
            'evidence_passed': bool(passed)}


LATE_FIRST_NAME = 'runtime::device_linking::tests::device_linking_first_old_cancel_after_newer_terminal_does_not_touch_current_gate'
LATE_FIRST_ASSERT = 'late first cancellation must reject old scope without touching the newer gate'
LATE_FIRST_PREREQS = {'successful_reply_abandoned', 'same_owned_retired', 'old_slot_unrevoked', 'newer_reservation_terminal'}
LATE_FIRST_RESULT = {'old_acknowledged', 'old_stale_rejected', 'current_revision_unchanged', 'owned_runtimes_closed'}


def late_first_revoke_oracle(output, fixture):
    expect_failure = True
    import json
    if type(expect_failure) is not bool:
        raise ValueError('real-guard-phase')
    if fixture.count('"' + LATE_FIRST_ASSERT + '"') != 1:
        raise ValueError('real-guard-source-expect')
    literal = fixture.index('"' + LATE_FIRST_ASSERT + '"')
    call = fixture.rfind('assert!(', 0, literal)
    if call < 0 or literal - call > 256:
        raise ValueError('real-guard-source-call')
    line = fixture[:call].count('\n') + 1
    prefixes = ('cancel-late-first-prerequisites ', 'cancel-late-first-result ')
    observations = [[], []]
    positions = [[], []]
    invalid = len(output) > 16 * 1024 * 1024
    def unique(pairs):
        value = {}
        for key, item in pairs:
            if key in value: raise ValueError('duplicate-field')
            value[key] = item
        return value
    for ordinal, raw in enumerate(output.splitlines()):
        for index, prefix in enumerate(prefixes):
            if prefix not in raw: continue
            try:
                match = re.fullmatch(r'[ \t]{0,8}' + re.escape(prefix) + r'(\{[^\r\n]*\})[ \t]{0,8}', raw)
                if match is None or len(raw) > 4096: raise ValueError('envelope')
                value = json.loads(match[1], object_pairs_hook=unique)
                expected = LATE_FIRST_PREREQS if index == 0 else LATE_FIRST_RESULT
                if type(value) is not dict or set(value) != expected or any(type(item) is not bool for item in value.values()):
                    raise ValueError('fields')
                if index == 0 and not all(value.values()): raise ValueError('prerequisites')
                observations[index].append(value); positions[index].append(ordinal)
            except (ValueError, TypeError): invalid = True
    complete = not invalid and all(len(value) == 1 for value in observations)
    ordered = complete and positions[0][0] < positions[1][0]
    expected_result = complete and observations[1][0] == {'old_acknowledged':True, 'old_stale_rejected':False, 'current_revision_unchanged':False, 'owned_runtimes_closed':True}
    counts = re.findall(r'test result: (ok|FAILED)\. (\d+) passed; (\d+) failed; (\d+) ignored', output)
    statuses = re.findall(r'(?m)^test ' + re.escape(LATE_FIRST_NAME) + r'[ \t]+\.\.\.[ \t]+(ok|FAILED)[ \t]*\r?$', output)
    compiler = re.findall(r'(?m)^error(?:\[E[0-9]+\])?: (?!test failed(?:,|$)|test run failed\r?$)[^\n]*', output)
    panic_count = output.count('panicked at ')
    panic = re.search(r"(?m)^[ \t]{0,8}thread '" + re.escape(LATE_FIRST_NAME)
        + r"'(?: \(\d+\))? panicked at " + re.escape(CANCEL_MAINTENANCE_FIXTURE)
        + ':' + str(line) + r':\d+:\r?\n[ \t]{0,8}'
        + re.escape(LATE_FIRST_ASSERT) + r'[ \t]*\r?$', output)
    before_panic = bool(ordered and panic and output.index(prefixes[1]) < panic.start())
    own = bool(panic and panic_count == 1)
    named = statuses == ['FAILED' if expect_failure else 'ok']
    expected_counts = [('FAILED', '0', '1', '0')] if expect_failure else [('ok', '1', '0', '0')]
    passed = (ordered and expected_result and named and counts == expected_counts and not compiler
              and (own and before_panic if expect_failure else panic_count == 0))
    return {'expected_test': LATE_FIRST_NAME, 'trusted_source_line': line,
            'actual_one_named_body': named, 'compiler_error_count': len(compiler),
            'panic_header_count': panic_count, 'prerequisite_marker_complete': complete,
            'prerequisites_before_result': bool(ordered),
            'late_first_observation': observations[1][0] if complete else None,
            'own_late_rejection_assertion': own, 'markers_before_own_panic': before_panic,
            'evidence_passed': bool(passed)}


def late_first_fixed_oracle(output, fixture, expect_failure):
    import json
    if type(expect_failure) is not bool:
        raise ValueError('real-guard-phase')
    if fixture.count('"' + LATE_FIRST_ASSERT + '"') != 1:
        raise ValueError('real-guard-source-expect')
    literal = fixture.index('"' + LATE_FIRST_ASSERT + '"')
    call = fixture.rfind('assert!(', 0, literal)
    if call < 0 or literal - call > 256:
        raise ValueError('real-guard-source-call')
    line = fixture[:call].count('\n') + 1
    prefixes = ('cancel-late-first-prerequisites ', 'cancel-late-first-result ')
    observations = [[], []]
    positions = [[], []]
    invalid = len(output) > 16 * 1024 * 1024
    def unique(pairs):
        value = {}
        for key, item in pairs:
            if key in value: raise ValueError('duplicate-field')
            value[key] = item
        return value
    for ordinal, raw in enumerate(output.splitlines()):
        for index, prefix in enumerate(prefixes):
            if prefix not in raw: continue
            try:
                match = re.fullmatch(r'[ \t]{0,8}' + re.escape(prefix) + r'(\{[^\r\n]*\})[ \t]{0,8}', raw)
                if match is None or len(raw) > 4096: raise ValueError('envelope')
                value = json.loads(match[1], object_pairs_hook=unique)
                expected = LATE_FIRST_PREREQS if index == 0 else LATE_FIRST_RESULT
                if type(value) is not dict or set(value) != expected or any(type(item) is not bool for item in value.values()):
                    raise ValueError('fields')
                if index == 0 and not all(value.values()): raise ValueError('prerequisites')
                observations[index].append(value); positions[index].append(ordinal)
            except (ValueError, TypeError): invalid = True
    complete = not invalid and all(len(value) == 1 for value in observations)
    ordered = complete and positions[0][0] < positions[1][0]
    expected_result = complete and observations[1][0] == {'old_acknowledged':False, 'old_stale_rejected':True, 'current_revision_unchanged':not expect_failure, 'owned_runtimes_closed':True}
    counts = re.findall(r'test result: (ok|FAILED)\. (\d+) passed; (\d+) failed; (\d+) ignored', output)
    statuses = re.findall(r'(?m)^test ' + re.escape(LATE_FIRST_NAME) + r'[ \t]+\.\.\.[ \t]+(ok|FAILED)[ \t]*\r?$', output)
    compiler = re.findall(r'(?m)^error(?:\[E[0-9]+\])?: (?!test failed(?:,|$)|test run failed\r?$)[^\n]*', output)
    panic_count = output.count('panicked at ')
    panic = re.search(r"(?m)^[ \t]{0,8}thread '" + re.escape(LATE_FIRST_NAME)
        + r"'(?: \(\d+\))? panicked at " + re.escape(CANCEL_MAINTENANCE_FIXTURE)
        + ':' + str(line) + r':\d+:\r?\n[ \t]{0,8}'
        + re.escape(LATE_FIRST_ASSERT) + r'[ \t]*\r?$', output)
    before_panic = bool(ordered and panic and output.index(prefixes[1]) < panic.start())
    own = bool(panic and panic_count == 1)
    named = statuses == ['FAILED' if expect_failure else 'ok']
    expected_counts = [('FAILED', '0', '1', '0')] if expect_failure else [('ok', '1', '0', '0')]
    passed = (ordered and expected_result and named and counts == expected_counts and not compiler
              and (own and before_panic if expect_failure else panic_count == 0))
    return {'expected_test': LATE_FIRST_NAME, 'trusted_source_line': line,
            'actual_one_named_body': named, 'compiler_error_count': len(compiler),
            'panic_header_count': panic_count, 'prerequisite_marker_complete': complete,
            'prerequisites_before_result': bool(ordered),
            'late_first_observation': observations[1][0] if complete else None,
            'own_late_rejection_assertion': own, 'markers_before_own_panic': before_panic,
            'evidence_passed': bool(passed)}


# An exact inverse of only the install-revision counter protection. Preserve CAS,
# returned-fence binding, actor fallback, and all fixture ownership prerequisites.
def late_first_counter_inverse(source):
    pattern = (r'(?m)^(?P<indent>[ ]{8,32})active\.negative_invite_revision[ \t\r\n]*=[ \t\r\n]*'
               r'active[ \t\r\n]*\.original_invite_revision[ \t\r\n]*\.as_ref\(\)[ \t\r\n]*'
               r'\.and_then\(\|original\|[ \t\r\n]*gate\.cancel_original_revision\(original\)\);')
    matches = list(re.finditer(pattern, source))
    if len(matches) != 1:
        raise ValueError('exact-install-revision-counter-anchor')
    match = matches[0]
    old = match[0]
    new = match['indent'] + 'gate.cancel();\n' + old
    return old, new


# Manual-only canonical membership cleanup counterfactual. No historical case changes.
CANONICAL_CASES = {'canonical-leaf-cleanup-default', 'canonical-leaf-cleanup-experimental'}
CANONICAL_FIXTURE = 'crates/marmot-app/src/tests/canonical_membership.rs'
CANONICAL_SIBLINGS = [
    'tests::canonical_membership::sibling_selfremove_preserves_surviving_app_device_after_reopen',
    'tests::canonical_membership::own_group_command_observes_retained_sibling_departure',
]
CANONICAL_NAMES = CANONICAL_SIBLINGS + [
    'tests::canonical_membership::real_departure_then_disband_projects_after_mls_deletion',
]
CANONICAL_LABEL = "the public command must observe the author's leaf cleanup"
CANONICAL_CLEANUP = """                self.app.remove_group_push_tokens_for_leaves(
                    &self.state.label,
                    &hex::encode(group_id.as_slice()),
                    leaves,
                    departed_members,
                )?;"""
CANONICAL_EMPTY = CANONICAL_CLEANUP.replace('                    leaves,', '                    &leaves[..0],')


def canonical_leaf_assertion_line(fixture):
    if fixture.count('"' + CANONICAL_LABEL + '"') != 1:
        raise ValueError('canonical-one-owned-cleanup-label')
    label = fixture.index('"' + CANONICAL_LABEL + '"')
    call = fixture.rfind('assert_eq!(', 0, label)
    if call < 0 or label - call > 256 or 'assert_eq!(author_tokens.len(),1,' not in re.sub(r'\s+', '', fixture[call:label]):
        raise ValueError('canonical-original-token-count-assertion')
    for name in CANONICAL_NAMES:
        if fixture.count('async fn ' + name.rsplit('::', 1)[1] + '(') != 1:
            raise ValueError('canonical-original-three-bodies')
    return fixture[:call].count('\n') + 1


def canonical_leaf_oracle(output, fixture, phase):
    from upstream_avatar_ready_turn_chain import compiler_diagnostics
    if phase not in {'baseline', 'mutant', 'restored-control'}:
        raise ValueError('canonical-owned-phase')
    site = canonical_leaf_assertion_line(fixture)
    selected = CANONICAL_SIBLINGS if phase == 'mutant' else CANONICAL_NAMES
    failed = phase == 'mutant'
    text = re.sub(r'\x1b\[[0-?]*[ -/]*[@-~]', '', output)
    summaries = re.findall(r'^test result: (ok|FAILED)\. (\d+) passed; (\d+) failed; (\d+) ignored; (\d+) measured; (\d+) filtered out;', text, re.M)
    statuses = re.findall(r'^test ([A-Za-z0-9_:]+) \.\.\. (ok|FAILED)[ \t]*\r?$', text, re.M)
    running = re.findall(r'^running ([0-9]+) tests?[ \t]*\r?$', text, re.M)
    diagnostics = compiler_diagnostics(text.encode(), cargo_test_context=('marmot-app', '--lib'))
    compiler_zero = not diagnostics['compiler_codes'] and diagnostics['compiler_header_count'] == 0
    named = sorted(statuses) == sorted((name, 'FAILED' if failed else 'ok') for name in selected)
    counts = (len(summaries) == 1 and summaries[0][:5] == (('FAILED', '0', '2', '0', '0') if failed else ('ok', '3', '0', '0', '0')) and running == [str(len(selected))])
    headers = re.findall(r"(?m)^[ \t]{0,8}thread '([^'\r\n]+)'(?: \([0-9]+\))? panicked at ([^\r\n]+):([0-9]+):([0-9]+):\r?$", text)
    exact = []
    for name in CANONICAL_SIBLINGS:
        pattern = (r"(?m)^[ \t]{0,8}thread '" + re.escape(name) + r"'(?: \([0-9]+\))? panicked at "
                   + re.escape(CANONICAL_FIXTURE) + ':' + str(site) + r':\d+:\r?\n(?:[ \t]{0,8}\r?\n){0,2}[ \t]{0,8}'
                   + re.escape('assertion `left == right` failed: ' + CANONICAL_LABEL)
                   + r'\r?\n[ \t]{0,8}left: 2\r?\n[ \t]{0,8}right: 1[ \t]*\r?$')
        exact.append(len(re.findall(pattern, text)) == 1)
    own = (len(headers) == 2 and text.count('panicked at ') == 2 and all(exact)
           and sorted(item[0] for item in headers) == sorted(CANONICAL_SIBLINGS))
    clean = not headers and text.count('panicked at ') == 0
    return {'selected_tests': selected, 'actual_exact_named_set': named,
            'expected_original_assertion_line': site, 'compiler_diagnostics': diagnostics,
            'compiler_error_count': diagnostics['compiler_header_count'],
            'panic_header_count': text.count('panicked at '),
            'each_sibling_own_token_count_2_vs_1': own,
            'evidence_passed': bool(len(text) <= 16 * 1024 * 1024 and counts and named and compiler_zero and (own if failed else clean))}


# Positive-only worker-mode timer precedence controls. Never a mutation gate.
PEER_TIMER_CASES = {'peer-leave-timer-default', 'peer-leave-timer-experimental'}
PEER_TIMER_NAMES = [
    'tests::due_peer_leave_does_not_shorten_a_collecting_convergence_pass',
    'tests::due_peer_leave_preserves_the_outbound_fanout_retry_barrier',
]


def peer_leave_timer_control_oracle(output):
    from upstream_avatar_ready_turn_chain import compiler_diagnostics
    text = re.sub(r'\x1b\[[0-?]*[ -/]*[@-~]', '', output)
    rows = re.findall(r'^test ([A-Za-z0-9_:]+) \.\.\. (ok|FAILED)[ \t]*\r?$', text, re.M)
    summaries = re.findall(r'^test result: (ok|FAILED)\. (\d+) passed; (\d+) failed; (\d+) ignored; (\d+) measured; (\d+) filtered out;', text, re.M)
    running = re.findall(r'^running ([0-9]+) tests?[ \t]*\r?$', text, re.M)
    diagnostics = compiler_diagnostics(text.encode(), cargo_test_context=('marmot-app', '--lib'))
    named = sorted(rows) == sorted((name, 'ok') for name in PEER_TIMER_NAMES)
    counts = len(summaries) == 1 and summaries[0][:5] == ('ok', '2', '0', '0', '0') and running == ['2']
    return {'selected_tests': PEER_TIMER_NAMES, 'actual_exact_named_set': named,
            'compiler_diagnostics': diagnostics, 'compiler_error_count': diagnostics['compiler_header_count'],
            'panic_header_count': text.count('panicked at '),
            'evidence_passed': bool(len(text) <= 16 * 1024 * 1024 and named and counts
                and not diagnostics['compiler_codes'] and diagnostics['compiler_header_count'] == 0
                and text.count('panicked at ') == 0)}


# Complementary current-source actor responsiveness witness; old enrollment survivor stays historical.
AUTOMATIC_BODY_CASE = 'automatic-body-publication-pfp'


def automatic_body_pfp_oracle(output, phase, exit_code):
    from qualify_upstream_automatic_body import parse, body_green, intended_red, NAME, FILE, MESSAGE
    from upstream_avatar_ready_turn_chain import compiler_diagnostics
    if phase not in {'baseline', 'mutant', 'restored-control'}:
        raise ValueError('automatic-body-owned-phase')
    text = re.sub(r'\x1b\[[0-?]*[ -/]*[@-~]', '', output)
    # The imported parser is internal only: never export its arbitrary event/path arrays.
    internal = parse(text)
    internal['body_exit_code'] = exit_code
    failed = phase == 'mutant'
    statuses = re.findall(r'^test ([A-Za-z0-9_:]+) \.\.\. (ok|FAILED)[ \t]*\r?$', text, re.M)
    named = statuses == [(NAME, 'FAILED' if failed else 'ok')]
    running = re.findall(r'^running ([0-9]+) tests?[ \t]*\r?$', text, re.M) == ['1']
    diagnostics = compiler_diagnostics(text.encode(), cargo_test_context=('marmot-app', '--lib'))
    compiler_zero = not diagnostics['compiler_codes'] and diagnostics['compiler_header_count'] == 0
    site = internal['expected_panic']['line']
    own_pattern = (r"(?m)^[ \t]{0,8}thread '" + re.escape(NAME)
        + r"'(?: \([0-9]+\))? panicked at " + re.escape(FILE) + ':' + str(site)
        + r':([0-9]+):\r?\n(?:[ \t]{0,8}\r?\n){0,2}[ \t]{0,8}' + re.escape(MESSAGE) + r'[ \t]*\r?$')
    own_matches = list(re.finditer(own_pattern, text))
    close_marker = 'automatic-body-control stage=positive-runtime-close index=1'
    closes_before_own = len(own_matches) == 1 and text.rfind(close_marker) >= 0 and text.rfind(close_marker) < own_matches[0].start()
    own = text.count('panicked at ') == 1 and len(own_matches) == 1 and closes_before_own
    valid = intended_red(internal) if failed else body_green(internal)
    counts = None
    if all(type(internal.get(k)) is int for k in ['passed', 'failed', 'ignored']):
        counts = [internal[k] for k in ['passed', 'failed', 'ignored']]
    return {'expected_test': NAME, 'expected_panic_file': FILE, 'expected_panic_line': site,
            'actual_exact_named_body': named, 'actual_body_counts': counts,
            'ordered_body_stages_and_two_positive_closes': internal['all_prerequisites_and_two_positive_closes'],
            'responsive_while_held_when_valid': internal['responsive_while_held'],
            'own_responsiveness_assertion': own, 'two_positive_closes_before_own_assertion': closes_before_own, 'compiler_error_count': diagnostics['compiler_header_count'],
            'compiler_diagnostics': diagnostics, 'panic_header_count': text.count('panicked at '),
            'evidence_passed': bool(len(text) <= 16 * 1024 * 1024 and named and running and compiler_zero
                and valid and (own if failed else text.count('panicked at ') == 0))}


EXPLICIT_LIFECYCLE_CASES = {'explicit-sync-lifecycle-default', 'explicit-sync-lifecycle-experimental'}
EXPLICIT_PROGRESS_CASES = {'explicit-sync-progress-default', 'explicit-sync-progress-experimental'}
EXPLICIT_LIFECYCLE_NAME = 'client::sync::explicit_ready_turn_tests::explicit_sync_preserves_a_genuinely_due_peer_leave_for_its_scheduled_owner'
EXPLICIT_LIFECYCLE_FIXTURE = 'crates/marmot-app/src/client/sync/explicit_ready_turn_tests.rs'
EXPLICIT_LIFECYCLE_LABEL = 'explicit sync must preserve a genuinely due peer removal for its scheduled convergence owner'
EXPLICIT_ELIGIBILITY = '                    if !explicit_sync_ready {'
EXPLICIT_INVERSE = '                    if false && !explicit_sync_ready {'
EXPLICIT_PROGRESS_NAMES = CANONICAL_NAMES + PEER_TIMER_NAMES


def explicit_lifecycle_assertion_line(fixture):
    if fixture.count('async fn ' + EXPLICIT_LIFECYCLE_NAME.rsplit('::', 1)[1] + '(') != 1 or fixture.count(EXPLICIT_LIFECYCLE_LABEL) != 1:
        raise ValueError('explicit-lifecycle-owned-fixture')
    start = fixture.index('async fn ' + EXPLICIT_LIFECYCLE_NAME.rsplit('::', 1)[1] + '(')
    label = fixture.index(EXPLICIT_LIFECYCLE_LABEL)
    call = fixture.rfind('assert!(', start, label)
    if call < start or label - call > 1024:
        raise ValueError('explicit-lifecycle-owned-assertion')
    condition = re.sub(r'\s+', '', fixture[call:label])
    if 'sync_preserved_lifecycle&&retry_published_once' not in condition:
        raise ValueError('explicit-lifecycle-original-no-removal-condition')
    return fixture[:call].count('\n') + 1


EXPLICIT_LIFECYCLE_PRIOR_FIELDS = ('actual_signed_leave', 'no_convergence_pass', 'no_deferred_input', 'timer_already_due', 'scheduled_ready', 'pending_edge', 'members_two')
EXPLICIT_LIFECYCLE_RESULT_FIELDS = ('no_removal_events', 'timer_retained', 'pending_edge_retained', 'members_two', 'retry_published_once', 'one_member_after_retry', 'storage_closed')


def explicit_lifecycle_marker(text, prefix, fields):
    import json
    rows = []
    def unique(pairs):
        result = {}
        for key, value in pairs:
            if key in result: raise ValueError('duplicate-lifecycle-marker-key')
            result[key] = value
        return result
    for line in text.splitlines():
        if prefix not in line: continue
        match = re.fullmatch(re.escape(prefix) + r'(\{[^\r\n]{1,1024}\})', line)
        if match is None: return None
        try: value = json.loads(match[1], object_pairs_hook=unique)
        except (ValueError, TypeError): return None
        if type(value) is not dict or set(value) != set(fields) or not all(type(v) is bool for v in value.values()): return None
        rows.append(value)
    return rows[0] if len(rows) == 1 else None


def explicit_sync_lifecycle_oracle(output, fixture, phase):
    from upstream_avatar_ready_turn_chain import compiler_diagnostics
    if phase not in {'baseline', 'mutant', 'restored-control'}:
        raise ValueError('explicit-lifecycle-owned-phase')
    text = re.sub(r'\x1b\[[0-?]*[ -/]*[@-~]', '', output)
    failed = phase == 'mutant'
    site = explicit_lifecycle_assertion_line(fixture)
    summaries = re.findall(r'^test result: (ok|FAILED)\. (\d+) passed; (\d+) failed; (\d+) ignored; (\d+) measured; (\d+) filtered out;', text, re.M)
    statuses = re.findall(r'^test ([A-Za-z0-9_:]+) \.\.\. (ok|FAILED)[ \t]*\r?$', text, re.M)
    running = re.findall(r'^running ([0-9]+) tests?[ \t]*\r?$', text, re.M)
    diagnostics = compiler_diagnostics(text.encode(), cargo_test_context=('marmot-app', '--lib'))
    named = statuses == [(EXPLICIT_LIFECYCLE_NAME, 'FAILED' if failed else 'ok')]
    counts = len(summaries) == 1 and summaries[0][:5] == (('FAILED', '0', '1', '0', '0') if failed else ('ok', '1', '0', '0', '0')) and running == ['1']
    pattern = (r"(?m)^[ \t]{0,8}thread '" + EXPLICIT_LIFECYCLE_NAME + r"'(?: \([0-9]+\))? panicked at "
        + re.escape(EXPLICIT_LIFECYCLE_FIXTURE) + ':' + str(site) + r':\d+:\r?\n(?:[ \t]{0,8}\r?\n){0,2}[ \t]{0,8}'
        + re.escape(EXPLICIT_LIFECYCLE_LABEL) + r'[ \t]*\r?$')
    own_matches = list(re.finditer(pattern, text))
    own = text.count('panicked at ') == 1 and len(own_matches) == 1
    prior = explicit_lifecycle_marker(text, 'explicit-sync-lifecycle-prerequisites ', EXPLICIT_LIFECYCLE_PRIOR_FIELDS)
    result = explicit_lifecycle_marker(text, 'explicit-sync-lifecycle-result ', EXPLICIT_LIFECYCLE_RESULT_FIELDS)
    prerequisites = prior is not None and all(prior.values())
    closes = result is not None and result['one_member_after_retry'] and result['storage_closed']
    result_valid = closes and ((not result['no_removal_events'] and not result['retry_published_once']) if failed else all(result.values()))
    ordered = prerequisites and result is not None and text.index('explicit-sync-lifecycle-prerequisites ') < text.index('explicit-sync-lifecycle-result ')
    if failed: ordered = ordered and own and text.index('explicit-sync-lifecycle-result ') < own_matches[0].start()
    return {'expected_test': EXPLICIT_LIFECYCLE_NAME, 'expected_original_assertion_file': EXPLICIT_LIFECYCLE_FIXTURE,
            'expected_original_assertion_line': site, 'actual_exact_named_body': named,
            'own_no_member_removal_assertion': own, 'compiler_diagnostics': diagnostics,
            'prerequisites': prior, 'result': result, 'prerequisites_and_results_ordered': bool(ordered),
            'compiler_error_count': diagnostics['compiler_header_count'],
            'panic_header_count': text.count('panicked at '),
            'evidence_passed': bool(len(text) <= 16 * 1024 * 1024 and named and counts and not diagnostics['compiler_codes']
                and diagnostics['compiler_header_count'] == 0 and prerequisites and result_valid and ordered
                and (own if failed else text.count('panicked at ') == 0))}


def explicit_sync_progress_oracle(output):
    from upstream_avatar_ready_turn_chain import compiler_diagnostics
    text = re.sub(r'\x1b\[[0-?]*[ -/]*[@-~]', '', output)
    statuses = re.findall(r'^test ([A-Za-z0-9_:]+) \.\.\. (ok|FAILED)[ \t]*\r?$', text, re.M)
    summaries = re.findall(r'^test result: (ok|FAILED)\. (\d+) passed; (\d+) failed; (\d+) ignored; (\d+) measured; (\d+) filtered out;', text, re.M)
    running = re.findall(r'^running ([0-9]+) tests?[ \t]*\r?$', text, re.M)
    diagnostics = compiler_diagnostics(text.encode(), cargo_test_context=('marmot-app', '--lib'))
    named = sorted(statuses) == sorted((name, 'ok') for name in EXPLICIT_PROGRESS_NAMES)
    return {'selected_tests': EXPLICIT_PROGRESS_NAMES, 'actual_exact_named_set': named,
            'compiler_diagnostics': diagnostics, 'compiler_error_count': diagnostics['compiler_header_count'],
            'panic_header_count': text.count('panicked at '),
            'evidence_passed': bool(len(text) <= 16 * 1024 * 1024 and named and running == ['5']
                and len(summaries) == 1 and summaries[0][:5] == ('ok', '5', '0', '0', '0')
                and not diagnostics['compiler_codes'] and diagnostics['compiler_header_count'] == 0 and text.count('panicked at ') == 0)}


# Independent positive original integration contract, never a jitter-dependent inverse.
def explicit_sync_original_relay_positive_oracle(output):
    from upstream_avatar_ready_turn_chain import compiler_diagnostics
    name = 'relay_app_runtime_publishes_member_leave'
    text = re.sub(r'\x1b\[[0-?]*[ -/]*[@-~]', '', output)
    statuses = re.findall(r'^test ([A-Za-z0-9_:]+) \.\.\. (ok|FAILED)[ \t]*\r?$', text, re.M)
    summaries = re.findall(r'^test result: (ok|FAILED)\. (\d+) passed; (\d+) failed; (\d+) ignored; (\d+) measured; (\d+) filtered out;', text, re.M)
    running = re.findall(r'^running ([0-9]+) tests?[ \t]*\r?$', text, re.M)
    diagnostics = compiler_diagnostics(text.encode())
    named = statuses == [(name, 'ok')]
    return {'expected_test': name, 'original_relay_positive_only': True,
            'actual_exact_named_body': named, 'compiler_diagnostics': diagnostics,
            'compiler_error_count': diagnostics['compiler_header_count'], 'panic_header_count': text.count('panicked at '),
            'evidence_passed': bool(len(text) <= 16 * 1024 * 1024 and named and running == ['1']
                and len(summaries) == 1 and summaries[0][:5] == ('ok', '1', '0', '0', '0')
                and not diagnostics['compiler_codes'] and diagnostics['compiler_header_count'] == 0 and text.count('panicked at ') == 0)}
