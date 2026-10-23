"""Closed current-factory runtime oracle; no process, source mutation or CI actions.

The caller must obtain the ENTIRE compiler and XCTest issue inventories from the
actual result bundle and bind them to the exact app/SDK source cohort. This
module does not turn a log marker or a caller's truncated inventory into proof.
"""
import hashlib
import json
import re

PREFIX = 'WN_FACTORY_SEMANTIC_V1 '
MAX_OUTPUT_BYTES = 16 * 1024 * 1024
MAX_MARKER_LINE_BYTES = 4096
SELECTOR = 'GenuineAutomaticHostFactoryTests/testExistingRosterWNPAIR2RequiresSiblingApprovalAndSharesHistory'
FIELDS = frozenset(('schema', 'stage', 'cause', 'bootstrap', 'roster_ready',
                    'scanner_fresh', 'histories_committed', 'missing_chats_absent'))
BOOLS = ('roster_ready', 'scanner_fresh', 'histories_committed', 'missing_chats_absent')
COUNTS = ('totalTestCount', 'passedTests', 'failedTests', 'skippedTests')


def require(value, label):
    if not value:
        raise ValueError(label)


def decode(text):
    require(type(text) is str, 'literal-runtime-output-required')
    require(len(text) <= MAX_OUTPUT_BYTES and len(text.encode('utf-8')) <= MAX_OUTPUT_BYTES,
            'bounded-actual-native-output-required')
    records = []
    for line in text.splitlines():
        if PREFIX not in line:
            continue
        require(len(records) < 3, 'at-most-three-source-owned-markers-required')
        require(len(line) <= MAX_MARKER_LINE_BYTES and len(line.encode('utf-8')) <= MAX_MARKER_LINE_BYTES,
                'bounded-source-owned-marker-line-required')
        require(line.count(PREFIX) == 1, 'one-marker-per-line')
        payload = line.split(PREFIX, 1)[1]
        # JSON duplicate keys must not silently replace a false prerequisite.
        def unique(pairs):
            result = {}
            for key, value in pairs:
                require(key not in result, 'duplicate-probe-field')
                result[key] = value
            return result
        value = json.loads(payload, object_pairs_hook=unique)
        require(type(value) is dict and set(value) == FIELDS, 'closed-probe-fields')
        require(type(value['schema']) is int and value['schema'] == 1, 'typed-schema')
        require(all(type(value[key]) is bool for key in BOOLS), 'typed-prerequisites')
        require(value['stage'] in ('begin', 'scan', 'complete')
                and value['cause'] in ('ok', 'not-ready', 'wrong-bootstrap', 'invalid-packet')
                and value['bootstrap'] in ('none', 'wnpair1', 'wnpair2', 'other'), 'closed-probe-enums')
        records.append(value)
    require(1 <= len(records) <= 3, 'bounded-actual-probes-required')
    return records



def source_sites(source, relative, expected_sha256):
    """Derive assertion coordinates only from the exact reviewed formatted input."""
    require(type(source) is bytes and hashlib.sha256(source).hexdigest() == expected_sha256,
            'exact-reviewed-formatted-test-source-required')
    text = source.decode('utf-8')
    pattern = r'(?m)^( +)func testExistingRosterWNPAIR2RequiresSiblingApprovalAndSharesHistory\(\) async throws \{'
    matches = list(re.finditer(pattern, text))
    require(len(matches) == 1, 'sole-WNPAIR2-method-owner-required')
    owner = matches[0]
    following = re.search(r'(?m)^' + re.escape(owner[1]) + r'(?:private )?func ', text[owner.end():])
    end = owner.end() + following.start() if following else len(text)
    segment = text[owner.start():end]
    tokens = {
        'begin-not-ready': ('XCTFail', 'factory-semantic-existing-roster-begin-not-ready'),
        'begin-bootstrap': ('XCTAssertTrue', 'factory-semantic-existing-roster-begin-bootstrap'),
        'scan-invalid-packet': ('XCTFail', 'factory-semantic-existing-roster-scan-invalid-packet'),
    }
    sites = {}
    for case, (assertion, token) in tokens.items():
        require(text.count('"' + token + '"') == 1, 'sole-source-owned-message-required')
        if assertion == 'XCTFail':
            literal = re.escape('XCTFail("' + token + '")')
        else:
            literal = (r'XCTAssertTrue\(\s*String\(data: code, encoding: \.utf8\)\?\.hasPrefix\("WNPAIR2:"\)'
                       r' == true,\s*"' + re.escape(token) + r'"\)')
        owned = list(re.finditer(literal, segment))
        require(len(owned) == 1, 'exact-assertion-in-WNPAIR2-method-required')
        position = owner.start() + owned[0].start()
        line_start = text.rfind('\n', 0, position) + 1
        sites[case] = {'path': relative, 'line': text.count('\n', 0, position) + 1,
                       'column': position - line_start + 1, 'message_token': token, 'assertion': assertion}
    return sites


def validate(records, counts, failures, compiler_inventory, compiler_body,
             *, phase, inverse, assertion_sites):
    """Validate complete normalized native evidence, not a marker-only verdict.

    failure rows MUST be all actual XCTest issue rows, normalized without
    dropping messages or paths to exactly {file,line,column,message}. Native result
    adapter admission and exact post-rustfmt/SwiftFormat source coordinates are
    separate required work; no guessed failure message is accepted as proof.
    """
    require(type(compiler_inventory) is list and compiler_inventory == []
            and type(compiler_body) is list and compiler_body == [], 'entire-compiler-inventory-and-body-empty')
    require(type(counts) is dict and set(counts) == set(COUNTS)
            and all(type(counts[k]) is int and counts[k] >= 0 for k in COUNTS), 'exact-typed-native-counts')
    require(type(failures) is list, 'entire-native-failure-inventory-required')
    require(type(records) is list and 1 <= len(records) <= 3
            and all(type(v) is dict and set(v) == FIELDS
                    and type(v['schema']) is int and v['schema'] == 1
                    and all(type(v[k]) is str for k in ('stage', 'cause', 'bootstrap'))
                    for v in records), 'decoded-closed-probes-required')
    require(all(all(type(v[k]) is bool and v[k] for k in BOOLS) for v in records), 'all-actual-prerequisites-true')
    require(phase in ('baseline', 'mutant', 'restored') and inverse in ('begin-legacy', 'scan-legacy'), 'closed-phase-and-inverse')
    sequence = [(v['stage'], v['cause'], v['bootstrap']) for v in records]
    normal = [('begin', 'ok', 'wnpair2'), ('scan', 'ok', 'wnpair2'), ('complete', 'ok', 'wnpair2')]
    if phase != 'mutant':
        require(sequence == normal and counts == dict(zip(COUNTS, (1, 1, 0, 0))) and failures == [],
                'one-real-control-pass-and-complete-original-scenario-required')
        return {'runtime_detected': False, 'actual_pass': True}
    if inverse == 'scan-legacy':
        require(sequence == normal[:1] + [('scan', 'invalid-packet', 'wnpair2')], 'actual-WNPAIR2-scan-typed-rejection-required')
        site = assertion_sites['scan-invalid-packet']
    elif sequence == [('begin', 'not-ready', 'none')]:
        site = assertion_sites['begin-not-ready']
    else:
        require(sequence in ([('begin', 'wrong-bootstrap', 'wnpair1')], [('begin', 'wrong-bootstrap', 'other')]),
                'actual-existing-roster-begin-counterfactual-required')
        site = assertion_sites['begin-bootstrap']
    require(counts == dict(zip(COUNTS, (1, 0, 1, 0))), 'one-actual-runtime-failure-no-skips-required')
    message = site['message_token']
    if site['assertion'] == 'XCTAssertTrue':
        message = 'XCTAssertTrue failed - ' + message
    expected = {'file': site['path'], 'line': site['line'], 'column': site['column'], 'message': message}
    require(len(failures) == 1 and type(failures[0]) is dict and set(failures[0]) == set(expected),
            'sole-entire-native-assertion-inventory-required')
    actual = failures[0]
    require(all(actual[k] == expected[k] for k in ('file', 'line', 'message'))
            and type(actual['line']) is int and actual['line'] > 0
            and (actual['column'] is None or type(actual['column']) is int and actual['column'] == expected['column']),
            'sole-exact-source-owned-native-assertion-required')
    expected = actual  # Preserve an actually unknown column; never fill it from source.
    return {'runtime_detected': True, 'actual_pass': False,
            'cause': records[-1]['cause'], 'failure_site': expected}
