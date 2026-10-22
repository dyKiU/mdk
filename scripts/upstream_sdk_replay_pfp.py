"""Closed adapter descriptors/oracles for the existing scoped PFP driver."""
import json
import re
from upstream_avatar_ready_turn_chain import compiler_diagnostics

FIXTURE = 'crates/transport-nostr-adapter/src/sdk_client.rs'
SOURCES = {'sdk-epoch': FIXTURE, 'sdk-alias': 'crates/transport-nostr-adapter/src/lib.rs'}
PREFIX = 'sdk_client::tests::private_sdk_replay_regressions::'
CASES = {
    'sdk-epoch': PREFIX + 'private_sdk_capture_requires_new_endpoint_epoch_eose',
    'sdk-alias': PREFIX + 'private_sdk_wire_routes_only_selected_mls_group_while_alias_uses_native_replay',
}
LABELS = {
    'sdk-epoch': 'actual SDK epoch change must require new endpoint EOSE',
    'sdk-alias': 'private SDK wire must not bypass native replay for another MLS group',
}
MARKERS = {'sdk-epoch': 'private-sdk-epoch ', 'sdk-alias': 'private-sdk-alias '}
KEYS = {
    'sdk-epoch': {'prerequisites', 'delayed_negative', 'endpoint_negative', 'connection_negative', 'reader_negative', 'closed'},
    'sdk-alias': {'prerequisites', 'private_alias_absent'},
}


def mutate(case, source):
    if case == 'sdk-epoch':
        start = source.index('impl SdkLiveNotificationReceiver {')
        end = source.index('\n// Match the SDK client', start)
        old = '.is_none_or(|(old, _)| epoch != *old)'
        new = '.is_none_or(|_| false)'
    elif case == 'sdk-alias':
        start = source.index('    async fn handle_captured_live_relay_event_scoped(')
        end = source.index('\n    /// Trusted actual SDK notification inlet', start)
        old = 'deliveries.retain(|delivery| delivery.group_id_hint.as_ref() == Some(group));'
        new = 'let _ = group; // Scoped runtime inverse: omit only exact MLS alias filtering.'
    else:
        raise ValueError('sdk-case')
    segment = source[start:end]
    if segment.count(old) != 1:
        raise ValueError('sdk-one-original-anchor')
    changed = source[:start] + segment.replace(old, new, 1) + source[end:]
    if changed == source or changed.replace(new, old, 1) != source:
        raise ValueError('sdk-exact-inverse')
    return changed


def assertion_line(case, fixture):
    lines = fixture.splitlines()
    labels = [i for i, line in enumerate(lines) if '"' + LABELS[case] + '"' in line]
    if len(labels) != 1:
        raise ValueError('sdk-one-own-label')
    preceding = [i for i in range(max(0, labels[0]-3), labels[0]+1) if 'assert!(' in lines[i]]
    if not preceding:
        raise ValueError('sdk-one-own-assert')
    nearest = preceding[-1]
    label_text = '"' + LABELS[case] + '"'
    prefix = lines[labels[0]].split(label_text, 1)[0]
    body = re.sub(r'\s+', '', ''.join(lines[nearest:labels[0]]) + prefix)
    expected = 'assert!(connection_negative&&reader_negative,' if case=='sdk-epoch' else 'assert!(private_alias_absent,'
    if body != expected:
        raise ValueError('sdk-own-condition')
    return nearest + 1


def panic_coordinates(raw):
    text = raw.decode('utf-8', errors='replace')
    headers = raw.count(b'panicked at ')
    matches = re.findall(r"(?m)^[ \t]{0,8}thread '[^'\r\n]{1,512}'(?: \([0-9]+\))? panicked at ([^\s]+):(\d+):(\d+):$", text)
    positions, unknown = [], max(0, headers-len(matches))
    for path, line, column in matches:
        if path in set(SOURCES.values()) and 0 < int(line) <= 1_000_000 and 0 < int(column) <= 1_000_000:
            positions.append(dict(source=path, line=int(line), column=int(column)))
        else:
            unknown += 1
    return dict(header_count=headers, trusted_source_positions=positions[:8],
                positions_overflow=len(positions)>8, unreviewed_position_count=unknown)


def partial_counts(raw):
    text = raw.decode('utf-8', errors='replace')
    rows = re.findall(r'(?m)^test result: (?:ok|FAILED)\. (\d+) passed; (\d+) failed; (\d+) ignored(?:;[^\r\n]*)?$', text)
    return dict(zip(('passed', 'failed', 'ignored'), map(int, rows[0]))) if len(rows)==1 else None


def oracle(raw, case, fixture, mutant):
    text = re.sub(r'\x1b\[[0-?]*[ -/]*[@-~]', '', raw.decode('utf-8', errors='replace'))
    name, prefix = CASES[case], MARKERS[case]
    summaries = re.findall(r'(?m)^test result: (ok|FAILED)\. (\d+) passed; (\d+) failed; (\d+) ignored(?:;[^\r\n]*)?$', text)
    named = re.findall(r'^test ' + re.escape(name) + r' \.\.\. (ok|FAILED)\s*$', text, re.M)
    running = re.findall(r'^running (\d+) tests?\s*$', text, re.M)
    rows, marker_ends = [], []
    def unique(pairs):
        value = {}
        for key, item in pairs:
            if key in value: raise ValueError('duplicate-marker-key')
            value[key] = item
        return value
    try:
        for match in re.finditer(r'^.*$', text, re.M):
            line = match[0]
            if 'private-sdk-' not in line: continue
            if not line.startswith(prefix) or len(line) > 1024: raise ValueError('marker-envelope')
            value = json.loads(line[len(prefix):], object_pairs_hook=unique)
            if type(value) is not dict or set(value) != KEYS[case] or any(type(v) is not bool for v in value.values()):
                raise ValueError('marker-schema')
            rows.append(value); marker_ends.append(match.end())
    except (TypeError, ValueError):
        rows = []
    marker = rows[0] if len(rows) == 1 else None
    expected_marker = dict.fromkeys(KEYS[case], True)
    if mutant:
        for key in (('connection_negative', 'reader_negative') if case == 'sdk-epoch' else ('private_alias_absent',)):
            expected_marker[key] = False
    site = assertion_line(case, fixture)
    intended = bool(raw.count(b'panicked at ') == 1 and re.search(
        r"(?m)^[ \t]{0,8}thread '" + re.escape(name) + r"'(?: \([0-9]+\))? panicked at "
        + re.escape(FIXTURE) + ':' + str(site) + r':\d+:\n(?:[ \t]*\n){0,2}'
        + re.escape(LABELS[case]) + r'\s*(?:\n|$)', text))
    diagnostics = compiler_diagnostics(raw, cargo_test_context=('transport-nostr-adapter', '--lib'))
    counts = (dict(passed=int(summaries[0][1]), failed=int(summaries[0][2]), ignored=int(summaries[0][3]))
              if len(summaries)==1 else None)
    expected = [('FAILED', '0', '1', '0')] if mutant else [('ok', '1', '0', '0')]
    ordered = not mutant or intended and marker_ends and marker_ends[0] < text.index('panicked at ')
    return dict(counts=counts, marker=marker, intended_assertion=intended,
                runtime_panic_coordinates=panic_coordinates(raw), compiler_diagnostics=diagnostics,
                evidence_passed=bool(summaries==expected and running==['1']
                    and named==['FAILED' if mutant else 'ok'] and marker==expected_marker and ordered
                    and (intended if mutant else raw.count(b'panicked at ')==0)
                    and not diagnostics['compiler_codes'] and diagnostics['compiler_header_count']==0))


def parser_controls(fixture):
    positives = negatives = 0
    for case, name in CASES.items():
        def sample(mutant):
            marker = dict.fromkeys(KEYS[case], True)
            if mutant:
                for key in (('connection_negative', 'reader_negative') if case=='sdk-epoch' else ('private_alias_absent',)):
                    marker[key] = False
            text = 'running 1 test\ntest '+name+' ... '+('FAILED' if mutant else 'ok')+'\n'
            text += MARKERS[case]+json.dumps(marker)+'\n'
            if mutant:
                text += "thread '"+name+"' (123) panicked at "+FIXTURE+':'+str(assertion_line(case,fixture))+':5:\n'+LABELS[case]+'\n'
                text += 'test result: FAILED. 0 passed; 1 failed; 0 ignored\nerror: test failed, to rerun pass `-p transport-nostr-adapter --lib`\n'
            else: text += 'test result: ok. 1 passed; 0 failed; 0 ignored\n'
            return text.encode()
        good, red = sample(False), sample(True)
        if not oracle(good,case,fixture,False)['evidence_passed'] or not oracle(red,case,fixture,True)['evidence_passed']:
            raise ValueError('sdk-parser-positive')
        positives += 2
        if not oracle(red.replace(b' (123)',b''),case,fixture,True)['evidence_passed']:
            raise ValueError('sdk-parser-thread-form')
        positives += 1
        bad = [red.replace(name.encode(), b'PRIVATE'), red.replace(LABELS[case].encode(),b'PRIVATE'),
               red.replace(FIXTURE.encode(),b'PRIVATE/path.rs'), red.replace(b'0 ignored',b'1 ignored'),
               red.replace(b'1 failed',b'0 failed'), red.replace(b'running 1 test',b'running 0 tests'),
               red.replace(MARKERS[case].encode(),b' '+MARKERS[case].encode()),
               red + MARKERS[case].encode()+b'{}\n', red+b'private-sdk-unknown {}\n',
               red.replace(b"thread '", b"PRIVATE thread '"), red+b"thread 'PRIVATE' panicked at PRIVATE/path.rs:1:1:\nPRIVATE\n",
               red+b'error[E0382]: PRIVATE\n', red+b'error: test failed, to rerun pass `-p transport-nostr-adapter --lib`\n',
               red.replace(b'"prerequisites": true',b'"prerequisites": false'),
               red.replace(b' (123)', b' (PRIVATE)'),
               red.replace(b'-p transport-nostr-adapter --lib', b'-p marmot-app --lib'),
               red + b'PRIVATE_NONTERMINAL\n',
               red.replace(b'test result: FAILED.', b'PRIVATE test result: FAILED.')]
        for item in bad:
            if oracle(item,case,fixture,True)['evidence_passed']: raise ValueError('sdk-parser-negative')
            negatives += 1
    return dict(positive=positives, negative=negatives, metadata_only=True, product_bodies=0)
