"""Closed metadata decoder; runtime/identity/source custody stay in replay runner."""
import re

CASES = {'uniffi-conversation', 'uniffi-list', 'uniffi-conversation-stale'}
STALE = 'private-stale-command-witness '
CLOSE = 'private_receive_positive_closes='


def observe(raw, case, ansi):
    if case not in CASES:
        raise ValueError('uniffi-case')
    text = ansi.sub('', raw.decode('utf-8', errors='replace'))

    def one(namespace, pattern):
        lines = [line for line in text.splitlines() if namespace in line]
        if len(lines) != 1 or text.count(namespace) != 1 or len(lines[0]) > 1024:
            raise ValueError('uniffi-marker-cardinality')
        match = re.fullmatch(r'[ \t]{0,8}' + pattern + r'[ \t]{0,8}', lines[0])
        if match is None:
            raise ValueError('uniffi-marker-envelope')
        return match, text.index(lines[0])

    close, closed_at = one(CLOSE.rstrip('='), re.escape(CLOSE)
        + r'(0|1) actual_command_replacement=(true|false) conversation=(true|false)')
    result = {'positive_closes': int(close[1]),
              'actual_command_replacement': close[2] == 'true',
              'conversation': close[3] == 'true', 'stale_witness': None,
              'panic_after_close': None}
    if case == 'uniffi-conversation-stale':
        match, witness_at = one(STALE.rstrip(), re.escape(STALE)
            + r'stale_observed=(true|false) command_after_stale=(true|false) cancellation_retained=(true|false)')
        if witness_at >= closed_at:
            raise ValueError('uniffi-witness-close-order')
        result['stale_witness'] = [match[i] == 'true' for i in (1, 2, 3)]
    elif STALE.rstrip() in text:
        raise ValueError('uniffi-unexpected-stale-marker')
    if 'panicked at ' in text:
        headers = list(re.finditer(r"(?m)^[ \t]{0,8}thread '[^'\r\n]+'(?: \([0-9]+\))? panicked at ", text))
        result['panic_after_close'] = (text.count('panicked at ') == 1 and len(headers) == 1
                                       and headers[0].start() > closed_at)
    return result


def oracle(value, case, mutant=False):
    if (value['positive_closes'] != 1 or not value['actual_command_replacement']
            or value['conversation'] != (case != 'uniffi-list')):
        return False
    if case != 'uniffi-conversation-stale':
        return not mutant and value['stale_witness'] is None and value['panic_after_close'] is None
    return (value['stale_witness'] == ([True, False, False] if mutant else [True, True, True])
            and value['panic_after_close'] is (True if mutant else None))


def controls(ansi):
    positive, negative = 0, 0
    witness = STALE + 'stale_observed=true command_after_stale=true cancellation_retained=true\n'
    close = CLOSE + '1 actual_command_replacement=true conversation=true\n'
    for case in sorted(CASES):
        raw = ((witness if case == 'uniffi-conversation-stale' else '')
               + close.replace('conversation=true', 'conversation=' + ('false' if case == 'uniffi-list' else 'true'))).encode()
        assert oracle(observe(raw, case, ansi), case)
        positive += 1
    red_witness = witness.replace('command_after_stale=true cancellation_retained=true',
                                  'command_after_stale=false cancellation_retained=false')
    panic = "thread 'controlled' (7) panicked at controlled.rs:1:1:\ncontrolled\n"
    red = (red_witness + close + panic).encode()
    assert oracle(observe(red, 'uniffi-conversation-stale', ansi), 'uniffi-conversation-stale', True)
    positive += 1
    invalid = [red + red, b'PRIVATE ' + red, b' '*9 + red,
               red.replace(close.encode(), b''), red.replace(red_witness.encode(), b''),
               red.replace(b'positive_closes=1', b'positive_closes=0'),
               red.replace(b'actual_command_replacement=true', b'actual_command_replacement=false'),
               red.replace(b'conversation=true', b'conversation=false'),
               red.replace(b'stale_observed=true', b'stale_observed=false'),
               red.replace(b'command_after_stale=false', b'command_after_stale=true'),
               red.replace(b'cancellation_retained=false', b'cancellation_retained=true'),
               red.replace(b'stale_observed=true', b'stale_observed=1'),
               red.replace(b'conversation=true', b'conversation=1'),
               red.replace(b'command_after_stale=false', b'unknown=false command_after_stale=false'),
               (close + red_witness + panic).encode(),
               (red_witness + panic + close).encode(),
               red + (STALE.rstrip() + '-PRIVATE\n').encode(),
               red + (CLOSE + 'PRIVATE\n').encode(),
               red + b'private_receive_positive_closes-PRIVATE\n',
               red + panic.encode()]
    for raw in invalid:
        try:
            accepted = oracle(observe(raw, 'uniffi-conversation-stale', ansi),
                              'uniffi-conversation-stale', True)
        except ValueError:
            accepted = False
        assert not accepted
        negative += 1
    for case in ['uniffi-conversation', 'uniffi-list']:
        assert not oracle(observe(red, 'uniffi-conversation-stale', ansi), case)
        negative += 1
    return {'positive': positive, 'negative': negative,
            'synthetic_metadata_only': True, 'product_bodies': 0}
