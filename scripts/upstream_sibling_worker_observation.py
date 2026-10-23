"""Passive actual worker checkpoints/selection attempts; no scheduling verdict."""
import json
import re

PREFIX = 'sibling-worker-observation '


def unique(pairs):
    value = {}
    for key, item in pairs:
        if key in value:
            raise ValueError('worker-observation-duplicate-key')
        value[key] = item
    return value


def parse(raw):
    text = raw.decode('utf-8', errors='strict')
    namespace = PREFIX.rstrip()
    lines = [line for line in text.splitlines() if namespace in line]
    if len(lines) != 1 or text.count(namespace) != 1:
        raise ValueError('one-worker-observation')
    match = re.fullmatch(r'[ \t]{0,8}' + re.escape(PREFIX) + r'(\{[^\r\n]*\})[ \t]{0,8}', lines[0])
    if match is None or len(lines[0]) > 2048:
        raise ValueError('worker-observation-envelope')
    value = json.loads(match[1], object_pairs_hook=unique)
    fields = {'registered', 'checkpoints', 'drain_attempts', 'last_turn', 'overflow', 'elapsed_ms'}
    if type(value) is not dict or set(value) != fields:
        raise ValueError('worker-observation-fields')
    if any(type(value[key]) is not bool for key in ('registered', 'overflow')):
        raise ValueError('worker-observation-booleans')
    uint = lambda item: type(item) is int and 0 <= item < 2**64
    if any(value[key] is not None and not uint(value[key])
           for key in ('checkpoints', 'drain_attempts', 'elapsed_ms')):
        raise ValueError('worker-observation-counters')
    turn = value['last_turn']
    if turn is not None and (type(turn) is not list or len(turn) != 6
            or not all(uint(item) for item in turn[:2])
            or not all(type(item) is bool for item in turn[2:])):
        raise ValueError('worker-observation-last-tuple')
    if not value['registered'] or value['overflow']:
        if any(value[key] is not None for key in ('checkpoints', 'drain_attempts', 'last_turn')):
            raise ValueError('unknown-worker-is-not-zero')
    elif (value['checkpoints'] is None or value['drain_attempts'] is None
          or ((value['checkpoints'] == 0) != (turn is None))):
        raise ValueError('checkpoint-last-tuple-binding')
    return {'observation': value, 'collection_complete': value['registered'] and not value['overflow']
            and value['elapsed_ms'] is not None,
            'scope': 'bob_only_selection_checkpoints_and_drain_attempts',
            'tuple_fields': ['pending', 'buffered', 'yielded', 'due', 'owed', 'retry_ready'],
            'not_task_polls_or_publication_count': True, 'product_pass_claim': False}


def controls():
    """Remote-only pure metadata; no runtime/probe/SQL execution."""
    zero = dict(registered=True, checkpoints=0, drain_attempts=0, last_turn=None, overflow=False, elapsed_ms=1000)
    turn = [0, 2, False, True, False, True]
    good = dict(zero, checkpoints=2, drain_attempts=1, last_turn=turn)
    unavailable = dict(zero, registered=False, checkpoints=None, drain_attempts=None)
    variants = [zero, good, dict(zero, drain_attempts=1), unavailable,
                dict(unavailable, registered=True, overflow=True), dict(good, elapsed_ms=None)]
    encode = lambda row: (PREFIX + json.dumps(row) + '\n').encode()
    for row in variants:
        assert parse(encode(row))['observation'] == row
    bad = [dict(good, registered=1), dict(good, overflow=0), dict(good, checkpoints=True),
           dict(good, drain_attempts=-1), dict(good, checkpoints=2**64), dict(good, elapsed_ms=True),
           dict(good, elapsed_ms=2**64), dict(good, last_turn=turn[:5]),
           dict(good, last_turn=[True] + turn[1:]), dict(good, last_turn=turn[:2] + [0] + turn[3:]),
           dict(good, checkpoints=0), dict(good, last_turn=None), dict(good, registered=False),
           dict(good, overflow=True), dict(good, private=True)]
    invalid = [encode(row) for row in bad]
    raw = encode(good)
    invalid += [b'', raw + raw, b'PRIVATE ' + raw, b' ' * 9 + raw, b'\xff' + raw,
                raw + b'sibling-worker-observation-PRIVATE\n',
                raw.replace(b'"checkpoints": 2', b'"checkpoints": 2, "checkpoints": 2'),
                (PREFIX + '{' + ' ' * 2048 + '}\n').encode()]
    for raw in invalid:
        try:
            parse(raw)
        except (ValueError, UnicodeError):
            pass
        else:
            raise AssertionError('worker-observation-negative-accepted')
    return {'positive': len(variants), 'negative': len(invalid), 'product_bodies': 0}
