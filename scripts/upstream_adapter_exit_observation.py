"""Passive two-call adapter exit rows, separate from existing SDK/body oracle."""
import json
import re

PREFIX = 'adapter-distinct-deliveries-exit '
REASONS = {'quiet_timeout', 'deadline_timeout', 'receive_error', 'stream_closed', 'authoritative_complete'}


def unique(pairs):
    value = {}
    for key, item in pairs:
        if key in value:
            raise ValueError('duplicate-exit-key')
        value[key] = item
    return value


def row(value):
    fields = {'reason', 'delivered', 'wait_ms', 'elapsed_ms', 'remaining_ms'}
    if type(value) is not dict or set(value) != fields:
        raise ValueError('exit-fields')
    if type(value['reason']) is not str or value['reason'] not in REASONS:
        raise ValueError('exit-reason')
    uint = lambda item: type(item) is int and 0 <= item < 2**64
    if not uint(value['delivered']):
        raise ValueError('exit-delivered')
    if any(value[key] is not None and not uint(value[key])
           for key in ('wait_ms', 'elapsed_ms', 'remaining_ms')):
        raise ValueError('exit-clock-type')
    wait, elapsed, remaining = [value[key] for key in ('wait_ms', 'elapsed_ms', 'remaining_ms')]
    if wait is not None and (not 0 < wait <= 15000 if value['reason'] == 'authoritative_complete' else wait != 15000):
        raise ValueError('original-fifteen-second-scope')
    if all(item is not None for item in (wait, elapsed, remaining)):
        if ((elapsed >= wait and remaining != 0)
                or (elapsed < wait and elapsed + remaining not in (wait - 1, wait))
                or (value['reason'] == 'deadline_timeout' and (elapsed < wait or remaining != 0))):
            raise ValueError('exit-clock-order')
    if value['reason'] == 'authoritative_complete' and (not all(uint(item) for item in (wait, elapsed, remaining))
            or elapsed < 1500 or remaining == 0 or value['delivered'] == 0):
        raise ValueError('authoritative-exit-incomplete')
    # A quiet timer may be serviced after the global deadline. The reason names
    # the actual armed deadline (next==deadline), not an inferred timely wake.
    return value


def parse(raw):
    text = raw.decode('utf-8', errors='strict')
    namespace = PREFIX.rstrip()
    lines = [line for line in text.splitlines() if namespace in line]
    if len(lines) != 2 or text.count(namespace) != 2:
        raise ValueError('two-actual-helper-exits')
    rows = []
    for line in lines:
        match = re.fullmatch(r'[ \t]{0,8}' + re.escape(PREFIX) + r'(\{[^\r\n]*\})[ \t]{0,8}', line)
        if match is None or len(line) > 2048:
            raise ValueError('exit-envelope')
        rows.append(row(json.loads(match[1], object_pairs_hook=unique)))
    return {'rows': rows, 'clock_fields_known': all(item[key] is not None for item in rows
            for key in ('wait_ms', 'elapsed_ms', 'remaining_ms')),
            'association': 'actual_original_unclamped_then_clamped_fixture_call_order',
            'product_pass_claim': False}


def controls():
    """Remote metadata only. Never reinterpret SDK rows or test verdicts."""
    good = dict(reason='quiet_timeout', delivered=1200, wait_ms=15000, elapsed_ms=2000, remaining_ms=13000)
    variants = [good, dict(good, reason='deadline_timeout', elapsed_ms=15001, remaining_ms=0),
                dict(good, reason='receive_error'), dict(good, reason='stream_closed'),
                dict(good, reason='authoritative_complete', wait_ms=14999, remaining_ms=12999),
                dict(good, reason='quiet_timeout', elapsed_ms=16000, remaining_ms=0),
                dict(good, elapsed_ms=None, remaining_ms=None)]
    encode = lambda rows: ''.join(PREFIX + json.dumps(value) + '\n' for value in rows).encode()
    for value in variants:
        assert parse(encode([good, value]))['rows'] == [good, value]
    bad = [dict(good, reason='PRIVATE'), dict(good, reason=False), dict(good, delivered=True),
           dict(good, delivered=-1), dict(good, delivered=2**64), dict(good, wait_ms=14999),
           dict(good, elapsed_ms=True), dict(good, remaining_ms=-1),
           dict(good, elapsed_ms=16000), dict(good, remaining_ms=1),
           dict(good, reason='deadline_timeout'), dict(good, private=True)]
    bad += [dict(good, reason='authoritative_complete', delivered=0),
            dict(good, reason='authoritative_complete', elapsed_ms=1000, remaining_ms=14000),
            dict(good, reason='authoritative_complete', elapsed_ms=15000, remaining_ms=0),
            dict(good, reason='authoritative_complete', wait_ms=None),
            dict(good, reason='authoritative_complete', wait_ms=15001, remaining_ms=13001)]
    invalid = [encode([good, value]) for value in bad]
    raw = encode([good, good])
    invalid += [b'', encode([good]), encode([good, good, good]), b'PRIVATE ' + raw,
                b' ' * 9 + raw, b'\xff' + raw, raw + b'adapter-distinct-deliveries-exit-PRIVATE\n',
                raw.replace(b'"delivered": 1200', b'"delivered": 1200, "delivered": 1200', 1)]
    for value in invalid:
        try:
            parse(value)
        except (ValueError, UnicodeError):
            pass
        else:
            raise AssertionError('exit-negative-accepted')
    return {'positive': len(variants), 'negative': len(invalid), 'product_bodies': 0}
