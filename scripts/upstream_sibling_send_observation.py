"""Closed passive sibling-send fixture observation; never a product verdict."""
import json
import re

PREFIX = 'sibling-send-observation '
STATES = {'unknown', 'none', 'queued', 'engine_owned', 'rejected', 'completed'}


def unique(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError('duplicate-observation-key')
        result[key] = value
    return result


def parse(raw):
    text = raw.decode('utf-8', errors='strict')
    namespace = PREFIX.rstrip()
    lines = [line for line in text.splitlines() if namespace in line]
    if len(lines) != 1 or text.count(namespace) != 1:
        raise ValueError('observation-cardinality')
    match = re.fullmatch(r'[ \t]{0,8}' + re.escape(PREFIX) + r'(\{[^\r\n]*\})[ \t]{0,8}', lines[0])
    if match is None or len(lines[0]) > 2048:
        raise ValueError('observation-envelope')
    value = json.loads(match[1], object_pairs_hook=unique)
    if type(value) is not dict or set(value) != {'submit_returned', 'status_polls', 'last_status'}:
        raise ValueError('observation-fields')
    returned, polls, status = value['submit_returned'], value['status_polls'], value['last_status']
    if (type(returned) is not bool or type(polls) is not int or not 0 <= polls < 2**64
            or type(status) is not str or status not in STATES):
        raise ValueError('observation-types')
    if ((not returned and (polls != 0 or status != 'unknown'))
            or (polls == 0 and status != 'unknown')):
        raise ValueError('observation-causal-order')
    # UNKNOWN with returned=True is valid for submission error or a status-query
    # error. No marker, including Completed, replaces the actual test verdict.
    return value


def controls():
    """Pure metadata fixtures, remote-only; no runtime or SQL."""
    positives = [dict(submit_returned=False, status_polls=0, last_status='unknown'),
                 dict(submit_returned=True, status_polls=0, last_status='unknown'),
                 dict(submit_returned=True, status_polls=1, last_status='unknown')]
    positives += [dict(submit_returned=True, status_polls=2, last_status=state)
                  for state in sorted(STATES - {'unknown'})]
    encode = lambda row: (PREFIX + json.dumps(row) + '\n').encode()
    for row in positives:
        assert parse(encode(row)) == row
    good = positives[-1]
    bad = [dict(good, submit_returned=1), dict(good, status_polls=True),
           dict(good, status_polls=-1), dict(good, status_polls=2**64),
           dict(good, last_status='PRIVATE'), dict(good, last_status=False),
           dict(good, submit_returned=False), dict(good, status_polls=0),
           dict(good, private=True)]
    invalid = [encode(row) for row in bad]
    raw = encode(good)
    invalid += [b'', raw + raw, b'PRIVATE ' + raw, b' ' * 9 + raw,
                raw + b'sibling-send-observation-PRIVATE\n', b'\xff' + raw,
                raw.replace(b'"status_polls": 2', b'"status_polls": 2, "status_polls": 2'),
                (PREFIX + '{' + ' ' * 2048 + '}\n').encode()]
    for raw in invalid:
        try:
            parse(raw)
        except (ValueError, UnicodeError):
            pass
        else:
            raise AssertionError('observation-negative-accepted')
    return {'positive': len(positives), 'negative': len(invalid), 'product_bodies': 0}
