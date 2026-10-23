"""Closed passive fresh-rejoin return counters; never a product verdict."""
import json
import re

PREFIX = 'fresh-rejoin-return-welcome-observation '
FIELDS = {'key_package_bytes', 'invite_published', 'invite_id_count', 'invite_accept',
          'invite_maintenance', 'welcome_before', 'welcome_after', 'welcome_delta',
          'decision_wait_succeeded'}

def unique(pairs):
    value = {}
    for key, item in pairs:
        if key in value:
            raise ValueError('duplicate-key')
        value[key] = item
    return value

def uint(value):
    return type(value) is int and 0 <= value <= 2**64 - 1

def fresh_rejoin_observation(raw):
    text = re.sub(r'\x1b\[[0-?]*[ -/]*[@-~]', '', raw.decode('utf-8', errors='strict'))
    namespace = PREFIX.rstrip()
    lines = [line for line in text.splitlines() if namespace in line]
    if len(lines) != 1 or text.count(namespace) != 1 or len(lines[0].encode()) > 2048:
        raise ValueError('fresh-rejoin-cardinality')
    match = re.fullmatch(r'[ \t]{0,8}' + re.escape(PREFIX) + r'(\{[^\r\n]*\})[ \t]{0,8}', lines[0])
    if match is None:
        raise ValueError('fresh-rejoin-envelope')
    value = json.loads(match[1], object_pairs_hook=unique)
    if type(value) is not dict or set(value) != FIELDS:
        raise ValueError('fresh-rejoin-fields')
    for key in ['key_package_bytes', 'invite_published', 'invite_id_count']:
        if value[key] is not None and not uint(value[key]):
            raise ValueError('fresh-rejoin-return-count')
    for key, maximum in [('invite_accept', 2), ('invite_maintenance', 1)]:
        if value[key] is not None and (not uint(value[key]) or value[key] > maximum):
            raise ValueError('fresh-rejoin-disposition')
    if value['decision_wait_succeeded'] is not None and type(value['decision_wait_succeeded']) is not bool:
        raise ValueError('fresh-rejoin-verdict')
    for key in ['welcome_before', 'welcome_after']:
        row = value[key]
        if row is not None and (type(row) is not list or len(row) != 4 or not all(uint(v) for v in row)):
            raise ValueError('fresh-rejoin-counter')
    row = value['welcome_delta']
    if type(row) is not list or len(row) != 4 or any(v is not None and not uint(v) for v in row):
        raise ValueError('fresh-rejoin-delta')
    before, after = value['welcome_before'], value['welcome_after']
    expected = [after[i]-before[i] if before is not None and after is not None and after[i] >= before[i]
                else None for i in range(4)]
    if row != expected:
        raise ValueError('fresh-rejoin-delta-mismatch')
    return value

def controls():
    empty = dict(key_package_bytes=None, invite_published=None, invite_id_count=None,
                 invite_accept=None, invite_maintenance=None, welcome_before=None,
                 welcome_after=None, welcome_delta=[None]*4, decision_wait_succeeded=None)
    complete = dict(key_package_bytes=1000, invite_published=1, invite_id_count=1,
                    invite_accept=0, invite_maintenance=0, welcome_before=[2,2,0,10],
                    welcome_after=[3,3,0,50], welcome_delta=[1,1,0,40], decision_wait_succeeded=True)
    timeout = dict(complete, welcome_after=[3,2,1,50], welcome_delta=[1,0,1,40], decision_wait_succeeded=False)
    inflight_unknown = dict(complete, welcome_after=[2,2,0,10], welcome_delta=[0,0,0,0], decision_wait_succeeded=False)
    decreasing = dict(complete, welcome_after=[1,1,0,5], welcome_delta=[None,None,0,None])
    emit = lambda value: (PREFIX + json.dumps(value) + '\n').encode()
    for value in [empty, complete, timeout, inflight_unknown, decreasing]:
        assert fresh_rejoin_observation(emit(value)) == value
    bad_values = [dict(complete, extra='PRIVATE'), dict(complete, key_package_bytes=True),
                  dict(complete, invite_published=-1), dict(complete, invite_id_count='PRIVATE'),
                  dict(complete, invite_accept=3), dict(complete, invite_maintenance=True),
                  dict(complete, decision_wait_succeeded=1), dict(complete, welcome_before=[1,2,3]),
                  dict(complete, welcome_after=[True,3,0,50]), dict(complete, welcome_delta=[1,1,0,39]),
                  dict(empty, welcome_delta=[0,0,0,0]), dict(complete, key_package_bytes=2**64)]
    encoded = emit(complete)
    bad_raw = [encoded+encoded, b'PRIVATE '+encoded, b' '*9+encoded,
               encoded+b'fresh-rejoin-return-welcome-observation-unknown PRIVATE\n',
               encoded.replace(b'"key_package_bytes": 1000', b'"key_package_bytes": 1000, "key_package_bytes": 1000')]
    for raw in [emit(value) for value in bad_values] + bad_raw:
        try:
            fresh_rejoin_observation(raw)
        except (ValueError, UnicodeError):
            continue
        raise AssertionError('invalid fresh-rejoin observation accepted')
    return dict(positive=5, negative=len(bad_values)+len(bad_raw), product_bodies=0, metadata_only=True)
