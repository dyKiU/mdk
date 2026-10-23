"""Passive actual worker checkpoints/selection attempts; no scheduling verdict."""
import json
import re

PREFIX = 'sibling-worker-observation '
PHASES = {1: 'StartupEnter', 2: 'StartupDeferredDone', 3: 'StartupWelcomeBefore', 4: 'StartupWelcomeAfter', 5: 'ReplayWatchBefore', 6: 'ReplayWatchAfter', 7: 'LoopEntry', 8: 'NativeAdmissionBefore', 9: 'NativeAdmissionAfter', 10: 'ComparisonTailBefore', 11: 'ComparisonTailCompleted', 12: 'NativeSummaryTailBefore', 13: 'PreambleCompleted', 14: 'Preselect', 15: 'CommandSelected', 16: 'LocalDrainSelected', 17: 'ReceiveSelected', 18: 'ReplaySelected', 19: 'ConvergenceSelected', 20: 'SiblingMaintenanceSelected', 21: 'LinkingMaintenanceSelected', 22: 'BroadMaintenanceSelected', 23: 'SelectBodyCompleted', 24: 'SiblingCompletionSelected', 25: 'MediaCompletionSelected', 26: 'PresentationSelected', 27: 'RecoveryCompletionSelected', 28: 'NetworkStartupReply'}


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
    fields = {'registered', 'checkpoints', 'drain_attempts', 'last_turn', 'overflow', 'elapsed_ms', 'before_phase', 'after_phase'}
    if type(value) is not dict or set(value) != fields:
        raise ValueError('worker-observation-fields')
    if any(type(value[key]) is not bool for key in ('registered', 'overflow')):
        raise ValueError('worker-observation-booleans')
    uint = lambda item: type(item) is int and 0 <= item < 2**64
    if any(value[key] is not None and not uint(value[key])
           for key in ('checkpoints', 'drain_attempts', 'elapsed_ms')):
        raise ValueError('worker-observation-counters')
    for key in ('before_phase', 'after_phase'):
        if value[key] is not None and not (type(value[key]) is int and value[key] in PHASES):
            raise ValueError('worker-observation-phase')
    if not value['registered'] and any(value[key] is not None for key in ('before_phase', 'after_phase')):
        raise ValueError('unregistered-worker-phase')
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
            'not_task_polls_or_publication_count': True, 'product_pass_claim': False,
            'phase_semantics': 'last_reached_location_not_exact_blocker',
            'phase_labels': {key: PHASES.get(value[key]) for key in ('before_phase', 'after_phase')},
            'preselect_may_include_blocking_future_poll': True}


def controls():
    """Remote-only pure metadata; no runtime/probe/SQL execution."""
    zero = dict(registered=True, checkpoints=0, drain_attempts=0, last_turn=None, overflow=False, elapsed_ms=1000, before_phase=None, after_phase=None)
    turn = [0, 2, False, True, False, True]
    good = dict(zero, checkpoints=2, drain_attempts=1, last_turn=turn)
    unavailable = dict(zero, registered=False, checkpoints=None, drain_attempts=None)
    variants = [zero, good, dict(zero, drain_attempts=1), unavailable,
                dict(unavailable, registered=True, overflow=True), dict(good, elapsed_ms=None), dict(zero, before_phase=1, after_phase=27),
                dict(zero, before_phase=14, after_phase=14), dict(zero, before_phase=28, after_phase=2)]
    encode = lambda row: (PREFIX + json.dumps(row) + '\n').encode()
    for row in variants:
        assert parse(encode(row))['observation'] == row
    bad = [dict(good, registered=1), dict(good, overflow=0), dict(good, checkpoints=True),
           dict(good, drain_attempts=-1), dict(good, checkpoints=2**64), dict(good, elapsed_ms=True),
           dict(good, elapsed_ms=2**64), dict(good, last_turn=turn[:5]),
           dict(good, last_turn=[True] + turn[1:]), dict(good, last_turn=turn[:2] + [0] + turn[3:]),
           dict(good, checkpoints=0), dict(good, last_turn=None), dict(good, registered=False),
           dict(good, overflow=True), dict(good, private=True),
           dict(zero, before_phase=True), dict(zero, after_phase=False),
           dict(zero, before_phase=0), dict(zero, after_phase=29),
           dict(unavailable, before_phase=1), dict(good, after_phase="14")]
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
