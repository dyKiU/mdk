"""Passive actual worker checkpoints/selection attempts; no scheduling verdict."""
import json
import re

PREFIX = 'sibling-worker-observation '
PHASES = {1: 'StartupEnter', 2: 'StartupDeferredDone', 3: 'StartupWelcomeBefore', 4: 'StartupWelcomeAfter', 5: 'ReplayWatchBefore', 6: 'ReplayWatchAfter', 7: 'LoopEntry', 8: 'NativeAdmissionBefore', 9: 'NativeAdmissionAfter', 10: 'ComparisonTailBefore', 11: 'ComparisonTailCompleted', 12: 'NativeSummaryTailBefore', 13: 'PreambleCompleted', 14: 'Preselect', 15: 'CommandSelected', 16: 'LocalDrainSelected', 17: 'ReceiveSelected', 18: 'ReplaySelected', 19: 'ConvergenceSelected', 20: 'SiblingMaintenanceSelected', 21: 'LinkingMaintenanceSelected', 22: 'BroadMaintenanceSelected', 23: 'SelectBodyCompleted', 24: 'SiblingCompletionSelected', 25: 'MediaCompletionSelected', 26: 'PresentationSelected', 27: 'RecoveryCompletionSelected', 28: 'NetworkStartupReply', 29: 'NativeBatchTakeBefore', 30: 'NativeBatchTakeAfter', 31: 'NativeFrameIngestBefore', 32: 'NativeFrameIngestAfter', 33: 'NativeAckBefore', 34: 'NativeAckAfter', 35: 'InventoryFlushBefore', 36: 'InventoryFlushAfter', 37: 'NativeReplayObservationBefore', 38: 'NativeReplayObservationReleased', 39: 'SynchronizeNativeReplayBefore', 40: 'SynchronizeNativeReplayAfter', 41: 'NativeCursorSaveBefore', 42: 'NativeCursorSaveAfter'}


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
                dict(zero, before_phase=14, after_phase=14), dict(zero, before_phase=28, after_phase=2), dict(zero, before_phase=29, after_phase=42)]
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
           dict(zero, before_phase=0), dict(zero, after_phase=43),
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


TRANSITION_PREFIX = 'sibling-worker-transition-observation '


def parse_transitions(raw):
    """Actual source checkpoints, not task polls or continuous blocking proof."""
    text = raw.decode('utf-8', errors='strict')
    namespace = TRANSITION_PREFIX.rstrip()
    lines = [line for line in text.splitlines() if namespace in line]
    if len(lines) != 1 or text.count(namespace) != 1:
        raise ValueError('one-worker-transition-observation')
    match = re.fullmatch(r'[ \t]{0,8}' + re.escape(TRANSITION_PREFIX) + r'(\{[^\r\n]*\})[ \t]{0,8}', lines[0])
    if match is None or len(lines[0]) > 1024:
        raise ValueError('worker-transition-envelope')
    row = json.loads(match[1], object_pairs_hook=unique)
    if type(row) is not dict or set(row) != {'registered', 'cooperative_yield_enabled', 'before', 'after', 'overflow'}:
        raise ValueError('worker-transition-fields')
    if any(type(row[key]) is not bool for key in ('registered', 'cooperative_yield_enabled', 'overflow')):
        raise ValueError('worker-transition-booleans')
    if not row['registered'] or row['overflow']:
        if row['before'] is not None or row['after'] is not None:
            raise ValueError('unknown-transition-is-not-zero')
        delta = None
    else:
        for values in (row['before'], row['after']):
            if (type(values) is not list or len(values) != 4
                    or any(type(value) is not int or not 0 <= value < 2**64 for value in values)
                    or values[2] > values[1] or values[3] > values[2]):
                raise ValueError('worker-transition-counters')
        if any(end < start for start, end in zip(row['before'], row['after'])):
            raise ValueError('worker-transition-regression')
        delta = [end - start for start, end in zip(row['before'], row['after'])]
    bound = delta is not None and row['before'][0] == row['after'][0] == 1
    return {'observation': row, 'delta': delta, 'single_worker_entry_bound': bound,
            'collection_complete': bound, 'product_pass_claim': False,
            'fields': ['worker_starts', 'loop_entries', 'loop_boundary_passed', 'comparison_early_continues'],
            'association': 'private-account-map-and-observed-start-count-not-worker-token',
            'straddling_delta_allowed': True, 'boundary_is_yield_only_when_enabled': True, 'continuous_blocker_proven': False}


def transition_controls():
    # Pure metadata only; never target execution or synthetic behavioral RED.
    encode = lambda row: (TRANSITION_PREFIX + json.dumps(row) + '\n').encode()
    good = dict(registered=True, cooperative_yield_enabled=True, before=[1, 5, 4, 1], after=[1, 5, 4, 1], overflow=False)
    unknown = dict(registered=False, cooperative_yield_enabled=True, before=None, after=None, overflow=False)
    rows = [good, dict(good, after=[1, 8, 7, 4]),
            dict(good, after=[1, 5, 5, 1]),  # Yield entered before window.
            dict(good, before=[2, 5, 4, 1], after=[2, 5, 4, 1]),
            unknown, dict(unknown, registered=True, overflow=True), dict(good, cooperative_yield_enabled=False)]
    for row in rows:
        result = parse_transitions(encode(row))
        assert result['observation'] == row
        assert result['collection_complete'] == (row in rows[:3] or row == rows[-1])
    bad = [dict(good, cooperative_yield_enabled=1), dict(good, registered=1), dict(good, overflow=0), dict(good, extra=True),
           dict(good, before=[True, 5, 4, 1]), dict(good, after=[1, -1, 0, 0]),
           dict(good, after=[1, 2**64, 4, 1]), dict(good, before=[1, 5, 4]),
           dict(good, after=[1, 3, 4, 1]), dict(good, after=[1, 5, 4, 5]),
           dict(good, after=[1, 4, 4, 1]), dict(good, registered=False),
           dict(good, overflow=True), dict(unknown, registered=True)]
    raw = encode(good)
    invalid = [encode(row) for row in bad] + [b'', raw + raw, b'PRIVATE ' + raw,
        b' ' * 9 + raw, b'\xff' + raw, raw + b'sibling-worker-transition-observation-unknown\n',
        raw.replace(b'"overflow": false', b'"overflow": false, "overflow": false'),
        (TRANSITION_PREFIX + '{' + ' ' * 1024 + '}\n').encode()]
    for raw in invalid:
        try:
            parse_transitions(raw)
        except (ValueError, UnicodeError):
            pass
        else:
            raise AssertionError('worker-transition-negative-accepted')
    return {'positive': len(rows), 'negative': len(invalid), 'product_bodies': 0}
