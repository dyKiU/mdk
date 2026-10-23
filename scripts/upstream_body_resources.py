"""Non-gating whole-invocation Linux child CPU/wall evidence, never a test verdict.

Bracket only the existing body capture, after inventory/compilation. No other
controller child may be spawned/reaped in this interval. CPU includes nextest
and its accounted reaped descendants: setup/catchup/teardown, not the 60s window.
"""
import math
import resource
import sys
import time


def _uint(value):
    return type(value) is int and 0 <= value < 2**64


def _micros(value):
    if type(value) not in (float, int) or not math.isfinite(value) or value < 0:
        return None
    result = int(value * 1_000_000)
    return result if _uint(result) else None


def start():
    """Short-lived private token; never serialize the token."""
    try:
        point = time.monotonic_ns()
        usage = resource.getrusage(resource.RUSAGE_CHILDREN) if sys.platform.startswith('linux') else None
        return {'point': point, 'user': _micros(usage.ru_utime) if usage is not None else None,
                'system': _micros(usage.ru_stime) if usage is not None else None}
    except Exception:
        return None


def _delta(before, after):
    return after - before if _uint(before) and _uint(after) and after >= before else None


def _closed(before, after):
    result = {'schema': 'body-resources-v1', 'non_gating': True,
              'scope': 'nextest_plus_accounted_reaped_descendants_whole_invocation',
              'not_60s_subwindow': True, 'snapshot_edges_atomic': False,
              'no_other_controller_children_during_capture': True,
              'cpu_unit_is_not_clock_resolution': True,
              'wall_usec': None, 'user_usec': None, 'system_usec': None,
              'status': 'unavailable',
              'psi_and_cgroup': {'status': 'not_collected',
                                  'reason': 'deferred_to_keep_observer_minimal_no_shared_scope_attribution'}}
    if type(before) is not dict or type(after) is not dict:
        return result
    wall = _delta(before.get('point'), after.get('point'))
    result['wall_usec'] = wall // 1000 if wall is not None else None
    for key in ('user', 'system'):
        result[key + '_usec'] = _delta(before.get(key), after.get(key))
    known = sum(result[key] is not None for key in ('wall_usec', 'user_usec', 'system_usec'))
    result['status'] = 'known' if known == 3 else 'partial' if known else 'unavailable'
    return result


def finish(token):
    """Errors return UNKNOWN/null and must never enter an acceptance predicate."""
    try:
        return _closed(token, start())
    except Exception:
        return _closed(None, None)


def controls():
    """Pure synthetic controls: execute remotely only, no OS observations."""
    before = {'point': 1_000_000, 'user': 7, 'system': 11}
    after = {'point': 2_000_000, 'user': 17, 'system': 31}
    value = _closed(before, after)
    assert [value[key] for key in ('wall_usec', 'user_usec', 'system_usec')] == [1000, 10, 20]
    assert value['status'] == 'known' and _closed(before, before)['user_usec'] == 0
    assert _closed(None, after)['user_usec'] is None
    assert _closed(before, dict(after, user=6))['user_usec'] is None
    assert 'PRIVATE' not in str(_closed({'private': 'PRIVATE'}, {}))
    rejected = [(True, 1), (-1, 1), (2, 1), (0, 2**64)]
    for a, b in rejected:
        assert _delta(a, b) is None
    for seconds in (True, -1, float('nan'), float('inf'), 2**64):
        assert _micros(seconds) is None
    return {'positive': 5, 'negative': len(rejected) + 5,
            'metadata_only': True, 'product_bodies': 0}
