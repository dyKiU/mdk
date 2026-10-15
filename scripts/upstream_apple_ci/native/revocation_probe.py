"""Exact-device native scenario; observations never construct SDK authority."""
import base64
from cross_host import GateFailure, require


def device_set(peer, role='observer'):
    try:
        rows = peer.ask('sharing-targets')
    except GateFailure as error:
        raise GateFailure('revocation-target-query-' + role + '-' + str(error)) from None
    keys = [row['device'] for row in rows]
    require(all(isinstance(key, str) and len(key) == 64 and
                all(c in '0123456789abcdef' for c in key) for key in keys),
            'revocation-exact-device-observation')
    require(len(set(keys)) == len(keys), 'revocation-duplicate-device-observation')
    return set(keys)


def third_device_key(a, b, c):
    first, second, third = (settled_device_set(peer, role, 2) for peer, role in
                            ((a, 'source-A'), (b, 'survivor-B'), (c, 'target-C')))
    common = first & second
    require(len(first) == len(second) == len(third) == 2 and len(common) == 1,
            'revocation-three-device-roster')
    target = next(iter(common))
    require(target not in third and third == (first | second) - common,
            'revocation-third-device-exact-binding')
    return target, first - common, second - common


def settled_device_set(peer, role, expected_count):
    from automatic_chat import eventually
    def read():
        try:
            return device_set(peer, role)
        except GateFailure as error:
            if str(error) == ('revocation-target-query-' + role +
                             '-agent-fresh-protected-sharing-observations-sdk-sharing-not-ready'):
                return None
            raise
    # Enrollment completion is not the completed settlement round. Only a fresh
    # SDK target view qualifies readiness; this wait neither approves nor retries.
    return eventually(read, lambda value: value is not None and len(value) == expected_count,
                      'revocation-settled-target-view-' + role, timeout=20)


def revoke_third(a, b, c):
    # Read-only public target sets exclude each observer's own device. Their
    # intersection identifies C; begin/approve still use the real SDK original.
    from automatic_chat import eventually
    target, remaining_a, remaining_b = third_device_key(a, b, c)
    encoded = base64.b64encode(bytes.fromhex(target)).decode('ascii')
    begun = a.ask('revocation-begin', target=encoded)
    require(begun['target_device'] == encoded and not begun['complete'],
            'revocation-fresh-unapproved-original')
    reviewed = a.ask('revocation-snapshot')
    require(reviewed['target_device'] == encoded and
            reviewed['protected_group'] == begun['protected_group'],
            'revocation-same-held-original-scope')
    require(not reviewed['complete'], 'revocation-no-approval-before-review')
    a.ask('revocation-approve', revision=reviewed['revision'])
    eventually(lambda: a.ask('revocation-snapshot'),
               lambda value: value['complete'] and value['target_device'] == encoded,
               'revocation-confirmed-remove')
    # Complete is not evidence that surviving peers settled the successor.
    for peer, expected, role in ((a, remaining_a, 'source-A'), (b, remaining_b, 'survivor-B')):
        eventually(lambda: settled_device_set(peer, role, 1), lambda value: value == expected,
                   'revocation-settled-survivor-roster')
    return target


def require_revoked_forwarding_refusal(peer, group):
    from automatic_chat import eventually
    token='native-revocation-denied-token'
    try:
        peer.ask('send-token',group=group,text='native-revocation-forbidden-forward',token=token)
    except GateFailure as error:
        require(str(error) in ('agent-durable-normal-client-token-send-sdk-sharing-not-ready',
                              'agent-durable-normal-client-token-send-sdk-forwarding-unavailable'),
                'revocation-forwarding-refusal-category-'+str(error))
        return
    status=eventually(lambda: peer.ask('send-token-status',group=group,token=token),
                      lambda value: value['state'] in ('rejected','completed'),
                      'revocation-forwarding-must-refuse',timeout=20)
    require(status['state']=='rejected','revocation-forwarding-must-not-complete')


def device_revocation_probe(a, b, c, d, outsider, witness, progress=None):
    from automatic_chat import accept, eventually, exact_mirror, confirmed
    def mark(stage):
        if progress is not None: progress(stage)
    revoke_third(a, b, c)
    mark('protected-remove-confirmed-survivors-settled')
    group, _, _ = witness
    text = 'native-revocation-survivor-fresh-message'
    event = a.ask('send-text', group=group, text=text)['message']
    exact_mirror(b, group, text, event)
    mark('survivor-fresh-canonical-message')
    # A surviving source-attested copy must still send through real membership.
    b.ask('send-token', group=group, text='native-revocation-survivor-forward',
          token='native-revocation-survivor-token')
    forwarded = confirmed(b, group, 'native-revocation-survivor-token')
    eventually(lambda: d.ask('message-seen', group=group, message=forwarded,
                            text='native-revocation-survivor-forward'),
               lambda value: value['seen'], 'revocation-survivor-ordinary-delivery')
    mark('survivor-ordinary-forward-delivered')
    fresh = a.ask('create-chat', member=outsider)['group']
    require(fresh != group, 'revocation-new-canonical-chat')
    accept(d, fresh)
    fresh_text = 'native-revocation-new-chat-message'
    fresh_event = a.ask('send-text', group=fresh, text=fresh_text)['message']
    exact_mirror(b, fresh, fresh_text, fresh_event)
    mark('survivor-new-chat-and-message')
    # Existing encrypted history need not disappear. Require no new disclosure
    # while surviving B provides a positive live-transport witness.
    import time
    until = time.monotonic() + 20
    while time.monotonic() < until:
        rows = c.ask('automatic-list')
        require(fresh not in rows['paired_groups'] and fresh not in rows['local_groups'],
                'revocation-no-new-chat-disclosure')
        try:
            view = c.ask('automatic-conversation', group=group, text=text)
        except GateFailure as error:
            require(str(error)=='agent-normal-source-qualified-conversation-window-sdk-sharing-not-ready',
                    'revocation-conversation-refusal-category')
        else:
            require(not view['matching_ids'], 'revocation-no-new-message-disclosure')
        time.sleep(0.25)
    mark('revoked-new-disclosure-blocked')
    require_revoked_forwarding_refusal(c,group)
    mark('revoked-forwarding-refused')
