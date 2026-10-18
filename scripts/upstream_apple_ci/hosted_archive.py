"""Hosted adaptation of the frozen original-owner selected-chat fixture.

Only ordinary invite acceptance is added before the original membership checks.
All no-history, exact-consent, original-offer and canonical-delivery checks stay.
"""
import os
import time

from automatic_chat import accept
from cross_host import GateFailure, require


def selected_chat(a, b, c, d, history=False, account=None):
    ordinary = d.ask('create')
    del ordinary['secret']
    d.ask('publish-key-package')
    chat = a.ask('create-chat', member=ordinary['account'])['group']
    # Receiving a Welcome does not grant ordinary invitation acceptance.
    accept(d, chat)
    deadline = time.monotonic() + 30
    while time.monotonic() < deadline:
        try:
            if d.ask('group-state', group=chat)['members'] == 2:
                break
        except GateFailure as error:
            require(str(error) == 'agent-actual-chat-membership-sdk', 'ordinary-chat-join-error')
        time.sleep(0.05)
    else:
        raise GateFailure('real-ordinary-recipient-join')
    old_text = ('native-pre-join-' + os.urandom(8).hex()).ljust(8192, 'x') if history else 'native-pre-join-' + os.urandom(8).hex()
    old_tags = [['t', 'native-history']] if history else []
    if history:
        old_id = a.ask('send-history-text', group=chat, text=old_text, tags=old_tags)['message']
    else:
        old_id = a.ask('send-text', group=chat, text=old_text)['message']
    deadline = time.monotonic() + 30
    while time.monotonic() < deadline:
        if d.ask('message-seen', group=chat, message=old_id, text=old_text)['seen']:
            break
        time.sleep(0.05)
    else:
        raise GateFailure('actual-pre-join-ordinary-delivery')
    for peer in (b, c):
        require(not peer.ask('message-seen', group=chat, message=old_id, text=old_text)['seen'],
                'no-chat-history-before-original-consent')
    target = a.ask('targets')
    require(len(target) == 1 and target[0]['device_count'] == 3, 'actual-copy-target-three')
    a.ask('copy-begin', group=chat, target=target[0]['selector'])
    observed = a.ask('copy-snapshot')
    require(observed['siblings'] == 2 and observed['consenting'] == observed['offered'] == 0,
            'original-copy-no-inherited-consent')
    request = a.ask('copy-request', revision=observed['revision'])['packet']
    for peer in (b, c):
        peer.ask('consent-receive', packet=request)
        current = peer.ask('consent-snapshot')
        require(current['phase'] == 'awaitingApproval' and current['selector'] == chat, 'exact-authenticated-chat-review')
        try:
            peer.ask('consent-response', revision=current['revision'])
        except GateFailure as error:
            require(str(error) == 'agent-original-chat-consent-response-sdk', 'original-consent-denial-error')
        else:
            raise GateFailure('chat-consent-required-before-response')
        peer.ask('consent-explicit', revision=current['revision'])
        current = peer.ask('consent-snapshot')
        require(current['phase'] == 'approved', 'original-chat-explicitly-approved')
        response = peer.ask('consent-response', revision=current['revision'])['packet']
        a.ask('copy-response', revision=a.ask('copy-snapshot')['revision'], packet=response)
        offer = peer.ask('consent-offer', revision=current['revision'])['packet']
        require(peer.ask('consent-offer', revision=current['revision'])['packet'] == offer, 'exact-owned-offer-retry')
        a.ask('copy-offer', revision=a.ask('copy-snapshot')['revision'], packet=offer)
    current = a.ask('copy-snapshot')
    require(current['consenting'] == current['offered'] == 2, 'all-original-chat-consents-and-offers')
    a.ask('copy-continue', revision=current['revision'])
    require(a.ask('copy-snapshot')['phase'] == 'inviteConfirmed', 'actual-selected-invite-confirmed')
    deadline = time.monotonic() + 30
    while time.monotonic() < deadline:
        complete = True
        for peer in (a, b, c, d):
            try:
                complete &= peer.ask('group-state', group=chat)['members'] == 4
            except GateFailure as error:
                require(str(error) == 'agent-actual-chat-membership-sdk', 'selected-chat-membership-error')
                complete = False
        if complete:
            break
        time.sleep(0.05)
    else:
        raise GateFailure('real-four-member-selected-chat')
    for peer in (b, c):
        require(not peer.ask('message-seen', group=chat, message=old_id, text=old_text)['seen'],
                'selected-admission-does-not-copy-history')
    text = 'native-cross-host-delivery-' + os.urandom(8).hex()
    sent = b.ask('send-text', group=chat, text=text)['message']
    deadline = time.monotonic() + 30
    while time.monotonic() < deadline:
        if all(peer.ask('message-seen', group=chat, message=sent, text=text)['seen'] for peer in (a, b, c, d)):
            return {'group': chat, 'message': sent, 'text': text, 'old_message': old_id,
                    'old_text': old_text, 'old_tags': old_tags, 'author': account}
        time.sleep(0.05)
    raise GateFailure('real-cross-host-new-message-delivery')
