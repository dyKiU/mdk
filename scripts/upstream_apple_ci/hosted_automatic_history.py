"""Representative >200 automatic history; explicit archive limits stay untouched."""
import automatic_chat as automatic
import cross_host as original
from cross_host import GateFailure, require

RECORDS = 205
PAGE = 37


class ObservationPeer:
    def __init__(self, original_peer, role, progress):
        self.original = original_peer
        self.role = role
        self.progress = progress

    def ask(self, command, **fields):
        if command == 'message-seen':
            command = 'message-seen-256'
        self.progress['last_commands'][self.role] = command
        try:
            return self.original.ask(command, **fields)
        except GateFailure as error:
            if str(error) == 'controller-response-timeout':
                self.progress['timeout_role'] = self.role
                self.progress['timeout_command'] = command
            raise

    def close(self):
        self.original.close()


def pages(peer, group):
    records, sizes, cursor = [], [], None
    for _ in range(8):
        fields = {} if cursor is None else {
            'afterCreatedAt': cursor['created_at'], 'afterMessage': cursor['message']}
        page = peer.ask('automatic-page-37', group=group, **fields)
        require(page['ready'] or not page['records'], 'automatic-history-no-unready-disclosure')
        rows = page['records']
        require(len(rows) <= PAGE, 'automatic-history-bounded-page')
        records.extend(rows)
        sizes.append(len(rows))
        following = page['next']
        if following is None:
            return records, sizes
        require(rows and following == {'created_at': rows[-1]['created_at'],
                                       'message': rows[-1]['message']}
                and following != cursor, 'automatic-history-exact-chronological-cursor')
        cursor = following
    raise GateFailure('automatic-history-terminal-page-required')


def assert_records(peer, group, expected, author):
    records, sizes = pages(peer, group)
    require(len(records) == len(expected) and {row['message'] for row in records} == set(expected),
            'automatic-history-exact-ids-no-duplicates-or-omissions')
    require([(row['created_at'], row['message']) for row in records]
            == sorted((row['created_at'], row['message']) for row in records),
            'automatic-history-chronological-keyset-order')
    sources = peer.ask('automatic-catalog-sources')
    matching = [row for row in sources if row['group'] == group]
    require(len(matching) == 1, 'automatic-history-one-canonical-source-chat')
    source = matching[0]['source']
    for row in records:
        require(row['content'] == expected[row['message']] and row['author'] == author
                and row['tags'] == [] and row['kind'] == 9 and row['canonical_chat']
                and row['created_at'] > 0 and row['expires_at'] is None
                and not row['deleted'] and row['media_count'] == 0,
                'automatic-history-exact-authored-content')
        evidence = row['source']
        require(all(evidence[field] == source[field] for field in ('device', 'policy', 'generation'))
                and evidence['sequence'] > 0 and evidence['epoch'] == source['epoch']
                and all(isinstance(evidence[field], str) and len(evidence[field]) == 64
                        and all(char in '0123456789abcdef' for char in evidence[field])
                        for field in ('device', 'policy', 'digest')),
                'automatic-history-current-catalog-bound-source-provenance')
    normal = peer.ask('automatic-list')
    require(normal['paired_groups'].count(group) == 1 and group not in normal['local_groups'],
            'automatic-history-discovery-without-fabricated-mls-membership')
    return records, sizes


def await_history(peer, group, expected, author, progress, label):
    automatic.eventually(lambda: peer.ask('automatic-list'),
                         lambda value: group in value['paired_groups'],
                         'automatic-history-catalog-discovery')
    # Match the existing automatic native controller's 90-second bound for
    # each expected message observation. A larger history adds bounded records,
    # not a longer original RPC, owner deadline or single-message wait.
    for ordinal, event in enumerate(expected, 1):
        def observation():
            records, sizes = pages(peer, group)
            progress[label] = {'expected_record_ordinal': ordinal,
                               'observed_records': len(records), 'page_sizes': sizes}
            return {row['message'] for row in records}
        automatic.eventually(observation, lambda observed: event in observed,
                             'automatic-history-exact-record-arrival')
    return assert_records(peer, group, expected, author)


def canonical(records):
    return [{key: row[key] for key in ('message', 'author', 'created_at', 'content', 'tags',
                                      'kind', 'canonical_chat', 'expires_at', 'deleted', 'media_count')}
            for row in records]


def run(journey):
    progress = {'phase': 'seed-prepair', 'last_commands': {}, 'prepair_sent': 0,
                'prepair_ordinary_verified': 0}
    journey.automatic_history_progress = progress
    a, b, c, d = (ObservationPeer(journey.open(role), role, progress) for role in journey.commands)
    identity, outside = a.ask('create'), d.ask('create')
    author = identity['account']
    require(author != outside['account'], 'automatic-history-independent-ordinary-account')
    del outside['secret']
    d.ask('publish-key-package')
    group = a.ask('create-chat', member=outside['account'])['group']
    automatic.accept(d, group)
    expected = {}
    for index in range(RECORDS):
        text = 'hosted-automatic-prepair-%03d' % index
        event = a.ask('send-text', group=group, text=text)['message']
        require(event not in expected, 'automatic-history-source-unique-ids')
        expected[event] = text
        progress['prepair_sent'] = len(expected)
        original.wait_message((d,), group, event, text, 'automatic-history-real-prepair-delivery')
        progress['prepair_ordinary_verified'] += 1
    progress['phase'] = 'explicit-first-pair'
    original.first_pair(a, b, c, automatic=True, identity=identity, retain_completed=True)
    automatic.require_completed_originals(a, b)
    require(c.ask('automatic-list')['paired_groups'] == [],
            'automatic-history-unapproved-device-has-no-catalog')
    negative, _ = pages(c, group)
    require(negative == [], 'automatic-history-unapproved-device-has-no-history')
    progress['phase'] = 'approved-second-device-catchup'
    b_records, b_sizes = await_history(b, group, expected, author, progress, 'second_catchup')
    require(b_sizes == [37, 37, 37, 37, 37, 20], 'automatic-history-six-complete-second-pages')
    a.ask('cancel'); b.ask('cancel')
    progress['phase'] = 'explicit-third-device-enrollment'
    original.third_device(a, b, c, automatic=True, retain_completed=True)
    automatic.require_completed_originals(a, b, c)
    progress['phase'] = 'both-approved-devices-catchup'
    b_after, _ = await_history(b, group, expected, author, progress, 'second_after_enrollment')
    c_records, c_sizes = await_history(c, group, expected, author, progress, 'third_catchup')
    require(canonical(b_after) == canonical(b_records) == canonical(c_records),
            'automatic-history-both-approved-devices-exact-history')
    require(c_sizes == b_sizes, 'automatic-history-six-complete-third-pages')
    require(d.ask('automatic-list')['paired_groups'] == [],
            'automatic-history-independent-account-not-paired-recipient')
    progress['phase'] = 'recipient-original-store-reopen'
    c.close()
    c = ObservationPeer(journey.open('third'), 'third-reopened', progress)
    c.ask('resume')
    reopened, _ = await_history(c, group, expected, author, progress, 'third_reopened')
    require(canonical(reopened) == canonical(c_records), 'automatic-history-reopen-exact-history')
    progress['phase'] = 'future-message-and-new-missing-chat'
    text = 'hosted-automatic-after-history'
    event = a.ask('send-text', group=group, text=text)['message']
    expected[event] = text
    original.wait_message((d,), group, event, text, 'automatic-history-future-ordinary-delivery')
    for label, peer in (('second_future', b), ('third_future', c)):
        await_history(peer, group, expected, author, progress, label)
    later = a.ask('create-chat', member=outside['account'])['group']
    require(later != group, 'automatic-history-new-missing-chat-identity')
    automatic.accept(d, later)
    later_text = 'hosted-automatic-later-missing-chat'
    later_event = a.ask('send-text', group=later, text=later_text)['message']
    original.wait_message((d,), later, later_event, later_text, 'automatic-history-later-ordinary-delivery')
    for label, peer in (('second_new_chat', b), ('third_new_chat', c)):
        await_history(peer, later, {later_event: later_text}, author, progress, label)
    progress['phase'] = 'completed'
    return {'actual_prepair_messages': RECORDS, 'approved_recipients': 2,
            'recipient_page_limit': PAGE, 'second_page_sizes': b_sizes, 'third_page_sizes': c_sizes,
            'exact_ids_content_and_source_provenance': True, 'unapproved_recipient_empty': True,
            'independent_account_not_paired': True, 'recipient_reopen_preserves_history': True,
            'future_message': True, 'later_missing_chat_discovered_by_both': True,
            'no_per_chat_history_transfer_or_approval': True,
            'limitations': ['Representative 205-record automatic history only; finite journal/outbox/receipt/storage quotas remain.',
                            'Explicit archive snapshots above 200 remain NotReady; no cap or original consent protection changed.',
                            'No full-history equivalence across all users, devices, retention/deletion cases or unbounded histories.']}
