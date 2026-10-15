"""199 actual prejoin records plus one live record at the SDK's 200-row cap.

The frozen original-owner consent and ordinary membership fixture is reused.
Only source message seeding and read-only cursor pagination are added. Private
IDs, payloads and provenance remain in the runner's temporary process memory.
"""
import time

from cross_host import GateFailure, require
import cross_host as original
from hosted_archive import selected_chat

PREJOIN = 199
PAGE_SIZE = 37


class BoundedObservationPeer:
    """Observe an exact ID over the complete bounded live fixture, not tail128."""

    def __init__(self, original_peer):
        self.original = original_peer

    def ask(self, command, **arguments):
        if command == "message-seen":
            command = "message-seen-bounded-id"
        return self.original.ask(command, **arguments)


class SeededSource:
    """Delegate original actions, seeding actual messages before admission."""

    def __init__(self, source, recipient, nonrecipient, ordinary):
        self.source = source
        self.absent = (recipient, nonrecipient)
        self.ordinary = ordinary
        self.expected = {}

    def ask(self, command, **arguments):
        value = self.source.ask(command, **arguments)
        if command != "send-history-text":
            return value
        require(not self.expected, "pagination-seed-exactly-once")
        group = arguments["group"]
        self.expected[value["message"]] = (arguments["text"], arguments["tags"])
        for index in range(1, PREJOIN):
            text = "hosted-pagination-prejoin-%03d" % index
            event = self.source.ask("send-text", group=group, text=text)["message"]
            require(event not in self.expected, "pagination-source-unique-canonical-ids")
            self.expected[event] = (text, [])
            original.wait_message((self.ordinary,), group, event, text,
                                  "pagination-prejoin-ordinary-delivery")
        # Observe every actual source event on an independent ordinary member,
        # and absence on both not-yet-admitted siblings before returning control
        # to the unmodified original selected-chat consent fixture.
        for event, (text, _) in self.expected.items():
            original.wait_message((self.ordinary,), group, event, text,
                                  "pagination-all-prejoin-ordinary-delivery")
            for peer in self.absent:
                require(not peer.ask("message-seen", group=group, message=event, text=text)["seen"],
                        "pagination-no-prejoin-disclosure")
        require(len(self.expected) == PREJOIN, "pagination-exact-prejoin-source-count")
        return value


def read_pages(peer, group):
    records, sizes, cursor = [], [], None
    for _ in range(7):  # Six expected pages plus a bounded terminal check.
        page = peer.ask("history-page-37", group=group, message=cursor)
        rows = page["records"]
        require(len(rows) <= PAGE_SIZE, "pagination-bounded-recipient-page")
        records.extend(rows)
        sizes.append(len(rows))
        following = page["next"]
        if following is None:
            break
        require(rows and following == rows[-1]["message"] and following != cursor,
                "pagination-exact-progressing-cursor")
        cursor = following
    else:
        raise GateFailure("pagination-terminal-page-required")
    return records, sizes


def run(journey):
    a, b, c, d = (BoundedObservationPeer(journey.open(role)) for role in journey.commands)
    account = original.first_pair(a, b, c)
    review = original.third_device(b, a, c)
    seeded = SeededSource(a, b, c, d)
    previous = selected_chat(seeded, b, c, d, history=True, account=account)
    group = previous["group"]
    for peer in (b, c):
        require(peer.ask("history-page-37", group=group)["records"] == [],
                "pagination-no-archive-before-original-consent")
        for event, (text, _) in seeded.expected.items():
            require(not peer.ask("message-seen", group=group, message=event, text=text)["seen"],
                    "pagination-admission-does-not-disclose-prejoin")
    source = a.ask("history-begin", group=group, member=review["source"])
    require(source["group"] == group and source["recipient"] == review["source"]
            and source["records"] == PREJOIN + 1 and not source["complete"],
            "pagination-entire-200-record-original-snapshot")
    deadline = time.monotonic() + 30
    while True:
        count = b.ask("history-pending")["count"]
        require(count <= 1, "pagination-single-original-consent")
        if count == 1:
            break
        require(time.monotonic() < deadline, "pagination-original-request-arrival")
        time.sleep(0.05)
    consent = b.ask("history-consent-snapshot")
    for field in ("group", "source", "recipient", "records", "encoded_bytes", "fragments", "ceiling"):
        require(consent[field] == source[field], "pagination-exact-original-review")
    require(not consent["complete"] and consent["imported"] == 0,
            "pagination-no-inherited-history-approval")
    for peer in (b, c):
        require(peer.ask("history-page-37", group=group)["records"] == [],
                "pagination-request-review-does-not-import")
    # Keep the original controller's shared 30-second request/consent/import
    # bound unchanged. Seeding and ordinary membership completed before it.
    b.ask("history-approve", revision=consent["revision"])
    a.ask("history-continue", revision=source["revision"])
    while True:
        sender = a.ask("history-snapshot")
        receiver = b.ask("history-consent-snapshot")
        if sender["complete"] and receiver["complete"]:
            break
        require(time.monotonic() < deadline, "pagination-committed-native-import")
        time.sleep(0.05)
    require(receiver["imported"] == PREJOIN and sender["records"] == PREJOIN + 1,
            "pagination-exact-import-and-live-shadow-count")
    records, sizes = read_pages(b, group)
    require(sizes == [37, 37, 37, 37, 37, 14], "pagination-exact-six-recipient-pages")
    require([row["message"] for row in records] == sorted(seeded.expected),
            "pagination-exact-canonical-ids-no-duplicates-or-omissions")
    transfers, manifests = set(), set()
    for row in records:
        text, tags = seeded.expected[row["message"]]
        require(row["content"] == text and row["tags"] == tags and row["author"] == account
                and row["created_at"] > 0 and row["expires_at"] is None
                and not row["deleted"] and row["media_count"] == 0,
                "pagination-exact-original-content-and-presentation")
        require(row["source"] == source["source"] and all(
            isinstance(row[field], str) and len(row[field]) == 64
            and all(char in "0123456789abcdef" for char in row[field])
            for field in ("source", "transfer", "manifest")),
            "pagination-source-attested-transfer-provenance")
        transfers.add(row["transfer"])
        manifests.add(row["manifest"])
    require(len(transfers) == len(manifests) == 1, "pagination-one-original-transfer-manifest")
    again, repeated_sizes = read_pages(b, group)
    require(again == records and repeated_sizes == sizes, "pagination-stable-exact-repeat")
    require(b.ask("history-page-37", group=group, message=records[-1]["message"])
            == {"records": [], "next": None}, "pagination-empty-tail")
    require(c.ask("history-page-37", group=group) == {"records": [], "next": None},
            "pagination-nonrecipient-archive-empty")
    require(b.ask("message-seen", group=group, message=previous["message"],
                  text=previous["text"])["seen"], "pagination-postjoin-live-record-preserved")
    return {"source_records": 200, "prejoin_records": PREJOIN, "imported_records": PREJOIN,
            "recipient_page_limit": PAGE_SIZE, "recipient_page_sizes": sizes,
            "complete_bounded_live_id_observation": True,
            "stable_repeated_enumeration": True, "exact_ids_content_and_provenance": True,
            "no_disclosure_before_consent": True, "nonrecipient_archive_empty": True,
            "postjoin_live_record_preserved": True, "source_complete": True,
            "recipient_complete": True,
            "limitations": ["Source snapshots above 200 records return NotReady in this SDK; this fixture does not establish full-history replacement equivalence.",
                            "No transferred expiry, retention or deletion claim."]}
