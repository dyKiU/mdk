/* Host ABI/refusal smoke only; no original consent is synthesized here. */
#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <marmot.h>

_Static_assert(MARMOT_STATUS_HISTORY_TRANSFER_UNSUPPORTED == 112, "history unsupported ABI");
_Static_assert(MARMOT_STATUS_HISTORY_TRANSFER_NOT_READY == 113, "history not-ready ABI");
_Static_assert(MARMOT_STATUS_HISTORY_TRANSFER_CLOSED == 114, "history closed ABI");
_Static_assert(MARMOT_STATUS_HISTORY_TRANSFER_STALE_REVISION == 115, "history revision ABI");
_Static_assert(MARMOT_STATUS_HISTORY_TRANSFER_RUNTIME_UNAVAILABLE == 116, "history runtime ABI");

int main(int argc, char **argv) {
    assert(argc == 3);
    bool experimental = atoi(argv[2]) == 1;
    const char *relays[] = {"wss://relay.example"};
    MarmotClient *client = NULL;
    assert(marmot_client_new(argv[1], relays, 1, &client) == MARMOT_STATUS_OK);
    MarmotHistoryTransfer *transfer = (MarmotHistoryTransfer *)(uintptr_t)1;
    MarmotStatus status = marmot_begin_history_transfer(NULL, NULL, NULL, NULL, SIZE_MAX, &transfer);
    assert(transfer == NULL);
    assert(status == (experimental ? MARMOT_STATUS_HISTORY_TRANSFER_NOT_READY
                                 : MARMOT_STATUS_HISTORY_TRANSFER_UNSUPPORTED));
    assert(marmot_begin_history_transfer(NULL, NULL, NULL, NULL, SIZE_MAX, NULL)
           == MARMOT_STATUS_NULL_POINTER);
    uint8_t recipient[32] = {0};
    status = marmot_begin_history_transfer(client, "missing", "01", recipient, sizeof recipient, &transfer);
    assert(transfer == NULL);
    assert(status == (experimental ? MARMOT_STATUS_HISTORY_TRANSFER_RUNTIME_UNAVAILABLE
                                 : MARMOT_STATUS_HISTORY_TRANSFER_UNSUPPORTED));
    MarmotHistoryConsentList *pending = (MarmotHistoryConsentList *)(uintptr_t)1;
    status = marmot_pending_history_requests(client, "missing", &pending);
    assert(pending == NULL);
    assert(status == (experimental ? MARMOT_STATUS_HISTORY_TRANSFER_RUNTIME_UNAVAILABLE
                                 : MARMOT_STATUS_HISTORY_TRANSFER_UNSUPPORTED));
    MarmotHistoryTransferRecipientList *choices = (MarmotHistoryTransferRecipientList *)(uintptr_t)1;
    assert(marmot_history_transfer_recipients(NULL, NULL, NULL, NULL) == MARMOT_STATUS_NULL_POINTER);
    status = marmot_history_transfer_recipients(NULL, NULL, NULL, &choices);
    assert(choices == NULL);
    assert(status == (experimental ? MARMOT_STATUS_NULL_POINTER : MARMOT_STATUS_HISTORY_TRANSFER_UNSUPPORTED));
    choices = (MarmotHistoryTransferRecipientList *)(uintptr_t)1;
    status = marmot_history_transfer_recipients(client, "missing", "01020304050607080910111213141516", &choices);
    assert(choices == NULL);
    assert(status == (experimental ? MARMOT_STATUS_HISTORY_TRANSFER_RUNTIME_UNAVAILABLE
                                 : MARMOT_STATUS_HISTORY_TRANSFER_UNSUPPORTED));
    marmot_history_transfer_recipient_list_free(NULL);
    MarmotHistoryTransferRecipient choice = {.leaf_index = UINT32_MAX, .device = recipient, .device_len = 32};
    assert(choice.leaf_index == UINT32_MAX && choice.device == recipient && choice.device_len == 32);
    _Static_assert(MARMOT_STATUS_DEVICE_REVOCATION_UNSUPPORTED == 121, "revocation unsupported ABI");
    _Static_assert(MARMOT_STATUS_DEVICE_REVOCATION_RUNTIME_UNAVAILABLE == 127, "revocation runtime ABI");
    MarmotDeviceRevocation *revocation = (MarmotDeviceRevocation *)(uintptr_t)1;
    assert(marmot_begin_device_revocation(NULL, NULL, NULL, SIZE_MAX, NULL) == MARMOT_STATUS_NULL_POINTER);
    status = marmot_begin_device_revocation(NULL, NULL, NULL, SIZE_MAX, &revocation);
    assert(revocation == NULL);
    assert(status == (experimental ? MARMOT_STATUS_DEVICE_REVOCATION_INVALID_SELECTION
                                  : MARMOT_STATUS_DEVICE_REVOCATION_UNSUPPORTED));
    status = marmot_begin_device_revocation(client, "missing", recipient, sizeof recipient, &revocation);
    assert(revocation == NULL);
    assert(status == (experimental ? MARMOT_STATUS_DEVICE_REVOCATION_RUNTIME_UNAVAILABLE
                                  : MARMOT_STATUS_DEVICE_REVOCATION_UNSUPPORTED));
    MarmotDeviceRevocationSnapshot review = {.revision = UINT64_MAX, .complete = true,
        .protected_group_id_hex = NULL, .ordinary_group_ids_hex = NULL, .ordinary_group_ids_hex_len = 0,
        .completed_group_ids_hex = NULL, .completed_group_ids_hex_len = 0, .target_device = recipient, .target_device_len = 32};
    assert(review.revision == UINT64_MAX && review.complete && review.target_device_len == 32
        && review.ordinary_group_ids_hex_len == 0 && review.completed_group_ids_hex_len == 0);
    marmot_device_revocation_free(NULL);
    marmot_device_revocation_snapshot_free(NULL);
    MarmotAccountSummaryList *accounts = NULL;
    assert(marmot_list_accounts(client, &accounts) == MARMOT_STATUS_OK);
    assert(accounts != NULL && accounts->len == 0);
    marmot_account_summary_list_free(accounts);
    marmot_history_transfer_free(NULL);
    marmot_history_consent_free(NULL);
    marmot_history_consent_list_free(NULL);
    marmot_history_transfer_snapshot_free(NULL);
    /* Access every field through the checked-in header, without minting a handle. */
    MarmotHistoryTransferSnapshot view = {.revision = UINT64_MAX, .imported_records = 199,
        .complete = true, .group_id_hex = NULL, .source_device = NULL, .source_device_len = 32,
        .recipient_device = NULL, .recipient_device_len = 32, .snapshot_timestamp_ceiling = UINT64_MAX,
        .record_count = 200, .encoded_bytes = 196608, .fragment_count = 128};
    assert(view.revision == UINT64_MAX && view.imported_records == 199 && view.complete
           && view.group_id_hex == NULL && view.source_device == NULL && view.source_device_len == 32
           && view.recipient_device == NULL && view.recipient_device_len == 32
           && view.snapshot_timestamp_ceiling == UINT64_MAX && view.record_count == 200
           && view.encoded_bytes == 196608 && view.fragment_count == 128);
    assert(marmot_client_shutdown_and_close(client) == MARMOT_STATUS_OK);
    marmot_client_free(client);
    printf("history C ABI: statuses=5 preflight=2 factory-gates=3 query-gates=2 no-account-effects=1 experimental=%d\n", experimental);
    return 0;
}
