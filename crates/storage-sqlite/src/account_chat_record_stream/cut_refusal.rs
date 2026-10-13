//! Synthetic SQL controls only; live Core authentication is qualified separately.
use super::*;
use crate::account_chat_departure::{AccountChatDepartureIntent, AccountChatDepartureTarget};
use cgka_traits::mirrored_chat_catalog::AcceptedChatOrigin;

fn accepted_record(storage: &SqliteAccountStorage) -> MirroredChatRecord {
    let origin = AcceptedChatOrigin {
        id: [42; 32],
        order: 1,
    };
    storage
        .apply_mirrored_chat_catalog(
            &scope(),
            &[MirroredChatEntry {
                group_id: group(),
                source_epoch: 1,
                source_sequence: 2,
                source_digest: [43; 32],
                profile: ProtocolProfile::Current,
                name: "accepted synthetic source".into(),
                description: String::new(),
                state: MirroredChatState::Active,
                accepted_origin: Some(origin),
                same_account_source_count: Some(1),
            }],
            &|| Ok(()),
        )
        .unwrap();
    let mut observation = record(44, 1);
    observation.accepted_origin = Some(origin);
    observation
}
fn assert_no_import(storage: &SqliteAccountStorage) {
    for table in [
        "mirrored_chat_messages",
        "account_chat_record_receipts",
        "account_chat_record_progress",
    ] {
        assert_eq!(
            rows(storage, table),
            0,
            "refusal must not write import state"
        );
    }
}

#[test]
fn exact_accepted_origin_cut_returns_typed_denial_without_import_receipt_or_progress() {
    let storage = stored();
    let observation = accepted_record(&storage);
    let policy = fact();
    let mut intent = AccountChatDepartureIntent {
        version: 1,
        action_id: [0; 32],
        account: policy.account,
        initiator: policy.local_device,
        protected_group: policy.protected_group,
        group: group(),
        targets: vec![AccountChatDepartureTarget {
            source_device: policy.peer_device,
            accepted_origin: observation.accepted_origin.unwrap(),
        }],
    };
    intent.action_id = intent.identity();
    assert!(
        storage
            .apply_account_chat_departure(
                &policy.local_device,
                &intent,
                &[policy.peer_device],
                &|| Ok(())
            )
            .unwrap()
    );
    let calls = Cell::new(0);
    let result = storage.apply_account_chat_record_batch(
        &scope(),
        &group(),
        &batch(&[observation]),
        1,
        &|| {
            calls.set(calls.get() + 1);
            Ok(())
        },
    );
    assert!(matches!(
        result,
        Err(StorageError::MirroredRecordDeniedByDeparture)
    ));
    assert_eq!(
        calls.get(),
        1,
        "actual before validator precedes typed cut refusal"
    );
    assert_no_import(&storage);
    assert!(
        storage
            .account_chat_departure_denies_source(
                &policy.account,
                &policy.local_device,
                &group(),
                &policy.peer_device,
                Some(intent.targets[0].accepted_origin)
            )
            .unwrap()
    );
}

#[test]
fn missing_catalog_without_cut_is_not_typed_permanent_departure_denial() {
    let storage = stored();
    let missing_group = GroupId::new(vec![45; 16]);
    let result = storage.apply_account_chat_record_batch(
        &scope(),
        &missing_group,
        &batch(&[record(46, 1)]),
        1,
        &|| Ok(()),
    );
    assert!(
        matches!(result, Err(StorageError::Serialization(_))),
        "missing catalog remains its existing prerequisite error"
    );
    assert_no_import(&storage);
    assert!(
        !storage
            .account_chat_departure_denies_source(
                &fact().account,
                &fact().local_device,
                &missing_group,
                &fact().peer_device,
                None
            )
            .unwrap()
    );
}

#[test]
fn owner_and_original_before_tail_failures_rollback_then_actual_retry_imports() {
    let storage = stored();
    let observation = accepted_record(&storage);
    let incoming = batch(&[observation]);
    let mut foreign_scope = scope();
    foreign_scope.local_device = [47; 32];
    assert!(matches!(
        storage.apply_account_chat_record_batch(&foreign_scope, &group(), &incoming, 1, &|| Ok(())),
        Err(StorageError::Serialization(_))
    ));
    assert_no_import(&storage);
    let before = storage.apply_account_chat_record_batch(&scope(), &group(), &incoming, 1, &|| {
        Err(StorageError::Busy(
            "synthetic original before failure".into(),
        ))
    });
    assert!(matches!(before, Err(StorageError::Busy(_))));
    assert_no_import(&storage);
    let calls = Cell::new(0);
    let tail = storage.apply_account_chat_record_batch(&scope(), &group(), &incoming, 1, &|| {
        calls.set(calls.get() + 1);
        if calls.get() == 2 {
            Err(StorageError::Busy("synthetic original tail failure".into()))
        } else {
            Ok(())
        }
    });
    assert!(matches!(tail, Err(StorageError::Busy(_))));
    assert_eq!(calls.get(), 2);
    assert_no_import(&storage);
    let receipt = storage
        .apply_account_chat_record_batch(&scope(), &group(), &incoming, 1, &|| Ok(()))
        .unwrap();
    assert_eq!(receipt.batch_digest, incoming.batch_digest);
    assert_eq!(receipt.imported_count, 1);
    for table in [
        "mirrored_chat_messages",
        "account_chat_record_receipts",
        "account_chat_record_progress",
    ] {
        assert_eq!(
            rows(&storage, table),
            1,
            "only validated retry commits import state"
        );
    }
}
