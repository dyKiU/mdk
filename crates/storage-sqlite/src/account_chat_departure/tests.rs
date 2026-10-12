use super::*;
use cgka_traits::{
    MemberId,
    storage::{AccountDeviceSignerBinding, AccountDeviceSignerStorage},
};
use std::cell::Cell;

fn configured() -> SqliteAccountStorage {
    let storage = SqliteAccountStorage::in_memory().unwrap();
    configure(&storage);
    storage
}
fn configure(storage: &SqliteAccountStorage) {
    storage
        .lock()
        .unwrap()
        .execute(
            "INSERT INTO account_state(label,updated_at,local_account_id_hex) VALUES('test',0,?1)",
            [hex::encode([1; 32])],
        )
        .unwrap();
    storage
        .put_account_device_signer(&AccountDeviceSignerBinding {
            marmot_identity: MemberId::new(vec![1; 32]),
            mls_signature_public_key: vec![2; 32],
        })
        .unwrap();
}
fn fixture_intent() -> AccountChatDepartureIntent {
    let mut intent = AccountChatDepartureIntent {
        version: 1,
        action_id: [0; 32],
        account: [1; 32],
        initiator: [2; 32],
        protected_group: GroupId::new(vec![7; 16]),
        group: GroupId::new(vec![8; 16]),
        targets: vec![AccountChatDepartureTarget {
            source_device: [3; 32],
            accepted_origin: AcceptedChatOrigin {
                id: [4; 32],
                order: 2,
            },
        }],
    };
    intent.action_id = intent.identity();
    intent
}
#[test]
fn exact_negative_intent_is_idempotent_and_new_accepted_origin_is_not_denied() {
    let storage = configured();
    let intent = fixture_intent();
    assert!(
        storage
            .apply_account_chat_departure(&[2; 32], &intent, &[[3; 32]], &|| Ok(()))
            .unwrap()
    );
    assert!(
        !storage
            .apply_account_chat_departure(&[2; 32], &intent, &[[3; 32]], &|| Ok(()))
            .unwrap()
    );
    assert!(
        storage
            .account_chat_departure_denies_source(
                &[1; 32],
                &[2; 32],
                &intent.group,
                &[3; 32],
                Some(intent.targets[0].accepted_origin)
            )
            .unwrap()
    );
    assert!(
        storage
            .account_chat_departure_denies_source(&[1; 32], &[2; 32], &intent.group, &[3; 32], None)
            .unwrap()
    );
    assert!(
        !storage
            .account_chat_departure_denies_source(
                &[1; 32],
                &[2; 32],
                &intent.group,
                &[3; 32],
                Some(AcceptedChatOrigin {
                    id: [5; 32],
                    order: 3
                })
            )
            .unwrap()
    );
    assert!(
        !storage
            .account_chat_departure_denies_source(&[1; 32], &[2; 32], &intent.group, &[9; 32], None)
            .unwrap()
    );
    assert!(
        storage
            .account_chat_departure_denies_source(&[9; 32], &[2; 32], &intent.group, &[3; 32], None)
            .is_err()
    );
}
#[test]
fn tail_failure_rolls_back_negative_cuts_and_outbox_together() {
    let storage = configured();
    let intent = fixture_intent();
    let calls = Cell::new(0);
    assert!(
        storage
            .apply_account_chat_departure(&[2; 32], &intent, &[[3; 32]], &|| {
                calls.set(calls.get() + 1);
                if calls.get() == 2 {
                    Err(StorageError::Busy("injected departure tail fault".into()))
                } else {
                    Ok(())
                }
            })
            .is_err()
    );
    assert!(
        !storage
            .account_chat_departure_denies_source(&[1; 32], &[2; 32], &intent.group, &[3; 32], None)
            .unwrap()
    );
    assert!(
        storage
            .account_chat_departure_outbox(&[1; 32], &[2; 32], &[3; 32], None, 1)
            .unwrap()
            .is_empty()
    );
    assert!(
        storage
            .apply_account_chat_departure(&[2; 32], &intent, &[[3; 32]], &|| Ok(()))
            .unwrap()
    );
}
#[test]
fn only_exact_authenticated_peer_route_can_acknowledge_and_refusal_is_honest() {
    let storage = configured();
    let intent = fixture_intent();
    storage
        .apply_account_chat_departure(&[2; 32], &intent, &[[3; 32]], &|| Ok(()))
        .unwrap();
    assert!(
        storage
            .acknowledge_account_chat_departure(
                &[1; 32],
                &[2; 32],
                &intent.action_id,
                &[9; 32],
                true,
                false,
                false,
                &|| Ok(())
            )
            .is_err()
    );
    storage
        .acknowledge_account_chat_departure(
            &[1; 32],
            &[2; 32],
            &intent.action_id,
            &[3; 32],
            false,
            true,
            false,
            &|| Ok(()),
        )
        .unwrap();
    let progress = storage
        .account_chat_departure_progress(&[1; 32], &[2; 32], &intent.group)
        .unwrap()
        .unwrap();
    assert_eq!(progress.pending_peers, 1);
    assert!(progress.needs_administrator);
    storage
        .acknowledge_account_chat_departure(
            &[1; 32],
            &[2; 32],
            &intent.action_id,
            &[3; 32],
            true,
            false,
            false,
            &|| Ok(()),
        )
        .unwrap();
    let progress = storage
        .account_chat_departure_progress(&[1; 32], &[2; 32], &intent.group)
        .unwrap()
        .unwrap();
    assert_eq!(progress.pending_peers, 0);
    assert!(!progress.needs_administrator);
}
#[test]
fn malformed_target_scope_and_received_transitive_routes_are_refused() {
    let storage = configured();
    let mut intent = fixture_intent();
    intent.targets.push(intent.targets[0].clone());
    intent.action_id = intent.identity();
    assert!(
        storage
            .apply_account_chat_departure(&[2; 32], &intent, &[[3; 32]], &|| Ok(()))
            .is_err()
    );
    let mut received = fixture_intent();
    received.initiator = [3; 32];
    received.action_id = received.identity();
    assert!(
        storage
            .apply_account_chat_departure(&[2; 32], &received, &[[4; 32]], &|| Ok(()))
            .is_err()
    );
}

#[test]
fn offline_receipts_and_awaiting_sources_do_not_claim_completion() {
    let storage = configured();
    let intent = fixture_intent();
    storage
        .apply_account_chat_departure(&[2; 32], &intent, &[[3; 32]], &|| Ok(()))
        .unwrap();
    storage
        .mark_account_chat_departure_local_state(
            &[1; 32],
            &[2; 32],
            &intent.action_id,
            AccountChatDepartureLocalState::Complete,
            &|| Ok(()),
        )
        .unwrap();
    let progress = storage
        .account_chat_departure_progress(&[1; 32], &[2; 32], &intent.group)
        .unwrap()
        .unwrap();
    assert!(progress.local_complete);
    assert!(!progress.global_complete);
    assert_eq!(progress.pending_peers, 1);
    storage
        .acknowledge_account_chat_departure(
            &[1; 32],
            &[2; 32],
            &intent.action_id,
            &[3; 32],
            false,
            false,
            true,
            &|| Ok(()),
        )
        .unwrap();
    assert!(
        storage
            .account_chat_departure_progress(&[1; 32], &[2; 32], &intent.group)
            .unwrap()
            .unwrap()
            .awaiting_sources
    );
    assert!(
        storage
            .acknowledge_account_chat_departure(
                &[1; 32],
                &[2; 32],
                &intent.action_id,
                &[3; 32],
                true,
                false,
                true,
                &|| Ok(())
            )
            .is_err()
    );
    storage
        .acknowledge_account_chat_departure(
            &[1; 32],
            &[2; 32],
            &intent.action_id,
            &[3; 32],
            true,
            false,
            false,
            &|| Ok(()),
        )
        .unwrap();
    storage
        .finalize_account_chat_departure_coordinator(&[1; 32], &[2; 32], &|| Ok(()))
        .unwrap();
    let progress = storage
        .account_chat_departure_progress(&[1; 32], &[2; 32], &intent.group)
        .unwrap()
        .unwrap();
    assert!(progress.global_complete);
    assert!(!progress.awaiting_sources);
    let row = storage
        .account_chat_departure_outbox(&[1; 32], &[2; 32], &[3; 32], None, 1)
        .unwrap()
        .remove(0);
    assert!(row.kind == AccountChatDepartureDeliveryKind::CompletionNotice);
}

#[test]
fn original_negative_operation_and_offline_outbox_survive_encrypted_reopen() {
    let root = tempfile::tempdir().unwrap();
    let path = root.path().join("departure.db");
    let key = crate::SqlCipherKey::new("42".repeat(32)).unwrap();
    let storage = SqliteAccountStorage::open_encrypted(&path, &key).unwrap();
    configure(&storage);
    let intent = fixture_intent();
    storage
        .apply_account_chat_departure(&[2; 32], &intent, &[[3; 32]], &|| Ok(()))
        .unwrap();
    storage
        .mark_account_chat_departure_local_state(
            &[1; 32],
            &[2; 32],
            &intent.action_id,
            AccountChatDepartureLocalState::Complete,
            &|| Ok(()),
        )
        .unwrap();
    drop(storage);
    let reopened = SqliteAccountStorage::open_encrypted(&path, &key).unwrap();
    let progress = reopened
        .account_chat_departure_progress(&[1; 32], &[2; 32], &intent.group)
        .unwrap()
        .unwrap();
    assert_eq!(progress.action_id, intent.action_id);
    assert!(progress.local_complete);
    assert!(!progress.global_complete);
    assert_eq!(progress.pending_peers, 1);
    let row = reopened
        .account_chat_departure_outbox(&[1; 32], &[2; 32], &[3; 32], None, 1)
        .unwrap()
        .remove(0);
    assert!(row.intent == intent && row.kind == AccountChatDepartureDeliveryKind::Intent);
    assert!(
        reopened
            .account_chat_departure_denies_source(
                &[1; 32],
                &[2; 32],
                &intent.group,
                &[3; 32],
                Some(intent.targets[0].accepted_origin)
            )
            .unwrap()
    );
}
