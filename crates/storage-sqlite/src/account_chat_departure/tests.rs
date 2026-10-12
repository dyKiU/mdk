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
    set_source_origin(
        storage,
        [3; 32],
        AcceptedChatOrigin {
            id: [4; 32],
            order: 2,
        },
    );
}
fn set_source_origin(storage: &SqliteAccountStorage, source: [u8; 32], origin: AcceptedChatOrigin) {
    let conn = storage.lock().unwrap();
    let exists:bool=conn.query_row("SELECT EXISTS(SELECT 1 FROM mirrored_chat_origin_current WHERE account=?1 AND local_device=?2 AND source_device=?3 AND group_id=?4)",params![[1u8;32].as_slice(),[2u8;32].as_slice(),source.as_slice(),[8u8;16].as_slice()],|row|row.get(0)).unwrap();
    let sql = if exists {
        "UPDATE mirrored_chat_origin_current SET origin_id=?5,origin_order=?6,epoch=?6 WHERE account=?1 AND local_device=?2 AND source_device=?3 AND group_id=?4"
    } else {
        "INSERT INTO mirrored_chat_origin_current(account,local_device,source_device,group_id,origin_id,origin_order,epoch) VALUES(?1,?2,?3,?4,?5,?6,?6)"
    };
    conn.execute(
        sql,
        params![
            [1u8; 32].as_slice(),
            [2u8; 32].as_slice(),
            source.as_slice(),
            [8u8; 16].as_slice(),
            origin.id.as_slice(),
            origin.order as i64
        ],
    )
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
                AccountChatDepartureReceiptStatus {
                    complete: true,
                    needs_administrator: false,
                    awaiting_sources: false
                },
                &|| Ok(()),
            )
            .is_err()
    );
    storage
        .acknowledge_account_chat_departure(
            &[1; 32],
            &[2; 32],
            &intent.action_id,
            &[3; 32],
            AccountChatDepartureReceiptStatus {
                complete: false,
                needs_administrator: true,
                awaiting_sources: false,
            },
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
            AccountChatDepartureReceiptStatus {
                complete: true,
                needs_administrator: false,
                awaiting_sources: false,
            },
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
            AccountChatDepartureReceiptStatus {
                complete: false,
                needs_administrator: false,
                awaiting_sources: true,
            },
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
                AccountChatDepartureReceiptStatus {
                    complete: true,
                    needs_administrator: false,
                    awaiting_sources: true
                },
                &|| Ok(()),
            )
            .is_err()
    );
    storage
        .acknowledge_account_chat_departure(
            &[1; 32],
            &[2; 32],
            &intent.action_id,
            &[3; 32],
            AccountChatDepartureReceiptStatus {
                complete: true,
                needs_administrator: false,
                awaiting_sources: false,
            },
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

#[test]
fn published_leave_clears_local_actionable_refusal_but_waits_for_actual_removal() {
    let storage = configured();
    let intent = fixture_intent();
    storage
        .apply_account_chat_departure(&[2; 32], &intent, &[[3; 32]], &|| Ok(()))
        .unwrap();
    storage
        .mark_account_chat_departure_needs_administrator(
            &[1; 32],
            &[2; 32],
            &intent.action_id,
            true,
            &|| Ok(()),
        )
        .unwrap();
    assert!(
        storage
            .account_chat_departure_progress(&[1; 32], &[2; 32], &intent.group)
            .unwrap()
            .unwrap()
            .needs_administrator
    );
    storage
        .mark_account_chat_departure_local_state(
            &[1; 32],
            &[2; 32],
            &intent.action_id,
            AccountChatDepartureLocalState::Published,
            &|| Ok(()),
        )
        .unwrap();
    let pending = storage
        .account_chat_departure_progress(&[1; 32], &[2; 32], &intent.group)
        .unwrap()
        .unwrap();
    assert!(!pending.needs_administrator && !pending.local_complete && !pending.global_complete);
    storage
        .acknowledge_account_chat_departure(
            &[1; 32],
            &[2; 32],
            &intent.action_id,
            &[3; 32],
            AccountChatDepartureReceiptStatus {
                complete: true,
                needs_administrator: false,
                awaiting_sources: false,
            },
            &|| Ok(()),
        )
        .unwrap();
    storage
        .finalize_account_chat_departure_coordinator(&[1; 32], &[2; 32], &|| Ok(()))
        .unwrap();
    assert!(
        !storage
            .account_chat_departure_progress(&[1; 32], &[2; 32], &intent.group)
            .unwrap()
            .unwrap()
            .global_complete
    );
}

#[test]
fn fresh_accepted_lineage_admits_distinct_negative_operation_without_old_cut() {
    let storage = configured();
    let first = fixture_intent();
    storage
        .apply_account_chat_departure(&[2; 32], &first, &[[3; 32]], &|| Ok(()))
        .unwrap();
    storage
        .mark_account_chat_departure_local_state(
            &[1; 32],
            &[2; 32],
            &first.action_id,
            AccountChatDepartureLocalState::Complete,
            &|| Ok(()),
        )
        .unwrap();
    storage
        .acknowledge_account_chat_departure(
            &[1; 32],
            &[2; 32],
            &first.action_id,
            &[3; 32],
            AccountChatDepartureReceiptStatus {
                complete: true,
                needs_administrator: false,
                awaiting_sources: false,
            },
            &|| Ok(()),
        )
        .unwrap();
    storage
        .finalize_account_chat_departure_coordinator(&[1; 32], &[2; 32], &|| Ok(()))
        .unwrap();
    let mut fresh = first.clone();
    fresh.targets[0].accepted_origin = AcceptedChatOrigin {
        id: [5; 32],
        order: 3,
    };
    fresh.action_id = fresh.identity();
    assert!(fresh.action_id != first.action_id);
    set_source_origin(&storage, [3; 32], fresh.targets[0].accepted_origin);
    assert!(
        !storage
            .account_chat_departure_denies_source(
                &[1; 32],
                &[2; 32],
                &fresh.group,
                &[3; 32],
                Some(fresh.targets[0].accepted_origin)
            )
            .unwrap()
    );
    storage
        .apply_account_chat_departure(&[2; 32], &fresh, &[[3; 32]], &|| Ok(()))
        .unwrap();
    let current = storage
        .account_chat_departure_progress(&[1; 32], &[2; 32], &fresh.group)
        .unwrap()
        .unwrap();
    assert_eq!(current.action_id, fresh.action_id);
    assert!(!current.local_complete && !current.global_complete);
}

#[test]
fn local_publication_does_not_clear_authenticated_peer_awaiting_source_receipt() {
    let storage = configured();
    let intent = fixture_intent();
    storage
        .apply_account_chat_departure(&[2; 32], &intent, &[[3; 32], [6; 32]], &|| Ok(()))
        .unwrap();
    storage
        .mark_account_chat_departure_needs_administrator(
            &[1; 32],
            &[2; 32],
            &intent.action_id,
            true,
            &|| Ok(()),
        )
        .unwrap();
    storage
        .mark_account_chat_departure_awaiting_sources(
            &[1; 32],
            &[2; 32],
            &intent.action_id,
            true,
            &|| Ok(()),
        )
        .unwrap();
    storage
        .acknowledge_account_chat_departure(
            &[1; 32],
            &[2; 32],
            &intent.action_id,
            &[3; 32],
            AccountChatDepartureReceiptStatus {
                complete: false,
                needs_administrator: false,
                awaiting_sources: true,
            },
            &|| Ok(()),
        )
        .unwrap();
    storage
        .acknowledge_account_chat_departure(
            &[1; 32],
            &[2; 32],
            &intent.action_id,
            &[6; 32],
            AccountChatDepartureReceiptStatus {
                complete: true,
                needs_administrator: false,
                awaiting_sources: false,
            },
            &|| Ok(()),
        )
        .unwrap();
    storage
        .mark_account_chat_departure_local_state(
            &[1; 32],
            &[2; 32],
            &intent.action_id,
            AccountChatDepartureLocalState::Published,
            &|| Ok(()),
        )
        .unwrap();
    let pending = storage
        .account_chat_departure_progress(&[1; 32], &[2; 32], &intent.group)
        .unwrap()
        .unwrap();
    assert!(!pending.needs_administrator);
    assert!(pending.awaiting_sources);
    assert!(!pending.local_complete && !pending.global_complete);
    assert_eq!(pending.pending_peers, 1);
    // Even our later genuine removal does not complete the coordinator while
    // that independently authenticated peer still reports unknown sources.
    storage
        .mark_account_chat_departure_local_state(
            &[1; 32],
            &[2; 32],
            &intent.action_id,
            AccountChatDepartureLocalState::Complete,
            &|| Ok(()),
        )
        .unwrap();
    storage
        .finalize_account_chat_departure_coordinator(&[1; 32], &[2; 32], &|| Ok(()))
        .unwrap();
    let pending = storage
        .account_chat_departure_progress(&[1; 32], &[2; 32], &intent.group)
        .unwrap()
        .unwrap();
    assert!(pending.local_complete && pending.awaiting_sources);
    assert!(!pending.global_complete);
    assert_eq!(pending.pending_peers, 1);
    let conn = storage.lock().unwrap();
    let local_awaiting: bool = conn
        .query_row(
            "SELECT awaiting_sources FROM account_chat_departures WHERE action_id=?1",
            [intent.action_id.as_slice()],
            |row| row.get(0),
        )
        .unwrap();
    let peer_awaiting:bool=conn.query_row("SELECT awaiting_sources FROM account_chat_departure_routes WHERE action_id=?1 AND peer_device=?2",params![intent.action_id.as_slice(),[3u8;32].as_slice()],|row|row.get(0)).unwrap();
    assert!(!local_awaiting && peer_awaiting);
}

#[test]
fn delayed_old_completed_intent_does_not_replace_fresh_pending_progress() {
    let storage = configured();
    let mut fresh = fixture_intent();
    fresh.targets[0].accepted_origin = AcceptedChatOrigin {
        id: [5; 32],
        order: 3,
    };
    fresh.action_id = fresh.identity();
    set_source_origin(&storage, [3; 32], fresh.targets[0].accepted_origin);
    storage
        .apply_account_chat_departure(&[2; 32], &fresh, &[[3; 32]], &|| Ok(()))
        .unwrap();
    let mut old = fixture_intent();
    old.initiator = [3; 32];
    old.action_id = old.identity();
    storage
        .apply_account_chat_departure(&[2; 32], &old, &[[3; 32]], &|| Ok(()))
        .unwrap();
    storage
        .mark_account_chat_departure_local_state(
            &[1; 32],
            &[2; 32],
            &old.action_id,
            AccountChatDepartureLocalState::Complete,
            &|| Ok(()),
        )
        .unwrap();
    storage
        .account_chat_departure_completion(
            &[1; 32],
            &[2; 32],
            &old.action_id,
            &[3; 32],
            false,
            &|| Ok(()),
        )
        .unwrap();
    let progress = storage
        .account_chat_departure_progress(&[1; 32], &[2; 32], &fresh.group)
        .unwrap()
        .unwrap();
    assert_eq!(progress.action_id, fresh.action_id);
    assert!(!progress.global_complete && !progress.local_complete);
}

#[test]
fn concurrent_current_lineage_pending_operation_takes_precedence_over_completed() {
    let storage = configured();
    let pending = fixture_intent();
    storage
        .apply_account_chat_departure(&[2; 32], &pending, &[[3; 32]], &|| Ok(()))
        .unwrap();
    let mut complete = pending.clone();
    complete.initiator = [3; 32];
    complete.action_id = complete.identity();
    storage
        .apply_account_chat_departure(&[2; 32], &complete, &[[3; 32]], &|| Ok(()))
        .unwrap();
    storage
        .mark_account_chat_departure_local_state(
            &[1; 32],
            &[2; 32],
            &complete.action_id,
            AccountChatDepartureLocalState::Complete,
            &|| Ok(()),
        )
        .unwrap();
    storage
        .account_chat_departure_completion(
            &[1; 32],
            &[2; 32],
            &complete.action_id,
            &[3; 32],
            false,
            &|| Ok(()),
        )
        .unwrap();
    let progress = storage
        .account_chat_departure_progress(&[1; 32], &[2; 32], &pending.group)
        .unwrap()
        .unwrap();
    assert_eq!(progress.action_id, pending.action_id);
    assert!(!progress.global_complete);
}

#[test]
fn missing_current_origin_and_fresh_origin_without_an_operation_supply_no_old_progress() {
    let storage = configured();
    let old = fixture_intent();
    storage
        .apply_account_chat_departure(&[2; 32], &old, &[[3; 32]], &|| Ok(()))
        .unwrap();
    // A separate bounded negative row whose source observation was never
    // recorded models missing metadata without deleting retained lineage.
    let mut unknown = old.clone();
    unknown.group = GroupId::new(vec![9; 16]);
    unknown.targets[0].source_device = [9; 32];
    unknown.action_id = unknown.identity();
    storage
        .apply_account_chat_departure(&[2; 32], &unknown, &[[3; 32]], &|| Ok(()))
        .unwrap();
    assert!(
        storage
            .account_chat_departure_progress(&[1; 32], &[2; 32], &unknown.group)
            .unwrap()
            .is_none()
    );
    set_source_origin(
        &storage,
        [3; 32],
        AcceptedChatOrigin {
            id: [5; 32],
            order: 3,
        },
    );
    assert!(
        storage
            .account_chat_departure_progress(&[1; 32], &[2; 32], &old.group)
            .unwrap()
            .is_none()
    );
    assert!(
        !storage
            .account_chat_departure_denies_source(
                &[1; 32],
                &[2; 32],
                &old.group,
                &[3; 32],
                Some(AcceptedChatOrigin {
                    id: [5; 32],
                    order: 3
                })
            )
            .unwrap()
    );
}

#[test]
fn source_local_origin_orders_do_not_globally_supersede_other_sources() {
    let storage = configured();
    let mut intent = fixture_intent();
    intent.targets.push(AccountChatDepartureTarget {
        source_device: [6; 32],
        accepted_origin: AcceptedChatOrigin {
            id: [6; 32],
            order: 7,
        },
    });
    intent.action_id = intent.identity();
    set_source_origin(&storage, [6; 32], intent.targets[1].accepted_origin);
    storage
        .apply_account_chat_departure(&[2; 32], &intent, &[[3; 32], [6; 32]], &|| Ok(()))
        .unwrap();
    set_source_origin(
        &storage,
        [3; 32],
        AcceptedChatOrigin {
            id: [5; 32],
            order: 500,
        },
    );
    let progress = storage
        .account_chat_departure_progress(&[1; 32], &[2; 32], &intent.group)
        .unwrap()
        .unwrap();
    assert_eq!(progress.action_id, intent.action_id);
    assert!(!progress.global_complete);
    assert!(
        storage
            .account_chat_departure_denies_source(
                &[1; 32],
                &[2; 32],
                &intent.group,
                &[6; 32],
                Some(intent.targets[1].accepted_origin)
            )
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
                    order: 500
                })
            )
            .unwrap()
    );
}

#[test]
fn departure_cut_removes_live_disclosure_and_blocks_late_records_but_not_fresh_lineage() {
    use cgka_traits::{
        group::ProtocolProfile,
        mirrored_chat_catalog::{
            MirroredChatCatalogStorage, MirroredChatEntry, MirroredChatScope, MirroredChatState,
        },
        mirrored_chat_messages::{MirroredChatMessageStorage, MirroredChatRecord},
    };
    let storage = configured();
    let intent = fixture_intent();
    let scope = MirroredChatScope {
        account: [1; 32],
        local_device: [2; 32],
        source_device: [3; 32],
        policy_digest: [6; 32],
        protected_group: intent.protected_group.clone(),
        protected_generation: 1,
    };
    let mut catalog = MirroredChatEntry {
        group_id: intent.group.clone(),
        source_epoch: 2,
        source_sequence: 1,
        source_digest: [8; 32],
        profile: ProtocolProfile::Current,
        name: "paired fixture".into(),
        description: String::new(),
        state: MirroredChatState::Active,
        accepted_origin: Some(intent.targets[0].accepted_origin),
        same_account_source_count: Some(1),
    };
    storage
        .apply_mirrored_chat_catalog(&scope, &[catalog.clone()], &|| Ok(()))
        .unwrap();
    let payload = serde_json::to_vec(&("fixture", Vec::<Vec<String>>::new())).unwrap();
    let mut record = MirroredChatRecord {
        event_id: [8; 32],
        author: [7; 32],
        created_at: 10,
        kind: 9,
        content_digest: Some(Sha256::digest(&payload).into()),
        payload,
        expires_at: None,
        deleted: false,
        source_epoch: 2,
        source_sequence: 1,
        source_digest: [8; 32],
        accepted_origin: catalog.accepted_origin,
    };
    storage
        .apply_mirrored_chat_messages(&scope, &intent.group, &[record.clone()], 1, &|| Ok(()))
        .unwrap();
    assert_eq!(
        storage
            .account_conversation_observation_window(&[scope.clone()], &intent.group, None, 128, 1)
            .unwrap()
            .len(),
        1
    );
    storage
        .apply_account_chat_departure(&[2; 32], &intent, &[[3; 32]], &|| Ok(()))
        .unwrap();
    assert!(
        storage
            .mirrored_catalog_observation_page(&[scope.clone()], None, 128)
            .unwrap()
            .is_empty()
    );
    assert!(
        storage
            .account_conversation_observation_window(&[scope.clone()], &intent.group, None, 128, 1)
            .unwrap()
            .is_empty()
    );
    assert!(
        storage
            .current_mirrored_chat_origin_observation(&[1; 32], &[2; 32], &[3; 32], &intent.group)
            .unwrap()
            == catalog.accepted_origin
    );
    catalog.source_sequence = 2;
    record.source_sequence = 2;
    assert_eq!(
        storage
            .apply_mirrored_chat_catalog(&scope, &[catalog.clone()], &|| Ok(()))
            .unwrap(),
        0
    );
    assert!(
        storage
            .apply_mirrored_chat_messages(&scope, &intent.group, &[record.clone()], 1, &|| Ok(()))
            .is_err()
    );
    catalog.accepted_origin = Some(AcceptedChatOrigin {
        id: [5; 32],
        order: 3,
    });
    catalog.source_epoch = 3;
    catalog.source_sequence = 3;
    storage
        .apply_mirrored_chat_catalog(&scope, &[catalog.clone()], &|| Ok(()))
        .unwrap();
    assert_eq!(
        storage
            .mirrored_catalog_observation_page(&[scope.clone()], None, 128)
            .unwrap()
            .len(),
        1
    );
    assert!(
        storage
            .account_conversation_observation_window(&[scope.clone()], &intent.group, None, 128, 1)
            .unwrap()
            .is_empty()
    );
    record.event_id = [9; 32];
    record.source_digest = [9; 32];
    record.source_sequence = 3;
    record.source_epoch = 3;
    record.accepted_origin = catalog.accepted_origin;
    storage
        .apply_mirrored_chat_messages(&scope, &intent.group, &[record], 1, &|| Ok(()))
        .unwrap();
    assert_eq!(
        storage
            .account_conversation_observation_window(&[scope], &intent.group, None, 128, 1)
            .unwrap()
            .len(),
        1
    );
}

#[test]
fn immutable_departure_rows_refuse_raw_replace_and_upsert_without_recursive_triggers() {
    for recursive in [None, Some(false), Some(true)] {
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
        storage
            .acknowledge_account_chat_departure(
                &[1; 32],
                &[2; 32],
                &intent.action_id,
                &[3; 32],
                AccountChatDepartureReceiptStatus {
                    complete: true,
                    needs_administrator: false,
                    awaiting_sources: false,
                },
                &|| Ok(()),
            )
            .unwrap();
        storage
            .finalize_account_chat_departure_coordinator(&[1; 32], &[2; 32], &|| Ok(()))
            .unwrap();
        storage
            .account_chat_departure_completion(
                &[1; 32],
                &[2; 32],
                &intent.action_id,
                &[3; 32],
                true,
                &|| Ok(()),
            )
            .unwrap();
        {
            let conn = storage.lock().unwrap();
            if let Some(recursive) = recursive {
                conn.pragma_update(None, "recursive_triggers", recursive)
                    .unwrap();
            }
            let original: Vec<u8> = conn
                .query_row(
                    "SELECT record FROM account_chat_departures WHERE action_id=?1",
                    [intent.action_id.as_slice()],
                    |row| row.get(0),
                )
                .unwrap();
            for suffix in [
                "",
                " ON CONFLICT(action_id) DO UPDATE SET record=excluded.record,local_state=0,global_complete=0",
            ] {
                let sql = format!(
                    "INSERT OR REPLACE INTO account_chat_departures(action_id,account,local_device,initiator,group_id,record) VALUES(?1,?2,?3,?4,?5,?6){suffix}"
                );
                assert!(
                    conn.execute(
                        &sql,
                        params![
                            intent.action_id.as_slice(),
                            intent.account.as_slice(),
                            [2u8; 32].as_slice(),
                            intent.initiator.as_slice(),
                            intent.group.as_slice(),
                            b"different".as_slice()
                        ]
                    )
                    .is_err()
                );
            }
            for suffix in [
                "",
                " ON CONFLICT(action_id,source_device) DO UPDATE SET origin_id=excluded.origin_id,origin_order=excluded.origin_order",
            ] {
                let sql = format!(
                    "INSERT OR REPLACE INTO account_chat_departure_cuts VALUES(?1,?2,?3,1){suffix}"
                );
                assert!(
                    conn.execute(
                        &sql,
                        params![
                            intent.action_id.as_slice(),
                            [3u8; 32].as_slice(),
                            [9u8; 32].as_slice()
                        ]
                    )
                    .is_err()
                );
            }
            for suffix in [
                "",
                " ON CONFLICT(action_id,peer_device) DO UPDATE SET acknowledged=0,complete=0,final_acknowledged=0",
            ] {
                let sql = format!(
                    "INSERT OR REPLACE INTO account_chat_departure_routes(action_id,peer_device) VALUES(?1,?2){suffix}"
                );
                assert!(
                    conn.execute(
                        &sql,
                        params![intent.action_id.as_slice(), [3u8; 32].as_slice()]
                    )
                    .is_err()
                );
            }
            assert!(conn.execute("INSERT INTO account_chat_departure_routes(action_id,peer_device,acknowledged,complete) VALUES(?1,?2,1,1)",params![intent.action_id.as_slice(),[9u8;32].as_slice()]).is_err());
            assert!(conn.execute("UPDATE account_chat_departure_routes SET complete=0,acknowledged=0,final_acknowledged=0 WHERE action_id=?1",[intent.action_id.as_slice()]).is_err());
            assert!(
                conn.execute(
                    "DELETE FROM account_chat_departure_routes WHERE action_id=?1",
                    [intent.action_id.as_slice()]
                )
                .is_err()
            );
            assert!(
                conn.execute(
                    "UPDATE account_chat_departures SET global_complete=0 WHERE action_id=?1",
                    [intent.action_id.as_slice()]
                )
                .is_err()
            );
            let after: Vec<u8> = conn
                .query_row(
                    "SELECT record FROM account_chat_departures WHERE action_id=?1",
                    [intent.action_id.as_slice()],
                    |row| row.get(0),
                )
                .unwrap();
            assert_eq!(after, original);
            let cut:(Vec<u8>,i64)=conn.query_row("SELECT origin_id,origin_order FROM account_chat_departure_cuts WHERE action_id=?1",[intent.action_id.as_slice()],|row|Ok((row.get(0)?,row.get(1)?))).unwrap();
            assert!(
                cut == (
                    intent.targets[0].accepted_origin.id.to_vec(),
                    intent.targets[0].accepted_origin.order as i64
                )
            );
            let route:(bool,bool,bool)=conn.query_row("SELECT acknowledged,complete,final_acknowledged FROM account_chat_departure_routes WHERE action_id=?1",[intent.action_id.as_slice()],|row|Ok((row.get(0)?,row.get(1)?,row.get(2)?))).unwrap();
            assert_eq!(route, (true, true, true));
        }
        // Actual API exact retry reads immutable rows before insertion, so the
        // stronger raw SQL guards do not break legitimate idempotence.
        assert!(
            !storage
                .apply_account_chat_departure(&[2; 32], &intent, &[[3; 32]], &|| Ok(()))
                .unwrap()
        );
        assert!(
            storage
                .account_chat_departure_progress(&[1; 32], &[2; 32], &intent.group)
                .unwrap()
                .unwrap()
                .global_complete
        );
    }
}

#[test]
fn stale_reply_publication_preserves_newer_completion_receipt() {
    for coordinator_completed in [false, true] {
        let storage = configured();
        let mut intent = fixture_intent();
        intent.initiator = [3; 32];
        intent.action_id = intent.identity();
        storage.apply_account_chat_departure(&[2; 32], &intent, &[[3; 32]], &|| Ok(())).unwrap();
        let old = storage.account_chat_departure_outbox(&[1; 32], &[2; 32], &[3; 32], None, 16).unwrap();
        assert_eq!(old.len(), 1);
        assert!(old[0].kind == AccountChatDepartureDeliveryKind::StatusReceipt);
        assert!(!old[0].complete);
        storage.mark_account_chat_departure_local_state(&[1; 32], &[2; 32], &intent.action_id, AccountChatDepartureLocalState::Complete, &|| Ok(())).unwrap();
        if coordinator_completed {
            storage.account_chat_departure_completion(&[1; 32], &[2; 32], &intent.action_id, &[3; 32], false, &|| Ok(())).unwrap();
        }
        storage.account_chat_departure_reply_published(&[1; 32], &[2; 32], &intent.action_id, &|| Ok(())).unwrap();
        let pending = storage.account_chat_departure_outbox(&[1; 32], &[2; 32], &[3; 32], None, 16).unwrap();
        assert_eq!(pending.len(), 1, "an older published receipt must not consume newer progress");
        assert!(pending[0].complete);
        assert!(pending[0].kind == if coordinator_completed { AccountChatDepartureDeliveryKind::CompletionAcknowledgement } else { AccountChatDepartureDeliveryKind::StatusReceipt });
    }
}
