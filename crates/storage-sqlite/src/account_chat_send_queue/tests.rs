//! Synthetic storage acceptance. Member authentication and publication stay Core/App-owned.
use super::*;
use cgka_traits::{
    MemberId,
    approved_account_sharing_policy::{
        ApprovedAccountSharingPolicyStorage, approved_account_sharing_identity,
    },
    storage::{AccountDeviceSignerBinding, AccountDeviceSignerStorage, GroupStorage},
};
use std::cell::Cell;
fn configure(s: &SqliteAccountStorage, local: u8) {
    s.lock()
        .unwrap()
        .execute(
            "INSERT INTO account_state(label,updated_at,local_account_id_hex) VALUES('test',0,?1)",
            [hex::encode([1; 32])],
        )
        .unwrap();
    s.put_account_device_signer(&AccountDeviceSignerBinding {
        marmot_identity: MemberId::new(vec![1; 32]),
        mls_signature_public_key: vec![local; 32],
    })
    .unwrap();
}
fn route(s: &SqliteAccountStorage, local: u8, peer: u8, approval: u8) -> AccountChatSendRoute {
    let p = ApprovedAccountSharingPolicy {
        account: [1; 32],
        local_device: [local; 32],
        peer_device: [peer; 32],
        protected_group: GroupId::new(vec![5; 16]),
        approval_id: [approval; 32],
        version: 1,
        capabilities: 0x0f,
        created_at: 10,
        approved_protected_epoch: 1,
        revoked: false,
    };
    s.put_approved_account_sharing_policy(&p, &|| Ok(()))
        .unwrap();
    AccountChatSendRoute {
        policy_id: approved_account_sharing_identity(
            &p.account,
            &p.protected_group,
            &p.local_device,
            &p.peer_device,
            &p.approval_id,
        )
        .unwrap(),
        local_device: p.local_device,
        peer_device: p.peer_device,
    }
}
fn stored(local: u8, peer: u8) -> (SqliteAccountStorage, AccountChatSendRoute) {
    let s = SqliteAccountStorage::in_memory().unwrap();
    configure(&s, local);
    let r = route(&s, local, peer, 4);
    (s, r)
}
fn intent(n: u32) -> AccountChatSendIntent {
    let event = MarmotAppEvent::new(
        hex::encode([1; 32]),
        100,
        9,
        vec![vec!["p".into(), "synthetic".into()]],
        "queued",
    );
    let payload = event.encode().unwrap();
    let mut id = [0; 32];
    id[..4].copy_from_slice(&n.to_be_bytes());
    AccountChatSendIntent {
        intent_id: id,
        account: [1; 32],
        originating_device: [2; 32],
        group: GroupId::new(vec![8; 16]),
        ordinary_event_id: hex::decode(event.id).unwrap().try_into().unwrap(),
        payload_digest: Sha256::digest(&payload).into(),
        event_payload: payload,
        created_at: 100,
    }
}
fn admit(
    s: &SqliteAccountStorage,
    i: &AccountChatSendIntent,
    r: &AccountChatSendRoute,
) -> StorageResult<()> {
    s.admit_account_chat_send_intent(i, r, &|| Ok(()))
}
fn pending(s: &SqliteAccountStorage, local: u8) -> Vec<AccountChatQueuedSend> {
    s.pending_account_chat_sends(&[1; 32], &[local; 32], None, 128)
        .unwrap()
}
fn receipt(
    i: &AccountChatSendIntent,
    r: &AccountChatSendRoute,
    member: u8,
    state: AccountChatSendState,
) -> AccountChatSendReceipt {
    AccountChatSendReceipt {
        intent_id: i.intent_id,
        route: r.clone(),
        actual_member_device: [member; 32],
        state,
    }
}
fn tail_failure() -> impl Fn() -> StorageResult<()> {
    let calls = Cell::new(0);
    move || {
        calls.set(calls.get() + 1);
        if calls.get() == 2 {
            Err(invalid())
        } else {
            Ok(())
        }
    }
}
#[test]
fn account_chat_queue_exact_event_retry_and_multiple_sources_keep_one_ordinary_id() {
    let (s, r) = stored(2, 3);
    let i = intent(1);
    admit(&s, &i, &r).unwrap();
    admit(&s, &i, &r).unwrap();
    let other = route(&s, 2, 6, 7);
    admit(&s, &i, &other).unwrap();
    let queued = pending(&s, 2);
    assert_eq!(queued.len(), 2);
    assert!(queued.iter().all(|q| q.intent == i));
    let ack = receipt(&i, &r, 3, AccountChatSendState::Received);
    s.receive_account_chat_send_receipt(&i.account, &ack, &|| Ok(()))
        .unwrap();
    let mut wrong = receipt(
        &i,
        &other,
        6,
        AccountChatSendState::Published {
            event_id: i.intent_id,
        },
    );
    assert!(
        s.receive_account_chat_send_receipt(&i.account, &wrong, &|| Ok(()))
            .is_err()
    );
    wrong.state = AccountChatSendState::Published {
        event_id: i.ordinary_event_id,
    };
    s.receive_account_chat_send_receipt(&i.account, &wrong, &|| Ok(()))
        .unwrap();
    assert!(pending(&s, 2).is_empty());
    // Lost ACK retry through another member still maps the exact canonical event.
    let published = receipt(
        &i,
        &r,
        3,
        AccountChatSendState::Published {
            event_id: i.ordinary_event_id,
        },
    );
    s.receive_account_chat_send_receipt(&i.account, &published, &|| Ok(()))
        .unwrap();
    s.receive_account_chat_send_receipt(&i.account, &ack, &|| Ok(()))
        .unwrap();
    admit(&s, &i, &r).unwrap();
    assert!(pending(&s, 2).is_empty());
    assert!(s.list_group_records().unwrap().is_empty());
    assert_eq!(
        s.lock()
            .unwrap()
            .query_row("SELECT count(*) FROM app_events", [], |r| r
                .get::<_, i64>(0))
            .unwrap(),
        0
    );
}
#[test]
fn account_chat_queue_original_tail_rolls_back_intent_receipt_and_outbox() {
    let (s, r) = stored(3, 2);
    let i = intent(1);
    assert!(
        s.admit_account_chat_send_intent(&i, &r, &tail_failure())
            .is_err()
    );
    assert!(pending(&s, 3).is_empty());
    admit(&s, &i, &r).unwrap();
    let ack = receipt(
        &i,
        &r,
        3,
        AccountChatSendState::Published {
            event_id: i.ordinary_event_id,
        },
    );
    assert!(
        s.stage_account_chat_send_receipt(&i.account, &ack, &tail_failure())
            .is_err()
    );
    assert!(pending(&s, 3)[0].state == AccountChatSendState::Queued);
    assert!(
        s.pending_account_chat_send_receipts(&i.account, &[3; 32], None, 128)
            .unwrap()
            .is_empty()
    );
    s.stage_account_chat_send_receipt(&i.account, &ack, &|| Ok(()))
        .unwrap();
    s.stage_account_chat_send_receipt(&i.account, &ack, &|| Ok(()))
        .unwrap();
    assert!(pending(&s, 3).is_empty());
    assert!(
        s.pending_account_chat_send_receipts(&i.account, &[3; 32], None, 128)
            .unwrap()
            == vec![ack.clone()]
    );
    assert!(
        s.acknowledge_account_chat_send_receipt(
            &i.account,
            &[3; 32],
            &ack.digest(),
            &tail_failure()
        )
        .is_err()
    );
    assert_eq!(
        s.pending_account_chat_send_receipts(&i.account, &[3; 32], None, 128)
            .unwrap()
            .len(),
        1
    );
    s.acknowledge_account_chat_send_receipt(&i.account, &[3; 32], &ack.digest(), &|| Ok(()))
        .unwrap();
    s.acknowledge_account_chat_send_receipt(&i.account, &[3; 32], &ack.digest(), &|| Ok(()))
        .unwrap();
    assert!(
        s.pending_account_chat_send_receipts(&i.account, &[3; 32], None, 128)
            .unwrap()
            .is_empty()
    );
}
#[test]
fn account_chat_queue_route_denial_allows_other_source_but_origin_cancel_is_global() {
    let (s, r) = stored(2, 3);
    let i = intent(1);
    admit(&s, &i, &r).unwrap();
    let other = route(&s, 2, 6, 7);
    admit(&s, &i, &other).unwrap();
    let denied = receipt(&i, &r, 3, AccountChatSendState::Denied);
    s.receive_account_chat_send_receipt(&i.account, &denied, &|| Ok(()))
        .unwrap();
    assert_eq!(pending(&s, 2).len(), 1);
    assert!(admit(&s, &i, &r).is_err());
    let revive = receipt(
        &i,
        &r,
        3,
        AccountChatSendState::Published {
            event_id: i.ordinary_event_id,
        },
    );
    assert!(
        s.receive_account_chat_send_receipt(&i.account, &revive, &|| Ok(()))
            .is_err()
    );
    assert!(
        s.deny_account_chat_send_intent(&i.account, &[2; 32], &i.intent_id, &tail_failure())
            .is_err()
    );
    assert_eq!(pending(&s, 2).len(), 1);
    s.deny_account_chat_send_intent(&i.account, &[2; 32], &i.intent_id, &|| Ok(()))
        .unwrap();
    assert!(pending(&s, 2).is_empty());
    assert!(admit(&s, &i, &other).is_err());
    let fresh = route(&s, 2, 6, 9);
    assert!(admit(&s, &i, &fresh).is_err());
    let late = receipt(
        &i,
        &other,
        6,
        AccountChatSendState::Published {
            event_id: i.ordinary_event_id,
        },
    );
    assert!(
        s.receive_account_chat_send_receipt(&i.account, &late, &|| Ok(()))
            .is_err()
    );
}
#[test]
fn account_chat_queue_requires_exact_owner_policy_event_and_member_provenance() {
    let (s, r) = stored(2, 3);
    let i = intent(1);
    for n in 0..7 {
        let mut changed = i.clone();
        match n {
            0 => changed.account = [9; 32],
            1 => changed.ordinary_event_id = changed.intent_id,
            2 => changed.payload_digest = [8; 32],
            3 => changed.event_payload.clear(),
            4 => changed.originating_device = [9; 32],
            5 => changed.created_at += 1,
            _ => changed.event_payload = vec![0; 65537],
        };
        assert!(admit(&s, &changed, &r).is_err());
    }
    admit(&s, &i, &r).unwrap();
    let mut changed = i.clone();
    changed.group = GroupId::new(vec![9]);
    assert!(admit(&s, &changed, &r).is_err());
    let ack = receipt(&i, &r, 2, AccountChatSendState::Received);
    assert!(
        s.receive_account_chat_send_receipt(&i.account, &ack, &|| Ok(()))
            .is_err()
    );
    assert!(
        s.stage_account_chat_send_receipt(&i.account, &ack, &|| Ok(()))
            .is_ok()
    );
    assert!(
        s.pending_account_chat_sends(&[1; 32], &[3; 32], None, 128)
            .is_err()
    );
    assert!(
        s.pending_account_chat_sends(&[1; 32], &[2; 32], None, 129)
            .is_err()
    );
    s.revoke_account_sharing_policy(&r.policy_id, &|| Ok(()))
        .unwrap();
    assert!(pending(&s, 2).is_empty());
    assert!(admit(&s, &i, &r).is_err());
}
#[test]
fn account_chat_queue_encrypted_restart_retains_pending_outbox_and_terminal_fences() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("queue.db");
    let key = crate::SqlCipherKey::new("42".repeat(32)).unwrap();
    let s = SqliteAccountStorage::open_encrypted(&path, &key).unwrap();
    configure(&s, 3);
    let r = route(&s, 3, 2, 4);
    let i = intent(1);
    admit(&s, &i, &r).unwrap();
    s.close().unwrap();
    assert!(matches!(
        s.pending_account_chat_sends(&i.account, &[3; 32], None, 128),
        Err(StorageError::Closed(_))
    ));
    let s = SqliteAccountStorage::open_encrypted(&path, &key).unwrap();
    assert!(pending(&s, 3)[0].intent == i);
    let ack = receipt(
        &i,
        &r,
        3,
        AccountChatSendState::Published {
            event_id: i.ordinary_event_id,
        },
    );
    s.stage_account_chat_send_receipt(&i.account, &ack, &|| Ok(()))
        .unwrap();
    s.close().unwrap();
    let s = SqliteAccountStorage::open_encrypted(&path, &key).unwrap();
    assert!(pending(&s, 3).is_empty());
    assert!(
        s.pending_account_chat_send_receipts(&i.account, &[3; 32], None, 128)
            .unwrap()
            == vec![ack]
    );
    admit(&s, &i, &r).unwrap();
    assert!(pending(&s, 3).is_empty());
}
#[test]
fn account_chat_queue_sql_cannot_mutate_replace_or_reactivate_retained_facts() {
    let (s, r) = stored(3, 2);
    let i = intent(1);
    admit(&s, &i, &r).unwrap();
    {
        let c = s.lock().unwrap();
        for sql in [
            "DELETE FROM account_chat_send_intents",
            "UPDATE account_chat_send_intents SET payload=x'01'",
            "UPDATE account_chat_send_intents SET digest=zeroblob(32)",
            "INSERT OR REPLACE INTO account_chat_send_intents SELECT * FROM account_chat_send_intents",
            "DELETE FROM account_chat_send_routes",
            "UPDATE account_chat_send_routes SET policy_id=zeroblob(32)",
            "INSERT OR REPLACE INTO account_chat_send_routes SELECT * FROM account_chat_send_routes",
        ] {
            assert!(c.execute(sql, []).is_err(), "{sql}");
        }
    }
    let ack = receipt(
        &i,
        &r,
        3,
        AccountChatSendState::Published {
            event_id: i.ordinary_event_id,
        },
    );
    s.stage_account_chat_send_receipt(&i.account, &ack, &|| Ok(()))
        .unwrap();
    let c = s.lock().unwrap();
    for sql in [
        "UPDATE account_chat_send_intents SET state=0,payload=x'01'",
        "UPDATE account_chat_send_routes SET state=0",
        "DELETE FROM account_chat_send_receipts",
        "UPDATE account_chat_send_receipts SET record=x'01'",
        "INSERT OR REPLACE INTO account_chat_send_receipts SELECT * FROM account_chat_send_receipts",
    ] {
        assert!(c.execute(sql, []).is_err(), "{sql}");
    }
}

#[test]
fn account_chat_queue_fair_cursor_and_revoked_route_cannot_rebind_old_intent() {
    let (s, r) = stored(2, 3);
    let other = route(&s, 2, 6, 7);
    for n in 1..=130 {
        admit(&s, &intent(n), &r).unwrap();
    }
    let first = s
        .pending_account_chat_sends(&[1; 32], &[2; 32], None, 128)
        .unwrap();
    assert_eq!(first.len(), 128);
    let last = first.last().unwrap();
    let after = AccountChatSendCursor {
        intent_id: last.intent.intent_id,
        policy_id: last.route.policy_id,
    };
    let next = s
        .pending_account_chat_sends(&[1; 32], &[2; 32], Some(&after), 128)
        .unwrap();
    assert_eq!(next.len(), 2);
    assert!(next[0].intent == intent(129));
    let i = intent(1);
    admit(&s, &i, &other).unwrap();
    s.revoke_account_sharing_policy(&r.policy_id, &|| Ok(()))
        .unwrap();
    // Existing approved alternate source still works; newly rebound route cannot resurrect an old intent.
    assert!(pending(&s, 2).iter().all(|q| q.route == other));
    let fresh = route(&s, 2, 6, 9);
    assert!(admit(&s, &i, &fresh).is_err());
    let ack = receipt(
        &i,
        &other,
        6,
        AccountChatSendState::Published {
            event_id: i.ordinary_event_id,
        },
    );
    s.receive_account_chat_send_receipt(&i.account, &ack, &|| Ok(()))
        .unwrap();
    assert!(pending(&s, 2).is_empty());
}

#[test]
fn account_chat_queue_actual_byte_budget_rolls_back_and_terminal_clears_only_payload() {
    let (s, r) = stored(2, 3);
    let mut i = intent(1);
    let empty = MarmotAppEvent::new(hex::encode(i.account), 100, 9, vec![], "");
    let overhead = empty.encode().unwrap().len();
    let event = MarmotAppEvent::new(
        hex::encode(i.account),
        100,
        9,
        vec![],
        "x".repeat(65536 - overhead),
    );
    i.event_payload = event.encode().unwrap();
    assert_eq!(i.event_payload.len(), 65536);
    i.payload_digest = Sha256::digest(&i.event_payload).into();
    i.ordinary_event_id = hex::decode(event.id).unwrap().try_into().unwrap();
    for n in 1u32..=256 {
        i.intent_id[..4].copy_from_slice(&n.to_be_bytes());
        admit(&s, &i, &r).unwrap();
    }
    i.intent_id[..4].copy_from_slice(&257u32.to_be_bytes());
    assert!(admit(&s, &i, &r).is_err());
    assert_eq!(
        s.lock()
            .unwrap()
            .query_row("SELECT count(*) FROM account_chat_send_routes", [], |r| r
                .get::<_, i64>(
                0
            ))
            .unwrap(),
        256
    );
    i.intent_id[..4].copy_from_slice(&1u32.to_be_bytes());
    s.deny_account_chat_send_intent(&i.account, &[2; 32], &i.intent_id, &|| Ok(()))
        .unwrap();
    assert!(admit(&s, &i, &r).is_err());
    i.intent_id[..4].copy_from_slice(&257u32.to_be_bytes());
    admit(&s, &i, &r).unwrap();
    assert_eq!(
        s.lock()
            .unwrap()
            .query_row(
                "SELECT count(*),sum(length(payload)) FROM account_chat_send_intents",
                [],
                |r| Ok((r.get::<_, i64>(0)?, r.get::<_, i64>(1)?))
            )
            .unwrap(),
        (257, MAX_ACCOUNT_CHAT_SEND_BYTES as i64)
    );
}

#[test]
fn account_chat_queue_lifetime_intent_and_route_capacity_survives_terminal_cleanup() {
    let (s, r) = stored(2, 3);
    let other = route(&s, 2, 6, 7);
    s.connection
        .with_transaction(|| {
            for n in 1..=4096 {
                let i = intent(n);
                admit(&s, &i, &r)?;
                admit(&s, &i, &other)?;
            }
            Ok::<_, StorageError>(())
        })
        .unwrap();
    assert!(admit(&s, &intent(4097), &r).is_err());
    let third = route(&s, 2, 9, 10);
    assert!(admit(&s, &intent(1), &third).is_err());
    s.deny_account_chat_send_intent(&[1; 32], &[2; 32], &intent(1).intent_id, &|| Ok(()))
        .unwrap();
    assert!(admit(&s, &intent(4097), &r).is_err());
    assert_eq!(
        s.lock()
            .unwrap()
            .query_row("SELECT count(*) FROM account_chat_send_intents", [], |r| {
                r.get::<_, i64>(0)
            })
            .unwrap(),
        4096
    );
    assert_eq!(
        s.lock()
            .unwrap()
            .query_row("SELECT count(*) FROM account_chat_send_routes", [], |r| r
                .get::<_, i64>(
                0
            ))
            .unwrap(),
        8192
    );
}

#[test]
fn account_chat_queue_exact_lookup_retains_original_time_before_retry_and_terminal_id() {
    let (s, r) = stored(2, 3);
    let i = intent(1);
    assert!(
        s.account_chat_send_intent(&i.account, &[2; 32], &i.intent_id)
            .unwrap()
            .is_none()
    );
    admit(&s, &i, &r).unwrap();
    let saved = s
        .account_chat_send_intent(&i.account, &[2; 32], &i.intent_id)
        .unwrap()
        .unwrap();
    assert!(saved.intent == i && saved.state == AccountChatSendState::Queued);
    let mut changed = i.clone();
    let later = MarmotAppEvent::new(
        hex::encode(i.account),
        101,
        9,
        vec![vec!["p".into(), "synthetic".into()]],
        "queued",
    );
    changed.event_payload = later.encode().unwrap();
    changed.created_at = 101;
    changed.ordinary_event_id = hex::decode(later.id).unwrap().try_into().unwrap();
    changed.payload_digest = Sha256::digest(&changed.event_payload).into();
    assert!(admit(&s, &changed, &r).is_err());
    let received = receipt(&i, &r, 3, AccountChatSendState::Received);
    s.receive_account_chat_send_receipt(&i.account, &received, &|| Ok(()))
        .unwrap();
    assert!(
        s.account_chat_send_intent(&i.account, &[2; 32], &i.intent_id)
            .unwrap()
            .unwrap()
            .state
            == AccountChatSendState::Received
    );
    let published = receipt(
        &i,
        &r,
        3,
        AccountChatSendState::Published {
            event_id: i.ordinary_event_id,
        },
    );
    s.receive_account_chat_send_receipt(&i.account, &published, &|| Ok(()))
        .unwrap();
    let terminal = s
        .account_chat_send_intent(&i.account, &[2; 32], &i.intent_id)
        .unwrap()
        .unwrap();
    assert!(
        terminal.state == published.state
            && terminal.intent.event_payload.is_empty()
            && terminal.intent.payload_digest == i.payload_digest
            && terminal.intent.created_at == i.created_at
    );
    assert!(
        s.account_chat_send_intent(&[9; 32], &[2; 32], &i.intent_id)
            .is_err()
    );
    assert!(
        s.account_chat_send_intent(&i.account, &[3; 32], &i.intent_id)
            .is_err()
    );
}
