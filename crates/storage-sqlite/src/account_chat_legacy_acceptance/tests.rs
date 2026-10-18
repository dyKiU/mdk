//! Persistence controls only. A callback here is not a native approval owner;
//! genuine original-action acceptance is exercised separately in the App.
use super::*;
use crate::SqliteAccountStorage;
use crate::account_chat_source::AccountChatSourceVerdict;
use cgka_traits::StorageProvider;
use cgka_traits::{
    GroupId, MemberId, MessageId,
    approved_account_sharing_policy::{
        ApprovedAccountSharingPolicy, ApprovedAccountSharingPolicyStorage,
    },
    storage::{AccountDeviceSignerBinding, AccountDeviceSignerStorage},
};
use std::cell::Cell;

fn policy() -> ApprovedAccountSharingPolicy {
    ApprovedAccountSharingPolicy {
        account: [1; 32],
        local_device: [2; 32],
        peer_device: [3; 32],
        protected_group: GroupId::new(vec![5; 16]),
        approval_id: [4; 32],
        version: 1,
        capabilities: 15,
        created_at: 100,
        approved_protected_epoch: 2,
        revoked: false,
    }
}
fn configured() -> SqliteAccountStorage {
    let store = SqliteAccountStorage::in_memory().unwrap();
    store
        .lock()
        .unwrap()
        .execute(
            "INSERT INTO account_state(label,updated_at,local_account_id_hex) VALUES('test',0,?1)",
            [hex::encode([1; 32])],
        )
        .unwrap();
    store
        .put_account_device_signer(&AccountDeviceSignerBinding {
            marmot_identity: MemberId::new(vec![1; 32]),
            mls_signature_public_key: vec![2; 32],
        })
        .unwrap();
    store
        .put_approved_account_sharing_policy(&policy(), &|| Ok(()))
        .unwrap();
    store
}
fn policy_id() -> [u8; 32] {
    let p = policy();
    approved_account_sharing_identity(
        &p.account,
        &p.protected_group,
        &p.local_device,
        &p.peer_device,
        &p.approval_id,
    )
    .unwrap()
}
fn change(n: usize) -> AccountChatSourceChange {
    AccountChatSourceChange {
        account: [1; 32],
        local_device: [2; 32],
        group: GroupId::new((n as u64).to_be_bytes().to_vec()),
        origin: AccountChatSourceOrigin::ExplicitLegacyAcceptance {
            approval_id: [4; 32],
        },
        operation: AccountChatSourceOperation::Observe {
            explicitly_accepted: true,
        },
    }
}
fn verdict(
    store: &SqliteAccountStorage,
    c: &AccountChatSourceChange,
) -> Option<AccountChatSourceVerdict> {
    store
        .app_storage()
        .current_account_chat_source(&c.account, &c.local_device, &c.group)
        .unwrap()
}
#[test]
fn ordinary_reducer_cannot_mint_explicit_legacy_and_exact_original_retry_is_idempotent() {
    let store = configured();
    let c = change(1);
    assert!(
        store
            .app_storage()
            .apply_account_chat_source_changes(std::slice::from_ref(&c), &|_| Ok(()))
            .is_err()
    );
    assert!(verdict(&store, &c).is_none());
    for _ in 0..2 {
        store
            .app_storage()
            .record_explicit_legacy_chat_acceptance(&policy_id(), std::slice::from_ref(&c), &|_| {
                Ok(())
            })
            .unwrap();
    }
    assert!(verdict(&store, &c) == Some(AccountChatSourceVerdict::Accepted));
    let conn = store.lock().unwrap();
    assert_eq!(
        conn.query_row(
            "SELECT count(*) FROM account_chat_legacy_acceptance_evidence",
            [],
            |r| r.get::<_, i64>(0)
        )
        .unwrap(),
        1
    );
    assert!(
        conn.execute("DELETE FROM account_chat_legacy_acceptance_evidence", [])
            .is_err()
    );
    assert!(
        conn.execute(
            "UPDATE account_chat_legacy_acceptance_evidence SET approval_id=zeroblob(32)",
            []
        )
        .is_err()
    );
}
#[test]
fn pending_and_denied_welcome_lineage_cannot_be_promoted_by_broad_capture() {
    for denied_origin in [false, true] {
        let store = configured();
        let c = change(1);
        let mut welcome = c.clone();
        welcome.origin = AccountChatSourceOrigin::Joined {
            via_welcome: MessageId::new(vec![7; 32]),
        };
        welcome.operation = AccountChatSourceOperation::Observe {
            explicitly_accepted: false,
        };
        store
            .app_storage()
            .apply_account_chat_source_changes(std::slice::from_ref(&welcome), &|_| Ok(()))
            .unwrap();
        if denied_origin {
            welcome.operation = AccountChatSourceOperation::Deny;
            store
                .app_storage()
                .apply_account_chat_source_changes(&[welcome], &|_| Ok(()))
                .unwrap();
        }
        assert!(
            store
                .app_storage()
                .record_explicit_legacy_chat_acceptance(
                    &policy_id(),
                    std::slice::from_ref(&c),
                    &|_| Ok(())
                )
                .is_err()
        );
        assert!(
            verdict(&store, &c)
                == Some(if denied_origin {
                    AccountChatSourceVerdict::Denied
                } else {
                    AccountChatSourceVerdict::Pending
                })
        );
    }
}
#[test]
fn original_tail_failure_rolls_back_policy_and_all_legacy_evidence() {
    let store = configured();
    let c = change(1);
    let mut p = policy();
    p.peer_device = [6; 32];
    let id = approved_account_sharing_identity(
        &p.account,
        &p.protected_group,
        &p.local_device,
        &p.peer_device,
        &p.approval_id,
    )
    .unwrap();
    let calls = Cell::new(0);
    assert!(
        store
            .with_transaction(|_| {
                store.put_approved_account_sharing_policy(&p, &|| Ok(()))?;
                store.app_storage().record_explicit_legacy_chat_acceptance(
                    &id,
                    std::slice::from_ref(&c),
                    &|_| {
                        calls.set(calls.get() + 1);
                        if calls.get() >= 4 {
                            Err(denied())
                        } else {
                            Ok(())
                        }
                    },
                )
            })
            .is_err()
    );
    assert!(verdict(&store, &c).is_none());
    assert_eq!(store.approved_account_sharing_policies().unwrap().len(), 1);
}
#[test]
fn actual_lifetime_capacity_failure_preserves_prior_evidence_and_current_pointer() {
    let store = configured();
    for start in (0..8192).step_by(128) {
        let batch: Vec<_> = (start..start + 128).map(change).collect();
        store
            .app_storage()
            .record_explicit_legacy_chat_acceptance(&policy_id(), &batch, &|_| Ok(()))
            .unwrap();
    }
    let extra = change(8192);
    assert!(
        store
            .app_storage()
            .record_explicit_legacy_chat_acceptance(
                &policy_id(),
                std::slice::from_ref(&extra),
                &|_| Ok(())
            )
            .is_err()
    );
    assert!(verdict(&store, &extra).is_none());
    assert!(verdict(&store, &change(0)) == Some(AccountChatSourceVerdict::Accepted));
    assert_eq!(
        store
            .lock()
            .unwrap()
            .query_row(
                "SELECT count(*) FROM account_chat_legacy_acceptance_evidence",
                [],
                |r| r.get::<_, i64>(0)
            )
            .unwrap(),
        8192
    );
}
