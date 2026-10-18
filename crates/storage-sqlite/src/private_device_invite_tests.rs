//! Isolated persistence facts; synthetic verified rows never construct SDK consent.
use crate::{DeviceLinkingBinding, DeviceLinkingOutcome, SqliteAccountStorage};
use cgka_traits::accepted_device_group_anchor::DeviceGroupAnchorRoster;
use cgka_traits::device_group_genesis::{GenesisBirthDraft, GenesisLeaf};
use cgka_traits::device_linking_key_package::PurposeAttemptScope;
use cgka_traits::private_device_invite::*;
use cgka_traits::storage::StorageProvider;
use cgka_traits::{EpochId, GroupId};
use sha2::{Digest, Sha256};

fn store() -> SqliteAccountStorage {
    let storage = SqliteAccountStorage::in_memory().unwrap();
    storage
        .app_storage()
        .ensure_account_projection_with_identity("private-invite-test", &hex::encode([1; 32]))
        .unwrap();
    let draft = raw(1);
    storage
        .device_group_genesis_storage()
        .unwrap()
        .store_genesis_birth(
            &[1; 32],
            &[2; 32],
            &GenesisBirthDraft {
                format_version: 1,
                group_id: draft.binding.group_id.clone(),
                epoch: draft.binding.predecessor.epoch,
                epoch_authenticator_digest: draft.binding.predecessor.epoch_authenticator_digest,
                leaves: draft.binding.predecessor.leaves.clone(),
                roster_commitment: [9; 32],
            },
        )
        .unwrap();
    verified_attempt(&storage);
    storage
}
fn verified_attempt(storage: &SqliteAccountStorage) -> u64 {
    let generation = storage
        .app_storage()
        .reserve_device_linking_attempt(&[1; 32], &[2; 32])
        .unwrap();
    let binding = DeviceLinkingBinding {
        generation,
        nonce: [6; 32],
        context_digest: [7; 32],
    };
    storage
        .app_storage()
        .bind_device_linking_context(&binding)
        .unwrap();
    storage
        .app_storage()
        .bind_device_linking_flow(&binding, "isolated-private-flow")
        .unwrap();
    storage
        .app_storage()
        .finish_device_linking_attempt(generation, DeviceLinkingOutcome::PairingVerified)
        .unwrap();
    generation
}
fn raw(generation: u64) -> PrivateInviteRawDraft {
    let leaf = GenesisLeaf {
        leaf_index: 0,
        account: [1; 32],
        signature_public_key: [2; 32],
    };
    let recipient = GenesisLeaf {
        leaf_index: 1,
        account: [1; 32],
        signature_public_key: [3; 32],
    };
    let commit = vec![11, 12];
    let welcome = vec![13, 14];
    PrivateInviteRawDraft {
        binding: PrivateInviteBinding {
            format_version: 1,
            approver_scope: PurposeAttemptScope {
                account: [1; 32],
                local_device: [2; 32],
                generation,
            },
            recipient_generation: 1,
            origin: PrivateInviteOrigin::Genesis(1),
            group_id: GroupId::new(vec![4; 19]),
            recipient: [3; 32],
            nonce: [6; 32],
            context_digest: [7; 32],
            key_package_reference: [8; 32],
            key_package_digest: [9; 32],
            commit_digest: Sha256::digest(&commit).into(),
            welcome_digest: Sha256::digest(&welcome).into(),
            predecessor: DeviceGroupAnchorRoster {
                epoch: EpochId(0),
                epoch_authenticator_digest: [5; 32],
                leaves: vec![leaf.clone()],
            },
            successor: DeviceGroupAnchorRoster {
                epoch: EpochId(1),
                epoch_authenticator_digest: [10; 32],
                leaves: vec![leaf, recipient],
            },
        },
        commit,
        welcome,
    }
}

#[test]
fn private_device_invite_stage_exact_retry_and_undispatched_retirement() {
    let storage = store();
    let cap = storage
        .private_device_invite_storage()
        .expect("atomic private invite fact capability");
    let draft = raw(1);
    let first = cap.stage_private_invite(&draft).unwrap();
    assert!(
        first.raw == draft
            && first.phase == PrivateInvitePhase::RawStaged
            && first.transport.is_none()
    );
    assert!(cap.stage_private_invite(&draft).unwrap() == first);
    let mut wrong_scope = first.scope.clone();
    wrong_scope.staging_generation += 1;
    assert!(
        cap.retire_undispatched_private_invite(&wrong_scope)
            .is_err()
    );
    cap.retire_undispatched_private_invite(&first.scope)
        .unwrap();
    assert!(cap.stage_private_invite(&draft).is_err());
    assert!(cap.confirmed_private_invite().unwrap().is_none());
    let next = verified_attempt(&storage);
    let second = cap.stage_private_invite(&raw(next)).unwrap();
    assert_eq!(
        second.scope.staging_generation,
        first.scope.staging_generation + 1
    );
}

#[test]
fn private_device_invite_wrong_origin_owner_or_raw_integrity_never_allocates() {
    let storage = store();
    let cap = storage.private_device_invite_storage().unwrap();
    for change in 0..9 {
        let mut draft = raw(1);
        match change {
            0 => draft.binding.origin = PrivateInviteOrigin::Genesis(2),
            1 => draft.binding.approver_scope.generation = 2,
            2 => draft.binding.approver_scope.local_device = [15; 32],
            3 => draft.binding.context_digest = [16; 32],
            4 => draft.binding.predecessor.epoch_authenticator_digest = [17; 32],
            5 => draft.binding.successor.leaves[0].signature_public_key = [18; 32],
            6 => draft.commit[0] ^= 1,
            7 => draft.welcome[0] ^= 1,
            _ => draft.binding.recipient_generation = 0,
        }
        assert!(cap.stage_private_invite(&draft).is_err());
        assert!(cap.private_invite().unwrap().is_none());
    }
    assert_eq!(
        storage
            .lock()
            .unwrap()
            .query_row(
                "SELECT count(*) FROM private_device_invite_counter",
                [],
                |row| row.get::<_, i64>(0)
            )
            .unwrap(),
        0
    );
}

fn transport() -> PrivateInviteTransport {
    use cgka_traits::{
        MemberId, MessageId, Timestamp, TransportEnvelope, TransportMessage, TransportSource,
    };
    let message = |value, envelope| TransportMessage {
        id: MessageId::new(vec![value; 32]),
        payload: vec![value; 64],
        timestamp: Timestamp(1),
        causal_deps: vec![],
        source: TransportSource("isolated-test".into()),
        envelope,
    };
    PrivateInviteTransport {
        commit: message(
            21,
            TransportEnvelope::GroupMessage {
                transport_group_id: vec![23; 32],
            },
        ),
        welcomes: vec![message(
            22,
            TransportEnvelope::Welcome {
                recipient: MemberId::new(vec![1; 32]),
            },
        )],
    }
}
fn confirmed(storage: &SqliteAccountStorage) -> ConfirmedPrivateInviteFact {
    let cap = storage.private_device_invite_storage().unwrap();
    let draft = raw(1);
    let first = cap.stage_private_invite(&draft).unwrap();
    cap.cache_private_invite_transport(&first.scope, &transport())
        .unwrap();
    cap.mark_private_invite_dispatch(&first.scope).unwrap();
    cap.confirm_private_invite(&first.scope, &draft.binding.successor)
        .unwrap()
}
fn next_raw(generation: u64, previous: &ConfirmedPrivateInviteFact) -> PrivateInviteRawDraft {
    let mut next = raw(generation);
    next.binding.origin = PrivateInviteOrigin::Confirmed(previous.scope.staging_generation);
    next.binding.predecessor = previous.binding.successor.clone();
    next.binding.recipient = [24; 32];
    next.binding.successor = next.binding.predecessor.clone();
    next.binding.successor.epoch.0 += 1;
    next.binding.successor.epoch_authenticator_digest = [25; 32];
    next.binding.successor.leaves.push(GenesisLeaf {
        leaf_index: 2,
        account: [1; 32],
        signature_public_key: [24; 32],
    });
    next
}
#[test]
fn private_device_invite_uncertain_publication_cannot_retire_or_replace() {
    let storage = store();
    let cap = storage.private_device_invite_storage().unwrap();
    let draft = raw(1);
    let first = cap.stage_private_invite(&draft).unwrap();
    assert!(cap.mark_private_invite_dispatch(&first.scope).is_err());
    assert!(
        cap.confirm_private_invite(&first.scope, &draft.binding.successor)
            .is_err()
    );
    let wrapped = cap
        .cache_private_invite_transport(&first.scope, &transport())
        .unwrap();
    assert!(
        cap.cache_private_invite_transport(&first.scope, &transport())
            .unwrap()
            == wrapped
    );
    let mut changed = transport();
    changed.commit.payload[0] ^= 1;
    assert!(
        cap.cache_private_invite_transport(&first.scope, &changed)
            .is_err()
    );
    cap.mark_private_invite_dispatch(&first.scope).unwrap();
    assert!(matches!(
        cap.retire_undispatched_private_invite(&first.scope),
        Err(PrivateInviteStorageError::PublicationUncertain)
    ));
    cap.mark_private_invite_publication_unknown(&first.scope)
        .unwrap();
    cap.mark_private_invite_publication_unknown(&first.scope)
        .unwrap();
    assert!(matches!(
        cap.retire_undispatched_private_invite(&first.scope),
        Err(PrivateInviteStorageError::PublicationUncertain)
    ));
    assert!(matches!(
        storage
            .app_storage()
            .reserve_device_linking_attempt(&[1; 32], &[2; 32]),
        Err(crate::DeviceLinkingError::Busy)
    ));
    assert!(cap.stage_private_invite(&raw(2)).is_err());
    let mut wrong = draft.binding.successor.clone();
    wrong.epoch_authenticator_digest = [99; 32];
    assert!(cap.confirm_private_invite(&first.scope, &wrong).is_err());
    assert!(cap.confirmed_private_invite().unwrap().is_none());
    let result = cap
        .confirm_private_invite(&first.scope, &draft.binding.successor)
        .unwrap();
    assert!(
        cap.confirm_private_invite(&first.scope, &draft.binding.successor)
            .unwrap()
            == result
    );
}
#[test]
fn private_device_invite_next_retirement_preserves_confirmed_anchor() {
    let storage = store();
    let previous = confirmed(&storage);
    let generation = verified_attempt(&storage);
    let cap = storage.private_device_invite_storage().unwrap();
    assert!(cap.stage_private_invite(&raw(generation)).is_err());
    let next = next_raw(generation, &previous);
    let pending = cap.stage_private_invite(&next).unwrap();
    cap.retire_undispatched_private_invite(&pending.scope)
        .unwrap();
    assert!(cap.confirmed_private_invite().unwrap() == Some(previous));
}
#[test]
fn private_device_invite_confirmation_failure_rolls_back_both_slots() {
    let storage = store();
    let cap = storage.private_device_invite_storage().unwrap();
    let draft = raw(1);
    let first = cap.stage_private_invite(&draft).unwrap();
    cap.cache_private_invite_transport(&first.scope, &transport())
        .unwrap();
    let dispatched = cap.mark_private_invite_dispatch(&first.scope).unwrap();
    storage.lock().unwrap().execute_batch("CREATE TEMP TRIGGER reject_invite_confirmation BEFORE UPDATE ON private_device_invite_staging WHEN NEW.phase=5 BEGIN SELECT RAISE(ABORT,'isolated confirmation failure'); END;").unwrap();
    assert!(
        cap.confirm_private_invite(&first.scope, &draft.binding.successor)
            .is_err()
    );
    assert!(cap.private_invite().unwrap() == Some(dispatched));
    assert!(cap.confirmed_private_invite().unwrap().is_none());
    storage
        .lock()
        .unwrap()
        .execute_batch("DROP TRIGGER reject_invite_confirmation")
        .unwrap();
    cap.confirm_private_invite(&first.scope, &draft.binding.successor)
        .unwrap();
}
#[test]
fn private_device_invite_denied_confirmed_origin_cannot_be_revived_by_pending_confirmation() {
    let storage = store();
    let previous = confirmed(&storage);
    let generation = verified_attempt(&storage);
    let cap = storage.private_device_invite_storage().unwrap();
    let next = next_raw(generation, &previous);
    let pending = cap.stage_private_invite(&next).unwrap();
    cap.cache_private_invite_transport(&pending.scope, &transport())
        .unwrap();
    cap.mark_private_invite_dispatch(&pending.scope).unwrap();
    cap.deny_confirmed_private_invite(&previous.scope, &previous.binding.group_id)
        .unwrap();
    assert!(
        cap.confirm_private_invite(&pending.scope, &next.binding.successor)
            .is_err(),
        "pending confirmation must not clear permanent origin denial"
    );
    let retained = cap.confirmed_private_invite().unwrap().unwrap();
    assert!(retained.denied && retained.scope == previous.scope);
}

#[test]
fn private_device_invite_denied_genesis_cannot_be_revived_by_pending_confirmation() {
    let storage = store();
    let cap = storage.private_device_invite_storage().unwrap();
    let draft = raw(1);
    let pending = cap.stage_private_invite(&draft).unwrap();
    cap.cache_private_invite_transport(&pending.scope, &transport())
        .unwrap();
    cap.mark_private_invite_dispatch(&pending.scope).unwrap();
    let genesis = storage.device_group_genesis_storage().unwrap();
    let selection = genesis.genesis_selection().unwrap().unwrap();
    genesis
        .deny_genesis_selection(&selection.fact.scope, &draft.binding.group_id)
        .unwrap();
    assert!(
        cap.confirm_private_invite(&pending.scope, &draft.binding.successor)
            .is_err(),
        "pending confirmation must not revive denied genesis"
    );
    assert!(cap.confirmed_private_invite().unwrap().is_none());
}

#[test]
fn private_device_invite_group_deletion_preserves_publication_uncertainty() {
    for unknown in [false, true] {
        let storage = store();
        let cap = storage.private_device_invite_storage().unwrap();
        let draft = raw(1);
        let pending = cap.stage_private_invite(&draft).unwrap();
        let mut batch = transport();
        let mut second = batch.welcomes[0].clone();
        second.id = cgka_traits::MessageId::new(vec![24; 32]);
        batch.welcomes.push(second);
        cap.cache_private_invite_transport(&pending.scope, &batch)
            .unwrap();
        cap.mark_private_invite_dispatch(&pending.scope).unwrap();
        if unknown {
            cap.mark_private_invite_publication_unknown(&pending.scope)
                .unwrap();
        }
        let before = cap.private_invite().unwrap().unwrap();
        storage
            .lock()
            .unwrap()
            .execute(
                "INSERT INTO cgka_groups(id,epoch,record) VALUES(?1,0,X'7b7d')",
                [draft.binding.group_id.as_slice()],
            )
            .unwrap();
        storage
            .lock()
            .unwrap()
            .execute(
                "DELETE FROM cgka_groups WHERE id=?1",
                [draft.binding.group_id.as_slice()],
            )
            .unwrap();
        let after = cap.private_invite().unwrap().unwrap();
        assert!(
            after == before,
            "group deletion must preserve dispatch uncertainty and exact bytes"
        );
        assert!(matches!(
            cap.retire_undispatched_private_invite(&pending.scope),
            Err(PrivateInviteStorageError::PublicationUncertain)
        ));
        assert!(matches!(
            storage
                .app_storage()
                .reserve_device_linking_attempt(&[1; 32], &[2; 32]),
            Err(crate::DeviceLinkingError::Busy)
        ));
        assert!(cap.stage_private_invite(&raw(2)).is_err());
    }
}

fn unresolved_store(phase: u8) -> SqliteAccountStorage {
    let storage = store();
    let cap = storage.private_device_invite_storage().unwrap();
    let pending = cap.stage_private_invite(&raw(1)).unwrap();
    if phase >= 1 {
        let mut batch = transport();
        let mut second = batch.welcomes[0].clone();
        second.id = cgka_traits::MessageId::new(vec![24; 32]);
        batch.welcomes.push(second);
        cap.cache_private_invite_transport(&pending.scope, &batch)
            .unwrap();
    }
    if phase >= 2 {
        cap.mark_private_invite_dispatch(&pending.scope).unwrap();
    }
    if phase >= 3 {
        cap.mark_private_invite_publication_unknown(&pending.scope)
            .unwrap();
    }
    storage
}
fn replacement_birth() -> GenesisBirthDraft {
    let draft = raw(1);
    GenesisBirthDraft {
        format_version: 1,
        group_id: GroupId::new(vec![31; 19]),
        epoch: EpochId(0),
        epoch_authenticator_digest: [32; 32],
        leaves: draft.binding.predecessor.leaves,
        roster_commitment: [33; 32],
    }
}
fn replacement_accepted()
-> cgka_traits::accepted_device_group_anchor::AcceptedDeviceGroupAnchorDraft {
    let local = GenesisLeaf {
        leaf_index: 1,
        account: [1; 32],
        signature_public_key: [2; 32],
    };
    let peer = GenesisLeaf {
        leaf_index: 0,
        account: [1; 32],
        signature_public_key: [3; 32],
    };
    cgka_traits::accepted_device_group_anchor::AcceptedDeviceGroupAnchorDraft {
        format_version: 1,
        purpose: PurposeAttemptScope {
            account: [1; 32],
            local_device: [2; 32],
            generation: 2,
        },
        group_id: GroupId::new(vec![34; 19]),
        nonce: [6; 32],
        context_digest: [7; 32],
        key_package_reference: [8; 32],
        welcome_digest: [9; 32],
        approver: [3; 32],
        recipient: [2; 32],
        predecessor: DeviceGroupAnchorRoster {
            epoch: EpochId(0),
            epoch_authenticator_digest: [35; 32],
            leaves: vec![peer.clone()],
        },
        successor: DeviceGroupAnchorRoster {
            epoch: EpochId(1),
            epoch_authenticator_digest: [36; 32],
            leaves: vec![peer, local],
        },
    }
}
fn deny_birth(storage: &SqliteAccountStorage) {
    let cap = storage.device_group_genesis_storage().unwrap();
    let selection = cap.genesis_selection().unwrap().unwrap();
    cap.deny_genesis_selection(&selection.fact.scope, &selection.fact.birth.group_id)
        .unwrap();
}
#[test]
fn private_device_invite_unresolved_blocks_new_pairing_without_changing_scope() {
    for phase in 0..4 {
        let storage = unresolved_store(phase);
        let before = storage
            .private_device_invite_storage()
            .unwrap()
            .private_invite()
            .unwrap();
        assert!(
            matches!(
                storage
                    .app_storage()
                    .reserve_device_linking_attempt(&[1; 32], &[2; 32]),
                Err(crate::DeviceLinkingError::Busy)
            ),
            "unresolved invite must block generation advance"
        );
        assert!(
            storage
                .private_device_invite_storage()
                .unwrap()
                .private_invite()
                .unwrap()
                == before
        );
    }
}
#[test]
fn private_device_invite_unresolved_blocks_replacing_denied_genesis() {
    for phase in 0..4 {
        let storage = unresolved_store(phase);
        deny_birth(&storage);
        let cap = storage.device_group_genesis_storage().unwrap();
        let before = cap.genesis_selection().unwrap().unwrap();
        assert!(
            matches!(
                cap.store_genesis_birth(&[1; 32], &[2; 32], &replacement_birth()),
                Err(cgka_traits::device_group_genesis::GenesisError::SelectionBusy)
            ),
            "unresolved invite must block new private birth"
        );
        assert!(cap.genesis_selection().unwrap().unwrap() == before);
    }
}
#[test]
fn private_device_invite_unresolved_blocks_selecting_an_accepted_group() {
    for phase in 0..4 {
        let storage = unresolved_store(phase);
        deny_birth(&storage);
        let cap = storage.accepted_device_group_anchor_storage().unwrap();
        assert!(
            matches!(
                cap.install_accepted_anchor(&replacement_accepted()),
                Err(cgka_traits::accepted_device_group_anchor::AnchorError::SelectionBusy)
            ),
            "unresolved invite must block accepted selection"
        );
        assert!(cap.accepted_anchor().unwrap().is_none());
    }
}

#[test]
fn private_device_invite_accepted_origin_retry_is_read_only_while_outgoing_is_pending() {
    let storage = SqliteAccountStorage::in_memory().unwrap();
    storage
        .app_storage()
        .ensure_account_projection_with_identity(
            "private-invite-accepted-test",
            &hex::encode([1; 32]),
        )
        .unwrap();
    verified_attempt(&storage);
    let mut accepted = replacement_accepted();
    accepted.purpose.generation = 1;
    let anchor_cap = storage.accepted_device_group_anchor_storage().unwrap();
    let anchor = anchor_cap.install_accepted_anchor(&accepted).unwrap();
    let generation = verified_attempt(&storage);
    let mut draft = raw(generation);
    draft.binding.origin = PrivateInviteOrigin::Accepted(anchor.scope.selection_generation);
    draft.binding.group_id = accepted.group_id.clone();
    draft.binding.predecessor = accepted.successor.clone();
    draft.binding.recipient = [24; 32];
    draft.binding.successor = draft.binding.predecessor.clone();
    draft.binding.successor.epoch.0 += 1;
    draft.binding.successor.epoch_authenticator_digest = [37; 32];
    draft.binding.successor.leaves.push(GenesisLeaf {
        leaf_index: 2,
        account: [1; 32],
        signature_public_key: [24; 32],
    });
    let cap = storage.private_device_invite_storage().unwrap();
    let pending = cap.stage_private_invite(&draft).unwrap();
    let retry = anchor_cap
        .install_accepted_anchor(&accepted)
        .expect("exact accepted fact retry must not allocate or orphan pending work");
    assert!(retry == anchor);
    assert!(cap.private_invite().unwrap() == Some(pending));
}

#[test]
fn private_device_invite_encrypted_reopen_retains_exact_uncertainty_and_scope() {
    for phase in [2, 3] {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("isolated-private-invite.sqlite");
        let key = crate::SqlCipherKey::new("42".repeat(32)).unwrap();
        let storage = SqliteAccountStorage::open_encrypted(&path, &key).unwrap();
        storage
            .app_storage()
            .ensure_account_projection_with_identity(
                "private-invite-reopen-test",
                &hex::encode([1; 32]),
            )
            .unwrap();
        let draft = raw(1);
        storage
            .device_group_genesis_storage()
            .unwrap()
            .store_genesis_birth(
                &[1; 32],
                &[2; 32],
                &GenesisBirthDraft {
                    format_version: 1,
                    group_id: draft.binding.group_id.clone(),
                    epoch: draft.binding.predecessor.epoch,
                    epoch_authenticator_digest: draft
                        .binding
                        .predecessor
                        .epoch_authenticator_digest,
                    leaves: draft.binding.predecessor.leaves.clone(),
                    roster_commitment: [9; 32],
                },
            )
            .unwrap();
        verified_attempt(&storage);
        let cap = storage.private_device_invite_storage().unwrap();
        let pending = cap.stage_private_invite(&draft).unwrap();
        let mut batch = transport();
        let mut second = batch.welcomes[0].clone();
        second.id = cgka_traits::MessageId::new(vec![24; 32]);
        batch.welcomes.push(second);
        cap.cache_private_invite_transport(&pending.scope, &batch)
            .unwrap();
        cap.mark_private_invite_dispatch(&pending.scope).unwrap();
        if phase == 3 {
            cap.mark_private_invite_publication_unknown(&pending.scope)
                .unwrap();
        }
        let before = cap.private_invite().unwrap().unwrap();
        storage.close().unwrap();
        drop(storage);
        let reopened = SqliteAccountStorage::open_encrypted(&path, &key).unwrap();
        let cap = reopened.private_device_invite_storage().unwrap();
        assert!(cap.private_invite().unwrap() == Some(before));
        assert!(cap.confirmed_private_invite().unwrap().is_none());
        assert!(matches!(
            cap.retire_undispatched_private_invite(&pending.scope),
            Err(PrivateInviteStorageError::PublicationUncertain)
        ));
        assert!(matches!(
            reopened
                .app_storage()
                .reserve_device_linking_attempt(&[1; 32], &[2; 32]),
            Err(crate::DeviceLinkingError::Busy)
        ));
        let mut stale = pending.scope.clone();
        stale.staging_generation += 1;
        assert!(cap.mark_private_invite_publication_unknown(&stale).is_err());
        reopened.close().unwrap();
    }
}

#[test]
fn private_invite_transport_duplicate_ids_do_not_freeze_a_draft() {
    let storage = store();
    let cap = storage.private_device_invite_storage().unwrap();
    let staged = cap.stage_private_invite(&raw(1)).unwrap();
    let mut duplicate = transport();
    duplicate.welcomes[0].id = duplicate.commit.id.clone();
    assert!(matches!(
        cap.cache_private_invite_transport(&staged.scope, &duplicate),
        Err(PrivateInviteStorageError::InvalidFact)
    ));
    assert!(cap.private_invite().unwrap() == Some(staged));
}

#[test]
fn private_invite_batch_bounds_and_exact_order_are_atomic() {
    let storage = store();
    let cap = storage.private_device_invite_storage().unwrap();
    let staged = cap.stage_private_invite(&raw(1)).unwrap();
    for mutation in 0..7 {
        let mut batch = transport();
        match mutation {
            0 => batch.welcomes.clear(),
            1 => {
                batch.welcomes =
                    vec![batch.welcomes[0].clone(); MAX_PRIVATE_INVITE_WELCOME_MESSAGES + 1]
            }
            2 => batch.welcomes.push(batch.welcomes[0].clone()),
            3 => batch.welcomes[0].id = cgka_traits::MessageId::new(vec![]),
            4 => batch.welcomes[0].envelope = batch.commit.envelope.clone(),
            5 => batch.welcomes[0].payload = vec![255; MAX_PRIVATE_INVITE_TRANSPORT_BYTES / 4 + 1],
            _ => batch.welcomes[0]
                .causal_deps
                .push(cgka_traits::MessageId::new(vec![1; 129])),
        }
        assert!(matches!(
            cap.cache_private_invite_transport(&staged.scope, &batch),
            Err(PrivateInviteStorageError::InvalidFact)
        ));
        assert!(cap.private_invite().unwrap() == Some(staged.clone()));
    }
    let mut batch = transport();
    let mut second = batch.welcomes[0].clone();
    second.id = cgka_traits::MessageId::new(vec![24; 32]);
    second.payload = vec![24; 64];
    batch.welcomes.push(second);
    let frozen = cap
        .cache_private_invite_transport(&staged.scope, &batch)
        .unwrap();
    assert!(
        cap.cache_private_invite_transport(&staged.scope, &batch)
            .unwrap()
            == frozen
    );
    let mut reordered = batch.clone();
    reordered.welcomes.reverse();
    assert!(matches!(
        cap.cache_private_invite_transport(&staged.scope, &reordered),
        Err(PrivateInviteStorageError::Busy)
    ));
    let mut changed = batch;
    changed.welcomes[1].payload[0] ^= 1;
    assert!(
        cap.cache_private_invite_transport(&staged.scope, &changed)
            .is_err()
    );
    assert!(cap.private_invite().unwrap() == Some(frozen));
}

#[test]
fn private_invite_full_bound_batch_survives_storage_and_old_singleton_shape_fails_closed() {
    let storage = store();
    let cap = storage.private_device_invite_storage().unwrap();
    let staged = cap.stage_private_invite(&raw(1)).unwrap();
    let mut batch = transport();
    batch.welcomes = (0..MAX_PRIVATE_INVITE_WELCOME_MESSAGES)
        .map(|index| {
            let mut message = batch.welcomes[0].clone();
            message.id = cgka_traits::MessageId::new(vec![100 + index as u8; 32]);
            message
        })
        .collect();
    let frozen = cap
        .cache_private_invite_transport(&staged.scope, &batch)
        .unwrap();
    assert!(cap.private_invite().unwrap() == Some(frozen));
    let mut singleton = serde_json::to_value(transport()).unwrap();
    let object = singleton.as_object_mut().unwrap();
    let messages = object.remove("welcomes").unwrap();
    object.insert("welcome".into(), messages[0].clone());
    assert!(serde_json::from_value::<PrivateInviteTransport>(singleton.clone()).is_err());
    storage
        .lock()
        .unwrap()
        .execute(
            "UPDATE private_device_invite_staging SET transport=?1",
            [serde_json::to_vec(&singleton).unwrap()],
        )
        .unwrap();
    assert!(matches!(
        cap.private_invite(),
        Err(PrivateInviteStorageError::InvalidFact)
    ));
}
