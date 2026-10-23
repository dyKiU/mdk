//! Crypto-authenticated experimental ACK facts, deliberately no grants.
use super::*;
use cgka_traits::engine::SendIntent;
use cgka_traits::storage::StorageProvider;

#[tokio::test]
async fn roster_ack_capture_real_mls_ingest_retains_exact_leaf_without_grant() {
    let store = SqliteAccountStorage::in_memory().unwrap();
    let mut alice = client(store.clone());
    let mut bob = client(SqliteAccountStorage::in_memory().unwrap());
    let kp = bob.fresh_key_package().await.unwrap();
    let (group, welcome) = invite(&mut alice, kp).await;
    bob.join_welcome(welcome).await.unwrap();
    alice.start_roster_ack_capture(&group).await.unwrap();
    let capture = store
        .roster_ack_capture_storage()
        .unwrap()
        .capture_state()
        .unwrap()
        .unwrap();
    let ack = peer_ack(&mut bob, &group, &capture).await;
    alice.ingest(ack.clone()).await.unwrap();
    let facts = alice.roster_ack_capture_facts(&group).unwrap();
    assert_eq!(
        facts.len(),
        1,
        "real crypto ACK must persist before the input is deduplicated"
    );
    let candidate = alice
        .candidate_device_group_snapshot(&group)
        .unwrap()
        .unwrap();
    assert!(
        facts[0].signature_public_key
            != hex::decode(
                key_package_metadata(&alice.fresh_key_package().await.unwrap())
                    .unwrap()
                    .signature_public_key_hex
            )
            .unwrap()
    );
    assert!(
        candidate
            .leaves
            .iter()
            .any(|leaf| leaf.leaf_index == facts[0].leaf_index
                && leaf.signature_public_key == facts[0].signature_public_key)
    );
    assert!(matches!(
        alice.ingest(ack).await.unwrap(),
        cgka_traits::ingest::IngestOutcome::Ignored {
            category: cgka_traits::ingest::InputRejectionCategory::Duplicate
        }
    ));
    assert_eq!(alice.roster_ack_capture_facts(&group).unwrap().len(), 1);
}

async fn peer_ack(
    bob: &mut Engine<SqliteAccountStorage>,
    group: &cgka_traits::types::GroupId,
    capture: &cgka_traits::roster_ack_capture::RosterAckCaptureState,
) -> TransportMessage {
    let nonce = capture.round_nonce.unwrap();
    // A genuine independently signed/encrypted peer statement. These fixture
    // bytes are not accepted through any proof or event-metadata API.
    let content = serde_json::json!({
        "protocol":"whitenoise.experimental.roster-capture.v1", "phase":"ack",
        "round_nonce":nonce, "roster_commitment":capture.roster_commitment,
        "epoch":capture.epoch.0
    })
    .to_string();
    let payload = cgka_traits::app_event::MarmotAppEvent::new(
        hex::encode(bob.self_id().as_slice()),
        1_700_000_000,
        38_173,
        vec![],
        content,
    )
    .encode()
    .unwrap();
    match bob
        .send(SendIntent::AppMessage {
            group_id: group.clone(),
            payload,
            expected_epoch: None,
        })
        .await
        .unwrap()
    {
        SendResult::ApplicationMessage { msg, .. } => msg,
        _ => panic!("expected real MLS application"),
    }
}

#[tokio::test]
async fn roster_ack_capture_sql_failure_rolls_back_ratchet_and_exact_retry_survives_reopen() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("isolated-ack-capture.db");
    let key = storage_sqlite::SqlCipherKey::new("37".repeat(32)).unwrap();
    let store = SqliteAccountStorage::open_encrypted(&path, &key).unwrap();
    let mut alice = client(store.clone());
    let mut bob = client(SqliteAccountStorage::in_memory().unwrap());
    let kp = bob.fresh_key_package().await.unwrap();
    let (group, welcome) = invite(&mut alice, kp).await;
    bob.join_welcome(welcome).await.unwrap();
    alice.start_roster_ack_capture(&group).await.unwrap();
    let capture = store
        .roster_ack_capture_storage()
        .unwrap()
        .capture_state()
        .unwrap()
        .unwrap();
    let ack = peer_ack(&mut bob, &group, &capture).await;
    let injector = rusqlite::Connection::open(&path).unwrap();
    storage_sqlite::open_hardened_sqlcipher(
        &injector,
        &key,
        storage_sqlite::SqlCipherHardening::default(),
    )
    .unwrap();
    injector.execute_batch("CREATE TRIGGER reject_ack_fact BEFORE INSERT ON roster_ack_capture_facts BEGIN SELECT RAISE(ABORT,'injected capture failure'); END;").unwrap();
    assert!(
        matches!(
            alice.ingest(ack.clone()).await,
            Err(cgka_traits::error::EngineError::Storage(_))
        ),
        "capture write failure must propagate and roll back its receive ratchet"
    );
    assert!(alice.roster_ack_capture_facts(&group).unwrap().is_empty());
    injector
        .execute_batch("DROP TRIGGER reject_ack_fact;")
        .unwrap();
    drop(injector);
    drop(alice);
    drop(store);
    let reopened = SqliteAccountStorage::open_encrypted(&path, &key).unwrap();
    let mut alice = client(reopened);
    alice.hydrate_stable_groups_from_storage().unwrap();
    assert!(matches!(
        alice.ingest(ack.clone()).await.unwrap(),
        cgka_traits::ingest::IngestOutcome::Processed
    ));
    assert_eq!(alice.roster_ack_capture_facts(&group).unwrap().len(), 1);
    assert!(matches!(
        alice.ingest(ack).await.unwrap(),
        cgka_traits::ingest::IngestOutcome::Ignored {
            category: cgka_traits::ingest::InputRejectionCategory::Duplicate
        }
    ));
}

fn application(result: SendResult) -> TransportMessage {
    match result {
        SendResult::ApplicationMessage { msg, .. } => msg,
        _ => panic!("expected private MLS application"),
    }
}

#[tokio::test]
async fn roster_ack_capture_selected_challenge_roundtrip_has_no_host_application_evidence() {
    let store = SqliteAccountStorage::in_memory().unwrap();
    let mut alice = client(store.clone());
    let mut bob = client(SqliteAccountStorage::in_memory().unwrap());
    let kp = bob.fresh_key_package().await.unwrap();
    let (group, welcome) = invite(&mut alice, kp).await;
    bob.join_welcome(welcome).await.unwrap();
    alice.drain_events();
    bob.drain_events();
    bob.select_roster_ack_capture(&group).unwrap();
    let challenge = application(alice.start_roster_ack_capture(&group).await.unwrap());
    assert_eq!(
        application(alice.start_roster_ack_capture(&group).await.unwrap()),
        challenge
    );
    assert!(matches!(
        bob.ingest(challenge).await.unwrap(),
        cgka_traits::ingest::IngestOutcome::Processed
    ));
    assert!(!bob.drain_events().iter().any(|event| matches!(
        event,
        cgka_traits::engine::GroupEvent::MessageReceived { .. }
    )));
    let ack = application(bob.prepare_roster_ack(&group).await.unwrap());
    assert_eq!(
        application(bob.prepare_roster_ack(&group).await.unwrap()),
        ack
    );
    alice.ingest(ack).await.unwrap();
    assert_eq!(alice.roster_ack_capture_facts(&group).unwrap().len(), 1);
    assert!(!alice.drain_events().iter().any(|event| matches!(
        event,
        cgka_traits::engine::GroupEvent::MessageReceived { .. }
    )));
}

#[tokio::test]
async fn roster_ack_capture_unsolicited_scope_and_wrong_round_are_ignored_without_facts() {
    let store = SqliteAccountStorage::in_memory().unwrap();
    let bob_store = SqliteAccountStorage::in_memory().unwrap();
    let mut alice = client(store.clone());
    let mut bob = client(bob_store.clone());
    let kp = bob.fresh_key_package().await.unwrap();
    let (group, welcome) = invite(&mut alice, kp).await;
    bob.join_welcome(welcome).await.unwrap();
    let challenge = application(alice.start_roster_ack_capture(&group).await.unwrap());
    assert!(matches!(
        bob.ingest(challenge).await.unwrap(),
        cgka_traits::ingest::IngestOutcome::Ignored {
            category: cgka_traits::ingest::InputRejectionCategory::AuthorizationFailed
        }
    ));
    assert!(
        bob_store
            .roster_ack_capture_storage()
            .unwrap()
            .capture_state()
            .unwrap()
            .is_none()
    );
    assert!(bob.prepare_roster_ack(&group).await.is_err());
    let capture = store
        .roster_ack_capture_storage()
        .unwrap()
        .capture_state()
        .unwrap()
        .unwrap();
    let mut wrong = capture.clone();
    let mut nonce = wrong.round_nonce.unwrap();
    nonce[0] ^= 1;
    wrong.round_nonce = Some(nonce);
    let ack = peer_ack(&mut bob, &group, &wrong).await;
    assert!(matches!(
        alice.ingest(ack).await.unwrap(),
        cgka_traits::ingest::IngestOutcome::Ignored {
            category: cgka_traits::ingest::InputRejectionCategory::AuthorizationFailed
        }
    ));
    assert!(alice.roster_ack_capture_facts(&group).unwrap().is_empty());
    let ack = peer_ack(&mut bob, &group, &capture).await;
    alice.ingest(ack).await.unwrap();
    assert_eq!(alice.roster_ack_capture_facts(&group).unwrap().len(), 1);
}

#[tokio::test]
async fn roster_ack_capture_outbound_failure_retries_exact_ciphertext_after_reopen() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("isolated-ack-outbound.db");
    let key = storage_sqlite::SqlCipherKey::new("43".repeat(32)).unwrap();
    let store = SqliteAccountStorage::open_encrypted(&path, &key).unwrap();
    let captured = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
    let build = |store| {
        EngineBuilder::new(store)
            .identity(pad32(ACCOUNT))
            .account_identity_proof_signer(proof_signer(ACCOUNT))
            .protocol_profile(ProtocolProfile::Current)
            .peeler(Box::new(MockPeeler {
                captured_ciphertexts: Some(captured.clone()),
                ..Default::default()
            }))
            .build()
            .unwrap()
    };
    let mut alice = build(store.clone());
    let mut bob = client(SqliteAccountStorage::in_memory().unwrap());
    let kp = bob.fresh_key_package().await.unwrap();
    let (group, welcome) = invite(&mut alice, kp).await;
    bob.join_welcome(welcome).await.unwrap();
    let injector = rusqlite::Connection::open(&path).unwrap();
    storage_sqlite::open_hardened_sqlcipher(
        &injector,
        &key,
        storage_sqlite::SqlCipherHardening::default(),
    )
    .unwrap();
    injector.execute_batch("CREATE TRIGGER reject_capture_outbound BEFORE UPDATE ON roster_ack_capture WHEN json_extract(CAST(NEW.state AS TEXT),'$.outbound') IS NOT NULL BEGIN SELECT RAISE(ABORT,'injected capture outbound failure'); END;").unwrap();
    assert!(matches!(
        alice.start_roster_ack_capture(&group).await,
        Err(cgka_traits::error::EngineError::Storage(_))
    ));
    let first = captured.lock().unwrap().last().unwrap().clone();
    injector
        .execute_batch("DROP TRIGGER reject_capture_outbound;")
        .unwrap();
    drop(injector);
    drop(alice);
    drop(store);
    let mut alice = build(SqliteAccountStorage::open_encrypted(&path, &key).unwrap());
    alice.hydrate_stable_groups_from_storage().unwrap();
    alice.ensure_hydrated(&group).unwrap();
    let retry = application(alice.start_roster_ack_capture(&group).await.unwrap());
    assert!(
        retry.payload == first,
        "failed outbox persistence must not advance to a different MLS ciphertext"
    );
    let cached = application(alice.start_roster_ack_capture(&group).await.unwrap());
    assert_eq!(retry, cached);
}

#[tokio::test]
async fn roster_ack_capture_wrong_kind_private_body_never_becomes_chat_evidence() {
    let store = SqliteAccountStorage::in_memory().unwrap();
    let mut alice = client(store.clone());
    let mut bob = client(SqliteAccountStorage::in_memory().unwrap());
    let kp = bob.fresh_key_package().await.unwrap();
    let (group, welcome) = invite(&mut alice, kp).await;
    bob.join_welcome(welcome).await.unwrap();
    alice.start_roster_ack_capture(&group).await.unwrap();
    alice.drain_events();
    let capture = store
        .roster_ack_capture_storage()
        .unwrap()
        .capture_state()
        .unwrap()
        .unwrap();
    let content = serde_json::json!({"protocol":"whitenoise.experimental.roster-capture.v1","phase":"ack","round_nonce":capture.round_nonce.unwrap(),"roster_commitment":capture.roster_commitment,"epoch":capture.epoch.0}).to_string();
    let payload = cgka_traits::app_event::MarmotAppEvent::new(
        hex::encode(bob.self_id().as_slice()),
        1_700_000_000,
        cgka_traits::app_event::MARMOT_APP_EVENT_KIND_CHAT,
        vec![],
        content,
    )
    .encode()
    .unwrap();
    let message = application(
        bob.send(SendIntent::AppMessage {
            group_id: group.clone(),
            payload,
            expected_epoch: None,
        })
        .await
        .unwrap(),
    );
    alice.ingest(message).await.unwrap();
    assert!(
        !alice.drain_events().iter().any(|event| matches!(
            event,
            cgka_traits::engine::GroupEvent::MessageReceived { .. }
        )),
        "wrong-kind private control must not become application/history evidence"
    );
    assert!(alice.roster_ack_capture_facts(&group).unwrap().is_empty());
}

#[tokio::test]
async fn roster_ack_capture_unknown_and_oversized_frames_never_emit_application_evidence() {
    let store = SqliteAccountStorage::in_memory().unwrap();
    let mut alice = client(store.clone());
    let mut bob = client(SqliteAccountStorage::in_memory().unwrap());
    let kp = bob.fresh_key_package().await.unwrap();
    let (group, welcome) = invite(&mut alice, kp).await;
    bob.join_welcome(welcome).await.unwrap();
    alice.start_roster_ack_capture(&group).await.unwrap();
    let capture = store
        .roster_ack_capture_storage()
        .unwrap()
        .capture_state()
        .unwrap()
        .unwrap();
    let frame = serde_json::json!({"protocol":"whitenoise.experimental.roster-capture.v1","phase":"ack","round_nonce":capture.round_nonce.unwrap(),"roster_commitment":capture.roster_commitment,"epoch":capture.epoch.0});
    let mut unknown = frame.clone();
    unknown["unexpected"] = serde_json::json!(true);
    let mut oversized = frame.clone();
    oversized["padding"] = serde_json::json!("x".repeat(5000));
    let mut wrongphase = frame;
    wrongphase["phase"] = serde_json::json!("not-an-ack");
    for content in [unknown, oversized, wrongphase] {
        alice.drain_events();
        let payload = cgka_traits::app_event::MarmotAppEvent::new(
            hex::encode(bob.self_id().as_slice()),
            1_700_000_000,
            38_173,
            vec![],
            content.to_string(),
        )
        .encode()
        .unwrap();
        let message = application(
            bob.send(SendIntent::AppMessage {
                group_id: group.clone(),
                payload,
                expected_epoch: None,
            })
            .await
            .unwrap(),
        );
        assert!(matches!(
            alice.ingest(message).await.unwrap(),
            cgka_traits::ingest::IngestOutcome::Ignored {
                category: cgka_traits::ingest::InputRejectionCategory::AuthorizationFailed
            }
        ));
        assert!(!alice.drain_events().iter().any(|event| matches!(
            event,
            cgka_traits::engine::GroupEvent::MessageReceived { .. }
        )));
        assert!(alice.roster_ack_capture_facts(&group).unwrap().is_empty());
    }
}

#[tokio::test]
async fn roster_ack_capture_epoch_transition_and_branch_reversion_never_resurrect_old_round() {
    use cgka_traits::storage::MessageStorage;
    let store = SqliteAccountStorage::in_memory().unwrap();
    let mut alice = client(store.clone());
    let mut bob = client(SqliteAccountStorage::in_memory().unwrap());
    let kp = bob.fresh_key_package().await.unwrap();
    let (group, welcome) = invite(&mut alice, kp).await;
    bob.join_welcome(welcome).await.unwrap();
    alice.start_roster_ack_capture(&group).await.unwrap();
    let capture = store
        .roster_ack_capture_storage()
        .unwrap()
        .capture_state()
        .unwrap()
        .unwrap();
    let ack = peer_ack(&mut bob, &group, &capture).await;
    alice.ingest(ack).await.unwrap();
    assert_eq!(alice.roster_ack_capture_facts(&group).unwrap().len(), 1);
    store
        .create_group_snapshot(&group, "capture-before-real-epoch-transition")
        .unwrap();
    let SendResult::GroupEvolution { pending, .. } = alice
        .send(SendIntent::SelfUpdate {
            group_id: group.clone(),
        })
        .await
        .unwrap()
    else {
        panic!("expected real MLS update")
    };
    alice.confirm_published(pending).await.unwrap();
    assert!(alice.roster_ack_capture_facts(&group).unwrap().is_empty());
    // A real retained crypto/tree image returns to A after B. The private local
    // round must be fenced permanently, not revived by matching an old tuple.
    store
        .rollback_group_to_snapshot(&group, "capture-before-real-epoch-transition")
        .unwrap();
    store
        .release_group_snapshot(&group, "capture-before-real-epoch-transition")
        .unwrap();
    drop(alice);
    let mut alice = client(store.clone());
    alice.hydrate_stable_groups_from_storage().unwrap();
    alice.ensure_hydrated(&group).unwrap();
    assert!(
        alice.roster_ack_capture_facts(&group).unwrap().is_empty(),
        "A-to-B-to-A must never resurrect old ACK facts"
    );
    let restarted = application(alice.start_roster_ack_capture(&group).await.unwrap());
    let fresh = store
        .roster_ack_capture_storage()
        .unwrap()
        .capture_state()
        .unwrap()
        .unwrap();
    assert!(fresh.round_nonce != capture.round_nonce);
    assert!(fresh.generation > capture.generation);
    assert!(!restarted.payload.is_empty());
}

#[tokio::test]
async fn roster_ack_capture_real_local_forget_permanently_fences_selected_round() {
    let store = SqliteAccountStorage::in_memory().unwrap();
    let mut alice = client(store.clone());
    let mut bob = client(SqliteAccountStorage::in_memory().unwrap());
    let kp = bob.fresh_key_package().await.unwrap();
    let (group, welcome) = invite(&mut alice, kp).await;
    bob.join_welcome(welcome).await.unwrap();
    alice.start_roster_ack_capture(&group).await.unwrap();
    let capture_store = store.roster_ack_capture_storage().unwrap();
    let before = capture_store.capture_state().unwrap().unwrap();
    let ack = peer_ack(&mut bob, &group, &before).await;
    alice.ingest(ack).await.unwrap();
    assert_eq!(capture_store.capture_facts().unwrap().len(), 1);
    assert!(alice.forget_group_local(&group).unwrap());
    let after = capture_store.capture_state().unwrap().unwrap();
    assert!(after.invalidated);
    assert_eq!(after.generation, before.generation);
    assert!(after.round_nonce == before.round_nonce);
    assert!(after.outbound.is_none());
    assert!(after.prepared_ciphertext.is_none());
    assert!(capture_store.capture_facts().unwrap().is_empty());
    assert!(alice.start_roster_ack_capture(&group).await.is_err());
}

#[tokio::test]
async fn roster_ack_capture_real_current_application_drain_authenticates_fact_without_app_output() {
    let store = SqliteAccountStorage::in_memory().unwrap();
    let mut alice = client(store.clone());
    let mut bob = client(SqliteAccountStorage::in_memory().unwrap());
    let kp = bob.fresh_key_package().await.unwrap();
    let (group, welcome) = invite(&mut alice, kp).await;
    bob.join_welcome(welcome).await.unwrap();
    alice.start_roster_ack_capture(&group).await.unwrap();
    let capture_store = store.roster_ack_capture_storage().unwrap();
    let capture = capture_store.capture_state().unwrap().unwrap();
    let ack = peer_ack(&mut bob, &group, &capture).await;
    alice
        .buffer_openmls_convergence_message_at(&group, ack, 1_000)
        .unwrap();
    alice.drain_events();
    alice
        .advance_convergence_inputs_until_settled(&group, 2_000_000)
        .await
        .unwrap();
    assert_eq!(
        capture_store.capture_facts().unwrap().len(),
        1,
        "real current drain must capture the authenticated leaf in its ratchet transaction"
    );
    assert!(!alice.drain_events().iter().any(|event| matches!(
        event,
        cgka_traits::engine::GroupEvent::MessageReceived { .. }
            | cgka_traits::engine::GroupEvent::AppMessageInvalidated { .. }
    )));
}

#[tokio::test]
async fn roster_ack_capture_real_crypto_probe_neither_captures_nor_exports_private_payload() {
    let store = SqliteAccountStorage::in_memory().unwrap();
    let mut alice = client(store.clone());
    let mut bob = client(SqliteAccountStorage::in_memory().unwrap());
    let kp = bob.fresh_key_package().await.unwrap();
    let (group, welcome) = invite(&mut alice, kp).await;
    bob.join_welcome(welcome).await.unwrap();
    alice.start_roster_ack_capture(&group).await.unwrap();
    let capture_store = store.roster_ack_capture_storage().unwrap();
    let before = capture_store.capture_state().unwrap().unwrap();
    let ack = peer_ack(&mut bob, &group, &before).await;
    let observations = cgka_engine::openmls_projection::replay_openmls_messages(
        &store,
        &group,
        std::slice::from_ref(&ack),
    )
    .unwrap();
    assert!(capture_store.capture_facts().unwrap().is_empty());
    assert!(capture_store.capture_state().unwrap().unwrap() == before);
    assert!(!observations.iter().any(|observation| matches!(
        observation,
        cgka_engine::openmls_projection::OpenMlsReplayObservation::ApplicationProcessed { .. }
    )));
    // Probe ratchets must roll back: the identical ciphertext remains live.
    alice.ingest(ack).await.unwrap();
    assert_eq!(capture_store.capture_facts().unwrap().len(), 1);
}

#[tokio::test]
async fn roster_ack_capture_current_drain_sql_failure_reopens_and_retries_exact_ciphertext() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("isolated-drain-ack.db");
    let key = storage_sqlite::SqlCipherKey::new("39".repeat(32)).unwrap();
    let store = SqliteAccountStorage::open_encrypted(&path, &key).unwrap();
    let mut alice = client(store.clone());
    let mut bob = client(SqliteAccountStorage::in_memory().unwrap());
    let kp = bob.fresh_key_package().await.unwrap();
    let (group, welcome) = invite(&mut alice, kp).await;
    bob.join_welcome(welcome).await.unwrap();
    alice.start_roster_ack_capture(&group).await.unwrap();
    let capture = store
        .roster_ack_capture_storage()
        .unwrap()
        .capture_state()
        .unwrap()
        .unwrap();
    let ack = peer_ack(&mut bob, &group, &capture).await;
    alice
        .buffer_openmls_convergence_message_at(&group, ack.clone(), 1_000)
        .unwrap();
    let injector = rusqlite::Connection::open(&path).unwrap();
    storage_sqlite::open_hardened_sqlcipher(
        &injector,
        &key,
        storage_sqlite::SqlCipherHardening::default(),
    )
    .unwrap();
    injector.execute_batch("CREATE TRIGGER reject_drain_ack BEFORE INSERT ON roster_ack_capture_facts BEGIN SELECT RAISE(ABORT,'injected capture failure'); END;").unwrap();
    assert!(
        alice
            .advance_convergence_inputs_until_settled(&group, 2_000_000)
            .await
            .is_err()
    );
    assert!(
        store
            .roster_ack_capture_storage()
            .unwrap()
            .capture_facts()
            .unwrap()
            .is_empty()
    );
    injector
        .execute_batch("DROP TRIGGER reject_drain_ack;")
        .unwrap();
    drop(injector);
    drop(alice);
    drop(store);
    let reopened = SqliteAccountStorage::open_encrypted(&path, &key).unwrap();
    let mut alice = client(reopened.clone());
    alice.hydrate_all_stored_groups().unwrap();
    alice.drain_events();
    alice
        .advance_convergence_inputs_until_settled(&group, 2_000_000)
        .await
        .unwrap();
    assert_eq!(
        reopened
            .roster_ack_capture_storage()
            .unwrap()
            .capture_facts()
            .unwrap()
            .len(),
        1
    );
    assert!(!alice.drain_events().iter().any(|event| matches!(
        event,
        cgka_traits::engine::GroupEvent::MessageReceived { .. }
            | cgka_traits::engine::GroupEvent::AppMessageInvalidated { .. }
    )));
    assert!(matches!(
        alice.ingest(ack).await.unwrap(),
        cgka_traits::ingest::IngestOutcome::Ignored {
            category: cgka_traits::ingest::InputRejectionCategory::Duplicate
        }
    ));
}

#[tokio::test]
async fn roster_ack_capture_old_epoch_drain_is_handled_without_current_fact_or_app_output() {
    let store = SqliteAccountStorage::in_memory().unwrap();
    let mut alice = client(store.clone());
    let mut bob = client(SqliteAccountStorage::in_memory().unwrap());
    let kp = bob.fresh_key_package().await.unwrap();
    let (group, welcome) = invite(&mut alice, kp).await;
    bob.join_welcome(welcome).await.unwrap();
    alice.start_roster_ack_capture(&group).await.unwrap();
    let capture = store
        .roster_ack_capture_storage()
        .unwrap()
        .capture_state()
        .unwrap()
        .unwrap();
    let old_ack = peer_ack(&mut bob, &group, &capture).await;
    let SendResult::GroupEvolution { pending, .. } = alice
        .send(SendIntent::SelfUpdate {
            group_id: group.clone(),
        })
        .await
        .unwrap()
    else {
        panic!("expected real MLS update")
    };
    alice.confirm_published(pending).await.unwrap();
    alice.start_roster_ack_capture(&group).await.unwrap();
    alice
        .buffer_openmls_convergence_message_at(&group, old_ack, 1_000)
        .unwrap();
    alice.drain_events();
    alice
        .advance_convergence_inputs_until_settled(&group, 2_000_000)
        .await
        .unwrap();
    assert!(
        store
            .roster_ack_capture_storage()
            .unwrap()
            .capture_facts()
            .unwrap()
            .is_empty()
    );
    assert!(!alice.drain_events().iter().any(|event| matches!(
        event,
        cgka_traits::engine::GroupEvent::MessageReceived { .. }
            | cgka_traits::engine::GroupEvent::AppMessageInvalidated { .. }
    )));
}

#[tokio::test]
async fn roster_ack_capture_selected_apply_reauthenticates_private_candidate_without_app_dto() {
    use cgka_traits::message::{MessageState, StoredMessagePayload};
    use cgka_traits::storage::MessageStorage;
    let store = SqliteAccountStorage::in_memory().unwrap();
    let mut alice = client(store.clone());
    let mut bob = client(SqliteAccountStorage::in_memory().unwrap());
    let kp = bob.fresh_key_package().await.unwrap();
    let (group, welcome) = invite(&mut alice, kp).await;
    bob.join_welcome(welcome).await.unwrap();
    alice.start_roster_ack_capture(&group).await.unwrap();
    let capture = store
        .roster_ack_capture_storage()
        .unwrap()
        .capture_state()
        .unwrap()
        .unwrap();
    let ack = peer_ack(&mut bob, &group, &capture).await;
    alice
        .buffer_openmls_convergence_message_at(&group, ack.clone(), 1_000)
        .unwrap();
    let record = store
        .list_messages(&group, cgka_traits::types::EpochId(0))
        .unwrap()
        .into_iter()
        .find(|row| {
            StoredMessagePayload::decode(&row.payload)
                .unwrap()
                .as_openmls_wire()
                .is_some_and(|wire| wire.payload == ack.payload)
        })
        .unwrap();
    let selection = selected_private_fixture(capture.epoch.0, hex::encode(record.id.as_slice()));
    // Trusted fixture selection, not end-to-end branch selection. Authority is
    // exclusively the real selected-tree MLS receiver reauthenticating input.
    let observations = cgka_engine::openmls_projection::apply_openmls_canonicalization_result(
        &store, &group, &selection, 8,
    )
    .unwrap();
    assert_eq!(
        store
            .roster_ack_capture_storage()
            .unwrap()
            .capture_facts()
            .unwrap()
            .len(),
        1
    );
    assert_eq!(
        store.get_message(&record.id).unwrap().state,
        MessageState::Processed
    );
    assert!(!observations.iter().any(|observation| matches!(
        observation,
        cgka_engine::openmls_projection::OpenMlsReplayObservation::ApplicationProcessed { .. }
    )));
}

fn selected_private_fixture(
    epoch: u64,
    message_id: String,
) -> cgka_engine::canonicalization::CanonicalizationResult {
    use cgka_engine::canonicalization::*;
    CanonicalizationResult {
        previous_tip: epoch,
        selected_tip: Some(epoch),
        selected_fork_epoch: Some(epoch),
        selected_branch_id: Some("trusted-test-selected-tree".into()),
        candidate_count: 1,
        eligible_count: 1,
        convergence_status: ConvergenceStatus::Settled,
        accepted_commits: vec![],
        accepted_proposals: vec![],
        accepted_app_messages: vec![],
        deferred_messages: vec![],
        invalidated_app_messages: vec![InvalidatedAppMessage {
            message_id,
            epoch,
            reason: InvalidatedAppMessageReason::UndecryptableInCanonicalState,
            decrypted_payload_ref: None,
        }],
        dropped_messages: vec![],
        already_seen: vec![],
        queued_outbound_intents: vec![],
        publishable_outbound_messages: vec![],
        errors: vec![],
        #[cfg(feature = "test-conformance-snapshot")]
        replay_probe_count: 0,
        selection_trace: None,
    }
}

#[tokio::test]
async fn roster_ack_capture_selected_private_scan_rolls_back_ordinary_receive_ratchet() {
    use cgka_traits::message::{MessageState, StoredMessagePayload};
    use cgka_traits::storage::MessageStorage;
    let store = SqliteAccountStorage::in_memory().unwrap();
    let mut alice = client(store.clone());
    let mut bob = client(SqliteAccountStorage::in_memory().unwrap());
    let kp = bob.fresh_key_package().await.unwrap();
    let (group, welcome) = invite(&mut alice, kp).await;
    bob.join_welcome(welcome).await.unwrap();
    alice.start_roster_ack_capture(&group).await.unwrap();
    let capture = store
        .roster_ack_capture_storage()
        .unwrap()
        .capture_state()
        .unwrap()
        .unwrap();
    let payload = cgka_traits::app_event::MarmotAppEvent::new(
        hex::encode(bob.self_id().as_slice()),
        1_700_000_000,
        1,
        vec![],
        "ordinary fixture",
    )
    .encode()
    .unwrap();
    let ordinary = application(
        bob.send(SendIntent::AppMessage {
            group_id: group.clone(),
            payload,
            expected_epoch: None,
        })
        .await
        .unwrap(),
    );
    alice
        .buffer_openmls_convergence_message_at(&group, ordinary.clone(), 1_000)
        .unwrap();
    let record = store
        .list_messages(&group, cgka_traits::types::EpochId(0))
        .unwrap()
        .into_iter()
        .find(|row| {
            StoredMessagePayload::decode(&row.payload)
                .unwrap()
                .as_openmls_wire()
                .is_some_and(|wire| wire.payload == ordinary.payload)
        })
        .unwrap();
    let selection = selected_private_fixture(capture.epoch.0, hex::encode(record.id.as_slice()));
    let observations = cgka_engine::openmls_projection::apply_openmls_canonicalization_result(
        &store, &group, &selection, 8,
    )
    .unwrap();
    assert!(observations.is_empty());
    assert_eq!(
        store.get_message(&record.id).unwrap().state,
        MessageState::EpochInvalidated
    );
    assert!(
        store
            .roster_ack_capture_storage()
            .unwrap()
            .capture_facts()
            .unwrap()
            .is_empty()
    );
    // The existing ordinary invalidation is preserved. Reauthentication of the
    // identical cipher proves the private-only scratch did not burn its ratchet.
    let retry =
        cgka_engine::openmls_projection::replay_openmls_messages(&store, &group, &[ordinary])
            .unwrap();
    assert!(retry.iter().any(|observation| matches!(
        observation,
        cgka_engine::openmls_projection::OpenMlsReplayObservation::ApplicationProcessed { .. }
    )));
}

#[tokio::test]
async fn roster_ack_capture_real_selected_branch_rejects_stale_ack_without_app_invalidation() {
    let store = SqliteAccountStorage::in_memory().unwrap();
    let mut alice = client(store.clone());
    let mut bob = client(SqliteAccountStorage::in_memory().unwrap());
    let kp = bob.fresh_key_package().await.unwrap();
    let (group, welcome) = invite(&mut alice, kp).await;
    bob.join_welcome(welcome).await.unwrap();
    alice.start_roster_ack_capture(&group).await.unwrap();
    let capture = store
        .roster_ack_capture_storage()
        .unwrap()
        .capture_state()
        .unwrap()
        .unwrap();
    let old_ack = peer_ack(&mut bob, &group, &capture).await;
    alice
        .buffer_openmls_convergence_message_at(&group, old_ack, 1_000)
        .unwrap();
    let SendResult::GroupEvolution { msg, pending, .. } = bob
        .send(SendIntent::SelfUpdate {
            group_id: group.clone(),
        })
        .await
        .unwrap()
    else {
        panic!("expected real peer MLS update")
    };
    bob.confirm_published(pending).await.unwrap();
    alice.ingest(msg).await.unwrap();
    alice.drain_events();
    alice
        .advance_convergence_inputs_until_settled(&group, 2_000_000)
        .await
        .unwrap();
    assert!(
        store
            .roster_ack_capture_storage()
            .unwrap()
            .capture_state()
            .unwrap()
            .unwrap()
            .invalidated
    );
    assert!(
        store
            .roster_ack_capture_storage()
            .unwrap()
            .capture_facts()
            .unwrap()
            .is_empty()
    );
    let events = alice.drain_events();
    assert_eq!(
        events
            .iter()
            .filter(|event| matches!(
                event,
                cgka_traits::engine::GroupEvent::MessageReceived { .. }
            ))
            .count(),
        0,
        "private ACK must not reach chat"
    );
    assert_eq!(
        events
            .iter()
            .filter(|event| matches!(
                event,
                cgka_traits::engine::GroupEvent::AppMessageInvalidated { .. }
            ))
            .count(),
        0,
        "stale private ACK must not become ordinary application invalidation after real branch selection"
    );
}

#[tokio::test]
async fn roster_ack_capture_selected_scan_sql_failure_reopens_and_retries_exact_ciphertext() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("isolated-selected-scan-ack.db");
    let key = storage_sqlite::SqlCipherKey::new("39".repeat(32)).unwrap();
    let store = SqliteAccountStorage::open_encrypted(&path, &key).unwrap();
    let mut alice = client(store.clone());
    let mut bob = client(SqliteAccountStorage::in_memory().unwrap());
    let kp = bob.fresh_key_package().await.unwrap();
    let (group, welcome) = invite(&mut alice, kp).await;
    bob.join_welcome(welcome).await.unwrap();
    alice.start_roster_ack_capture(&group).await.unwrap();
    let capture = store
        .roster_ack_capture_storage()
        .unwrap()
        .capture_state()
        .unwrap()
        .unwrap();
    let ack = peer_ack(&mut bob, &group, &capture).await;
    alice
        .buffer_openmls_convergence_message_at(&group, ack.clone(), 1_000)
        .unwrap();
    use cgka_traits::message::StoredMessagePayload;
    use cgka_traits::storage::MessageStorage;
    let record = store
        .list_messages(&group, cgka_traits::types::EpochId(0))
        .unwrap()
        .into_iter()
        .find(|row| {
            StoredMessagePayload::decode(&row.payload)
                .unwrap()
                .as_openmls_wire()
                .is_some_and(|wire| wire.payload == ack.payload)
        })
        .unwrap();
    let selection = selected_private_fixture(capture.epoch.0, hex::encode(record.id.as_slice()));
    let injector = rusqlite::Connection::open(&path).unwrap();
    storage_sqlite::open_hardened_sqlcipher(
        &injector,
        &key,
        storage_sqlite::SqlCipherHardening::default(),
    )
    .unwrap();
    injector.execute_batch("CREATE TRIGGER reject_drain_ack BEFORE INSERT ON roster_ack_capture_facts BEGIN SELECT RAISE(ABORT,'injected capture failure'); END;").unwrap();
    assert!(
        cgka_engine::openmls_projection::apply_openmls_canonicalization_result(
            &store, &group, &selection, 8
        )
        .is_err()
    );
    assert!(
        store
            .roster_ack_capture_storage()
            .unwrap()
            .capture_facts()
            .unwrap()
            .is_empty()
    );
    injector
        .execute_batch("DROP TRIGGER reject_drain_ack;")
        .unwrap();
    drop(injector);
    drop(alice);
    drop(store);
    let reopened = SqliteAccountStorage::open_encrypted(&path, &key).unwrap();
    let mut alice = client(reopened.clone());
    alice.hydrate_all_stored_groups().unwrap();
    alice.drain_events();
    cgka_engine::openmls_projection::apply_openmls_canonicalization_result(
        &reopened, &group, &selection, 8,
    )
    .unwrap();
    assert_eq!(
        reopened
            .roster_ack_capture_storage()
            .unwrap()
            .capture_facts()
            .unwrap()
            .len(),
        1
    );
    assert!(!alice.drain_events().iter().any(|event| matches!(
        event,
        cgka_traits::engine::GroupEvent::MessageReceived { .. }
            | cgka_traits::engine::GroupEvent::AppMessageInvalidated { .. }
    )));
    assert!(matches!(
        alice.ingest(ack).await.unwrap(),
        cgka_traits::ingest::IngestOutcome::Ignored {
            category: cgka_traits::ingest::InputRejectionCategory::Duplicate
        }
    ));
}

#[tokio::test]
async fn roster_ack_capture_real_commit_probe_does_not_permanently_fence_live_round() {
    let store = SqliteAccountStorage::in_memory().unwrap();
    let mut alice = client(store.clone());
    let mut bob = client(SqliteAccountStorage::in_memory().unwrap());
    let kp = bob.fresh_key_package().await.unwrap();
    let (group, welcome) = invite(&mut alice, kp).await;
    bob.join_welcome(welcome).await.unwrap();
    alice.start_roster_ack_capture(&group).await.unwrap();
    let capture_store = store.roster_ack_capture_storage().unwrap();
    let before = capture_store.capture_state().unwrap().unwrap();
    let ack = peer_ack(&mut bob, &group, &before).await;
    alice.ingest(ack).await.unwrap();
    let facts = capture_store.capture_facts().unwrap();
    let SendResult::GroupEvolution { msg, pending, .. } = bob
        .send(SendIntent::SelfUpdate {
            group_id: group.clone(),
        })
        .await
        .unwrap()
    else {
        panic!("expected real peer MLS update")
    };
    bob.confirm_published(pending).await.unwrap();
    let observations =
        cgka_engine::openmls_projection::replay_openmls_messages(&store, &group, &[msg]).unwrap();
    assert!(observations.iter().any(|observation| matches!(
        observation,
        cgka_engine::openmls_projection::OpenMlsReplayObservation::CommitStaged { .. }
    )));
    assert!(capture_store.capture_state().unwrap().unwrap() == before);
    assert!(capture_store.capture_facts().unwrap() == facts);
    assert_eq!(alice.roster_ack_capture_facts(&group).unwrap().len(), 1);
}

#[tokio::test]
async fn roster_ack_capture_selected_historical_scan_preserves_ordinary_old_epoch_retry() {
    use cgka_traits::message::{MessageState, StoredMessagePayload};
    use cgka_traits::storage::MessageStorage;
    let store = SqliteAccountStorage::in_memory().unwrap();
    let mut alice = client(store.clone());
    let mut bob = client(SqliteAccountStorage::in_memory().unwrap());
    let kp = bob.fresh_key_package().await.unwrap();
    let (group, welcome) = invite(&mut alice, kp).await;
    bob.join_welcome(welcome).await.unwrap();
    alice.start_roster_ack_capture(&group).await.unwrap();
    let capture = store
        .roster_ack_capture_storage()
        .unwrap()
        .capture_state()
        .unwrap()
        .unwrap();
    let payload = cgka_traits::app_event::MarmotAppEvent::new(
        hex::encode(bob.self_id().as_slice()),
        1_700_000_000,
        1,
        vec![],
        "ordinary fixture",
    )
    .encode()
    .unwrap();
    let ordinary = application(
        bob.send(SendIntent::AppMessage {
            group_id: group.clone(),
            payload,
            expected_epoch: None,
        })
        .await
        .unwrap(),
    );
    let SendResult::GroupEvolution { pending, .. } = alice
        .send(SendIntent::SelfUpdate {
            group_id: group.clone(),
        })
        .await
        .unwrap()
    else {
        panic!("expected real MLS update")
    };
    alice.confirm_published(pending).await.unwrap();
    alice.start_roster_ack_capture(&group).await.unwrap();
    let current_epoch = alice.epoch(&group).unwrap().0;
    alice
        .buffer_openmls_convergence_message_at(&group, ordinary.clone(), 1_000)
        .unwrap();
    let record = store
        .list_messages(&group, cgka_traits::types::EpochId(0))
        .unwrap()
        .into_iter()
        .find(|row| {
            StoredMessagePayload::decode(&row.payload)
                .unwrap()
                .as_openmls_wire()
                .is_some_and(|wire| wire.payload == ordinary.payload)
        })
        .unwrap();
    let mut selection =
        selected_private_fixture(capture.epoch.0, hex::encode(record.id.as_slice()));
    selection.previous_tip = current_epoch;
    selection.selected_tip = Some(current_epoch);
    selection.selected_fork_epoch = Some(current_epoch);
    let observations = cgka_engine::openmls_projection::apply_openmls_canonicalization_result(
        &store, &group, &selection, 8,
    )
    .unwrap();
    assert!(observations.is_empty());
    assert_eq!(
        store.get_message(&record.id).unwrap().state,
        MessageState::EpochInvalidated
    );
    assert!(
        store
            .roster_ack_capture_storage()
            .unwrap()
            .capture_facts()
            .unwrap()
            .is_empty()
    );
    // The existing ordinary invalidation is preserved. Reauthentication of the
    // identical cipher proves the private-only scratch did not burn its ratchet.
    let retry =
        cgka_engine::openmls_projection::replay_openmls_messages(&store, &group, &[ordinary])
            .unwrap();
    assert!(retry.iter().any(|observation| matches!(
        observation,
        cgka_engine::openmls_projection::OpenMlsReplayObservation::ApplicationProcessed { .. }
    )));
}
