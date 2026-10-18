//! Explicit account-wide departure cannot fall back to a device-only leave.
use super::*;
use cgka_traits::storage::LeaveRequestStorage;

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn no_approved_policy_refuses_account_departure_without_public_leave_effects() {
    let dir = tempfile::tempdir().unwrap();
    let home = AccountHome::open(dir.path());
    home.create_account("alice").unwrap();
    let bob_account = home.create_account("bob").unwrap();
    let relay = Arc::new(ScriptedPushRelayClient::default());
    let app = MarmotApp::with_relay(dir.path(), "wss://relay.example")
        .with_test_relay_client(relay.clone());
    remember_test_member_inbox(&app, &bob_account.account_id_hex, "wss://relay.example");
    let plane = MarmotRelayPlane::new(None, relay.clone());
    let mut alice = app
        .client_with_relay_plane("alice", &plane, None)
        .await
        .unwrap();
    let mut bob = app
        .client_with_relay_plane("bob", &plane, None)
        .await
        .unwrap();
    bob.sync().await.unwrap();
    let group = alice
        .create_group(
            "ordinary public chat",
            &[bob_account.account_id_hex.as_str()],
        )
        .await
        .unwrap();
    assert!(bob.sync().await.unwrap().joined_groups.contains(&group));
    let published = relay.published_events.lock().unwrap().len();
    for state in [
        bob.account_chat_departure_state(&group).unwrap(),
        bob.leave_account_chat(&group).await.unwrap(),
    ] {
        assert_eq!(state.status, crate::AccountChatDepartureStatus::Unavailable);
        assert_eq!(
            state.reason,
            crate::AccountChatDepartureReason::SharingUnavailable
        );
        assert!(state.operation_id.is_none());
    }
    assert_eq!(relay.published_events.lock().unwrap().len(), published);
    assert!(
        app.account_storage("bob")
            .unwrap()
            .leave_request(&group)
            .unwrap()
            .is_none()
    );
    assert!(
        bob.runtime
            .session()
            .canonical_group_membership(&group)
            .unwrap()
            .local_leaf_active
    );
    assert_eq!(
        app.stored_group_self_membership("bob", &hex::encode(group.as_slice()))
            .unwrap(),
        Some(SelfMembership::Member)
    );
    bob.leave_group(&group).await.unwrap();
    assert!(
        app.account_storage("bob")
            .unwrap()
            .leave_request(&group)
            .unwrap()
            .is_some()
    );
    assert!(relay.published_events.lock().unwrap().len() > published);
}
