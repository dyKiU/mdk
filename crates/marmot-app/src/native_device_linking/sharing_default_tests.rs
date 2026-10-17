//! Feature-off broad approval cannot start a worker or interpret a selector.
use super::*;

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn default_original_sibling_sharing_is_unsupported_before_effects() {
    let dir = tempfile::tempdir().unwrap();
    let runtime = crate::MarmotAppRuntime::new(crate::MarmotApp::with_relay(
        dir.path(),
        "wss://relay.example",
    ));
    let accounts = runtime.accounts();
    let approval = DeviceLinkingApproval { _private: () };
    assert_eq!(
        approval.approve_and_share_chats(u64::MAX).await,
        Err(DeviceLinkingError::Unsupported)
    );
    assert!(accounts.managed_accounts().unwrap().is_empty());
    runtime.shutdown_and_close().await.unwrap();
}
