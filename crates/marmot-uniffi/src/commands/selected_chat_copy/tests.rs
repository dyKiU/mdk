#[cfg(not(feature = "experimental-device-sync"))]
use super::*;
#[cfg(not(feature = "experimental-device-sync"))]
#[tokio::test]
async fn default_selected_chat_refuses_before_account_effects() {
    let dir = tempfile::tempdir().unwrap();
    let app = marmot_app::MarmotApp::with_relay(dir.path(), "wss://relay.example");
    let kit = Marmot {
        runtime: app.runtime(),
        app,
    };
    assert!(matches!(
        kit.begin_selected_chat_copy("missing".into(), "invalid".into(), vec![0; 16385])
            .await,
        Err(MarmotKitError::SelectedChatCopyUnsupported)
    ));
    assert!(matches!(
        kit.receive_selected_chat_copy_request("missing".into(), vec![0; 16385])
            .await,
        Err(MarmotKitError::SelectedChatCopyUnsupported)
    ));
    assert!(
        kit.runtime
            .accounts()
            .managed_accounts()
            .unwrap()
            .is_empty()
    );
    kit.runtime.shutdown_and_close().await.unwrap();
}
