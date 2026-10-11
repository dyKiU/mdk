//! Real client-token send from a paired mirror through an actual member.
use super::*;
use cgka_traits::StorageProvider;

#[tokio::test]
async fn automatic_forwarding_uses_original_client_token_and_real_ordinary_event() {
    actual::run_native_public_three_device_enrollment(
        actual::ApprovalScenario::AutomaticForwarding,
    )
    .await;
}

pub(super) async fn verify(
    apps: &[MarmotApp; 3],
    runtime: &MarmotAppRuntime,
    group: &crate::GroupId,
    scope: &cgka_traits::mirrored_chat_catalog::MirroredChatScope,
) {
    let token = "paired-source-forwarding-original-token".to_owned();
    let text = "message from the paired mirror".to_owned();
    let accepted = runtime
        .submit_text("test", group, text.clone(), token.clone())
        .await
        .unwrap();
    let retry = runtime
        .submit_text("test", group, text.clone(), token.clone())
        .await
        .unwrap();
    assert!(
        accepted == retry,
        "same token must retain canonical event identity"
    );
    assert!(
        runtime
            .submit_text("test", group, "changed request".into(), token.clone())
            .await
            .is_err()
    );
    assert!(apps[2].load_state("test").unwrap().groups.is_empty());
    tokio::time::timeout(std::time::Duration::from_secs(90), async {
        loop {
            let state = runtime.local_send_status("test", group, &token).unwrap();
            if let Some(crate::LocalSendStatus::Completed(summary)) = state {
                assert_eq!(summary.published, 1);
                assert!(summary.message_ids == [accepted.message_id_hex.clone()]);
                let source = apps[0].account_storage("test").unwrap();
                let row = source
                    .app_message(&hex::encode(group.as_slice()), &accepted.message_id_hex)
                    .unwrap();
                let receiver = apps[2].account_storage("test").unwrap();
                let rows = receiver
                    .mirrored_chat_message_storage()
                    .unwrap()
                    .mirrored_chat_message_page(scope, group, None, 128, crate::unix_now_seconds())
                    .unwrap();
                if let Some(row) = row
                    && rows
                        .iter()
                        .any(|r| hex::encode(r.event_id) == accepted.message_id_hex)
                {
                    assert!(row.plaintext == text);
                    break;
                }
            }
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        }
    })
    .await
    .expect(
        "actual member publish, authenticated receipt and automatic record import must complete",
    );
    assert!(
        apps[2].load_state("test").unwrap().groups.is_empty(),
        "forwarding never creates synthetic ordinary membership"
    );
}
