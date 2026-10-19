//! Public-relay chat delivery after actual three-device, one-scan enrollment.
use super::*;
use std::time::Duration;

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "explicit synthetic public-network chat delivery acceptance"]
async fn public_three_device_automatic_chats_and_messages() {
    let relay = public_enrollment_relay();
    four_device_enrollment_with_delivery(HeldPublication::None, Some(&relay), false, true).await;
}

pub(super) async fn verify(
    apps: &[MarmotApp; 4],
    runtimes: &[MarmotAppRuntime; 4],
    account: &str,
    contact: &str,
    existing_chat: &(crate::GroupId, Vec<u8>),
) {
    wait_for_mirrors(
        runtimes,
        account,
        &existing_chat.0,
        &existing_chat.1,
        "Synthetic pre-pairing message",
    )
    .await;

    let source = runtimes[0].accounts();
    let peer = runtimes[3].accounts();
    let group = source
        .create_group(
            account,
            "New shared public chat",
            &[contact.to_owned()],
            None,
        )
        .await
        .unwrap();
    tokio::time::timeout(Duration::from_secs(30), async {
        while !apps[3]
            .group(contact, &hex::encode(group.as_slice()))
            .unwrap()
            .is_some_and(|row| row.pending_confirmation)
        {
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
    })
    .await
    .expect("real ordinary peer must receive the new chat invitation");
    peer.accept_group_invite(contact, &group).await.unwrap();

    let text = "New chat created after the third device joined";
    let sent = source
        .send_message(account, &group, text.as_bytes().to_vec())
        .await
        .unwrap();
    assert_eq!(sent.message_ids.len(), 1);
    let event = hex::decode(&sent.message_ids[0]).unwrap();
    wait_for_mirrors(runtimes, account, &group, &event, text).await;

    let forwarded = "Third device sends through its shared chat";
    let token = "public-third-device-forwarded-send".to_owned();
    let accepted = runtimes[2]
        .submit_text(account, &group, forwarded.to_owned(), token.clone())
        .await
        .unwrap();
    tokio::time::timeout(Duration::from_secs(90), async {
        loop {
            let completed = runtimes[2]
                .local_send_status(account, &group, &token)
                .unwrap();
            if let Some(crate::LocalSendStatus::Completed(summary)) = completed {
                assert_eq!(summary.published, 1);
                assert!(summary.message_ids == [accepted.message_id_hex.clone()]);
                if apps[3].messages(contact).unwrap().iter().any(|message| {
                    message.message_id_hex == accepted.message_id_hex
                        && message.plaintext == forwarded
                }) {
                    break;
                }
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
    })
    .await
    .expect("third-device send must complete and reach the actual ordinary peer");
    let event = hex::decode(&accepted.message_id_hex).unwrap();
    wait_for_mirrors(runtimes, account, &group, &event, forwarded).await;

    let reply = "Ordinary peer replies to all three installations";
    let sent = peer
        .send_message(contact, &group, reply.as_bytes().to_vec())
        .await
        .unwrap();
    assert_eq!(sent.message_ids.len(), 1);
    tokio::time::timeout(Duration::from_secs(30), async {
        while !apps[0].messages(account).unwrap().iter().any(|message| {
            message.message_id_hex == sent.message_ids[0] && message.plaintext == reply
        }) {
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
    })
    .await
    .expect("the ordinary peer reply must reach the actual group member");
    let event = hex::decode(&sent.message_ids[0]).unwrap();
    wait_for_mirrors(runtimes, account, &group, &event, reply).await;

    for app in &apps[1..3] {
        assert!(
            app.load_state(account)
                .unwrap()
                .groups
                .iter()
                .all(|row| row.group_id_hex != hex::encode(group.as_slice())),
            "shared-chat forwarding must not invent ordinary group membership"
        );
    }
}

async fn wait_for_mirrors(
    runtimes: &[MarmotAppRuntime; 4],
    account: &str,
    group: &crate::GroupId,
    event: &[u8],
    text: &str,
) {
    tokio::time::timeout(Duration::from_secs(30), async {
        loop {
            let mut all_received = true;
            for runtime in &runtimes[1..3] {
                let accounts = runtime.accounts();
                let chats = accounts.paired_chat_list_page(account, None, 128).await;
                let messages = accounts
                    .paired_chat_message_page(account, group.clone(), None, 128)
                    .await;
                all_received &= chats
                    .is_ok_and(|page| page.chats.iter().any(|chat| &chat.group_id == group))
                    && messages.is_ok_and(|page| {
                        page.messages.iter().any(|message| {
                            message.event_id.as_slice() == event
                                && !message.deleted
                                && message.content == text
                        })
                    });
            }
            if all_received {
                break;
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
    })
    .await
    .expect("both paired devices must automatically receive the chat and exact message");
}
