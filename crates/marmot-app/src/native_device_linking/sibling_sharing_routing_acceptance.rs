//! Genuine B→A request observed on C through the public original and real relay.
use super::actual::{ApprovalScenario, run_native_public_three_device_enrollment};
use super::*;
use cgka_traits::StorageProvider;

pub(super) async fn assert_wrong_recipient_request_is_not_pending(
    apps: &[MarmotApp; 3],
    managers: &[crate::AccountManager; 3],
    c: &DeviceLinkingSession,
) {
    let devices = apps.each_ref().map(|app| {
        app.account_storage("test")
            .unwrap()
            .private_roster_settlement_storage()
            .unwrap()
            .read_round()
            .unwrap()
            .unwrap()
            .anchor
            .local_device
    });
    let baseline = c
        .sibling_recipient_diagnostics_for_test()
        .expect("actual C choice remains held");
    let original = managers[1]
        .begin_account_chat_sharing("test", devices[0].to_vec())
        .await
        .unwrap();
    let nonce = original
        .original
        .scope
        .lock()
        .expect("sharing scope")
        .as_ref()
        .expect("actual source channel bound")
        .nonce;
    let probe = c.arm_sibling_routing_probe_for_test(nonce).unwrap();
    let source = original.snapshot().unwrap();
    assert!(
        source.source_device.as_slice() == devices[1]
            && source.recipient_device.as_slice() == devices[0]
    );
    original.approve(source.revision).await.unwrap();
    let mut last_addressed_a_intake = false;
    let mut last_c_observed_count = None;
    let prerequisite_wait = tokio::time::timeout(std::time::Duration::from_secs(15), async {
        loop {
            let intended_received = managers[0]
                .pending_account_chat_sharing("test")
                .await
                .unwrap()
                .iter()
                .any(|pending| {
                    pending
                        .original
                        .scope
                        .lock()
                        .expect("sharing scope")
                        .as_ref()
                        .is_some_and(|scope| scope.nonce == nonce)
                });
            last_addressed_a_intake = intended_received;
            last_c_observed_count = intended_received.then(|| probe.snapshot_for_test()[0]);
            if last_c_observed_count.is_some_and(|count| count > 0) {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        }
    })
    .await;
    let wait_succeeded = prerequisite_wait.is_ok();
    let c_observed_count_json = last_c_observed_count
        .map_or_else(|| "null".to_owned(), |count| count.to_string());
    crate::test_support::emit_line(format_args!(
        "sibling-routing-prerequisite {{\"addressed_a_intake\":{},\"c_observed_count\":{},\"wait_succeeded\":{}}}",
        last_addressed_a_intake, c_observed_count_json, wait_succeeded
    ));
    prerequisite_wait
        .expect("actual addressed A intake and verified exact-request observation on C");
    // Let ordinary maintenance retry anything C retained, without another
    // approval, refetch or direct invocation of its private control handler.
    tokio::time::sleep(std::time::Duration::from_millis(2200)).await;
    let observed = probe.snapshot_for_test();
    assert!(
        observed[0] > 0,
        "C must observe the actual verified request"
    );
    assert_eq!(
        observed[1], 0,
        "wrong-recipient intake must not invoke C's addressed original authentication"
    );
    let after = c.sibling_recipient_diagnostics_for_test().unwrap();
    assert!(
        after[6] <= baseline[6],
        "wrong-recipient request must not remain in C's opaque pending queue"
    );
    original.cancel();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn public_wrong_recipient_sharing_request_is_not_retained_by_c_original() {
    run_native_public_three_device_enrollment(ApprovalScenario::BroadWrongRecipientRouting).await;
}
