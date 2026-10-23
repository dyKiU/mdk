//! A real known-approver control cannot starve the independent B/C original.
use super::actual::{ApprovalScenario, run_native_public_three_device_enrollment};
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn public_broad_sibling_projection_head_failure_does_not_starve_original() {
    run_native_public_three_device_enrollment(ApprovalScenario::BroadProjectionHeadFailure).await;
}

/// Publish an unrelated genuine A→B original; this never approves sharing with C.
pub(super) async fn begin_actual_approver_distractor(
    apps: &[crate::MarmotApp; 3],
    managers: &[crate::AccountManager; 3],
) -> crate::AccountSharingApproval {
    use cgka_traits::StorageProvider;
    let target = apps[1]
        .account_storage("test")
        .unwrap()
        .private_roster_settlement_storage()
        .unwrap()
        .read_round()
        .unwrap()
        .unwrap()
        .anchor
        .local_device;
    let action = managers[0]
        .begin_account_chat_sharing("test", target.to_vec())
        .await
        .unwrap();
    let source = action.snapshot().unwrap();
    assert!(source.recipient_device.as_slice() == target);
    action.approve(source.revision).await.unwrap();
    action
}
