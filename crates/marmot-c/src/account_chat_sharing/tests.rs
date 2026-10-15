use super::*;
use std::ptr;

#[cfg(feature = "experimental-device-sync")]
pub(crate) unsafe fn verify_account_sharing_binding_originals(
    clients: &[MarmotClient],
    accounts: &[std::ffi::CString],
) {
    use crate::types::account_chat_sharing::{
        marmot_account_sharing_snapshot_free, marmot_account_sharing_targets_free,
    };
    unsafe {
        let mut targets = ptr::null_mut();
        assert_eq!(
            marmot_account_chat_sharing_targets(&clients[0], accounts[0].as_ptr(), &mut targets),
            MarmotStatus::Ok
        );
        assert_eq!((*targets).targets_len, 1);
        let target = &*(*targets).targets;
        let recipient = std::slice::from_raw_parts(target.device, target.device_len).to_vec();
        marmot_account_sharing_targets_free(targets);
        let begin = || {
            let mut handle = ptr::null_mut();
            assert_eq!(
                marmot_begin_account_chat_sharing(
                    &clients[0],
                    accounts[0].as_ptr(),
                    recipient.as_ptr(),
                    recipient.len(),
                    &mut handle
                ),
                MarmotStatus::Ok
            );
            handle
        };
        let observe = |handle| {
            let mut out = ptr::null_mut();
            assert_eq!(
                marmot_account_sharing_approval_snapshot(handle, &mut out),
                MarmotStatus::Ok
            );
            out
        };
        let original = begin();
        let mut source = ptr::null_mut();
        assert_eq!(
            marmot_account_sharing_approval_clone(original, &mut source),
            MarmotStatus::Ok
        );
        marmot_account_sharing_approval_free(original);
        let review = observe(source);
        assert!(!(*review).approved && !(*review).complete);
        assert_eq!(
            marmot_account_sharing_approval_approve(source, (*review).revision + 1),
            MarmotStatus::AccountSharingStaleRevision
        );
        marmot_account_sharing_snapshot_free(review);
        assert_eq!(
            marmot_account_sharing_approval_cancel(source),
            MarmotStatus::Ok
        );
        let mut closed = ptr::dangling_mut();
        assert_eq!(
            marmot_account_sharing_approval_snapshot(source, &mut closed),
            MarmotStatus::AccountSharingClosed
        );
        assert!(closed.is_null());
        marmot_account_sharing_approval_free(source);

        let source = begin();
        let review = observe(source);
        let revision = (*review).revision;
        let source_device =
            std::slice::from_raw_parts((*review).source_device, (*review).source_device_len)
                .to_vec();
        marmot_account_sharing_snapshot_free(review);
        // A runtime-worker invocation exercises the same blocking C ABI used by callbacks.
        let address = source as usize;
        let status = clients[0].runtime.block_on(async {
            tokio::spawn(async move {
                marmot_account_sharing_approval_approve(
                    address as *const MarmotAccountSharingApproval,
                    revision,
                )
            })
            .await
            .unwrap()
        });
        assert_eq!(status, MarmotStatus::Ok);
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(30);
        let recipient_handle = loop {
            let mut pending = ptr::null_mut();
            assert_eq!(
                marmot_pending_account_chat_sharing(
                    &clients[1],
                    accounts[1].as_ptr(),
                    &mut pending
                ),
                MarmotStatus::Ok
            );
            let mut retained = ptr::null_mut();
            let entries = if (*pending).items_len == 0 {
                &[][..]
            } else {
                std::slice::from_raw_parts((*pending).items, (*pending).items_len)
            };
            for entry in entries {
                let review = observe(entry.handle);
                let addressed = std::slice::from_raw_parts(
                    (*review).source_device,
                    (*review).source_device_len,
                ) == source_device
                    && std::slice::from_raw_parts(
                        (*review).recipient_device,
                        (*review).recipient_device_len,
                    ) == recipient;
                marmot_account_sharing_snapshot_free(review);
                if addressed {
                    assert_eq!(
                        marmot_account_sharing_approval_clone(entry.handle, &mut retained),
                        MarmotStatus::Ok
                    );
                    break;
                }
            }
            marmot_account_sharing_approval_list_free(pending);
            if !retained.is_null() {
                break retained;
            }
            assert!(
                std::time::Instant::now() < deadline,
                "addressed review timed out"
            );
            std::thread::sleep(std::time::Duration::from_millis(50));
        };
        let review = observe(recipient_handle);
        assert!(!(*review).approved && !(*review).complete);
        assert_eq!(
            marmot_account_sharing_approval_approve(recipient_handle, (*review).revision + 1),
            MarmotStatus::AccountSharingStaleRevision
        );
        assert_eq!(
            marmot_account_sharing_approval_approve(recipient_handle, (*review).revision),
            MarmotStatus::Ok
        );
        marmot_account_sharing_snapshot_free(review);
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(30);
        loop {
            let a = observe(source);
            let c = observe(recipient_handle);
            let complete = (*a).complete && (*c).complete;
            marmot_account_sharing_snapshot_free(a);
            marmot_account_sharing_snapshot_free(c);
            if complete {
                break;
            }
            assert!(std::time::Instant::now() < deadline, "sharing timed out");
            std::thread::sleep(std::time::Duration::from_millis(50));
        }
        marmot_account_sharing_approval_free(source);
        marmot_account_sharing_approval_free(recipient_handle);
    }
}
#[test]
fn account_sharing_required_outputs_preflight_before_foreign_inputs() {
    unsafe {
        assert_eq!(
            marmot_account_chat_sharing_targets(ptr::null(), ptr::dangling(), ptr::null_mut()),
            MarmotStatus::NullPointer
        );
        assert_eq!(
            marmot_begin_account_chat_sharing(
                ptr::null(),
                ptr::dangling(),
                ptr::dangling(),
                usize::MAX,
                ptr::null_mut()
            ),
            MarmotStatus::NullPointer
        );
        assert_eq!(
            marmot_pending_account_chat_sharing(ptr::null(), ptr::dangling(), ptr::null_mut()),
            MarmotStatus::NullPointer
        );
        assert_eq!(
            marmot_account_sharing_approval_clone(ptr::null(), ptr::null_mut()),
            MarmotStatus::NullPointer
        );
        assert_eq!(
            marmot_account_sharing_approval_snapshot(ptr::null(), ptr::null_mut()),
            MarmotStatus::NullPointer
        );
        assert_eq!(
            marmot_account_sharing_approval_approve(ptr::null(), 0),
            MarmotStatus::NullPointer
        );
        assert_eq!(
            marmot_account_sharing_approval_cancel(ptr::null()),
            MarmotStatus::NullPointer
        );
        marmot_account_sharing_approval_free(ptr::null_mut());
        marmot_account_sharing_approval_list_free(ptr::null_mut());
    }
}
#[cfg(not(feature = "experimental-device-sync"))]
#[test]
fn account_sharing_default_refuses_before_bad_inputs_and_clears_outputs() {
    unsafe {
        let mut targets = ptr::dangling_mut();
        assert_eq!(
            marmot_account_chat_sharing_targets(ptr::null(), ptr::dangling(), &mut targets),
            MarmotStatus::AccountSharingUnsupported
        );
        assert!(targets.is_null());
        let mut handle = ptr::dangling_mut();
        assert_eq!(
            marmot_begin_account_chat_sharing(
                ptr::null(),
                ptr::dangling(),
                ptr::dangling(),
                usize::MAX,
                &mut handle
            ),
            MarmotStatus::AccountSharingUnsupported
        );
        assert!(handle.is_null());
        let mut pending = ptr::dangling_mut();
        assert_eq!(
            marmot_pending_account_chat_sharing(ptr::null(), ptr::dangling(), &mut pending),
            MarmotStatus::AccountSharingUnsupported
        );
        assert!(pending.is_null());
    }
}
#[cfg(feature = "experimental-device-sync")]
#[test]
fn account_sharing_recipient_bound_precedes_foreign_byte_access() {
    unsafe {
        let mut handle = ptr::dangling_mut();
        assert_eq!(
            marmot_begin_account_chat_sharing(
                ptr::null(),
                ptr::dangling(),
                ptr::dangling(),
                usize::MAX,
                &mut handle
            ),
            MarmotStatus::AccountSharingNotReady
        );
        assert!(handle.is_null());
    }
}
#[cfg(feature = "alloc-audit")]
#[test]
fn account_sharing_observation_deep_free_releases_ordered_device_bytes() {
    let _serial = crate::memory::audit::test_lock();
    let before = crate::memory::audit::live_allocations();
    let targets = boxed(MarmotAccountSharingTargets::from(
        marmot_uniffi::AccountSharingTargetsFfi {
            protected_group_id_hex: "08".repeat(16),
            protected_epoch: 9,
            targets: vec![
                marmot_uniffi::AccountSharingTargetFfi {
                    leaf_index: 2,
                    device: vec![3; 32],
                },
                marmot_uniffi::AccountSharingTargetFfi {
                    leaf_index: 7,
                    device: vec![4; 32],
                },
            ],
        },
    ));
    unsafe {
        assert_eq!((*targets).targets_len, 2);
        assert_eq!((*(*targets).targets.add(1)).leaf_index, 7);
        assert_eq!((*(*targets).targets).device_len, 32);
        crate::types::account_chat_sharing::marmot_account_sharing_targets_free(targets);
    }
    assert_eq!(crate::memory::audit::live_allocations(), before);
    let snapshot = boxed(MarmotAccountSharingSnapshot::from(
        marmot_uniffi::AccountSharingSnapshotFfi {
            protected_group_id_hex: "08".repeat(16),
            protected_epoch: 9,
            source_device: vec![2; 32],
            recipient_device: vec![3; 32],
            revision: 1,
            approved: false,
            complete: false,
        },
    ));
    unsafe {
        crate::types::account_chat_sharing::marmot_account_sharing_snapshot_free(snapshot);
    }
    assert_eq!(crate::memory::audit::live_allocations(), before);
}
