use super::*;
use crate::memory::audit;
use std::collections::HashMap;
#[cfg(feature = "experimental-device-sync")]
use std::ffi::CStr;
use std::ffi::CString;
use std::sync::Mutex;

#[derive(Default)]
struct Secrets(Mutex<HashMap<String, String>>);
impl marmot_uniffi::SecretStore for Secrets {
    fn has_secret_for_label(&self, label: String) -> Result<bool, marmot_uniffi::MarmotKitError> {
        Ok(self.0.lock().unwrap().contains_key(&label))
    }
    fn has_secret_for_account_id(&self, id: String) -> Result<bool, marmot_uniffi::MarmotKitError> {
        Ok(self.0.lock().unwrap().contains_key(&id))
    }
    fn write_secret(
        &self,
        label: String,
        id: String,
        key: String,
    ) -> Result<(), marmot_uniffi::MarmotKitError> {
        let mut store = self.0.lock().unwrap();
        store.insert(label, key.clone());
        store.insert(id, key);
        Ok(())
    }
    fn load_secret(
        &self,
        label: String,
        _id: String,
    ) -> Result<String, marmot_uniffi::MarmotKitError> {
        Ok(self.0.lock().unwrap().get(&label).unwrap().clone())
    }
    fn remove_secret(
        &self,
        label: String,
        id: String,
    ) -> Result<(), marmot_uniffi::MarmotKitError> {
        let mut store = self.0.lock().unwrap();
        store.remove(&label);
        store.remove(&id);
        Ok(())
    }
}
fn client(dir: &std::path::Path, relay: String) -> MarmotClient {
    let runtime = tokio::runtime::Runtime::new().unwrap();
    let marmot = marmot_uniffi::Marmot::new_with_options(
        dir.to_str().unwrap().into(),
        vec![relay],
        marmot_uniffi::RelayPolicyFfi::AllowLoopback,
        Some(Arc::new(Secrets::default())),
    )
    .unwrap();
    MarmotClient { runtime, marmot }
}
#[test]
fn device_binding_null_outputs_precede_handle_or_input_access() {
    unsafe {
        assert_eq!(
            marmot_begin_device_linking_session(
                std::ptr::null(),
                std::ptr::null(),
                std::ptr::null_mut()
            ),
            MarmotStatus::NullPointer
        );
        assert_eq!(
            marmot_approve_device_linking_session(
                std::ptr::null(),
                std::ptr::null(),
                std::ptr::dangling(),
                usize::MAX,
                std::ptr::null(),
                0,
                std::ptr::null_mut()
            ),
            MarmotStatus::NullPointer
        );
        assert_eq!(
            marmot_device_linking_subscription_next(std::ptr::null(), 0, std::ptr::null_mut()),
            MarmotStatus::NullPointer
        );
        // The bounded copier refuses before dereferencing caller memory.
        assert!(matches!(
            packet(std::ptr::dangling(), usize::MAX, 512 * 1024),
            Err(MarmotStatus::DeviceLinkingInvalidPacket)
        ));
        marmot_device_linking_session_free(std::ptr::null_mut());
        marmot_device_linking_subscription_free(std::ptr::null_mut());
    }
}
#[cfg(not(feature = "experimental-device-sync"))]
#[test]
fn default_device_binding_is_typed_unsupported_and_clears_output() {
    let _guard = audit::test_lock();
    let dir = tempfile::tempdir().unwrap();
    let client = client(dir.path(), "wss://relay.example".into());
    let account = CString::new("missing").unwrap();
    unsafe {
        let mut out = std::ptr::dangling_mut();
        assert_eq!(
            marmot_begin_device_linking_session(&client, account.as_ptr(), &mut out),
            MarmotStatus::DeviceLinkingUnsupported
        );
        assert!(out.is_null());
        let mut targets = std::ptr::dangling_mut();
        assert_eq!(
            marmot_device_linking_targets(&client, account.as_ptr(), &mut targets),
            MarmotStatus::DeviceLinkingUnsupported
        );
        assert!(targets.is_null());
        let mut approvals = std::ptr::dangling_mut();
        assert_eq!(
            marmot_pending_device_linking_approvals(&client, account.as_ptr(), &mut approvals),
            MarmotStatus::DeviceLinkingUnsupported
        );
        assert!(approvals.is_null());
        let mut caps = std::ptr::null_mut();
        assert_eq!(
            marmot_device_linking_capabilities(&client, &mut caps),
            MarmotStatus::Ok
        );
        assert!(!(*caps).verification_supported && !(*caps).enrollment_supported);
        marmot_device_linking_capabilities_free(caps);
    }
    client.block_on(client.marmot.shutdown_and_close()).unwrap();
}
#[test]
fn device_binding_deep_free_preserves_binary_and_optional_decimals() {
    let _guard = audit::test_lock();
    #[cfg(feature = "alloc-audit")]
    let before = audit::live_allocations();
    let packets = vec![marmot_uniffi::DeviceLinkingOutgoingPacketFfi {
        acknowledgement_id: "frame/ack".into(),
        bytes: vec![0, 255, 0, 1],
    }];
    let packet_list: MarmotDeviceLinkingOutgoingPacketList = packets.into();
    let snapshot: MarmotDeviceLinkingSnapshot = marmot_uniffi::DeviceLinkingSnapshotFfi {
        revision: 7,
        phase: marmot_uniffi::DeviceLinkingPhaseFfi::ComparisonAvailable,
        decimals: Some(marmot_uniffi::DeviceLinkingDecimalsFfi {
            first: 1234,
            second: 5678,
            third: 9012,
        }),
    }
    .into();
    unsafe {
        assert_eq!(
            std::slice::from_raw_parts((*packet_list.items).bytes, (*packet_list.items).bytes_len),
            &[0, 255, 0, 1]
        );
        assert_eq!((*snapshot.decimals).third, 9012);
        marmot_device_linking_outgoing_packet_list_free(boxed(packet_list));
        marmot_device_linking_snapshot_free(boxed(snapshot));
        marmot_device_linking_bytes_free(boxed(vec![0, 1, 255].into()));
    }
    #[cfg(feature = "alloc-audit")]
    assert_eq!(before, audit::live_allocations());
}
#[cfg(feature = "experimental-device-sync")]
#[test]
fn actual_c_sessions_continue_original_enrollment_and_close_is_reentrant() {
    use nostr::prelude::ToBech32;
    let _guard = audit::test_lock();
    #[cfg(feature = "alloc-audit")]
    let before = audit::live_allocations();
    let relay_runtime = tokio::runtime::Runtime::new().unwrap();
    let relay = relay_runtime
        .block_on(nostr_relay_builder::MockRelay::run())
        .unwrap();
    let url = relay_runtime.block_on(relay.url()).to_string();
    let keys = nostr::prelude::Keys::generate();
    let dirs = [tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap()];
    let clients = dirs
        .iter()
        .map(|dir| client(dir.path(), url.clone()))
        .collect::<Vec<_>>();
    let mut accounts = Vec::new();
    for client in &clients {
        let account = client
            .block_on(client.marmot.login(
                keys.secret_key().to_bech32().unwrap(),
                vec![url.clone()],
                Vec::new(),
                Vec::new(),
            ))
            .unwrap();
        accounts.push(CString::new(account.account_id_hex).unwrap());
    }
    unsafe {
        // A null output must not reserve C's actual purpose; the following valid call succeeds.
        assert_eq!(
            marmot_begin_device_linking_session(
                &clients[1],
                accounts[1].as_ptr(),
                std::ptr::null_mut()
            ),
            MarmotStatus::NullPointer
        );
        let mut c = std::ptr::null_mut();
        assert_eq!(
            marmot_begin_device_linking_session(&clients[1], accounts[1].as_ptr(), &mut c),
            MarmotStatus::Ok
        );
        let mut request = std::ptr::null_mut();
        assert_eq!(
            marmot_device_linking_session_setup_packet(c, &mut request),
            MarmotStatus::Ok
        );
        let mut a = std::ptr::null_mut();
        assert_eq!(
            marmot_approve_device_linking_session(
                &clients[0],
                accounts[0].as_ptr(),
                (*request).bytes,
                (*request).bytes_len,
                std::ptr::null(),
                0,
                &mut a
            ),
            MarmotStatus::Ok
        );
        marmot_device_linking_bytes_free(request);
        let mut challenge = std::ptr::null_mut();
        assert_eq!(
            marmot_device_linking_session_setup_packet(a, &mut challenge),
            MarmotStatus::Ok
        );
        assert_eq!(
            marmot_device_linking_session_receive_setup_packet(
                c,
                (*challenge).bytes,
                (*challenge).bytes_len
            ),
            MarmotStatus::Ok
        );
        marmot_device_linking_bytes_free(challenge);
        assert_eq!(
            marmot_device_linking_session_receive_packet(c, std::ptr::dangling(), usize::MAX),
            MarmotStatus::DeviceLinkingInvalidPacket
        );
        for _ in 0..8 {
            drain(a, c);
            drain(c, a);
        }
        let ac = snapshot(a);
        let cc = snapshot(c);
        assert_eq!((*ac).phase, MarmotDeviceLinkingPhase::ComparisonAvailable);
        assert!(!(*ac).decimals.is_null());
        assert_eq!((*(*ac).decimals).first, (*(*cc).decimals).first);
        assert_eq!(
            marmot_device_linking_session_confirm_comparison(a, (*ac).revision + 1),
            MarmotStatus::DeviceLinkingStaleRevision
        );
        assert_eq!(
            marmot_device_linking_session_confirm_comparison(a, (*ac).revision),
            MarmotStatus::Ok
        );
        assert_eq!(
            marmot_device_linking_session_confirm_comparison(c, (*cc).revision),
            MarmotStatus::Ok
        );
        marmot_device_linking_snapshot_free(ac);
        marmot_device_linking_snapshot_free(cc);
        for _ in 0..8 {
            drain(a, c);
            drain(c, a);
        }
        let ac = snapshot(a);
        assert_eq!(
            (*ac).phase,
            MarmotDeviceLinkingPhase::VerificationCompleteEnrollmentPending
        );
        let cc = snapshot(c);
        assert_eq!(
            marmot_device_linking_session_continue_linking(c, (*cc).revision),
            MarmotStatus::Ok
        );
        marmot_device_linking_snapshot_free(cc);
        assert_eq!(
            marmot_device_linking_session_continue_linking(a, (*ac).revision),
            MarmotStatus::Ok
        );
        marmot_device_linking_snapshot_free(ac);
        let mut sub = std::ptr::null_mut();
        assert_eq!(
            marmot_device_linking_session_subscribe(a, &mut sub),
            MarmotStatus::Ok
        );
        let mut initial = std::ptr::null_mut();
        assert_eq!(
            marmot_device_linking_subscription_next(sub, 1000, &mut initial),
            MarmotStatus::Ok
        );
        marmot_device_linking_snapshot_free(initial);
        let mut timeout = std::ptr::dangling_mut();
        assert_eq!(
            marmot_device_linking_subscription_next(sub, 1, &mut timeout),
            MarmotStatus::Timeout
        );
        assert!(timeout.is_null());
        // A blocking SDK observation from a runtime worker exercises callback re-entry.
        let address = a as usize;
        let (status, observed) = clients[0].runtime.block_on(async {
            tokio::spawn(async move {
                let mut observed = std::ptr::null_mut();
                let status = marmot_device_linking_session_snapshot(
                    address as *const MarmotDeviceLinkingSession,
                    &mut observed,
                );
                (status, observed as usize)
            })
            .await
            .unwrap()
        });
        assert_eq!(status, MarmotStatus::Ok);
        marmot_device_linking_snapshot_free(observed as *mut MarmotDeviceLinkingSnapshot);
        let address = sub as usize;
        let status = clients[0].runtime.block_on(async {
            tokio::spawn(async move {
                marmot_device_linking_subscription_close(
                    address as *const MarmotDeviceLinkingSubscription,
                )
            })
            .await
            .unwrap()
        });
        assert_eq!(status, MarmotStatus::Ok);
        let mut closed = std::ptr::dangling_mut();
        assert_eq!(
            marmot_device_linking_subscription_next(sub, 1000, &mut closed),
            MarmotStatus::DeviceLinkingClosed
        );
        assert!(closed.is_null());
        marmot_device_linking_subscription_free(sub);
        assert_eq!(marmot_device_linking_session_cancel(a), MarmotStatus::Ok);
        assert_eq!(marmot_device_linking_session_cancel(c), MarmotStatus::Ok);
        marmot_device_linking_session_free(a);
        marmot_device_linking_session_free(c);
    }
    for client in clients {
        client.block_on(client.marmot.shutdown_and_close()).unwrap();
    }
    relay.shutdown();
    #[cfg(feature = "alloc-audit")]
    assert_eq!(before, audit::live_allocations());
}
#[cfg(feature = "experimental-device-sync")]
unsafe fn snapshot(session: *const MarmotDeviceLinkingSession) -> *mut MarmotDeviceLinkingSnapshot {
    let mut out = std::ptr::null_mut();
    assert_eq!(
        unsafe { marmot_device_linking_session_snapshot(session, &mut out) },
        MarmotStatus::Ok
    );
    out
}
#[cfg(feature = "experimental-device-sync")]
unsafe fn drain(from: *const MarmotDeviceLinkingSession, to: *const MarmotDeviceLinkingSession) {
    unsafe {
        let mut out = std::ptr::null_mut();
        assert_eq!(
            marmot_device_linking_session_outgoing_packets(from, &mut out),
            MarmotStatus::Ok
        );
        let packets = if (*out).len == 0 {
            &[][..]
        } else {
            std::slice::from_raw_parts((*out).items, (*out).len)
        };
        for p in packets {
            assert_eq!(
                marmot_device_linking_session_receive_packet(to, p.bytes, p.bytes_len),
                MarmotStatus::Ok
            );
            let id = CStr::from_ptr(p.acknowledgement_id).to_bytes();
            assert_eq!(
                marmot_device_linking_session_acknowledge_packet(from, id.as_ptr(), id.len()),
                MarmotStatus::Ok
            );
        }
        marmot_device_linking_outgoing_packet_list_free(out);
    }
}

#[test]
fn enrollment_outputs_preflight_and_new_records_deep_free() {
    let _guard = audit::test_lock();
    #[cfg(feature = "alloc-audit")]
    let before = audit::live_allocations();
    unsafe {
        let mut targets = std::ptr::dangling_mut();
        assert_eq!(
            marmot_device_linking_targets(std::ptr::null(), std::ptr::null(), &mut targets),
            MarmotStatus::NullPointer
        );
        assert!(targets.is_null());
        let mut approvals = std::ptr::dangling_mut();
        assert_eq!(
            marmot_pending_device_linking_approvals(
                std::ptr::null(),
                std::ptr::null(),
                &mut approvals
            ),
            MarmotStatus::NullPointer
        );
        assert!(approvals.is_null());
        let mut cloned = std::ptr::dangling_mut();
        assert_eq!(
            marmot_device_linking_approval_clone(std::ptr::null(), &mut cloned),
            MarmotStatus::NullPointer
        );
        assert!(cloned.is_null());
        let mut observed = std::ptr::dangling_mut();
        assert_eq!(
            marmot_device_linking_approval_snapshot(std::ptr::null(), &mut observed),
            MarmotStatus::NullPointer
        );
        assert!(observed.is_null());
        let mut review = std::ptr::dangling_mut();
        assert_eq!(
            marmot_device_linking_approval_review_metadata(std::ptr::null(), u64::MAX, &mut review),
            MarmotStatus::NullPointer
        );
        assert!(review.is_null());
        assert_eq!(
            marmot_device_linking_approval_review_metadata(
                std::ptr::dangling(),
                0,
                std::ptr::null_mut()
            ),
            MarmotStatus::NullPointer
        );
        let review = MarmotDeviceLinkingApprovalReviewMetadata::from(
            marmot_uniffi::DeviceLinkingApprovalReviewMetadataFfi {
                revision: u64::MAX,
                source_device_public_key: vec![0, 255, 0],
                joining_device_public_key: vec![255, 0, 255],
                existing_device_count: 2,
            },
        );
        assert_eq!(
            std::slice::from_raw_parts(
                review.source_device_public_key,
                review.source_device_public_key_len
            ),
            &[0, 255, 0]
        );
        assert_eq!(
            std::slice::from_raw_parts(
                review.joining_device_public_key,
                review.joining_device_public_key_len
            ),
            &[255, 0, 255]
        );
        marmot_device_linking_approval_review_metadata_free(boxed(review));
        marmot_device_linking_approval_review_metadata_free(std::ptr::null_mut());
        let mut bytes = std::ptr::dangling_mut();
        assert_eq!(
            marmot_device_linking_session_enrollment_packet(std::ptr::null(), 0, &mut bytes),
            MarmotStatus::NullPointer
        );
        assert!(bytes.is_null());
        let values = vec![marmot_uniffi::DeviceLinkingTargetFfi {
            selector: vec![0, 255, 0],
            device_count: 3,
        }];
        let targets: MarmotDeviceLinkingTargetList = values.into();
        assert_eq!((*targets.items).device_count, 3);
        assert_eq!(
            std::slice::from_raw_parts((*targets.items).selector, (*targets.items).selector_len),
            &[0, 255, 0]
        );
        marmot_device_linking_target_list_free(boxed(targets));
        marmot_device_linking_approval_snapshot_free(boxed(
            MarmotDeviceLinkingApprovalSnapshot::from(
                marmot_uniffi::DeviceLinkingApprovalSnapshotFfi {
                    revision: u64::MAX,
                    phase: marmot_uniffi::DeviceLinkingApprovalPhaseFfi::Settled,
                },
            ),
        ));
        marmot_device_linking_approval_list_free(boxed(MarmotDeviceLinkingApprovalList {
            items: std::ptr::null_mut(),
            len: 0,
        }));
        marmot_device_linking_approval_list_free(std::ptr::null_mut());
        marmot_device_linking_approval_free(std::ptr::null_mut());
        assert_eq!(MarmotDeviceLinkingPhase::EnrollmentComplete as u32, 8);
        assert_eq!(MarmotDeviceLinkingPhase::Failed as u32, 7);
    }
    #[cfg(feature = "alloc-audit")]
    assert_eq!(before, audit::live_allocations());
}

#[cfg(feature = "experimental-device-sync")]
#[test]
fn actual_c_three_device_enrollment_retains_approval_after_list_free() {
    use nostr::prelude::ToBech32;
    use std::time::{Duration, Instant};
    let _guard = audit::test_lock();
    #[cfg(feature = "alloc-audit")]
    let before = audit::live_allocations();
    let relay_runtime = tokio::runtime::Runtime::new().unwrap();
    let relay = nostr_relay_builder::LocalRelay::new(nostr_relay_builder::RelayBuilder::default());
    relay_runtime.block_on(relay.run()).unwrap();
    let url = relay_runtime.block_on(relay.url()).to_string();
    let keys = nostr::prelude::Keys::generate();
    let dirs: [tempfile::TempDir; 3] = std::array::from_fn(|_| tempfile::tempdir().unwrap());
    let clients = dirs
        .iter()
        .map(|dir| client(dir.path(), url.clone()))
        .collect::<Vec<_>>();
    let accounts = clients
        .iter()
        .map(|client| {
            let account = client
                .block_on(client.marmot.login(
                    keys.secret_key().to_bech32().unwrap(),
                    vec![url.clone()],
                    Vec::new(),
                    Vec::new(),
                ))
                .unwrap();
            CString::new(account.account_id_hex).unwrap()
        })
        .collect::<Vec<_>>();
    let retained_revocation;
    unsafe {
        let (initial_a, b) = c_pair(&clients[0], &accounts[0], &clients[1], &accounts[1], None);
        c_verify(initial_a, b);
        c_continue(b);
        c_continue(initial_a);
        c_wait_complete(initial_a);
        c_wait_complete(b);
        assert_eq!(
            marmot_device_linking_session_cancel(initial_a),
            MarmotStatus::Ok
        );
        assert_eq!(marmot_device_linking_session_cancel(b), MarmotStatus::Ok);
        marmot_device_linking_session_free(initial_a);
        marmot_device_linking_session_free(b);
        let mut targets = std::ptr::null_mut();
        assert_eq!(
            marmot_device_linking_targets(&clients[0], accounts[0].as_ptr(), &mut targets),
            MarmotStatus::Ok
        );
        assert_eq!((*targets).len, 1);
        assert_eq!((*(*targets).items).device_count, 2);
        let target = &*(*targets).items;
        let (a, c) = c_pair(
            &clients[0],
            &accounts[0],
            &clients[2],
            &accounts[2],
            Some((target.selector, target.selector_len)),
        );
        marmot_device_linking_target_list_free(targets);
        c_verify(a, c);
        c_continue(c);
        c_continue(a);
        let deadline = Instant::now() + Duration::from_secs(20);
        let mut retained = std::ptr::null_mut();
        loop {
            let mut list = std::ptr::null_mut();
            assert_eq!(
                marmot_pending_device_linking_approvals(
                    &clients[1],
                    accounts[1].as_ptr(),
                    &mut list
                ),
                MarmotStatus::Ok
            );
            if (*list).len > 0 {
                assert_eq!((*list).len, 1);
                assert_eq!(
                    marmot_device_linking_approval_clone((*(*list).items).handle, &mut retained),
                    MarmotStatus::Ok
                );
            }
            marmot_device_linking_approval_list_free(list);
            if !retained.is_null() {
                break;
            }
            assert!(
                Instant::now() < deadline,
                "actual encrypted proposal must reach opaque C approval"
            );
            std::thread::sleep(Duration::from_millis(20));
        }
        // The original list is gone: this clone retains exactly the same action.
        let mut observed = std::ptr::null_mut();
        assert_eq!(
            marmot_device_linking_approval_snapshot(retained, &mut observed),
            MarmotStatus::Ok
        );
        assert_eq!(
            (*observed).phase,
            MarmotDeviceLinkingApprovalPhase::AwaitingApproval
        );
        assert_eq!(
            marmot_device_linking_approval_approve(retained, (*observed).revision + 1),
            MarmotStatus::DeviceLinkingStaleRevision
        );
        let mut stale_review = std::ptr::dangling_mut();
        assert_eq!(
            marmot_device_linking_approval_review_metadata(
                retained,
                (*observed).revision + 1,
                &mut stale_review
            ),
            MarmotStatus::DeviceLinkingStaleRevision
        );
        assert!(stale_review.is_null());
        let mut review = std::ptr::dangling_mut();
        assert_eq!(
            marmot_device_linking_approval_review_metadata(
                retained,
                (*observed).revision,
                &mut review
            ),
            MarmotStatus::Ok,
            "original C approval must expose authenticated review metadata"
        );
        assert_eq!((*review).revision, (*observed).revision);
        assert_eq!((*review).existing_device_count, 2);
        assert_eq!((*review).source_device_public_key_len, 32);
        assert_eq!((*review).joining_device_public_key_len, 32);
        assert_ne!(
            std::slice::from_raw_parts((*review).source_device_public_key, 32),
            std::slice::from_raw_parts((*review).joining_device_public_key, 32)
        );
        marmot_device_linking_approval_review_metadata_free(review);
        assert_eq!(
            marmot_device_linking_approval_approve(retained, (*observed).revision),
            MarmotStatus::Ok
        );
        marmot_device_linking_approval_snapshot_free(observed);
        let deadline = Instant::now() + Duration::from_secs(20);
        let packet = loop {
            let current = snapshot(a);
            let mut bytes = std::ptr::null_mut();
            let status =
                marmot_device_linking_session_enrollment_packet(a, (*current).revision, &mut bytes);
            marmot_device_linking_snapshot_free(current);
            match status {
                MarmotStatus::Ok => break bytes,
                MarmotStatus::DeviceLinkingNotReady => assert!(bytes.is_null()),
                _ => panic!("actual packet export failed: {status:?}"),
            }
            assert!(
                Instant::now() < deadline,
                "complete all-leaf approval packet must arrive"
            );
            std::thread::sleep(Duration::from_millis(20));
        };
        assert!((*packet).bytes_len <= 16 * 1024);
        let current = snapshot(c);
        assert_eq!(
            marmot_device_linking_session_receive_enrollment_packet(
                c,
                (*current).revision,
                std::ptr::dangling(),
                usize::MAX
            ),
            MarmotStatus::DeviceLinkingInvalidPacket
        );
        assert_eq!(
            marmot_device_linking_session_receive_enrollment_packet(
                c,
                (*current).revision,
                (*packet).bytes,
                (*packet).bytes_len
            ),
            MarmotStatus::Ok
        );
        marmot_device_linking_snapshot_free(current);
        let mut observed = std::ptr::null_mut();
        assert_eq!(
            marmot_device_linking_approval_snapshot(retained, &mut observed),
            MarmotStatus::Ok
        );
        assert_eq!(
            marmot_device_linking_approval_receive_enrollment_packet(
                retained,
                (*observed).revision,
                (*packet).bytes,
                (*packet).bytes_len
            ),
            MarmotStatus::Ok
        );
        marmot_device_linking_approval_snapshot_free(observed);
        marmot_device_linking_bytes_free(packet);
        let current = snapshot(a);
        assert_eq!(
            marmot_device_linking_session_finalize_linking(a, (*current).revision),
            MarmotStatus::Ok
        );
        marmot_device_linking_snapshot_free(current);
        c_wait_complete(a);
        c_wait_complete(c);
        let deadline = Instant::now() + Duration::from_secs(20);
        loop {
            let mut observed = std::ptr::null_mut();
            assert_eq!(
                marmot_device_linking_approval_snapshot(retained, &mut observed),
                MarmotStatus::Ok
            );
            let settled = (*observed).phase == MarmotDeviceLinkingApprovalPhase::Settled;
            marmot_device_linking_approval_snapshot_free(observed);
            if settled {
                break;
            }
            assert!(
                Instant::now() < deadline,
                "original B approval must observe protected completion"
            );
            std::thread::sleep(Duration::from_millis(20));
        }
        for (client, account) in clients.iter().zip(&accounts) {
            let mut targets = std::ptr::null_mut();
            assert_eq!(
                marmot_device_linking_targets(client, account.as_ptr(), &mut targets),
                MarmotStatus::Ok
            );
            assert_eq!((*targets).len, 1);
            assert_eq!((*(*targets).items).device_count, 3);
            marmot_device_linking_target_list_free(targets);
        }
        retained_revocation = c_selected_chat_after_actual_abc(&clients, &accounts, &url);
        assert_eq!(marmot_device_linking_session_cancel(a), MarmotStatus::Ok);
        assert_eq!(marmot_device_linking_session_cancel(c), MarmotStatus::Ok);
        assert_eq!(
            marmot_device_linking_approval_cancel(retained),
            MarmotStatus::Ok
        );
        marmot_device_linking_session_free(a);
        marmot_device_linking_session_free(c);
        marmot_device_linking_approval_free(retained);
    }
    for client in clients {
        client.block_on(client.marmot.shutdown_and_close()).unwrap();
    }
    unsafe {
        let mut observed = std::ptr::null_mut();
        assert!(matches!(
            crate::device_revocation::marmot_device_revocation_snapshot(
                retained_revocation,
                &mut observed
            ),
            MarmotStatus::DeviceRevocationClosed | MarmotStatus::DeviceRevocationRuntimeUnavailable
        ));
        assert!(observed.is_null());
        assert!(matches!(
            crate::device_revocation::marmot_device_revocation_approve(retained_revocation, 2),
            MarmotStatus::DeviceRevocationClosed | MarmotStatus::DeviceRevocationRuntimeUnavailable
        ));
        crate::device_revocation::marmot_device_revocation_free(retained_revocation);
    }
    relay.shutdown();
    #[cfg(feature = "alloc-audit")]
    assert_eq!(before, audit::live_allocations());
}

#[cfg(feature = "experimental-device-sync")]
unsafe fn c_pair(
    existing: &MarmotClient,
    existing_account: &CString,
    recipient: &MarmotClient,
    recipient_account: &CString,
    target: Option<(*const u8, usize)>,
) -> (
    *mut MarmotDeviceLinkingSession,
    *mut MarmotDeviceLinkingSession,
) {
    unsafe {
        let mut c = std::ptr::null_mut();
        assert_eq!(
            marmot_begin_device_linking_session(recipient, recipient_account.as_ptr(), &mut c),
            MarmotStatus::Ok
        );
        let mut request = std::ptr::null_mut();
        assert_eq!(
            marmot_device_linking_session_setup_packet(c, &mut request),
            MarmotStatus::Ok
        );
        let (target, len) = target.unwrap_or((std::ptr::null(), 0));
        let mut a = std::ptr::null_mut();
        assert_eq!(
            marmot_approve_device_linking_session(
                existing,
                existing_account.as_ptr(),
                (*request).bytes,
                (*request).bytes_len,
                target,
                len,
                &mut a
            ),
            MarmotStatus::Ok
        );
        marmot_device_linking_bytes_free(request);
        let mut challenge = std::ptr::null_mut();
        assert_eq!(
            marmot_device_linking_session_setup_packet(a, &mut challenge),
            MarmotStatus::Ok
        );
        assert_eq!(
            marmot_device_linking_session_receive_setup_packet(
                c,
                (*challenge).bytes,
                (*challenge).bytes_len
            ),
            MarmotStatus::Ok
        );
        marmot_device_linking_bytes_free(challenge);
        (a, c)
    }
}
#[cfg(feature = "experimental-device-sync")]
unsafe fn c_verify(a: *const MarmotDeviceLinkingSession, c: *const MarmotDeviceLinkingSession) {
    unsafe {
        for _ in 0..8 {
            drain(a, c);
            drain(c, a);
        }
        let ac = snapshot(a);
        let cc = snapshot(c);
        assert_eq!((*ac).phase, MarmotDeviceLinkingPhase::ComparisonAvailable);
        assert!(!(*ac).decimals.is_null() && !(*cc).decimals.is_null());
        assert_eq!((*(*ac).decimals).first, (*(*cc).decimals).first);
        assert_eq!((*(*ac).decimals).second, (*(*cc).decimals).second);
        assert_eq!((*(*ac).decimals).third, (*(*cc).decimals).third);
        assert_eq!(
            marmot_device_linking_session_confirm_comparison(a, (*ac).revision),
            MarmotStatus::Ok
        );
        assert_eq!(
            marmot_device_linking_session_confirm_comparison(c, (*cc).revision),
            MarmotStatus::Ok
        );
        marmot_device_linking_snapshot_free(ac);
        marmot_device_linking_snapshot_free(cc);
        for _ in 0..8 {
            drain(a, c);
            drain(c, a);
        }
    }
}
#[cfg(feature = "experimental-device-sync")]
unsafe fn c_continue(handle: *const MarmotDeviceLinkingSession) {
    unsafe {
        let current = snapshot(handle);
        assert_eq!(
            marmot_device_linking_session_continue_linking(handle, (*current).revision),
            MarmotStatus::Ok
        );
        marmot_device_linking_snapshot_free(current);
    }
}
#[cfg(feature = "experimental-device-sync")]
unsafe fn c_wait_complete(handle: *const MarmotDeviceLinkingSession) {
    use std::time::{Duration, Instant};
    let deadline = Instant::now() + Duration::from_secs(20);
    unsafe {
        loop {
            let current = snapshot(handle);
            let phase = (*current).phase;
            if phase == MarmotDeviceLinkingPhase::EnrollmentComplete {
                assert!((*current).decimals.is_null());
            }
            marmot_device_linking_snapshot_free(current);
            if phase == MarmotDeviceLinkingPhase::EnrollmentComplete {
                break;
            }
            assert!(!matches!(
                phase,
                MarmotDeviceLinkingPhase::Failed
                    | MarmotDeviceLinkingPhase::Cancelled
                    | MarmotDeviceLinkingPhase::Expired
            ));
            assert!(
                Instant::now() < deadline,
                "opaque C session must observe actual protected completion"
            );
            std::thread::sleep(Duration::from_millis(20));
        }
    }
}

#[cfg(feature = "experimental-device-sync")]
unsafe fn c_selected_chat_after_actual_abc(
    clients: &[MarmotClient],
    accounts: &[CString],
    url: &str,
) -> *mut crate::device_revocation::MarmotDeviceRevocation {
    use crate::selected_chat_copy::*;
    use nostr::prelude::ToBech32;
    use std::time::{Duration, Instant};
    let dir = tempfile::tempdir().unwrap();
    let keys = nostr::prelude::Keys::generate();
    let d = client(dir.path(), url.into());
    let account = d
        .block_on(d.marmot.login(
            keys.secret_key().to_bech32().unwrap(),
            vec![url.into()],
            Vec::new(),
            Vec::new(),
        ))
        .unwrap();
    d.block_on(
        d.marmot
            .publish_new_key_package(account.account_id_hex.clone()),
    )
    .unwrap();
    let chat = clients[0]
        .block_on(clients[0].marmot.create_group(
            accounts[0].to_str().unwrap().into(),
            "C selected chat".into(),
            vec![account.account_id_hex.clone()],
            None,
        ))
        .unwrap();
    let deadline = Instant::now() + Duration::from_secs(20);
    loop {
        if d.block_on(
            d.marmot
                .group_mls_state(account.account_id_hex.clone(), chat.clone()),
        )
        .is_ok()
        {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "D must genuinely join C fixture ordinary chat"
        );
        std::thread::sleep(Duration::from_millis(20));
    }
    let chat = CString::new(chat).unwrap();
    let retained_revocation;
    unsafe {
        let mut targets = std::ptr::null_mut();
        assert_eq!(
            marmot_device_linking_targets(&clients[0], accounts[0].as_ptr(), &mut targets),
            MarmotStatus::Ok
        );
        assert_eq!((*(*targets).items).device_count, 3);
        let target = &*(*targets).items;
        let mut request = std::ptr::dangling_mut();
        let status = marmot_begin_selected_chat_copy(
            &clients[0],
            accounts[0].as_ptr(),
            chat.as_ptr(),
            target.selector,
            target.selector_len,
            &mut request,
        );
        marmot_device_linking_target_list_free(targets);
        assert_eq!(
            status,
            MarmotStatus::Ok,
            "C must retain original selected-chat request"
        );
        use crate::types::selected_chat_copy::*;
        let mut retained = std::ptr::null_mut();
        assert_eq!(
            marmot_selected_chat_copy_clone(request, &mut retained),
            MarmotStatus::Ok
        );
        marmot_selected_chat_copy_free(request);
        request = retained;
        let reentrant = request as usize;
        let status = clients[0].block_on(async move {
            tokio::spawn(async move {
                let mut observed = std::ptr::null_mut();
                let status = marmot_selected_chat_copy_snapshot(
                    reentrant as *const MarmotSelectedChatCopy,
                    &mut observed,
                );
                if !observed.is_null() {
                    marmot_selected_chat_copy_snapshot_free(observed);
                }
                status
            })
            .await
            .unwrap()
        });
        assert_eq!(
            status,
            MarmotStatus::Ok,
            "selected snapshot must block safely from a runtime worker"
        );
        let mut observed = std::ptr::null_mut();
        assert_eq!(
            marmot_selected_chat_copy_snapshot(request, &mut observed),
            MarmotStatus::Ok
        );
        assert_eq!((*observed).sibling_count, 2);
        assert_eq!(
            marmot_selected_chat_copy_request_packet(
                request,
                (*observed).revision + 1,
                std::ptr::null_mut()
            ),
            MarmotStatus::NullPointer
        );
        let mut bytes = std::ptr::dangling_mut();
        assert_eq!(
            marmot_selected_chat_copy_request_packet(request, (*observed).revision + 1, &mut bytes),
            MarmotStatus::SelectedChatCopyStaleRevision
        );
        assert!(bytes.is_null());
        assert_eq!(
            marmot_selected_chat_copy_request_packet(request, (*observed).revision, &mut bytes),
            MarmotStatus::Ok
        );
        assert_eq!(
            marmot_selected_chat_copy_receive_consent_packet(
                request,
                (*observed).revision,
                std::ptr::dangling(),
                usize::MAX
            ),
            MarmotStatus::SelectedChatCopyInvalidPacket
        );
        marmot_selected_chat_copy_snapshot_free(observed);
        let packet = std::slice::from_raw_parts((*bytes).bytes, (*bytes).bytes_len).to_vec();
        marmot_selected_chat_bytes_free(bytes);
        let mut consents = Vec::new();
        for (client, account) in clients[1..].iter().zip(&accounts[1..]) {
            let mut consent = std::ptr::null_mut();
            assert_eq!(
                marmot_receive_selected_chat_copy_request(
                    client,
                    account.as_ptr(),
                    packet.as_ptr(),
                    packet.len(),
                    &mut consent
                ),
                MarmotStatus::Ok
            );
            let mut retained = std::ptr::null_mut();
            assert_eq!(
                marmot_selected_chat_consent_clone(consent, &mut retained),
                MarmotStatus::Ok
            );
            marmot_selected_chat_consent_free(consent);
            consent = retained;
            let mut observed = std::ptr::null_mut();
            assert_eq!(
                marmot_selected_chat_consent_snapshot(consent, &mut observed),
                MarmotStatus::Ok
            );
            assert_eq!(
                (*observed).phase,
                MarmotSelectedChatConsentPhase::AwaitingApproval
            );
            assert_eq!(
                marmot_selected_chat_consent_approve(consent, (*observed).revision + 1),
                MarmotStatus::SelectedChatCopyStaleRevision
            );
            assert_eq!(
                marmot_selected_chat_consent_approve(consent, (*observed).revision),
                MarmotStatus::Ok
            );
            marmot_selected_chat_consent_snapshot_free(observed);
            assert_eq!(
                marmot_selected_chat_consent_snapshot(consent, &mut observed),
                MarmotStatus::Ok
            );
            let mut response = std::ptr::null_mut();
            assert_eq!(
                marmot_selected_chat_consent_response_packet(
                    consent,
                    (*observed).revision,
                    &mut response
                ),
                MarmotStatus::Ok
            );
            let consent_revision = (*observed).revision;
            marmot_selected_chat_consent_snapshot_free(observed);
            let mut source = std::ptr::null_mut();
            assert_eq!(
                marmot_selected_chat_copy_snapshot(request, &mut source),
                MarmotStatus::Ok
            );
            assert_eq!(
                marmot_selected_chat_copy_receive_consent_packet(
                    request,
                    (*source).revision,
                    (*response).bytes,
                    (*response).bytes_len
                ),
                MarmotStatus::Ok
            );
            marmot_selected_chat_copy_snapshot_free(source);
            marmot_selected_chat_bytes_free(response);
            let mut offer = std::ptr::null_mut();
            assert_eq!(
                marmot_selected_chat_consent_offer_packet(consent, consent_revision, &mut offer),
                MarmotStatus::Ok
            );
            assert!((*offer).bytes_len <= 16384);
            let mut retry = std::ptr::null_mut();
            assert_eq!(
                marmot_selected_chat_consent_offer_packet(consent, consent_revision, &mut retry),
                MarmotStatus::Ok
            );
            assert_eq!(
                std::slice::from_raw_parts((*offer).bytes, (*offer).bytes_len),
                std::slice::from_raw_parts((*retry).bytes, (*retry).bytes_len)
            );
            marmot_selected_chat_bytes_free(retry);
            assert_eq!(
                marmot_selected_chat_copy_snapshot(request, &mut source),
                MarmotStatus::Ok
            );
            assert_eq!(
                marmot_selected_chat_copy_receive_offer_packet(
                    request,
                    (*source).revision,
                    (*offer).bytes,
                    (*offer).bytes_len
                ),
                MarmotStatus::Ok
            );
            marmot_selected_chat_copy_snapshot_free(source);
            assert_eq!(
                marmot_selected_chat_copy_snapshot(request, &mut source),
                MarmotStatus::Ok
            );
            let revision = (*source).revision;
            assert_eq!(
                marmot_selected_chat_copy_receive_offer_packet(
                    request,
                    revision,
                    (*offer).bytes,
                    (*offer).bytes_len
                ),
                MarmotStatus::Ok
            );
            marmot_selected_chat_copy_snapshot_free(source);
            marmot_selected_chat_bytes_free(offer);
            consents.push(consent);
        }
        let mut observed = std::ptr::null_mut();
        assert_eq!(
            marmot_selected_chat_copy_snapshot(request, &mut observed),
            MarmotStatus::Ok
        );
        assert_eq!((*observed).consenting_sibling_count, 2);
        assert_eq!((*observed).offered_sibling_count, 2);
        assert_eq!(
            marmot_selected_chat_copy_continue(request, (*observed).revision + 1),
            MarmotStatus::SelectedChatCopyStaleRevision
        );
        assert_eq!(
            marmot_selected_chat_copy_continue(request, (*observed).revision),
            MarmotStatus::Ok
        );
        marmot_selected_chat_copy_snapshot_free(observed);
        assert_eq!(
            marmot_selected_chat_copy_snapshot(request, &mut observed),
            MarmotStatus::Ok
        );
        assert_eq!(
            (*observed).phase,
            MarmotSelectedChatCopyPhase::InviteConfirmed
        );
        marmot_selected_chat_copy_snapshot_free(observed);
        let deadline = Instant::now() + Duration::from_secs(20);
        loop {
            let all = clients.iter().zip(accounts).all(|(client, account)| {
                client
                    .block_on(client.marmot.group_mls_state(
                        account.to_str().unwrap().into(),
                        chat.to_str().unwrap().into(),
                    ))
                    .is_ok_and(|state| state.member_count == 4)
            });
            let peer = d
                .block_on(d.marmot.group_mls_state(
                    account.account_id_hex.clone(),
                    chat.to_str().unwrap().into(),
                ))
                .is_ok_and(|state| state.member_count == 4);
            if all && peer {
                break;
            }
            assert!(
                Instant::now() < deadline,
                "C wrappers must genuinely admit both original siblings"
            );
            std::thread::sleep(Duration::from_millis(20));
        }
        assert_eq!(marmot_selected_chat_copy_cancel(request), MarmotStatus::Ok);
        assert_eq!(
            marmot_selected_chat_copy_snapshot(request, &mut observed),
            MarmotStatus::Ok
        );
        assert_eq!(
            marmot_selected_chat_copy_continue(request, (*observed).revision),
            MarmotStatus::SelectedChatCopyClosed
        );
        marmot_selected_chat_copy_snapshot_free(observed);
        for consent in consents {
            assert_eq!(
                marmot_selected_chat_consent_cancel(consent),
                MarmotStatus::Ok
            );
            marmot_selected_chat_consent_free(consent);
        }
        marmot_selected_chat_copy_free(request);
        retained_revocation = c_revoke_actual_selected_device(clients, accounts, &chat);
    }
    d.block_on(d.marmot.shutdown_and_close()).unwrap();
    retained_revocation
}

#[test]
fn selected_chat_c_outputs_precede_input_access_and_bounds_precede_copy() {
    use crate::selected_chat_copy::*;
    let dir = tempfile::tempdir().unwrap();
    let client = client(dir.path(), "wss://relay.example".into());
    let account = CString::new("missing").unwrap();
    let group = CString::new("00").unwrap();
    unsafe {
        assert_eq!(
            marmot_begin_selected_chat_copy(
                std::ptr::null(),
                std::ptr::null(),
                std::ptr::null(),
                std::ptr::dangling(),
                usize::MAX,
                std::ptr::null_mut()
            ),
            MarmotStatus::NullPointer
        );
        let mut request = std::ptr::dangling_mut();
        assert_eq!(
            marmot_begin_selected_chat_copy(
                &client,
                account.as_ptr(),
                group.as_ptr(),
                std::ptr::dangling(),
                usize::MAX,
                &mut request
            ),
            MarmotStatus::SelectedChatCopyInvalidPacket
        );
        assert!(request.is_null());
        let mut consent = std::ptr::dangling_mut();
        assert_eq!(
            marmot_receive_selected_chat_copy_request(
                &client,
                account.as_ptr(),
                std::ptr::dangling(),
                usize::MAX,
                &mut consent
            ),
            MarmotStatus::SelectedChatCopyInvalidPacket
        );
        assert!(consent.is_null());
        assert_eq!(
            marmot_selected_chat_copy_snapshot(std::ptr::null(), std::ptr::null_mut()),
            MarmotStatus::NullPointer
        );
        let mut alias = std::ptr::dangling_mut();
        assert_eq!(
            marmot_selected_chat_consent_clone(std::ptr::null(), &mut alias),
            MarmotStatus::NullPointer
        );
        assert!(alias.is_null());
    }
    client.block_on(client.marmot.shutdown_and_close()).unwrap();
}
#[cfg(not(feature = "experimental-device-sync"))]
#[test]
fn default_selected_chat_c_is_typed_unsupported_and_clears_outputs() {
    use crate::selected_chat_copy::*;
    let dir = tempfile::tempdir().unwrap();
    let client = client(dir.path(), "wss://relay.example".into());
    let account = CString::new("missing").unwrap();
    let group = CString::new("invalid").unwrap();
    unsafe {
        let mut request = std::ptr::dangling_mut();
        assert_eq!(
            marmot_begin_selected_chat_copy(
                &client,
                account.as_ptr(),
                group.as_ptr(),
                std::ptr::null(),
                0,
                &mut request
            ),
            MarmotStatus::SelectedChatCopyUnsupported
        );
        assert!(request.is_null());
        let mut consent = std::ptr::dangling_mut();
        assert_eq!(
            marmot_receive_selected_chat_copy_request(
                &client,
                account.as_ptr(),
                std::ptr::null(),
                0,
                &mut consent
            ),
            MarmotStatus::SelectedChatCopyUnsupported
        );
        assert!(consent.is_null());
    }
    client.block_on(client.marmot.shutdown_and_close()).unwrap();
}
#[test]
fn selected_chat_c_deep_frees_preserve_exact_binary_and_phase_layouts() {
    use crate::types::selected_chat_copy::*;
    let _guard = audit::test_lock();
    #[cfg(feature = "alloc-audit")]
    let before = audit::live_allocations();
    let snapshot =
        MarmotSelectedChatConsentSnapshot::from(marmot_uniffi::SelectedChatConsentSnapshotFfi {
            revision: u64::MAX,
            phase: marmot_uniffi::SelectedChatConsentPhaseFfi::Approved,
            chat_selector: vec![0, 255, 0],
        });
    unsafe {
        assert_eq!(
            std::slice::from_raw_parts(snapshot.chat_selector, snapshot.chat_selector_len),
            &[0, 255, 0]
        );
        marmot_selected_chat_consent_snapshot_free(boxed(snapshot));
        marmot_selected_chat_copy_snapshot_free(boxed(MarmotSelectedChatCopySnapshot::from(
            marmot_uniffi::SelectedChatCopySnapshotFfi {
                revision: 7,
                phase: marmot_uniffi::SelectedChatCopyPhaseFfi::InviteConfirmed,
                sibling_count: 2,
                consenting_sibling_count: 2,
                offered_sibling_count: 2,
            },
        )));
        marmot_selected_chat_bytes_free(boxed(MarmotSelectedChatBytes::from(vec![0, 255, 0])));
        marmot_selected_chat_bytes_free(std::ptr::null_mut());
    }
    assert_eq!(MarmotSelectedChatCopyPhase::InviteConfirmed as u32, 4);
    #[cfg(feature = "alloc-audit")]
    assert_eq!(before, audit::live_allocations());
}

#[cfg(feature = "experimental-device-sync")]
unsafe fn c_revoke_actual_selected_device(
    clients: &[MarmotClient],
    accounts: &[CString],
    chat: &CString,
) -> *mut crate::device_revocation::MarmotDeviceRevocation {
    use crate::device_revocation::*;
    use crate::types::device_revocation::marmot_device_revocation_snapshot_free;
    use std::ptr;
    use std::time::{Duration, Instant};
    let choices = clients[0]
        .block_on(clients[0].marmot.history_transfer_recipients(
            accounts[0].to_str().unwrap().into(),
            chat.to_str().unwrap().into(),
        ))
        .unwrap();
    let own_excluded = clients[2]
        .block_on(clients[2].marmot.history_transfer_recipients(
            accounts[2].to_str().unwrap().into(),
            chat.to_str().unwrap().into(),
        ))
        .unwrap();
    let target = &choices
        .iter()
        .find(|item| !own_excluded.iter().any(|other| item.device == other.device))
        .unwrap()
        .device;
    let mut original = ptr::null_mut();
    unsafe {
        assert_eq!(
            marmot_begin_device_revocation(
                &clients[0],
                accounts[0].as_ptr(),
                target.as_ptr(),
                target.len(),
                &mut original
            ),
            MarmotStatus::Ok
        );
        let mut alias = ptr::null_mut();
        assert_eq!(
            marmot_device_revocation_clone(original, &mut alias),
            MarmotStatus::Ok
        );
        marmot_device_revocation_free(original);
        let mut observed = ptr::null_mut();
        assert_eq!(
            marmot_device_revocation_snapshot(alias, &mut observed),
            MarmotStatus::Ok
        );
        assert_eq!((*observed).ordinary_group_ids_hex_len, 1);
        assert_eq!((*observed).completed_group_ids_hex_len, 0);
        assert_eq!(
            std::slice::from_raw_parts((*observed).target_device, (*observed).target_device_len),
            target.as_slice()
        );
        let revision = (*observed).revision;
        assert_eq!(
            marmot_device_revocation_approve(alias, revision + 1),
            MarmotStatus::DeviceRevocationStaleRevision
        );
        marmot_device_revocation_snapshot_free(observed);
        assert_eq!(marmot_device_revocation_cancel(alias), MarmotStatus::Ok);
        assert_eq!(
            marmot_device_revocation_approve(alias, revision),
            MarmotStatus::DeviceRevocationClosed
        );
        marmot_device_revocation_free(alias);
        assert_eq!(
            marmot_begin_device_revocation(
                &clients[0],
                accounts[0].as_ptr(),
                target.as_ptr(),
                target.len(),
                &mut original
            ),
            MarmotStatus::Ok
        );
        assert_eq!(
            marmot_device_revocation_snapshot(original, &mut observed),
            MarmotStatus::Ok
        );
        let revision = (*observed).revision;
        marmot_device_revocation_snapshot_free(observed);
        assert_eq!(
            marmot_device_revocation_approve(original, revision),
            MarmotStatus::Ok
        );
        assert_eq!(
            marmot_device_revocation_snapshot(original, &mut observed),
            MarmotStatus::Ok
        );
        assert!((*observed).complete);
        assert_eq!((*observed).completed_group_ids_hex_len, 2);
        marmot_device_revocation_snapshot_free(observed);
    }
    let deadline = Instant::now() + Duration::from_secs(30);
    loop {
        let survivors = [0, 1].into_iter().all(|i| {
            clients[i]
                .block_on(clients[i].marmot.group_mls_state(
                    accounts[i].to_str().unwrap().into(),
                    chat.to_str().unwrap().into(),
                ))
                .is_ok_and(|state| state.member_count == 3)
        });
        let removed = clients[2]
            .block_on(clients[2].marmot.group_roster(
                accounts[2].to_str().unwrap().into(),
                chat.to_str().unwrap().into(),
            ))
            .is_ok_and(|state| {
                matches!(
                    state.self_membership,
                    marmot_uniffi::conversions::SelfMembershipFfi::Removed
                )
            });
        if survivors && removed {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "C original exact-device Remove must reach authenticated runtimes"
        );
        std::thread::sleep(Duration::from_millis(20));
    }
    assert!(
        clients[2]
            .block_on(clients[2].marmot.send_text(
                accounts[2].to_str().unwrap().into(),
                chat.to_str().unwrap().into(),
                "removed must refuse".into()
            ))
            .is_err()
    );
    let sent = clients[1]
        .block_on(clients[1].marmot.send_text(
            accounts[1].to_str().unwrap().into(),
            chat.to_str().unwrap().into(),
            "survivor future epoch".into(),
        ))
        .unwrap();
    let id = &sent.message_ids[0];
    let deadline = Instant::now() + Duration::from_secs(20);
    loop {
        if [0, 1].into_iter().all(|i| {
            clients[i]
                .marmot
                .messages(
                    accounts[i].to_str().unwrap().into(),
                    Some(chat.to_str().unwrap().into()),
                    None,
                    None,
                )
                .unwrap()
                .iter()
                .any(|message| &message.message_id_hex == id)
        }) {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "survivor message must reach intended runtimes"
        );
        std::thread::sleep(Duration::from_millis(20));
    }
    assert!(
        clients[2]
            .marmot
            .messages(
                accounts[2].to_str().unwrap().into(),
                Some(chat.to_str().unwrap().into()),
                None,
                None
            )
            .unwrap()
            .iter()
            .all(|message| &message.message_id_hex != id)
    );
    original
}
