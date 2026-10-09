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
