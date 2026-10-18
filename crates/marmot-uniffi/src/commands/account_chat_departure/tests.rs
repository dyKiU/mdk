use std::{
    mem::ManuallyDrop,
    sync::{Arc, mpsc},
    time::{Duration, Instant},
};

use cgka_traits::TransportEndpoint;
use marmot_app::{AccountSetupRequest, MarmotApp};
use nostr_relay_builder::MockRelay;
use uniffi::{Lift, Lower, RustBuffer, RustCallStatus, RustCallStatusCode, RustFuturePoll};

use super::*;
use crate::{UniFfiTag, conversions::AccountChatDepartureReasonFfi};

struct ForeignFuture(uniffi::Handle);

impl Drop for ForeignFuture {
    fn drop(&mut self) {
        // SAFETY: this guard exclusively owns the generated RustBuffer-returning
        // future handle and frees it exactly once after polling/completion.
        unsafe { uniffi::rust_future_free::<RustBuffer, UniFfiTag>(self.0) };
    }
}

extern "C" fn continuation(data: u64, status: RustFuturePoll) {
    // SAFETY: every poll transfers one boxed sender, and UniFFI promises exactly
    // one callback for that poll, including cancellation of a pending poll.
    let sender = unsafe { Box::from_raw(data as *mut mpsc::Sender<RustFuturePoll>) };
    let _ = sender.send(status);
}

fn invoke_export_without_tokio(kit: Arc<Marmot>, account: String, group: String, leave: bool) {
    assert!(
        tokio::runtime::Handle::try_current().is_err(),
        "the foreign caller must not supply a Tokio runtime"
    );
    let object = <Arc<Marmot> as Lower<UniFfiTag>>::lower(kit);
    let account = <String as Lower<UniFfiTag>>::lower(account);
    let group = <String as Lower<UniFfiTag>>::lower(group);
    // These are the actual #[uniffi::export]-generated entry points. Calling the
    // Rust async methods directly would bypass the runtime adapter under test.
    let handle = if leave {
        super::uniffi_marmot_uniffi_fn_method_marmot_leave_account_chat(object, account, group)
    } else {
        super::uniffi_marmot_uniffi_fn_method_marmot_account_chat_departure_state(
            object, account, group,
        )
    };
    let future = ForeignFuture(handle);
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        let (sender, receiver) = mpsc::channel();
        let callback_data = Box::into_raw(Box::new(sender)) as u64;
        // SAFETY: the live generated handle returns RustBuffer. The boxed
        // callback sender remains owned by UniFFI until its one continuation.
        unsafe {
            uniffi::rust_future_poll::<RustBuffer, UniFfiTag>(
                future.0,
                continuation,
                callback_data,
            );
        }
        match receiver.recv_timeout(deadline.saturating_duration_since(Instant::now())) {
            Ok(RustFuturePoll::Ready) => break,
            Ok(RustFuturePoll::MaybeReady) => {}
            Err(_) => {
                // SAFETY: cancellation releases a pending continuation before
                // the owning guard frees the same live handle during unwind.
                unsafe { uniffi::rust_future_cancel::<RustBuffer, UniFfiTag>(future.0) };
                panic!("exported departure future did not complete within its bound");
            }
        }
    }
    let mut status = RustCallStatus::default();
    // SAFETY: polling reported Ready, this is the first completion, and the
    // return type matches the generated record-returning entry point.
    let buffer =
        unsafe { uniffi::rust_future_complete::<RustBuffer, UniFfiTag>(future.0, &mut status) };
    let code = status.code;
    // Error details may contain a Rust panic payload. Release without printing.
    ManuallyDrop::into_inner(status.error_buf).destroy();
    if code != RustCallStatusCode::Success {
        buffer.destroy();
        assert_eq!(
            code,
            RustCallStatusCode::Success,
            "foreign departure call failed"
        );
        return;
    }
    let value = <AccountChatDepartureStateFfi as Lift<UniFfiTag>>::try_lift(buffer)
        .expect("lift successful departure record");
    assert!(matches!(
        value.status,
        crate::conversions::AccountChatDepartureStatusFfi::Unavailable
    ));
    assert!(matches!(
        value.reason,
        AccountChatDepartureReasonFfi::SharingUnavailable
    ));
    assert!(value.operation_id.is_none());
}

fn departure_fixture(leave: bool) {
    let executor = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .unwrap();
    let directory = tempfile::tempdir().unwrap();
    let (kit, relay, account, group) = executor.block_on(async {
        let relay = MockRelay::run().await.unwrap();
        let url = relay.url().await.to_string();
        let app = MarmotApp::with_relays(directory.path(), vec![url.clone()]);
        let kit = Arc::new(Marmot {
            runtime: app.runtime(),
            app,
        });
        let endpoint = TransportEndpoint(url);
        let account = kit
            .runtime
            .create_identity(AccountSetupRequest {
                default_relays: vec![endpoint.clone()],
                bootstrap_relays: vec![endpoint],
                publish_missing_relay_lists: true,
                publish_initial_key_package: true,
                ..Default::default()
            })
            .await
            .unwrap()
            .account
            .account_id_hex;
        let group = kit
            .create_group(
                account.clone(),
                "Foreign future fixture".into(),
                vec![],
                None,
            )
            .await
            .unwrap();
        (kit, relay, account, group)
    });
    let caller = Arc::clone(&kit);
    let result = std::thread::spawn(move || {
        invoke_export_without_tokio(caller, account, group, leave);
    })
    .join();
    // Keep the setup executor and real worker alive during foreign polling,
    // then positively shut down before propagating any regression assertion.
    executor.block_on(kit.runtime.shutdown());
    drop(kit);
    drop(relay);
    if let Err(panic) = result {
        std::panic::resume_unwind(panic);
    }
}

#[test]
fn exported_departure_state_future_needs_no_caller_tokio() {
    departure_fixture(false);
}

#[test]
fn exported_leave_account_chat_future_needs_no_caller_tokio() {
    departure_fixture(true);
}
