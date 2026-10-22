//! Real C ABI -> UniFFI -> App acceptance on a genuine two-source fixture.
//! Explicit same-source producer invocation only; never a shipping test factory.
use crate::account_chat_presentation::marmot_paired_chat_list_page;
use crate::commands::*;
use crate::secret_store::{MarmotSecretStore, MarmotSecretStoreStatus};
use crate::types::account_chat_departure::{
    MarmotAccountChatDepartureState, MarmotAccountChatDepartureStatus,
    marmot_account_chat_departure_state_free,
};
use crate::types::account_chat_presentation::{
    MarmotPairedChatListPage, marmot_paired_chat_list_page_free,
};
use crate::types::local_submissions::{
    MarmotLocalSendAcceptance, MarmotLocalSendStatus, marmot_local_send_acceptance_free,
    marmot_local_send_status_free,
};
use crate::{MarmotClient, MarmotClientOptions, MarmotStatus, marmot_client_start};
use serde::{Deserialize, Serialize};
use std::ffi::{CStr, CString, c_char, c_void};
use std::io::{Read, Write};
use std::os::unix::fs::OpenOptionsExt;
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};
use zeroize::{Zeroize, Zeroizing};

const FRAME_LIMIT: usize = 32_768;
const SOURCE: Option<&str> = option_env!("MARMOT_ACCEPTANCE_SOURCE_COMMIT");

// Deliberately no Debug: a failed assertion must not print a credential/frame.
#[derive(Deserialize)]
struct Fixture {
    source: String,
    nonce: String,
    roots: [String; 3],
    relay: String,
    label: String,
    account: String,
    secret: String,
    group: String,
}
#[derive(Serialize)]
struct Request<'a> {
    command: &'a str,
    nonce: &'a str,
    messages: &'a [String],
}
#[derive(Deserialize)]
struct Observation {
    a_active: bool,
    b_active: bool,
    leaves: usize,
    delivered: bool,
    closed: bool,
}

fn hex(value: &str, bytes: usize) -> bool {
    value.len() == bytes * 2
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}
fn read_frame<T: serde::de::DeserializeOwned>(stream: &mut UnixStream) -> T {
    let mut size = [0; 4];
    let read = stream.read_exact(&mut size);
    if let Err(error) = &read {
        eprintln!("ffi_fixture_response_read_error_kind={:?}", error.kind());
    }
    assert!(read.is_ok(), "private fixture response read");
    let size = u32::from_be_bytes(size) as usize;
    assert!(
        size > 0 && size <= FRAME_LIMIT,
        "private fixture frame bound"
    );
    let mut bytes = vec![0; size];
    assert!(
        stream.read_exact(&mut bytes).is_ok(),
        "private fixture response read"
    );
    let parsed = serde_json::from_slice(&bytes);
    bytes.zeroize();
    assert!(parsed.is_ok(), "private fixture response shape");
    parsed.ok().unwrap()
}
fn ask(stream: &mut UnixStream, nonce: &str, command: &str, ids: &[String]) -> Observation {
    let encoded = serde_json::to_vec(&Request {
        command,
        nonce,
        messages: ids,
    });
    assert!(encoded.is_ok(), "private fixture request shape");
    let mut encoded = encoded.ok().unwrap();
    assert!(encoded.len() <= FRAME_LIMIT, "private fixture frame bound");
    assert!(
        stream
            .write_all(&(encoded.len() as u32).to_be_bytes())
            .is_ok(),
        "private fixture request write"
    );
    let written = stream.write_all(&encoded);
    encoded.zeroize();
    assert!(written.is_ok(), "private fixture request write");
    read_frame(stream)
}

#[derive(Default)]
struct CallbackAudit {
    loads: AtomicUsize,
    frees: AtomicUsize,
    destroys: AtomicUsize,
}
struct Credential {
    label: String,
    account: String,
    secret: Zeroizing<String>,
    audit: Arc<CallbackAudit>,
}
unsafe fn credential<'a>(data: *mut c_void) -> Option<&'a Credential> {
    unsafe { data.cast::<Credential>().as_ref() }
}
unsafe fn matches(value: *const c_char, expected: &str) -> bool {
    !value.is_null() && unsafe { CStr::from_ptr(value) }.to_bytes() == expected.as_bytes()
}
unsafe extern "C" fn has(data: *mut c_void, key: *const c_char, out: *mut u8) -> u32 {
    let Some(store) = (unsafe { credential(data) }) else {
        return MarmotSecretStoreStatus::Failed as u32;
    };
    if out.is_null() {
        return MarmotSecretStoreStatus::Failed as u32;
    }
    unsafe {
        *out = u8::from(matches(key, &store.label) || matches(key, &store.account));
    }
    MarmotSecretStoreStatus::Ok as u32
}
unsafe extern "C" fn write_secret(
    data: *mut c_void,
    label: *const c_char,
    account: *const c_char,
    secret: *const c_char,
) -> u32 {
    let Some(store) = (unsafe { credential(data) }) else {
        return MarmotSecretStoreStatus::Failed as u32;
    };
    if unsafe {
        matches(label, &store.label)
            && matches(account, &store.account)
            && matches(secret, &store.secret)
    } {
        MarmotSecretStoreStatus::Ok as u32
    } else {
        MarmotSecretStoreStatus::Failed as u32
    }
}
unsafe extern "C" fn load(
    data: *mut c_void,
    label: *const c_char,
    account: *const c_char,
    out: *mut *mut c_char,
) -> u32 {
    let Some(store) = (unsafe { credential(data) }) else {
        return MarmotSecretStoreStatus::Failed as u32;
    };
    if out.is_null() || !unsafe { matches(label, &store.label) && matches(account, &store.account) }
    {
        return MarmotSecretStoreStatus::NotFound as u32;
    }
    unsafe {
        *out = std::ptr::null_mut();
    }
    let Ok(value) = CString::new(store.secret.as_bytes()) else {
        return MarmotSecretStoreStatus::Failed as u32;
    };
    store.audit.loads.fetch_add(1, Ordering::SeqCst);
    unsafe {
        *out = value.into_raw();
    }
    MarmotSecretStoreStatus::Ok as u32
}
unsafe extern "C" fn remove(_: *mut c_void, _: *const c_char, _: *const c_char) -> u32 {
    // Acceptance never removes/replaces the fixture's account credential.
    MarmotSecretStoreStatus::Failed as u32
}
unsafe extern "C" fn free_secret(data: *mut c_void, value: *mut c_char) {
    if !value.is_null() {
        let mut bytes = unsafe { CString::from_raw(value) }.into_bytes_with_nul();
        bytes.zeroize();
        if let Some(store) = unsafe { credential(data) } {
            store.audit.frees.fetch_add(1, Ordering::SeqCst);
        }
    }
}
unsafe extern "C" fn destroy(data: *mut c_void) {
    if !data.is_null() {
        let store = unsafe { Box::from_raw(data.cast::<Credential>()) };
        store.audit.destroys.fetch_add(1, Ordering::SeqCst);
    }
}

struct Client {
    pointer: *mut MarmotClient,
    audit: Arc<CallbackAudit>,
}
impl Client {
    fn open(root: &str, fixture: &Fixture, secret: &str) -> Self {
        let audit = Arc::new(CallbackAudit::default());
        let store = Box::into_raw(Box::new(Credential {
            label: fixture.label.clone(),
            account: fixture.account.clone(),
            secret: Zeroizing::new(secret.to_owned()),
            audit: audit.clone(),
        }));
        let table = MarmotSecretStore {
            user_data: store.cast(),
            has_secret_for_label: Some(has),
            has_secret_for_account_id: Some(has),
            write_secret: Some(write_secret),
            load_secret: Some(load),
            remove_secret: Some(remove),
            free_secret: Some(free_secret),
            destroy: Some(destroy),
        };
        let root = CString::new(root).expect("validated private root");
        let relay = CString::new(fixture.relay.as_str()).expect("actual private relay");
        let options = MarmotClientOptions {
            relay_policy: 1,
            cursor_persistence: 0,
            client_name: std::ptr::null(),
            store: &table,
            attachment_acquisition_mode: 0,
        };
        let mut pointer = std::ptr::null_mut();
        let status = unsafe {
            crate::marmot_client_new_with_configuration(
                root.as_ptr(),
                &relay.as_ptr(),
                1,
                &options,
                crate::deployment::OwnedDeployment::white_noise().as_ptr(),
                &mut pointer,
            )
        };
        if status != MarmotStatus::Ok {
            // Constructor transfers callback ownership only on success.
            unsafe {
                drop(Box::from_raw(store));
            }
        }
        assert!(
            status == MarmotStatus::Ok && !pointer.is_null(),
            "real C constructor failed"
        );
        let mut client = Self { pointer, audit };
        if unsafe { marmot_client_start(client.pointer) } != MarmotStatus::Ok {
            let closed = client.close_checked();
            eprintln!("ffi_fixture_constructor_cleanup_closed={closed}");
            panic!("real C client start failed");
        }
        client
    }
    fn close_checked(&mut self) -> bool {
        if self.pointer.is_null() {
            return true;
        }
        let shutdown = unsafe { marmot_client_shutdown_and_close(self.pointer) };
        let mut closed = false;
        let storage = unsafe { marmot_storage_is_closed(self.pointer, &mut closed) };
        unsafe {
            crate::marmot_client_free(self.pointer);
        }
        self.pointer = std::ptr::null_mut();
        let deadline = Instant::now() + Duration::from_secs(2);
        while self.audit.destroys.load(Ordering::SeqCst) == 0 && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(20));
        }
        shutdown == MarmotStatus::Ok
            && storage == MarmotStatus::Ok
            && closed
            && self.audit.loads.load(Ordering::SeqCst) > 0
            && self.audit.loads.load(Ordering::SeqCst) == self.audit.frees.load(Ordering::SeqCst)
            && self.audit.destroys.load(Ordering::SeqCst) == 1
    }
    fn close(&mut self) {
        assert!(!self.pointer.is_null(), "client must close exactly once");
        assert!(
            self.close_checked(),
            "real C client positive closure failed"
        );
    }
}
impl Drop for Client {
    fn drop(&mut self) {
        if !self.pointer.is_null() {
            eprintln!("ffi_fixture_client_cleanup_closed={}", self.close_checked());
        }
    }
}
struct Producer(Child, bool);
impl Producer {
    fn finish_checked(&mut self, socket: Option<&mut UnixStream>, nonce: &str) -> bool {
        if self.1 {
            return true;
        }
        let mut positive = false;
        if let Some(socket) = socket {
            // Protocol assertions are caught so a broken socket cannot bypass wait/cleanup.
            positive = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                ask(socket, nonce, "finish", &[]).closed
            }))
            .unwrap_or(false);
        }
        let deadline = Instant::now() + Duration::from_secs(15);
        while Instant::now() < deadline {
            match self.0.try_wait() {
                Ok(Some(exit)) => {
                    self.1 = true;
                    return positive && exit.success();
                }
                Ok(None) => std::thread::sleep(Duration::from_millis(20)),
                Err(_) => break,
            }
        }
        let _ = self.0.kill();
        let _ = self.0.wait();
        self.1 = true;
        false
    }
}
impl Drop for Producer {
    fn drop(&mut self) {
        if !self.1 {
            let closed = self.finish_checked(None, "");
            eprintln!("ffi_fixture_producer_positive_exit={closed}");
        }
    }
}

fn state(
    client: &Client,
    label: &CStr,
    group: &CStr,
    leave: bool,
) -> (MarmotAccountChatDepartureStatus, Option<String>) {
    let mut output: *mut MarmotAccountChatDepartureState = std::ptr::null_mut();
    let status = unsafe {
        if leave {
            marmot_leave_account_chat(client.pointer, label.as_ptr(), group.as_ptr(), &mut output)
        } else {
            marmot_account_chat_departure_state(
                client.pointer,
                label.as_ptr(),
                group.as_ptr(),
                &mut output,
            )
        }
    };
    if status != MarmotStatus::Ok {
        if !output.is_null() {
            unsafe {
                marmot_account_chat_departure_state_free(output);
            }
        }
        assert_eq!(status, MarmotStatus::Ok);
    }
    assert!(!output.is_null(), "real departure DTO");
    let view = unsafe { &*output };
    let value = (
        view.status,
        (!view.operation_id.is_null()).then(|| {
            unsafe { CStr::from_ptr(view.operation_id) }
                .to_string_lossy()
                .into_owned()
        }),
    );
    unsafe {
        marmot_account_chat_departure_state_free(output);
    }
    value
}
fn wait(predicate: impl Fn() -> bool, stage: &'static str) {
    let deadline = Instant::now() + Duration::from_secs(45);
    while Instant::now() < deadline {
        if predicate() {
            return;
        }
        std::thread::sleep(Duration::from_millis(250));
    }
    panic!("{stage}");
}
fn denied(client: &Client, label: &CStr, group: &CStr, token: &str) {
    let token = CString::new(token).unwrap();
    let text = c"isolated forbidden departure post";
    let mut output: *mut MarmotLocalSendAcceptance = std::ptr::null_mut();
    let status = unsafe {
        marmot_send_text_with_client_token(
            client.pointer,
            label.as_ptr(),
            group.as_ptr(),
            text.as_ptr(),
            token.as_ptr(),
            &mut output,
        )
    };
    if !output.is_null() {
        unsafe {
            marmot_local_send_acceptance_free(output);
        }
    }
    assert_eq!(status, MarmotStatus::AccountChatDepartureDenied);
    assert!(
        output.is_null(),
        "denied send must produce no acceptance DTO"
    );
}

fn ordinary_event(client: &Client, label: &CStr, group: &CStr, token: &str) -> String {
    let text = CString::new(format!("isolated live ordinary {token}")).unwrap();
    let token = CString::new(token).unwrap();
    let mut accepted: *mut MarmotLocalSendAcceptance = std::ptr::null_mut();
    let status = unsafe {
        marmot_send_text_with_client_token(
            client.pointer,
            label.as_ptr(),
            group.as_ptr(),
            text.as_ptr(),
            token.as_ptr(),
            &mut accepted,
        )
    };
    if !accepted.is_null() {
        unsafe {
            marmot_local_send_acceptance_free(accepted);
        }
    }
    assert_eq!(status, MarmotStatus::Ok);
    assert!(!accepted.is_null(), "ordinary send actual admission");
    let deadline = Instant::now() + Duration::from_secs(45);
    while Instant::now() < deadline {
        let mut output: *mut MarmotLocalSendStatus = std::ptr::null_mut();
        let status = unsafe {
            marmot_local_send_status(
                client.pointer,
                label.as_ptr(),
                group.as_ptr(),
                token.as_ptr(),
                &mut output,
            )
        };
        if status != MarmotStatus::Ok {
            if !output.is_null() {
                unsafe {
                    marmot_local_send_status_free(output);
                }
            }
            assert_eq!(status, MarmotStatus::Ok);
        }
        if !output.is_null() {
            let view = unsafe { &*output };
            let rejected = view.state == 3;
            let event = if view.state == 2 && !view.summary.is_null() {
                let summary = unsafe { &*view.summary };
                if summary.message_ids_len == 1 && !summary.message_ids.is_null() {
                    let id = unsafe { *summary.message_ids };
                    (!id.is_null())
                        .then(|| unsafe { CStr::from_ptr(id) }.to_string_lossy().into_owned())
                } else {
                    None
                }
            } else {
                None
            };
            unsafe {
                marmot_local_send_status_free(output);
            }
            assert!(!rejected, "actual ordinary member send rejected");
            if let Some(event) = event {
                assert!(hex(&event, 32), "actual canonical ordinary event");
                return event;
            }
        }
        std::thread::sleep(Duration::from_millis(250));
    }
    panic!("ordinary send did not receive a genuine completion");
}

fn paired_visible(client: &Client, label: &CStr, group: &CStr) -> bool {
    let mut output: *mut MarmotPairedChatListPage = std::ptr::null_mut();
    let status = unsafe {
        marmot_paired_chat_list_page(
            client.pointer,
            label.as_ptr(),
            std::ptr::null(),
            128,
            &mut output,
        )
    };
    if status != MarmotStatus::Ok {
        if !output.is_null() {
            unsafe {
                marmot_paired_chat_list_page_free(output);
            }
        }
        assert_eq!(status, MarmotStatus::Ok);
    }
    assert!(!output.is_null(), "real paired catalog DTO");
    let view = unsafe { &*output };
    let valid = view.chats_len <= 128 && (view.chats_len == 0 || !view.chats.is_null());
    let visible = valid
        && (0..view.chats_len).any(|index| {
            let row = unsafe { &*view.chats.add(index) };
            !row.group_id_hex.is_null() && unsafe { CStr::from_ptr(row.group_id_hex) } == group
        });
    unsafe {
        marmot_paired_chat_list_page_free(output);
    }
    assert!(valid, "bounded paired catalog DTO");
    visible
}

fn source_kind(client: &Client, label: &CStr, group: &CStr) -> Option<bool> {
    let client = unsafe { &*client.pointer };
    let observation = client.block_on(client.marmot.open_account_conversation_window(
        label.to_str().unwrap().to_owned(),
        group.to_str().unwrap().to_owned(),
        128,
    ));
    match observation {
        Ok(window) => {
            let snapshot = window.snapshot();
            window.cancel();
            let snapshot = snapshot.expect("real initial conversation snapshot");
            Some(matches!(
                snapshot.header,
                marmot_uniffi::conversions::AccountConversationHeaderFfi::LocalMls { .. }
            ))
        }
        Err(marmot_uniffi::MarmotKitError::AccountSharingNotReady) => None,
        Err(_) => panic!("fresh source-qualified observation failed outside readiness"),
    }
}

#[test]
#[ignore = "requires pinned same-source App producer executable; run explicitly, never count as skipped native acceptance"]
fn genuine_two_source_departure_crosses_real_c_and_uniffi_boundaries() {
    let _audit = crate::memory::audit::test_lock();
    #[cfg(feature = "alloc-audit")]
    let allocations_before = crate::memory::audit::live_allocations();
    let source = SOURCE.expect("consumer needs same-source compile stamp");
    assert!(hex(source, 20), "immutable source stamp");
    let executable =
        std::env::var("MARMOT_ACCOUNT_DEPARTURE_FIXTURE_EXE").expect("pinned producer executable");
    let expected =
        std::env::var("MARMOT_ACCOUNT_DEPARTURE_FIXTURE_SHA256").expect("pinned producer SHA");
    assert!(
        Path::new(&executable).is_absolute() && hex(&expected, 32),
        "producer identity bound"
    );
    let metadata = std::fs::symlink_metadata(&executable).expect("producer executable metadata");
    assert!(
        metadata.is_file()
            && metadata.len() <= 1_073_741_824
            && metadata.permissions().mode() & 0o111 != 0
    );
    let digest = Command::new("/usr/bin/shasum")
        .args(["-a", "256", &executable])
        .output()
        .expect("producer hash command");
    assert!(
        digest.status.success()
            && std::str::from_utf8(&digest.stdout)
                .is_ok_and(|value| value.split_whitespace().next() == Some(expected.as_str())),
        "exact producer bytes"
    );
    let root = tempfile::Builder::new()
        .permissions(std::fs::Permissions::from_mode(0o700))
        .tempdir()
        .expect("private consumer IPC root");
    assert_eq!(
        std::fs::metadata(root.path()).unwrap().permissions().mode() & 0o077,
        0
    );
    let socket_path = root.path().join("fixture.sock");
    let listener = fs_private::bind_unix_listener_private(&socket_path, 0o600)
        .expect("private fixture listener");
    listener.set_nonblocking(true).unwrap();
    let nonce = Zeroizing::new(
        ::nostr::prelude::Keys::generate()
            .secret_key()
            .to_secret_hex(),
    );
    let log = std::env::var("MARMOT_ACCOUNT_DEPARTURE_FIXTURE_LOG")
        .expect("retained private producer log");
    assert!(Path::new(&log).is_absolute(), "absolute producer log");
    let log = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(log)
        .expect("fresh private producer log");
    let producer = Command::new(&executable)
        .args(["native_device_linking::tests::account_departure_ffi_fixture::account_departure_ffi_fixture_producer", "--exact", "--ignored", "--nocapture", "--test-threads=1"])
        .env("MARMOT_ACCOUNT_DEPARTURE_FIXTURE_SOCKET", &socket_path)
        .env("MARMOT_ACCOUNT_DEPARTURE_FIXTURE_NONCE", nonce.as_str())
        .stdin(Stdio::null()).stdout(log.try_clone().unwrap()).stderr(log)
        .spawn().expect("producer subprocess");
    let mut producer = Producer(producer, false);
    let mut clients: Vec<Client> = Vec::new();
    let mut cleanup_socket: Option<UnixStream> = None;
    let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let deadline = Instant::now() + Duration::from_secs(120);
        let mut stream = loop {
            match listener.accept() {
                Ok((stream, _)) => {
                    // macOS can inherit the listener's nonblocking mode.
                    // This consumer uses bounded blocking frame reads.
                    stream
                        .set_nonblocking(false)
                        .expect("blocking accepted fixture stream");
                    break stream;
                }
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                    assert!(
                        producer.0.try_wait().unwrap().is_none(),
                        "producer exited before private handoff"
                    );
                    assert!(
                        Instant::now() < deadline,
                        "producer private handoff timeout"
                    );
                    std::thread::sleep(Duration::from_millis(20));
                }
                Err(_) => panic!("private fixture accept"),
            }
        };
        stream
            .set_read_timeout(Some(Duration::from_secs(90)))
            .unwrap();
        stream
            .set_write_timeout(Some(Duration::from_secs(10)))
            .unwrap();
        cleanup_socket = Some(stream.try_clone().expect("cleanup socket clone"));
        let mut fixture: Fixture = read_frame(&mut stream);
        assert!(
            fixture.source == source && fixture.nonce == *nonce,
            "same-source authenticated fixture handoff"
        );
        assert!(hex(&fixture.account, 32) && hex(&fixture.secret, 32));
        assert!(
            fixture.group.len() >= 2
                && fixture.group.len() <= 510
                && fixture.group.len().is_multiple_of(2)
                && fixture.group.bytes().all(|byte| byte.is_ascii_hexdigit())
        );
        assert!(fixture.label.len() <= 128 && !fixture.label.contains('\0'));
        assert!(fixture.relay.starts_with("ws://127.0.0.1:") && fixture.relay.len() <= 128);
        assert!(
            fixture
                .roots
                .iter()
                .all(|path| Path::new(path).is_absolute() && !path.contains('\0'))
        );
        assert!(
            fixture.roots[0] != fixture.roots[1]
                && fixture.roots[0] != fixture.roots[2]
                && fixture.roots[1] != fixture.roots[2]
        );
        eprintln!("ffi_fixture_private_handoff_valid=true");
        let secret = Zeroizing::new(std::mem::take(&mut fixture.secret));
        let label = CString::new(fixture.label.as_str()).unwrap();
        let group = CString::new(fixture.group.as_str()).unwrap();
        for root in &fixture.roots {
            clients.push(Client::open(root, &fixture, &secret));
        }
        eprintln!("ffi_fixture_native_clients_open={}", clients.len());
        let before = ask(&mut stream, &nonce, "canonical", &[]);
        assert!(before.a_active && before.b_active && before.leaves == 3);
        wait(
            || source_kind(&clients[0], &label, &group) == Some(true),
            "A must have an actual ordinary header",
        );
        wait(
            || source_kind(&clients[1], &label, &group) == Some(true),
            "B must have an actual ordinary header",
        );
        wait(
            || source_kind(&clients[2], &label, &group) == Some(false),
            "C must have an actual paired-only header",
        );
        let from_a = ordinary_event(&clients[0], &label, &group, "live-a");
        let from_b = ordinary_event(&clients[1], &label, &group, "live-b");
        assert!(
            from_a != from_b,
            "independent ordinary sources produce distinct actual events"
        );
        assert!(ask(&mut stream, &nonce, "delivered", &[from_a, from_b]).delivered);
        eprintln!("ffi_fixture_real_native_ordinary_sends_decrypted=true");
        wait(
            || paired_visible(&clients[2], &label, &group),
            "actual C mirrored chat must be present before departure",
        );
        wait(
            || {
                state(&clients[2], &label, &group, false).0
                    == MarmotAccountChatDepartureStatus::Available
            },
            "fresh mirrored initiator not ready",
        );
        eprintln!("ffi_fixture_mirrored_initiator_available=true");
        clients[1].close();
        let (status, operation) = state(&clients[2], &label, &group, true);
        assert!(
            status == MarmotAccountChatDepartureStatus::Pending
                && operation.as_ref().is_some_and(|value| !value.is_empty())
        );
        let operation = operation.unwrap();
        eprintln!("ffi_fixture_offline_pending=true");
        wait(
            || {
                let observation = ask(&mut stream.try_clone().unwrap(), &nonce, "canonical", &[]);
                !observation.a_active && observation.b_active && observation.leaves == 2
            },
            "offline B must preserve its actual leaf until fresh removal",
        );
        let pending = state(&clients[2], &label, &group, false);
        assert!(
            pending.0 == MarmotAccountChatDepartureStatus::Pending
                && pending.1.as_ref() == Some(&operation)
        );
        denied(&clients[0], &label, &group, "cut-a");
        denied(&clients[2], &label, &group, "cut-c");
        wait(
            || !paired_visible(&clients[2], &label, &group),
            "principal cut must withdraw actual C paired presentation",
        );
        clients[1] = Client::open(&fixture.roots[1], &fixture, &secret);
        wait(
            || {
                let observation = ask(&mut stream.try_clone().unwrap(), &nonce, "canonical", &[]);
                !observation.a_active && !observation.b_active && observation.leaves == 1
            },
            "D must authenticate both actual leaf removals",
        );
        eprintln!("ffi_fixture_actual_ordinary_removals=true");
        wait(
            || {
                let value = state(&clients[2], &label, &group, false);
                value.0 == MarmotAccountChatDepartureStatus::Completed
                    && value.1.as_ref() == Some(&operation)
            },
            "completion must follow actual independent removals and peer receipts",
        );
        eprintln!("ffi_fixture_receipt_complete=true");
        for (client, token) in [
            (&clients[0], "done-a"),
            (&clients[1], "done-b"),
            (&clients[2], "done-c"),
        ] {
            denied(client, &label, &group, token);
        }
        clients[0].close();
        clients[1].close();
        clients[2].close();
        clients[2] = Client::open(&fixture.roots[2], &fixture, &secret);
        let restored = state(&clients[2], &label, &group, false);
        assert!(
            restored.0 == MarmotAccountChatDepartureStatus::Completed
                && restored.1.as_ref() == Some(&operation)
        );
        denied(&clients[2], &label, &group, "reopened-c");
        assert!(
            !paired_visible(&clients[2], &label, &group),
            "reopened C must retain authenticated departure fence"
        );
        clients[2].close();
        eprintln!("ffi_fixture_same_root_reopen_completed=true");
    }));
    eprintln!("ffi_fixture_cleanup_client_count={}", clients.len());
    let mut clients_closed = true;
    for client in &mut clients {
        clients_closed &= client.close_checked();
    }
    let producer_closed = producer.finish_checked(cleanup_socket.as_mut(), &nonce);
    eprintln!(
        "ffi_fixture_cleanup_clients_closed={clients_closed} producer_closed={producer_closed}"
    );
    let unchanged = Command::new("/usr/bin/shasum")
        .args(["-a", "256", &executable])
        .output()
        .is_ok_and(|result| {
            result.status.success()
                && std::str::from_utf8(&result.stdout)
                    .is_ok_and(|value| value.split_whitespace().next() == Some(expected.as_str()))
        });
    eprintln!("ffi_fixture_producer_bytes_unchanged={unchanged}");
    if let Err(original) = outcome {
        std::panic::resume_unwind(original);
    }
    assert!(
        clients_closed && producer_closed && unchanged,
        "fixture cleanup failed separately from SDK scenario"
    );
    #[cfg(feature = "alloc-audit")]
    assert_eq!(crate::memory::audit::live_allocations(), allocations_before);
    eprintln!(
        "ffi_departure_real_two_sources=true all_clients_closed=true producer_exit_zero=true"
    );
}
