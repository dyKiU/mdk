//! Test-only same-root handoff to real UF/C constructors. No shipping factory.
//! Credentials cross a private bounded socket, never stdout or fixture logs.
use super::automatic_two_source_leave_acceptance::{
    TwoSourcePeer, stored_indices, wait_for_paired_records,
};
use crate::{MarmotApp, MarmotAppRuntime};
use futures::FutureExt;
use serde::{Deserialize, Serialize};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UnixStream;
use zeroize::{Zeroize, Zeroizing};

const FRAME_LIMIT: usize = 32_768;
const SOURCE: Option<&str> = option_env!("MARMOT_ACCEPTANCE_SOURCE_COMMIT");

#[test]
#[ignore = "requires explicit same-source UF/C fixture consumer; not standalone native qualification"]
fn account_departure_ffi_fixture_producer() {
    crate::tests::run_composed_app_runtime_test("account-departure-ffi-producer", || async {
        Box::pin(super::actual::run_native_public_three_device_enrollment(
            super::actual::ApprovalScenario::AutomaticDepartureFfiFixture,
        ))
        .await;
    });
}

#[derive(Serialize)]
struct Fixture<'a> {
    source: &'a str,
    nonce: &'a str,
    roots: [&'a std::path::Path; 3],
    relay: &'a str,
    label: &'a str,
    account: &'a str,
    secret: &'a str,
    group: String,
}

#[derive(Deserialize)]
struct Request {
    command: String,
    nonce: String,
    #[serde(default)]
    messages: Vec<String>,
}

#[derive(Serialize)]
struct Observation {
    a_active: bool,
    b_active: bool,
    leaves: usize,
    delivered: bool,
    closed: bool,
}

async fn write_frame<T: Serialize>(socket: &mut UnixStream, value: &T) -> Result<(), &'static str> {
    let mut frame = serde_json::to_vec(value).map_err(|_| "fixture encoding")?;
    if frame.is_empty() || frame.len() > FRAME_LIMIT {
        frame.zeroize();
        return Err("fixture frame bound");
    }
    let result = async {
        socket
            .write_u32(frame.len() as u32)
            .await
            .map_err(|_| "fixture write")?;
        socket.write_all(&frame).await.map_err(|_| "fixture write")
    }
    .await;
    frame.zeroize();
    result
}

async fn read_request(socket: &mut UnixStream) -> Result<Request, &'static str> {
    let length = socket.read_u32().await.map_err(|_| "fixture read")? as usize;
    if length == 0 || length > FRAME_LIMIT {
        return Err("fixture frame bound");
    }
    let mut frame = vec![0; length];
    socket
        .read_exact(&mut frame)
        .await
        .map_err(|_| "fixture read")?;
    let value = serde_json::from_slice(&frame).map_err(|_| "fixture request shape");
    frame.zeroize();
    value
}

/// Called only after the genuine two-leaf setup and all broad originals complete.
/// Root-owned fixture glue registers this child and preserves the real pairing.
pub(super) async fn serve_fixture(
    apps: &[MarmotApp; 3],
    runtimes: &[MarmotAppRuntime; 3],
    peer: &TwoSourcePeer,
    relay_url: &str,
) {
    let outcome = std::panic::AssertUnwindSafe(run_fixture(apps, runtimes, peer, relay_url))
        .catch_unwind()
        .await;
    // Attempt every close even when an earlier owner reports a cleanup failure.
    let mut closed = true;
    for runtime in runtimes {
        let result = runtime.shutdown_and_close().await;
        closed &= result.is_ok() && runtime.storage_is_closed();
    }
    let result = peer.runtime.shutdown_and_close().await;
    closed &= result.is_ok() && peer.runtime.storage_is_closed();
    eprintln!("ffi_fixture_producer_cleanup_closed={closed}");
    if let Err(original) = outcome {
        std::panic::resume_unwind(original);
    }
    assert!(closed, "producer cleanup failed after protocol completion");
}

async fn run_fixture(
    apps: &[MarmotApp; 3],
    runtimes: &[MarmotAppRuntime; 3],
    peer: &TwoSourcePeer,
    relay_url: &str,
) {
    let source = SOURCE.expect("producer needs same-source compile stamp");
    assert!(source.len() == 40 && source.bytes().all(|byte| byte.is_ascii_hexdigit()));
    let socket_path = std::env::var("MARMOT_ACCOUNT_DEPARTURE_FIXTURE_SOCKET")
        .expect("producer requires private consumer socket");
    let nonce = Zeroizing::new(
        std::env::var("MARMOT_ACCOUNT_DEPARTURE_FIXTURE_NONCE")
            .expect("producer requires private consumer nonce"),
    );
    assert!(nonce.len() == 64 && nonce.bytes().all(|byte| byte.is_ascii_hexdigit()));
    assert!(std::path::Path::new(&socket_path).is_absolute());
    let initial = stored_indices(&peer.app, &peer.group);
    assert!(
        initial.len() == 3 && initial.contains(&peer.a_index) && initial.contains(&peer.b_index)
    );
    wait_for_paired_records(&runtimes[2], &peer.group, &peer.initial_ids, None).await;
    assert!(
        apps[2]
            .load_state("test")
            .expect("actual C projection")
            .groups
            .iter()
            .all(|row| row.group_id_hex != hex::encode(peer.group.as_slice()))
    );
    let home = apps[0].account_home();
    let account = home.account("test").expect("actual synthetic account");
    let secret = Zeroizing::new(
        home.load_signing_keys("test")
            .expect("original fixture credential")
            .secret_key()
            .to_secret_hex(),
    );
    for app in apps {
        assert!(
            app.account_home()
                .account("test")
                .is_ok_and(|value| value.account_id_hex == account.account_id_hex
                    && value.label == account.label)
        );
    }
    for runtime in runtimes {
        runtime
            .shutdown_and_close()
            .await
            .expect("producer source positive close");
        assert!(runtime.storage_is_closed());
    }
    let outcome = tokio::time::timeout(Duration::from_secs(300), async {
        let mut socket = UnixStream::connect(&socket_path)
            .await
            .map_err(|_| "fixture connect")?;
        write_frame(
            &mut socket,
            &Fixture {
                source,
                nonce: &nonce,
                roots: [&apps[0].root, &apps[1].root, &apps[2].root],
                relay: relay_url,
                label: &account.label,
                account: &account.account_id_hex,
                secret: &secret,
                group: hex::encode(peer.group.as_slice()),
            },
        )
        .await?;
        for _ in 0..1024 {
            let request = read_request(&mut socket).await?;
            if request.nonce != *nonce || request.command.len() > 32 || request.messages.len() > 8 {
                return Err("fixture request scope");
            }
            if !request.messages.iter().all(|value| {
                value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
            }) {
                return Err("fixture event bound");
            }
            let delivered = match request.command.as_str() {
                "canonical" if request.messages.is_empty() => false,
                "delivered" if !request.messages.is_empty() => {
                    tokio::time::timeout(Duration::from_secs(45), async {
                        loop {
                            let storage = peer
                                .app
                                .account_storage("test")
                                .expect("actual independent observer");
                            if request.messages.iter().all(|id| {
                                storage
                                    .app_storage().app_message(&hex::encode(peer.group.as_slice()), id)
                                    .is_ok_and(|row| row.is_some())
                            }) {
                                break;
                            }
                            tokio::time::sleep(Duration::from_millis(20)).await;
                        }
                    })
                    .await
                    .map_err(|_| "fixture ordinary delivery")?;
                    true
                }
                "finish" if request.messages.is_empty() => {
                    let final_indices = stored_indices(&peer.app, &peer.group);
                    peer.runtime
                        .shutdown_and_close()
                        .await
                        .map_err(|_| "fixture peer close")?;
                    if !peer.runtime.storage_is_closed() {
                        return Err("fixture peer close");
                    }
                    write_frame(
                        &mut socket,
                        &Observation {
                            a_active: final_indices.contains(&peer.a_index),
                            b_active: final_indices.contains(&peer.b_index),
                            leaves: final_indices.len(),
                            delivered: false,
                            closed: true,
                        },
                    )
                    .await?;
                    return Ok(());
                }
                _ => return Err("fixture command"),
            };
            let indices = stored_indices(&peer.app, &peer.group);
            write_frame(
                &mut socket,
                &Observation {
                    a_active: indices.contains(&peer.a_index),
                    b_active: indices.contains(&peer.b_index),
                    leaves: indices.len(),
                    delivered,
                    closed: false,
                },
            )
            .await?;
        }
        Err("fixture request count")
    })
    .await;
    // Also positively close the independent observer on protocol failure/timeout.
    peer.runtime
        .shutdown_and_close()
        .await
        .expect("producer observer positive close");
    assert!(peer.runtime.storage_is_closed());
    assert!(
        matches!(outcome, Ok(Ok(()))),
        "private fixture protocol did not complete"
    );
}
