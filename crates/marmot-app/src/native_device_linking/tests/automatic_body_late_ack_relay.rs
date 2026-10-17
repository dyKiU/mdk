//! Test-only transparent loopback relay proxy. It delays actual selected OK bytes only.
// Fixture connections are confined to a freshly owned loopback MockRelay.
#![allow(clippy::disallowed_methods)]

use futures::{SinkExt, StreamExt};
use sha2::{Digest, Sha256};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::watch;
use tokio::task::{JoinHandle, JoinSet};
use tokio_tungstenite::{accept_async, connect_async, tungstenite::Message};

#[derive(Clone, Copy, Default)]
pub(super) struct Observed {
    pub(super) wire_events: u64,
    pub(super) delivered_events: u64,
    pub(super) actual_ok_held: u64,
    pub(super) actual_ok_sent: u64,
    pub(super) exact_ok_sent: u64,
    pub(super) connections: u64,
    pub(super) closed_connections: u64,
    pub(super) invalid: bool,
    // Rows: frontend read, backend read, frontend write, backend write,
    // frontend close, backend close, frontend handshake, backend connect.
    // Columns: success, EOF, Close frame, ConnectionClosed, AlreadyClosed,
    // IO reset, IO broken pipe, IO unexpected EOF, IO other, protocol reset
    // without close, send after closing, receive after closing, protocol other, other.
    pub(super) io_categories: [[u64; 14]; 8],
    // Successful child, returned error, cancelled join, panicked join.
    pub(super) child_outcomes: [u64; 4],
}

pub(super) struct CloseFailure {
    pub(super) observed: Observed,
    // 1: child/server error, 2: join failure, 3: timeout/abort,
    // 4: missing task, 5: invalid or incomplete positive socket counts.
    pub(super) task_outcome: u8,
}

#[derive(Default)]
struct State {
    // The exact canonical prepared message identity never leaves test memory.
    selected: Option<String>,
    observed: Observed,
}

pub(super) struct AckProxy {
    pub(super) url: String,
    state: Arc<Mutex<State>>,
    release: watch::Sender<bool>,
    shutdown: watch::Sender<bool>,
    task: Option<JoinHandle<Result<(), ()>>>,
}

impl AckProxy {
    pub(super) async fn start(backend: String) -> Self {
        // The caller retains the freshly created MockRelay for this whole trial.
        // Refuse credentials, DNS names, external hosts and auxiliary URL routing.
        let parsed = url::Url::parse(&backend).expect("fresh mock backend URL");
        let loopback = match parsed.host() {
            Some(url::Host::Ipv4(address)) => address.is_loopback(),
            Some(url::Host::Ipv6(address)) => address.is_loopback(),
            _ => false,
        };
        assert!(
            parsed.scheme() == "ws"
                && loopback
                && parsed.username().is_empty()
                && parsed.password().is_none()
                && parsed.port().is_some_and(|port| port != 0)
                && matches!(parsed.path(), "" | "/")
                && parsed.query().is_none()
                && parsed.fragment().is_none(),
            "ACK proxy requires its freshly owned loopback websocket backend"
        );
        let backend = parsed.to_string();
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("ws://{}", listener.local_addr().unwrap());
        let state = Arc::new(Mutex::new(State::default()));
        let (release, released) = watch::channel(false);
        let (shutdown, mut stopping) = watch::channel(false);
        let server_state = state.clone();
        let task = tokio::spawn(async move {
            let mut connections = JoinSet::new();
            let mut failed = false;
            loop {
                tokio::select! {
                    biased;
                    changed = stopping.changed() => {
                        if changed.is_err() || *stopping.borrow() { break; }
                    }
                    result = connections.join_next(), if !connections.is_empty() => {
                        if let Some(result) = result {
                            failed |= record_child(&server_state, result);
                        } else { failed = true; }
                    }
                    accepted = listener.accept() => {
                        let Ok((stream, _)) = accepted else { failed = true; break };
                        let within_bound = {
                            let mut state = server_state.lock().expect("ACK proxy");
                            state.observed.connections += 1;
                            if state.observed.connections > 64 {
                                state.observed.invalid = true;
                                false
                            } else { true }
                        };
                        if !within_bound { failed = true; break; }
                        connections.spawn(connection(
                            stream,
                            backend.clone(),
                            server_state.clone(),
                            released.clone(),
                            stopping.clone(),
                        ));
                    }
                }
            }
            drop(listener);
            while let Some(result) = connections.join_next().await {
                failed |= record_child(&server_state, result);
            }
            if failed { Err(()) } else { Ok(()) }
        });
        Self {
            url,
            state,
            release,
            shutdown,
            task: Some(task),
        }
    }

    pub(super) fn armer(&self) -> impl Fn(&cgka_traits::MessageId) + Send + Sync + 'static {
        let state = self.state.clone();
        move |prepared| {
            assert!(
                prepared.as_slice().len() == 32,
                "actual prepared event identity width"
            );
            let mut state = state.lock().expect("ACK proxy");
            assert!(
                state.selected.is_none(),
                "one immutable selected publication"
            );
            state.selected = Some(hex::encode(prepared.as_slice()));
        }
    }

    pub(super) fn observed(&self) -> Observed {
        self.state.lock().expect("ACK proxy").observed
    }

    pub(super) fn release_actual_ok(&self) {
        self.release.send_replace(true);
    }

    pub(super) async fn close(mut self) -> Result<Observed, CloseFailure> {
        self.release_actual_ok();
        self.shutdown.send_replace(true);
        let mut task = self.task.take().ok_or_else(|| CloseFailure {
            observed: self.observed(), task_outcome: 4,
        })?;
        let outcome = tokio::time::timeout(Duration::from_secs(5), &mut task).await;
        match outcome {
            Ok(Ok(Ok(()))) => {
                let observed = self.observed();
                if !observed.invalid
                    && observed.connections > 0
                    && observed.connections == observed.closed_connections
                {
                    Ok(observed)
                } else {
                    Err(CloseFailure { observed, task_outcome: 5 })
                }
            }
            Ok(Ok(Err(()))) => Err(CloseFailure { observed: self.observed(), task_outcome: 1 }),
            Ok(Err(_)) => Err(CloseFailure { observed: self.observed(), task_outcome: 2 }),
            Err(_) => {
                // Abort is failed cleanup, never positive close evidence.
                task.abort();
                let _ = task.await;
                Err(CloseFailure { observed: self.observed(), task_outcome: 3 })
            }
        }
    }
}

impl Drop for AckProxy {
    fn drop(&mut self) {
        self.release.send_replace(true);
        self.shutdown.send_replace(true);
        if let Some(task) = &self.task {
            task.abort();
        }
    }
}

fn record_io(state: &Arc<Mutex<State>>, operation: usize, category: usize) {
    state.lock().expect("ACK proxy").observed.io_categories[operation][category] += 1;
}

fn record_error(state: &Arc<Mutex<State>>, operation: usize, error: &tokio_tungstenite::tungstenite::Error) {
    use tokio_tungstenite::tungstenite::Error;
    let category = match error {
        Error::ConnectionClosed => 3,
        Error::AlreadyClosed => 4,
        Error::Io(error) => match error.kind() {
            std::io::ErrorKind::ConnectionReset => 5,
            std::io::ErrorKind::BrokenPipe => 6,
            std::io::ErrorKind::UnexpectedEof => 7,
            _ => 8,
        },
        Error::Protocol(error) => match error {
            tokio_tungstenite::tungstenite::error::ProtocolError::ResetWithoutClosingHandshake => 9,
            tokio_tungstenite::tungstenite::error::ProtocolError::SendAfterClosing => 10,
            tokio_tungstenite::tungstenite::error::ProtocolError::ReceivedAfterClosing => 11,
            _ => 12,
        },
        _ => 13,
    };
    record_io(state, operation, category);
}

fn record_child(state: &Arc<Mutex<State>>, result: Result<Result<(), ()>, tokio::task::JoinError>) -> bool {
    let category = match &result {
        Ok(Ok(())) => 0,
        Ok(Err(())) => 1,
        Err(error) if error.is_cancelled() => 2,
        Err(_) => 3,
    };
    state.lock().expect("ACK proxy").observed.child_outcomes[category] += 1;
    category != 0
}

fn terminal(error: &tokio_tungstenite::tungstenite::Error) -> bool {
    matches!(
        error,
        tokio_tungstenite::tungstenite::Error::ConnectionClosed
            | tokio_tungstenite::tungstenite::Error::AlreadyClosed
    )
}

fn inspect(state: &Arc<Mutex<State>>, message: &Message, upstream: bool) -> Result<bool, ()> {
    let Message::Text(text) = message else {
        return Ok(false);
    };
    if text.len() > 1024 * 1024 {
        state.lock().expect("ACK proxy").observed.invalid = true;
        return Err(());
    }
    let Ok(value) = serde_json::from_str::<serde_json::Value>(text) else {
        return Ok(false);
    };
    let Some(fields) = value.as_array() else {
        return Ok(false);
    };
    let mut state = state.lock().expect("ACK proxy");
    let Some(selected) = state.selected.as_deref() else {
        return Ok(false);
    };
    let kind = fields.first().and_then(serde_json::Value::as_str);
    let matches_event = kind == Some("EVENT")
        && fields
            .get(if upstream { 2 } else { 1 })
            .and_then(|event| event.get("id"))
            .and_then(serde_json::Value::as_str)
            == Some(selected);
    let matches_ok = upstream
        && kind == Some("OK")
        && fields.get(1).and_then(serde_json::Value::as_str) == Some(selected);
    if matches_event {
        let event: nostr::prelude::Event =
            serde_json::from_value(fields[if upstream { 2 } else { 1 }].clone()).map_err(|_| ())?;
        if event.verify().is_err() {
            state.observed.invalid = true;
            return Err(());
        }
        if upstream {
            state.observed.delivered_events += 1;
        } else {
            state.observed.wire_events += 1;
        }
    }
    if matches_ok {
        if fields.get(2).and_then(serde_json::Value::as_bool) != Some(true)
            || state.observed.wire_events == 0
        {
            state.observed.invalid = true;
            return Err(());
        }
        state.observed.actual_ok_held += 1;
    }
    Ok(matches_ok)
}

async fn connection(
    stream: TcpStream,
    backend: String,
    state: Arc<Mutex<State>>,
    mut released: watch::Receiver<bool>,
    mut stopping: watch::Receiver<bool>,
) -> Result<(), ()> {
    let mut client = accept_async(stream).await.map_err(|error| { record_error(&state, 6, &error); })?;
    record_io(&state, 6, 0);
    let (mut relay, _) = connect_async(backend).await.map_err(|error| { record_error(&state, 7, &error); })?;
    record_io(&state, 7, 0);
    let mut held = Vec::new();
    let result = async {
        loop {
            tokio::select! {
                biased;
                changed = stopping.changed() => {
                    if changed.is_err() || *stopping.borrow() { break; }
                }
                changed = released.changed() => {
                    if changed.is_err() { return Err(()); }
                    let release_now = *released.borrow();
                    if release_now {
                        for (message, original_digest) in held.drain(..) {
                            let Message::Text(text) = &message else { return Err(()) };
                            if <[u8;32]>::from(Sha256::digest(text.as_bytes())) != original_digest { return Err(()) }
                            client.send(message).await.map_err(|error| { record_error(&state, 2, &error); })?;
                            record_io(&state, 2, 0);
                            let mut state = state.lock().expect("ACK proxy");
                            state.observed.actual_ok_sent += 1;
                            state.observed.exact_ok_sent += 1;
                        }
                    }
                }
                incoming = client.next() => {
                    let message = match incoming {
                        Some(Ok(message)) => { record_io(&state, 0, if matches!(message, Message::Close(_)) { 2 } else { 0 }); message },
                        None => { record_io(&state, 0, 1); break; },
                        Some(Err(error)) if terminal(&error) => { record_error(&state, 0, &error); break; },
                        Some(Err(error)) => { record_error(&state, 0, &error); return Err(()); },
                    };
                    inspect(&state, &message, false)?;
                    let closing = matches!(message, Message::Close(_));
                    relay.send(message).await.map_err(|error| { record_error(&state, 3, &error); })?;
                    record_io(&state, 3, 0);
                    if closing { break; }
                }
                incoming = relay.next() => {
                    let message = match incoming {
                        Some(Ok(message)) => { record_io(&state, 1, if matches!(message, Message::Close(_)) { 2 } else { 0 }); message },
                        None => { record_io(&state, 1, 1); break; },
                        Some(Err(error)) if terminal(&error) => { record_error(&state, 1, &error); break; },
                        Some(Err(error)) => { record_error(&state, 1, &error); return Err(()); },
                    };
                    let selected_ok = inspect(&state, &message, true)?;
                    let release_now = *released.borrow();
                    if selected_ok && !release_now {
                        if held.len() >= 8 {
                            state.lock().expect("ACK proxy").observed.invalid = true;
                            return Err(());
                        }
                        // Preserve the backend's complete original frame, never fabricate OK.
                        let Message::Text(text) = &message else { return Err(()) };
                        let original_digest: [u8;32] = Sha256::digest(text.as_bytes()).into();
                        held.push((message, original_digest));
                    } else {
                        let closing = matches!(message, Message::Close(_));
                        client.send(message).await.map_err(|error| { record_error(&state, 2, &error); })?;
                        record_io(&state, 2, 0);
                        if selected_ok {
                            let mut state = state.lock().expect("ACK proxy");
                            state.observed.actual_ok_sent += 1;
                            state.observed.exact_ok_sent += 1;
                        }
                        if closing { break; }
                    }
                }
            }
        }
        Ok(())
    }.await;
    // Both sockets are explicitly closed even after a forwarding error.
    let client_closed = match client.close(None).await {
        Ok(()) => { record_io(&state, 4, 0); true },
        Err(error) => { record_error(&state, 4, &error); terminal(&error) },
    };
    let relay_closed = match relay.close(None).await {
        Ok(()) => { record_io(&state, 5, 0); true },
        Err(error) => { record_error(&state, 5, &error); terminal(&error) },
    };
    if result.is_ok() && client_closed && relay_closed {
        state.lock().expect("ACK proxy").observed.closed_connections += 1;
        Ok(())
    } else {
        Err(())
    }
}
