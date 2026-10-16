//! Bounded diagnostic metadata only. Private wire identities are never exported.
use std::sync::{Mutex, OnceLock};
use std::time::Instant;

const LIMIT: usize = 128;
pub const STAGES: [&str; 20] = [
    "sdk-entry",
    "prepared-single",
    "operation-returned",
    "retain-lock-start",
    "retain-lock-acquired",
    "retain-eviction-returned",
    "connect-start",
    "connect-returned",
    "sdk-send-start",
    "sdk-send-returned",
    "aborted-join-drain-start",
    "aborted-join-drain-returned",
    "ambiguous-reset-start",
    "ambiguous-reset-returned",
    "single-release-start",
    "single-release-returned",
    "release-lock-start",
    "release-lock-acquired",
    "release-eviction-start",
    "release-eviction-returned",
];
struct Message {
    identity: String,
    kind: u64,
    recipient: bool,
    registrations: u64,
    mismatch: bool,
}
struct Operation {
    token: u64,
    endpoints: usize,
    stages: [[u64; 3]; 20],
}
struct State {
    origin: Instant,
    messages: Vec<Message>,
    operations: Vec<Operation>,
    // Message capacity, operation capacity, invalid registration, unmatched SDK
    // operations, invalid stage/operation, unmapped batches. No runtime input.
    unknown: [u64; 6],
}
fn state() -> &'static Mutex<State> {
    static STATE: OnceLock<Mutex<State>> = OnceLock::new();
    STATE.get_or_init(|| {
        Mutex::new(State {
            origin: Instant::now(),
            messages: Vec::new(),
            operations: Vec::new(),
            unknown: [0; 6],
        })
    })
}
fn time(state: &State) -> u64 {
    state.origin.elapsed().as_millis() as u64 + 1
}
pub fn register_app_message(identity: &[u8], kind: u64, recipient: bool) -> (u64, u64) {
    let mut state = state().lock().expect("publication diagnostic");
    if identity.len() != 32 || kind > 2 {
        state.unknown[2] += 1;
        return (0, 0);
    }
    // MessageId is the decoded 32-byte event ID; the SDK DTO already contains
    // its canonical lowercase hex (NostrTransportEvent::to_transport_message).
    let identity = hex::encode(identity);
    if let Some(index) = state
        .messages
        .iter()
        .position(|entry| entry.identity == identity)
    {
        let entry = &mut state.messages[index];
        entry.registrations += 1;
        entry.mismatch |= entry.kind != kind || entry.recipient != recipient;
        return (index as u64 + 1, entry.registrations);
    }
    if state.messages.len() == LIMIT {
        state.unknown[0] += 1;
        return (0, 0);
    }
    state.messages.push(Message {
        identity,
        kind,
        recipient,
        registrations: 1,
        mismatch: false,
    });
    (state.messages.len() as u64, 1)
}
pub fn begin_sdk_operation(identity: &str, endpoints: usize) -> u64 {
    let mut state = state().lock().expect("publication diagnostic");
    let Some(index) = state
        .messages
        .iter()
        .position(|entry| entry.identity == identity)
    else {
        state.unknown[3] += 1;
        return 0;
    };
    if state.operations.len() == LIMIT {
        state.unknown[1] += 1;
        return 0;
    }
    let mut stages = [[0; 3]; 20];
    let now = time(&state);
    stages[0] = [now, now, 1];
    state.operations.push(Operation {
        token: index as u64 + 1,
        endpoints,
        stages,
    });
    state.operations.len() as u64
}
pub fn record_unmapped_batch() {
    state().lock().expect("publication diagnostic").unknown[5] += 1;
}
pub fn record_stage(operation: u64, stage: &str) {
    if operation == 0 {
        return;
    }
    let mut state = state().lock().expect("publication diagnostic");
    let now = time(&state);
    let Some(column) = STAGES.iter().position(|known| *known == stage) else {
        state.unknown[4] += 1;
        return;
    };
    let Some(operation) = state.operations.get_mut(operation as usize - 1) else {
        state.unknown[4] += 1;
        return;
    };
    let row = &mut operation.stages[column];
    if row[2] == 0 {
        row[0] = now;
    }
    row[1] = now;
    row[2] += 1;
}
pub fn snapshot() -> serde_json::Value {
    let state = state().lock().expect("publication diagnostic");
    let messages = state
        .messages
        .iter()
        .enumerate()
        .map(|(index, entry)| {
            [
                index as u64 + 1,
                entry.kind,
                u64::from(entry.recipient),
                entry.registrations,
                u64::from(entry.mismatch),
            ]
        })
        .collect::<Vec<_>>();
    let operations = state.operations.iter().enumerate().map(|(index, entry)| {
        serde_json::json!({"ordinal": index + 1, "token": entry.token, "endpoints": entry.endpoints, "stages": entry.stages})
    }).collect::<Vec<_>>();
    serde_json::json!({"at_ms":time(&state), "messages":messages, "operations":operations, "unknown":state.unknown})
}
