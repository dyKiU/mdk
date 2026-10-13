//! Test-only, bounded diagnostic output; no payloads, identifiers or authority.
use cgka_traits::storage::StorageError;
pub(super) fn storage_category(error: &StorageError) -> &'static str {
    match error {
        StorageError::Serialization(message)
            if message == "conflicting mirrored chat observation" =>
        {
            "catalog_conflict"
        }
        StorageError::Serialization(message)
            if message == "invalid mirrored message observation" =>
        {
            "invalid_record_observation"
        }
        StorageError::Serialization(message) if message == "invalid mirrored chat observation" => {
            "invalid_observation"
        }
        StorageError::Serialization(message)
            if message == "automatic sharing original unavailable" =>
        {
            "original_unavailable"
        }
        StorageError::Backend(message) if message.contains("mirrored catalog regression") => {
            "catalog_regression_trigger"
        }
        StorageError::Backend(message) if message.contains("source lineage refused") => {
            "lineage_trigger"
        }
        StorageError::Backend(message)
            if message.contains("source origin observation regressed") =>
        {
            "origin_current_trigger"
        }
        StorageError::Backend(_) => "backend_other",
        StorageError::Serialization(_) => "serialization_other",
        StorageError::Closed(_) => "closed",
        StorageError::Capacity(_) => "capacity",
        _ => "other",
    }
}
pub(super) fn json_category(error: &serde_json::Error) -> &'static str {
    match error.classify() {
        serde_json::error::Category::Io => "io",
        serde_json::error::Category::Syntax => "syntax",
        serde_json::error::Category::Data => "data",
        serde_json::error::Category::Eof => "eof",
    }
}
pub(super) fn report(
    stage: &'static str,
    category: &str,
    query: impl FnOnce() -> Result<Option<String>, &'static str>,
    mut publish: impl FnMut(&str),
) {
    // Publish the real boundary first. An optional diagnostic read cannot erase
    // it, change its category, or interrupt original runtime cleanup.
    publish(&format!(
        "rejoin boundary diagnostic: stage={stage}, category={category}"
    ));
    match query() {
        Ok(Some(comparison)) => publish(&format!("rejoin comparison diagnostic: {comparison}")),
        Ok(None) => {}
        Err(category) => publish(&format!(
            "rejoin comparison diagnostic: query_category={category}"
        )),
    }
}
#[test]
fn failed_diagnostic_query_keeps_the_original_boundary_before_its_own_failure() {
    let lines = std::cell::RefCell::new(Vec::new());
    report(
        "catalog_sql",
        "catalog_conflict",
        || {
            assert_eq!(
                lines.borrow().as_slice(),
                &["rejoin boundary diagnostic: stage=catalog_sql, category=catalog_conflict"]
            );
            Err("closed")
        },
        |line| lines.borrow_mut().push(line.to_owned()),
    );
    assert_eq!(
        lines.into_inner(),
        [
            "rejoin boundary diagnostic: stage=catalog_sql, category=catalog_conflict",
            "rejoin comparison diagnostic: query_category=closed"
        ]
    );
}

struct TraceRegistration {
    owner: &'static str,
    peers: Vec<([u8; 32], &'static str)>,
}
fn traced_roots()
-> &'static std::sync::Mutex<std::collections::BTreeMap<std::path::PathBuf, TraceRegistration>> {
    static ROOTS: std::sync::OnceLock<
        std::sync::Mutex<std::collections::BTreeMap<std::path::PathBuf, TraceRegistration>>,
    > = std::sync::OnceLock::new();
    ROOTS.get_or_init(Default::default)
}
pub(super) struct TraceRoot(std::path::PathBuf);
impl Drop for TraceRoot {
    fn drop(&mut self) {
        traced_roots()
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .remove(&self.0);
    }
}
pub(super) fn trace_root(root: &std::path::Path, owner: &'static str) -> TraceRoot {
    assert!(matches!(
        owner,
        "source" | "source_a" | "source_b" | "recipient"
    ));
    let mut roots = traced_roots().lock().unwrap();
    assert!(
        roots.len() < 8
            && roots
                .insert(
                    root.to_owned(),
                    TraceRegistration {
                        owner,
                        peers: Vec::new()
                    }
                )
                .is_none()
    );
    TraceRoot(root.to_owned())
}
pub(super) fn owner(root: &std::path::Path) -> Option<&'static str> {
    traced_roots()
        .lock()
        .unwrap()
        .get(root)
        .map(|registration| registration.owner)
}
pub(super) fn label_peers(root: &std::path::Path, peers: &[([u8; 32], &'static str)]) {
    assert!(
        peers.len() <= 3
            && peers
                .iter()
                .all(|(_, label)| matches!(*label, "source_a" | "source_b" | "recipient"))
    );
    let mut roots = traced_roots().lock().unwrap();
    let registration = roots
        .get_mut(root)
        .expect("actual fixture trace must be registered");
    assert!(registration.peers.is_empty());
    registration.peers = peers.to_vec();
}
pub(super) fn peer(root: &std::path::Path, device: &[u8]) -> &'static str {
    traced_roots()
        .lock()
        .unwrap()
        .get(root)
        .and_then(|registration| {
            registration
                .peers
                .iter()
                .find(|(peer, _)| peer.as_slice() == device)
                .map(|(_, label)| *label)
        })
        .unwrap_or("unknown")
}
pub(crate) fn sharing_category(error: &crate::AccountSharingError) -> &'static str {
    match error {
        crate::AccountSharingError::Unsupported => "unsupported",
        crate::AccountSharingError::NotReady => "not_ready",
        crate::AccountSharingError::Closed => "closed",
        crate::AccountSharingError::StaleRevision => "stale_revision",
        crate::AccountSharingError::RuntimeUnavailable => "runtime_unavailable",
    }
}
