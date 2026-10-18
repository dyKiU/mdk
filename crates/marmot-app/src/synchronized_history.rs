//! Local read-only presentation of committed source-attested logical history.
use crate::{GroupId, MarmotApp, MediaAttachmentOutcome};

#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum SynchronizedHistoryReadError {
    #[error("Synchronized history is unsupported by this build")]
    Unsupported,
    #[error("Invalid synchronized history query")]
    InvalidQuery,
    #[error("Synchronized history storage is unavailable")]
    Unavailable,
    #[error("Invalid synchronized history logical record")]
    InvalidRecord,
}

/// Source-attested archive content, never independent MLS authentication or consent.
#[derive(Clone)]
pub struct ArchivedHistoryRecord {
    pub message_id: [u8; 32],
    pub author: [u8; 32],
    pub created_at: u64,
    pub expires_at: Option<u64>,
    pub deleted: bool,
    pub content: String,
    pub tags: Vec<Vec<String>>,
    pub media_attachments: Vec<MediaAttachmentOutcome>,
    pub transfer_id: [u8; 32],
    pub source_device: [u8; 32],
    pub manifest_digest: [u8; 32],
}
impl std::fmt::Debug for ArchivedHistoryRecord {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ArchivedHistoryRecord")
            .finish_non_exhaustive()
    }
}
/// Keyset order is message ID, not timestamp. Cursor is read-only, never a grant.
#[derive(Clone, Debug)]
pub struct ArchivedHistoryPage {
    pub records: Vec<ArchivedHistoryRecord>,
    pub next_message_id: Option<[u8; 32]>,
}

impl MarmotApp {
    /// Read committed history separately from authenticated live conversations.
    /// This performs no relay I/O, acknowledgment, moderation or media acquisition.
    pub fn synchronized_history_page(
        &self,
        account_ref: &str,
        group: &GroupId,
        after_message_id: Option<[u8; 32]>,
        limit: u32,
    ) -> Result<ArchivedHistoryPage, SynchronizedHistoryReadError> {
        #[cfg(not(feature = "experimental-device-sync"))]
        {
            let _ = (account_ref, group, after_message_id, limit);
            Err(SynchronizedHistoryReadError::Unsupported)
        }
        #[cfg(feature = "experimental-device-sync")]
        {
            if !(1..=200).contains(&limit)
                || group.as_slice().is_empty()
                || group.as_slice().len() > 255
            {
                return Err(SynchronizedHistoryReadError::InvalidQuery);
            }
            let home = self.account_home();
            let account = match home.account(account_ref) {
                Ok(account) => account,
                Err(marmot_account::AccountHomeError::UnknownAccount(_)) => {
                    // Resolve a legacy label directory by its actual public identity.
                    let id = crate::account_id_hex_from_ref(account_ref)
                        .map_err(|_| SynchronizedHistoryReadError::Unavailable)?;
                    home.accounts()
                        .map_err(|_| SynchronizedHistoryReadError::Unavailable)?
                        .into_iter()
                        .find(|account| account.account_id_hex == id)
                        .ok_or(SynchronizedHistoryReadError::Unavailable)?
                }
                Err(_) => return Err(SynchronizedHistoryReadError::Unavailable),
            };
            self.ensure_account_state(&account.label)
                .map_err(|_| SynchronizedHistoryReadError::Unavailable)?;
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_err(|_| SynchronizedHistoryReadError::Unavailable)?
                .as_secs();
            let rows = self
                .account_storage(&account.label)
                .map_err(|_| SynchronizedHistoryReadError::Unavailable)?
                .app_storage().synchronized_history_page(
                    &hex::encode(group.as_slice()),
                    after_message_id.as_ref(),
                    limit as usize,
                    now,
                )
                .map_err(|_| SynchronizedHistoryReadError::Unavailable)?;
            let next_message_id = (rows.len() == limit as usize)
                .then(|| rows.last().map(|row| row.record.message_id))
                .flatten();
            let records = rows
                .into_iter()
                .map(|row| present_archive(row, self.config.allow_loopback_blob_endpoints))
                .collect::<Result<_, _>>()?;
            Ok(ArchivedHistoryPage {
                records,
                next_message_id,
            })
        }
    }
}

#[cfg(feature = "experimental-device-sync")]
fn present_archive(
    row: storage_sqlite::ProvenancedSynchronizedHistoryRecord,
    allow_loopback: bool,
) -> Result<ArchivedHistoryRecord, SynchronizedHistoryReadError> {
    let record = row.record;
    if record.kind != 9 || record.payload.len() > storage_sqlite::MAX_HISTORY_ARCHIVE_BYTES {
        return Err(SynchronizedHistoryReadError::InvalidRecord);
    }
    let (content, tags) = if record.deleted {
        if !record.payload.is_empty() {
            return Err(SynchronizedHistoryReadError::InvalidRecord);
        }
        (String::new(), Vec::new())
    } else {
        let value: (String, Vec<Vec<String>>) = serde_json::from_slice(&record.payload)
            .map_err(|_| SynchronizedHistoryReadError::InvalidRecord)?;
        if serde_json::to_vec(&value).map_err(|_| SynchronizedHistoryReadError::InvalidRecord)?
            != record.payload
        {
            return Err(SynchronizedHistoryReadError::InvalidRecord);
        }
        value
    };
    let media_attachments = crate::media_attachment_outcomes_from_tags(&tags, None, allow_loopback);
    Ok(ArchivedHistoryRecord {
        message_id: record.message_id,
        author: record.author,
        created_at: record.created_at,
        expires_at: record.expires_at,
        deleted: record.deleted,
        content,
        tags,
        media_attachments,
        transfer_id: row.transfer_id,
        source_device: row.source_device,
        manifest_digest: row.manifest_digest,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    #[cfg(feature = "experimental-device-sync")]
    use storage_sqlite::{
        SynchronizedHistoryBinding, SynchronizedHistoryManifest, SynchronizedHistoryRecord,
        synchronized_history_chunk_digest,
    };

    #[cfg(feature = "experimental-device-sync")]
    #[test]
    fn committed_history_has_read_only_content_provenance_and_keyset_pages() {
        let dir = tempfile::tempdir().unwrap();
        let home = marmot_account::AccountHome::open(dir.path());
        let account = home.create_account("alice").unwrap();
        home.create_account("bob").unwrap();
        let app = MarmotApp::with_relay(dir.path(), "wss://history.example");
        app.ensure_account_state("alice").unwrap();
        let group = GroupId::new(vec![8; 16]);
        let records: Vec<_> = [1, 2]
            .into_iter()
            .map(|id| SynchronizedHistoryRecord {
                message_id: [id; 32],
                author: [7; 32],
                created_at: 100,
                kind: 9,
                payload: serde_json::to_vec(&(format!("archived {id}"), Vec::<Vec<String>>::new()))
                    .unwrap(),
                expires_at: None,
                deleted: false,
            })
            .collect();
        let binding = SynchronizedHistoryBinding {
            transfer_id: [9; 32],
            account_id: hex::decode(&account.account_id_hex)
                .unwrap()
                .try_into()
                .unwrap(),
            source_device: [2; 32],
            recipient_device: [3; 32],
            group_id_hex: hex::encode(group.as_slice()),
            snapshot_timestamp_ceiling: 200,
        };
        let manifest = SynchronizedHistoryManifest {
            chunk_digests: vec![synchronized_history_chunk_digest(&binding, 0, &records).unwrap()],
            binding,
            retain_since: 0,
            max_record_lifetime_seconds: None,
        };
        let storage = app.account_storage("alice").unwrap();
        storage.app_storage().admit_synchronized_history(&manifest).unwrap();
        assert!(
            storage
                .app_storage().import_synchronized_history_chunk(&manifest, 0, &records, 120, &|| false)
                .unwrap()
                .complete
        );
        let first = app
            .synchronized_history_page(&account.account_id_hex, &group, None, 1)
            .expect("committed archive must be available through the public App query");
        assert_eq!(first.records.len(), 1);
        assert_eq!(first.records[0].message_id, [1; 32]);
        assert_eq!(first.records[0].content, "archived 1");
        assert_eq!(first.records[0].source_device, [2; 32]);
        assert_eq!(first.records[0].transfer_id, [9; 32]);
        assert_eq!(first.next_message_id, Some([1; 32]));
        let next = app
            .synchronized_history_page("alice", &group, first.next_message_id, 2)
            .unwrap();
        assert_eq!(next.records.len(), 1);
        assert_eq!(next.records[0].message_id, [2; 32]);
        assert_eq!(next.next_message_id, None);
        assert!(
            app.synchronized_history_page("bob", &group, None, 2)
                .unwrap()
                .records
                .is_empty()
        );
        assert!(
            app.synchronized_history_page("alice", &GroupId::new(vec![8; 32]), None, 2)
                .unwrap()
                .records
                .is_empty()
        );
        app.close_storage().unwrap();
    }

    #[cfg(not(feature = "experimental-device-sync"))]
    #[test]
    fn default_history_read_is_unsupported_before_account_or_storage_effects() {
        let dir = tempfile::tempdir().unwrap();
        let app = MarmotApp::with_relay(dir.path(), "wss://history.example");
        assert!(matches!(
            app.synchronized_history_page("missing", &GroupId::new(Vec::new()), None, u32::MAX),
            Err(SynchronizedHistoryReadError::Unsupported)
        ));
        assert!(!app.account_storage_cached_for_test("missing"));
        app.close_storage().unwrap();
    }
}

#[cfg(all(test, feature = "experimental-device-sync"))]
#[path = "synchronized_history/tests.rs"]
mod controls;
