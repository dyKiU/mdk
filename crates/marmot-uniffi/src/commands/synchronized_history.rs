//! Local archive reads use App's retention and projection boundary.
use crate::{ArchivedHistoryPageFfi, Marmot, MarmotKitError};

#[uniffi::export]
impl Marmot {
    /// Read source-attested committed history separately from the live conversation.
    /// Uses message-ID keyset order and performs no relay or media acquisition.
    pub fn synchronized_history_page(
        &self,
        account_ref: String,
        group_id_hex: String,
        after_message_id_hex: Option<String>,
        limit: u32,
    ) -> Result<ArchivedHistoryPageFfi, MarmotKitError> {
        #[cfg(not(feature = "experimental-device-sync"))]
        {
            let _ = (account_ref, group_id_hex, after_message_id_hex, limit);
            Err(MarmotKitError::SynchronizedHistoryUnsupported)
        }
        #[cfg(feature = "experimental-device-sync")]
        {
            if !(1..=200).contains(&limit) || group_id_hex.trim().len() > 510 {
                return Err(MarmotKitError::SynchronizedHistoryInvalidQuery);
            }
            let group = crate::conversions::group_id_from_hex(&group_id_hex)
                .map_err(|_| MarmotKitError::SynchronizedHistoryInvalidQuery)?;
            let after = after_message_id_hex
                .map(|id| {
                    if id.len() != 64 {
                        return Err(MarmotKitError::SynchronizedHistoryInvalidQuery);
                    }
                    hex::decode(id)
                        .map_err(|_| MarmotKitError::SynchronizedHistoryInvalidQuery)?
                        .try_into()
                        .map_err(|_| MarmotKitError::SynchronizedHistoryInvalidQuery)
                })
                .transpose()?;
            Ok(self
                .app
                .synchronized_history_page(&account_ref, &group, after, limit)?
                .into())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(feature = "experimental-device-sync")]
    #[tokio::test]
    async fn native_query_bounds_refuse_before_unknown_account_or_worker_effects() {
        let dir = tempfile::tempdir().unwrap();
        let app = marmot_app::MarmotApp::with_relay(dir.path(), "wss://relay.example");
        let kit = Marmot {
            runtime: app.runtime(),
            app,
        };
        for (group, cursor, limit) in [
            ("ab".repeat(16), None, 0),
            ("ab".repeat(16), None, 201),
            ("ab".repeat(256), None, 1),
            ("".into(), None, 1),
            ("invalid".into(), None, 1),
            ("ab".repeat(16), Some("ab".repeat(31)), 1),
            ("ab".repeat(16), Some("zz".repeat(32)), 1),
        ] {
            assert!(matches!(
                kit.synchronized_history_page("missing".into(), group, cursor, limit),
                Err(MarmotKitError::SynchronizedHistoryInvalidQuery)
            ));
        }
        assert!(
            kit.runtime
                .accounts()
                .managed_accounts()
                .unwrap()
                .is_empty()
        );
        kit.runtime.shutdown_and_close().await.unwrap();
    }

    #[cfg(feature = "experimental-device-sync")]
    #[tokio::test]
    async fn native_query_reads_empty_archive_for_known_account_without_worker() {
        let dir = tempfile::tempdir().unwrap();
        let home = marmot_account::AccountHome::open(dir.path());
        let account = home.create_account("alice").unwrap();
        home.set_account_signed_out(&account.label, true).unwrap();
        let app = marmot_app::MarmotApp::with_relay(dir.path(), "wss://relay.example");
        let kit = Marmot {
            runtime: app.runtime(),
            app,
        };
        let page = kit
            .synchronized_history_page(account.account_id_hex, "ab".repeat(16), None, 1)
            .expect("known account must have an empty readable committed archive");
        assert!(page.records.is_empty());
        assert!(page.next_message_id_hex.is_none());
        let accounts = kit.runtime.accounts().managed_accounts().unwrap();
        assert_eq!(accounts.len(), 1);
        assert!(accounts[0].signed_out);
        assert!(!accounts[0].running);
        kit.runtime.shutdown_and_close().await.unwrap();
    }

    #[cfg(not(feature = "experimental-device-sync"))]
    #[tokio::test]
    async fn default_native_query_refuses_before_input_or_account_effects() {
        let dir = tempfile::tempdir().unwrap();
        let app = marmot_app::MarmotApp::with_relay(dir.path(), "wss://relay.example");
        let kit = Marmot {
            runtime: app.runtime(),
            app,
        };
        assert!(matches!(
            kit.synchronized_history_page(
                "missing".into(),
                "invalid".into(),
                Some("bad".into()),
                0
            ),
            Err(MarmotKitError::SynchronizedHistoryUnsupported)
        ));
        assert!(
            kit.runtime
                .accounts()
                .managed_accounts()
                .unwrap()
                .is_empty()
        );
        kit.runtime.shutdown_and_close().await.unwrap();
    }
}
