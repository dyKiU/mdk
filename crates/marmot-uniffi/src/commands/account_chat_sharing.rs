//! Thin forwards of the original account-wide approval, never host-supplied grants.
use crate::{AccountSharingSnapshotFfi, AccountSharingTargetsFfi, Marmot, MarmotKitError};
use std::sync::Arc;
#[derive(uniffi::Object)]
pub struct AccountSharingApproval {
    inner: marmot_app::AccountSharingApproval,
}
#[marmot_uniffi_macros::on_tokio_runtime]
#[uniffi::export]
impl Marmot {
    /// Observe current actual same-account Completed protected peers. No approval.
    pub async fn account_chat_sharing_targets(
        &self,
        account_ref: String,
    ) -> Result<AccountSharingTargetsFfi, MarmotKitError> {
        Ok(self
            .runtime
            .accounts()
            .account_chat_sharing_targets(&account_ref)
            .await?
            .into())
    }
    /// Start one original review covering existing/future chats, history and messaging.
    pub async fn begin_account_chat_sharing(
        &self,
        account_ref: String,
        recipient_device: Vec<u8>,
    ) -> Result<Arc<AccountSharingApproval>, MarmotKitError> {
        let inner = self
            .runtime
            .accounts()
            .begin_account_chat_sharing(&account_ref, recipient_device)
            .await?;
        Ok(Arc::new(AccountSharingApproval { inner }))
    }
    /// Observe addressed authenticated original requests; polling never approves.
    pub async fn pending_account_chat_sharing(
        &self,
        account_ref: String,
    ) -> Result<Vec<Arc<AccountSharingApproval>>, MarmotKitError> {
        Ok(self
            .runtime
            .accounts()
            .pending_account_chat_sharing(&account_ref)
            .await?
            .into_iter()
            .map(|inner| Arc::new(AccountSharingApproval { inner }))
            .collect())
    }
}
#[marmot_uniffi_macros::on_tokio_runtime]
#[uniffi::export]
impl AccountSharingApproval {
    /// Explicitly approve this exact original at the displayed revision.
    pub async fn approve(&self, displayed_revision: u64) -> Result<(), MarmotKitError> {
        Ok(self.inner.approve(displayed_revision).await?)
    }
}

#[cfg(all(test, feature = "experimental-device-sync"))]
pub(crate) async fn verify_account_sharing_binding_originals(kits: &[Marmot]) {
    use std::time::Duration;
    let targets = kits[0]
        .account_chat_sharing_targets("test".into())
        .await
        .unwrap();
    assert_eq!(targets.targets.len(), 1);
    let peer = targets.targets[0].device.clone();
    let original = kits[0]
        .begin_account_chat_sharing("test".into(), peer.clone())
        .await
        .unwrap();
    let alias = original.clone();
    drop(original);
    let view = alias.snapshot().unwrap();
    assert_eq!(view.recipient_device, peer);
    assert!(!view.approved && !view.complete);
    assert!(matches!(
        alias.approve(view.revision + 1).await,
        Err(MarmotKitError::AccountSharingStaleRevision)
    ));
    alias.cancel();
    assert!(matches!(
        alias.approve(view.revision).await,
        Err(MarmotKitError::AccountSharingClosed)
    ));
    let source = kits[0]
        .begin_account_chat_sharing("test".into(), peer)
        .await
        .unwrap();
    let initial = source.snapshot().unwrap();
    source.approve(initial.revision).await.unwrap();
    let recipient = tokio::time::timeout(Duration::from_secs(30), async {
        loop {
            let pending = kits[1]
                .pending_account_chat_sharing("test".into())
                .await
                .unwrap();
            if let Some(original) = pending.into_iter().next() {
                break original;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await
    .unwrap();
    let review = recipient.snapshot().unwrap();
    assert_eq!(review.source_device, initial.source_device);
    assert_eq!(review.recipient_device, initial.recipient_device);
    assert!(!review.approved);
    assert!(matches!(
        recipient.approve(review.revision + 1).await,
        Err(MarmotKitError::AccountSharingStaleRevision)
    ));
    recipient.approve(review.revision).await.unwrap();
    tokio::time::timeout(Duration::from_secs(30), async {
        loop {
            if source.snapshot().unwrap().complete && recipient.snapshot().unwrap().complete {
                break;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await
    .unwrap();
}
#[uniffi::export]
impl AccountSharingApproval {
    /// Read authenticated review and completion; DTOs never reconstruct originals.
    pub fn snapshot(&self) -> Result<AccountSharingSnapshotFfi, MarmotKitError> {
        Ok(self.inner.snapshot()?.into())
    }
    /// Cancel the unfinished original; does not revoke an already completed policy.
    pub fn cancel(&self) {
        self.inner.cancel();
    }
}

#[cfg(all(test, not(feature = "experimental-device-sync")))]
mod tests {
    use super::*;
    #[tokio::test]
    async fn default_account_sharing_bindings_refuse_before_inputs_or_effects() {
        let dir = tempfile::tempdir().unwrap();
        let app = marmot_app::MarmotApp::with_relay(dir.path(), "wss://relay.example");
        let kit = Marmot {
            runtime: app.runtime(),
            app,
        };
        assert!(matches!(
            kit.account_chat_sharing_targets("missing".into()).await,
            Err(MarmotKitError::AccountSharingUnsupported)
        ));
        assert!(matches!(
            kit.begin_account_chat_sharing("missing".into(), vec![0; 65536])
                .await,
            Err(MarmotKitError::AccountSharingUnsupported)
        ));
        assert!(matches!(
            kit.pending_account_chat_sharing("missing".into()).await,
            Err(MarmotKitError::AccountSharingUnsupported)
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
