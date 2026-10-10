//! Explicit one-group device removal boundary.
//!
//! A target signer is a selector, never authority. A usable action must originate
//! from fresh authenticated Core state and a new explicit administrator review.
use crate::{GroupId, runtime::AccountManager};
#[cfg(feature = "experimental-device-sync")]
pub(crate) mod enabled;

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum GroupDeviceRevocationError {
    #[error("Device revocation is unsupported by this build")]
    Unsupported,
    #[error("Device revocation is not ready")]
    NotReady,
    #[error("Device revocation original action is closed")]
    Closed,
    #[error("Device revocation selection is unavailable")]
    InvalidSelection,
    #[error("Device revocation original action is already active")]
    Busy,
    #[error("Device revocation runtime is unavailable")]
    RuntimeUnavailable,
}

/// Observation for explicit review; it cannot authorize or reconstruct a Remove.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GroupDeviceRevocationSnapshot {
    pub revision: u64,
    pub group: GroupId,
    pub epoch: u64,
    pub target_leaf_index: u32,
    pub target_device: Vec<u8>,
    pub surviving_same_account_leaves: u32,
}

/// Opaque original administrator action for exactly one ordinary group.
///
/// Linked-device observations cannot construct this owner or authorize removal.
pub struct GroupDeviceRevocation {
    #[cfg(feature = "experimental-device-sync")]
    original: std::sync::Arc<enabled::State>,
    #[cfg(feature = "experimental-device-sync")]
    manager: AccountManager,
    #[cfg(feature = "experimental-device-sync")]
    account: String,
    #[cfg(not(feature = "experimental-device-sync"))]
    _private: (),
}

impl AccountManager {
    pub async fn begin_group_device_revocation(
        &self,
        account: &str,
        group: &GroupId,
        target_device: Vec<u8>,
    ) -> Result<GroupDeviceRevocation, GroupDeviceRevocationError> {
        #[cfg(feature = "experimental-device-sync")]
        {
            let original = self
                .begin_original_group_device_revocation(account, group, target_device)
                .await?;
            Ok(GroupDeviceRevocation {
                original,
                manager: self.clone(),
                account: account.to_owned(),
            })
        }
        #[cfg(not(feature = "experimental-device-sync"))]
        {
            let _ = (account, group, target_device);
            Err(GroupDeviceRevocationError::Unsupported)
        }
    }
}

impl GroupDeviceRevocation {
    pub async fn snapshot(
        &self,
    ) -> Result<GroupDeviceRevocationSnapshot, GroupDeviceRevocationError> {
        #[cfg(feature = "experimental-device-sync")]
        {
            self.manager
                .observe_original_group_device_revocation(&self.account, self.original.clone())
                .await
        }
        #[cfg(not(feature = "experimental-device-sync"))]
        {
            Err(GroupDeviceRevocationError::Unsupported)
        }
    }
    pub fn cancel(&self) {
        #[cfg(feature = "experimental-device-sync")]
        self.original.cancel();
    }
}
impl Drop for GroupDeviceRevocation {
    fn drop(&mut self) {
        self.cancel();
    }
}

#[cfg(all(test, not(feature = "experimental-device-sync")))]
mod tests {
    use super::*;
    use crate::{MarmotApp, MarmotAppRuntime};

    #[tokio::test]
    async fn default_group_device_revocation_is_unsupported_before_account_or_worker_effects() {
        let dir = tempfile::tempdir().unwrap();
        let runtime =
            MarmotAppRuntime::new(MarmotApp::with_relay(dir.path(), "wss://relay.example"));
        let accounts = runtime.accounts();
        assert!(matches!(
            accounts
                .begin_group_device_revocation("missing", &GroupId::new(vec![]), vec![0; 600_000])
                .await,
            Err(GroupDeviceRevocationError::Unsupported)
        ));
        assert!(accounts.managed_accounts().unwrap().is_empty());
        let original = GroupDeviceRevocation { _private: () };
        assert!(matches!(
            original.snapshot().await,
            Err(GroupDeviceRevocationError::Unsupported)
        ));
        original.cancel();
        assert!(accounts.managed_accounts().unwrap().is_empty());
        runtime.shutdown_and_close().await.unwrap();
    }
}
