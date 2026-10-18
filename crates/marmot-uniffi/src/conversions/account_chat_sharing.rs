//! Display-only authenticated device observations; never an approval constructor.
#[derive(Clone, PartialEq, Eq, uniffi::Record)]
pub struct AccountSharingSnapshotFfi {
    pub protected_group_id_hex: String,
    pub protected_epoch: u64,
    pub source_device: Vec<u8>,
    pub recipient_device: Vec<u8>,
    pub revision: u64,
    pub approved: bool,
    pub complete: bool,
}
impl From<marmot_app::AccountSharingSnapshot> for AccountSharingSnapshotFfi {
    fn from(v: marmot_app::AccountSharingSnapshot) -> Self {
        Self {
            protected_group_id_hex: hex::encode(v.protected_group.as_slice()),
            protected_epoch: v.protected_epoch,
            source_device: v.source_device,
            recipient_device: v.recipient_device,
            revision: v.revision,
            approved: v.approved,
            complete: v.complete,
        }
    }
}
impl std::fmt::Debug for AccountSharingSnapshotFfi {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AccountSharingSnapshotFfi")
            .field("revision", &self.revision)
            .field("approved", &self.approved)
            .field("complete", &self.complete)
            .finish_non_exhaustive()
    }
}
#[derive(Clone, PartialEq, Eq, uniffi::Record)]
pub struct AccountSharingTargetFfi {
    pub leaf_index: u32,
    pub device: Vec<u8>,
}
impl From<marmot_app::AccountSharingTarget> for AccountSharingTargetFfi {
    fn from(v: marmot_app::AccountSharingTarget) -> Self {
        Self {
            leaf_index: v.leaf_index,
            device: v.device,
        }
    }
}
impl std::fmt::Debug for AccountSharingTargetFfi {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AccountSharingTargetFfi")
            .field("leaf_index", &self.leaf_index)
            .finish_non_exhaustive()
    }
}
#[derive(Clone, PartialEq, Eq, uniffi::Record)]
pub struct AccountSharingTargetsFfi {
    pub protected_group_id_hex: String,
    pub protected_epoch: u64,
    pub targets: Vec<AccountSharingTargetFfi>,
}
impl From<marmot_app::AccountSharingTargets> for AccountSharingTargetsFfi {
    fn from(v: marmot_app::AccountSharingTargets) -> Self {
        Self {
            protected_group_id_hex: hex::encode(v.protected_group.as_slice()),
            protected_epoch: v.protected_epoch,
            targets: v.targets.into_iter().map(Into::into).collect(),
        }
    }
}
impl std::fmt::Debug for AccountSharingTargetsFfi {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AccountSharingTargetsFfi")
            .field("target_count", &self.targets.len())
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn account_sharing_observations_preserve_order_and_redact_identity_debug() {
        let dto = AccountSharingTargetsFfi::from(marmot_app::AccountSharingTargets {
            protected_group: cgka_traits::GroupId::new(vec![8; 16]),
            protected_epoch: 9,
            targets: vec![
                marmot_app::AccountSharingTarget {
                    leaf_index: 2,
                    device: vec![3; 32],
                },
                marmot_app::AccountSharingTarget {
                    leaf_index: 7,
                    device: vec![4; 32],
                },
            ],
        });
        assert_eq!(dto.protected_group_id_hex, "08".repeat(16));
        assert_eq!(dto.targets[1].leaf_index, 7);
        assert_eq!(dto.targets[0].device, vec![3; 32]);
        assert!(!format!("{dto:?}").contains("0808"));
        assert!(!format!("{:?}", dto.targets[0]).contains("3, 3"));
        let snapshot = AccountSharingSnapshotFfi {
            protected_group_id_hex: "sensitive-group".into(),
            protected_epoch: 9,
            source_device: vec![2; 32],
            recipient_device: vec![3; 32],
            revision: 1,
            approved: false,
            complete: false,
        };
        let debug = format!("{snapshot:?}");
        assert!(!debug.contains("sensitive-group") && !debug.contains("3, 3"));
    }
}
