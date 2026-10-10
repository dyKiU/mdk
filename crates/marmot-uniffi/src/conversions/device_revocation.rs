//! Fixed captured review observations; no field can restore a Remove lease.
#[derive(Clone, PartialEq, Eq, uniffi::Record)]
pub struct DeviceRevocationSnapshotFfi {
    pub revision: u64,
    pub complete: bool,
    pub protected_group_id_hex: String,
    pub ordinary_group_ids_hex: Vec<String>,
    pub completed_group_ids_hex: Vec<String>,
    pub target_device: Vec<u8>,
}
impl From<marmot_app::DeviceRevocationSnapshot> for DeviceRevocationSnapshotFfi {
    fn from(value: marmot_app::DeviceRevocationSnapshot) -> Self {
        Self {
            revision: value.revision,
            complete: value.complete,
            protected_group_id_hex: hex::encode(value.protected_group.as_slice()),
            ordinary_group_ids_hex: value
                .ordinary_groups
                .into_iter()
                .map(|id| hex::encode(id.as_slice()))
                .collect(),
            completed_group_ids_hex: value
                .completed_groups
                .into_iter()
                .map(|id| hex::encode(id.as_slice()))
                .collect(),
            target_device: value.target_device,
        }
    }
}
impl std::fmt::Debug for DeviceRevocationSnapshotFfi {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DeviceRevocationSnapshotFfi")
            .field("revision", &self.revision)
            .field("complete", &self.complete)
            .field("ordinary_groups", &self.ordinary_group_ids_hex.len())
            .field("completed_groups", &self.completed_group_ids_hex.len())
            .finish_non_exhaustive()
    }
}
