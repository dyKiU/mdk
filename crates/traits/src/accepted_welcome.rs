//! Experimental device-local facts produced only by a fully accepted MLS Welcome.
//! These facts do not authorize enrollment, roster settlement, or history access.
use crate::types::{EpochId, GroupId, MemberId, MessageId};
use serde::{Deserialize, Serialize};

/// Immutable evidence from the atomic accepted-join transaction. No Debug:
/// identifiers and signature keys must not escape into diagnostics.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AcceptedWelcomeReceipt {
    pub welcome_id: MessageId,
    pub content_id: MessageId,
    pub group_id: GroupId,
    pub consumed_key_package_ref: Vec<u8>,
    pub own_account: MemberId,
    pub own_signature_public_key: Vec<u8>,
    pub welcomer_account: MemberId,
    pub welcomer_signature_public_key: Vec<u8>,
    pub joined_epoch: EpochId,
    /// SHA256 commitment to the authenticated joined epoch. No exporter secret;
    /// never a replay-state fingerprint or a claim of cross-device settlement.
    pub joined_epoch_authenticator_digest: [u8; 32],
}
