//! Source-epoch leaf evidence produced by authenticated MLS processing.
//!
//! This fact is not an enrollment or history permission. A control consumer
//! must compare its group, epoch and branch with authoritative settled state.
use crate::types::EpochId;
use serde::{Deserialize, Serialize};

/// Exact leaf that authenticated an application while its source tree was live.
/// Historical direct processing cannot reconstruct this from the current tree.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SourceLeafProof {
    pub leaf_index: u32,
    pub signature_public_key: Vec<u8>,
    pub epoch: EpochId,
    pub epoch_authenticator_digest: [u8; 32],
}

impl std::fmt::Debug for SourceLeafProof {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("SourceLeafProof(<redacted>)")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::engine::GroupEvent;
    use crate::types::{GroupId, MemberId, MessageId};

    #[test]
    fn legacy_event_omits_and_decodes_absent_source_leaf() {
        let event = GroupEvent::MessageReceived {
            group_id: GroupId::new(vec![1]),
            message_id: MessageId::new(vec![2]),
            sender: MemberId::new(vec![3]),
            epoch: EpochId(4),
            source_leaf: None,
            payload: Vec::new(),
            retention: None,
            authority: None,
            encrypted_media_secret: None,
        };
        let value = serde_json::to_value(&event).unwrap();
        assert!(value["MessageReceived"].get("source_leaf").is_none());
        let decoded: GroupEvent = serde_json::from_value(value).unwrap();
        assert!(matches!(
            decoded,
            GroupEvent::MessageReceived {
                source_leaf: None,
                ..
            }
        ));
    }

    #[test]
    fn source_leaf_debug_never_discloses_evidence() {
        let proof = SourceLeafProof {
            leaf_index: 7,
            signature_public_key: vec![9; 32],
            epoch: EpochId(11),
            epoch_authenticator_digest: [13; 32],
        };
        assert_eq!(format!("{proof:?}"), "SourceLeafProof(<redacted>)");
        let decoded: SourceLeafProof =
            serde_json::from_slice(&serde_json::to_vec(&proof).unwrap()).unwrap();
        assert!(decoded == proof);
    }
}
