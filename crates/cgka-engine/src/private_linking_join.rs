//! Dedicated private recipient path. Transport metadata and durable facts never
//! authorize a join: the trusted runtime must hold the original live SDK lease.
use crate::Engine;
use cgka_traits::device_linking_key_package::{LinkingWelcomeDenied, PurposeKeyPackage};
use cgka_traits::peeler::PrivateLinkingWelcomeContext;
use cgka_traits::private_device_invite::{
    MAX_PRIVATE_INVITE_TRANSPORT_BYTES, MAX_PRIVATE_INVITE_WELCOME_BYTES,
    MAX_PRIVATE_INVITE_WELCOME_MESSAGES,
};
use cgka_traits::{EngineError, GroupId, StorageProvider, TransportMessage};
use sha2::{Digest, Sha256};

pub(crate) struct PrivateJoinInput<'a> {
    pub context: &'a PrivateLinkingWelcomeContext,
    pub messages: &'a [TransportMessage],
}
pub(crate) fn denial() -> EngineError {
    EngineError::LinkingWelcomeDenied(LinkingWelcomeDenied::ContextMismatch)
}
pub(crate) fn check_purpose(
    saved: &PurposeKeyPackage,
    context: &PrivateLinkingWelcomeContext,
) -> Result<(), EngineError> {
    let binding = saved.context.as_ref().ok_or_else(denial)?;
    if saved.consumed
        || saved.scope.account != context.account
        || saved.scope.local_device != context.recipient
        || saved.scope.generation != context.recipient_generation
        || saved.reference != context.key_package_reference
        || saved.signature_public_key != context.recipient
        || <[u8; 32]>::from(Sha256::digest(&saved.public_bytes)) != context.key_package_digest
        || binding.nonce != context.nonce
        || binding.context_digest != context.context_digest
    {
        return Err(denial());
    }
    Ok(())
}

impl<S: StorageProvider> Engine<S> {
    /// Atomically accepts one complete bounded batch under an exact live lease.
    /// Failed/incomplete attempts create no ingress disposition. The batch never
    /// enters ordinary Welcome delivery/retry storage.
    pub async fn join_private_linking_welcome_batch(
        &mut self,
        messages: Vec<TransportMessage>,
        context: &PrivateLinkingWelcomeContext,
    ) -> Result<GroupId, EngineError> {
        use cgka_traits::ingest::{PeeledContent, PeeledMessage};
        use cgka_traits::transport::TransportEnvelope;
        use std::collections::BTreeSet;
        if messages.is_empty()
            || messages.len() > MAX_PRIVATE_INVITE_WELCOME_MESSAGES
            || context.approver_generation == 0
            || context.recipient_generation == 0
            || context.group_id.as_slice().is_empty()
            || context.group_id.as_slice().len() > 255
            || self.identity.self_id().as_slice() != context.account
            || self.identity.signer.public() != context.recipient
        {
            return Err(denial());
        }
        let mut ids = BTreeSet::new();
        let mut total = 0usize;
        for message in &messages {
            if message.payload.len() > MAX_PRIVATE_INVITE_TRANSPORT_BYTES
                || message.id.as_slice().is_empty()
                || message.id.as_slice().len() > 256
                || !ids.insert(message.id.as_slice().to_vec())
                || !matches!(&message.envelope,TransportEnvelope::Welcome{recipient} if recipient == self.identity.self_id())
            {
                return Err(denial());
            }
            total = total
                .checked_add(
                    serde_json::to_vec(message)
                        .map_err(|e| EngineError::Serialize(e.to_string()))?
                        .len(),
                )
                .ok_or_else(denial)?;
            if total > MAX_PRIVATE_INVITE_TRANSPORT_BYTES {
                return Err(denial());
            }
        }
        let bytes = self
            .peeler
            .peel_private_linking_welcome_batch(&messages, context)
            .await
            .map_err(EngineError::Peeler)?;
        if bytes.is_empty()
            || bytes.len() > MAX_PRIVATE_INVITE_WELCOME_BYTES
            || <[u8; 32]>::from(Sha256::digest(&bytes)) != context.welcome_digest
        {
            return Err(denial());
        }
        let origin = messages[0].clone();
        let peeled = PeeledMessage {
            id: origin.id.clone(),
            group_id: None,
            sender: None,
            content: PeeledContent::Welcome {
                bytes,
                created_at: None,
            },
            origin: origin.clone(),
        };
        let content_id = crate::group_lifecycle::welcome_content_dedup_id(&peeled)?;
        if self.storage.has_ingress_dedup_marker(&content_id)? {
            return Err(EngineError::WelcomeAlreadyProcessed);
        }
        self.join_peeled_welcome_with_consent(
            origin,
            peeled,
            content_id,
            None,
            Some(PrivateJoinInput {
                context,
                messages: &messages,
            }),
        )
        .await
    }
}

pub(crate) fn anchor_draft(
    saved: &PurposeKeyPackage,
    context: &PrivateLinkingWelcomeContext,
    actual: &crate::linking_welcome_policy::AuthenticatedLinkingWelcome,
    predecessor: cgka_traits::accepted_device_group_anchor::DeviceGroupAnchorRoster,
) -> Result<cgka_traits::accepted_device_group_anchor::AcceptedDeviceGroupAnchorDraft, EngineError>
{
    use cgka_traits::accepted_device_group_anchor::*;
    use cgka_traits::device_group_genesis::GenesisLeaf;
    use std::collections::BTreeSet;
    let mut indices = BTreeSet::new();
    let mut signers = BTreeSet::new();
    if predecessor.leaves.is_empty()
        || predecessor.leaves.len() > 127
        || predecessor.epoch.0.checked_add(1) != Some(actual.joined_epoch.0)
        || !actual.private_device_profile
        || actual.group_id != context.group_id
        || actual.own_account.as_slice() != context.account
        || actual.welcomer_account.as_slice() != context.account
        || actual.own_signature_public_key != context.recipient
        || actual.welcomer_signature_public_key != context.approver
        || predecessor
            .leaves
            .windows(2)
            .any(|w| w[0].leaf_index >= w[1].leaf_index)
        || predecessor.leaves.iter().any(|l| {
            l.account != context.account
                || l.signature_public_key == context.recipient
                || !indices.insert(l.leaf_index)
                || !signers.insert(l.signature_public_key)
        })
        || !predecessor.leaves.iter().any(|l| {
            l.signature_public_key == context.approver && l.leaf_index == actual.welcomer_leaf_index
        })
    {
        return Err(denial());
    }
    let leaves = actual
        .leaves
        .iter()
        .map(|l| {
            Ok(GenesisLeaf {
                leaf_index: l.leaf_index,
                account: l.account.as_slice().try_into().map_err(|_| denial())?,
                signature_public_key: l
                    .signature_public_key
                    .as_slice()
                    .try_into()
                    .map_err(|_| denial())?,
            })
        })
        .collect::<Result<Vec<_>, EngineError>>()?;
    if leaves.len() != predecessor.leaves.len() + 1
        || leaves.iter().any(|l| l.account != context.account)
        || predecessor.leaves.iter().any(|l| !leaves.contains(l))
        || !leaves.iter().any(|l| {
            l.leaf_index == actual.own_leaf_index && l.signature_public_key == context.recipient
        })
    {
        return Err(denial());
    }
    Ok(AcceptedDeviceGroupAnchorDraft {
        format_version: 1,
        purpose: saved.scope.clone(),
        group_id: actual.group_id.clone(),
        nonce: context.nonce,
        context_digest: context.context_digest,
        key_package_reference: context.key_package_reference,
        welcome_digest: context.welcome_digest,
        approver: context.approver,
        recipient: context.recipient,
        predecessor,
        successor: DeviceGroupAnchorRoster {
            epoch: actual.joined_epoch,
            epoch_authenticator_digest: actual.epoch_authenticator_digest,
            leaves,
        },
    })
}
