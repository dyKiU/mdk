//! Original selected-consent private packages. No publication or join permission.
use super::offer::{OFFER, Offer};
use super::*;
use cgka_traits::accepted_device_group_anchor::DeviceGroupAnchorRoster;
use cgka_traits::device_group_genesis::GenesisLeaf;
use cgka_traits::engine::KeyPackage;
use cgka_traits::selected_chat_key_package::*;
use openmls::prelude::{KeyPackageBundle, KeyPackageRef, MlsMessageOut};
use openmls_traits::storage::StorageProvider as OpenMlsStorageProvider;
use tls_codec::{Deserialize as _, Serialize as _};

/// Trusted runtime's original process owner. Implementations check only memory:
/// fixed deadline, exact generation/revision, cancellation and original context.
/// A row or imported observation must never construct this lease.
pub trait SelectedChatPackageLease: Send {
    fn check_original(
        &mut self,
        scope: &SelectedChatPurposeScope,
        context: &SelectedChatPurposeContext,
    ) -> Result<(), EngineError>;
}

/// Bounded signed metadata plus exact negative cleanup identity, never a grant.
pub struct SelectedChatPackageOffer {
    wire: Vec<u8>,
    scope: SelectedChatPurposeScope,
    reference: [u8; 32],
}
impl SelectedChatPackageOffer {
    pub fn into_parts(self) -> (Vec<u8>, SelectedChatPurposeScope, [u8; 32]) {
        (self.wire, self.scope, self.reference)
    }
}

impl<S: StorageProvider> Engine<S> {
    /// Persist exactly one single-use bundle and independent purpose under the
    /// original approved owner. Signing/encoding and the live tail are atomic.
    pub fn resolve_selected_chat_package(
        &self,
        original: &AuthenticatedSelectedChatRequest,
        response: &[u8],
        lease: &mut dyn SelectedChatPackageLease,
    ) -> Result<SelectedChatPackageOffer, EngineError> {
        self.storage.with_transaction(|storage| {
            let purpose = storage
                .selected_chat_key_package_storage()
                .ok_or_else(denied)?;
            let request = self.authenticate_selected_chat_request(&original.wire)?;
            if request.actual != original.actual
                || self.new_protocol_profile != ProtocolProfile::Current
            {
                return Err(denied());
            }
            let consent = self.authenticate_selected_chat_consent(&request.wire, response)?;
            let local_device: [u8; 32] = self
                .identity
                .signer
                .public()
                .try_into()
                .map_err(|_| denied())?;
            if consent.source_key != local_device {
                return Err(denied());
            }
            let account: [u8; 32] = self
                .identity
                .self_id
                .as_slice()
                .try_into()
                .map_err(|_| denied())?;
            let selected = self
                .validated_settled_device_roster(&request.protected_group())?
                .ok_or_else(denied)?;
            if selected.candidate() != &request.actual {
                return Err(denied());
            }
            let scope = SelectedChatPurposeScope {
                account,
                local_device,
                generation: consent.generation,
                request_binding: request.binding(),
            };
            let context = SelectedChatPurposeContext {
                approved_response_digest: Sha256::digest(response).into(),
                protected_group: request.protected_group(),
                protected_anchor: DeviceGroupAnchorRoster {
                    epoch: request.actual.epoch,
                    epoch_authenticator_digest: request.actual.epoch_authenticator_digest,
                    leaves: request
                        .actual
                        .leaves
                        .iter()
                        .map(|leaf| {
                            Ok(GenesisLeaf {
                                account,
                                leaf_index: leaf.leaf_index,
                                signature_public_key: leaf
                                    .signature_public_key
                                    .as_slice()
                                    .try_into()
                                    .map_err(|_| denied())?,
                            })
                        })
                        .collect::<Result<_, EngineError>>()?,
                },
                protected_settlement_generation: selected.settlement_generation(),
                ordinary_group: request.ordinary_group(),
                ordinary_epoch: cgka_traits::EpochId(request.frame.ordinary.epoch),
                ordinary_own_leaf_index: request.frame.ordinary.own_index,
                ordinary_own_leaf_hash: request.frame.ordinary.own_hash.clone(),
                ordinary_roster_digest: request.frame.ordinary.roster,
            };
            lease.check_original(&scope, &context)?;
            let package = match purpose.selected_chat_key_package(&scope)? {
                Some(saved) => {
                    if saved.scope != scope
                        || saved.signature_public_key != local_device
                        || saved.context != context
                        || saved.state != SelectedChatPurposeState::Pending
                    {
                        return Err(denied());
                    }
                    saved
                }
                None => {
                    let public = self.build_key_package(storage, false)?;
                    let validated = self.parse_key_package(&public)?;
                    let reference = validated.hash_ref(&self.crypto).map_err(|_| denied())?;
                    SelectedChatPurposeKeyPackage {
                        scope: scope.clone(),
                        context: context.clone(),
                        public_bytes: public.bytes().to_vec(),
                        reference: reference.as_slice().try_into().map_err(|_| denied())?,
                        signature_public_key: local_device,
                        state: SelectedChatPurposeState::Pending,
                    }
                }
            };
            let public = KeyPackage::new(package.public_bytes.clone())
                .with_protocol_profile(ProtocolProfile::Current);
            let validated = self.parse_key_package(&public)?;
            let reference = validated.hash_ref(&self.crypto).map_err(|_| denied())?;
            let bundle: Option<KeyPackageBundle> =
                OpenMlsStorageProvider::key_package(storage.mls_storage(), &reference)
                    .map_err(|_| denied())?;
            if validated.last_resort()
                || reference.as_slice() != package.reference
                || validated.leaf_node().signature_key().as_slice() != local_device
                || crate::identity::validated_member_id_of_leaf(validated.leaf_node())?.as_slice()
                    != account
                || bundle
                    .as_ref()
                    .is_none_or(|bundle| bundle.key_package() != &validated)
            {
                return Err(denied());
            }
            let mut frame = Offer {
                protocol: OFFER.into(),
                binding: scope.request_binding,
                approved_response_digest: context.approved_response_digest,
                generation: scope.generation,
                source_index: consent.source_index,
                source_key: local_device.to_vec(),
                package: package.public_bytes.clone(),
                signature: vec![],
            };
            frame.signature = self
                .identity
                .signer
                .sign(&encode(&frame)?)
                .map_err(|_| denied())?;
            let wire = encode(&frame)?;
            purpose.put_selected_chat_key_package(&package)?;
            lease.check_original(&scope, &context)?;
            Ok(SelectedChatPackageOffer {
                wire,
                scope,
                reference: package.reference,
            })
        })
    }

    /// Negative cleanup checks exact stored bytes/reference and actual private
    /// bundle source. Terminal tombstones remain outside group snapshots.
    pub fn retire_selected_chat_package(
        &self,
        scope: &SelectedChatPurposeScope,
        reference: &[u8; 32],
    ) -> Result<(), EngineError> {
        self.storage.with_transaction(|storage| {
            let purpose = storage
                .selected_chat_key_package_storage()
                .ok_or_else(denied)?;
            let saved = purpose
                .selected_chat_key_package(scope)?
                .ok_or_else(denied)?;
            if saved.reference != *reference || saved.signature_public_key != scope.local_device {
                return Err(denied());
            }
            let encoded = tls_codec::VLBytes::from(reference.as_slice())
                .tls_serialize_detached()
                .map_err(|_| denied())?;
            let hash_ref = KeyPackageRef::tls_deserialize_exact(&encoded).map_err(|_| denied())?;
            let bundle: Option<KeyPackageBundle> =
                OpenMlsStorageProvider::key_package(storage.mls_storage(), &hash_ref)
                    .map_err(|_| denied())?;
            if let Some(bundle) = &bundle {
                let package = bundle.key_package();
                let message: MlsMessageOut = package.clone().into();
                if package.last_resort()
                    || package
                        .hash_ref(&self.crypto)
                        .map_err(|_| denied())?
                        .as_slice()
                        != reference
                    || message.tls_serialize_detached().map_err(|_| denied())? != saved.public_bytes
                    || package.leaf_node().signature_key().as_slice() != scope.local_device
                    || crate::identity::validated_member_id_of_leaf(package.leaf_node())?.as_slice()
                        != scope.account
                {
                    return Err(denied());
                }
            }
            purpose.deny_selected_chat_key_package(scope, reference)?;
            if bundle.is_some() {
                OpenMlsStorageProvider::delete_key_package(storage.mls_storage(), &hash_ref)
                    .map_err(|_| denied())?;
            }
            Ok(())
        })
    }

    /// Exclusive startup abandons old process owners; never restores approval.
    pub fn cleanup_selected_chat_packages_on_startup(&self) -> Result<(), EngineError> {
        self.storage.with_transaction(|storage| {
            let purpose = storage
                .selected_chat_key_package_storage()
                .ok_or_else(denied)?;
            for saved in purpose.selected_chat_key_packages()? {
                if saved.state == SelectedChatPurposeState::Pending {
                    self.retire_selected_chat_package(&saved.scope, &saved.reference)?;
                }
            }
            Ok(())
        })
    }
}
