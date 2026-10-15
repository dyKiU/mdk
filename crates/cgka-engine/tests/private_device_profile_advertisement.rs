//! Actual signed KeyPackage advertising must reflect compiled runtime support.
use async_trait::async_trait;
use cgka_engine::{EngineBuilder, key_package::key_package_metadata};
use cgka_traits::device_group_genesis::PRIVATE_DEVICE_GROUP_COMPONENT_ID;
use cgka_traits::engine::CgkaEngine;
use cgka_traits::error::PeelerError;
use cgka_traits::group_context::GroupContextSnapshot;
use cgka_traits::ingest::PeeledMessage;
use cgka_traits::peeler::TransportPeeler;
use cgka_traits::transport::{EncryptedPayload, TransportMessage};
use cgka_traits::types::MemberId;
mod support;
struct UnusedPeeler;
#[async_trait]
impl TransportPeeler for UnusedPeeler {
    async fn peel_group_message(
        &self,
        _: &TransportMessage,
        _: &GroupContextSnapshot,
    ) -> Result<PeeledMessage, PeelerError> {
        panic!("KeyPackage test does not ingest");
    }
    async fn peel_welcome(&self, _: &TransportMessage) -> Result<PeeledMessage, PeelerError> {
        panic!("KeyPackage test does not join");
    }
    async fn wrap_group_message(
        &self,
        _: &EncryptedPayload,
        _: &GroupContextSnapshot,
    ) -> Result<TransportMessage, PeelerError> {
        panic!("KeyPackage test does not send");
    }
    async fn wrap_welcome(
        &self,
        _: &EncryptedPayload,
        _: &MemberId,
    ) -> Result<TransportMessage, PeelerError> {
        panic!("KeyPackage test does not invite");
    }
}
#[tokio::test]
async fn actual_signed_key_package_cannot_advertise_uncompiled_private_device_profile() {
    let mut components = cgka_traits::app_components::default_group_components();
    // Caller configuration cannot manufacture compiled backend support.
    components.insert(PRIVATE_DEVICE_GROUP_COMPONENT_ID);
    let mut engine = EngineBuilder::new(storage_sqlite::SqliteAccountStorage::in_memory().unwrap())
        .identity(support::account_identity(b"profile-advertisement"))
        .account_identity_proof_signer(support::proof_signer(b"profile-advertisement"))
        .supported_app_components(components)
        .peeler(Box::new(UnusedPeeler))
        .build()
        .unwrap();
    let package = engine.fresh_key_package().await.unwrap();
    let metadata = key_package_metadata(&package).unwrap();
    assert_eq!(
        metadata
            .app_components
            .contains(&PRIVATE_DEVICE_GROUP_COMPONENT_ID),
        cfg!(feature = "experimental-device-sync")
    );
}
