//! Atomic private-bundle and reservation ownership, using real MLS packages.
use super::*;
use cgka_traits::device_linking_key_package::PurposeAttemptScope;
use cgka_traits::storage::StorageProvider;

#[tokio::test]
async fn purpose_factory_resolves_exact_package_and_rejects_scope_substitution() {
    let storage = SqliteAccountStorage::in_memory().unwrap();
    storage
        .ensure_account_projection_with_identity(
            "isolated-purpose-test",
            &hex::encode(pad32(ACCOUNT)),
        )
        .unwrap();
    let mut recipient = client(storage.clone());
    let public = recipient.fresh_key_package().await.unwrap();
    let signer: [u8; 32] = hex::decode(
        key_package_metadata(&public)
            .unwrap()
            .signature_public_key_hex,
    )
    .unwrap()
    .try_into()
    .unwrap();
    let account: [u8; 32] = pad32(ACCOUNT).try_into().unwrap();
    let generation = storage
        .reserve_device_linking_attempt(&account, &signer)
        .unwrap();
    let scope = PurposeAttemptScope {
        account,
        local_device: signer,
        generation,
    };
    let package = recipient.resolve_linking_key_package(&scope).await.unwrap();
    let retry = recipient.resolve_linking_key_package(&scope).await.unwrap();
    assert!(package == retry);
    assert!(!cgka_engine::key_package::is_last_resort_key_package(&package).unwrap());
    let saved = storage
        .device_linking_key_package_storage()
        .unwrap()
        .purpose_key_package()
        .unwrap()
        .unwrap();
    assert!(saved.public_bytes == package.bytes());
    assert!(saved.scope == scope);
    assert!(saved.context.is_none());
    assert!(
        recipient
            .durably_owned_key_packages()
            .unwrap()
            .contains(&public)
    );
    for wrong in [
        PurposeAttemptScope {
            generation: generation + 1,
            ..scope.clone()
        },
        PurposeAttemptScope {
            local_device: [9; 32],
            ..scope.clone()
        },
        PurposeAttemptScope {
            account: [9; 32],
            ..scope.clone()
        },
    ] {
        assert!(recipient.resolve_linking_key_package(&wrong).await.is_err());
    }
    assert!(
        storage
            .device_linking_key_package_storage()
            .unwrap()
            .purpose_key_package()
            .unwrap()
            .unwrap()
            == saved
    );
}

async fn reserve(
    storage: &SqliteAccountStorage,
    engine: &mut Engine<SqliteAccountStorage>,
) -> PurposeAttemptScope {
    let account: [u8; 32] = pad32(ACCOUNT).try_into().unwrap();
    storage
        .ensure_account_projection_with_identity("isolated-purpose-test", &hex::encode(account))
        .unwrap();
    let public = engine.fresh_key_package().await.unwrap();
    let device: [u8; 32] = hex::decode(
        key_package_metadata(&public)
            .unwrap()
            .signature_public_key_hex,
    )
    .unwrap()
    .try_into()
    .unwrap();
    let generation = storage
        .reserve_device_linking_attempt(&account, &device)
        .unwrap();
    PurposeAttemptScope {
        account,
        local_device: device,
        generation,
    }
}

#[tokio::test]
async fn cancelled_purpose_blocks_new_reservation_until_exact_cleanup() {
    let storage = SqliteAccountStorage::in_memory().unwrap();
    let mut recipient = client(storage.clone());
    let scope = reserve(&storage, &mut recipient).await;
    recipient.resolve_linking_key_package(&scope).await.unwrap();
    storage
        .finish_device_linking_attempt(
            scope.generation,
            storage_sqlite::DeviceLinkingOutcome::Cancelled,
        )
        .unwrap();
    assert!(matches!(
        storage.reserve_device_linking_attempt(&scope.account, &scope.local_device),
        Err(storage_sqlite::DeviceLinkingError::Busy)
    ));
    assert!(
        storage
            .device_linking_key_package_storage()
            .unwrap()
            .purpose_key_package()
            .unwrap()
            .unwrap()
            .scope
            == scope
    );
}

#[tokio::test]
async fn purpose_factory_storage_failure_rolls_back_bundle_then_exact_reopen_retry() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("purpose-factory.db");
    let key = storage_sqlite::SqlCipherKey::new("11".repeat(32)).unwrap();
    let storage = SqliteAccountStorage::open_encrypted(&path, &key).unwrap();
    let mut recipient = client(storage.clone());
    let scope = reserve(&storage, &mut recipient).await;
    let before = recipient.durably_owned_key_packages().unwrap();
    let injector = rusqlite::Connection::open(&path).unwrap();
    storage_sqlite::open_hardened_sqlcipher(
        &injector,
        &key,
        storage_sqlite::SqlCipherHardening::default(),
    )
    .unwrap();
    injector.execute_batch("CREATE TRIGGER reject_purpose BEFORE INSERT ON device_linking_key_package BEGIN SELECT RAISE(ABORT,'injected purpose failure'); END;").unwrap();
    assert!(recipient.resolve_linking_key_package(&scope).await.is_err());
    assert!(recipient.durably_owned_key_packages().unwrap() == before);
    assert!(
        storage
            .device_linking_key_package_storage()
            .unwrap()
            .purpose_key_package()
            .unwrap()
            .is_none()
    );
    injector
        .execute_batch("DROP TRIGGER reject_purpose;")
        .unwrap();
    let package = recipient.resolve_linking_key_package(&scope).await.unwrap();
    drop(recipient);
    drop(injector);
    storage.close().unwrap();
    let reopened = SqliteAccountStorage::open_encrypted(&path, &key).unwrap();
    let mut recipient = client(reopened.clone());
    assert!(recipient.resolve_linking_key_package(&scope).await.unwrap() == package);
    assert_eq!(
        recipient.durably_owned_key_packages().unwrap().len(),
        before.len() + 1
    );
}

#[tokio::test]
async fn terminal_cleanup_retires_only_exact_private_package_and_allows_fresh_generation() {
    let storage = SqliteAccountStorage::in_memory().unwrap();
    let mut recipient = client(storage.clone());
    let scope = reserve(&storage, &mut recipient).await;
    let package = recipient.resolve_linking_key_package(&scope).await.unwrap();
    let spare = recipient.fresh_linking_key_package().await.unwrap();
    let before = recipient.durably_owned_key_packages().unwrap();
    assert!(recipient.retire_linking_key_package(&scope).await.is_err());
    assert!(recipient.durably_owned_key_packages().unwrap() == before);
    storage
        .finish_device_linking_attempt(
            scope.generation,
            storage_sqlite::DeviceLinkingOutcome::Cancelled,
        )
        .unwrap();
    assert!(
        recipient
            .retire_linking_key_package(&PurposeAttemptScope {
                generation: scope.generation + 1,
                ..scope.clone()
            })
            .await
            .is_err()
    );
    recipient.retire_linking_key_package(&scope).await.unwrap();
    recipient.retire_linking_key_package(&scope).await.unwrap();
    let owned = recipient.durably_owned_key_packages().unwrap();
    assert!(!owned.contains(&package));
    assert!(owned.contains(&spare));
    assert_eq!(owned.len(), before.len() - 1);
    assert!(
        storage
            .device_linking_key_package_storage()
            .unwrap()
            .purpose_key_package()
            .unwrap()
            .is_none()
    );
    let fresh = storage
        .reserve_device_linking_attempt(&scope.account, &scope.local_device)
        .unwrap();
    assert_eq!(fresh, scope.generation + 1);
    assert!(recipient.resolve_linking_key_package(&scope).await.is_err());
}

#[tokio::test]
async fn expired_signed_private_package_can_be_retired_without_new_admission() {
    use openmls::prelude::{
        BasicCredential, CredentialWithKey, Lifetime, MlsMessageBodyIn, MlsMessageIn,
        MlsMessageOut, ProtocolVersion, SignatureScheme,
    };
    use openmls_basic_credential::SignatureKeyPair;
    use openmls_traits::OpenMlsProvider as _;
    use openmls_traits::storage::StorageProvider as MlsStorage;
    use tls_codec::{Deserialize as _, Serialize as _};
    let storage = SqliteAccountStorage::in_memory().unwrap();
    let mut recipient = client(storage.clone());
    let scope = reserve(&storage, &mut recipient).await;
    let public = recipient.fresh_key_package().await.unwrap();
    let provider = openmls_rust_crypto::OpenMlsRustCrypto::default();
    let fresh = MlsMessageIn::tls_deserialize_exact(public.bytes()).unwrap();
    let MlsMessageBodyIn::KeyPackage(fresh) = fresh.extract() else {
        panic!("fixture package expected");
    };
    let fresh = fresh
        .validate(provider.crypto(), ProtocolVersion::Mls10)
        .unwrap();
    let signer = SignatureKeyPair::read(
        storage.mls_storage(),
        scope.local_device.as_ref(),
        SignatureScheme::ED25519,
    )
    .unwrap();
    let credential = CredentialWithKey {
        credential: BasicCredential::new(scope.account.to_vec()).into(),
        signature_key: scope.local_device.to_vec().into(),
    };
    // Freshly signed synthetic fixture whose admission lifetime has elapsed.
    let bundle = openmls::prelude::KeyPackage::builder()
        .leaf_node_capabilities(fresh.leaf_node().capabilities().clone())
        .leaf_node_extensions(fresh.leaf_node().extensions().clone())
        .key_package_lifetime(Lifetime::init(0, 1))
        .build(fresh.ciphersuite(), &provider, &signer, credential)
        .unwrap();
    let reference = bundle.key_package().hash_ref(provider.crypto()).unwrap();
    let message: MlsMessageOut = bundle.key_package().clone().into();
    let bytes = message.tls_serialize_detached().unwrap();
    let expired = cgka_traits::engine::KeyPackage::new(bytes.clone())
        .with_protocol_profile(ProtocolProfile::Current);
    assert!(key_package_metadata(&expired).is_err());
    storage
        .with_transaction(
            |storage| -> Result<(), cgka_traits::storage::StorageError> {
                MlsStorage::write_key_package(storage.mls_storage(), &reference, &bundle).unwrap();
                storage
                    .device_linking_key_package_storage()
                    .unwrap()
                    .put_purpose_key_package(
                        &cgka_traits::device_linking_key_package::PurposeKeyPackage {
                            scope: scope.clone(),
                            public_bytes: bytes,
                            reference: reference.as_slice().to_vec(),
                            signature_public_key: scope.local_device.to_vec(),
                            context: None,
                            consumed: false,
                        },
                    )?;
                Ok(())
            },
        )
        .unwrap();
    storage
        .finish_device_linking_attempt(
            scope.generation,
            storage_sqlite::DeviceLinkingOutcome::Expired,
        )
        .unwrap();
    recipient.retire_linking_key_package(&scope).await.unwrap();
    let remaining: Option<openmls::prelude::KeyPackageBundle> =
        MlsStorage::key_package(storage.mls_storage(), &reference).unwrap();
    assert!(remaining.is_none());
    assert!(
        storage
            .device_linking_key_package_storage()
            .unwrap()
            .purpose_key_package()
            .unwrap()
            .is_none()
    );
    assert!(
        recipient
            .durably_owned_key_packages()
            .unwrap()
            .contains(&public)
    );
}

#[tokio::test]
async fn startup_cleanup_retires_verified_but_unjoined_material_after_encrypted_reopen() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("purpose-startup.db");
    let key = storage_sqlite::SqlCipherKey::new("12".repeat(32)).unwrap();
    let storage = SqliteAccountStorage::open_encrypted(&path, &key).unwrap();
    let mut recipient = client(storage.clone());
    let scope = reserve(&storage, &mut recipient).await;
    let package = recipient.resolve_linking_key_package(&scope).await.unwrap();
    let binding = storage_sqlite::DeviceLinkingBinding {
        generation: scope.generation,
        nonce: [61; 32],
        context_digest: [62; 32],
    };
    storage.bind_device_linking_context(&binding).unwrap();
    storage
        .device_linking_key_package_storage()
        .unwrap()
        .bind_purpose_context(
            &scope,
            &cgka_traits::device_linking_key_package::PurposeContextBinding {
                nonce: binding.nonce,
                context_digest: binding.context_digest,
            },
        )
        .unwrap();
    storage
        .bind_device_linking_flow(&binding, "verified-but-unjoined")
        .unwrap();
    storage
        .finish_device_linking_attempt(
            scope.generation,
            storage_sqlite::DeviceLinkingOutcome::PairingVerified,
        )
        .unwrap();
    drop(recipient);
    storage.close().unwrap();
    let reopened = SqliteAccountStorage::open_encrypted(&path, &key).unwrap();
    let mut recipient = client(reopened.clone());
    assert!(
        recipient
            .durably_owned_key_packages()
            .unwrap()
            .contains(&package)
    );
    assert!(
        recipient
            .cleanup_unjoined_linking_key_package_on_startup()
            .unwrap()
    );
    assert!(
        !recipient
            .cleanup_unjoined_linking_key_package_on_startup()
            .unwrap()
    );
    assert!(
        !recipient
            .durably_owned_key_packages()
            .unwrap()
            .contains(&package)
    );
    assert!(
        reopened
            .device_linking_key_package_storage()
            .unwrap()
            .purpose_key_package()
            .unwrap()
            .is_none()
    );
    assert_eq!(
        reopened
            .reserve_device_linking_attempt(&scope.account, &scope.local_device)
            .unwrap(),
        scope.generation + 1
    );
}
