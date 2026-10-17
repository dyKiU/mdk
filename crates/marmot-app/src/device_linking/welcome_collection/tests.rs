//! Real stock SDK plus authenticated NIP59 collection. Opaque Welcome bytes
//! exercise transport collection only; they do not claim actual MLS admission.
use super::*;
use crate::device_linking::runtime_gate::tests::verified_for_context;
use cgka_traits::device_linking_key_package::{PurposeAttemptScope, PurposeContextBinding};
use cgka_traits::transport::EncryptedPayload;
use sha2::{Digest, Sha256};
use std::sync::Arc;

async fn fixture() -> (
    RuntimeWelcomeGate,
    PurposeKeyPackage,
    transport_nostr_peeler::NostrMlsPeeler,
    PrivateLinkingWelcomeContext,
    EncryptedPayload,
) {
    let keys = nostr::prelude::Keys::generate();
    let mut context = crate::device_linking::tests::context();
    context.account = keys.public_key().to_bytes();
    let storage = || {
        let s = Arc::new(storage_sqlite::SqliteAccountStorage::in_memory().unwrap());
        s.app_storage()
            .ensure_account_projection_with_identity(
                "isolated-collector",
                &hex::encode(context.account),
            )
            .unwrap();
        s
    };
    let (new_device, _) = verified_for_context(context.clone(), storage(), storage()).await;
    let gate = RuntimeWelcomeGate::new();
    gate.arm(new_device).unwrap();
    let purpose = PurposeKeyPackage {
        scope: PurposeAttemptScope {
            account: context.account,
            local_device: context.recipient,
            generation: context.new_device_generation,
        },
        public_bytes: context.exact_key_package.clone(),
        reference: context.key_package_reference.to_vec(),
        signature_public_key: context.recipient.to_vec(),
        context: Some(PurposeContextBinding {
            nonce: context.nonce,
            context_digest: context.digest().unwrap(),
        }),
        consumed: false,
    };
    let payload = EncryptedPayload {
        ciphertext: vec![17; 100_000],
        aad: vec![],
    };
    let transport_context = PrivateLinkingWelcomeContext {
        account: context.account,
        approver: context.approver,
        recipient: context.recipient,
        approver_generation: context.approver_generation,
        recipient_generation: context.new_device_generation,
        group_id: cgka_traits::GroupId::new(context.device_group.clone()),
        nonce: context.nonce,
        context_digest: context.digest().unwrap(),
        key_package_reference: context.key_package_reference,
        key_package_digest: Sha256::digest(&context.exact_key_package).into(),
        commit_digest: [9; 32],
        welcome_digest: Sha256::digest(&payload.ciphertext).into(),
    };
    (
        gate,
        purpose,
        transport_nostr_peeler::NostrMlsPeeler::new().with_welcome_signer(keys),
        transport_context,
        payload,
    )
}

#[tokio::test]
async fn bounded_recipient_collection_assembles_out_of_order_with_exact_duplicate() {
    let (gate, purpose, peeler, context, payload) = fixture().await;
    let mut messages = peeler
        .wrap_private_linking_welcome(&payload, &context)
        .await
        .unwrap();
    assert!(messages.len() > 1);
    let mut collection = PrivateWelcomeCollection::default();
    assert!(
        !collection
            .observe(&gate, &purpose, &peeler, messages.last().unwrap().clone())
            .await
            .unwrap()
    );
    assert!(
        !collection
            .observe(&gate, &purpose, &peeler, messages.last().unwrap().clone())
            .await
            .unwrap()
    );
    assert!(collection.take_complete(&gate, &purpose).unwrap().is_none());
    messages.reverse();
    for (i, message) in messages.into_iter().enumerate() {
        let complete = collection
            .observe(&gate, &purpose, &peeler, message)
            .await
            .unwrap();
        if i == 0 {
            assert!(!complete);
        }
    }
    let batch = collection.take_complete(&gate, &purpose).unwrap().unwrap();
    assert!(batch.context == context);
    assert!(
        peeler
            .peel_private_linking_welcome_batch(&batch.messages, &context)
            .await
            .unwrap()
            == payload.ciphertext
    );
    assert!(collection.take_complete(&gate, &purpose).unwrap().is_none());
    assert!(
        gate.maintain().unwrap(),
        "collection does not consume or create SDK consent"
    );
}

#[tokio::test]
async fn bounded_recipient_collection_stale_scope_cannot_erase_current_batch() {
    let (gate, purpose, peeler, context, payload) = fixture().await;
    let messages = peeler
        .wrap_private_linking_welcome(&payload, &context)
        .await
        .unwrap();
    let mut collection = PrivateWelcomeCollection::default();
    collection
        .observe(&gate, &purpose, &peeler, messages[0].clone())
        .await
        .unwrap();
    let mut wrong = purpose.clone();
    wrong.scope.generation += 1;
    assert!(
        collection
            .observe(&gate, &wrong, &peeler, messages[0].clone())
            .await
            .is_err()
    );
    for message in &messages[1..] {
        collection
            .observe(&gate, &purpose, &peeler, message.clone())
            .await
            .unwrap();
    }
    assert!(
        collection.take_complete(&gate, &purpose).unwrap().is_some(),
        "a rejected unrelated generation must not erase the actual live attempt"
    );
}

#[tokio::test]
async fn bounded_recipient_collection_checks_sdk_bindings_before_buffering() {
    let (gate, purpose, peeler, context, payload) = fixture().await;
    let messages = peeler
        .wrap_private_linking_welcome(&payload, &context)
        .await
        .unwrap();
    let mut collection = PrivateWelcomeCollection::default();
    for field in 0..9 {
        let mut wrong = context.clone();
        match field {
            0 => wrong.approver = [81; 32],
            1 => wrong.recipient = [82; 32],
            2 => wrong.approver_generation += 1,
            3 => wrong.recipient_generation += 1,
            4 => wrong.group_id = cgka_traits::GroupId::new(vec![83; 16]),
            5 => wrong.nonce = [84; 32],
            6 => wrong.context_digest = [85; 32],
            7 => wrong.key_package_reference = [86; 32],
            8 => wrong.key_package_digest = [87; 32],
            _ => unreachable!(),
        }
        let wrong_messages = peeler
            .wrap_private_linking_welcome(&payload, &wrong)
            .await
            .unwrap();
        // This is an authentic same-account transport statement, not SDK consent.
        assert!(
            peeler
                .observe_private_linking_welcome(&wrong_messages[0])
                .await
                .unwrap()
                .context
                == wrong
        );
        assert_eq!(
            collection
                .observe(&gate, &purpose, &peeler, wrong_messages[0].clone())
                .await,
            Err(CollectionError::UnrelatedContext)
        );
    }
    for message in &messages[1..] {
        collection
            .observe(&gate, &purpose, &peeler, message.clone())
            .await
            .unwrap();
    }
    assert!(
        collection.take_complete(&gate, &purpose).unwrap().is_none(),
        "no rejected chunk may occupy the missing first slot"
    );
    assert!(
        collection
            .observe(&gate, &purpose, &peeler, messages[0].clone())
            .await
            .unwrap()
    );
    assert!(collection.take_complete(&gate, &purpose).unwrap().is_some());
}

#[tokio::test]
async fn bounded_recipient_collection_preserves_exact_batch_on_conflicts_and_limits() {
    let (gate, purpose, peeler, context, payload) = fixture().await;
    let messages = peeler
        .wrap_private_linking_welcome(&payload, &context)
        .await
        .unwrap();
    let mut collection = PrivateWelcomeCollection::default();
    collection
        .observe(&gate, &purpose, &peeler, messages[0].clone())
        .await
        .unwrap();
    let rewrapped = peeler
        .wrap_private_linking_welcome(&payload, &context)
        .await
        .unwrap();
    assert!(rewrapped[0].id != messages[0].id);
    assert_eq!(
        collection
            .observe(&gate, &purpose, &peeler, rewrapped[0].clone())
            .await,
        Err(CollectionError::Conflict)
    );
    let mut other_context = context.clone();
    other_context.commit_digest = [91; 32];
    let other = peeler
        .wrap_private_linking_welcome(&payload, &other_context)
        .await
        .unwrap();
    assert_eq!(
        collection
            .observe(&gate, &purpose, &peeler, other[1].clone())
            .await,
        Err(CollectionError::Conflict)
    );
    let other_payload = EncryptedPayload {
        ciphertext: vec![18; 100_000],
        aad: vec![],
    };
    other_context = context.clone();
    other_context.welcome_digest = Sha256::digest(&other_payload.ciphertext).into();
    let other = peeler
        .wrap_private_linking_welcome(&other_payload, &other_context)
        .await
        .unwrap();
    assert_eq!(
        collection
            .observe(&gate, &purpose, &peeler, other[1].clone())
            .await,
        Err(CollectionError::Conflict)
    );
    let mut excessive_source = messages[1].clone();
    excessive_source.source.0 = "x".repeat(MAX_TRANSPORT_HINT_BYTES + 1);
    assert_eq!(
        collection
            .observe(&gate, &purpose, &peeler, excessive_source)
            .await,
        Err(CollectionError::LimitExceeded)
    );
    let mut excessive_dependencies = messages[1].clone();
    excessive_dependencies.causal_deps =
        vec![messages[0].id.clone(); MAX_PRIVATE_INVITE_WELCOME_MESSAGES + 1];
    assert_eq!(
        collection
            .observe(&gate, &purpose, &peeler, excessive_dependencies)
            .await,
        Err(CollectionError::LimitExceeded)
    );
    let mut excessive_payload = messages[1].clone();
    excessive_payload
        .payload
        .resize(MAX_CHUNK_TRANSPORT_BYTES + 1, 0);
    assert_eq!(
        collection
            .observe(&gate, &purpose, &peeler, excessive_payload)
            .await,
        Err(CollectionError::LimitExceeded)
    );
    for message in &messages[1..] {
        collection
            .observe(&gate, &purpose, &peeler, message.clone())
            .await
            .unwrap();
    }
    let batch = collection.take_complete(&gate, &purpose).unwrap().unwrap();
    assert!(
        peeler
            .peel_private_linking_welcome_batch(&batch.messages, &context)
            .await
            .unwrap()
            == payload.ciphertext
    );
}

struct PausedObservation {
    inner: transport_nostr_peeler::NostrMlsPeeler,
    entered: tokio::sync::Notify,
    release: tokio::sync::Notify,
}

#[async_trait::async_trait]
impl TransportPeeler for PausedObservation {
    async fn peel_group_message(
        &self,
        message: &TransportMessage,
        context: &cgka_traits::GroupContextSnapshot,
    ) -> Result<cgka_traits::ingest::PeeledMessage, cgka_traits::PeelerError> {
        self.inner.peel_group_message(message, context).await
    }
    async fn peel_welcome(
        &self,
        message: &TransportMessage,
    ) -> Result<cgka_traits::ingest::PeeledMessage, cgka_traits::PeelerError> {
        self.inner.peel_welcome(message).await
    }
    async fn wrap_group_message(
        &self,
        payload: &EncryptedPayload,
        context: &cgka_traits::GroupContextSnapshot,
    ) -> Result<TransportMessage, cgka_traits::PeelerError> {
        self.inner.wrap_group_message(payload, context).await
    }
    async fn wrap_welcome(
        &self,
        payload: &EncryptedPayload,
        recipient: &cgka_traits::MemberId,
    ) -> Result<TransportMessage, cgka_traits::PeelerError> {
        self.inner.wrap_welcome(payload, recipient).await
    }
    async fn observe_private_linking_welcome(
        &self,
        message: &TransportMessage,
    ) -> Result<cgka_traits::peeler::PrivateLinkingWelcomeObservation, cgka_traits::PeelerError>
    {
        let observation = self.inner.observe_private_linking_welcome(message).await?;
        self.entered.notify_one();
        self.release.notified().await;
        Ok(observation)
    }
}

#[tokio::test]
async fn bounded_recipient_collection_rechecks_cancellation_after_authentication_await() {
    let (gate, purpose, peeler, context, payload) = fixture().await;
    let messages = peeler
        .wrap_private_linking_welcome(&payload, &context)
        .await
        .unwrap();
    let peeler = PausedObservation {
        inner: peeler,
        entered: tokio::sync::Notify::new(),
        release: tokio::sync::Notify::new(),
    };
    let mut collection = PrivateWelcomeCollection::default();
    let cancellation = async {
        peeler.entered.notified().await;
        gate.cancel().unwrap();
        peeler.release.notify_one();
    };
    let (result, ()) = tokio::join!(
        collection.observe(&gate, &purpose, &peeler, messages[0].clone()),
        cancellation
    );
    assert_eq!(result, Err(CollectionError::Denied));
    assert!(collection.take_complete(&gate, &purpose).is_err());
    assert!(!gate.maintain().unwrap());
}
