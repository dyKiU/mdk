//! Bounded transient recipient collection; transport metadata never grants membership.
use super::runtime_gate::RuntimeWelcomeGate;
use cgka_engine::linking_welcome_policy::{LinkingWelcomeDenied, LinkingWelcomePolicy};
use cgka_traits::device_linking_key_package::PurposeKeyPackage;
use cgka_traits::peeler::{
    PrivateLinkingWelcomeContext, PrivateLinkingWelcomeObservation, TransportPeeler,
};
use cgka_traits::private_device_invite::{
    MAX_PRIVATE_INVITE_TRANSPORT_BYTES, MAX_PRIVATE_INVITE_WELCOME_BYTES,
    MAX_PRIVATE_INVITE_WELCOME_MESSAGES,
};
use cgka_traits::transport::{TransportEnvelope, TransportMessage};
use std::future::Future;

// The private NIP59 wire format already limits each outer event to 128 KiB.
// Bound auxiliary transport hints too before serialization or retaining them.
const MAX_CHUNK_TRANSPORT_BYTES: usize = 128 * 1024;
const MAX_TRANSPORT_HINT_BYTES: usize = 256;

#[derive(Debug, PartialEq, Eq)]
pub(crate) enum CollectionError {
    Denied,
    InvalidTransport,
    Conflict,
    LimitExceeded,
    Storage,
}

#[derive(Default)]
pub(crate) struct PrivateWelcomeCollection {
    batch: Option<PartialBatch>,
}

struct PartialBatch {
    context: PrivateLinkingWelcomeContext,
    total: usize,
    bytes: usize,
    messages: Vec<Option<TransportMessage>>,
}

pub(crate) struct CompleteWelcomeBatch {
    pub(crate) context: PrivateLinkingWelcomeContext,
    pub(crate) messages: Vec<TransportMessage>,
}

impl PrivateWelcomeCollection {
    /// The serial account owner clears this on cancellation, expiry and teardown.
    /// Reopening creates a fresh empty collector; nothing is serialized.
    pub(crate) fn clear(&mut self) {
        self.batch = None;
    }

    /// Shape alone is never permission; this only avoids unnecessary retry work.
    pub(crate) fn has_complete(&self) -> bool {
        self.batch
            .as_ref()
            .is_some_and(|batch| batch.messages.iter().all(Option::is_some))
    }

    /// Queue-pin cleanup only. These identifiers convey no membership authority.
    pub(crate) fn transport_ids(&self) -> Vec<cgka_traits::MessageId> {
        self.batch
            .as_ref()
            .map(|batch| {
                batch
                    .messages
                    .iter()
                    .flatten()
                    .map(|message| message.id.clone())
                    .collect()
            })
            .unwrap_or_default()
    }

    fn gate_error(&mut self, error: LinkingWelcomeDenied) -> CollectionError {
        // A rejected unrelated scope or package must not erase the actual live
        // collection. Terminal/absent permission still drops cached transport.
        if !matches!(error, LinkingWelcomeDenied::ContextMismatch) {
            self.clear();
        }
        CollectionError::Denied
    }

    fn live_context(
        &mut self,
        gate: &RuntimeWelcomeGate,
        purpose: &PurposeKeyPackage,
        context: &PrivateLinkingWelcomeContext,
    ) -> Result<(), CollectionError> {
        let mut lease = gate
            .begin_join(purpose)
            .map_err(|error| self.gate_error(error))?;
        // Dropping this short lease does not consume consent. Engine must acquire
        // its own live lease and authenticate the actual full tree before joining.
        lease
            .check_transport_context(context)
            .map_err(|_| CollectionError::Denied)
    }

    pub(crate) async fn observe(
        &mut self,
        gate: &RuntimeWelcomeGate,
        purpose: &PurposeKeyPackage,
        peeler: &dyn TransportPeeler,
        message: TransportMessage,
    ) -> Result<bool, CollectionError> {
        self.observe_with(gate, purpose, &message, async {
            peeler
                .observe_private_linking_welcome(&message)
                .await
                .map_err(|_| CollectionError::InvalidTransport)
        })
        .await
    }

    /// Authenticate through the caller's configured Session; the future must
    /// also freshly check the actual purpose before yielding metadata. It cannot
    /// grant consent. The original gate is checked before and after this await.
    pub(crate) async fn observe_with<F>(
        &mut self,
        gate: &RuntimeWelcomeGate,
        purpose: &PurposeKeyPackage,
        message: &TransportMessage,
        observation: F,
    ) -> Result<bool, CollectionError>
    where
        F: Future<Output = Result<PrivateLinkingWelcomeObservation, CollectionError>>,
    {
        let deadline = gate
            .collection_deadline(purpose)
            .map_err(|error| self.gate_error(error))?;
        bound_transport(message)?;
        let observation = tokio::time::timeout_at(deadline.into(), observation)
            .await
            .map_err(|_| {
                self.clear();
                CollectionError::Denied
            })??;
        // Revalidate after the await, before retaining any chunk. Deadline or
        // cancellation during authentication never permits a stale buffer write.
        self.live_context(gate, purpose, &observation.context)?;
        if observation.count == 0
            || observation.count > MAX_PRIVATE_INVITE_WELCOME_MESSAGES
            || observation.index >= observation.count
            || observation.total == 0
            || observation.total > MAX_PRIVATE_INVITE_WELCOME_BYTES
        {
            return Err(CollectionError::LimitExceeded);
        }
        if !matches!(&message.envelope, TransportEnvelope::Welcome { recipient }
            if recipient.as_slice() == observation.context.account)
        {
            return Err(CollectionError::InvalidTransport);
        }
        let encoded_bytes = serde_json::to_vec(message)
            .map_err(|_| CollectionError::InvalidTransport)?
            .len();
        if encoded_bytes > MAX_PRIVATE_INVITE_TRANSPORT_BYTES {
            return Err(CollectionError::LimitExceeded);
        }
        let batch = self.batch.get_or_insert_with(|| PartialBatch {
            context: observation.context.clone(),
            total: observation.total,
            bytes: 0,
            messages: (0..observation.count).map(|_| None).collect(),
        });
        if batch.context != observation.context
            || batch.total != observation.total
            || batch.messages.len() != observation.count
        {
            return Err(CollectionError::Conflict);
        }
        if let Some(previous) = &batch.messages[observation.index] {
            if previous != message {
                return Err(CollectionError::Conflict);
            }
            return Ok(batch.messages.iter().all(Option::is_some));
        }
        if batch
            .messages
            .iter()
            .flatten()
            .any(|previous| previous.id == message.id)
        {
            return Err(CollectionError::Conflict);
        }
        let bytes = batch
            .bytes
            .checked_add(encoded_bytes)
            .filter(|bytes| *bytes <= MAX_PRIVATE_INVITE_TRANSPORT_BYTES)
            .ok_or(CollectionError::LimitExceeded)?;
        batch.messages[observation.index] = Some(message.clone());
        batch.bytes = bytes;
        Ok(batch.messages.iter().all(Option::is_some))
    }

    /// Snapshot only bounded authenticated transport; verifier evidence is never
    /// cloned. The retained batch survives a failed atomic join under the same
    /// original deadline. The serial caller holds at most one working snapshot
    /// and clears the retained batch after successful joining or cancellation.
    pub(crate) fn complete_for_retry(
        &mut self,
        gate: &RuntimeWelcomeGate,
        purpose: &PurposeKeyPackage,
    ) -> Result<Option<CompleteWelcomeBatch>, CollectionError> {
        gate.collection_deadline(purpose)
            .map_err(|error| self.gate_error(error))?;
        let Some(batch) = self.batch.as_ref() else {
            return Ok(None);
        };
        let context = batch.context.clone();
        self.live_context(gate, purpose, &context)?;
        let batch = self.batch.as_ref().unwrap();
        if !batch.messages.iter().all(Option::is_some) {
            return Ok(None);
        }
        Ok(Some(CompleteWelcomeBatch {
            context,
            messages: batch.messages.iter().flatten().cloned().collect(),
        }))
    }

    pub(crate) fn take_complete(
        &mut self,
        gate: &RuntimeWelcomeGate,
        purpose: &PurposeKeyPackage,
    ) -> Result<Option<CompleteWelcomeBatch>, CollectionError> {
        gate.collection_deadline(purpose)
            .map_err(|error| self.gate_error(error))?;
        let Some(batch) = self.batch.as_ref() else {
            return Ok(None);
        };
        let context = batch.context.clone();
        self.live_context(gate, purpose, &context)?;
        if !self
            .batch
            .as_ref()
            .unwrap()
            .messages
            .iter()
            .all(Option::is_some)
        {
            return Ok(None);
        }
        let batch = self.batch.take().unwrap();
        Ok(Some(CompleteWelcomeBatch {
            context: batch.context,
            messages: batch.messages.into_iter().flatten().collect(),
        }))
    }
}

pub(crate) fn bound_transport(message: &TransportMessage) -> Result<(), CollectionError> {
    if message.payload.is_empty()
        || message.payload.len() > MAX_CHUNK_TRANSPORT_BYTES
        || message.id.as_slice().is_empty()
        || message.id.as_slice().len() > MAX_TRANSPORT_HINT_BYTES
        || message.source.0.len() > MAX_TRANSPORT_HINT_BYTES
        || message.causal_deps.len() > MAX_PRIVATE_INVITE_WELCOME_MESSAGES
        || message
            .causal_deps
            .iter()
            .any(|id| id.as_slice().len() > MAX_TRANSPORT_HINT_BYTES)
        || !matches!(&message.envelope, TransportEnvelope::Welcome { recipient }
            if recipient.as_slice().len() == 32)
    {
        return Err(CollectionError::LimitExceeded);
    }
    Ok(())
}

#[cfg(test)]
#[path = "welcome_collection/tests.rs"]
mod tests;
