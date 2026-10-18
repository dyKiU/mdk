//! Single account-runtime owner of verifier secrets and durable facts.
//! Construct exactly once on account startup. Never use startup to open another
//! live handle: it deliberately abandons any prior ephemeral verification.
use super::*;
use std::sync::Arc;
use storage_sqlite::{DeviceLinkingBinding, DeviceLinkingOutcome, SqliteAccountStorage};

#[derive(Debug)]
pub(crate) enum OwnerError {
    Verifier(LinkError),
    // Do not expose database error text, verifier identities, or input payloads.
    Storage,
}
type OwnerResult<T> = std::result::Result<T, OwnerError>;
pub(crate) struct LinkingOwner {
    storage: Arc<SqliteAccountStorage>,
    account: [u8; 32],
    device: [u8; 32],
    linker: DeviceLinker,
    generation: Option<u64>,
    binding: Option<DeviceLinkingBinding>,
    reservation_deadline: Option<Instant>,
    // Retain the first terminal write intent across transient storage failures.
    // It carries no verifier permission and cannot recreate discarded secrets.
    pending_terminal: Option<DeviceLinkingOutcome>,
}
impl LinkingOwner {
    pub(super) fn startup(
        storage: Arc<SqliteAccountStorage>,
        account: [u8; 32],
        device: [u8; 32],
    ) -> OwnerResult<Self> {
        storage
            .app_storage()
            .abandon_device_linking_on_startup()
            .map_err(|_| OwnerError::Storage)?;
        Ok(Self::attach_after_restart_fence(storage, account, device))
    }
    // Construction after the actual app open has acquired its exclusive session
    // and completed typed restart cleanup. Never clear another owner's flow.
    pub(crate) fn attach_after_restart_fence(
        storage: Arc<SqliteAccountStorage>,
        account: [u8; 32],
        device: [u8; 32],
    ) -> Self {
        Self {
            storage,
            account,
            device,
            linker: DeviceLinker::new(),
            generation: None,
            binding: None,
            reservation_deadline: None,
            pending_terminal: None,
        }
    }
    pub(crate) fn reserve_scope(
        &mut self,
    ) -> OwnerResult<cgka_traits::device_linking_key_package::PurposeAttemptScope> {
        let generation = self.reserve()?;
        Ok(
            cgka_traits::device_linking_key_package::PurposeAttemptScope {
                account: self.account,
                local_device: self.device,
                generation,
            },
        )
    }
    pub(super) fn reserve(&mut self) -> OwnerResult<u64> {
        if self.linker.closed {
            return Err(OwnerError::Verifier(LinkError::Closed));
        }
        if self.generation.is_some() {
            self.finish(DeviceLinkingOutcome::SimultaneousRequest)?;
            return Err(OwnerError::Verifier(LinkError::SimultaneousRequest));
        }
        // Start before the durable write or any offer/setup work. SDK request
        // timers must never extend this account-owned attempt lifetime.
        let deadline = Instant::now() + ATTEMPT_LIFETIME;
        let generation = self
            .storage
            .app_storage()
            .reserve_device_linking_attempt(&self.account, &self.device)
            .map_err(|_| OwnerError::Storage)?;
        self.generation = Some(generation);
        self.reservation_deadline = Some(deadline);
        Ok(generation)
    }
    fn check_deadline(&mut self, now: Instant) -> OwnerResult<()> {
        if self.pending_terminal.is_some() {
            return Err(OwnerError::Verifier(LinkError::Cancelled));
        }
        if self
            .reservation_deadline
            .is_some_and(|deadline| now >= deadline)
        {
            self.finish(DeviceLinkingOutcome::Expired)?;
            return Err(OwnerError::Verifier(LinkError::Expired));
        }
        Ok(())
    }
    // Fence an existing exact generation before passing input into the SDK.
    fn guard(&mut self, now: Instant) -> OwnerResult<()> {
        self.check_deadline(now)?;
        let binding = self
            .binding
            .as_ref()
            .ok_or(OwnerError::Verifier(LinkError::NotReady))?;
        let checked =
            if let Some(flow) = self.linker.attempt.as_ref().and_then(|a| a.flow.as_deref()) {
                self.storage
                    .app_storage()
                    .check_device_linking_flow(binding, flow)
            } else {
                self.storage
                    .app_storage()
                    .bind_device_linking_context(binding)
            };
        if checked.is_err() {
            self.linker.cancel();
            return Err(OwnerError::Storage);
        }
        Ok(())
    }
    // This must happen before an offer/frame/result leaves this module.
    fn bind_flow(&mut self) -> OwnerResult<()> {
        if let Some(flow) = self.linker.attempt.as_ref().and_then(|a| a.flow.as_deref()) {
            let binding = self.binding.as_ref().ok_or(OwnerError::Storage)?;
            if self
                .storage
                .app_storage()
                .bind_device_linking_flow(binding, flow)
                .is_err()
            {
                self.linker.cancel();
                return Err(OwnerError::Storage);
            }
        }
        Ok(())
    }
    fn finish(&mut self, outcome: DeviceLinkingOutcome) -> OwnerResult<()> {
        self.linker.cancel(); // Drop verifier secrets even if the durable write fails.
        let outcome = *self.pending_terminal.get_or_insert(outcome);
        if let Some(generation) = self.generation {
            self.storage
                .app_storage()
                .finish_device_linking_attempt(generation, outcome)
                .map_err(|_| OwnerError::Storage)?;
        }
        self.generation = None;
        self.binding = None;
        self.reservation_deadline = None;
        self.pending_terminal = None;
        Ok(())
    }
    fn after<T>(&mut self, result: Result<T>) -> OwnerResult<T> {
        match result {
            Ok(value) => {
                self.bind_flow()?;
                Ok(value)
            }
            Err(error) => {
                let terminal = match error {
                    LinkError::Expired => Some(DeviceLinkingOutcome::Expired),
                    LinkError::Cancelled => Some(DeviceLinkingOutcome::Cancelled),
                    LinkError::SimultaneousRequest => {
                        Some(DeviceLinkingOutcome::SimultaneousRequest)
                    }
                    LinkError::Closed => Some(DeviceLinkingOutcome::Shutdown),
                    LinkError::Sdk => Some(DeviceLinkingOutcome::IntegrityFailure),
                    _ => None,
                };
                if let Some(outcome) = terminal {
                    self.finish(outcome)?;
                }
                Err(OwnerError::Verifier(error))
            }
        }
    }
    pub(super) async fn begin(
        &mut self,
        context: LinkingContext,
        role: Role,
        now: Instant,
    ) -> OwnerResult<()> {
        self.check_deadline(now)?;
        let generation = self
            .generation
            .ok_or(OwnerError::Verifier(LinkError::NotReady))?;
        let expected_device = match role {
            Role::NewDevice => context.recipient,
            Role::Approver => context.approver,
        };
        if context.account != self.account
            || expected_device != self.device
            || context.local_generation(role) != generation
        {
            return Err(OwnerError::Verifier(LinkError::BindingMismatch));
        }
        let binding = DeviceLinkingBinding {
            generation,
            nonce: context.nonce,
            context_digest: context.digest().map_err(OwnerError::Verifier)?,
        };
        self.storage
            .app_storage()
            .bind_device_linking_context(&binding)
            .map_err(|_| OwnerError::Storage)?;
        self.binding = Some(binding);
        let result = self.linker.begin(context, role, generation, now).await;
        self.after(result)
    }
    /// Bind the real account-client scope and its exact private package before
    /// releasing any verifier offer. The resulting proof grants no enrollment.
    pub(crate) async fn begin_for_scope(
        &mut self,
        scope: &cgka_traits::device_linking_key_package::PurposeAttemptScope,
        context: LinkingContext,
        role: Role,
        now: Instant,
    ) -> OwnerResult<()> {
        use cgka_traits::StorageProvider;
        use cgka_traits::device_linking_key_package::PurposeContextBinding;
        self.check_scope(scope)?;
        let binding = PurposeContextBinding {
            nonce: context.nonce,
            context_digest: context.digest().map_err(OwnerError::Verifier)?,
        };
        if role == Role::NewDevice {
            let purpose = self
                .storage
                .device_linking_key_package_storage()
                .ok_or(OwnerError::Storage)?
                .purpose_key_package()
                .map_err(|_| OwnerError::Storage)?
                .ok_or(OwnerError::Verifier(LinkError::NotReady))?;
            if purpose.consumed
                || purpose.scope != *scope
                || purpose.public_bytes != context.exact_key_package
                || purpose.reference.as_slice() != context.key_package_reference.as_slice()
                || purpose.signature_public_key.as_slice() != context.recipient.as_slice()
            {
                return Err(OwnerError::Verifier(LinkError::BindingMismatch));
            }
        }
        self.begin(context, role, now).await?;
        if role == Role::NewDevice
            && self
                .storage
                .device_linking_key_package_storage()
                .ok_or(OwnerError::Storage)?
                .bind_purpose_context(scope, &binding)
                .is_err()
        {
            // Compensate setup before exposing an offer; never retain a live
            // SDK flow whose exact purpose binding failed to become durable.
            self.finish(DeviceLinkingOutcome::IntegrityFailure)?;
            return Err(OwnerError::Storage);
        }
        Ok(())
    }
    pub(crate) fn offer(&mut self, now: Instant) -> OwnerResult<PeerOffer> {
        self.guard(now)?;
        let result = self.linker.offer(now);
        self.after(result)
    }
    pub(crate) async fn admit_peer(&mut self, offer: &PeerOffer, now: Instant) -> OwnerResult<()> {
        self.guard(now)?;
        let result = self.linker.admit_peer(offer, now).await;
        self.after(result)
    }
    pub(crate) async fn start_verification(&mut self, now: Instant) -> OwnerResult<()> {
        self.guard(now)?;
        let result = self.linker.start_verification(now).await;
        self.after(result)
    }
    pub(crate) async fn receive(&mut self, frame: &LinkFrame, now: Instant) -> OwnerResult<()> {
        self.guard(now)?;
        let result = self.linker.receive(frame, now).await;
        self.after(result)
    }
    pub(crate) fn outgoing(&mut self, now: Instant) -> OwnerResult<Vec<LinkFrame>> {
        self.guard(now)?;
        let result = self.linker.outgoing(now);
        self.after(result)
    }
    pub(crate) async fn acknowledge(&mut self, token: &str, now: Instant) -> OwnerResult<()> {
        self.guard(now)?;
        let result = self.linker.acknowledge(token, now).await;
        self.after(result)
    }
    /// Observations cannot consume a proof or reconstruct permission from SQL.
    pub(crate) fn native_observation_for_scope(
        &mut self,
        scope: &cgka_traits::device_linking_key_package::PurposeAttemptScope,
        now: Instant,
    ) -> OwnerResult<(
        crate::DeviceLinkingPhase,
        Option<crate::DeviceLinkingDecimals>,
    )> {
        self.check_scope(scope)?;
        self.check_deadline(now)?;
        if self.generation != Some(scope.generation) {
            return Err(OwnerError::Verifier(LinkError::StaleFlow));
        }
        if self.linker.attempt.is_none() {
            if self.binding.is_some() {
                return Err(OwnerError::Verifier(LinkError::Cancelled));
            }
            return Ok((crate::DeviceLinkingPhase::AwaitingSetup, None));
        }
        self.guard(now)?;
        let result = self.linker.native_observation(now);
        self.after(result)
    }

    pub(crate) fn decimals(&mut self, now: Instant) -> OwnerResult<Option<(u16, u16, u16)>> {
        self.guard(now)?;
        let result = self.linker.decimals(now);
        self.after(result)
    }
    pub(crate) async fn confirm(&mut self, now: Instant) -> OwnerResult<()> {
        self.guard(now)?;
        let result = self.linker.confirm(now).await;
        self.after(result)
    }
    /// Refuse the singleton Add path before consuming the original SDK result.
    /// This is a negative context check, not enrollment authority: genuine
    /// genesis/tree validation and both human confirmations still happen later.
    pub(crate) fn validate_singleton_invite_preparation(
        &mut self,
        scope: &cgka_traits::device_linking_key_package::PurposeAttemptScope,
        now: Instant,
    ) -> OwnerResult<()> {
        self.check_scope(scope)?;
        self.guard(now)?;
        let attempt = self.linker.live(now).map_err(OwnerError::Verifier)?;
        let context = &attempt.context;
        if attempt.role != Role::Approver
            || context.predecessor.epoch != 0
            || context.predecessor.leaves.len() != 1
            || context.predecessor.leaves[0].leaf_index != 0
            || context.predecessor.leaves[0].signature_public_key != context.approver
            || context.approver != scope.local_device
        {
            return Err(OwnerError::Verifier(LinkError::BindingMismatch));
        }
        Ok(())
    }

    /// Negative bootstrap checks against the current owned context and actual
    /// purpose. Metadata cannot authorize a multi-leaf predecessor or release
    /// the one-shot SDK result; take_verified still enforces both confirmations.
    pub(crate) fn validate_singleton_bootstrap(
        &mut self,
        scope: &cgka_traits::device_linking_key_package::PurposeAttemptScope,
        now: Instant,
    ) -> OwnerResult<()> {
        use cgka_traits::StorageProvider;
        self.check_scope(scope)?;
        self.guard(now)?;
        let attempt = self.linker.live(now).map_err(OwnerError::Verifier)?;
        let context = &attempt.context;
        if attempt.role != Role::NewDevice
            || context.predecessor.epoch != 0
            || context.predecessor.leaves.len() != 1
            || context.predecessor.leaves[0].leaf_index != 0
            || context.predecessor.leaves[0].signature_public_key != context.approver
        {
            return Err(OwnerError::Verifier(LinkError::BindingMismatch));
        }
        let purpose = self
            .storage
            .device_linking_key_package_storage()
            .ok_or(OwnerError::Storage)?
            .purpose_key_package()
            .map_err(|_| OwnerError::Storage)?
            .ok_or(OwnerError::Verifier(LinkError::NotReady))?;
        let digest = context.digest().map_err(OwnerError::Verifier)?;
        if purpose.consumed
            || purpose.scope != *scope
            || purpose.public_bytes != context.exact_key_package
            || purpose.reference.as_slice() != context.key_package_reference.as_slice()
            || purpose.signature_public_key.as_slice() != context.recipient.as_slice()
            || purpose.context.as_ref().is_none_or(|binding| {
                binding.nonce != context.nonce || binding.context_digest != digest
            })
        {
            return Err(OwnerError::Verifier(LinkError::BindingMismatch));
        }
        Ok(())
    }

    /// Read only the current original recipient context. This cannot release SDK evidence.
    pub(crate) fn validate_endorsed_recipient(
        &mut self,
        scope: &cgka_traits::device_linking_key_package::PurposeAttemptScope,
        now: Instant,
    ) -> OwnerResult<LinkingContext> {
        use cgka_traits::StorageProvider;
        self.check_scope(scope)?;
        self.guard(now)?;
        let attempt = self.linker.live(now).map_err(OwnerError::Verifier)?;
        let context = &attempt.context;
        if attempt.role != Role::NewDevice
            || context.version != 2
            || context.predecessor.epoch == 0
            || context.predecessor.leaves.len() < 2
        {
            return Err(OwnerError::Verifier(LinkError::BindingMismatch));
        }
        let digest = context.digest().map_err(OwnerError::Verifier)?;
        let purpose = self
            .storage
            .device_linking_key_package_storage()
            .ok_or(OwnerError::Storage)?
            .purpose_key_package()
            .map_err(|_| OwnerError::Storage)?
            .ok_or(OwnerError::Verifier(LinkError::NotReady))?;
        if purpose.consumed
            || purpose.scope != *scope
            || purpose.public_bytes != context.exact_key_package
            || purpose.reference.as_slice() != context.key_package_reference
            || purpose.signature_public_key.as_slice() != context.recipient
            || purpose.context.as_ref().is_none_or(|binding| {
                binding.nonce != context.nonce || binding.context_digest != digest
            })
        {
            return Err(OwnerError::Verifier(LinkError::BindingMismatch));
        }
        Ok(context.clone())
    }

    /// Explicit broad approval is attached only to this verified original,
    /// before SDK custody is consumed. Metadata never restores that custody.
    pub(crate) fn native_sharing_context(
        &mut self,
        scope: &cgka_traits::device_linking_key_package::PurposeAttemptScope,
        now: Instant,
    ) -> OwnerResult<(LinkingContext, Instant)> {
        let (phase, _) = self.native_observation_for_scope(scope, now)?;
        if phase != crate::DeviceLinkingPhase::VerificationCompleteEnrollmentPending {
            return Err(OwnerError::Verifier(LinkError::NotReady));
        }
        self.guard(now)?;
        let reservation = self
            .reservation_deadline
            .ok_or(OwnerError::Verifier(LinkError::NotReady))?;
        let attempt = self.linker.live(now).map_err(OwnerError::Verifier)?;
        Ok((
            attempt.context.clone(),
            reservation.min(attempt.response_deadline.unwrap_or(attempt.setup_deadline)),
        ))
    }

    /// Private scheduling observation of the exact original live attempt.
    pub(crate) fn native_context_version(
        &mut self,
        scope: &cgka_traits::device_linking_key_package::PurposeAttemptScope,
        now: Instant,
    ) -> OwnerResult<u32> {
        self.check_scope(scope)?;
        self.guard(now)?;
        Ok(self
            .linker
            .live(now)
            .map_err(OwnerError::Verifier)?
            .context
            .version)
    }

    pub(crate) async fn take_verified(&mut self, now: Instant) -> OwnerResult<VerifiedPairing> {
        self.guard(now)?;
        // Deliver and acknowledge the stock done event before sealing the flow;
        // otherwise durable terminal admission would strand the peer verifier.
        let outgoing = self.linker.outgoing(now);
        let outgoing = self.after(outgoing)?;
        if !outgoing.is_empty() {
            return Err(OwnerError::Verifier(LinkError::NotReady));
        }
        let result = self.linker.take_verified(now).await;
        let mut verified = self.after(result)?;
        // SDK completion never starts another lifetime. Recheck after the await
        // and retain the reservation bound before finish clears owner state.
        self.check_deadline(Instant::now().max(now))?;
        verified.owner_deadline = Some(
            self.reservation_deadline
                .ok_or(OwnerError::Verifier(LinkError::NotReady))?,
        );
        self.finish(DeviceLinkingOutcome::PairingVerified)?;
        Ok(verified) // The only release point, after exact-generation terminal CAS.
    }
    /// Expire the original reservation without waiting for another SDK frame.
    /// Returns whether this owner still holds a live reservation.
    pub(crate) fn maintain(&mut self, now: Instant) -> OwnerResult<bool> {
        if let Some(outcome) = self.pending_terminal {
            self.finish(outcome)?;
            return Ok(false);
        }
        match self.check_deadline(now) {
            Err(OwnerError::Verifier(LinkError::Expired)) => Ok(false),
            result => result.map(|_| self.generation.is_some()),
        }
    }

    // Validate owner identity and current reservation before reading purpose state.
    // This is a negative scope fence, never verifier or publication permission.
    fn purpose_for_scope(
        &self,
        scope: &cgka_traits::device_linking_key_package::PurposeAttemptScope,
    ) -> OwnerResult<Option<cgka_traits::device_linking_key_package::PurposeKeyPackage>> {
        use cgka_traits::StorageProvider;
        if scope.account != self.account
            || scope.local_device != self.device
            || scope.generation == 0
            || scope.generation > i64::MAX as u64
        {
            return Err(OwnerError::Verifier(LinkError::BindingMismatch));
        }
        if self
            .generation
            .is_some_and(|generation| generation != scope.generation)
        {
            return Err(OwnerError::Verifier(LinkError::StaleFlow));
        }
        self.storage
            .device_linking_key_package_storage()
            .ok_or(OwnerError::Storage)?
            .purpose_key_package()
            .map_err(|_| OwnerError::Storage)
    }

    pub(crate) fn check_scope(
        &self,
        scope: &cgka_traits::device_linking_key_package::PurposeAttemptScope,
    ) -> OwnerResult<()> {
        if self.purpose_for_scope(scope)?.is_some_and(|package| {
            // A consumed package records a historical join. Only the exact
            // live owner reservation may supersede its old scope; neither
            // that row nor an arbitrary caller can create a new attempt.
            package.scope != *scope
                && !(package.consumed && self.generation == Some(scope.generation))
        }) {
            return Err(OwnerError::Verifier(LinkError::StaleFlow));
        }
        Ok(())
    }

    /// Caller must first match its actual retained SDK-owned invite exactly.
    /// A historical consumed join cannot veto that continuation after the
    /// verifier releases its reservation. Unconsumed purpose conflicts and
    /// storage errors still deny; this check cannot create a live continuation.
    pub(crate) fn check_retained_invite_scope(
        &self,
        scope: &cgka_traits::device_linking_key_package::PurposeAttemptScope,
    ) -> OwnerResult<()> {
        if self
            .purpose_for_scope(scope)?
            .is_some_and(|package| !package.consumed && package.scope != *scope)
        {
            return Err(OwnerError::Verifier(LinkError::StaleFlow));
        }
        Ok(())
    }
    pub(crate) fn unjoined_purpose_scope(
        &self,
    ) -> OwnerResult<Option<cgka_traits::device_linking_key_package::PurposeAttemptScope>> {
        use cgka_traits::StorageProvider;
        let purpose = self
            .storage
            .device_linking_key_package_storage()
            .ok_or(OwnerError::Storage)?;
        Ok(purpose
            .purpose_key_package()
            .map_err(|_| OwnerError::Storage)?
            .filter(|package| !package.consumed)
            .map(|package| package.scope))
    }
    pub(crate) fn cancel(&mut self) -> OwnerResult<()> {
        self.finish(DeviceLinkingOutcome::Cancelled)
    }
    pub(super) fn shutdown(&mut self) -> OwnerResult<()> {
        self.linker.shutdown();
        self.finish(DeviceLinkingOutcome::Shutdown)
    }
}
impl Drop for LinkingOwner {
    fn drop(&mut self) {
        // Always discard verifier secrets, including on reconnect/aborted work.
        // The app shutdown lease may already have closed SQLCipher. If the
        // durable write cannot run, the next exclusive startup abandons the
        // generation; no verifier secret or authorization is restored from SQL.
        if self.shutdown().is_err() {
            tracing::debug!(
                target: "marmot_app::device_linking",
                method = "owner_drop",
                "device linking shutdown fence deferred to exclusive startup"
            );
        }
    }
}
#[cfg(test)]
#[path = "owner_tests.rs"]
mod tests;
