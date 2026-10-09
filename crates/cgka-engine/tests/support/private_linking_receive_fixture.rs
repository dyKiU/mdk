// Shared real-MLS receive fixture with injected policy, never SDK consent.
struct BatchPeeler;
// Included with both a stateful integration MockPeeler and a unit peeler.
// Default is the common construction contract for those test contexts.
#[allow(clippy::default_constructed_unit_structs)]
#[async_trait]
impl TransportPeeler for BatchPeeler {
    async fn peel_group_message(
        &self,
        m: &TransportMessage,
        c: &GroupContextSnapshot,
    ) -> Result<PeeledMessage, PeelerError> {
        MockPeeler::default().peel_group_message(m, c).await
    }
    async fn peel_welcome(&self, m: &TransportMessage) -> Result<PeeledMessage, PeelerError> {
        MockPeeler::default().peel_welcome(m).await
    }
    async fn wrap_group_message(
        &self,
        p: &EncryptedPayload,
        c: &GroupContextSnapshot,
    ) -> Result<TransportMessage, PeelerError> {
        MockPeeler::default().wrap_group_message(p, c).await
    }
    async fn wrap_welcome(
        &self,
        p: &EncryptedPayload,
        r: &MemberId,
    ) -> Result<TransportMessage, PeelerError> {
        MockPeeler::default().wrap_welcome(p, r).await
    }
    async fn wrap_private_linking_welcome(
        &self,
        p: &EncryptedPayload,
        c: &PrivateLinkingWelcomeContext,
    ) -> Result<Vec<TransportMessage>, PeelerError> {
        Ok(vec![
            self.wrap_welcome(p, &MemberId::new(c.account.to_vec()))
                .await?,
        ])
    }
    async fn peel_private_linking_welcome_batch(
        &self,
        m: &[TransportMessage],
        _: &PrivateLinkingWelcomeContext,
    ) -> Result<Vec<u8>, PeelerError> {
        if m.len() != 1 {
            return Err(PeelerError::Malformed(
                "fixture complete batch required".into(),
            ));
        }
        Ok(m[0].payload.clone())
    }
}
#[derive(Clone)]
struct IncomingPolicy {
    purpose: PurposeKeyPackage,
    context: PrivateLinkingWelcomeContext,
    predecessor: DeviceGroupAnchorRoster,
    successor: DeviceGroupAnchorRoster,
    live: Arc<AtomicBool>,
    consumed: Arc<AtomicUsize>,
    expire_after_predecessor: bool,
}
struct IncomingLease(IncomingPolicy);
impl LinkingWelcomePolicy for IncomingPolicy {
    fn begin_join(
        &self,
        purpose: &PurposeKeyPackage,
    ) -> Result<Box<dyn LinkingWelcomeLease>, LinkingWelcomeDenied> {
        if *purpose != self.purpose {
            return Err(LinkingWelcomeDenied::ContextMismatch);
        }
        Ok(Box::new(IncomingLease(self.clone())))
    }
}
impl LinkingWelcomeLease for IncomingLease {
    fn check_transport_context(
        &mut self,
        c: &PrivateLinkingWelcomeContext,
    ) -> Result<(), LinkingWelcomeDenied> {
        if *c != self.0.context {
            return Err(LinkingWelcomeDenied::ContextMismatch);
        }
        self.check_live_before_commit()
    }
    fn approved_predecessor(&mut self) -> Result<DeviceGroupAnchorRoster, LinkingWelcomeDenied> {
        self.check_live_before_commit()?;
        let predecessor = self.0.predecessor.clone();
        if self.0.expire_after_predecessor {
            self.0.live.store(false, Ordering::SeqCst);
        }
        Ok(predecessor)
    }
    fn check_authenticated(
        &mut self,
        actual: &AuthenticatedLinkingWelcome,
    ) -> Result<(), LinkingWelcomeDenied> {
        if actual.group_id != self.0.context.group_id
            || actual.joined_epoch != self.0.successor.epoch
            || actual.epoch_authenticator_digest != self.0.successor.epoch_authenticator_digest
            || actual.leaves.len() != self.0.successor.leaves.len()
            || actual
                .leaves
                .iter()
                .zip(&self.0.successor.leaves)
                .any(|(a, b)| {
                    a.leaf_index != b.leaf_index
                        || a.account.as_slice() != b.account
                        || a.signature_public_key != b.signature_public_key
                })
        {
            return Err(LinkingWelcomeDenied::ContextMismatch);
        }
        self.check_live_before_commit()
    }
    fn check_live_before_commit(&mut self) -> Result<(), LinkingWelcomeDenied> {
        if self.0.live.load(Ordering::SeqCst) {
            Ok(())
        } else {
            Err(LinkingWelcomeDenied::Expired)
        }
    }
    fn commit_accepted(self: Box<Self>, _: &cgka_traits::accepted_welcome::AcceptedWelcomeReceipt) {
        self.0.consumed.fetch_add(1, Ordering::SeqCst);
    }
}
