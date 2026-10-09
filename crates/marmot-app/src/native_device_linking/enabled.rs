//! Verification-only native facade. The serial worker retains every SDK secret.
use super::*;
use crate::client::device_linking::{ClientLinkingError, setup::SetupPacket};
use crate::device_linking::{
    LinkError, LinkFrame, MAX_VERIFIER_PACKET_BYTES, OwnerError, PeerOffer,
};
use cgka_traits::device_linking_key_package::PurposeAttemptScope;
use std::sync::{
    Arc, Mutex,
    atomic::{AtomicBool, Ordering},
};
use tokio::sync::{Mutex as AsyncMutex, Notify, watch};

pub(super) struct SessionState {
    manager: AccountManager,
    account: String,
    scope: PurposeAttemptScope,
    setup: Vec<u8>,
    new_device: bool,
    operation: AsyncMutex<PacketProgress>,
    snapshot: Mutex<DeviceLinkingSnapshot>,
    updates: watch::Sender<DeviceLinkingSnapshot>,
    closed: AtomicBool,
    runtime: tokio::runtime::Handle,
}
#[derive(Default)]
struct PacketProgress {
    offer_acknowledged: bool,
    started: bool,
}
pub(super) struct SubscriptionState {
    receiver: AsyncMutex<(watch::Receiver<DeviceLinkingSnapshot>, bool)>,
    closed: AtomicBool,
    wake: Notify,
}
fn map_error(error: ClientLinkingError) -> DeviceLinkingError {
    match error {
        ClientLinkingError::Owner(OwnerError::Verifier(error)) => match error {
            LinkError::InvalidFrame
            | LinkError::InvalidContext
            | LinkError::BindingMismatch
            | LinkError::LimitExceeded => DeviceLinkingError::InvalidPacket,
            LinkError::NotReady => DeviceLinkingError::NotReady,
            LinkError::Expired
            | LinkError::Cancelled
            | LinkError::Closed
            | LinkError::StaleFlow
            | LinkError::AlreadyConsumed => DeviceLinkingError::Closed,
            _ => DeviceLinkingError::RuntimeUnavailable,
        },
        _ => DeviceLinkingError::RuntimeUnavailable,
    }
}
impl SessionState {
    fn check_open(&self) -> Result<(), DeviceLinkingError> {
        if self.closed.load(Ordering::Acquire) {
            Err(DeviceLinkingError::Closed)
        } else {
            Ok(())
        }
    }
    fn update(
        &self,
        phase: DeviceLinkingPhase,
        decimals: Option<DeviceLinkingDecimals>,
    ) -> DeviceLinkingSnapshot {
        let mut snapshot = self.snapshot.lock().expect("native observation lock");
        // Once terminal, late worker replies cannot revive the native session.
        if !matches!(
            snapshot.phase,
            DeviceLinkingPhase::Cancelled
                | DeviceLinkingPhase::Expired
                | DeviceLinkingPhase::Failed
        ) && (snapshot.phase != phase || snapshot.decimals != decimals)
        {
            snapshot.revision = snapshot.revision.saturating_add(1);
            snapshot.phase = phase;
            snapshot.decimals = decimals;
            self.updates.send_replace(snapshot.clone());
        }
        snapshot.clone()
    }
    async fn refresh(&self) -> Result<DeviceLinkingSnapshot, DeviceLinkingError> {
        if self.closed.load(Ordering::Acquire) {
            return Ok(self
                .snapshot
                .lock()
                .expect("native observation lock")
                .clone());
        }
        match self
            .manager
            .linking_native_observation(&self.account, &self.scope)
            .await
        {
            Ok((phase, decimals)) => Ok(self.update(phase, decimals)),
            Err(error) => {
                let phase = match &error {
                    ClientLinkingError::Owner(OwnerError::Verifier(LinkError::Expired)) => {
                        DeviceLinkingPhase::Expired
                    }
                    ClientLinkingError::Owner(OwnerError::Verifier(
                        LinkError::Cancelled
                        | LinkError::Closed
                        | LinkError::StaleFlow
                        | LinkError::AlreadyConsumed,
                    )) => DeviceLinkingPhase::Cancelled,
                    _ => DeviceLinkingPhase::Failed,
                };
                self.closed.store(true, Ordering::Release);
                Ok(self.update(phase, None))
            }
        }
    }
    fn close(&self) {
        self.closed.store(true, Ordering::Release);
        self.update(DeviceLinkingPhase::Cancelled, None);
    }
    fn defer_cleanup(&self) {
        let manager = self.manager.clone();
        let account = self.account.clone();
        let scope = self.scope.clone();
        self.runtime.spawn(async move {
            if manager.cancel_device_linking(&account, &scope).await.is_err() {
                tracing::debug!(target: "marmot_app::device_linking", "native session cleanup deferred");
            }
        });
    }
}
impl AccountManager {
    pub async fn begin_device_linking_session(
        &self,
        account_ref: &str,
    ) -> Result<DeviceLinkingSession, DeviceLinkingError> {
        let account = self
            .resolve(account_ref)
            .map_err(|_| DeviceLinkingError::RuntimeUnavailable)?
            .label;
        let packet = self
            .reserve_device_linking_setup(account_ref)
            .await
            .map_err(map_error)?;
        Ok(DeviceLinkingSession::new(
            self.clone(),
            account,
            packet,
            true,
        ))
    }
    pub async fn approve_device_linking_session(
        &self,
        account_ref: &str,
        request: Vec<u8>,
        target: Option<Vec<u8>>,
    ) -> Result<DeviceLinkingSession, DeviceLinkingError> {
        // Existing-group native enrollment remains unavailable until ABC admission qualifies.
        if target.is_some() {
            return Err(DeviceLinkingError::NotReady);
        }
        let account = self
            .resolve(account_ref)
            .map_err(|_| DeviceLinkingError::RuntimeUnavailable)?
            .label;
        let packet = self
            .approve_device_linking_setup(account_ref, request, None)
            .await
            .map_err(map_error)?;
        Ok(DeviceLinkingSession::new(
            self.clone(),
            account,
            packet,
            false,
        ))
    }
}
impl DeviceLinkingSession {
    fn new(
        manager: AccountManager,
        account: String,
        packet: SetupPacket,
        new_device: bool,
    ) -> Self {
        let snapshot = DeviceLinkingSnapshot {
            revision: 1,
            phase: if new_device {
                DeviceLinkingPhase::AwaitingSetup
            } else {
                DeviceLinkingPhase::AwaitingPeer
            },
            decimals: None,
        };
        let (updates, _) = watch::channel(snapshot.clone());
        let inner = Arc::new(SessionState {
            manager,
            account,
            scope: packet.scope,
            setup: packet.packet,
            new_device,
            operation: AsyncMutex::new(PacketProgress::default()),
            snapshot: Mutex::new(snapshot),
            updates,
            closed: AtomicBool::new(false),
            runtime: tokio::runtime::Handle::current(),
        });
        let weak = Arc::downgrade(&inner);
        inner.runtime.spawn(async move {
            loop {
                tokio::time::sleep(std::time::Duration::from_secs(1)).await;
                let Some(state) = weak.upgrade() else { break };
                if state.closed.load(Ordering::Acquire) {
                    break;
                }
                // Observe the original SDK with bounded purpose checks; never restore SQL permission.
                let _ = state.refresh().await;
            }
        });
        Self { inner }
    }
    pub fn setup_packet(&self) -> Vec<u8> {
        self.inner.setup.clone()
    }
    pub async fn receive_setup_packet(&self, packet: Vec<u8>) -> Result<(), DeviceLinkingError> {
        let _operation = self.inner.operation.lock().await;
        self.inner.check_open()?;
        if !self.inner.new_device {
            return Err(DeviceLinkingError::NotReady);
        }
        self.inner
            .manager
            .accept_device_linking_setup(&self.inner.account, &self.inner.scope, packet)
            .await
            .map_err(map_error)?;
        self.inner.check_open()?;
        self.inner.refresh().await?;
        Ok(())
    }
    pub async fn outgoing_packets(
        &self,
    ) -> Result<Vec<DeviceLinkingOutgoingPacket>, DeviceLinkingError> {
        let progress = self.inner.operation.lock().await;
        self.inner.check_open()?;
        let mut packets = Vec::new();
        if !progress.offer_acknowledged {
            let offer = self
                .inner
                .manager
                .device_linking_offer(&self.inner.account, &self.inner.scope)
                .await
                .map_err(map_error)?;
            packets.push(DeviceLinkingOutgoingPacket {
                acknowledgement_id: "offer".into(),
                bytes: offer
                    .encode_wire()
                    .map_err(|_| DeviceLinkingError::InvalidPacket)?,
            });
        }
        for frame in self
            .inner
            .manager
            .device_linking_outgoing(&self.inner.account, &self.inner.scope)
            .await
            .map_err(map_error)?
        {
            packets.push(DeviceLinkingOutgoingPacket {
                acknowledgement_id: format!("frame/{}", frame.acknowledgement_token()),
                bytes: frame
                    .encode_wire()
                    .map_err(|_| DeviceLinkingError::InvalidPacket)?,
            });
        }
        self.inner.check_open()?;
        Ok(packets)
    }
    pub async fn receive_packet(&self, packet: Vec<u8>) -> Result<(), DeviceLinkingError> {
        if packet.len() > MAX_VERIFIER_PACKET_BYTES {
            return Err(DeviceLinkingError::InvalidPacket);
        }
        let mut progress = self.inner.operation.lock().await;
        self.inner.check_open()?;
        match packet.get(5) {
            Some(1) => {
                let offer = PeerOffer::decode_wire(&packet)
                    .map_err(|_| DeviceLinkingError::InvalidPacket)?;
                self.inner
                    .manager
                    .admit_device_linking_peer(&self.inner.account, &self.inner.scope, offer)
                    .await
                    .map_err(map_error)?;
                self.inner.check_open()?;
                if self.inner.new_device && !progress.started {
                    self.inner
                        .manager
                        .start_device_linking_verification(&self.inner.account, &self.inner.scope)
                        .await
                        .map_err(map_error)?;
                    progress.started = true;
                }
            }
            Some(2) => {
                let frame = LinkFrame::decode_wire(&packet)
                    .map_err(|_| DeviceLinkingError::InvalidPacket)?;
                self.inner
                    .manager
                    .receive_device_linking_frame(&self.inner.account, &self.inner.scope, frame)
                    .await
                    .map_err(map_error)?;
            }
            _ => return Err(DeviceLinkingError::InvalidPacket),
        }
        self.inner.check_open()?;
        self.inner.refresh().await?;
        Ok(())
    }
    pub async fn acknowledge_packet(&self, id: String) -> Result<(), DeviceLinkingError> {
        if id.len() > 134 {
            return Err(DeviceLinkingError::InvalidPacket);
        }
        let mut progress = self.inner.operation.lock().await;
        self.inner.check_open()?;
        if id == "offer" {
            progress.offer_acknowledged = true;
        } else if let Some(token) = id.strip_prefix("frame/") {
            self.inner
                .manager
                .acknowledge_device_linking_frame(
                    &self.inner.account,
                    &self.inner.scope,
                    token.into(),
                )
                .await
                .map_err(map_error)?;
        } else {
            return Err(DeviceLinkingError::InvalidPacket);
        }
        self.inner.check_open()?;
        self.inner.refresh().await?;
        Ok(())
    }
    pub async fn snapshot(&self) -> Result<DeviceLinkingSnapshot, DeviceLinkingError> {
        self.inner.refresh().await
    }
    pub async fn confirm_comparison(&self, revision: u64) -> Result<(), DeviceLinkingError> {
        let _operation = self.inner.operation.lock().await;
        self.inner.check_open()?;
        let snapshot = self.inner.refresh().await?;
        self.inner.check_open()?;
        if snapshot.revision != revision {
            return Err(DeviceLinkingError::StaleRevision);
        }
        if snapshot.phase != DeviceLinkingPhase::ComparisonAvailable {
            return Err(DeviceLinkingError::NotReady);
        }
        self.inner
            .manager
            .confirm_device_linking(&self.inner.account, &self.inner.scope)
            .await
            .map_err(map_error)?;
        self.inner.check_open()?;
        self.inner.refresh().await?;
        Ok(())
    }
    pub fn subscribe(&self) -> DeviceLinkingSubscription {
        DeviceLinkingSubscription {
            inner: SubscriptionState {
                receiver: AsyncMutex::new((self.inner.updates.subscribe(), true)),
                closed: AtomicBool::new(false),
                wake: Notify::new(),
            },
        }
    }
    pub async fn cancel(&self) -> Result<(), DeviceLinkingError> {
        // Negative revocation bypasses the positive-operation lock.
        self.inner.close();
        self.inner
            .manager
            .cancel_device_linking(&self.inner.account, &self.inner.scope)
            .await
            .map_err(map_error)
    }
    pub async fn continue_linking(&self, _revision: u64) -> Result<(), DeviceLinkingError> {
        self.inner.check_open()?;
        Err(DeviceLinkingError::NotReady)
    }
}
impl Drop for DeviceLinkingSession {
    fn drop(&mut self) {
        self.inner.close();
        self.inner.defer_cleanup();
    }
}
impl DeviceLinkingSubscription {
    pub async fn next(&self) -> Result<DeviceLinkingSnapshot, DeviceLinkingError> {
        let notified = self.inner.wake.notified();
        tokio::pin!(notified);
        notified.as_mut().enable();
        if self.inner.closed.load(Ordering::Acquire) {
            return Err(DeviceLinkingError::Closed);
        }
        let mut state = tokio::select! {
            biased;
            _ = &mut notified => return Err(DeviceLinkingError::Closed),
            state = self.inner.receiver.lock() => state,
        };
        if !state.1 {
            tokio::select! {
                biased;
                _ = &mut notified => return Err(DeviceLinkingError::Closed),
                result = state.0.changed() => result.map_err(|_| DeviceLinkingError::Closed)?,
            }
        }
        state.1 = false;
        if self.inner.closed.load(Ordering::Acquire) {
            return Err(DeviceLinkingError::Closed);
        }
        Ok(state.0.borrow_and_update().clone())
    }
    pub fn close(&self) {
        self.inner.closed.store(true, Ordering::Release);
        self.inner.wake.notify_waiters();
    }
}
impl Drop for DeviceLinkingSubscription {
    fn drop(&mut self) {
        self.close();
    }
}
