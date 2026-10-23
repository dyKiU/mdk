//! QR display is a transport role, separate from the SDK's enrollment role.
use super::*;
use crate::device_linking::network::{
    Bootstrap, Channel,
    rendezvous::{self, Rendezvous},
};
use nostr::prelude::{Keys, Timestamp};
use std::time::{Duration, Instant};
use tokio_util::sync::CancellationToken;

enum Start {
    Original(Arc<DeviceLinkingSession>),
    Display {
        keys: Keys,
        rendezvous: Rendezvous,
        target: Vec<u8>,
    },
    Scan {
        keys: Keys,
        rendezvous: Rendezvous,
    },
}
/// No SDK scope or proof is fabricated for the pending transport. Once selected,
/// the genuine original is retained and cancelled together with this host handle.
pub(in super::super) struct State {
    manager: AccountManager,
    account: String,
    deadline: Instant,
    cancellation: CancellationToken,
    original: Mutex<Option<Arc<DeviceLinkingSession>>>,
    start: AsyncMutex<Option<Start>>,
    code: Mutex<String>,
    updates: watch::Sender<DeviceLinkingSnapshot>,
}
fn wire_error(_: crate::device_linking::network::Error) -> DeviceLinkingError {
    DeviceLinkingError::InvalidPacket
}
impl State {
    #[cfg(all(test, feature = "test-policy-overrides"))]
    pub(in super::super) fn original_for_test(&self) -> Option<Arc<DeviceLinkingSession>> {
        self.original().ok()
    }

    fn create_session(
        manager: AccountManager,
        account: String,
        deadline: Instant,
        code: String,
        start: Start,
    ) -> AutomaticDeviceLinkingSession {
        let (updates, _) = watch::channel(DeviceLinkingSnapshot {
            revision: 0,
            phase: DeviceLinkingPhase::AwaitingSetup,
            decimals: None,
        });
        AutomaticDeviceLinkingSession {
            inner: Arc::new(Self {
                manager,
                account,
                deadline,
                cancellation: CancellationToken::new(),
                original: Mutex::new(None),
                start: AsyncMutex::new(Some(start)),
                code: Mutex::new(code),
                updates,
            }),
        }
    }
    fn check(&self) -> Result<(), DeviceLinkingError> {
        if self.cancellation.is_cancelled() || Instant::now() >= self.deadline {
            Err(DeviceLinkingError::Closed)
        } else {
            Ok(())
        }
    }
    pub(in super::super) fn close(&self) {
        self.retire(DeviceLinkingPhase::Cancelled);
    }
    fn retire(&self, phase: DeviceLinkingPhase) {
        // Negative fence precedes every asynchronous wait and adoption lock.
        self.cancellation.cancel();
        // A handle cancelled before activation still owns a genuine reservation.
        // Drop it now; if activation holds the lock its post-await fence closes it.
        if let Ok(mut start) = self.start.try_lock() {
            start.take();
        }
        if let Some(original) = self.original.lock().expect("negotiated original").take() {
            original.inner.close();
            original.inner.defer_cleanup();
        }
        self.updates.send_if_modified(|snapshot| {
            if matches!(
                snapshot.phase,
                DeviceLinkingPhase::EnrollmentComplete
                    | DeviceLinkingPhase::Failed
                    | DeviceLinkingPhase::Expired
                    | DeviceLinkingPhase::Cancelled
            ) {
                return false;
            }
            snapshot.revision = snapshot.revision.saturating_add(1);
            snapshot.phase = phase;
            snapshot.decimals = None;
            true
        });
    }
    fn original(&self) -> Result<Arc<DeviceLinkingSession>, DeviceLinkingError> {
        self.check()?;
        self.original
            .lock()
            .expect("negotiated original")
            .clone()
            .ok_or(DeviceLinkingError::NotReady)
    }
    fn adopt(
        self: &Arc<Self>,
        original: Arc<DeviceLinkingSession>,
    ) -> Result<(), DeviceLinkingError> {
        let mut slot = self.original.lock().expect("negotiated original");
        self.check()?;
        if slot.is_some() {
            return Err(DeviceLinkingError::NotReady);
        }
        let subscription = original.subscribe();
        *slot = Some(original);
        let weak = Arc::downgrade(self);
        let cancellation = self.cancellation.clone();
        tokio::spawn(async move {
            loop {
                let observation = tokio::select! { biased; _ = cancellation.cancelled() => break, value = subscription.next() => value };
                let Ok(observation) = observation else {
                    break;
                };
                let Some(state) = weak.upgrade() else {
                    break;
                };
                if state.cancellation.is_cancelled() {
                    break;
                }
                state.updates.send_if_modified(|snapshot| {
                    if state.cancellation.is_cancelled() {
                        return false;
                    }
                    *snapshot = observation;
                    true
                });
            }
            subscription.close();
        });
        Ok(())
    }
    pub(in super::super) async fn automatic_pairing_code(
        self: &Arc<Self>,
    ) -> Result<String, DeviceLinkingError> {
        self.check()?;
        let mut start = self.start.lock().await;
        self.check()?;
        let Some(plan) = start.take() else {
            return Ok(self.code.lock().expect("negotiated code").clone());
        };
        if let Start::Original(original) = plan {
            let result = async {
                self.adopt(original.clone())?;
                let code = original.automatic_pairing_code().await?;
                self.check()?;
                *self.code.lock().expect("negotiated code") = code.clone();
                Ok(code)
            }
            .await;
            if result.is_err() && !self.cancellation.is_cancelled() {
                self.retire(DeviceLinkingPhase::Failed);
            }
            return result;
        }
        let weak = Arc::downgrade(self);
        let cancellation = self.cancellation.clone();
        tokio::spawn(async move {
            let Some(state) = weak.upgrade() else {
                return;
            };
            let result = tokio::select! {
                biased;
                _ = cancellation.cancelled() => return,
                _ = tokio::time::sleep_until(state.deadline.into()) => Err(DeviceLinkingError::Closed),
                result = state.run(plan) => result,
            };
            if result.is_err() && !cancellation.is_cancelled() {
                state.retire(if Instant::now() >= state.deadline {
                    DeviceLinkingPhase::Expired
                } else {
                    DeviceLinkingPhase::Failed
                });
            }
        });
        Ok(self.code.lock().expect("negotiated code").clone())
    }
    async fn run(self: &Arc<Self>, plan: Start) -> Result<(), DeviceLinkingError> {
        match plan {
            Start::Original(original) => {
                self.adopt(original.clone())?;
                original.automatic_pairing_code().await?;
            }
            Start::Display {
                keys,
                rendezvous,
                target,
            } => {
                let channel = Channel::new(
                    keys,
                    rendezvous.bootstrap(),
                    Timestamp::now().as_secs(),
                    self.deadline,
                )
                .map_err(wire_error)?;
                let (plane, endpoints) = self.manager.device_pairing_transport();
                let mut mailbox = plane
                    .pairing_mailbox(endpoints, channel.public_key(), self.deadline)
                    .await
                    .map_err(|_| DeviceLinkingError::RuntimeUnavailable)?;
                loop {
                    self.check()?;
                    let Some(event) = mailbox
                        .next()
                        .await
                        .map_err(|_| DeviceLinkingError::RuntimeUnavailable)?
                    else {
                        continue;
                    };
                    let Ok(message) =
                        channel.open(event.pubkey, &event, Timestamp::now().as_secs())
                    else {
                        continue;
                    };
                    let Ok(code) = rendezvous::receive_reverse_hello(
                        &rendezvous,
                        &message,
                        Timestamp::now().as_secs(),
                    ) else {
                        continue;
                    };
                    // Re-read the protected roster; the QR's scheduling choice is never a grant.
                    let current = self.manager.device_linking_targets(&self.account).await?;
                    if current.len() != 1 || current[0].selector != target {
                        return Err(DeviceLinkingError::NotReady);
                    }
                    let original = Arc::new(
                        self.manager
                            .approve_automatic_device_linking_session(
                                &self.account,
                                code.to_string(),
                                Some(target),
                            )
                            .await?,
                    );
                    self.adopt(original.clone())?;
                    original.automatic_pairing_code().await?;
                    break;
                }
            }
            Start::Scan { keys, rendezvous } => {
                let original = Arc::new(
                    self.manager
                        .begin_device_linking_session_until(&self.account, self.deadline)
                        .await?,
                );
                self.adopt(original.clone())?;
                let code = original.automatic_pairing_code().await?;
                let channel = Channel::new(
                    keys,
                    rendezvous.bootstrap(),
                    Timestamp::now().as_secs(),
                    self.deadline,
                )
                .map_err(wire_error)?;
                let message =
                    rendezvous::reverse_hello(&rendezvous, code, Timestamp::now().as_secs())
                        .map_err(wire_error)?;
                let (plane, endpoints) = self.manager.device_pairing_transport();
                let mut mailbox = plane
                    .pairing_mailbox(endpoints, channel.public_key(), self.deadline)
                    .await
                    .map_err(|_| DeviceLinkingError::RuntimeUnavailable)?;
                loop {
                    self.check()?;
                    let event = channel
                        .seal(
                            rendezvous.bootstrap().public_key,
                            &message,
                            Timestamp::now().as_secs(),
                        )
                        .map_err(wire_error)?;
                    // Retransmission is bounded by the original scanned QR deadline.
                    let _ = mailbox.publish(&event).await;
                    let observation = original.snapshot().await?;
                    if matches!(
                        observation.phase,
                        DeviceLinkingPhase::ComparisonAvailable
                            | DeviceLinkingPhase::AwaitingPeerVerification
                            | DeviceLinkingPhase::VerificationCompleteEnrollmentPending
                            | DeviceLinkingPhase::EnrollmentComplete
                    ) {
                        break;
                    }
                    if matches!(
                        observation.phase,
                        DeviceLinkingPhase::Failed
                            | DeviceLinkingPhase::Cancelled
                            | DeviceLinkingPhase::Expired
                    ) {
                        return Err(DeviceLinkingError::Closed);
                    }
                    tokio::time::sleep(Duration::from_secs(1)).await;
                }
            }
        }
        Ok(())
    }
    pub(in super::super) fn setup_packet(&self) -> Vec<u8> {
        self.code
            .lock()
            .expect("negotiated code")
            .as_bytes()
            .to_vec()
    }
    pub(in super::super) async fn snapshot(
        &self,
    ) -> Result<DeviceLinkingSnapshot, DeviceLinkingError> {
        if let Ok(original) = self.original() {
            return original.snapshot().await;
        }
        Ok(self.updates.borrow().clone())
    }
    pub(in super::super) fn subscribe(&self) -> DeviceLinkingSubscription {
        DeviceLinkingSubscription {
            inner: SubscriptionState {
                receiver: AsyncMutex::new((self.updates.subscribe(), true)),
                closed: AtomicBool::new(false),
                wake: Notify::new(),
            },
        }
    }
    pub(in super::super) async fn confirm_comparison(
        &self,
        revision: u64,
    ) -> Result<(), DeviceLinkingError> {
        self.original()?.confirm_comparison(revision).await
    }
    pub(in super::super) async fn continue_automatic_linking(
        &self,
        revision: u64,
        share_chats: bool,
    ) -> Result<(), DeviceLinkingError> {
        self.original()?
            .continue_automatic_linking(revision, share_chats)
            .await
    }
    pub(in super::super) async fn cancel(&self) -> Result<(), DeviceLinkingError> {
        self.cancellation.cancel();
        let original = self.original.lock().expect("negotiated original").clone();
        let pending = self
            .start
            .try_lock()
            .ok()
            .and_then(|mut start| start.take());
        // Revoke the SDK original before waiting for a positive activation.
        // Retain any unactivated reservation so explicit Cancel can await cleanup.
        self.close();
        let pending = match pending {
            Some(pending) => Some(pending),
            None => self.start.lock().await.take(),
        };
        if let Some(original) = original {
            original.cancel().await?;
        }
        if let Some(Start::Original(original)) = pending {
            original.cancel().await?;
        }
        Ok(())
    }
}
impl AccountManager {
    pub async fn begin_automatic_device_linking_session(
        &self,
        account_ref: &str,
    ) -> Result<AutomaticDeviceLinkingSession, DeviceLinkingError> {
        let deadline = Instant::now() + Duration::from_secs(600);
        let targets = self.device_linking_targets(account_ref).await?;
        if targets.len() > 1 {
            return Err(DeviceLinkingError::NotReady);
        }
        if let Some(target) = targets.into_iter().next() {
            let keys = Keys::generate();
            let rendezvous = Rendezvous::new(
                keys.public_key(),
                Timestamp::now().as_secs()
                    + deadline.saturating_duration_since(Instant::now()).as_secs(),
            );
            let code = rendezvous
                .encode(Timestamp::now().as_secs())
                .map_err(wire_error)?;
            Ok(State::create_session(
                self.clone(),
                account_ref.into(),
                deadline,
                code,
                Start::Display {
                    keys,
                    rendezvous,
                    target: target.selector,
                },
            ))
        } else {
            let original = Arc::new(
                self.begin_device_linking_session_until(account_ref, deadline)
                    .await?,
            );
            // The direct mailbox activates only after the host adopts this handle.
            let code = String::new();
            Ok(State::create_session(
                self.clone(),
                account_ref.into(),
                deadline,
                code,
                Start::Original(original),
            ))
        }
    }
    pub async fn scan_automatic_device_linking_session(
        &self,
        account_ref: &str,
        code: String,
    ) -> Result<AutomaticDeviceLinkingSession, DeviceLinkingError> {
        let now = Timestamp::now().as_secs();
        let targets = self.device_linking_targets(account_ref).await?;
        if targets.len() > 1 {
            return Err(DeviceLinkingError::NotReady);
        }
        if code.starts_with("WNPAIR2:") {
            let rendezvous = Rendezvous::decode(&code, now).map_err(wire_error)?;
            if !targets.is_empty() {
                return Err(DeviceLinkingError::NotReady);
            }
            let deadline =
                Instant::now() + Duration::from_secs(rendezvous.bootstrap().expires_at - now);
            Ok(State::create_session(
                self.clone(),
                account_ref.into(),
                deadline,
                code,
                Start::Scan {
                    keys: Keys::generate(),
                    rendezvous,
                },
            ))
        } else {
            let bootstrap = Bootstrap::decode(&code, now).map_err(wire_error)?;
            let deadline = Instant::now() + Duration::from_secs(bootstrap.expires_at - now);
            let original = Arc::new(
                self.approve_automatic_device_linking_session(
                    account_ref,
                    code.clone(),
                    targets.into_iter().next().map(|target| target.selector),
                )
                .await?,
            );
            Ok(State::create_session(
                self.clone(),
                account_ref.into(),
                deadline,
                code,
                Start::Original(original),
            ))
        }
    }
}

#[cfg(all(test, feature = "test-policy-overrides"))]
mod tests {
    use super::*;
    use crate::{MarmotApp, MarmotAppRuntime};

    #[tokio::test]
    async fn cancel_before_activation_retires_the_reserved_original() {
        let relay = nostr_relay_builder::MockRelay::run().await.unwrap();
        let dir = tempfile::tempdir().unwrap();
        let keys = Keys::generate();
        crate::AccountHome::open(dir.path())
            .import_account("test", &keys.secret_key().to_secret_hex())
            .unwrap();
        let runtime = MarmotAppRuntime::new(MarmotApp::with_relay(
            dir.path(),
            relay.url().await.to_string(),
        ));
        runtime.reconcile_accounts().await.unwrap();
        let accounts = runtime.accounts();
        let session = accounts
            .begin_automatic_device_linking_session("test")
            .await
            .unwrap();
        session.cancel().await.unwrap();
        assert_eq!(
            session.automatic_pairing_code().await,
            Err(DeviceLinkingError::Closed)
        );
        assert_eq!(
            session.snapshot().await.unwrap().phase,
            DeviceLinkingPhase::Cancelled
        );
        let fresh = accounts.begin_device_linking_session("test").await.unwrap();
        fresh.cancel().await.unwrap();
        runtime.shutdown_and_close().await.unwrap();
    }

    #[tokio::test]
    async fn cancellation_revokes_original_before_waiting_for_activation_lock() {
        let relay = nostr_relay_builder::MockRelay::run().await.unwrap();
        let dir = tempfile::tempdir().unwrap();
        let keys = Keys::generate();
        crate::AccountHome::open(dir.path())
            .import_account("test", &keys.secret_key().to_secret_hex())
            .unwrap();
        let runtime = MarmotAppRuntime::new(MarmotApp::with_relay(
            dir.path(),
            relay.url().await.to_string(),
        ));
        runtime.reconcile_accounts().await.unwrap();
        let session = runtime
            .accounts()
            .begin_automatic_device_linking_session("test")
            .await
            .unwrap();
        let mut activation = session.inner.start.lock().await;
        let Some(Start::Original(original)) = activation.take() else {
            panic!("fresh fixture must own a real reservation");
        };
        let retired = original.automatic_retirement_probe_for_test();
        session.inner.adopt(original).unwrap();
        let state = session.inner.clone();
        let cancellation = tokio::spawn(async move { state.cancel().await });
        session.inner.cancellation.cancelled().await;
        let revoked_before_unlock = retired();
        drop(activation);
        cancellation.await.unwrap().unwrap();
        runtime.shutdown_and_close().await.unwrap();
        assert!(
            revoked_before_unlock,
            "negative SDK revocation must precede the positive activation lock wait"
        );
    }

    #[tokio::test]
    async fn cancelled_transport_rejects_and_retires_a_late_genuine_original() {
        let relay = nostr_relay_builder::MockRelay::run().await.unwrap();
        let dir = tempfile::tempdir().unwrap();
        let keys = Keys::generate();
        crate::AccountHome::open(dir.path())
            .import_account("test", &keys.secret_key().to_secret_hex())
            .unwrap();
        let runtime = MarmotAppRuntime::new(MarmotApp::with_relay(
            dir.path(),
            relay.url().await.to_string(),
        ));
        runtime.reconcile_accounts().await.unwrap();
        let accounts = runtime.accounts();
        let rendezvous = Rendezvous::new(
            Keys::generate().public_key(),
            Timestamp::now().as_secs() + 600,
        );
        let pending = State::create_session(
            accounts.clone(),
            "test".into(),
            Instant::now() + Duration::from_secs(600),
            rendezvous.encode(Timestamp::now().as_secs()).unwrap(),
            Start::Scan {
                keys: Keys::generate(),
                rendezvous,
            },
        );
        pending.cancel().await.unwrap();
        // This is the real SDK-created reservation, delivered after transport
        // cancellation. The probe borrows state, never the owning session.
        let original = accounts.begin_device_linking_session("test").await.unwrap();
        let retired = original.automatic_retirement_probe_for_test();
        assert_eq!(
            pending.inner.adopt(Arc::new(original)),
            Err(DeviceLinkingError::Closed)
        );
        assert!(retired());
        assert_eq!(
            pending.snapshot().await.unwrap().phase,
            DeviceLinkingPhase::Cancelled
        );
        runtime.shutdown_and_close().await.unwrap();
    }
}
