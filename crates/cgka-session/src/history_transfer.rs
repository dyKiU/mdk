//! Original Core history continuations; no serialized grant or key exports.
use super::AccountDeviceSession;
use cgka_engine::history_transfer::{
    AuthenticatedHistoryRequest, HistoryControl, HistoryScope, HistorySnapshotDescriptor,
    OpenedHistoryChunk, OwnedHistoryChannel, ReceivedHistoryControl, TrustedHistoryLease,
};
use cgka_traits::{EngineError, GroupId, TransportMessage};
use std::sync::Arc;
impl AccountDeviceSession {
    #[cfg(feature = "test-policy-overrides")]
    pub fn discard_original_history_request_ciphertext_for_test(
        &self,
        channel: &mut OwnedHistoryChannel,
    ) -> Result<(), EngineError> {
        self.engine
            .discard_original_history_request_ciphertext_for_test(channel)
    }

    pub fn begin_history_snapshot_channel(
        &self,
        ordinary: &GroupId,
        protected: &GroupId,
        recipient: &[u8],
        lease: Arc<dyn TrustedHistoryLease>,
        build: &dyn Fn(&HistoryScope) -> Result<HistorySnapshotDescriptor, EngineError>,
    ) -> Result<OwnedHistoryChannel, EngineError> {
        self.engine
            .begin_history_snapshot_channel(ordinary, protected, recipient, lease, build)
    }
    pub fn authenticate_received_history_control(
        &self,
        protected: &GroupId,
        source: &cgka_traits::source_leaf::SourceLeafProof,
        wire: &[u8],
    ) -> Result<ReceivedHistoryControl, EngineError> {
        self.engine
            .authenticate_received_history_control(protected, source, wire)
    }
    pub fn authenticate_history_request(
        &self,
        wire: &[u8],
    ) -> Result<AuthenticatedHistoryRequest, EngineError> {
        self.engine.authenticate_history_request(wire)
    }
    pub fn approve_history_channel(
        &self,
        request: &AuthenticatedHistoryRequest,
        lease: Arc<dyn TrustedHistoryLease>,
    ) -> Result<OwnedHistoryChannel, EngineError> {
        self.engine.approve_history_channel(request, lease)
    }
    pub fn bind_history_consent(
        &self,
        channel: &mut OwnedHistoryChannel,
        wire: &[u8],
    ) -> Result<(), EngineError> {
        self.engine.bind_history_consent(channel, wire)
    }
    pub fn validate_history_channel(
        &self,
        channel: &OwnedHistoryChannel,
    ) -> Result<(), EngineError> {
        self.engine.validate_history_channel(channel)
    }
    pub fn seal_history_chunk(
        &self,
        channel: &mut OwnedHistoryChannel,
        archive: [u8; 32],
        ordinal: u32,
        body: &[u8],
        receipt: bool,
    ) -> Result<Vec<u8>, EngineError> {
        self.engine
            .seal_history_chunk(channel, archive, ordinal, body, receipt)
    }
    pub fn open_history_chunk(
        &self,
        channel: &mut OwnedHistoryChannel,
        wire: &[u8],
    ) -> Result<OpenedHistoryChunk, EngineError> {
        self.engine.open_history_chunk(channel, wire)
    }
    pub async fn wrap_history_control(
        &mut self,
        channel: &mut OwnedHistoryChannel,
        kind: HistoryControl,
    ) -> Result<TransportMessage, EngineError> {
        self.engine.wrap_history_control(channel, kind).await
    }
}
