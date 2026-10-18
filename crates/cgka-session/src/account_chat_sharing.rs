//! Forward actual Core originals; Session does not own approval or relay policy.
use super::AccountDeviceSession;
use cgka_engine::{
    account_chat_catalog::{
        AccountChatCatalog, AccountChatCatalogEntry, AccountChatCatalogJournal,
    },
    account_chat_sharing::{
        AccountSharedBodyKind, AccountSharingControl, AuthenticatedAccountSharingRequest,
        OwnedAccountSharingChannel, ReceivedAccountSharingControl, TrustedAccountSharingLease,
    },
};
use cgka_traits::{EngineError, GroupId, TransportMessage, source_leaf::SourceLeafProof};
use std::sync::Arc;
impl AccountDeviceSession {
    pub fn account_chat_sharing_targets(
        &self,
        protected: &GroupId,
    ) -> Result<cgka_engine::account_chat_sharing::AccountSharingTargets, EngineError> {
        self.engine.account_chat_sharing_targets(protected)
    }
    pub fn account_chat_catalog(
        &self,
        protected: &GroupId,
        after: Option<&GroupId>,
        limit: usize,
    ) -> Result<AccountChatCatalog, EngineError> {
        self.engine.account_chat_catalog(protected, after, limit)
    }
    pub fn account_chat_catalog_journal(
        &self,
        protected: &GroupId,
        after: Option<&GroupId>,
        limit: usize,
    ) -> Result<AccountChatCatalogJournal, EngineError> {
        self.engine
            .account_chat_catalog_journal(protected, after, limit)
    }
    pub fn account_chat_catalog_entry(
        &self,
        protected: &GroupId,
        group: &GroupId,
    ) -> Result<Option<AccountChatCatalogEntry>, EngineError> {
        self.engine.account_chat_catalog_entry(protected, group)
    }
    pub fn begin_account_sharing_policy(
        &self,
        protected: &GroupId,
        recipient: &[u8],
        lease: Arc<dyn TrustedAccountSharingLease>,
    ) -> Result<OwnedAccountSharingChannel, EngineError> {
        self.engine
            .begin_account_sharing_policy(protected, recipient, lease)
    }
    pub fn authenticate_received_account_sharing_control(
        &self,
        protected: &GroupId,
        source: &SourceLeafProof,
        wire: &[u8],
    ) -> Result<ReceivedAccountSharingControl, EngineError> {
        self.engine
            .authenticate_received_account_sharing_control(protected, source, wire)
    }
    pub fn authenticate_account_sharing_request(
        &self,
        wire: &[u8],
    ) -> Result<AuthenticatedAccountSharingRequest, EngineError> {
        self.engine.authenticate_account_sharing_request(wire)
    }
    pub fn approve_account_sharing_policy(
        &self,
        request: &AuthenticatedAccountSharingRequest,
        lease: Arc<dyn TrustedAccountSharingLease>,
    ) -> Result<OwnedAccountSharingChannel, EngineError> {
        self.engine.approve_account_sharing_policy(request, lease)
    }
    pub fn bind_account_sharing_consent(
        &self,
        channel: &mut OwnedAccountSharingChannel,
        wire: &[u8],
    ) -> Result<(), EngineError> {
        self.engine.bind_account_sharing_consent(channel, wire)
    }
    pub fn validate_account_sharing_channel(
        &self,
        channel: &OwnedAccountSharingChannel,
    ) -> Result<(), EngineError> {
        self.engine.validate_account_sharing_channel(channel)
    }
    pub fn seal_account_shared_body(
        &self,
        channel: &mut OwnedAccountSharingChannel,
        kind: AccountSharedBodyKind,
        sequence: u64,
        body: &[u8],
    ) -> Result<Vec<u8>, EngineError> {
        self.engine
            .seal_account_shared_body(channel, kind, sequence, body)
    }
    pub fn open_account_shared_body(
        &self,
        channel: &OwnedAccountSharingChannel,
        wire: &[u8],
    ) -> Result<(AccountSharedBodyKind, u64, Vec<u8>), EngineError> {
        self.engine.open_account_shared_body(channel, wire)
    }
    pub async fn wrap_account_sharing_control(
        &mut self,
        channel: &mut OwnedAccountSharingChannel,
        kind: AccountSharingControl,
    ) -> Result<TransportMessage, EngineError> {
        self.engine
            .wrap_account_sharing_control(channel, kind)
            .await
    }
}
