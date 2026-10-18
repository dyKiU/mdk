//! Durable origin correlation, separate from actual-member publication.
use super::*;
mod transport;
use crate::local_submissions::LocalMessageRequest;
use cgka_traits::account_chat_send_queue::{
    AccountChatSendIntent, AccountChatSendRoute, AccountChatSendState,
};
pub(super) use transport::SendProgress;

fn unavailable() -> crate::AppError {
    crate::AppError::InvalidAppMessagePayload("approved chat forwarding is unavailable".into())
}

pub(crate) fn forwarding_intent_id(
    account: &[u8; 32],
    local: &[u8; 32],
    group: &crate::GroupId,
    token: &str,
) -> [u8; 32] {
    let mut hash = Sha256::new();
    hash.update(b"WN-account-chat-client-token-v1");
    hash.update(account);
    hash.update(local);
    hash.update((group.as_slice().len() as u16).to_be_bytes());
    hash.update(group.as_slice());
    hash.update((token.len() as u16).to_be_bytes());
    hash.update(token.as_bytes());
    hash.finalize().into()
}

impl AppClient {
    fn forwarding_scope(
        &self,
        policy: &ApprovedAccountSharingPolicy,
    ) -> Result<MirroredChatScope, crate::AppError> {
        self.automatic_policy_current(policy)
            .map_err(|error| match error {
                AccountSharingError::RuntimeUnavailable => crate::AppError::TransportClosed,
                _ => unavailable(),
            })?;
        let catalog = self
            .runtime
            .session()
            .account_chat_catalog(&policy.protected_group, None, 1)
            .map_err(cgka_session::SessionError::Engine)?;
        Ok(MirroredChatScope {
            account: policy.account,
            local_device: policy.local_device,
            source_device: policy.peer_device,
            policy_digest: Self::automatic_policy_id(policy).map_err(|_| unavailable())?,
            protected_group: policy.protected_group.clone(),
            protected_generation: catalog.settlement_generation,
        })
    }

    pub(crate) fn admit_forwarded_chat(
        &self,
        group: &crate::GroupId,
        token: String,
        request: LocalMessageRequest,
    ) -> Result<crate::LocalSendAcceptance, crate::AppError> {
        if token.is_empty() || token.len() > 128 {
            return Err(crate::AppError::InvalidAppMessagePayload(
                "client token must contain 1 to 128 UTF-8 bytes".into(),
            ));
        }
        // Media needs an actual member's fresh epoch-bound upload path. Do not
        // treat an origin mirror as an encryption or membership authority.
        if !request.attachments.is_empty() {
            return Err(crate::AppError::InvalidAppMessagePayload(
                "forwarded media upload is unavailable".into(),
            ));
        }
        let storage = self.app.account_storage(&self.state.label)?;
        let policies = storage
            .approved_account_sharing_policy_storage()
            .ok_or_else(unavailable)?
            .approved_account_sharing_policies()?;
        let catalog = storage
            .mirrored_chat_catalog_storage()
            .ok_or_else(unavailable)?;
        let mut routes = Vec::new();
        for policy in policies {
            if policy.revoked {
                continue;
            }
            match self.automatic_policy_current(&policy) {
                Err(AccountSharingError::Closed) => continue,
                Err(AccountSharingError::RuntimeUnavailable) => {
                    return Err(crate::AppError::TransportClosed);
                }
                Err(_) => return Err(unavailable()),
                Ok(()) => {}
            }
            let scope = self.forwarding_scope(&policy)?;
            let mut after = None;
            loop {
                let page = catalog.mirrored_chat_catalog_page(&scope, after.as_ref(), 128)?;
                if let Some(row) = page.iter().find(|row| &row.group_id == group) {
                    if row.state == MirroredChatState::Active
                        && !storage.app_storage().account_chat_departure_denies_source(
                            &scope.account,
                            &scope.local_device,
                            group,
                            &scope.source_device,
                            row.accepted_origin,
                        )?
                    {
                        routes.push((policy, scope));
                    }
                    break;
                }
                if page.len() < 128
                    || page
                        .last()
                        .is_some_and(|row| row.group_id.as_slice() > group.as_slice())
                {
                    break;
                }
                after = page.last().map(|row| row.group_id.clone());
            }
        }
        if routes.is_empty() {
            let identity = self.runtime.session().self_id();
            use cgka_traits::storage::AccountDeviceSignerStorage;
            if let Some(signer) = storage.account_device_signer(&identity)? {
                let account: [u8; 32] =
                    identity.as_slice().try_into().map_err(|_| unavailable())?;
                let local: [u8; 32] = signer
                    .mls_signature_public_key
                    .as_slice()
                    .try_into()
                    .map_err(|_| unavailable())?;
                if storage.app_storage().has_account_chat_departure(&account, &local, group)? {
                    return Err(crate::AppError::AccountChatDepartureDenied);
                }
            }
        }
        let (first, _) = routes.first().ok_or_else(unavailable)?;
        let queue = storage
            .account_chat_send_queue_storage()
            .ok_or_else(unavailable)?;
        let intent_id = forwarding_intent_id(&first.account, &first.local_device, group, &token);
        let old =
            queue.account_chat_send_intent(&first.account, &first.local_device, &intent_id)?;
        let created_at = old
            .as_ref()
            .map_or_else(crate::unix_now_seconds, |old| old.intent.created_at);
        let event = crate::messages::build_inner_event_with_media_reply(
            &request.intent(),
            &hex::encode(first.account),
            created_at,
            None,
        )?;
        let payload = crate::messages::encode_inner_event(&event)?;
        let ordinary_event_id = hex::decode(&event.id)
            .map_err(|_| unavailable())?
            .try_into()
            .map_err(|_| unavailable())?;
        let intent = AccountChatSendIntent {
            intent_id,
            account: first.account,
            originating_device: first.local_device,
            group: group.clone(),
            ordinary_event_id,
            payload_digest: Sha256::digest(&payload).into(),
            event_payload: payload,
            created_at,
        };
        if old.as_ref().is_some_and(|old| {
            old.intent.payload_digest != intent.payload_digest
                || old.intent.ordinary_event_id != intent.ordinary_event_id
        }) {
            return Err(crate::AppError::InvalidAppMessagePayload(
                "client token is already bound to another forwarded submission".into(),
            ));
        }
        cgka_traits::StorageProvider::with_transaction(&storage, |_| {
            for (policy, scope) in &routes {
                let validate = || {
                    use cgka_traits::storage::StorageError;
                    let current = self.forwarding_scope(policy).map_err(|error| match error {
                        crate::AppError::Storage(error)
                        | crate::AppError::Session(cgka_session::SessionError::Storage(error))
                        | crate::AppError::Session(cgka_session::SessionError::Engine(
                            cgka_traits::EngineError::Storage(error),
                        )) => error,
                        crate::AppError::TransportClosed => {
                            StorageError::Backend("forwarding runtime unavailable".into())
                        }
                        _ => StorageError::Serialization(
                            "original forwarding admission unavailable".into(),
                        ),
                    })?;
                    if &current != scope {
                        return Err(StorageError::Serialization(
                            "original forwarding admission changed".into(),
                        ));
                    }
                    let mut after = None;
                    loop {
                        let page =
                            catalog.mirrored_chat_catalog_page(scope, after.as_ref(), 128)?;
                        if let Some(row) = page.iter().find(|row| &row.group_id == group) {
                            if row.state == MirroredChatState::Active {
                                return Ok(());
                            }
                            break;
                        }
                        if page.len() < 128
                            || page
                                .last()
                                .is_some_and(|row| row.group_id.as_slice() > group.as_slice())
                        {
                            break;
                        }
                        after = page.last().map(|row| row.group_id.clone());
                    }
                    Err(StorageError::Serialization(
                        "original forwarding catalog is unavailable".into(),
                    ))
                };
                queue.admit_account_chat_send_intent(
                    &intent,
                    &AccountChatSendRoute {
                        policy_id: scope.policy_digest,
                        local_device: policy.local_device,
                        peer_device: policy.peer_device,
                    },
                    &validate,
                )?;
            }
            Ok::<(), crate::AppError>(())
        })?;
        Ok(crate::LocalSendAcceptance {
            client_token: token,
            message_id_hex: event.id,
        })
    }
}

impl crate::MarmotApp {
    pub(crate) fn forwarded_local_send_status(
        &self,
        account_ref: &str,
        group: &crate::GroupId,
        token: &str,
    ) -> Result<Option<crate::LocalSendStatus>, crate::AppError> {
        use cgka_traits::storage::AccountDeviceSignerStorage;
        if token.is_empty() || token.len() > 128 {
            return Err(unavailable());
        }
        let account = self.account_home().account(account_ref)?;
        let storage = self.account_storage(&account.label)?;
        let Some(queue) = storage.account_chat_send_queue_storage() else {
            return Ok(None);
        };
        let account_key: [u8; 32] = hex::decode(&account.account_id_hex)
            .map_err(|_| unavailable())?
            .try_into()
            .map_err(|_| unavailable())?;
        let Some(binding) =
            storage.account_device_signer(&cgka_traits::MemberId::new(account_key.to_vec()))?
        else {
            return Ok(None);
        };
        let local: [u8; 32] = binding
            .mls_signature_public_key
            .try_into()
            .map_err(|_| unavailable())?;
        let id = forwarding_intent_id(&account_key, &local, group, token);
        let Some(observation) = queue.account_chat_send_intent(&account_key, &local, &id)? else {
            return Ok(None);
        };
        Ok(Some(match observation.state {
            AccountChatSendState::Queued | AccountChatSendState::Received => {
                crate::LocalSendStatus::Queued
            }
            AccountChatSendState::Denied => crate::LocalSendStatus::Rejected,
            AccountChatSendState::Published { event_id } => {
                if event_id != observation.intent.ordinary_event_id {
                    return Err(unavailable());
                }
                crate::LocalSendStatus::Completed(crate::SendSummary {
                    published: 1,
                    message_ids: vec![hex::encode(event_id)],
                    accept_disposition: cgka_traits::SendAcceptDisposition::Published,
                    maintenance_disposition: cgka_traits::SendMaintenanceDisposition::Ready,
                })
            }
        }))
    }
}
