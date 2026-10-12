//! Negative user departure journal. Rows never supply membership or sharing authority.
use crate::{SqliteAccountStorage, SqliteResultExt};
use cgka_traits::{
    GroupId,
    mirrored_chat_catalog::AcceptedChatOrigin,
    storage::{StorageError, StorageResult},
};
use rusqlite::{OptionalExtension, params};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

pub const MAX_ACCOUNT_CHAT_DEPARTURES: usize = 8192;
pub const MAX_ACCOUNT_CHAT_DEPARTURE_TARGETS: usize = 128;
pub const MAX_ACCOUNT_CHAT_DEPARTURE_BYTES: usize = 65536;
const MAX_CUTS: usize = 32768;
const MAX_ROUTES: usize = 32768;

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AccountChatDepartureTarget {
    pub source_device: [u8; 32],
    pub accepted_origin: AcceptedChatOrigin,
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AccountChatDepartureIntent {
    pub version: u8,
    pub action_id: [u8; 32],
    pub account: [u8; 32],
    pub initiator: [u8; 32],
    pub protected_group: GroupId,
    pub group: GroupId,
    pub targets: Vec<AccountChatDepartureTarget>,
}

/// Durable negative work state, not an ordinary-MLS membership fact.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum AccountChatDepartureLocalState {
    Queued,
    Published,
    Complete,
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum AccountChatDepartureDeliveryKind {
    Intent,
    StatusReceipt,
    CompletionNotice,
    CompletionAcknowledgement,
}

#[derive(Clone)]
pub struct AccountChatDepartureProgress {
    pub action_id: [u8; 32],
    pub local_complete: bool,
    pub pending_peers: usize,
    pub needs_administrator: bool,
    pub awaiting_sources: bool,
    pub global_complete: bool,
}

#[derive(Clone)]
pub struct AccountChatDepartureDelivery {
    pub intent: AccountChatDepartureIntent,
    pub kind: AccountChatDepartureDeliveryKind,
    pub complete: bool,
    pub needs_administrator: bool,
    pub awaiting_sources: bool,
}

fn invalid() -> StorageError {
    StorageError::Serialization("invalid account chat departure".into())
}
fn capacity() -> StorageError {
    StorageError::Capacity("account chat departure capacity reached".into())
}
fn valid_group(group: &GroupId) -> bool {
    (1..=255).contains(&group.as_slice().len())
}

impl AccountChatDepartureIntent {
    /// Deterministic negative-intent identity. This digest never authenticates it.
    pub fn identity(&self) -> [u8; 32] {
        let mut h = Sha256::new();
        h.update(b"WN-account-chat-departure-v1");
        h.update(self.account);
        h.update(self.initiator);
        for group in [&self.protected_group, &self.group] {
            h.update((group.as_slice().len() as u16).to_be_bytes());
            h.update(group.as_slice());
        }
        for target in &self.targets {
            h.update(target.source_device);
            h.update(target.accepted_origin.id);
            h.update(target.accepted_origin.order.to_be_bytes());
        }
        h.finalize().into()
    }
    pub fn validate(&self) -> StorageResult<()> {
        if self.version != 1
            || self.account == [0; 32]
            || self.initiator == [0; 32]
            || !valid_group(&self.group)
            || !valid_group(&self.protected_group)
            || self.group == self.protected_group
            || self.targets.is_empty()
            || self.targets.len() > MAX_ACCOUNT_CHAT_DEPARTURE_TARGETS
            || self.targets.iter().any(|target| {
                target.source_device == [0; 32]
                    || target.accepted_origin.id == [0; 32]
                    || !(1..=8192).contains(&target.accepted_origin.order)
            })
            || self
                .targets
                .windows(2)
                .any(|pair| pair[0].source_device >= pair[1].source_device)
            || self.action_id != self.identity()
        {
            return Err(invalid());
        }
        Ok(())
    }
}

/// Shared locked-connection predicate for mirrored read/append transactions.
/// It acquires no second lock and creates no positive authority.
pub(crate) fn account_chat_departure_denies_source_on_connection(
    conn: &rusqlite::Connection,
    account: &[u8; 32],
    local: &[u8; 32],
    group: &GroupId,
    source: &[u8; 32],
    origin: Option<AcceptedChatOrigin>,
) -> StorageResult<bool> {
    crate::approved_account_sharing_policy::check_configured_owner(conn, account, local)?;
    let (id, order) = origin.map_or((vec![0; 32], 0), |origin| {
        (origin.id.to_vec(), origin.order)
    });
    conn.query_row("SELECT EXISTS(SELECT 1 FROM account_chat_departures d JOIN account_chat_departure_cuts c USING(action_id) WHERE d.account=?1 AND d.local_device=?2 AND d.group_id=?3 AND c.source_device=?4 AND (?5=0 OR c.origin_id=?6 OR c.origin_order>=?5))", params![account.as_slice(),local.as_slice(),group.as_slice(),source.as_slice(),order as i64,id], |row| row.get(0)).storage()
}

impl SqliteAccountStorage {
    /// Compose the durable cuts/outbox with caller work; validate the same actual
    /// owner before mutation and at SQL tail. Duplicate exact controls are idempotent.
    pub fn apply_account_chat_departure(
        &self,
        local: &[u8; 32],
        intent: &AccountChatDepartureIntent,
        peers: &[[u8; 32]],
        validate_original: &dyn Fn() -> StorageResult<()>,
    ) -> StorageResult<bool> {
        intent.validate()?;
        if peers.is_empty()
            || peers.len() > MAX_ACCOUNT_CHAT_DEPARTURE_TARGETS
            || peers.iter().any(|peer| peer == local || *peer == [0; 32])
            || peers.windows(2).any(|pair| pair[0] >= pair[1])
        {
            return Err(invalid());
        }
        // Received intent can reply only to its genuinely authenticated initiator.
        if *local != intent.initiator && peers != [intent.initiator] {
            return Err(invalid());
        }
        let record = serde_json::to_vec(intent).map_err(|_| invalid())?;
        if record.len() > MAX_ACCOUNT_CHAT_DEPARTURE_BYTES {
            return Err(capacity());
        }
        self.connection.with_transaction(|| {
            validate_original()?;
            let inserted;
            {
                let conn = self.lock()?;
                crate::approved_account_sharing_policy::check_configured_owner(&conn, &intent.account, local)?;
                let old: Option<Vec<u8>> = conn.query_row(
                    "SELECT record FROM account_chat_departures WHERE action_id=?1",
                    [intent.action_id.as_slice()], |row| row.get(0)).optional().storage()?;
                inserted = old.is_none();
                if old.as_ref().is_some_and(|old| old != &record) { return Err(invalid()); }
                if inserted {
                    let rows: i64 = conn.query_row("SELECT count(*) FROM account_chat_departures", [], |row| row.get(0)).storage()?;
                    let cuts: i64 = conn.query_row("SELECT count(*) FROM account_chat_departure_cuts", [], |row| row.get(0)).storage()?;
                    if rows >= MAX_ACCOUNT_CHAT_DEPARTURES as i64 || cuts + intent.targets.len() as i64 > MAX_CUTS as i64 { return Err(capacity()); }
                    conn.execute("INSERT INTO account_chat_departures(action_id,account,local_device,initiator,group_id,record) VALUES(?1,?2,?3,?4,?5,?6)", params![intent.action_id.as_slice(), intent.account.as_slice(), local.as_slice(), intent.initiator.as_slice(), intent.group.as_slice(), record]).storage()?;
                    for target in &intent.targets {
                        conn.execute("INSERT INTO account_chat_departure_cuts(action_id,source_device,origin_id,origin_order) VALUES(?1,?2,?3,?4)", params![intent.action_id.as_slice(),target.source_device.as_slice(),target.accepted_origin.id.as_slice(),target.accepted_origin.order as i64]).storage()?;
                    }
                }
                if *local != intent.initiator { conn.execute("UPDATE account_chat_departures SET reply_pending=1 WHERE action_id=?1", [intent.action_id.as_slice()]).storage()?; }
                for peer in peers {
                    let exists: bool = conn.query_row("SELECT EXISTS(SELECT 1 FROM account_chat_departure_routes WHERE action_id=?1 AND peer_device=?2)", params![intent.action_id.as_slice(),peer.as_slice()], |row| row.get(0)).storage()?;
                    if !exists {
                        let count: i64 = conn.query_row("SELECT count(*) FROM account_chat_departure_routes", [], |row| row.get(0)).storage()?;
                        if count >= MAX_ROUTES as i64 { return Err(capacity()); }
                        conn.execute("INSERT INTO account_chat_departure_routes(action_id,peer_device) VALUES(?1,?2)", params![intent.action_id.as_slice(),peer.as_slice()]).storage()?;
                    }
                }
            }
            validate_original()?;
            Ok(inserted)
        })
    }

    pub fn has_account_chat_departure(
        &self,
        account: &[u8; 32],
        local: &[u8; 32],
        group: &GroupId,
    ) -> StorageResult<bool> {
        let conn = self.lock()?;
        crate::approved_account_sharing_policy::check_configured_owner(&conn, account, local)?;
        conn.query_row("SELECT EXISTS(SELECT 1 FROM account_chat_departures WHERE account=?1 AND local_device=?2 AND group_id=?3)",params![account.as_slice(),local.as_slice(),group.as_slice()],|row|row.get(0)).storage()
    }

    /// Old/no-origin observations remain denied; an independently accepted new
    /// source lineage may supersede an older cut. No catalog sequence clears it.
    pub fn account_chat_departure_denies_source(
        &self,
        account: &[u8; 32],
        local: &[u8; 32],
        group: &GroupId,
        source: &[u8; 32],
        origin: Option<AcceptedChatOrigin>,
    ) -> StorageResult<bool> {
        let conn = self.lock()?;
        account_chat_departure_denies_source_on_connection(
            &conn, account, local, group, source, origin,
        )
    }

    pub fn account_chat_departure_outbox(
        &self,
        account: &[u8; 32],
        local: &[u8; 32],
        peer: &[u8; 32],
        after: Option<&[u8; 32]>,
        limit: usize,
    ) -> StorageResult<Vec<AccountChatDepartureDelivery>> {
        if !(1..=128).contains(&limit) {
            return Err(invalid());
        }
        let conn = self.lock()?;
        crate::approved_account_sharing_policy::check_configured_owner(&conn, account, local)?;
        let mut statement = conn.prepare("SELECT d.record,d.initiator,d.local_state,d.needs_administrator,d.global_complete,d.awaiting_sources FROM account_chat_departures d JOIN account_chat_departure_routes r USING(action_id) WHERE d.account=?1 AND d.local_device=?2 AND r.peer_device=?3 AND ((d.initiator!=d.local_device AND d.reply_pending=1) OR (d.initiator=d.local_device AND (r.complete=0 OR r.final_acknowledged=0))) AND (?4 IS NULL OR d.action_id>?4) ORDER BY d.action_id LIMIT ?5").storage()?;
        let rows = statement
            .query_map(
                params![
                    account.as_slice(),
                    local.as_slice(),
                    peer.as_slice(),
                    after.map(|id| id.as_slice()),
                    limit as i64
                ],
                |row| {
                    Ok((
                        row.get::<_, Vec<u8>>(0)?,
                        row.get::<_, Vec<u8>>(1)?,
                        row.get::<_, u8>(2)?,
                        row.get::<_, bool>(3)?,
                        row.get::<_, bool>(4)?,
                        row.get::<_, bool>(5)?,
                    ))
                },
            )
            .storage()?;
        rows.map(|row| {
            let (bytes, initiator, state, needs_administrator, global_complete, awaiting_sources) =
                row.storage()?;
            let intent: AccountChatDepartureIntent =
                serde_json::from_slice(&bytes).map_err(|_| invalid())?;
            intent.validate()?;
            let kind = if initiator == local.as_slice() {
                if global_complete {
                    AccountChatDepartureDeliveryKind::CompletionNotice
                } else {
                    AccountChatDepartureDeliveryKind::Intent
                }
            } else if global_complete {
                AccountChatDepartureDeliveryKind::CompletionAcknowledgement
            } else {
                AccountChatDepartureDeliveryKind::StatusReceipt
            };
            Ok(AccountChatDepartureDelivery {
                intent,
                kind,
                complete: state == 2,
                needs_administrator,
                awaiting_sources,
            })
        })
        .collect()
    }

    pub fn pending_local_account_chat_departures(
        &self,
        account: &[u8; 32],
        local: &[u8; 32],
        after: Option<&[u8; 32]>,
        limit: usize,
    ) -> StorageResult<Vec<(AccountChatDepartureIntent, AccountChatDepartureLocalState)>> {
        if !(1..=128).contains(&limit) {
            return Err(invalid());
        }
        let conn = self.lock()?;
        crate::approved_account_sharing_policy::check_configured_owner(&conn, account, local)?;
        let mut statement = conn.prepare("SELECT record,local_state FROM account_chat_departures WHERE account=?1 AND local_device=?2 AND local_state<2 AND (?3 IS NULL OR action_id>?3) ORDER BY action_id LIMIT ?4").storage()?;
        let rows = statement
            .query_map(
                params![
                    account.as_slice(),
                    local.as_slice(),
                    after.map(|id| id.as_slice()),
                    limit as i64
                ],
                |row| Ok((row.get::<_, Vec<u8>>(0)?, row.get::<_, u8>(1)?)),
            )
            .storage()?;
        rows.map(|row| {
            let (bytes, state) = row.storage()?;
            let intent: AccountChatDepartureIntent =
                serde_json::from_slice(&bytes).map_err(|_| invalid())?;
            intent.validate()?;
            Ok((
                intent,
                if state == 0 {
                    AccountChatDepartureLocalState::Queued
                } else {
                    AccountChatDepartureLocalState::Published
                },
            ))
        })
        .collect()
    }

    pub fn mark_account_chat_departure_local_state(
        &self,
        account: &[u8; 32],
        local: &[u8; 32],
        id: &[u8; 32],
        state: AccountChatDepartureLocalState,
        validate: &dyn Fn() -> StorageResult<()>,
    ) -> StorageResult<()> {
        self.connection.with_transaction(|| {
            validate()?;
            {
                let conn = self.lock()?;
                crate::approved_account_sharing_policy::check_configured_owner(&conn,account,local)?;
                let value = match state { AccountChatDepartureLocalState::Queued => 0, AccountChatDepartureLocalState::Published => 1, AccountChatDepartureLocalState::Complete => 2 };
                let changed = conn.execute("UPDATE account_chat_departures SET local_state=max(local_state,?4),reply_pending=1,needs_administrator=CASE WHEN ?4=2 THEN 0 ELSE needs_administrator END,awaiting_sources=CASE WHEN ?4=2 THEN 0 ELSE awaiting_sources END WHERE account=?1 AND local_device=?2 AND action_id=?3", params![account.as_slice(),local.as_slice(),id.as_slice(),value]).storage()?;
                if changed != 1 { return Err(invalid()); }
            }
            validate()
        })
    }

    pub fn acknowledge_account_chat_departure(
        &self,
        account: &[u8; 32],
        local: &[u8; 32],
        id: &[u8; 32],
        peer: &[u8; 32],
        complete: bool,
        needs_administrator: bool,
        awaiting_sources: bool,
        validate: &dyn Fn() -> StorageResult<()>,
    ) -> StorageResult<()> {
        if complete && (needs_administrator || awaiting_sources) {
            return Err(invalid());
        }
        self.connection.with_transaction(|| {
            validate()?;
            {
                let conn = self.lock()?;
                crate::approved_account_sharing_policy::check_configured_owner(&conn,account,local)?;
                let changed = conn.execute("UPDATE account_chat_departure_routes SET acknowledged=1,complete=max(complete,?5),needs_administrator=CASE WHEN complete=1 OR ?5=1 THEN 0 ELSE ?6 END,awaiting_sources=CASE WHEN complete=1 OR ?5=1 THEN 0 ELSE ?7 END WHERE action_id=?1 AND peer_device=?2 AND EXISTS(SELECT 1 FROM account_chat_departures d WHERE d.action_id=?1 AND d.account=?3 AND d.local_device=?4 AND d.initiator=?4)", params![id.as_slice(),peer.as_slice(),account.as_slice(),local.as_slice(),u8::from(complete),u8::from(needs_administrator),u8::from(awaiting_sources)]).storage()?;
                if changed != 1 { return Err(invalid()); }
            }
            validate()
        })
    }
    pub fn mark_account_chat_departure_needs_administrator(
        &self,
        account: &[u8; 32],
        local: &[u8; 32],
        id: &[u8; 32],
        needs: bool,
        validate: &dyn Fn() -> StorageResult<()>,
    ) -> StorageResult<()> {
        self.connection.with_transaction(|| {
            validate()?;
            {
                let conn = self.lock()?;
                crate::approved_account_sharing_policy::check_configured_owner(&conn,account,local)?;
                if conn.execute("UPDATE account_chat_departures SET needs_administrator=?4,reply_pending=1 WHERE account=?1 AND local_device=?2 AND action_id=?3 AND local_state<2", params![account.as_slice(),local.as_slice(),id.as_slice(),u8::from(needs)]).storage()? != 1 { return Err(invalid()); }
            }
            validate()
        })
    }

    pub fn mark_account_chat_departure_awaiting_sources(
        &self,
        account: &[u8; 32],
        local: &[u8; 32],
        id: &[u8; 32],
        awaiting: bool,
        validate: &dyn Fn() -> StorageResult<()>,
    ) -> StorageResult<()> {
        self.connection.with_transaction(|| {
            validate()?;
            {
                let conn=self.lock()?;
                crate::approved_account_sharing_policy::check_configured_owner(&conn,account,local)?;
                if conn.execute("UPDATE account_chat_departures SET awaiting_sources=?4,reply_pending=1 WHERE account=?1 AND local_device=?2 AND action_id=?3 AND local_state<2",params![account.as_slice(),local.as_slice(),id.as_slice(),u8::from(awaiting)]).storage()?!=1 { return Err(invalid()); }
            }
            validate()
        })
    }

    /// Negative progress only. Receipt observations never supply membership facts.
    pub fn account_chat_departure_progress(
        &self,
        account: &[u8; 32],
        local: &[u8; 32],
        group: &GroupId,
    ) -> StorageResult<Option<AccountChatDepartureProgress>> {
        let conn = self.lock()?;
        crate::approved_account_sharing_policy::check_configured_owner(&conn, account, local)?;
        let row: Option<(Vec<u8>,bool,bool,bool,bool,bool)> = conn.query_row(
            "SELECT action_id,local_state=2,needs_administrator,initiator=local_device,global_complete,awaiting_sources FROM account_chat_departures WHERE account=?1 AND local_device=?2 AND group_id=?3 ORDER BY rowid DESC LIMIT 1",
            params![account.as_slice(),local.as_slice(),group.as_slice()], |row| Ok((row.get(0)?,row.get(1)?,row.get(2)?,row.get(3)?,row.get(4)?,row.get(5)?)),
        ).optional().storage()?;
        let Some((
            id,
            local_complete,
            local_blocked,
            is_initiator,
            global_complete,
            local_awaiting,
        )) = row
        else {
            return Ok(None);
        };
        let (pending,peer_blocked,peer_awaiting): (i64,bool,bool) = conn.query_row(
            "SELECT coalesce(sum(complete=0),0),coalesce(max(needs_administrator),0),coalesce(max(awaiting_sources),0) FROM account_chat_departure_routes WHERE action_id=?1",
            [id.as_slice()], |row| Ok((row.get(0)?,row.get(1)?,row.get(2)?)),
        ).storage()?;
        Ok(Some(AccountChatDepartureProgress {
            action_id: id.try_into().map_err(|_| invalid())?,
            local_complete,
            pending_peers: if is_initiator { pending as usize } else { 0 },
            needs_administrator: local_blocked || (is_initiator && peer_blocked),
            awaiting_sources: local_awaiting || (is_initiator && peer_awaiting),
            global_complete: global_complete || (is_initiator && local_complete && pending == 0),
        }))
    }

    /// Final receipt metadata is accepted only for an existing exact negative
    /// operation and authenticated opposite role. It cannot complete local MLS.
    pub fn account_chat_departure_completion(
        &self,
        account: &[u8; 32],
        local: &[u8; 32],
        id: &[u8; 32],
        peer: &[u8; 32],
        acknowledgement: bool,
        validate: &dyn Fn() -> StorageResult<()>,
    ) -> StorageResult<()> {
        self.connection.with_transaction(|| {
            validate()?;
            {
                let conn = self.lock()?;
                crate::approved_account_sharing_policy::check_configured_owner(&conn,account,local)?;
                let changed = if acknowledgement {
                    conn.execute("UPDATE account_chat_departure_routes SET final_acknowledged=1 WHERE action_id=?1 AND peer_device=?2 AND complete=1 AND EXISTS(SELECT 1 FROM account_chat_departures d WHERE d.action_id=?1 AND d.account=?3 AND d.local_device=?4 AND d.initiator=?4 AND d.global_complete=1)", params![id.as_slice(),peer.as_slice(),account.as_slice(),local.as_slice()]).storage()?
                } else {
                    conn.execute("UPDATE account_chat_departures SET global_complete=1,reply_pending=1 WHERE action_id=?1 AND account=?3 AND local_device=?4 AND initiator=?2 AND local_state=2", params![id.as_slice(),peer.as_slice(),account.as_slice(),local.as_slice()]).storage()?
                };
                if changed!=1 { return Err(invalid()); }
            }
            validate()
        })
    }

    /// Schedule coordinator completion only after all actual per-device receipts
    /// plus local completion. These rows remain observations, never authority.
    pub fn finalize_account_chat_departure_coordinator(
        &self,
        account: &[u8; 32],
        local: &[u8; 32],
        validate: &dyn Fn() -> StorageResult<()>,
    ) -> StorageResult<()> {
        self.connection.with_transaction(|| {
            validate()?;
            {
                let conn = self.lock()?;
                crate::approved_account_sharing_policy::check_configured_owner(&conn,account,local)?;
                conn.execute("UPDATE account_chat_departures SET global_complete=1 WHERE account=?1 AND local_device=?2 AND initiator=?2 AND local_state=2 AND global_complete=0 AND NOT EXISTS(SELECT 1 FROM account_chat_departure_routes r WHERE r.action_id=account_chat_departures.action_id AND r.complete=0)", params![account.as_slice(),local.as_slice()]).storage()?;
            }
            validate()
        })
    }

    /// Relay ACK only releases this receipt attempt; it does not assert remote
    /// commit. A new authenticated retry requeues the same negative operation.
    pub fn account_chat_departure_reply_published(
        &self,
        account: &[u8; 32],
        local: &[u8; 32],
        id: &[u8; 32],
        validate: &dyn Fn() -> StorageResult<()>,
    ) -> StorageResult<()> {
        self.connection.with_transaction(|| {
            validate()?;
            {
                let conn = self.lock()?;
                crate::approved_account_sharing_policy::check_configured_owner(&conn,account,local)?;
                conn.execute("UPDATE account_chat_departures SET reply_pending=0 WHERE account=?1 AND local_device=?2 AND action_id=?3 AND initiator!=local_device", params![account.as_slice(),local.as_slice(),id.as_slice()]).storage()?;
            }
            validate()
        })
    }
}

#[cfg(test)]
mod tests;
