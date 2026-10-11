//! Exact event retry across independent actual members; no live grant reconstruction.
use crate::{
    SqliteAccountStorage, SqliteResultExt, approved_account_sharing_policy::check_configured_owner,
};
use cgka_traits::{
    GroupId,
    account_chat_send_queue::*,
    app_event::MarmotAppEvent,
    approved_account_sharing_policy::ApprovedAccountSharingPolicy,
    storage::{StorageError, StorageResult},
};
use rusqlite::{Connection, OptionalExtension, Row, params};
use sha2::{Digest, Sha256};

fn invalid() -> StorageError {
    StorageError::Serialization("invalid account chat send metadata".into())
}
fn check_intent(intent: &AccountChatSendIntent) -> StorageResult<()> {
    if [
        intent.intent_id,
        intent.account,
        intent.originating_device,
        intent.ordinary_event_id,
        intent.payload_digest,
    ]
    .contains(&[0; 32])
        || !(1..=255).contains(&intent.group.as_slice().len())
        || intent.created_at > i64::MAX as u64
        || intent.event_payload.is_empty()
        || intent.event_payload.len() > MAX_ACCOUNT_CHAT_SEND_PAYLOAD
        || <[u8; 32]>::from(Sha256::digest(&intent.event_payload)) != intent.payload_digest
    {
        return Err(invalid());
    }
    let event = MarmotAppEvent::decode(&intent.event_payload).map_err(|_| invalid())?;
    if event.pubkey != hex::encode(intent.account)
        || event.id != hex::encode(intent.ordinary_event_id)
        || event.created_at != intent.created_at
    {
        return Err(invalid());
    }
    Ok(())
}
fn check_route(
    conn: &Connection,
    account: &[u8; 32],
    route: &AccountChatSendRoute,
) -> StorageResult<()> {
    if route.policy_id == [0; 32]
        || route.local_device == [0; 32]
        || route.peer_device == [0; 32]
        || route.local_device == route.peer_device
    {
        return Err(invalid());
    }
    check_configured_owner(conn, account, &route.local_device)?;
    let bytes:Vec<u8>=conn.query_row("SELECT record FROM approved_account_sharing_policies WHERE policy_id=?1 AND account=?2 AND local_device=?3 AND revoked=0",params![route.policy_id.as_slice(),account.as_slice(),route.local_device.as_slice()],|r|r.get(0)).storage()?;
    let policy: ApprovedAccountSharingPolicy =
        serde_json::from_slice(&bytes).map_err(|_| invalid())?;
    if policy.peer_device != route.peer_device {
        return Err(invalid());
    }
    Ok(())
}
fn fixed(row: &Row<'_>, col: usize) -> rusqlite::Result<[u8; 32]> {
    let b: Vec<u8> = row.get(col)?;
    b.try_into().map_err(|_| rusqlite::Error::InvalidQuery)
}
fn read_intent(row: &Row<'_>) -> rusqlite::Result<AccountChatSendIntent> {
    Ok(AccountChatSendIntent {
        intent_id: fixed(row, 0)?,
        account: fixed(row, 1)?,
        originating_device: fixed(row, 2)?,
        group: GroupId::new(row.get::<_, Vec<u8>>(3)?),
        ordinary_event_id: fixed(row, 4)?,
        event_payload: row.get(5)?,
        payload_digest: fixed(row, 6)?,
        created_at: row.get::<_, i64>(7)? as u64,
    })
}
const INTENT_COLUMNS: &str =
    "intent_id,account,origin,group_id,event_id,payload,digest,created_at,state";
fn load(conn: &Connection, id: &[u8; 32]) -> StorageResult<Option<(AccountChatSendIntent, i64)>> {
    conn.query_row(
        &format!("SELECT {INTENT_COLUMNS} FROM account_chat_send_intents WHERE intent_id=?1"),
        [id.as_slice()],
        |r| Ok((read_intent(r)?, r.get(8)?)),
    )
    .optional()
    .storage()
}
fn state_code(state: &AccountChatSendState) -> i64 {
    match state {
        AccountChatSendState::Queued => 0,
        AccountChatSendState::Received => 1,
        AccountChatSendState::Published { .. } => 2,
        AccountChatSendState::Denied => 3,
    }
}
fn state_from(code: i64, id: [u8; 32]) -> StorageResult<AccountChatSendState> {
    match code {
        0 => Ok(AccountChatSendState::Queued),
        1 => Ok(AccountChatSendState::Received),
        2 => Ok(AccountChatSendState::Published { event_id: id }),
        3 => Ok(AccountChatSendState::Denied),
        _ => Err(invalid()),
    }
}
fn same_identity(a: &AccountChatSendIntent, b: &AccountChatSendIntent) -> bool {
    a.intent_id == b.intent_id
        && a.account == b.account
        && a.originating_device == b.originating_device
        && a.group == b.group
        && a.ordinary_event_id == b.ordinary_event_id
        && a.payload_digest == b.payload_digest
        && a.created_at == b.created_at
}
fn receipt_transition(
    storage: &SqliteAccountStorage,
    account: &[u8; 32],
    receipt: &AccountChatSendReceipt,
    outgoing: bool,
    validate_original: &dyn Fn() -> StorageResult<()>,
) -> StorageResult<()> {
    let status = state_code(&receipt.state);
    if status == 0
        || receipt.actual_member_device == [0; 32]
        || (outgoing && receipt.actual_member_device != receipt.route.local_device)
        || (!outgoing && receipt.actual_member_device != receipt.route.peer_device)
    {
        return Err(invalid());
    }
    storage.connection.with_transaction(|| {
        validate_original()?;let conn=storage.lock()?;check_route(&conn,account,&receipt.route)?;
        let (intent,global)=load(&conn,&receipt.intent_id)?.ok_or_else(invalid)?;
        if intent.account!=*account || global==3 || matches!(receipt.state,AccountChatSendState::Published{event_id} if event_id!=intent.ordinary_event_id) {return Err(invalid());}
        let (previous,member):(i64,Option<Vec<u8>>)=conn.query_row("SELECT state,member FROM account_chat_send_routes WHERE intent_id=?1 AND policy_id=?2 AND local_device=?3 AND peer_device=?4",params![receipt.intent_id.as_slice(),receipt.route.policy_id.as_slice(),receipt.route.local_device.as_slice(),receipt.route.peer_device.as_slice()],|r|Ok((r.get(0)?,r.get(1)?))).storage()?;
        if previous==status {
            if member.as_deref()!=Some(receipt.actual_member_device.as_slice()) {return Err(invalid());}
        } else if previous>status && previous==2 && status==1 {
            // Late Received ACK cannot regress confirmed publication.
        } else {
            if global==2 && status!=2 {return Err(invalid());}
            conn.execute("UPDATE account_chat_send_routes SET state=?3,member=?4 WHERE intent_id=?1 AND policy_id=?2",params![receipt.intent_id.as_slice(),receipt.route.policy_id.as_slice(),status,receipt.actual_member_device.as_slice()]).storage()?;
        }
        if status==2 && global==0 {
            conn.execute("UPDATE account_chat_send_intents SET state=2,payload=x'' WHERE intent_id=?1",[receipt.intent_id.as_slice()]).storage()?;
        }
        if outgoing {
            let digest=receipt.digest(); let encoded=serde_json::to_vec(receipt).map_err(|_|invalid())?;
            let old:Option<Vec<u8>>=conn.query_row("SELECT record FROM account_chat_send_receipts WHERE digest=?1",[digest.as_slice()],|r|r.get(0)).optional().storage()?;
            if let Some(old)=old {if old!=encoded {return Err(invalid());}} else {
                conn.execute("INSERT INTO account_chat_send_receipts VALUES(?1,?2,?3,?4,0)",params![digest.as_slice(),receipt.intent_id.as_slice(),receipt.route.policy_id.as_slice(),encoded]).storage()?;
            }
        }
        drop(conn);validate_original()?;Ok(())
    })
}
impl AccountChatSendQueueStorage for SqliteAccountStorage {
    fn account_chat_send_intent(
        &self,
        account: &[u8; 32],
        local: &[u8; 32],
        id: &[u8; 32],
    ) -> StorageResult<Option<AccountChatSendIntentObservation>> {
        if id == &[0; 32] {
            return Err(invalid());
        }
        let conn = self.lock()?;
        check_configured_owner(&conn, account, local)?;
        let Some((intent, global)) = load(&conn, id)? else {
            return Ok(None);
        };
        if intent.account != *account {
            return Err(invalid());
        }
        let mut state = state_from(global, intent.ordinary_event_id)?;
        if global == 0 {
            check_intent(&intent)?;
            let received:bool=conn.query_row("SELECT EXISTS(SELECT 1 FROM account_chat_send_routes WHERE intent_id=?1 AND state=1)",[id.as_slice()],|r|r.get(0)).storage()?;
            if received {
                state = AccountChatSendState::Received;
            }
        } else if !intent.event_payload.is_empty() {
            return Err(invalid());
        }
        Ok(Some(AccountChatSendIntentObservation { intent, state }))
    }
    fn admit_account_chat_send_intent(
        &self,
        intent: &AccountChatSendIntent,
        route: &AccountChatSendRoute,
        validate_original: &dyn Fn() -> StorageResult<()>,
    ) -> StorageResult<()> {
        check_intent(intent)?;
        if intent.originating_device != route.local_device
            && intent.originating_device != route.peer_device
        {
            return Err(invalid());
        }
        self.connection.with_transaction(|| {
            validate_original()?;let conn=self.lock()?;check_route(&conn,&intent.account,route)?;
            if let Some((old,state))=load(&conn,&intent.intent_id)? {
                if !same_identity(&old,intent) || (state==0 && old.event_payload!=intent.event_payload) || state==3 {return Err(invalid());}
                if state==2 {drop(conn);validate_original()?;return Ok(());}
            } else {
                conn.execute("INSERT INTO account_chat_send_intents VALUES(?1,?2,?3,?4,?5,?6,?7,?8,0)",params![intent.intent_id.as_slice(),intent.account.as_slice(),intent.originating_device.as_slice(),intent.group.as_slice(),intent.ordinary_event_id.as_slice(),intent.event_payload,intent.payload_digest.as_slice(),intent.created_at as i64]).storage()?;
            }
            let previous:Option<(Vec<u8>,Vec<u8>,i64)>=conn.query_row("SELECT local_device,peer_device,state FROM account_chat_send_routes WHERE intent_id=?1 AND policy_id=?2",params![intent.intent_id.as_slice(),route.policy_id.as_slice()],|r|Ok((r.get(0)?,r.get(1)?,r.get(2)?))).optional().storage()?;
            if let Some((local,peer,status))=previous {
                if local!=route.local_device || peer!=route.peer_device || status==3 {return Err(invalid());}
            } else {
                conn.execute("INSERT INTO account_chat_send_routes VALUES(?1,?2,?3,?4,0,NULL)",params![intent.intent_id.as_slice(),route.policy_id.as_slice(),route.local_device.as_slice(),route.peer_device.as_slice()]).storage()?;
            }
            drop(conn);validate_original()?;Ok(())
        })
    }
    fn pending_account_chat_sends(
        &self,
        account: &[u8; 32],
        local: &[u8; 32],
        after: Option<&AccountChatSendCursor>,
        limit: usize,
    ) -> StorageResult<Vec<AccountChatQueuedSend>> {
        if !(1..=MAX_ACCOUNT_CHAT_SEND_PAGE).contains(&limit) {
            return Err(invalid());
        }
        let conn = self.lock()?;
        check_configured_owner(&conn, account, local)?;
        let mut statement=conn.prepare("SELECT i.intent_id,i.account,i.origin,i.group_id,i.event_id,i.payload,i.digest,i.created_at,r.policy_id,r.local_device,r.peer_device,r.state FROM account_chat_send_intents i JOIN account_chat_send_routes r USING(intent_id) JOIN approved_account_sharing_policies p USING(policy_id) WHERE i.account=?1 AND r.local_device=?2 AND i.state=0 AND r.state IN (0,1) AND p.revoked=0 AND (?4=0 OR (i.intent_id,r.policy_id)>(?5,?6)) ORDER BY i.intent_id,r.policy_id LIMIT ?3").storage()?;
        let rows = statement
            .query_map(
                params![
                    account.as_slice(),
                    local.as_slice(),
                    limit as i64,
                    after.is_some(),
                    after.map(|c| c.intent_id.as_slice()).unwrap_or(&[]),
                    after.map(|c| c.policy_id.as_slice()).unwrap_or(&[])
                ],
                |r| {
                    Ok((
                        read_intent(r)?,
                        AccountChatSendRoute {
                            policy_id: fixed(r, 8)?,
                            local_device: fixed(r, 9)?,
                            peer_device: fixed(r, 10)?,
                        },
                        r.get::<_, i64>(11)?,
                    ))
                },
            )
            .storage()?;
        let mut out = Vec::new();
        for row in rows {
            let (intent, route, state) = row.storage()?;
            check_intent(&intent)?;
            let state = state_from(state, intent.ordinary_event_id)?;
            out.push(AccountChatQueuedSend {
                intent,
                route,
                state,
            });
        }
        Ok(out)
    }
    fn stage_account_chat_send_receipt(
        &self,
        account: &[u8; 32],
        receipt: &AccountChatSendReceipt,
        validator: &dyn Fn() -> StorageResult<()>,
    ) -> StorageResult<()> {
        receipt_transition(self, account, receipt, true, validator)
    }
    fn receive_account_chat_send_receipt(
        &self,
        account: &[u8; 32],
        receipt: &AccountChatSendReceipt,
        validator: &dyn Fn() -> StorageResult<()>,
    ) -> StorageResult<()> {
        receipt_transition(self, account, receipt, false, validator)
    }
    fn pending_account_chat_send_receipts(
        &self,
        account: &[u8; 32],
        local: &[u8; 32],
        after_digest: Option<&[u8; 32]>,
        limit: usize,
    ) -> StorageResult<Vec<AccountChatSendReceipt>> {
        if !(1..=MAX_ACCOUNT_CHAT_SEND_PAGE).contains(&limit) {
            return Err(invalid());
        }
        let conn = self.lock()?;
        check_configured_owner(&conn, account, local)?;
        let mut statement=conn.prepare("SELECT o.digest,o.record FROM account_chat_send_receipts o JOIN account_chat_send_routes r USING(intent_id,policy_id) JOIN account_chat_send_intents i USING(intent_id) JOIN approved_account_sharing_policies p USING(policy_id) WHERE i.account=?1 AND r.local_device=?2 AND o.acknowledged=0 AND i.state!=3 AND p.revoked=0 AND (?4=0 OR o.digest>?5) ORDER BY o.digest LIMIT ?3").storage()?;
        let rows = statement
            .query_map(
                params![
                    account.as_slice(),
                    local.as_slice(),
                    limit as i64,
                    after_digest.is_some(),
                    after_digest.map(|d| d.as_slice()).unwrap_or(&[])
                ],
                |r| Ok((fixed(r, 0)?, r.get::<_, Vec<u8>>(1)?)),
            )
            .storage()?;
        let mut out = Vec::new();
        for row in rows {
            let (digest, bytes) = row.storage()?;
            let receipt: AccountChatSendReceipt =
                serde_json::from_slice(&bytes).map_err(|_| invalid())?;
            if receipt.digest() != digest {
                return Err(invalid());
            }
            out.push(receipt);
        }
        Ok(out)
    }
    fn acknowledge_account_chat_send_receipt(
        &self,
        account: &[u8; 32],
        local: &[u8; 32],
        digest: &[u8; 32],
        validator: &dyn Fn() -> StorageResult<()>,
    ) -> StorageResult<()> {
        self.connection.with_transaction(|| {validator()?;let conn=self.lock()?;check_configured_owner(&conn,account,local)?;
            let acknowledged:i64=conn.query_row("SELECT o.acknowledged FROM account_chat_send_receipts o JOIN account_chat_send_routes r USING(intent_id,policy_id) JOIN account_chat_send_intents i USING(intent_id) WHERE o.digest=?1 AND i.account=?2 AND r.local_device=?3",params![digest.as_slice(),account.as_slice(),local.as_slice()],|r|r.get(0)).storage()?;
            if acknowledged==0 {conn.execute("UPDATE account_chat_send_receipts SET acknowledged=1 WHERE digest=?1",[digest.as_slice()]).storage()?;}
            drop(conn);validator()?;Ok(())})
    }
    fn deny_account_chat_send_intent(
        &self,
        account: &[u8; 32],
        local: &[u8; 32],
        id: &[u8; 32],
        validator: &dyn Fn() -> StorageResult<()>,
    ) -> StorageResult<()> {
        self.connection.with_transaction(|| {
            validator()?;
            let conn = self.lock()?;
            check_configured_owner(&conn, account, local)?;
            let (intent, state) = load(&conn, id)?.ok_or_else(invalid)?;
            if intent.account != *account || intent.originating_device != *local || state == 2 {
                return Err(invalid());
            }
            if state == 0 {
                conn.execute(
                    "UPDATE account_chat_send_intents SET state=3,payload=x'' WHERE intent_id=?1",
                    [id.as_slice()],
                )
                .storage()?;
            }
            drop(conn);
            validator()?;
            Ok(())
        })
    }
}
#[cfg(test)]
#[path = "account_chat_send_queue/tests.rs"]
mod tests;
