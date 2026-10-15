//! Distinct human broad-approval evidence, never a historical creation claim.
use crate::SqliteResultExt;
use cgka_traits::storage::StorageResult;
use rusqlite::Transaction;

pub(crate) fn apply(tx: &Transaction<'_>) -> StorageResult<()> {
    tx.execute_batch(
        "CREATE TABLE account_chat_legacy_acceptance_evidence (
          origin_id BLOB PRIMARY KEY NOT NULL REFERENCES account_chat_source_origins(origin_id),
          policy_id BLOB NOT NULL REFERENCES approved_account_sharing_policies(policy_id),
          approval_id BLOB NOT NULL CHECK(length(approval_id)=32));
        CREATE TRIGGER legacy_acceptance_insert BEFORE INSERT ON account_chat_legacy_acceptance_evidence
        WHEN (SELECT count(*) FROM account_chat_legacy_acceptance_evidence)>=8192
          OR EXISTS(SELECT 1 FROM account_chat_legacy_acceptance_evidence WHERE origin_id=NEW.origin_id)
          OR NOT EXISTS(SELECT 1 FROM account_chat_source_origins o
            JOIN approved_account_sharing_policies p ON p.policy_id=NEW.policy_id
            WHERE o.origin_id=NEW.origin_id AND o.verdict=1
              AND length(o.origin)=33 AND substr(o.origin,1,1)=X'02'
              AND substr(o.origin,2,32)=NEW.approval_id
              AND o.account=p.account AND o.local_device=p.local_device AND p.revoked=0)
        BEGIN SELECT RAISE(ABORT,'invalid explicit legacy acceptance evidence'); END;
        CREATE TRIGGER legacy_acceptance_update BEFORE UPDATE ON account_chat_legacy_acceptance_evidence
        BEGIN SELECT RAISE(ABORT,'explicit legacy acceptance evidence is immutable'); END;
        CREATE TRIGGER legacy_acceptance_delete BEFORE DELETE ON account_chat_legacy_acceptance_evidence
        BEGIN SELECT RAISE(ABORT,'explicit legacy acceptance evidence is retained'); END;",
    ).storage()
}
