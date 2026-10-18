//! Immutable accepted-join facts; imported archives never write this table.
use crate::{SqliteAccountStorage, SqliteResultExt};
use cgka_traits::accepted_welcome::AcceptedWelcomeReceipt;
use cgka_traits::storage::{AcceptedWelcomeStorage, StorageError, StorageProvider, StorageResult};
use cgka_traits::types::{EpochId, GroupId, MemberId, MessageId};
use rusqlite::{Connection, OptionalExtension, params};

const SELECT_RECEIPT: &str = "
    SELECT content_id, group_id, key_package_ref, own_account,
           own_signature_key, welcomer_account, welcomer_signature_key,
           joined_epoch, authenticator_digest
    FROM accepted_welcome_receipts WHERE welcome_id = ?1";
const INSERT_RECEIPT: &str = "
    INSERT INTO accepted_welcome_receipts (
        welcome_id, content_id, group_id, key_package_ref, own_account,
        own_signature_key, welcomer_account, welcomer_signature_key,
        joined_epoch, authenticator_digest
    ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)";

fn invalid() -> StorageError {
    StorageError::Serialization("invalid accepted Welcome receipt".into())
}
fn bounded(bytes: &[u8], max: usize) -> bool {
    !bytes.is_empty() && bytes.len() <= max
}
fn validate(receipt: &AcceptedWelcomeReceipt) -> StorageResult<()> {
    if !bounded(receipt.welcome_id.as_slice(), 512)
        || !bounded(receipt.content_id.as_slice(), 512)
        || !bounded(receipt.group_id.as_slice(), 255)
        || !bounded(&receipt.consumed_key_package_ref, 256)
        || receipt.own_account.as_slice().len() != 32
        || receipt.welcomer_account.as_slice().len() != 32
        || !bounded(&receipt.own_signature_public_key, 256)
        || !bounded(&receipt.welcomer_signature_public_key, 256)
        || receipt.joined_epoch.0 > i64::MAX as u64
    {
        return Err(invalid());
    }
    Ok(())
}
fn read(conn: &Connection, id: &MessageId) -> StorageResult<Option<AcceptedWelcomeReceipt>> {
    if !bounded(id.as_slice(), 512) {
        return Err(invalid());
    }
    let receipt = conn
        .query_row(SELECT_RECEIPT, [id.as_slice()], |row| {
            let epoch: i64 = row.get(7)?;
            let digest: Vec<u8> = row.get(8)?;
            // Invalid representations return a generic decoding error.
            if epoch < 0 || digest.len() != 32 {
                return Err(rusqlite::Error::InvalidQuery);
            }
            let mut hash = [0; 32];
            hash.copy_from_slice(&digest);
            Ok(AcceptedWelcomeReceipt {
                welcome_id: id.clone(),
                content_id: MessageId::new(row.get::<_, Vec<u8>>(0)?),
                group_id: GroupId::new(row.get::<_, Vec<u8>>(1)?),
                consumed_key_package_ref: row.get(2)?,
                own_account: MemberId::new(row.get::<_, Vec<u8>>(3)?),
                own_signature_public_key: row.get(4)?,
                welcomer_account: MemberId::new(row.get::<_, Vec<u8>>(5)?),
                welcomer_signature_public_key: row.get(6)?,
                joined_epoch: EpochId(epoch as u64),
                joined_epoch_authenticator_digest: hash,
            })
        })
        .optional()
        .storage()?;
    if let Some(receipt) = receipt.as_ref() {
        validate(receipt)?;
    }
    Ok(receipt)
}
impl AcceptedWelcomeStorage for SqliteAccountStorage {
    fn put_accepted_welcome_receipt(&self, receipt: &AcceptedWelcomeReceipt) -> StorageResult<()> {
        validate(receipt)?;
        self.with_transaction(|storage| {
            let conn = storage.lock()?;
            if let Some(existing) = read(&conn, &receipt.welcome_id)? {
                return if existing == *receipt {
                    Ok(())
                } else {
                    Err(StorageError::AlreadyExists)
                };
            }
            conn.execute(
                INSERT_RECEIPT,
                params![
                    receipt.welcome_id.as_slice(),
                    receipt.content_id.as_slice(),
                    receipt.group_id.as_slice(),
                    receipt.consumed_key_package_ref.as_slice(),
                    receipt.own_account.as_slice(),
                    receipt.own_signature_public_key.as_slice(),
                    receipt.welcomer_account.as_slice(),
                    receipt.welcomer_signature_public_key.as_slice(),
                    receipt.joined_epoch.0 as i64,
                    receipt.joined_epoch_authenticator_digest.as_slice(),
                ],
            )
            .storage()?;
            Ok(())
        })
    }
    fn accepted_welcome_receipt(
        &self,
        id: &MessageId,
    ) -> StorageResult<Option<AcceptedWelcomeReceipt>> {
        let conn = self.lock()?;
        read(&conn, id)
    }
}
#[cfg(test)]
#[path = "accepted_welcome/tests.rs"]
mod tests;
