//! Loaded [`MlsGroup`]s kept across engine calls.
//!
//! `MlsGroup::load` is 13 storage reads plus a ratchet-tree decode that grows
//! with the member count, and the send, receive, and group-read paths each
//! paid it on every call. An entry is reused only while the storage backend's
//! OpenMLS write generation is unchanged since the entry was stored, so a
//! write through a freshly loaded group, a snapshot restore, or a rolled-back
//! transaction invalidates it without any call-site bookkeeping.
//!
//! Protocol: `take` removes the entry for the duration of an operation and
//! records the generation it saw. `return_unmodified` stores the object back
//! only if that generation is still current, so it is safe on any exit that
//! did not write through the object. `return` stores it back after an
//! operation that wrote through the object, and only if no other connection
//! committed meanwhile. An error path after a write drops the object.
//!
//! The generation is one counter per storage connection plus SQLite's
//! `data_version`, which moves on commits from other connections and
//! processes. What it cannot see is a second writer on the same connection
//! touching this group's state during an operation; the engine is the only
//! writer of group state on its connection and is single-threaded per
//! account, so that case does not arise.
//!
//! ponytail: one counter for the whole connection, so a write for one group
//! evicts every other group's entry; per-group counters if an account works
//! many groups at once.

use std::collections::HashMap;
use std::sync::Mutex;

use cgka_traits::error::EngineError;
use cgka_traits::storage::StorageProvider;
use cgka_traits::types::GroupId;
use openmls::group::MlsGroup;

use crate::engine::Engine;

/// ponytail: whole-map clear at the cap; an LRU only matters once an account
/// actively works more groups than this at once.
const MAX_CACHED_MLS_GROUPS: usize = 32;

/// The half of a generation that comes from other connections and processes;
/// see `StorageProvider::mls_write_generation`.
fn foreign_half(generation: u64) -> u64 {
    generation >> 32
}

struct CachedMlsGroup {
    generation: u64,
    group: MlsGroup,
}

#[derive(Default)]
pub(crate) struct MlsGroupCache {
    entries: Mutex<HashMap<GroupId, CachedMlsGroup>>,
    /// Generation observed when each in-flight group was taken.
    taken: Mutex<HashMap<GroupId, u64>>,
    #[cfg(test)]
    hits: std::sync::atomic::AtomicU64,
    /// Actual calls to MlsGroup::load, independent of cached accessor reads.
    #[cfg(test)]
    load_attempts: std::sync::atomic::AtomicU64,
}

impl MlsGroupCache {
    pub(crate) fn forget_group(&self, group_id: &GroupId) {
        self.entries
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .remove(group_id);
        self.taken
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .remove(group_id);
    }

    fn store(&self, group_id: &GroupId, generation: u64, group: MlsGroup) {
        let mut entries = self
            .entries
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if entries.len() >= MAX_CACHED_MLS_GROUPS && !entries.contains_key(group_id) {
            entries.clear();
        }
        entries.insert(group_id.clone(), CachedMlsGroup { generation, group });
    }

    fn taken_at(&self, group_id: &GroupId) -> Option<u64> {
        self.taken
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .remove(group_id)
    }
}

impl<S: StorageProvider> Engine<S> {
    /// The group's `MlsGroup`: the cached object when nothing has written to
    /// the OpenMLS store since it was stored, otherwise a fresh load. `None`
    /// for an unknown group.
    pub(crate) fn take_mls_group(
        &self,
        group_id: &GroupId,
    ) -> Result<Option<MlsGroup>, EngineError> {
        // Sampled before the load so a write that lands during the load still
        // invalidates the object on return.
        let generation = self.storage.mls_write_generation();
        if let Some(generation) = generation {
            self.mls_group_cache
                .taken
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .insert(group_id.clone(), generation);
            let cached = self
                .mls_group_cache
                .entries
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .remove(group_id);
            if let Some(cached) = cached
                && cached.generation == generation
            {
                #[cfg(test)]
                self.mls_group_cache
                    .hits
                    .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                return Ok(Some(cached.group));
            }
        }
        let provider = crate::provider::EngineOpenMlsProvider::<S>::new(
            &self.crypto,
            self.storage.mls_storage(),
        );
        let mls_gid = openmls::group::GroupId::from_slice(group_id.as_slice());
        #[cfg(test)]
        self.mls_group_cache
            .load_attempts
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        MlsGroup::load(
            <crate::provider::EngineOpenMlsProvider<'_, S> as openmls_traits::OpenMlsProvider>::storage(&provider),
            &mls_gid,
        )
        .map_err(|e| EngineError::Backend(format!("load: {e:?}")))
    }

    /// Store `group` after an operation that wrote through it and succeeded.
    /// Dropped instead when another connection committed since the take, so
    /// an object derived from the earlier state is never tagged as current.
    pub(crate) fn return_mls_group(&self, group_id: &GroupId, group: MlsGroup) {
        let taken = self.mls_group_cache.taken_at(group_id);
        let Some(now) = self.storage.mls_write_generation() else {
            return;
        };
        if taken.is_none_or(|taken| foreign_half(taken) != foreign_half(now)) {
            return;
        }
        self.mls_group_cache.store(group_id, now, group);
    }

    /// Store `group` after an operation that did not write through it. Kept
    /// only if nothing at all wrote to the OpenMLS store since the take, which
    /// makes this safe on every early exit regardless of what else ran.
    pub(crate) fn return_unmodified_mls_group(&self, group_id: &GroupId, group: MlsGroup) {
        let taken = self.mls_group_cache.taken_at(group_id);
        let Some(now) = self.storage.mls_write_generation() else {
            return;
        };
        if taken != Some(now) {
            return;
        }
        self.mls_group_cache.store(group_id, now, group);
    }

    /// Run a read-only `f` against the group's `MlsGroup` and keep the object
    /// cached afterwards. `f` must not write through the group.
    pub(crate) fn with_mls_group<R>(
        &self,
        group_id: &GroupId,
        f: impl FnOnce(&MlsGroup) -> Result<R, EngineError>,
    ) -> Result<R, EngineError> {
        let group = self
            .take_mls_group(group_id)?
            .ok_or_else(|| EngineError::UnknownGroup(group_id.clone()))?;
        let result = f(&group);
        self.return_unmodified_mls_group(group_id, group);
        result
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::Ordering;

    use cgka_traits::app_event::{MARMOT_APP_EVENT_KIND_CHAT, MarmotAppEvent};
    use cgka_traits::engine::{CgkaEngine, CreateGroupRequest, SendIntent, SendResult};
    use cgka_traits::error::EngineError;
    use cgka_traits::storage::StorageProvider;

    use crate::distributed_convergence::tests::test_engine;

    #[tokio::test]
    async fn cached_group_is_reused_until_storage_is_written_behind_it() {
        let mut engine = test_engine();
        let (group_id, _) = engine
            .create_group(CreateGroupRequest {
                name: "cache".into(),
                description: String::new(),
                members: vec![],
                required_features: vec![],
                app_components: vec![],
                initial_admins: vec![],
            })
            .await
            .unwrap();
        let payload = MarmotAppEvent::new(
            hex::encode(engine.self_id().as_slice()),
            1_700_000_000,
            MARMOT_APP_EVENT_KIND_CHAT,
            vec![],
            "cache",
        )
        .encode()
        .unwrap();
        async fn send(
            engine: &mut crate::Engine<storage_sqlite::SqliteAccountStorage>,
            group_id: &cgka_traits::types::GroupId,
            payload: &[u8],
        ) -> Result<bool, EngineError> {
            engine
                .send(SendIntent::AppMessage {
                    group_id: group_id.clone(),
                    payload: payload.to_vec(),
                    expected_epoch: None,
                })
                .await
                .map(|result| {
                    matches!(result, SendResult::ApplicationMessage { group_id: actual, .. } if actual == *group_id)
                })
        }
        let loads = |engine: &crate::Engine<storage_sqlite::SqliteAccountStorage>| {
            engine.mls_group_cache.load_attempts.load(Ordering::Relaxed)
        };
        let cached = |engine: &crate::Engine<storage_sqlite::SqliteAccountStorage>| {
            engine.mls_group_cache.entries.lock().unwrap().len()
        };

        // Private-group admission can legitimately read the cached group more
        // than once. Count real MLS loads instead of incidental accessor hits.
        let first_application = send(&mut engine, &group_id, &payload).await.unwrap();
        let initial_cached_groups = cached(&engine);
        assert_eq!(
            initial_cached_groups, 1,
            "a successful send stores the group"
        );
        let after_first_send = loads(&engine);

        let second_application = send(&mut engine, &group_id, &payload).await.unwrap();
        let after_second_send = loads(&engine);

        // A rolled-back transaction counts as a write: whatever the cached
        // object believes about storage can no longer be trusted.
        let generation = engine.storage.mls_write_generation().unwrap();
        engine
            .storage
            .with_transaction(|_| Err::<(), EngineError>(EngineError::Other("abort".into())))
            .unwrap_err();
        let rollback_changed_generation =
            engine.storage.mls_write_generation().unwrap() != generation;
        assert!(rollback_changed_generation);

        let third_application = send(&mut engine, &group_id, &payload).await.unwrap();
        let after_third_send = loads(&engine);
        let fourth_application = send(&mut engine, &group_id, &payload).await.unwrap();
        let after_fourth_send = loads(&engine);
        let application_sends = [
            first_application,
            second_application,
            third_application,
            fourth_application,
        ];
        let load_deltas = [
            after_second_send - after_first_send,
            after_third_send - after_second_send,
            after_fourth_send - after_third_send,
        ];
        eprintln!(
            "mls-cache-actual-load {}",
            serde_json::json!({
                "application_sends": application_sends,
                "initial_cached_groups": initial_cached_groups,
                "rollback_changed_generation": rollback_changed_generation,
                "load_deltas": load_deltas,
            })
        );
        assert!(
            application_sends.into_iter().all(|actual| actual),
            "all four real sends must produce application messages for the exact group"
        );
        assert_eq!(
            load_deltas,
            [0, 1, 0],
            "cached sends avoid real MLS loads and rollback forces exactly one reload"
        );
    }
}
