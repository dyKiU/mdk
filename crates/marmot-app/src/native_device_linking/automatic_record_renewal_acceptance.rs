//! Actual source ACK under AB, followed by original broad ABC enrollment.
use super::*;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn automatic_records_remain_visible_after_acknowledged_ab_batch_and_broad_abc_renewal() {
    Box::pin(actual::run_native_public_three_device_enrollment(
        actual::ApprovalScenario::AutomaticRecordGenerationRenewal,
    ))
    .await;
}

pub(super) struct RenewalWitness {
    group: crate::GroupId,
    event: String,
    initial_generation: u64,
}

impl RenewalWitness {
    pub(super) async fn before_abc(
        apps: &[MarmotApp; 3],
        runtimes: &[MarmotAppRuntime; 3],
        incoming: &super::automatic_forwarding_non_admin_acceptance::IncomingPeer,
        probe: std::sync::Arc<crate::account_chat_sharing::enabled::RecordReceiptProbe>,
    ) -> Self {
        let group = incoming.group.clone();
        let event = incoming.preapproval_message.clone();
        let group_hex = hex::encode(group.as_slice());
        let storage = apps[0].account_storage("test").unwrap();
        let source = storage
            .app_storage()
            .app_message(&group_hex, &event)
            .unwrap()
            .unwrap();
        assert!(!source.invalidated);
        let visible = storage
            .app_storage()
            .timeline_message(&group_hex, &event)
            .unwrap()
            .unwrap();
        assert!(!visible.deleted && visible.invalidation_status.is_none());
        assert!(
            visible
                .retention_expires_at
                .is_none_or(|time| time > crate::unix_now_seconds())
        );
        let initial_generation =
            Self::wait_record(&runtimes[1], &group, &event, Some(&probe)).await;
        // The observer increments only after the authenticated actual peer
        // receipt has successfully committed the source's durable global ACK.
        tokio::time::timeout(std::time::Duration::from_secs(30), async {
            while probe.committed.load(Ordering::Acquire) == 0 {
                tokio::time::sleep(std::time::Duration::from_millis(20)).await;
            }
        })
        .await
        .expect("actual source must commit its genuine AB RecordReceipt before C enrollment");
        Self {
            group,
            event,
            initial_generation,
        }
    }

    pub(super) async fn after_abc(self, _apps: &[MarmotApp; 3], runtimes: &[MarmotAppRuntime; 3]) {
        let generation = Self::wait_record(&runtimes[1], &self.group, &self.event, None).await;
        assert_ne!(
            generation, self.initial_generation,
            "the retained canonical record must be republished under B's fresh ABC projection generation"
        );
        Self::wait_record(&runtimes[2], &self.group, &self.event, None).await;
    }

    async fn wait_record(
        runtime: &MarmotAppRuntime,
        group: &crate::GroupId,
        event: &str,
        probe: Option<&crate::account_chat_sharing::enabled::RecordReceiptProbe>,
    ) -> u64 {
        let opened = AtomicBool::new(false);
        let paired_header = AtomicBool::new(false);
        let row_count = AtomicUsize::new(0);
        let generation_seen = AtomicU64::new(0);
        let result = tokio::time::timeout(std::time::Duration::from_secs(45), async {
            loop {
                let window = runtime.open_account_conversation_window("test", group, 128).await;
                if let Ok(window) = window {
                    opened.store(true, Ordering::Relaxed);
                    row_count.store(window.snapshot.rows.len(), Ordering::Relaxed);
                    let generation = match &window.snapshot.header {
                        crate::AccountConversationHeader::PairedSource(header) => Some(header.source.protected_generation),
                        crate::AccountConversationHeader::LocalMls(_) => None,
                    };
                    paired_header.store(generation.is_some(), Ordering::Relaxed);
                    if let Some(generation) = generation { generation_seen.store(generation, Ordering::Relaxed); }
                    let present = window.snapshot.rows.iter().any(|row| matches!(row,
                        crate::AccountConversationRow::PairedSource(row) if hex::encode(row.event_id) == event));
                    window.window_handle().cancel();
                    if let Some(generation) = generation && present {
                        return generation;
                    }
                }
                tokio::time::sleep(std::time::Duration::from_millis(20)).await;
            }
        }).await;
        result.unwrap_or_else(|_| panic!(
            "canonical record wait elapsed; window_opened={} paired_header={} generation={} rows={} committed_receipts={}",
            opened.load(Ordering::Relaxed),
            paired_header.load(Ordering::Relaxed),
            generation_seen.load(Ordering::Relaxed),
            row_count.load(Ordering::Relaxed),
            probe.map_or(0, |probe| probe.committed.load(Ordering::Acquire))
        ))
    }
}
