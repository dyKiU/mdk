//! Bounded, read-only exact-content observation for genuine convergence tests.
//! This module is absent unless the explicit test-policy feature is enabled.
use crate::canonicalization::{CanonicalizationResult, DroppedMessageReason};
use cgka_traits::{GroupId, MessageId};
use std::sync::{Arc, Mutex, OnceLock, Weak};

#[derive(Clone, Debug, Default)]
pub struct Observation {
    pub replay_failures: u64,
    pub failed_kind: Option<&'static str>,
    pub failed_source_epoch: Option<u64>,
    pub failed_candidate_epoch: Option<u64>,
    pub failure_category: Option<&'static str>,
    pub candidates: usize,
    pub eligible: usize,
    pub target_present: bool,
    pub target_selected: bool,
    pub target_eligible: bool,
    pub target_depth: Option<u64>,
    pub target_witnesses: Option<usize>,
    pub decisive_rule: Option<&'static str>,
    pub drop_reason: Option<DroppedMessageReason>,
    pub superseded_processed: bool,
}
pub struct Probe {
    group: GroupId,
    own_leaf: u32,
    content: MessageId,
    observed: Mutex<Observation>,
}
static PROBES: OnceLock<Mutex<Vec<Weak<Probe>>>> = OnceLock::new();
impl Probe {
    pub fn arm(group: GroupId, own_leaf: u32, content: MessageId) -> Arc<Self> {
        let probe = Arc::new(Self {
            group,
            own_leaf,
            content,
            observed: Mutex::new(Observation::default()),
        });
        let mut probes = PROBES
            .get_or_init(Mutex::default)
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        probes.retain(|p| p.strong_count() > 0);
        assert!(probes.len() < 4, "bounded convergence observer capacity");
        probes.push(Arc::downgrade(&probe));
        probe
    }
    pub fn snapshot(&self) -> Observation {
        self.observed
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone()
    }
}
fn visit(group: &GroupId, own_leaf: u32, mut f: impl FnMut(&Probe, &mut Observation)) {
    let Some(probes) = PROBES.get() else { return };
    let probes = probes.lock().unwrap_or_else(|e| e.into_inner());
    for probe in probes.iter().filter_map(Weak::upgrade) {
        if probe.group == *group && probe.own_leaf == own_leaf {
            let mut observed = probe.observed.lock().unwrap_or_else(|e| e.into_inner());
            f(&probe, &mut observed);
        }
    }
}
pub(crate) fn replay_failure(
    group: &GroupId,
    own_leaf: u32,
    messages: &[cgka_traits::transport::TransportMessage],
    kind: &'static str,
    source: u64,
    candidate: u64,
    category: &'static str,
) {
    visit(group, own_leaf, |probe, o| {
        if messages.iter().any(|m| m.id == probe.content) {
            o.replay_failures = o.replay_failures.saturating_add(1);
            o.failed_kind = Some(kind);
            o.failed_source_epoch = Some(source);
            o.failed_candidate_epoch = Some(candidate);
            o.failure_category = Some(category);
        }
    });
}
pub(crate) fn result(group: &GroupId, own_leaf: u32, result: &CanonicalizationResult) {
    visit(group, own_leaf, |probe, o| {
        let content = hex::encode(probe.content.as_slice());
        if let Some(dropped) = result
            .dropped_messages
            .iter()
            .find(|d| d.message_id == content)
        {
            o.drop_reason = Some(dropped.reason);
        }
        if let Some(trace) = &result.selection_trace {
            if let Some(target) = trace
                .candidates
                .iter()
                .find(|c| c.tip_digest.as_slice() == probe.content.as_slice())
            {
                o.target_present = true;
                o.target_eligible = target.eligible;
                o.target_selected |= trace.selected_branch_id.as_ref() == Some(&target.branch_id);
                o.target_depth = Some(target.score.effective_commit_depth);
                o.target_witnesses = Some(target.score.app_witness_score);
                o.candidates = result.candidate_count;
                o.eligible = result.eligible_count;
                o.decisive_rule = trace
                    .rule_trace
                    .iter()
                    .find(|r| r.decisive)
                    .map(|r| r.rule_name);
            }
        }
    });
}
pub(crate) fn superseded(group: &GroupId, own_leaf: u32, content: &MessageId) {
    visit(group, own_leaf, |probe, o| {
        if probe.content == *content {
            o.superseded_processed = true;
        }
    });
}
