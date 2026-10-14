//! Bounded test-only observations of actual private settlement intake.
//! Identifiers stay private; callers receive only exact-message aggregate counts.
#[cfg(any(test, all(feature = "test-crash-hooks", debug_assertions)))]
mod enabled {
    use cgka_traits::{GroupId, MessageId};
    use std::sync::{Mutex, OnceLock};

    const MAX_SCOPES: usize = 8;
    const MAX_RECORDS: usize = 64;
    #[derive(Clone, Copy)]
    pub(crate) enum Category {
        Attempt,
        MissingSource,
        MissingAdmission,
        InvalidFrame,
        Expired,
        MissingRound,
        RoundScope,
        SelectedScope,
        TreeScope,
        LocalSource,
        ConflictingFact,
        ChallengeBinding,
        AckBinding,
        Accepted,
    }
    impl Category {
        fn label(self) -> &'static str {
            match self {
                Self::Attempt => "attempt",
                Self::MissingSource => "missing_source",
                Self::MissingAdmission => "missing_admission",
                Self::InvalidFrame => "invalid_frame",
                Self::Expired => "expired",
                Self::MissingRound => "missing_round",
                Self::RoundScope => "round_scope",
                Self::SelectedScope => "selected_scope",
                Self::TreeScope => "tree_scope",
                Self::LocalSource => "local_source",
                Self::ConflictingFact => "conflicting_fact",
                Self::ChallengeBinding => "challenge_binding",
                Self::AckBinding => "ack_binding",
                Self::Accepted => "accepted",
            }
        }
    }
    struct Scope {
        token: u64,
        group: GroupId,
        recipient: [u8; 32],
        records: Vec<(MessageId, Category)>,
        incomplete: bool,
    }
    #[derive(Default)]
    struct Registry {
        next: u64,
        scopes: Vec<Scope>,
    }
    #[derive(Debug, Default)]
    pub struct Summary {
        pub counts: Vec<(&'static str, usize)>,
        pub incomplete: bool,
    }
    impl Registry {
        fn arm(&mut self, group: &GroupId, recipient: [u8; 32]) -> Result<u64, &'static str> {
            if group.as_slice().len() > 128
                || self.scopes.len() >= MAX_SCOPES
                || self
                    .scopes
                    .iter()
                    .any(|s| s.group == *group && s.recipient == recipient)
            {
                return Err("settlement observation scope unavailable");
            }
            self.next = self
                .next
                .checked_add(1)
                .ok_or("settlement observation exhausted")?;
            self.scopes.push(Scope {
                token: self.next,
                group: group.clone(),
                recipient,
                records: Vec::new(),
                incomplete: false,
            });
            Ok(self.next)
        }
        fn record(
            &mut self,
            group: &GroupId,
            recipient: Option<[u8; 32]>,
            id: &MessageId,
            category: Category,
        ) {
            let Some(scope) = self
                .scopes
                .iter_mut()
                .find(|s| s.group == *group && Some(s.recipient) == recipient)
            else {
                return;
            };
            if scope.records.len() == MAX_RECORDS || id.as_slice().len() > 128 {
                scope.incomplete = true;
                return;
            }
            scope.records.push((id.clone(), category));
        }
        fn summary(&self, token: u64, expected: Option<&MessageId>) -> Summary {
            let Some(scope) = self.scopes.iter().find(|s| s.token == token) else {
                return Summary {
                    incomplete: true,
                    ..Summary::default()
                };
            };
            let mut summary = Summary {
                incomplete: scope.incomplete || expected.is_none(),
                ..Summary::default()
            };
            for (_, category) in scope.records.iter().filter(|(id, _)| Some(id) == expected) {
                let label = category.label();
                if let Some((_, count)) = summary.counts.iter_mut().find(|(name, _)| *name == label)
                {
                    *count += 1;
                } else {
                    summary.counts.push((label, 1));
                }
            }
            summary
        }
    }
    fn registry() -> &'static Mutex<Registry> {
        static REGISTRY: OnceLock<Mutex<Registry>> = OnceLock::new();
        REGISTRY.get_or_init(|| Mutex::new(Registry::default()))
    }
    /// Test observation only: this handle cannot select, admit, retry or publish.
    pub struct Observer(u64);
    pub fn arm(group: &GroupId, recipient: [u8; 32]) -> Result<Observer, &'static str> {
        registry()
            .lock()
            .map_err(|_| "settlement observation unavailable")?
            .arm(group, recipient)
            .map(Observer)
    }
    impl Observer {
        pub fn summary(&self, expected: Option<&MessageId>) -> Summary {
            summary_in(registry(), self.0, expected)
        }
    }
    impl Drop for Observer {
        fn drop(&mut self) {
            if let Ok(mut registry) = registry().lock() {
                registry.scopes.retain(|s| s.token != self.0);
            }
        }
    }
    pub(crate) fn record(
        group: &GroupId,
        recipient: Option<[u8; 32]>,
        id: &MessageId,
        category: Category,
    ) {
        record_in(registry(), group, recipient, id, category);
    }
    fn record_in(
        registry: &Mutex<Registry>,
        group: &GroupId,
        recipient: Option<[u8; 32]>,
        id: &MessageId,
        category: Category,
    ) {
        // Poisoning is an Unknown observation, never an error in actual intake.
        if let Ok(mut registry) = registry.lock() {
            registry.record(group, recipient, id, category);
        }
    }
    fn summary_in(registry: &Mutex<Registry>, token: u64, expected: Option<&MessageId>) -> Summary {
        registry
            .lock()
            .map(|r| r.summary(token, expected))
            .unwrap_or_else(|_| Summary {
                incomplete: true,
                ..Summary::default()
            })
    }
    pub(crate) fn recipient(group: &openmls::group::MlsGroup) -> Option<[u8; 32]> {
        group
            .own_leaf_node()?
            .signature_key()
            .as_slice()
            .try_into()
            .ok()
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        #[test]
        fn poisoned_observer_does_not_unwind_intake_and_is_unknown() {
            let registry = Mutex::new(Registry::default());
            let group = GroupId::new(vec![1]);
            let id = MessageId::new(vec![2]);
            let token = registry.lock().unwrap().arm(&group, [3; 32]).unwrap();
            assert!(
                std::panic::catch_unwind(|| {
                    let _guard = registry.lock().unwrap();
                    panic!("isolated observation fault");
                })
                .is_err()
            );
            record_in(&registry, &group, Some([3; 32]), &id, Category::Attempt);
            let summary = summary_in(&registry, token, Some(&id));
            assert!(summary.incomplete && summary.counts.is_empty());
        }
        #[test]
        fn exact_group_recipient_and_message_scoping() {
            let mut r = Registry::default();
            let group = GroupId::new(vec![1]);
            let id = MessageId::new(vec![2]);
            let token = r.arm(&group, [3; 32]).unwrap();
            r.record(
                &GroupId::new(vec![4]),
                Some([3; 32]),
                &id,
                Category::Accepted,
            );
            r.record(&group, Some([4; 32]), &id, Category::Accepted);
            r.record(&group, None, &id, Category::Accepted);
            r.record(
                &group,
                Some([3; 32]),
                &MessageId::new(vec![5]),
                Category::Accepted,
            );
            assert!(r.summary(token, Some(&id)).counts.is_empty());
            r.record(&group, Some([3; 32]), &id, Category::MissingAdmission);
            assert_eq!(
                r.summary(token, Some(&id)).counts,
                vec![("missing_admission", 1)]
            );
            assert!(r.summary(token, None).incomplete);
            r.record(
                &group,
                Some([3; 32]),
                &MessageId::new(vec![7; 129]),
                Category::Attempt,
            );
            assert!(r.summary(token, Some(&id)).incomplete);
            assert_eq!(r.scopes[0].records.len(), 2);
        }
        #[test]
        fn overflow_is_unknown_and_never_replaces_retained_evidence() {
            let mut r = Registry::default();
            let group = GroupId::new(vec![1]);
            let id = MessageId::new(vec![2]);
            let token = r.arm(&group, [3; 32]).unwrap();
            for _ in 0..MAX_RECORDS + 1 {
                r.record(&group, Some([3; 32]), &id, Category::Attempt);
            }
            assert_eq!(r.scopes[0].records.len(), MAX_RECORDS);
            assert_eq!(
                r.summary(token, Some(&id)).counts,
                vec![("attempt", MAX_RECORDS)]
            );
            assert!(r.summary(token, Some(&id)).incomplete);
        }
        #[test]
        fn capacity_and_retired_token_do_not_capture_other_scope() {
            let mut r = Registry::default();
            let group = GroupId::new(vec![1]);
            let old = r.arm(&group, [0; 32]).unwrap();
            for i in 1..MAX_SCOPES {
                r.arm(&group, [i as u8; 32]).unwrap();
            }
            assert!(r.arm(&group, [9; 32]).is_err());
            r.scopes.retain(|s| s.token != old);
            let fresh = r.arm(&group, [0; 32]).unwrap();
            assert_ne!(old, fresh);
            assert!(r.summary(old, Some(&MessageId::new(vec![2]))).incomplete);
        }
    }
}
#[cfg(any(test, all(feature = "test-crash-hooks", debug_assertions)))]
pub(crate) use enabled::{Category, recipient, record};
#[cfg(any(test, all(feature = "test-crash-hooks", debug_assertions)))]
pub use enabled::{Observer, Summary, arm};
// App tests can compile without crash hooks; unavailable observations stay
// explicit Unknown and cannot affect the existing scenario's result.
#[cfg(not(any(test, all(feature = "test-crash-hooks", debug_assertions))))]
mod disabled {
    #[derive(Debug, Default)]
    pub struct Summary {
        pub counts: Vec<(&'static str, usize)>,
        pub incomplete: bool,
    }
    pub struct Observer;
    pub fn arm(_: &cgka_traits::GroupId, _: [u8; 32]) -> Result<Observer, &'static str> {
        Err("settlement observation hooks unavailable")
    }
    impl Observer {
        pub fn summary(&self, _: Option<&cgka_traits::MessageId>) -> Summary {
            Summary {
                incomplete: true,
                ..Summary::default()
            }
        }
    }
}
#[cfg(not(any(test, all(feature = "test-crash-hooks", debug_assertions))))]
pub use disabled::{Observer, Summary, arm};
