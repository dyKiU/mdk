//! Trusted policy fixture inspecting genuine staged-tree facts, not SAS grants.
use super::*;
use cgka_engine::device_group_snapshot::CandidateDeviceGroupSnapshot;
use cgka_traits::engine::SendIntent;

struct TreePolicy {
    expected: CandidateDeviceGroupSnapshot,
    accepted: Arc<Mutex<usize>>,
}
struct TreeLease {
    expected: CandidateDeviceGroupSnapshot,
    accepted: Arc<Mutex<usize>>,
}
impl LinkingWelcomePolicy for TreePolicy {
    fn begin_join(
        &self,
        _: &PurposeKeyPackage,
    ) -> Result<Box<dyn LinkingWelcomeLease>, LinkingWelcomeDenied> {
        Ok(Box::new(TreeLease {
            expected: self.expected.clone(),
            accepted: self.accepted.clone(),
        }))
    }
}
impl LinkingWelcomeLease for TreeLease {
    fn check_authenticated(
        &mut self,
        welcome: &AuthenticatedLinkingWelcome,
    ) -> Result<(), LinkingWelcomeDenied> {
        if welcome.protocol_profile != ProtocolProfile::Current
            || welcome.group_id != self.expected.group_id
            || welcome.joined_epoch != self.expected.epoch
            || welcome.epoch_authenticator_digest != self.expected.epoch_authenticator_digest
            || welcome.leaves.len() != self.expected.leaves.len()
            || !welcome
                .leaves
                .iter()
                .zip(&self.expected.leaves)
                .all(|(actual, expected)| {
                    actual.account == self.expected.account
                        && actual.leaf_index == expected.leaf_index
                        && actual.signature_public_key == expected.signature_public_key
                })
        {
            return Err(LinkingWelcomeDenied::ContextMismatch);
        }
        Ok(())
    }
    fn check_live_before_commit(&mut self) -> Result<(), LinkingWelcomeDenied> {
        Ok(())
    }
    fn commit_accepted(self: Box<Self>, _: &AcceptedWelcomeReceipt) {
        *self.accepted.lock().unwrap() += 1;
    }
}
async fn self_only(approver: &mut Engine<SqliteAccountStorage>) -> cgka_traits::types::GroupId {
    let (group, result) = approver
        .create_group(CreateGroupRequest {
            name: "isolated-joined-tree".into(),
            description: String::new(),
            members: vec![],
            required_features: vec![],
            app_components: vec![],
            initial_admins: vec![],
        })
        .await
        .unwrap();
    assert!(matches!(result, SendResult::FoundingGroupCreated { .. }));
    group
}
async fn add(
    approver: &mut Engine<SqliteAccountStorage>,
    group: &cgka_traits::types::GroupId,
    key_packages: Vec<cgka_traits::engine::KeyPackage>,
) -> Vec<TransportMessage> {
    let SendResult::GroupEvolution {
        pending, welcomes, ..
    } = approver
        .send(SendIntent::Invite {
            group_id: group.clone(),
            key_packages,
            initial_admins: vec![],
        })
        .await
        .unwrap()
    else {
        panic!("expected actual Add");
    };
    approver.confirm_published(pending).await.unwrap();
    welcomes
}
#[tokio::test]
async fn joined_tree_welcome_actual_add_exposes_authenticated_indexed_tree() {
    let store = SqliteAccountStorage::in_memory().unwrap();
    let mut recipient = client(store.clone());
    let mut approver = client(SqliteAccountStorage::in_memory().unwrap());
    let (_, package) = verified_package(&store, &mut recipient).await;
    let group = self_only(&mut approver).await;
    let predecessor = approver
        .candidate_device_group_snapshot(&group)
        .unwrap()
        .unwrap();
    let mut welcomes = add(&mut approver, &group, vec![package]).await;
    let expected = approver
        .candidate_device_group_snapshot(&group)
        .unwrap()
        .unwrap();
    assert_eq!(expected.epoch.0, predecessor.epoch.0 + 1);
    assert_eq!(expected.leaves.len(), 2);
    let accepted = Arc::new(Mutex::new(0));
    recipient.install_trusted_linking_welcome_policy(Arc::new(TreePolicy {
        expected,
        accepted: accepted.clone(),
    }));
    recipient.join_welcome(welcomes.remove(0)).await.unwrap();
    assert_eq!(*accepted.lock().unwrap(), 1);
}
#[tokio::test]
async fn joined_tree_welcome_real_unexpected_same_account_leaf_rolls_back_exact_retry() {
    let store = SqliteAccountStorage::in_memory().unwrap();
    let mut recipient = client(store.clone());
    let mut approver = client(SqliteAccountStorage::in_memory().unwrap());
    let mut third = client(SqliteAccountStorage::in_memory().unwrap());
    let (purpose, package) = verified_package(&store, &mut recipient).await;
    let group = self_only(&mut approver).await;
    // Add the extra device first, then generate an actual recipient Welcome.
    let third_package = third.fresh_key_package().await.unwrap();
    add(&mut approver, &group, vec![third_package]).await;
    let mut welcomes = add(&mut approver, &group, vec![package.clone()]).await;
    let actual = approver
        .candidate_device_group_snapshot(&group)
        .unwrap()
        .unwrap();
    let mut expected = actual.clone();
    let approver_key = hex::decode(
        key_package_metadata(&approver.fresh_key_package().await.unwrap())
            .unwrap()
            .signature_public_key_hex,
    )
    .unwrap();
    expected.leaves.retain(|leaf| {
        leaf.signature_public_key == approver_key
            || leaf.signature_public_key == purpose.scope.local_device
    });
    assert_eq!(actual.leaves.len(), 3);
    assert_eq!(expected.leaves.len(), 2);
    let accepted = Arc::new(Mutex::new(0));
    recipient.install_trusted_linking_welcome_policy(Arc::new(TreePolicy {
        expected,
        accepted: accepted.clone(),
    }));
    let welcome = welcomes.remove(0);
    assert!(matches!(
        recipient.join_welcome(welcome.clone()).await,
        Err(cgka_traits::EngineError::LinkingWelcomeDenied(
            LinkingWelcomeDenied::ContextMismatch
        ))
    ));
    assert!(
        recipient
            .durably_owned_key_packages()
            .unwrap()
            .contains(&package)
    );
    assert!(recipient.epoch(&group).is_err());
    assert!(
        recipient
            .accepted_welcome_receipt(&welcome.id)
            .unwrap()
            .is_none()
    );
    assert!(
        !store
            .device_linking_key_package_storage()
            .unwrap()
            .purpose_key_package()
            .unwrap()
            .unwrap()
            .consumed
    );
    assert_eq!(*accepted.lock().unwrap(), 0);
    // This fixture accepts the full actual set solely to prove rollback/retry.
    // It does not represent a production approved predecessor or SDK grant.
    recipient.install_trusted_linking_welcome_policy(Arc::new(TreePolicy {
        expected: actual,
        accepted: accepted.clone(),
    }));
    recipient.join_welcome(welcome).await.unwrap();
    assert_eq!(*accepted.lock().unwrap(), 1);
}
struct AccountTreePolicy {
    account: MemberId,
    saw_other_account: Arc<Mutex<bool>>,
}
impl LinkingWelcomePolicy for AccountTreePolicy {
    fn begin_join(
        &self,
        _: &PurposeKeyPackage,
    ) -> Result<Box<dyn LinkingWelcomeLease>, LinkingWelcomeDenied> {
        Ok(Box::new(Self {
            account: self.account.clone(),
            saw_other_account: self.saw_other_account.clone(),
        }))
    }
}
impl LinkingWelcomeLease for AccountTreePolicy {
    fn check_authenticated(
        &mut self,
        welcome: &AuthenticatedLinkingWelcome,
    ) -> Result<(), LinkingWelcomeDenied> {
        if welcome
            .leaves
            .iter()
            .any(|leaf| leaf.account != self.account)
        {
            *self.saw_other_account.lock().unwrap() = true;
            return Err(LinkingWelcomeDenied::ContextMismatch);
        }
        Ok(())
    }
    fn check_live_before_commit(&mut self) -> Result<(), LinkingWelcomeDenied> {
        Ok(())
    }
    fn commit_accepted(self: Box<Self>, _: &AcceptedWelcomeReceipt) {}
}
#[tokio::test]
async fn joined_tree_welcome_real_other_account_leaf_is_not_erased_from_metadata() {
    let store = SqliteAccountStorage::in_memory().unwrap();
    let mut recipient = client(store.clone());
    let mut approver = client(SqliteAccountStorage::in_memory().unwrap());
    let (_, package) = verified_package(&store, &mut recipient).await;
    let other_label = b"isolated-unapproved-other-account";
    let mut other = EngineBuilder::new(SqliteAccountStorage::in_memory().unwrap())
        .identity(pad32(other_label))
        .account_identity_proof_signer(proof_signer(other_label))
        .protocol_profile(ProtocolProfile::Current)
        .peeler(Box::new(MockPeeler::default()))
        .build()
        .unwrap();
    let other_package = other.fresh_key_package().await.unwrap();
    let bad_group = self_only(&mut approver).await;
    let bad_welcomes = add(
        &mut approver,
        &bad_group,
        vec![package.clone(), other_package],
    )
    .await;
    let bad_welcome = bad_welcomes
        .into_iter()
        .find(|welcome| {
            matches!(&welcome.envelope,
        TransportEnvelope::Welcome { recipient } if recipient.as_slice() == pad32(ACCOUNT))
        })
        .unwrap();
    let saw_other = Arc::new(Mutex::new(false));
    recipient.install_trusted_linking_welcome_policy(Arc::new(AccountTreePolicy {
        account: MemberId::new(pad32(ACCOUNT)),
        saw_other_account: saw_other.clone(),
    }));
    assert!(matches!(
        recipient.join_welcome(bad_welcome.clone()).await,
        Err(cgka_traits::EngineError::LinkingWelcomeDenied(
            LinkingWelcomeDenied::ContextMismatch
        ))
    ));
    assert!(
        *saw_other.lock().unwrap(),
        "actual foreign credential must reach trusted policy unaltered"
    );
    assert!(
        recipient
            .durably_owned_key_packages()
            .unwrap()
            .contains(&package)
    );
    assert!(recipient.epoch(&bad_group).is_err());
    assert!(
        recipient
            .accepted_welcome_receipt(&bad_welcome.id)
            .unwrap()
            .is_none()
    );
    assert!(
        !store
            .device_linking_key_package_storage()
            .unwrap()
            .purpose_key_package()
            .unwrap()
            .unwrap()
            .consumed
    );
    // Same private KeyPackage remains usable for a genuine same-account Add.
    let good_group = self_only(&mut approver).await;
    let mut good_welcomes = add(&mut approver, &good_group, vec![package]).await;
    recipient
        .join_welcome(good_welcomes.remove(0))
        .await
        .unwrap();
}
