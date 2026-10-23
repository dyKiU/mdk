//! Device-only departure preserves another real ordinary leaf and its approved source.
//! Admission uses actual App-owned Current packages and the Core administrator Invite,
//! before managed workers start. No rows, roster, original consent or grant are fabricated.
use super::*;
use cgka_traits::{StorageProvider, engine::SendIntent};
use marmot_account::AccountHome;
use std::collections::BTreeSet;

#[test]
fn automatic_two_legitimate_sources_keep_surviving_device_history_after_self_remove() {
    // The repository's established composed App/Core harness owns a current-
    // thread Tokio runtime on an 8MiB test thread. This is not a native SDK
    // stack qualification, and does not change the runner's RUST_MIN_STACK.
    crate::tests::run_composed_app_runtime_test("two-legitimate-source-device-only", || async {
        eprintln!("two_source_fixture_stage=test_entered_composed_8mib");
        Box::pin(actual::run_native_public_three_device_enrollment(
            actual::ApprovalScenario::AutomaticTwoLegitimateSources,
        ))
        .await;
    });
}

pub(super) struct TwoSourcePeer {
    _root: tempfile::TempDir,
    pub(super) app: MarmotApp,
    pub(super) runtime: MarmotAppRuntime,
    pub(super) group: crate::GroupId,
    pub(super) a_index: u32,
    pub(super) b_index: u32,
    pub(super) initial_ids: Vec<String>,
}

impl TwoSourcePeer {
    pub(super) async fn prepare(apps: &[MarmotApp; 3], url: &str) -> Self {
        Self::prepare_with_committer_order(apps, url, None).await
    }

    pub(super) async fn prepare_preferred_administrator(apps: &[MarmotApp; 3], url: &str) -> Self {
        Self::prepare_with_committer_order(apps, url, Some(true)).await
    }

    pub(super) async fn prepare_preferred_source(apps: &[MarmotApp; 3], url: &str) -> Self {
        Self::prepare_with_committer_order(apps, url, Some(false)).await
    }

    async fn prepare_with_committer_order(
        apps: &[MarmotApp; 3],
        url: &str,
        prefer_administrator: Option<bool>,
    ) -> Self {
        eprintln!("two_source_fixture_stage=ordinary_setup_entered");
        let root = tempfile::tempdir().unwrap();
        let source_account = apps[0].account_home().account("test").unwrap();
        // Real independent principals are selected before any invitation or
        // commit. Equal ordinary forks prefer the lower authenticated committer.
        let keys = (0..1024)
            .map(|_| nostr::prelude::Keys::generate())
            .find(|keys| match prefer_administrator {
                None => true,
                Some(true) => keys.public_key().to_hex() < source_account.account_id_hex,
                Some(false) => keys.public_key().to_hex() > source_account.account_id_hex,
            })
            .expect("bounded genuine principal selection must find preferred administrator");
        let peer_account = AccountHome::open(root.path())
            .import_account("test", &keys.secret_key().to_secret_hex())
            .unwrap();
        let app = MarmotApp::with_relay(root.path(), url);
        assert!(source_account.account_id_hex != peer_account.account_id_hex);
        if prefer_administrator == Some(true) {
            assert!(peer_account.account_id_hex < source_account.account_id_hex);
            eprintln!("two_source_fixture_preferred_real_administrator_committer=true");
        }
        if prefer_administrator == Some(false) {
            assert!(peer_account.account_id_hex > source_account.account_id_hex);
            eprintln!("two_source_fixture_preferred_real_source_committer=true");
        }
        crate::tests::remember_test_member_inbox(&app, &source_account.account_id_hex, url);
        // B has no engine/public package yet: the public first invitation has only A.
        let (mut a, mut d, group, a_index, a_metadata) = Box::pin(prepare_first_source(
            &app,
            apps,
            &source_account.account_id_hex,
        ))
        .await;
        let mut b = Box::pin(admit_second_source(
            &app,
            apps,
            url,
            &source_account.account_id_hex,
            &mut d,
            group.clone(),
            &a_metadata,
        ))
        .await;
        let (b_index, initial_ids) = Box::pin(converge_and_send(
            &app,
            &source_account.account_id_hex,
            &mut a,
            &mut b,
            &mut d,
            group.clone(),
            a_index,
        ))
        .await;
        // Release the actual exclusive engines before runtime workers reopen these SAME roots.
        drop((a, b, d));
        eprintln!("two_source_fixture_stage=ordinary_owners_released");
        let runtime = MarmotAppRuntime::new(app.clone());
        Box::pin(runtime.reconcile_accounts()).await.unwrap();
        Self {
            _root: root,
            app,
            runtime,
            group,
            a_index,
            b_index,
            initial_ids,
        }
    }

    pub(super) async fn verify_device_only_leave(
        &self,
        apps: &[MarmotApp; 3],
        runtimes: &[MarmotAppRuntime; 3],
    ) {
        eprintln!("two_source_fixture_stage=broad_abc_completed");
        assert_eq!(stored_indices(&self.app, &self.group).len(), 3);
        for app in apps {
            let policies = app
                .account_storage("test")
                .unwrap()
                .approved_account_sharing_policy_storage()
                .unwrap()
                .approved_account_sharing_policies()
                .unwrap();
            assert_eq!(
                policies.len(),
                2,
                "all ABC broad approvals must be real and complete"
            );
        }
        wait_for_paired_records(&runtimes[2], &self.group, &self.initial_ids, None).await;
        assert!(
            !apps[2]
                .load_state("test")
                .unwrap()
                .groups
                .iter()
                .any(|row| row.group_id_hex == hex::encode(self.group.as_slice()))
        );
        let departure = Box::pin(runtimes[0].leave_group("test", &self.group))
            .await
            .unwrap();
        assert_eq!(departure.published, 1);
        tokio::time::timeout(std::time::Duration::from_secs(30), async {
            loop {
                let indices = stored_indices(&self.app, &self.group);
                if indices.len() == 2
                    && !indices.contains(&self.a_index)
                    && indices.contains(&self.b_index)
                {
                    break;
                }
                tokio::time::sleep(std::time::Duration::from_millis(20)).await;
            }
        })
        .await
        .expect("D must confirm only A device departure while B actual leaf survives");
        tokio::time::timeout(std::time::Duration::from_secs(30), async {
            loop {
                let source = apps[1].account_storage("test").unwrap();
                let recipient = self.app.account_storage("test").unwrap();
                let (source_epoch, recipient_epoch, authenticator_equal, head_equal) = super::automatic_account_departure_acceptance::compare_actual_branches_for_test(&source, &recipient, &self.group).expect("ordinary surviving-source convergence observation must not hide storage failure");
                if source_epoch == recipient_epoch && authenticator_equal && head_equal { break; }
                tokio::time::sleep(std::time::Duration::from_millis(20)).await;
            }
        }).await.expect("B and D must reach the same actual canonical branch before the surviving-source steady-state send");
        let future = runtimes[1]
            .send_message(
                "test",
                &self.group,
                b"surviving actual B ordinary send".to_vec(),
            )
            .await
            .unwrap();
        assert_eq!(future.published, 1);
        assert_eq!(future.message_ids.len(), 1);
        let group_hex = hex::encode(self.group.as_slice());
        let delivery = tokio::time::timeout(std::time::Duration::from_secs(30), async {
            loop {
                let storage = self.app.account_storage("test").unwrap();
                if future.message_ids.iter().all(|id| {
                    storage
                        .app_storage()
                        .app_message(&group_hex, id)
                        .unwrap()
                        .is_some()
                }) {
                    break;
                }
                tokio::time::sleep(std::time::Duration::from_millis(20)).await;
            }
        })
        .await;
        if delivery.is_err() {
            use futures::FutureExt;
            let diagnostics = tokio::time::timeout(std::time::Duration::from_secs(5),
                std::panic::AssertUnwindSafe(async {
                    use cgka_traits::storage::MessageStorage;
                    use sha2::{Digest, Sha256};
                    let source = apps[1].account_storage("test").map_err(|_| ())?;
                    let recipient = self.app.account_storage("test").map_err(|_| ())?;
                    let branches = super::automatic_account_departure_acceptance::compare_actual_branches_for_test(&source,&recipient,&self.group).map_err(|_| ())?;
                    eprintln!("two_source_delivery_failure_actual_branch_epochs_and_equal={branches:?}");
                    for id in &future.message_ids {
                        let outer = cgka_traits::MessageId::new(hex::decode(id).map_err(|_| ())?);
                        let row = source.get_message(&outer).map_err(|_| ())?;
                        let payload = cgka_traits::message::StoredMessagePayload::decode(&row.payload).map_err(|_| ())?;
                        let wire = payload.as_openmls_wire().ok_or(())?;
                        let content = cgka_traits::MessageId::new(Sha256::digest(&wire.payload).to_vec());
                        let canonical = match recipient.get_message(&content) {
                            Ok(row) => Some((row.epoch.0, row.state)),
                            Err(cgka_traits::StorageError::NotFound) => None,
                            Err(_) => return Err(()),
                        };
                        let alias = recipient.app_storage().app_message(&group_hex,&hex::encode(content.as_slice())).map_err(|_| ())?.is_some();
                        eprintln!("two_source_delivery_failure_source_state={:?} recipient_canonical={canonical:?} canonical_alias_delivered={alias}",row.state);
                    }
                    Ok::<(), ()>(())
                }).catch_unwind()).await;
            eprintln!(
                "two_source_delivery_failure_diagnostics_unknown={}",
                !matches!(diagnostics, Ok(Ok(Ok(()))))
            );
        }
        delivery.expect("independent D must actually decrypt surviving B ordinary send");
        let b_device = apps[1]
            .account_storage("test")
            .unwrap()
            .private_roster_settlement_storage()
            .unwrap()
            .read_round()
            .unwrap()
            .unwrap()
            .anchor
            .local_device;
        wait_for_paired_records(
            &runtimes[2],
            &self.group,
            &future.message_ids,
            Some(b_device),
        )
        .await;
    }
}

// Separate actual setup phases bound debug future construction and poll frames.
async fn prepare_first_source(
    app: &MarmotApp,
    apps: &[MarmotApp; 3],
    account_id: &str,
) -> (
    crate::AppClient,
    crate::AppClient,
    crate::GroupId,
    u32,
    cgka_engine::key_package::KeyPackageMetadata,
) {
    let mut a = Box::pin(apps[0].client("test")).await.unwrap();
    let a_package = Box::pin(a.publish_key_package()).await.unwrap();
    let a_metadata = cgka_engine::key_package_metadata(&a_package).unwrap();
    let mut d = Box::pin(app.client("test")).await.unwrap();
    eprintln!("two_source_fixture_stage=creator_invite");
    let group = Box::pin(d.create_group("Two real devices of one ordinary member", &[account_id]))
        .await
        .unwrap();
    Box::pin(wait_for_invitation(&apps[0], &mut a, &group)).await;
    accept_actual_welcome(&apps[0], &mut a, &group);
    let a_index = a.runtime.session().own_leaf_index(&group).unwrap();

    (a, d, group, a_index, a_metadata)
}

async fn admit_second_source(
    app: &MarmotApp,
    apps: &[MarmotApp; 3],
    url: &str,
    account_id: &str,
    d: &mut crate::AppClient,
    group: crate::GroupId,
    a_metadata: &cgka_engine::key_package::KeyPackageMetadata,
) -> crate::AppClient {
    let mut b = Box::pin(apps[1].client("test")).await.unwrap();
    let b_package = Box::pin(b.publish_key_package()).await.unwrap();
    let b_metadata = cgka_engine::key_package_metadata(&b_package).unwrap();
    assert!(a_metadata.credential_identity_hex == b_metadata.credential_identity_hex);
    assert!(a_metadata.signature_public_key_hex != b_metadata.signature_public_key_hex);
    // Locally owned packages do not carry directory SourceRef metadata.
    // Publication is witnessed by the real lifecycle's acknowledged current
    // package and authored event, without fabricating a transport SourceRef.
    let published = b.key_package_maintenance_status().unwrap().unwrap();
    assert!(published.authored_event_id.is_some());
    assert!(published.current_key_package.as_ref() == Some(&b_package));
    assert!(published.pending_replacement.is_none());
    // Fetch the exact actual signed publication through the normal relay
    // directory reader; only that parser may attach its Welcome SourceRef.
    let published_id = hex::encode(published.authored_event_id.unwrap().as_slice());
    let records = Box::pin(app.directory().fetch_key_package_events_for_account_id(
        account_id,
        &[cgka_traits::TransportEndpoint(url.to_owned())],
    ))
    .await
    .unwrap();
    let record = records
        .into_iter()
        .find(|record| record.event.id == published_id)
        .expect("the real B signed publication must be present at the relay");
    let fetched = crate::key_package_records::key_package_from_record(record).unwrap();
    let fetched_metadata = cgka_engine::key_package_metadata(&fetched.key_package).unwrap();
    assert!(fetched_metadata.key_package_ref_hex == b_metadata.key_package_ref_hex);
    assert!(fetched_metadata.signature_public_key_hex == b_metadata.signature_public_key_hex);
    assert!(fetched.key_package.source.is_some());
    let b_package = fetched.key_package;
    // The administrator admits this exact real package, not directory recency or a host DTO.
    eprintln!("two_source_fixture_stage=exact_sibling_invite");
    let invite = Box::pin(d.runtime.send(SendIntent::Invite {
        group_id: group.clone(),
        key_packages: vec![b_package],
        initial_admins: vec![],
    }));
    eprintln!("two_source_fixture_stage=exact_sibling_invite_future_boxed");
    let effects = invite.await.unwrap();
    assert!(effects.failures.is_empty());
    eprintln!("two_source_fixture_stage=exact_sibling_invite_published");
    observe_confirmed_invite(d, &effects).await.unwrap();
    eprintln!("two_source_fixture_stage=exact_sibling_invite_observed");
    Box::pin(wait_for_invitation(&apps[1], &mut b, &group)).await;
    accept_actual_welcome(&apps[1], &mut b, &group);
    b
}

async fn converge_and_send(
    app: &MarmotApp,
    account_id: &str,
    a: &mut crate::AppClient,
    b: &mut crate::AppClient,
    d: &mut crate::AppClient,
    group: crate::GroupId,
    a_index: u32,
) -> (u32, Vec<String>) {
    tokio::time::timeout(std::time::Duration::from_secs(30), async {
        loop {
            Box::pin(a.sync()).await.unwrap();
            Box::pin(b.sync()).await.unwrap();
            Box::pin(d.sync()).await.unwrap();
            if [&*a, &*b, &*d].iter().all(|client| {
                client
                    .runtime
                    .session()
                    .canonical_group_membership(&group)
                    .is_ok_and(|membership| {
                        membership.local_leaf_active && membership.member_leaves.len() == 3
                    })
            }) {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        }
    })
    .await
    .expect("three actual Current leaves must converge before App owners start");
    let b_index = b.runtime.session().own_leaf_index(&group).unwrap();
    assert!(a_index != b_index);
    let membership = d
        .runtime
        .session()
        .canonical_group_membership(&group)
        .unwrap();
    let account_bytes = hex::decode(account_id).unwrap();
    let same_account = membership
        .member_leaves
        .iter()
        .filter(|leaf| leaf.member.as_slice() == account_bytes)
        .collect::<Vec<_>>();
    assert_eq!(same_account.len(), 2);
    assert!(same_account.iter().any(|leaf| leaf.leaf_index == a_index));
    assert!(same_account.iter().any(|leaf| leaf.leaf_index == b_index));
    assert!(
        a.runtime
            .session()
            .group_authority(&group)
            .unwrap()
            .facts
            .is_member
    );
    assert!(
        b.runtime
            .session()
            .group_authority(&group)
            .unwrap()
            .facts
            .is_member
    );
    assert!(
        !a.runtime
            .session()
            .group_authority(&group)
            .unwrap()
            .facts
            .is_admin
    );
    assert!(
        !b.runtime
            .session()
            .group_authority(&group)
            .unwrap()
            .facts
            .is_admin
    );
    eprintln!("two_source_fixture_stage=ordinary_sends");
    let from_a = Box::pin(a.send(&group, b"actual ordinary source A before sharing"))
        .await
        .unwrap();
    let from_b = Box::pin(b.send(&group, b"actual ordinary source B before sharing"))
        .await
        .unwrap();
    assert_eq!(from_a.published, 1);
    assert_eq!(from_b.published, 1);
    assert_eq!(from_a.message_ids.len(), 1);
    assert_eq!(from_b.message_ids.len(), 1);
    let mut initial_ids = from_a.message_ids;
    initial_ids.extend(from_b.message_ids);
    Box::pin(wait_for_peer_messages(app, d, &group, &initial_ids)).await;
    Box::pin(a.sync()).await.unwrap();
    Box::pin(b.sync()).await.unwrap();
    (b_index, initial_ids)
}

// Keep construction of the large App observation future outside the composed
// setup poll frame. Type erasure prevents that frame from retaining its concrete
// temporary size; the same actual confirmed effects still pass through App.
#[inline(never)]
pub(super) fn observe_confirmed_invite<'a>(
    client: &'a mut crate::AppClient,
    effects: &'a marmot_account::AccountDeviceEffects,
) -> std::pin::Pin<
    Box<dyn std::future::Future<Output = Result<crate::SyncSummary, crate::AppError>> + 'a>,
> {
    eprintln!("two_source_fixture_stage=confirmed_invite_observation_constructing");
    Box::pin(client.observe_drained_session_events(effects))
}

fn accept_actual_welcome(app: &MarmotApp, client: &mut crate::AppClient, group: &crate::GroupId) {
    let before = app
        .group("test", &hex::encode(group.as_slice()))
        .unwrap()
        .unwrap();
    assert!(before.pending_confirmation);
    assert!(
        before.via_welcome_message_id_hex.is_some(),
        "actual received Welcome provenance is required"
    );
    assert!(
        before.welcomer_account_id_hex.is_some(),
        "actual inviter provenance is required"
    );
    let accepted = client.accept_group_invite(group).unwrap();
    assert!(!accepted.pending_confirmation);
    assert!(accepted.self_membership == crate::SelfMembership::Member);
    assert!(accepted.via_welcome_message_id_hex == before.via_welcome_message_id_hex);
    assert!(accepted.welcomer_account_id_hex == before.welcomer_account_id_hex);
    let persisted = app
        .group("test", &hex::encode(group.as_slice()))
        .unwrap()
        .unwrap();
    assert!(!persisted.pending_confirmation);
    assert!(persisted.via_welcome_message_id_hex == before.via_welcome_message_id_hex);
}

async fn wait_for_invitation(
    app: &MarmotApp,
    client: &mut crate::AppClient,
    group: &crate::GroupId,
) {
    let group_hex = hex::encode(group.as_slice());
    tokio::time::timeout(std::time::Duration::from_secs(30), async {
        loop {
            Box::pin(client.sync()).await.unwrap();
            if app
                .group("test", &group_hex)
                .unwrap()
                .is_some_and(|row| row.pending_confirmation)
            {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        }
    })
    .await
    .expect("the exact real device must receive an ordinary Welcome invitation");
}

async fn wait_for_peer_messages(
    app: &MarmotApp,
    client: &mut crate::AppClient,
    group: &crate::GroupId,
    ids: &[String],
) {
    let group_hex = hex::encode(group.as_slice());
    tokio::time::timeout(std::time::Duration::from_secs(30), async {
        loop {
            Box::pin(client.sync()).await.unwrap();
            if ids.iter().all(|id| {
                app.account_storage("test")
                    .unwrap()
                    .app_storage()
                    .app_message(&group_hex, id)
                    .unwrap()
                    .is_some()
            }) {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        }
    })
    .await
    .expect("independent D must decrypt both real ordinary sender events");
}

pub(super) fn stored_indices(app: &MarmotApp, group: &crate::GroupId) -> BTreeSet<u32> {
    let storage = app.account_storage("test").unwrap();
    storage
        .with_read_snapshot(|storage| -> Result<_, cgka_traits::StorageError> {
            let actual = openmls::group::MlsGroup::load(
                storage.mls_storage(),
                &openmls::group::GroupId::from_slice(group.as_slice()),
            )
            .unwrap()
            .expect("actual D MLS group");
            Ok(actual.members().map(|member| member.index.u32()).collect())
        })
        .unwrap()
}

pub(super) async fn wait_for_paired_records(
    runtime: &MarmotAppRuntime,
    group: &crate::GroupId,
    ids: &[String],
    source: Option<[u8; 32]>,
) {
    tokio::time::timeout(std::time::Duration::from_secs(40), async {
        loop {
            let observation = match runtime
                .open_account_conversation_window("test", group, 128)
                .await
            {
                Ok(window) => Some(window),
                Err(crate::AccountChatReadError::NotReady) => None,
                Err(_) => panic!("paired observation must not hide a non-readiness failure"),
            };
            if let Some(window) = observation {
                let ready = matches!(
                    window.snapshot.header,
                    crate::AccountConversationHeader::PairedSource(_)
                ) && ids.iter().all(|id| {
                    window.snapshot.rows.iter().any(|row| match row {
                        crate::AccountConversationRow::PairedSource(row) => {
                            hex::encode(row.event_id) == *id
                                && source.is_none_or(|expected| row.source.device == expected)
                        }
                        crate::AccountConversationRow::LocalMls(_) => false,
                    })
                });
                window.window_handle().cancel();
                if ready {
                    break;
                }
            }
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        }
    })
    .await
    .expect("C must observe genuine committed history from its still-eligible source");
}
