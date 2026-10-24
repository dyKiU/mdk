//! Actual foreign-executor login with owned complete and incomplete discovery endpoints.

use std::collections::BTreeMap;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use futures::executor::block_on;
use marmot_uniffi::{Marmot, MarmotKitError, MarmotOptions, RelayPolicyFfi, SecretStore};
use nostr::prelude::ToBech32;
use nostr_relay_builder::MockRelay;

#[derive(Default)]
struct Secrets(Mutex<BTreeMap<String, String>>);

impl SecretStore for Secrets {
    fn has_secret_for_label(&self, _label: String) -> Result<bool, MarmotKitError> {
        Ok(false)
    }

    fn has_secret_for_account_id(&self, account: String) -> Result<bool, MarmotKitError> {
        Ok(self.0.lock().unwrap().contains_key(&account))
    }

    fn write_secret(
        &self,
        _label: String,
        account: String,
        key: String,
    ) -> Result<(), MarmotKitError> {
        self.0.lock().unwrap().insert(account, key);
        Ok(())
    }

    fn load_secret(&self, _label: String, account: String) -> Result<String, MarmotKitError> {
        self.0
            .lock()
            .unwrap()
            .get(&account)
            .cloned()
            .ok_or(MarmotKitError::SecretNotFound {
                details: "fixture secret unavailable".into(),
            })
    }

    fn remove_secret(&self, _label: String, account: String) -> Result<(), MarmotKitError> {
        self.0.lock().unwrap().remove(&account);
        Ok(())
    }
}

fn discovery(healthy: &str, incomplete: &str, negative_control: bool) -> Vec<String> {
    if negative_control {
        vec![incomplete.to_owned()]
    } else {
        vec![healthy.to_owned()]
    }
}

struct LoginObservation {
    succeeded: bool,
    typed_incomplete: bool,
    account_bound: bool,
    owned_contact: bool,
    shutdown_complete: bool,
    no_panic: bool,
}

fn login_once(
    healthy: &str,
    incomplete: &str,
    negative_control: bool,
    contacts: &AtomicUsize,
) -> LoginObservation {
    let root = tempfile::tempdir().unwrap();
    let keys = nostr::prelude::Keys::generate();
    let expected_account = keys.public_key().to_hex();
    let mut deployment = marmot_uniffi::marmot_deployment_white_noise();
    deployment.discovery_indexer_relays = discovery(healthy, incomplete, negative_control);
    let kit = Marmot::new_with_configuration(
        root.path().to_string_lossy().into_owned(),
        vec![healthy.to_owned()],
        MarmotOptions {
            relay_policy: Some(RelayPolicyFfi::AllowLoopback),
            secret_store: Some(Arc::new(Secrets::default())),
            ..MarmotOptions::for_deployment(deployment)
        },
    )
    .expect("open actual directory fixture");
    let before = contacts.load(Ordering::SeqCst);
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        block_on(kit.__ffi_login(
            keys.secret_key().to_bech32().unwrap(),
            vec![healthy.to_owned()],
            vec![healthy.to_owned()],
            vec![],
        ))
    }));
    let owned_contact = contacts.load(Ordering::SeqCst) > before;
    // Every constructed original owner closes before any verdict or root removal.
    let shutdown_complete = block_on(kit.__ffi_shutdown_and_close()).is_ok();
    if !shutdown_complete {
        // A failed close must not delete storage still owned by the original runtime.
        let _ = root.keep();
    }
    let succeeded = matches!(&result, Ok(Ok(_)));
    let typed_incomplete = matches!(
        &result,
        Ok(Err(MarmotKitError::DirectoryLookupIncomplete { .. }))
    );
    let account_bound = match &result {
        Ok(Ok(account)) => account.account_id_hex == expected_account,
        Ok(Err(MarmotKitError::DirectoryLookupIncomplete { account })) => {
            account == &expected_account
        }
        _ => false,
    };
    LoginObservation {
        succeeded,
        typed_incomplete,
        account_bound,
        owned_contact,
        shutdown_complete,
        no_panic: result.is_ok(),
    }
}

async fn incomplete_indexer() -> (String, Arc<AtomicUsize>, tokio::task::JoinHandle<()>) {
    let listener = tokio::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))
        .await
        .unwrap();
    let url = format!("ws://{}", listener.local_addr().unwrap());
    let contacts = Arc::new(AtomicUsize::new(0));
    let observed = Arc::clone(&contacts);
    let endpoint = tokio::spawn(async move {
        while let Ok((socket, _)) = listener.accept().await {
            observed.fetch_add(1, Ordering::SeqCst);
            // The owned indexer never completes a WebSocket handshake or claims EOSE.
            drop(socket);
        }
    });
    (url, contacts, endpoint)
}

#[test]
fn directory_discovery_coverage_remains_fail_closed_for_owned_incomplete_indexer() {
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .unwrap();
    let (relay, healthy, negative_endpoint, positive_endpoint) = runtime.block_on(async {
        let relay = MockRelay::run().await.unwrap();
        let healthy = relay.url().await.to_string();
        (
            relay,
            healthy,
            incomplete_indexer().await,
            incomplete_indexer().await,
        )
    });
    let (negative_url, negative_contacts, negative_task) = negative_endpoint;
    let (positive_url, positive_contacts, positive_task) = positive_endpoint;
    let host = std::thread::spawn(move || {
        let host_without_tokio = tokio::runtime::Handle::try_current().is_err();
        // Separate identities, roots, and refusing endpoints prevent cache or reconnect contamination.
        let negative = login_once(&healthy, &negative_url, true, &negative_contacts);
        let positive = login_once(&healthy, &positive_url, false, &positive_contacts);
        (
            host_without_tokio,
            negative,
            positive,
            tokio::runtime::Handle::try_current().is_err(),
        )
    });
    let outcome = host.join();
    negative_task.abort();
    positive_task.abort();
    let endpoints_joined = runtime.block_on(async {
        let negative_joined = negative_task.await.is_err_and(|error| error.is_cancelled());
        let positive_joined = positive_task.await.is_err_and(|error| error.is_cancelled());
        negative_joined && positive_joined
    });
    drop(relay);
    drop(runtime);
    let (host_without_tokio, negative, positive, host_still_without_tokio) =
        outcome.expect("actual directory host completed");
    let prerequisites = host_without_tokio
        && host_still_without_tokio
        && endpoints_joined
        && negative.no_panic
        && positive.no_panic
        && negative.typed_incomplete
        && !negative.succeeded
        && negative.account_bound
        && negative.owned_contact
        && negative.shutdown_complete
        && positive.account_bound
        && positive.shutdown_complete;
    eprintln!(
        "owned-directory-fixture {{\"host_without_tokio\":{},\"host_still_without_tokio\":{},\"endpoints_joined\":{},\"negative_no_panic\":{},\"negative_typed_incomplete\":{},\"negative_rejected\":{},\"negative_account_bound\":{},\"negative_owned_contact\":{},\"negative_shutdown_complete\":{},\"positive_no_panic\":{},\"positive_account_bound\":{},\"positive_shutdown_complete\":{},\"positive_login_succeeded\":{},\"positive_typed_incomplete\":{},\"positive_owned_contact\":{}}}",
        host_without_tokio,
        host_still_without_tokio,
        endpoints_joined,
        negative.no_panic,
        negative.typed_incomplete,
        !negative.succeeded,
        negative.account_bound,
        negative.owned_contact,
        negative.shutdown_complete,
        positive.no_panic,
        positive.account_bound,
        positive.shutdown_complete,
        positive.succeeded,
        positive.typed_incomplete,
        positive.owned_contact,
    );
    assert!(
        prerequisites
            && positive.succeeded
            && !positive.typed_incomplete
            && !positive.owned_contact,
        "owned complete discovery must permit real login while incomplete discovery stays fail closed"
    );
}
