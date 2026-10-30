//! #479: an empty page under a positive total must end removal with a refusal.
#![cfg(feature = "kvstore")]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#[path = "support/identity_reveal_wallet.rs"]
mod identity_reveal_wallet;
#[path = "support/kvstore_tokens_343.rs"]
mod support;

use bsv_rs::kvstore::{KVStoreConfig, LocalKVStore};
use bsv_rs::wallet::*;
use bsv_rs::Error;
use identity_reveal_wallet::Counting;
use std::time::Duration;

#[derive(Debug)]
struct PagedWallet(Counting);

// The delay is essential: an immediately ready stub would starve the timeout
// while the base's remove future loops within a single poll.
macro_rules! paged_wallet {
    ($(($method:ident, $args:ty, $result:ty)),* $(,)?;
     $(($status:ident, $status_result:ty)),* $(,)?) => {
        #[async_trait::async_trait]
        impl WalletInterface for PagedWallet {
            async fn list_outputs(
                &self,
                args: ListOutputsArgs,
                originator: Option<&str>,
            ) -> bsv_rs::Result<ListOutputsResult> {
                tokio::time::sleep(Duration::from_millis(1)).await;
                self.0.list_outputs(args, originator).await
            }

            $(async fn $method(
                &self,
                args: $args,
                originator: Option<&str>,
            ) -> bsv_rs::Result<$result> {
                self.0.$method(args, originator).await
            })*

            $(async fn $status(&self, originator: Option<&str>) -> bsv_rs::Result<$status_result> {
                self.0.$status(originator).await
            })*
        }
    };
}

paged_wallet! {
    (get_public_key, GetPublicKeyArgs, GetPublicKeyResult),
    (verify_signature, VerifySignatureArgs, VerifySignatureResult),
    (create_signature, CreateSignatureArgs, CreateSignatureResult),
    (create_action, CreateActionArgs, CreateActionResult),
    (sign_action, SignActionArgs, SignActionResult),
    (abort_action, AbortActionArgs, AbortActionResult),
    (encrypt, EncryptArgs, EncryptResult),
    (decrypt, DecryptArgs, DecryptResult),
    (create_hmac, CreateHmacArgs, CreateHmacResult),
    (verify_hmac, VerifyHmacArgs, VerifyHmacResult),
    (reveal_counterparty_key_linkage, WalletRevealCounterpartyArgs, RevealCounterpartyKeyLinkageResult),
    (reveal_specific_key_linkage, WalletRevealSpecificArgs, RevealSpecificKeyLinkageResult),
    (list_actions, ListActionsArgs, ListActionsResult),
    (internalize_action, InternalizeActionArgs, InternalizeActionResult),
    (relinquish_output, RelinquishOutputArgs, RelinquishOutputResult),
    (acquire_certificate, AcquireCertificateArgs, WalletCertificate),
    (list_certificates, ListCertificatesArgs, ListCertificatesResult),
    (prove_certificate, ProveCertificateArgs, ProveCertificateResult),
    (relinquish_certificate, RelinquishCertificateArgs, RelinquishCertificateResult),
    (discover_by_identity_key, DiscoverByIdentityKeyArgs, DiscoverCertificatesResult),
    (discover_by_attributes, DiscoverByAttributesArgs, DiscoverCertificatesResult),
    (get_header_for_height, GetHeaderArgs, GetHeaderResult);
    (is_authenticated, AuthenticatedResult),
    (wait_for_authentication, AuthenticatedResult),
    (get_height, GetHeightResult),
    (get_network, GetNetworkResult),
    (get_version, GetVersionResult),
}

fn empty_page(total_outputs: u64) -> ListOutputsResult {
    ListOutputsResult {
        total_outputs,
        outputs: Vec::new(),
        beef: None,
    }
}

fn store(wallet: &Counting) -> LocalKVStore<PagedWallet> {
    let mut wallet = wallet.clone();
    wallet.create_from_request = true;
    *wallet.sign_mode.lock().unwrap() = "valid";
    LocalKVStore::new(PagedWallet(wallet), KVStoreConfig::default()).unwrap()
}

async fn remove(store: &LocalKVStore<PagedWallet>) -> bsv_rs::Result<Vec<String>> {
    tokio::time::timeout(Duration::from_secs(1), store.remove("alpha", None))
        .await
        .expect("RED #479: remove timed out after 1 s on an empty page with totalOutputs=7")
}

fn assert_inconsistent_page(error: Error) {
    let message = "Wallet returned an inconsistent KVStore output list: totalOutputs is 7, but page at offset 0 is empty for key alpha";
    assert_eq!(error, Error::KvStoreLocalError(message.into()));
    assert_eq!(error.to_string(), message);
}

#[tokio::test]
async fn remove_refuses_first_empty_page_with_positive_total_479() {
    let wallet = Counting::of_scalar(9);
    *wallet.listed.lock().unwrap() = Some(empty_page(7));
    let store = store(&wallet);
    assert_inconsistent_page(remove(&store).await.unwrap_err());
    assert_eq!(wallet.list_args.lock().unwrap().len(), 1);
    assert!(wallet.creates.lock().unwrap().is_empty());
    assert!(wallet.signs.lock().unwrap().is_empty());

    // A refusal releases the per-key lock; the next operation can complete.
    *wallet.listed.lock().unwrap() = Some(empty_page(0));
    assert!(remove(&store).await.unwrap().is_empty());
}

#[tokio::test]
async fn remove_refuses_empty_page_after_partial_removal_479() {
    let h = support::setup(false, 2).await;
    let mut first = h.wallet.listed.lock().unwrap().clone().unwrap();
    first.total_outputs = 7;
    h.wallet.list_answers.lock().unwrap().push_back(first);
    *h.wallet.listed.lock().unwrap() = Some(empty_page(7));
    h.wallet.list_args.lock().unwrap().clear();
    h.wallet.creates.lock().unwrap().clear();
    let store = store(&h.wallet);

    // One page has already been spent, but the result must be Err, not its txid.
    assert_inconsistent_page(remove(&store).await.unwrap_err());
    assert_eq!(h.wallet.list_args.lock().unwrap().len(), 2);
    assert_eq!(h.wallet.creates.lock().unwrap().len(), 1);
    assert_eq!(h.wallet.signs.lock().unwrap().len(), 1);
}

#[tokio::test]
async fn remove_consistent_two_pages_keeps_wallet_requests_479() {
    let h = support::setup(false, 3).await;
    let complete = h.wallet.listed.lock().unwrap().clone().unwrap();
    let mut first = complete.clone();
    first.outputs.truncate(2);
    let mut last = complete;
    last.outputs.drain(..2);
    last.total_outputs = 1;
    let expected_outpoints: Vec<_> = [&first, &last]
        .into_iter()
        .map(|page| {
            page.outputs
                .iter()
                .map(|output| output.outpoint.clone())
                .collect::<Vec<_>>()
        })
        .collect();
    h.wallet.list_answers.lock().unwrap().extend([first, last]);
    h.wallet.list_args.lock().unwrap().clear();
    h.wallet.creates.lock().unwrap().clear();
    let store = store(&h.wallet);

    let txids = remove(&store).await.unwrap();
    assert_eq!(txids.len(), 2);
    assert!(txids.iter().all(|txid| txid.len() == 64));
    assert_ne!(txids[0], txids[1]);
    let expected_list = ListOutputsArgs {
        basket: "kvstore".into(),
        tags: Some(vec!["alpha".into()]),
        tag_query_mode: Some(QueryMode::All),
        include: Some(OutputInclude::EntireTransactions),
        limit: Some(10_000),
        offset: None,
        include_custom_instructions: None,
        include_tags: None,
        include_labels: None,
        seek_permission: None,
    };
    let lists = h.wallet.list_args.lock().unwrap();
    assert_eq!(lists.len(), 2);
    for list in lists.iter() {
        assert_eq!(
            serde_json::to_value(list).unwrap(),
            serde_json::to_value(&expected_list).unwrap()
        );
    }
    let creates = h.wallet.creates.lock().unwrap();
    assert_eq!(creates.len(), 2);
    for (create, expected) in creates.iter().zip(expected_outpoints) {
        let inputs = create.inputs.as_ref().unwrap();
        assert_eq!(
            inputs
                .iter()
                .map(|input| input.outpoint.clone())
                .collect::<Vec<_>>(),
            expected
        );
        assert!(inputs
            .iter()
            .all(|input| input.input_description == "Previous key-value token"));
        assert!(create.outputs.is_none());
    }
    assert_eq!(h.wallet.signs.lock().unwrap().len(), 2);
}

#[tokio::test]
async fn remove_consistent_empty_store_is_a_noop_479() {
    let wallet = Counting::of_scalar(9);
    *wallet.listed.lock().unwrap() = Some(empty_page(0));
    assert!(remove(&store(&wallet)).await.unwrap().is_empty());
    assert_eq!(wallet.list_args.lock().unwrap().len(), 1);
    assert!(wallet.creates.lock().unwrap().is_empty());
}
