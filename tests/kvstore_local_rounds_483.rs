//! #483: cap removal at two rounds, with shrinking totals required beneath that cap.
#![cfg(feature = "kvstore")]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#[path = "support/identity_reveal_wallet.rs"]
mod identity_reveal_wallet;
#[path = "support/kvstore_tokens_343.rs"]
mod support;

use bsv_rs::kvstore::{KVStoreConfig, LocalKVStore};
use bsv_rs::transaction::Transaction;
use bsv_rs::wallet::*;
use bsv_rs::Error;
use identity_reveal_wallet::Counting;
use std::sync::Mutex;
use std::time::Duration;

#[derive(Debug)]
struct FreshWallet {
    inner: Counting,
    source: Mutex<Transaction>,
    page: ListOutputsResult,
    totals: Vec<u32>,
    empty_from: Option<usize>,
}

// Every page carries a new transaction with the writer's signed token intact.
// Yielding lets the timeout stop the unbounded base loop within a single thread.
macro_rules! fresh_wallet {
    ($(($method:ident, $args:ty, $result:ty)),* $(,)?;
     $(($status:ident, $status_result:ty)),* $(,)?) => {
        #[async_trait::async_trait]
        impl WalletInterface for FreshWallet {
            async fn list_outputs(
                &self,
                args: ListOutputsArgs,
                originator: Option<&str>,
            ) -> bsv_rs::Result<ListOutputsResult> {
                tokio::time::sleep(Duration::from_millis(1)).await;
                self.inner.list_outputs(args, originator).await?;
                let round = self.inner.list_args.lock().unwrap().len();
                let mut page = self.page.clone();
                page.total_outputs = *self.totals.get(round - 1)
                    .unwrap_or_else(|| self.totals.last().unwrap());
                if self.empty_from.is_some_and(|first| round >= first) {
                    page.outputs.clear();
                    page.beef = None;
                } else {
                    let mut source = self.source.lock().unwrap().clone();
                    source.lock_time = u32::try_from(round).unwrap();
                    source.invalidate_caches();
                    page.outputs[0].outpoint =
                        Outpoint::from_string(&format!("{}.0", source.id())).unwrap();
                    page.beef = Some(source.to_beef(true).unwrap());
                }
                Ok(page)
            }

            $(async fn $method(
                &self,
                args: $args,
                originator: Option<&str>,
            ) -> bsv_rs::Result<$result> {
                self.inner.$method(args, originator).await
            })*

            $(async fn $status(&self, originator: Option<&str>) -> bsv_rs::Result<$status_result> {
                self.inner.$status(originator).await
            })*
        }
    };
}

fresh_wallet! {
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

async fn store(totals: &[u32], empty_from: Option<usize>) -> (LocalKVStore<FreshWallet>, Counting) {
    let h = support::setup(false, 1).await;
    let page = h.wallet.listed.lock().unwrap().clone().unwrap();
    let mut wallet = h.wallet;
    wallet.create_from_request = true;
    *wallet.sign_mode.lock().unwrap() = "valid";
    wallet.list_args.lock().unwrap().clear();
    wallet.creates.lock().unwrap().clear();
    wallet.signature_args.lock().unwrap().clear();
    let fresh = FreshWallet {
        inner: wallet.clone(),
        source: Mutex::new(h.sources[0].0.clone()),
        page,
        totals: totals.to_vec(),
        empty_from,
    };
    (
        LocalKVStore::new(fresh, KVStoreConfig::default()).unwrap(),
        wallet,
    )
}

async fn remove(store: &LocalKVStore<FreshWallet>) -> bsv_rs::Result<Vec<String>> {
    tokio::time::timeout(Duration::from_secs(1), store.remove("alpha", None))
        .await
        .expect("RED #483: remove timed out after 1 s on fresh authenticated outputs")
}

fn assert_refusal(error: Error, message: String, rounds: usize, wallet: &Counting) {
    assert_eq!(error, Error::KvStoreLocalError(message.clone()));
    assert_eq!(error.to_string(), message);
    assert_eq!(wallet.list_args.lock().unwrap().len(), rounds + 1);
    assert_eq!(wallet.creates.lock().unwrap().len(), rounds);
    assert_eq!(wallet.signs.lock().unwrap().len(), rounds);
    assert_eq!(wallet.signature_args.lock().unwrap().len(), rounds);
    let creates = wallet.creates.lock().unwrap();
    let outpoints: std::collections::HashSet<_> = creates
        .iter()
        .map(|action| &action.inputs.as_ref().unwrap()[0].outpoint)
        .collect();
    assert_eq!(outpoints.len(), rounds);
}

fn assert_cap_refusal(error: Error, current_total: u32, wallet: &Counting) {
    assert_refusal(
        error,
        format!("Wallet returned an inconsistent KVStore output list: after 2 removal rounds, first totalOutputs was 7, previous totalOutputs was 6 and current totalOutputs is {current_total} for key alpha"),
        2,
        wallet,
    );
}

fn assert_shrinking_refusal(error: Error, current_total: u32, wallet: &Counting) {
    assert_refusal(
        error,
        format!("Wallet returned an inconsistent KVStore output list: after 1 removal round, previous totalOutputs was 7 and current totalOutputs is {current_total} for key alpha"),
        1,
        wallet,
    );
}

#[tokio::test]
async fn remove_refuses_fresh_outputs_under_unchanged_total_483() {
    let (store, wallet) = store(&[7, 7], None).await;
    assert_shrinking_refusal(remove(&store).await.unwrap_err(), 7, &wallet);

    // The refusal releases the per-key lock for a subsequent operation.
    wallet.list_args.lock().unwrap().clear();
    wallet.creates.lock().unwrap().clear();
    wallet.signs.lock().unwrap().clear();
    wallet.signature_args.lock().unwrap().clear();
    assert_shrinking_refusal(remove(&store).await.unwrap_err(), 7, &wallet);
}

#[tokio::test]
async fn remove_refuses_fresh_outputs_under_growing_total_483() {
    let (store, wallet) = store(&[7, 8, 9], None).await;
    assert_shrinking_refusal(remove(&store).await.unwrap_err(), 8, &wallet);
}

#[tokio::test]
async fn remove_refuses_fresh_outputs_when_total_drops_once_then_holds_483() {
    let (store, wallet) = store(&[7, 6, 6], None).await;
    // The cap refuses this third listing before the shrinking guard.
    assert_cap_refusal(remove(&store).await.unwrap_err(), 6, &wallet);
}

#[tokio::test]
async fn remove_two_rounds_for_token_written_during_first_483() {
    let (store, wallet) = store(&[2, 1], None).await;
    let txids = remove(&store).await.unwrap();
    assert_eq!(txids.len(), 2);
    assert_ne!(txids[0], txids[1]);
    assert_eq!(wallet.signs.lock().unwrap().len(), 2);
    let lists = wallet.list_args.lock().unwrap();
    assert_eq!(lists.len(), 2);
    assert_eq!(
        serde_json::to_value(&lists[0]).unwrap(),
        serde_json::to_value(&lists[1]).unwrap()
    );
    assert_eq!(lists[0].limit, Some(10_000));
    assert_eq!(lists[0].offset, None);
    let creates = wallet.creates.lock().unwrap();
    assert_eq!(creates.len(), 2);
    assert!(creates.iter().all(|action| action.outputs.is_none()));
}

#[tokio::test]
async fn remove_refuses_third_round_even_when_totals_shrink_by_one_483() {
    let (store, wallet) = store(&[7, 6, 5, 4, 3, 2, 1], None).await;
    // On 33fd45b5 this succeeds after seven listings and seven spends.
    let result = remove(&store).await;
    assert_eq!(wallet.list_args.lock().unwrap().len(), 3);
    assert_eq!(wallet.signs.lock().unwrap().len(), 2);
    assert_cap_refusal(result.unwrap_err(), 5, &wallet);
}

#[tokio::test]
async fn remove_two_rounds_complete_on_third_zero_total_listing_483() {
    let (store, wallet) = store(&[3, 2, 0], Some(3)).await;
    let txids = remove(&store).await.unwrap();
    assert_eq!(txids.len(), 2);
    assert_eq!(
        txids.iter().collect::<std::collections::HashSet<_>>().len(),
        2
    );
    assert_eq!(wallet.list_args.lock().unwrap().len(), 3);
    assert_eq!(wallet.creates.lock().unwrap().len(), 2);
    assert_eq!(wallet.signs.lock().unwrap().len(), 2);
    assert_eq!(wallet.signature_args.lock().unwrap().len(), 2);
}

#[tokio::test]
async fn remove_empty_page_keeps_the_479_refusal() {
    for empty_from in [1, 3] {
        let (store, wallet) = store(&[7, 6, 5], Some(empty_from)).await;
        let total = [7, 6, 5][empty_from - 1];
        let message = format!("Wallet returned an inconsistent KVStore output list: totalOutputs is {total}, but page at offset 0 is empty for key alpha");
        let error = remove(&store).await.unwrap_err();
        assert_eq!(error, Error::KvStoreLocalError(message.clone()));
        assert_eq!(error.to_string(), message);
        assert_eq!(wallet.list_args.lock().unwrap().len(), empty_from);
        assert_eq!(wallet.signs.lock().unwrap().len(), empty_from - 1);
    }
}

#[tokio::test]
async fn remove_one_round_keeps_a_consistent_wallet_483() {
    let (store, wallet) = store(&[1], None).await;
    assert_eq!(remove(&store).await.unwrap().len(), 1);
    assert_eq!(wallet.list_args.lock().unwrap().len(), 1);
    assert_eq!(wallet.signs.lock().unwrap().len(), 1);
}
