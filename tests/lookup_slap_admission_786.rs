//! #786: the SLAP discovery admits a host only from an output carrying
//! exactly 1 satoshi whose `txid` hint, when present, is the BEEF subject's
//! txid lower-cased, as the reference's `extractHostsFromAnswer` admits it
//! (`ts-stack@edf6e03` `packages/sdk/src/overlay-tools/LookupResolver.ts:2194-2216`):
//!
//! ```text
//! 2199:        const tx = Transaction.fromBEEF(output.beef)
//! 2200:        const txid = tx.id('hex')
//! 2201:        if (output.txid !== undefined && output.txid.toLowerCase() !== txid) continue
//! 2202:        const selectedOutput = tx.outputs[output.outputIndex]
//! 2203:        if (selectedOutput == null || selectedOutput.satoshis !== 1) continue
//! ```
//!
//! Any other output is skipped, the tracker's other outputs still read and
//! the tracker a success (its call at `:1974` returned). The reference's
//! verdicts are recorded in `vectors/lookup_slap_admission_786.json` by
//! `support/lookup_slap_admission_786.mjs` (its own `LookupResolver.query`
//! on a scripted facilitator, Node v22.18.0), and each recorded BEEF is
//! served here to the same hosts beside the own-writer cases. Every
//! tracker is an `.invalid` name of this file's own (the reputation
//! tracker is one global keyed by URL); nothing is dialled.
#![cfg(feature = "overlay")]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use bsv_rs::overlay::{
    create_signed_overlay_admin_token, get_overlay_host_reputation_tracker, LookupAnswer,
    LookupQuestion, LookupResolver, LookupResolverConfig, OutputListItem, OverlayLookupFacilitator,
    Protocol,
};
use bsv_rs::primitives::PrivateKey;
use bsv_rs::script::LockingScript;
use bsv_rs::transaction::{
    Beef, MerklePath, MerklePathLeaf, Transaction, TransactionInput, TransactionOutput,
};
use bsv_rs::Error;
use serde_json::Value;
use std::collections::HashMap;
use std::sync::Arc;

const SERVICE: &str = "ls_slap_admission";

/// A facilitator answering each tracker by URL from its script.
struct Scripted(HashMap<String, Vec<OutputListItem>>);

#[async_trait::async_trait(?Send)]
impl OverlayLookupFacilitator for Scripted {
    async fn lookup(
        &self,
        url: &str,
        _question: &LookupQuestion,
        _timeout_ms: Option<u64>,
    ) -> bsv_rs::Result<LookupAnswer> {
        self.0
            .get(url)
            .map(|outputs| LookupAnswer::OutputList {
                outputs: outputs.clone(),
            })
            .ok_or_else(|| Error::OverlayError(format!("unscripted: {url}")))
    }
}

/// The hosts one tracker's answer admits, sorted.
async fn admitted(tracker: &str, outputs: Vec<OutputListItem>) -> Vec<String> {
    let resolver = LookupResolver::new(LookupResolverConfig {
        slap_trackers: Some(vec![tracker.to_string()]),
        facilitator: Some(Arc::new(Scripted(HashMap::from([(
            tracker.to_string(),
            outputs,
        )])))),
        ..Default::default()
    });
    let mut hosts = resolver.find_competent_hosts(SERVICE).await.unwrap();
    hosts.sort();
    hosts
}

/// A SLAP advertisement of `host` by this crate's writer, at `satoshis`, in
/// a transaction proven by a block of its own (a lone leaf at offset 0).
/// The txid and the lookup output, without a hint.
fn advertisement(host: &str, satoshis: u64) -> (String, OutputListItem) {
    let script: LockingScript =
        create_signed_overlay_admin_token(&PrivateKey::random(), Protocol::Slap, host, SERVICE);
    let mut tx = Transaction::new();
    tx.add_input(TransactionInput::new("11".repeat(32).parse().unwrap(), 0))
        .unwrap();
    tx.add_output(TransactionOutput::new(satoshis, script))
        .unwrap();
    let txid = tx.id();
    let mut beef = Beef::new();
    let index = beef.merge_bump(
        MerklePath::new(900, vec![vec![MerklePathLeaf::new_txid(0, txid.clone())]]).unwrap(),
    );
    beef.merge_raw_tx(tx.to_binary(), Some(index))
        .expect("the bytes are one transaction");
    (
        txid,
        OutputListItem {
            beef: beef.to_binary().expect("the BEEF is writable"),
            output_index: 0,
            context: None,
            txid: None,
        },
    )
}

fn host(name: &str) -> String {
    format!("https://{name}.slap-admission-786.invalid")
}

fn tracker(name: &str) -> String {
    format!("https://tracker-{name}.slap-admission-786-rs.invalid")
}

#[tokio::test]
async fn a_slap_advertisement_of_zero_satoshis_admits_no_host_786() {
    let (_, output) = advertisement(&host("zero"), 0);
    assert_eq!(
        admitted(&tracker("zero"), vec![output]).await,
        Vec::<String>::new()
    );
}

#[tokio::test]
async fn a_slap_advertisement_of_two_satoshis_admits_no_host_786() {
    let (_, output) = advertisement(&host("two"), 2);
    assert_eq!(
        admitted(&tracker("two"), vec![output]).await,
        Vec::<String>::new()
    );
}

#[tokio::test]
async fn a_tracker_naming_one_host_at_one_satoshi_and_one_at_two_admits_the_one_786() {
    let url = tracker("mixed");
    let (_, one) = advertisement(&host("mixed-one"), 1);
    let (_, two) = advertisement(&host("mixed-two"), 2);
    assert_eq!(admitted(&url, vec![two, one]).await, [host("mixed-one")]);
    // A skipped output is no failure of its tracker (`:1974` returned).
    let entry = get_overlay_host_reputation_tracker()
        .snapshot(&url)
        .unwrap();
    assert_eq!(
        (
            entry.total_successes,
            entry.total_failures,
            entry.backoff_until
        ),
        (1, 0, 0),
        "{entry:?}"
    );
}

#[tokio::test]
async fn a_slap_advertisement_whose_txid_hint_disagrees_admits_no_host_786() {
    let (_, mut output) = advertisement(&host("disagreeing"), 1);
    output.txid = Some("ab".repeat(32));
    assert_eq!(
        admitted(&tracker("disagreeing"), vec![output]).await,
        Vec::<String>::new()
    );
}

#[tokio::test]
async fn a_txid_hint_in_upper_case_that_agrees_admits_the_host_786() {
    let (txid, mut output) = advertisement(&host("upper"), 1);
    output.txid = Some(txid.to_ascii_uppercase());
    assert_eq!(
        admitted(&tracker("upper"), vec![output]).await,
        [host("upper")]
    );
}

#[tokio::test]
async fn an_absent_txid_hint_admits_the_host_786() {
    let (_, output) = advertisement(&host("absent"), 1);
    assert_eq!(
        admitted(&tracker("absent"), vec![output]).await,
        [host("absent")]
    );
}

#[tokio::test]
async fn the_reference_recorded_admissions_are_this_crates_786() {
    let recorded: Value =
        serde_json::from_str(include_str!("vectors/lookup_slap_admission_786.json")).unwrap();
    assert_eq!(recorded["service"], SERVICE);
    let cases = recorded["cases"].as_array().unwrap();
    assert_eq!(cases.len(), 7);
    for case in cases {
        let name = case["name"].as_str().unwrap();
        let beef = hex::decode(case["beef"].as_str().unwrap()).unwrap();
        // The recorded BEEF's subject and its output's value, read here.
        let tx = Transaction::from_beef(&beef, None).unwrap();
        assert_eq!(tx.id(), case["txid"].as_str().unwrap(), "{name}");
        assert_eq!(
            tx.outputs()[0].satoshis,
            Some(case["satoshis"].as_u64().unwrap()),
            "{name}"
        );
        let output = OutputListItem {
            beef,
            output_index: case["output_index"].as_u64().unwrap() as u32,
            context: None,
            txid: case["hint"].as_str().map(str::to_string),
        };
        let expected: Vec<String> = case["hosts"]
            .as_array()
            .unwrap()
            .iter()
            .map(|h| h.as_str().unwrap().to_string())
            .collect();
        assert_eq!(
            admitted(&tracker(&format!("vector-{name}")), vec![output]).await,
            expected,
            "{name}"
        );
    }
}
