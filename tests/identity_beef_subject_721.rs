//! #721: the identity client's two `ls_identity` parsers read a lookup
//! output's token from the transaction the reference's discovery reads it
//! from: `beef.atomicTxid ?? beef.txs.at(-1)?.txid`, loaded by
//! `findAtomicTransaction`, its `outputIndex` checked on that transaction
//! (`ts-stack@edf6e03` `packages/sdk/src/transaction/TransactionEvidence.ts:110-127`,
//! reached through `IdentityEvidenceVerifier.parse`,
//! `wallet-toolbox/src/utility/identityUtils.ts:600-612`, before
//! `decodeIdentityOutput`, `:497-559`), the rule of
//! `Transaction::from_beef(_, None)`. Until #721 both parsers read
//! `beef.txs.first()`: the parent of the order every writer writes (TS 2,
//! TS 3 and this crate's sort put the subject last), so a revelation whose own
//! transaction is unproven was skipped, and a BEEF listing the subject before its
//! parent was read where the reference reads the parent. Against
//! `tests/vectors/identity_beef_subject_721.json`
//! (`tests/support/identity_beef_subject_721.mjs`, Node v22.18.0): five
//! shapes of the same two transactions, each rebuilt here by this crate's
//! writer to the recorded bytes, with `parseResults`' outcome. Hermetic: an
//! in-process facilitator on an `.invalid` host.
#![cfg(feature = "identity")]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use bsv_rs::identity::IdentityClient;
use bsv_rs::overlay::{
    LookupAnswer, LookupQuestion, LookupResolver, LookupResolverConfig, OutputListItem,
    OverlayLookupFacilitator,
};
use bsv_rs::primitives::{to_hex, Writer};
use bsv_rs::script::{LockingScript, UnlockingScript};
use bsv_rs::transaction::{
    Beef, MerklePath, MerklePathLeaf, Transaction, TransactionInput, TransactionOutput,
};
use bsv_rs::wallet::ProtoWallet;
use indexmap::IndexMap;
use serde_json::Value;
use std::collections::HashMap;
use std::sync::Arc;

fn vector() -> Value {
    serde_json::from_str(include_str!("vectors/identity_beef_subject_721.json")).unwrap()
}

/// The reference's own revelation token and its subject (#553's vector).
fn token_and_subject() -> (LockingScript, String) {
    let v: Value =
        serde_json::from_str(include_str!("vectors/identity_certificate_record_553.json")).unwrap();
    let script = LockingScript::from_hex(v["cases"][0]["locking_script"].as_str().unwrap());
    (script.unwrap(), v["subject"].as_str().unwrap().to_string())
}

/// One input spending `txid:0` with `unlocking`, one 1-satoshi output.
fn spending(txid: String, unlocking: &str, output: LockingScript) -> Transaction {
    let mut input = TransactionInput::new(txid, 0);
    input.set_unlocking_script(UnlockingScript::from_hex(unlocking).unwrap());
    let mut tx = Transaction::new();
    tx.add_input(input).unwrap();
    tx.add_output(TransactionOutput::new(1, output)).unwrap();
    tx
}

/// A block of `tx` alone at height 900: its BUMP a lone leaf at offset 0.
fn lone_leaf(tx: &Transaction) -> MerklePath {
    MerklePath::new(900, vec![vec![MerklePathLeaf::new_txid(0, tx.id())]]).unwrap()
}

/// The BEEF of `entries` (raw, proven by `bump`) in the order given, never
/// sorted, after an Atomic BEEF prefix naming `atomic` when given.
fn write(bump: MerklePath, entries: &[(&Transaction, bool)], atomic: Option<&str>) -> Vec<u8> {
    let mut beef = Beef::new();
    let index = beef.merge_bump(bump);
    for (tx, proven) in entries {
        beef.merge_raw_tx(tx.to_binary(), proven.then_some(index))
            .expect("the bytes are one transaction");
    }
    let mut writer = Writer::new();
    if let Some(txid) = atomic {
        writer.write_u32_le(0x0101_0101);
        let mut subject = bsv_rs::primitives::from_hex(txid).unwrap();
        subject.reverse();
        writer.write_bytes(&subject);
    }
    beef.to_writer(&mut writer).expect("the BEEF is writable");
    writer.into_bytes()
}

/// The five shapes, by the recorder's names.
fn shapes(v: &Value, token: &LockingScript) -> Vec<(&'static str, Vec<u8>)> {
    let op_true = LockingScript::from_hex("51").unwrap();
    let parent = spending("11".repeat(32), "51", op_true);
    let subject = spending(parent.id(), "", token.clone());
    let alone = spending("11".repeat(32), "51", token.clone());
    assert_eq!(parent.id(), v["parent_txid"].as_str().unwrap());
    assert_eq!(subject.id(), v["subject_txid"].as_str().unwrap());
    assert_eq!(alone.id(), v["single_txid"].as_str().unwrap());
    let sid = subject.id();
    vec![
        ("single", write(lone_leaf(&alone), &[(&alone, true)], None)),
        (
            "parent_first",
            write(
                lone_leaf(&parent),
                &[(&parent, true), (&subject, false)],
                None,
            ),
        ),
        (
            "atomic_parent_first",
            write(
                lone_leaf(&parent),
                &[(&parent, true), (&subject, false)],
                Some(&sid),
            ),
        ),
        (
            "subject_first",
            write(
                lone_leaf(&parent),
                &[(&subject, false), (&parent, true)],
                None,
            ),
        ),
        (
            "atomic_subject_first",
            write(
                lone_leaf(&parent),
                &[(&subject, false), (&parent, true)],
                Some(&sid),
            ),
        ),
    ]
}

/// A facilitator answering every question with one output.
struct Answering(OutputListItem);

#[async_trait::async_trait(?Send)]
impl OverlayLookupFacilitator for Answering {
    async fn lookup(
        &self,
        _url: &str,
        _question: &LookupQuestion,
        _timeout_ms: Option<u64>,
    ) -> bsv_rs::Result<LookupAnswer> {
        Ok(LookupAnswer::OutputList {
            outputs: vec![self.0.clone()],
        })
    }
}

/// How many identities and certificates the two parsers return for `beef`.
async fn read(beef: Vec<u8>, subject: &str) -> (usize, usize) {
    let output = OutputListItem {
        beef,
        output_index: 0,
        context: None,
        txid: None,
    };
    let resolver = Arc::new(LookupResolver::new(LookupResolverConfig {
        facilitator: Some(Arc::new(Answering(output))),
        slap_trackers: Some(vec![]),
        host_overrides: Some(HashMap::from([(
            "ls_identity".to_string(),
            vec!["https://ls_identity.invalid".to_string()],
        )])),
        ..Default::default()
    }));
    let client =
        IdentityClient::with_resolver(ProtoWallet::new(None), Default::default(), resolver);
    let attributes = IndexMap::from([("email".to_string(), "alice@example.com".to_string())]);
    let identities = client
        .resolve_by_attributes(attributes, false)
        .await
        .unwrap();
    let certificates = client.discover_certificates(subject).await.unwrap();
    (identities.len(), certificates.len())
}

#[tokio::test]
async fn the_identity_parsers_read_the_token_from_the_beef_subject_the_reference_reads_721() {
    let v = vector();
    let (token, subject) = token_and_subject();
    let recorded = v["shapes"].as_array().unwrap();
    let built = shapes(&v, &token);
    assert_eq!(recorded.len(), built.len());
    let mut differ = Vec::new();
    for (case, (name, beef)) in recorded.iter().zip(built) {
        assert_eq!(case["name"], name);
        assert_eq!(
            to_hex(&beef),
            case["beef"].as_str().unwrap(),
            "{name}: this crate's writer and the recorded bytes"
        );
        // The transaction the reference selects is the one this crate's
        // BEEF subject rule names
        let selected = Transaction::from_beef(&beef, None).unwrap().id();
        assert_eq!(selected, case["selected_txid"].as_str().unwrap(), "{name}");
        let expected = match case["outcome"].as_str().unwrap() {
            "read" => (1, 1),
            "skipped" => (0, 0),
            other => panic!("{name}: unexpected outcome {other}"),
        };
        let got = read(beef, &subject).await;
        if got != expected {
            differ.push(format!("{name}: {got:?}, the reference {expected:?}"));
        }
    }
    assert!(differ.is_empty(), "{differ:#?}");
}
