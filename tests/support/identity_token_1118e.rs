//! Hermetic support for the identity token-authentication regression
//! (bsv-rs#1118e): an in-process `ls_identity` resolver on an `.invalid`
//! host (never dialled), and a lookup output carrying a token in a
//! transaction proven by a block of its own (a lone leaf at offset 0).
#![allow(dead_code)]

use bsv_rs::overlay::{
    LookupAnswer, LookupQuestion, LookupResolver, LookupResolverConfig, OutputListItem,
    OverlayLookupFacilitator,
};
use bsv_rs::script::LockingScript;
use bsv_rs::transaction::{
    Beef, MerklePath, MerklePathLeaf, Transaction, TransactionInput, TransactionOutput,
};
use std::collections::HashMap;
use std::sync::Arc;

/// A transaction of one made-up input whose output 0 is `script`.
fn source_of(script: LockingScript) -> Transaction {
    let mut tx = Transaction::new();
    tx.add_input(TransactionInput::new("11".repeat(32), 0))
        .unwrap();
    tx.add_output(TransactionOutput::new(1, script)).unwrap();
    tx
}

/// A lookup output carrying `script` at index 0, its transaction proven by
/// a block of its own (a lone leaf at offset 0), so the identity parsers'
/// evidence check admits it without the made-up parent (#730).
pub fn output_of(script: LockingScript) -> OutputListItem {
    let tx = source_of(script);
    let leaf = MerklePathLeaf::new_txid(0, tx.id());
    let mut beef = Beef::new();
    let index = beef.merge_bump(MerklePath::new(900, vec![vec![leaf]]).unwrap());
    beef.merge_raw_tx(tx.to_binary(), Some(index));
    OutputListItem {
        beef: beef.to_binary(),
        output_index: 0,
        context: None,
    }
}

/// A facilitator answering every question with the outputs given.
struct Answering(Vec<OutputListItem>);

#[async_trait::async_trait(?Send)]
impl OverlayLookupFacilitator for Answering {
    async fn lookup(
        &self,
        _url: &str,
        _question: &LookupQuestion,
        _timeout_ms: Option<u64>,
    ) -> bsv_rs::Result<LookupAnswer> {
        Ok(LookupAnswer::OutputList {
            outputs: self.0.clone(),
        })
    }
}

/// A resolver whose one host for `service` (an `.invalid` name carrying
/// `tag`, never dialled, unique per test so the process-wide host
/// reputation is not shared) answers `outputs`.
pub fn answering(service: &str, tag: &str, outputs: Vec<OutputListItem>) -> Arc<LookupResolver> {
    Arc::new(LookupResolver::new(LookupResolverConfig {
        facilitator: Some(Arc::new(Answering(outputs))),
        slap_trackers: Some(vec![]),
        host_overrides: Some(HashMap::from([(
            service.to_string(),
            vec![format!("https://{service}.{tag}-1118e.invalid")],
        )])),
        ..Default::default()
    }))
}
