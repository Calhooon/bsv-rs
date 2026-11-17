//! The #537 vector's cases and the outputs and resolvers its site tests serve
//! them through (`tests/vectors/pushdrop_lock_position_537.json`, written by
//! `tests/support/pushdrop_lock_position_537.mjs`).
#![allow(dead_code)]

use bsv_rs::overlay::{
    LookupAnswer, LookupQuestion, LookupResolver, LookupResolverConfig, OutputListItem,
    OverlayLookupFacilitator,
};
use bsv_rs::script::templates::PushDrop;
use bsv_rs::script::LockingScript;
use bsv_rs::transaction::{
    Beef, MerklePath, MerklePathLeaf, Transaction, TransactionInput, TransactionOutput,
};
use serde_json::Value;
use std::collections::HashMap;
use std::sync::Arc;

/// The site's two cases, the not-a-point kind first, then the corner.
pub fn cases(site: &str) -> Vec<Value> {
    let recorded: Value =
        serde_json::from_str(include_str!("../vectors/pushdrop_lock_position_537.json")).unwrap();
    let site = recorded["sites"]
        .as_array()
        .unwrap()
        .iter()
        .find(|entry| entry["site"] == site)
        .unwrap();
    site["cases"].as_array().unwrap().clone()
}

pub fn script(case: &Value) -> LockingScript {
    LockingScript::from_hex(case["script"].as_str().unwrap()).unwrap()
}

/// The same fields locked before, by this crate's writer: the control a site
/// accepts on base and tip.
pub fn relocked_before(case: &Value) -> LockingScript {
    let token = PushDrop::decode(&script(case)).unwrap();
    PushDrop::new(token.locking_public_key, token.fields).lock()
}

/// A transaction of one made-up input whose output 0 is `script`.
pub fn source_of(script: LockingScript) -> Transaction {
    let mut tx = Transaction::new();
    tx.add_input(TransactionInput::new("11".repeat(32), 0))
        .unwrap();
    tx.add_output(TransactionOutput::new(1, script)).unwrap();
    tx
}

/// A lookup output carrying `script` at index 0, its transaction proven by
/// a block of its own (a lone leaf at offset 0), so the identity parsers'
/// evidence check, the reference's, admits it without the made-up parent
/// (#730, `TransactionEvidence.ts:173`).
pub fn output_of(script: LockingScript) -> OutputListItem {
    let tx = source_of(script);
    let leaf = MerklePathLeaf::new_txid(0, tx.id());
    let mut beef = Beef::new();
    let index = beef.merge_bump(MerklePath::new(900, vec![vec![leaf]]).unwrap());
    beef.merge_raw_tx(tx.to_binary(), Some(index))
        .expect("the bytes are one transaction");
    OutputListItem {
        beef: beef.to_binary().expect("the BEEF is writable"),
        output_index: 0,
        context: None,
        txid: None,
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

/// A resolver whose one host for `service` (an `.invalid` name, never
/// dialled) answers `script`'s output.
pub fn answering(service: &str, script: LockingScript) -> Arc<LookupResolver> {
    Arc::new(LookupResolver::new(
        LookupResolverConfig::default()
            .with_facilitator(Some(Arc::new(Answering(vec![output_of(script)]))))
            .with_slap_trackers(Some(vec![]))
            .with_host_overrides(Some(HashMap::from([(
                service.to_string(),
                vec![format!("https://{service}.invalid")],
            )]))),
    ))
}

/// A facilitator whose `freeform` host answers a freeform result and whose
/// every other host answers the outputs given.
struct BesideFreeform {
    freeform: String,
    outputs: Vec<OutputListItem>,
}

#[async_trait::async_trait(?Send)]
impl OverlayLookupFacilitator for BesideFreeform {
    async fn lookup(
        &self,
        url: &str,
        _question: &LookupQuestion,
        _timeout_ms: Option<u64>,
    ) -> bsv_rs::Result<LookupAnswer> {
        if url == self.freeform {
            return Ok(LookupAnswer::Freeform {
                result: serde_json::json!({ "note": "no outputs here" }),
            });
        }
        Ok(LookupAnswer::OutputList {
            outputs: self.outputs.clone(),
        })
    }
}

/// A resolver with two hosts for `service` (`.invalid` names carrying `door`,
/// never dialled, a test's own so the process-wide host reputation is not
/// shared): the one ranked ahead answers freeform, the other `script`'s
/// output (#815: the consumer doors beside a freeform host).
pub fn answering_beside_freeform(
    service: &str,
    script: LockingScript,
    door: &str,
) -> Arc<LookupResolver> {
    let freeform = format!("https://freeform.{door}-815.invalid");
    Arc::new(LookupResolver::new(
        LookupResolverConfig::default()
            .with_facilitator(Some(Arc::new(BesideFreeform {
                freeform: freeform.clone(),
                outputs: vec![output_of(script)],
            })))
            .with_slap_trackers(Some(vec![]))
            .with_host_overrides(Some(HashMap::from([(
                service.to_string(),
                vec![freeform, format!("https://list.{door}-815.invalid")],
            )]))),
    ))
}
