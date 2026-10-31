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
use bsv_rs::transaction::{Beef, Transaction, TransactionInput, TransactionOutput};
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

/// A lookup output carrying `script` at index 0.
pub fn output_of(script: LockingScript) -> OutputListItem {
    let mut beef = Beef::new();
    beef.merge_transaction(source_of(script));
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

/// A resolver whose one host for `service` (an `.invalid` name, never
/// dialled) answers `script`'s output.
pub fn answering(service: &str, script: LockingScript) -> Arc<LookupResolver> {
    Arc::new(LookupResolver::new(LookupResolverConfig {
        facilitator: Some(Arc::new(Answering(vec![output_of(script)]))),
        slap_trackers: Some(vec![]),
        host_overrides: Some(HashMap::from([(
            service.to_string(),
            vec![format!("https://{service}.invalid")],
        )])),
        ..Default::default()
    }))
}
