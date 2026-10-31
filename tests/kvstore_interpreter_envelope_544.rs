//! #544, site 4: the kvstore interpreter reads a token through the
//! reference's `decodeAndVerifyKVStoreToken` (`ts-stack@edf6e03`
//! `kvStoreTokenValidation.ts:86-122`): the canonical envelope of five or
//! six fields, the canonical JSON protocol, the bounds, the controller-linked
//! locking key and the controller's signature, a refused token no value, as
//! `kvStoreInterpreter.ts:48` answers `undefined`. Against the kvstore cases
//! of `tests/vectors/token_envelope_544.json` (`tests/support/token_envelope_544.mjs`,
//! Node v22.18.0): the reference's token with and without tags read to its
//! value, and five one-change tokens (the raw-protocol form this crate wrote
//! before #343 among them) no value, as the reference interpreter gives them.
//! The reader's words are pinned by the unit test in
//! `src/kvstore/token_validation_tests.rs`.
#![cfg(feature = "kvstore")]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#[path = "support/pushdrop_lock_position_537.rs"]
mod lock_position;

use bsv_rs::kvstore::{KVStoreContext, KVStoreInterpreter};
use bsv_rs::script::LockingScript;
use serde_json::Value;

fn vector() -> Value {
    serde_json::from_str(include_str!("vectors/token_envelope_544.json")).unwrap()
}

#[test]
fn the_interpreter_reads_only_what_the_reference_interpreter_reads_544() {
    let v = vector();
    let kvstore = &v["kvstore"];
    let ctx = KVStoreContext::new(kvstore["context"]["key"].as_str().unwrap(), "kvstore");
    let cases = kvstore["cases"].as_array().unwrap();
    assert_eq!(cases.len(), 7);
    for case in cases {
        let script = LockingScript::from_hex(case["locking_script"].as_str().unwrap()).unwrap();
        let tx = lock_position::source_of(script);
        let value = KVStoreInterpreter::interpret(&tx, 0, Some(&ctx)).map(|entry| entry.value);
        assert_eq!(
            value.as_deref(),
            case["value"].as_str(),
            "{}: {}",
            case["name"],
            case["words"]
        );
    }
}
