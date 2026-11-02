//! #537, site 4: the kvstore interpreter's three readers decode a token
//! lock-before alone, as their counterpart does (`ts-stack@edf6e03`
//! `kvStoreTokenValidation.ts:88`, `decodeCanonicalPushDrop` over
//! `PushDrop.decode` at its default position): a lock-after token is no
//! value, as the reference's interpreter answers `undefined` from its catch
//! (`kvStoreInterpreter.ts:48`).
#![cfg(feature = "kvstore")]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#[path = "support/pushdrop_decode_618.rs"]
mod decode_618;
#[path = "support/pushdrop_lock_position_537.rs"]
mod lock_position;

use bsv_rs::kvstore::KVStoreInterpreter;
use bsv_rs::script::LockingScript;
use serde_json::Value;

/// What `extract_fields`, `extract_value` and `is_kvstore_token` read.
fn read(script: &LockingScript) -> (bool, Option<String>, bool) {
    (
        KVStoreInterpreter::extract_fields(script).is_some(),
        KVStoreInterpreter::extract_value(script),
        KVStoreInterpreter::is_kvstore_token(script),
    )
}

#[test]
fn a_lock_after_kvstore_token_is_no_value_as_in_the_reference_537() {
    let cases = lock_position::cases("kvstore_interpreter");
    assert_eq!(cases.len(), 2);
    for case in &cases {
        assert_eq!(case["outcome"], "skipped", "{}", case["name"]);
        let script = lock_position::script(case);
        assert_eq!(read(&script), (false, None, false), "{}", case["name"]);
    }
    // The same token locked before is read by all three.
    let control = lock_position::relocked_before(&cases[0]);
    assert_eq!(read(&control), (true, Some("one".to_string()), true));
}

/// The #537 case a #618 case was built from.
fn from_537<'a>(cases: &'a [Value], case: &Value) -> &'a Value {
    cases
        .iter()
        .find(|old| old["name"] == case["from_537"])
        .unwrap()
}

/// #618: a key alone and a token without CHECKSIG second, which the public
/// `PushDrop::decode` reads as the reference does, are no value to the
/// three readers, as `decodeCanonicalPushDrop` refuses them
/// (`kvStoreTokenValidation.ts:88`, `PushDropValidation.ts:54-79`) and the
/// interpreter's catch answers `undefined` (`kvStoreInterpreter.ts:48`).
#[test]
fn a_key_only_and_a_no_checksig_kvstore_token_are_no_value_as_in_the_reference_618() {
    let old = lock_position::cases("kvstore_interpreter");
    let cases = decode_618::cases("kvstore_interpreter");
    assert_eq!(cases.len(), 2);
    for case in &cases {
        assert_eq!(case["outcome"], "skipped", "{}", case["name"]);
        assert!(!case["site_words"].is_null());
        let script = decode_618::script(case, from_537(&old, case));
        assert_eq!(read(&script), (false, None, false), "{}", case["name"]);
    }
}
