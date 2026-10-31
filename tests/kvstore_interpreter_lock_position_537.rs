//! #537, site 4: the kvstore interpreter's three readers decode a token
//! lock-before alone, as their counterpart does (`ts-stack@edf6e03`
//! `kvStoreTokenValidation.ts:88`, `decodeCanonicalPushDrop` over
//! `PushDrop.decode` at its default position): a lock-after token is no
//! value, as the reference's interpreter answers `undefined` from its catch
//! (`kvStoreInterpreter.ts:48`).
#![cfg(feature = "kvstore")]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#[path = "support/pushdrop_lock_position_537.rs"]
mod lock_position;

use bsv_rs::kvstore::KVStoreInterpreter;
use bsv_rs::script::LockingScript;

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
