#![cfg(test)]
//! The revocation's lock position, pinned at its decode site (#746):
//! `decode_revocation_token` reads lock-before alone, as the reference's
//! `PushDrop.decode` at its default position reads the revelation token it
//! spends (`ts-stack@edf6e03` `IdentityClient.ts:773`, #537). The token check
//! after it (`is_canonical_signed_pushdrop`, #544: a 33-byte key push, then
//! `OP_CHECKSIG`) refuses every lock-after layout on its own, so the
//! revocation's answers cannot tell the position's rule from the check's;
//! the pin is here, as #744's is at the parsers' `decode_token`, on the
//! reference's own revelation token (#553's `reference` case) relocked after
//! its fields: the same key, the same two fields, the same signature.

use super::*;
use crate::script::templates::LockPosition;
use crate::script::LockingScript;

/// #553's `reference` case: the reference's revelation token.
fn reference_token() -> LockingScript {
    let v: serde_json::Value = serde_json::from_str(include_str!(
        "../../tests/vectors/identity_certificate_record_553.json"
    ))
    .unwrap();
    let case = v["cases"]
        .as_array()
        .unwrap()
        .iter()
        .find(|c| c["name"] == "reference")
        .unwrap();
    LockingScript::from_hex(case["locking_script"].as_str().unwrap()).unwrap()
}

#[test]
fn a_lock_after_revelation_is_refused_by_the_revocations_decode_site_746() {
    let before = reference_token();

    // The control: the reference's token, read at the site and passing the
    // token check the revocation runs after it.
    let read = decode_revocation_token(&before).expect("the reference's lock-before token is read");
    assert_eq!(read.fields.len(), 2);
    assert!(super::super::token_envelope::is_canonical_signed_pushdrop(
        &before,
        &read.fields
    ));

    // The same key and fields locked after, which `PushDrop::decode` (the
    // lock position either way) reads with the same fields.
    let after = PushDrop::new(read.locking_public_key.clone(), read.fields.clone())
        .with_position(LockPosition::After)
        .lock();
    let either = PushDrop::decode(&after).expect("PushDrop::decode reads either position");
    assert_eq!(either.lock_position, LockPosition::After);
    assert_eq!(either.locking_public_key, read.locking_public_key);
    assert_eq!(either.fields, read.fields);

    // The token check refuses it on its own (why the revocation's answers
    // cannot pin the position) ...
    assert!(!super::super::token_envelope::is_canonical_signed_pushdrop(
        &after,
        &either.fields
    ));
    // ... and the decode site refuses it by the position alone (#537).
    assert!(
        decode_revocation_token(&after).is_none(),
        "the revocation's decode site reads lock-before alone"
    );
}
