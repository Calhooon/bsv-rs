#![cfg(test)]
//! The two `ls_identity` parsers' lock position, pinned at their decode site
//! (#744): `decode_token` reads lock-before alone, as the reference's
//! `PushDrop.decode` at its default position reads a revelation token
//! (`ts-stack@edf6e03` `IdentityClient.ts:773`, #537). Since #544 the token
//! check refuses every lock-after layout on its own
//! (`is_canonical_signed_pushdrop`: a 33-byte key push, then `OP_CHECKSIG`),
//! so no token can pass it locked after and the parsers' public answers
//! cannot tell the position's rule from the check's; the pin is here, on the
//! reference's own revelation token (#553's `reference` case, the subject 9)
//! relocked after its fields: the same key, the same two fields, the same
//! signature over the same bytes.

use super::*;
use crate::primitives::PublicKey;
use crate::script::templates::LockPosition;
use crate::script::LockingScript;

/// #553's `reference` case: the reference's revelation token, and its
/// subject.
fn reference_token() -> (LockingScript, PublicKey) {
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
    let script = LockingScript::from_hex(case["locking_script"].as_str().unwrap()).unwrap();
    let subject = PublicKey::from_hex(v["subject"].as_str().unwrap()).unwrap();
    (script, subject)
}

#[test]
fn a_lock_after_revelation_is_refused_by_the_parsers_decode_site_744() {
    let (before, subject) = reference_token();
    let client = IdentityClient::new(ProtoWallet::new(None), Default::default());

    // The control: the reference's token, read at the site and authenticated.
    let read = decode_token(&before).expect("the reference's lock-before token is read");
    assert!(client.is_authenticated_token(&before, &read, &subject));

    // The same key and fields locked after, which `PushDrop::decode` (the
    // lock position either way) reads with the same fields.
    let after = PushDrop::new(read.locking_public_key.clone(), read.fields.clone())
        .with_position(LockPosition::After)
        .lock();
    let either = PushDrop::decode(&after).expect("PushDrop::decode reads either position");
    assert_eq!(either.lock_position, LockPosition::After);
    assert_eq!(either.locking_public_key, read.locking_public_key);
    assert_eq!(either.fields, read.fields);

    // The token check refuses it on its own (why the parsers' answers
    // cannot pin the position) ...
    assert!(!client.is_authenticated_token(&after, &either, &subject));
    // ... and the decode site refuses it by the position alone (#537).
    assert!(
        decode_token(&after).is_none(),
        "the parsers' decode site reads lock-before alone"
    );
}
