//! #537, site 5: `decode_overlay_admin_token` decodes an advertisement
//! lock-before alone, as its counterpart does (`ts-stack@edf6e03`
//! `OverlayAdminTokenTemplate.ts:164`, `decodeCanonicalPushDrop` over
//! `PushDrop.decode` at its default position, thrown to the caller from
//! `:237-239`): a lock-after token is refused in the reference's words, the
//! key parse's where its first field is no point, the field count's where it
//! is one (the corner).
#![cfg(feature = "overlay")]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#[path = "support/pushdrop_decode_618.rs"]
mod decode_618;
#[path = "support/pushdrop_lock_position_537.rs"]
mod lock_position;

use bsv_rs::overlay::decode_overlay_admin_token;
use bsv_rs::Error;
use serde_json::Value;

#[test]
fn a_lock_after_advertisement_is_refused_in_the_reference_words_537() {
    let cases = lock_position::cases("overlay_admin_token");
    assert_eq!(cases.len(), 2);
    for case in &cases {
        assert_eq!(case["outcome"], "refused", "{}", case["name"]);
        let words = case["site_words"].as_str().unwrap().to_string();
        assert_eq!(
            decode_overlay_admin_token(&lock_position::script(case)).unwrap_err(),
            Error::OverlayError(words),
            "{}",
            case["name"]
        );
    }
    // The same advertisement locked before is decoded.
    let control = lock_position::relocked_before(&cases[0]);
    let token = decode_overlay_admin_token(&control).unwrap();
    assert_eq!(token.domain, "https://ship.example");
    assert_eq!(token.topic_or_service, "tm_test");
}

/// The #537 case a #618 case was built from.
fn from_537<'a>(cases: &'a [Value], case: &Value) -> &'a Value {
    cases
        .iter()
        .find(|old| old["name"] == case["from_537"])
        .unwrap()
}

/// #618: a key alone and a token without CHECKSIG second, which the public
/// `PushDrop::decode` reads as the reference does, are refused in
/// `decodeCanonicalPushDrop`'s words (`OverlayAdminTokenTemplate.ts:164`,
/// thrown from `:237-239`; `PushDropValidation.ts:54-79`).
#[test]
fn a_key_only_and_a_no_checksig_advertisement_are_refused_in_the_reference_words_618() {
    let old = lock_position::cases("overlay_admin_token");
    let cases = decode_618::cases("overlay_admin_token");
    assert_eq!(cases.len(), 2);
    for case in &cases {
        assert_eq!(case["outcome"], "refused", "{}", case["name"]);
        let script = decode_618::script(case, from_537(&old, case));
        assert_eq!(
            decode_overlay_admin_token(&script).unwrap_err(),
            Error::OverlayError(case["site_words"].as_str().unwrap().to_string()),
            "{}",
            case["name"]
        );
    }
}
