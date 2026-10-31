//! #537, site 5: `decode_overlay_admin_token` decodes an advertisement
//! lock-before alone, as its counterpart does (`ts-stack@edf6e03`
//! `OverlayAdminTokenTemplate.ts:164`, `decodeCanonicalPushDrop` over
//! `PushDrop.decode` at its default position, thrown to the caller from
//! `:237-239`): a lock-after token is refused in the reference's words, the
//! key parse's where its first field is no point, the field count's where it
//! is one (the corner).
#![cfg(feature = "overlay")]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#[path = "support/pushdrop_lock_position_537.rs"]
mod lock_position;

use bsv_rs::overlay::decode_overlay_admin_token;
use bsv_rs::Error;

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
