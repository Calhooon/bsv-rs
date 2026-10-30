//! #400: the reference re-stringifies a certificateResponse before signing
//! or verifying it, including JavaScript's numeric property order.
#![cfg(feature = "auth")]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)] // #134: regression assertions

use bsv_rs::auth::AuthMessage;
use serde::Deserialize;

#[derive(Deserialize)]
struct Witness {
    input_message: String,
    reference_preimage: String,
    reordered_message: String,
}

fn witness() -> Witness {
    serde_json::from_str(include_str!("vectors/auth_response_order_400.json")).unwrap()
}

#[test]
fn certificate_response_numeric_keys_use_the_recorded_reference_preimage() {
    let witness = witness();
    let message: AuthMessage = serde_json::from_str(&witness.input_message).unwrap();
    assert_eq!(
        message.signing_data(),
        witness.reference_preimage.as_bytes()
    );
}

#[test]
fn typed_certificates_sign_in_reference_order_without_retained_text() {
    let witness = witness();
    let mut message: AuthMessage = serde_json::from_str(&witness.input_message).unwrap();
    // Force the typed fallback: fields/keyring retain the input's 10,2,z,a
    // order, while signing puts numeric names first and keeps z before a.
    message.certificates_text = None;
    assert_eq!(
        message.signing_data(),
        witness.reference_preimage.as_bytes()
    );
}

#[test]
fn certificate_response_restores_reference_class_property_order() {
    let witness = witness();
    let message: AuthMessage = serde_json::from_str(&witness.reordered_message).unwrap();
    assert_eq!(
        message.signing_data(),
        witness.reference_preimage.as_bytes()
    );
}
