//! Utility functions for authentication.
//!
//! This module provides utilities for:
//! - Nonce creation and verification
//! - Certificate validation

mod nonce;
mod received_message;
mod requested_set;
mod validation;

pub use nonce::{
    create_nonce, get_nonce_random, validate_nonce_format, verify_nonce, NONCE_PROTOCOL,
};
pub(crate) use received_message::{check_received_message, MAX_CERTIFICATES};
pub use requested_set::assert_requested_certificate_set;
pub(crate) use requested_set::check_received_requested_certificates;
pub use validation::{
    certificates_match_request, get_verifiable_certificates, validate_certificate,
    validate_certificate_encoding, validate_certificates, validate_requested_certificate_set,
};

/// One Promise continuation turn without a runtime or timer. Certificate
/// checks and wallet decryptions retain the reference's await boundaries,
/// including when a Rust wallet future completes on its opening poll.
pub(crate) async fn certificate_continuation() {
    let mut yielded = false;
    std::future::poll_fn(|cx| {
        if std::mem::replace(&mut yielded, true) {
            std::task::Poll::Ready(())
        } else {
            cx.waker().wake_by_ref();
            std::task::Poll::Pending
        }
    })
    .await;
}
