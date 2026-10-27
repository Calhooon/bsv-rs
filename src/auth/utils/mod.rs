//! Utility functions for authentication.
//!
//! This module provides utilities for:
//! - Nonce creation and verification
//! - Certificate validation

mod nonce;
mod requested_set;
mod validation;

pub use nonce::{
    create_nonce, get_nonce_random, validate_nonce_format, verify_nonce, NONCE_PROTOCOL,
};
pub use requested_set::assert_requested_certificate_set;
pub(crate) use requested_set::check_received_requested_certificates;
pub use validation::{
    certificates_match_request, get_verifiable_certificates, validate_certificate,
    validate_certificate_encoding, validate_certificates, validate_requested_certificate_set,
};
