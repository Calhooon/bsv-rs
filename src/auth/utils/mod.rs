//! Utility functions for authentication.
//!
//! This module provides utilities for:
//! - Nonce creation and verification
//! - Certificate validation

mod nonce;
mod validation;

pub use nonce::{create_nonce, get_nonce_random, validate_nonce_format, verify_nonce, NONCE_PROTOCOL};
pub use validation::{
    certificates_match_request, get_verifiable_certificates, validate_certificate,
    validate_certificates,
};
