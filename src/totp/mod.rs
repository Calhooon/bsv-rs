//! # TOTP Module
//!
//! Time-based One-Time Password (TOTP) implementation following RFC 6238.
//!
//! This module provides TOTP generation and validation commonly used for
//! two-factor authentication (2FA). It supports multiple HMAC algorithms
//! (SHA-1, SHA-256, SHA-512) and uses constant-time comparison to prevent
//! timing attacks during validation.
//!
//! ## Example
//!
//! ```rust
//! use bsv_rs::totp::{Totp, TotpOptions, Algorithm};
//!
//! // Shared secret (typically from a base32-decoded QR code)
//! let secret = b"12345678901234567890";
//!
//! // Generate a 6-digit TOTP code
//! let code = Totp::generate(secret, None);
//! println!("Current TOTP: {}", code);
//!
//! // Validate a code (accepts codes from adjacent time windows)
//! assert!(Totp::validate(secret, &code, None));
//!
//! // Use SHA-256 algorithm with 8 digits
//! let options = TotpOptions {
//!     algorithm: Algorithm::Sha256,
//!     digits: 8,
//!     ..Default::default()
//! };
//! let code_sha256 = Totp::generate(secret, Some(options));
//! ```
//!
//! ## RFC Compliance
//!
//! This implementation follows:
//! - RFC 6238: TOTP (Time-Based One-Time Password Algorithm)
//! - RFC 4226: HOTP (HMAC-Based One-Time Password Algorithm)

mod core;

pub use core::{Algorithm, Totp, TotpOptions, TotpValidateOptions};
