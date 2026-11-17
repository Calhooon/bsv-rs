//! TOTP (Time-based One-Time Password) implementation.
//!
//! Implements RFC 6238 for generating time-based OTPs commonly used in 2FA.

use crate::primitives::hash::{sha1_hmac, sha256_hmac, sha512_hmac};
use subtle::ConstantTimeEq;

crate::util::non_exhaustive::non_exhaustive_enum! {
    path = bsv_rs::totp::Algorithm;
/// HMAC algorithm for TOTP generation.
///
/// Per RFC 6238, SHA-1 is the default algorithm for backwards compatibility
/// with most authenticator apps, though SHA-256 and SHA-512 offer stronger
/// security margins.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[non_exhaustive]
pub enum Algorithm {
    /// HMAC-SHA1 (default, 20-byte output)
    #[default]
    Sha1,
    /// HMAC-SHA256 (32-byte output)
    Sha256,
    /// HMAC-SHA512 (64-byte output)
    Sha512,
}
}

/// Options for TOTP generation.
///
/// All fields have sensible defaults following RFC 6238 recommendations.
#[derive(Debug, Clone)]
pub struct TotpOptions {
    /// Number of digits in the generated code (default: 6).
    ///
    /// Common values are 6 or 8. The value should be between 1 and 10
    /// for practical use.
    pub digits: u32,

    /// HMAC algorithm to use (default: SHA-1).
    ///
    /// SHA-1 is the most widely supported by authenticator apps.
    /// SHA-256 and SHA-512 provide stronger security.
    pub algorithm: Algorithm,

    /// Time period in seconds (default: 30).
    ///
    /// The counter increments every `period` seconds. 30 seconds is
    /// the standard value used by most services.
    pub period: u64,

    /// Override timestamp in seconds since Unix epoch.
    ///
    /// If `None`, uses the current system time. Set this for testing
    /// or when generating codes for a specific time.
    pub timestamp: Option<u64>,
}

impl Default for TotpOptions {
    fn default() -> Self {
        Self {
            digits: 6,
            algorithm: Algorithm::Sha1,
            period: 30,
            timestamp: None,
        }
    }
}

/// Options for TOTP validation.
///
/// Extends `TotpOptions` with a skew parameter to handle clock drift.
#[derive(Debug, Clone)]
pub struct TotpValidateOptions {
    /// Base TOTP options (digits, algorithm, period, timestamp).
    pub options: TotpOptions,

    /// Number of time periods to check before and after the current period.
    ///
    /// Default is 1, which means codes from the previous period, current
    /// period, and next period are all accepted. This accommodates up to
    /// 30 seconds of clock drift in either direction (with default 30-second
    /// periods).
    ///
    /// Higher values increase tolerance for clock drift but reduce security.
    pub skew: u32,
}

impl Default for TotpValidateOptions {
    fn default() -> Self {
        Self {
            options: TotpOptions::default(),
            skew: 1,
        }
    }
}

/// TOTP (Time-based One-Time Password) implementation.
///
/// Implements RFC 6238 for generating time-based OTPs commonly used in 2FA.
///
/// # Security Considerations
///
/// - The secret should be at least 16 bytes (128 bits) of high-entropy data
/// - Codes should be transmitted over secure channels only
/// - Validation uses constant-time comparison to prevent timing attacks
/// - Consider rate limiting validation attempts to prevent brute force attacks
///
/// # Example
///
/// ```rust
/// use bsv_rs::totp::{Totp, TotpOptions};
///
/// let secret = b"12345678901234567890";
///
/// // Generate with defaults (6 digits, SHA-1, 30-second period)
/// let code = Totp::generate(secret, None);
///
/// // Validate the code
/// assert!(Totp::validate(secret, &code, None));
/// ```
pub struct Totp;

impl Totp {
    /// Generate a TOTP code from a shared secret.
    ///
    /// # Arguments
    ///
    /// * `secret` - The shared secret key (raw bytes, typically 20+ bytes)
    /// * `options` - Optional TOTP parameters; uses defaults if `None`
    ///
    /// # Returns
    ///
    /// A string containing the TOTP code, zero-padded to the configured
    /// number of digits.
    ///
    /// # Example
    ///
    /// ```rust
    /// use bsv_rs::totp::{Totp, TotpOptions, Algorithm};
    ///
    /// let secret = b"12345678901234567890";
    ///
    /// // Generate with defaults
    /// let code = Totp::generate(secret, None);
    /// assert_eq!(code.len(), 6);
    ///
    /// // Generate with custom options
    /// let options = TotpOptions {
    ///     digits: 8,
    ///     algorithm: Algorithm::Sha256,
    ///     timestamp: Some(59), // Fixed time for testing
    ///     ..Default::default()
    /// };
    /// let code = Totp::generate(secret, Some(options));
    /// assert_eq!(code.len(), 8);
    /// ```
    pub fn generate(secret: &[u8], options: Option<TotpOptions>) -> String {
        let options = options.unwrap_or_default();
        let timestamp = options.timestamp.unwrap_or_else(current_unix_seconds);
        let counter = timestamp / options.period;
        generate_hotp(secret, counter, &options)
    }

    /// Validate a TOTP code against a shared secret.
    ///
    /// Checks the provided passcode against codes generated for the current
    /// time window and adjacent windows (determined by the `skew` parameter).
    ///
    /// # Arguments
    ///
    /// * `secret` - The shared secret key (raw bytes)
    /// * `passcode` - The TOTP code to validate (will be trimmed of whitespace)
    /// * `options` - Optional validation parameters; uses defaults if `None`
    ///
    /// # Returns
    ///
    /// `true` if the passcode matches any valid code within the skew window,
    /// `false` otherwise.
    ///
    /// # Security
    ///
    /// This function uses constant-time comparison to prevent timing attacks.
    ///
    /// # Example
    ///
    /// ```rust
    /// use bsv_rs::totp::{Totp, TotpValidateOptions, TotpOptions};
    ///
    /// let secret = b"12345678901234567890";
    /// let code = Totp::generate(secret, None);
    ///
    /// // Validate with default skew (1 period before/after)
    /// assert!(Totp::validate(secret, &code, None));
    ///
    /// // Validate with custom options
    /// let validate_options = TotpValidateOptions {
    ///     options: TotpOptions::default(),
    ///     skew: 2, // Accept codes from 2 periods before/after
    /// };
    /// assert!(Totp::validate(secret, &code, Some(validate_options)));
    ///
    /// // Invalid codes are rejected
    /// assert!(!Totp::validate(secret, "000000", None));
    /// ```
    pub fn validate(secret: &[u8], passcode: &str, options: Option<TotpValidateOptions>) -> bool {
        let options = options.unwrap_or_default();
        let passcode = passcode.trim();

        // Quick reject if length doesn't match expected digits
        if passcode.len() != options.options.digits as usize {
            return false;
        }

        let timestamp = options
            .options
            .timestamp
            .unwrap_or_else(current_unix_seconds);
        let counter = timestamp / options.options.period;

        // Check current counter and adjacent counters within skew window
        // We check current first, then alternating before/after
        let mut counters_to_check = Vec::with_capacity(1 + 2 * options.skew as usize);
        counters_to_check.push(counter);

        for i in 1..=options.skew as u64 {
            counters_to_check.push(counter.wrapping_add(i));
            // Use saturating_sub to handle counter near 0
            if counter >= i {
                counters_to_check.push(counter - i);
            }
        }

        for check_counter in counters_to_check {
            let expected = generate_hotp(secret, check_counter, &options.options);
            if constant_time_eq(passcode, &expected) {
                return true;
            }
        }

        false
    }
}

/// Generate an HOTP code for a specific counter value.
///
/// Implements RFC 4226 (HOTP algorithm):
/// 1. Compute HMAC of counter (as 8-byte big-endian) using the secret
/// 2. Dynamic truncation to extract 4-byte code
/// 3. Reduce modulo 10^digits
/// 4. Zero-pad to required length
fn generate_hotp(secret: &[u8], counter: u64, options: &TotpOptions) -> String {
    // Counter as 8-byte big-endian (RFC 4226 Section 5.1)
    let counter_bytes = counter.to_be_bytes();

    // Compute HMAC based on algorithm
    let hmac_result: Vec<u8> = match options.algorithm {
        Algorithm::Sha1 => sha1_hmac(secret, &counter_bytes).to_vec(),
        Algorithm::Sha256 => sha256_hmac(secret, &counter_bytes).to_vec(),
        Algorithm::Sha512 => sha512_hmac(secret, &counter_bytes).to_vec(),
    };

    // Dynamic truncation (RFC 4226 Section 5.4)
    let offset = (hmac_result[hmac_result.len() - 1] & 0x0f) as usize;

    // Extract 4 bytes starting at offset
    let code_bytes = [
        hmac_result[offset] & 0x7f, // Mask high bit to ensure positive
        hmac_result[offset + 1],
        hmac_result[offset + 2],
        hmac_result[offset + 3],
    ];

    let code = u32::from_be_bytes(code_bytes);

    // Reduce modulo 10^digits
    let divisor = 10u32.pow(options.digits);
    let truncated = code % divisor;

    // Zero-pad to required length
    format!("{:0>width$}", truncated, width = options.digits as usize)
}

/// Get current Unix timestamp in seconds.
fn current_unix_seconds() -> u64 {
    crate::util::time::current_time_secs()
}

/// Constant-time string comparison to prevent timing attacks.
fn constant_time_eq(a: &str, b: &str) -> bool {
    if a.len() != b.len() {
        return false;
    }
    a.as_bytes().ct_eq(b.as_bytes()).into()
}

#[cfg(test)]
#[path = "core_tests.rs"]
mod tests;
