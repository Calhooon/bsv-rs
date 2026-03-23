//! TOTP (Time-based One-Time Password) implementation.
//!
//! Implements RFC 6238 for generating time-based OTPs commonly used in 2FA.

use crate::primitives::hash::{sha1_hmac, sha256_hmac, sha512_hmac};
use std::time::{SystemTime, UNIX_EPOCH};
use subtle::ConstantTimeEq;

/// HMAC algorithm for TOTP generation.
///
/// Per RFC 6238, SHA-1 is the default algorithm for backwards compatibility
/// with most authenticator apps, though SHA-256 and SHA-512 offer stronger
/// security margins.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Algorithm {
    /// HMAC-SHA1 (default, 20-byte output)
    #[default]
    Sha1,
    /// HMAC-SHA256 (32-byte output)
    Sha256,
    /// HMAC-SHA512 (64-byte output)
    Sha512,
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
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("System time is before Unix epoch")
        .as_secs()
}

/// Constant-time string comparison to prevent timing attacks.
fn constant_time_eq(a: &str, b: &str) -> bool {
    if a.len() != b.len() {
        return false;
    }
    a.as_bytes().ct_eq(b.as_bytes()).into()
}

#[cfg(test)]
mod tests {
    use super::*;

    // RFC 6238 Appendix B test vectors
    // Secret keys for different algorithms (from the RFC)
    const SHA1_SECRET: &[u8] = b"12345678901234567890";
    const SHA256_SECRET: &[u8] = b"12345678901234567890123456789012";
    const SHA512_SECRET: &[u8] =
        b"1234567890123456789012345678901234567890123456789012345678901234";

    // RFC 6238 test vectors (8-digit codes)
    #[test]
    fn test_rfc6238_sha1_time_59() {
        let options = TotpOptions {
            digits: 8,
            algorithm: Algorithm::Sha1,
            timestamp: Some(59),
            ..Default::default()
        };
        let code = Totp::generate(SHA1_SECRET, Some(options));
        assert_eq!(code, "94287082");
    }

    #[test]
    fn test_rfc6238_sha256_time_59() {
        let options = TotpOptions {
            digits: 8,
            algorithm: Algorithm::Sha256,
            timestamp: Some(59),
            ..Default::default()
        };
        let code = Totp::generate(SHA256_SECRET, Some(options));
        assert_eq!(code, "46119246");
    }

    #[test]
    fn test_rfc6238_sha512_time_59() {
        let options = TotpOptions {
            digits: 8,
            algorithm: Algorithm::Sha512,
            timestamp: Some(59),
            ..Default::default()
        };
        let code = Totp::generate(SHA512_SECRET, Some(options));
        assert_eq!(code, "90693936");
    }

    #[test]
    fn test_rfc6238_sha1_time_1111111109() {
        let options = TotpOptions {
            digits: 8,
            algorithm: Algorithm::Sha1,
            timestamp: Some(1111111109),
            ..Default::default()
        };
        let code = Totp::generate(SHA1_SECRET, Some(options));
        assert_eq!(code, "07081804");
    }

    #[test]
    fn test_rfc6238_sha256_time_1111111109() {
        let options = TotpOptions {
            digits: 8,
            algorithm: Algorithm::Sha256,
            timestamp: Some(1111111109),
            ..Default::default()
        };
        let code = Totp::generate(SHA256_SECRET, Some(options));
        assert_eq!(code, "68084774");
    }

    #[test]
    fn test_rfc6238_sha512_time_1111111109() {
        let options = TotpOptions {
            digits: 8,
            algorithm: Algorithm::Sha512,
            timestamp: Some(1111111109),
            ..Default::default()
        };
        let code = Totp::generate(SHA512_SECRET, Some(options));
        assert_eq!(code, "25091201");
    }

    #[test]
    fn test_rfc6238_sha1_time_1111111111() {
        let options = TotpOptions {
            digits: 8,
            algorithm: Algorithm::Sha1,
            timestamp: Some(1111111111),
            ..Default::default()
        };
        let code = Totp::generate(SHA1_SECRET, Some(options));
        assert_eq!(code, "14050471");
    }

    #[test]
    fn test_rfc6238_sha256_time_1111111111() {
        let options = TotpOptions {
            digits: 8,
            algorithm: Algorithm::Sha256,
            timestamp: Some(1111111111),
            ..Default::default()
        };
        let code = Totp::generate(SHA256_SECRET, Some(options));
        assert_eq!(code, "67062674");
    }

    #[test]
    fn test_rfc6238_sha512_time_1111111111() {
        let options = TotpOptions {
            digits: 8,
            algorithm: Algorithm::Sha512,
            timestamp: Some(1111111111),
            ..Default::default()
        };
        let code = Totp::generate(SHA512_SECRET, Some(options));
        assert_eq!(code, "99943326");
    }

    #[test]
    fn test_rfc6238_sha1_time_1234567890() {
        let options = TotpOptions {
            digits: 8,
            algorithm: Algorithm::Sha1,
            timestamp: Some(1234567890),
            ..Default::default()
        };
        let code = Totp::generate(SHA1_SECRET, Some(options));
        assert_eq!(code, "89005924");
    }

    #[test]
    fn test_rfc6238_sha256_time_1234567890() {
        let options = TotpOptions {
            digits: 8,
            algorithm: Algorithm::Sha256,
            timestamp: Some(1234567890),
            ..Default::default()
        };
        let code = Totp::generate(SHA256_SECRET, Some(options));
        assert_eq!(code, "91819424");
    }

    #[test]
    fn test_rfc6238_sha512_time_1234567890() {
        let options = TotpOptions {
            digits: 8,
            algorithm: Algorithm::Sha512,
            timestamp: Some(1234567890),
            ..Default::default()
        };
        let code = Totp::generate(SHA512_SECRET, Some(options));
        assert_eq!(code, "93441116");
    }

    #[test]
    fn test_rfc6238_sha1_time_2000000000() {
        let options = TotpOptions {
            digits: 8,
            algorithm: Algorithm::Sha1,
            timestamp: Some(2000000000),
            ..Default::default()
        };
        let code = Totp::generate(SHA1_SECRET, Some(options));
        assert_eq!(code, "69279037");
    }

    #[test]
    fn test_rfc6238_sha256_time_2000000000() {
        let options = TotpOptions {
            digits: 8,
            algorithm: Algorithm::Sha256,
            timestamp: Some(2000000000),
            ..Default::default()
        };
        let code = Totp::generate(SHA256_SECRET, Some(options));
        assert_eq!(code, "90698825");
    }

    #[test]
    fn test_rfc6238_sha512_time_2000000000() {
        let options = TotpOptions {
            digits: 8,
            algorithm: Algorithm::Sha512,
            timestamp: Some(2000000000),
            ..Default::default()
        };
        let code = Totp::generate(SHA512_SECRET, Some(options));
        assert_eq!(code, "38618901");
    }

    #[test]
    fn test_rfc6238_sha1_time_20000000000() {
        let options = TotpOptions {
            digits: 8,
            algorithm: Algorithm::Sha1,
            timestamp: Some(20000000000),
            ..Default::default()
        };
        let code = Totp::generate(SHA1_SECRET, Some(options));
        assert_eq!(code, "65353130");
    }

    #[test]
    fn test_rfc6238_sha256_time_20000000000() {
        let options = TotpOptions {
            digits: 8,
            algorithm: Algorithm::Sha256,
            timestamp: Some(20000000000),
            ..Default::default()
        };
        let code = Totp::generate(SHA256_SECRET, Some(options));
        assert_eq!(code, "77737706");
    }

    #[test]
    fn test_rfc6238_sha512_time_20000000000() {
        let options = TotpOptions {
            digits: 8,
            algorithm: Algorithm::Sha512,
            timestamp: Some(20000000000),
            ..Default::default()
        };
        let code = Totp::generate(SHA512_SECRET, Some(options));
        assert_eq!(code, "47863826");
    }

    // 6-digit tests (common use case)
    #[test]
    fn test_6_digit_sha1_time_59() {
        let options = TotpOptions {
            digits: 6,
            algorithm: Algorithm::Sha1,
            timestamp: Some(59),
            ..Default::default()
        };
        let code = Totp::generate(SHA1_SECRET, Some(options));
        // Last 6 digits of 94287082
        assert_eq!(code, "287082");
    }

    #[test]
    fn test_6_digit_sha256_time_59() {
        let options = TotpOptions {
            digits: 6,
            algorithm: Algorithm::Sha256,
            timestamp: Some(59),
            ..Default::default()
        };
        let code = Totp::generate(SHA256_SECRET, Some(options));
        // Last 6 digits of 46119246
        assert_eq!(code, "119246");
    }

    #[test]
    fn test_6_digit_sha512_time_59() {
        let options = TotpOptions {
            digits: 6,
            algorithm: Algorithm::Sha512,
            timestamp: Some(59),
            ..Default::default()
        };
        let code = Totp::generate(SHA512_SECRET, Some(options));
        // Last 6 digits of 90693936
        assert_eq!(code, "693936");
    }

    // Validation tests
    #[test]
    fn test_validate_current_code() {
        let options = TotpOptions {
            digits: 6,
            timestamp: Some(59),
            ..Default::default()
        };
        let code = Totp::generate(SHA1_SECRET, Some(options.clone()));

        let validate_options = TotpValidateOptions { options, skew: 1 };
        assert!(Totp::validate(SHA1_SECRET, &code, Some(validate_options)));
    }

    #[test]
    fn test_validate_rejects_invalid_code() {
        let options = TotpOptions {
            digits: 6,
            timestamp: Some(59),
            ..Default::default()
        };
        let validate_options = TotpValidateOptions { options, skew: 1 };
        assert!(!Totp::validate(
            SHA1_SECRET,
            "000000",
            Some(validate_options)
        ));
    }

    #[test]
    fn test_validate_with_skew_previous_period() {
        // Generate code for time 59 (counter 1)
        let gen_options = TotpOptions {
            digits: 6,
            timestamp: Some(59),
            ..Default::default()
        };
        let code = Totp::generate(SHA1_SECRET, Some(gen_options));

        // Validate at time 89 (counter 2, but skew=1 should accept counter 1)
        let validate_options = TotpValidateOptions {
            options: TotpOptions {
                digits: 6,
                timestamp: Some(89),
                ..Default::default()
            },
            skew: 1,
        };
        assert!(Totp::validate(SHA1_SECRET, &code, Some(validate_options)));
    }

    #[test]
    fn test_validate_with_skew_next_period() {
        // Generate code for time 59 (counter 1)
        let gen_options = TotpOptions {
            digits: 6,
            timestamp: Some(59),
            ..Default::default()
        };
        let code = Totp::generate(SHA1_SECRET, Some(gen_options));

        // Validate at time 29 (counter 0, but skew=1 should accept counter 1)
        let validate_options = TotpValidateOptions {
            options: TotpOptions {
                digits: 6,
                timestamp: Some(29),
                ..Default::default()
            },
            skew: 1,
        };
        assert!(Totp::validate(SHA1_SECRET, &code, Some(validate_options)));
    }

    #[test]
    fn test_validate_rejects_outside_skew() {
        // Generate code for time 59 (counter 1)
        let gen_options = TotpOptions {
            digits: 6,
            timestamp: Some(59),
            ..Default::default()
        };
        let code = Totp::generate(SHA1_SECRET, Some(gen_options));

        // Validate at time 119 (counter 3, skew=1 only accepts counters 2,3,4)
        let validate_options = TotpValidateOptions {
            options: TotpOptions {
                digits: 6,
                timestamp: Some(119),
                ..Default::default()
            },
            skew: 1,
        };
        assert!(!Totp::validate(SHA1_SECRET, &code, Some(validate_options)));
    }

    #[test]
    fn test_validate_rejects_wrong_length() {
        let validate_options = TotpValidateOptions {
            options: TotpOptions {
                digits: 6,
                timestamp: Some(59),
                ..Default::default()
            },
            skew: 1,
        };

        // Too short
        assert!(!Totp::validate(
            SHA1_SECRET,
            "12345",
            Some(validate_options.clone())
        ));

        // Too long
        assert!(!Totp::validate(
            SHA1_SECRET,
            "1234567",
            Some(validate_options)
        ));
    }

    #[test]
    fn test_validate_trims_whitespace() {
        let options = TotpOptions {
            digits: 6,
            timestamp: Some(59),
            ..Default::default()
        };
        let code = Totp::generate(SHA1_SECRET, Some(options.clone()));

        let validate_options = TotpValidateOptions { options, skew: 1 };

        // Should accept code with leading/trailing whitespace
        let padded_code = format!("  {}  ", code);
        assert!(Totp::validate(
            SHA1_SECRET,
            &padded_code,
            Some(validate_options)
        ));
    }

    #[test]
    fn test_60_second_period() {
        let options_30 = TotpOptions {
            digits: 6,
            timestamp: Some(59),
            period: 30,
            ..Default::default()
        };
        let options_60 = TotpOptions {
            digits: 6,
            timestamp: Some(59),
            period: 60,
            ..Default::default()
        };

        let code_30 = Totp::generate(SHA1_SECRET, Some(options_30));
        let code_60 = Totp::generate(SHA1_SECRET, Some(options_60));

        // Different periods should produce different codes (same counter value)
        // At time 59: 30-second period has counter 1, 60-second period has counter 0
        assert_ne!(code_30, code_60);
    }

    // Cross-SDK compatibility tests (TypeScript SDK vectors)
    #[test]
    fn test_ts_sdk_compat_unix_epoch() {
        // TypeScript SDK test vector: time=0, secret=0x48656c6c6f21deadbeef
        let secret = hex::decode("48656c6c6f21deadbeef").unwrap();
        let options = TotpOptions {
            digits: 6,
            algorithm: Algorithm::Sha1,
            period: 30,
            timestamp: Some(0),
        };
        let code = Totp::generate(&secret, Some(options));
        assert_eq!(code, "282760");
    }

    #[test]
    fn test_ts_sdk_compat_2016_timestamp() {
        // TypeScript SDK test vector: time=1465324707000ms = 1465324707s
        let secret = hex::decode("48656c6c6f21deadbeef").unwrap();
        let options = TotpOptions {
            digits: 6,
            algorithm: Algorithm::Sha1,
            period: 30,
            timestamp: Some(1465324707),
        };
        let code = Totp::generate(&secret, Some(options));
        assert_eq!(code, "341128");
    }

    #[test]
    fn test_ts_sdk_compat_leading_zero() {
        // TypeScript SDK test vector with leading zero: time=1365324707000ms = 1365324707s
        let secret = hex::decode("48656c6c6f21deadbeef").unwrap();
        let options = TotpOptions {
            digits: 6,
            algorithm: Algorithm::Sha1,
            period: 30,
            timestamp: Some(1365324707),
        };
        let code = Totp::generate(&secret, Some(options));
        assert_eq!(code, "089029");
    }

    #[test]
    fn test_ts_sdk_compat_cycle_boundary_start() {
        // TypeScript SDK: time=(1665644340000 + 1)ms = 1665644340s (counter 55521478)
        let secret = hex::decode("48656c6c6f21deadbeef").unwrap();
        let options = TotpOptions {
            digits: 6,
            algorithm: Algorithm::Sha1,
            period: 30,
            timestamp: Some(1665644340),
        };
        let code = Totp::generate(&secret, Some(options));
        assert_eq!(code, "886842");
    }

    #[test]
    fn test_ts_sdk_compat_cycle_boundary_end() {
        // TypeScript SDK: time=(1665644340000 - 1)ms = 1665644339s (counter 55521477)
        let secret = hex::decode("48656c6c6f21deadbeef").unwrap();
        let options = TotpOptions {
            digits: 6,
            algorithm: Algorithm::Sha1,
            period: 30,
            timestamp: Some(1665644339),
        };
        let code = Totp::generate(&secret, Some(options));
        assert_eq!(code, "134996");
    }

    // Edge cases
    #[test]
    fn test_default_options() {
        // Ensure defaults work without panicking
        let code = Totp::generate(SHA1_SECRET, None);
        assert_eq!(code.len(), 6);
    }

    #[test]
    fn test_validate_with_none_options() {
        let code = Totp::generate(SHA1_SECRET, None);
        assert!(Totp::validate(SHA1_SECRET, &code, None));
    }

    #[test]
    fn test_constant_time_eq() {
        assert!(constant_time_eq("123456", "123456"));
        assert!(!constant_time_eq("123456", "654321"));
        assert!(!constant_time_eq("123", "123456"));
        assert!(!constant_time_eq("123456", "123"));
    }

    #[test]
    fn test_constant_time_eq_empty() {
        // Both empty - they are equal
        assert!(constant_time_eq("", ""));
    }

    #[test]
    fn test_counter_near_zero() {
        // Test validation when counter is 0 (edge case for skew subtraction)
        let options = TotpOptions {
            digits: 6,
            timestamp: Some(0), // counter = 0
            ..Default::default()
        };
        let code = Totp::generate(SHA1_SECRET, Some(options.clone()));

        let validate_options = TotpValidateOptions { options, skew: 1 };
        assert!(Totp::validate(SHA1_SECRET, &code, Some(validate_options)));
    }

    #[test]
    fn test_algorithm_enum_default() {
        let algo: Algorithm = Default::default();
        assert_eq!(algo, Algorithm::Sha1);
    }

    #[test]
    fn test_algorithm_enum_clone_eq() {
        let algo1 = Algorithm::Sha256;
        let algo2 = algo1;
        assert_eq!(algo1, algo2);
    }

    #[test]
    fn test_totp_options_clone() {
        let options = TotpOptions {
            digits: 8,
            algorithm: Algorithm::Sha512,
            period: 60,
            timestamp: Some(12345),
        };
        let cloned = options.clone();
        assert_eq!(cloned.digits, 8);
        assert_eq!(cloned.algorithm, Algorithm::Sha512);
        assert_eq!(cloned.period, 60);
        assert_eq!(cloned.timestamp, Some(12345));
    }

    // Unusual digit count tests
    #[test]
    fn test_digits_1() {
        let options = TotpOptions {
            digits: 1,
            timestamp: Some(59),
            ..Default::default()
        };
        let code = Totp::generate(SHA1_SECRET, Some(options.clone()));
        assert_eq!(code.len(), 1);

        // Should still validate
        let validate_options = TotpValidateOptions { options, skew: 0 };
        assert!(Totp::validate(SHA1_SECRET, &code, Some(validate_options)));
    }

    #[test]
    fn test_digits_9() {
        // 9 digits is the max that fits in u32 (10^9 = 1_000_000_000 < u32::MAX)
        let options = TotpOptions {
            digits: 9,
            timestamp: Some(59),
            ..Default::default()
        };
        let code = Totp::generate(SHA1_SECRET, Some(options.clone()));
        assert_eq!(code.len(), 9);

        // Should still validate
        let validate_options = TotpValidateOptions { options, skew: 0 };
        assert!(Totp::validate(SHA1_SECRET, &code, Some(validate_options)));
    }

    // RFC 4226 Appendix D HOTP test vectors
    // Secret: "12345678901234567890" (ASCII), 6-digit codes
    // These verify the underlying HOTP algorithm by using period=1 and timestamp=counter
    #[test]
    fn test_rfc4226_hotp_vectors() {
        let expected = [
            "755224", // counter 0
            "287082", // counter 1
            "359152", // counter 2
            "969429", // counter 3
            "338314", // counter 4
            "254676", // counter 5
            "287922", // counter 6
            "162583", // counter 7
            "399871", // counter 8
            "520489", // counter 9
        ];

        for (counter, expected_code) in expected.iter().enumerate() {
            let options = TotpOptions {
                digits: 6,
                algorithm: Algorithm::Sha1,
                period: 1,                       // 1-second period so timestamp == counter
                timestamp: Some(counter as u64), // counter value
            };
            let code = Totp::generate(SHA1_SECRET, Some(options));
            assert_eq!(
                &code, expected_code,
                "RFC 4226 HOTP vector failed for counter {}",
                counter
            );
        }
    }
}
