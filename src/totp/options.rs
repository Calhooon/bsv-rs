//! `TotpOptions` and `TotpValidateOptions` (moved from `core.rs` by #843d8c
//! for that file's line ceiling; `bsv_rs::totp` re-exports both as before).

use super::core::Algorithm;

/// Options for TOTP generation.
///
/// All fields have sensible defaults following RFC 6238 recommendations.
///
/// `#[non_exhaustive]` (#843d8c): no struct expression builds one outside the
/// crate, a functional update that names no field included:
///
/// ```compile_fail,E0639
/// fn rebuilt(value: bsv_rs::totp::TotpOptions) -> bsv_rs::totp::TotpOptions {
///     bsv_rs::totp::TotpOptions { ..value }
/// }
/// ```
///
/// ```
/// fn kept(value: bsv_rs::totp::TotpOptions) -> bsv_rs::totp::TotpOptions {
///     value
/// }
/// ```
#[derive(Debug, Clone)]
#[non_exhaustive]
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

crate::util::non_exhaustive::assert_no_drop!(TotpOptions, bsv_rs::totp::TotpOptions);

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

impl TotpOptions {
    /// Sets `digits`.
    #[must_use]
    pub fn with_digits(mut self, digits: u32) -> Self {
        self.digits = digits;
        self
    }

    /// Sets `algorithm`.
    #[must_use]
    pub fn with_algorithm(mut self, algorithm: Algorithm) -> Self {
        self.algorithm = algorithm;
        self
    }

    /// Sets `period`.
    #[must_use]
    pub fn with_period(mut self, period: u64) -> Self {
        self.period = period;
        self
    }

    /// Sets `timestamp`.
    #[must_use]
    pub fn with_timestamp(mut self, timestamp: Option<u64>) -> Self {
        self.timestamp = timestamp;
        self
    }
}

/// Options for TOTP validation.
///
/// Extends `TotpOptions` with a skew parameter to handle clock drift.
///
/// `#[non_exhaustive]` (#843d8c): no struct expression builds one outside the
/// crate, a functional update that names no field included:
///
/// ```compile_fail,E0639
/// fn rebuilt(value: bsv_rs::totp::TotpValidateOptions) -> bsv_rs::totp::TotpValidateOptions {
///     bsv_rs::totp::TotpValidateOptions { ..value }
/// }
/// ```
///
/// ```
/// fn kept(value: bsv_rs::totp::TotpValidateOptions) -> bsv_rs::totp::TotpValidateOptions {
///     value
/// }
/// ```
#[derive(Debug, Clone)]
#[non_exhaustive]
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

crate::util::non_exhaustive::assert_no_drop!(
    TotpValidateOptions,
    bsv_rs::totp::TotpValidateOptions
);

impl Default for TotpValidateOptions {
    fn default() -> Self {
        Self {
            options: TotpOptions::default(),
            skew: 1,
        }
    }
}

impl TotpValidateOptions {
    /// Sets `options`.
    #[must_use]
    pub fn with_options(mut self, options: TotpOptions) -> Self {
        self.options = options;
        self
    }

    /// Sets `skew`.
    #[must_use]
    pub fn with_skew(mut self, skew: u32) -> Self {
        self.skew = skew;
        self
    }
}
