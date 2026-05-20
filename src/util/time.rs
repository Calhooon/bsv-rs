//! Wasm32-safe wall-clock helpers.
//!
//! `std::time::SystemTime::now()` is not implemented on
//! `wasm32-unknown-unknown` — calling it panics at runtime (it traps with
//! `unreachable!()` from libstd before returning a `Result`, so callers
//! can't even `unwrap_or` their way out). That blocks any downstream that
//! drives BSV protocol code from inside a Cloudflare Worker or similar
//! `wasm32-unknown-unknown` host.
//!
//! These helpers cfg-gate the implementation:
//!
//! - Native (default): delegate to `std::time::SystemTime::now()` exactly
//!   as before. Native callers see zero behavioral change.
//! - `wasm32-unknown-unknown` with the `wasm` feature: use
//!   `js_sys::Date::now()`, which returns milliseconds since the Unix
//!   epoch as an `f64` and is available in every JS host (browsers,
//!   Node.js, Cloudflare Workers, Deno). Sub-millisecond precision is
//!   lost — `js_sys::Date::now()` is millisecond-quantized — but
//!   `SystemTime` is unreachable on this target so there is no
//!   higher-precision alternative without pulling in a JS-specific dep
//!   like `web-sys`'s `Performance` API.
//!
//! All helpers return monotonically-non-decreasing values relative to
//! the Unix epoch; callers that previously computed
//! `SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default()`
//! can be ported by calling [`duration_since_unix_epoch`] directly.

use std::time::Duration;

/// Returns the wall-clock duration since the Unix epoch (1970-01-01 UTC).
///
/// Returns `Duration::ZERO` if the system clock is set before the Unix
/// epoch (a near-impossible edge case on real deployments, but preserved
/// so call sites that previously used `unwrap_or_default()` keep the same
/// behavior).
#[allow(dead_code)] // Not used by every feature combination.
#[cfg(all(target_arch = "wasm32", feature = "wasm"))]
pub(crate) fn duration_since_unix_epoch() -> Duration {
    let ms = js_sys::Date::now();
    if !ms.is_finite() || ms < 0.0 {
        return Duration::ZERO;
    }
    // `Date::now()` is millisecond-quantized, so casting to u64 loses no
    // information for any plausible wall-clock value (u64 milliseconds
    // covers ~584 million years).
    Duration::from_millis(ms as u64)
}

/// Returns the wall-clock duration since the Unix epoch (1970-01-01 UTC).
#[allow(dead_code)] // Not used by every feature combination.
#[cfg(not(all(target_arch = "wasm32", feature = "wasm")))]
pub(crate) fn duration_since_unix_epoch() -> Duration {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or(Duration::ZERO)
}

/// Returns current wall-clock time in milliseconds since the Unix epoch.
///
/// Equivalent to `duration_since_unix_epoch().as_millis() as u64`.
#[allow(dead_code)] // Not used by every feature combination.
pub(crate) fn current_time_ms() -> u64 {
    duration_since_unix_epoch().as_millis() as u64
}

/// Returns current wall-clock time in seconds since the Unix epoch.
///
/// Equivalent to `duration_since_unix_epoch().as_secs()`.
#[allow(dead_code)] // Not used by every feature combination.
pub(crate) fn current_time_secs() -> u64 {
    duration_since_unix_epoch().as_secs()
}
