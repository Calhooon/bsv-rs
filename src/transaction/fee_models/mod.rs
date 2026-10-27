//! Fee model implementations.
//!
//! This module provides various fee model implementations for computing
//! transaction fees.
//!
//! # Available Fee Models
//!
//! - [`SatoshisPerKilobyte`] - Computes fees based on transaction size
//! - [`LivePolicy`] - Fetches the live fee rate from a policy endpoint of the
//!   caller's, in ARC's schema (ARCade serves it); no default endpoint since 0.9.0

mod live_policy;
mod sats_per_kb;

#[allow(deprecated)] // `DEFAULT_POLICY_URL` re-exported for the callers who name it
pub use live_policy::{
    LivePolicy, LivePolicyConfig, DEFAULT_CACHE_TTL_SECS, DEFAULT_FALLBACK_RATE, DEFAULT_POLICY_URL,
};
pub use sats_per_kb::SatoshisPerKilobyte;
