//! Fee model implementations.
//!
//! This module provides various fee model implementations for computing
//! transaction fees.
//!
//! # Available Fee Models
//!
//! - [`SatoshisPerKilobyte`] - Computes fees based on transaction size
//! - [`LivePolicy`] - Fetches live fee rate from ARC policy endpoint

mod live_policy;
mod sats_per_kb;

pub use live_policy::{
    LivePolicy, LivePolicyConfig, DEFAULT_CACHE_TTL_SECS, DEFAULT_FALLBACK_RATE, DEFAULT_POLICY_URL,
};
pub use sats_per_kb::SatoshisPerKilobyte;
