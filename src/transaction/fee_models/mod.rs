//! Fee model implementations.
//!
//! This module provides various fee model implementations for computing
//! transaction fees.
//!
//! # Available Fee Models
//!
//! - [`SatoshisPerKilobyte`] - Computes fees based on transaction size

mod sats_per_kb;

pub use sats_per_kb::SatoshisPerKilobyte;
