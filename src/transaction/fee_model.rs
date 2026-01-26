//! Fee model trait for transaction fee computation.
//!
//! This module provides the [`FeeModel`] trait that defines how transaction
//! fees are computed. Different fee models can be implemented for various
//! fee calculation strategies.
//!
//! # Example
//!
//! ```rust,ignore
//! use bsv_sdk::transaction::{FeeModel, SatoshisPerKilobyte, Transaction};
//!
//! let fee_model = SatoshisPerKilobyte::new(100); // 100 sat/KB
//! let tx = Transaction::new();
//! let fee = fee_model.compute_fee(&tx)?;
//! ```

use super::transaction::Transaction;
use crate::Result;

/// Represents the interface for a transaction fee model.
///
/// This trait defines a standard method for computing a fee when given
/// a transaction. Implementations can use different strategies such as
/// fixed fees, satoshis per kilobyte, or dynamic fee calculation based
/// on network conditions.
///
/// # Example
///
/// ```rust,ignore
/// use bsv_sdk::transaction::{FeeModel, Transaction};
///
/// struct FixedFee(u64);
///
/// impl FeeModel for FixedFee {
///     fn compute_fee(&self, _tx: &Transaction) -> Result<u64> {
///         Ok(self.0)
///     }
/// }
/// ```
pub trait FeeModel: Send + Sync {
    /// Computes the fee for a given transaction.
    ///
    /// # Arguments
    ///
    /// * `tx` - The transaction for which a fee is to be computed
    ///
    /// # Returns
    ///
    /// The fee in satoshis for the transaction.
    fn compute_fee(&self, tx: &Transaction) -> Result<u64>;
}

/// A fixed fee model that always returns the same fee.
///
/// This is useful for testing or when a specific fee amount is required.
///
/// # Example
///
/// ```rust,ignore
/// use bsv_sdk::transaction::{FixedFee, FeeModel, Transaction};
///
/// let fee_model = FixedFee::new(500);
/// let tx = Transaction::new();
/// assert_eq!(fee_model.compute_fee(&tx)?, 500);
/// ```
#[derive(Debug, Clone, Copy)]
pub struct FixedFee(u64);

impl FixedFee {
    /// Creates a new fixed fee model.
    ///
    /// # Arguments
    ///
    /// * `satoshis` - The fixed fee in satoshis
    pub fn new(satoshis: u64) -> Self {
        Self(satoshis)
    }
}

impl FeeModel for FixedFee {
    fn compute_fee(&self, _tx: &Transaction) -> Result<u64> {
        Ok(self.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_fixed_fee() {
        let fee_model = FixedFee::new(500);
        let tx = Transaction::new();
        assert_eq!(fee_model.compute_fee(&tx).unwrap(), 500);
    }
}
