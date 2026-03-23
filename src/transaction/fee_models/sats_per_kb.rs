//! Satoshis per kilobyte fee model.
//!
//! This module provides the [`SatoshisPerKilobyte`] fee model that computes
//! transaction fees based on the estimated transaction size.

use crate::transaction::fee_model::FeeModel;
use crate::transaction::transaction::Transaction;
use crate::Result;

/// Calculates the size of a Bitcoin varint.
fn varint_size(val: usize) -> usize {
    if val < 0xFD {
        1
    } else if val <= 0xFFFF {
        3
    } else if val <= 0xFFFFFFFF {
        5
    } else {
        9
    }
}

/// Represents the "satoshis per kilobyte" transaction fee model.
///
/// This fee model computes fees based on the transaction size in bytes,
/// charging a specified number of satoshis per kilobyte of transaction data.
///
/// # Example
///
/// ```rust,ignore
/// use bsv_rs::transaction::{SatoshisPerKilobyte, FeeModel, Transaction};
///
/// // 100 satoshis per kilobyte (standard BSV fee rate)
/// let fee_model = SatoshisPerKilobyte::new(100);
/// let tx = Transaction::new();
/// let fee = fee_model.compute_fee(&tx)?;
/// ```
#[derive(Debug, Clone, Copy)]
pub struct SatoshisPerKilobyte {
    /// The number of satoshis paid per kilobyte of transaction size.
    pub value: u64,
}

impl SatoshisPerKilobyte {
    /// Constructs an instance of the sat/kb fee model.
    ///
    /// # Arguments
    ///
    /// * `value` - The number of satoshis per kilobyte to charge as a fee
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// use bsv_rs::transaction::SatoshisPerKilobyte;
    ///
    /// let fee_model = SatoshisPerKilobyte::new(100); // 100 sat/KB
    /// ```
    pub fn new(value: u64) -> Self {
        Self { value }
    }

    /// Estimates the transaction size in bytes.
    ///
    /// This method computes the (potentially estimated) size of the transaction
    /// by calculating the size of all inputs and outputs, including varint
    /// lengths.
    ///
    /// # Arguments
    ///
    /// * `tx` - The transaction to estimate the size of
    ///
    /// # Returns
    ///
    /// The estimated size in bytes.
    fn estimate_size(&self, tx: &Transaction) -> Result<usize> {
        let mut size = 4; // version

        // Input count varint
        size += varint_size(tx.inputs.len());

        // Process inputs
        for (i, input) in tx.inputs.iter().enumerate() {
            size += 40; // txid (32) + output index (4) + sequence number (4)

            let script_len = match (&input.unlocking_script, &input.unlocking_script_template) {
                (Some(s), _) => s.to_binary().len(),
                (_, Some(t)) => t.estimate_length(),
                (None, None) => {
                    return Err(crate::Error::FeeModelError(format!(
                        "Input {} must have an unlocking script or template for fee computation",
                        i
                    )));
                }
            };

            size += varint_size(script_len); // unlocking script length
            size += script_len; // unlocking script
        }

        // Output count varint
        size += varint_size(tx.outputs.len());

        // Process outputs
        for output in &tx.outputs {
            size += 8; // satoshis
            let script_len = output.locking_script.to_binary().len();
            size += varint_size(script_len); // script length
            size += script_len; // script
        }

        size += 4; // lock time

        Ok(size)
    }
}

impl FeeModel for SatoshisPerKilobyte {
    /// Computes the fee for a given transaction.
    ///
    /// The fee is calculated by estimating the transaction size and multiplying
    /// by the satoshis per kilobyte rate. The result is rounded up using
    /// ceiling division to ensure miners receive at least the minimum fee.
    ///
    /// # Arguments
    ///
    /// * `tx` - The transaction for which a fee is to be computed
    ///
    /// # Returns
    ///
    /// The fee in satoshis for the transaction.
    fn compute_fee(&self, tx: &Transaction) -> Result<u64> {
        let size = self.estimate_size(tx)?;

        // Calculate fee with ceiling division
        // This ensures miners get the extra satoshi for any fractional KB
        let fee = (size as u64 * self.value).div_ceil(1000);

        Ok(fee)
    }
}

impl Default for SatoshisPerKilobyte {
    /// Creates a default fee model with 100 sat/KB (standard BSV fee rate).
    fn default() -> Self {
        Self::new(100)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_new() {
        let fee_model = SatoshisPerKilobyte::new(100);
        assert_eq!(fee_model.value, 100);
    }

    #[test]
    fn test_default() {
        let fee_model = SatoshisPerKilobyte::default();
        assert_eq!(fee_model.value, 100);
    }

    #[test]
    fn test_varint_size() {
        assert_eq!(varint_size(0), 1);
        assert_eq!(varint_size(0xFC), 1);
        assert_eq!(varint_size(0xFD), 3);
        assert_eq!(varint_size(0xFFFF), 3);
        assert_eq!(varint_size(0x10000), 5);
    }

    #[test]
    fn test_empty_transaction_fee() {
        let fee_model = SatoshisPerKilobyte::new(1000); // 1 sat/byte
        let tx = Transaction::new();
        // Empty transaction: 4 (version) + 1 (input count) + 1 (output count) + 4 (locktime) = 10 bytes
        // 10 bytes * 1000 sat/KB / 1000 = 10 sats, rounded up
        let fee = fee_model.compute_fee(&tx).unwrap();
        assert_eq!(fee, 10);
    }
}
