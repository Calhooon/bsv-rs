//! Transaction Output.
//!
//! Represents an output in a Bitcoin transaction, specifying the amount
//! of satoshis and the conditions under which they can be spent.

use crate::script::LockingScript;

/// Represents an output in a Bitcoin transaction.
///
/// Each output specifies an amount of satoshis and a locking script that
/// defines the conditions under which those satoshis can be spent.
///
/// # Example
///
/// ```rust,ignore
/// use bsv_rs::transaction::TransactionOutput;
/// use bsv_rs::script::LockingScript;
///
/// // Create a regular output
/// let output = TransactionOutput::new(
///     100_000,
///     LockingScript::from_hex("76a914...88ac")?,
/// );
///
/// // Create a change output (amount computed during fee calculation)
/// let change = TransactionOutput::new_change(
///     LockingScript::from_hex("76a914...88ac")?,
/// );
/// ```
#[derive(Debug, Clone, Default)]
pub struct TransactionOutput {
    /// The amount of satoshis in this output.
    ///
    /// This is `None` for change outputs before fee computation.
    pub satoshis: Option<u64>,

    /// The locking script (scriptPubKey) that specifies spending conditions.
    pub locking_script: LockingScript,

    /// Whether this is a change output.
    ///
    /// Change outputs have their satoshi amounts computed during fee calculation.
    pub change: bool,
}

impl TransactionOutput {
    /// Creates a new transaction output with a specified amount.
    ///
    /// # Arguments
    ///
    /// * `satoshis` - The amount of satoshis
    /// * `locking_script` - The locking script defining spending conditions
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// let output = TransactionOutput::new(
    ///     100_000,
    ///     LockingScript::from_hex("76a914...88ac")?,
    /// );
    /// ```
    pub fn new(satoshis: u64, locking_script: LockingScript) -> Self {
        Self {
            satoshis: Some(satoshis),
            locking_script,
            change: false,
        }
    }

    /// Creates a new change output.
    ///
    /// The satoshi amount will be computed during fee calculation.
    ///
    /// # Arguments
    ///
    /// * `locking_script` - The locking script for the change output
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// let change = TransactionOutput::new_change(
    ///     LockingScript::from_hex("76a914...88ac")?,
    /// );
    /// ```
    pub fn new_change(locking_script: LockingScript) -> Self {
        Self {
            satoshis: None,
            locking_script,
            change: true,
        }
    }

    /// Returns the satoshi amount of this output.
    ///
    /// Returns 0 if the amount is not set (e.g., for uncomputed change outputs).
    pub fn get_satoshis(&self) -> u64 {
        self.satoshis.unwrap_or(0)
    }

    /// Returns whether this output has a defined satoshi amount.
    pub fn has_satoshis(&self) -> bool {
        self.satoshis.is_some()
    }

    /// Returns the size of this output when serialized.
    ///
    /// Output format: 8 bytes (satoshis) + varint (script length) + script
    pub fn serialized_size(&self) -> usize {
        let script_bytes = self.locking_script.to_binary();
        let script_len = script_bytes.len();

        // 8 bytes for satoshis + varint length + script
        let varint_size = if script_len < 0xFD {
            1
        } else if script_len <= 0xFFFF {
            3
        } else if script_len <= 0xFFFFFFFF {
            5
        } else {
            9
        };

        8 + varint_size + script_len
    }
}

impl PartialEq for TransactionOutput {
    fn eq(&self, other: &Self) -> bool {
        self.satoshis == other.satoshis
            && self.locking_script.to_binary() == other.locking_script.to_binary()
            && self.change == other.change
    }
}

impl Eq for TransactionOutput {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_new_output() {
        let locking = LockingScript::new();
        let output = TransactionOutput::new(100_000, locking);

        assert_eq!(output.satoshis, Some(100_000));
        assert!(!output.change);
    }

    #[test]
    fn test_new_change_output() {
        let locking = LockingScript::new();
        let output = TransactionOutput::new_change(locking);

        assert!(output.satoshis.is_none());
        assert!(output.change);
    }

    #[test]
    fn test_get_satoshis() {
        let locking = LockingScript::new();
        let output = TransactionOutput::new(50_000, locking.clone());
        assert_eq!(output.get_satoshis(), 50_000);

        let change = TransactionOutput::new_change(locking);
        assert_eq!(change.get_satoshis(), 0);
    }

    #[test]
    fn test_serialized_size() {
        let locking = LockingScript::new();
        let output = TransactionOutput::new(100_000, locking);

        // Empty script: 8 bytes + 1 byte varint + 0 bytes script = 9
        assert_eq!(output.serialized_size(), 9);
    }

    #[test]
    fn test_serialized_size_with_script() {
        // P2PKH script: 25 bytes
        let locking =
            LockingScript::from_hex("76a914000000000000000000000000000000000000000088ac").unwrap();
        let output = TransactionOutput::new(100_000, locking);

        // 8 bytes + 1 byte varint + 25 bytes script = 34
        assert_eq!(output.serialized_size(), 34);
    }
}
