//! Transaction Input.
//!
//! Represents an input to a Bitcoin transaction, referencing a previous
//! transaction output (UTXO) that is being spent.

use crate::script::{LockingScript, ScriptTemplateUnlock, UnlockingScript};

/// Represents an unspent transaction output (UTXO).
///
/// A lightweight struct for referencing a specific output from a previous
/// transaction by its TXID, output index, satoshi value, and locking script.
/// Used with `Transaction::add_inputs_from_utxos` for convenient input creation.
///
/// # Example
///
/// ```rust,ignore
/// use bsv_rs::transaction::Utxo;
/// use bsv_rs::script::LockingScript;
///
/// let utxo = Utxo {
///     txid: "abc123...".to_string(),
///     vout: 0,
///     satoshis: 100_000,
///     locking_script: LockingScript::from_hex("76a914...88ac")?,
/// };
/// ```
#[derive(Debug, Clone)]
pub struct Utxo {
    /// The transaction ID (TXID) of the transaction containing this output.
    pub txid: String,

    /// The index of this output in the source transaction.
    pub vout: u32,

    /// The amount of satoshis in this output.
    pub satoshis: u64,

    /// The locking script (scriptPubKey) that defines spending conditions.
    pub locking_script: LockingScript,
}

/// Represents an input to a Bitcoin transaction.
///
/// Each input references a previous transaction output (UTXO) that is being spent.
/// The input provides either a reference to the source transaction itself or its TXID,
/// along with an unlocking script that satisfies the locking script conditions.
///
/// # Example
///
/// ```rust,ignore
/// use bsv_rs::transaction::TransactionInput;
///
/// // Create an input referencing a specific UTXO
/// let input = TransactionInput::new(
///     "abc123...".to_string(),
///     0,
/// );
/// ```
#[derive(Debug)]
pub struct TransactionInput {
    /// Optional reference to the full source transaction.
    ///
    /// When available, this provides direct access to the source transaction
    /// for obtaining satoshis and locking script without external lookups.
    pub source_transaction: Option<Box<super::Transaction>>,

    /// The transaction ID (TXID) of the source transaction.
    ///
    /// This is the hex string representation of the reversed hash.
    /// Either `source_txid` or `source_transaction` must be provided.
    pub source_txid: Option<String>,

    /// The index of the output being spent in the source transaction.
    pub source_output_index: u32,

    /// The unlocking script (scriptSig) that satisfies the locking conditions.
    ///
    /// This is `None` before signing and populated after signing.
    pub unlocking_script: Option<UnlockingScript>,

    /// Optional template for generating the unlocking script during signing.
    ///
    /// When present, the `sign()` method will use this template to generate
    /// the unlocking script.
    pub unlocking_script_template: Option<Box<ScriptTemplateUnlock>>,

    /// The sequence number for this input.
    ///
    /// Used for transaction replacement (BIP 125) and relative lock-time (BIP 68).
    /// Default value is 0xFFFFFFFF (final).
    pub sequence: u32,
}

impl TransactionInput {
    /// Creates a new transaction input from a TXID and output index.
    ///
    /// # Arguments
    ///
    /// * `source_txid` - The hex string TXID of the source transaction
    /// * `source_output_index` - The index of the output being spent
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// let input = TransactionInput::new(
    ///     "abc123def456...".to_string(),
    ///     0,
    /// );
    /// ```
    pub fn new(source_txid: String, source_output_index: u32) -> Self {
        Self {
            source_transaction: None,
            source_txid: Some(source_txid),
            source_output_index,
            unlocking_script: None,
            unlocking_script_template: None,
            sequence: 0xFFFFFFFF,
        }
    }

    /// Creates a new transaction input from a source transaction and output index.
    ///
    /// This is preferred when the full source transaction is available, as it
    /// provides access to the source satoshis and locking script.
    ///
    /// # Arguments
    ///
    /// * `tx` - The source transaction
    /// * `output_index` - The index of the output being spent
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// let source_tx = Transaction::from_hex("...")?;
    /// let input = TransactionInput::with_source_transaction(source_tx, 0);
    /// ```
    pub fn with_source_transaction(tx: super::Transaction, output_index: u32) -> Self {
        Self {
            source_transaction: Some(Box::new(tx)),
            source_txid: None,
            source_output_index: output_index,
            unlocking_script: None,
            unlocking_script_template: None,
            sequence: 0xFFFFFFFF,
        }
    }

    /// Gets the source transaction ID (TXID).
    ///
    /// Returns the TXID from either `source_txid` or by computing it from
    /// `source_transaction` if available.
    ///
    /// # Errors
    ///
    /// Returns an error if neither `source_txid` nor `source_transaction` is set.
    pub fn get_source_txid(&self) -> crate::Result<String> {
        if let Some(ref txid) = self.source_txid {
            return Ok(txid.clone());
        }

        if let Some(ref tx) = self.source_transaction {
            return Ok(tx.id());
        }

        Err(crate::Error::TransactionError(
            "Input has neither sourceTXID nor sourceTransaction".to_string(),
        ))
    }

    /// Returns the source TXID as internal byte order (not reversed).
    ///
    /// Used for transaction serialization where the TXID is stored in
    /// internal byte order (reversed from display order).
    pub fn get_source_txid_bytes(&self) -> crate::Result<[u8; 32]> {
        let txid = self.get_source_txid()?;
        let bytes = crate::primitives::from_hex(&txid)?;

        if bytes.len() != 32 {
            return Err(crate::Error::TransactionError(format!(
                "Invalid TXID length: expected 32, got {}",
                bytes.len()
            )));
        }

        let mut result = [0u8; 32];
        // Reverse to get internal byte order
        for (i, byte) in bytes.iter().enumerate() {
            result[31 - i] = *byte;
        }
        Ok(result)
    }

    /// Returns the satoshi value of the source output.
    ///
    /// Returns `None` if the source transaction is not available.
    pub fn source_satoshis(&self) -> Option<u64> {
        self.source_transaction
            .as_ref()
            .and_then(|tx| tx.outputs.get(self.source_output_index as usize))
            .and_then(|out| out.satoshis)
    }

    /// Returns a reference to the locking script of the source output.
    ///
    /// Returns `None` if the source transaction is not available.
    pub fn source_locking_script(&self) -> Option<&LockingScript> {
        self.source_transaction
            .as_ref()
            .and_then(|tx| tx.outputs.get(self.source_output_index as usize))
            .map(|out| &out.locking_script)
    }

    /// Sets the unlocking script template for this input.
    ///
    /// The template will be used during signing to generate the unlocking script.
    pub fn set_unlocking_script_template(&mut self, template: ScriptTemplateUnlock) {
        self.unlocking_script_template = Some(Box::new(template));
    }

    /// Sets the unlocking script directly.
    pub fn set_unlocking_script(&mut self, script: UnlockingScript) {
        self.unlocking_script = Some(script);
    }

    /// Returns whether this input has a source transaction available.
    pub fn has_source_transaction(&self) -> bool {
        self.source_transaction.is_some()
    }
}

impl Clone for TransactionInput {
    fn clone(&self) -> Self {
        Self {
            source_transaction: self.source_transaction.clone(),
            source_txid: self.source_txid.clone(),
            source_output_index: self.source_output_index,
            unlocking_script: self.unlocking_script.clone(),
            // Templates are not cloned - they contain closures
            unlocking_script_template: None,
            sequence: self.sequence,
        }
    }
}

impl Default for TransactionInput {
    fn default() -> Self {
        Self {
            source_transaction: None,
            source_txid: None,
            source_output_index: 0,
            unlocking_script: None,
            unlocking_script_template: None,
            sequence: 0xFFFFFFFF,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_new_input() {
        let txid = "abc123def456789012345678901234567890123456789012345678901234abcd".to_string();
        let input = TransactionInput::new(txid.clone(), 0);

        assert_eq!(input.source_txid, Some(txid));
        assert_eq!(input.source_output_index, 0);
        assert_eq!(input.sequence, 0xFFFFFFFF);
        assert!(input.unlocking_script.is_none());
    }

    #[test]
    fn test_get_source_txid() {
        let txid = "abc123def456789012345678901234567890123456789012345678901234abcd".to_string();
        let input = TransactionInput::new(txid.clone(), 0);

        assert_eq!(input.get_source_txid().unwrap(), txid);
    }

    #[test]
    fn test_get_source_txid_missing() {
        let input = TransactionInput::default();
        assert!(input.get_source_txid().is_err());
    }

    #[test]
    fn test_source_satoshis_none() {
        let input = TransactionInput::new("abc123".repeat(11), 0);
        assert!(input.source_satoshis().is_none());
    }
}
