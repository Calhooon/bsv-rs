//! Locking Script (scriptPubKey).
//!
//! The LockingScript class represents a locking script in a Bitcoin SV transaction.
//! It extends the Script class and is used specifically for output scripts that lock funds.

use super::chunk::ScriptChunk;
use super::script::Script;
use crate::Result;

/// Represents a locking script (output script / scriptPubKey).
///
/// A locking script defines the conditions that must be satisfied to spend
/// the output it locks.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LockingScript(Script);

impl LockingScript {
    /// Creates a new empty locking script.
    pub fn new() -> Self {
        Self(Script::new())
    }

    /// Creates a locking script from a vector of chunks.
    pub fn from_chunks(chunks: Vec<ScriptChunk>) -> Self {
        Self(Script::from_chunks(chunks))
    }

    /// Constructs a LockingScript from an ASM formatted string.
    pub fn from_asm(asm: &str) -> Result<Self> {
        Ok(Self(Script::from_asm(asm)?))
    }

    /// Constructs a LockingScript from a hexadecimal string.
    pub fn from_hex(hex: &str) -> Result<Self> {
        Ok(Self(Script::from_hex(hex)?))
    }

    /// Constructs a LockingScript from binary data.
    pub fn from_binary(bin: &[u8]) -> Result<Self> {
        Ok(Self(Script::from_binary(bin)?))
    }

    /// Constructs a LockingScript from a Script.
    pub fn from_script(script: Script) -> Self {
        Self(script)
    }

    /// Returns a reference to the underlying Script.
    pub fn as_script(&self) -> &Script {
        &self.0
    }

    /// Converts this LockingScript into its underlying Script.
    pub fn into_script(self) -> Script {
        self.0
    }

    /// Serializes to ASM string.
    pub fn to_asm(&self) -> String {
        self.0.to_asm()
    }

    /// Serializes to hex string.
    pub fn to_hex(&self) -> String {
        self.0.to_hex()
    }

    /// Serializes to binary.
    pub fn to_binary(&self) -> Vec<u8> {
        self.0.to_binary()
    }

    /// Returns the chunks.
    pub fn chunks(&self) -> Vec<ScriptChunk> {
        self.0.chunks()
    }

    /// Returns the number of chunks.
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Returns true if empty.
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Checks if push-only.
    pub fn is_push_only(&self) -> bool {
        self.0.is_push_only()
    }

    /// Returns true (this is a locking script).
    pub fn is_locking_script(&self) -> bool {
        true
    }

    /// Returns false (this is not an unlocking script).
    pub fn is_unlocking_script(&self) -> bool {
        false
    }
}

impl Default for LockingScript {
    fn default() -> Self {
        Self::new()
    }
}

impl From<Script> for LockingScript {
    fn from(script: Script) -> Self {
        Self(script)
    }
}

impl From<LockingScript> for Script {
    fn from(locking: LockingScript) -> Self {
        locking.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_is_locking_script() {
        let script = LockingScript::new();
        assert!(script.is_locking_script());
        assert!(!script.is_unlocking_script());
    }

    #[test]
    fn test_from_hex() {
        let hex = "76a914000000000000000000000000000000000000000088ac";
        let script = LockingScript::from_hex(hex).unwrap();
        assert_eq!(script.to_hex(), hex);
    }

    #[test]
    fn test_from_asm() {
        let asm = "OP_DUP OP_HASH160";
        let script = LockingScript::from_asm(asm).unwrap();
        assert_eq!(script.to_hex(), "76a9");
    }

    #[test]
    fn test_conversion() {
        let script = Script::from_hex("76a9").unwrap();
        let locking = LockingScript::from_script(script.clone());
        let back: Script = locking.into();
        assert_eq!(back.to_hex(), script.to_hex());
    }
}
