//! Unlocking Script (scriptSig).
//!
//! The UnlockingScript class represents an unlocking script in a Bitcoin SV transaction.
//! It extends the Script class and is used specifically for input scripts that unlock funds.

use super::chunk::ScriptChunk;
use super::script::Script;
use crate::Result;

/// Represents an unlocking script (input script / scriptSig).
///
/// An unlocking script provides the data needed to satisfy a locking script's
/// conditions in order to spend the output.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnlockingScript(Script);

impl UnlockingScript {
    /// Creates a new empty unlocking script.
    pub fn new() -> Self {
        Self(Script::new())
    }

    /// Creates an unlocking script from a vector of chunks.
    pub fn from_chunks(chunks: Vec<ScriptChunk>) -> Self {
        Self(Script::from_chunks(chunks))
    }

    /// Constructs an UnlockingScript from an ASM formatted string.
    pub fn from_asm(asm: &str) -> Result<Self> {
        Ok(Self(Script::from_asm(asm)?))
    }

    /// Constructs an UnlockingScript from a hexadecimal string.
    pub fn from_hex(hex: &str) -> Result<Self> {
        Ok(Self(Script::from_hex(hex)?))
    }

    /// Constructs an UnlockingScript from binary data.
    pub fn from_binary(bin: &[u8]) -> Result<Self> {
        Ok(Self(Script::from_binary(bin)?))
    }

    /// Constructs an UnlockingScript from a Script.
    pub fn from_script(script: Script) -> Self {
        Self(script)
    }

    /// Returns a reference to the underlying Script.
    pub fn as_script(&self) -> &Script {
        &self.0
    }

    /// Converts this UnlockingScript into its underlying Script.
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

    /// Returns false (this is not a locking script).
    pub fn is_locking_script(&self) -> bool {
        false
    }

    /// Returns true (this is an unlocking script).
    pub fn is_unlocking_script(&self) -> bool {
        true
    }
}

impl Default for UnlockingScript {
    fn default() -> Self {
        Self::new()
    }
}

impl From<Script> for UnlockingScript {
    fn from(script: Script) -> Self {
        Self(script)
    }
}

impl From<UnlockingScript> for Script {
    fn from(unlocking: UnlockingScript) -> Self {
        unlocking.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_is_unlocking_script() {
        let script = UnlockingScript::new();
        assert!(!script.is_locking_script());
        assert!(script.is_unlocking_script());
    }

    #[test]
    fn test_from_hex() {
        let script = UnlockingScript::from_hex("00").unwrap();
        assert_eq!(script.to_hex(), "00");
    }

    #[test]
    fn test_from_asm() {
        let asm = "0 abcdef1234";
        let script = UnlockingScript::from_asm(asm).unwrap();
        assert!(script.is_unlocking_script());
    }

    #[test]
    fn test_conversion() {
        let script = Script::from_hex("00").unwrap();
        let unlocking = UnlockingScript::from_script(script.clone());
        let back: Script = unlocking.into();
        assert_eq!(back.to_hex(), script.to_hex());
    }

    #[test]
    fn test_is_push_only() {
        // Unlocking scripts should typically be push-only
        let script = UnlockingScript::from_asm("0 OP_1 OP_2").unwrap();
        assert!(script.is_push_only());
    }
}
