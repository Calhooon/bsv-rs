//! Script chunk representation.
//!
//! A ScriptChunk represents a single element of a script: either an opcode
//! or a data push operation.

use super::op::opcode_to_name;
use crate::primitives::to_hex;

/// A representation of a chunk of a script, which includes an opcode.
/// For push operations, the associated data to push onto the stack is also included.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScriptChunk {
    /// The opcode value
    pub op: u8,
    /// Data for push operations (None for non-push ops)
    pub data: Option<Vec<u8>>,
}

impl ScriptChunk {
    /// Creates a new opcode-only chunk (no data).
    pub fn new_opcode(op: u8) -> Self {
        Self { op, data: None }
    }

    /// Creates a new data push chunk.
    ///
    /// The appropriate opcode is determined based on the data length:
    /// - 0 bytes: OP_0
    /// - 1-75 bytes: direct push (opcode = length)
    /// - 76-255 bytes: OP_PUSHDATA1
    /// - 256-65535 bytes: OP_PUSHDATA2
    /// - Larger: OP_PUSHDATA4
    pub fn new_push(data: Vec<u8>) -> Self {
        let len = data.len();
        let op = if len == 0 {
            super::op::OP_0
        } else if len < super::op::OP_PUSHDATA1 as usize {
            len as u8
        } else if len < 256 {
            super::op::OP_PUSHDATA1
        } else if len < 65536 {
            super::op::OP_PUSHDATA2
        } else {
            super::op::OP_PUSHDATA4
        };

        Self {
            op,
            data: if data.is_empty() { None } else { Some(data) },
        }
    }

    /// Creates a chunk from an opcode and optional data.
    pub fn new(op: u8, data: Option<Vec<u8>>) -> Self {
        Self { op, data }
    }

    /// Returns true if this chunk is a data push operation.
    pub fn is_push_data(&self) -> bool {
        self.op <= super::op::OP_16
    }

    /// Converts this chunk to its ASM string representation.
    pub fn to_asm(&self) -> String {
        match &self.data {
            Some(data) => to_hex(data),
            None => {
                if self.op == super::op::OP_0 {
                    "0".to_string()
                } else if self.op == super::op::OP_1NEGATE {
                    "-1".to_string()
                } else {
                    opcode_to_name(self.op)
                        .map(|s| s.to_string())
                        .unwrap_or_else(|| format!("OP_UNKNOWN{}", self.op))
                }
            }
        }
    }
}

impl Default for ScriptChunk {
    fn default() -> Self {
        Self::new_opcode(super::op::OP_0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::script::op::*;

    #[test]
    fn test_new_opcode() {
        let chunk = ScriptChunk::new_opcode(OP_DUP);
        assert_eq!(chunk.op, OP_DUP);
        assert!(chunk.data.is_none());
    }

    #[test]
    fn test_new_push_empty() {
        let chunk = ScriptChunk::new_push(vec![]);
        assert_eq!(chunk.op, OP_0);
        assert!(chunk.data.is_none());
    }

    #[test]
    fn test_new_push_small() {
        let data = vec![0x01, 0x02, 0x03];
        let chunk = ScriptChunk::new_push(data.clone());
        assert_eq!(chunk.op, 3); // Direct push opcode
        assert_eq!(chunk.data, Some(data));
    }

    #[test]
    fn test_new_push_medium() {
        let data = vec![0u8; 100];
        let chunk = ScriptChunk::new_push(data.clone());
        assert_eq!(chunk.op, OP_PUSHDATA1);
        assert_eq!(chunk.data, Some(data));
    }

    #[test]
    fn test_new_push_large() {
        let data = vec![0u8; 300];
        let chunk = ScriptChunk::new_push(data.clone());
        assert_eq!(chunk.op, super::super::op::OP_PUSHDATA2);
        assert_eq!(chunk.data, Some(data));
    }

    #[test]
    fn test_is_push_data() {
        assert!(ScriptChunk::new_opcode(OP_0).is_push_data());
        assert!(ScriptChunk::new_opcode(OP_1).is_push_data());
        assert!(ScriptChunk::new_opcode(OP_16).is_push_data());
        assert!(!ScriptChunk::new_opcode(OP_DUP).is_push_data());
        assert!(!ScriptChunk::new_opcode(OP_CHECKSIG).is_push_data());
    }

    #[test]
    fn test_to_asm_opcode() {
        assert_eq!(ScriptChunk::new_opcode(OP_DUP).to_asm(), "OP_DUP");
        assert_eq!(ScriptChunk::new_opcode(OP_HASH160).to_asm(), "OP_HASH160");
        assert_eq!(ScriptChunk::new_opcode(OP_CHECKSIG).to_asm(), "OP_CHECKSIG");
    }

    #[test]
    fn test_to_asm_special() {
        assert_eq!(ScriptChunk::new_opcode(OP_0).to_asm(), "0");
        assert_eq!(ScriptChunk::new_opcode(OP_1NEGATE).to_asm(), "-1");
    }

    #[test]
    fn test_to_asm_data() {
        let chunk = ScriptChunk::new(0x03, Some(vec![0xab, 0xcd, 0xef]));
        assert_eq!(chunk.to_asm(), "abcdef");
    }
}
