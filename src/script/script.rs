//! Bitcoin Script class.
//!
//! The Script class represents a script in a Bitcoin SV transaction,
//! encapsulating the functionality to construct, parse, and serialize
//! scripts used in both locking (output) and unlocking (input) scripts.

use std::cell::RefCell;

use super::chunk::ScriptChunk;
use super::op::*;
use crate::primitives::{from_hex, to_hex};
use crate::Result;

/// The Script class represents a script in a Bitcoin SV transaction.
///
/// Scripts can be constructed from ASM strings, hex strings, or binary data,
/// and can be serialized back to any of these formats.
#[derive(Debug, Clone)]
pub struct Script {
    /// The chunks that make up this script
    chunks: RefCell<Vec<ScriptChunk>>,
    /// Whether the chunks have been parsed from raw bytes
    parsed: RefCell<bool>,
    /// Cached raw bytes (for lazy parsing)
    raw_bytes_cache: RefCell<Option<Vec<u8>>>,
    /// Cached hex string
    hex_cache: RefCell<Option<String>>,
}

impl Script {
    /// Creates a new empty script.
    pub fn new() -> Self {
        Self {
            chunks: RefCell::new(Vec::new()),
            parsed: RefCell::new(true),
            raw_bytes_cache: RefCell::new(None),
            hex_cache: RefCell::new(None),
        }
    }

    /// Creates a script from a vector of chunks.
    pub fn from_chunks(chunks: Vec<ScriptChunk>) -> Self {
        Self {
            chunks: RefCell::new(chunks),
            parsed: RefCell::new(true),
            raw_bytes_cache: RefCell::new(None),
            hex_cache: RefCell::new(None),
        }
    }

    /// Constructs a Script instance from an ASM (Assembly) formatted string.
    ///
    /// # Example
    ///
    /// ```
    /// use bsv_sdk::script::Script;
    ///
    /// let script = Script::from_asm("OP_DUP OP_HASH160 abcd1234 OP_EQUALVERIFY OP_CHECKSIG").unwrap();
    /// ```
    pub fn from_asm(asm: &str) -> Result<Self> {
        let mut chunks = Vec::new();

        if asm.is_empty() {
            return Ok(Self::from_chunks(chunks));
        }

        let tokens: Vec<&str> = asm.split(' ').filter(|s| !s.is_empty()).collect();
        let mut i = 0;

        while i < tokens.len() {
            let token = tokens[i];

            // Check if it's an opcode
            let op_code_num = name_to_opcode(token);

            // Handle special cases: "0" and "-1"
            if token == "0" {
                chunks.push(ScriptChunk::new_opcode(OP_0));
                i += 1;
            } else if token == "-1" {
                chunks.push(ScriptChunk::new_opcode(OP_1NEGATE));
                i += 1;
            } else if op_code_num.is_none() {
                // It's hex data
                let mut hex = token.to_string();
                if hex.len() % 2 != 0 {
                    hex = format!("0{}", hex);
                }

                let data = from_hex(&hex)?;
                let len = data.len();

                let op = if len < OP_PUSHDATA1 as usize {
                    len as u8
                } else if len < 256 {
                    OP_PUSHDATA1
                } else if len < 65536 {
                    OP_PUSHDATA2
                } else {
                    OP_PUSHDATA4
                };

                chunks.push(ScriptChunk::new(op, Some(data)));
                i += 1;
            } else if let Some(op) = op_code_num {
                // Handle PUSHDATA opcodes specially (they have length and data following)
                if op == OP_PUSHDATA1 || op == OP_PUSHDATA2 || op == OP_PUSHDATA4 {
                    // Format: OP_PUSHDATA1 <length> <hex>
                    if i + 2 < tokens.len() {
                        let data = from_hex(tokens[i + 2])?;
                        chunks.push(ScriptChunk::new(op, Some(data)));
                        i += 3;
                    } else {
                        chunks.push(ScriptChunk::new_opcode(op));
                        i += 1;
                    }
                } else {
                    chunks.push(ScriptChunk::new_opcode(op));
                    i += 1;
                }
            } else {
                i += 1;
            }
        }

        Ok(Self::from_chunks(chunks))
    }

    /// Constructs a Script instance from a hexadecimal string.
    ///
    /// # Example
    ///
    /// ```
    /// use bsv_sdk::script::Script;
    ///
    /// let script = Script::from_hex("76a914000000000000000000000000000000000000000088ac").unwrap();
    /// ```
    pub fn from_hex(hex: &str) -> Result<Self> {
        if hex.is_empty() {
            return Ok(Self::new());
        }

        let bin = from_hex(hex)?;
        let raw_bytes = bin.clone();
        let hex_lower = hex.to_lowercase();

        Ok(Self {
            chunks: RefCell::new(Vec::new()),
            parsed: RefCell::new(false),
            raw_bytes_cache: RefCell::new(Some(raw_bytes)),
            hex_cache: RefCell::new(Some(hex_lower)),
        })
    }

    /// Constructs a Script instance from binary data.
    ///
    /// # Example
    ///
    /// ```
    /// use bsv_sdk::script::Script;
    ///
    /// let script = Script::from_binary(&[0x76, 0xa9]).unwrap();
    /// ```
    pub fn from_binary(bin: &[u8]) -> Result<Self> {
        Ok(Self {
            chunks: RefCell::new(Vec::new()),
            parsed: RefCell::new(false),
            raw_bytes_cache: RefCell::new(Some(bin.to_vec())),
            hex_cache: RefCell::new(None),
        })
    }

    /// Ensures that the chunks have been parsed from raw bytes.
    fn ensure_parsed(&self) {
        if *self.parsed.borrow() {
            return;
        }

        if let Some(ref bytes) = *self.raw_bytes_cache.borrow() {
            *self.chunks.borrow_mut() = Self::parse_chunks(bytes);
        }
        *self.parsed.borrow_mut() = true;
    }

    /// Parses raw bytes into script chunks.
    fn parse_chunks(bytes: &[u8]) -> Vec<ScriptChunk> {
        let mut chunks = Vec::new();
        let length = bytes.len();
        let mut pos = 0;
        let mut in_conditional_block = 0i32;

        while pos < length {
            let op = bytes[pos];
            pos += 1;

            // Handle OP_RETURN outside conditional blocks
            if op == OP_RETURN && in_conditional_block == 0 {
                // Everything after OP_RETURN is data
                let data = if pos < length {
                    Some(bytes[pos..].to_vec())
                } else {
                    None
                };
                chunks.push(ScriptChunk::new(op, data));
                break;
            }

            // Track conditional blocks
            if op == OP_IF || op == OP_NOTIF || op == OP_VERIF || op == OP_VERNOTIF {
                in_conditional_block += 1;
            } else if op == OP_ENDIF {
                in_conditional_block = (in_conditional_block - 1).max(0);
            }

            // Handle push operations
            if op > 0 && op < OP_PUSHDATA1 {
                let len = op as usize;
                let end = (pos + len).min(length);
                let data = bytes[pos..end].to_vec();
                chunks.push(ScriptChunk::new(op, Some(data)));
                pos = end;
            } else if op == OP_PUSHDATA1 {
                let len = if pos < length { bytes[pos] as usize } else { 0 };
                pos += 1;
                let end = (pos + len).min(length);
                let data = bytes[pos..end].to_vec();
                chunks.push(ScriptChunk::new(op, Some(data)));
                pos = end;
            } else if op == OP_PUSHDATA2 {
                let b0 = if pos < length { bytes[pos] as usize } else { 0 };
                let b1 = if pos + 1 < length {
                    bytes[pos + 1] as usize
                } else {
                    0
                };
                let len = b0 | (b1 << 8);
                pos = (pos + 2).min(length);
                let end = (pos + len).min(length);
                let data = bytes[pos..end].to_vec();
                chunks.push(ScriptChunk::new(op, Some(data)));
                pos = end;
            } else if op == OP_PUSHDATA4 {
                let b0 = if pos < length { bytes[pos] as u32 } else { 0 };
                let b1 = if pos + 1 < length {
                    bytes[pos + 1] as u32
                } else {
                    0
                };
                let b2 = if pos + 2 < length {
                    bytes[pos + 2] as u32
                } else {
                    0
                };
                let b3 = if pos + 3 < length {
                    bytes[pos + 3] as u32
                } else {
                    0
                };
                let len = (b0 | (b1 << 8) | (b2 << 16) | (b3 << 24)) as usize;
                pos = (pos + 4).min(length);
                let end = (pos + len).min(length);
                let data = bytes[pos..end].to_vec();
                chunks.push(ScriptChunk::new(op, Some(data)));
                pos = end;
            } else {
                chunks.push(ScriptChunk::new_opcode(op));
            }
        }

        chunks
    }

    /// Serializes the script to an ASM formatted string.
    pub fn to_asm(&self) -> String {
        self.ensure_parsed();
        let chunks = self.chunks.borrow();
        let parts: Vec<String> = chunks.iter().map(|c| c.to_asm()).collect();
        parts.join(" ")
    }

    /// Serializes the script to a hexadecimal string.
    pub fn to_hex(&self) -> String {
        if let Some(ref hex) = *self.hex_cache.borrow() {
            return hex.clone();
        }

        let bytes = self.to_binary();
        let hex = to_hex(&bytes);
        *self.hex_cache.borrow_mut() = Some(hex.clone());
        hex
    }

    /// Serializes the script to binary (byte array).
    pub fn to_binary(&self) -> Vec<u8> {
        if let Some(ref bytes) = *self.raw_bytes_cache.borrow() {
            return bytes.clone();
        }

        self.ensure_parsed();
        let bytes = self.serialize_chunks_to_bytes();
        *self.raw_bytes_cache.borrow_mut() = Some(bytes.clone());
        bytes
    }

    /// Computes the serialized length of the chunks.
    fn compute_serialized_length(chunks: &[ScriptChunk]) -> usize {
        let mut total = 0;
        for chunk in chunks {
            total += 1; // opcode byte
            if let Some(ref data) = chunk.data {
                let len = data.len();
                if chunk.op == OP_RETURN {
                    total += len;
                    break;
                }
                if chunk.op < OP_PUSHDATA1 {
                    total += len;
                } else if chunk.op == OP_PUSHDATA1 {
                    total += 1 + len;
                } else if chunk.op == OP_PUSHDATA2 {
                    total += 2 + len;
                } else if chunk.op == OP_PUSHDATA4 {
                    total += 4 + len;
                }
            }
        }
        total
    }

    /// Serializes chunks to raw bytes.
    fn serialize_chunks_to_bytes(&self) -> Vec<u8> {
        let chunks = self.chunks.borrow();
        let total_length = Self::compute_serialized_length(&chunks);
        let mut bytes = Vec::with_capacity(total_length);

        for chunk in chunks.iter() {
            bytes.push(chunk.op);

            if let Some(ref data) = chunk.data {
                if chunk.op == OP_RETURN {
                    bytes.extend_from_slice(data);
                    break;
                }

                if chunk.op < OP_PUSHDATA1 {
                    bytes.extend_from_slice(data);
                } else if chunk.op == OP_PUSHDATA1 {
                    bytes.push(data.len() as u8);
                    bytes.extend_from_slice(data);
                } else if chunk.op == OP_PUSHDATA2 {
                    let len = data.len() as u16;
                    bytes.push((len & 0xff) as u8);
                    bytes.push(((len >> 8) & 0xff) as u8);
                    bytes.extend_from_slice(data);
                } else if chunk.op == OP_PUSHDATA4 {
                    let len = data.len() as u32;
                    bytes.push((len & 0xff) as u8);
                    bytes.push(((len >> 8) & 0xff) as u8);
                    bytes.push(((len >> 16) & 0xff) as u8);
                    bytes.push(((len >> 24) & 0xff) as u8);
                    bytes.extend_from_slice(data);
                }
            }
        }

        bytes
    }

    /// Invalidates the serialization caches.
    fn invalidate_caches(&self) {
        *self.raw_bytes_cache.borrow_mut() = None;
        *self.hex_cache.borrow_mut() = None;
    }

    /// Appends another script to this script.
    pub fn write_script(&mut self, script: &Script) -> &mut Self {
        self.invalidate_caches();
        self.ensure_parsed();
        script.ensure_parsed();
        {
            let mut chunks = self.chunks.borrow_mut();
            chunks.extend(script.chunks.borrow().iter().cloned());
        }
        self
    }

    /// Appends an opcode to the script.
    pub fn write_opcode(&mut self, op: u8) -> &mut Self {
        self.invalidate_caches();
        self.ensure_parsed();
        self.chunks.borrow_mut().push(ScriptChunk::new_opcode(op));
        self
    }

    /// Appends binary data to the script, determining the appropriate opcode based on length.
    pub fn write_bin(&mut self, bin: &[u8]) -> &mut Self {
        self.invalidate_caches();
        self.ensure_parsed();

        let len = bin.len();
        let op: u8;
        let data: Option<Vec<u8>>;

        if len == 0 {
            op = OP_0;
            data = None;
        } else if len < OP_PUSHDATA1 as usize {
            op = len as u8;
            data = Some(bin.to_vec());
        } else if len < 256 {
            op = OP_PUSHDATA1;
            data = Some(bin.to_vec());
        } else if len < 65536 {
            op = OP_PUSHDATA2;
            data = Some(bin.to_vec());
        } else if len < 0x100000000 {
            op = OP_PUSHDATA4;
            data = Some(bin.to_vec());
        } else {
            panic!("Data too large to push");
        }

        self.chunks.borrow_mut().push(ScriptChunk::new(op, data));
        self
    }

    /// Appends a number to the script.
    ///
    /// Numbers 0, -1, and 1-16 use special opcodes.
    /// Larger numbers are encoded in little-endian sign-magnitude format.
    pub fn write_number(&mut self, num: i64) -> &mut Self {
        self.invalidate_caches();
        self.ensure_parsed();

        if num == 0 {
            self.chunks.borrow_mut().push(ScriptChunk::new_opcode(OP_0));
        } else if num == -1 {
            self.chunks
                .borrow_mut()
                .push(ScriptChunk::new_opcode(OP_1NEGATE));
        } else if (1..=16).contains(&num) {
            let op = (OP_1 as i64 + num - 1) as u8;
            self.chunks.borrow_mut().push(ScriptChunk::new_opcode(op));
        } else {
            // Encode as little-endian sign-magnitude
            let data = Self::encode_script_number(num);
            let len = data.len();
            let op = if len < OP_PUSHDATA1 as usize {
                len as u8
            } else if len < 256 {
                OP_PUSHDATA1
            } else {
                OP_PUSHDATA2
            };
            self.chunks
                .borrow_mut()
                .push(ScriptChunk::new(op, Some(data)));
        }

        self
    }

    /// Encodes a number in Bitcoin script number format (little-endian sign-magnitude).
    fn encode_script_number(num: i64) -> Vec<u8> {
        if num == 0 {
            return vec![];
        }

        let negative = num < 0;
        let mut abs_val = num.unsigned_abs();
        let mut result = Vec::new();

        while abs_val > 0 {
            result.push((abs_val & 0xff) as u8);
            abs_val >>= 8;
        }

        // If the most significant byte has its high bit set, we need an extra byte
        // to indicate the sign
        if result.last().is_some_and(|&b| b & 0x80 != 0) {
            result.push(if negative { 0x80 } else { 0x00 });
        } else if negative {
            // Set the sign bit on the most significant byte
            if let Some(last) = result.last_mut() {
                *last |= 0x80;
            }
        }

        result
    }

    /// Removes all OP_CODESEPARATOR opcodes from the script.
    pub fn remove_codeseparators(&mut self) -> &mut Self {
        self.invalidate_caches();
        self.ensure_parsed();

        {
            let mut chunks = self.chunks.borrow_mut();
            chunks.retain(|chunk| chunk.op != OP_CODESEPARATOR);
        }

        self
    }

    /// Deletes the given script wherever it appears in the current script.
    pub fn find_and_delete(&mut self, script: &Script) -> &mut Self {
        self.invalidate_caches();
        self.ensure_parsed();
        script.ensure_parsed();

        let target_hex = script.to_hex();
        {
            let mut chunks = self.chunks.borrow_mut();

            chunks.retain(|chunk| {
                let chunk_script = Script::from_chunks(vec![chunk.clone()]);
                chunk_script.to_hex() != target_hex
            });
        }

        self
    }

    /// Checks if the script contains only push data operations.
    pub fn is_push_only(&self) -> bool {
        self.ensure_parsed();
        let chunks = self.chunks.borrow();
        chunks.iter().all(|chunk| chunk.op <= OP_16)
    }

    /// Returns the chunks that make up this script.
    pub fn chunks(&self) -> Vec<ScriptChunk> {
        self.ensure_parsed();
        self.chunks.borrow().clone()
    }

    /// Returns the number of chunks in this script.
    pub fn len(&self) -> usize {
        self.ensure_parsed();
        self.chunks.borrow().len()
    }

    /// Returns true if this script is empty.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Sets a specific chunk's opcode at the given index.
    pub fn set_chunk_opcode(&mut self, index: usize, op: u8) -> &mut Self {
        self.invalidate_caches();
        self.ensure_parsed();
        {
            let mut chunks = self.chunks.borrow_mut();
            if index < chunks.len() {
                chunks[index] = ScriptChunk::new_opcode(op);
            }
        }
        self
    }

    /// Returns true if this script is a locking script.
    /// Base Script always returns false; use LockingScript for true.
    pub fn is_locking_script(&self) -> bool {
        false
    }

    /// Returns true if this script is an unlocking script.
    /// Base Script always returns false; use UnlockingScript for true.
    pub fn is_unlocking_script(&self) -> bool {
        false
    }
}

impl Default for Script {
    fn default() -> Self {
        Self::new()
    }
}

impl PartialEq for Script {
    fn eq(&self, other: &Self) -> bool {
        self.to_binary() == other.to_binary()
    }
}

impl Eq for Script {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_new_empty_script() {
        let script = Script::new();
        assert!(script.is_empty());
        assert_eq!(script.to_hex(), "");
        assert_eq!(script.to_asm(), "");
    }

    #[test]
    fn test_from_hex() {
        // OP_DUP OP_HASH160 <20 bytes> OP_EQUALVERIFY OP_CHECKSIG
        let hex = "76a914000000000000000000000000000000000000000088ac";
        let script = Script::from_hex(hex).unwrap();
        assert_eq!(script.to_hex(), hex);
    }

    #[test]
    fn test_from_binary() {
        let bin = vec![0x76, 0xa9]; // OP_DUP OP_HASH160
        let script = Script::from_binary(&bin).unwrap();
        assert_eq!(script.to_binary(), bin);
    }

    #[test]
    fn test_from_asm_simple() {
        let asm = "OP_DUP OP_HASH160";
        let script = Script::from_asm(asm).unwrap();
        assert_eq!(script.to_hex(), "76a9");
    }

    #[test]
    fn test_from_asm_with_data() {
        let asm =
            "OP_DUP OP_HASH160 0000000000000000000000000000000000000000 OP_EQUALVERIFY OP_CHECKSIG";
        let script = Script::from_asm(asm).unwrap();
        assert_eq!(
            script.to_hex(),
            "76a914000000000000000000000000000000000000000088ac"
        );
    }

    #[test]
    fn test_from_asm_special_values() {
        let script = Script::from_asm("0").unwrap();
        assert_eq!(script.to_hex(), "00");

        let script = Script::from_asm("-1").unwrap();
        assert_eq!(script.to_hex(), "4f");
    }

    #[test]
    fn test_to_asm() {
        let hex = "76a914000000000000000000000000000000000000000088ac";
        let script = Script::from_hex(hex).unwrap();
        let asm = script.to_asm();
        assert!(asm.contains("OP_DUP"));
        assert!(asm.contains("OP_HASH160"));
        assert!(asm.contains("OP_EQUALVERIFY"));
        assert!(asm.contains("OP_CHECKSIG"));
    }

    #[test]
    fn test_write_opcode() {
        let mut script = Script::new();
        script.write_opcode(OP_DUP).write_opcode(OP_HASH160);
        assert_eq!(script.to_hex(), "76a9");
    }

    #[test]
    fn test_write_bin() {
        let mut script = Script::new();
        script.write_bin(&[0x01, 0x02, 0x03]);
        assert_eq!(script.to_hex(), "03010203");
    }

    #[test]
    fn test_write_bin_empty() {
        let mut script = Script::new();
        script.write_bin(&[]);
        assert_eq!(script.to_hex(), "00"); // OP_0
    }

    #[test]
    fn test_write_number() {
        let mut script = Script::new();
        script.write_number(0);
        assert_eq!(script.to_hex(), "00"); // OP_0

        let mut script = Script::new();
        script.write_number(-1);
        assert_eq!(script.to_hex(), "4f"); // OP_1NEGATE

        let mut script = Script::new();
        script.write_number(1);
        assert_eq!(script.to_hex(), "51"); // OP_1

        let mut script = Script::new();
        script.write_number(16);
        assert_eq!(script.to_hex(), "60"); // OP_16
    }

    #[test]
    fn test_write_number_large() {
        let mut script = Script::new();
        script.write_number(127);
        assert_eq!(script.to_hex(), "017f");

        let mut script = Script::new();
        script.write_number(128);
        assert_eq!(script.to_hex(), "028000"); // Needs sign byte

        let mut script = Script::new();
        script.write_number(-127);
        assert_eq!(script.to_hex(), "01ff");
    }

    #[test]
    fn test_is_push_only() {
        let script = Script::from_asm("OP_1 OP_2 OP_3").unwrap();
        assert!(script.is_push_only());

        let script = Script::from_asm("OP_DUP OP_HASH160").unwrap();
        assert!(!script.is_push_only());
    }

    #[test]
    fn test_remove_codeseparators() {
        let mut script =
            Script::from_asm("OP_DUP OP_CODESEPARATOR OP_HASH160 OP_CODESEPARATOR").unwrap();
        script.remove_codeseparators();
        assert_eq!(script.to_asm(), "OP_DUP OP_HASH160");
    }

    #[test]
    fn test_find_and_delete() {
        let mut script = Script::from_asm("OP_DUP OP_HASH160 OP_DUP").unwrap();
        let target = Script::from_asm("OP_DUP").unwrap();
        script.find_and_delete(&target);
        assert_eq!(script.to_asm(), "OP_HASH160");
    }

    #[test]
    fn test_chunks() {
        let script = Script::from_asm("OP_DUP OP_HASH160").unwrap();
        let chunks = script.chunks();
        assert_eq!(chunks.len(), 2);
        assert_eq!(chunks[0].op, OP_DUP);
        assert_eq!(chunks[1].op, OP_HASH160);
    }

    #[test]
    fn test_write_script() {
        let mut script1 = Script::from_asm("OP_DUP").unwrap();
        let script2 = Script::from_asm("OP_HASH160").unwrap();
        script1.write_script(&script2);
        assert_eq!(script1.to_asm(), "OP_DUP OP_HASH160");
    }

    #[test]
    fn test_op_return_parsing() {
        // OP_RETURN followed by data
        let hex = "6a0568656c6c6f"; // OP_RETURN <5 bytes "hello">
        let script = Script::from_hex(hex).unwrap();
        let chunks = script.chunks();
        assert_eq!(chunks.len(), 1);
        assert_eq!(chunks[0].op, OP_RETURN);
        // The data includes the push opcode and data
        assert!(chunks[0].data.is_some());
    }

    #[test]
    fn test_pushdata1() {
        // Create a script with PUSHDATA1
        let data = vec![0u8; 100];
        let mut script = Script::new();
        script.write_bin(&data);
        let bytes = script.to_binary();
        assert_eq!(bytes[0], OP_PUSHDATA1);
        assert_eq!(bytes[1], 100);
        assert_eq!(&bytes[2..], &data[..]);
    }

    #[test]
    fn test_pushdata2() {
        // Create a script with PUSHDATA2
        let data = vec![0u8; 300];
        let mut script = Script::new();
        script.write_bin(&data);
        let bytes = script.to_binary();
        assert_eq!(bytes[0], OP_PUSHDATA2);
        assert_eq!(bytes[1], (300 & 0xff) as u8);
        assert_eq!(bytes[2], ((300 >> 8) & 0xff) as u8);
        assert_eq!(&bytes[3..], &data[..]);
    }

    #[test]
    fn test_roundtrip_hex() {
        let hex = "76a914000000000000000000000000000000000000000088ac";
        let script = Script::from_hex(hex).unwrap();
        assert_eq!(script.to_hex(), hex);
    }

    #[test]
    fn test_equality() {
        let script1 = Script::from_hex("76a9").unwrap();
        let script2 = Script::from_asm("OP_DUP OP_HASH160").unwrap();
        assert_eq!(script1, script2);
    }
}
