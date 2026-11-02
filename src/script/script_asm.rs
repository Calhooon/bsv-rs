//! `Script`'s ASM reader and writer, a child of `script.rs` (its private
//! parser and chunk cache): the rest a folded `OP_RETURN` carries reads back
//! byte for byte (#634); a non-minimal push or an undefined opcode before it
//! does not, as before.

use super::{Script, ScriptChunk};
use crate::primitives::{from_hex, to_hex};
use crate::script::op::*;
use crate::Result;

impl Script {
    /// Constructs a Script instance from an ASM (Assembly) formatted string.
    ///
    /// # Example
    ///
    /// ```
    /// use bsv_rs::script::Script;
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
            } else if let Some(raw) = token.strip_prefix("0x") {
                // The rest after an `OP_RETURN`, as raw bytes (`to_asm`);
                // an empty one is the bare `OP_RETURN`
                match chunks.last_mut() {
                    Some(c) if c.op == OP_RETURN && c.data.is_none() && i + 1 == tokens.len() => {
                        let rest = from_hex(raw)?;
                        c.data = (!rest.is_empty()).then_some(rest);
                    }
                    _ => {
                        return Err(crate::Error::ScriptParseError(format!(
                            "{token}: raw bytes only end a script after OP_RETURN"
                        )))
                    }
                }
                i += 1;
            } else if op_code_num.is_none() {
                // It's hex data
                let mut hex = token.to_string();
                #[allow(unknown_lints, clippy::manual_is_multiple_of)]
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

    /// Serializes the script to an ASM formatted string.
    ///
    /// An `OP_RETURN` chunk carrying the rest of the script is written as
    /// `OP_RETURN` and the rest's own ASM when that reads back to the same
    /// bytes, else as `OP_RETURN 0x<hex>`, the raw bytes `from_asm` reads
    /// there; an empty rest is written as `OP_RETURN` alone. The reference
    /// writes the data's hex alone (`Script.ts:668-677`), which reads back as
    /// a push, and an empty rest as nothing (#634).
    pub fn to_asm(&self) -> String {
        self.ensure_parsed();
        let chunks = self.chunks.borrow();
        let parts: Vec<String> = chunks.iter().map(Self::chunk_asm).collect();
        parts.join(" ")
    }

    fn chunk_asm(chunk: &ScriptChunk) -> String {
        let rest = match &chunk.data {
            Some(rest) if chunk.op == OP_RETURN => rest,
            _ => return chunk.to_asm(),
        };
        if rest.is_empty() {
            return "OP_RETURN".to_string();
        }
        let mut parts = vec!["OP_RETURN".to_string()];
        parts.extend(
            Self::parse_chunks(rest, false)
                .iter()
                .map(ScriptChunk::to_asm),
        );
        let asm = parts.join(" ");
        match Self::from_asm(&asm) {
            Ok(s) if s.to_binary().get(1..) == Some(&rest[..]) => asm,
            _ => format!("OP_RETURN 0x{}", to_hex(rest)),
        }
    }
}
