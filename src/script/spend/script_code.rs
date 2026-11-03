//! The scriptCode a signature check commits to, built from the script's bytes
//! as bitcoin-sv v1.2.3 builds it (#654): `CScript scriptCode{pbegincodehash,
//! pend}`, the executing script's bytes from the last executed
//! `OP_CODESEPARATOR` to its end; inside the unlocking script under
//! `SCRIPT_CHRONICLE`, the locking script's bytes appended (`scriptCode +=
//! *checksigData`); then `CleanupScriptCode`'s `FindAndDelete` for every
//! signature without `SIGHASH_FORKID` (`interpreter.cpp:1470-1484`,
//! `1566-1579`, `255-263`; `script.h:201-224`). The bytes are read with
//! `GetOp` alone: no top-level `OP_RETURN` folds the rest into one chunk, so
//! nothing after it is dropped (the chunk serializer's stop, `Script::to_binary`
//! over concatenated chunks, dropped the locking script behind a data-carrying
//! `OP_RETURN` until #654). The sibling's Lean states the same rule
//! (`lean/BsvScript/Ops/Crypto.lean` `scriptCodeOf`, `Sighash.lean`
//! `findAndDelete`).

use crate::script::evaluation_error::ExecutionContext;
use crate::script::op::{OP_PUSHDATA1, OP_PUSHDATA2, OP_PUSHDATA4};
use crate::script::{Script, ScriptFlags};

use super::crypto::has_forkid_bit;
use super::Spend;

impl Spend {
    /// The scriptCode of the signature check executing now, with the push of
    /// each signature in `sigs` that lacks `SIGHASH_FORKID` deleted, in order.
    ///
    /// The locking script is appended inside the unlocking script under a word
    /// carrying `CHRONICLE`, as the node appends it (a word without it, a
    /// pre-Chronicle one, signs the unlocking script's bytes alone), and in the
    /// default mode at every version, as the reference's `Spend` appends it
    /// (`Spend.ts:1688-1690`). The node's `CleanupScriptCode` also deletes a
    /// FORKID signature's push under a word without `SIGHASH_FORKID`
    /// (`interpreter.cpp:260-261`); no such word runs here (`ScriptFlags::check`).
    pub(super) fn script_code(&self, sigs: &[&[u8]]) -> Script {
        let (script, chunks) = match self.context {
            ExecutionContext::UnlockingScript => {
                (self.unlocking_script.as_script(), &self.unlocking_chunks)
            }
            ExecutionContext::LockingScript => {
                (self.locking_script.as_script(), &self.locking_chunks)
            }
        };
        let start = self.last_code_separator.map_or(0, |i| i + 1);
        let offset = Script::compute_serialized_length(chunks.get(..start).unwrap_or(chunks));
        let bytes = script.to_binary();
        let mut code = bytes.get(offset..).unwrap_or_default().to_vec();
        let appends = self
            .flags
            .is_none_or(|word| word.contains(ScriptFlags::CHRONICLE));
        if self.context == ExecutionContext::UnlockingScript && appends {
            code.extend_from_slice(&self.locking_script.as_script().to_binary());
        }
        for sig in sigs {
            if !has_forkid_bit(sig) {
                code = find_and_delete(&code, &push_of(sig));
            }
        }
        Script::from_binary(&code).unwrap_or_default()
    }
}

/// `CScript() << vchSig` (`script.h:104-130`): the minimal push of `data`,
/// `OP_0` for an empty one.
fn push_of(data: &[u8]) -> Vec<u8> {
    let len = data.len();
    let mut push = Vec::with_capacity(len + 5);
    if len < OP_PUSHDATA1 as usize {
        push.push(len as u8);
    } else if len <= 0xff {
        push.extend_from_slice(&[OP_PUSHDATA1, len as u8]);
    } else if len <= 0xffff {
        push.push(OP_PUSHDATA2);
        push.extend_from_slice(&(len as u16).to_le_bytes());
    } else {
        push.push(OP_PUSHDATA4);
        push.extend_from_slice(&(len as u32).to_le_bytes());
    }
    push.extend_from_slice(data);
    push
}

/// `CScript::GetOp2` (`script.h:164-198`): the position after the instruction
/// at `pc`, or `None` where the read fails (the end, or a push cut short).
fn next_op(script: &[u8], pc: usize) -> Option<usize> {
    let op = *script.get(pc)?;
    let mut pc = pc + 1;
    let size = if op < OP_PUSHDATA1 {
        op as usize
    } else if op == OP_PUSHDATA1 {
        let n = *script.get(pc)? as usize;
        pc += 1;
        n
    } else if op == OP_PUSHDATA2 {
        let n = u16::from_le_bytes(script.get(pc..pc + 2)?.try_into().ok()?) as usize;
        pc += 2;
        n
    } else if op == OP_PUSHDATA4 {
        let n = u32::from_le_bytes(script.get(pc..pc + 4)?.try_into().ok()?) as usize;
        pc += 4;
        n
    } else {
        0
    };
    if script.len() - pc < size {
        return None;
    }
    Some(pc + size)
}

/// `CScript::FindAndDelete` (`script.h:201-224`): every copy of `b` the walk
/// meets at an instruction boundary removed, consecutive copies included, in
/// one pass; the bytes after a read that fails are kept as they are.
pub(super) fn find_and_delete(script: &[u8], b: &[u8]) -> Vec<u8> {
    if b.is_empty() {
        return script.to_vec();
    }
    let mut result = Vec::with_capacity(script.len());
    let mut found = false;
    let (mut pc, mut pc2) = (0usize, 0usize);
    // Every step advances a byte at least, so the walk ends within one step
    // more than the script has bytes, and a copy of `b` (one byte at least)
    // repeats at most that many times: the two bounds end a walk that does
    // not advance, and never cut short one that does (#681).
    for _ in 0..=script.len() {
        result.extend_from_slice(script.get(pc2..pc).unwrap_or_default());
        for _ in 0..script.len() {
            if script.get(pc..pc + b.len()) != Some(b) {
                break;
            }
            pc += b.len();
            found = true;
        }
        pc2 = pc;
        match next_op(script, pc) {
            Some(next) => pc = next,
            None => break,
        }
    }
    if !found {
        return script.to_vec();
    }
    result.extend_from_slice(script.get(pc2..).unwrap_or_default());
    result
}

#[cfg(test)]
#[path = "script_code_tests.rs"]
mod tests;
