//! The scriptCode a signature check commits to, built from the executing
//! script's bytes as bitcoin-sv v1.2.3 builds it (#654): `CScript
//! scriptCode{pbegincodehash, pend}`, the executing script's bytes from the
//! byte after the last executed `OP_CODESEPARATOR` to its end
//! (`interpreter.cpp:1470-1484`, `1566-1579`). Inside the unlocking script the
//! locking script's bytes are appended under a word carrying CHRONICLE
//! (`scriptCode += *checksigData`) and in the default mode, as the node and the
//! reference's `Spend` append them (`Spend.ts:1688-1690`); a pre-Chronicle word
//! signs the unlocking script's bytes alone. Then `CleanupScriptCode`'s
//! `FindAndDelete` removes the push of each signature that lacks `SIGHASH_FORKID`,
//! in order (`script.h:201-224`).
//!
//! Built from the bytes, not the chunk serializer: a top-level data-carrying
//! `OP_RETURN` makes the chunk serializer stop and drop everything after it (the
//! appended locking script included; `Script::serialize_chunks_to_bytes` breaks
//! at the `OP_RETURN` chunk), so a signature was taken over the wrong digest and
//! a wrong-digest spend verified where the node refuses it, until #654. Lives in
//! its own file so the monolith does not grow past its line ratchet.

use crate::script::evaluation_error::ExecutionContext;
use crate::script::op::{OP_PUSHDATA1, OP_PUSHDATA2, OP_PUSHDATA4};
use crate::script::{Script, ScriptFlags};

use super::{has_forkid_bit, Spend};

impl Spend {
    /// The scriptCode of the signature check executing now, with the push of
    /// each signature in `sigs` that lacks `SIGHASH_FORKID` deleted, in order.
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
                code = find_and_delete_bytes(&code, &push_of(sig));
            }
        }
        Script::from_binary(&code).unwrap_or_default()
    }
}

/// `CScript() << vchSig` (`script.h:104-130`): the minimal push of `data`
/// (`OP_0` for an empty one), for `FindAndDelete` over scriptCode bytes (#654).
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

/// `CScript::GetOp2` (`script.h:164-198`): the position after the instruction at
/// `pc`, or `None` where the read fails (the end, or a push cut short). Used to
/// walk scriptCode bytes at instruction boundaries for `FindAndDelete` (#654).
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
/// meets at an instruction boundary removed, consecutive copies included, in one
/// pass; the bytes after a read that fails are kept as they are (#654).
fn find_and_delete_bytes(script: &[u8], b: &[u8]) -> Vec<u8> {
    if b.is_empty() {
        return script.to_vec();
    }
    let mut result = Vec::with_capacity(script.len());
    let mut found = false;
    let (mut pc, mut pc2) = (0usize, 0usize);
    loop {
        result.extend_from_slice(script.get(pc2..pc).unwrap_or_default());
        while script.get(pc..pc + b.len()) == Some(b) {
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
