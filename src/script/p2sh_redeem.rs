//! The node's pay-to-script-hash step, for the default mode's input core.
//!
//! bitcoin-sv v1.2.2 `src/script/interpreter.cpp:2380-2420`: under
//! `SCRIPT_VERIFY_P2SH` without `SCRIPT_UTXO_AFTER_GENESIS`, a coin whose
//! locking script is `OP_HASH160 <20 bytes> OP_EQUAL` (`IsP2SH`) is spent
//! only when, after both scripts succeed, the unlocking script is push-only
//! and its last push, read as a script, succeeds on the stack the other
//! pushes leave. Once Genesis is active a transaction creating such an output
//! is refused (`src/validation.cpp:611-622`, `bad-txns-vout-p2sh`), so a coin
//! of that shape was created before Genesis: the default mode, which knows no
//! coin's height, takes the shape for the era and runs the step for every
//! coin of it. A word carries `UTXO_AFTER_GENESIS` ([`ScriptFlags::check`]),
//! for which the node takes no such step, so the core asks for none under one.
//!
//! The step runs the last push as the locking script of a second [`Spend`] of
//! the same input, under the caller's mode, with the other pushes as its
//! unlocking script: the signature checks inside it sign the redeem script
//! as their scriptCode, as the node's do. It only refuses: an input it is
//! asked of has already been judged valid by the first evaluation. It judges
//! the redeem script by the default mode's post-Genesis rules (the Chronicle
//! opcodes off); a door that proves the coin below the chain's Genesis height
//! runs it again inside the evaluation of that era (`spend/pre_genesis.rs`).
//!
//! [`ScriptFlags::check`]: super::ScriptFlags::check

use std::ops::Range;
use std::sync::Arc;

use super::op::{OP_1NEGATE, OP_EQUAL, OP_HASH160, OP_PUSHDATA1, OP_PUSHDATA2, OP_PUSHDATA4};
use super::{
    ExecutionContext, LockingScript, ScriptEvaluationError, Spend, TxSpendParams, UnlockingScript,
};
use crate::primitives::bsv::sighash::TxSighashCache;

/// The second evaluation the node runs for a coin of the P2SH shape: its
/// unlocking script (every push but the last), its locking script (the last
/// push's bytes), and the input and budgets of the first evaluation.
pub(crate) struct Redeem {
    unlocking: Vec<u8>,
    locking: Vec<u8>,
    transaction: Arc<TxSighashCache>,
    input_index: usize,
    source_satoshis: u64,
    memory_limit: Option<usize>,
    work_limit: Option<u64>,
}

/// The node's `IsP2SH`: exactly 23 bytes, `a9 14 <20 bytes> 87`.
pub(crate) fn is_p2sh_shape(locking: &[u8]) -> bool {
    matches!(locking, [OP_HASH160, 0x14, .., OP_EQUAL] if locking.len() == 23)
}

impl Redeem {
    /// The step for the input `first` describes, whose coin is locked by
    /// `locking` and spent by `unlocking` (the bytes of `first`'s scripts),
    /// or `None` for a coin of any other shape, or when `default_mode` is
    /// `false` (a word: `UTXO_AFTER_GENESIS`, no step).
    ///
    /// An unlocking script that is not push-only, or whose pushes cannot be
    /// read, is kept whole: the step's push-only rule refuses the first
    /// ([`Redeem::judge`]), and its walk reaches the bad push of the second.
    pub(crate) fn of(
        locking: &[u8],
        unlocking: &[u8],
        first: &TxSpendParams,
        default_mode: bool,
    ) -> Option<Self> {
        if !default_mode || !is_p2sh_shape(locking) {
            return None;
        }
        let (unlocking, locking) = match last_push(unlocking) {
            Some((at, top)) => (unlocking.get(..at).unwrap_or_default().to_vec(), top),
            None => (unlocking.to_vec(), locking.to_vec()),
        };
        Some(Self {
            unlocking,
            locking,
            transaction: Arc::clone(&first.transaction),
            input_index: first.input_index,
            source_satoshis: first.source_satoshis,
            memory_limit: first.memory_limit,
            work_limit: first.work_limit,
        })
    }

    /// Validates `first`, then, when it succeeds and `step` is `Some`, the
    /// step's own [`Spend`]: set by `configure` (the caller's mode, as
    /// `first`'s), then held to a push-only unlocking script at every
    /// version (`SCRIPT_ERR_SIG_PUSHONLY`) and to the opcodes of a coin from
    /// before Chronicle (a coin from before Genesis is one), within the work
    /// `first` left of the budget. The verdict is the step's, the work the
    /// two together.
    pub(crate) fn judge(
        step: Option<Self>,
        mut first: Spend,
        configure: impl FnOnce(&mut Spend),
    ) -> (Result<bool, ScriptEvaluationError>, u64) {
        let verdict = first.validate();
        let work = first.work_spent();
        let (Ok(true), Some(step)) = (&verdict, step) else {
            return (verdict, work);
        };
        let params = |locking, unlocking| TxSpendParams {
            transaction: step.transaction,
            input_index: step.input_index,
            source_satoshis: step.source_satoshis,
            locking_script: locking,
            unlocking_script: unlocking,
            memory_limit: step.memory_limit,
            work_limit: step.work_limit.map(|limit| limit.saturating_sub(work)),
        };
        let built = LockingScript::from_binary(&step.locking).and_then(|locking| {
            let unlocking = UnlockingScript::from_binary(&step.unlocking)?;
            Spend::with_transaction(params(locking, unlocking))
        });
        match built {
            Ok(mut spend) => {
                configure(&mut spend);
                spend.set_require_push_only(true);
                spend.set_utxo_after_chronicle(false);
                let verdict = spend.validate();
                (verdict, work.saturating_add(spend.work_spent()))
            }
            Err(error) => (Err(unbuilt(&error)), work),
        }
    }
}

/// A refusal for a step that could not be built (an index naming no input,
/// which the first evaluation has already ruled out): never a pass.
fn unbuilt(error: &crate::Error) -> ScriptEvaluationError {
    let message = format!("the pay-to-script-hash step could not be built: {error}");
    let context = ExecutionContext::LockingScript;
    ScriptEvaluationError::new(message, "", 0, context, 0, vec![], vec![], vec![], 0, 0)
}

/// Where the element a push leaves on the stack lies: bytes of the script,
/// or a small number's one byte.
enum Top {
    Bytes(Range<usize>),
    Byte(u8),
}

/// The offset of the last push of a push-only `script` and the element it
/// leaves on the stack, or `None` for an empty script, an opcode that pushes
/// nothing (`OP_RESERVED` or any above `OP_16`) or a push cut short.
fn last_push(script: &[u8]) -> Option<(usize, Vec<u8>)> {
    let mut at = 0usize;
    let mut last = None;
    while let Some(&op) = script.get(at) {
        let (header, len) = match op {
            0x00..=0x4b => (1, usize::from(op)),
            OP_PUSHDATA1 => (2, usize::from(*script.get(at + 1)?)),
            OP_PUSHDATA2 => (3, usize::from(u16::from_le_bytes(array(script, at + 1)?))),
            OP_PUSHDATA4 => (
                5,
                usize::try_from(u32::from_le_bytes(array(script, at + 1)?)).ok()?,
            ),
            OP_1NEGATE | 0x51..=0x60 => {
                let byte = if op == OP_1NEGATE { 0x81 } else { op - 0x50 };
                last = Some((at, Top::Byte(byte)));
                at += 1;
                continue;
            }
            _ => return None,
        };
        let start = at.checked_add(header)?;
        let end = start.checked_add(len)?;
        script.get(start..end)?;
        last = Some((at, Top::Bytes(start..end)));
        at = end;
    }
    let (at, top) = last?;
    Some(match top {
        Top::Bytes(range) => (at, script.get(range)?.to_vec()),
        Top::Byte(byte) => (at, vec![byte]),
    })
}

/// `N` bytes of `script` from `at`, or `None` past its end.
fn array<const N: usize>(script: &[u8], at: usize) -> Option<[u8; N]> {
    script.get(at..at.checked_add(N)?)?.try_into().ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_shape_is_the_nodes_is_p2sh() {
        let mut p2sh = vec![OP_HASH160, 0x14];
        p2sh.extend([7u8; 20]);
        p2sh.push(OP_EQUAL);
        assert!(is_p2sh_shape(&p2sh));
        assert!(!is_p2sh_shape(&p2sh[..22]));
        let mut longer = p2sh.clone();
        longer.push(0x51);
        assert!(!is_p2sh_shape(&longer));
        let mut other = p2sh.clone();
        other[1] = 0x15;
        assert!(!is_p2sh_shape(&other));
        // `a9 14 ... 87` of another length is not the shape: the node's
        // `IsP2SH` reads exactly 23 bytes.
        for len in [3usize, 22, 24, 25] {
            let mut near = vec![7u8; len];
            near[0] = OP_HASH160;
            near[1] = 0x14;
            near[len - 1] = OP_EQUAL;
            assert!(!is_p2sh_shape(&near), "{len} bytes");
        }
    }

    #[test]
    fn the_last_push_is_the_top_of_the_stack() {
        assert_eq!(last_push(&[]), None);
        assert_eq!(last_push(&[0x00]), Some((0, Vec::new())));
        assert_eq!(last_push(&[0x51, 0x4f]), Some((1, vec![0x81])));
        assert_eq!(last_push(&[0x00, 0x60]), Some((1, vec![16])));
        assert_eq!(last_push(&[0x02, 1, 2, 0x4c, 1, 9]), Some((3, vec![9])));
        assert_eq!(last_push(&[0x4d, 1, 0, 9]), Some((0, vec![9])));
        assert_eq!(last_push(&[0x4e, 1, 0, 0, 0, 9]), Some((0, vec![9])));
        // Cut short, a non-push, OP_RESERVED: no step input; kept whole.
        assert_eq!(last_push(&[0x02, 1]), None);
        assert_eq!(last_push(&[0x4e, 0xff, 0xff, 0xff, 0xff]), None);
        assert_eq!(last_push(&[0x51, 0x76]), None);
        assert_eq!(last_push(&[0x50]), None);
    }
}
