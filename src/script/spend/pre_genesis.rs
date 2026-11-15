//! The consensus rules of a coin created before Genesis, for the default
//! mode's doors that prove the coin's height (GHSA-h4m7-c6p8-725m).
//!
//! A coin is judged by the era of the block that created it
//! (`IsUtxoAfterGenesis`, bitcoin-sv v1.2.3 `src/script/interpreter.cpp:411`).
//! For a coin from before Genesis the rule set is the post-Genesis one plus
//! these refusals (every pre-Genesis site of that interpreter; the others
//! compute the same value):
//!
//! | rule | site |
//! |---|---|
//! | each script at most 10,000 bytes | `2290`, `consensus.h:58` |
//! | a push at most 520 bytes, executed or not | `455`, `script.h:29` |
//! | at most 500 opcodes above `OP_16` per script, executed or not, plus each `OP_CHECKMULTISIG`'s keys | `466-467`, `1534-1535`, `consensus.h:40` |
//! | `OP_2MUL`, `OP_2DIV` disabled, executed or not | `360-375`, `470` |
//! | `OP_VERIF`, `OP_VERNOTIF` a bad opcode, executed or not | `773-779` |
//! | `OP_CHECKLOCKTIMEVERIFY`, `OP_CHECKSEQUENCEVERIFY` enforced (5-byte operand) | `519-600`, `2165-2235` |
//! | an executed `OP_RETURN` fails the script | `856-871` |
//! | a number operand at most 4 bytes (results unbounded; `OP_BIN2NUM`'s result bounded) | `consensus.h:62`, `1789-1790` |
//! | `OP_CAT`'s result and `OP_NUM2BIN`'s size at most 520 bytes | `1699-1702`, `1752-1753` |
//! | at most 20 keys in `OP_CHECKMULTISIG` | `1531`, `consensus.h:50` |
//! | main and alt stack together at most 1,000 elements | `1800-1803`, `script.h:32` |
//! | the opcodes of a coin from before Chronicle | `411-427` |
//!
//! The door runs this as a SECOND evaluation of an input its first
//! evaluation (the default mode, unchanged) found valid
//! ([`Spend::pre_genesis_refusal`]):
//! the answer is valid only when both are, so an answer can only move from
//! valid to refused, and only where these rules refuse. A refusal the first
//! evaluation gives keeps its words. The second evaluation charges no work:
//! the rules it adds bound it (each script at most 10,000 bytes, at most 500
//! opcodes, elements of at most 520 bytes).

use crate::script::evaluation_error::ScriptEvaluationError;
use crate::script::op::{OP_16, OP_2DIV, OP_2MUL, OP_NOP2, OP_VERIF, OP_VERNOTIF};

use super::Spend;

/// `MAX_SCRIPT_ELEMENT_SIZE_BEFORE_GENESIS` (`src/script/script.h:29`).
const ELEMENT: usize = 520;
/// [`ELEMENT`] as a script number's value.
const ELEMENT_VALUE: i64 = 520;
/// `MAX_STACK_ELEMENTS_BEFORE_GENESIS` (`src/script/script.h:32`).
const STACK: usize = 1_000;
/// `MAX_OPS_PER_SCRIPT_BEFORE_GENESIS` (`src/consensus/consensus.h:40`).
const OPS: u64 = 500;
/// `MAX_PUBKEYS_PER_MULTISIG_BEFORE_GENESIS` (`src/consensus/consensus.h:50`).
const KEYS: i64 = 20;
/// `MAX_SCRIPT_SIZE_BEFORE_GENESIS` (`src/consensus/consensus.h:58`).
#[cfg(feature = "transaction")]
const SCRIPT: usize = 10_000;
/// `MAX_SCRIPT_NUM_LENGTH_BEFORE_GENESIS` (`src/consensus/consensus.h:62`).
pub(super) const NUMBER: usize = 4;
/// The lock-time operands' length (`interpreter.cpp:542`, `576`).
const LOCK_TIME_NUMBER: usize = 5;
/// `LOCKTIME_THRESHOLD` (`src/script/script.h:40`).
const LOCKTIME_THRESHOLD: i64 = 500_000_000;
/// `CTxIn::SEQUENCE_FINAL`, `SEQUENCE_LOCKTIME_DISABLE_FLAG`,
/// `SEQUENCE_LOCKTIME_TYPE_FLAG`, `SEQUENCE_LOCKTIME_MASK`
/// (`src/primitives/transaction.h`).
const SEQUENCE_FINAL: u32 = 0xffff_ffff;
const DISABLE_FLAG: i64 = 1 << 31;
const TYPE_FLAG: i64 = 1 << 22;
const MASK: i64 = 0xffff;

impl Spend {
    /// Judges the coin as one created before Genesis: the refusals above, in
    /// the default mode (a word carries its own era), and the opcodes of a
    /// coin from before Chronicle.
    #[cfg_attr(not(feature = "transaction"), allow(dead_code))]
    pub(crate) fn set_pre_genesis(&mut self) {
        self.pre_genesis = Some(0);
        self.utxo_after_chronicle = false;
        self.chronicle_opcodes = false;
    }

    /// The coin is judged as one from before Genesis.
    pub(super) fn pre_genesis(&self) -> bool {
        self.pre_genesis.is_some() && self.flags.is_none()
    }

    fn pre_genesis_error(&self, rule: &str) -> ScriptEvaluationError {
        self.error(&format!("A coin created before Genesis: {rule}"))
    }

    /// The checks before an operation runs, executed or not: its push's
    /// size, the opcode count, the opcodes that are refused in every branch.
    pub(super) fn pre_genesis_before(
        &mut self,
        opcode: u8,
        data: Option<&[u8]>,
    ) -> Result<(), ScriptEvaluationError> {
        if !self.pre_genesis() {
            return Ok(());
        }
        if self.program_counter == 0 {
            self.pre_genesis_next_script();
        }
        if let Some(len) = data.map(<[u8]>::len).filter(|len| *len > ELEMENT) {
            return Err(self.pre_genesis_error(&format!(
                "a push of {len} bytes exceeds {ELEMENT} bytes (SCRIPT_ERR_PUSH_SIZE)."
            )));
        }
        if opcode > OP_16 {
            self.count_operations(1)?;
        }
        if matches!(opcode, OP_VERIF | OP_VERNOTIF) {
            return Err(self.pre_genesis_error(
                "OP_VERIF and OP_VERNOTIF are bad opcodes in every branch (SCRIPT_ERR_BAD_OPCODE).",
            ));
        }
        if matches!(opcode, OP_2MUL | OP_2DIV) {
            return Err(self.pre_genesis_error(
                "OP_2MUL and OP_2DIV are disabled in every branch (SCRIPT_ERR_DISABLED_OPCODE).",
            ));
        }
        Ok(())
    }

    fn count_operations(&mut self, more: u64) -> Result<(), ScriptEvaluationError> {
        let Some(count) = self.pre_genesis.as_mut() else {
            return Ok(());
        };
        *count = count.saturating_add(more);
        if *count > OPS {
            return Err(self.pre_genesis_error(&format!(
                "more than {OPS} opcodes in one script (SCRIPT_ERR_OP_COUNT)."
            )));
        }
        Ok(())
    }

    /// The count of opcodes starts again with each script.
    fn pre_genesis_next_script(&mut self) {
        if let Some(count) = self.pre_genesis.as_mut() {
            *count = 0;
        }
    }

    /// The check after an operation: both stacks together.
    pub(super) fn pre_genesis_after(&self) -> Result<(), ScriptEvaluationError> {
        let elements = self.stack.len() + self.alt_stack.len();
        if self.pre_genesis() && elements > STACK {
            return Err(self.pre_genesis_error(&format!(
                "{elements} stack elements exceed {STACK} (SCRIPT_ERR_STACK_SIZE)."
            )));
        }
        Ok(())
    }

    /// An element an opcode would build: `OP_CAT`'s result, `OP_NUM2BIN`'s size.
    pub(super) fn pre_genesis_element(&self, size: i64) -> Result<(), ScriptEvaluationError> {
        if self.pre_genesis() && !(0..=ELEMENT_VALUE).contains(&size) {
            return Err(self.pre_genesis_error(&format!(
                "an element of {size} bytes is outside 0 to {ELEMENT} bytes (SCRIPT_ERR_PUSH_SIZE)."
            )));
        }
        Ok(())
    }

    /// `OP_CHECKMULTISIG`'s key count: at most 20, counted as opcodes.
    pub(super) fn pre_genesis_keys(&mut self, keys: i64) -> Result<(), ScriptEvaluationError> {
        if !self.pre_genesis() {
            return Ok(());
        }
        if keys > KEYS {
            return Err(self.pre_genesis_error(&format!(
                "{keys} keys exceed {KEYS} (SCRIPT_ERR_PUBKEY_COUNT)."
            )));
        }
        self.count_operations(keys.unsigned_abs())
    }

    /// An executed `OP_CHECKLOCKTIMEVERIFY` (`OP_NOP2`) or
    /// `OP_CHECKSEQUENCEVERIFY` (`OP_NOP3`): BIP65 and BIP112 against this
    /// input (`CheckLockTime`, `CheckSequence`, `interpreter.cpp:2165-2235`).
    pub(super) fn pre_genesis_lock_time(&self, opcode: u8) -> Result<(), ScriptEvaluationError> {
        let top = self.stack.last().ok_or_else(|| {
            self.pre_genesis_error("the lock-time opcodes need an item on the stack (SCRIPT_ERR_INVALID_STACK_OPERATION).")
        })?;
        let operand = self
            .read_number_within(top, 0, Some(LOCK_TIME_NUMBER))?
            .to_i64()
            .unwrap_or(-1);
        if operand < 0 {
            return Err(
                self.pre_genesis_error("a negative lock time (SCRIPT_ERR_NEGATIVE_LOCKTIME).")
            );
        }
        let sequence = self
            .transaction
            .inputs()
            .get(self.input_index)
            .map_or(SEQUENCE_FINAL, |input| input.sequence);
        let satisfied = if opcode == OP_NOP2 {
            let lock_time = i64::from(self.transaction.locktime());
            (lock_time < LOCKTIME_THRESHOLD) == (operand < LOCKTIME_THRESHOLD)
                && operand <= lock_time
                && sequence != SEQUENCE_FINAL
        } else if operand & DISABLE_FLAG != 0 {
            true
        } else {
            let sequence = i64::from(sequence);
            u32::from_ne_bytes(self.transaction.version().to_ne_bytes()) >= 2
                && sequence & DISABLE_FLAG == 0
                && (operand & TYPE_FLAG) == (sequence & TYPE_FLAG)
                && (operand & (TYPE_FLAG | MASK)) <= (sequence & (TYPE_FLAG | MASK))
        };
        if satisfied {
            Ok(())
        } else {
            Err(self.pre_genesis_error(
                "the lock time is not satisfied (SCRIPT_ERR_UNSATISFIED_LOCKTIME).",
            ))
        }
    }

    /// An executed `OP_RETURN` fails the script.
    pub(super) fn pre_genesis_return(&self) -> Result<(), ScriptEvaluationError> {
        if self.pre_genesis() {
            return Err(self.pre_genesis_error(
                "an executed OP_RETURN fails the script (SCRIPT_ERR_OP_RETURN).",
            ));
        }
        Ok(())
    }
}

/// The second evaluation, at the doors that prove a coin's height.
#[cfg(feature = "transaction")]
mod driver {
    use std::sync::Arc;

    use crate::primitives::bsv::sighash::TxSighashCache;
    use crate::script::evaluation_error::{ExecutionContext, ScriptEvaluationError};
    use crate::script::p2sh_redeem::Redeem;
    use crate::script::{LockingScript, UnlockingScript};

    use super::super::{Spend, TxSpendParams};
    use super::SCRIPT;

    impl Spend {
        /// The second evaluation a door runs for an input whose coin it proves
        /// was created before the chain's Genesis height, after the default mode
        /// has judged the input valid: the same input in the default mode, judged
        /// as a coin of that era. `None` when it holds; else its refusal. It
        /// charges no work: the rules it adds bound it.
        pub(crate) fn pre_genesis_refusal(
            transaction: &Arc<TxSighashCache>,
            input_index: usize,
            locking: &[u8],
            unlocking: &[u8],
            source_satoshis: u64,
            memory_limit: Option<usize>,
        ) -> Option<ScriptEvaluationError> {
            if locking.len() > SCRIPT || unlocking.len() > SCRIPT {
                return Some(refusal(&format!(
                    "A coin created before Genesis: a script exceeds {SCRIPT} bytes (SCRIPT_ERR_SCRIPT_SIZE)."
                )));
            }
            let built = LockingScript::from_binary(locking).and_then(|locking_script| {
                let params = TxSpendParams {
                    transaction: Arc::clone(transaction),
                    input_index,
                    source_satoshis,
                    locking_script,
                    unlocking_script: UnlockingScript::from_binary(unlocking)?,
                    memory_limit,
                    work_limit: None,
                };
                let step = Redeem::of(locking, unlocking, &params, true);
                Ok((step, Spend::with_transaction(params)?))
            });
            let (step, mut spend) = match built {
                Ok(built) => built,
                Err(error) => return Some(refusal(&error.to_string())),
            };
            spend.set_pre_genesis();
            match Redeem::judge(step, spend, Spend::set_pre_genesis).0 {
                Ok(true) => None,
                Ok(false) => Some(refusal(
                    "A coin created before Genesis: the script did not succeed.",
                )),
                Err(error) => Some(error),
            }
        }
    }

    fn refusal(message: &str) -> ScriptEvaluationError {
        let context = ExecutionContext::LockingScript;
        ScriptEvaluationError::new(message, "", 0, context, 0, vec![], vec![], vec![], 0, 0)
    }
}
