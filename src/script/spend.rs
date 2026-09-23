//! Bitcoin Script interpreter for spend validation.
//!
// Allow large error type - ScriptEvaluationError intentionally captures full
// execution state for debugging failed script executions.
#![allow(clippy::result_large_err)]
//!
//! This module implements the full Bitcoin Script interpreter for BSV, enabling
//! validation of transaction spends by executing unlocking and locking scripts.
//!
//! # Two ways to run it
//!
//! Without a flag word, [`Spend`] runs the TypeScript SDK's default evaluation
//! mode: strict for a transaction of version 1 or lower (minimal pushes and
//! numbers, low-S, a clean stack, an empty CHECKMULTISIG dummy), relaxed for
//! version 2 and above, push-only unlocking scripts at every version, and no
//! NULLFAIL rule. That mode is neither of the words a node validates under.
//!
//! With [`Spend::set_flags`], every rule is derived from a
//! [`ScriptFlags`] word and the transaction version
//! exactly as bitcoin-sv v1.2.2 derives it at each site: the block word
//! ([`ScriptFlags::block`]) is what a mining
//! node applies, the standard word
//! ([`ScriptFlags::standard`]) is what a
//! relaying node with default policy applies. A consensus oracle selects the
//! block word. The `flags` module documents every rule, its gate and its site.
//!
//! # Example
//!
//! ```rust,ignore
//! use bsv_rs::script::{Spend, LockingScript, UnlockingScript};
//!
//! let spend = Spend::new(SpendParams {
//!     source_txid: [0u8; 32],
//!     source_output_index: 0,
//!     source_satoshis: 100_000,
//!     locking_script: LockingScript::from_asm("OP_DUP OP_HASH160 ... OP_CHECKSIG")?,
//!     transaction_version: 1,
//!     other_inputs: vec![],
//!     outputs: vec![],
//!     input_index: 0,
//!     unlocking_script: UnlockingScript::from_asm("<sig> <pubkey>")?,
//!     input_sequence: 0xffffffff,
//!     lock_time: 0,
//!     memory_limit: None,
//! });
//!
//! let valid = spend.validate()?;
//! ```

use super::evaluation_error::{
    ExecutionContext, ScriptEvaluationError, ScriptResource, ScriptResourceLimit,
};
use super::flags::{Gates, ScriptFlags};
use super::op::*;
use super::script_num::ScriptNum;
use super::{LockingScript, Script, ScriptChunk, UnlockingScript};
use crate::primitives::bsv::sighash::{
    compute_sighash_for_signing, SighashParams, TxInput, TxOutput, SIGHASH_FORKID,
};
use crate::primitives::bsv::tx_signature::TransactionSignature;
use crate::primitives::ec::PublicKey;
use crate::primitives::{hash160, ripemd160, sha1, sha256, sha256d, to_hex, BigNumber};

// ============================================================================
// Configuration Constants
// ============================================================================

/// Maximum size of a single script element (1GB for BSV unlimited)
const MAX_SCRIPT_ELEMENT_SIZE: usize = 1024 * 1024 * 1024;

/// Default memory limit for stack usage (32MB)
const DEFAULT_MEMORY_LIMIT: usize = 32_000_000;

/// Maximum number of keys in a multisig (i32::MAX for BSV)
const MAX_MULTISIG_KEY_COUNT: i64 = i32::MAX as i64;

/// Require minimal push encoding
const REQUIRE_MINIMAL_PUSH: bool = true;

/// Require push-only unlocking scripts
const REQUIRE_PUSH_ONLY_UNLOCKING: bool = true;

/// Require low-S signatures
const REQUIRE_LOW_S_SIGNATURES: bool = true;

/// Require clean stack after execution
const REQUIRE_CLEAN_STACK: bool = true;

// ============================================================================
// Pre-computed Script Numbers
// ============================================================================

lazy_static::lazy_static! {
    /// Pre-computed script number for -1
    static ref SCRIPTNUM_NEG_1: Vec<u8> = ScriptNum::to_bytes(&BigNumber::from_i64(-1));

    /// Pre-computed script numbers for 0-16
    static ref SCRIPTNUMS_0_TO_16: Vec<Vec<u8>> = (0..=16)
        .map(|i| ScriptNum::to_bytes(&BigNumber::from_i64(i)))
        .collect();
}

// ============================================================================
// Spend Parameters
// ============================================================================

/// Parameters for constructing a Spend validator.
pub struct SpendParams {
    /// The transaction ID of the source UTXO (32 bytes, internal byte order).
    pub source_txid: [u8; 32],
    /// The index of the output in the source transaction.
    pub source_output_index: u32,
    /// The satoshi value of the source UTXO.
    pub source_satoshis: u64,
    /// The locking script of the source UTXO.
    pub locking_script: LockingScript,
    /// The version of the spending transaction.
    pub transaction_version: i32,
    /// Other inputs in the spending transaction (excluding this one).
    pub other_inputs: Vec<TxInput>,
    /// Outputs of the spending transaction.
    pub outputs: Vec<TxOutput>,
    /// The index of this input in the spending transaction.
    pub input_index: usize,
    /// The unlocking script for this spend.
    pub unlocking_script: UnlockingScript,
    /// The sequence number of this input.
    pub input_sequence: u32,
    /// The lock time of the spending transaction.
    pub lock_time: u32,
    /// Optional memory limit in bytes (default: 32MB).
    pub memory_limit: Option<usize>,
}

// ============================================================================
// Spend Struct
// ============================================================================

/// The Spend struct represents a spend action and validates it by executing
/// the unlocking and locking scripts.
pub struct Spend {
    // Transaction context
    source_txid: [u8; 32],
    source_output_index: u32,
    source_satoshis: u64,
    locking_script: LockingScript,
    transaction_version: i32,
    other_inputs: Vec<TxInput>,
    outputs: Vec<TxOutput>,
    input_index: usize,
    unlocking_script: UnlockingScript,
    input_sequence: u32,
    lock_time: u32,

    // Execution state
    context: ExecutionContext,
    program_counter: usize,
    last_code_separator: Option<usize>,
    stack: Vec<Vec<u8>>,
    alt_stack: Vec<Vec<u8>>,
    if_stack: Vec<bool>,
    memory_limit: usize,
    stack_mem: usize,
    alt_stack_mem: usize,
    require_push_only: bool,
    require_minimal: bool,
    require_low_s: bool,
    require_clean_stack: bool,
    require_null_dummy: bool,
    require_null_fail: bool,
    require_minimal_if: bool,
    require_compressed_pubkey: bool,
    discourage_upgradable_nops: bool,
    /// The flag word the rules above were derived from, if `set_flags` was
    /// called; `None` in the TypeScript default mode.
    flags: Option<ScriptFlags>,
    /// The UTXO being spent is taken as created after Chronicle: `OP_2MUL`,
    /// `OP_2DIV`, `OP_VER`, `OP_VERIF`, `OP_VERNOTIF` and the Chronicle
    /// meanings of `0xb3`-`0xb7` follow it (`interpreter.cpp:360-375`,
    /// `598-812`). Default: the TypeScript SDK's `isAfterChronicle()`, which
    /// is `isRelaxed()`, version > 1; under a word, its `UTXO_AFTER_CHRONICLE`.
    utxo_after_chronicle: bool,
    /// Whether an `OP_ELSE` was seen at each conditional depth (the
    /// reference's `conditional_tracker`: a second `OP_ELSE` for one `OP_IF`
    /// is unbalanced after Genesis, `interpreter.cpp:829-831`).
    else_stack: Vec<bool>,
    /// A non-top-level `OP_RETURN` executed after Genesis: execution stops,
    /// the walk continues for the conditional balance and the parse
    /// (`interpreter.cpp:856-871` with `482`).
    returning: bool,
    /// The chunk index of a push that declares more bytes than the script
    /// holds, per script (`Script::truncated_push`): reaching it is
    /// `SCRIPT_ERR_BAD_OPCODE` on the reference.
    unlocking_truncated: Option<usize>,
    locking_truncated: Option<usize>,

    // Parsed-chunk caches. `Script::chunks()` deep-clones the whole chunk
    // vector; calling it from `step()` made execution O(N²) in script size,
    // which is prohibitive for large covenant scripts (a ~500 KB script
    // would take hours). Cached once here; `step()` indexes the cache.
    unlocking_chunks: Vec<crate::script::chunk::ScriptChunk>,
    locking_chunks: Vec<crate::script::chunk::ScriptChunk>,
}

impl Spend {
    /// Creates a new Spend validator from the given parameters.
    pub fn new(params: SpendParams) -> Self {
        let mut spend = Self {
            source_txid: params.source_txid,
            source_output_index: params.source_output_index,
            source_satoshis: params.source_satoshis,
            locking_script: params.locking_script,
            transaction_version: params.transaction_version,
            other_inputs: params.other_inputs,
            outputs: params.outputs,
            input_index: params.input_index,
            unlocking_script: params.unlocking_script,
            input_sequence: params.input_sequence,
            lock_time: params.lock_time,
            context: ExecutionContext::UnlockingScript,
            program_counter: 0,
            unlocking_chunks: Vec::new(),
            locking_chunks: Vec::new(),
            last_code_separator: None,
            stack: Vec::new(),
            alt_stack: Vec::new(),
            if_stack: Vec::new(),
            memory_limit: params.memory_limit.unwrap_or(DEFAULT_MEMORY_LIMIT),
            stack_mem: 0,
            alt_stack_mem: 0,
            require_push_only: REQUIRE_PUSH_ONLY_UNLOCKING,
            // ts-sdk parity: transactions with version > 1 run "relaxed"
            // (post-Genesis semantics) — MINIMALDATA, LOW_S, CLEANSTACK and
            // NULLDUMMY are not enforced (mirrors ts-sdk Spend.isRelaxed() and
            // its shouldEnforceNullDummy()). The reference gates the same four
            // on the version at Chronicle (`interpreter.cpp:40-44`).
            require_minimal: REQUIRE_MINIMAL_PUSH && params.transaction_version <= 1,
            require_low_s: REQUIRE_LOW_S_SIGNATURES && params.transaction_version <= 1,
            require_clean_stack: REQUIRE_CLEAN_STACK && params.transaction_version <= 1,
            require_null_dummy: params.transaction_version <= 1,
            // Not in the ts-sdk default mode (its NULLFAIL, MINIMALIF and
            // DISCOURAGE_UPGRADABLE_NOPS exist only under explicit verifyFlags);
            // derived from a word by `set_flags`.
            require_null_fail: false,
            require_minimal_if: false,
            require_compressed_pubkey: false,
            discourage_upgradable_nops: false,
            flags: None,
            // ts-sdk parity: isAfterChronicle() is isRelaxed() without explicit flags.
            utxo_after_chronicle: params.transaction_version > 1,
            else_stack: Vec::new(),
            returning: false,
            unlocking_truncated: None,
            locking_truncated: None,
        };
        spend.unlocking_chunks = spend.unlocking_script.chunks();
        spend.locking_chunks = spend.locking_script.chunks();
        spend.unlocking_truncated = spend.unlocking_script.as_script().truncated_push();
        spend.locking_truncated = spend.locking_script.as_script().truncated_push();
        spend.reset();
        spend
    }

    /// Overrides MINIMALDATA enforcement (script-number and push minimality).
    ///
    /// Default follows ts-sdk: enforced for version <= 1 transactions, relaxed
    /// for version > 1 (post-Genesis semantics). Called after [`set_flags`](Self::set_flags),
    /// it overrides the rule the word derived.
    pub fn set_require_minimal(&mut self, require: bool) {
        self.require_minimal = require;
    }

    /// Allows opting out of the push-only unlocking-script check.
    ///
    /// The TypeScript `@bsv/sdk` Spend engine does not enforce push-only
    /// unlocking scripts; some OP_PUSH_TX-style covenant designs place
    /// executable code in the unlocking script and verify under that engine.
    /// Default remains `true` (enforced). Called after [`set_flags`](Self::set_flags),
    /// it overrides the rule the word derived (the reference requires push-only
    /// unlocking scripts post-Chronicle only for version <= 1).
    pub fn set_require_push_only(&mut self, require: bool) {
        self.require_push_only = require;
    }

    /// Applies a verification flag word: every rule this interpreter enforces
    /// is re-derived from `flags` and the transaction version exactly as
    /// bitcoin-sv v1.2.2 derives it at the rule's site, including its version
    /// gate `EnforceNonMalleability` (`interpreter.cpp:40-44`; the table on
    /// [`ScriptFlags`]). The TypeScript default mode's switches are replaced,
    /// not merged; `set_require_minimal` and `set_require_push_only` override
    /// a derived rule when called afterwards.
    ///
    /// A consensus oracle selects the block word:
    ///
    /// ```rust,ignore
    /// spend.set_flags(ScriptFlags::block(ProtocolEra::PostChronicle));
    /// ```
    ///
    /// A word this interpreter cannot honor ([`ScriptFlags::check`]) is
    /// accepted here and refused by [`validate`](Self::validate), as the
    /// reference refuses an invalid word at `VerifyScript`
    /// (`interpreter.cpp:2312-2313`).
    pub fn set_flags(&mut self, flags: ScriptFlags) {
        let Gates {
            push_only,
            minimal,
            low_s,
            clean_stack,
            null_dummy,
            null_fail,
            minimal_if,
            discourage_upgradable_nops,
            compressed_pubkey,
            utxo_after_chronicle,
        } = flags.gates(self.transaction_version);
        self.require_push_only = push_only;
        self.require_minimal = minimal;
        self.require_low_s = low_s;
        self.require_clean_stack = clean_stack;
        self.require_null_dummy = null_dummy;
        self.require_null_fail = null_fail;
        self.require_minimal_if = minimal_if;
        self.discourage_upgradable_nops = discourage_upgradable_nops;
        self.require_compressed_pubkey = compressed_pubkey;
        self.utxo_after_chronicle = utxo_after_chronicle;
        self.flags = Some(flags);
    }

    /// Overrides the UTXO's era for the re-enabled opcodes: `true` runs
    /// `OP_2MUL`, `OP_2DIV`, `OP_VER`, `OP_VERIF`, `OP_VERNOTIF` and the
    /// Chronicle meanings of `0xb3`-`0xb7` (a coin created after Chronicle),
    /// `false` keeps them disabled, `BAD_OPCODE` or NOPs as before it. Default:
    /// version > 1 (the TypeScript SDK's `isAfterChronicle()`); under a word,
    /// its `UTXO_AFTER_CHRONICLE` bit. Called after [`set_flags`](Self::set_flags),
    /// it overrides the bit.
    pub fn set_utxo_after_chronicle(&mut self, after: bool) {
        self.utxo_after_chronicle = after;
    }

    /// The flag word applied by [`set_flags`](Self::set_flags), or `None` in
    /// the TypeScript default mode.
    pub fn flags(&self) -> Option<ScriptFlags> {
        self.flags
    }

    /// Resets the interpreter state for re-execution.
    pub fn reset(&mut self) {
        self.context = ExecutionContext::UnlockingScript;
        self.program_counter = 0;
        self.last_code_separator = None;
        self.stack.clear();
        self.alt_stack.clear();
        self.if_stack.clear();
        self.else_stack.clear();
        self.returning = false;
        self.stack_mem = 0;
        self.alt_stack_mem = 0;
    }

    /// Validates the spend by executing both scripts.
    ///
    /// # Returns
    ///
    /// `Ok(true)` if the spend is valid, or an error describing why validation failed.
    pub fn validate(&mut self) -> Result<bool, ScriptEvaluationError> {
        // A word this interpreter cannot honor, or one the reference refuses
        // (`SCRIPT_ERR_INVALID_FLAGS`, interpreter.cpp:2312-2313, 2436-2437).
        if let Some(flags) = self.flags {
            if let Err(e) = flags.check() {
                return Err(self.error(&format!("Invalid verification flags: {e}.")));
            }
        }

        // Check that unlocking script is push-only
        if self.require_push_only && !self.unlocking_script.is_push_only() {
            return Err(self.error(
                "Unlocking scripts can only contain push operations, and no other opcodes.",
            ));
        }

        // Execute both scripts
        while self.step()? {
            // Continue until script ends
            if self.context == ExecutionContext::LockingScript
                && self.program_counter >= self.locking_chunks.len()
            {
                break;
            }
        }

        // Verify if_stack is empty (all conditionals closed)
        if !self.if_stack.is_empty() {
            return Err(self.error(
                "Every OP_IF, OP_NOTIF, or OP_ELSE must be terminated with OP_ENDIF prior to the end of the script.",
            ));
        }

        // Clean stack rule
        if self.require_clean_stack && self.stack.len() != 1 {
            return Err(self.error(&format!(
                "The clean stack rule requires exactly one item to be on the stack after script execution, found {}.",
                self.stack.len()
            )));
        }

        // Top value must be truthy
        if self.stack.is_empty() {
            return Err(self.error(
                "The top stack element must be truthy after script evaluation (stack is empty).",
            ));
        }

        if !ScriptNum::cast_to_bool(&self.stack[self.stack.len() - 1]) {
            return Err(self.error("The top stack element must be truthy after script evaluation."));
        }

        Ok(true)
    }

    /// Executes a single instruction (step).
    ///
    /// # Returns
    ///
    /// `Ok(true)` if execution should continue, `Ok(false)` if the script is complete.
    pub fn step(&mut self) -> Result<bool, ScriptEvaluationError> {
        // Check memory limits — a LOCAL budget, reported as a resource limit
        // (the reference's `ScriptResourceLimitError`), never as a verdict on
        // the script.
        if self.stack_mem > self.memory_limit {
            return Err(self.resource_error(ScriptResource::Stack, self.stack_mem));
        }
        if self.alt_stack_mem > self.memory_limit {
            return Err(self.resource_error(ScriptResource::AltStack, self.alt_stack_mem));
        }

        // Switch from unlocking to locking script when unlocking is complete.
        // ts-sdk parity: conditionals must be terminated, the alt stack is
        // cleared, and the last code separator does not carry across scripts.
        if self.context == ExecutionContext::UnlockingScript
            && self.program_counter >= self.unlocking_chunks.len()
        {
            if !self.if_stack.is_empty() {
                return Err(self.error(
                    "Every OP_IF, OP_NOTIF, or OP_ELSE must be terminated with OP_ENDIF prior to the end of the unlocking script.",
                ));
            }
            self.alt_stack.clear();
            self.alt_stack_mem = 0;
            self.last_code_separator = None;
            self.else_stack.clear();
            self.returning = false;
            self.context = ExecutionContext::LockingScript;
            self.program_counter = 0;
        }

        // Get current script and check if we're done (cached chunks: the
        // per-step deep clone of the whole script was O(N²) — see field docs)
        let current_len = match self.context {
            ExecutionContext::UnlockingScript => self.unlocking_chunks.len(),
            ExecutionContext::LockingScript => self.locking_chunks.len(),
        };

        if self.program_counter >= current_len {
            return Ok(false);
        }

        let op_owned = match self.context {
            ExecutionContext::UnlockingScript => {
                self.unlocking_chunks[self.program_counter].clone()
            }
            ExecutionContext::LockingScript => self.locking_chunks[self.program_counter].clone(),
        };
        let operation = &op_owned;
        let current_opcode = operation.op;

        // A push that declares more bytes than the script holds: the reference's
        // GetOp fails and the script is SCRIPT_ERR_BAD_OPCODE when the walk
        // reaches it, executed or not (script.h:190-191, interpreter.cpp:450-451).
        let truncated = match self.context {
            ExecutionContext::UnlockingScript => self.unlocking_truncated,
            ExecutionContext::LockingScript => self.locking_truncated,
        };
        if truncated == Some(self.program_counter) {
            return Err(self.error(&format!(
                "A push declares more bytes than the script holds; the script cannot be parsed past it (pc={}).",
                self.program_counter
            )));
        }

        // Check for oversized data push
        if let Some(ref data) = operation.data {
            if data.len() > MAX_SCRIPT_ELEMENT_SIZE {
                return Err(self.error(&format!(
                    "Data push > {} bytes (pc={})",
                    MAX_SCRIPT_ELEMENT_SIZE, self.program_counter
                )));
            }
        }

        // Determine if we're currently executing (not in a false conditional branch)
        let is_executing = !self.returning && !self.if_stack.contains(&false);

        // Check for disabled opcodes when executing
        if is_executing && is_opcode_disabled(current_opcode, self.utxo_after_chronicle) {
            return Err(self.error(&format!(
                "This opcode is currently disabled. (Opcode: {}, PC: {})",
                opcode_to_name(current_opcode).unwrap_or("UNKNOWN"),
                self.program_counter
            )));
        }

        // Execute opcode
        if is_executing && current_opcode <= OP_PUSHDATA4 {
            // Push data operations
            if self.require_minimal && !is_chunk_minimal_push(operation) {
                return Err(self.error(&format!(
                    "This data is not minimally-encoded. (PC: {})",
                    self.program_counter
                )));
            }
            let data = operation.data.clone().unwrap_or_default();
            self.push_stack(data)?;
        } else if is_executing || (OP_IF..=OP_ENDIF).contains(&current_opcode) {
            // Execute the opcode
            self.execute_opcode(current_opcode, operation)?;
        }

        self.program_counter += 1;
        Ok(true)
    }

    // ========================================================================
    // Opcode Execution
    // ========================================================================

    fn execute_opcode(
        &mut self,
        opcode: u8,
        chunk: &ScriptChunk,
    ) -> Result<(), ScriptEvaluationError> {
        let is_executing = !self.returning && !self.if_stack.contains(&false);

        match opcode {
            // ================================================================
            // Push Operations (0x00-0x60)
            // ================================================================
            OP_1NEGATE => {
                self.push_stack_copy(&SCRIPTNUM_NEG_1)?;
            }
            OP_0 => {
                self.push_stack_copy(&SCRIPTNUMS_0_TO_16[0])?;
            }
            OP_1..=OP_16 => {
                let n = (opcode - OP_1 + 1) as usize;
                self.push_stack_copy(&SCRIPTNUMS_0_TO_16[n])?;
            }

            // ================================================================
            // NOPs (do nothing)
            // ================================================================
            OP_NOP => {}
            // The upgradable NOPs 0xb0-0xb9. Under DISCOURAGE_UPGRADABLE_NOPS an
            // executed one fails the script (interpreter.cpp:765-771 for NOP1,
            // NOP9, NOP10; 520-523 and 563-566 for CHECKLOCKTIMEVERIFY and
            // CHECKSEQUENCEVERIFY, NOPs for a post-Genesis UTXO; 606-700 for
            // NOP4-NOP8 before their Chronicle meanings). ts-sdk: "is
            // discouraged by verification flags".
            OP_NOP1 | OP_NOP2 | OP_NOP3 | OP_NOP9 | OP_NOP10 => {
                if self.discourage_upgradable_nops {
                    return Err(self.error(&format!(
                        "{} is discouraged by verification flags.",
                        opcode_to_name(opcode).unwrap_or("OP_NOP")
                    )));
                }
            }
            // 0xb3-0xb7: NOP4-NOP8 before Chronicle; OP_SUBSTR, OP_LEFT, OP_RIGHT,
            // OP_LSHIFTNUM, OP_RSHIFTNUM for a UTXO created after it
            // (interpreter.cpp:609-764; the NOP branch with the discouragement at
            // each arm's head).
            OP_NOP4 | OP_NOP5 | OP_NOP6 | OP_NOP7 | OP_NOP8 => {
                if !self.utxo_after_chronicle {
                    if self.discourage_upgradable_nops {
                        return Err(self.error(&format!(
                            "{} is discouraged by verification flags.",
                            opcode_to_name(opcode).unwrap_or("OP_NOP")
                        )));
                    }
                } else {
                    self.op_chronicle_splice(opcode)?;
                }
            }
            // 0xba-0xff are undefined: the reference's `default:` is
            // SCRIPT_ERR_BAD_OPCODE when one is executed (interpreter.cpp:1795),
            // and this arm is only reached when executing: they fall to the
            // invalid-opcode arm below.
            // OP_VER: the transaction version as 4 little-endian bytes for a UTXO
            // created after Chronicle (interpreter.cpp:598-608); BAD_OPCODE before.
            OP_VER => {
                if !self.utxo_after_chronicle {
                    return Err(self.error("OP_VER is disabled until Chronicle."));
                }
                self.push_stack(self.transaction_version.to_le_bytes().to_vec())?;
            }

            // ================================================================
            // Flow Control (0x63-0x6a)
            // ================================================================
            OP_IF | OP_NOTIF => {
                let mut f_value = false;
                if is_executing {
                    if self.stack.is_empty() {
                        return Err(self.error(
                            "OP_IF and OP_NOTIF require at least one item on the stack when they are used!",
                        ));
                    }
                    let buf = self.pop_stack()?;
                    // MINIMALIF (interpreter.cpp:795-803, under the version
                    // gate): the argument must be empty or exactly 0x01.
                    if self.require_minimal_if && !(buf.is_empty() || buf == [1]) {
                        return Err(self.error("OP_IF and OP_NOTIF require minimal truth values."));
                    }
                    f_value = ScriptNum::cast_to_bool(&buf);
                    if opcode == OP_NOTIF {
                        f_value = !f_value;
                    }
                }
                self.if_stack.push(f_value);
                self.else_stack.push(false);
            }
            // OP_VERIF / OP_VERNOTIF (interpreter.cpp:773-812): for a UTXO created
            // after Chronicle, a conditional on "the top element is exactly the
            // transaction version as 4 little-endian bytes"; before Chronicle,
            // skipped when not executing (post-Genesis) and BAD_OPCODE when
            // executed. This arm runs whether or not the branch executes (the
            // opcodes sit in the OP_IF..OP_ENDIF range).
            OP_VERIF | OP_VERNOTIF => {
                if !self.utxo_after_chronicle {
                    if !is_executing {
                        return Ok(());
                    }
                    return Err(self.error(&format!(
                        "{} is disabled until Chronicle.",
                        opcode_to_name(opcode).unwrap_or("OP_VERIF")
                    )));
                }
                let mut f_value = false;
                if is_executing {
                    if self.stack.is_empty() {
                        return Err(self.error(
                            "OP_VERIF and OP_VERNOTIF require at least one item on the stack when they are used!",
                        ));
                    }
                    let buf = self.pop_stack()?;
                    if buf.len() == 4 {
                        f_value = buf == self.transaction_version.to_le_bytes();
                    }
                    if opcode == OP_VERNOTIF {
                        f_value = !f_value;
                    }
                }
                self.if_stack.push(f_value);
                self.else_stack.push(false);
            }
            OP_ELSE => {
                if self.if_stack.is_empty() {
                    return Err(self.error("OP_ELSE requires a preceeding OP_IF."));
                }
                // One OP_ELSE per OP_IF after Genesis (conditional_tracker.cpp:51-55,
                // interpreter.cpp:829-831); every UTXO here is post-Genesis.
                if self.else_stack.last() == Some(&true) {
                    return Err(self.error(
                        "OP_ELSE may only be used once for each OP_IF or OP_NOTIF after Genesis.",
                    ));
                }
                if let Some(seen) = self.else_stack.last_mut() {
                    *seen = true;
                }
                let last = self.if_stack.len() - 1;
                self.if_stack[last] = !self.if_stack[last];
            }
            OP_ENDIF => {
                if self.if_stack.is_empty() {
                    return Err(self.error("OP_ENDIF requires a preceeding OP_IF."));
                }
                self.if_stack.pop();
                self.else_stack.pop();
            }
            OP_VERIFY => {
                if self.stack.is_empty() {
                    return Err(
                        self.error("OP_VERIFY requires at least one item to be on the stack.")
                    );
                }
                let f_value = ScriptNum::cast_to_bool(self.stack_top()?);
                if !f_value {
                    return Err(self.error("OP_VERIFY requires the top stack value to be truthy."));
                }
                self.pop_stack()?;
            }
            OP_RETURN => {
                // After Genesis (interpreter.cpp:856-871): at the top level the
                // script ends successfully, whatever follows; inside a conditional,
                // execution stops but the walk continues, so the conditionals must
                // still balance and every later opcode must still parse (`482`).
                if self.if_stack.is_empty() {
                    let end = match self.context {
                        ExecutionContext::UnlockingScript => self.unlocking_chunks.len(),
                        ExecutionContext::LockingScript => self.locking_chunks.len(),
                    };
                    self.program_counter = end;
                    // Counteract the final increment
                    if self.program_counter > 0 {
                        self.program_counter -= 1;
                    }
                } else {
                    self.returning = true;
                }
            }

            // ================================================================
            // Stack Operations (0x6b-0x7d)
            // ================================================================
            OP_TOALTSTACK => {
                if self.stack.is_empty() {
                    return Err(
                        self.error("OP_TOALTSTACK requires at least one item to be on the stack.")
                    );
                }
                let item = self.pop_stack()?;
                self.push_alt_stack(item)?;
            }
            OP_FROMALTSTACK => {
                if self.alt_stack.is_empty() {
                    return Err(self.error(
                        "OP_FROMALTSTACK requires at least one item to be on the alt stack.",
                    ));
                }
                let item = self.pop_alt_stack()?;
                self.push_stack(item)?;
            }
            OP_2DROP => {
                if self.stack.len() < 2 {
                    return Err(
                        self.error("OP_2DROP requires at least two items to be on the stack.")
                    );
                }
                self.pop_stack()?;
                self.pop_stack()?;
            }
            OP_2DUP => {
                if self.stack.len() < 2 {
                    return Err(
                        self.error("OP_2DUP requires at least two items to be on the stack.")
                    );
                }
                let buf1 = self.stack_top_n(2)?.to_vec();
                let buf2 = self.stack_top()?.to_vec();
                self.push_stack(buf1)?;
                self.push_stack(buf2)?;
            }
            OP_3DUP => {
                if self.stack.len() < 3 {
                    return Err(
                        self.error("OP_3DUP requires at least three items to be on the stack.")
                    );
                }
                let buf1 = self.stack_top_n(3)?.to_vec();
                let buf2 = self.stack_top_n(2)?.to_vec();
                let buf3 = self.stack_top()?.to_vec();
                self.push_stack(buf1)?;
                self.push_stack(buf2)?;
                self.push_stack(buf3)?;
            }
            OP_2OVER => {
                if self.stack.len() < 4 {
                    return Err(
                        self.error("OP_2OVER requires at least four items to be on the stack.")
                    );
                }
                let buf1 = self.stack_top_n(4)?.to_vec();
                let buf2 = self.stack_top_n(3)?.to_vec();
                self.push_stack(buf1)?;
                self.push_stack(buf2)?;
            }
            OP_2ROT => {
                if self.stack.len() < 6 {
                    return Err(
                        self.error("OP_2ROT requires at least six items to be on the stack.")
                    );
                }
                let x6 = self.pop_stack()?;
                let x5 = self.pop_stack()?;
                let x4 = self.pop_stack()?;
                let x3 = self.pop_stack()?;
                let x2 = self.pop_stack()?;
                let x1 = self.pop_stack()?;
                self.push_stack(x3)?;
                self.push_stack(x4)?;
                self.push_stack(x5)?;
                self.push_stack(x6)?;
                self.push_stack(x1)?;
                self.push_stack(x2)?;
            }
            OP_2SWAP => {
                if self.stack.len() < 4 {
                    return Err(
                        self.error("OP_2SWAP requires at least four items to be on the stack.")
                    );
                }
                let x4 = self.pop_stack()?;
                let x3 = self.pop_stack()?;
                let x2 = self.pop_stack()?;
                let x1 = self.pop_stack()?;
                self.push_stack(x3)?;
                self.push_stack(x4)?;
                self.push_stack(x1)?;
                self.push_stack(x2)?;
            }
            OP_IFDUP => {
                if self.stack.is_empty() {
                    return Err(
                        self.error("OP_IFDUP requires at least one item to be on the stack.")
                    );
                }
                let top = self.stack_top()?.to_vec();
                if ScriptNum::cast_to_bool(&top) {
                    self.push_stack(top)?;
                }
            }
            OP_DEPTH => {
                let depth = BigNumber::from_u64(self.stack.len() as u64);
                self.push_stack(ScriptNum::to_bytes(&depth))?;
            }
            OP_DROP => {
                if self.stack.is_empty() {
                    return Err(
                        self.error("OP_DROP requires at least one item to be on the stack.")
                    );
                }
                self.pop_stack()?;
            }
            OP_DUP => {
                if self.stack.is_empty() {
                    return Err(self.error("OP_DUP requires at least one item to be on the stack."));
                }
                let top = self.stack_top()?.to_vec();
                self.push_stack(top)?;
            }
            OP_NIP => {
                if self.stack.len() < 2 {
                    return Err(
                        self.error("OP_NIP requires at least two items to be on the stack.")
                    );
                }
                let top = self.pop_stack()?;
                self.pop_stack()?;
                self.push_stack(top)?;
            }
            OP_OVER => {
                if self.stack.len() < 2 {
                    return Err(
                        self.error("OP_OVER requires at least two items to be on the stack.")
                    );
                }
                let second = self.stack_top_n(2)?.to_vec();
                self.push_stack(second)?;
            }
            OP_PICK | OP_ROLL => {
                if self.stack.len() < 2 {
                    return Err(self.error(&format!(
                        "{} requires at least two items to be on the stack.",
                        opcode_to_name(opcode).unwrap_or("OP_PICK/ROLL")
                    )));
                }
                let n_bytes = self.pop_stack()?;
                let bn = ScriptNum::from_bytes(&n_bytes, self.require_minimal)
                    .map_err(|e| self.error(&format!("Invalid script number: {}", e)))?;

                let n = bn.to_i64().unwrap_or(i64::MAX);
                if n < 0 || n >= self.stack.len() as i64 {
                    return Err(self.error(&format!(
                        "{} requires the top stack element to be 0 or a positive number less than the current size of the stack.",
                        opcode_to_name(opcode).unwrap_or("OP_PICK/ROLL")
                    )));
                }

                let n_idx = n as usize;
                let item = self.stack[self.stack.len() - 1 - n_idx].clone();

                if opcode == OP_ROLL {
                    let remove_idx = self.stack.len() - 1 - n_idx;
                    let removed = self.stack.remove(remove_idx);
                    self.stack_mem -= removed.len();
                    self.push_stack(item)?;
                } else {
                    // OP_PICK
                    self.push_stack(item)?;
                }
            }
            OP_ROT => {
                if self.stack.len() < 3 {
                    return Err(
                        self.error("OP_ROT requires at least three items to be on the stack.")
                    );
                }
                let x3 = self.pop_stack()?;
                let x2 = self.pop_stack()?;
                let x1 = self.pop_stack()?;
                self.push_stack(x2)?;
                self.push_stack(x3)?;
                self.push_stack(x1)?;
            }
            OP_SWAP => {
                if self.stack.len() < 2 {
                    return Err(
                        self.error("OP_SWAP requires at least two items to be on the stack.")
                    );
                }
                let x2 = self.pop_stack()?;
                let x1 = self.pop_stack()?;
                self.push_stack(x2)?;
                self.push_stack(x1)?;
            }
            OP_TUCK => {
                if self.stack.len() < 2 {
                    return Err(
                        self.error("OP_TUCK requires at least two items to be on the stack.")
                    );
                }
                let top = self.stack_top()?.to_vec();
                self.ensure_stack_mem(top.len())?;
                let insert_idx = self.stack.len() - 2;
                self.stack.insert(insert_idx, top.clone());
                self.stack_mem += top.len();
            }
            OP_SIZE => {
                if self.stack.is_empty() {
                    return Err(
                        self.error("OP_SIZE requires at least one item to be on the stack.")
                    );
                }
                let size = self.stack_top()?.len();
                let bn = BigNumber::from_u64(size as u64);
                self.push_stack(ScriptNum::to_bytes(&bn))?;
            }

            // ================================================================
            // Splice Operations (BSV re-enabled)
            // ================================================================
            OP_CAT => {
                if self.stack.len() < 2 {
                    return Err(
                        self.error("OP_CAT requires at least two items to be on the stack.")
                    );
                }
                let buf2 = self.pop_stack()?;
                let buf1 = self.pop_stack()?;
                let mut result = buf1;
                result.extend(buf2);
                if result.len() > MAX_SCRIPT_ELEMENT_SIZE {
                    return Err(self.error(&format!(
                        "It's not currently possible to push data larger than {} bytes.",
                        MAX_SCRIPT_ELEMENT_SIZE
                    )));
                }
                self.push_stack(result)?;
            }
            OP_SPLIT => {
                if self.stack.len() < 2 {
                    return Err(
                        self.error("OP_SPLIT requires at least two items to be on the stack.")
                    );
                }
                let pos_bytes = self.pop_stack()?;
                let data = self.pop_stack()?;

                let pos_bn = ScriptNum::from_bytes(&pos_bytes, self.require_minimal)
                    .map_err(|e| self.error(&format!("Invalid script number: {}", e)))?;
                let pos = pos_bn.to_i64().unwrap_or(-1);

                if pos < 0 || pos > data.len() as i64 {
                    return Err(self.error(
                        "OP_SPLIT requires the first stack item to be a non-negative number less than or equal to the size of the second-from-top stack item.",
                    ));
                }

                let split_idx = pos as usize;
                let left = data[..split_idx].to_vec();
                let right = data[split_idx..].to_vec();
                self.push_stack(left)?;
                self.push_stack(right)?;
            }
            OP_NUM2BIN => {
                if self.stack.len() < 2 {
                    return Err(
                        self.error("OP_NUM2BIN requires at least two items to be on the stack.")
                    );
                }
                let size_bytes = self.pop_stack()?;
                let size_bn = ScriptNum::from_bytes(&size_bytes, self.require_minimal)
                    .map_err(|e| self.error(&format!("Invalid script number: {}", e)))?;
                let size = size_bn.to_i64().unwrap_or(-1);

                if size < 0 || size > MAX_SCRIPT_ELEMENT_SIZE as i64 {
                    return Err(self.error(&format!(
                        "It's not currently possible to push data larger than {} bytes or negative size.",
                        MAX_SCRIPT_ELEMENT_SIZE
                    )));
                }
                let size = size as usize;
                // Reference parity (0.3.23): the element the script asks for is
                // refused BEFORE it is allocated when it alone exceeds the
                // local memory budget — the TypeScript SDK's `element-size`
                // resource check. Without this a 9-byte script could make the
                // evaluator allocate up to MAX_SCRIPT_ELEMENT_SIZE (1 GB) and
                // only then trip the stack budget on the push.
                if size > self.memory_limit {
                    return Err(self.resource_error(ScriptResource::ElementSize, size));
                }

                let rawnum = self.pop_stack()?;
                let minimal = ScriptNum::minimally_encode(&rawnum);

                if minimal.len() > size {
                    return Err(self.error(
                        "OP_NUM2BIN requires that the size expressed in the top stack item is large enough to hold the value expressed in the second-from-top stack item.",
                    ));
                }

                if minimal.len() == size {
                    self.push_stack(minimal)?;
                } else {
                    // Pad to size, preserving sign
                    let mut result = vec![0u8; size];
                    let mut signbit = 0u8;

                    if !minimal.is_empty() {
                        signbit = minimal[minimal.len() - 1] & 0x80;
                        let mut minimal_copy = minimal.clone();
                        if let Some(last) = minimal_copy.last_mut() {
                            *last &= 0x7f;
                        }
                        result[..minimal_copy.len()].copy_from_slice(&minimal_copy);
                    }

                    if signbit != 0 {
                        result[size - 1] |= 0x80;
                    }
                    self.push_stack(result)?;
                }
            }
            OP_BIN2NUM => {
                if self.stack.is_empty() {
                    return Err(
                        self.error("OP_BIN2NUM requires at least one item to be on the stack.")
                    );
                }
                let buf = self.pop_stack()?;
                let result = ScriptNum::minimally_encode(&buf);
                if !ScriptNum::is_minimally_encoded(&result) {
                    return Err(
                        self.error("OP_BIN2NUM requires that the resulting number is valid.")
                    );
                }
                self.push_stack(result)?;
            }

            // ================================================================
            // Bitwise Operations
            // ================================================================
            OP_INVERT => {
                if self.stack.is_empty() {
                    return Err(
                        self.error("OP_INVERT requires at least one item to be on the stack.")
                    );
                }
                let buf = self.pop_stack()?;
                let result: Vec<u8> = buf.iter().map(|&b| !b).collect();
                self.push_stack(result)?;
            }
            OP_AND | OP_OR | OP_XOR => {
                if self.stack.len() < 2 {
                    return Err(self.error(&format!(
                        "{} requires at least two items on the stack.",
                        opcode_to_name(opcode).unwrap_or("OP")
                    )));
                }
                let buf2 = self.pop_stack()?;
                let buf1 = self.pop_stack()?;
                if buf1.len() != buf2.len() {
                    return Err(self.error(&format!(
                        "{} requires the top two stack items to be the same size.",
                        opcode_to_name(opcode).unwrap_or("OP")
                    )));
                }
                let result: Vec<u8> = buf1
                    .iter()
                    .zip(buf2.iter())
                    .map(|(&a, &b)| match opcode {
                        OP_AND => a & b,
                        OP_OR => a | b,
                        _ => a ^ b, // OP_XOR
                    })
                    .collect();
                self.push_stack(result)?;
            }
            OP_EQUAL | OP_EQUALVERIFY => {
                if self.stack.len() < 2 {
                    return Err(self.error(&format!(
                        "{} requires at least two items to be on the stack.",
                        opcode_to_name(opcode).unwrap_or("OP_EQUAL")
                    )));
                }
                let buf2 = self.pop_stack()?;
                let buf1 = self.pop_stack()?;
                let equal = buf1 == buf2;
                self.push_stack(if equal { vec![1] } else { vec![] })?;

                if opcode == OP_EQUALVERIFY {
                    if !equal {
                        return Err(self.error(
                            "OP_EQUALVERIFY requires the top two stack items to be equal.",
                        ));
                    }
                    self.pop_stack()?;
                }
            }
            OP_LSHIFT | OP_RSHIFT => {
                if self.stack.len() < 2 {
                    return Err(self.error(&format!(
                        "{} requires at least two items to be on the stack.",
                        opcode_to_name(opcode).unwrap_or("OP")
                    )));
                }
                let n_bytes = self.pop_stack()?;
                let buf = self.pop_stack()?;

                let n_bn = ScriptNum::from_bytes(&n_bytes, self.require_minimal)
                    .map_err(|e| self.error(&format!("Invalid script number: {}", e)))?;
                let n = n_bn.to_i64().unwrap_or(-1);

                if n < 0 {
                    return Err(self.error(&format!(
                        "{} requires the top item on the stack not to be negative.",
                        opcode_to_name(opcode).unwrap_or("OP")
                    )));
                }

                if buf.is_empty() {
                    self.push_stack(vec![])?;
                } else {
                    // Node semantics (and ts-sdk post-#493): LSHIFT/RSHIFT are
                    // WIDTH-PRESERVING bitwise shifts on the raw byte buffer —
                    // bits shifted past the end are discarded, the result is
                    // exactly buf.len() bytes. The previous BigNumber
                    // mul/to_bytes_be(buf.len()) implementation PANICKED on
                    // overflow ("BigNumber requires N bytes") and clamped the
                    // shift count to 63 bits (conformance vectors
                    // lshift-truncation.0001/.0003).
                    let len = buf.len();
                    let result: Vec<u8> = if (n as u128) >= (len as u128) * 8 {
                        vec![0u8; len]
                    } else {
                        let byte_shift = (n as usize) / 8;
                        let bit_shift = (n as usize) % 8;
                        let mut out = vec![0u8; len];
                        #[allow(clippy::needless_range_loop)]
                        for i in 0..len {
                            if opcode == OP_LSHIFT {
                                let src = i + byte_shift;
                                let hi = if src < len { buf[src] } else { 0 };
                                let lo = if bit_shift > 0 && src + 1 < len {
                                    buf[src + 1]
                                } else {
                                    0
                                };
                                out[i] = if bit_shift == 0 {
                                    hi
                                } else {
                                    (hi << bit_shift) | (lo >> (8 - bit_shift))
                                };
                            } else {
                                // OP_RSHIFT
                                if i >= byte_shift {
                                    let src = i - byte_shift;
                                    let hi = buf[src];
                                    let carry = if bit_shift > 0 && src >= 1 {
                                        buf[src - 1]
                                    } else {
                                        0
                                    };
                                    out[i] = if bit_shift == 0 {
                                        hi
                                    } else {
                                        (hi >> bit_shift) | (carry << (8 - bit_shift))
                                    };
                                }
                            }
                        }
                        out
                    };
                    self.push_stack(result)?;
                }
            }

            // ================================================================
            // Arithmetic Operations
            // ================================================================
            // OP_2MUL / OP_2DIV run only for a UTXO created after Chronicle
            // (interpreter.cpp:1247-1254; disabled before it, `360-375`, refused
            // above in `step`).
            OP_1ADD | OP_1SUB | OP_2MUL | OP_2DIV | OP_NEGATE | OP_ABS | OP_NOT | OP_0NOTEQUAL => {
                if self.stack.is_empty() {
                    return Err(self.error(&format!(
                        "{} requires at least one item to be on the stack.",
                        opcode_to_name(opcode).unwrap_or("OP")
                    )));
                }
                let buf = self.pop_stack()?;
                let mut bn = ScriptNum::from_bytes(&buf, self.require_minimal)
                    .map_err(|e| self.error(&format!("Invalid script number: {}", e)))?;

                bn = match opcode {
                    OP_1ADD => bn.add(&BigNumber::one()),
                    OP_1SUB => bn.sub(&BigNumber::one()),
                    OP_2MUL => bn.add(&bn),
                    OP_2DIV => bn.div(&BigNumber::from_i64(2)),
                    OP_NEGATE => bn.neg(),
                    OP_ABS => bn.abs(),
                    OP_NOT => {
                        if bn.is_zero() {
                            BigNumber::one()
                        } else {
                            BigNumber::zero()
                        }
                    }
                    OP_0NOTEQUAL => {
                        if bn.is_zero() {
                            BigNumber::zero()
                        } else {
                            BigNumber::one()
                        }
                    }
                    _ => bn,
                };
                self.push_stack(ScriptNum::to_bytes(&bn))?;
            }
            OP_ADD
            | OP_SUB
            | OP_MUL
            | OP_DIV
            | OP_MOD
            | OP_BOOLAND
            | OP_BOOLOR
            | OP_NUMEQUAL
            | OP_NUMEQUALVERIFY
            | OP_NUMNOTEQUAL
            | OP_LESSTHAN
            | OP_GREATERTHAN
            | OP_LESSTHANOREQUAL
            | OP_GREATERTHANOREQUAL
            | OP_MIN
            | OP_MAX => {
                if self.stack.len() < 2 {
                    return Err(self.error(&format!(
                        "{} requires at least two items to be on the stack.",
                        opcode_to_name(opcode).unwrap_or("OP")
                    )));
                }
                let buf2 = self.pop_stack()?;
                let buf1 = self.pop_stack()?;
                let bn1 = ScriptNum::from_bytes(&buf1, self.require_minimal)
                    .map_err(|e| self.error(&format!("Invalid script number: {}", e)))?;
                let bn2 = ScriptNum::from_bytes(&buf2, self.require_minimal)
                    .map_err(|e| self.error(&format!("Invalid script number: {}", e)))?;

                let result = match opcode {
                    OP_ADD => bn1.add(&bn2),
                    OP_SUB => bn1.sub(&bn2),
                    OP_MUL => bn1.mul(&bn2),
                    OP_DIV => {
                        if bn2.is_zero() {
                            return Err(self.error("OP_DIV cannot divide by zero!"));
                        }
                        bn1.div(&bn2)
                    }
                    OP_MOD => {
                        if bn2.is_zero() {
                            return Err(self.error("OP_MOD cannot divide by zero!"));
                        }
                        bn1.mod_floor(&bn2)
                    }
                    OP_BOOLAND => {
                        if !bn1.is_zero() && !bn2.is_zero() {
                            BigNumber::one()
                        } else {
                            BigNumber::zero()
                        }
                    }
                    OP_BOOLOR => {
                        if !bn1.is_zero() || !bn2.is_zero() {
                            BigNumber::one()
                        } else {
                            BigNumber::zero()
                        }
                    }
                    OP_NUMEQUAL | OP_NUMEQUALVERIFY => {
                        if bn1 == bn2 {
                            BigNumber::one()
                        } else {
                            BigNumber::zero()
                        }
                    }
                    OP_NUMNOTEQUAL => {
                        if bn1 != bn2 {
                            BigNumber::one()
                        } else {
                            BigNumber::zero()
                        }
                    }
                    OP_LESSTHAN => {
                        if bn1 < bn2 {
                            BigNumber::one()
                        } else {
                            BigNumber::zero()
                        }
                    }
                    OP_GREATERTHAN => {
                        if bn1 > bn2 {
                            BigNumber::one()
                        } else {
                            BigNumber::zero()
                        }
                    }
                    OP_LESSTHANOREQUAL => {
                        if bn1 <= bn2 {
                            BigNumber::one()
                        } else {
                            BigNumber::zero()
                        }
                    }
                    OP_GREATERTHANOREQUAL => {
                        if bn1 >= bn2 {
                            BigNumber::one()
                        } else {
                            BigNumber::zero()
                        }
                    }
                    OP_MIN => {
                        if bn1 < bn2 {
                            bn1
                        } else {
                            bn2
                        }
                    }
                    OP_MAX => {
                        if bn1 > bn2 {
                            bn1
                        } else {
                            bn2
                        }
                    }
                    _ => BigNumber::zero(),
                };

                self.push_stack(ScriptNum::to_bytes(&result))?;

                if opcode == OP_NUMEQUALVERIFY {
                    if !ScriptNum::cast_to_bool(self.stack_top()?) {
                        return Err(self
                            .error("OP_NUMEQUALVERIFY requires the top stack item to be truthy."));
                    }
                    self.pop_stack()?;
                }
            }
            OP_WITHIN => {
                if self.stack.len() < 3 {
                    return Err(
                        self.error("OP_WITHIN requires at least three items to be on the stack.")
                    );
                }
                let max_bytes = self.pop_stack()?;
                let min_bytes = self.pop_stack()?;
                let x_bytes = self.pop_stack()?;
                let max_bn = ScriptNum::from_bytes(&max_bytes, self.require_minimal)
                    .map_err(|e| self.error(&format!("Invalid script number: {}", e)))?;
                let min_bn = ScriptNum::from_bytes(&min_bytes, self.require_minimal)
                    .map_err(|e| self.error(&format!("Invalid script number: {}", e)))?;
                let x_bn = ScriptNum::from_bytes(&x_bytes, self.require_minimal)
                    .map_err(|e| self.error(&format!("Invalid script number: {}", e)))?;

                let in_range = x_bn >= min_bn && x_bn < max_bn;
                self.push_stack(if in_range { vec![1] } else { vec![] })?;
            }

            // ================================================================
            // Crypto Operations
            // ================================================================
            OP_RIPEMD160 => {
                if self.stack.is_empty() {
                    return Err(
                        self.error("OP_RIPEMD160 requires at least one item to be on the stack.")
                    );
                }
                let buf = self.pop_stack()?;
                let hash = ripemd160(&buf);
                self.push_stack(hash.to_vec())?;
            }
            OP_SHA1 => {
                if self.stack.is_empty() {
                    return Err(
                        self.error("OP_SHA1 requires at least one item to be on the stack.")
                    );
                }
                let buf = self.pop_stack()?;
                let hash = sha1(&buf);
                self.push_stack(hash.to_vec())?;
            }
            OP_SHA256 => {
                if self.stack.is_empty() {
                    return Err(
                        self.error("OP_SHA256 requires at least one item to be on the stack.")
                    );
                }
                let buf = self.pop_stack()?;
                let hash = sha256(&buf);
                self.push_stack(hash.to_vec())?;
            }
            OP_HASH160 => {
                if self.stack.is_empty() {
                    return Err(
                        self.error("OP_HASH160 requires at least one item to be on the stack.")
                    );
                }
                let buf = self.pop_stack()?;
                let hash = hash160(&buf);
                self.push_stack(hash.to_vec())?;
            }
            OP_HASH256 => {
                if self.stack.is_empty() {
                    return Err(
                        self.error("OP_HASH256 requires at least one item to be on the stack.")
                    );
                }
                let buf = self.pop_stack()?;
                let hash = sha256d(&buf);
                self.push_stack(hash.to_vec())?;
            }
            OP_CODESEPARATOR => {
                self.last_code_separator = Some(self.program_counter);
            }
            OP_CHECKSIG | OP_CHECKSIGVERIFY => {
                if self.stack.len() < 2 {
                    return Err(self.error(&format!(
                        "{} requires at least two items to be on the stack.",
                        opcode_to_name(opcode).unwrap_or("OP_CHECKSIG")
                    )));
                }
                let pubkey_bytes = self.pop_stack()?;
                let sig_bytes = self.pop_stack()?;

                // Validate encodings
                self.check_signature_encoding(&sig_bytes)?;
                self.check_public_key_encoding(&pubkey_bytes)?;

                // Build subscript
                let subscript = self.build_subscript(&sig_bytes)?;

                // Verify signature
                let success = if sig_bytes.is_empty() {
                    false
                } else {
                    self.verify_signature(&sig_bytes, &pubkey_bytes, &subscript)?
                };

                // NULLFAIL (interpreter.cpp:1491-1497, under the version gate):
                // a signature that fails must be the empty vector.
                if !success && self.require_null_fail && !sig_bytes.is_empty() {
                    return Err(self.error(&format!(
                        "{} requires failing signatures to be empty.",
                        opcode_to_name(opcode).unwrap_or("OP_CHECKSIG")
                    )));
                }

                self.push_stack(if success { vec![1] } else { vec![] })?;

                if opcode == OP_CHECKSIGVERIFY {
                    if !success {
                        return Err(self.error(
                            "OP_CHECKSIGVERIFY requires that a valid signature is provided.",
                        ));
                    }
                    self.pop_stack()?;
                }
            }
            OP_CHECKMULTISIG | OP_CHECKMULTISIGVERIFY => {
                self.op_checkmultisig(opcode)?;
            }

            // ================================================================
            // Data Push (handled above, but catch any missed)
            // ================================================================
            0x01..=0x4b => {
                // Direct push opcodes - should have data
                let data = chunk.data.clone().unwrap_or_default();
                self.push_stack(data)?;
            }
            OP_PUSHDATA1 | OP_PUSHDATA2 | OP_PUSHDATA4 => {
                let data = chunk.data.clone().unwrap_or_default();
                self.push_stack(data)?;
            }

            // ================================================================
            // Unknown/Invalid Opcode
            // ================================================================
            _ => {
                return Err(self.error(&format!(
                    "Invalid opcode {} (pc={}).",
                    opcode, self.program_counter
                )));
            }
        }

        Ok(())
    }

    // ========================================================================
    // OP_CHECKMULTISIG Implementation
    // ========================================================================

    fn op_checkmultisig(&mut self, opcode: u8) -> Result<(), ScriptEvaluationError> {
        // Get number of public keys
        if self.stack.is_empty() {
            return Err(self.error(&format!(
                "{} requires at least 1 item for nKeys.",
                opcode_to_name(opcode).unwrap_or("OP_CHECKMULTISIG")
            )));
        }

        let n_keys_bytes = self.pop_stack()?;
        let n_keys_bn = ScriptNum::from_bytes(&n_keys_bytes, self.require_minimal)
            .map_err(|e| self.error(&format!("Invalid script number: {}", e)))?;
        let n_keys = n_keys_bn.to_i64().unwrap_or(-1);

        if !(0..=MAX_MULTISIG_KEY_COUNT).contains(&n_keys) {
            return Err(self.error(&format!(
                "{} requires a key count between 0 and {}.",
                opcode_to_name(opcode).unwrap_or("OP_CHECKMULTISIG"),
                MAX_MULTISIG_KEY_COUNT
            )));
        }
        let n_keys = n_keys as usize;

        // Get public keys
        if self.stack.len() < n_keys {
            return Err(self.error(&format!(
                "{} stack too small for keys. Need {}, have {}.",
                opcode_to_name(opcode).unwrap_or("OP_CHECKMULTISIG"),
                n_keys,
                self.stack.len()
            )));
        }

        let mut pubkeys = Vec::with_capacity(n_keys);
        for _ in 0..n_keys {
            pubkeys.push(self.pop_stack()?);
        }

        // Get number of signatures
        if self.stack.is_empty() {
            return Err(self.error(&format!(
                "{} requires item for nSigs.",
                opcode_to_name(opcode).unwrap_or("OP_CHECKMULTISIG")
            )));
        }

        let n_sigs_bytes = self.pop_stack()?;
        let n_sigs_bn = ScriptNum::from_bytes(&n_sigs_bytes, self.require_minimal)
            .map_err(|e| self.error(&format!("Invalid script number: {}", e)))?;
        let n_sigs = n_sigs_bn.to_i64().unwrap_or(-1);

        if n_sigs < 0 || n_sigs as usize > n_keys {
            return Err(self.error(&format!(
                "{} requires the number of signatures to be no greater than the number of keys.",
                opcode_to_name(opcode).unwrap_or("OP_CHECKMULTISIG")
            )));
        }
        let n_sigs = n_sigs as usize;

        // Get signatures
        if self.stack.len() < n_sigs {
            return Err(self.error(&format!(
                "{} stack too small for sigs. Need {}, have {}.",
                opcode_to_name(opcode).unwrap_or("OP_CHECKMULTISIG"),
                n_sigs,
                self.stack.len()
            )));
        }

        let mut sigs = Vec::with_capacity(n_sigs);
        for _ in 0..n_sigs {
            sigs.push(self.pop_stack()?);
        }

        // Build subscript and remove all signatures
        let base_script = match self.context {
            ExecutionContext::UnlockingScript => self.unlocking_script.as_script().clone(),
            ExecutionContext::LockingScript => self.locking_script.as_script().clone(),
        };
        let start_idx = self.last_code_separator.map(|i| i + 1).unwrap_or(0);
        let chunks = base_script.chunks();
        let mut subscript_chunks: Vec<ScriptChunk> = chunks.into_iter().skip(start_idx).collect();
        // See build_subscript: unlock-context subscripts continue into the
        // full locking script (combined-script semantics, ts-sdk parity).
        if self.context == ExecutionContext::UnlockingScript {
            subscript_chunks.extend(self.locking_script.as_script().chunks());
        }
        let mut subscript = Script::from_chunks(subscript_chunks);

        // CleanupScriptCode (interpreter.cpp:255-263, applied per signature at
        // 1573-1578): a signature's push is deleted from the scriptCode only when
        // it does not carry SIGHASH_FORKID; FORKID is always enabled here, so
        // only an empty signature (no hash type) is deleted, as an OP_0 push.
        for sig in &sigs {
            if !has_forkid_bit(sig) {
                let mut sig_script = Script::new();
                sig_script.write_bin(sig);
                subscript.find_and_delete(&sig_script);
            }
        }

        // Verify signatures
        let mut success = true;
        let mut sig_idx = 0;
        let mut key_idx = 0;

        while success && sig_idx < n_sigs {
            if key_idx >= n_keys {
                success = false;
                break;
            }

            let sig_bytes = &sigs[sig_idx];
            let pubkey_bytes = &pubkeys[key_idx];

            // Validate encodings
            if self.check_signature_encoding(sig_bytes).is_err()
                || self.check_public_key_encoding(pubkey_bytes).is_err()
            {
                return Err(self.error(&format!(
                    "{} requires correct encoding for the public key and signature.",
                    opcode_to_name(opcode).unwrap_or("OP_CHECKMULTISIG")
                )));
            }

            let sig_valid = if sig_bytes.is_empty() {
                false
            } else {
                self.verify_signature(sig_bytes, pubkey_bytes, &subscript)
                    .unwrap_or(false)
            };

            if sig_valid {
                sig_idx += 1;
            }
            key_idx += 1;

            if n_sigs - sig_idx > n_keys - key_idx {
                success = false;
            }
        }

        // NULLFAIL (interpreter.cpp:1640-1646, under the version gate): when
        // the operation fails, every signature must be the empty vector.
        if !success && self.require_null_fail && sigs.iter().any(|s| !s.is_empty()) {
            return Err(self.error(&format!(
                "{} requires failing signatures to be empty.",
                opcode_to_name(opcode).unwrap_or("OP_CHECKMULTISIG")
            )));
        }

        // Pop the dummy element. NULLDUMMY (interpreter.cpp:1664-1670, under
        // the version gate) requires it to be empty.
        if self.stack.is_empty() {
            return Err(self.error(&format!(
                "{} requires an extra item (dummy) to be on the stack.",
                opcode_to_name(opcode).unwrap_or("OP_CHECKMULTISIG")
            )));
        }
        let dummy = self.pop_stack()?;
        if self.require_null_dummy && !dummy.is_empty() {
            return Err(self.error(&format!(
                "{} requires the extra stack item (dummy) to be empty.",
                opcode_to_name(opcode).unwrap_or("OP_CHECKMULTISIG")
            )));
        }

        self.push_stack(if success { vec![1] } else { vec![] })?;

        if opcode == OP_CHECKMULTISIGVERIFY {
            if !success {
                return Err(self.error(
                    "OP_CHECKMULTISIGVERIFY requires that a sufficient number of valid signatures are provided.",
                ));
            }
            self.pop_stack()?;
        }

        Ok(())
    }

    // ========================================================================
    // Signature Verification Helpers
    // ========================================================================

    fn check_signature_encoding(&self, sig: &[u8]) -> Result<(), ScriptEvaluationError> {
        if sig.is_empty() {
            return Ok(());
        }

        // Check basic DER format
        if !is_valid_signature_encoding(sig) {
            return Err(self.error("The signature format is invalid."));
        }

        // Parse and check additional requirements
        let tx_sig = TransactionSignature::from_checksig_format(sig)
            .map_err(|_| self.error("The signature format is invalid."))?;

        // LOW_S as the reference checks it (`CPubKey::CheckLowS`, pubkey.cpp:356-365):
        // the lax parser (146-173) turns an `r` or `s` at or above the curve order
        // into the zero signature, which is low, so the check passes and the
        // signature fails to verify afterwards (NULLFAIL under the flag, else a
        // false top). Only n/2 < s < n is a high-S refusal.
        if self.require_low_s && !tx_sig.has_low_s() && !signature_overflows_the_order(&tx_sig) {
            return Err(self.error("The signature must have a low S value."));
        }

        if (tx_sig.scope() & SIGHASH_FORKID) == 0 {
            return Err(self.error("The signature must use SIGHASH_FORKID."));
        }

        Ok(())
    }

    fn check_public_key_encoding(&self, pubkey: &[u8]) -> Result<(), ScriptEvaluationError> {
        if pubkey.is_empty() {
            return Err(self.error("Public key is empty."));
        }

        if pubkey.len() < 33 {
            return Err(self.error("The public key is too short, it must be at least 33 bytes."));
        }

        if pubkey[0] == 0x04 {
            if pubkey.len() != 65 {
                return Err(self.error("The non-compressed public key must be 65 bytes."));
            }
        } else if pubkey[0] == 0x02 || pubkey[0] == 0x03 {
            if pubkey.len() != 33 {
                return Err(self.error("The compressed public key must be 33 bytes."));
            }
        } else {
            return Err(self.error("The public key is in an unknown format."));
        }

        // COMPRESSED_PUBKEYTYPE (interpreter.cpp:322-327): only compressed
        // keys are accepted under the flag.
        if self.require_compressed_pubkey && pubkey[0] == 0x04 {
            return Err(self.error("The public key must be compressed."));
        }

        // Try to parse it
        PublicKey::from_bytes(pubkey)
            .map_err(|_| self.error("The public key is in an unknown format."))?;

        Ok(())
    }

    fn build_subscript(&self, sig_bytes: &[u8]) -> Result<Script, ScriptEvaluationError> {
        let base_script = match self.context {
            ExecutionContext::UnlockingScript => self.unlocking_script.as_script().clone(),
            ExecutionContext::LockingScript => self.locking_script.as_script().clone(),
        };

        let start_idx = self.last_code_separator.map(|i| i + 1).unwrap_or(0);
        let chunks = base_script.chunks();
        let mut subscript_chunks: Vec<ScriptChunk> = chunks.into_iter().skip(start_idx).collect();
        // When a CHECKSIG executes in the unlocking script, the subscript
        // continues across the unlock/lock boundary into the full locking
        // script (legacy combined-script semantics; matches BSV node consensus
        // and ts-sdk). Without this, signatures taken over such a subscript
        // (e.g. OP_PUSH_TX-style contracts) are wrongly rejected.
        if self.context == ExecutionContext::UnlockingScript {
            subscript_chunks.extend(self.locking_script.as_script().chunks());
        }
        let mut subscript = Script::from_chunks(subscript_chunks);

        // CleanupScriptCode (interpreter.cpp:255-263, applied at 1484): the
        // signature's push is deleted from the scriptCode only when the
        // signature does not carry SIGHASH_FORKID (FORKID is always enabled
        // here). A signature that does is hashed with its own push in place, so
        // a signature whose push appears in the scriptCode cannot verify, as on
        // the reference. An empty signature carries no hash type and is deleted
        // as an OP_0 push, as on the reference.
        if !has_forkid_bit(sig_bytes) {
            let mut sig_script = Script::new();
            sig_script.write_bin(sig_bytes);
            subscript.find_and_delete(&sig_script);
        }

        Ok(subscript)
    }

    /// `OP_SUBSTR`, `OP_LEFT`, `OP_RIGHT`, `OP_LSHIFTNUM`, `OP_RSHIFTNUM` at
    /// `0xb3`-`0xb7` for a UTXO created after Chronicle (`interpreter.cpp:609-764`).
    /// The two shifts act on script NUMBERS (not on bytes, unlike `OP_LSHIFT`);
    /// a left shift whose result would not fit the memory budget is refused
    /// before it is computed (a local budget; the reference's bound is its
    /// consensus number length, `SCRIPTNUM_OVERFLOW`).
    fn op_chronicle_splice(&mut self, opcode: u8) -> Result<(), ScriptEvaluationError> {
        let name = match opcode {
            OP_NOP4 => "OP_SUBSTR",
            OP_NOP5 => "OP_LEFT",
            OP_NOP6 => "OP_RIGHT",
            OP_NOP7 => "OP_LSHIFTNUM",
            _ => "OP_RSHIFTNUM",
        };
        let need = if opcode == OP_NOP4 { 3 } else { 2 };
        if self.stack.len() < need {
            return Err(self.error(&format!(
                "{name} requires at least {} items to be on the stack.",
                if need == 3 { "three" } else { "two" }
            )));
        }
        let num = |s: &Self, bytes: &[u8]| -> Result<BigNumber, ScriptEvaluationError> {
            ScriptNum::from_bytes(bytes, s.require_minimal)
                .map_err(|e| s.error(&format!("Invalid script number: {}", e)))
        };
        match opcode {
            OP_NOP4 => {
                // (data offset len -- data[offset..offset+len])
                let len_bytes = self.pop_stack()?;
                let off_bytes = self.pop_stack()?;
                let len = num(self, &len_bytes)?.to_i64().unwrap_or(-1);
                let offset = num(self, &off_bytes)?.to_i64().unwrap_or(-1);
                let data = self.pop_stack()?;
                let size = data.len() as i64;
                if offset < 0 || offset >= size || len < 0 || len > size - offset {
                    return Err(self.error(&format!(
                        "OP_SUBSTR offset ({offset}) must be in range [0, {size}) and length ({len}) must be in range [0, {}]",
                        size - offset
                    )));
                }
                let (o, l) = (offset as usize, len as usize);
                self.push_stack(data[o..o + l].to_vec())?;
            }
            OP_NOP5 | OP_NOP6 => {
                // (data len -- the first / last len bytes)
                let len_bytes = self.pop_stack()?;
                let len = num(self, &len_bytes)?.to_i64().unwrap_or(-1);
                let data = self.pop_stack()?;
                let size = data.len() as i64;
                if len < 0 || len > size {
                    return Err(self.error(&format!(
                        "{name} length ({len}) must be in range [0, {size}]"
                    )));
                }
                let l = len as usize;
                let out = if opcode == OP_NOP5 {
                    data[..l].to_vec()
                } else {
                    data[data.len() - l..].to_vec()
                };
                self.push_stack(out)?;
            }
            _ => {
                // (x n -- x << n) / (x n -- x >> n), on script numbers
                let n_bytes = self.pop_stack()?;
                let n_bn = num(self, &n_bytes)?;
                if n_bn.is_negative() {
                    return Err(self.error(&format!("{name} bits to shift must not be negative.")));
                }
                let x_bytes = self.pop_stack()?;
                let x = num(self, &x_bytes)?;
                let n = n_bn.to_i64().map(|v| v as u64).unwrap_or(u64::MAX);
                let out = if opcode == OP_NOP7 {
                    // the result's size, before allocating it: a LOCAL budget
                    let bits = (x.bit_length() as u64).saturating_add(n);
                    let bytes = (bits / 8 + 2) as usize;
                    if !x.is_zero() && bytes > self.memory_limit {
                        return Err(self.resource_error(ScriptResource::ElementSize, bytes));
                    }
                    if x.is_zero() {
                        x
                    } else {
                        x.shl_bits(n)
                    }
                } else if n >= x.bit_length() as u64 {
                    BigNumber::zero()
                } else {
                    x.shr_bits_toward_zero(n)
                };
                self.push_stack(ScriptNum::to_bytes(&out))?;
            }
        }
        Ok(())
    }

    fn verify_signature(
        &self,
        sig_bytes: &[u8],
        pubkey_bytes: &[u8],
        subscript: &Script,
    ) -> Result<bool, ScriptEvaluationError> {
        // Parse signature and public key
        let tx_sig = match TransactionSignature::from_checksig_format(sig_bytes) {
            Ok(s) => s,
            Err(_) => return Ok(false),
        };

        let pubkey = match PublicKey::from_bytes(pubkey_bytes) {
            Ok(p) => p,
            Err(_) => return Ok(false),
        };

        // Build inputs array for sighash
        let inputs = self.build_inputs_array();

        // Compute sighash
        let sighash = compute_sighash_for_signing(&SighashParams {
            version: self.transaction_version,
            inputs: &inputs,
            outputs: &self.outputs,
            locktime: self.lock_time,
            input_index: self.input_index,
            subscript: &subscript.to_binary(),
            satoshis: self.source_satoshis,
            scope: tx_sig.scope(),
        });

        // Verify
        Ok(pubkey.verify(&sighash, tx_sig.signature()))
    }

    fn build_inputs_array(&self) -> Vec<TxInput> {
        let mut inputs = Vec::with_capacity(self.other_inputs.len() + 1);

        // Add other inputs
        for (i, other) in self.other_inputs.iter().enumerate() {
            if i == self.input_index {
                // Insert our input at the correct position
                inputs.push(TxInput {
                    txid: self.source_txid,
                    output_index: self.source_output_index,
                    script: self.unlocking_script.to_binary(),
                    sequence: self.input_sequence,
                });
            }
            inputs.push(other.clone());
        }

        // Handle case where our input is at the end or other_inputs is empty
        if self.input_index >= self.other_inputs.len() {
            inputs.push(TxInput {
                txid: self.source_txid,
                output_index: self.source_output_index,
                script: self.unlocking_script.to_binary(),
                sequence: self.input_sequence,
            });
        }

        inputs
    }

    // ========================================================================
    // Stack Helpers
    // ========================================================================

    fn push_stack(&mut self, item: Vec<u8>) -> Result<(), ScriptEvaluationError> {
        self.ensure_stack_mem(item.len())?;
        self.stack_mem += item.len();
        self.stack.push(item);
        Ok(())
    }

    fn push_stack_copy(&mut self, item: &[u8]) -> Result<(), ScriptEvaluationError> {
        self.push_stack(item.to_vec())
    }

    fn pop_stack(&mut self) -> Result<Vec<u8>, ScriptEvaluationError> {
        if self.stack.is_empty() {
            return Err(self.error("Attempted to pop from an empty stack."));
        }
        let item = self.stack.pop().unwrap();
        self.stack_mem -= item.len();
        Ok(item)
    }

    fn stack_top(&self) -> Result<&Vec<u8>, ScriptEvaluationError> {
        if self.stack.is_empty() {
            return Err(self.error("Stack is empty."));
        }
        Ok(&self.stack[self.stack.len() - 1])
    }

    fn stack_top_n(&self, n: usize) -> Result<&Vec<u8>, ScriptEvaluationError> {
        if self.stack.len() < n {
            return Err(self.error(&format!(
                "Stack underflow accessing element at index {}. Stack length is {}.",
                n,
                self.stack.len()
            )));
        }
        Ok(&self.stack[self.stack.len() - n])
    }

    fn push_alt_stack(&mut self, item: Vec<u8>) -> Result<(), ScriptEvaluationError> {
        self.ensure_alt_stack_mem(item.len())?;
        self.alt_stack_mem += item.len();
        self.alt_stack.push(item);
        Ok(())
    }

    fn pop_alt_stack(&mut self) -> Result<Vec<u8>, ScriptEvaluationError> {
        if self.alt_stack.is_empty() {
            return Err(self.error("Attempted to pop from an empty alt stack."));
        }
        let item = self.alt_stack.pop().unwrap();
        self.alt_stack_mem -= item.len();
        Ok(item)
    }

    fn ensure_stack_mem(&self, additional: usize) -> Result<(), ScriptEvaluationError> {
        if self.stack_mem + additional > self.memory_limit {
            return Err(self.resource_error(ScriptResource::Stack, self.stack_mem + additional));
        }
        Ok(())
    }

    fn ensure_alt_stack_mem(&self, additional: usize) -> Result<(), ScriptEvaluationError> {
        if self.alt_stack_mem + additional > self.memory_limit {
            return Err(
                self.resource_error(ScriptResource::AltStack, self.alt_stack_mem + additional)
            );
        }
        Ok(())
    }

    /// A LOCAL resource-limit error (the reference's `ScriptResourceLimitError`):
    /// the same message shape (`<label> has exceeded <limit> bytes`) plus the
    /// structured `resource_limit` a caller can branch on.
    fn resource_error(&self, resource: ScriptResource, attempted: usize) -> ScriptEvaluationError {
        let label = match resource {
            ScriptResource::Stack => "Stack memory usage",
            ScriptResource::AltStack => "Alt stack memory usage",
            ScriptResource::ElementSize => "Script element allocation",
        };
        self.error(&format!("{label} has exceeded {} bytes", self.memory_limit))
            .with_resource_limit(ScriptResourceLimit {
                resource,
                limit: self.memory_limit,
                attempted,
            })
    }

    // ========================================================================
    // Error Helpers
    // ========================================================================

    fn error(&self, message: &str) -> ScriptEvaluationError {
        ScriptEvaluationError::new(
            message,
            to_hex(&self.source_txid),
            self.source_output_index,
            self.context,
            self.program_counter,
            self.stack.clone(),
            self.alt_stack.clone(),
            self.if_stack.clone(),
            self.stack_mem,
            self.alt_stack_mem,
        )
    }
}

// ============================================================================
// Helper Functions
// ============================================================================

/// `IsOpcodeDisabled` (interpreter.cpp:360-375): `OP_2MUL` and `OP_2DIV`
/// unless the UTXO was created after Chronicle. `OP_VER`, `OP_VERIF` and
/// `OP_VERNOTIF` are not "disabled" there but `BAD_OPCODE` when executed
/// before Chronicle, handled in their arms.
fn is_opcode_disabled(op: u8, utxo_after_chronicle: bool) -> bool {
    !utxo_after_chronicle && matches!(op, OP_2MUL | OP_2DIV)
}

/// Whether the signature's `r` or `s` is at or above the curve order: the
/// reference's lax DER parse (`ecdsa_signature_parse_der_lax`, pubkey.cpp:146-173)
/// overwrites such a signature with the all-zero one, which is low for
/// `CheckLowS` (356-365) and never verifies.
fn signature_overflows_the_order(sig: &TransactionSignature) -> bool {
    let n = BigNumber::secp256k1_order();
    BigNumber::from_bytes_be(sig.r()) >= n || BigNumber::from_bytes_be(sig.s()) >= n
}

/// Whether a signature's hash type carries `SIGHASH_FORKID`; an empty
/// signature has no hash type (`GetHashType`, interpreter.cpp:246-252).
fn has_forkid_bit(sig: &[u8]) -> bool {
    sig.last().is_some_and(|t| t & (SIGHASH_FORKID as u8) != 0)
}

/// Checks if a chunk uses minimal push encoding.
fn is_chunk_minimal_push(chunk: &ScriptChunk) -> bool {
    let data = match &chunk.data {
        Some(d) => d,
        None => return true,
    };
    let op = chunk.op;

    if data.is_empty() {
        return op == OP_0;
    }

    if data.len() == 1 && data[0] >= 1 && data[0] <= 16 {
        return op == OP_1 + (data[0] - 1);
    }

    if data.len() == 1 && data[0] == 0x81 {
        return op == OP_1NEGATE;
    }

    if data.len() <= 75 {
        return op as usize == data.len();
    }

    if data.len() <= 255 {
        return op == OP_PUSHDATA1;
    }

    if data.len() <= 65535 {
        return op == OP_PUSHDATA2;
    }

    true
}

/// Validates DER signature encoding (simplified check).
fn is_valid_signature_encoding(sig: &[u8]) -> bool {
    if sig.len() < 9 || sig.len() > 73 {
        return false;
    }

    // Sequence tag
    if sig[0] != 0x30 {
        return false;
    }

    // Length check
    if sig[1] as usize != sig.len() - 3 {
        return false;
    }

    // R value
    if sig[2] != 0x02 {
        return false;
    }

    let r_len = sig[3] as usize;
    if r_len == 0 || 5 + r_len >= sig.len() {
        return false;
    }

    // S value
    let s_offset = 4 + r_len;
    if sig[s_offset] != 0x02 {
        return false;
    }

    let s_len = sig[s_offset + 1] as usize;
    if s_len == 0 {
        return false;
    }

    // Check total length
    if r_len + s_len + 7 != sig.len() {
        return false;
    }

    // Check R not negative
    if (sig[4] & 0x80) != 0 {
        return false;
    }

    // Check R not excessively padded
    if r_len > 1 && sig[4] == 0x00 && (sig[5] & 0x80) == 0 {
        return false;
    }

    // Check S not negative
    let s_value_offset = s_offset + 2;
    if (sig[s_value_offset] & 0x80) != 0 {
        return false;
    }

    // Check S not excessively padded
    if s_len > 1 && sig[s_value_offset] == 0x00 && (sig[s_value_offset + 1] & 0x80) == 0 {
        return false;
    }

    true
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_is_opcode_disabled() {
        assert!(is_opcode_disabled(OP_2MUL, false));
        assert!(is_opcode_disabled(OP_2DIV, false));
        assert!(!is_opcode_disabled(OP_2MUL, true));
        assert!(!is_opcode_disabled(OP_2DIV, true));
        // BAD_OPCODE in their arms, not "disabled" (interpreter.cpp:360-375)
        assert!(!is_opcode_disabled(OP_VER, false));
        assert!(!is_opcode_disabled(OP_VERIF, false));
        assert!(!is_opcode_disabled(OP_VERNOTIF, false));

        assert!(!is_opcode_disabled(OP_DUP, false));
        assert!(!is_opcode_disabled(OP_MUL, false));
        assert!(!is_opcode_disabled(OP_CAT, false));
    }

    #[test]
    fn test_is_chunk_minimal_push() {
        // OP_0 for empty data
        let chunk = ScriptChunk::new(OP_0, Some(vec![]));
        assert!(is_chunk_minimal_push(&chunk));

        // Direct push for small data
        let chunk = ScriptChunk::new(3, Some(vec![1, 2, 3]));
        assert!(is_chunk_minimal_push(&chunk));

        // OP_1 for [1]
        let chunk = ScriptChunk::new(OP_1, Some(vec![1]));
        assert!(is_chunk_minimal_push(&chunk));

        // Non-minimal: using push opcode for [1] instead of OP_1
        let chunk = ScriptChunk::new(1, Some(vec![1]));
        assert!(!is_chunk_minimal_push(&chunk));
    }

    #[test]
    fn test_simple_stack_script() {
        // Test: OP_1 OP_2 OP_ADD OP_3 OP_EQUAL
        // Should leave [1] on stack (true)
        let locking = LockingScript::from_asm("OP_ADD OP_3 OP_EQUAL").unwrap();
        let unlocking = UnlockingScript::from_asm("OP_1 OP_2").unwrap();

        let mut spend = Spend::new(SpendParams {
            source_txid: [0u8; 32],
            source_output_index: 0,
            source_satoshis: 0,
            locking_script: locking,
            transaction_version: 1,
            other_inputs: vec![],
            outputs: vec![],
            input_index: 0,
            unlocking_script: unlocking,
            input_sequence: 0xffffffff,
            lock_time: 0,
            memory_limit: None,
        });

        let result = spend.validate();
        assert!(result.is_ok(), "Expected valid spend, got {:?}", result);
    }

    #[test]
    fn test_if_else_endif() {
        // Test: OP_1 OP_IF OP_2 OP_ELSE OP_3 OP_ENDIF
        // Should push 2 (true branch)
        let locking = LockingScript::from_asm("OP_IF OP_2 OP_ELSE OP_3 OP_ENDIF").unwrap();
        let unlocking = UnlockingScript::from_asm("OP_1").unwrap();

        let mut spend = Spend::new(SpendParams {
            source_txid: [0u8; 32],
            source_output_index: 0,
            source_satoshis: 0,
            locking_script: locking,
            transaction_version: 1,
            other_inputs: vec![],
            outputs: vec![],
            input_index: 0,
            unlocking_script: unlocking,
            input_sequence: 0xffffffff,
            lock_time: 0,
            memory_limit: None,
        });

        let result = spend.validate();
        assert!(result.is_ok(), "Expected valid spend, got {:?}", result);
    }

    #[test]
    fn test_hash_operations() {
        // Test that hash operations work
        // SHA256 produces 32 bytes, we check the size is 32 (0x20)
        // Use NIP to remove the hash after SIZE, leaving just the size to compare
        let locking = LockingScript::from_asm("OP_SHA256 OP_SIZE OP_NIP 20 OP_EQUAL").unwrap();
        let unlocking = UnlockingScript::from_asm("00").unwrap();

        let mut spend = Spend::new(SpendParams {
            source_txid: [0u8; 32],
            source_output_index: 0,
            source_satoshis: 0,
            locking_script: locking,
            transaction_version: 1,
            other_inputs: vec![],
            outputs: vec![],
            input_index: 0,
            unlocking_script: unlocking,
            input_sequence: 0xffffffff,
            lock_time: 0,
            memory_limit: None,
        });

        let result = spend.validate();
        assert!(result.is_ok(), "Expected valid spend, got {:?}", result);
    }

    #[test]
    fn test_failing_script() {
        // Test: just OP_0 should fail (stack has falsy value)
        let locking = LockingScript::from_asm("OP_0").unwrap();
        let unlocking = UnlockingScript::new();

        let mut spend = Spend::new(SpendParams {
            source_txid: [0u8; 32],
            source_output_index: 0,
            source_satoshis: 0,
            locking_script: locking,
            transaction_version: 1,
            other_inputs: vec![],
            outputs: vec![],
            input_index: 0,
            unlocking_script: unlocking,
            input_sequence: 0xffffffff,
            lock_time: 0,
            memory_limit: None,
        });

        let result = spend.validate();
        assert!(result.is_err(), "Expected failed validation");
    }
}

/// The flag words on the interpreter: every gate `set_flags` derives, exercised
/// on the smallest script that reaches it, against the TypeScript default
/// mode. The reference sites are cited in `flags.rs`.
#[cfg(test)]
mod flag_tests {
    use super::*;
    use crate::primitives::from_hex;
    use crate::script::flags::ProtocolEra;

    /// A compressed public key and a well-formed low-S signature with the
    /// FORKID hash type that does not verify in any context below.
    const PUBKEY: &str = "035935f55855afd8c999bdb5a8d08ae8e73b7618e200d4ef7687cd55d3c2e4c9d7";
    const WRONG_SIG: &str = "304402204bbb723c10080132ef81641e0e9963eb77782bf50c149f0f15c6d7b8e263464e02207f18ea8fdff74fb4d4d2dc677555fb1c94cf6219fe4bb4c40162e1e270f8924941";

    fn spend(lock_asm: &str, unlock_asm: &str, version: i32) -> Spend {
        Spend::new(SpendParams {
            source_txid: [0u8; 32],
            source_output_index: 0,
            source_satoshis: 1000,
            locking_script: LockingScript::from_asm(lock_asm).unwrap(),
            transaction_version: version,
            other_inputs: vec![],
            outputs: vec![],
            input_index: 0,
            unlocking_script: UnlockingScript::from_asm(unlock_asm).unwrap(),
            input_sequence: 0xffff_ffff,
            lock_time: 0,
            memory_limit: None,
        })
    }

    fn with_flags(lock_asm: &str, unlock_asm: &str, version: i32, flags: ScriptFlags) -> Spend {
        let mut s = spend(lock_asm, unlock_asm, version);
        s.set_flags(flags);
        s
    }

    fn message(r: Result<bool, ScriptEvaluationError>) -> String {
        r.expect_err("expected a refusal").message
    }

    fn valid(r: Result<bool, ScriptEvaluationError>) -> bool {
        matches!(r, Ok(true))
    }

    fn block() -> ScriptFlags {
        ScriptFlags::block(ProtocolEra::PostChronicle)
    }

    fn standard() -> ScriptFlags {
        ScriptFlags::standard(ProtocolEra::PostChronicle)
    }

    #[test]
    fn nullfail_refuses_a_failing_non_empty_checksig_signature_at_version_1_under_the_block_word() {
        let lock = format!("{PUBKEY} OP_CHECKSIG OP_NOT");
        // Version 1: NULLFAIL is mandatory and the gate is on.
        let msg = message(with_flags(&lock, WRONG_SIG, 1, block()).validate());
        assert_eq!(msg, "OP_CHECKSIG requires failing signatures to be empty.");
        // Version 2 post-Chronicle: the gate is off, the negated failure is a true top.
        assert!(valid(with_flags(&lock, WRONG_SIG, 2, block()).validate()));
        // Before Chronicle the gate is always on.
        assert!(with_flags(
            &lock,
            WRONG_SIG,
            2,
            ScriptFlags::block(ProtocolEra::PostGenesis)
        )
        .validate()
        .is_err());
        // An empty signature is what NULLFAIL asks for.
        assert!(valid(with_flags(&lock, "0", 1, block()).validate()));
        // The TypeScript default mode has no NULLFAIL rule.
        assert!(valid(spend(&lock, WRONG_SIG, 1).validate()));
    }

    #[test]
    fn nullfail_refuses_a_failing_checkmultisig_with_any_non_empty_signature_at_version_1() {
        let lock = format!("OP_1 {PUBKEY} OP_1 OP_CHECKMULTISIG OP_NOT");
        let msg = message(with_flags(&lock, &format!("0 {WRONG_SIG}"), 1, block()).validate());
        assert_eq!(
            msg,
            "OP_CHECKMULTISIG requires failing signatures to be empty."
        );
        assert!(valid(with_flags(&lock, "0 0", 1, block()).validate()));
        assert!(valid(
            with_flags(&lock, &format!("0 {WRONG_SIG}"), 2, block()).validate()
        ));
        assert!(valid(spend(&lock, &format!("0 {WRONG_SIG}"), 1).validate()));
    }

    #[test]
    fn nulldummy_is_a_standard_only_rule_gated_on_the_version() {
        // 0-of-0 multisig: only the dummy is consumed; OP_1 as the dummy.
        let lock = "OP_0 OP_0 OP_CHECKMULTISIG";
        // The block word never carries NULLDUMMY.
        assert!(valid(with_flags(lock, "OP_1", 1, block()).validate()));
        // The standard word does, under the gate: version 1 refused, version 2 accepted.
        let msg = message(with_flags(lock, "OP_1", 1, standard()).validate());
        assert_eq!(
            msg,
            "OP_CHECKMULTISIG requires the extra stack item (dummy) to be empty."
        );
        assert!(valid(with_flags(lock, "OP_1", 2, standard()).validate()));
        assert!(with_flags(
            lock,
            "OP_1",
            2,
            ScriptFlags::standard(ProtocolEra::PostGenesis)
        )
        .validate()
        .is_err());
        // The TypeScript default mode: strict at version 1, relaxed at version 2.
        assert!(spend(lock, "OP_1", 1).validate().is_err());
        assert!(valid(spend(lock, "OP_1", 2).validate()));
        // An empty dummy passes everywhere.
        assert!(valid(with_flags(lock, "0", 1, standard()).validate()));
    }

    #[test]
    fn minimaldata_low_s_and_cleanstack_follow_the_word_and_the_gate() {
        // A non-minimal push of 1 (`01 01` instead of OP_1) leaves a true top.
        let non_minimal = UnlockingScript::from_binary(&[0x01, 0x01]).unwrap();
        let mut s = spend("OP_1 OP_EQUAL", "", 1);
        s = Spend::new(SpendParams {
            unlocking_script: non_minimal.clone(),
            ..params_of(&s)
        });
        assert!(
            s.validate().is_err(),
            "the default mode enforces MINIMALDATA at version 1"
        );
        let mut s = Spend::new(SpendParams {
            unlocking_script: non_minimal.clone(),
            ..params_of(&spend("OP_1 OP_EQUAL", "", 1))
        });
        s.set_flags(block());
        assert!(
            valid(s.validate()),
            "the block word never carries MINIMALDATA"
        );
        let mut s = Spend::new(SpendParams {
            unlocking_script: non_minimal,
            ..params_of(&spend("OP_1 OP_EQUAL", "", 1))
        });
        s.set_flags(standard());
        assert!(
            s.validate().is_err(),
            "the standard word carries it, and version 1 is gated on"
        );

        // Two elements at the end: CLEANSTACK.
        assert!(valid(with_flags("OP_1 OP_1", "", 1, block()).validate()));
        assert!(with_flags("OP_1 OP_1", "", 1, standard())
            .validate()
            .is_err());
        assert!(valid(with_flags("OP_1 OP_1", "", 2, standard()).validate()));
    }

    /// `SpendParams` for a fresh interpreter with the same context as `s`.
    fn params_of(s: &Spend) -> SpendParams {
        SpendParams {
            source_txid: s.source_txid,
            source_output_index: s.source_output_index,
            source_satoshis: s.source_satoshis,
            locking_script: s.locking_script.clone(),
            transaction_version: s.transaction_version,
            other_inputs: s.other_inputs.clone(),
            outputs: s.outputs.clone(),
            input_index: s.input_index,
            unlocking_script: s.unlocking_script.clone(),
            input_sequence: s.input_sequence,
            lock_time: s.lock_time,
            memory_limit: Some(s.memory_limit),
        }
    }

    #[test]
    fn push_only_is_derived_from_the_word_and_the_version() {
        // A non-push opcode in the unlocking script.
        let lock = "OP_1 OP_EQUAL";
        let unlock = "OP_0 OP_1ADD";
        assert!(
            spend(lock, unlock, 2).validate().is_err(),
            "the default mode requires push-only at every version"
        );
        assert!(
            valid(with_flags(lock, unlock, 2, block()).validate()),
            "post-Chronicle, version 2: not required"
        );
        assert!(
            with_flags(lock, unlock, 1, block()).validate().is_err(),
            "post-Chronicle, version 1: required"
        );
        assert!(
            with_flags(
                lock,
                unlock,
                2,
                ScriptFlags::block(ProtocolEra::PostGenesis)
            )
            .validate()
            .is_err(),
            "pre-Chronicle: required at every version"
        );
        // The setter still overrides a derived rule.
        let mut s = with_flags(lock, unlock, 1, block());
        s.set_require_push_only(false);
        assert!(valid(s.validate()));
    }

    #[test]
    fn discourage_upgradable_nops_refuses_an_executed_nop1_to_nop10_under_the_standard_word_only() {
        // 0xb0-0xb2 and 0xb8-0xb9 are NOPs in every era; 0xb3-0xb7 only for a coin created
        // before Chronicle (their Chronicle meanings live under UTXO_AFTER_CHRONICLE), so
        // those are tested under the post-Genesis words.
        for (nop, era) in [
            ("OP_NOP1", ProtocolEra::PostChronicle),
            ("OP_NOP2", ProtocolEra::PostChronicle),
            ("OP_NOP3", ProtocolEra::PostChronicle),
            ("OP_NOP4", ProtocolEra::PostGenesis),
            ("OP_NOP8", ProtocolEra::PostGenesis),
            ("OP_NOP9", ProtocolEra::PostChronicle),
            ("OP_NOP10", ProtocolEra::PostChronicle),
        ] {
            let lock = format!("{nop} OP_1");
            assert!(
                valid(with_flags(&lock, "", 2, ScriptFlags::block(era)).validate()),
                "{nop}: a NOP in a block"
            );
            let msg = message(with_flags(&lock, "", 2, ScriptFlags::standard(era)).validate());
            assert_eq!(msg, format!("{nop} is discouraged by verification flags."));
            assert!(
                valid(spend(&lock, "", 1).validate()),
                "{nop}: the default mode has no such rule"
            );
        }
        // Not executed: not discouraged (interpreter.cpp: the check is inside fExec).
        assert!(valid(
            with_flags("OP_0 OP_IF OP_NOP1 OP_ENDIF OP_1", "", 2, standard()).validate()
        ));
        // OP_NOP itself is never discouraged.
        assert!(valid(
            with_flags("OP_NOP OP_1", "", 2, standard()).validate()
        ));
    }

    #[test]
    fn minimalif_requires_an_empty_or_0x01_argument_under_the_flag_and_the_gate() {
        let word = block() | ScriptFlags::MINIMALIF;
        let lock = "OP_IF OP_1 OP_ELSE OP_0 OP_ENDIF";
        assert!(valid(with_flags(lock, "OP_1", 1, word).validate()));
        let msg = message(with_flags(lock, "OP_2", 1, word).validate());
        assert_eq!(msg, "OP_IF and OP_NOTIF require minimal truth values.");
        assert!(
            valid(with_flags(lock, "OP_2", 2, word).validate()),
            "version 2 post-Chronicle: gated off"
        );
        assert!(
            valid(with_flags(lock, "OP_2", 1, block()).validate()),
            "not in the block word"
        );
        assert!(
            valid(spend(lock, "OP_2", 1).validate()),
            "not in the default mode"
        );
    }

    #[test]
    fn compressed_pubkeytype_refuses_an_uncompressed_key_under_the_flag() {
        // A well-formed uncompressed key (the generator point) with an empty signature:
        // CHECKSIG fails cleanly to false, then OP_NOT makes it true.
        let g = "0479be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8";
        let lock = format!("{g} OP_CHECKSIG OP_NOT");
        assert!(valid(with_flags(&lock, "0", 1, block()).validate()));
        let msg = message(
            with_flags(&lock, "0", 1, block() | ScriptFlags::COMPRESSED_PUBKEYTYPE).validate(),
        );
        assert_eq!(msg, "The public key must be compressed.");
        let compressed = format!("{PUBKEY} OP_CHECKSIG OP_NOT");
        assert!(valid(
            with_flags(
                &compressed,
                "0",
                1,
                block() | ScriptFlags::COMPRESSED_PUBKEYTYPE
            )
            .validate()
        ));
    }

    #[test]
    fn a_word_the_interpreter_cannot_honor_is_refused_by_validate_as_invalid_flags() {
        let word = block().without(ScriptFlags::SIGHASH_FORKID);
        let msg = message(with_flags("OP_1", "", 1, word).validate());
        assert!(
            msg.starts_with("Invalid verification flags: SIGHASH_FORKID is not set"),
            "{msg}"
        );
        let word = (standard() | ScriptFlags::CLEANSTACK).without(ScriptFlags::P2SH);
        let msg = message(with_flags("OP_1", "", 1, word).validate());
        assert!(msg.contains("CLEANSTACK without P2SH"), "{msg}");
        let s = with_flags("OP_1", "", 1, block());
        assert_eq!(s.flags(), Some(block()));
        assert_eq!(spend("OP_1", "", 1).flags(), None);
    }

    #[test]
    fn set_flags_replaces_the_default_switches_and_the_setters_override_afterwards() {
        // The default mode at version 1 enforces MINIMALDATA; the block word does not;
        // `set_require_minimal(true)` after `set_flags` re-enables it.
        let non_minimal = UnlockingScript::from_binary(&[0x01, 0x01]).unwrap();
        let mut s = Spend::new(SpendParams {
            unlocking_script: non_minimal,
            ..params_of(&spend("OP_1 OP_EQUAL", "", 1))
        });
        s.set_flags(block());
        s.set_require_minimal(true);
        assert!(s.validate().is_err());
        let _ = from_hex; // used by the witnesses' integration test; keep the import honest
    }
}

/// The five consensus divergences left after 0.3.26 (Calhooon/bsv-rs#12), each
/// rule on the smallest script that reaches it: the post-Chronicle opcodes and
/// their gate, the single-ELSE rule, a RETURN inside a conditional, truncated
/// pushes, undefined opcodes, and the scriptCode cleanup. Sites in `flags.rs`
/// and at the arms.
#[cfg(test)]
mod chronicle_tests {
    use super::*;
    use crate::script::flags::ProtocolEra;

    fn spend(lock_asm: &str, unlock_asm: &str, version: i32) -> Spend {
        Spend::new(SpendParams {
            source_txid: [0u8; 32],
            source_output_index: 0,
            source_satoshis: 1000,
            locking_script: LockingScript::from_asm(lock_asm).unwrap(),
            transaction_version: version,
            other_inputs: vec![],
            outputs: vec![],
            input_index: 0,
            unlocking_script: UnlockingScript::from_asm(unlock_asm).unwrap(),
            input_sequence: 0xffff_ffff,
            lock_time: 0,
            memory_limit: None,
        })
    }

    fn valid(r: Result<bool, ScriptEvaluationError>) -> bool {
        matches!(r, Ok(true))
    }

    fn message(r: Result<bool, ScriptEvaluationError>) -> String {
        r.expect_err("expected a refusal").message
    }

    #[test]
    fn substr_left_and_right_take_ranges_after_chronicle_and_refuse_out_of_range_ones() {
        // 0xb3 OP_SUBSTR (data offset len), 0xb4 OP_LEFT, 0xb5 OP_RIGHT (data len)
        assert!(valid(
            spend("OP_1 OP_2 OP_NOP4 bbcc OP_EQUAL", "aabbccdd", 2).validate()
        ));
        assert!(valid(
            spend("OP_2 OP_NOP5 aabb OP_EQUAL", "aabbccdd", 2).validate()
        ));
        assert!(valid(
            spend("OP_2 OP_NOP6 ccdd OP_EQUAL", "aabbccdd", 2).validate()
        ));
        assert!(valid(
            spend("OP_0 OP_NOP5 OP_0 OP_EQUAL", "aabbccdd", 2).validate()
        ));
        assert_eq!(
            message(spend("OP_5 OP_NOP5", "aabbccdd", 2).validate()),
            "OP_LEFT length (5) must be in range [0, 4]"
        );
        assert_eq!(
            message(spend("OP_4 OP_0 OP_NOP4", "aabbccdd", 2).validate()),
            "OP_SUBSTR offset (4) must be in range [0, 4) and length (0) must be in range [0, 0]"
        );
        assert!(
            message(spend("OP_1 OP_4 OP_NOP4", "aabbccdd", 2).validate())
                .starts_with("OP_SUBSTR offset (1)")
        );
        assert!(
            message(spend("OP_1NEGATE OP_NOP6", "aabbccdd", 2).validate())
                .contains("OP_RIGHT length (-1)")
        );
    }

    #[test]
    fn lshiftnum_and_rshiftnum_shift_script_numbers_toward_zero() {
        // 0xb6 OP_LSHIFTNUM, 0xb7 OP_RSHIFTNUM: (x n -- out) on numbers
        assert!(valid(
            spend("OP_1 OP_NOP7 OP_14 OP_EQUAL", "OP_7", 2).validate()
        ));
        assert!(valid(
            spend("OP_10 OP_NOP7 0004 OP_EQUAL", "OP_1", 2).validate()
        )); // 1 << 10 = 1024 = 0x0400 LE
            // -7 >> 1 is -3 (toward zero; 0x87 is -7, 0x83 is -3), not -4
        assert!(valid(spend("OP_1 OP_NOP8 83 OP_EQUAL", "87", 2).validate()));
        assert!(valid(
            spend("OP_1 OP_NOP8 OP_3 OP_EQUAL", "OP_7", 2).validate()
        ));
        // a shift past every bit is zero (the empty number)
        assert!(valid(
            spend("OP_16 OP_NOP8 OP_0 OP_EQUAL", "OP_7", 2).validate()
        ));
        assert!(valid(
            spend("OP_16 OP_NOP8 OP_0 OP_EQUAL", "87", 2).validate()
        ));
        // zero shifted left stays zero
        assert!(valid(
            spend("OP_16 OP_NOP7 OP_0 OP_EQUAL", "OP_0", 2).validate()
        ));
        assert_eq!(
            message(spend("OP_1NEGATE OP_NOP7", "OP_7", 2).validate()),
            "OP_LSHIFTNUM bits to shift must not be negative."
        );
        assert_eq!(
            message(spend("OP_1NEGATE OP_NOP8", "OP_7", 2).validate()),
            "OP_RSHIFTNUM bits to shift must not be negative."
        );
    }

    #[test]
    fn lshiftnum_refuses_a_result_beyond_the_memory_budget_before_computing_it() {
        let mut s = Spend::new(SpendParams {
            source_txid: [0u8; 32],
            source_output_index: 0,
            source_satoshis: 1000,
            locking_script: LockingScript::from_asm("2823 OP_NOP7").unwrap(), // 0x2328 = 9000 bits
            transaction_version: 2,
            other_inputs: vec![],
            outputs: vec![],
            input_index: 0,
            unlocking_script: UnlockingScript::from_asm("OP_1").unwrap(),
            input_sequence: 0xffff_ffff,
            lock_time: 0,
            memory_limit: Some(1000),
        });
        let err = s.validate().unwrap_err();
        assert!(err.is_resource_limit(), "{}", err.message);
        assert_eq!(
            err.resource_limit.unwrap().resource,
            ScriptResource::ElementSize
        );
    }

    #[test]
    fn before_chronicle_0xb3_to_0xb7_are_nops_and_discouraged_under_the_standard_word() {
        // version 1 in the default mode: the UTXO is taken as pre-Chronicle
        assert!(valid(
            spend("OP_NOP4 OP_NOP5 OP_NOP6 OP_NOP7 OP_NOP8", "OP_1", 1).validate()
        ));
        let mut s = spend("OP_NOP7 OP_1", "", 2);
        s.set_flags(ScriptFlags::standard(ProtocolEra::PostGenesis));
        assert_eq!(
            message(s.validate()),
            "OP_NOP7 is discouraged by verification flags."
        );
        // the block word of a post-Chronicle coin turns them on even at version 1
        let mut s = spend("OP_1 OP_NOP7 OP_14 OP_EQUAL", "OP_7", 1);
        s.set_flags(ScriptFlags::block(ProtocolEra::PostChronicle));
        assert!(valid(s.validate()));
        // and the setter overrides either way
        let mut s = spend("OP_1 OP_NOP7 OP_14 OP_EQUAL", "OP_7", 1);
        s.set_utxo_after_chronicle(true);
        assert!(valid(s.validate()));
    }

    #[test]
    fn op_ver_pushes_the_version_after_chronicle_and_is_refused_before() {
        assert!(valid(spend("OP_VER 02000000 OP_EQUAL", "", 2).validate()));
        assert_eq!(
            message(spend("OP_VER", "", 1).validate()),
            "OP_VER is disabled until Chronicle."
        );
        let mut s = spend("OP_VER 01000000 OP_EQUAL", "", 1);
        s.set_flags(ScriptFlags::block(ProtocolEra::PostChronicle));
        assert!(valid(s.validate()));
        // not executed: nothing happens, before or after Chronicle
        assert!(valid(
            spend("OP_0 OP_IF OP_VER OP_ENDIF OP_1", "", 1).validate()
        ));
    }

    #[test]
    fn op_verif_compares_the_top_with_the_version_and_is_skipped_or_refused_before_chronicle() {
        assert!(valid(
            spend("OP_VERIF OP_1 OP_ELSE OP_0 OP_ENDIF", "02000000", 2).validate()
        ));
        assert!(!valid(
            spend("OP_VERIF OP_1 OP_ELSE OP_0 OP_ENDIF", "01000000", 2).validate()
        ));
        // only an exactly 4-byte element can match; OP_2 (one byte) does not
        assert!(valid(
            spend("OP_VERIF OP_0 OP_ELSE OP_1 OP_ENDIF", "OP_2", 2).validate()
        ));
        assert!(valid(
            spend("OP_VERNOTIF OP_1 OP_ELSE OP_0 OP_ENDIF", "01000000", 2).validate()
        ));
        assert!(valid(
            spend("OP_VERNOTIF OP_0 OP_ELSE OP_1 OP_ENDIF", "02000000", 2).validate()
        ));
        // before Chronicle: executed is refused, not executed is skipped (no conditional pushed)
        assert_eq!(
            message(spend("OP_VERIF OP_1 OP_ENDIF", "02000000", 1).validate()),
            "OP_VERIF is disabled until Chronicle."
        );
        assert!(valid(
            spend("OP_0 OP_IF OP_VERIF OP_ENDIF OP_1", "", 1).validate()
        ));
        assert!(valid(
            spend("OP_0 OP_IF OP_VERNOTIF OP_ENDIF OP_1", "", 1).validate()
        ));
    }

    #[test]
    fn two_mul_and_two_div_are_disabled_before_chronicle_and_compute_after() {
        assert!(message(spend("OP_2MUL", "OP_7", 1).validate()).contains("currently disabled"));
        assert!(message(spend("OP_2DIV", "OP_7", 1).validate()).contains("currently disabled"));
        assert!(valid(spend("OP_2MUL OP_14 OP_EQUAL", "OP_7", 2).validate()));
        assert!(valid(spend("OP_2DIV OP_3 OP_EQUAL", "OP_7", 2).validate()));
        assert!(valid(spend("OP_2DIV 83 OP_EQUAL", "87", 2).validate())); // -7 / 2 = -3
        assert!(valid(spend("OP_2MUL 8e OP_EQUAL", "87", 2).validate())); // -7 * 2 = -14 (0x8e)
                                                                          // not executed: no refusal before Chronicle either (interpreter.cpp:458-459, post-Genesis)
        assert!(valid(
            spend("OP_0 OP_IF OP_2MUL OP_ENDIF OP_1", "", 1).validate()
        ));
    }

    #[test]
    fn one_op_else_per_op_if_after_genesis() {
        assert!(valid(
            spend("OP_IF OP_1 OP_ELSE OP_0 OP_ENDIF", "OP_1", 2).validate()
        ));
        assert_eq!(
            message(spend("OP_IF OP_1 OP_ELSE OP_1 OP_ELSE OP_1 OP_ENDIF", "OP_1", 2).validate()),
            "OP_ELSE may only be used once for each OP_IF or OP_NOTIF after Genesis."
        );
        // one per level, nested
        assert!(valid(
            spend(
                "OP_IF OP_0 OP_IF OP_ELSE OP_ENDIF OP_ELSE OP_ENDIF OP_1",
                "OP_1",
                2
            )
            .validate()
        ));
        // in every mode: version 1 too
        assert!(
            message(spend("OP_IF OP_ELSE OP_ELSE OP_ENDIF OP_1", "OP_1", 1).validate())
                .contains("only be used once")
        );
    }

    #[test]
    fn a_return_inside_a_conditional_stops_execution_but_the_balance_and_the_parse_still_hold() {
        // execution stops at the RETURN: the OP_0 after it never runs, the ENDIF still closes the IF
        assert!(valid(
            spend("OP_1 OP_IF OP_RETURN OP_0 OP_ENDIF", "OP_1", 2).validate()
        ));
        // the conditional must still balance
        assert!(message(spend("OP_1 OP_IF OP_RETURN", "OP_1", 2).validate())
            .contains("terminated with OP_ENDIF"));
        // an undefined opcode after the RETURN is not executed: fine
        let lock = LockingScript::from_binary(&[0x51, 0x63, 0x6a, 0x68, 0xba]).unwrap();
        let mut s = spend("OP_1", "OP_1", 2);
        s = Spend::new(SpendParams {
            locking_script: lock,
            ..params_of(&s)
        });
        assert!(valid(s.validate()));
        // a truncated push after the RETURN is still a parse failure
        let lock = LockingScript::from_binary(&[0x51, 0x63, 0x6a, 0x68, 0x03, 0x01]).unwrap();
        let mut s = Spend::new(SpendParams {
            locking_script: lock,
            ..params_of(&spend("OP_1", "OP_1", 2))
        });
        assert!(message(s.validate()).starts_with("A push declares more bytes"));
        // a top-level RETURN ends the script successfully, whatever follows
        let lock = LockingScript::from_binary(&[0x51, 0x6a, 0xba, 0x03, 0x01]).unwrap();
        let mut s = Spend::new(SpendParams {
            locking_script: lock,
            ..params_of(&spend("OP_1", "", 2))
        });
        assert!(valid(s.validate()));
    }

    #[test]
    fn an_undefined_opcode_is_refused_only_when_executed() {
        assert!(message(spend("OP_1 OP_NOP77", "", 2).validate()).starts_with("Invalid opcode 252"));
        assert!(valid(
            spend("OP_0 OP_IF OP_NOP77 OP_ENDIF OP_1", "", 2).validate()
        ));
        let lock = LockingScript::from_binary(&[0x51, 0xba]).unwrap();
        let mut s = Spend::new(SpendParams {
            locking_script: lock,
            ..params_of(&spend("OP_1", "", 1))
        });
        assert!(message(s.validate()).starts_with("Invalid opcode 186"));
    }

    #[test]
    fn a_truncated_push_is_refused_where_the_walk_reaches_it_even_unexecuted() {
        // OP_0 OP_IF <push 3 with 1 byte>: the branch does not execute, the parse still fails there
        let lock = LockingScript::from_binary(&[0x00, 0x63, 0x03, 0x01]).unwrap();
        assert_eq!(lock.as_script().truncated_push(), Some(2));
        let mut s = Spend::new(SpendParams {
            locking_script: lock,
            ..params_of(&spend("OP_1", "", 2))
        });
        assert!(message(s.validate()).contains("(pc=2)"));
        // a complete script has no truncated push; bytes after a top-level RETURN are data
        assert_eq!(
            Script::from_binary(&[0x51, 0x03, 0x01, 0x02, 0x03])
                .unwrap()
                .truncated_push(),
            None
        );
        assert_eq!(
            Script::from_binary(&[0x6a, 0x03, 0x01])
                .unwrap()
                .truncated_push(),
            None
        );
        assert_eq!(
            Script::from_binary(&[0x4c]).unwrap().truncated_push(),
            Some(0)
        );
        assert_eq!(
            Script::from_binary(&[0x51, 0x4d, 0x01])
                .unwrap()
                .truncated_push(),
            Some(1)
        );
        assert_eq!(
            Script::from_binary(&[0x4e, 0x01, 0x00, 0x00, 0x00])
                .unwrap()
                .truncated_push(),
            Some(0)
        );
        assert_eq!(
            Script::from_binary(&[0x4e, 0x01, 0x00, 0x00, 0x00, 0xaa])
                .unwrap()
                .truncated_push(),
            None
        );
        // an earlier failure wins: the walk never reaches the truncated push
        let lock = LockingScript::from_binary(&[0x69, 0x03, 0x01]).unwrap(); // OP_VERIFY on an empty stack
        let mut s = Spend::new(SpendParams {
            locking_script: lock,
            ..params_of(&spend("OP_1", "", 2))
        });
        assert!(message(s.validate()).contains("OP_VERIFY requires"));
    }

    #[test]
    fn the_scriptcode_keeps_a_forkid_signatures_push_and_deletes_an_empty_ones_op_0() {
        let sig = "304402204c9195e05dc41a9119b4cf65f43e450a057818d74c12265faee6a21ae2e0ab87022051c94bb55d9c54d68efaa16785c6ba6a7958757745528974a92d8cddcb993c1241";
        let lock_asm = format!("{sig} OP_DROP OP_1");
        let mut s = spend(&lock_asm, "", 2);
        s.context = ExecutionContext::LockingScript;
        let sig_bytes = crate::primitives::from_hex(sig).unwrap();
        assert!(has_forkid_bit(&sig_bytes));
        let sub = s.build_subscript(&sig_bytes).unwrap();
        assert_eq!(
            sub.to_binary(),
            s.locking_script.to_binary(),
            "a FORKID signature's push stays"
        );
        // an empty signature carries no hash type: its OP_0 push is deleted, as on the reference
        let mut s = spend("OP_0 OP_1 OP_0", "", 2);
        s.context = ExecutionContext::LockingScript;
        assert!(!has_forkid_bit(&[]));
        let sub = s.build_subscript(&[]).unwrap();
        assert_eq!(sub.to_asm(), "OP_1");
        // a signature without the FORKID bit would be deleted (and is refused by the encoding check)
        assert!(!has_forkid_bit(&[
            0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01, 0x01
        ]));
    }

    /// `SpendParams` for a fresh interpreter with the same context as `s`.
    fn params_of(s: &Spend) -> SpendParams {
        SpendParams {
            source_txid: s.source_txid,
            source_output_index: s.source_output_index,
            source_satoshis: s.source_satoshis,
            locking_script: s.locking_script.clone(),
            transaction_version: s.transaction_version,
            other_inputs: s.other_inputs.clone(),
            outputs: s.outputs.clone(),
            input_index: s.input_index,
            unlocking_script: s.unlocking_script.clone(),
            input_sequence: s.input_sequence,
            lock_time: s.lock_time,
            memory_limit: Some(s.memory_limit),
        }
    }
}

/// The low-S check at the curve order (Calhooon/bsv-rs#14): an `r` or `s` at or
/// above the order is the zero signature for the reference's lax parse, which
/// is low; only n/2 < s < n is a high-S refusal.
#[cfg(test)]
mod low_s_order_tests {
    use super::*;

    const N: &str = "fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141";
    const HALF: &str = "7fffffffffffffffffffffffffffffff5d576e7357a4501ddfe92f46681b20a0";

    /// A strict-DER signature (r, s as 32-byte big-endian hex) with the FORKID hash type.
    fn der(r: &str, s: &str) -> Vec<u8> {
        fn int(hex: &str) -> Vec<u8> {
            let mut v = crate::primitives::from_hex(hex).unwrap();
            while v.len() > 1 && v[0] == 0 && v[1] & 0x80 == 0 {
                v.remove(0);
            }
            if v[0] & 0x80 != 0 {
                v.insert(0, 0);
            }
            let mut out = vec![0x02, v.len() as u8];
            out.extend(v);
            out
        }
        let body = [int(r), int(s)].concat();
        let mut out = vec![0x30, body.len() as u8];
        out.extend(body);
        out.push(0x41);
        out
    }

    fn checker() -> Spend {
        Spend::new(SpendParams {
            source_txid: [0u8; 32],
            source_output_index: 0,
            source_satoshis: 1000,
            locking_script: LockingScript::from_asm("OP_1").unwrap(),
            transaction_version: 1, // the default mode at version 1 requires low S
            other_inputs: vec![],
            outputs: vec![],
            input_index: 0,
            unlocking_script: UnlockingScript::new(),
            input_sequence: 0xffff_ffff,
            lock_time: 0,
            memory_limit: None,
        })
    }

    fn s_plus(hex: &str, k: u64) -> String {
        let v = BigNumber::from_bytes_be(&crate::primitives::from_hex(hex).unwrap())
            .add(&BigNumber::from_i64(k as i64));
        crate::primitives::to_hex(&v.to_bytes_be(32))
    }

    #[test]
    fn s_at_or_above_the_order_passes_the_low_s_check_as_the_zero_signature() {
        let one = "0000000000000000000000000000000000000000000000000000000000000001";
        let c = checker();
        assert!(c.check_signature_encoding(&der(one, N)).is_ok(), "s = n");
        assert!(
            c.check_signature_encoding(&der(one, &s_plus(N, 1))).is_ok(),
            "s = n + 1"
        );
        assert!(c.check_signature_encoding(&der(N, one)).is_ok(), "r = n");
        // the boundary: n/2 is low, n/2 + 1 through n - 1 are high
        assert!(
            c.check_signature_encoding(&der(one, HALF)).is_ok(),
            "s = n/2"
        );
        let high = c
            .check_signature_encoding(&der(one, &s_plus(HALF, 1)))
            .unwrap_err();
        assert_eq!(high.message, "The signature must have a low S value.");
        let n_minus_1 = "fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364140";
        assert_eq!(
            c.check_signature_encoding(&der(one, n_minus_1))
                .unwrap_err()
                .message,
            "The signature must have a low S value."
        );
        // and such a signature never verifies: a CHECKSIG with s = n at version 1 under the
        // block word is NULLFAIL, in the default mode a false top
        let pk = "035935f55855afd8c999bdb5a8d08ae8e73b7618e200d4ef7687cd55d3c2e4c9d7";
        let sig_hex = crate::primitives::to_hex(&der(one, N));
        let mut spend = Spend::new(SpendParams {
            source_txid: [0u8; 32],
            source_output_index: 0,
            source_satoshis: 1000,
            locking_script: LockingScript::from_asm(&format!("{pk} OP_CHECKSIG")).unwrap(),
            transaction_version: 1,
            other_inputs: vec![],
            outputs: vec![],
            input_index: 0,
            unlocking_script: UnlockingScript::from_asm(&sig_hex).unwrap(),
            input_sequence: 0xffff_ffff,
            lock_time: 0,
            memory_limit: None,
        });
        spend.set_flags(ScriptFlags::block(
            crate::script::flags::ProtocolEra::PostChronicle,
        ));
        assert_eq!(
            spend.validate().unwrap_err().message,
            "OP_CHECKSIG requires failing signatures to be empty."
        );
    }
}
