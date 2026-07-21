//! Bitcoin Script interpreter for spend validation.
//!
// Allow large error type - ScriptEvaluationError intentionally captures full
// execution state for debugging failed script executions.
#![allow(clippy::result_large_err)]
//!
//! This module implements the full Bitcoin Script interpreter for BSV, enabling
//! validation of transaction spends by executing unlocking and locking scripts.
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

use super::evaluation_error::{ExecutionContext, ScriptEvaluationError};
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
            // (post-Genesis semantics) — MINIMALDATA, LOW_S and CLEANSTACK are
            // not enforced (mirrors ts-sdk Spend.isRelaxed()).
            require_minimal: REQUIRE_MINIMAL_PUSH && params.transaction_version <= 1,
            require_low_s: REQUIRE_LOW_S_SIGNATURES && params.transaction_version <= 1,
            require_clean_stack: REQUIRE_CLEAN_STACK && params.transaction_version <= 1,
        };
        spend.unlocking_chunks = spend.unlocking_script.chunks();
        spend.locking_chunks = spend.locking_script.chunks();
        spend.reset();
        spend
    }

    /// Overrides MINIMALDATA enforcement (script-number and push minimality).
    ///
    /// Default follows ts-sdk: enforced for version <= 1 transactions, relaxed
    /// for version > 1 (post-Genesis semantics).
    pub fn set_require_minimal(&mut self, require: bool) {
        self.require_minimal = require;
    }

    /// Allows opting out of the push-only unlocking-script check.
    ///
    /// The TypeScript `@bsv/sdk` Spend engine does not enforce push-only
    /// unlocking scripts; some OP_PUSH_TX-style covenant designs place
    /// executable code in the unlocking script and verify under that engine.
    /// Default remains `true` (enforced).
    pub fn set_require_push_only(&mut self, require: bool) {
        self.require_push_only = require;
    }

    /// Resets the interpreter state for re-execution.
    pub fn reset(&mut self) {
        self.context = ExecutionContext::UnlockingScript;
        self.program_counter = 0;
        self.last_code_separator = None;
        self.stack.clear();
        self.alt_stack.clear();
        self.if_stack.clear();
        self.stack_mem = 0;
        self.alt_stack_mem = 0;
    }

    /// Validates the spend by executing both scripts.
    ///
    /// # Returns
    ///
    /// `Ok(true)` if the spend is valid, or an error describing why validation failed.
    pub fn validate(&mut self) -> Result<bool, ScriptEvaluationError> {
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
        // Check memory limits
        if self.stack_mem > self.memory_limit {
            return Err(self.error(&format!(
                "Stack memory usage has exceeded {} bytes",
                self.memory_limit
            )));
        }
        if self.alt_stack_mem > self.memory_limit {
            return Err(self.error(&format!(
                "Alt stack memory usage has exceeded {} bytes",
                self.memory_limit
            )));
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
        let is_executing = !self.if_stack.contains(&false);

        // Check for disabled opcodes when executing
        if is_executing && is_opcode_disabled(current_opcode) {
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
        let is_executing = !self.if_stack.contains(&false);

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
            OP_NOP | OP_NOP1 | OP_NOP2 | OP_NOP3 | OP_NOP4 | OP_NOP5 | OP_NOP6 | OP_NOP7
            | OP_NOP8 | OP_NOP9 | OP_NOP10 => {}
            // Extended NOPs (0xba-0xff)
            0xba..=0xff => {}

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
                    f_value = ScriptNum::cast_to_bool(&buf);
                    if opcode == OP_NOTIF {
                        f_value = !f_value;
                    }
                }
                self.if_stack.push(f_value);
            }
            OP_ELSE => {
                if self.if_stack.is_empty() {
                    return Err(self.error("OP_ELSE requires a preceeding OP_IF."));
                }
                let last = self.if_stack.len() - 1;
                self.if_stack[last] = !self.if_stack[last];
            }
            OP_ENDIF => {
                if self.if_stack.is_empty() {
                    return Err(self.error("OP_ENDIF requires a preceeding OP_IF."));
                }
                self.if_stack.pop();
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
                // Jump to end of current script
                let end = match self.context {
                    ExecutionContext::UnlockingScript => self.unlocking_chunks.len(),
                    ExecutionContext::LockingScript => self.locking_chunks.len(),
                };
                self.program_counter = end;
                self.if_stack.clear();
                // Counteract the final increment
                if self.program_counter > 0 {
                    self.program_counter -= 1;
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
            OP_1ADD | OP_1SUB | OP_NEGATE | OP_ABS | OP_NOT | OP_0NOTEQUAL => {
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

        for sig in &sigs {
            let sig_script = Script::new();
            let mut sig_script = sig_script;
            sig_script.write_bin(sig);
            subscript.find_and_delete(&sig_script);
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

        // Pop dummy element (NULLDUMMY)
        if self.stack.is_empty() {
            return Err(self.error(&format!(
                "{} requires an extra item (dummy) to be on the stack.",
                opcode_to_name(opcode).unwrap_or("OP_CHECKMULTISIG")
            )));
        }
        let dummy = self.pop_stack()?;
        if !dummy.is_empty() {
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

        if self.require_low_s && !tx_sig.has_low_s() {
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

        // Remove the signature from the subscript
        let mut sig_script = Script::new();
        sig_script.write_bin(sig_bytes);
        subscript.find_and_delete(&sig_script);

        Ok(subscript)
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
            return Err(self.error(&format!(
                "Stack memory usage has exceeded {} bytes",
                self.memory_limit
            )));
        }
        Ok(())
    }

    fn ensure_alt_stack_mem(&self, additional: usize) -> Result<(), ScriptEvaluationError> {
        if self.alt_stack_mem + additional > self.memory_limit {
            return Err(self.error(&format!(
                "Alt stack memory usage has exceeded {} bytes",
                self.memory_limit
            )));
        }
        Ok(())
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

/// Checks if an opcode is disabled.
fn is_opcode_disabled(op: u8) -> bool {
    matches!(op, OP_2MUL | OP_2DIV | OP_VER | OP_VERIF | OP_VERNOTIF)
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
        assert!(is_opcode_disabled(OP_2MUL));
        assert!(is_opcode_disabled(OP_2DIV));
        assert!(is_opcode_disabled(OP_VER));
        assert!(is_opcode_disabled(OP_VERIF));
        assert!(is_opcode_disabled(OP_VERNOTIF));

        assert!(!is_opcode_disabled(OP_DUP));
        assert!(!is_opcode_disabled(OP_MUL));
        assert!(!is_opcode_disabled(OP_CAT));
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
