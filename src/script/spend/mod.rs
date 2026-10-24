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
//! # The memory budget
//!
//! `SpendParams::memory_limit` is a LOCAL budget: exhausting it stops the
//! evaluation with a resource limit
//! ([`ScriptEvaluationError::resource_limit`]), never a verdict, and `Some(n)`
//! wins in every mode. With `None`, the default mode keeps the TypeScript
//! SDK's 32,000,000 bytes for each stack apart, counting the bytes alone.
//! Under a word the count is the node's (one budget over the main and the alt
//! stack, 32 bytes of overhead per element, every growth charged before it
//! happens, `src/script/limitedstack.cpp`) and `None` selects 100,000,000
//! bytes, the node's policy default (`src/policy/policy.h:153`), on both
//! paths. On the mempool path the node's stack memory policy is a verdict
//! besides: a growth above it is `SCRIPT_ERR_STACK_SIZE` on the reference
//! ([`Spend::stack_memory_policy`], [`Spend::set_stack_memory_policy`]).
//!
//! On the block path a node's budget is its operator's
//! `-maxstackmemoryusageconsensus`, a mandatory setting (bitcoin-sv v1.2.2 does
//! not start without it, `src/bitcoind.cpp:140-157`) in which 0 means
//! `INT64_MAX` (`src/configscriptpolicy.cpp:280-283`): no constant a library can
//! adopt, so above its local budget the evaluator declines, it never decides.
//! A caller modelling a node run with 0 passes `memory_limit: Some(usize::MAX)`:
//! the evaluation then allocates what the script asks (`OP_NUM2BIN` alone asks
//! up to `INT32_MAX` bytes, and an error's report copies the stack) and decides
//! as that node does.
//!
//! A decline is an `Err` whose
//! [`resource_limit`](ScriptEvaluationError::resource_limit) is `Some`
//! ([`ScriptEvaluationError::is_resource_limit`]): the evaluator stopped and the
//! script was not judged. A caller that judges validity branches on it first
//! and never reads a decline as invalid.
//!
//! # The work budget
//!
//! `work_limit: Some(n)` bounds one input's evaluation: one unit per opcode
//! reached (including skipped branches), plus each byte fed to a hash. Double
//! SHA-256 and HASH160 include the 32-byte intermediate; sighashes include the
//! serialized preimage and uncached BIP-143 midstates. Every charge precedes
//! its work. Overflow declines, and charged work never exceeds the budget.
//! `None` preserves the unbounded evaluation. This is a local resource bound,
//! not a clock or a node rule: parsing, allocation, arithmetic and EC costs
//! are not byte-hash measurements. A declined spend must be reset to run again.
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
//!     work_limit: None,
//! });
//!
//! let valid = spend.validate()?;
//! ```

use super::evaluation_error::{ExecutionContext, ScriptEvaluationError, ScriptResource};
use super::flags::{
    ScriptFlags, DEFAULT_SCRIPT_NUM_LENGTH_POLICY, DEFAULT_STACK_MEMORY_USAGE_POLICY,
};
use super::op::*;
use super::script_num::ScriptNum;
use super::{LockingScript, ScriptChunk, UnlockingScript};
use crate::primitives::bsv::sighash::{TxInput, TxOutput, TxSighashCache};
use crate::primitives::{to_hex, BigNumber};
use std::sync::Arc;

mod arithmetic;
mod bitwise;
mod crypto;
mod flow;
mod limits;
mod num;
mod splice;
mod stack;
mod stack_ops;
mod word;

use flow::is_opcode_disabled;
use limits::MAX_SCRIPT_ELEMENT_SIZE;

// ============================================================================
// Configuration Constants
// ============================================================================

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
    /// The LOCAL memory budget in bytes: exhausting it is a resource limit
    /// ([`ScriptEvaluationError::resource_limit`]), never a verdict, and
    /// `Some(n)` wins in every mode. `None` selects the mode's figure: 32,000,000
    /// bytes in the default mode, 100,000,000 on the node's count under a word
    /// ([`Spend::memory_limit`]). `Some(usize::MAX)` under the block word models
    /// a node run with `-maxstackmemoryusageconsensus=0`.
    pub memory_limit: Option<usize>,
    /// LOCAL work budget: one unit per opcode plus bytes hashed (both rounds
    /// of double hashes and uncached sighash midstates). `None` is unbounded.
    /// Exhaustion is `ScriptResource::Work`, never a validity verdict.
    pub work_limit: Option<u64>,
}

/// Parameters for a spend of one input of a transaction whose input and
/// output lists, and sighash midstates, are shared by the spends of all its
/// inputs ([`Spend::with_transaction`]). The outpoint and the sequence are
/// the transaction's input at `input_index`.
pub struct TxSpendParams {
    /// The spending transaction: its version, inputs, outputs and lock time,
    /// with the midstates every input's signature checks share.
    pub transaction: Arc<TxSighashCache>,
    /// The index of this input in the spending transaction.
    pub input_index: usize,
    /// The satoshi value of the source UTXO.
    pub source_satoshis: u64,
    /// The locking script of the source UTXO.
    pub locking_script: LockingScript,
    /// The unlocking script for this spend.
    pub unlocking_script: UnlockingScript,
    /// As [`SpendParams::memory_limit`].
    pub memory_limit: Option<usize>,
    /// LOCAL work budget: one unit per opcode plus bytes hashed (both rounds
    /// of double hashes and uncached sighash midstates). `None` is unbounded.
    /// Exhaustion is `ScriptResource::Work`, never a validity verdict.
    pub work_limit: Option<u64>,
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
    /// The spending transaction and its sighash midstates, shared by the
    /// spends of its inputs (one input list per transaction, not per input).
    transaction: Arc<TxSighashCache>,
    input_index: usize,
    unlocking_script: UnlockingScript,

    // Execution state
    context: ExecutionContext,
    program_counter: usize,
    last_code_separator: Option<usize>,
    stack: Vec<Vec<u8>>,
    alt_stack: Vec<Vec<u8>>,
    if_stack: Vec<bool>,
    /// `SpendParams::memory_limit`; `None` selects the mode's figure
    /// ([`Spend::memory_limit`]).
    memory_limit: Option<usize>,
    work_limit: Option<u64>,
    work_spent: u64,
    work_declined: Option<u64>,
    stack_mem: usize,
    alt_stack_mem: usize,
    /// Under a word, the node's stack memory count: ONE budget over the main
    /// and the alt stack (the alt stack is a child of the main stack,
    /// `interpreter.cpp:1993`, whose growth the parent counts,
    /// `limitedstack.cpp:196-199`), every element at its size plus
    /// `STACK_ELEMENT_OVERHEAD` (`limitedstack.h:43`, charged at `163`,
    /// `171`), every growth charged before it happens (`194-209`). The node's
    /// alt stack is created per script and nothing releases its elements'
    /// charge when it is dropped (`LimitedStack` declares no destructor,
    /// `limitedstack.h:78-151`), so an alt stack the unlocking script leaves
    /// non-empty stays charged while the locking script runs.
    node_mem: u64,
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
    /// The node's `-maxscriptnumlengthpolicy`, the script-number length limit
    /// of the mempool path (`src/policy/policy.h:156`, default 10,000; 0
    /// selects the consensus limit); read under a word carrying the mempool
    /// word's bits, see [`Spend::max_script_num_length`].
    script_num_length_policy: usize,
    /// The node's `-maxstackmemoryusagepolicy`, the stack memory budget of the
    /// mempool path (`src/policy/policy.h:153`, default 100,000,000; 0 selects
    /// none); read under a word carrying the mempool word's bits, see
    /// [`Spend::stack_memory_policy`].
    stack_memory_policy: usize,
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
    /// Creates a new Spend validator from the given parameters. The input
    /// list is `other_inputs` with this input inserted at `input_index` (at
    /// the end when the index is past them), built once here.
    pub fn new(params: SpendParams) -> Self {
        let ours = TxInput {
            txid: params.source_txid,
            output_index: params.source_output_index,
            script: params.unlocking_script.to_binary(),
            sequence: params.input_sequence,
        };
        let mut inputs = params.other_inputs;
        inputs.insert(params.input_index.min(inputs.len()), ours);
        let transaction = Arc::new(TxSighashCache::new(
            params.transaction_version,
            inputs,
            params.outputs,
            params.lock_time,
        ));
        Self::from_parts(
            transaction,
            params.input_index,
            (params.source_txid, params.source_output_index),
            params.source_satoshis,
            params.locking_script,
            params.unlocking_script,
            params.memory_limit,
            params.work_limit,
        )
    }

    /// A spend of input `input_index` of a transaction shared among the
    /// spends of its inputs: nothing is copied per input, and the BIP-143
    /// midstates are computed at most once per transaction
    /// ([`TxSighashCache`]). The outpoint and sequence are the transaction's
    /// input's. The verdict is [`Spend::new`]'s for the same transaction.
    ///
    /// # Errors
    ///
    /// `input_index` names no input of the transaction.
    pub fn with_transaction(params: TxSpendParams) -> crate::Result<Self> {
        let input = params
            .transaction
            .inputs()
            .get(params.input_index)
            .ok_or_else(|| {
                crate::Error::ScriptExecutionError(format!(
                    "input index {} out of range (transaction has {} inputs)",
                    params.input_index,
                    params.transaction.inputs().len()
                ))
            })?;
        let outpoint = (input.txid, input.output_index);
        Ok(Self::from_parts(
            params.transaction,
            params.input_index,
            outpoint,
            params.source_satoshis,
            params.locking_script,
            params.unlocking_script,
            params.memory_limit,
            params.work_limit,
        ))
    }

    #[allow(clippy::too_many_arguments)]
    fn from_parts(
        transaction: Arc<TxSighashCache>,
        input_index: usize,
        (source_txid, source_output_index): ([u8; 32], u32),
        source_satoshis: u64,
        locking_script: LockingScript,
        unlocking_script: UnlockingScript,
        memory_limit: Option<usize>,
        work_limit: Option<u64>,
    ) -> Self {
        let transaction_version = transaction.version();
        let mut spend = Self {
            source_txid,
            source_output_index,
            source_satoshis,
            locking_script,
            transaction_version,
            transaction,
            input_index,
            unlocking_script,
            context: ExecutionContext::UnlockingScript,
            program_counter: 0,
            unlocking_chunks: Vec::new(),
            locking_chunks: Vec::new(),
            last_code_separator: None,
            stack: Vec::new(),
            alt_stack: Vec::new(),
            if_stack: Vec::new(),
            memory_limit,
            work_limit,
            work_spent: 0,
            work_declined: None,
            stack_mem: 0,
            alt_stack_mem: 0,
            node_mem: 0,
            require_push_only: REQUIRE_PUSH_ONLY_UNLOCKING,
            // ts-sdk parity: transactions with version > 1 run "relaxed"
            // (post-Genesis semantics) — MINIMALDATA, LOW_S, CLEANSTACK and
            // NULLDUMMY are not enforced (mirrors ts-sdk Spend.isRelaxed() and
            // its shouldEnforceNullDummy()). The reference gates the same four
            // on the version at Chronicle (`interpreter.cpp:40-44`).
            require_minimal: REQUIRE_MINIMAL_PUSH && transaction_version <= 1,
            require_low_s: REQUIRE_LOW_S_SIGNATURES && transaction_version <= 1,
            require_clean_stack: REQUIRE_CLEAN_STACK && transaction_version <= 1,
            require_null_dummy: transaction_version <= 1,
            // Not in the ts-sdk default mode (its NULLFAIL, MINIMALIF and
            // DISCOURAGE_UPGRADABLE_NOPS exist only under explicit verifyFlags);
            // derived from a word by `set_flags`.
            require_null_fail: false,
            require_minimal_if: false,
            require_compressed_pubkey: false,
            discourage_upgradable_nops: false,
            flags: None,
            // ts-sdk parity: isAfterChronicle() is isRelaxed() without explicit flags.
            utxo_after_chronicle: transaction_version > 1,
            script_num_length_policy: DEFAULT_SCRIPT_NUM_LENGTH_POLICY,
            stack_memory_policy: DEFAULT_STACK_MEMORY_USAGE_POLICY,
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
        self.node_mem = 0;
        self.work_spent = 0;
        self.work_declined = None;
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
        if let Some(attempted) = self.work_declined {
            return Err(self.work_error(attempted));
        }
        // Check memory limits — a LOCAL budget, reported as a resource limit
        // (the reference's `ScriptResourceLimitError`), never as a verdict on
        // the script. The default mode's, each stack apart; under a word every
        // growth is charged to the node's count before it happens instead
        // (`charge`).
        if self.flags.is_none() {
            let limit = self.memory_limit();
            if self.stack_mem > limit {
                return Err(self.resource_error(ScriptResource::Stack, self.stack_mem));
            }
            if self.alt_stack_mem > limit {
                return Err(self.resource_error(ScriptResource::AltStack, self.alt_stack_mem));
            }
        }

        // Switch from unlocking to locking script when unlocking is complete.
        // ts-sdk parity: conditionals must be terminated, the alt stack is
        // cleared, and the last code separator does not carry across scripts.
        // Under a word the node's count keeps the cleared alt stack's charge
        // (`node_mem`): the reference drops the unlocking script's alt stack
        // without releasing it.
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

        self.charge_work(1)?;
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
            OP_NOP1 | OP_NOP2 | OP_NOP3 | OP_NOP9 | OP_NOP10 => self.op_upgradable_nop(opcode)?,
            OP_NOP4 | OP_NOP5 | OP_NOP6 | OP_NOP7 | OP_NOP8 => self.op_nop4_to_nop8(opcode)?,
            OP_VER => self.op_ver()?,

            // ================================================================
            // Flow Control (0x63-0x6a)
            // ================================================================
            OP_IF | OP_NOTIF => self.op_if(opcode, is_executing)?,
            OP_VERIF | OP_VERNOTIF => self.op_verif(opcode, is_executing)?,
            OP_ELSE => self.op_else()?,
            OP_ENDIF => self.op_endif()?,
            OP_VERIFY => self.op_verify()?,
            OP_RETURN => self.op_return()?,

            // ================================================================
            // Stack Operations (0x6b-0x7d)
            // ================================================================
            OP_TOALTSTACK => self.op_toaltstack()?,
            OP_FROMALTSTACK => self.op_fromaltstack()?,
            OP_2DROP => self.op_2drop()?,
            OP_2DUP => self.op_2dup()?,
            OP_3DUP => self.op_3dup()?,
            OP_2OVER => self.op_2over()?,
            OP_2ROT => self.op_2rot()?,
            OP_2SWAP => self.op_2swap()?,
            OP_IFDUP => self.op_ifdup()?,
            OP_DEPTH => self.op_depth()?,
            OP_DROP => self.op_drop()?,
            OP_DUP => self.op_dup()?,
            OP_NIP => self.op_nip()?,
            OP_OVER => self.op_over()?,
            OP_PICK | OP_ROLL => self.op_pick_roll(opcode)?,
            OP_ROT => self.op_rot()?,
            OP_SWAP => self.op_swap()?,
            OP_TUCK => self.op_tuck()?,
            OP_SIZE => self.op_size()?,

            // ================================================================
            // Splice Operations (BSV re-enabled)
            // ================================================================
            OP_CAT => self.op_cat()?,
            OP_SPLIT => self.op_split()?,
            OP_NUM2BIN => self.op_num2bin()?,
            OP_BIN2NUM => self.op_bin2num()?,

            // ================================================================
            // Bitwise Operations
            // ================================================================
            OP_INVERT => self.op_invert()?,
            OP_AND | OP_OR | OP_XOR => self.op_bitwise_logic(opcode)?,
            OP_EQUAL | OP_EQUALVERIFY => self.op_equal(opcode)?,
            OP_LSHIFT | OP_RSHIFT => self.op_shift(opcode)?,

            // ================================================================
            // Arithmetic Operations
            // ================================================================
            OP_1ADD | OP_1SUB | OP_2MUL | OP_2DIV | OP_NEGATE | OP_ABS | OP_NOT | OP_0NOTEQUAL => {
                self.op_unary_number(opcode)?
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
            | OP_MAX => self.op_binary_number(opcode)?,
            OP_WITHIN => self.op_within()?,

            // ================================================================
            // Crypto Operations
            // ================================================================
            OP_RIPEMD160 => self.op_ripemd160()?,
            OP_SHA1 => self.op_sha1()?,
            OP_SHA256 => self.op_sha256()?,
            OP_HASH160 => self.op_hash160()?,
            OP_HASH256 => self.op_hash256()?,
            OP_CODESEPARATOR => self.op_codeseparator()?,
            OP_CHECKSIG | OP_CHECKSIGVERIFY => self.op_checksig(opcode)?,
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
            // 0xba-0xff are undefined: the reference's `default:` is
            // SCRIPT_ERR_BAD_OPCODE when one is executed (interpreter.cpp:1795),
            // and this arm is only reached when executing: they fall to the
            // invalid-opcode arm below.
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

#[cfg(test)]
mod tests;

/// The flag words on the interpreter: every gate `set_flags` derives, exercised
/// on the smallest script that reaches it, against the TypeScript default
/// mode. The reference sites are cited in `flags.rs`.
#[cfg(test)]
mod flag_tests;

/// The five consensus divergences left after 0.3.26 (Calhooon/bsv-rs#12), each
/// rule on the smallest script that reaches it: the post-Chronicle opcodes and
/// their gate, the single-ELSE rule, a RETURN inside a conditional, truncated
/// pushes, undefined opcodes, and the scriptCode cleanup. Sites in `flags.rs`
/// and at the arms.
#[cfg(test)]
mod chronicle_tests;

/// The low-S check at the curve order (Calhooon/bsv-rs#14): an `r` or `s` at or
/// above the order is the zero signature for the reference's lax parse, which
/// is low; only n/2 < s < n is a high-S refusal.
#[cfg(test)]
mod low_s_order_tests;

#[cfg(test)]
mod script_num_length_tests;

#[cfg(test)]
mod fixed_width_operand_tests;
