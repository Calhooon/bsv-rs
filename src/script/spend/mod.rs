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

use super::evaluation_error::{
    ExecutionContext, ScriptEvaluationError, ScriptResource, ScriptResourceLimit,
};
use super::flags::{
    Gates, ScriptFlags, DEFAULT_SCRIPT_NUM_LENGTH_POLICY, DEFAULT_STACK_MEMORY_USAGE_POLICY,
    STACK_ELEMENT_OVERHEAD,
};
use super::op::*;
use super::script_num::ScriptNum;
use super::{LockingScript, Script, ScriptChunk, UnlockingScript};
use crate::primitives::bsv::sighash::{
    TxInput, TxOutput, TxSighashCache, SIGHASH_ALL, SIGHASH_ANYONECANPAY, SIGHASH_CHRONICLE,
    SIGHASH_FORKID, SIGHASH_SINGLE,
};
use crate::primitives::bsv::tx_signature::TransactionSignature;
use crate::primitives::ec::PublicKey;
use crate::primitives::{hash160, ripemd160, sha1, sha256, sha256d, to_hex, BigNumber};
use std::sync::Arc;

// ============================================================================
// Configuration Constants
// ============================================================================

/// Maximum size of a single script element (1GB for BSV unlimited)
const MAX_SCRIPT_ELEMENT_SIZE: usize = 1024 * 1024 * 1024;

/// The local memory budget of the default mode when `memory_limit` is `None`
/// (32,000,000 bytes, each stack apart, the bytes alone).
const DEFAULT_MEMORY_LIMIT: usize = 32_000_000;

/// The local memory budget under a word when `memory_limit` is `None`: the
/// node's policy default ([`DEFAULT_STACK_MEMORY_USAGE_POLICY`],
/// `src/policy/policy.h:153`) on the block path as on the mempool path. The
/// block path has no protocol figure to take instead: a node's is its
/// operator's mandatory `-maxstackmemoryusageconsensus`
/// (`src/bitcoind.cpp:140-157`; 0 = `INT64_MAX`,
/// `src/configscriptpolicy.cpp:280-283`), and a library embedded in a wallet
/// cannot honor an unbounded budget by default.
const WORD_MEMORY_LIMIT: usize = DEFAULT_STACK_MEMORY_USAGE_POLICY;

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
    /// The memory budget follows the word too: the node's stack memory count
    /// and, on the mempool path, its policy verdict ([`memory_limit`](Self::memory_limit),
    /// [`stack_memory_policy`](Self::stack_memory_policy)).
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

    /// The script-number length limit in force: `None` in the TypeScript
    /// default mode (the SDK reads a number of any length); under a word the
    /// reference's limit ([`ScriptFlags::max_script_num_length`]) for the
    /// coin's era, following
    /// [`set_utxo_after_chronicle`](Self::set_utxo_after_chronicle), and on
    /// the mempool path the policy of
    /// [`set_script_num_length_policy`](Self::set_script_num_length_policy).
    /// Applied before the decode at every read (`script_num.cpp:62-68`), on
    /// every arithmetic result before it is pushed (`164`, `194`, `214`,
    /// `301-315`), at `OP_BIN2NUM`'s result (`interpreter.cpp:1789-1790`), and
    /// as 4 bytes on `OP_CHECKMULTISIG`'s counts (`1519-1525`, `1550-1552`).
    pub fn max_script_num_length(&self) -> Option<usize> {
        self.flags.map(|word| {
            word.max_script_num_length(self.utxo_after_chronicle, self.script_num_length_policy)
        })
    }

    /// The node's `-maxscriptnumlengthpolicy` for a word on the mempool path
    /// (`src/policy/policy.h:156`, 10,000 bytes by default; 0 selects the
    /// consensus limit of the coin's era). A block word and the default mode
    /// ignore it.
    pub fn set_script_num_length_policy(&mut self, bytes: usize) {
        self.script_num_length_policy = bytes;
    }

    /// The LOCAL memory budget in force: `SpendParams::memory_limit` when it
    /// is `Some`, in every mode. Otherwise, in the TypeScript default mode,
    /// 32,000,000 bytes for each stack apart, counting the bytes alone, as
    /// that SDK counts; under a word, 100,000,000 bytes on the node's count,
    /// one budget over both stacks with [`STACK_ELEMENT_OVERHEAD`] bytes per
    /// element (the node's policy default, `src/policy/policy.h:153`, on the
    /// block path as on the mempool path: a node's block-path budget is its
    /// operator's mandatory `-maxstackmemoryusageconsensus`,
    /// `src/bitcoind.cpp:140-157`, 0 meaning `INT64_MAX`,
    /// `src/configscriptpolicy.cpp:280-283`, so there is no protocol figure to
    /// adopt; `Some(usize::MAX)` models a node run with 0). Exhausting it stops
    /// the evaluation with a resource limit
    /// ([`ScriptEvaluationError::resource_limit`]): the evaluator declines to go
    /// on, it does not decide, and a caller that judges validity must not read
    /// that `Err` as invalid.
    pub fn memory_limit(&self) -> usize {
        self.memory_limit.unwrap_or(if self.flags.is_some() {
            WORD_MEMORY_LIMIT
        } else {
            DEFAULT_MEMORY_LIMIT
        })
    }

    /// The stack memory budget whose excess is a VERDICT, in force: `None` in
    /// the default mode and on the block path (a node's block-path budget is
    /// its operator's mandatory `-maxstackmemoryusageconsensus`, which this
    /// interpreter cannot know: the local budget declines instead,
    /// [`memory_limit`](Self::memory_limit)); on the mempool path the policy of
    /// [`set_stack_memory_policy`](Self::set_stack_memory_policy)
    /// ([`ScriptFlags::max_stack_memory_usage`]). A growth that would take the
    /// node's count above it is refused before it happens, as the reference
    /// refuses it (`limitedstack.cpp:202-205`, `SCRIPT_ERR_STACK_SIZE`,
    /// `interpreter.cpp:1815-1817`): `Stack size limit exceeded: N bytes, the
    /// stack memory policy is M bytes.`
    pub fn stack_memory_policy(&self) -> Option<usize> {
        self.flags
            .and_then(|word| word.max_stack_memory_usage(self.stack_memory_policy))
    }

    /// The node's `-maxstackmemoryusagepolicy` for a word on the mempool path
    /// (`src/policy/policy.h:153`, 100,000,000 bytes by default; 0 selects no
    /// policy verdict, as the node sets a policy of 0 to `INT64_MAX`,
    /// `src/configscriptpolicy.cpp:289-292`). A block word and the default
    /// mode ignore it. The local budget is `SpendParams::memory_limit`, a
    /// separate knob: the policy's verdict fires at its figure whatever the
    /// local budget, and the local budget stops the evaluation below it.
    pub fn set_stack_memory_policy(&mut self, bytes: usize) {
        self.stack_memory_policy = bytes;
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
                let bn = self.read_number(&n_bytes)?;

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
                    self.release(removed.len());
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
                self.reserve_stack(top.len())?;
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
                // The default mode's 1 GiB element bound; under a word an element
                // after Genesis is bounded by the stack memory budget alone
                // (`src/consensus/consensus.h:81-82`), which the push charges.
                if self.flags.is_none() && result.len() > MAX_SCRIPT_ELEMENT_SIZE {
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

                let pos_bn = self.read_number(&pos_bytes)?;
                let split_idx = self.split_position(&pos_bn, data.len())?;
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
                let size_bn = self.read_number(&size_bytes)?;
                let size = size_bn.to_i64().unwrap_or(-1);

                let size = if self.flags.is_some() {
                    // Under a word the reference's bound: a size below 0 or above
                    // INT32_MAX is SCRIPT_ERR_PUSH_SIZE before anything is
                    // allocated, on every path (`interpreter.cpp:1747-1749`); an
                    // element after Genesis is otherwise bounded by the stack
                    // memory budget alone (`src/consensus/consensus.h:81-82`),
                    // charged below.
                    if size < 0 || size > i64::from(i32::MAX) {
                        return Err(self.error(&format!(
                            "OP_NUM2BIN requires a size from 0 to 2147483647, found {}.",
                            size_bn.to_dec_string()
                        )));
                    }
                    size as usize
                } else {
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
                    if size > self.memory_limit() {
                        return Err(self.resource_error(ScriptResource::ElementSize, size));
                    }
                    size
                };

                let rawnum = self.pop_stack()?;
                let minimal = ScriptNum::minimally_encode(&rawnum);

                if minimal.len() > size {
                    return Err(self.error(
                        "OP_NUM2BIN requires that the size expressed in the top stack item is large enough to hold the value expressed in the second-from-top stack item.",
                    ));
                }

                // Under a word the growth is charged before the element is
                // resized (`LimitedVector::padRight`, `limitedstack.cpp:60-71`:
                // the charge at `:66`, the resize at `:68`), so a size the budget
                // refuses is refused before it is allocated. The node's count
                // after the pad equals the count of the padded element pushed
                // here (the value's minimal encoding is never longer than it).
                if self.flags.is_some() && minimal.len() < size {
                    self.check_node_budget(
                        self.node_mem + size as u64 + STACK_ELEMENT_OVERHEAD as u64,
                    )?;
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
                // A result longer than the limit in force is refused as the
                // reference refuses it (`IsMinimallyEncoded(max)`,
                // `interpreter.cpp:1789-1790`: `SCRIPT_ERR_INVALID_NUMBER_RANGE`).
                let over = matches!(self.max_script_num_length(), Some(max) if result.len() > max);
                if over || !ScriptNum::is_minimally_encoded(&result) {
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

                let n_bn = self.read_number(&n_bytes)?;
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
                let mut bn = self.read_number(&buf)?;

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
                self.push_number(&bn)?;
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
                let bn1 = self.read_number(&buf1)?;
                let bn2 = self.read_number(&buf2)?;

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

                self.push_number(&result)?;

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
                let max_bn = self.read_number(&max_bytes)?;
                let min_bn = self.read_number(&min_bytes)?;
                let x_bn = self.read_number(&x_bytes)?;

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
                self.charge_work(buf.len() as u64)?;
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
                self.charge_work(buf.len() as u64)?;
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
                self.charge_work(buf.len() as u64)?;
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
                self.charge_work(buf.len() as u64 + 32)?;
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
                self.charge_work(buf.len() as u64 + 32)?;
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
        let n_keys_bn = self.read_count(&n_keys_bytes)?;
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
        let n_sigs_bn = self.read_count(&n_sigs_bytes)?;
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
                self.verify_signature(sig_bytes, pubkey_bytes, &subscript)?
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

        // STRICTENC (interpreter.cpp:291-294): the hash type must have a defined
        // base once the CHRONICLE, FORKID and ANYONECANPAY bits are cleared
        // (`SigHashType::isDefined`, sighashtype.h:82-90): ALL, NONE or SINGLE;
        // `SCRIPT_ERR_SIG_HASHTYPE` otherwise. Both node words carry STRICTENC;
        // the default mode tests it too, as the TypeScript SDK refuses an
        // undefined type (Calhooon/bsv-rs#23).
        if self
            .flags
            .is_none_or(|word| word.contains(ScriptFlags::STRICTENC))
        {
            let base =
                tx_sig.scope() & !(SIGHASH_CHRONICLE | SIGHASH_FORKID | SIGHASH_ANYONECANPAY);
            if !(SIGHASH_ALL..=SIGHASH_SINGLE).contains(&base) {
                return Err(self.error(&format!(
                    "The signature's hash type (0x{:02x}) has no defined base type.",
                    tx_sig.scope()
                )));
            }
        }

        // STRICTENC (interpreter.cpp:296-303): the CHRONICLE bit is legal only
        // when the word carries SCRIPT_CHRONICLE (the block is in the
        // Chronicle era); `SCRIPT_ERR_ILLEGAL_CHRONICLE` otherwise. The default
        // mode has no word and admits the bit (Calhooon/bsv-rs#22).
        if let Some(word) = self.flags {
            if word.contains(ScriptFlags::STRICTENC)
                && !word.contains(ScriptFlags::CHRONICLE)
                && (tx_sig.scope() & SIGHASH_CHRONICLE) != 0
            {
                return Err(
                    self.error("The signature must not use SIGHASH_CHRONICLE before Chronicle.")
                );
            }
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
    /// The splice operands are read by [`read_splice_operand`](Self::read_splice_operand)
    /// (the reference's `int64` path under a word). The two shifts act on
    /// script NUMBERS (not on bytes, unlike `OP_LSHIFT`). Under a word the
    /// reference's two bounds come first (Calhooon/bsv-rs#21): a left shift's
    /// result size against the era's maximum number length before the shift
    /// (`script_num.cpp:305-308`, `SCRIPTNUM_OVERFLOW`), then on both shifts a
    /// count above `INT_MAX` as the big-integer error (`big_int.cpp:359-369`,
    /// `383-393`; `SCRIPT_ERR_BIG_INT`, `interpreter.cpp:1819-1821`). After
    /// them, a left shift's result is sized exactly before it is computed: over
    /// the era's number length it is the reference's size test after the shift
    /// (`script_num.cpp:315-316`), and its charge to the node's stack memory
    /// count is tested as the push will charge it. The default mode shifts by
    /// any count, as the TypeScript SDK does, and refuses a result that alone
    /// would exceed the local budget before computing it (a resource limit).
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
            s.read_number(bytes)
        };
        match opcode {
            OP_NOP4 => {
                // (data offset len -- data[offset..offset+len])
                let len_bytes = self.pop_stack()?;
                let off_bytes = self.pop_stack()?;
                let len = self.read_splice_operand(&len_bytes)?;
                let offset = self.read_splice_operand(&off_bytes)?;
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
                let len = self.read_splice_operand(&len_bytes)?;
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
                if let Some(max) = self.max_script_num_length() {
                    // Under a word, the reference's bounds (Calhooon/bsv-rs#21).
                    // A left shift first tests the result's size, the value's
                    // serialized size plus count / 8 bytes, against the era's
                    // maximum number length, before any shift or allocation
                    // (`CScriptNum::operator<<=`, `script_num.cpp:305-308`); a
                    // right shift has no size test (`363-367`).
                    if opcode == OP_NOP7 {
                        let current = ScriptNum::to_bytes(&x).len() as u64;
                        match n_bn.to_u64().and_then(|n| current.checked_add(n / 8)) {
                            Some(size) if size <= max as u64 => {}
                            Some(size) => return Err(self.overflow_error(size as usize, max)),
                            None => {
                                return Err(self.error(&format!(
                                    "Script number overflow: a shift by {} bits, the limit is {max} bytes.",
                                    n_bn.to_dec_string()
                                )))
                            }
                        }
                    }
                    // Then, on both shifts, a count above INT_MAX is the
                    // reference's `big_int_error` (`bint::operator<<=` and
                    // `operator>>=` on a `bint` count, `big_int.cpp:359-369`,
                    // `383-393`), caught as `SCRIPT_ERR_BIG_INT`
                    // (`interpreter.cpp:1819-1821`).
                    if n_bn.to_i64().is_none_or(|n| n > i64::from(i32::MAX)) {
                        return Err(self.error(&format!(
                            "{name} count ({}) does not fit an int.",
                            n_bn.to_dec_string()
                        )));
                    }
                }
                let n = n_bn.to_i64().map(|v| v as u64).unwrap_or(u64::MAX);
                let out = if opcode == OP_NOP7 {
                    if x.is_zero() {
                        x
                    } else if let Some(max) = self.max_script_num_length() {
                        // Under a word the size test above bounds the result, and
                        // its exact length is known before the shift: the
                        // magnitude's bits plus the count, one byte for each 8
                        // bits and one for the sign's room. The reference's size
                        // test after the shift (`script_num.cpp:315-316`,
                        // SCRIPTNUM_OVERFLOW) and the node's charge of the pushed
                        // result (`limitedstack.h:171`) are decided on it before
                        // anything is allocated.
                        let bits = (x.bit_length() as u64).saturating_add(n);
                        let len = bits / 8 + 1;
                        if len > max as u64 {
                            return Err(self.overflow_error(len as usize, max));
                        }
                        self.check_node_budget(
                            self.node_mem + len + STACK_ELEMENT_OVERHEAD as u64,
                        )?;
                        x.shl_bits(n)
                    } else {
                        // the default mode: the result's size, before allocating
                        // it, against the LOCAL budget
                        let bits = (x.bit_length() as u64).saturating_add(n);
                        let bytes = (bits / 8 + 2) as usize;
                        if bytes > self.memory_limit() {
                            return Err(self.resource_error(ScriptResource::ElementSize, bytes));
                        }
                        x.shl_bits(n)
                    }
                } else if n >= x.bit_length() as u64 {
                    BigNumber::zero()
                } else {
                    x.shr_bits_toward_zero(n)
                };
                self.push_number(&out)?;
            }
        }
        Ok(())
    }

    /// The OP_SPLIT position check, separate from slicing so its boundary can
    /// be tested without allocating the data: bitcoin-sv v1.2.3,
    /// `interpreter.cpp:1708-1721` at `6504a3aff65ba97c0f6c80962b033e35ecbfed4b`.
    fn split_position(
        &self,
        position: &BigNumber,
        data_len: usize,
    ) -> Result<usize, ScriptEvaluationError> {
        let pos = position.to_i64().unwrap_or(-1);
        if pos < 0
            || (self.flags.is_some() && pos > i64::from(i32::MAX))
            || pos as u64 > data_len as u64
        {
            return Err(self.error(
                "OP_SPLIT requires the first stack item to be a non-negative number less than or equal to the size of the second-from-top stack item.",
            ));
        }
        Ok(pos as usize)
    }

    /// The `OP_SUBSTR`, `OP_LEFT` and `OP_RIGHT` length and offset operands.
    /// Under a word, follows bitcoin-sv v1.2.3's fixed-width construction sites
    /// (`interpreter.cpp:622-625`, `655-656`, `680-681`) and checked decoder
    /// (`int_serialization.h:61-118`), at
    /// `6504a3aff65ba97c0f6c80962b033e35ecbfed4b`. The era width and minimality
    /// checks precede conversion (`script_num.cpp:62-87`). A failed conversion
    /// is SCRIPT_ERR_SCRIPTNUM_OVERFLOW (`script_num.cpp:80-91`,
    /// `interpreter.cpp:1807-1809`). `getint` then saturates to the `int` range
    /// (`script_num.cpp:396-422`).
    /// The default mode uses the TypeScript SDK's unrestricted number reader.
    fn read_splice_operand(&self, bytes: &[u8]) -> Result<i64, ScriptEvaluationError> {
        if self.flags.is_none() {
            return Ok(self.read_number(bytes)?.to_i64().unwrap_or(-1));
        }
        // Preserve the era-width/minimality ordering and their messages.
        let as_number = self.read_number(bytes)?;
        let decode_error = || self.error("Script number overflow: operand does not fit int64.");
        if bytes.len() > 9 || (bytes.len() == 9 && bytes[8] & 0x7f != 0) {
            return Err(decode_error());
        }
        // The sign-magnitude value must fit i64, including i64::MIN, whose
        // magnitude is 2^63 and whose ninth byte must be 0x80.
        let value = as_number.to_i64().ok_or_else(decode_error)?;
        Ok(value.clamp(i64::from(i32::MIN), i64::from(i32::MAX)))
    }

    fn verify_signature(
        &mut self,
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

        // The digest, dispatched as the reference's `SignatureHash` does
        // (`interpreter.cpp:2112-2124`; FORKID is always enabled here): BIP143
        // for a FORKID type without the CHRONICLE bit, the original digest
        // otherwise (Calhooon/bsv-rs#22). The BIP143 midstates are the
        // transaction's, shared by every input's spend (bsv-low #591).
        let script_bytes = subscript.to_binary();
        if self.work_limit.is_some() {
            let cost =
                self.transaction
                    .hashing_work(self.input_index, &script_bytes, tx_sig.scope());
            self.charge_work(cost)?;
        }
        let sighash = self.transaction.sighash_dispatched_for_signing(
            self.input_index,
            &script_bytes,
            self.source_satoshis,
            tx_sig.scope(),
        );

        // Verify
        Ok(pubkey.verify(&sighash, tx_sig.signature()))
    }

    // ========================================================================
    // Stack Helpers
    // ========================================================================

    fn push_stack(&mut self, item: Vec<u8>) -> Result<(), ScriptEvaluationError> {
        self.reserve_stack(item.len())?;
        self.stack_mem += item.len();
        self.stack.push(item);
        Ok(())
    }

    fn push_stack_copy(&mut self, item: &[u8]) -> Result<(), ScriptEvaluationError> {
        self.push_stack(item.to_vec())
    }

    fn pop_stack(&mut self) -> Result<Vec<u8>, ScriptEvaluationError> {
        let Some(item) = self.stack.pop() else {
            return Err(self.error("Attempted to pop from an empty stack."));
        };
        self.stack_mem -= item.len();
        self.release(item.len());
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
        self.reserve_alt_stack(item.len())?;
        self.alt_stack_mem += item.len();
        self.alt_stack.push(item);
        Ok(())
    }

    fn pop_alt_stack(&mut self) -> Result<Vec<u8>, ScriptEvaluationError> {
        let Some(item) = self.alt_stack.pop() else {
            return Err(self.error("Attempted to pop from an empty alt stack."));
        };
        self.alt_stack_mem -= item.len();
        self.release(item.len());
        Ok(item)
    }

    /// Before an element of `len` bytes joins the main stack: the default
    /// mode's budget for that stack, or under a word the node's charge.
    fn reserve_stack(&mut self, len: usize) -> Result<(), ScriptEvaluationError> {
        if self.flags.is_some() {
            self.charge(len)
        } else {
            self.ensure_stack_mem(len)
        }
    }

    /// Before an element of `len` bytes joins the alt stack: the default
    /// mode's budget for that stack, or under a word the node's charge (the
    /// node moves an element between the two stacks without a charge,
    /// `limitedstack.cpp:290-305`; here it leaves one and joins the other,
    /// released then charged again, the same count at every step).
    fn reserve_alt_stack(&mut self, len: usize) -> Result<(), ScriptEvaluationError> {
        if self.flags.is_some() {
            self.charge(len)
        } else {
            self.ensure_alt_stack_mem(len)
        }
    }

    /// Under a word, charges an element of `len` bytes to the node's count
    /// (`LimitedStack::push_back`, `limitedstack.h:163`, `171`: its size plus
    /// `STACK_ELEMENT_OVERHEAD`), tested before the element is held.
    fn charge(&mut self, len: usize) -> Result<(), ScriptEvaluationError> {
        let attempted = self
            .node_mem
            .saturating_add(len as u64 + STACK_ELEMENT_OVERHEAD as u64);
        self.check_node_budget(attempted)?;
        self.node_mem = attempted;
        Ok(())
    }

    /// Under a word, releases an element of `len` bytes that left either stack
    /// (`LimitedStack::pop_back`, `erase`, `limitedstack.cpp:211-219`,
    /// `245-268`).
    fn release(&mut self, len: usize) {
        if self.flags.is_some() {
            self.node_mem = self
                .node_mem
                .saturating_sub(len as u64 + STACK_ELEMENT_OVERHEAD as u64);
        }
    }

    /// Whether the node's count may reach `attempted` bytes. Above the stack
    /// memory policy in force ([`stack_memory_policy`](Self::stack_memory_policy))
    /// it is the reference's verdict: `LimitedStack::increaseCombinedStackSize`
    /// throws before the growth (`limitedstack.cpp:202-205`), caught as
    /// `SCRIPT_ERR_STACK_SIZE` (`interpreter.cpp:1815-1817`). Above the local
    /// budget ([`memory_limit`](Self::memory_limit)) it is a resource limit.
    /// The policy is tested first: its verdict needs nothing allocated.
    fn check_node_budget(&self, attempted: u64) -> Result<(), ScriptEvaluationError> {
        if let Some(policy) = self.stack_memory_policy() {
            if attempted > policy as u64 {
                return Err(self.error(&format!(
                    "Stack size limit exceeded: {attempted} bytes, the stack memory policy is {policy} bytes."
                )));
            }
        }
        if attempted > self.memory_limit() as u64 {
            return Err(self.resource_error(
                ScriptResource::Stack,
                usize::try_from(attempted).unwrap_or(usize::MAX),
            ));
        }
        Ok(())
    }

    fn ensure_stack_mem(&self, additional: usize) -> Result<(), ScriptEvaluationError> {
        if self.stack_mem + additional > self.memory_limit() {
            return Err(self.resource_error(ScriptResource::Stack, self.stack_mem + additional));
        }
        Ok(())
    }

    fn ensure_alt_stack_mem(&self, additional: usize) -> Result<(), ScriptEvaluationError> {
        if self.alt_stack_mem + additional > self.memory_limit() {
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
            ScriptResource::Work => "Work",
        };
        let limit = self.memory_limit();
        self.error(&format!("{label} has exceeded {limit} bytes"))
            .with_resource_limit(ScriptResourceLimit {
                resource,
                limit: limit as u64,
                attempted: attempted as u64,
                work_spent: None,
            })
    }

    // ========================================================================
    // Script numbers under the length limit
    // ========================================================================

    /// Decodes a stack element as a script number under `limit`: the length
    /// test precedes the decode and the minimal-encoding check, as on the
    /// reference (`script_num.cpp:62-68`; `SCRIPT_ERR_SCRIPTNUM_OVERFLOW`,
    /// `interpreter.cpp:1807-1810`).
    fn read_number_within(
        &self,
        bytes: &[u8],
        limit: Option<usize>,
    ) -> Result<BigNumber, ScriptEvaluationError> {
        if let Some(max) = limit {
            if bytes.len() > max {
                return Err(self.overflow_error(bytes.len(), max));
            }
        }
        ScriptNum::from_bytes(bytes, self.require_minimal)
            .map_err(|e| self.error(&format!("Invalid script number: {}", e)))
    }

    /// A script number read under the limit in force
    /// ([`max_script_num_length`](Self::max_script_num_length)).
    fn read_number(&self, bytes: &[u8]) -> Result<BigNumber, ScriptEvaluationError> {
        self.read_number_within(bytes, self.max_script_num_length())
    }

    /// `OP_CHECKMULTISIG`'s two counts: 4-byte numbers in every era
    /// (`CScriptNum::MAXIMUM_ELEMENT_SIZE`, `interpreter.cpp:1519-1525`,
    /// `1550-1552`) under a word; the default mode reads them as the
    /// TypeScript SDK does.
    fn read_count(&self, bytes: &[u8]) -> Result<BigNumber, ScriptEvaluationError> {
        self.read_number_within(bytes, self.flags.map(|_| 4))
    }

    /// Pushes a computed number, refusing one longer than the limit in force
    /// before it reaches the stack (the reference bounds the results of `+`,
    /// `-`, `*` and the numeric shifts: `script_num.cpp:164`, `194`, `214`,
    /// `301-315`).
    fn push_number(&mut self, value: &BigNumber) -> Result<(), ScriptEvaluationError> {
        let bytes = ScriptNum::to_bytes(value);
        if let Some(max) = self.max_script_num_length() {
            if bytes.len() > max {
                return Err(self.overflow_error(bytes.len(), max));
            }
        }
        self.push_stack(bytes)
    }

    fn overflow_error(&self, len: usize, max: usize) -> ScriptEvaluationError {
        self.error(&format!(
            "Script number overflow: {len} bytes, the limit is {max} bytes."
        ))
    }

    /// Work charged in this evaluation when a work budget is configured.
    /// Unbounded evaluations do not calculate hash costs.
    pub fn work_spent(&self) -> u64 {
        self.work_spent
    }

    fn charge_work(&mut self, cost: u64) -> Result<(), ScriptEvaluationError> {
        let Some(limit) = self.work_limit else {
            return Ok(());
        };
        match self.work_spent.checked_add(cost) {
            Some(next) if next <= limit => {
                self.work_spent = next;
                Ok(())
            }
            attempted => {
                let attempted = attempted.unwrap_or(u64::MAX);
                self.work_declined = Some(attempted);
                Err(self.work_error(attempted))
            }
        }
    }

    fn work_error(&self, attempted: u64) -> ScriptEvaluationError {
        let limit = self.work_limit.unwrap_or(u64::MAX);
        self.error(&format!(
            "Work budget exhausted: spent {} units, budget {limit}",
            self.work_spent
        ))
        .with_resource_limit(ScriptResourceLimit {
            resource: ScriptResource::Work,
            limit,
            attempted,
            work_spent: Some(self.work_spent),
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
