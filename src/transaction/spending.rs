//! A door that verifies ONE input of a transaction held as bytes, in the
//! shape of the node's consensus library (#855), and the one core under it,
//! [`Transaction::verify`] and the streaming reader.
//!
//! The node states this door as `bitcoinconsensus_verify_script_with_amount`
//! (bitcoin-sv v1.2.2 `src/script/bitcoinconsensus.h:90-98`): the locking
//! script, the amount, the spending transaction's bytes, the input index and
//! a flag word, refused before evaluation for invalid flags, bytes that are
//! not one transaction and an index past its inputs (`bitcoinconsensus.cpp:
//! 88-97`). Here:
//!
//! - [`SpendingTransaction::from_bytes`] reads the bytes once, exactly one
//!   transaction, by [`Transaction::from_binary`]'s strict reader (#840), and
//!   keeps the transaction with its sighash midstates for every input;
//! - [`SpendingTransaction::verify_input`] judges one input against the
//!   output it spends, under [`InputRules`];
//! - [`verify_input`] is the one-shot in the node's argument order.
//!
//! [`InputRules`] is the reference SDK's default mode (its `Spend` without
//! flags, as [`Transaction::verify`] runs it without chain parameters), or a
//! node's word as a typed [`ScriptFlags`], checked when the rules are built.
//! The answer is [`InputVerified`] or an [`InputRefusal`] whose arms keep a
//! verdict ([`InputRefusal::Invalid`]) apart from a local budget's decline
//! ([`InputRefusal::Declined`]), as the reference keeps its
//! `ScriptEvaluationError` apart from its `ScriptResourceLimitError`
//! (`ts-stack@edf6e03` `packages/sdk/src/script/Spend.ts:2017-2026`).
//!
//! `judge_input` is the only place outside `src/script/` that builds a
//! [`Spend`] for an input (`tests/arch_one_input_core.rs`).

use std::fmt;
use std::sync::Arc;

use crate::primitives::bsv::sighash::{TxInput, TxOutput, TxSighashCache};
use crate::script::flags::{DEFAULT_SCRIPT_NUM_LENGTH_POLICY, DEFAULT_STACK_MEMORY_USAGE_POLICY};
use crate::script::{
    ExecutionContext, LockingScript, ScriptEvaluationError, ScriptFlags, ScriptFlagsError,
    ScriptResourceLimit, Spend, TxSpendParams, UnlockingScript,
};

use super::Transaction;

/// The reference SDK's default mode, with the three overrides that mode
/// takes ([`InputRules::reference_default_with`]).
///
/// Each override replaces the rule the default mode derives from the
/// transaction's version; `None` keeps the derived rule. They exist for the
/// default mode alone: a node's word decides every rule itself, so
/// [`InputRules::under`] takes no `DefaultMode` and [`InputRules`] has no
/// override setter (a word with an override does not compile):
///
/// ```compile_fail,E0599
/// use bsv_rs::script::{ProtocolEra, ScriptFlags};
/// use bsv_rs::transaction::InputRules;
///
/// let word = ScriptFlags::block(ProtocolEra::PostChronicle);
/// let rules = InputRules::under(word).unwrap().with_require_push_only(true);
/// ```
///
/// The setters commute: the order of the calls never changes the result.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub struct DefaultMode {
    require_push_only: Option<bool>,
    require_minimal: Option<bool>,
    utxo_after_chronicle: Option<bool>,
}

impl DefaultMode {
    /// The default mode with no override.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            require_push_only: None,
            require_minimal: None,
            utxo_after_chronicle: None,
        }
    }

    /// Requires (`true`) or waives (`false`) a push-only unlocking script at
    /// every version, where the default mode requires one at a version of 1
    /// or below alone (#816). An overlay that refuses a non-push unlocking
    /// script at every version passes `true` ([`Spend::set_require_push_only`]).
    #[must_use]
    pub const fn with_require_push_only(mut self, require: bool) -> Self {
        self.require_push_only = Some(require);
        self
    }

    /// Requires (`true`) or waives (`false`) minimal pushes and numbers at
    /// every version ([`Spend::set_require_minimal`]).
    #[must_use]
    pub const fn with_require_minimal(mut self, require: bool) -> Self {
        self.require_minimal = Some(require);
        self
    }

    /// The coin's era for the ten Chronicle opcodes: `false` keeps them
    /// disabled, as before Chronicle, where the default mode runs them at
    /// every version (#397; [`Spend::set_utxo_after_chronicle`]).
    #[must_use]
    pub const fn with_utxo_after_chronicle(mut self, after: bool) -> Self {
        self.utxo_after_chronicle = Some(after);
        self
    }

    /// The push-only override, `None` when the version decides.
    #[must_use]
    pub const fn require_push_only(&self) -> Option<bool> {
        self.require_push_only
    }

    /// The minimal-encoding override, `None` when the version decides.
    #[must_use]
    pub const fn require_minimal(&self) -> Option<bool> {
        self.require_minimal
    }

    /// The Chronicle opcodes' override, `None` when they run (the default).
    #[must_use]
    pub const fn utxo_after_chronicle(&self) -> Option<bool> {
        self.utxo_after_chronicle
    }
}

/// A node operator's own figures for a word ([`InputRules::under_with`]):
/// the three settings bitcoin-sv v1.2.2 reads from its configuration beside
/// the flag word, each the [`Spend`] setter of the same name.
///
/// They exist for a word alone: the default mode reads none of them
/// ([`Spend`] ignores them without a word), so only
/// [`InputRules::under_with`] takes a `NodeFigures` and no default-mode
/// constructor does:
///
/// ```compile_fail,E0599
/// use bsv_rs::transaction::{InputRules, NodeFigures};
///
/// let figures = NodeFigures::new().with_stack_memory_consensus(0);
/// let rules = InputRules::reference_default().with_node_figures(figures);
/// ```
///
/// Nor can the two modes' values be swapped: a `NodeFigures` is not a
/// [`DefaultMode`], and a `DefaultMode` is not a `NodeFigures` (each a type
/// mismatch, not a missing name):
///
/// ```compile_fail,E0308
/// use bsv_rs::transaction::{InputRules, NodeFigures};
///
/// let rules = InputRules::reference_default_with(NodeFigures::new());
/// ```
///
/// ```compile_fail,E0308
/// use bsv_rs::script::{ProtocolEra, ScriptFlags};
/// use bsv_rs::transaction::{DefaultMode, InputRules};
///
/// let word = ScriptFlags::block(ProtocolEra::PostChronicle);
/// let rules = InputRules::under_with(word, DefaultMode::new());
/// ```
///
/// [`NodeFigures::new`] (also [`Default`]) is the node's defaults, the figures
/// [`InputRules::under`] judges by. The setters commute.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct NodeFigures {
    stack_memory_policy: usize,
    stack_memory_consensus: usize,
    script_num_length_policy: usize,
}

impl Default for NodeFigures {
    fn default() -> Self {
        Self::new()
    }
}

impl NodeFigures {
    /// The node's defaults: a stack memory policy of 100,000,000 bytes
    /// (`-maxstackmemoryusagepolicy`, `src/policy/policy.h:153`), no block-path
    /// consensus figure (0, the verdict none, the local budget deciding), a
    /// script-number length policy of 10,000 bytes
    /// (`-maxscriptnumlengthpolicy`, `src/policy/policy.h:156`).
    #[must_use]
    pub const fn new() -> Self {
        Self {
            stack_memory_policy: DEFAULT_STACK_MEMORY_USAGE_POLICY,
            stack_memory_consensus: 0,
            script_num_length_policy: DEFAULT_SCRIPT_NUM_LENGTH_POLICY,
        }
    }

    /// The node's `-maxstackmemoryusagepolicy`: on the mempool path (a word
    /// carrying the mempool bits) a stack past it is a VERDICT; 0 selects
    /// none ([`Spend::set_stack_memory_policy`]). A block word ignores it.
    #[must_use]
    pub const fn with_stack_memory_policy(mut self, bytes: usize) -> Self {
        self.stack_memory_policy = bytes;
        self
    }

    /// The node's `-maxstackmemoryusageconsensus`: on the block path a stack
    /// past it is a VERDICT; 0 (the default) selects none, as the node reads 0
    /// as `INT64_MAX` ([`Spend::set_stack_memory_consensus`]). A node run with
    /// 0 judges every stack: pass a memory limit of `usize::MAX`
    /// ([`InputRules::with_memory_limit`]) beside it, as the local budget of
    /// 100,000,000 bytes otherwise declines first. The mempool word ignores it.
    #[must_use]
    pub const fn with_stack_memory_consensus(mut self, bytes: usize) -> Self {
        self.stack_memory_consensus = bytes;
        self
    }

    /// The node's `-maxscriptnumlengthpolicy`: the script-number length bound
    /// on the mempool path; 0 selects the consensus limit of the coin's era
    /// ([`Spend::set_script_num_length_policy`]). A block word ignores it.
    #[must_use]
    pub const fn with_script_num_length_policy(mut self, bytes: usize) -> Self {
        self.script_num_length_policy = bytes;
        self
    }

    /// The stack memory policy, in bytes.
    #[must_use]
    pub const fn stack_memory_policy(&self) -> usize {
        self.stack_memory_policy
    }

    /// The block path's stack memory figure, in bytes; 0 for none.
    #[must_use]
    pub const fn stack_memory_consensus(&self) -> usize {
        self.stack_memory_consensus
    }

    /// The script-number length policy, in bytes.
    #[must_use]
    pub const fn script_num_length_policy(&self) -> usize {
        self.script_num_length_policy
    }
}

/// Which rules judge an input: the default mode or a node's word with its
/// figures.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
enum Mode {
    Default(DefaultMode),
    Word(ScriptFlags, NodeFigures),
}

/// The rules an input's scripts are judged by, and the local budgets of its
/// evaluation.
///
/// Built by [`InputRules::reference_default`] (also [`Default`]),
/// [`InputRules::reference_default_with`], [`InputRules::under`] or
/// [`InputRules::under_with`]; the
/// budgets by [`InputRules::with_memory_limit`] and
/// [`InputRules::with_work_limit`]. The fields are private and the setters
/// commute, so a later knob is a setter added, never a break.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct InputRules {
    mode: Mode,
    memory_limit: Option<usize>,
    work_limit: Option<u64>,
}

impl Default for InputRules {
    fn default() -> Self {
        Self::reference_default()
    }
}

impl InputRules {
    /// The reference SDK's `Spend` without flags, exactly as
    /// [`Transaction::verify`] runs every input when no chain parameters are
    /// given: strict at a version of 1 or below, relaxed above, no NULLFAIL,
    /// the Chronicle opcodes at every version (the contract on
    /// [`crate::script::Spend`]). No memory or work budget.
    #[must_use]
    pub const fn reference_default() -> Self {
        Self::reference_default_with(DefaultMode::new())
    }

    /// The default mode with its overrides ([`DefaultMode`]).
    #[must_use]
    pub const fn reference_default_with(mode: DefaultMode) -> Self {
        Self {
            mode: Mode::Default(mode),
            memory_limit: None,
            work_limit: None,
        }
    }

    /// A node's word: every rule derived from `word` and the transaction's
    /// version as bitcoin-sv v1.2.2 derives it ([`Spend::set_flags`]).
    ///
    /// # Errors
    ///
    /// A word this interpreter cannot honor ([`ScriptFlags::check`]), before
    /// any input is judged, as the node refuses invalid flags before it reads
    /// the transaction (`bitcoinconsensus.cpp:88-90`). A judge holding a
    /// number writes `InputRules::under(ScriptFlags::from_bits(n)?)?`, which
    /// refuses an unknown bit first.
    pub fn under(word: ScriptFlags) -> Result<Self, ScriptFlagsError> {
        Self::under_with(word, NodeFigures::new())
    }

    /// A node's word judged with that node's own figures ([`NodeFigures`]):
    /// its stack memory policy, its block-path consensus figure and its
    /// script-number length policy, where [`InputRules::under`] takes the
    /// node's defaults.
    ///
    /// # Errors
    ///
    /// As [`InputRules::under`]: a word this interpreter cannot honor.
    pub fn under_with(word: ScriptFlags, figures: NodeFigures) -> Result<Self, ScriptFlagsError> {
        word.check()?;
        Ok(Self {
            mode: Mode::Word(word, figures),
            memory_limit: None,
            work_limit: None,
        })
    }

    /// The crate's own verifiers' rules: a word left for [`Spend::validate`]
    /// to check, so its refusal keeps the words those verifiers answer with.
    pub(crate) const fn for_verifier(
        word: Option<ScriptFlags>,
        memory_limit: Option<usize>,
        work_limit: Option<u64>,
    ) -> Self {
        Self {
            mode: match word {
                Some(word) => Mode::Word(word, NodeFigures::new()),
                None => Mode::Default(DefaultMode::new()),
            },
            memory_limit,
            work_limit,
        }
    }

    /// A LOCAL memory budget in bytes: exhausting it is
    /// [`InputRefusal::Declined`], never a verdict
    /// ([`crate::script::SpendParams::memory_limit`]). Without one the
    /// default mode is uncapped, as the reference's `Spend` is, and a word
    /// counts the node's 100,000,000 bytes. A Worker passes one.
    #[must_use]
    pub const fn with_memory_limit(mut self, bytes: usize) -> Self {
        self.memory_limit = Some(bytes);
        self
    }

    /// A LOCAL work budget: one unit per opcode reached plus each byte
    /// hashed; exhausting it is [`InputRefusal::Declined`], never a verdict
    /// ([`crate::script::SpendParams::work_limit`]). Without one, unbounded;
    /// the door counts the work either way ([`InputVerified::work_spent`]).
    #[must_use]
    pub const fn with_work_limit(mut self, units: u64) -> Self {
        self.work_limit = Some(units);
        self
    }

    /// The node's word, or `None` in the default mode.
    #[must_use]
    pub const fn word(&self) -> Option<ScriptFlags> {
        match self.mode {
            Mode::Word(word, _) => Some(word),
            Mode::Default(_) => None,
        }
    }

    /// The node's figures under a word, or `None` in the default mode.
    #[must_use]
    pub const fn node_figures(&self) -> Option<NodeFigures> {
        match self.mode {
            Mode::Word(_, figures) => Some(figures),
            Mode::Default(_) => None,
        }
    }

    /// The default mode and its overrides, or `None` under a word.
    #[must_use]
    pub const fn default_mode(&self) -> Option<DefaultMode> {
        match self.mode {
            Mode::Default(mode) => Some(mode),
            Mode::Word(..) => None,
        }
    }

    /// The memory budget, `None` for the mode's.
    #[must_use]
    pub const fn memory_limit(&self) -> Option<usize> {
        self.memory_limit
    }

    /// The work budget, `None` for unbounded.
    #[must_use]
    pub const fn work_limit(&self) -> Option<u64> {
        self.work_limit
    }
}

/// An input judged valid.
#[non_exhaustive]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct InputVerified {
    /// The work the evaluation spent, always counted, with or without a work
    /// limit ([`InputRules::with_work_limit`] bounds it, never decides
    /// whether it is counted). The unit is the work budget's: one per opcode
    /// reached plus one per byte hashed (an `OP_SHA256` or `OP_HASH160`
    /// operand, both rounds of a double hash, a signature check's sighash
    /// preimage), as [`Spend::work_spent`] counts it under a budget, so a
    /// caller can charge a transaction's inputs to one total
    /// ([`super::WorkBudget::charge`]). Every valid input spends at least 1.
    /// A [`SpendingTransaction`] hashes its BIP143 midstates once, charged to
    /// the input whose signature check computes them, so the inputs of one
    /// preparation judged one after another are charged that work once
    /// between them, as [`Transaction::verify`] charges it: the sum over the
    /// inputs is the same in any order, one input's figure is not (the
    /// earliest to need a midstate carries it). Judged concurrently on one
    /// preparation, two inputs that both find a midstate not yet computed
    /// are each charged it, so the sum is at least the sequential one.
    pub work_spent: u64,
}

/// Why an input was not judged valid. A verdict and a local budget's decline
/// are separate arms: reading a decline as invalid takes a match arm written
/// for it.
#[non_exhaustive]
#[derive(Clone, Debug, thiserror::Error)]
pub enum InputRefusal {
    /// The one-shot's bytes are not exactly one transaction: the strict
    /// reader's own error ([`Transaction::from_binary`]), before evaluation.
    #[error(transparent)]
    Transaction(crate::Error),
    /// The index names no input of the transaction, before evaluation.
    #[error("input index {index} out of range (transaction has {inputs} inputs)")]
    InputIndex {
        /// The index asked for.
        index: usize,
        /// The transaction's input count.
        inputs: usize,
    },
    /// A verdict: the scripts do not spend the output, in the interpreter's
    /// words ([`ScriptEvaluationError::message`]).
    #[error("{}", .0.message)]
    Invalid(Box<ScriptEvaluationError>),
    /// A local budget stopped the evaluation before a verdict: the error's
    /// [`ScriptEvaluationError::resource_limit`] is `Some`. Never a verdict.
    #[error("{}", .0.message)]
    Declined(Box<ScriptEvaluationError>),
}

impl InputRefusal {
    /// The interpreter's error, for [`InputRefusal::Invalid`] and
    /// [`InputRefusal::Declined`].
    #[must_use]
    pub fn evaluation(&self) -> Option<&ScriptEvaluationError> {
        match self {
            Self::Invalid(error) | Self::Declined(error) => Some(error),
            Self::Transaction(_) | Self::InputIndex { .. } => None,
        }
    }

    /// The budget a decline reached; `None` for every other arm.
    #[must_use]
    pub fn resource_limit(&self) -> Option<ScriptResourceLimit> {
        match self {
            Self::Declined(error) => error.resource_limit,
            _ => None,
        }
    }

    /// The crate's own verifiers' error for a refusal before evaluation: the
    /// reader's, or [`Spend::with_transaction`]'s text for an index.
    pub(crate) fn before_evaluation(self) -> Result<ScriptEvaluationError, crate::Error> {
        match self {
            Self::Invalid(error) | Self::Declined(error) => Ok(*error),
            Self::Transaction(error) => Err(error),
            index @ Self::InputIndex { .. } => {
                Err(crate::Error::ScriptExecutionError(index.to_string()))
            }
        }
    }
}

impl PartialEq for InputRefusal {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (Self::Transaction(a), Self::Transaction(b)) => a == b,
            (
                Self::InputIndex { index, inputs },
                Self::InputIndex {
                    index: other_index,
                    inputs: other_inputs,
                },
            ) => index == other_index && inputs == other_inputs,
            (Self::Invalid(a), Self::Invalid(b)) | (Self::Declined(a), Self::Declined(b)) => {
                same_evaluation(a, b)
            }
            _ => false,
        }
    }
}

impl Eq for InputRefusal {}

/// Every field of two interpreter errors equal. The destructure names every
/// field, so a field added to [`ScriptEvaluationError`] fails to compile here
/// until it is compared.
fn same_evaluation(a: &ScriptEvaluationError, b: &ScriptEvaluationError) -> bool {
    let ScriptEvaluationError {
        message,
        source_txid,
        source_output_index,
        context,
        program_counter,
        stack,
        alt_stack,
        if_stack,
        stack_mem,
        alt_stack_mem,
        resource_limit,
    } = a;
    *message == b.message
        && *source_txid == b.source_txid
        && *source_output_index == b.source_output_index
        && *context == b.context
        && *program_counter == b.program_counter
        && *stack == b.stack
        && *alt_stack == b.alt_stack
        && *if_stack == b.if_stack
        && *stack_mem == b.stack_mem
        && *alt_stack_mem == b.alt_stack_mem
        && *resource_limit == b.resource_limit
}

/// A transaction read from its bytes, prepared to verify any of its inputs:
/// one parse and one set of sighash midstates for every input.
///
/// `Send + Sync`: inputs may be judged on several threads at once.
#[derive(Clone)]
pub struct SpendingTransaction {
    transaction: Arc<TxSighashCache>,
}

impl fmt::Debug for SpendingTransaction {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SpendingTransaction")
            .field("version", &self.transaction.version())
            .field("inputs", &self.transaction.inputs().len())
            .field("outputs", &self.transaction.outputs().len())
            .field("lock_time", &self.transaction.locktime())
            .finish()
    }
}

const _: () = {
    const fn shareable<T: Send + Sync>() {}
    shareable::<SpendingTransaction>();
    shareable::<InputRules>();
    shareable::<NodeFigures>();
    shareable::<InputRefusal>();
};

impl SpendingTransaction {
    /// Reads exactly one transaction from `bytes`, as
    /// [`Transaction::from_binary`] reads it.
    ///
    /// # Errors
    ///
    /// The reader's own: bytes that end before the transaction does, or a
    /// byte after its lock time (`Serialized transaction contains trailing
    /// data`, #840).
    pub fn from_bytes(bytes: &[u8]) -> crate::Result<Self> {
        let transaction = Transaction::from_binary(bytes)?;
        Ok(Self {
            transaction: sighash_of(&transaction)?,
        })
    }

    /// The number of inputs the transaction carries.
    #[must_use]
    pub fn input_count(&self) -> usize {
        self.transaction.inputs().len()
    }

    /// Verifies input `input_index` against the output it spends: its
    /// `locking_script` and `source_satoshis`, under `rules`. The unlocking
    /// script is the input's own; the version, the other inputs, the outputs
    /// and the lock time are the transaction's.
    ///
    /// # Errors
    ///
    /// [`InputRefusal::InputIndex`] for an index past the inputs, before
    /// evaluation; [`InputRefusal::Invalid`] for a verdict;
    /// [`InputRefusal::Declined`] when a budget of `rules` stopped it.
    pub fn verify_input(
        &self,
        input_index: usize,
        locking_script: &[u8],
        source_satoshis: u64,
        rules: &InputRules,
    ) -> Result<InputVerified, InputRefusal> {
        let inputs = self.input_count();
        let Some(input) = self.transaction.inputs().get(input_index) else {
            return Err(InputRefusal::InputIndex {
                index: input_index,
                inputs,
            });
        };
        // The work is counted whatever the rules carry: a budget of
        // `u64::MAX` counts without bounding (the production paths call the
        // core with their own rules, unchanged).
        let counted = InputRules {
            work_limit: Some(rules.work_limit.unwrap_or(u64::MAX)),
            ..*rules
        };
        judge_input(
            &self.transaction,
            input_index,
            locking_script,
            &input.script,
            source_satoshis,
            &counted,
        )
        .result
    }
}

/// Verifies input `input_index` of the transaction `spending_tx` against the
/// output it spends, in the node's argument order
/// (`bitcoinconsensus_verify_script_with_amount`: the locking script, the
/// amount, the transaction, the index; the word in `rules`).
///
/// [`SpendingTransaction::from_bytes`] then
/// [`SpendingTransaction::verify_input`], nothing else: a caller with more
/// than one input of a transaction prepares it once and calls the method,
/// sharing the parse and the sighash midstates.
///
/// The two byte slices are the locking script first and the transaction
/// second, as the node's call has them; swapped, the locking script is read
/// as the transaction and refused as not one, save a script built to be one.
///
/// # Errors
///
/// [`InputRefusal::Transaction`] for bytes that are not exactly one
/// transaction, then the method's.
pub fn verify_input(
    locking_script: &[u8],
    source_satoshis: u64,
    spending_tx: &[u8],
    input_index: usize,
    rules: &InputRules,
) -> Result<InputVerified, InputRefusal> {
    SpendingTransaction::from_bytes(spending_tx)
        .map_err(InputRefusal::Transaction)?
        .verify_input(input_index, locking_script, source_satoshis, rules)
}

/// What the core answers: the door's result and the work charged either way
/// (the stream charges a refused input's work to its total too).
pub(crate) struct Judged {
    pub(crate) result: Result<InputVerified, InputRefusal>,
    pub(crate) work_spent: u64,
}

/// THE core: one input of `transaction` judged under `rules`, the only
/// construction of a [`Spend`] for an input outside `src/script/`. The door,
/// [`Transaction::verify`] and the streaming reader all call it.
pub(crate) fn judge_input(
    transaction: &Arc<TxSighashCache>,
    input_index: usize,
    locking_script: &[u8],
    unlocking_script: &[u8],
    source_satoshis: u64,
    rules: &InputRules,
) -> Judged {
    let refused = |refusal| Judged {
        result: Err(refusal),
        work_spent: 0,
    };
    let scripts = LockingScript::from_binary(locking_script).and_then(|locking| {
        UnlockingScript::from_binary(unlocking_script).map(|unlocking| (locking, unlocking))
    });
    let (locking_script, unlocking_script) = match scripts {
        Ok(scripts) => scripts,
        Err(error) => return refused(InputRefusal::Transaction(error)),
    };
    let inputs = transaction.inputs().len();
    let Ok(mut spend) = Spend::with_transaction(TxSpendParams {
        transaction: Arc::clone(transaction),
        input_index,
        source_satoshis,
        locking_script,
        unlocking_script,
        memory_limit: rules.memory_limit,
        work_limit: rules.work_limit,
    }) else {
        return refused(InputRefusal::InputIndex {
            index: input_index,
            inputs,
        });
    };
    apply_mode(&mut spend, rules.mode);
    let verdict = spend.validate();
    let work_spent = spend.work_spent();
    Judged {
        result: classify(verdict, work_spent),
        work_spent,
    }
}

fn apply_mode(spend: &mut Spend, mode: Mode) {
    match mode {
        Mode::Word(word, figures) => {
            spend.set_flags(word);
            spend.set_stack_memory_policy(figures.stack_memory_policy);
            spend.set_stack_memory_consensus(figures.stack_memory_consensus);
            spend.set_script_num_length_policy(figures.script_num_length_policy);
        }
        Mode::Default(mode) => {
            if let Some(require) = mode.require_push_only {
                spend.set_require_push_only(require);
            }
            if let Some(require) = mode.require_minimal {
                spend.set_require_minimal(require);
            }
            if let Some(after) = mode.utxo_after_chronicle {
                spend.set_utxo_after_chronicle(after);
            }
        }
    }
}

fn classify(
    verdict: Result<bool, ScriptEvaluationError>,
    work_spent: u64,
) -> Result<InputVerified, InputRefusal> {
    match verdict {
        Ok(true) => Ok(InputVerified { work_spent }),
        // `Spend::validate` answers `Ok(true)` or `Err`; were it ever to
        // answer `Ok(false)`, that is no proof of validity.
        Ok(false) => Err(InputRefusal::Invalid(Box::new(ScriptEvaluationError::new(
            "the script did not succeed",
            String::new(),
            0,
            ExecutionContext::LockingScript,
            0,
            Vec::new(),
            Vec::new(),
            Vec::new(),
            0,
            0,
        )))),
        Err(error) if error.is_resource_limit() => Err(InputRefusal::Declined(Box::new(error))),
        Err(error) => Err(InputRefusal::Invalid(Box::new(error))),
    }
}

/// The transaction and its midstates, shared by the spends of its inputs:
/// each input's unlocking script kept (the door's unlocking script), the
/// digest reading none of them.
pub(crate) fn sighash_of(tx: &Transaction) -> crate::Result<Arc<TxSighashCache>> {
    let outputs = tx
        .outputs()
        .iter()
        .map(|o| TxOutput {
            satoshis: o.satoshis.unwrap_or(0),
            script: o.locking_script.to_binary(),
        })
        .collect();
    let inputs = tx
        .inputs()
        .iter()
        .map(|i| {
            Ok(TxInput {
                txid: i.get_source_txid_bytes()?,
                output_index: i.source_output_index,
                script: i
                    .unlocking_script
                    .as_ref()
                    .map(|s| s.to_binary())
                    .unwrap_or_default(),
                sequence: i.sequence,
            })
        })
        .collect::<crate::Result<_>>()?;
    Ok(Arc::new(TxSighashCache::new(
        tx.version() as i32,
        inputs,
        outputs,
        tx.lock_time(),
    )))
}
