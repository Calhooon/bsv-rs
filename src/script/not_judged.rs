//! Typed reasons why a verifier cannot judge an input within its scope or resources.

use std::fmt;

use crate::block::ActivationHeightsError;

/// A refusal of the verifier's scope or resources, never a transaction judgment.
///
/// The transaction and stream verifiers carry this cause beside the input index.
/// Match its fields instead of parsing its diagnostic text.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum NotJudgedCause {
    /// The input exhausted the verifier's local work budget before its next charge.
    WorkBudgetExceeded {
        /// The index of the input whose evaluation stopped.
        input: u32,
        /// The local per-input budget in `SpendParams::work_limit` units.
        budget: u64,
        /// Work already charged, at or below the budget; excludes the refused charge.
        work_done: u64,
    },
    /// The total charged after this input exceeded the transaction's local budget.
    TransactionWorkBudgetExceeded {
        /// The input where the running total crossed the bound, in verification order.
        input: u32,
        /// The local per-transaction bound in `SpendParams::work_limit` units.
        limit: u64,
        /// Work charged across this transaction's evaluated inputs, including this one.
        /// Saturates at `u64::MAX` if the counter overflows; overflow also declines.
        total: u64,
    },
    /// The proven coin predates the interpreter's supported eras.
    PreGenesisCoin {
        /// The coin's verified BUMP height.
        height: u32,
        /// The inclusive Genesis activation height in `ChainParams`.
        genesis_height: u32,
    },
    /// The candidate spend predates the interpreter's supported eras.
    PreGenesisSpend {
        /// The candidate spend height.
        height: u32,
        /// The inclusive Genesis activation height in `ChainParams`.
        genesis_height: u32,
    },
    /// The tip has no representable next block height.
    TipHeightOverflow {
        /// The supplied tip height.
        tip: u32,
    },
    /// A public activation field was set to zero.
    ZeroActivationHeight(ActivationHeightsError),
    /// A streaming BUMP's height cannot be passed to the word selector.
    ///
    /// Reachable through synchronous streaming `Headers`, which accepts
    /// `u64` heights. The in-memory `MerklePath` conversion and asynchronous
    /// `ChainTracker` path reject such heights before word selection.
    SourceHeightOverflow {
        /// The coin's verified BUMP height.
        height: u64,
    },
}

impl NotJudgedCause {
    // Preserve the standalone word selector's existing error API and text.
    pub(crate) fn flags_message(self) -> &'static str {
        match self {
            Self::WorkBudgetExceeded { .. } => {
                "The input exceeded the verifier's local work budget."
            }
            Self::TransactionWorkBudgetExceeded { .. } => {
                "The transaction exceeded the verifier's local work budget."
            }
            Self::PreGenesisCoin { .. } => {
                "The source output was created before Genesis; its script era is unsupported."
            }
            Self::PreGenesisSpend { .. } => {
                "The spending transaction is before Genesis; its script era is unsupported."
            }
            Self::TipHeightOverflow { .. } => "The mining tip has no next block height in u32.",
            Self::ZeroActivationHeight(error) => error.message(),
            Self::SourceHeightOverflow { .. } => "The source output's proven height exceeds u32.",
        }
    }
}

impl fmt::Display for NotJudgedCause {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::WorkBudgetExceeded {
                budget, work_done, ..
            } => write!(
                f,
                "exceeded work budget {budget} units after {work_done} units of work."
            ),
            Self::TransactionWorkBudgetExceeded { limit, total, .. } => write!(
                f,
                "exceeded transaction work budget {limit} units after {total} units of work."
            ),
            Self::PreGenesisCoin {
                height,
                genesis_height,
            } => {
                write!(
                    f,
                    "coin height {height} is before Genesis height {genesis_height}."
                )
            }
            Self::PreGenesisSpend {
                height,
                genesis_height,
            } => {
                write!(
                    f,
                    "spend height {height} is before Genesis height {genesis_height}."
                )
            }
            Self::TipHeightOverflow { tip } => write!(
                f,
                "tip height {tip} cannot produce a spend height within u32 (maximum {}).",
                u32::MAX
            ),
            Self::ZeroActivationHeight(error) => {
                let name = match error {
                    ActivationHeightsError::ZeroGenesis => "Genesis",
                    ActivationHeightsError::ZeroChronicle => "Chronicle",
                };
                write!(
                    f,
                    "{name} activation height 0 is outside the supported range 1..={}.",
                    u32::MAX
                )
            }
            Self::SourceHeightOverflow { height } => write!(
                f,
                "coin height {height} exceeds the supported maximum height {}.",
                u32::MAX
            ),
        }
    }
}
