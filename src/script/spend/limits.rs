//! The local budgets and their declines: the element and memory bounds, the
//! node's stack memory policy, the work budget, and the resource-limit errors
//! (`ScriptResourceLimit`) they raise.

use crate::script::evaluation_error::{ScriptEvaluationError, ScriptResource, ScriptResourceLimit};
use crate::script::flags::DEFAULT_STACK_MEMORY_USAGE_POLICY;

use super::Spend;

/// Maximum size of a single script element (1GB for BSV unlimited)
pub(super) const MAX_SCRIPT_ELEMENT_SIZE: usize = 1024 * 1024 * 1024;

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
pub(super) const MAX_MULTISIG_KEY_COUNT: i64 = i32::MAX as i64;

impl Spend {
    /// The LOCAL memory budget in force: `SpendParams::memory_limit` when it
    /// is `Some`, in every mode. Otherwise, in the TypeScript default mode,
    /// 32,000,000 bytes for each stack apart, counting the bytes alone, as
    /// that SDK counts; under a word, 100,000,000 bytes on the node's count,
    /// one budget over both stacks with [`STACK_ELEMENT_OVERHEAD`](crate::script::flags::STACK_ELEMENT_OVERHEAD) bytes per
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
    /// ([`ScriptFlags::max_stack_memory_usage`](crate::script::ScriptFlags::max_stack_memory_usage)). A growth that would take the
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

    /// Whether the node's count may reach `attempted` bytes. Above the stack
    /// memory policy in force ([`stack_memory_policy`](Self::stack_memory_policy))
    /// it is the reference's verdict: `LimitedStack::increaseCombinedStackSize`
    /// throws before the growth (`limitedstack.cpp:202-205`), caught as
    /// `SCRIPT_ERR_STACK_SIZE` (`interpreter.cpp:1815-1817`). Above the local
    /// budget ([`memory_limit`](Self::memory_limit)) it is a resource limit.
    /// The policy is tested first: its verdict needs nothing allocated.
    pub(super) fn check_node_budget(&self, attempted: u64) -> Result<(), ScriptEvaluationError> {
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

    /// A LOCAL resource-limit error (the reference's `ScriptResourceLimitError`):
    /// the same message shape (`<label> has exceeded <limit> bytes`) plus the
    /// structured `resource_limit` a caller can branch on.
    pub(super) fn resource_error(
        &self,
        resource: ScriptResource,
        attempted: usize,
    ) -> ScriptEvaluationError {
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

    /// Work charged in this evaluation when a work budget is configured.
    /// Unbounded evaluations do not calculate hash costs.
    pub fn work_spent(&self) -> u64 {
        self.work_spent
    }

    pub(super) fn charge_work(&mut self, cost: u64) -> Result<(), ScriptEvaluationError> {
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

    pub(super) fn work_error(&self, attempted: u64) -> ScriptEvaluationError {
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
}
