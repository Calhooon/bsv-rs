//! Script evaluation error with full execution context.
//!
//! This module provides a rich error type that captures the complete state
//! of the script interpreter at the time of failure, enabling detailed debugging.

use crate::primitives::to_hex;
use std::fmt;

/// The execution context within which an error occurred.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExecutionContext {
    /// Error occurred while executing the unlocking script (scriptSig).
    UnlockingScript,
    /// Error occurred while executing the locking script (scriptPubKey).
    LockingScript,
}

impl fmt::Display for ExecutionContext {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ExecutionContext::UnlockingScript => write!(f, "UnlockingScript"),
            ExecutionContext::LockingScript => write!(f, "LockingScript"),
        }
    }
}

/// A rich error type for script evaluation failures.
///
/// Contains the full execution state at the time of failure, enabling
/// detailed debugging and error reporting.
/// A LOCAL interpreter resource the evaluation ran out of — the TypeScript
/// SDK's `ScriptResourceLimitError` (`ScriptResource`): `'stack'`,
/// `'alt-stack'`, `'element-size'`. Resource exhaustion is a verdict about the
/// EVALUATOR's budget, never about the script's validity on the network, and
/// a caller (an overlay door, a wallet) must be able to tell the two apart.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScriptResource {
    /// The main stack's memory budget (`memory_limit`).
    Stack,
    /// The alt stack's memory budget (`memory_limit`).
    AltStack,
    /// A single element the script asked to allocate (`OP_NUM2BIN`'s size
    /// operand), refused BEFORE the allocation.
    ElementSize,
}

impl fmt::Display for ScriptResource {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ScriptResource::Stack => write!(f, "stack"),
            ScriptResource::AltStack => write!(f, "alt-stack"),
            ScriptResource::ElementSize => write!(f, "element-size"),
        }
    }
}

/// The resource a [`ScriptEvaluationError`] ran out of, with the limit and
/// the attempted usage (the reference's `ScriptResourceLimitError` fields).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ScriptResourceLimit {
    pub resource: ScriptResource,
    pub limit: usize,
    pub attempted: usize,
}

#[derive(Debug, Clone)]
pub struct ScriptEvaluationError {
    /// The error message describing what went wrong.
    pub message: String,
    /// The TXID of the source UTXO being spent (hex, display order).
    pub source_txid: String,
    /// The output index of the source UTXO.
    pub source_output_index: u32,
    /// Whether the error occurred in the unlocking or locking script.
    pub context: ExecutionContext,
    /// The program counter (chunk index) when the error occurred.
    pub program_counter: usize,
    /// The state of the main stack at the time of failure.
    pub stack: Vec<Vec<u8>>,
    /// The state of the alt stack at the time of failure.
    pub alt_stack: Vec<Vec<u8>>,
    /// The state of the if/else condition stack.
    pub if_stack: Vec<bool>,
    /// Memory usage of the main stack in bytes.
    pub stack_mem: usize,
    /// Memory usage of the alt stack in bytes.
    pub alt_stack_mem: usize,
    /// `Some` when the evaluation stopped because a LOCAL resource budget was
    /// exhausted (the TypeScript SDK throws a distinct
    /// `ScriptResourceLimitError` for these); `None` for every verdict about
    /// the script itself. Added in 0.3.23 (reference parity).
    pub resource_limit: Option<ScriptResourceLimit>,
}

impl ScriptEvaluationError {
    /// Creates a new script evaluation error with the given context.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        message: impl Into<String>,
        source_txid: impl Into<String>,
        source_output_index: u32,
        context: ExecutionContext,
        program_counter: usize,
        stack: Vec<Vec<u8>>,
        alt_stack: Vec<Vec<u8>>,
        if_stack: Vec<bool>,
        stack_mem: usize,
        alt_stack_mem: usize,
    ) -> Self {
        Self {
            message: message.into(),
            source_txid: source_txid.into(),
            source_output_index,
            context,
            program_counter,
            stack,
            alt_stack,
            if_stack,
            stack_mem,
            alt_stack_mem,
            resource_limit: None,
        }
    }

    /// Mark this error as a LOCAL resource exhaustion (the reference's
    /// `ScriptResourceLimitError`): the evaluator's budget, not the script's
    /// validity.
    pub fn with_resource_limit(mut self, limit: ScriptResourceLimit) -> Self {
        self.resource_limit = Some(limit);
        self
    }

    /// Whether the evaluation stopped on a LOCAL resource budget (see
    /// [`ScriptEvaluationError::resource_limit`]) rather than on the script.
    pub fn is_resource_limit(&self) -> bool {
        self.resource_limit.is_some()
    }

    /// Formats the stack as a hex string list.
    fn format_stack(stack: &[Vec<u8>]) -> String {
        let hex_items: Vec<String> = stack
            .iter()
            .map(|item| {
                if item.is_empty() {
                    "[]".to_string()
                } else {
                    to_hex(item)
                }
            })
            .collect();
        format!("[{}]", hex_items.join(", "))
    }

    /// Formats the if stack as a boolean list.
    fn format_if_stack(if_stack: &[bool]) -> String {
        let items: Vec<&str> = if_stack
            .iter()
            .map(|&b| if b { "true" } else { "false" })
            .collect();
        format!("[{}]", items.join(", "))
    }
}

impl fmt::Display for ScriptEvaluationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "Script evaluation error: {}\n\
             TXID: {}, OutputIdx: {}\n\
             Context: {}, PC: {}\n\
             Stack: {} (len: {}, mem: {})\n\
             AltStack: {} (len: {}, mem: {})\n\
             IfStack: {}",
            self.message,
            self.source_txid,
            self.source_output_index,
            self.context,
            self.program_counter,
            Self::format_stack(&self.stack),
            self.stack.len(),
            self.stack_mem,
            Self::format_stack(&self.alt_stack),
            self.alt_stack.len(),
            self.alt_stack_mem,
            Self::format_if_stack(&self.if_stack),
        )
    }
}

impl std::error::Error for ScriptEvaluationError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_error_display() {
        let error = ScriptEvaluationError::new(
            "Stack underflow",
            "abc123",
            0,
            ExecutionContext::LockingScript,
            5,
            vec![vec![1, 2, 3], vec![]],
            vec![],
            vec![true, false],
            3,
            0,
        );

        let display = format!("{}", error);
        assert!(display.contains("Stack underflow"));
        assert!(display.contains("abc123"));
        assert!(display.contains("LockingScript"));
        assert!(display.contains("PC: 5"));
        assert!(display.contains("010203"));
        assert!(display.contains("[]"));
    }

    #[test]
    fn test_execution_context_display() {
        assert_eq!(
            format!("{}", ExecutionContext::UnlockingScript),
            "UnlockingScript"
        );
        assert_eq!(
            format!("{}", ExecutionContext::LockingScript),
            "LockingScript"
        );
    }

    #[test]
    fn test_format_stack() {
        let stack = vec![vec![0x01, 0x02], vec![], vec![0xff]];
        let formatted = ScriptEvaluationError::format_stack(&stack);
        assert_eq!(formatted, "[0102, [], ff]");
    }

    #[test]
    fn test_format_if_stack() {
        let if_stack = vec![true, false, true];
        let formatted = ScriptEvaluationError::format_if_stack(&if_stack);
        assert_eq!(formatted, "[true, false, true]");
    }
}
