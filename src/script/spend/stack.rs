//! The main and the alt stack: push, pop and peek, and the memory each
//! element is charged (the default mode's per-stack count, or the node's
//! count under a word).

use crate::script::evaluation_error::{ScriptEvaluationError, ScriptResource};
use crate::script::flags::STACK_ELEMENT_OVERHEAD;
use crate::script::op::opcode_to_name;

use super::Spend;

impl Spend {
    // ========================================================================
    // Stack Helpers
    // ========================================================================

    pub(super) fn push_stack(&mut self, item: Vec<u8>) -> Result<(), ScriptEvaluationError> {
        self.reserve_stack(item.len())?;
        self.stack_mem += item.len();
        self.stack.push(item);
        Ok(())
    }

    pub(super) fn push_stack_copy(&mut self, item: &[u8]) -> Result<(), ScriptEvaluationError> {
        self.push_stack(item.to_vec())
    }

    pub(super) fn pop_stack(&mut self) -> Result<Vec<u8>, ScriptEvaluationError> {
        let Some(item) = self.stack.pop() else {
            return Err(self.error("Attempted to pop from an empty stack."));
        };
        self.stack_mem -= item.len();
        self.release(item.len());
        Ok(item)
    }

    pub(super) fn stack_top(&self) -> Result<&Vec<u8>, ScriptEvaluationError> {
        if self.stack.is_empty() {
            return Err(self.error("Stack is empty."));
        }
        Ok(&self.stack[self.stack.len() - 1])
    }

    pub(super) fn stack_top_n(&self, n: usize) -> Result<&Vec<u8>, ScriptEvaluationError> {
        if self.stack.len() < n {
            return Err(self.error(&format!(
                "Stack underflow accessing element at index {}. Stack length is {}.",
                n,
                self.stack.len()
            )));
        }
        Ok(&self.stack[self.stack.len() - n])
    }

    /// The guard of a two-operand opcode: `<name> requires at least two items
    /// to be on the stack.` when the stack holds fewer than two.
    pub(super) fn require_two_items(
        &self,
        opcode: u8,
        fallback: &str,
    ) -> Result<(), ScriptEvaluationError> {
        if self.stack.len() < 2 {
            return Err(self.error(&format!(
                "{} requires at least two items to be on the stack.",
                opcode_to_name(opcode).unwrap_or(fallback)
            )));
        }
        Ok(())
    }

    pub(super) fn push_alt_stack(&mut self, item: Vec<u8>) -> Result<(), ScriptEvaluationError> {
        self.reserve_alt_stack(item.len())?;
        self.alt_stack_mem += item.len();
        self.alt_stack.push(item);
        Ok(())
    }

    pub(super) fn pop_alt_stack(&mut self) -> Result<Vec<u8>, ScriptEvaluationError> {
        let Some(item) = self.alt_stack.pop() else {
            return Err(self.error("Attempted to pop from an empty alt stack."));
        };
        self.alt_stack_mem -= item.len();
        self.release(item.len());
        Ok(item)
    }

    /// Before an element of `len` bytes joins the main stack: the default
    /// mode's budget for that stack, or under a word the node's charge.
    pub(super) fn reserve_stack(&mut self, len: usize) -> Result<(), ScriptEvaluationError> {
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
    pub(super) fn reserve_alt_stack(&mut self, len: usize) -> Result<(), ScriptEvaluationError> {
        if self.flags.is_some() {
            self.charge(len)
        } else {
            self.ensure_alt_stack_mem(len)
        }
    }

    /// Under a word, charges an element of `len` bytes to the node's count
    /// (`LimitedStack::push_back`, `limitedstack.h:163`, `171`: its size plus
    /// `STACK_ELEMENT_OVERHEAD`), tested before the element is held.
    pub(super) fn charge(&mut self, len: usize) -> Result<(), ScriptEvaluationError> {
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
    pub(super) fn release(&mut self, len: usize) {
        if self.flags.is_some() {
            self.node_mem = self
                .node_mem
                .saturating_sub(len as u64 + STACK_ELEMENT_OVERHEAD as u64);
        }
    }

    pub(super) fn ensure_stack_mem(&self, additional: usize) -> Result<(), ScriptEvaluationError> {
        if self.stack_mem + additional > self.memory_limit() {
            return Err(self.resource_error(ScriptResource::Stack, self.stack_mem + additional));
        }
        Ok(())
    }

    pub(super) fn ensure_alt_stack_mem(
        &self,
        additional: usize,
    ) -> Result<(), ScriptEvaluationError> {
        if self.alt_stack_mem + additional > self.memory_limit() {
            return Err(
                self.resource_error(ScriptResource::AltStack, self.alt_stack_mem + additional)
            );
        }
        Ok(())
    }
}
