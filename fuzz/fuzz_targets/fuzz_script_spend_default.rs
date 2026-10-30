#![no_main]
//! An arbitrary unlocking and locking script pair through `Spend` in the
//! default mode, no `set_flags` (CLAUDE.md, the contracts: the TypeScript
//! reference's verdicts), under `fuzz_script_spend`'s work budget, counting
//! allocator and bounds (`spend/mod.rs`; bsv-rs#398). The word target picks
//! a node word for every input, so until this target the default mode's own
//! verdicts were never fuzzed: the reference's read and push figure, 536,870,888
//! bits, `Invalid string length` (bsv-rs#331); a shift count above `INT_MAX`
//! refused before the value is read (bsv-rs#383); the splice operands read
//! by `#readSpliceOperand` and `OP_NUM2BIN`'s size in the reference's words
//! (bsv-rs#382).
//!
//! The input is the word target's: byte 0's bit 2 picks the spending
//! transaction's version (1 or 2), bit 3 the budget (the word target's 1 MiB,
//! or [`spend::READ_LIMIT_BUDGET`], 128 MiB, where an operand past the read
//! figure fits), bits 0 and 1 (the word target's word and era) read nothing;
//! bytes 1 and 2 are the unlocking script's length (little-endian); then the
//! unlocking script, and the rest is the locking script. So every entry of
//! the word target's corpus is an input here, its seeds this target's
//! (`fuzz/corpus/fuzz_script_spend_default/`, copied, every one with bit 3
//! clear), beside one seed per verdict above (`issue-331-…`, `issue-382-…`,
//! `issue-383-…`).
mod spend;

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let [mode, low, high, rest @ ..] = data else {
        return;
    };
    let version = if mode & 4 == 0 { 1 } else { 2 };
    let budget = if mode & 8 == 0 {
        spend::MEMORY_LIMIT
    } else {
        spend::READ_LIMIT_BUDGET
    };
    let split = (u16::from_le_bytes([*low, *high]) as usize).min(rest.len());
    let (unlocking, locking) = rest.split_at(split);
    spend::evaluate(None, version, budget, unlocking, locking);
});
