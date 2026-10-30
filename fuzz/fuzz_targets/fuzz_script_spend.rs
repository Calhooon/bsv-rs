#![no_main]
//! An arbitrary unlocking and locking script pair through `Spend` under the
//! node's block word and its standard word (CLAUDE.md, the contracts), with a
//! small work budget and the local memory budget set. The assertion is no
//! panic and no allocation past the budget, never a verdict: a counting
//! allocator's largest single request and live peak within the budget's
//! bounds (`spend/mod.rs`, shared with `fuzz_script_spend_default`, which
//! evaluates the same inputs without a word, bsv-rs#398).
//!
//! The input: byte 0 picks the word (bit 0: block or standard), the era
//! (bit 1: post-Genesis or post-Chronicle) and the spending transaction's
//! version (bit 2: 1 or 2); bytes 1 and 2 are the unlocking script's length
//! (little-endian); then the unlocking script, and the rest is the locking
//! script. `fuzz/corpus-gen` writes the sibling harness's seed rows in this
//! shape.
mod spend;

use bsv_rs::script::{ProtocolEra, ScriptFlags};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let [mode, low, high, rest @ ..] = data else {
        return;
    };
    let era = if mode & 2 == 0 {
        ProtocolEra::PostGenesis
    } else {
        ProtocolEra::PostChronicle
    };
    let word = if mode & 1 == 0 {
        ScriptFlags::block(era)
    } else {
        ScriptFlags::standard(era)
    };
    let version = if mode & 4 == 0 { 1 } else { 2 };
    let split = (u16::from_le_bytes([*low, *high]) as usize).min(rest.len());
    let (unlocking, locking) = rest.split_at(split);
    spend::evaluate(Some(word), version, spend::MEMORY_LIMIT, unlocking, locking);
});
