//! This crate's own words on every entry of a sibling corpus (#97, S1): the companion
//! `sibling_harness.py run` drops into its SCRATCH copy of the sibling's harness as
//! `src/bin/bsvrs_words.rs` (never into the sibling's tree), built beside `run_diff`.
//!
//! The sibling's `run_diff` judges the verdicts against the node's specification column
//! and counts a reason that moved from its recorded `bsv-rs@0.7.0` text without naming the
//! entry (`recorded_disagree`, `harness/src/bin/run_diff.rs:375-378` at the pin). This
//! binary runs the same three evaluations per entry through the harness's own adapter
//! (`engine::run_tx`, `engine::run_tx_words`, `engine::words_of`, the manifest's
//! `EngineConfig`), so the words are judged against `tests/sibling/column.json`, entry by
//! entry, by name. `spec_words` is `run_diff.rs`'s, transcribed (it is private there).
//!
//! Run: bsvrs_words --corpus <corpus.jsonl> --out <words.jsonl>
//! One line per entry: {"id", "rec", "spec", "mempool"}, each `[verdict, reason]`
//! (`reason` null for a valid spend).

use std::io::{BufRead, Write};

use bsv_rs::script::ScriptFlags;
use bsv_script_harness::corpus::Entry;
use bsv_script_harness::differential::CorpusInput;
use bsv_script_harness::engine::{run_tx, run_tx_words, words_of, EngineConfig, Mode, Verdict};
use bsv_script_harness::txraw::RawTx;

fn arg(args: &[String], name: &str) -> Option<String> {
    args.iter()
        .position(|a| a == name)
        .and_then(|i| args.get(i + 1).cloned())
}

/// `run_diff.rs`'s `spec_words`: the entry's explicit `flags` when it carries them, else
/// the word of its own `params.consensus`.
fn spec_words(
    flags: Option<&[u32]>,
    consensus: bool,
    words_block: &[Option<ScriptFlags>],
    words_std: &[Option<ScriptFlags>],
) -> Result<Vec<Option<ScriptFlags>>, String> {
    match flags {
        Some(f) => f
            .iter()
            .map(|&bits| {
                ScriptFlags::from_bits(bits)
                    .map(Some)
                    .map_err(|err| format!("flags word 0x{bits:X}: {err}"))
            })
            .collect(),
        None => Ok(if consensus {
            words_block.to_vec()
        } else {
            words_std.to_vec()
        }),
    }
}

fn pair(v: &Verdict) -> serde_json::Value {
    serde_json::json!([v.kind(), v.reason()])
}

fn run() -> Result<(), String> {
    let args: Vec<String> = std::env::args().collect();
    let corpus = arg(&args, "--corpus").ok_or("--corpus <file.jsonl>")?;
    let out = arg(&args, "--out").ok_or("--out <words.jsonl>")?;
    let input = CorpusInput::load(std::path::Path::new(&corpus)).map_err(|e| e.to_string())?;
    let mut cfg = EngineConfig::default();
    if let Some(m) = &input.manifest {
        if let Some(imp) = m.implementations.iter().find(|i| i.name == "bsv-rs") {
            cfg = EngineConfig::try_from_json(&imp.config)?;
        }
    }
    let mut sink = std::io::BufWriter::new(
        std::fs::File::create(&out).map_err(|e| format!("{out}: {e}"))?,
    );
    std::panic::set_hook(Box::new(|_| {}));
    let mut n = 0u64;
    for line in std::io::BufReader::new(&input.bytes[..]).lines() {
        let line = line.map_err(|e| e.to_string())?;
        if line.trim().is_empty() {
            continue;
        }
        let e: Entry = serde_json::from_str(&line).map_err(|err| format!("entry: {err}"))?;
        let bytes = hex::decode(&e.tx).map_err(|err| format!("{}: tx hex: {err}", e.id))?;
        let tx = RawTx::decode(&bytes).map_err(|err| format!("{}: tx frame: {err}", e.id))?;
        let prevouts: Vec<_> = e
            .prevouts
            .iter()
            .map(|p| p.to_prevout())
            .collect::<Result<_, _>>()
            .map_err(|err| format!("{}: prevout: {err}", e.id))?;
        let heights: Vec<u32> = e.prevouts.iter().map(|p| p.height).collect();
        let words_block = words_of(e.params.spend_height, &heights, true);
        let words_std = words_of(e.params.spend_height, &heights, false);
        let words_spec = spec_words(e.flags.as_deref(), e.params.consensus, &words_block, &words_std)
            .map_err(|err| format!("{}: {err}", e.id))?;
        let (v_rec, _) = if cfg.per_input_words {
            let words = if e.params.consensus { &words_block } else { &words_std };
            run_tx_words(&tx, &prevouts, Mode::Native, &cfg, words)
        } else {
            run_tx(&tx, &prevouts, Mode::Native, &cfg)
        };
        let (v_spec, _) = run_tx_words(&tx, &prevouts, Mode::Native, &cfg, &words_spec);
        let (v_std, _) = run_tx_words(&tx, &prevouts, Mode::Native, &cfg, &words_std);
        let row = serde_json::json!({
            "id": e.id,
            "rec": pair(&v_rec),
            "spec": pair(&v_spec),
            "mempool": pair(&v_std),
        });
        writeln!(sink, "{row}").map_err(|err| format!("{out}: {err}"))?;
        n += 1;
    }
    sink.flush().map_err(|err| format!("{out}: {err}"))?;
    println!("bsvrs_words: {n} entries of {corpus} into {out}");
    Ok(())
}

fn main() -> std::process::ExitCode {
    match run() {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("bsvrs_words: {e}");
            std::process::ExitCode::from(2)
        }
    }
}
