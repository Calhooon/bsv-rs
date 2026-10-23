//! The sibling seed corpus through Spend under each input's block word.
#![allow(missing_docs)] // #135: Criterion entry point

use std::collections::{BTreeSet, HashSet};
use std::error::Error;
use std::path::{Path, PathBuf};

use bsv_rs::primitives::bsv::sighash::{TxInput, TxOutput};
use bsv_rs::primitives::sha256;
use bsv_rs::script::{LockingScript, ProtocolEra, ScriptFlags, Spend, SpendParams};
use bsv_rs::transaction::Transaction;
use criterion::{black_box, Criterion, Throughput};
use serde::Deserialize;

#[derive(Deserialize)]
struct Prevout {
    txid: String,
    vout: u32,
    script: String,
    satoshis: u64,
    height: u32,
}

#[derive(Deserialize)]
struct Params {
    spend_height: u32,
    tx_version: i32,
}

#[derive(Deserialize)]
struct Entry {
    id: String,
    tx: String,
    prevouts: Vec<Prevout>,
    params: Params,
}

struct Case {
    params: SpendParams,
    flags: ScriptFlags,
}

impl Case {
    fn run(&self) {
        let p = &self.params;
        let mut spend = Spend::new(SpendParams {
            source_txid: p.source_txid,
            source_output_index: p.source_output_index,
            source_satoshis: p.source_satoshis,
            locking_script: p.locking_script.clone(),
            transaction_version: p.transaction_version,
            other_inputs: p.other_inputs.clone(),
            outputs: p.outputs.clone(),
            input_index: p.input_index,
            unlocking_script: p.unlocking_script.clone(),
            input_sequence: p.input_sequence,
            lock_time: p.lock_time,
            memory_limit: p.memory_limit,
            work_limit: None,
        });
        spend.set_flags(self.flags);
        // Accepts and refusals both cost time; their verdict belongs to the harness.
        let _ = black_box(spend.validate());
    }
}

fn corpus_file(path: PathBuf) -> PathBuf {
    if path.is_dir() {
        path.join("seed.jsonl")
    } else {
        path
    }
}

fn load(path: &Path) -> Result<Vec<Case>, Box<dyn Error>> {
    let bytes = std::fs::read(path)?;
    let mut cases = Vec::new();
    let mut ids = HashSet::new();
    let mut words = BTreeSet::new();
    for line in std::str::from_utf8(&bytes)?
        .lines()
        .filter(|line| !line.trim().is_empty())
    {
        let entry: Entry = serde_json::from_str(line)?;
        if !ids.insert(entry.id) {
            return Err("duplicate corpus row".into());
        }
        let tx = Transaction::from_hex(&entry.tx)?;
        if tx.inputs.len() != entry.prevouts.len() || tx.version as i32 != entry.params.tx_version {
            return Err("corpus input count or version mismatch".into());
        }
        let era = ProtocolEra::mainnet(entry.params.spend_height)
            .ok_or("pre-Genesis spend is unsupported")?;
        let inputs: Vec<_> = tx
            .inputs
            .iter()
            .map(|input| {
                Ok(TxInput {
                    txid: input.get_source_txid_bytes()?,
                    output_index: input.source_output_index,
                    script: Vec::new(), // matches harness::engine::run_input
                    sequence: input.sequence,
                })
            })
            .collect::<bsv_rs::Result<_>>()?;
        let outputs: Vec<_> = tx
            .outputs
            .iter()
            .map(|output| TxOutput {
                satoshis: output.satoshis.unwrap_or(0),
                script: output.locking_script.to_binary(),
            })
            .collect();
        for (index, (input, prevout)) in tx.inputs.iter().zip(&entry.prevouts).enumerate() {
            let utxo =
                ProtocolEra::mainnet(prevout.height).ok_or("pre-Genesis UTXO is unsupported")?;
            let mut hash = hex::decode(&prevout.txid)?;
            hash.reverse();
            let source_txid: [u8; 32] = hash.try_into().map_err(|_| "invalid txid length")?;
            if source_txid != input.get_source_txid_bytes()?
                || prevout.vout != input.source_output_index
            {
                return Err("corpus prevout does not match input".into());
            }
            // harness::engine::word_for, block path: spend era plus the coin's marker.
            let mut flags = ScriptFlags::block(era).without(ScriptFlags::UTXO_AFTER_CHRONICLE);
            if utxo.is_chronicle() {
                flags |= ScriptFlags::UTXO_AFTER_CHRONICLE;
            }
            words.insert(flags.bits());
            cases.push(Case {
                flags,
                params: SpendParams {
                    source_txid,
                    source_output_index: prevout.vout,
                    source_satoshis: prevout.satoshis,
                    locking_script: LockingScript::from_hex(&prevout.script)?,
                    transaction_version: tx.version as i32,
                    other_inputs: inputs
                        .iter()
                        .enumerate()
                        .filter(|(i, _)| *i != index)
                        .map(|(_, v)| v.clone())
                        .collect(),
                    outputs: outputs.clone(),
                    input_index: index,
                    unlocking_script: input.unlocking_script.clone().ok_or("missing unlock")?,
                    input_sequence: input.sequence,
                    lock_time: tx.lock_time,
                    memory_limit: None,
                    work_limit: None,
                },
            });
        }
    }
    if cases.is_empty() {
        return Err("empty corpus".into());
    }
    println!(
        "BSV_BENCH_CORPUS {}",
        serde_json::json!({
            "sha256": hex::encode(sha256(&bytes)), "rows": ids.len(),
            "inputs": cases.len(), "block_words": words,
            "adapter": "bsv-script-lean@8840488:engine::run_input/word_for",
        })
    );
    Ok(cases)
}

fn main() -> Result<(), Box<dyn Error>> {
    let mut c = Criterion::default().configure_from_args();
    let Some(path) = std::env::var_os("BSV_SCRIPT_CORPUS") else {
        eprintln!("SKIP script_spend: set BSV_SCRIPT_CORPUS to the sibling corpus/seed directory or seed.jsonl; no script throughput measured");
        return Ok(());
    };
    let cases = load(&corpus_file(path.into()))?;
    let mut group = c.benchmark_group("script_spend");
    group.throughput(Throughput::Elements(cases.len() as u64));
    group.bench_function("seed_block", |b| {
        b.iter(|| {
            for case in black_box(&cases) {
                case.run();
            }
        })
    });
    group.finish();
    c.final_summary();
    Ok(())
}
