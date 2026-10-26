//! File-backed BEEF streaming: decimal MB, with sampled RSS in fresh processes.
//!
//! `BSV_BEEF_REVERSED=1` adds `beef_stream_reversed`: the same chains written
//! newest first, the proven funding transaction last (bsv-rs#240: every link
//! held until it arrives, then released on a heap). Off by default, so the
//! gate's inventory (`tools/bench-compare`) is unchanged.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)] // #134: benchmark setup

use std::collections::HashMap;
use std::fs::File;
use std::io::BufReader;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use bsv_rs::primitives::{from_hex, sha256d};
use bsv_rs::script::{LockingScript, UnlockingScript};
use bsv_rs::transaction::{
    verify_stream, verify_stream_structure, Beef, BeefTx, MerklePath, Progress, StreamVerifier,
    Transaction, TransactionInput, TransactionOutput,
};
use criterion::{black_box, BenchmarkId, Criterion, Throughput};

const HEIGHT: u64 = 800_000;
const SIZES: [usize; 2] = [1_000_000, 10_000_000];

fn transaction(previous: String, payload: usize) -> Transaction {
    let mut tx = Transaction::new();
    let mut input = TransactionInput::new(previous, 0);
    // A push-only unlock; the lock consumes the padding, then leaves true.
    let mut unlock = vec![0x4d]; // OP_PUSHDATA2
    unlock.extend_from_slice(&(payload as u16).to_le_bytes());
    unlock.resize(payload + 3, 0);
    input.unlocking_script = Some(UnlockingScript::from_binary(&unlock).expect("padding push"));
    tx.inputs.push(input);
    tx.outputs.push(TransactionOutput::new(
        1_000,
        LockingScript::from_binary(&[0x75, 0x51]).expect("OP_DROP OP_TRUE"),
    ));
    tx
}

fn fixtures_dir() -> PathBuf {
    let base = std::env::var_os("BSV_BENCH_ARTIFACT_DIR")
        .or_else(|| std::env::var_os("CARGO_TARGET_DIR"))
        .or_else(|| std::env::var_os("TMPDIR"))
        .expect("set BSV_BENCH_ARTIFACT_DIR, CARGO_TARGET_DIR or TMPDIR outside the checkout");
    let dir = PathBuf::from(base).join("beef-fixtures");
    std::fs::create_dir_all(&dir).expect("create fixture directory");
    dir
}

fn build_fixture(path: &Path, bytes: usize) -> [u8; 32] {
    // One BUMP and a chain of roughly 1 KB transactions, all written by Beef.
    // Neither fixture construction nor a resident byte vector is timed.
    let sample = transaction("aa".repeat(32), 512);
    let payload = 999 - sample.to_binary().len() + 512;
    let funding = transaction("aa".repeat(32), payload);
    let root = sha256d(&funding.to_binary());
    let mut prev = funding.id();
    let mut beef = Beef::new();
    beef.bumps
        .push(MerklePath::from_coinbase_txid(&prev, HEIGHT as u32));
    beef.txs
        .push(BeefTx::from_raw_tx(funding.to_binary(), Some(0)));
    let count = bytes / 1_000;
    for _ in 1..count - 1 {
        let tx = transaction(prev, payload);
        prev = tx.id();
        beef.txs.push(BeefTx::from_raw_tx(tx.to_binary(), None));
    }
    let tail = transaction(prev.clone(), payload);
    beef.txs.push(BeefTx::from_raw_tx(tail.to_binary(), None));
    let overhead = beef.to_binary().len() - bytes;
    let tail = transaction(prev, payload - overhead);
    *beef.txs.last_mut().expect("tail") = BeefTx::from_raw_tx(tail.to_binary(), None);
    let encoded = beef.to_binary();
    assert_eq!(encoded.len(), bytes, "fixture byte count");
    std::fs::write(path, encoded).expect("write fixture");
    root
}

/// The chain at `forward` written newest first, at `path`.
fn build_reversed(forward: &Path, path: &Path) {
    let mut beef = Beef::from_binary(&std::fs::read(forward).expect("fixture")).expect("a BEEF");
    beef.txs.reverse();
    let mut writer = bsv_rs::primitives::Writer::new();
    beef.to_writer(&mut writer);
    std::fs::write(path, writer.into_bytes()).expect("write fixture");
}

fn rss() -> usize {
    memory_stats::memory_stats()
        .expect("RSS is unavailable on this host")
        .physical_mem
}

fn rss_probe(path: &Path, root: [u8; 32], scripts: bool) {
    let source = BufReader::with_capacity(64 * 1024, File::open(path).expect("fixture"));
    let headers = HashMap::from([(HEIGHT, root)]);
    let mut reader = if scripts {
        StreamVerifier::new(source, headers, None)
    } else {
        StreamVerifier::structure_only(source, headers, None)
    };
    let start_rss = rss();
    let done = Arc::new(AtomicBool::new(false));
    let stop = Arc::clone(&done);
    let sampler = std::thread::spawn(move || {
        let mut peak = start_rss;
        while !stop.load(Ordering::Relaxed) {
            peak = peak.max(rss());
            std::thread::sleep(Duration::from_micros(100));
        }
        peak.max(rss())
    });
    let started = Instant::now();
    let verdict = loop {
        if let Progress::Verdict(verdict) = reader.step().expect("read fixture") {
            break verdict;
        }
    };
    let wall_ns = started.elapsed().as_nanos();
    let end_rss = rss();
    done.store(true, Ordering::Relaxed);
    let peak = sampler.join().expect("RSS sampler").max(end_rss);
    println!(
        "BSV_BENCH_MEMORY {}",
        serde_json::json!({
            "bytes": std::fs::metadata(path).expect("fixture length").len(),
            "mode": if scripts { "scripts" } else { "structure" },
            "start_rss_bytes": start_rss,
            "peak_rss_bytes": peak,
            "delta_rss_bytes": peak.saturating_sub(start_rss),
            "wall_ns": wall_ns,
            "entries": reader.index().entries(),
            "verdict": format!("{verdict:?}").split('{').next().unwrap_or("unknown").trim(),
        })
    );
}

fn main() {
    if let Some(path) = std::env::var_os("BSV_BEEF_RSS_INPUT") {
        let root: [u8; 32] = from_hex(&std::env::var("BSV_BEEF_RSS_ROOT").expect("root"))
            .expect("root hex")
            .try_into()
            .expect("32-byte root");
        rss_probe(
            Path::new(&path),
            root,
            std::env::var("BSV_BEEF_RSS_MODE").expect("mode") == "scripts",
        );
        return;
    }
    let dir = fixtures_dir();
    let mut c = Criterion::default().configure_from_args();
    let mut group = c.benchmark_group("beef_stream");
    for bytes in SIZES {
        let path = dir.join(format!("{bytes}.beef"));
        let root = build_fixture(&path, bytes);
        group.throughput(Throughput::Bytes(bytes as u64));
        for scripts in [false, true] {
            let mode = if scripts { "scripts" } else { "structure" };
            // Fresh process per size and mode: no allocator pages from the writer
            // or from a preceding, larger fixture can contaminate the high water.
            let output = Command::new(std::env::current_exe().expect("bench executable"))
                .env("BSV_BEEF_RSS_INPUT", &path)
                .env("BSV_BEEF_RSS_ROOT", hex::encode(root))
                .env("BSV_BEEF_RSS_MODE", mode)
                .output()
                .expect("RSS probe process");
            assert!(
                output.status.success(),
                "RSS probe failed: {}",
                String::from_utf8_lossy(&output.stderr)
            );
            print!("{}", String::from_utf8_lossy(&output.stdout));
            let headers = HashMap::from([(HEIGHT, root)]);
            group.bench_with_input(BenchmarkId::new(mode, bytes), &path, |b, path| {
                b.iter(|| {
                    let source =
                        BufReader::with_capacity(64 * 1024, File::open(path).expect("fixture"));
                    if scripts {
                        black_box(verify_stream(source, &headers, None).expect("read fixture"));
                    } else {
                        black_box(
                            verify_stream_structure(source, &headers, None).expect("read fixture"),
                        );
                    }
                });
            });
        }
    }
    group.finish();
    if std::env::var_os("BSV_BEEF_REVERSED").is_some() {
        let mut group = c.benchmark_group("beef_stream_reversed");
        for bytes in SIZES {
            let forward = dir.join(format!("{bytes}.beef"));
            let root = build_fixture(&forward, bytes);
            let path = dir.join(format!("{bytes}.reversed.beef"));
            build_reversed(&forward, &path);
            let headers = HashMap::from([(HEIGHT, root)]);
            group.throughput(Throughput::Bytes(bytes as u64));
            for scripts in [false, true] {
                let mode = if scripts { "scripts" } else { "structure" };
                let read = |path: &Path| {
                    let source =
                        BufReader::with_capacity(64 * 1024, File::open(path).expect("fixture"));
                    if scripts {
                        verify_stream(source, &headers, None)
                    } else {
                        verify_stream_structure(source, &headers, None)
                    }
                    .expect("read fixture")
                };
                let verdict = format!("{:?}", read(&path));
                println!(
                    "beef_stream_reversed/{mode}/{bytes}: {}",
                    verdict.split(" {").next().unwrap_or("unknown")
                );
                group.bench_with_input(BenchmarkId::new(mode, bytes), &path, |b, path| {
                    b.iter(|| {
                        let source =
                            BufReader::with_capacity(64 * 1024, File::open(path).expect("fixture"));
                        let verdict = if scripts {
                            verify_stream(source, &headers, None)
                        } else {
                            verify_stream_structure(source, &headers, None)
                        };
                        black_box(verdict.expect("read fixture"));
                    });
                });
            }
        }
        group.finish();
    }
    c.final_summary();
}
