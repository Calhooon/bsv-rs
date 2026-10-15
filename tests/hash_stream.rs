//! The incremental hashers equal the one-shot hashes for every chunking.
//!
//! The witness is the corpus of BEEF of any size (bsv-stack-lean
//! `corpus/beef-of-any-size`, copied under `tests/vectors/beef_of_any_size/`):
//! every row's bytes hashed whole and in chunks of 1, 7, 64 KiB, the row's
//! full length and seeded random boundaries, against the digests the corpus
//! pins. Then generated buffers of 0 to 300,000 bytes.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)] // #134: test code: a failed unwrap is the test failing

use bsv_rs::primitives::hash::{sha256, sha256d, Sha256, Sha256d};
use rand::rngs::StdRng;
use rand::{Rng, RngCore, SeedableRng};
use std::path::{Path, PathBuf};

const SEED: u64 = 0x0061_5EED;

fn fixtures() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/vectors/beef_of_any_size")
}

struct Row {
    name: String,
    length: usize,
    generated: bool,
    sha256: String,
    sha256d: String,
}

fn rows() -> Vec<Row> {
    let text = std::fs::read_to_string(fixtures().join("rows.txt")).expect("rows.txt");
    text.lines()
        .map(|line| {
            let f: Vec<&str> = line.split(' ').collect();
            assert_eq!(f.len(), 5, "rows.txt line {line:?}");
            Row {
                name: f[0].to_string(),
                length: f[1].parse().expect("length"),
                generated: match f[2] {
                    "fixture" => false,
                    "generated" => true,
                    other => panic!("rows.txt kind {other:?}"),
                },
                sha256: f[3].to_string(),
                sha256d: f[4].to_string(),
            }
        })
        .collect()
}

/// The named chunkings of `len` bytes: (label, the chunk lengths in order).
fn chunkings(len: usize, rng: &mut StdRng) -> Vec<(String, Vec<usize>)> {
    let fixed = |size: usize| -> Vec<usize> {
        let mut out = vec![size; len / size];
        if !len.is_multiple_of(size) {
            out.push(len % size);
        }
        out
    };
    let mut random = Vec::new();
    let mut left = len;
    while left > 0 {
        let take = rng.gen_range(1..=left.min(70_000));
        random.push(take);
        left -= take;
    }
    // Empty updates in the middle and at both ends change nothing.
    let mut with_empty = vec![0];
    for c in &random {
        with_empty.push(*c);
        with_empty.push(0);
    }
    vec![
        ("1".to_string(), fixed(1)),
        ("7".to_string(), fixed(7)),
        ("64KiB".to_string(), fixed(64 * 1024)),
        (
            "whole".to_string(),
            if len == 0 { vec![] } else { vec![len] },
        ),
        ("random".to_string(), random),
        ("random+empty".to_string(), with_empty),
    ]
}

fn feed(data: &[u8], sizes: &[usize]) -> ([u8; 32], [u8; 32]) {
    assert_eq!(sizes.iter().sum::<usize>(), data.len());
    let mut single = Sha256::new();
    let mut double = Sha256d::new();
    let mut at = 0;
    for &size in sizes {
        single.update(&data[at..at + size]);
        double.update(&data[at..at + size]);
        at += size;
    }
    (single.finalize(), double.finalize())
}

/// Every chunking of `data` gives the one-shot digests; returns the count.
fn check_every_chunking(label: &str, data: &[u8], rng: &mut StdRng) -> usize {
    let whole = (sha256(data), sha256d(data));
    let all = chunkings(data.len(), rng);
    for (name, sizes) in &all {
        assert_eq!(
            feed(data, sizes),
            whole,
            "{label}: chunking {name} ({} updates) differs from the one-shot hash",
            sizes.len()
        );
    }
    all.len()
}

#[test]
fn every_corpus_row_hashes_the_same_whole_and_chunked() {
    let rows = rows();
    assert_eq!(rows.len(), 52, "the corpus has 52 rows");
    let extra = std::env::var_os("BSV_RS_BEEF_ROWS_DIR").map(PathBuf::from);
    let mut rng = StdRng::seed_from_u64(SEED);
    let (mut hashed, mut skipped) = (0, Vec::new());
    for row in &rows {
        let path = match (&extra, row.generated) {
            (_, false) => fixtures().join(format!("{}.bin", row.name)),
            (Some(dir), true) => dir.join(format!("{}.bin", row.name)),
            (None, true) => {
                skipped.push(row.name.as_str());
                continue;
            }
        };
        let data = std::fs::read(&path).unwrap_or_else(|e| panic!("{}: {e}", path.display()));
        assert_eq!(data.len(), row.length, "{}: length", row.name);
        assert_eq!(
            hex::encode(sha256(&data)),
            row.sha256,
            "{}: sha256",
            row.name
        );
        assert_eq!(
            hex::encode(sha256d(&data)),
            row.sha256d,
            "{}: sha256d",
            row.name
        );
        let n = check_every_chunking(&row.name, &data, &mut rng);
        println!("row {} {} bytes: {n} chunkings equal", row.name, row.length);
        hashed += 1;
    }
    println!(
        "{hashed} rows hashed whole and chunked; {} generated rows skipped {:?} (set BSV_RS_BEEF_ROWS_DIR)",
        skipped.len(),
        skipped
    );
    assert_eq!(hashed + skipped.len(), 52);
    assert!(hashed >= 47, "the 47 committed rows always run");
}

#[test]
fn generated_buffers_of_0_to_300000_bytes_hash_the_same_chunked() {
    let mut rng = StdRng::seed_from_u64(SEED ^ 1);
    // The block boundaries of SHA-256 (64-byte blocks, the 55/56 padding edge)
    // and the ends of the range, then sizes drawn across it.
    let mut sizes: Vec<usize> = vec![
        0, 1, 7, 55, 56, 57, 63, 64, 65, 119, 120, 127, 128, 129, 65_535, 65_536, 65_537, 300_000,
    ];
    sizes.extend((0..40).map(|_| rng.gen_range(0..=300_000)));
    for size in sizes {
        let mut data = vec![0u8; size];
        rng.fill_bytes(&mut data);
        check_every_chunking(&format!("buffer of {size}"), &data, &mut rng);
    }
}

#[test]
fn a_clone_finalizes_a_prefix_while_the_original_reads_on() {
    let data: Vec<u8> = (0..200_000u32).map(|i| (i * 31 % 251) as u8).collect();
    let (head, tail) = data.split_at(70_001);
    let mut single = Sha256::new();
    let mut double = Sha256d::new();
    single.update(head);
    double.update(head);
    assert_eq!(single.clone().finalize(), sha256(head));
    assert_eq!(double.clone().finalize(), sha256d(head));
    single.update(tail);
    double.update(tail);
    assert_eq!(single.finalize(), sha256(&data));
    assert_eq!(double.finalize(), sha256d(&data));
}
