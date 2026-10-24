//! Ten thousand distinct depth-20 paths into one synthetic block.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)] // #134: benchmark setup
#![allow(missing_docs)] // #135: Criterion entry point

use bsv_rs::primitives::sha256d;
use bsv_rs::transaction::{ChainTracker, MerklePath, MerklePathLeaf, MockChainTracker};
use criterion::{black_box, criterion_group, criterion_main, Criterion, Throughput};

fn display(mut hash: [u8; 32]) -> String {
    hash.reverse();
    hex::encode(hash)
}

fn bench(c: &mut Criterion) {
    let mut levels: Vec<Vec<[u8; 32]>> = vec![(0..1_u32 << 20)
        .map(|i| sha256d(&i.to_le_bytes()))
        .collect()];
    for depth in 0..20 {
        let parents = levels[depth]
            .as_chunks::<2>()
            .0
            .iter()
            .map(|pair| {
                let mut data = [0; 64];
                data[..32].copy_from_slice(&pair[0]);
                data[32..].copy_from_slice(&pair[1]);
                sha256d(&data)
            })
            .collect();
        levels.push(parents);
    }
    let mut tracker = MockChainTracker::new(800_000);
    tracker.add_root(800_000, display(levels[20][0]));
    let paths: Vec<_> = (0..10_000)
        .map(|i| {
            let offset = i * 97; // distinct leaves, spread across the block
            let txid = display(levels[0][offset]);
            let mut path = vec![vec![
                MerklePathLeaf::new_txid(offset as u64, txid.clone()),
                MerklePathLeaf::new((offset ^ 1) as u64, display(levels[0][offset ^ 1])),
            ]];
            for (depth, level) in levels.iter().enumerate().take(20).skip(1) {
                let sibling = (offset >> depth) ^ 1;
                path.push(vec![MerklePathLeaf::new(
                    sibling as u64,
                    display(level[sibling]),
                )]);
            }
            (
                txid,
                MerklePath {
                    block_height: 800_000,
                    path,
                },
            )
        })
        .collect();
    drop(levels);
    let matches = futures::executor::block_on(async {
        let mut matches = 0;
        for (txid, path) in &paths {
            let root = path.compute_root(Some(txid)).expect("path root");
            matches +=
                usize::from(tracker.is_valid_root_for_height(&root, 800_000).await == Ok(true));
        }
        matches
    });
    // This observation is not a conformance assertion or part of the timing.
    println!("BSV_BENCH_FIXTURE merkle_path root_matches={matches}/10000 depth=20");
    let mut group = c.benchmark_group("merkle_path");
    group.throughput(Throughput::Elements(10_000));
    group.bench_function("verify_depth20_10000", |b| {
        b.iter(|| {
            futures::executor::block_on(async {
                for (txid, path) in &paths {
                    let root = path.compute_root(Some(black_box(txid))).expect("path root");
                    let _ = black_box(tracker.is_valid_root_for_height(&root, 800_000).await);
                }
            });
        })
    });
    group.finish();
}

criterion_group!(benches, bench);
criterion_main!(benches);
