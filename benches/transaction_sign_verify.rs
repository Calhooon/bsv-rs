//! Sign every P2PKH input, or verify every input, of a 100-input transaction.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)] // #134: benchmark setup
#![allow(missing_docs)] // #135: Criterion entry point

use bsv_rs::primitives::PrivateKey;
use bsv_rs::script::templates::P2PKH;
use bsv_rs::script::{LockingScript, ScriptTemplate, SignOutputs, UnlockingScript};
use bsv_rs::transaction::{
    MerklePath, MockChainTracker, Transaction, TransactionInput, TransactionOutput,
};
use criterion::{black_box, criterion_group, criterion_main, BatchSize, Criterion, Throughput};

fn prepare_to_sign(unsigned: &Transaction, key: &PrivateKey) -> Transaction {
    // Transaction's clone copies data but deliberately drops callback templates.
    // Reinstall them during setup so every timed iteration signs all inputs.
    let mut tx = unsigned.clone();
    for input in &mut tx.inputs {
        input.unlocking_script_template =
            Some(Box::new(P2PKH::unlock(key, SignOutputs::All, false)));
    }
    tx
}

fn bench(c: &mut Criterion) {
    let key = PrivateKey::random(); // ephemeral, never written to an artifact
    let lock = P2PKH::new()
        .lock(&key.public_key().hash160())
        .expect("P2PKH");
    let mut source = Transaction::new();
    let mut input = TransactionInput::new("aa".repeat(32), 0);
    input.unlocking_script = Some(UnlockingScript::new());
    source.inputs.push(input);
    source.outputs = (0..100)
        .map(|_| TransactionOutput::new(1_000, lock.clone()))
        .collect();
    let txid = source.id();
    source.merkle_path = Some(MerklePath::from_coinbase_txid(&txid, 800_000));
    let mut tracker = MockChainTracker::new(800_000);
    tracker.add_root(800_000, txid);
    let mut unsigned = Transaction::new();
    for index in 0..100 {
        unsigned
            .inputs
            .push(TransactionInput::with_source_transaction(
                source.clone(),
                index,
            ));
    }
    unsigned.outputs.push(TransactionOutput::new(
        99_000,
        LockingScript::from_binary(&[0x51]).expect("OP_TRUE"),
    ));
    let mut signed = prepare_to_sign(&unsigned, &key);
    futures::executor::block_on(signed.sign()).expect("sign fixture");
    // Observe the prepared workload outside timing, without asserting a verdict.
    println!(
        "BSV_BENCH_FIXTURE transaction_sign_verify inputs={} verify={:?}",
        signed.inputs.len(),
        futures::executor::block_on(signed.verify(&tracker, None, None))
    );
    let mut group = c.benchmark_group("transaction_sign_verify");
    group.throughput(Throughput::Elements(100));
    group.bench_function("sign_100_p2pkh", |b| {
        b.iter_batched_ref(
            || prepare_to_sign(&unsigned, &key),
            |tx| black_box(futures::executor::block_on(tx.sign())),
            BatchSize::PerIteration,
        )
    });
    group.bench_function("verify_100_p2pkh", |b| {
        b.iter(|| {
            black_box(futures::executor::block_on(
                black_box(&signed).verify(&tracker, None, None),
            ))
        })
    });
    group.finish();
}

criterion_group!(benches, bench);
criterion_main!(benches);
