//! Benchmarks for script operations, template construction, and transaction serialization.
//!
//! Run with: cargo bench --bench script_bench

use bsv_rs::primitives::ec::PrivateKey;
use bsv_rs::script::templates::{Multisig, PushDrop, P2PK, P2PKH};
use bsv_rs::script::{Script, ScriptTemplate};
use criterion::{black_box, criterion_group, criterion_main, Criterion};

// ============================================================================
// Script Parsing Benchmarks
// ============================================================================

fn bench_script_parsing(c: &mut Criterion) {
    let mut group = c.benchmark_group("Script Parsing");

    // P2PKH script hex
    let p2pkh_hex = "76a914000000000000000000000000000000000000000088ac";
    group.bench_function("Script::from_hex (P2PKH)", |b| {
        b.iter(|| Script::from_hex(black_box(p2pkh_hex)))
    });

    let script = Script::from_hex(p2pkh_hex).unwrap();
    let binary = script.to_binary();
    group.bench_function("Script::from_binary (P2PKH)", |b| {
        b.iter(|| Script::from_binary(black_box(&binary)))
    });

    let asm = script.to_asm();
    group.bench_function("Script::from_asm (P2PKH)", |b| {
        b.iter(|| Script::from_asm(black_box(&asm)))
    });

    group.finish();
}

// ============================================================================
// Script Type Detection Benchmarks
// ============================================================================

fn bench_script_detection(c: &mut Criterion) {
    let mut group = c.benchmark_group("Script Type Detection");

    let key = PrivateKey::random();
    let pubkey_hash = key.public_key().hash160();
    let p2pkh_script = P2PKH::new().lock(&pubkey_hash).unwrap();

    group.bench_function("is_p2pkh", |b| {
        b.iter(|| black_box(p2pkh_script.as_script()).is_p2pkh())
    });

    let p2pk_script = P2PK::new().lock(&key.public_key().to_compressed()).unwrap();
    group.bench_function("is_p2pk", |b| {
        b.iter(|| black_box(p2pk_script.as_script()).is_p2pk())
    });

    let keys: Vec<_> = (0..3).map(|_| PrivateKey::random().public_key()).collect();
    let multisig_script = Multisig::new(2).lock_from_keys(&keys).unwrap();
    group.bench_function("is_multisig (2-of-3)", |b| {
        b.iter(|| black_box(multisig_script.as_script()).is_multisig())
    });

    group.finish();
}

// ============================================================================
// Template Construction Benchmarks
// ============================================================================

fn bench_template_lock(c: &mut Criterion) {
    let mut group = c.benchmark_group("Template Lock");

    let key = PrivateKey::random();
    let pubkey_hash = key.public_key().hash160();
    let pubkey = key.public_key().to_compressed();

    group.bench_function("P2PKH::lock", |b| {
        b.iter(|| P2PKH::new().lock(black_box(&pubkey_hash)))
    });

    group.bench_function("P2PK::lock", |b| {
        b.iter(|| P2PK::new().lock(black_box(&pubkey)))
    });

    let keys: Vec<_> = (0..3).map(|_| PrivateKey::random().public_key()).collect();
    group.bench_function("Multisig::lock_from_keys (2-of-3)", |b| {
        b.iter(|| Multisig::new(2).lock_from_keys(black_box(&keys)))
    });

    let pubkey_obj = key.public_key();
    let fields = vec![b"BSV20".to_vec(), b"transfer".to_vec(), b"1000".to_vec()];
    group.bench_function("PushDrop::lock (3 fields)", |b| {
        b.iter(|| PushDrop::new(black_box(pubkey_obj.clone()), black_box(fields.clone())).lock())
    });

    group.finish();
}

// ============================================================================
// Template Signing Benchmarks
// ============================================================================

fn bench_template_sign(c: &mut Criterion) {
    let mut group = c.benchmark_group("Template Sign");

    let key = PrivateKey::random();
    let sighash = [0x42u8; 32];

    group.bench_function("P2PKH::sign_with_sighash", |b| {
        b.iter(|| {
            P2PKH::sign_with_sighash(
                black_box(&key),
                black_box(&sighash),
                bsv_rs::script::SignOutputs::All,
                false,
            )
        })
    });

    group.bench_function("P2PK::sign_with_sighash", |b| {
        b.iter(|| {
            P2PK::sign_with_sighash(
                black_box(&key),
                black_box(&sighash),
                bsv_rs::script::SignOutputs::All,
                false,
            )
        })
    });

    let keys: Vec<PrivateKey> = (0..2).map(|_| PrivateKey::random()).collect();
    group.bench_function("Multisig::sign_with_sighash (2 sigs)", |b| {
        b.iter(|| {
            Multisig::sign_with_sighash(
                black_box(&keys),
                black_box(&sighash),
                bsv_rs::script::SignOutputs::All,
                false,
            )
        })
    });

    group.finish();
}

// ============================================================================
// Script Serialization Benchmarks
// ============================================================================

fn bench_script_serialization(c: &mut Criterion) {
    let mut group = c.benchmark_group("Script Serialization");

    let key = PrivateKey::random();
    let pubkey_hash = key.public_key().hash160();
    let script = P2PKH::new().lock(&pubkey_hash).unwrap();

    group.bench_function("to_hex (P2PKH)", |b| b.iter(|| black_box(&script).to_hex()));

    group.bench_function("to_binary (P2PKH)", |b| {
        b.iter(|| black_box(&script).to_binary())
    });

    group.bench_function("to_asm (P2PKH)", |b| b.iter(|| black_box(&script).to_asm()));

    // Larger script: PushDrop with multiple fields
    let pubkey_obj = key.public_key();
    let fields: Vec<Vec<u8>> = (0..10)
        .map(|i| format!("field_{}", i).into_bytes())
        .collect();
    let pushdrop = PushDrop::new(pubkey_obj, fields);
    let large_script = pushdrop.lock();

    group.bench_function("to_hex (PushDrop 10 fields)", |b| {
        b.iter(|| black_box(&large_script).to_hex())
    });

    group.bench_function("to_binary (PushDrop 10 fields)", |b| {
        b.iter(|| black_box(&large_script).to_binary())
    });

    group.finish();
}

criterion_group!(
    benches,
    bench_script_parsing,
    bench_script_detection,
    bench_template_lock,
    bench_template_sign,
    bench_script_serialization,
);
criterion_main!(benches);
