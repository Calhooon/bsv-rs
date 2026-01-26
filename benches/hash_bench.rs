//! Benchmarks for hash functions.

use bsv_sdk::primitives::hash;
use criterion::{black_box, criterion_group, criterion_main, Criterion};

fn bench_sha256(c: &mut Criterion) {
    let data = b"hello world this is a benchmark test";
    c.bench_function("sha256", |b| b.iter(|| hash::sha256(black_box(data))));
}

fn bench_sha512(c: &mut Criterion) {
    let data = b"hello world this is a benchmark test";
    c.bench_function("sha512", |b| b.iter(|| hash::sha512(black_box(data))));
}

fn bench_sha256d(c: &mut Criterion) {
    let data = b"hello world this is a benchmark test";
    c.bench_function("sha256d", |b| b.iter(|| hash::sha256d(black_box(data))));
}

fn bench_hash160(c: &mut Criterion) {
    let data = b"hello world this is a benchmark test";
    c.bench_function("hash160", |b| b.iter(|| hash::hash160(black_box(data))));
}

fn bench_sha256_hmac(c: &mut Criterion) {
    let key = b"secret key for hmac";
    let data = b"hello world this is a benchmark test";
    c.bench_function("sha256_hmac", |b| {
        b.iter(|| hash::sha256_hmac(black_box(key), black_box(data)))
    });
}

criterion_group!(
    benches,
    bench_sha256,
    bench_sha512,
    bench_sha256d,
    bench_hash160,
    bench_sha256_hmac,
);
criterion_main!(benches);
