//! Field codecs for all 28 request/result shapes, without a wallet or transport.
//!
//! The bytes are #76's recordings (`tests/fixtures/wire/<method>.json`, the
//! `full` case): the request frame the transceiver wrote and the result frame
//! the wallet side wrote. Each frame is walked through its layout
//! (`wire_codec/support.rs`) with the public WireReader/WireWriter helpers: the
//! decode op reads the recorded bytes, the encode op writes the values read
//! back to the same bytes. `tests/wire_codec_bench_bytes.rs` pins every layout
//! to the recordings (#138). Not async dispatch, not cryptography.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)] // #134: benchmark fixtures
#![allow(missing_docs)] // #135: Criterion entry point

#[path = "wire_codec/support.rs"]
mod support;

use criterion::{black_box, criterion_group, criterion_main, Criterion, Throughput};
use support::{calls, decode, encode, frames, request_layout, result_layout, CASE};

fn bench(c: &mut Criterion) {
    for call in calls() {
        let recorded = frames(call, CASE);
        let mut group = c.benchmark_group(format!("wire_codec/{}", call.method_name()));
        for (name, layout, bytes) in [
            ("request", request_layout(call), recorded.request),
            ("result", result_layout(call), recorded.result),
        ] {
            let values = decode(&layout, &bytes).expect("the layout reads the recorded frame");
            assert_eq!(encode(&values), bytes, "{call} {name}: the recorded bytes");
            group.throughput(Throughput::Bytes(bytes.len() as u64));
            group.bench_function(format!("{name}_encode"), |b| {
                b.iter(|| black_box(encode(black_box(&values))))
            });
            group.bench_function(format!("{name}_decode"), |b| {
                b.iter(|| decode(black_box(&layout), black_box(&bytes)))
            });
        }
        group.finish();
    }
}

criterion_group!(benches, bench);
criterion_main!(benches);
