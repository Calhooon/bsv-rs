//! The wire_codec bench's bytes are #76's recordings (#138).
//!
//! The bench decodes each call's recorded request and result frames through its
//! layout and encodes the values back. Here, for all 28 calls and both recorded
//! cases, each layout consumes its frame exactly and the encode op returns the
//! recording byte for byte; `fixtures_replay` pins those recordings to the
//! transceiver's writer and the wallet side's writers.
#![cfg(feature = "wallet")]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

#[path = "../benches/wire_codec/support.rs"]
mod support;

use support::{calls, decode, encode, frames, request_layout, result_layout, CASE, CASES};

#[test]
fn the_bench_frames_are_the_recordings_byte_for_byte() {
    let mut drift = Vec::new();
    for call in calls() {
        for case in CASES {
            let recorded = frames(call, case);
            for (side, layout, bytes) in [
                ("request", request_layout(call), &recorded.request),
                ("result", result_layout(call), &recorded.result),
            ] {
                match decode(&layout, bytes) {
                    Err(e) => drift.push(format!("{call} {case} {side}: {e}")),
                    Ok(values) => {
                        let written = encode(&values);
                        if &written != bytes {
                            let at = written
                                .iter()
                                .zip(bytes.iter())
                                .position(|(a, b)| a != b)
                                .unwrap_or(written.len().min(bytes.len()));
                            drift.push(format!(
                                "{call} {case} {side}: re-encoded {} bytes, recorded {}, first difference at {at}",
                                written.len(),
                                bytes.len()
                            ));
                        }
                    }
                }
            }
        }
    }
    assert!(
        drift.is_empty(),
        "{} frames drift:\n{}",
        drift.len(),
        drift.join("\n")
    );
}

#[test]
fn the_bench_measures_all_28_calls_on_the_full_recording() {
    assert_eq!(CASE, "full");
    let calls = calls();
    assert_eq!(calls.len(), 28);
    for call in calls {
        let recorded = frames(call, CASE);
        assert_eq!(recorded.request.first(), Some(&call.as_u8()), "{call}");
        assert_eq!(recorded.result.first(), Some(&0), "{call}: a success frame");
    }
}
