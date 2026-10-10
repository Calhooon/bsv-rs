//! A clock between inputs (bsv-low #591, LOW's R400-H1 and R403-H1): the
//! reader consults the caller's budget between the inputs of an unproven
//! transaction, and its cursor can stand inside one. At 0.4.3 the budget was
//! read between elements only, so one transaction of `n` inputs was one
//! uninterruptible step.
//!
//! A paused reading's cursor is the state before the transaction (its offset
//! is the element's first byte, the format byte before the raw transaction in
//! a V2 BEEF; the index unchanged) and the input the
//! reading reached; a resume re-reads that transaction and runs the scripts
//! from that input on, the inputs already checked never run again.
#![cfg(feature = "transaction")]

use std::cell::Cell;
use std::collections::HashMap;

use bsv_rs::primitives::sha256d;
use bsv_rs::transaction::beef_stream::{AsyncByteSource, Hash32, Progress, SpendRefusal};
use bsv_rs::transaction::{
    verify_stream, AsyncStreamVerifier, Cursor, MockChainTracker, StreamVerifier, Timed, Verdict,
};

const HEIGHT: u64 = 800_000;
const OP_FALSE: u8 = 0x00;
const OP_TRUE: u8 = 0x51;
const N: usize = 64_000;

fn varint(n: u64) -> Vec<u8> {
    if n < 0xFD {
        vec![n as u8]
    } else if n < 0x1_0000 {
        let mut v = vec![0xFD];
        v.extend_from_slice(&(n as u16).to_le_bytes());
        v
    } else {
        let mut v = vec![0xFE];
        v.extend_from_slice(&(n as u32).to_le_bytes());
        v
    }
}

fn raw_tx(inputs: &[(Hash32, u32)], outputs: &[(u64, u8)]) -> Vec<u8> {
    let mut v = 1u32.to_le_bytes().to_vec();
    v.extend(varint(inputs.len() as u64));
    for (prev, vout) in inputs {
        v.extend_from_slice(prev);
        v.extend_from_slice(&vout.to_le_bytes());
        v.push(0);
        v.extend_from_slice(&0xFFFF_FFFFu32.to_le_bytes());
    }
    v.extend(varint(outputs.len() as u64));
    for (satoshis, op) in outputs {
        v.extend_from_slice(&satoshis.to_le_bytes());
        v.push(1);
        v.push(*op);
    }
    v.extend_from_slice(&0u32.to_le_bytes());
    v
}

/// LOW's shape at `N`: a proven parent with `N` outputs, `OP_TRUE` but for
/// `false_at`'s `OP_FALSE`, and a subject spending all of them with empty
/// unlocks. Returns the BEEF, the headers, the subject and the offset of its
/// raw bytes (after the format byte).
fn wide(false_at: Option<usize>) -> (Vec<u8>, HashMap<u64, Hash32>, Hash32, u64) {
    let outputs: Vec<(u64, u8)> = (0..N)
        .map(|i| {
            (
                1_000,
                if Some(i) == false_at {
                    OP_FALSE
                } else {
                    OP_TRUE
                },
            )
        })
        .collect();
    let parent = raw_tx(&[([0xAA; 32], 0)], &outputs);
    let prev = sha256d(&parent);
    let inputs: Vec<_> = (0..N as u32).map(|vout| (prev, vout)).collect();
    let subject = raw_tx(&inputs, &[(1, OP_TRUE)]);
    let root = prev;
    let mut v = 0xEFBE_0002u32.to_le_bytes().to_vec();
    v.push(1);
    v.extend(varint(HEIGHT));
    v.extend_from_slice(&[1, 1, 0, 2]);
    v.extend_from_slice(&root);
    v.push(2);
    v.extend_from_slice(&[1, 0]);
    v.extend_from_slice(&parent);
    v.push(0);
    let at = v.len() as u64;
    v.extend_from_slice(&subject);
    (v, HashMap::from([(HEIGHT, root)]), sha256d(&subject), at)
}

/// Reads `bytes` to a verdict in slices of `every` inputs, each pause's
/// cursor stored as bytes and resumed by a fresh reader over the rest of the
/// stream. Returns the verdict and the inputs each pause reached.
fn sliced(
    bytes: &[u8],
    headers: &HashMap<u64, Hash32>,
    subject: Hash32,
    every: u64,
) -> (Verdict, Vec<(u64, Option<u32>)>) {
    let mut pauses = Vec::new();
    let mut from: Option<Cursor> = None;
    loop {
        let mut reader = match from.take() {
            None => StreamVerifier::new(bytes, headers, Some(subject)),
            Some(cursor) => {
                let rest = &bytes[cursor.offset() as usize..];
                StreamVerifier::resume(cursor, rest, headers)
            }
        };
        let asked = Cell::new(0u64);
        let mut spent = || {
            asked.set(asked.get() + 1);
            asked.get() >= every
        };
        loop {
            match reader.step_until(&mut spent).unwrap() {
                Timed::Progress(Progress::Stepped) => {}
                Timed::Progress(Progress::Verdict(verdict)) => return (verdict, pauses),
                Timed::Paused => {
                    let cursor = reader.cursor();
                    let stored = cursor.to_binary();
                    let restored = Cursor::from_binary(&stored).expect("the cursor reads back");
                    assert_eq!(restored, cursor);
                    assert_eq!(restored.to_binary(), stored);
                    pauses.push((restored.offset(), restored.input_reached()));
                    from = Some(restored);
                    break;
                }
            }
        }
    }
}

#[test]
fn a_reading_with_a_slice_pauses_inside_the_subject_and_resumes_to_the_same_verdict() {
    let (bytes, headers, subject, at) = wide(None);
    let whole = verify_stream(&bytes[..], &headers, Some(subject)).unwrap();
    assert!(whole.is_valid(), "{whole:?}");

    let (verdict, pauses) = sliced(&bytes, &headers, subject, 10_000);
    assert_eq!(verdict, whole);
    // Ten thousand inputs a slice: six pauses inside the subject, each at its
    // element, each further on than the last, none at the start.
    let reached: Vec<u32> = pauses
        .iter()
        .map(|(offset, input)| {
            assert_eq!(*offset, at - 1, "a pause stands at the subject's element");
            input.expect("the cursor names the input reached")
        })
        .collect();
    // Each slice runs ten thousand inputs past the input it resumed at: had
    // a resume run the subject's scripts from its first input again, every
    // pause would be at 10,000.
    assert_eq!(reached, [10_000, 20_000, 30_000, 40_000, 50_000, 60_000]);
}

#[test]
fn a_spend_refused_after_a_pause_is_the_whole_reading_refusal() {
    let (bytes, headers, subject, _) = wide(Some(60_000));
    let whole = verify_stream(&bytes[..], &headers, Some(subject)).unwrap();
    assert!(
        matches!(
            &whole,
            Verdict::SpendRefused { txid, input: Some(60_000), why: SpendRefusal::Script(_), .. }
                if *txid == subject
        ),
        "{whole:?}"
    );
    let (verdict, pauses) = sliced(&bytes, &headers, subject, 10_000);
    assert_eq!(verdict, whole);
    assert!(pauses.len() >= 5, "{pauses:?}");
}

#[test]
fn a_paused_reader_continues_in_place() {
    let (bytes, headers, subject, at) = wide(None);
    let mut reader = StreamVerifier::new(&bytes[..], &headers, Some(subject));
    let asked = Cell::new(0u64);
    let mut spent = || {
        asked.set(asked.get() + 1);
        asked.get().is_multiple_of(25_000)
    };
    let mut paused = 0;
    let verdict = loop {
        match reader.step_until(&mut spent).unwrap() {
            Timed::Progress(Progress::Stepped) => {}
            Timed::Progress(Progress::Verdict(verdict)) => break verdict,
            Timed::Paused => {
                paused += 1;
                assert_eq!(reader.cursor().offset(), at - 1);
                assert!(reader.cursor().input_reached().is_some());
            }
        }
    };
    assert_eq!(paused, 2);
    assert!(verdict.is_valid(), "{verdict:?}");
}

#[test]
fn a_reading_with_no_slice_never_pauses() {
    let (bytes, headers, subject, _) = wide(None);
    let mut reader = StreamVerifier::new(&bytes[..], &headers, Some(subject));
    let mut steps = 0;
    let verdict = loop {
        match reader.step().unwrap() {
            Progress::Stepped => {
                steps += 1;
                assert_eq!(reader.cursor().input_reached(), None);
            }
            Progress::Verdict(verdict) => break verdict,
        }
    };
    assert_eq!(steps, 3, "one BUMP, the parent, the subject");
    assert!(verdict.is_valid());
    // And a slice that is never spent is the same reading.
    let (verdict, pauses) = sliced(&bytes, &headers, subject, u64::MAX);
    assert!(verdict.is_valid());
    assert!(pauses.is_empty());
}

struct Chunks {
    bytes: Vec<u8>,
    at: usize,
}

impl AsyncByteSource for Chunks {
    async fn next_chunk(&mut self) -> std::io::Result<Option<Vec<u8>>> {
        if self.at == self.bytes.len() {
            return Ok(None);
        }
        let end = (self.at + 4_096).min(self.bytes.len());
        let chunk = self.bytes[self.at..end].to_vec();
        self.at = end;
        Ok(Some(chunk))
    }
}

/// A cursor paused by the reader over `Read` resumes in the asynchronous
/// reader to the verdict of the whole: valid, and the refusal of input
/// 60,000 after a pause at 30,000.
#[tokio::test]
async fn a_paused_cursor_resumes_in_the_asynchronous_reader() {
    for false_at in [None, Some(60_000)] {
        let (bytes, headers, subject, _) = wide(false_at);
        let whole = verify_stream(&bytes[..], &headers, Some(subject)).unwrap();
        let mut reader = StreamVerifier::new(&bytes[..], &headers, Some(subject));
        let asked = Cell::new(0u64);
        let mut spent = || {
            asked.set(asked.get() + 1);
            asked.get() >= 30_000
        };
        let cursor = loop {
            match reader.step_until(&mut spent).unwrap() {
                Timed::Progress(Progress::Stepped) => {}
                Timed::Progress(Progress::Verdict(v)) => panic!("no pause: {v:?}"),
                Timed::Paused => break reader.cursor(),
            }
        };
        assert_eq!(cursor.input_reached(), Some(30_000));
        let mut rest = Chunks {
            bytes: bytes[cursor.offset() as usize..].to_vec(),
            at: 0,
        };
        let tracker = MockChainTracker::new(900_000);
        let got = AsyncStreamVerifier::resume(cursor)
            .run(&mut rest, &tracker)
            .await
            .unwrap();
        assert_eq!(got, whole, "false at {false_at:?}");
    }
}
