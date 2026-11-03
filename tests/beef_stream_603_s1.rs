//! #603, `src/transaction/beef_stream.rs` shard S1: the stream's cursor and
//! element reading, each surviving mutant of the widened oracle (run
//! 41327640129) killed by a row of the sibling's corpus read as its rule reads
//! it, or by a cursor of such a reading resumed to the same verdict.
//!
//! The rows are bsv-script-lean@387dab35's `corpus/wire` (`beef.jsonl`,
//! `atomic-beef.jsonl`, `bump.jsonl`), copied by id with the reference's
//! reading of each into `tests/vectors/beef_reference_603.json` by
//! `tests/support/beef_reference_603.mjs` (ts-stack@edf6e03 `Beef.ts`, Node
//! v22.18.0): the reader's position after the header and after each element
//! (`Beef.fromReader`, `Beef.ts:1240-1284`), the version, the atomic subject,
//! the element kinds and `verifyValid`. The sibling's rules are its wire views
//! at the same pin: `lean/BsvChain/Views/Wire/BEEF.lean:121-128`
//! (`Beef.decodePrefix`: the version, the BUMPs, the entries),
//! `AtomicBEEF.lean:36-41` (the prefix and the subject before the BEEF),
//! and `BUMP.lean:108-115` (a BUMP's levels). A fixture the reference has no row for is
//! built by this crate's writer (`Beef::to_writer`, `Transaction::to_binary`)
//! from the rows' shapes.
//!
//! The mutants' lines the doc comments name are the base's (`6fe627df`). The
//! second fold's two rustdoc lines (`Cursor::to_binary`'s and
//! `Cursor::from_binary`'s) put every site from line 2587 on two lines
//! later: the BSC2 guard at `2771:22` (`2769:22` is then the BSC4 guard's),
//! the flags check at 2830, the raw bit at 2863, the edge check at 2888, the
//! pause at 2935 and 2943, the verifier at 3177 and 3216.
#![cfg(feature = "transaction")]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)] // #134: test code: a failed unwrap is the test failing

use std::collections::HashMap;
use std::io::Read;
use std::sync::mpsc;
use std::time::Duration;

use bsv_rs::primitives::{from_hex, sha256d, to_hex, Writer};
use bsv_rs::script::{LockingScript, UnlockingScript};
use bsv_rs::transaction::beef_stream::{AsyncByteSource, Hash32, StreamError};
use bsv_rs::transaction::{
    verify_stream, AsyncStreamVerifier, Beef, BeefDecoder, BeefStream, BeefTx, Cursor, Element,
    Kind, MerklePath, MockChainTracker, Progress, Reason, StreamVerifier, Timed, Transaction,
    TransactionInput, TransactionOutput, Verdict, BEEF_V1, BEEF_V2,
};
use serde_json::Value;

#[path = "support/beef_chain.rs"]
mod beef_chain;

fn vector() -> Value {
    serde_json::from_str(include_str!("vectors/beef_reference_603.json")).unwrap()
}

/// A row's bytes, copied by id from the sibling's corpus.
fn row(id: &str) -> Vec<u8> {
    from_hex(vector()["rows"][id]["hex"].as_str().unwrap()).unwrap()
}

/// The reference's reading of a row (`cases.stream`).
fn reading(id: &str) -> Value {
    vector()["cases"]["stream"][id].clone()
}

/// A display txid in wire order.
fn wire(display: &str) -> Hash32 {
    let mut hash: Hash32 = from_hex(display).unwrap().try_into().unwrap();
    hash.reverse();
    hash
}

/// The display txid of a wire-order hash.
fn display(hash: &Hash32) -> String {
    let mut bytes = *hash;
    bytes.reverse();
    to_hex(&bytes)
}

/// Block 9's coinbase (`0437cd7f…`), the parent of beef-023 to beef-026 and
/// atomic-beef-023, the one transaction of its block: its txid is the root.
const BLOCK_9_COINBASE: &str = "0437cd7f8525ceed2324359c2d0ba26006d92d856a9c20fa0241106ee5a597c9";
/// The child (`f4184fc5…`, block 170) spending it.
const BLOCK_170_SPEND: &str = "f4184fc596403b9d638783cf57adfe4c75c605f6356fbc91338530e9831e9e16";

/// The headers of the rows: block 9's root, and a tip at block 169, where the
/// child was mined next, so the coinbase it spends is mature.
fn headers() -> MockChainTracker {
    let mut tracker = MockChainTracker::new(169);
    tracker.add_root(9, BLOCK_9_COINBASE.to_string());
    tracker
}

/// The rows the reference reads whole and `verifyValid` judges.
const READ_ROWS: [&str; 5] = [
    "beef-023",
    "beef-024",
    "beef-025",
    "beef-026",
    "atomic-beef-023",
];

// ---------------------------------------------------------------------------
// The element reading (BeefStream's and BeefDecoder's accessors)
// ---------------------------------------------------------------------------

/// The kind the reference names an element by.
fn kind_of(element: &Element) -> &'static str {
    match element {
        Element::Bump(_) => "bump",
        Element::Tx { .. } => "tx",
        Element::TxidOnly { .. } => "txid",
    }
}

/// Each row read element by element: after each, the stream stands where the
/// reference's reader stands, has read as many elements, and holds the
/// version word and the atomic subject the reference read from the header
/// (`BEEF.lean:121-128`, `AtomicBEEF.lean:36-41`). Kills `offset`,
/// `elements_read` (the stream's and the decoder's), `version` and `subject`
/// replaced by constants (1413, 1418, 809, 1423, 1428).
#[test]
fn the_stream_stands_where_the_reference_reader_stands_wire_beef_023_024_025_026_atomic_beef_023() {
    for id in [
        "beef-001",
        "beef-023",
        "beef-024",
        "beef-025",
        "beef-026",
        "atomic-beef-023",
    ] {
        let theirs = reading(id);
        assert!(theirs["error"].is_null(), "{id}: {theirs}");
        let ends: Vec<u64> = theirs["ends"]
            .as_array()
            .unwrap()
            .iter()
            .map(|v| v.as_u64().unwrap())
            .collect();
        let version = theirs["version"].as_u64().unwrap() as u32;
        let subject = theirs["atomic_txid"].as_str().map(wire);
        let bytes = row(id);
        let mut stream = BeefStream::new(&bytes[..]);
        assert_eq!(stream.version(), None, "{id}: no header read yet");
        assert_eq!(stream.elements_read(), 0, "{id}");
        assert_eq!(stream.offset(), 0, "{id}");
        for (i, end) in ends.iter().enumerate() {
            let element = stream.next_element().unwrap().expect("an element");
            assert_eq!(kind_of(&element), theirs["kinds"][i], "{id}: element {i}");
            assert_eq!(stream.offset(), *end, "{id}: after element {i}");
            assert_eq!(stream.elements_read(), i as u64 + 1, "{id}: element {i}");
            assert_eq!(stream.version(), Some(version), "{id}: element {i}");
            assert_eq!(stream.subject(), subject, "{id}: element {i}");
        }
        assert!(stream.next_element().unwrap().is_none(), "{id}");
        assert_eq!(stream.offset(), bytes.len() as u64, "{id}");
        assert_eq!(stream.elements_read(), ends.len() as u64, "{id}");
    }
}

/// beef-023 through the decoder alone: a caller that stops at the last
/// element and ends the stream has a complete frame (the reference reads
/// two transactions and nothing is left, `left: 0`); beef-031, the same row
/// less its last byte, ends at the last entry's BUMP flag, one byte at the
/// field's offset (`BEEF.lean:89-98`: a version-1 entry is the transaction,
/// then `00` or `01` and the index; the reference's reader `Reader read
/// exceeds available data` after two elements). Kills `finish`'s `==`
/// replaced by `!=` (899).
#[test]
fn a_frame_ends_at_its_last_element_and_a_cut_one_at_its_field_wire_beef_023_031() {
    let whole = row("beef-023");
    assert_eq!(reading("beef-023")["left"], 0);
    let mut decoder = BeefDecoder::new();
    let mut input = &whole[..];
    let mut elements = 0;
    while elements < 3 {
        match decoder.next(&mut input).unwrap() {
            bsv_rs::transaction::beef_stream::Step::Element(_) => elements += 1,
            other => panic!("{other:?} before the third element"),
        }
    }
    assert!(input.is_empty());
    assert_eq!(decoder.finish(), Ok(()));

    let cut = row("beef-031");
    let theirs = reading("beef-031");
    assert_eq!(theirs["ends"].as_array().unwrap().len(), 2);
    assert!(theirs["error"].as_str().unwrap().contains("exceeds"));
    let mut decoder = BeefDecoder::new();
    let mut input = &cut[..];
    let mut elements = 0;
    loop {
        match decoder.next(&mut input).unwrap() {
            bsv_rs::transaction::beef_stream::Step::Element(_) => elements += 1,
            bsv_rs::transaction::beef_stream::Step::NeedMore => break,
            other => panic!("{other:?}"),
        }
    }
    assert_eq!(elements, 2);
    let refused = decoder.finish().unwrap_err();
    // The BUMP flag is the whole row's last byte.
    assert_eq!(cut.len(), whole.len() - 1);
    assert_eq!(refused.offset, cut.len() as u64);
    assert_eq!(refused.reason, Reason::Truncated { needed: 1 });
}

/// A source's `Interrupted` is retried (`std::io::Read::read`: "the read
/// operation should be retried"), any other failure ends the stream: beef-023
/// read through a source that is interrupted once is read whole; through one
/// that fails once it is the source's error. Kills `next_element`'s guard
/// replaced by `true` or `false` and its `==` by `!=` (1450).
#[test]
fn an_interrupted_read_is_retried_and_a_failed_one_ends_the_stream_wire_beef_023() {
    struct Once {
        bytes: Vec<u8>,
        at: usize,
        fail: Option<std::io::ErrorKind>,
    }
    impl Read for Once {
        fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
            if let Some(kind) = self.fail.take() {
                return Err(std::io::Error::new(kind, "once"));
            }
            let n = buf.len().min(self.bytes.len() - self.at);
            buf[..n].copy_from_slice(&self.bytes[self.at..self.at + n]);
            self.at += n;
            Ok(n)
        }
    }
    let bytes = row("beef-023");
    let elements = reading("beef-023")["ends"].as_array().unwrap().len();
    let source = |fail| Once {
        bytes: bytes.clone(),
        at: 0,
        fail: Some(fail),
    };
    let read: Vec<Element> = BeefStream::new(source(std::io::ErrorKind::Interrupted))
        .collect::<Result<_, _>>()
        .expect("an interrupted read is retried");
    assert_eq!(read.len(), elements);
    let mut failed = BeefStream::new(source(std::io::ErrorKind::Other));
    match failed.next_element() {
        Err(StreamError::Io(e)) => assert_eq!(e.kind(), std::io::ErrorKind::Other),
        other => panic!("{other:?}"),
    }
}

/// beef-001 read under a bound of its own: every script field of its one
/// transaction passes and the reading ends (`BEEF.lean:89-98`, an entry is a
/// transaction then its BUMP flag). A reading that never leaves a script is
/// the timed-out mutant (`on_run_done` replaced by `()`, 1263: under it the
/// sibling's wire run stops at beef-001, its first row with a script).
#[test]
fn a_reading_passes_every_script_and_ends_within_its_bound_wire_beef_001() {
    let bytes = row("beef-001");
    let expected = reading("beef-001")["ends"].as_array().unwrap().len();
    let (done, read) = mpsc::channel();
    std::thread::spawn(move || {
        let elements = BeefStream::new(&bytes[..]).count();
        let _ = done.send(elements);
    });
    let elements = read
        .recv_timeout(Duration::from_secs(60))
        .expect("the reading ends within its bound");
    assert_eq!(elements, expected);
}

// ---------------------------------------------------------------------------
// A BUMP's offsets
// ---------------------------------------------------------------------------

/// bump-003 (tree height 2) with its first level-1 leaf moved to offset 2,
/// the level's width (`2^(2-1)`, BRC-74 `0074.md:59-79`; the recorder's
/// `bump_offset_outside_its_level`): refused at the leaf, as the reference
/// refuses it (`Invalid offset: 2, at height: 1, …`). A level-0 leaf would
/// not tell the width's subtraction from an addition. Kills `on_varint`'s
/// `-` replaced by `+` (1196).
#[test]
fn a_level_1_leaf_past_its_level_is_refused_wire_bump_003() {
    let case = &vector()["cases"]["bump_offset_outside_its_level"];
    assert!(case["refused"]
        .as_str()
        .unwrap()
        .starts_with("Invalid offset: 2"));
    let bytes = from_hex(case["hex"].as_str().unwrap()).unwrap();
    let refused = MerklePath::from_binary(&bytes).unwrap_err().to_string();
    let expected = format!(
        "invalid BUMP at byte {}: {:?}",
        case["leaf_at"],
        Reason::OffsetOutsideTree {
            level: 1,
            offset: 2
        }
    );
    assert!(refused.ends_with(&expected), "{refused}");
    // The same BUMP inside a BEEF (BEEF.lean:121-128: the version, one BUMP,
    // no transaction), refused at the same byte past the five of the frame.
    let mut beef = BEEF_V1.to_le_bytes().to_vec();
    beef.push(1);
    beef.extend_from_slice(&bytes);
    beef.push(0);
    let mut stream = BeefStream::new(&beef[..]);
    match stream.next_element() {
        Err(StreamError::Refused(r)) => {
            assert_eq!(
                r.reason,
                Reason::OffsetOutsideTree {
                    level: 1,
                    offset: 2
                }
            );
            assert_eq!(r.offset, case["leaf_at"].as_u64().unwrap() + 5);
        }
        other => panic!("{other:?}"),
    }
}

// ---------------------------------------------------------------------------
// The verifier's steps and the named subject
// ---------------------------------------------------------------------------

/// Each row's verdict, `Valid` where the reference's `verifyValid` is true.
fn whole(id: &str) -> Verdict {
    let verdict = verify_stream(&row(id)[..], headers(), None).unwrap();
    assert_eq!(
        verdict.is_valid(),
        reading(id)["verify_valid"].as_bool().unwrap(),
        "{id}: {verdict:?}"
    );
    verdict
}

/// Each row's verdict reached in no more steps than twice its elements and
/// the end: a step reads an element, releases one held for its parent (one
/// per step, beef-026's child) or ends the reading. Kills `step_until`'s
/// `&&` replaced by `||` (3214, timed out in the oracle: under it a step
/// with nothing held releases nothing, forever).
#[test]
fn a_verdict_is_reached_within_one_step_an_element_wire_rows() {
    // Stepped first, under the bound: an unbounded reading (`run`) of the
    // same row is taken only after the bounded one has reached a verdict.
    for id in READ_ROWS {
        let bytes = row(id);
        let elements = reading(id)["ends"].as_array().unwrap().len();
        let tracker = headers();
        let mut reader = StreamVerifier::new(&bytes[..], &tracker, None);
        let mut verdict = None;
        for _ in 0..=2 * elements {
            if let Progress::Verdict(v) = reader.step().unwrap() {
                verdict = Some(v);
                break;
            }
        }
        let verdict = verdict.unwrap_or_else(|| panic!("{id}: no verdict within the bound"));
        assert_eq!(verdict, whole(id), "{id}");
    }
}

/// An asynchronous source handing out `size` bytes at a time.
struct Chunks {
    bytes: Vec<u8>,
    at: usize,
    size: usize,
}

impl AsyncByteSource for Chunks {
    async fn next_chunk(&mut self) -> std::io::Result<Option<Vec<u8>>> {
        if self.at == self.bytes.len() {
            return Ok(None);
        }
        let end = (self.at + self.size).min(self.bytes.len());
        let chunk = self.bytes[self.at..end].to_vec();
        self.at = end;
        Ok(Some(chunk))
    }
}

/// atomic-beef-023's prefix names the child (`f4184fc5…`,
/// `AtomicBEEF.lean:36-41`); a caller naming the parent is refused at the
/// prefix's 32 bytes, however the source's chunks cut the header. In chunks
/// of two bytes the first chunks end before the header is read. Kills
/// `header_read` replaced by `true` (824).
#[test]
fn a_named_subject_the_prefix_does_not_name_is_refused_at_the_prefix_wire_atomic_beef_023() {
    let bytes = row("atomic-beef-023");
    assert_eq!(
        reading("atomic-beef-023")["atomic_txid"],
        BLOCK_170_SPEND,
        "the prefix names the child"
    );
    let named = wire(BLOCK_9_COINBASE);
    let tracker = headers();
    let expected = Verdict::Invalid {
        offset: 4,
        kind: Kind::SubjectMissing,
        reason: Reason::SubjectMissing { subject: named },
    };
    assert_eq!(
        verify_stream(&bytes[..], &tracker, Some(named)).unwrap(),
        expected
    );
    for size in [2, 7, bytes.len()] {
        let mut source = Chunks {
            bytes: bytes.clone(),
            at: 0,
            size,
        };
        let verdict = futures::executor::block_on(
            AsyncStreamVerifier::new(Some(named)).run(&mut source, &tracker),
        )
        .unwrap();
        assert_eq!(verdict, expected, "chunks of {size}");
    }
}

// ---------------------------------------------------------------------------
// The cursor between elements
// ---------------------------------------------------------------------------

/// Reads `bytes` `k` steps, takes the cursor, writes it, reads it back and
/// resumes it over the rest of the bytes: the verdict.
fn resumed_after(bytes: &[u8], k: usize, budget: Option<u64>) -> (Vec<u8>, Option<Verdict>) {
    let tracker = headers();
    let mut reader = StreamVerifier::new(bytes, &tracker, None).with_work_budget(budget);
    for _ in 0..k {
        if let Progress::Verdict(_) = reader.step().unwrap() {
            return (Vec::new(), None);
        }
    }
    let cursor = reader.cursor();
    assert_eq!(cursor.input_reached(), None, "between two elements");
    let stored = cursor.to_binary();
    let restored = Cursor::from_binary(&stored).expect("the cursor reads back");
    let rest = &bytes[restored.offset() as usize..];
    let verdict = StreamVerifier::resume(restored, rest, &tracker)
        .with_work_budget(budget)
        .run()
        .unwrap();
    (stored, Some(verdict))
}

/// Every cursor between two elements of each row, written and read back,
/// resumes to the row's one-pass verdict, the reference's `verifyValid`
/// (`BEEF.lean:121-128`: the reading is the frame's, wherever it is cut).
/// With a work budget a cursor after an unproven transaction is BSC5 (its
/// charged work), and beef-026's child, written before its parent, is held
/// (BSC4). Kills `to_binary`'s `!` deleted (2728), `from_binary`'s BSC5 and
/// BSC4 guards replaced by `false` (2766, 2767) and the BSC5 held byte's `0`
/// arm deleted (2910).
#[test]
fn every_cursor_between_elements_resumes_to_the_one_pass_verdict_wire_rows() {
    let mut magics = std::collections::BTreeSet::new();
    for id in READ_ROWS {
        let bytes = row(id);
        let expected = whole(id);
        let elements = reading(id)["ends"].as_array().unwrap().len();
        for budget in [None, Some(1_000_000_000)] {
            for k in 0..=elements {
                let (stored, verdict) = resumed_after(&bytes, k, budget);
                let Some(verdict) = verdict else { continue };
                magics.insert(String::from_utf8(stored[..4].to_vec()).unwrap());
                assert_eq!(verdict, expected, "{id}: k = {k}, budget {budget:?}");
            }
        }
    }
    let magics: Vec<&str> = magics.iter().map(String::as_str).collect();
    assert_eq!(magics, ["BSC3", "BSC4", "BSC5"]);
}

/// The proven funding transaction of the crate's chain witness with `n`
/// `OP_TRUE` outputs, its one-leaf BUMP, and the headers carrying it.
fn funding(n: usize) -> (Vec<u8>, MerklePath, HashMap<u64, Hash32>) {
    let funding = beef_chain::spend(&[0xAA; 32], n);
    let root = sha256d(&funding);
    let bump = MerklePath::from_coinbase_txid(&display(&root), beef_chain::HEIGHT as u32);
    (funding, bump, HashMap::from([(beef_chain::HEIGHT, root)]))
}

/// `raws` under `bump`, the first proven by it, in the order given, by this
/// crate's writer without its sort (`to_writer`).
fn written(bump: MerklePath, raws: &[Vec<u8>]) -> Vec<u8> {
    let mut beef = Beef::with_version(BEEF_V1);
    beef.bumps.push(bump);
    for (i, raw) in raws.iter().enumerate() {
        beef.txs
            .push(BeefTx::from_raw_tx(raw.clone(), (i == 0).then_some(0)));
    }
    let mut writer = Writer::new();
    beef.to_writer(&mut writer);
    writer.into_bytes()
}

/// beef-026's shape (a child written before its parent) after an unproven
/// spend: the funding, `a` spending it, then `c` spending `b`, then `b`
/// spending `a`. After `a` the reading's work is charged and after `c` the
/// child is held: the cursor is BSC5 with a held transaction, and resumes to
/// the one-pass verdict, valid as the reference reads beef-026. Kills the
/// BSC5 held byte's `1` arm deleted (2911).
#[test]
fn a_charged_cursor_holding_a_child_resumes_to_the_one_pass_verdict_wire_beef_026_shape() {
    assert_eq!(reading("beef-026")["verify_valid"], true);
    let (funding, bump, roots) = funding(2);
    let a = beef_chain::spend(&sha256d(&funding), 1);
    let b = beef_chain::spend(&sha256d(&a), 1);
    let c = beef_chain::spend(&sha256d(&b), 1);
    let bytes = written(bump, &[funding, a, c, b]);
    let budget = Some(1_000_000_000);
    let one_pass = StreamVerifier::new(&bytes[..], &roots, None)
        .with_work_budget(budget)
        .run()
        .unwrap();
    assert!(one_pass.is_valid(), "{one_pass:?}");
    let mut reader = StreamVerifier::new(&bytes[..], &roots, None).with_work_budget(budget);
    // The BUMP, the funding, `a`, `c`.
    for _ in 0..4 {
        assert!(matches!(reader.step().unwrap(), Progress::Stepped));
    }
    let stored = reader.cursor().to_binary();
    assert_eq!(&stored[..4], b"BSC5");
    let restored = Cursor::from_binary(&stored).expect("the cursor reads back");
    let rest = &bytes[restored.offset() as usize..];
    let verdict = StreamVerifier::resume(restored, rest, &roots)
        .with_work_budget(budget)
        .run()
        .unwrap();
    assert_eq!(verdict, one_pass);
}

/// The cursor of beef-023 after the BUMP and the parent (BSC3).
fn cursor_after_the_parent() -> (Vec<u8>, Vec<u8>) {
    let bytes = row("beef-023");
    let tracker = headers();
    let mut reader = StreamVerifier::new(&bytes[..], &tracker, None);
    for _ in 0..2 {
        assert!(matches!(reader.step().unwrap(), Progress::Stepped));
    }
    let stored = reader.cursor().to_binary();
    assert_eq!(&stored[..4], b"BSC3");
    (bytes, stored)
}

/// The index of the one byte after `pattern` in `bytes`.
fn after_the_one(bytes: &[u8], pattern: &[u8]) -> usize {
    let found: Vec<usize> = bytes
        .windows(pattern.len())
        .enumerate()
        .filter(|(_, w)| *w == pattern)
        .map(|(i, _)| i + pattern.len())
        .collect();
    assert_eq!(found.len(), 1, "one occurrence");
    found[0]
}

/// The flags byte of the parent's index entry in the cursor of beef-023
/// after the parent: its txid, its offset (43, the byte after the BUMP and
/// the transaction count), then the flags, 2 (a raw transaction).
fn parent_flags_at(stored: &[u8]) -> usize {
    let mut pattern = wire(BLOCK_9_COINBASE).to_vec();
    pattern.extend_from_slice(&43u64.to_le_bytes());
    pattern.push(2);
    after_the_one(stored, &pattern) - 1
}

/// A BSC2 cursor, written by 0.5.0 to 0.8.0, still reads, as BSC3 with no
/// edge, and resumes: the documenting lines are `Cursor::to_binary`'s
/// rustdoc ("[`from_binary`](Self::from_binary) reads a BSC2 cursor as BSC3
/// with no edge for a transaction read before it: the walk reaches less, so
/// it only refuses more, never accepts wrongly"), `src/transaction/CLAUDE.md`
/// ("a BSC2 cursor reads as BSC3 with no edge") and the 0.8.1 entry of
/// `CHANGELOG.md` ("A BSC2 cursor (0.5.0 to 0.8.0) reads as BSC3 with no
/// edge"); a BSC2 index entry carries 0.8.0's spent flag (0.8.0's module
/// documentation: "the transactions by txid with a spent flag", written as
/// bit 0 of the flags byte, `v0.8.0` `beef_stream.rs:2713`). beef-023's BSC3
/// cursor after the parent, its input count and edges cut and its parent's
/// flags the spent raw transaction's 3, reads and resumes to beef-023's
/// verdict, the reference's `verifyValid`. Crate-contract pin, no sibling
/// rule, stated: no `BSC*` layout is the sibling's or the reference's. Kills
/// the flags check's `>` replaced by `==` or `>=` (2828) and the raw bit's
/// `&` replaced by `|` (2861). The BSC3 half (the spent bit and every higher
/// bit refused) is
/// `a_bsc3_cursor_with_flags_its_writer_never_writes_is_refused_wire_beef_023`'s,
/// on the line promoted into `Cursor::from_binary`'s rustdoc.
#[test]
fn a_bsc2_cursor_carrying_the_spent_bit_reads_and_resumes_wire_beef_023() {
    let (bytes, stored) = cursor_after_the_parent();
    let at = parent_flags_at(&stored);
    // BSC2: the input count (1, the parent's one input) and the edges (none:
    // a coinbase names no parent) and the wanted byte cut from the tail.
    let tail = 8 + 1 + 1;
    assert_eq!(
        stored[stored.len() - tail..],
        [1, 0, 0, 0, 0, 0, 0, 0, 0, 0]
    );
    let mut bsc2 = b"BSC2".to_vec();
    bsc2.extend_from_slice(&stored[4..stored.len() - tail]);
    bsc2.push(0);
    bsc2[at] = 3;
    let restored = Cursor::from_binary(&bsc2).expect("BSC2 carries the spent bit");
    let tracker = headers();
    let rest = &bytes[restored.offset() as usize..];
    let verdict = StreamVerifier::resume(restored, rest, &tracker)
        .run()
        .unwrap();
    assert_eq!(verdict, whole("beef-023"));
}

/// A BSC3 transaction's flags byte is the raw bit alone, and a stored cursor
/// changed to carry another is refused: the documenting line is
/// `Cursor::from_binary`'s rustdoc ("A BSC3 (and BSC4, BSC5) transaction's
/// flags byte is 0 or 2, the raw bit; any other value is refused"), with
/// `Cursor::to_binary`'s ("A transaction's flags byte this writes is 0 or 2;
/// [`from_binary`](Self::from_binary) refuses any other") and
/// `src/transaction/CLAUDE.md`'s. Reachability decides (the keeper's word of
/// 2026-11-03 01:1xZ): the writer never produces the state, but the parser is
/// public and takes the bytes a caller stores. beef-023's cursor after the
/// parent round-trips byte for byte; with the parent's flags 1 or 3 (BSC2's
/// spent bit), 4 or 6 (a bit above the raw bit), 5, 7 or 255 it is refused.
/// Crate-contract pin, no sibling rule, stated; the behaviour alone, no
/// message. Kills the flags check's `||` replaced by `&&` (2828:26: 1, 3, 4
/// and 6 then read as cursors).
#[test]
fn a_bsc3_cursor_with_flags_its_writer_never_writes_is_refused_wire_beef_023() {
    let (_, stored) = cursor_after_the_parent();
    let at = parent_flags_at(&stored);
    assert_eq!(stored[at], 2);
    let read = Cursor::from_binary(&stored).expect("the valid cursor reads back");
    assert_eq!(read.to_binary(), stored, "the valid cursor round-trips");
    for flags in [1u8, 3, 4, 6, 5, 7, 0xff] {
        let mut changed = stored.clone();
        changed[at] = flags;
        assert!(
            Cursor::from_binary(&changed).is_err(),
            "BSC3 flags {flags} read as a cursor"
        );
    }
}

/// A cursor's edges name each raw transaction's parents (BSC3, 0.8.1; kept
/// under a subject, for the atomic walk, `AtomicBEEF.lean:36-41`), and edges
/// of a txid the index does not hold raw are refused: the documenting lines
/// are `src/transaction/CLAUDE.md`'s ("a list out of order, or edges of a
/// txid the index does not hold raw, is refused") and the 0.8.1 entry of
/// `CHANGELOG.md` ("`Cursor::from_binary` refuses a list out of order, with a
/// repeat, or naming a txid the index does not hold raw"), with
/// `Cursor::to_binary`'s rustdoc ("the edges the atomic walk follows: each
/// raw transaction's prevs"). atomic-beef-023's cursor after the child
/// carries one edge, the child to the parent; with the child's index entry
/// read without its bytes (its flags 0, the raw bit cleared, at the child's
/// offset 216, after the V2 format byte at the reference's end of the
/// parent, 215) the edge names a txid the index does not hold raw and is
/// refused. The refusal is the edge's, not the entry's: a cursor whose index
/// holds a txid not raw with no edge for it reads back and resumes to the
/// verdict of the whole, the documenting line `StreamVerifier::resume`'s
/// rustdoc ("the verdict is the verdict of the whole"), with
/// `src/transaction/CLAUDE.md`'s "every other entry, raw or txid-only, is
/// reached" and `Element::TxidOnly`'s "A txid-only entry (V2)": a V2 BEEF of
/// beef-023's BUMP and its coinbase as a txid-only entry, which the BUMP
/// proves, read past both, its cursor (BSC3, the entry's flags 0) read back
/// and resumed. Crate-contract pin, no sibling rule, stated; the behaviour
/// alone, no message (no public line states one). Kills the edge check's
/// guard replaced by `true` and its `&&` by `||` (2886), and the flags
/// check's `&` replaced by `^` or `|` (2828:44: a txid-only entry's flags 0
/// is then refused, and the cursor does not read back).
#[test]
fn a_cursor_edge_of_a_transaction_not_held_raw_is_refused_wire_atomic_beef_023() {
    let bytes = row("atomic-beef-023");
    let tracker = headers();
    let mut reader = StreamVerifier::new(&bytes[..], &tracker, None);
    for _ in 0..3 {
        assert!(matches!(reader.step().unwrap(), Progress::Stepped));
    }
    let stored = reader.cursor().to_binary();
    assert!(Cursor::from_binary(&stored).is_ok());
    let mut edge = wire(BLOCK_170_SPEND).to_vec();
    edge.push(1);
    edge.extend_from_slice(&wire(BLOCK_9_COINBASE));
    after_the_one(&stored, &edge);
    // BEEF V2: the child's bytes start after its entry's format byte, which
    // follows the reference's end of the parent.
    let child_at = reading("atomic-beef-023")["ends"][1].as_u64().unwrap() + 1;
    assert_eq!(child_at, 216);
    let mut entry = wire(BLOCK_170_SPEND).to_vec();
    entry.extend_from_slice(&child_at.to_le_bytes());
    entry.push(2);
    let flags_at = after_the_one(&stored, &entry) - 1;
    let mut not_raw = stored.clone();
    not_raw[flags_at] = 0;
    assert!(Cursor::from_binary(&not_raw).is_err());

    let beef023 = Beef::from_binary(&row("beef-023")).unwrap();
    let mut beef = Beef::with_version(BEEF_V2);
    beef.bumps.push(beef023.bumps[0].clone());
    beef.txs
        .push(BeefTx::from_txid(BLOCK_9_COINBASE.to_string()));
    let mut writer = Writer::new();
    beef.to_writer(&mut writer);
    let txid_only = writer.into_bytes();
    let whole_verdict = StreamVerifier::new(&txid_only[..], &tracker, None)
        .run()
        .unwrap();
    assert!(whole_verdict.is_valid(), "{whole_verdict:?}");
    let mut reader = StreamVerifier::new(&txid_only[..], &tracker, None);
    // The BUMP, the txid-only entry.
    for _ in 0..2 {
        assert!(matches!(reader.step().unwrap(), Progress::Stepped));
    }
    let stored = reader.cursor().to_binary();
    assert_eq!(&stored[..4], b"BSC3");
    let mut entry = wire(BLOCK_9_COINBASE).to_vec();
    entry.extend_from_slice(&(txid_only.len() as u64 - 32).to_le_bytes());
    entry.push(0);
    after_the_one(&stored, &entry);
    let restored = Cursor::from_binary(&stored).expect("the cursor reads back");
    let rest = &txid_only[restored.offset() as usize..];
    let verdict = StreamVerifier::resume(restored, rest, &tracker)
        .run()
        .unwrap();
    assert_eq!(verdict, whole_verdict);
}

/// A cursor's leading word is one of the four layouts; BSC1 is refused,
/// never read as another: the documenting line is `Cursor::to_binary`'s
/// rustdoc ("BSC1 is refused: restart its reading"), with the 0.5.0 entry of
/// `CHANGELOG.md` ("Cursors now use `BSC2`; `BSC1` lacks maturity evidence
/// and is rejected"). The refusal is the word's: beef-023's cursor after the
/// parent, its input count and edges cut (a BSC2 body), reads under `BSC2`
/// (the same rustdoc: "reads a BSC2 cursor as BSC3 with no edge") and is
/// refused under `BSC1`, `BSC6` and `bsc3`; so is the BSC3 body under those
/// words. Crate-contract pin, no sibling rule, stated; the behaviour alone,
/// no message (no public line states one). Kills the BSC2 guard replaced by
/// `true` (2769: every word is then read as BSC2, and the BSC2 body reads).
#[test]
fn a_cursor_in_no_layout_is_refused_by_its_word_wire_beef_023() {
    let (_, stored) = cursor_after_the_parent();
    // The input count, the edges and the wanted byte cut; the wanted byte
    // put back.
    let mut bsc2 = stored[..stored.len() - (8 + 1 + 1)].to_vec();
    bsc2.push(0);
    bsc2[..4].copy_from_slice(b"BSC2");
    assert!(Cursor::from_binary(&bsc2).is_ok(), "a BSC2 body reads");
    for word in [b"BSC1", b"BSC6", b"bsc3"] {
        for body in [&stored, &bsc2] {
            let mut other = body.clone();
            other[..4].copy_from_slice(word);
            assert!(Cursor::from_binary(&other).is_err());
        }
    }
}

// ---------------------------------------------------------------------------
// The cursor inside a transaction
// ---------------------------------------------------------------------------

/// The crate's chain witness with a subject of three inputs: the funding
/// (three `OP_TRUE` outputs, proven) and a transaction spending all three
/// with empty unlocks, written by this crate's `Transaction::to_binary`;
/// with `refused`, that input's unlock is `OP_0`, leaving two items on the
/// stack, which the default mode refuses at version 1 (CLEANSTACK, the
/// contract of `CLAUDE.md`: strict for version 1). Returns the BEEF, the
/// headers and the subject's element offset.
fn three_inputs_with(refused: Option<u32>) -> (Vec<u8>, HashMap<u64, Hash32>, u64) {
    let (funding, bump, roots) = funding(3);
    let mut spend = Transaction::new();
    for vout in 0..3 {
        let mut input = TransactionInput::new(display(&sha256d(&funding)), vout);
        let unlock = if refused == Some(vout) {
            UnlockingScript::from_binary(&[0x00]).unwrap()
        } else {
            UnlockingScript::new()
        };
        input.set_unlocking_script(unlock);
        spend.add_input(input).unwrap();
    }
    spend
        .add_output(TransactionOutput::new(
            beef_chain::SATS,
            LockingScript::from_binary(&[0x51]).unwrap(),
        ))
        .unwrap();
    let raw = spend.to_binary();
    let bytes = written(bump, &[funding, raw.clone()]);
    // Version 1: the subject's bytes, then its BUMP flag, 0 (BEEF.lean:89-98).
    let at = (bytes.len() - 1 - raw.len()) as u64;
    (bytes, roots, at)
}

fn three_inputs() -> (Vec<u8>, HashMap<u64, Hash32>, u64) {
    three_inputs_with(None)
}

/// A reading paused inside the subject after two of its three inputs: the
/// cursor names the transaction's first byte and input 2, reads back from its
/// bytes, and resumes to the one-pass verdict; a cursor between two elements
/// names no input. Kills `input_reached` replaced by `None`, `Some(0)` or
/// `Some(1)` (2570; against the verdict in
/// `the_input_reached_is_the_input_the_resumed_reading_refuses`), the
/// verifier's paused-cursor arm deleted (3175), the
/// pause presence byte's `!=` replaced by `==` (2933) and the pause offset
/// check's `<` replaced by `<=` or `==` and its `&&` by `||` (2941).
#[test]
fn a_cursor_inside_a_transaction_names_the_input_reached_and_resumes() {
    let (bytes, roots, at) = three_inputs();
    let one_pass = verify_stream(&bytes[..], &roots, None).unwrap();
    assert!(one_pass.is_valid(), "{one_pass:?}");
    let mut reader = StreamVerifier::new(&bytes[..], &roots, None);
    // The BUMP, the funding.
    for _ in 0..2 {
        assert!(matches!(reader.step().unwrap(), Progress::Stepped));
    }
    assert_eq!(reader.cursor().input_reached(), None);
    assert_eq!(reader.cursor().offset(), at);
    let mut asked = 0;
    let mut spent = || {
        asked += 1;
        asked == 2
    };
    assert_eq!(reader.step_until(&mut spent).unwrap(), Timed::Paused);
    let cursor = reader.cursor();
    assert_eq!(cursor.input_reached(), Some(2));
    assert_eq!(cursor.offset(), at);
    let stored = cursor.to_binary();
    let restored = Cursor::from_binary(&stored).expect("a paused cursor reads back");
    assert_eq!(restored.input_reached(), Some(2));
    let rest = &bytes[restored.offset() as usize..];
    let verdict = StreamVerifier::resume(restored, rest, &roots)
        .run()
        .unwrap();
    assert_eq!(verdict, one_pass);
}

/// A pause names its transaction where the stream read it: at the frame's
/// offset, or before it only for a held transaction a step released
/// (bsv-rs#240). The documenting lines are `Cursor::input_reached`'s rustdoc
/// ("The input a reading paused inside a transaction reached: the
/// transaction starts at [`offset`](Self::offset)") and
/// `src/transaction/CLAUDE.md`'s exception for a released held transaction
/// ("under `step_until` its scripts run under the caller's budget and may
/// pause inside it, the cursor naming it before the frame"). The paused
/// cursor of the three-input witness with its pause moved before the frame,
/// to 0, names a transaction neither line allows and is refused.
/// Crate-contract pin, no sibling rule, stated. Kills the pause offset
/// check's `<` replaced by `>` and its `!` deleted (2941).
#[test]
fn a_pause_before_its_frame_is_refused() {
    let (bytes, roots, _) = three_inputs();
    let mut reader = StreamVerifier::new(&bytes[..], &roots, None);
    for _ in 0..2 {
        assert!(matches!(reader.step().unwrap(), Progress::Stepped));
    }
    let mut asked = 0;
    let mut spent = || {
        asked += 1;
        asked == 2
    };
    assert_eq!(reader.step_until(&mut spent).unwrap(), Timed::Paused);
    let mut stored = reader.cursor().to_binary();
    // The pause: the presence byte, the offset, the txid, the input.
    let offset_at = stored.len() - 4 - 32 - 8;
    assert_eq!(stored[offset_at - 1], 1);
    stored[offset_at..offset_at + 8].copy_from_slice(&0u64.to_le_bytes());
    assert_eq!(
        Cursor::from_binary(&stored).unwrap_err().to_string(),
        "BEEF error: not a cursor: a pause before its frame"
    );
}

// ---------------------------------------------------------------------------
// The whole-BEEF reader: the earliest refusal of the reading
// ---------------------------------------------------------------------------

/// bsv-stack-lean@fc914087's `noInputAnchorWire` (`lean/BeefOfAnySize/
/// Scenarios.lean:630-638`, the row `no_input_anchor` of
/// `vectors/beef_of_any_size/`): a transaction with no input under its BUMP,
/// refused `noInputs` at 49. With a byte after the frame (`:491-494`, a
/// trailing byte refused at its offset) the reading still stops at 49: the
/// earliest refusal is the transaction's, which the stream meets first. The
/// whole-BEEF reader is the stream's decoder collecting (0.4.1, 0.4.2: the
/// whole path follows the streaming reader), so `Beef::from_binary` refuses
/// at 49 too, the transaction's refusal kept by the decoder and taken after
/// it is yielded, not the trailing byte's at 79. The verdict under which
/// `take_deferred` replaced by `None` (788) is a candidate equivalence, not a
/// kill: the whole reader's structure-only fold judges the same element by
/// the same rule first (`check_transaction`, the Lean's `checkTx`,
/// `bsv-script-lean@387dab35` `TxRules.lean:82-95`, `checkTransactionCommon`), so the dropped
/// refusal is the fold's, at the same offset; this test is green on it.
#[test]
fn the_earliest_refusal_is_a_transactions_before_a_trailing_byte_lean_no_input_anchor() {
    let row = include_bytes!("vectors/beef_of_any_size/no_input_anchor.bin");
    assert_eq!(row.len(), 79);
    let mut bytes = row.to_vec();
    bytes.push(0);
    let mut stream = BeefStream::new(&bytes[..]);
    let refused = loop {
        match stream.next_element() {
            Ok(Some(_)) => continue,
            Ok(None) => panic!("the row is read"),
            Err(StreamError::Refused(r)) => break r,
            Err(e) => panic!("{e:?}"),
        }
    };
    assert_eq!((refused.offset, &refused.reason), (49, &Reason::NoInputs));
    let whole = Beef::from_binary(&bytes).unwrap_err().to_string();
    assert_eq!(whole, format!("BEEF error: {refused}"));
    // The row alone parses: its transaction is the structure check's to judge.
    assert!(Beef::from_binary(row).is_ok());
}

/// The three-input witness with its third input refused by its script: a
/// reading paused after two inputs names, as the input reached, the input the
/// resumed reading refuses (the inputs before it ran; a resume runs from it
/// on), and the one-pass verdict names the same input. Kills
/// `input_reached` replaced by `None`, `Some(0)` or `Some(1)` (2570) against
/// the verdict, not a constant.
#[test]
fn the_input_reached_is_the_input_the_resumed_reading_refuses() {
    let (bytes, roots, at) = three_inputs_with(Some(2));
    let one_pass = verify_stream(&bytes[..], &roots, None).unwrap();
    let Verdict::SpendRefused { input, offset, .. } = &one_pass else {
        panic!("{one_pass:?}")
    };
    assert!(*offset > at);
    let mut reader = StreamVerifier::new(&bytes[..], &roots, None);
    for _ in 0..2 {
        assert!(matches!(reader.step().unwrap(), Progress::Stepped));
    }
    let mut asked = 0;
    let mut spent = || {
        asked += 1;
        asked == 2
    };
    assert_eq!(reader.step_until(&mut spent).unwrap(), Timed::Paused);
    let cursor = reader.cursor();
    assert_eq!(
        cursor.input_reached(),
        *input,
        "the input the verdict names"
    );
    let restored = Cursor::from_binary(&cursor.to_binary()).unwrap();
    assert_eq!(restored.input_reached(), *input);
    let rest = &bytes[restored.offset() as usize..];
    let verdict = StreamVerifier::resume(restored, rest, &roots)
        .run()
        .unwrap();
    assert_eq!(verdict, one_pass);
}
