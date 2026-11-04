//! #661: a script built by hand through `Script::from_chunks` and
//! `ScriptChunk::new` from chunks whose opcode and data disagree (empty data
//! on `OP_1`, `OP_0`, a direct push or `OP_PUSHDATA1`; data on an opcode that
//! carries none; a push whose data length is not its opcode's; an `OP_RETURN`
//! with data followed by more chunks). The reference holds any `{ op, data? }`
//! (`ts-stack@edf6e03` `ScriptChunk.ts`, `new Script(chunks)` with no check),
//! writes its bytes through `#serializeChunksToBytes` and `#writeChunkData`
//! (`Script.ts:474-490`, `:539-562`: the data only after an opcode below
//! `OP_PUSHDATA1` or a PUSHDATA opcode, nothing after an `OP_RETURN` with
//! data) and its ASM through `#_chunkToString` (`:668-677`: a chunk with data
//! its data's hex alone, whatever its opcode). So the reference round-trips
//! none of these shapes either, and this crate's answer is the reference's,
//! not a stricter one: `from_chunks` refuses nothing, the bytes and the ASM
//! are the reference's, save the rows stated in `CLAUDE.md` (#634's writer
//! of an `OP_RETURN` with data, the name of a direct push without data;
//! `OP_0` and `OP_1NEGATE` written by the reference's names since #723) and
//! the readings of `from_asm` #603 shard A states (the empty token, the short
//! inline PUSHDATA).
//!
//! go-sdk@2ca481c holds no such chunk in a script: `NewScriptFromScriptOps`
//! (`script/script_chunk.go:119-163`) re-encodes every push opcode as the
//! minimal push of its data and drops data on any other opcode, and `ToASM`
//! reads the bytes written (`script/script.go:190-213`); its bytes are in the
//! vector, transcribed, not run.
//!
//! The vector `tests/vectors/script_chunk_asm_661.json` is the reference's
//! answer on twenty-four shapes under Node 22 (`toHex`, `toASM`, `fromASM` of
//! that text, `fromHex` of those bytes), written by
//! `tests/support/script_chunk_asm_661.mjs`.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use bsv_rs::primitives::from_hex;
use bsv_rs::script::{LockingScript, Script, ScriptChunk, UnlockingScript};
use serde_json::Value;

/// The ASM this crate writes where the reference writes other text, each a
/// stated row: #634's `OP_RETURN` writer (the rest's ASM after `OP_RETURN`,
/// the chunks after it as they are), a direct push without data as
/// `OP_UNKNOWN<n>` (the reference's `OP[op]` is `undefined`); neither text
/// reads back in either SDK.
const ASM_STATED: &[(&str, &str, &str)] = &[
    ("op-return-data-then-op1", "OP_RETURN OP_1 OP_1", "#634"),
    (
        "op-return-push-then-dup",
        "OP_RETURN 68656c6c6f OP_DUP",
        "#634",
    ),
    ("op-return-empty-data-then-op1", "OP_RETURN OP_1", "#634"),
    ("op-return-empty-data", "OP_RETURN", "#634"),
    ("push1-no-data", "OP_UNKNOWN1", "#661"),
    ("push4b-no-data", "OP_UNKNOWN75", "#661"),
];

/// The reference's text read back by `from_asm` to other bytes, each #603
/// shard A's stated reading: an empty token skipped (the reference's empty
/// push, `00`), a short inline PUSHDATA the opcode alone (the reference's
/// empty push of that opcode).
const READ_BACK_STATED: &[(&str, &str)] = &[
    ("op1-empty-data", ""),
    ("op0-empty-data", ""),
    ("push1-empty-data", ""),
    ("pushdata1-empty-data", ""),
    ("dup-op1empty-dup", "7676"),
    ("op-return-empty-data-then-op1", "51"),
    ("op-return-empty-data", ""),
    ("pushdata1-no-data", "4c"),
    ("pushdata4-no-data", "4e"),
];

/// The shapes whose own ASM reads back to their own bytes here: the chunks
/// the parser produces (`OP_0`, `OP_1NEGATE`, two undefined opcodes, a bare
/// `OP_RETURN`) and the two PUSHDATA opcodes without data (#603 shard A's
/// reading). Every other shape's opcode and data disagree, and its round trip
/// fails here as it fails in the reference.
const ROUND_TRIPS_HERE: &[&str] = &[
    "op-return-empty-data",
    "pushdata1-no-data",
    "pushdata4-no-data",
    "op0-no-data",
    "op1negate-no-data",
    "undefined-op-ba",
    "undefined-op-ff",
];

fn vector() -> Value {
    serde_json::from_str(include_str!("vectors/script_chunk_asm_661.json")).unwrap()
}

fn shapes() -> Vec<(String, Vec<ScriptChunk>, Value)> {
    vector()["shapes"]
        .as_array()
        .unwrap()
        .iter()
        .map(|s| {
            let chunks = s["chunks"]
                .as_array()
                .unwrap()
                .iter()
                .map(|c| {
                    let op = u8::try_from(c["op"].as_u64().unwrap()).unwrap();
                    ScriptChunk::new(op, c["data"].as_str().map(|d| from_hex(d).unwrap()))
                })
                .collect();
            (
                s["id"].as_str().unwrap().to_string(),
                chunks,
                s["ts"].clone(),
            )
        })
        .collect()
}

fn stated<'a>(table: &'a [(&str, &'a str, &str)], id: &str) -> Option<&'a str> {
    table
        .iter()
        .find(|(i, ..)| *i == id)
        .map(|(_, asm, _)| *asm)
}

#[test]
fn every_shape_held_by_from_chunks_writes_the_references_bytes_661() {
    let shapes = shapes();
    assert_eq!(shapes.len(), 24);
    for (id, chunks, ts) in shapes {
        let script = Script::from_chunks(chunks.clone());
        assert_eq!(script.chunks(), chunks, "{id}: held as given");
        assert_eq!(script.to_hex(), ts["to_hex"].as_str().unwrap(), "{id}");
    }
}

#[test]
fn every_shape_writes_the_references_asm_save_the_stated_rows_661() {
    let mut stated_seen = 0;
    for (id, chunks, ts) in shapes() {
        let asm = Script::from_chunks(chunks.clone()).to_asm();
        let reference = ts["asm"].as_str().unwrap();
        match stated(ASM_STATED, &id) {
            Some(ours) => {
                stated_seen += 1;
                assert_ne!(ours, reference, "{id}: no longer a difference");
                assert_eq!(asm, ours, "{id}");
            }
            None => assert_eq!(asm, reference, "{id}"),
        }
        assert_eq!(LockingScript::from_chunks(chunks.clone()).to_asm(), asm);
        assert_eq!(UnlockingScript::from_chunks(chunks).to_asm(), asm);
    }
    assert_eq!(stated_seen, ASM_STATED.len());
}

#[test]
fn the_issues_shapes_write_their_datas_hex_as_the_reference_does_661() {
    // `Some(vec![])` on OP_1, OP_0, 0x01 and OP_PUSHDATA1: the empty hex,
    // as the reference's `toHex([])`; the bytes the opcode and, for the
    // PUSHDATA opcode, a zero length
    for (op, hex) in [(0x51, "51"), (0x00, "00"), (0x01, "01"), (0x4c, "4c00")] {
        let script = Script::from_chunks(vec![ScriptChunk::new(op, Some(vec![]))]);
        assert_eq!(script.to_asm(), "", "op {op:#04x}");
        assert_eq!(script.to_hex(), hex, "op {op:#04x}");
    }
    // OP_DUP with [1, 2]: the data's hex, the opcode alone written
    let dup = Script::from_chunks(vec![ScriptChunk::new(0x76, Some(vec![1, 2]))]);
    assert_eq!(
        (dup.to_asm().as_str(), dup.to_hex().as_str()),
        ("0102", "76")
    );
}

#[test]
fn the_references_asm_reads_back_as_the_reference_reads_it_save_603s_readings_661() {
    let mut stated_seen = 0;
    for (id, _, ts) in shapes() {
        let reference = ts["asm"].as_str().unwrap();
        let read = Script::from_asm(reference).map(|s| s.to_hex());
        match (
            ts["asm_back_hex"].as_str(),
            READ_BACK_STATED.iter().find(|(i, _)| *i == id),
        ) {
            (Some(theirs), Some((_, ours))) => {
                stated_seen += 1;
                assert_ne!(*ours, theirs, "{id}: no longer a difference");
                assert_eq!(read.unwrap(), *ours, "{id}");
            }
            (Some(theirs), None) => assert_eq!(read.unwrap(), theirs, "{id}"),
            // `undefined`: refused by both readers as no hex
            (None, _) => {
                assert!(ts["asm_back_error"].as_str().unwrap().contains("hex"));
                assert!(read.is_err(), "{id}: {read:?}");
            }
        }
    }
    assert_eq!(stated_seen, READ_BACK_STATED.len());
}

#[test]
fn the_round_trip_holds_only_where_the_opcode_and_its_data_agree_661() {
    for (id, chunks, ts) in shapes() {
        let script = Script::from_chunks(chunks);
        let back = Script::from_asm(&script.to_asm()).map(|s| s.to_hex());
        let here = back.as_deref() == Ok(script.to_hex().as_str());
        assert_eq!(
            here,
            ROUND_TRIPS_HERE.contains(&id.as_str()),
            "{id}: {back:?}"
        );
        // the reference's own round trip holds on the parser's chunks alone
        let there = ts["asm_back_hex"].as_str() == ts["to_hex"].as_str();
        let theirs = [
            "op0-empty-data",
            "op0-no-data",
            "op1negate-no-data",
            "undefined-op-ba",
            "undefined-op-ff",
        ];
        assert_eq!(there, theirs.contains(&id.as_str()), "{id}");
    }
}
