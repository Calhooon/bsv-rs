#![cfg(test)]
//! #603, shard C: `compute_serialized_length` by the two-path rule. The sum
//! of a script's chunks equals the length of the bytes `to_binary` writes for
//! them, and both equal the length the reference's `toBinary` writes
//! (`Script.#computeSerializedLength`, `Script.ts:450-476` at
//! `ts-stack@edf6e03`, the length of its `Uint8Array`), recorded in
//! `tests/vectors/script_writers_603_c.json` by
//! `tests/support/script_writers_603_c.mjs`. The length is `pushData`'s
//! (`lean/BsvScript/Sighash.lean:275-282` at `bsv-script-lean@5dc337e1`): one
//! opcode byte, the data, and 0, 1, 2 or 4 length bytes for a direct push,
//! `OP_PUSHDATA1`, `OP_PUSHDATA2` and `OP_PUSHDATA4` (`le32`, `:66`); after a
//! top-level `OP_RETURN`, the data as read (`Machine.lean:24-50`). The sum is
//! crate-visible and sizes the writer's buffer alone, so it is read here, in
//! the crate, with no assumption about the allocator (`Vec::with_capacity` is
//! at least, not exactly). The writers' kills are
//! `tests/script_script_603_c.rs`.

use super::Script;
use crate::primitives::{from_hex, sha256, to_hex};
use crate::script::ScriptChunk;
use serde_json::Value;

/// The recording (`tests/support/script_writers_603_c.mjs`).
fn vectors() -> Value {
    serde_json::from_str(include_str!(
        "../../tests/vectors/script_writers_603_c.json"
    ))
    .unwrap()
}

/// The recorder's form of a script: its hex up to 4096 bytes, else its
/// length, its first 16 bytes and its SHA-256.
fn shape(bytes: &[u8]) -> Value {
    if bytes.len() <= 4096 {
        serde_json::json!({ "hex": to_hex(bytes) })
    } else {
        serde_json::json!({
            "len": bytes.len(),
            "head": to_hex(&bytes[..16]),
            "sha256": to_hex(&sha256(bytes)),
        })
    }
}

/// The length of a recorded script: its hex's bytes, or its `len`.
fn recorded_len(shape: &Value) -> usize {
    match shape["hex"].as_str() {
        Some(hex) => hex.len() / 2,
        None => shape["len"].as_u64().unwrap() as usize,
    }
}

/// A push's data as the recording describes it: the corpus chunk's bytes, one
/// byte repeated, or the pattern `(7i + 1) mod 256`.
fn data(p: &Value) -> Vec<u8> {
    let len = p["len"].as_u64().unwrap() as usize;
    let d = &p["data"];
    if let Some(hex) = d["hex"].as_str() {
        from_hex(hex).unwrap()
    } else if let Some(fill) = d["fill"].as_u64() {
        vec![fill as u8; len]
    } else {
        assert_eq!(d["pattern"], "(7i + 1) mod 256");
        (0..len).map(|i| ((7 * i + 1) % 256) as u8).collect()
    }
}

/// The two paths agree on `chunks`: the sum is the length of the bytes
/// `to_binary` writes, which are the reference's (`reference`, the recorder's
/// shape), of the reference's length.
fn assert_two_paths_agree(what: &str, chunks: Vec<ScriptChunk>, reference: &Value) {
    let sum = Script::compute_serialized_length(&chunks);
    let written = Script::from_chunks(chunks).to_binary();
    assert_eq!(&shape(&written), reference, "{what}: the reference's bytes");
    assert_eq!(sum, written.len(), "{what}: the sum, the bytes written");
    assert_eq!(
        sum,
        recorded_len(reference),
        "{what}: the reference's length"
    );
}

/// The recording's corpus scripts, each read into its chunks: `bytes-00076`,
/// the 75-byte direct push (kills `328:9` `0` and `1`, `330:19`, `337:29` `==`
/// and `>`: the opcode byte or the direct push's data left out);
/// `bytes-00077`, `OP_PUSHDATA1` of one byte (`337:29` `<=`, `339:36`,
/// `340:27`, `340:32`: its length byte); `bytes-00078`, `OP_PUSHDATA2`
/// (`341:36`, `342:32`); `bytes-00079`, `OP_PUSHDATA4` (`343:36`, `344:27`,
/// `344:32`); `seed-000647`, `OP_9 OP_RETURN` and six bytes (`333:29`,
/// `334:27`: the data after the `OP_RETURN` miscounted, or the sum
/// underflowing); `arith-00011`, `arith-00013`, `arith-00687` and `gen-00999`
/// the same rules over several chunks; `seed-000785`'s 65535-byte push and
/// `tx-00040`'s 10,000,036-byte output, recorded by length and hash, rebuilt
/// by the writers from the recording's pushes.
#[test]
fn the_length_sum_is_the_bytes_written_bytes_00076_to_00079_seed_000647_tx_00040() {
    let v = vectors();
    let pushes = v["pushes"].as_array().unwrap();
    let mut seen = Vec::new();
    for entry in v["scripts"].as_array().unwrap() {
        let id = entry["id"].as_str().unwrap();
        assert_eq!(entry["script"], entry["reference_rewritten"], "{id}");
        let chunks = match (id, entry["script"]["hex"].as_str()) {
            (_, Some(hex)) => Script::from_binary(&from_hex(hex).unwrap())
                .unwrap()
                .chunks()
                .to_vec(),
            ("seed-000785", None) => {
                let p = pushes
                    .iter()
                    .find(|p| p["from"].as_str().is_some_and(|f| f.starts_with(id)))
                    .unwrap();
                let mut s = Script::new();
                s.write_bin(&data(p));
                s.chunks().to_vec()
            }
            ("tx-00040", None) => {
                let rec = &v["op_return_push"];
                assert_eq!(rec["id"], id);
                let fill = rec["fill"].as_u64().unwrap() as u8;
                let mut s = Script::new();
                s.write_opcode(0x00).write_opcode(0x6a).write_bin(&vec![
                    fill;
                    rec["data_len"].as_u64().unwrap()
                        as usize
                ]);
                s.chunks().to_vec()
            }
            _ => panic!("{id}: no rebuild for a script recorded by length"),
        };
        assert_two_paths_agree(id, chunks, &entry["reference_rewritten"]);
        seen.push(id);
    }
    assert_eq!(
        seen,
        [
            "bytes-00076",
            "bytes-00077",
            "bytes-00078",
            "bytes-00079",
            "arith-00011",
            "arith-00013",
            "arith-00687",
            "seed-000647",
            "gen-00999",
            "seed-000785",
            "tx-00040"
        ]
    );
}

/// The pushes `write_bin` writes at the recording's twelve lengths (the
/// corpus's 75, 80, 100, 520, 600 and 65535, and 1, 76, 255, 256, 65536 and
/// 2^24): the direct push, `OP_PUSHDATA1`, `OP_PUSHDATA2` and `OP_PUSHDATA4`
/// at their edges, the sum the length of the reference's `writeBin` bytes.
#[test]
fn the_length_sum_is_the_bytes_written_at_each_push_edge_arith_00643_seed_000785() {
    let v = vectors();
    let pushes = v["pushes"].as_array().unwrap();
    assert_eq!(pushes.len(), 12);
    for p in pushes {
        let len = p["len"].as_u64().unwrap();
        let mut s = Script::new();
        s.write_bin(&data(p));
        assert_two_paths_agree(
            &format!("a push of {len}"),
            s.chunks().to_vec(),
            &p["reference"],
        );
    }
}
