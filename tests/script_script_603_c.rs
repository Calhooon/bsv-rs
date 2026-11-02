//! `Script`'s writers on the sibling's corpus entries and the reference's
//! writer (#603, shard C): the survivors of `serialize_chunks_to_bytes`,
//! `write_bin` and `write_number` under the widened oracle (run 41327640129),
//! each killed here by a vector of `bsv-script-lean` at `5dc337e1`, copied by
//! its id, or by the reference's recording of a shape the corpus lacks. The
//! length path (`compute_serialized_length`, crate-visible) is read by the two-path
//! rule in `src/script/script_length_603_tests.rs`. `write_bin`'s 4 GiB bound
//! (`451:32`) has no test: an input past `u32::MAX` bytes is above the
//! mutation oracle's memory ceiling (`ulimit -v 4000000`, #574).
//!
//! The rules:
//!
//! * the push: `pushData` (`lean/BsvScript/Sighash.lean:275-282` at `5dc337e1`,
//!   `CScript::operator<<`, bitcoin-sv v1.2.3 `script.h:104-133`): a direct
//!   push below 76 bytes, `OP_PUSHDATA1` to 255, `OP_PUSHDATA2` to 65535,
//!   `OP_PUSHDATA4` above, its length `le32` (`Sighash.lean:66`), four bytes
//!   little-endian; the minimal push `checkMinimalPush` asks for
//!   (`Machine.lean:67-80`);
//! * the number: `encode` (`lean/BsvScript/Numbers.lean:143-147`,
//!   `CScriptNum::serialize`, `int_serialization.h:23-59`): zero the empty
//!   vector, else the magnitude's little-endian bytes with the sign on the top
//!   byte, a `0x00` or `0x80` byte added when the top byte's bit 7 is taken
//!   (`signTopRev`, `:134-140`);
//! * the reference's writer, `Script.writeBin` (`Script.ts:338-360` at
//!   `ts-stack@edf6e03`, refusing 2^32 bytes and more), `writeBn` (`:309-329`),
//!   `toBinary` (`:254-260`).
//!
//! A full-corpus run of each of the 28 mutants (the sibling's `harness/run
//! --impl bsv-rs --corpus all --spec recorded`, nine corpora) moved no verdict:
//! the harness reads every script with `from_binary`, whose bytes `to_binary`
//! returns unwritten. The vectors below reach the writers: the corpus's push
//! and script shapes at the encoding edges, written by this crate's writer and
//! compared with the corpus's bytes and the reference's.
//! `tests/vectors/script_writers_603_c.json` is the recording, written by
//! `tests/support/script_writers_603_c.mjs`.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)] // #134: test code: a failed unwrap is the test failing

use bsv_rs::primitives::bsv::sighash::{parse_transaction, TxOutput};
use bsv_rs::primitives::{from_hex, sha256, to_hex};
use bsv_rs::script::{
    LockingScript, ProtocolEra, Script, ScriptFlags, Spend, SpendParams, UnlockingScript,
};
use serde_json::Value;

/// The recording (`tests/support/script_writers_603_c.mjs`).
fn vectors() -> Value {
    serde_json::from_str(include_str!("vectors/script_writers_603_c.json")).unwrap()
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

/// The corpus entry's recorded verdict for this crate (`bsv-rs@0.7.0`, equal
/// to the node's, `sv-node@v1.2.3`, on every entry here), with `locking` as its
/// previous output's script, under the post-Chronicle block word its params
/// name (spend height 967,896, consensus).
fn assert_recorded_verdict(entry: &Value, locking: &[u8]) {
    let id = entry["id"].as_str().unwrap();
    assert_eq!(entry["params"]["era"], "post-chronicle", "{id}");
    assert_eq!(entry["params"]["consensus"], true, "{id}");
    assert_eq!(
        entry["verdicts"]["bsv-rs@0.7.0"],
        entry["verdicts"]["sv-node@v1.2.3"]
    );
    let tx = parse_transaction(&from_hex(entry["tx"].as_str().unwrap()).unwrap()).unwrap();
    let input = &tx.inputs[0];
    let mut spend = Spend::new(SpendParams {
        source_txid: input.txid,
        source_output_index: input.output_index,
        source_satoshis: entry["prevout_satoshis"].as_u64().unwrap(),
        locking_script: LockingScript::from_binary(locking).unwrap(),
        transaction_version: tx.version,
        other_inputs: Vec::new(),
        outputs: tx
            .outputs
            .iter()
            .map(|o| TxOutput {
                satoshis: o.satoshis,
                script: o.script.clone(),
            })
            .collect(),
        input_index: 0,
        unlocking_script: UnlockingScript::from_binary(&input.script).unwrap(),
        input_sequence: input.sequence,
        lock_time: tx.locktime,
        memory_limit: None,
        work_limit: None,
    });
    spend.set_flags(ScriptFlags::block(ProtocolEra::PostChronicle));
    let got = spend.validate().map_err(|e| e.message);
    match entry["verdicts"]["bsv-rs@0.7.0"].as_str().unwrap() {
        "valid" => assert_eq!(got, Ok(true), "{id}: the recorded verdict is valid"),
        v => panic!("{id}: no entry here records {v}"),
    }
}

/// `pushData` at every edge (`Sighash.lean:278-282`): the corpus's pushes of
/// 75 (`bytes-00076`, 0x4b, the last direct push), 80 and 100
/// (`arith-00011`, `arith-00687`, `OP_PUSHDATA1`), 520 and 600 (`arith-00013`,
/// `arith-00643`, `OP_PUSHDATA2`) and 65535 bytes (`seed-000785`, the last
/// `OP_PUSHDATA2`), and the lengths no entry carries, 1, 76, 255, 256, 65536 and
/// 16,777,216, each written by `write_bin` to the opcode and the bytes of the
/// reference's `writeBin`, and the corpus's script where the push is the whole
/// of it or leads it. At 65536 the push is `OP_PUSHDATA4` with `le32` length
/// `00 00 01 00`, at 2^24 `00 00 00 01`. Kills `write_bin`'s `448:23` (`<=`:
/// 65536 bytes as `OP_PUSHDATA2`, its length cut to `00 00`) and
/// `serialize_chunks_to_bytes`' `380:38` (`<<`: 65536's third length byte 0)
/// and `381:38` (`<<`: 2^24's fourth length byte 0). At 76, the length where
/// `442:23`'s `<=` takes the direct branch, its opcode is `76`, which is
/// `OP_PUSHDATA1`: the bytes the same (the candidate equivalence).
#[test]
fn the_push_writer_is_push_data_at_each_edge_bytes_00076_arith_00011_seed_000785() {
    let v = vectors();
    let scripts = v["scripts"].as_array().unwrap();
    let pushes = v["pushes"].as_array().unwrap();
    assert_eq!(pushes.len(), 12);
    for p in pushes {
        let len = p["len"].as_u64().unwrap();
        let bin = data(p);
        let mut s = Script::new();
        s.write_bin(&bin);
        let chunks = s.chunks();
        assert_eq!(chunks.len(), 1, "{len}: one push");
        assert_eq!(
            u64::from(chunks[0].op),
            p["op"].as_u64().unwrap(),
            "{len}: the reference's push opcode"
        );
        let written = s.to_binary();
        assert_eq!(
            shape(&written),
            p["reference"],
            "{len}: the reference's bytes"
        );
        let le32 = (len as u32).to_le_bytes();
        let prefix: Vec<u8> = match len {
            0..=75 => vec![len as u8],
            76..=255 => vec![0x4c, len as u8],
            256..=65535 => vec![0x4d, le32[0], le32[1]],
            _ => vec![0x4e, le32[0], le32[1], le32[2], le32[3]],
        };
        assert_eq!(
            written[..prefix.len()],
            prefix[..],
            "{len}: pushData's prefix"
        );
        assert_eq!(written.len(), prefix.len() + bin.len(), "{len}");

        let Some(from) = p["from"].as_str() else {
            continue;
        };
        let id = from.split(' ').next().unwrap();
        let Some(entry) = scripts.iter().find(|e| e["id"] == id) else {
            continue;
        };
        match entry["script"]["hex"].as_str() {
            Some(hex) => {
                let corpus = from_hex(hex).unwrap();
                assert_eq!(
                    corpus[..written.len()],
                    written[..],
                    "{id}: the corpus's push"
                );
            }
            // seed-000785's scriptSig is this one push.
            None => {
                assert_eq!(
                    entry["script"]["len"],
                    written.len() as u64,
                    "{id}: one push"
                );
                assert_eq!(
                    shape(&written),
                    entry["script"],
                    "{id}: the corpus's script"
                );
            }
        }
    }
}

/// `tx-00040` (`corpus/tx/tx.jsonl`, `tx/policy/tx-size/over`): its output
/// script, `OP_0 OP_RETURN` then a push of 10,000,029 zeros, written by the
/// writers is the corpus's bytes and the reference's (`4e 9d 96 98 00`: the
/// push's `le32` length has a second and a third byte, `Sighash.lean:66`).
/// The entry is valid in a block and refused by the mempool for its size
/// (`sv-node@v1.2.3`; `bsv-rs@0.7.0` valid, the interpreter's verdict), a
/// verdict on the transaction's size, which the script's bytes make. Kills
/// `serialize_chunks_to_bytes`' `379:38` (`<<`: the second length byte 0)
/// and `380:38` (the third).
#[test]
fn an_op_return_output_rebuilt_by_the_writers_is_the_corpus_script_tx_00040() {
    let v = vectors();
    let rec = &v["op_return_push"];
    assert_eq!(rec["id"], "tx-00040");
    let entry = v["scripts"]
        .as_array()
        .unwrap()
        .iter()
        .find(|e| e["id"] == "tx-00040")
        .unwrap();
    assert_eq!(entry["verdicts"]["sv-node@v1.2.3"], "valid");
    let mut s = Script::new();
    s.write_opcode(0x00).write_opcode(0x6a).write_bin(&vec![
        0u8;
        rec["data_len"].as_u64().unwrap()
            as usize
    ]);
    let written = s.to_binary();
    assert_eq!(written[..7], [0x00, 0x6a, 0x4e, 0x9d, 0x96, 0x98, 0x00]);
    assert_eq!(shape(&written), rec["reference"], "the reference's writers");
    assert_eq!(shape(&written), entry["script"], "tx-00040's output script");
}

/// `encode` at every edge (`Numbers.lean:143-147`): each value written by
/// `write_number` is the push the corpus carries for it (by id: `seed-000040`
/// -2, `arith-00101` 17, `seed-000126` 127, `seed-000092` -127 and -128,
/// `arith-00005` 128, `seed-000001` -129, `seed-000101` 255, `seed-000824`
/// -255, `seed-000159` 256, `seed-005218` -256, `seed-000195` 32767,
/// `seed-000050` -32767, `seed-000020` 32768, `seed-000030` -32768,
/// `arith-00117` 65535, `arith-00119` 65536, `arith-00121` 2^31 - 1,
/// `arith-00123` 2^31, `seed-000027` -2^31, `seed-000044` 2^63 - 1,
/// `seed-000133` -(2^63 - 1)) and the reference's `writeBn`, `i64::MIN` (nine
/// bytes, `00 x7 80 80`) the reference's alone. The encodings are 1 to 9
/// bytes: `write_number`'s `OP_PUSHDATA1` and `OP_PUSHDATA2` branches are not
/// reached from an `i64`, nor `encode_script_number`'s sign test at 0 (the
/// candidate equivalences of `486:29`, `488:27` and `507:28`).
#[test]
fn the_number_writer_is_encode_at_each_edge_seed_000040_arith_00005_seed_000133() {
    let v = vectors();
    let numbers = v["numbers"].as_array().unwrap();
    assert_eq!(numbers.len(), 23);
    for n in numbers {
        let value: i64 = n["value"].as_str().unwrap().parse().unwrap();
        let mut s = Script::new();
        s.write_number(value);
        let written = s.to_hex();
        assert_eq!(
            written,
            n["reference"].as_str().unwrap(),
            "{value}: writeBn"
        );
        if let Some(push) = n["corpus_push"].as_str() {
            assert_eq!(written, push, "{value}: {}'s push", n["id"]);
            assert_eq!(
                n["verdicts"]["bsv-rs@0.7.0"],
                n["verdicts"]["sv-node@v1.2.3"]
            );
        }
    }
}

/// A corpus script read into its chunks and written back from them is its
/// bytes (`getOpTail` then `pushData` of each push at the opcode it was read
/// with, `Machine.lean:29-50`, `Sighash.lean:278-282`), as the reference's
/// `new Script(chunks).toBinary()` writes it, and spends to the verdict the
/// corpus records: `bytes-00076` to `-00079` (a 75-byte direct push, then
/// `OP_PUSHDATA1`, `2`, `4` of one byte, the non-minimal pushes a locking
/// script may carry, `checkMinimalPush` being the unlocking script's rule),
/// `arith-00011`, `arith-00013`, `arith-00687` (two pushes of 80, 520 and 100
/// bytes around an operator), `seed-000647` and `gen-00999` (data after a
/// top-level `OP_RETURN`, written as it was read).
#[test]
fn a_corpus_script_written_back_from_its_chunks_is_its_bytes_bytes_00079_seed_000647() {
    let v = vectors();
    let mut seen = 0;
    for entry in v["scripts"].as_array().unwrap() {
        let id = entry["id"].as_str().unwrap();
        assert_eq!(entry["script"], entry["reference_rewritten"], "{id}");
        let Some(hex) = entry["script"]["hex"].as_str() else {
            continue;
        };
        let corpus = from_hex(hex).unwrap();
        let rewritten = Script::from_chunks(Script::from_binary(&corpus).unwrap().chunks());
        let bytes = rewritten.to_binary();
        assert_eq!(to_hex(&bytes), hex, "{id}: the chunks written back");
        assert_eq!(entry["where"], "prevout 0", "{id}");
        assert_recorded_verdict(entry, &bytes);
        seen += 1;
    }
    assert_eq!(seen, 9);
}
