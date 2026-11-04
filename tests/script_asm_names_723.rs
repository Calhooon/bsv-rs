//! #723: `to_asm` writes `0x00` as `OP_0` and `0x4f` as `OP_1NEGATE`, the
//! reference's names (`ts-stack@edf6e03` `packages/sdk/src/script/OP.ts:6-7,11`:
//! `OP_0` listed before `OP_FALSE`, "the top one will be used in standard ASM
//! output"; `toASM` through `#_chunkToString`, `Script.ts:668-677`, writing
//! `OP[op]`), where it wrote `0` and `-1` until #723; `from_asm` reads both
//! the old texts and the names, as the reference's `fromASM` does
//! (`#parseASMToken`, `Script.ts:91-92`, the literals `0` and `-1` before any
//! name), so a script written by the old writer still reads.
//!
//! go-sdk@2ca481c's `NewFromASM` (`script/script.go:46-63`) reads the names
//! and refuses `0` and `-1` (`ErrInvalidOpCode`: neither is a name or hex);
//! its `ToASM` writes `OP_FALSE` for `0x00` (`script/opcodes.go:546`), which
//! the reference and this crate read; transcribed in the recorder, not run.
//!
//! The vector `tests/vectors/script_asm_names_723.json` is the reference's
//! answer under Node 22 (`fromHex(..).toASM()` and its read back on eight
//! scripts, `fromASM(..)` and its `toHex`/`toASM` on ten texts), written by
//! `tests/support/script_asm_names_723.mjs`.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use bsv_rs::script::op::{OP_0, OP_1NEGATE};
use bsv_rs::script::{LockingScript, Script, ScriptChunk, UnlockingScript};
use serde_json::Value;

fn vector() -> Value {
    let text = std::fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/vectors/script_asm_names_723.json"
    ))
    .unwrap();
    serde_json::from_str(&text).unwrap()
}

fn cases<'a>(v: &'a Value, group: &str) -> &'a Vec<Value> {
    v[group].as_array().unwrap()
}

fn s<'a>(v: &'a Value, key: &str) -> &'a str {
    v[key].as_str().unwrap()
}

#[test]
fn op_0_and_op_1negate_are_written_by_the_references_names_723() {
    assert_eq!(ScriptChunk::new_opcode(OP_0).to_asm(), "OP_0");
    assert_eq!(ScriptChunk::new_opcode(OP_1NEGATE).to_asm(), "OP_1NEGATE");
    assert_eq!(Script::from_hex("00").unwrap().to_asm(), "OP_0");
    assert_eq!(Script::from_hex("4f").unwrap().to_asm(), "OP_1NEGATE");
}

#[test]
fn op_0_inside_a_longer_script_is_written_by_its_name_723() {
    assert_eq!(
        Script::from_hex("760075").unwrap().to_asm(),
        "OP_DUP OP_0 OP_DROP"
    );
    assert_eq!(
        Script::from_hex("0003aabbcc").unwrap().to_asm(),
        "OP_0 aabbcc"
    );
}

#[test]
fn every_script_writes_the_references_asm_and_reads_it_back_723() {
    let v = vector();
    let bytes = cases(&v, "bytes");
    assert_eq!(bytes.len(), 8);
    for case in bytes {
        let id = s(case, "id");
        let hex = s(case, "hex");
        let reference = s(&case["ts"], "asm");
        let script = Script::from_hex(hex).unwrap();
        let asm = script.to_asm();
        assert_eq!(asm, reference, "{id}");
        assert_eq!(LockingScript::from_hex(hex).unwrap().to_asm(), asm, "{id}");
        assert_eq!(
            UnlockingScript::from_hex(hex).unwrap().to_asm(),
            asm,
            "{id}"
        );
        let back = Script::from_asm(&asm).unwrap().to_hex();
        assert_eq!(back, s(&case["ts"], "asm_back_hex"), "{id}");
        assert_eq!(back, hex, "{id}: round trip");
    }
}

#[test]
fn from_asm_reads_the_old_texts_and_the_names_as_the_reference_does_723() {
    let v = vector();
    let texts = cases(&v, "texts");
    assert_eq!(texts.len(), 10);
    for case in texts {
        let id = s(case, "id");
        let ts = &case["ts"];
        assert!(
            ts["error"].is_null(),
            "{id}: the reference reads every text"
        );
        let script = Script::from_asm(s(case, "text")).unwrap();
        assert_eq!(script.to_hex(), s(ts, "hex"), "{id}");
        assert_eq!(script.to_asm(), s(ts, "asm"), "{id}");
    }
}

#[test]
fn the_text_written_is_one_go_reads_and_the_old_text_is_not_723() {
    // The vector's Go column is `NewFromASM` transcribed: it reads every
    // text this crate now writes for `0x00` and `0x4f` to the reference's
    // bytes, and refuses each old text.
    let v = vector();
    for case in cases(&v, "texts") {
        let id = s(case, "id");
        let text = s(case, "text");
        let go = &case["go_transcribed"];
        let old = text.split(' ').any(|t| t == "0" || t == "-1");
        if old {
            assert_eq!(s(go, "error"), "ErrInvalidOpCode", "{id}");
        } else {
            assert_eq!(s(go, "hex"), s(&case["ts"], "hex"), "{id}");
        }
        let written = Script::from_asm(text).unwrap().to_asm();
        assert!(
            written.split(' ').all(|t| t != "0" && t != "-1"),
            "{id}: {written}"
        );
    }
}
