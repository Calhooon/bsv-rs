//! #634: a stray `OP_ENDIF` before `OP_RETURN`. `Script::parse_chunks`
//! counts an IF depth as it reads and ends the parse at an `OP_RETURN` read
//! at depth 0, the rest of the script that chunk's data. As the reference
//! does (`ts-stack@edf6e03` `Script.ts:599-631`), a stray `OP_ENDIF` takes the
//! depth below 0 (`:616`) and only `=== 0` ends the parse (`:608`), so
//! `686a51` (`OP_ENDIF OP_RETURN OP_1`) is three chunks (#634's fold; until
//! then this crate clamped the depth at 0 and read two). go-sdk@2ca481c's
//! `Script.Chunks()` (`DecodeScript`) lets it go negative too
//! (`script/script_chunk.go:255-257`) but reads `OP_RETURN` as an opcode only
//! at `> 0` (`:258-260`): two chunks on `686a51`, and on a stray `OP_ENDIF`
//! followed by an `OP_IF` around the `OP_RETURN` (depth -1 + 1 = 0) it ends
//! the parse as the reference does. go-sdk's interpreter's legacy parser
//! clamps at 0 (`interpreter/opcodeparser.go:389-401`); its
//! `ToASM` reader and its engine's parser count no depth and fold nothing
//! (`script_chunk.go:25-115`, `opcodeparser.go:218-266`); those are read from
//! the source, not recorded.
//! The node reads no chunks: `CScript::GetOp2` (bitcoin-sv v1.2.3 `6504a3a`
//! `src/script/script.h:165-198`) reads one opcode and its push with no depth,
//! and the interpreter judges both rules at run time: `OP_ENDIF` on an empty
//! conditional stack is `SCRIPT_ERR_UNBALANCED_CONDITIONAL`
//! (`interpreter.cpp:835-840`), `OP_RETURN` after Genesis on an empty stack
//! ends the script with success, inside an executed branch it stops execution
//! and the walk goes on checking the conditionals (`:856-871`, `:459`), inside
//! an unexecuted branch it is not executed (`:482`).
//!
//! The vector `tests/vectors/script_if_depth_634.json` is the reference's
//! reading of fifteen shapes (its chunks, `toASM`, its `Spend` verdict at
//! versions 1 and 2), written by `tests/support/script_if_depth_634.mjs` under
//! Node 22, with go-sdk's reading transcribed from its source (run once by
//! the cold read of #652). The shapes are this crate's writer's bytes. The
//! difference from go-sdk is stated (`CLAUDE.md`'s divergence list). The
//! verdicts are pinned in every mode, and pinned not to
//! depend on the chunking: the interpreter reaches a stray `OP_ENDIF` (and
//! refuses the script) before any `OP_RETURN` the readers fold differently.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use bsv_rs::primitives::{from_hex, to_hex};
use bsv_rs::script::{
    LockingScript, ProtocolEra, Script, ScriptChunk, ScriptFlags, Spend, SpendParams,
    UnlockingScript,
};
use serde_json::Value;

fn recorded() -> Value {
    let recorded: Value =
        serde_json::from_str(include_str!("vectors/script_if_depth_634.json")).unwrap();
    assert_eq!(recorded["runtime"].as_str().unwrap(), "node v22.18.0");
    recorded
}

fn shapes() -> Vec<Value> {
    recorded()["shapes"].as_array().unwrap().clone()
}

fn shape(id: &str) -> Value {
    shapes()
        .into_iter()
        .find(|s| s["id"] == id)
        .unwrap_or_else(|| panic!("unrecorded shape {id}"))
}

/// A chunk as the recording writes one: the opcode and its data's hex.
type Reading = Vec<(u8, Option<String>)>;

fn reading_of(chunks: &[ScriptChunk]) -> Reading {
    chunks
        .iter()
        .map(|c| (c.op, c.data.as_ref().map(|d| to_hex(d))))
        .collect()
}

fn recorded_reading(list: &Value) -> Reading {
    list.as_array()
        .unwrap()
        .iter()
        .map(|c| {
            (
                u8::try_from(c["op"].as_u64().unwrap()).unwrap(),
                c["data"].as_str().map(str::to_string),
            )
        })
        .collect()
}

fn chunks_of(reading: &Reading) -> Vec<ScriptChunk> {
    reading
        .iter()
        .map(|(op, data)| ScriptChunk::new(*op, data.as_ref().map(|d| from_hex(d).unwrap())))
        .collect()
}

fn ours(s: &Value) -> Reading {
    reading_of(
        &Script::from_hex(s["hex"].as_str().unwrap())
            .unwrap()
            .chunks(),
    )
}

fn reference(s: &Value) -> Reading {
    recorded_reading(&s["ts"]["chunks"])
}

fn go(s: &Value) -> Reading {
    assert!(s["go_transcribed"]["error"].is_null());
    recorded_reading(&s["go_transcribed"]["chunks"])
}

#[derive(Clone, Copy, Debug)]
enum Mode {
    /// No word, transaction version 1 (the reference's strict default).
    DefaultV1,
    /// No word, version 2 (relaxed; the coin after Chronicle by default).
    DefaultV2,
    /// A word for a block in an era, the coin created after Chronicle or not.
    Block(ProtocolEra, bool),
    Standard(ProtocolEra, bool),
}

const MODES: [Mode; 8] = [
    Mode::DefaultV1,
    Mode::DefaultV2,
    Mode::Block(ProtocolEra::PostGenesis, false),
    Mode::Standard(ProtocolEra::PostGenesis, false),
    Mode::Block(ProtocolEra::PostChronicle, false),
    Mode::Standard(ProtocolEra::PostChronicle, false),
    Mode::Block(ProtocolEra::PostChronicle, true),
    Mode::Standard(ProtocolEra::PostChronicle, true),
];

/// The shape as the locking script under the unlocking script `OP_1`, as the
/// recorder ran the reference's `Spend`.
fn verdict(lock: LockingScript, mode: Mode) -> Result<bool, String> {
    let mut s = Spend::new(SpendParams {
        source_txid: [0u8; 32],
        source_output_index: 0,
        source_satoshis: 1000,
        locking_script: lock,
        transaction_version: if matches!(mode, Mode::DefaultV1) {
            1
        } else {
            2
        },
        other_inputs: vec![],
        outputs: vec![],
        input_index: 0,
        unlocking_script: UnlockingScript::from_hex("51").unwrap(),
        input_sequence: 0xffff_ffff,
        lock_time: 0,
        memory_limit: None,
        work_limit: None,
    });
    match mode {
        Mode::DefaultV1 | Mode::DefaultV2 => {}
        Mode::Block(era, after) => {
            s.set_flags(ScriptFlags::block(era));
            s.set_utxo_after_chronicle(after);
        }
        Mode::Standard(era, after) => {
            s.set_flags(ScriptFlags::standard(era));
            s.set_utxo_after_chronicle(after);
        }
    }
    s.validate().map_err(|e| e.message)
}

const UNBALANCED_ENDIF: &str = "OP_ENDIF requires a preceeding OP_IF.";
const UNBALANCED_END: &str =
    "Every OP_IF, OP_NOTIF, or OP_ELSE must be terminated with OP_ENDIF prior to the end of the script.";

/// The shapes with an `OP_ENDIF` no conditional is open for, before an
/// `OP_RETURN`: the clamp's chunking of each was not the reference's.
const STRAY_ENDIF_BEFORE_RETURN: [&str; 8] = [
    "endif-return-op1",
    "endif-return-push",
    "if-endif-endif-return-push",
    "op1-if-endif-endif-return-op1",
    "endif-endif-return-op1",
    "nested-balanced-endif-return-op1",
    "endif-if-return-op1-endif",
    "balanced-endif-if-return-op1-endif",
];

/// Where go-sdk's chunks equal the reference's although a stray `OP_ENDIF`
/// comes first: an `OP_IF` around the `OP_RETURN`, the depth -1 + 1 = 0.
const GO_AGREES_AFTER_A_STRAY_ENDIF: [&str; 2] = [
    "endif-if-return-op1-endif",
    "balanced-endif-if-return-op1-endif",
];

/// The issue's script: three chunks, as the reference reads it (its depth
/// -1 at the `OP_RETURN`); two in go-sdk, whose `> 0` test reads -1 as the
/// top level, and two with the clamp this crate had until #634's fold.
#[test]
fn a_stray_endif_before_op_return_parses_as_three_chunks_the_if_depth_negative_634() {
    let s = shape("endif-return-op1");
    assert_eq!(s["hex"], "686a51");
    let script = Script::from_hex("686a51").unwrap();
    assert_eq!(
        reading_of(&script.chunks()),
        vec![(0x68, None), (0x6a, None), (0x51, None)]
    );
    assert_eq!(script.to_asm(), "OP_ENDIF OP_RETURN OP_1");
    assert_eq!(reference(&s), reading_of(&script.chunks()));
    assert_eq!(s["ts"]["asm"], "OP_ENDIF OP_RETURN OP_1");
    assert_eq!(go(&s), vec![(0x68, None), (0x6a, Some("51".to_string()))]);
    // The issue's other two forms: a push after the OP_RETURN, and a balanced
    // OP_IF OP_ENDIF before the stray one.
    for (id, n) in [
        ("endif-return-push", 3),
        ("if-endif-endif-return-push", 5),
        ("return-push", 1),
    ] {
        let s = shape(id);
        assert_eq!((ours(&s).len(), reference(&s).len()), (n, n), "{id}");
    }
}

/// Every shape is this crate's writer's bytes, and each reader's chunks write
/// back to them: the readers differ in where the data starts, not in the bytes.
#[test]
fn each_shape_is_this_crates_writers_bytes_and_every_chunking_writes_them_back_634() {
    let shapes = shapes();
    assert_eq!(shapes.len(), 15);
    for s in &shapes {
        let hex = s["hex"].as_str().unwrap();
        let id = &s["id"];
        assert_eq!(
            Script::from_asm(s["asm_in"].as_str().unwrap())
                .unwrap()
                .to_hex(),
            hex,
            "{id}"
        );
        assert_eq!(s["ts"]["to_hex"], hex, "{id}");
        for reading in [ours(s), reference(s), go(s)] {
            assert_eq!(
                Script::from_chunks(chunks_of(&reading)).to_hex(),
                hex,
                "{id}"
            );
        }
    }
}

/// The three readers on every shape: this crate's chunks are the reference's
/// on all fifteen, and go-sdk's everywhere but the six shapes whose
/// `OP_RETURN` follows a stray `OP_ENDIF` at a negative depth.
#[test]
fn the_chunks_are_the_references_and_part_from_go_sdk_after_a_stray_endif_634() {
    for s in shapes() {
        let id = s["id"].as_str().unwrap();
        assert_eq!(ours(&s), reference(&s), "{id} against the reference");
        let parts =
            STRAY_ENDIF_BEFORE_RETURN.contains(&id) && !GO_AGREES_AFTER_A_STRAY_ENDIF.contains(&id);
        assert_eq!(ours(&s) != go(&s), parts, "{id} against go-sdk");
    }
    // The shape row 26 asks of the reference: an OP_IF is open at the
    // OP_RETURN, yet the depth -1 + 1 = 0 reads it as the top level.
    let s = shape("endif-if-return-op1-endif");
    assert_eq!(s["hex"], "68636a5168");
    assert_eq!(reference(&s), go(&s));
    assert_eq!(
        ours(&s),
        vec![(0x68, None), (0x63, None), (0x6a, Some("5168".to_string()))]
    );
}

/// `from_asm(to_asm(s))` is `s` on every shape. A folded `OP_RETURN` is written
/// as `OP_RETURN` and the rest's own ASM (`OP_ENDIF OP_IF OP_RETURN OP_1
/// OP_ENDIF` on `68636a5168`); the reference writes the rest's hex alone
/// (`Script.ts:668-677`), `OP_ENDIF OP_IF 5168`, which its `fromASM` reads
/// back as a push (`:108-117`), as this crate's does: `6863025168`. A rest
/// whose ASM would not read back is written as raw bytes (`OP_RETURN 0x..`).
#[test]
fn the_asm_round_trips_on_every_shape_both_readings_of_op_return_included_634() {
    for s in shapes() {
        let (id, hex) = (s["id"].as_str().unwrap(), s["hex"].as_str().unwrap());
        let asm = Script::from_hex(hex).unwrap().to_asm();
        assert_eq!(Script::from_asm(&asm).unwrap().to_hex(), hex, "{id}: {asm}");
    }
    let asm = |hex: &str| Script::from_hex(hex).unwrap().to_asm();
    assert_eq!(asm("686a51"), "OP_ENDIF OP_RETURN OP_1");
    assert_eq!(asm("68636a5168"), "OP_ENDIF OP_IF OP_RETURN OP_1 OP_ENDIF");
    let theirs = shape("endif-if-return-op1-endif")["ts"]["asm"].clone();
    assert_eq!(theirs, "OP_ENDIF OP_IF 5168");
    let back = Script::from_asm(theirs.as_str().unwrap()).unwrap();
    assert_eq!(back.to_hex(), "6863025168");
    // A rest no ASM reads back (a truncated push), and a nested fold.
    for (hex, want) in [
        ("6a05aabb", "OP_RETURN 0x05aabb"),
        ("006a0568656c6c6f", "OP_0 OP_RETURN 68656c6c6f"),
        ("6a6a6a51", "OP_RETURN OP_RETURN OP_RETURN OP_1"),
    ] {
        assert_eq!(asm(hex), want);
        assert_eq!(Script::from_asm(want).unwrap().to_hex(), hex);
    }
    assert!(Script::from_asm("OP_1 0x51").is_err());
    assert!(Script::from_asm("OP_RETURN 0x51 OP_1").is_err());
}

/// An `OP_RETURN` with an empty rest is written as `OP_RETURN` alone, and an
/// empty raw token after it (`OP_RETURN 0x`) reads as that bare `OP_RETURN`:
/// the round trip holds on `6a` and `006a`, from the bytes and from the ASM.
/// The reference's parser gives a bare `OP_RETURN` an empty data array
/// (`Script.ts:609`), so its `toASM` writes `""` for `6a` and `"OP_0 "` for
/// `006a`, which its `fromASM` reads back as `00` and `0000`; its `fromASM`
/// has no raw token and refuses `OP_RETURN 0x` as invalid hex (recorded under
/// Node 22 at `edf6e03`).
#[test]
fn an_empty_raw_token_after_op_return_round_trips_634() {
    for (asm, hex, written) in [
        ("OP_RETURN 0x", "6a", "OP_RETURN"),
        ("0 OP_RETURN 0x", "006a", "OP_0 OP_RETURN"),
        ("OP_RETURN", "6a", "OP_RETURN"),
        ("0 OP_RETURN", "006a", "OP_0 OP_RETURN"),
    ] {
        let s = Script::from_asm(asm).unwrap();
        assert_eq!(s.to_hex(), hex, "{asm}");
        assert_eq!(s.to_asm(), written, "{asm}");
        assert_eq!(Script::from_asm(&s.to_asm()).unwrap(), s, "{asm}");
        let b = Script::from_hex(hex).unwrap();
        assert_eq!(b.to_asm(), written, "{hex}");
        assert_eq!(Script::from_asm(&b.to_asm()).unwrap().to_hex(), hex);
    }
    // A chunk built by hand with empty data writes and reads back the same.
    let held = Script::from_chunks(vec![
        ScriptChunk::new(0x00, None),
        ScriptChunk::new(0x6a, Some(vec![])),
    ]);
    assert_eq!(held.to_asm(), "OP_0 OP_RETURN");
    assert_eq!(Script::from_asm(&held.to_asm()).unwrap(), held);
}

/// `from_asm(to_asm(s))` is `s` for an `OP_RETURN` followed by 200,000
/// random rests of 0 to 8 bytes, at the top level and after an `OP_0`.
#[test]
fn the_asm_round_trips_on_random_rests_after_op_return_634() {
    let mut x: u64 = 0x9e37_79b9_7f4a_7c15;
    let mut next = || {
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        x
    };
    for _ in 0..200_000 {
        let r = next();
        let mut bytes = if r & 1 == 0 {
            vec![0x6a]
        } else {
            vec![0x00, 0x6a]
        };
        let len = (r >> 1) % 9;
        bytes.extend((0..len).map(|_| next() as u8));
        let asm = Script::from_binary(&bytes).unwrap().to_asm();
        let back = Script::from_asm(&asm).unwrap().to_binary();
        assert_eq!(back, bytes, "{}: {asm}", to_hex(&bytes));
    }
}

/// The interpreter refuses every shape whose walk reaches the stray
/// `OP_ENDIF`, in every mode, as the node refuses it
/// (`SCRIPT_ERR_UNBALANCED_CONDITIONAL`, `interpreter.cpp:835-840`); the
/// default mode's words and verdicts are the reference's `Spend`'s.
#[test]
fn a_stray_endif_is_refused_as_unbalanced_in_every_mode_634() {
    for id in STRAY_ENDIF_BEFORE_RETURN {
        let s = shape(id);
        let lock = || LockingScript::from_hex(s["hex"].as_str().unwrap()).unwrap();
        for mode in MODES {
            assert_eq!(
                verdict(lock(), mode),
                Err(UNBALANCED_ENDIF.to_string()),
                "{id} {mode:?}"
            );
        }
    }
}

/// Every verdict in every mode, on this crate's chunks, the reference's and
/// go-sdk's: the same verdict whichever reader split the script, and in the
/// default mode the reference's recorded verdict.
#[test]
fn the_verdict_does_not_depend_on_the_chunking_634() {
    let ok = Ok(true);
    let endif = Err(UNBALANCED_ENDIF.to_string());
    let end = Err(UNBALANCED_END.to_string());
    for s in shapes() {
        let id = s["id"].as_str().unwrap();
        let expected: [&Result<bool, String>; 8] = if STRAY_ENDIF_BEFORE_RETURN.contains(&id) {
            [&endif; 8]
        } else if id == "false-if-verif-endif-return-op1" {
            // OP_VERIF in an unexecuted branch: the reference's default and a
            // coin created after Chronicle open a conditional with it, so the
            // OP_RETURN is skipped and the script ends unbalanced; a coin
            // created before skips it (`interpreter.cpp:773-781`), the
            // OP_ENDIF closes the OP_IF and the OP_RETURN ends the script at
            // the top level.
            [&end, &end, &ok, &ok, &ok, &ok, &end, &end]
        } else {
            [&ok; 8]
        };
        for (mode, expected) in MODES.into_iter().zip(expected) {
            for (reader, reading) in [
                ("ours", ours(&s)),
                ("reference", reference(&s)),
                ("go-sdk", go(&s)),
            ] {
                assert_eq!(
                    &verdict(LockingScript::from_chunks(chunks_of(&reading)), mode),
                    expected,
                    "{id} {mode:?} on {reader}'s chunks"
                );
            }
        }
        for (mode, version) in [(Mode::DefaultV1, "v1"), (Mode::DefaultV2, "v2")] {
            let theirs = &s["ts_spend"][version];
            let theirs = match theirs["valid"].as_bool() {
                Some(valid) => Ok(valid),
                None => Err(theirs["error"]
                    .as_str()
                    .unwrap()
                    .strip_prefix("Script evaluation error: ")
                    .unwrap()
                    .to_string()),
            };
            let lock = LockingScript::from_hex(s["hex"].as_str().unwrap()).unwrap();
            assert_eq!(
                verdict(lock, mode),
                theirs,
                "{id} {version} against the reference"
            );
        }
    }
}
