//! #634: a stray `OP_ENDIF` before `OP_RETURN`. `Script::parse_chunks`
//! counts an IF depth as it reads and ends the parse at an `OP_RETURN` read
//! at depth 0, the rest of the script that chunk's data; a stray `OP_ENDIF`
//! leaves the depth at 0 (`(in_conditional_block - 1).max(0)`), so `686a51`
//! (`OP_ENDIF OP_RETURN OP_1`) is two chunks here. The reference lets the
//! depth go negative (`ts-stack@edf6e03` `Script.ts:616`) and ends the parse
//! only at `=== 0` (`:608`): three chunks. go-sdk@2ca481c's `Script.Chunks()`
//! (`DecodeScript`) lets it go negative too (`script/script_chunk.go:255-257`)
//! but reads `OP_RETURN` as an opcode only at `> 0` (`:258-260`): two chunks
//! on `686a51`, and on a stray `OP_ENDIF` followed by an `OP_IF` around the
//! `OP_RETURN` (depth -1 + 1 = 0) both other readers end the parse where this
//! crate's (depth 0 + 1 = 1) does not. go-sdk's interpreter's legacy parser
//! clamps at 0 as this crate does (`interpreter/opcodeparser.go:389-401`); its
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
//! Node 22, with go-sdk's reading transcribed from its source (not run). The
//! shapes are this crate's writer's bytes. No behaviour changes here: the
//! difference is stated (`CLAUDE.md`'s divergence list) and its door is the
//! reads' call. The verdicts are pinned in every mode, and pinned not to
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
/// `OP_RETURN`: the reference's chunking of each is not this crate's, and
/// go-sdk's is not on the two of `GO_DIFFERS`.
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

/// Where go-sdk's chunks are not this crate's: a stray `OP_ENDIF` then an
/// `OP_IF` around the `OP_RETURN`, the depth -1 + 1 = 0 there.
const GO_DIFFERS: [&str; 2] = [
    "endif-if-return-op1-endif",
    "balanced-endif-if-return-op1-endif",
];

/// The issue's script: two chunks here, the `OP_RETURN` at the clamped depth
/// 0 ending the parse with `OP_1` its data; three in the reference, whose
/// depth is -1 there; two in go-sdk, whose `> 0` test reads -1 as the top
/// level.
#[test]
fn a_stray_endif_before_op_return_parses_as_two_chunks_the_if_depth_clamped_at_0_634() {
    let s = shape("endif-return-op1");
    assert_eq!(s["hex"], "686a51");
    let script = Script::from_hex("686a51").unwrap();
    assert_eq!(
        reading_of(&script.chunks()),
        vec![(0x68, None), (0x6a, Some("51".to_string()))]
    );
    assert_eq!(script.to_asm(), "OP_ENDIF 51");
    assert_eq!(
        reference(&s),
        vec![(0x68, None), (0x6a, None), (0x51, None)]
    );
    assert_eq!(s["ts"]["asm"], "OP_ENDIF OP_RETURN OP_1");
    assert_eq!(go(&s), reading_of(&script.chunks()));
    // The issue's other two forms: a push after the OP_RETURN, and a balanced
    // OP_IF OP_ENDIF before the stray one.
    for (id, ours_n, reference_n) in [
        ("endif-return-push", 2, 3),
        ("if-endif-endif-return-push", 4, 5),
        ("return-push", 1, 1),
    ] {
        let s = shape(id);
        assert_eq!(
            (ours(&s).len(), reference(&s).len()),
            (ours_n, reference_n),
            "{id}"
        );
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

/// The three readers on every shape: this crate's chunks equal the
/// reference's exactly where no stray `OP_ENDIF` comes before the
/// `OP_RETURN`, and go-sdk's everywhere but the two shapes whose stray
/// `OP_ENDIF` is followed by an `OP_IF` around the `OP_RETURN`.
#[test]
fn the_readers_differ_only_after_a_stray_endif_634() {
    for s in shapes() {
        let id = s["id"].as_str().unwrap();
        let stray = STRAY_ENDIF_BEFORE_RETURN.contains(&id);
        assert_eq!(
            ours(&s) == reference(&s),
            !stray,
            "{id} against the reference"
        );
        assert_eq!(
            ours(&s) == go(&s),
            !GO_DIFFERS.contains(&id),
            "{id} against go-sdk"
        );
    }
    // The three-way shape: five chunks here, three in both others.
    let s = shape("endif-if-return-op1-endif");
    assert_eq!(s["hex"], "68636a5168");
    assert_eq!(ours(&s).len(), 5);
    assert_eq!(reference(&s), go(&s));
    assert_eq!(
        reference(&s),
        vec![(0x68, None), (0x63, None), (0x6a, Some("5168".to_string()))]
    );
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
