//! `Script::parse_chunks` (`src/script/script.rs`, shard B of #603) on the
//! sibling's corpus entries: the 28 mutants the widened oracle left in the
//! chunk parser (run 41327640129), 24 killed here, each by a vector copied by
//! its id with the expectation its corpus records; the other four, the `|` of
//! the little-endian size reads replaced with `^`, are declared equivalent in
//! `.cargo/mutants.toml`.
//!
//! The rule is the node's `GetOp` as the sibling's Lean definition states it
//! (`~/bsv/bsv-script-lean` at `5dc337e1`, `lean/BsvScript/Machine.lean`):
//!
//! * `getOpTail` (`:29-50`, `CScript::GetOp2`, bitcoin-sv `script.h:165-200`):
//!   below `OP_PUSHDATA1` the opcode is the size (`:32`); `OP_PUSHDATA1`,
//!   `OP_PUSHDATA2` and `OP_PUSHDATA4` read one, two and four little-endian
//!   size bytes, `a + 256 * b` (`:39`) and `a + 256 * (b + 256 * (c + 256 *
//!   d))` (`:43`); a short size word or a short body fails the parse
//!   (`:36,40,44,49`); an opcode above `OP_PUSHDATA4` consumes nothing and
//!   pushes nothing (`:50`).
//! * A failed `GetOp` is `SCRIPT_ERR_BAD_OPCODE` when the walk reaches it,
//!   executed or not (`interpreter.cpp:450-451`): nothing after it is an
//!   instruction. This crate keeps the truncated push as the script's last
//!   chunk, its data the bytes that remain (0.3.27, bsv-rs#12), and
//!   `Script::truncated_push` names its index.
//! * A top-level `OP_RETURN` post-Genesis ends the script (`:342-344`,
//!   `interpreter.cpp:856-871`); this crate's chunk holds the bytes after it
//!   as data, as the reference's parser does (`ts-stack@edf6e03`
//!   `packages/sdk/src/script/Script.ts:608-611`). Inside a conditional,
//!   `OP_IF`, `OP_NOTIF`, `OP_VERIF` and `OP_VERNOTIF` each open one
//!   (`Script.ts:613-617`; post-Chronicle the last two are conditionals of
//!   the node's too, `Machine.lean:326-329`), and the `OP_RETURN` is an
//!   opcode with the walk going on.
//!
//! The vectors: the sibling's `corpus/flow` and `corpus/seed` (each entry's
//! spend run under the configuration its `bsv-rs@0.7.0` verdict was recorded
//! with, the standard word of the post-Chronicle era), `corpus/bytes`, and
//! `corpus/cpp` (the node's own unit-test vectors, `sv-node-unit@v1.2.2`:
//! `cscript_tests.cpp`'s `GetOp2`, `instruction_iterator_tests.cpp`'s decoder
//! and iterator, `sighash_tests.cpp`'s digests); and the ts-stack corpus at
//! `edf6e03` (`conformance/vectors/sdk/scripts/evaluation.json`: `script-001`
//! and the node's `script_tests.json` #74). A run of the sibling's harness
//! (`harness/run --impl bsv-rs --corpus all --spec recorded`, then `road`,
//! `million` and `xsig-144`) under each mutant moved the verdicts of 18 of
//! the 28 (each a panic of the parser on a short size word); the other ten
//! move a chunk, a separator removal or nothing (the four equivalents).
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)] // #134: test code: a failed unwrap is the test failing

use bsv_rs::primitives::bsv::sighash::{
    compute_sighash_original_for_signing, parse_transaction, SighashParams, TxOutput,
};
use bsv_rs::primitives::{from_hex, to_hex};
use bsv_rs::script::op::{OP_PUSHDATA4, OP_RETURN};
use bsv_rs::script::{
    LockingScript, ProtocolEra, Script, ScriptChunk, ScriptFlags, Spend, SpendParams,
    UnlockingScript,
};

/// A sibling corpus entry: one input, one output, the previous output's script
/// and the verdict recorded for this crate (`bsv-rs@0.7.0`).
struct Entry {
    id: &'static str,
    tx_hex: &'static str,
    prevout_script_hex: &'static str,
    /// `None` valid; `Some(reason)` the recorded refusal's words.
    refused: Option<&'static str>,
}

/// The recorded refusal of a truncated push at instruction `pc`.
macro_rules! truncated_at {
    ($pc:literal) => {
        concat!(
            "A push declares more bytes than the script holds; the script cannot be parsed past it (pc=",
            $pc,
            ")."
        )
    };
}

/// `corpus/flow/flow.jsonl` `flow-00751` (`flow/truncated-push`, "unlock:
/// PUSHDATA2 with one length byte"): scriptSig `4d01`; invalid, recorded at
/// pc 0 (the node: `SCRIPT_ERR_BAD_OPCODE`).
const FLOW_00751: Entry = Entry {
    id: "flow-00751",
    tx_hex: "020000000162a149f3d3dd7594129dfabc699fad281e707342eacf99655a634f17d3ad055900000000024d01ffffffff010100000000000000015100000000",
    prevout_script_hex: "51",
    refused: Some(truncated_at!("0")),
};

/// `flow-00752` (`flow/truncated-push/v1`), the version-1 twin of flow-00751.
const FLOW_00752: Entry = Entry {
    id: "flow-00752",
    tx_hex: "01000000014a882b006e84ee2aa6a9bd04b85a1fa9e2a55172be01304037355ee0c14fdbed00000000024d01ffffffff010100000000000000015100000000",
    prevout_script_hex: "51",
    refused: Some(truncated_at!("0")),
};

/// `flow-00753` (`flow/truncated-push`, "unlock: PUSHDATA4 with three length
/// bytes"): scriptSig `4e010000`; invalid at pc 0.
const FLOW_00753: Entry = Entry {
    id: "flow-00753",
    tx_hex: "0200000001e5e6ac81cc3f2a53a3738b1c71cb058a118459013cb3b242dff1f10edbadca6e00000000044e010000ffffffff010100000000000000015100000000",
    prevout_script_hex: "51",
    refused: Some(truncated_at!("0")),
};

/// `flow-00754` (`flow/truncated-push/v1`), the version-1 twin of flow-00753.
const FLOW_00754: Entry = Entry {
    id: "flow-00754",
    tx_hex: "010000000135c0d47488d958a6809ffc2728f4d6f82c4b54796d59374e9e4779728271da0700000000044e010000ffffffff010100000000000000015100000000",
    prevout_script_hex: "51",
    refused: Some(truncated_at!("0")),
};

/// `corpus/seed/seed.jsonl` `seed-000397` (`mutation/lock`): the locking
/// script `950307845c844e` ends in a bare `OP_PUSHDATA4`; invalid at pc 3.
const SEED_000397: Entry = Entry {
    id: "seed-000397",
    tx_hex: "0200000001fa071316de0f4a3985074aee05b0f3a15b85f0b4b8d09d9545096e7af8123906000000000603f65b840111ffffffff010100000000000000015100000000",
    prevout_script_hex: "950307845c844e",
    refused: Some(truncated_at!("3")),
};

/// `seed-001993` (`mutation/unlock`): the scriptSig ends `4ebcbc`, a
/// PUSHDATA4 with two size bytes; refused by `OP_XOR` at pc 1 before the walk
/// reaches it.
const SEED_001993: Entry = Entry {
    id: "seed-001993",
    tx_hex: "02000000019d31a4f3853d321d07ab7ab5fbcb77a1fc598ad248250df0f2aa9e46f77f3b9a000000000e08d322ff017476740186bc4ebcbcffffffff010100000000000000015100000000",
    prevout_script_hex: "8f08d322ff017476bc3c87",
    refused: Some("OP_XOR requires at least two items on the stack."),
};

/// `seed-003106` (`mutation/unlock`): the scriptSig ends `f34ef2dd00`, an
/// undefined opcode and a PUSHDATA4 with three size bytes; refused by the
/// opcode at pc 1.
const SEED_003106: Entry = Entry {
    id: "seed-003106",
    tx_hex: "0200000001aa2e5fa88d4521d37748a9524fdf46821969cbff35ebd0d3323d8fefded77c64000000000e0895f179f179f34ef2f34ef2dd00ffffffff010100000000000000015100000000",
    prevout_script_hex: "900896b179f344f2dd2b87",
    refused: Some("Invalid opcode 243 (pc=1)."),
};

/// `seed-006614` (`mutation/unlock`): the scriptSig ends `4e97`, a PUSHDATA4
/// with one size byte; invalid at pc 1.
const SEED_006614: Entry = Entry {
    id: "seed-006614",
    tx_hex: "020000000135d31faaee6b2d64f22eb87ef38f932212facba1096db5a5ddb14d75b110f1ce000000000b089d75df06e17651c94e97ffffffff010100000000000000015100000000",
    prevout_script_hex: "90089d06e17651c9641787",
    refused: Some(truncated_at!("1")),
};

/// `seed-009101` (`mutation/unlock`): scriptSig `000000004e86030e0000`, a
/// whole size word `86030e00` (918,406 bytes) over one; invalid at pc 4.
const SEED_009101: Entry = Entry {
    id: "seed-009101",
    tx_hex: "0200000001d5ca1b41a13ec10ce9d7b26f8455043b682f36e3100c445ca2392d7a8d331e01000000000a000000004e86030e0000ffffffff010100000000000000015100000000",
    prevout_script_hex: "94038ee00887",
    refused: Some(truncated_at!("4")),
};

/// `seed-009157` (`mutation/unlock`): scriptSig
/// `4e000080000886fe05d09e17cf38`, a size word `00008000` (8,388,608 bytes,
/// its third byte set) over nine; invalid at pc 0.
const SEED_009157: Entry = Entry {
    id: "seed-009157",
    tx_hex: "02000000010b5e42987ffd54643e08b0a2be55fbb6e8f4375bae03fa4358ec54cb7f76fc67000000000e4e000080000886fe05d09e17cf38ffffffff010100000000000000015100000000",
    prevout_script_hex: "965187",
    refused: Some(truncated_at!("0")),
};

/// `seed-009276` (`mutation/unlock`): scriptSig `80feffffffff4eff3f`, a
/// PUSHDATA4 with two size bytes after `OP_NUM2BIN`, which refuses first.
const SEED_009276: Entry = Entry {
    id: "seed-009276",
    tx_hex: "02000000016d8544acb989af8b7351b29148fb4b2b52ab270b162a09f1f1d22581ceeba63a000000000980feffffffff4eff3fffffffff010100000000000000015100000000",
    prevout_script_hex: "8c08feffffffffffff3f87",
    refused: Some("OP_NUM2BIN requires at least two items to be on the stack."),
};

/// `corpus/bytes/cases.jsonl` `bytes-00107` (`bytes/6a`, "byte 0x6a as the
/// locking script on the stack 1 2 3 4 5 6, version 2"): valid.
const BYTES_00107: Entry = Entry {
    id: "bytes-00107",
    tx_hex: "02000000013eb78a56a45928e81b160b0f9607acc8306518e8e6085c516a8594f418d35d8a0000000006515253545556ffffffff010100000000000000015100000000",
    prevout_script_hex: "6a",
    refused: None,
};

/// The entry's scriptSig bytes, as the transaction carries them.
fn script_sig(e: &Entry) -> Vec<u8> {
    let tx = parse_transaction(&from_hex(e.tx_hex).unwrap()).expect("a parseable transaction");
    assert_eq!(tx.inputs.len(), 1, "{}: one input", e.id);
    tx.inputs[0].script.clone()
}

/// Runs the entry's input under the configuration its `bsv-rs@0.7.0` verdict
/// was recorded with (the harness's `EngineConfig::default`: the standard word
/// of the post-Chronicle era, `0x3D47FF`; the coin's 1,000 satoshis) and
/// asserts the recorded verdict.
fn assert_recorded_verdict(e: &Entry) {
    let tx = parse_transaction(&from_hex(e.tx_hex).unwrap()).unwrap();
    let input = &tx.inputs[0];
    let outputs: Vec<TxOutput> = tx
        .outputs
        .iter()
        .map(|o| TxOutput {
            satoshis: o.satoshis,
            script: o.script.clone(),
        })
        .collect();
    let mut spend = Spend::new(SpendParams {
        source_txid: input.txid,
        source_output_index: input.output_index,
        source_satoshis: 1000,
        locking_script: LockingScript::from_hex(e.prevout_script_hex).unwrap(),
        transaction_version: tx.version,
        other_inputs: Vec::new(),
        outputs,
        input_index: 0,
        unlocking_script: UnlockingScript::from_binary(&input.script).unwrap(),
        input_sequence: input.sequence,
        lock_time: tx.locktime,
        memory_limit: None,
        work_limit: None,
    });
    spend.set_flags(ScriptFlags::standard(ProtocolEra::PostChronicle));
    let got = spend.validate().map_err(|err| err.message);
    match e.refused {
        None => assert_eq!(got, Ok(true), "{}: the recorded verdict is valid", e.id),
        Some(reason) => {
            let msg = got.expect_err(&format!("{}: the recorded verdict is invalid", e.id));
            assert!(
                msg.contains(reason),
                "{}: expected {reason:?}, got {msg:?}",
                e.id
            );
        }
    }
}

/// A chunk as `(opcode, data)`, for the comparisons below.
fn shape(script: &Script) -> Vec<(u8, Option<Vec<u8>>)> {
    script
        .chunks()
        .into_iter()
        .map(|c| (c.op, c.data))
        .collect()
}

fn hex(h: &str) -> Vec<u8> {
    from_hex(h).unwrap()
}

/// `OP_PUSHDATA2` and `OP_PUSHDATA4` with a short size word, as the flow
/// family writes them (`flow/truncated-push`, flow-00751 to flow-00754): the
/// size bytes are read only where they are (`Machine.lean:40,44`, a short word
/// fails the parse), so the push is the script's one chunk, empty, its index
/// the truncated push's, and the spend refused at pc 0 as recorded. Kills
/// `src/script/script.rs:252:33` (`*`, `-`) and `252:37` (`<=`), the second
/// size byte of `OP_PUSHDATA2` read past the script (flow-00751, flow-00752),
/// and `275:33` (`*`), `275:37` (`==`, `<=`), the fourth of `OP_PUSHDATA4`
/// (flow-00753, flow-00754): each one an index past the bytes, a panic.
#[test]
fn push_truncated_flow_truncated_push_flow_00751_00752_00753_00754() {
    for (e, op) in [
        (&FLOW_00751, 0x4d),
        (&FLOW_00752, 0x4d),
        (&FLOW_00753, 0x4e),
        (&FLOW_00754, 0x4e),
    ] {
        let unlocking = Script::from_binary(&script_sig(e)).unwrap();
        assert_eq!(
            shape(&unlocking),
            vec![(op, Some(Vec::new()))],
            "{}: the short size word is one empty push and nothing after it",
            e.id
        );
        assert_eq!(unlocking.truncated_push(), Some(0), "{}", e.id);
        assert_recorded_verdict(e);
    }
}

/// `OP_PUSHDATA4`'s four size bytes on the seed family's mutated scripts
/// (`Machine.lean:43`): each byte read only when the script holds it, and the
/// spend's verdict the recorded one, a refusal at the truncated push
/// (seed-000397 at pc 3, seed-006614 at 1, seed-009101 at 4) or at an earlier
/// instruction (seed-001993's `OP_XOR`, seed-003106's undefined opcode,
/// seed-009276's `OP_NUM2BIN`). Under every mutant below the parser indexes
/// past the bytes and panics before any verdict: `264:33` (`<=`, the first
/// size byte; seed-000397), `265:33` (`*`, `-`) and `265:37` (`<=`, the
/// second; seed-006614, seed-000397), `270:37` (`==`, `<=`, `>`, the third;
/// seed-001993, seed-009276, seed-000397, seed-006614), `271:31` (`*`, the
/// third read at `pos * 2`; seed-003106, seed-009101), `275:37` (`>`, the
/// fourth; seed-000397) and `275:37` (`==`, `<=`; seed-003106).
#[test]
fn pushdata4_size_word_seed_mutation_000397_001993_003106_006614_009101_009276() {
    for e in [
        &SEED_000397,
        &SEED_001993,
        &SEED_003106,
        &SEED_006614,
        &SEED_009101,
        &SEED_009276,
    ] {
        assert_recorded_verdict(e);
    }

    // seed-000397's locking script: `OP_ABS` (0x95), a three-byte push, `OP_SUB`
    // (0x94) and a bare `OP_PUSHDATA4`, which takes no size byte (`:44`).
    let lock = Script::from_binary(&hex(SEED_000397.prevout_script_hex)).unwrap();
    assert_eq!(
        shape(&lock),
        vec![
            (0x95, None),
            (0x03, Some(hex("07845c"))),
            (0x84, None),
            (0x4e, Some(Vec::new())),
        ],
        "seed-000397"
    );
    assert_eq!(lock.truncated_push(), Some(3), "seed-000397");

    // seed-009101's scriptSig: four `OP_0`s, then the size word `86030e00`
    // (`a + 256 * (b + 256 * (c + 256 * d))` = 918,406) over the one byte
    // left: one chunk holding it.
    let sig = Script::from_binary(&script_sig(&SEED_009101)).unwrap();
    assert_eq!(
        shape(&sig),
        vec![
            (0x00, None),
            (0x00, None),
            (0x00, None),
            (0x00, None),
            (0x4e, Some(vec![0x00])),
        ],
        "seed-009101"
    );
    assert_eq!(sig.truncated_push(), Some(4), "seed-009101");
}

/// The size word's third byte weighs `256 * 256` (`Machine.lean:43`):
/// seed-009157's `4e 00008000` declares 8,388,608 bytes over the nine its
/// scriptSig holds, a failed parse at the first instruction, so the push is
/// the one chunk and holds the nine; refused at pc 0 as recorded. Kills
/// `280:49` (`<<` to `>>` on the third byte) and `280:56` (`|` to `&`, which
/// binds first: `(b2 << 16) & (b3 << 24)`, the third byte dropped), each
/// reading the size as 0 and splitting the nine bytes into an empty push and
/// an eight-byte one; with them `270:37` (`==`, `>`) and `271:31` (`*`), which
/// read the third byte from elsewhere.
#[test]
fn pushdata4_third_size_byte_seed_mutation_seed_009157() {
    let sig = Script::from_binary(&script_sig(&SEED_009157)).unwrap();
    assert_eq!(
        shape(&sig),
        vec![(0x4e, Some(hex("0886fe05d09e17cf38")))],
        "seed-009157: the declared 0x00800000 bytes are more than the script holds"
    );
    assert_eq!(sig.truncated_push(), Some(0), "seed-009157");
    assert_recorded_verdict(&SEED_009157);
}

/// The node's `GetOp2` and `decode_instruction` on short pushes (`corpus/cpp`,
/// recorded `sv-node-unit@v1.2.2`): `cscript_tests.cpp:64` (cpp-cscript-00001
/// to 00014, `returns: false`) and `instruction_iterator_tests.cpp:102`
/// (cpp-instruction_iterator-00001 to 00019, `status: false`), every one
/// failing at offset 0, so each is one chunk, its opcode the first byte, the
/// truncated push at index 0. Kills `251:33` (`<=`, `OP_PUSHDATA2`'s first
/// size byte read at the end of `4d`: cpp-cscript-00007,
/// cpp-instruction_iterator-00010) and `270:33` (`*`, `OP_PUSHDATA4`'s third
/// size byte read at `pos * 2` past `4e0101`: cpp-instruction_iterator-00016),
/// both panics, and with them every short-word mutant of the two tests above.
#[test]
fn get_op_refuses_a_short_push_cpp_cscript_get_op2_and_decode_instruction() {
    let cscript: [(&str, &str); 14] = [
        ("cpp-cscript-00001", "01"),
        ("cpp-cscript-00002", "02"),
        ("cpp-cscript-00003", "0201"),
        ("cpp-cscript-00004", "4b01"),
        ("cpp-cscript-00005", "4c"),
        ("cpp-cscript-00006", "4c01"),
        ("cpp-cscript-00007", "4d"),
        ("cpp-cscript-00008", "4d01"),
        ("cpp-cscript-00009", "4d0001"),
        ("cpp-cscript-00010", "4e"),
        ("cpp-cscript-00011", "4e01"),
        ("cpp-cscript-00012", "4e0001"),
        ("cpp-cscript-00013", "4e000001"),
        ("cpp-cscript-00014", "4e00000001"),
    ];
    let decode: [(&str, &str); 19] = [
        ("cpp-instruction_iterator-00001", "01"),
        ("cpp-instruction_iterator-00002", "02"),
        ("cpp-instruction_iterator-00003", "022a"),
        ("cpp-instruction_iterator-00004", "4b"),
        ("cpp-instruction_iterator-00005", "4b01"),
        ("cpp-instruction_iterator-00006", "4b0102"),
        ("cpp-instruction_iterator-00007", "4c"),
        ("cpp-instruction_iterator-00008", "4c01"),
        ("cpp-instruction_iterator-00009", "4c022a"),
        ("cpp-instruction_iterator-00010", "4d"),
        ("cpp-instruction_iterator-00011", "4d01"),
        ("cpp-instruction_iterator-00012", "4d0100"),
        ("cpp-instruction_iterator-00013", "4d02002a"),
        ("cpp-instruction_iterator-00014", "4e"),
        ("cpp-instruction_iterator-00015", "4e01"),
        ("cpp-instruction_iterator-00016", "4e0101"),
        ("cpp-instruction_iterator-00017", "4e010101"),
        ("cpp-instruction_iterator-00018", "4e01000000"),
        ("cpp-instruction_iterator-00019", "4e020000002a"),
    ];
    for (id, h) in cscript.iter().chain(decode.iter()) {
        let bytes = hex(h);
        let script = Script::from_binary(&bytes).unwrap();
        let chunks = script.chunks();
        assert_eq!(
            chunks.len(),
            1,
            "{id}: the failed instruction and nothing after it"
        );
        assert_eq!(chunks[0].op, bytes[0], "{id}");
        assert_eq!(
            script.truncated_push(),
            Some(0),
            "{id}: the decoder fails at offset 0"
        );
    }
}

/// The node's instruction iterator over a whole push followed by a short one
/// (`instruction_iterator_tests.cpp:188`, cpp-instruction_iterator-00021,
/// `4e010000002a4e01000000`, recorded: two instructions, the first
/// `OP_PUSHDATA4` with a one-byte operand at offset 5, the second the failure
/// sentinel); and the short one alone (`:166`, cpp-instruction_iterator-00020,
/// `4e01000000`, one instruction, the failure). The size word `01000000` is 1
/// (`Machine.lean:43`). The second push's size word is read where the script
/// holds it: under `271:31` (`*`, the third size byte read at `pos * 2`) the
/// parser indexes past the eleven bytes and panics. No survivor falls to this
/// test alone: it pins the iterator's two instructions.
#[test]
fn instruction_iterator_pushdata4_size_word_cpp_instruction_iterator_00020_00021() {
    let two = Script::from_binary(&hex("4e010000002a4e01000000")).unwrap();
    assert_eq!(
        shape(&two),
        vec![(0x4e, Some(vec![0x2a])), (0x4e, Some(Vec::new()))],
        "cpp-instruction_iterator-00021: opcode 78 with its one-byte operand, then the failure"
    );
    assert_eq!(
        two.truncated_push(),
        Some(1),
        "cpp-instruction_iterator-00021"
    );

    let one = Script::from_binary(&hex("4e01000000")).unwrap();
    assert_eq!(
        shape(&one),
        vec![(0x4e, Some(Vec::new()))],
        "cpp-instruction_iterator-00020: the failure alone"
    );
    assert_eq!(
        one.truncated_push(),
        Some(0),
        "cpp-instruction_iterator-00020"
    );
}

/// The size word's fourth byte weighs `2^24` (`Machine.lean:43`; the size word
/// `00000001` of cpp-cscript-00014, which the node's `GetOp2` refuses over no
/// body): with its 16,777,216 bytes present the node reads one push
/// (`:49`). The script is built by this crate's writer (`write_bin` takes
/// `OP_PUSHDATA4` above 65,535 bytes) and a trailing `OP_1`; read back, it is
/// the push and the `OP_1`. Kills `280:62` (`<<` to `>>` on the fourth byte),
/// which reads the size as 0 and the body as instructions (its first byte,
/// `OP_RETURN`, then swallows the rest). No corpus entry carries a size word
/// with its fourth byte set and anything after it: cpp-cscript-00014 parses
/// to one empty chunk either way. `280:56` (`&`) and `275:37` (`==`, `>`) fail
/// here too.
#[test]
fn pushdata4_fourth_size_byte_cpp_cscript_00014_with_its_body() {
    let body = vec![OP_RETURN; 1 << 24];
    let mut written = Script::new();
    written.write_bin(&body).write_opcode(0x51);
    let bytes = written.to_binary();
    assert_eq!(bytes[..5], [OP_PUSHDATA4, 0x00, 0x00, 0x00, 0x01]);

    let read = Script::from_binary(&bytes).unwrap();
    let chunks = read.chunks();
    assert_eq!(chunks.len(), 2, "the 2^24-byte push and OP_1");
    assert_eq!(chunks[0].op, OP_PUSHDATA4);
    assert_eq!(chunks[0].data.as_ref().map(Vec::len), Some(1 << 24));
    assert_eq!(chunks[1], ScriptChunk::new_opcode(0x51));
    assert_eq!(read.truncated_push(), None);
}

/// `sighash_tests.cpp:152`'s scriptCode `656a6a00ab` (cpp-sighash-00018,
/// recorded original digest `a19bbf4e...`): `OP_VERIF`, `OP_RETURN`,
/// `OP_RETURN`, `OP_0`, `OP_CODESEPARATOR`. The node's `GetOp` reads five
/// instructions (`Machine.lean:29-50`, none a push but `OP_0`'s empty one),
/// and `SerializeScriptCode` writes the four before the separator
/// (`interpreter.cpp:1864-1892`), which is the digest recorded. The crate's
/// parser agrees because `OP_VERIF` opens a conditional (`Script.ts:613-615`;
/// post-Chronicle the node's too, `Machine.lean:326-329`), so the `OP_RETURN`
/// after it is an opcode and the separator one too: `remove_codeseparators`
/// leaves the bytes the digest covers. Kills `225:64` (`||` to `&&` before
/// `OP_VERNOTIF`), under which neither `OP_VERIF` nor `OP_VERNOTIF` opens one,
/// the first `OP_RETURN` takes `6a00ab` as data and no separator is removed.
#[test]
fn verif_opens_a_conditional_cpp_sighash_00018() {
    let code = hex("656a6a00ab");
    let script = Script::from_binary(&code).unwrap();
    assert_eq!(
        shape(&script),
        vec![
            (0x65, None),
            (0x6a, None),
            (0x6a, None),
            (0x00, None),
            (0xab, None),
        ],
        "cpp-sighash-00018: five instructions"
    );
    let mut stripped = script.clone();
    stripped.remove_codeseparators();
    assert_eq!(to_hex(&stripped.to_binary()), "656a6a00");

    // The recorded digest: the original algorithm (`hash_type` 3644077434 has
    // no FORKID) over the vector's transaction, input 0, with this scriptCode.
    let tx = parse_transaction(&hex(
        "a932dc4801e8f6b5d72ba8e418158ecb614db5ab24c6dcdfa69a068dae038893fdecc2895600000000046a65ac65ffffffff01327934040000000008005200ac52ab516500000000",
    ))
    .unwrap();
    let digest = compute_sighash_original_for_signing(&SighashParams {
        version: tx.version,
        inputs: &tx.inputs,
        outputs: &tx.outputs,
        locktime: tx.locktime,
        input_index: 0,
        subscript: &code,
        satoshis: 0,
        scope: 3_644_077_434,
    });
    assert_eq!(
        to_hex(&digest),
        "a19bbf4e3915562dad8f42f5156cb6f3bc3b7781a29bc4629fa2b379601a9653",
        "cpp-sighash-00018: the recorded original digest"
    );
}

/// The node's `script_tests.json` #74 in the ts-stack corpus
/// (`conformance/vectors/sdk/scripts/evaluation.json` at `edf6e03`,
/// `node.script.bitcoin-sv.0074`, "UNBALANCED_CONDITIONAL"): scriptSig `00`,
/// scriptPubKey `IF 1 IF RETURN ELSE RETURN ELSE RETURN ENDIF ELSE 1 IF 1 ELSE
/// RETURN ELSE 1 ENDIF ELSE RETURN ENDIF ADD 2 EQUAL`, refused. Every byte is
/// an instruction of its own (`Machine.lean:29-50`), and every `OP_RETURN` sits
/// inside an `OP_IF`, so none takes the bytes after it (`Script.ts:613-617`):
/// 24 chunks. Kills `226:38` (`+=` to `-=`), under which the depth goes
/// negative, the first `ENDIF` clamps it to 0 and the last `OP_RETURN` takes
/// `ENDIF ADD 2 EQUAL` as data.
#[test]
fn every_return_inside_an_if_is_an_opcode_node_script_tests_0074() {
    let lock_hex = "6351636a676a676a6867516351676a675168676a68935287";
    let lock = Script::from_binary(&hex(lock_hex)).unwrap();
    let expected: Vec<(u8, Option<Vec<u8>>)> =
        hex(lock_hex).into_iter().map(|op| (op, None)).collect();
    assert_eq!(shape(&lock), expected, "node.script.bitcoin-sv.0074");

    // The recorded refusal, as the ts-stack runner evaluates the fixture
    // (`tests/conformance_scripts.rs` `run_node_script`): the default mode, the
    // transaction version 1, no amount.
    let mut spend = Spend::new(SpendParams {
        source_txid: [0u8; 32],
        source_output_index: 0,
        source_satoshis: 0,
        locking_script: LockingScript::from_hex(lock_hex).unwrap(),
        transaction_version: 1,
        other_inputs: vec![],
        outputs: vec![TxOutput {
            satoshis: 0,
            script: vec![],
        }],
        input_index: 0,
        unlocking_script: UnlockingScript::from_hex("00").unwrap(),
        input_sequence: 0xffff_ffff,
        lock_time: 0,
        memory_limit: None,
        work_limit: None,
    });
    assert!(
        spend.validate().is_err(),
        "node.script.bitcoin-sv.0074: UNBALANCED_CONDITIONAL"
    );
}

/// `OP_0` is a bare opcode in the reference's parser (`Script.ts:619-627`:
/// the push branch is `op > 0`, so `OP_0` is `{ op }` with no data), the one
/// chunk of the ts-stack vector `script-001` (`evaluation.json`, hex `00`,
/// one chunk, op 0); this crate's writer builds the same chunk for an empty
/// push (`ScriptChunk::new_push`, no data). The node pushes an empty element
/// for it (`Machine.lean:32,49`), which `Spend` does from the opcode. Kills
/// `232:19` (`>` to `>=`), under which `OP_0` carries an empty `Some` and
/// prints as `""` where the tree prints `0`.
#[test]
fn op_0_is_an_opcode_without_data_ts_stack_script_001() {
    let script = Script::from_binary(&hex("00")).unwrap();
    assert_eq!(script.chunks(), vec![ScriptChunk::new_push(Vec::new())]);
    assert_eq!(script.to_asm(), "0");
}

/// A bare `OP_RETURN` is an opcode above `OP_PUSHDATA4`, which consumes no
/// byte and pushes nothing (`Machine.lean:50`); post-Genesis at the top level
/// it ends the script, the stack deciding (`:342-344`). bytes-00107
/// (`corpus/bytes`, the locking script `6a` on the stack 1 2 3 4 5 6, version
/// 2) is recorded valid. Its chunk is the one this crate's writer builds for
/// the opcode (`write_opcode`, no data), and it prints as `OP_RETURN`. Kills
/// `215:35` (`<` to `<=`), under which the chunk carries an empty `Some` and
/// prints as `""`.
#[test]
fn a_bare_op_return_is_an_opcode_without_data_bytes_00107() {
    let lock = Script::from_binary(&hex(BYTES_00107.prevout_script_hex)).unwrap();
    let mut written = Script::new();
    written.write_opcode(OP_RETURN);
    assert_eq!(lock.chunks(), written.chunks());
    assert_eq!(lock.chunks(), vec![ScriptChunk::new_opcode(OP_RETURN)]);
    assert_eq!(lock.to_asm(), "OP_RETURN");
    assert_recorded_verdict(&BYTES_00107);
}
