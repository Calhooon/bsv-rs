//! `Script`'s ASM parser and predicates (#603, shard A): the 32 mutants of
//! `src/script/script.rs` in `from_asm`, `len`, `is_empty`, `set_chunk_opcode`,
//! `is_locking_script`, `is_unlocking_script`, `is_data`, `is_multisig` and
//! `PartialEq::eq` the widened oracle left (run 41327640129), each killed here
//! by a vector of the reference or of `bsv-script-lean` at `387dab35`, or named
//! a candidate equivalence in the changelog.
//!
//! The sources:
//!
//! * the reference's `Script.fromASM` (`ts-stack@edf6e03`
//!   `packages/sdk/src/script/Script.ts:73-123`), recorded under Node 22 by
//!   `tests/support/script_asm_603_a.mjs` into
//!   `tests/vectors/script_asm_603_a.json`: an inline PUSHDATA takes the next
//!   two tokens (`:102-108`), a hex token's opcode is the smallest push that
//!   carries it (`#pushdataOpCodeNum`, `:85-90`), the bound the sibling's
//!   `checkMinimalPush` states (`lean/BsvScript/Machine.lean:66-80`);
//! * the node's `Solver` as the sibling defines it
//!   (`lean/BsvScript/Standard.lean`): the data carrier (`solver`, `:163-173`)
//!   and the multisig template, whose keys are 33 to 65 byte pushes
//!   (`pubkeysLoop`, `:74-85`; `matchOne`, `:87-102`), on the recorded entries
//!   of `corpus/cpp/multisig_tests.jsonl` and `corpus/flow/flow.jsonl`;
//! * `getOpTail`'s instruction split (`Machine.lean:29-50`) and `verifyScript`
//!   evaluating the script's own bytes (`:495-509`), on recorded flow entries.
//!
//! A full-corpus run of each of the 32 mutants (the sibling's `harness/run
//! --impl bsv-rs --corpus all`) moved no verdict: the harness reads scripts
//! from bytes and never calls these functions. The vectors below reach them.
//!
//! Four mutants of `from_asm` can parse forever (`i *= 3` at index 0, `i *= 1`
//! anywhere, `-=` past the first tokens), so every `from_asm` case runs in a child process of this test
//! binary that the parent kills after a deadline: a parse that does not end is
//! a failed test, never a hung one.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)] // #134: test code: a failed unwrap is the test failing

use std::io::Read;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use bsv_rs::primitives::bsv::sighash::{parse_transaction, TxOutput};
use bsv_rs::primitives::{from_hex, sha256, to_hex};
use bsv_rs::script::op::OP_0;
use bsv_rs::script::{
    LockingScript, ProtocolEra, Script, ScriptFlags, Spend, SpendParams, UnlockingScript,
};
use serde_json::Value;

const VECTOR: &str = include_str!("vectors/script_asm_603_a.json");

/// Set in a child's environment: run the named test's `from_asm` cases and
/// print one line per case instead of judging them.
const WORKER: &str = "BSV_RS_SCRIPT_603_A_WORKER";
const LINE: &str = "ASM603A";
/// The original parse of every case of a test takes milliseconds; a mutant
/// that loops grows memory without bound, so the deadline is short.
const DEADLINE: Duration = Duration::from_secs(3);

fn vector() -> Value {
    serde_json::from_str(VECTOR).unwrap()
}

/// A case's ASM text, as the recorder builds it: string parts as written,
/// `{ "bytes": n }` a hex token of n bytes, byte i being (7i + 1) mod 256.
fn asm_text(parts: &Value) -> String {
    parts
        .as_array()
        .unwrap()
        .iter()
        .map(|part| match part {
            Value::String(s) => s.clone(),
            other => {
                let n = other["bytes"].as_u64().unwrap() as usize;
                to_hex(
                    &(0..n)
                        .map(|i| ((7 * i + 1) % 256) as u8)
                        .collect::<Vec<_>>(),
                )
            }
        })
        .collect::<Vec<_>>()
        .join(" ")
}

fn case(name: &str) -> Value {
    vector()["asm"]
        .as_array()
        .unwrap()
        .iter()
        .find(|c| c["name"] == name)
        .unwrap_or_else(|| panic!("{name}: not in the vector"))
        .clone()
}

/// What `from_asm` gave, in the vector's terms: the bytes' length, first six
/// bytes and SHA-256, or the error.
#[derive(Debug, PartialEq, Eq)]
enum Parsed {
    Script {
        length: usize,
        head: String,
        sha256: String,
    },
    Error(String),
}

impl Parsed {
    fn of_bytes(bytes: &[u8]) -> Self {
        Parsed::Script {
            length: bytes.len(),
            head: to_hex(&bytes[..bytes.len().min(6)]),
            sha256: to_hex(&sha256(bytes)),
        }
    }

    /// The reference's recorded outcome of a case.
    fn recorded(case: &Value) -> Self {
        match case.get("error") {
            Some(e) => Parsed::Error(e.as_str().unwrap().to_string()),
            None => Parsed::Script {
                length: case["length"].as_u64().unwrap() as usize,
                head: case["head"].as_str().unwrap().to_string(),
                sha256: case["sha256"].as_str().unwrap().to_string(),
            },
        }
    }
}

/// Parses each case's ASM with `from_asm` in a child process of this binary
/// running `test`, and returns the outcomes in order; `None` in the child,
/// which prints them and returns. A child that has not exited by the deadline
/// is killed and the test fails; so does one that exits unsuccessfully (a
/// mutant's index or arithmetic panic).
fn parse_guarded(test: &str, cases: &[&str]) -> Option<Vec<Parsed>> {
    if std::env::var_os(WORKER).is_some() {
        for name in cases {
            let line = match Script::from_asm(&asm_text(&case(name)["parts"])) {
                Ok(s) => match Parsed::of_bytes(&s.to_binary()) {
                    Parsed::Script {
                        length,
                        head,
                        sha256,
                    } => format!("{LINE}\t{name}\tok\t{length}\t{head}\t{sha256}"),
                    Parsed::Error(_) => unreachable!(),
                },
                Err(e) => format!("{LINE}\t{name}\terr\t{e}"),
            };
            println!("{line}");
        }
        return None;
    }
    let mut child = Command::new(std::env::current_exe().unwrap())
        .args([test, "--exact", "--nocapture", "--test-threads=1"])
        .env(WORKER, "1")
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let start = Instant::now();
    let status = loop {
        if let Some(status) = child.try_wait().unwrap() {
            break status;
        }
        if start.elapsed() > DEADLINE {
            child.kill().unwrap();
            child.wait().unwrap();
            panic!("{test}: from_asm did not return within {DEADLINE:?} on {cases:?}");
        }
        std::thread::sleep(Duration::from_millis(5));
    };
    let mut out = String::new();
    child
        .stdout
        .take()
        .unwrap()
        .read_to_string(&mut out)
        .unwrap();
    assert!(
        status.success(),
        "{test}: the parse failed ({status}):\n{out}"
    );
    let got: Vec<Parsed> = out
        .lines()
        // libtest writes the test's name on the line the first record opens
        .filter_map(|l| l.find(LINE).map(|i| &l[i + LINE.len() + 1..]))
        .map(|l| {
            let f: Vec<&str> = l.split('\t').collect();
            match f[1] {
                "ok" => Parsed::Script {
                    length: f[2].parse().unwrap(),
                    head: f[3].to_string(),
                    sha256: f[4].to_string(),
                },
                _ => Parsed::Error(f[2..].join("\t")),
            }
        })
        .collect();
    assert_eq!(got.len(), cases.len(), "{test}: one line per case:\n{out}");
    Some(got)
}

/// Asserts each case's outcome is the reference's recorded one.
fn assert_reference(test: &str, cases: &[&str]) {
    let Some(got) = parse_guarded(test, cases) else {
        return;
    };
    for (name, got) in cases.iter().zip(got) {
        let c = case(name);
        assert_eq!(
            got,
            Parsed::recorded(&c),
            "{name}: {:?} is not the reference's reading",
            c["parts"]
        );
        if let Some(hex) = c.get("hex") {
            // the recorded hex and its hash agree (the vector's own consistency)
            assert_eq!(
                Parsed::of_bytes(&from_hex(hex.as_str().unwrap()).unwrap()),
                Parsed::recorded(&c)
            );
        }
    }
}

/// An inline `OP_PUSHDATA<n> <size> <hex>` is one push of the hex, the three
/// tokens consumed (`Script.ts:102-108`), at index 0, 1 and 3 and before
/// another opcode, for each of the three PUSHDATA opcodes. Kills `from_asm`'s
/// `108:39` and `108:61` (`||` to `&&`), `110:26` (`+` to `*`, `-`), `110:30`
/// (`<` to `==`, `>`), `111:54` (`+` to `*`, `-`), `113:27` (`+=` to `*=`,
/// `-=`).
#[test]
fn an_inline_pushdata_takes_the_next_two_tokens_script_ts_102_108() {
    assert_reference(
        "an_inline_pushdata_takes_the_next_two_tokens_script_ts_102_108",
        &[
            "pushdata1_at_1",
            "pushdata1_at_3",
            "pushdata1_then_op",
            "pushdata2_at_0",
            "pushdata4_at_0",
            "pushdata1_at_0",
        ],
    );
}

/// A hex token is pushed with the smallest opcode that carries it, at each
/// bound of `#pushdataOpCodeNum` (`Script.ts:85-90`; the sibling's
/// `checkMinimalPush`, `Machine.lean:66-80`): 75 bytes direct, 76 to 255
/// `OP_PUSHDATA1`, 256 to 65,535 `OP_PUSHDATA2`, 65,536 `OP_PUSHDATA4`. Kills
/// `from_asm`'s `96:31` and `98:31` (`<` to `<=`, `==`, `>`); `94:33` (`<` to
/// `<=`; `91:37` after #639's fold) is declared equivalent on three reads
/// (`.cargo/mutants.toml`): at 76, the one length where its branches
/// differ, both write the byte 0x4c (`Opcodes.lean:21`, `OP_PUSHDATA1 :=
/// 0x4c`), as the 76-byte cases here show on the tree and the mutant alike.
#[test]
fn a_hex_token_is_the_minimal_push_script_ts_85_90_machine_lean_66_80() {
    assert_reference(
        "a_hex_token_is_the_minimal_push_script_ts_85_90_machine_lean_66_80",
        &[
            "hex_75",
            "hex_76",
            "hex_76_after_op",
            "hex_77",
            "hex_100",
            "hex_255",
            "hex_256",
            "hex_257",
            "hex_65535",
            "hex_65536",
            "zero_and_negative_one",
        ],
    );
}

/// The short inline forms, fewer than two tokens after the PUSHDATA opcode:
/// this crate reads the opcode alone (the next token, if any, a push of its
/// own), where the reference reads an empty push of that opcode and consumes
/// three tokens (`toArray(undefined, 'hex')`, `Script.ts:102-108`), recorded
/// here; a stated difference (the #603 shard A parity note). The parse ends on
/// every one. Kills `from_asm`'s `110:30` (`<` to `<=`, an index past the
/// tokens) and `116:27` (`+=` to `*=`, a parse that never ends; `-=`, an
/// underflow).
#[test]
fn a_short_inline_pushdata_is_the_opcode_alone_stated_against_script_ts_102_108() {
    let cases = [
        "pushdata1_alone",
        "pushdata1_one_token",
        "pushdata1_alone_at_1",
        "pushdata1_one_token_at_1",
    ];
    let Some(got) = parse_guarded(
        "a_short_inline_pushdata_is_the_opcode_alone_stated_against_script_ts_102_108",
        &cases,
    ) else {
        return;
    };
    // this crate's reading: OP_PUSHDATA1 with no length, then `01` pushed
    let crate_reading = ["4c", "4c0101", "514c", "514c0101"];
    for ((name, got), hex) in cases.iter().zip(got).zip(crate_reading) {
        assert_eq!(
            got,
            Parsed::of_bytes(&from_hex(hex).unwrap()),
            "{name}: this crate's reading"
        );
        assert_ne!(
            got,
            Parsed::recorded(&case(name)),
            "{name}: the reference's reading, recorded, differs (the parity note)"
        );
    }
}

/// An empty token, which the reference's split on one space gives for the
/// empty text and a double space and reads as an empty push (`00`), is
/// skipped here; a stated difference older than #603, pinned beside the
/// recording.
#[test]
fn an_empty_token_is_skipped_stated_against_script_ts_75() {
    let cases = ["empty_text", "double_space"];
    let Some(got) = parse_guarded(
        "an_empty_token_is_skipped_stated_against_script_ts_75",
        &cases,
    ) else {
        return;
    };
    for ((name, got), hex) in cases.iter().zip(got).zip(["", "5152"]) {
        assert_eq!(got, Parsed::of_bytes(&from_hex(hex).unwrap()), "{name}");
        assert_ne!(got, Parsed::recorded(&case(name)), "{name}: recorded");
    }
}

/// A recorded entry of the sibling's flow corpus: one input, one output, the
/// previous output's script and this crate's recorded verdict
/// (`bsv-rs@0.7.0`, equal to `spec@cb7e46e`).
struct Entry {
    id: &'static str,
    tx_hex: &'static str,
    prevout_script_hex: &'static str,
    /// `None` valid; `Some(reason)` the recorded refusal's words.
    refused: Option<&'static str>,
}

/// `flow-01005` (`stack/final`, "two true elements"): lock `5151`, empty
/// scriptSig; valid.
const FLOW_01005: Entry = Entry {
    id: "flow-01005",
    tx_hex: "02000000010967130f5aa84275680f30589a52e9243547d8a3cd864ddea81c5ca9f5d064610000000000ffffffff010100000000000000015100000000",
    prevout_script_hex: "5151",
    refused: None,
};

/// `flow-01007` (`stack/final`, "false on top"): lock `5100`, empty scriptSig;
/// invalid, `SCRIPT_ERR_EVAL_FALSE`.
const FLOW_01007: Entry = Entry {
    id: "flow-01007",
    tx_hex: "020000000196fc94a7706d5f81c1c9997349698dcaf548cfd21669c3f702222e330d139c800000000000ffffffff010100000000000000015100000000",
    prevout_script_hex: "5100",
    refused: Some("The top stack element must be truthy after script evaluation."),
};

/// `flow-01009` (`stack/final`, "empty lock, true from the unlock"): the
/// empty lock, scriptSig `51`; valid.
const FLOW_01009: Entry = Entry {
    id: "flow-01009",
    tx_hex: "020000000106edd410eb9662c34922a458807e9572292f3b85e65166e0ebc21b0eff635437000000000151ffffffff010100000000000000015100000000",
    prevout_script_hex: "",
    refused: None,
};

/// `flow-01013` (`stack/final`, "extra elements below a true top"): lock `51`,
/// scriptSig `000000`; valid.
const FLOW_01013: Entry = Entry {
    id: "flow-01013",
    tx_hex: "0200000001388fc8aca84b903993c73b5123a0ad982c7c8948786777a90214474dcc82e7b50000000003000000ffffffff010100000000000000015100000000",
    prevout_script_hex: "51",
    refused: None,
};

/// `flow-00953` (`flow/return`, "a push after a top-level RETURN never
/// runs"): lock `516a00`, empty scriptSig; valid.
const FLOW_00953: Entry = Entry {
    id: "flow-00953",
    tx_hex: "0200000001c730e6c9095e5c2819fc49f46be17153fa506b95e840e9b0b7c7296943cab3770000000000ffffffff010100000000000000015100000000",
    prevout_script_hex: "516a00",
    refused: None,
};

fn script_sig(e: &Entry) -> Vec<u8> {
    let tx = parse_transaction(&from_hex(e.tx_hex).unwrap()).unwrap();
    assert_eq!(tx.inputs.len(), 1, "{}: one input", e.id);
    tx.inputs[0].script.clone()
}

fn lock_script(e: &Entry) -> Script {
    Script::from_binary(&from_hex(e.prevout_script_hex).unwrap()).unwrap()
}

/// Runs the entry's input with `locking` as the previous output's script under
/// the block word of the entry's era (post-Chronicle, consensus) and asserts
/// the recorded verdict.
fn assert_recorded_verdict(e: &Entry, locking: Script) {
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
        locking_script: LockingScript::from_script(locking),
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
    spend.set_flags(ScriptFlags::block(ProtocolEra::PostChronicle));
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

/// `len` and `is_empty` count `getOpTail`'s instructions
/// (`lean/BsvScript/Machine.lean:29-50`) on a `Script`: three for flow-01013's
/// scriptSig `000000`, two for flow-01005's lock `5151`, none for flow-01009's
/// empty lock, each entry valid as recorded. Kills `len -> 0` (`583:9`) and
/// `is_empty -> true` (`589:9`).
#[test]
fn instruction_count_is_the_get_op_split_flow_01013_flow_01005_flow_01009() {
    let sig = Script::from_binary(&script_sig(&FLOW_01013)).unwrap();
    assert_eq!(sig.len(), 3, "flow-01013: 00 00 00 is three instructions");
    assert!(!sig.is_empty(), "flow-01013: three instructions");
    assert_recorded_verdict(&FLOW_01013, lock_script(&FLOW_01013));

    let two = lock_script(&FLOW_01005);
    assert_eq!(two.len(), 2, "flow-01005: 51 51 is two instructions");
    assert!(!two.is_empty(), "flow-01005: two instructions");
    assert_recorded_verdict(&FLOW_01005, two);

    let none = lock_script(&FLOW_01009);
    assert_eq!(none.len(), 0, "flow-01009: the empty lock");
    assert!(none.is_empty(), "flow-01009: the empty lock");
    assert_recorded_verdict(&FLOW_01009, none);
}

/// `set_chunk_opcode` as the reference's `setChunkOpCode` (`Script.ts:297-301`,
/// recorded): `OP_0` at instruction 1 of flow-01005's lock `5151` is
/// flow-01007's lock `5100`, refused as that entry records; at index 2, the
/// chunk count, it appends an instruction (`515100`, three chunks), as a
/// JavaScript array's assignment at its length does. Beyond the count the
/// reference leaves a hole (four chunks, its `toHex` throwing, recorded) that
/// no byte form carries; this crate leaves the script unchanged there, a
/// stated difference (the #603 parity note). Kills `set_chunk_opcode`'s
/// `601:22` (`<` to `<=`; `598:22` after #639's fold).
#[test]
fn set_chunk_opcode_at_the_chunk_count_appends_as_the_reference_does_ts_297_301() {
    let recorded = vector()["setChunkOpCode"].as_array().unwrap().clone();
    let entry = |index: u64| {
        recorded
            .iter()
            .find(|e| e["index"] == index && e["script"] == FLOW_01005.prevout_script_hex)
            .unwrap()
            .clone()
    };

    let mut at = lock_script(&FLOW_01005);
    at.set_chunk_opcode(1, OP_0);
    assert_eq!(at.to_hex(), entry(1)["hex"]);
    assert_eq!(at.to_hex(), FLOW_01007.prevout_script_hex);
    assert_recorded_verdict(&FLOW_01007, at);

    let mut appended = lock_script(&FLOW_01005);
    appended.set_chunk_opcode(2, OP_0);
    assert_eq!(
        appended.to_hex(),
        entry(2)["hex"],
        "index 2: the reference appends"
    );
    assert_eq!(
        appended.chunks().len() as u64,
        entry(2)["chunks"].as_u64().unwrap()
    );

    let beyond = entry(3);
    assert_eq!(beyond["chunks"], 4, "index 3: the reference's hole");
    assert!(
        beyond["error"].is_string(),
        "index 3: the reference's toHex throws"
    );
    let mut past = lock_script(&FLOW_01005);
    past.set_chunk_opcode(3, OP_0);
    assert_eq!(
        past.to_hex(),
        FLOW_01005.prevout_script_hex,
        "index 3: stated, unchanged here"
    );
    assert_recorded_verdict(&FLOW_01005, past);
}

/// `PartialEq` on scripts is equality of their bytes: reflexive on equal bytes
/// and false on bytes that differ (the trait's contract, `core::cmp::PartialEq`:
/// "a == b if and only if" the relation holds, consistent with `!=`). Two
/// scripts of flow-01005's lock `5151`, one parsed and one built from the
/// chunks, are equal; flow-01005's and flow-01007's locks differ in one
/// instruction and their recorded verdicts differ. Kills `eq -> true`
/// (`835:9`).
#[test]
fn scripts_are_equal_by_their_bytes_flow_01005_flow_01007() {
    let a = lock_script(&FLOW_01005);
    let b = Script::from_chunks(lock_script(&FLOW_01005).chunks());
    assert!(a == b, "flow-01005: the same bytes");
    let c = lock_script(&FLOW_01007);
    assert!(a != c, "5151 and 5100 differ in their second instruction");
    assert!(!(a == c), "5151 and 5100 are not equal");
    assert_recorded_verdict(&FLOW_01005, a);
    assert_recorded_verdict(&FLOW_01007, c);
}

/// The type predicates: the reference's base `Script` answers neither
/// (`isLockingScript` and `isUnlockingScript` throw `Not implemented`,
/// `Script.ts:430-441`, recorded), its `LockingScript` and `UnlockingScript`
/// one each; this crate's base `Script` answers `false` to both (its
/// documented reading of the reference's refusal: no base script is either),
/// its two types as the reference's do. Kills `is_locking_script -> true`
/// (`611:9`) and `is_unlocking_script -> true` (`617:9`).
#[test]
fn a_base_script_is_neither_locking_nor_unlocking_script_ts_430_441() {
    let p = &vector()["predicates"];
    assert_eq!(p["script"]["isLockingScript"]["error"], "Not implemented");
    assert_eq!(p["script"]["isUnlockingScript"]["error"], "Not implemented");
    for e in [&FLOW_01005, &FLOW_01009] {
        let s = lock_script(e);
        assert!(!s.is_locking_script(), "{}: a base Script", e.id);
        assert!(!s.is_unlocking_script(), "{}: a base Script", e.id);
        let locking = LockingScript::from_script(s.clone());
        assert_eq!(
            locking.is_locking_script(),
            p["lockingScript"]["isLockingScript"]["returns"] == true
        );
        assert_eq!(
            locking.is_unlocking_script(),
            p["lockingScript"]["isUnlockingScript"]["returns"] == true
        );
        let unlocking = UnlockingScript::from_script(s);
        assert_eq!(
            unlocking.is_locking_script(),
            p["unlockingScript"]["isLockingScript"]["returns"] == true
        );
        assert_eq!(
            unlocking.is_unlocking_script(),
            p["unlockingScript"]["isUnlockingScript"]["returns"] == true
        );
    }
}

/// A data carrier opens with `OP_FALSE OP_RETURN` (or, before Genesis,
/// `OP_RETURN`; `solver`, `lean/BsvScript/Standard.lean:163-173`):
/// flow-00953's lock `516a00` opens with `OP_1`, is no data carrier, and its
/// spend is valid as recorded (the RETURN after a true top ends the script).
/// Kills `is_data`'s `674:55` (`&&` to `||`: the second instruction's
/// `OP_RETURN` alone taken for a carrier).
#[test]
fn a_return_after_a_true_push_is_no_data_carrier_standard_lean_163_flow_00953() {
    let s = lock_script(&FLOW_00953);
    assert!(!s.is_data(), "flow-00953: 51 6a 00 is no data carrier");
    assert!(!s.is_safe_data_carrier(), "flow-00953: no OP_FALSE first");
    assert_recorded_verdict(&FLOW_00953, s);
}

/// `corpus/cpp/multisig_tests.jsonl` entries (bitcoin-sv v1.2.2
/// `src/test/multisig_tests.cpp`, `IsStandardOutput` at height 1, recorded
/// `sv-node-unit@v1.2.2`).
const CPP_MULTISIG_00031: &str = "5221020caaa2ac8e426aaa1ce4b392107d80c05a5d4723a83d165a1dc2aab360a8bdc4210264ae6f94efae9fadc2c5f2d4432517348ee75b90e102d3ae44ef920018f97a8b52ae";
const CPP_MULTISIG_00033: &str = "5221020caaa2ac8e426aaa1ce4b392107d80c05a5d4723a83d165a1dc2aab360a8bdc4210264ae6f94efae9fadc2c5f2d4432517348ee75b90e102d3ae44ef920018f97a8b2102bddee64d4550aa8aebd94504bf8a8a3ecb15083fdd5de1510ce3f979ab99a37c53ae";
const CPP_MULTISIG_00036: &str = "5221020caaa2ac8e426aaa1ce4b392107d80c05a5d4723a83d165a1dc2aab360a8bdc4210264ae6f94efae9fadc2c5f2d4432517348ee75b90e102d3ae44ef920018f97a8b53ae";
const CPP_MULTISIG_00038: &str = "5121020caaa2ac8e426aaa1ce4b392107d80c05a5d4723a83d165a1dc2aab360a8bdc4210264ae6f94efae9fadc2c5f2d4432517348ee75b90e102d3ae44ef920018f97a8b00ae";

fn multisig(hex: &str) -> Option<(u8, u8)> {
    Script::from_hex(hex).unwrap().is_multisig()
}

/// The multisig template's keys are pushes of 33 to 65 bytes, every one of
/// them (`pubkeysLoop`, `lean/BsvScript/Standard.lean:74-85`: the key loop
/// ends at the first push outside that size, and `matchOne`, `:87-102`, then
/// refuses it as the count): cpp-multisig-00031 (2 of 2) and 00033 (2 of 3)
/// are multisig (recorded standard), 00036 (three keys named, two given) and
/// 00038 (a count of `OP_0`) are not (recorded non-standard); 00031 with its
/// last key cut to its first 20 bytes is no multisig: the 20-byte push ends
/// the key loop and is no count (a hand derivation from the recorded entry,
/// read by the Lean rule). Kills `is_multisig`'s `711:54` (`+` to `*`, `-`:
/// the last key slot, or every one, unchecked) and `713:47` (`!=` to `==`:
/// only a 65-byte push refused).
#[test]
fn every_multisig_key_is_a_33_to_65_byte_push_standard_lean_74_102_cpp_multisig_00031() {
    assert_eq!(
        multisig(CPP_MULTISIG_00031),
        Some((2, 2)),
        "cpp-multisig-00031"
    );
    assert_eq!(
        multisig(CPP_MULTISIG_00033),
        Some((2, 3)),
        "cpp-multisig-00033"
    );
    assert_eq!(multisig(CPP_MULTISIG_00036), None, "cpp-multisig-00036");
    assert_eq!(multisig(CPP_MULTISIG_00038), None, "cpp-multisig-00038");

    // 52 <21 key0> <21 key1> 52 ae, the second key's push cut to 20 bytes
    let bytes = from_hex(CPP_MULTISIG_00031).unwrap();
    let key1 = &bytes[36..69];
    let mut cut = bytes[..35].to_vec();
    cut.push(20);
    cut.extend_from_slice(&key1[..20]);
    cut.extend_from_slice(&bytes[69..]);
    assert_eq!(cut.len(), bytes.len() - 13);
    assert_eq!(
        Script::from_binary(&cut).unwrap().is_multisig(),
        None,
        "cpp-multisig-00031 with a 20-byte last key"
    );
}
