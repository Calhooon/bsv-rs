//! #843d7 (decided 2026-11-12: `docs/design/843-identity-and-framing.md`
//! section 9, item 8; six design reads): where an
//! amount of 2^53 satoshis or more is refused, and where it is written.
//!
//! Decided: the plain writer (`to_binary`, `to_hex`, `hash`, `id`) stays
//! infallible and is the node's serializer, any 64-bit amount its eight
//! little-endian bytes (bitcoin-sv v1.2.2 `primitives/transaction.h:190-194`,
//! `amount.h:109-112`; go-sdk@2ca481c `transaction/output.go:92`), STATED
//! against the reference's writer, which throws `The number is larger than
//! 2 ^ 53 (unsafe)` (`ts-stack@edf6e03` `Transaction.ts:1083`,
//! `WriterUint8Array.ts:184-185`, `BigNumber.ts:460-463`). Two doors refuse:
//!
//! - `Transaction::from_json` of a document without `hex` refuses an output
//!   `satoshis` of 2^53 or more in the byte readers' words (`Number can only
//!   safely store up to 53 bits`), before the output's script is read. No
//!   reference twin (its `Transaction.ts` has no JSON form).
//! - `to_ef` and `to_hex_ef` refuse an output amount, or a linked source
//!   output's, of 2^53 or more in the reference writer's words, at the amount
//!   in written order, as `#writeEF` throws (`Transaction.ts:1150,1158`):
//!   every cell of `vectors/transaction_amount_doors_843d7.json`
//!   (`support/transaction_amount_doors_843d7.mjs`, Node v22.18.0); for an
//!   input that names no txid, ahead of its other checks, an amount in any
//!   output of its source or of a source reached the same way, as the
//!   reference writes that outpoint from the source's `hash()`
//!   (`Transaction.ts:1137-1138`; the fold of the rule read of PR #913).
//!   The walk stops at an input that names a txid and runs for every input,
//!   the vector's `walk` cells (the scoped re-read of that fold, M1 and M2),
//!   beside the residual it named: a source failing both its unlocking
//!   script's check and the amount, one cell agreeing and one stated.
//!   Since the third fold the two rules are a property over their whole
//!   small space: `the_walk_is_the_references_over_every_depth_and_input_843d7`
//!   holds an oracle written from the reference's lines against the
//!   recording of a fixed sample (`walk.space.sample`, 38 cells), then every
//!   one of the space's 452 cases against the oracle. The space is the
//!   property's bound: depth up to 4 and the unnamed input at index up to 3
//!   of four inputs; a fault past it is outside what it pins.
//!
//! `the_writer_is_the_nodes_serializer_stated_843d7` is a stating pin, its writer half green on the
//! base (its RED two serializer plants on the tip) and its field-door half, F2, RED on the base
//! where `from_json` held the amount (`docs/lanes/fix-843d7.md`).
#![cfg(feature = "transaction")]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)] // Test code: a failed unwrap is the test failing.

use std::collections::BTreeMap;

use bsv_rs::primitives::{from_hex, sha256, sha256d, to_hex};
use bsv_rs::script::{LockingScript, UnlockingScript};
use bsv_rs::transaction::{SpendingTransaction, Transaction, TransactionInput, TransactionOutput};
use bsv_rs::Error;
use serde_json::{json, Value};

const VECTOR: &str = include_str!("vectors/transaction_amount_doors_843d7.json");

/// The byte readers' words (`BigNumber.ts:628`).
const UNSAFE: &str = "Number can only safely store up to 53 bits";
/// The reference writer's words (`BigNumber.ts:462`).
const UNSAFE_WRITE: &str = "The number is larger than 2 ^ 53 (unsafe)";

const TWO_53: u64 = 1 << 53;
const TWO_63: u64 = 1 << 63;
/// The node's `MAX_MONEY` (`amount.h:130`).
const MAX_MONEY: u64 = 2_100_000_000_000_000;

fn vector() -> Value {
    serde_json::from_str(VECTOR).unwrap()
}

fn unsafe_read() -> Error {
    Error::TransactionError(UNSAFE.to_string())
}

// ============================================================================
// The field-built JSON document
// ============================================================================

/// A field-built document of three `OP_1` outputs, `value` at `position`.
fn field_document(position: usize, value: u64, hex: Option<&str>) -> String {
    let outputs: Vec<Value> = (0..3)
        .map(|i| {
            json!({
                "satoshis": if i == position { value } else { 1 + i as u64 },
                "lockingScript": "51",
            })
        })
        .collect();
    let mut doc = json!({
        "inputs": [{
            "unlockingScript": "51",
            "txid": "11".repeat(32),
            "vout": 0,
            "sequence": 4294967295u32,
        }],
        "outputs": outputs,
        "version": 1,
        "lockTime": 0,
    });
    if let Some(hex) = hex {
        doc["hex"] = json!(hex);
    }
    doc.to_string()
}

#[test]
fn a_json_output_amount_of_two_to_the_53_is_refused_843d7() {
    for hex in [None, Some("")] {
        for position in 0..3 {
            // The last amount every reader holds.
            let tx = Transaction::from_json(&field_document(position, TWO_53 - 1, hex)).unwrap();
            assert_eq!(tx.outputs()[position].satoshis, Some(TWO_53 - 1));
            let back = Transaction::from_binary(&tx.to_binary()).unwrap();
            assert_eq!(back.id(), tx.id(), "what the door holds, the readers read");
            for value in [TWO_53, TWO_63, u64::MAX] {
                assert_eq!(
                    Transaction::from_json(&field_document(position, value, hex)).unwrap_err(),
                    unsafe_read(),
                    "hex {hex:?}, output {position}, {value}"
                );
            }
        }
    }
    // Before the script is read, as the byte readers read the amount ahead
    // of the script (`transaction.rs`, the output loop): a document whose
    // output carries both faults answers the amount's words.
    let both = r#"{"inputs":[],"outputs":[{"satoshis":9007199254740992,"lockingScript":"zz"}],"version":1,"lockTime":0}"#;
    assert_eq!(Transaction::from_json(both).unwrap_err(), unsafe_read());
    let script_alone = r#"{"inputs":[],"outputs":[{"satoshis":9007199254740991,"lockingScript":"zz"}],"version":1,"lockTime":0}"#;
    assert_ne!(
        Transaction::from_json(script_alone).unwrap_err(),
        unsafe_read()
    );
}

// ============================================================================
// The EF writer against the recording
// ============================================================================

fn script(v: &Value) -> LockingScript {
    LockingScript::from_hex(v.as_str().unwrap()).unwrap()
}

/// A source of one output, as the recorder's `source`.
fn source_of(output: &Value) -> Transaction {
    Transaction::with_params(
        1,
        vec![],
        vec![TransactionOutput::new(
            output["satoshis"].as_u64().unwrap(),
            script(&output["locking_script"]),
        )],
        0,
    )
}

/// The recorder's `base`: block 170's transaction, a third output, its
/// input linked to a source of one output.
fn base(v: &Value) -> Transaction {
    let t = &v["transaction"];
    let mut tx = Transaction::from_hex(t["hex"].as_str().unwrap()).unwrap();
    tx.outputs_mut().push(TransactionOutput::new(
        t["third_output"]["satoshis"].as_u64().unwrap(),
        script(&t["third_output"]["locking_script"]),
    ));
    tx.inputs_mut()[0].source_transaction = Some(Box::new(source_of(&t["source_output"])));
    tx
}

/// The recorder's `place`.
fn place(tx: &mut Transaction, position: &str, value: u64) {
    if position == "source_output" {
        tx.inputs_mut()[0]
            .source_transaction
            .as_mut()
            .unwrap()
            .outputs_mut()[0]
            .satoshis = Some(value);
    } else {
        let index: usize = position.strip_prefix("output_").unwrap().parse().unwrap();
        tx.outputs_mut()[index].satoshis = Some(value);
    }
}

/// The recorder's `withSecondInput`.
fn with_second_input(v: &Value, linked: bool, unlocking: bool) -> Transaction {
    let s = &v["transaction"]["second_input"];
    let mut tx = base(v);
    let mut input = TransactionInput::new(
        s["txid"].as_str().unwrap().to_string(),
        s["vout"].as_u64().unwrap() as u32,
    );
    input.sequence = s["sequence"].as_u64().unwrap() as u32;
    if unlocking {
        input.unlocking_script =
            Some(UnlockingScript::from_hex(s["unlocking_script"].as_str().unwrap()).unwrap());
    }
    if linked {
        input.source_transaction = Some(Box::new(source_of(&s["source_output"])));
    }
    tx.inputs_mut().push(input);
    tx
}

/// A recorded amount; 2^64, which no `u64` holds, is `u64::MAX`.
fn amount(decimal: &Value) -> u64 {
    let n: u128 = decimal.as_str().unwrap().parse().unwrap();
    u64::try_from(n).unwrap_or(u64::MAX)
}

/// Both doors on `tx` against the recorded answers, differences gathered.
fn judge_ef(name: &str, tx: &Transaction, cell: &Value, differing: &mut Vec<String>) {
    let doors: [(&str, Result<String, Error>); 2] = [
        ("to_ef", tx.to_ef().map(|bytes| to_hex(&bytes))),
        ("to_hex_ef", tx.to_hex_ef()),
    ];
    for (door, here) in doors {
        let there = &cell[door];
        let agrees = match (&here, there["ok"].as_bool().unwrap()) {
            (Ok(hex), true) => {
                // What the reference writes, this crate's EF reader reads
                // back to the same bytes.
                let read = Transaction::from_ef(&from_hex(hex).unwrap()).unwrap();
                there["hex"] == hex.as_str() && read.to_hex_ef().as_deref() == Ok(hex.as_str())
            }
            (Err(Error::TransactionError(words)), false) => there["error"] == words.as_str(),
            _ => false,
        };
        if !agrees {
            let bytes_refused = here
                .as_ref()
                .ok()
                .map(|hex| Transaction::from_ef(&from_hex(hex).unwrap()).err());
            differing.push(format!(
                "{name} {door}: here {:?} (from_ef of it: {bytes_refused:?}), there {there}",
                here.as_ref().map(|hex| &hex[..20.min(hex.len())])
            ));
        }
    }
}

#[test]
fn to_ef_refuses_an_amount_the_ef_reader_refuses_843d7() {
    let v = vector();
    let mut differing = Vec::new();

    judge_ef("control", &base(&v), &v["control"], &mut differing);
    judge_ef(
        "two-input control",
        &with_second_input(&v, true, true),
        &v["two_input_control"],
        &mut differing,
    );

    let cells = v["cells"].as_array().unwrap();
    assert_eq!(cells.len(), 16, "four edges by four positions");
    let mut refused = 0;
    for cell in cells {
        let position = cell["position"].as_str().unwrap();
        let value = amount(&cell["satoshis"]);
        let mut tx = base(&v);
        place(&mut tx, position, value);
        let name = format!("{} {position}", cell["edge"].as_str().unwrap());
        // The recording refuses exactly the amounts of 2^53 or more, in the
        // writer's words.
        assert_eq!(
            cell["to_ef"]["ok"].as_bool().unwrap(),
            value < TWO_53,
            "{name}"
        );
        if value >= TWO_53 {
            assert_eq!(cell["to_ef"]["error"], UNSAFE_WRITE, "{name}");
            assert_eq!(cell["to_hex_ef"]["error"], UNSAFE_WRITE, "{name}");
            refused += 1;
        }
        judge_ef(&name, &tx, cell, &mut differing);
    }
    assert_eq!(refused, 12, "three edges by four positions");

    // The order of the refusals: the amount is refused where it is written.
    let two_fault = v["two_fault_cells"].as_array().unwrap();
    assert_eq!(two_fault.len(), 3);
    let value = amount(&v["two_fault_satoshis"]);
    assert_eq!(value, TWO_53);
    let expected = [
        UNSAFE_WRITE,
        "All inputs must have source transactions when serializing to EF format",
        "unlockingScript is undefined",
    ];
    for (cell, words) in two_fault.iter().zip(expected) {
        let second = &cell["second_input"];
        let mut tx = with_second_input(
            &v,
            second["linked"].as_bool().unwrap(),
            second["unlocking"].as_bool().unwrap(),
        );
        place(&mut tx, cell["position"].as_str().unwrap(), value);
        assert_eq!(cell["to_ef"]["error"], words, "the recording");
        judge_ef(cell["name"].as_str().unwrap(), &tx, cell, &mut differing);
    }

    assert!(differing.is_empty(), "{differing:#?}");
}

// ============================================================================
// The EF writer on an input that names no txid (the fold, the rule read)
// ============================================================================

/// The recorder's `unnamedSource`: two outputs (the spent one and the
/// vector's `source_other_output`), and with `grandparent` an input naming no
/// txid (`OP_1`, the final sequence) over a source of the vector's
/// `grandparent_output`.
fn unnamed_source(v: &Value, grandparent: bool) -> Transaction {
    let t = &v["transaction"];
    let n = &v["no_txid"];
    let output = |o: &Value| {
        TransactionOutput::new(
            o["satoshis"].as_u64().unwrap(),
            script(&o["locking_script"]),
        )
    };
    let mut inputs = Vec::new();
    if grandparent {
        let mut input =
            TransactionInput::with_source_transaction(source_of(&n["grandparent_output"]), 0);
        input.unlocking_script = Some(UnlockingScript::from_hex("51").unwrap());
        inputs.push(input);
    }
    Transaction::with_params(
        1,
        inputs,
        vec![
            output(&t["source_output"]),
            output(&n["source_other_output"]),
        ],
        0,
    )
}

/// The recorder's `unnamedBase`: input 0 names no txid, as
/// `TransactionInput::with_source_transaction` leaves it.
fn unnamed_base(v: &Value, grandparent: bool, vout: u32) -> Transaction {
    let mut tx = base(v);
    let input = &mut tx.inputs_mut()[0];
    input.source_txid = None;
    input.source_output_index = vout;
    input.source_transaction = Some(Box::new(unnamed_source(v, grandparent)));
    tx
}

/// The recorder's `placeUnnamed`, on input `at`'s source.
fn place_unnamed(tx: &mut Transaction, at: usize, position: &str, value: u64) {
    let source = tx.inputs_mut()[at].source_transaction.as_mut().unwrap();
    match position {
        "source_spent_output" => source.outputs_mut()[0].satoshis = Some(value),
        "source_other_output" => source.outputs_mut()[1].satoshis = Some(value),
        _ => {
            source.inputs_mut()[0]
                .source_transaction
                .as_mut()
                .unwrap()
                .outputs_mut()[0]
                .satoshis = Some(value)
        }
    }
}

/// A cell's transaction, built anew for each door.
type Build<'a> = Box<dyn Fn() -> Transaction + 'a>;

/// The recorder's `withUnnamedSecondInput`.
fn with_unnamed_second_input(v: &Value, mut tx: Transaction) -> Transaction {
    let mut input = TransactionInput::with_source_transaction(unnamed_source(v, false), 0);
    input.unlocking_script = Some(UnlockingScript::from_hex("51").unwrap());
    tx.inputs_mut().push(input);
    tx
}

#[test]
fn to_ef_on_an_input_that_names_no_txid_refuses_as_the_reference_843d7() {
    // `#writeEF` writes an unnamed input's outpoint from the source's
    // `hash()` (`Transaction.ts:1137-1138`), the plain writer, which throws
    // for an amount of 2^53 or more in any output of the source or of a
    // source it reaches the same way, ahead of the unlocking script's check.
    let v = vector();
    let n = &v["no_txid"];
    let mut differing = Vec::new();
    judge_ef(
        "no-txid control",
        &unnamed_base(&v, true, 0),
        &n["control"],
        &mut differing,
    );

    let cells = n["cells"].as_array().unwrap();
    assert_eq!(cells.len(), 12, "four edges by three positions");
    let mut refused = 0;
    for cell in cells {
        let position = cell["position"].as_str().unwrap();
        let value = amount(&cell["satoshis"]);
        let mut tx = unnamed_base(&v, true, 0);
        place_unnamed(&mut tx, 0, position, value);
        let name = format!("no txid {} {position}", cell["edge"].as_str().unwrap());
        assert_eq!(
            cell["to_ef"]["ok"].as_bool().unwrap(),
            value < TWO_53,
            "{name}"
        );
        if value >= TWO_53 {
            assert_eq!(cell["to_ef"]["error"], UNSAFE_WRITE, "{name}");
            refused += 1;
        }
        judge_ef(&name, &tx, cell, &mut differing);
    }
    assert_eq!(refused, 9, "three edges by three positions");

    let two_fault = n["two_fault_cells"].as_array().unwrap();
    let builds: [(&str, Build, &str); 6] = [
        (
            "source_other_output_with_input_0_lacking_its_unlocking_script",
            Box::new(|| {
                let mut tx = unnamed_base(&v, false, 0);
                tx.inputs_mut()[0].unlocking_script = None;
                place_unnamed(&mut tx, 0, "source_other_output", TWO_53);
                tx
            }),
            UNSAFE_WRITE,
        ),
        (
            "source_spent_output_with_input_0_lacking_its_unlocking_script",
            Box::new(|| {
                let mut tx = unnamed_base(&v, false, 0);
                tx.inputs_mut()[0].unlocking_script = None;
                place_unnamed(&mut tx, 0, "source_spent_output", TWO_53);
                tx
            }),
            UNSAFE_WRITE,
        ),
        (
            "source_other_output_with_input_0_spending_past_the_source",
            Box::new(|| {
                let mut tx = unnamed_base(&v, false, 2);
                place_unnamed(&mut tx, 0, "source_other_output", TWO_53);
                tx
            }),
            UNSAFE_WRITE,
        ),
        (
            "source_other_output_then_input_1_unlinked",
            Box::new(|| {
                let mut tx = unnamed_base(&v, false, 0);
                place_unnamed(&mut tx, 0, "source_other_output", TWO_53);
                let s = &v["transaction"]["second_input"];
                let mut input = TransactionInput::new(s["txid"].as_str().unwrap().to_string(), 0);
                input.unlocking_script = Some(UnlockingScript::from_hex("51").unwrap());
                tx.inputs_mut().push(input);
                tx
            }),
            UNSAFE_WRITE,
        ),
        (
            "input_0_lacking_its_unlocking_script_then_input_1_unnamed_with_source_other_output",
            Box::new(|| {
                let mut tx = with_unnamed_second_input(&v, base(&v));
                tx.inputs_mut()[0].unlocking_script = None;
                place_unnamed(&mut tx, 1, "source_other_output", TWO_53);
                tx
            }),
            "unlockingScript is undefined",
        ),
        (
            "input_1_unnamed_with_source_other_output_then_output_0",
            Box::new(|| {
                let mut tx = with_unnamed_second_input(&v, base(&v));
                place_unnamed(&mut tx, 1, "source_other_output", TWO_53);
                tx.outputs_mut()[0].satoshis = Some(TWO_53);
                tx
            }),
            UNSAFE_WRITE,
        ),
    ];
    assert_eq!(two_fault.len(), builds.len());
    for (cell, (name, build, words)) in two_fault.iter().zip(builds.iter()) {
        assert_eq!(cell["name"], *name);
        assert_eq!(cell["to_ef"]["error"], *words, "the recording: {name}");
        judge_ef(name, &build(), cell, &mut differing);
    }

    assert!(differing.is_empty(), "{differing:#?}");
}

#[test]
fn the_three_orders_the_strength_read_named_are_the_references_843d7() {
    // F1 of the strength read of PR #913: S1 the unlocking script before the
    // spent amount, S2 an unlinked input 0 before input 1's amount, S3 a
    // named input's unspent source output not judged.
    let v = vector();
    let cells = v["strength_cells"].as_array().unwrap();
    let builds: [(&str, Build); 3] = [
        (
            "s1_source_amount_with_input_0_lacking_its_unlocking_script",
            Box::new(|| {
                let mut tx = base(&v);
                tx.inputs_mut()[0].unlocking_script = None;
                place(&mut tx, "source_output", TWO_53);
                tx
            }),
        ),
        (
            "s2_input_0_unlinked_then_input_1_source_amount",
            Box::new(|| {
                let mut tx = with_second_input(&v, true, true);
                tx.inputs_mut()[0].source_transaction = None;
                tx.inputs_mut()[1]
                    .source_transaction
                    .as_mut()
                    .unwrap()
                    .outputs_mut()[0]
                    .satoshis = Some(TWO_53);
                tx
            }),
        ),
        (
            "s3_named_input_whose_source_carries_an_unspent_output",
            Box::new(|| {
                let mut tx = base(&v);
                tx.inputs_mut()[0]
                    .source_transaction
                    .as_mut()
                    .unwrap()
                    .outputs_mut()
                    .push(TransactionOutput::new(
                        TWO_53,
                        LockingScript::from_hex("51").unwrap(),
                    ));
                tx
            }),
        ),
    ];
    assert_eq!(cells.len(), builds.len());
    let mut differing = Vec::new();
    for (cell, (name, build)) in cells.iter().zip(builds.iter()) {
        assert_eq!(cell["name"], *name);
        judge_ef(name, &build(), cell, &mut differing);
    }
    assert!(differing.is_empty(), "{differing:#?}");
}

/// The recorder's `namedInput`: the vector's `walk.named_txid`, output 0,
/// linked to `source`, `OP_1` its unlocking script unless absent.
fn named_input(v: &Value, source: Transaction, unlocking: bool) -> TransactionInput {
    let mut input = TransactionInput::new(v["walk"]["named_txid"].as_str().unwrap().to_string(), 0);
    if unlocking {
        input.unlocking_script = Some(UnlockingScript::from_hex("51").unwrap());
    }
    input.source_transaction = Some(Box::new(source));
    input
}

/// A source of one `OP_1` output of `satoshis`, the grandparent's script.
fn grandparent_at(v: &Value, satoshis: u64) -> Transaction {
    let mut g = source_of(&v["no_txid"]["grandparent_output"]);
    g.outputs_mut()[0].satoshis = Some(satoshis);
    g
}

#[test]
fn the_walk_stops_at_a_named_input_and_judges_every_input_843d7() {
    // The scoped re-read of the fold (PR #913): two cells no test reached.
    // M1: the walk stops at an input that names a txid, as the reference's
    // plain writer writes that outpoint from its text and never hashes what
    // it links (`Transaction.ts:1069-1071`): written. M2: the check runs on
    // every input, not input 0 alone: an unnamed input 1 whose source
    // carries 2^53 in an output it does not spend is refused in the writer's
    // words (`:1137-1138`). And the residual it named, a source failing both
    // its unlocking script's check and the amount: where the source's input
    // names a txid the reference reaches the unlocking script's check
    // (`:1072-1074`) before the output (`:1083`) and this crate's walk, which
    // judges amounts alone, the amount (STATED, `docs/lanes/fix-843d7.md`,
    // rows left); where that input names none the grandparent's hash is
    // written ahead of that check (`:1067`) and both refuse the amount.
    let v = vector();
    let cells = v["walk"]["cells"].as_array().unwrap();
    let builds: [(&str, Build, Option<&str>, &str); 4] = [
        (
            "m1_unnamed_source_whose_input_names_a_txid_over_a_grandparent_at_two_to_the_53",
            Box::new(|| {
                let mut tx = unnamed_base(&v, false, 0);
                let gp = grandparent_at(&v, TWO_53);
                let input = named_input(&v, gp, true);
                tx.inputs_mut()[0]
                    .source_transaction
                    .as_mut()
                    .unwrap()
                    .inputs_mut()
                    .push(input);
                tx
            }),
            None,
            "written",
        ),
        (
            "m2_input_1_unnamed_with_source_other_output_alone",
            Box::new(|| {
                let mut tx = with_unnamed_second_input(&v, base(&v));
                place_unnamed(&mut tx, 1, "source_other_output", TWO_53);
                tx
            }),
            Some(UNSAFE_WRITE),
            UNSAFE_WRITE,
        ),
        (
            "source_input_named_lacking_its_unlocking_script_with_source_other_output",
            Box::new(|| {
                let mut tx = unnamed_base(&v, false, 0);
                let gp = source_of(&v["no_txid"]["grandparent_output"]);
                let input = named_input(&v, gp, false);
                tx.inputs_mut()[0]
                    .source_transaction
                    .as_mut()
                    .unwrap()
                    .inputs_mut()
                    .push(input);
                place_unnamed(&mut tx, 0, "source_other_output", TWO_53);
                tx
            }),
            Some("unlockingScript is undefined"),
            UNSAFE_WRITE,
        ),
        (
            "source_input_unnamed_lacking_its_unlocking_script_over_a_grandparent_at_two_to_the_53",
            Box::new(|| {
                let mut tx = unnamed_base(&v, true, 0);
                tx.inputs_mut()[0]
                    .source_transaction
                    .as_mut()
                    .unwrap()
                    .inputs_mut()[0]
                    .unlocking_script = None;
                place_unnamed(&mut tx, 0, "grandparent_output", TWO_53);
                tx
            }),
            Some(UNSAFE_WRITE),
            UNSAFE_WRITE,
        ),
    ];
    assert_eq!(cells.len(), builds.len());
    let mut differing = Vec::new();
    for (cell, (name, build, there, here)) in cells.iter().zip(builds.iter()) {
        assert_eq!(cell["name"], *name);
        for door in ["to_ef", "to_hex_ef"] {
            assert_eq!(
                cell[door]["error"].as_str(),
                *there,
                "the recording: {name} {door}"
            );
        }
        let tx = build();
        let answers = [tx.to_ef().map(|b| to_hex(&b)), tx.to_hex_ef()];
        for answer in answers {
            let answered = match answer {
                Ok(_) => "written".to_string(),
                Err(Error::TransactionError(words)) => words,
                Err(e) => panic!("{name}: {e:?}"),
            };
            assert_eq!(answered, *here, "this crate's answer: {name}");
        }
        if there.is_some_and(|words| words != *here) {
            // The one stated cell: both refuse, in other words.
            assert_eq!(
                *name,
                "source_input_named_lacking_its_unlocking_script_with_source_other_output"
            );
        } else {
            judge_ef(name, &tx, cell, &mut differing);
        }
    }
    assert!(differing.is_empty(), "{differing:#?}");
}

// ============================================================================
// The walk's two rules as a property (the third fold)
// ============================================================================

/// The inputs of every case's transaction, and the deepest chain.
const WALK_INPUTS: usize = 4;
const WALK_MAX_DEPTH: usize = 4;

/// One case of the space, as the recorder's `walkCase` describes it: a
/// transaction of four inputs, `unnamed` naming no txid and the others
/// naming `walk.named_txid`, linked to a clean source; the unnamed input
/// spends output 0 of level 1 of a chain of `depth` levels, each of two
/// outputs (7 and 1 satoshis) and, above the last, one input linking the next
/// level, naming a txid where `links[k - 1]` is true; `at` puts 2^53 at
/// `(level, output)`.
#[derive(Clone, Debug)]
struct WalkCase {
    unnamed: usize,
    depth: usize,
    links: Vec<bool>,
    at: Option<(usize, usize)>,
}

impl WalkCase {
    /// The recorder's `walkCaseName`.
    fn name(&self) -> String {
        let links: String = self
            .links
            .iter()
            .map(|&n| if n { 'n' } else { 'u' })
            .collect();
        format!(
            "u{}_d{}_links_{}_at_{}",
            self.unnamed,
            self.depth,
            if links.is_empty() { "none" } else { &links },
            self.at
                .map_or("none".to_string(), |(level, o)| format!("l{level}o{o}"))
        )
    }

    /// Every case: four unnamed positions, depth 1 to 4, every pattern of
    /// links, 2^53 nowhere or at either output of any level.
    fn space() -> Vec<WalkCase> {
        let mut cases = Vec::new();
        for unnamed in 0..WALK_INPUTS {
            for depth in 1..=WALK_MAX_DEPTH {
                for mask in 0..1u32 << (depth - 1) {
                    let links: Vec<bool> = (0..depth - 1).map(|k| mask >> k & 1 == 1).collect();
                    let mut ats = vec![None];
                    for level in 1..=depth {
                        ats.extend([Some((level, 0)), Some((level, 1))]);
                    }
                    for at in ats {
                        cases.push(WalkCase {
                            unnamed,
                            depth,
                            links: links.clone(),
                            at,
                        });
                    }
                }
            }
        }
        cases
    }

    /// A recorded sample cell's description.
    fn from_cell(cell: &Value) -> WalkCase {
        let at = &cell["at"];
        WalkCase {
            unnamed: cell["unnamed_input"].as_u64().unwrap() as usize,
            depth: cell["depth"].as_u64().unwrap() as usize,
            links: cell["links"]
                .as_str()
                .unwrap()
                .chars()
                .map(|c| c == 'n')
                .collect(),
            at: (!at.is_null()).then(|| {
                (
                    at["level"].as_u64().unwrap() as usize,
                    at["output"].as_u64().unwrap() as usize,
                )
            }),
        }
    }

    /// The case built by this crate's builders.
    fn build(&self, named_txid: &str) -> Transaction {
        let op1 = || LockingScript::from_hex("51").unwrap();
        let input = |named: bool, source: Transaction| {
            let mut input = if named {
                let mut input = TransactionInput::new(named_txid.to_string(), 0);
                input.source_transaction = Some(Box::new(source));
                input
            } else {
                TransactionInput::with_source_transaction(source, 0)
            };
            input.unlocking_script = Some(UnlockingScript::from_hex("51").unwrap());
            input
        };
        let mut below: Option<Transaction> = None;
        for level in (1..=self.depth).rev() {
            let mut outputs = vec![
                TransactionOutput::new(7, op1()),
                TransactionOutput::new(1, op1()),
            ];
            if let Some((at, o)) = self.at {
                if at == level {
                    outputs[o].satoshis = Some(TWO_53);
                }
            }
            let inputs = match below.take() {
                Some(next) => vec![input(self.links[level - 1], next)],
                None => vec![],
            };
            below = Some(Transaction::with_params(1, inputs, outputs, 0));
        }
        let mut level_1 = below;
        let inputs = (0..WALK_INPUTS)
            .map(|i| {
                if i == self.unnamed {
                    input(false, level_1.take().unwrap())
                } else {
                    let clean = Transaction::with_params(
                        1,
                        vec![],
                        vec![TransactionOutput::new(7, op1())],
                        0,
                    );
                    input(true, clean)
                }
            })
            .collect();
        Transaction::with_params(1, inputs, vec![TransactionOutput::new(1, op1())], 0)
    }
}

/// The oracle: what the reference's `toEF` answers on `case`, written from
/// its lines (`ts-stack@edf6e03` `Transaction.ts`), never from `src/`:
/// `None` written, `Some(words)` refused.
fn reference_to_ef(case: &WalkCase) -> Option<&'static str> {
    // `#writeEF` walks the inputs in order (`:1131`). A named input writes
    // its txid's text (`:1140`), its `OP_1` (`:1143-1148`) and its clean
    // source's 7 satoshis (`:1150`). The unnamed input writes
    // `sourceTransaction.hash()` (`:1137-1138`), level 1's plain writer,
    // `#writeTransactionBody` (`:1059-1089`). There a level's link input
    // naming no txid writes the next level's hash ahead of the rest (`:1063-1067`), the
    // same writer one level down; one naming a txid writes its text and never
    // hashes what it links (`:1069-1071`); every unlocking script is present
    // (`:1073`); then each output through `writeUInt64LE` (`:1083`), which
    // throws at 2^53 or more (`WriterUint8Array.ts:184-185`,
    // `BigNumber.ts:460-463`). So the hash throws exactly when 2^53 sits at a
    // level every link above it reaches naming no txid, whichever input is the
    // unnamed one. Nothing else can throw: the unnamed input's spent amount
    // (`:1150`) is level 1's output 0, which the hash judged earlier, and the one
    // output (`:1158`) is 1 satoshi.
    let (level, _) = case.at?;
    case.links[..level - 1]
        .iter()
        .all(|named| !named)
        .then_some(UNSAFE_WRITE)
}

/// This crate's answer on `tx` through both doors, as the oracle speaks.
fn crate_to_ef(tx: &Transaction) -> [Result<Option<String>, String>; 2] {
    let speak = |answer: Result<String, Error>| match answer {
        Ok(hex) => Ok(Some(hex)),
        Err(Error::TransactionError(words)) => Err(words),
        Err(e) => Err(format!("{e:?}")),
    };
    [speak(tx.to_ef().map(|b| to_hex(&b))), speak(tx.to_hex_ef())]
}

#[test]
fn the_walk_is_the_references_over_every_depth_and_input_843d7() {
    // The third fold (PR #913): the walk's stop at a named input and the
    // check on every input, pinned over their whole small space (depth 1 to
    // 4, the unnamed input at index 0 to 3, every pattern of named links,
    // 2^53 nowhere or at either output of any level: 452 cases) against the
    // oracle above, and the oracle against the reference's recording of a
    // fixed sample (`walk.space.sample`, 38 cells), that one before the space. A wrong
    // oracle fails on the recording; a wrong crate fails on the oracle.
    let v = vector();
    let named_txid = v["walk"]["named_txid"].as_str().unwrap();
    let space = WalkCase::space();
    assert_eq!(space.len(), 452);

    // The oracle against the recording, before the space: a wrong oracle
    // fails here.
    let mut differing = Vec::new();
    let space_v = &v["walk"]["space"];
    assert_eq!(space_v["inputs"], WALK_INPUTS);
    assert_eq!(space_v["max_depth"], WALK_MAX_DEPTH);
    let sample = space_v["sample"].as_array().unwrap();
    assert_eq!(sample.len(), 38);
    let mut by_depth = BTreeMap::new();
    let mut by_input = BTreeMap::new();
    for cell in sample {
        let case = WalkCase::from_cell(cell);
        assert_eq!(cell["name"], case.name().as_str());
        assert!(
            space.iter().any(|c| c.name() == case.name()),
            "{} is in the space",
            case.name()
        );
        *by_depth.entry(case.depth).or_insert(0) += 1;
        *by_input.entry(case.unnamed).or_insert(0) += 1;
        let oracle = reference_to_ef(&case);
        for door in ["to_ef", "to_hex_ef"] {
            let recorded = &cell[door];
            let there = if recorded["ok"].as_bool().unwrap() {
                None
            } else {
                Some(recorded["error"].as_str().unwrap())
            };
            if there != oracle {
                differing.push(format!(
                    "{} {door}: recorded {there:?}, the oracle {oracle:?}",
                    case.name()
                ));
            }
        }
        // And the crate's bytes, where both write, the reference's.
        judge_ef(&case.name(), &case.build(named_txid), cell, &mut differing);
    }
    assert!(
        differing.is_empty(),
        "the oracle against the recording: {differing:#?}"
    );
    // The sample covers every depth and every unnamed input at least
    // twice.
    assert_eq!(by_depth.len(), WALK_MAX_DEPTH);
    assert!(by_depth.values().all(|&n| n >= 2), "{by_depth:?}");
    assert_eq!(by_input.len(), WALK_INPUTS);
    assert!(by_input.values().all(|&n| n >= 2), "{by_input:?}");
    // The second re-read's two deeper cells (P2, P3).
    for name in ["u0_d3_links_un_at_l3o0", "u2_d1_links_none_at_l1o1"] {
        assert!(sample.iter().any(|c| c["name"] == name), "{name} recorded");
    }

    // Then the crate against the oracle over the whole space.
    let mut differing = Vec::new();
    for case in &space {
        let tx = case.build(named_txid);
        let oracle = reference_to_ef(case);
        for (door, answer) in ["to_ef", "to_hex_ef"].into_iter().zip(crate_to_ef(&tx)) {
            let agrees = match (&answer, oracle) {
                (Ok(Some(hex)), None) => {
                    // What it writes, its EF reader reads back.
                    Transaction::from_hex_ef(hex)
                        .and_then(|t| t.to_hex_ef())
                        .as_deref()
                        == Ok(hex)
                }
                (Err(words), Some(there)) => words == there,
                _ => false,
            };
            if !agrees {
                differing.push(format!(
                    "{} {door}: here {:?}, the oracle {:?}",
                    case.name(),
                    answer.map(|hex| hex.map(|h| h[..20].to_string())),
                    oracle.unwrap_or("written")
                ));
            }
        }
    }
    assert!(
        differing.is_empty(),
        "the crate against the oracle: {differing:#?}"
    );
}

// ============================================================================
// The plain writer, stated
// ============================================================================

/// xorshift64*: the file's own generator, reproducible from its seed.
struct Rng(u64);
impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 >> 12;
        self.0 ^= self.0 << 25;
        self.0 ^= self.0 >> 27;
        self.0.wrapping_mul(0x2545_f491_4f6c_dd1d)
    }
    fn below(&mut self, n: u64) -> u64 {
        self.next() % n.max(1)
    }
    fn txid(&mut self) -> String {
        let bytes: Vec<u8> = (0..32).map(|_| self.next() as u8).collect();
        to_hex(&bytes)
    }
    /// A script of opcodes that carry no data, so its bytes are its chunks.
    fn script(&mut self) -> Vec<u8> {
        let len = self.below(6) as usize;
        (0..len).map(|_| 0x51 + (self.next() % 16) as u8).collect()
    }
    fn safe_amount(&mut self) -> u64 {
        self.below(TWO_53)
    }
    fn unsafe_amount(&mut self) -> u64 {
        match self.below(4) {
            0 => TWO_53,
            1 => TWO_63,
            2 => u64::MAX,
            _ => TWO_53 + self.below(u64::MAX - TWO_53),
        }
    }
}

/// An input's fields, and its linked source output when it has one.
struct PlanInput {
    txid: String,
    vout: u32,
    unlocking: Vec<u8>,
    sequence: u32,
    source: Option<(u64, Vec<u8>)>,
    /// `false`: the input names no txid (`with_source_transaction`), its
    /// outpoint the linked source's hash.
    named: bool,
    /// A second output of the linked source after the spent one, unspent.
    extra: Option<u64>,
}

/// A transaction's fields, held apart from any `Transaction`.
struct Plan {
    version: u32,
    inputs: Vec<PlanInput>,
    outputs: Vec<(u64, Vec<u8>)>,
    lock_time: u32,
}

impl Plan {
    fn random(rng: &mut Rng, outputs: usize, link: impl Fn(&mut Rng) -> bool) -> Self {
        let inputs = (0..1 + rng.below(3))
            .map(|_| PlanInput {
                txid: rng.txid(),
                vout: rng.below(3) as u32,
                unlocking: rng.script(),
                sequence: rng.next() as u32,
                source: if link(rng) {
                    Some((rng.safe_amount(), rng.script()))
                } else {
                    None
                },
                named: true,
                extra: None,
            })
            .collect();
        Plan {
            version: 1 + rng.below(2) as u32,
            inputs,
            outputs: (0..outputs)
                .map(|_| (rng.safe_amount(), rng.script()))
                .collect(),
            lock_time: rng.next() as u32,
        }
    }

    /// The transaction, built through this crate's public constructors.
    fn build(&self) -> Transaction {
        let inputs = self
            .inputs
            .iter()
            .map(|i| {
                let mut input = TransactionInput::new(i.txid.clone(), i.vout);
                input.unlocking_script = Some(UnlockingScript::from_binary(&i.unlocking).unwrap());
                input.sequence = i.sequence;
                if !i.named {
                    input.source_txid = None;
                }
                if let Some((satoshis, script)) = &i.source {
                    // The spent output at `vout`, placeholders before it.
                    let mut outputs: Vec<TransactionOutput> = (0..i.vout)
                        .map(|_| TransactionOutput::new(0, LockingScript::new()))
                        .collect();
                    outputs.push(TransactionOutput::new(
                        *satoshis,
                        LockingScript::from_binary(script).unwrap(),
                    ));
                    if let Some(extra) = i.extra {
                        outputs.push(TransactionOutput::new(extra, LockingScript::new()));
                    }
                    input.source_transaction =
                        Some(Box::new(Transaction::with_params(1, vec![], outputs, 0)));
                }
                input
            })
            .collect();
        let outputs = self
            .outputs
            .iter()
            .map(|(satoshis, script)| {
                TransactionOutput::new(*satoshis, LockingScript::from_binary(script).unwrap())
            })
            .collect();
        Transaction::with_params(self.version, inputs, outputs, self.lock_time)
    }

    /// The node's serialization of the fields, written by this file: each
    /// amount its eight little-endian bytes (`READWRITE(nValue)`).
    fn node_bytes(&self) -> Vec<u8> {
        let mut out = self.version.to_le_bytes().to_vec();
        out.push(self.inputs.len() as u8);
        for i in &self.inputs {
            let mut txid = from_hex(&i.txid).unwrap();
            txid.reverse();
            out.extend_from_slice(&txid);
            out.extend_from_slice(&i.vout.to_le_bytes());
            out.push(i.unlocking.len() as u8);
            out.extend_from_slice(&i.unlocking);
            out.extend_from_slice(&i.sequence.to_le_bytes());
        }
        out.push(self.outputs.len() as u8);
        for (satoshis, script) in &self.outputs {
            out.extend_from_slice(&satoshis.to_le_bytes());
            out.push(script.len() as u8);
            out.extend_from_slice(script);
        }
        out.extend_from_slice(&self.lock_time.to_le_bytes());
        out
    }

    /// The field-built JSON document (no `hex` member).
    fn field_json(&self) -> String {
        let inputs: Vec<Value> = self
            .inputs
            .iter()
            .map(|i| {
                json!({
                    "unlockingScript": to_hex(&i.unlocking),
                    "txid": i.txid,
                    "vout": i.vout,
                    "sequence": i.sequence,
                })
            })
            .collect();
        let outputs: Vec<Value> = self
            .outputs
            .iter()
            .map(|(satoshis, script)| json!({ "satoshis": satoshis, "lockingScript": to_hex(script) }))
            .collect();
        json!({
            "inputs": inputs,
            "outputs": outputs,
            "version": self.version,
            "lockTime": self.lock_time,
        })
        .to_string()
    }

    fn all_outputs_safe(&self) -> bool {
        self.outputs.iter().all(|(satoshis, _)| *satoshis < TWO_53)
    }
}

fn txid_of(bytes: &[u8]) -> String {
    let mut hash = sha256d(bytes);
    hash.reverse();
    to_hex(&hash)
}

/// tx-00026 (bsv-script-lean `corpus/tx/tx.jsonl`, an output of 2^63), the
/// node oracle's bytes, as `tests/verify_input_door_amount_874.rs` holds them.
const TX_00026: &str = "0200000001636324f2afc64bfbe8bc2327a0cdd05ec515df96c5ca1c92538fc18521587d060000000000ffffffff010000000000000080015100000000";

#[test]
fn the_writer_is_the_nodes_serializer_stated_843d7() {
    // STATED against the reference, whose writer throws from 2^53 up
    // (`Transaction.ts:1083`): `to_binary`, `to_hex`, `hash` and `id` are the
    // node's serializer at every amount. Green on the base; its RED is the
    // two plants named in the lane record.
    const SEED: u64 = 0x0843_d700_5eed_0001;
    const PER_CELL: usize = 200;
    let classes: [(&str, Option<u64>); 7] = [
        ("zero", Some(0)),
        ("max_money", Some(MAX_MONEY)),
        ("two_to_the_53_minus_1", Some(TWO_53 - 1)),
        ("two_to_the_53", Some(TWO_53)),
        ("two_to_the_63", Some(TWO_63)),
        ("u64_max", Some(u64::MAX)),
        ("random", None),
    ];
    let mut rng = Rng(SEED);
    let mut counts: BTreeMap<(&str, &str, bool), usize> = BTreeMap::new();
    for (class, fixed) in classes {
        for place in ["output_0", "middle", "last"] {
            for _ in 0..PER_CELL {
                let outputs = 3 + rng.below(4) as usize;
                let mut plan = Plan::random(&mut rng, outputs, |_| false);
                // One output in five of the others draws from every `u64`.
                for output in plan.outputs.iter_mut() {
                    if rng.below(5) == 0 {
                        output.0 = rng.next();
                    }
                }
                let at = match place {
                    "output_0" => 0,
                    "middle" => outputs / 2,
                    _ => outputs - 1,
                };
                plan.outputs[at].0 = fixed.unwrap_or_else(|| rng.next());
                let label = format!(
                    "{class} {place} {:?}",
                    plan.outputs.iter().map(|o| o.0).collect::<Vec<_>>()
                );

                let expected = plan.node_bytes();
                let tx = plan.build();
                let bytes = tx.to_binary();
                assert_eq!(to_hex(&bytes), to_hex(&expected), "to_binary: {label}");
                assert_eq!(tx.to_hex(), to_hex(&expected), "to_hex: {label}");
                assert_eq!(tx.hash(), sha256d(&expected), "hash: {label}");
                assert_eq!(tx.id(), txid_of(&expected), "id: {label}");

                // The node's door reads them whatever the amounts (#874).
                let read = SpendingTransaction::from_bytes(&bytes)
                    .unwrap_or_else(|e| panic!("from_bytes: {label}: {e}"));
                assert_eq!(read.input_count(), plan.inputs.len(), "{label}");

                // The reference's readers read them back exactly when every
                // amount is one they hold (#844).
                let safe = plan.all_outputs_safe();
                match Transaction::from_binary(&bytes) {
                    Ok(back) => {
                        assert!(safe, "from_binary read an amount of 2^53 or more: {label}");
                        assert_eq!(back.to_binary(), bytes, "{label}");
                        assert_eq!(back.id(), tx.id(), "{label}");
                    }
                    Err(e) => {
                        assert!(!safe, "from_binary refused safe amounts: {label}: {e}");
                        assert_eq!(e, unsafe_read(), "{label}");
                    }
                }
                // The field door answers what the byte readers answer: the
                // verdict, the id and the error (the strength read's F2).
                match (
                    Transaction::from_json(&plan.field_json()),
                    Transaction::from_binary(&bytes),
                ) {
                    (Ok(fields), Ok(read)) => assert_eq!(fields.id(), read.id(), "{label}"),
                    (Err(fields), Err(read)) => assert_eq!(fields, read, "{label}"),
                    (fields, read) => panic!(
                        "from_json {:?} where from_binary {:?}: {label}",
                        fields.map(|t| t.id()),
                        read.map(|t| t.id())
                    ),
                }
                *counts.entry((class, place, safe)).or_default() += 1;
            }
        }
    }
    // The reach: every class at every place, each fixed class of 2^53 or
    // more never read back, each below it read back at least once.
    for (class, fixed) in classes {
        for place in ["output_0", "middle", "last"] {
            let read = counts.get(&(class, place, true)).copied().unwrap_or(0);
            let refused = counts.get(&(class, place, false)).copied().unwrap_or(0);
            assert_eq!(read + refused, PER_CELL, "{class} {place}");
            match fixed {
                Some(value) if value >= TWO_53 => assert_eq!(read, 0, "{class} {place}"),
                Some(_) => assert!(
                    read >= 20 && refused >= 20,
                    "{class} {place}: {read}/{refused}"
                ),
                None => assert!(refused >= PER_CELL / 2, "{class} {place}: {refused}"),
            }
        }
    }

    // tx-00026 rebuilt from its fields is the node oracle's bytes.
    let mut input = TransactionInput::new(
        "067d582185c18f53921ccac596df15c55ed0cda02723bce8fb4bc6aff2246363".to_string(),
        0,
    );
    input.unlocking_script = Some(UnlockingScript::from_binary(&[]).unwrap());
    let output = TransactionOutput::new(TWO_63, LockingScript::from_binary(&[0x51]).unwrap());
    let tx = Transaction::with_params(2, vec![input], vec![output], 0);
    assert_eq!(tx.to_hex(), TX_00026);
    assert_eq!(tx.id(), txid_of(&from_hex(TX_00026).unwrap()));
    assert!(SpendingTransaction::from_bytes(&tx.to_binary()).is_ok());
    assert_eq!(Transaction::from_hex(TX_00026).unwrap_err(), unsafe_read());
}

// ============================================================================
// The differential's recorder (base against tip)
// ============================================================================

/// The leading eight bytes of the SHA-256 of an answer.
fn digest(bytes: &[u8]) -> String {
    to_hex(&sha256(bytes)[..8])
}

fn class<T>(answer: Result<T, Error>, bytes: impl Fn(&T) -> Vec<u8>) -> String {
    match answer {
        Ok(value) => format!("Ok {}", digest(&bytes(&value))),
        Err(e) => format!("Err {e}"),
    }
}

/// Writes, for 20,000 seeded transactions (a tenth with an output, a linked
/// source's spent output or a second, unspent output of a linked source at or
/// past 2^53; a third of the linked inputs naming no txid since the fold),
/// one line per call with its class.
/// Run on a scratch copy of the base and on the tip, then diff:
///   AMOUNT_DOORS_843D7_OUT=<file> cargo test --features "full,http" \
///     --test transaction_amount_doors_843d7 -- --ignored record_the_differential
#[test]
#[ignore = "the differential's recorder: run by hand on the base and on the tip"]
fn record_the_differential_843d7() {
    use std::fmt::Write as _;
    const SEED: u64 = 0x0843_d7d1_ff00_0001;
    const TRANSACTIONS: usize = 20_000;
    let out = std::env::var("AMOUNT_DOORS_843D7_OUT").expect("AMOUNT_DOORS_843D7_OUT names a file");
    let mut rng = Rng(SEED);
    let mut lines = String::new();
    let mut with_unsafe = 0;
    let mut unnamed_inputs = 0;
    for n in 0..TRANSACTIONS {
        let outputs = 1 + rng.below(5) as usize;
        // One input in twenty unlinked, so `to_ef`'s older refusal is met.
        let mut plan = Plan::random(&mut rng, outputs, |rng| rng.below(20) != 0);
        // A third of the linked inputs name no txid (the fold).
        for input in plan.inputs.iter_mut() {
            if input.source.is_some() && rng.below(3) == 0 {
                input.named = false;
                unnamed_inputs += 1;
            }
        }
        let mut kind = "safe";
        if rng.below(10) == 0 {
            with_unsafe += 1;
            let linked: Vec<usize> = (0..plan.inputs.len())
                .filter(|i| plan.inputs[*i].source.is_some())
                .collect();
            let value = rng.unsafe_amount();
            let pick = rng.below(3);
            if pick < 2 && !linked.is_empty() {
                let at = linked[rng.below(linked.len() as u64) as usize];
                let named = if plan.inputs[at].named {
                    "named"
                } else {
                    "unnamed"
                };
                if pick == 0 {
                    plan.inputs[at].source.as_mut().unwrap().0 = value;
                    kind = if named == "named" {
                        "unsafe_source_named"
                    } else {
                        "unsafe_source_unnamed"
                    };
                } else {
                    plan.inputs[at].extra = Some(value);
                    kind = if named == "named" {
                        "unsafe_unspent_named"
                    } else {
                        "unsafe_unspent_unnamed"
                    };
                }
            } else {
                let at = rng.below(outputs as u64) as usize;
                plan.outputs[at].0 = value;
                kind = "unsafe_output";
            }
        }
        let tx = plan.build();
        let calls: [(&str, String); 8] = [
            ("to_binary", class(Ok(tx.to_binary()), |b| b.clone())),
            ("to_hex", class(Ok(tx.to_hex()), |s| s.clone().into_bytes())),
            ("id", class(Ok(tx.id()), |s| s.clone().into_bytes())),
            ("to_json", class(tx.to_json(), |s| s.clone().into_bytes())),
            ("to_ef", class(tx.to_ef(), |b| b.clone())),
            (
                "to_hex_ef",
                class(tx.to_hex_ef(), |s| s.clone().into_bytes()),
            ),
            (
                "from_json_fields",
                class(Transaction::from_json(&plan.field_json()), |t| {
                    t.to_binary()
                }),
            ),
            (
                "from_json_of_to_json",
                class(tx.to_json().and_then(|j| Transaction::from_json(&j)), |t| {
                    t.to_binary()
                }),
            ),
        ];
        for (call, answer) in calls {
            writeln!(lines, "{n} {kind} {call} {answer}").unwrap();
        }
    }
    assert!(
        (TRANSACTIONS / 10 - 300..=TRANSACTIONS / 10 + 300).contains(&with_unsafe),
        "a tenth carry an amount at or past 2^53: {with_unsafe}"
    );
    std::fs::write(&out, lines).unwrap();
    println!(
        "{TRANSACTIONS} transactions, {with_unsafe} with an unsafe amount, {unnamed_inputs} inputs naming no txid -> {out}"
    );
}
