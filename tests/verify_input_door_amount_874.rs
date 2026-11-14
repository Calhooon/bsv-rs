//! The one-input door reads a transaction as the node's script door reads it
//! (#874): `SpendingTransaction::from_bytes` takes an output amount as any
//! 64-bit value, as bitcoin-sv v1.2.2's consensus library deserializes it
//! (`bitcoinconsensus.cpp:92-93`, `primitives/transaction.h:190-194`,
//! `amount.h:111`) and checks none; under a word the door judges the input;
//! in the reference's default mode a transaction holding an amount of 2^53 or
//! more is refused before the index check and before evaluation as
//! `InputRefusal::Transaction`, in `Transaction::from_binary`'s words
//! (`Number can only safely store up to 53 bits`, `ts-stack@edf6e03`
//! `BigNumber.ts:624-628`). `from_binary` keeps the reference's bound (#844).
//!
//! The invariant: `from_bytes` refuses exactly what `from_binary` refuses,
//! with its error, save a transaction whose only refusal there is an amount of
//! 2^53 or more; in the default mode the door answers `from_binary`'s error
//! for those. A seeded property over transactions this crate's writer builds,
//! every amount class at an output's first, middle and last place, each cell
//! counted against a floor.
//!
//! The oracle's entry `tx/tx-00026` (bsv-script-lean@1c051eae
//! `corpus/tx/tx.jsonl`, family `tx/rules/vout-negative`, an output of 2^63)
//! is judged valid by the node's door (GoBDK at 4eab3acd, both columns): here
//! under both words of both eras, and refused in the default mode.
#![cfg(feature = "transaction")]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)] // Test code: a failed unwrap is the test failing.

use std::collections::BTreeMap;

use bsv_rs::primitives::{from_hex, to_hex};
use bsv_rs::script::{LockingScript, ProtocolEra, ScriptFlags, UnlockingScript};
use bsv_rs::transaction::{
    verify_input, DefaultMode, InputRefusal, InputRules, SpendingTransaction, Transaction,
    TransactionInput, TransactionOutput,
};
use bsv_rs::Error;

/// `from_binary`'s refusal of an amount of 2^53 or more (#844).
fn unsafe_amount() -> Error {
    Error::TransactionError("Number can only safely store up to 53 bits".to_string())
}

/// The four words of the two post-Genesis eras.
fn words() -> Vec<InputRules> {
    let mut rules = Vec::new();
    for era in [ProtocolEra::PostGenesis, ProtocolEra::PostChronicle] {
        rules.push(InputRules::under(ScriptFlags::block(era)).unwrap());
        rules.push(InputRules::under(ScriptFlags::standard(era)).unwrap());
    }
    rules
}

/// The default mode, bare and with each override.
fn default_modes() -> Vec<InputRules> {
    vec![
        InputRules::reference_default(),
        InputRules::reference_default_with(DefaultMode::new().with_require_push_only(true)),
        InputRules::reference_default_with(DefaultMode::new().with_require_minimal(false)),
        InputRules::reference_default_with(DefaultMode::new().with_utxo_after_chronicle(false)),
    ]
}

const OP_1: &[u8] = &[0x51];

// ============================================================================
// tx-00026
// ============================================================================

/// The corpus entry's bytes, as the sibling's corpus carries them.
const TX_00026: &str = "0200000001636324f2afc64bfbe8bc2327a0cdd05ec515df96c5ca1c92538fc18521587d060000000000ffffffff010000000000000080015100000000";

/// tx-00026 built by this crate's writer: version 2, one input with an empty
/// unlocking script spending `067d..6363:0`, one output of 2^63 satoshis
/// locked by `OP_1`, lock time 0.
fn tx_00026() -> Vec<u8> {
    let mut input = TransactionInput::new(
        "067d582185c18f53921ccac596df15c55ed0cda02723bce8fb4bc6aff2246363"
            .parse()
            .unwrap(),
        0,
    );
    input.set_unlocking_script(UnlockingScript::from_binary(&[]).unwrap());
    let output = TransactionOutput::new(1 << 63, LockingScript::from_binary(OP_1).unwrap());
    Transaction::with_params(2, vec![input], vec![output], 0).to_binary()
}

#[test]
fn tx_00026_is_judged_valid_under_every_word_as_the_node_judges_it_874() {
    let bytes = tx_00026();
    assert_eq!(
        to_hex(&bytes),
        TX_00026,
        "the writer's bytes are the corpus's"
    );
    // The prevout: `51`, 1000 satoshis. Every word's one-shot answer first,
    // so a refusal names each word it reaches.
    let refused: Vec<_> = words()
        .iter()
        .map(|rules| (rules.word(), verify_input(OP_1, 1000, &bytes, 0, rules)))
        .filter(|(_, answer)| answer.is_err())
        .collect();
    assert!(refused.is_empty(), "refused under a word: {refused:?}");
    let prepared = SpendingTransaction::from_bytes(&bytes).unwrap();
    assert_eq!(prepared.input_count(), 1);
    for rules in words() {
        let answer = prepared.verify_input(0, OP_1, 1000, &rules);
        assert!(answer.is_ok(), "{:?}: {answer:?}", rules.word());
        assert_eq!(verify_input(OP_1, 1000, &bytes, 0, &rules), answer);
    }
}

#[test]
fn tx_00026_is_refused_in_the_default_mode_in_the_readers_words_874() {
    let bytes = from_hex(TX_00026).unwrap();
    assert_eq!(
        Transaction::from_binary(&bytes).unwrap_err(),
        unsafe_amount()
    );
    let prepared = SpendingTransaction::from_bytes(&bytes).unwrap();
    for rules in default_modes() {
        let refusal = prepared.verify_input(0, OP_1, 1000, &rules).unwrap_err();
        assert_eq!(refusal, InputRefusal::Transaction(unsafe_amount()));
        assert_eq!(
            refusal.to_string(),
            "transaction error: Number can only safely store up to 53 bits"
        );
        assert!(refusal.evaluation().is_none());
        assert_eq!(verify_input(OP_1, 1000, &bytes, 0, &rules), Err(refusal));
    }
}

#[test]
fn the_default_mode_refuses_the_amount_before_the_index_874() {
    let bytes = tx_00026();
    let prepared = SpendingTransaction::from_bytes(&bytes).unwrap();
    for index in [1usize, 7, usize::MAX] {
        for rules in default_modes() {
            // Before the index: the reference's reader refuses the bytes first.
            assert_eq!(
                prepared.verify_input(index, OP_1, 1000, &rules),
                Err(InputRefusal::Transaction(unsafe_amount()))
            );
            assert_eq!(
                verify_input(OP_1, 1000, &bytes, index, &rules),
                Err(InputRefusal::Transaction(unsafe_amount()))
            );
        }
        // A word reads the amount and answers the index.
        for rules in words() {
            assert_eq!(
                prepared.verify_input(index, OP_1, 1000, &rules),
                Err(InputRefusal::InputIndex { index, inputs: 1 })
            );
        }
    }
}

#[test]
fn the_default_mode_refuses_the_amount_before_evaluation_874() {
    // A lock that would fail and one that would decline: the amount answers.
    let bytes = tx_00026();
    for lock in [&[0x00][..], &[0x6a][..], &[0xff][..]] {
        for rules in default_modes() {
            assert_eq!(
                verify_input(lock, 1000, &bytes, 0, &rules.with_work_limit(0)),
                Err(InputRefusal::Transaction(unsafe_amount()))
            );
        }
        for rules in words() {
            assert!(matches!(
                verify_input(lock, 1000, &bytes, 0, &rules),
                Err(InputRefusal::Invalid(_))
            ));
        }
    }
}

// ============================================================================
// The property: every amount class, at the first, middle and last output
// ============================================================================

/// A small seeded generator, so a failure names its seed.
struct Seeded(u64);

impl Seeded {
    fn next(&mut self) -> u64 {
        // xorshift64*
        self.0 ^= self.0 >> 12;
        self.0 ^= self.0 << 25;
        self.0 ^= self.0 >> 27;
        self.0.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }

    fn below(&mut self, n: u64) -> u64 {
        self.next() % n
    }
}

/// The amount classes: the safe ones `from_binary` reads, the unsafe ones it
/// refuses.
const SAFE: [(&str, u64); 4] = [
    ("zero", 0),
    ("max_money_plus_one", 2_100_000_000_000_001),
    ("two_to_the_53_minus_one", (1 << 53) - 1),
    ("one", 1),
];
const UNSAFE: [(&str, u64); 5] = [
    ("two_to_the_53", 1 << 53),
    ("two_to_the_53_plus_one", (1 << 53) + 1),
    ("two_to_the_63_minus_one", (1 << 63) - 1),
    ("two_to_the_63", 1 << 63),
    ("two_to_the_64_minus_one", u64::MAX),
];

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
enum Place {
    First,
    Middle,
    Last,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
enum Shape {
    /// The transaction whole.
    Whole,
    /// A byte after the lock time.
    Trailing,
    /// Cut after the amount: a refusal after it.
    CutAfter,
    /// Cut before the amount: a refusal ahead of it.
    CutBefore,
}

/// A transaction of `outputs` outputs (at least 3), the amount `amount` at
/// `place`, every other output a safe amount; each input's unlocking script
/// empty, so `OP_1` spends it under every mode. Returns the bytes and the
/// offset of the placed amount's first byte.
fn built(rng: &mut Seeded, amount: u64, place: Place) -> (Vec<u8>, usize) {
    let inputs = 1 + rng.below(3) as usize;
    let outputs = 3 + rng.below(3) as usize;
    let at = match place {
        Place::First => 0,
        Place::Middle => 1 + rng.below(outputs as u64 - 2) as usize,
        Place::Last => outputs - 1,
    };
    let inputs = (0..inputs)
        .map(|n| {
            let mut input = TransactionInput::new(
                (format!("{:064x}", rng.next() ^ n as u64)).parse().unwrap(),
                n as u32,
            );
            input.set_unlocking_script(UnlockingScript::from_binary(&[]).unwrap());
            input
        })
        .collect();
    let outputs = (0..outputs)
        .map(|n| {
            let satoshis = if n == at {
                amount
            } else {
                SAFE[rng.below(SAFE.len() as u64) as usize].1
            };
            let script = vec![0x51; rng.below(4) as usize];
            TransactionOutput::new(satoshis, LockingScript::from_binary(&script).unwrap())
        })
        .collect();
    let tx = Transaction::with_params(1 + rng.below(2) as u32, inputs, outputs, rng.next() as u32);
    let bytes = tx.to_binary();
    let offsets = Transaction::parse_script_offsets(&bytes).unwrap();
    let script = &offsets.outputs[at];
    // the amount, then the script's length (one byte: every script here is short)
    let amount_at = script.offset - 1 - 8;
    assert_eq!(bytes[amount_at..amount_at + 8], amount.to_le_bytes());
    (bytes, amount_at)
}

fn shaped(bytes: &[u8], amount_at: usize, shape: Shape) -> Vec<u8> {
    match shape {
        Shape::Whole => bytes.to_vec(),
        Shape::Trailing => {
            let mut more = bytes.to_vec();
            more.push(0);
            more
        }
        Shape::CutAfter => bytes[..amount_at + 8].to_vec(),
        Shape::CutBefore => bytes[..amount_at + 4].to_vec(),
    }
}

/// The invariant on one input: `from_bytes` against `from_binary`, and the
/// door's answer in every mode. Returns what the cell was, for the floors.
fn judge(bytes: &[u8], unsafe_placed: bool, shape: Shape) -> &'static str {
    let read = Transaction::from_binary(bytes);
    let door = SpendingTransaction::from_bytes(bytes);
    match (&read, &door) {
        (Ok(tx), Ok(prepared)) => {
            assert!(!unsafe_placed, "from_binary read an unsafe amount");
            assert_eq!(tx.inputs().len(), prepared.input_count());
            for rules in default_modes().into_iter().chain(words()) {
                for index in 0..prepared.input_count() {
                    assert!(prepared.verify_input(index, OP_1, 1000, &rules).is_ok());
                }
            }
            "read by both"
        }
        (Err(reader), Err(refused)) => {
            assert_eq!(reader, refused, "the door refuses in the reader's error");
            // An unsafe amount ahead of the refusal: the reader's refusal is
            // the amount, and so is the door's.
            if unsafe_placed && shape != Shape::CutBefore {
                assert_eq!(*reader, unsafe_amount());
            }
            for rules in default_modes().into_iter().chain(words()) {
                assert_eq!(
                    verify_input(OP_1, 1000, bytes, 0, &rules),
                    Err(InputRefusal::Transaction(reader.clone()))
                );
            }
            "refused by both"
        }
        (Err(reader), Ok(prepared)) => {
            // The only refusal there is the amount.
            assert!(unsafe_placed && shape == Shape::Whole, "{shape:?}");
            assert_eq!(*reader, unsafe_amount());
            for rules in default_modes() {
                for index in [0, prepared.input_count(), usize::MAX] {
                    assert_eq!(
                        prepared.verify_input(index, OP_1, 1000, &rules),
                        Err(InputRefusal::Transaction(reader.clone()))
                    );
                    assert_eq!(
                        verify_input(OP_1, 1000, bytes, index, &rules),
                        Err(InputRefusal::Transaction(reader.clone()))
                    );
                }
            }
            for rules in words() {
                for index in 0..prepared.input_count() {
                    assert!(prepared.verify_input(index, OP_1, 1000, &rules).is_ok());
                }
                let past = prepared.input_count();
                assert_eq!(
                    prepared.verify_input(past, OP_1, 1000, &rules),
                    Err(InputRefusal::InputIndex {
                        index: past,
                        inputs: past
                    })
                );
            }
            "read by the door alone"
        }
        (Ok(_), Err(error)) => panic!("the door refused what from_binary reads: {error}"),
    }
}

#[test]
fn every_amount_class_at_every_place_is_read_as_the_node_reads_it_874() {
    const SEED: u64 = 0x874_0874_0874;
    const PER_CELL: usize = 6;
    let mut rng = Seeded(SEED);
    let mut cells: BTreeMap<(&str, Place, Shape), (usize, &str)> = BTreeMap::new();
    let classes = SAFE
        .iter()
        .map(|c| (c, false))
        .chain(UNSAFE.iter().map(|c| (c, true)));
    for ((name, amount), unsafe_placed) in classes {
        for place in [Place::First, Place::Middle, Place::Last] {
            for shape in [
                Shape::Whole,
                Shape::Trailing,
                Shape::CutAfter,
                Shape::CutBefore,
            ] {
                for _ in 0..PER_CELL {
                    let (bytes, amount_at) = built(&mut rng, *amount, place);
                    let input = shaped(&bytes, amount_at, shape);
                    let what = judge(&input, unsafe_placed, shape);
                    let cell = cells.entry((name, place, shape)).or_insert((0, what));
                    assert_eq!(cell.1, what, "seed {SEED:#x}: one cell, two answers");
                    cell.0 += 1;
                }
            }
        }
    }
    // The floors: every class at every place under every shape, each judged
    // PER_CELL times, and what each cell is.
    assert_eq!(cells.len(), (SAFE.len() + UNSAFE.len()) * 3 * 4);
    for ((name, place, shape), (count, what)) in &cells {
        assert_eq!(*count, PER_CELL, "{name} {place:?} {shape:?}");
        let unsafe_placed = UNSAFE.iter().any(|(n, _)| n == name);
        let expected = match (unsafe_placed, shape) {
            (_, Shape::CutAfter | Shape::CutBefore) => "refused by both",
            (false, Shape::Trailing) => "refused by both",
            (true, Shape::Trailing) => "refused by both",
            (false, Shape::Whole) => "read by both",
            (true, Shape::Whole) => "read by the door alone",
        };
        assert_eq!(*what, expected, "{name} {place:?} {shape:?}");
    }
}

#[test]
fn an_unsafe_amount_behind_a_later_refusal_is_answered_in_the_amount_words_874() {
    // from_binary stops at the amount; the door reads on and meets a later
    // refusal (a cut, a byte after the lock time), and answers the amount.
    let bytes = tx_00026();
    let amount_at = 4 + 1 + 41 + 1;
    for input in [
        bytes[..amount_at + 8].to_vec(),
        bytes[..bytes.len() - 1].to_vec(),
        [bytes.as_slice(), &[0]].concat(),
    ] {
        assert_eq!(
            Transaction::from_binary(&input).unwrap_err(),
            unsafe_amount()
        );
        assert_eq!(
            SpendingTransaction::from_bytes(&input).unwrap_err(),
            unsafe_amount()
        );
    }
    // Cut ahead of the amount: the reader's own underflow on both.
    let cut = &bytes[..amount_at + 3];
    let reader = Transaction::from_binary(cut).unwrap_err();
    assert_ne!(reader, unsafe_amount());
    assert_eq!(SpendingTransaction::from_bytes(cut).unwrap_err(), reader);
}

#[test]
fn from_binary_and_its_family_keep_the_references_bound_874() {
    let bytes = tx_00026();
    assert_eq!(
        Transaction::from_binary(&bytes).unwrap_err(),
        unsafe_amount()
    );
    assert_eq!(
        Transaction::from_hex(&to_hex(&bytes)).unwrap_err(),
        unsafe_amount()
    );
    let mut reader = bsv_rs::primitives::Reader::new(&bytes);
    assert_eq!(
        Transaction::from_reader(&mut reader).unwrap_err(),
        unsafe_amount()
    );
}
