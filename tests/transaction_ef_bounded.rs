//! `Transaction::from_ef_bounded` and `from_hex_ef_bounded`: an Extended
//! Format transaction read as `from_ef` reads it, under a caller's figure
//! for the outputs its inputs' source transactions hold together (an input
//! spending output `n` is given a source of `n + 1` outputs). Under the
//! figure the answer is `from_ef`'s, byte for byte; past it, a refusal.
//! `from_ef` and `from_hex_ef` answer as before: 20,000 transactions this
//! crate's writer wrote, read through both, to one digest. Every EF here is
//! written by this crate's own `to_ef`.
#![cfg(feature = "transaction")]
#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)] // Test assertions.

use bsv_rs::primitives::{sha256, to_hex};
use bsv_rs::script::{LockingScript, UnlockingScript};
use bsv_rs::transaction::{Transaction, TransactionInput, TransactionOutput};
use bsv_rs::Error;

/// A seeded generator (splitmix64), so every run reads the same inputs.
struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9e37_79b9_7f4a_7c15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
        z ^ (z >> 31)
    }
    fn below(&mut self, n: u64) -> u64 {
        self.next() % n
    }
    fn bytes(&mut self, n: usize) -> Vec<u8> {
        (0..n).map(|_| self.next() as u8).collect()
    }
}

/// A pay-to-public-key-hash locking script of random hash, or a short data
/// carrier, as honest outputs are.
fn locking(rng: &mut Rng) -> LockingScript {
    let mut bytes = if rng.below(4) == 0 {
        let len = rng.below(40) as usize;
        let mut data = vec![0x00, 0x6a, len as u8];
        data.extend(rng.bytes(len));
        data
    } else {
        let mut p2pkh = vec![0x76, 0xa9, 0x14];
        p2pkh.extend(rng.bytes(20));
        p2pkh.extend([0x88, 0xac]);
        p2pkh
    };
    if rng.below(16) == 0 {
        bytes.clear();
    }
    LockingScript::from_binary(&bytes).expect("a well-formed locking script")
}

/// One push of up to 75 random bytes, or none.
fn unlocking(rng: &mut Rng) -> UnlockingScript {
    let len = rng.below(76) as usize;
    let mut bytes = Vec::new();
    if len > 0 {
        bytes.push(len as u8);
        bytes.extend(rng.bytes(len));
    }
    UnlockingScript::from_binary(&bytes).expect("a well-formed unlocking script")
}

fn source(rng: &mut Rng, outputs: usize) -> Transaction {
    let mut source = Transaction::new();
    source
        .add_input(TransactionInput::new(
            to_hex(&rng.bytes(32)),
            rng.below(4) as u32,
        ))
        .unwrap();
    for _ in 0..outputs {
        let amount = rng.below(1 << 40);
        source
            .add_output(TransactionOutput::new(amount, locking(rng)))
            .unwrap();
    }
    source
}

/// An honest transaction spending outputs of up to three sources: a
/// consolidation (outputs 0 to k - 1 of one source) one time in four,
/// otherwise outputs at random positions. Returns it and the outputs its
/// inputs' sources hold together as `from_ef` reads them.
fn honest(rng: &mut Rng) -> (Transaction, usize) {
    let consolidation = rng.below(4) == 0;
    let sources: Vec<Transaction> = (0..1 + rng.below(3))
        .map(|_| {
            let n = 1 + rng.below(48) as usize;
            source(rng, n)
        })
        .collect();
    let mut tx = Transaction::new();
    tx.set_version(1 + rng.below(2) as u32);
    let inputs = 1 + rng.below(12) as usize;
    let mut held = 0;
    for i in 0..inputs {
        let from = &sources[if consolidation {
            0
        } else {
            rng.below(sources.len() as u64) as usize
        }];
        let count = from.outputs().len();
        let vout = if consolidation {
            i % count
        } else {
            rng.below(count as u64) as usize
        };
        let mut input = TransactionInput::with_source_transaction(from.clone(), vout as u32);
        input.unlocking_script = Some(unlocking(rng));
        input.sequence = if rng.below(2) == 0 {
            0xffff_ffff
        } else {
            rng.next() as u32
        };
        tx.add_input(input).unwrap();
        held += vout + 1;
    }
    for _ in 0..1 + rng.below(4) {
        let amount = rng.below(1 << 40);
        tx.add_output(TransactionOutput::new(amount, locking(rng)))
            .unwrap();
    }
    tx.set_lock_time(rng.below(2) as u32 * rng.next() as u32);
    (tx, held)
}

/// Every part of an EF answer: the bytes, the id, the EF written back and
/// each input's source transaction whole.
fn answer(read: &bsv_rs::Result<Transaction>) -> Vec<u8> {
    let mut out = Vec::new();
    match read {
        Ok(tx) => {
            out.extend(tx.to_binary());
            out.extend(tx.id().as_bytes());
            out.extend(tx.to_ef().expect("an EF read writes back"));
            for input in tx.inputs() {
                let source = input.source_transaction.as_ref().expect("a source");
                out.extend((source.outputs().len() as u64).to_le_bytes());
                out.extend(source.to_binary());
                out.extend(input.source_output_index.to_le_bytes());
            }
        }
        Err(error) => out.extend(error.to_string().as_bytes()),
    }
    out
}

fn held(tx: &Transaction) -> usize {
    tx.inputs()
        .iter()
        .map(|input| input.source_transaction.as_ref().unwrap().outputs().len())
        .sum()
}

/// `from_ef` and `from_hex_ef` over 20,000 honest transactions, as they
/// answered before the bounded doors: the digest is the bases'
/// (`origin/beta` `f549192a` and `8719c7aa`), equal on the tip.
#[test]
fn the_unbounded_doors_answer_twenty_thousand_honest_transactions_as_before() {
    let mut rng = Rng(0x82_6e_f0_01);
    let mut all = Vec::new();
    let mut held_total = 0usize;
    for _ in 0..20_000 {
        let (tx, held) = honest(&mut rng);
        let ef = tx.to_ef().expect("the writer writes an EF");
        let by_bytes = Transaction::from_ef(&ef);
        let by_hex = Transaction::from_hex_ef(&to_hex(&ef));
        assert_eq!(by_bytes.as_ref().map(Transaction::id).ok(), Some(tx.id()));
        assert_eq!(answer(&by_bytes), answer(&by_hex));
        all.extend(sha256(&answer(&by_bytes)));
        held_total += held;
    }
    assert!(
        held_total > 1_000_000,
        "the inputs' sources hold {held_total}"
    );
    assert_eq!(
        to_hex(&sha256(&all)),
        "862ca7c2d0ef7f4ae77faea9f8693a9490866be13d2413b226573a9a4ca00e89",
        "from_ef's answers over the 20,000"
    );
}

/// Under the figure, through bytes and hex, the bounded doors' answer is
/// `from_ef`'s; at the figure exactly it reads; one below, it refuses.
#[test]
fn the_bounded_doors_answer_as_from_ef_at_and_under_the_figure_and_refuse_below_it() {
    let mut rng = Rng(0x82_6e_f0_02);
    let mut refused = 0;
    for _ in 0..2_000 {
        let (tx, needed) = honest(&mut rng);
        let ef = tx.to_ef().unwrap();
        let hex = to_hex(&ef);
        let plain = answer(&Transaction::from_ef(&ef));
        assert_eq!(held(&Transaction::from_ef(&ef).unwrap()), needed);
        for figure in [needed, needed + 1, needed * 2, usize::MAX] {
            assert_eq!(
                answer(&Transaction::from_ef_bounded(&ef, figure)),
                plain,
                "{figure}"
            );
            assert_eq!(
                answer(&Transaction::from_hex_ef_bounded(&hex, figure)),
                plain
            );
        }
        for figure in [0, needed / 2, needed - 1] {
            let expected = Error::TransactionError(format!(
                "EF inputs' source outputs exceed the bound of {figure}"
            ));
            assert_eq!(
                Transaction::from_ef_bounded(&ef, figure).err(),
                Some(expected.clone())
            );
            assert_eq!(
                Transaction::from_hex_ef_bounded(&hex, figure).err(),
                Some(expected)
            );
            refused += 1;
        }
    }
    assert_eq!(refused, 6_000);
}

/// A consolidation of 400 inputs (outputs 0 to 399 of one source) holds
/// 80,200 source outputs as `from_ef` reads it: the bounded doors read it
/// under a figure of 80,200 and refuse it under 80,199, through bytes and
/// hex.
#[test]
fn the_bounded_doors_refuse_a_transaction_whose_inputs_pass_the_figure_together() {
    let mut rng = Rng(0x82_6e_f0_03);
    let from = source(&mut rng, 400);
    let mut tx = Transaction::new();
    for vout in 0..400 {
        let mut input = TransactionInput::with_source_transaction(from.clone(), vout);
        input.unlocking_script = Some(UnlockingScript::new());
        tx.add_input(input).unwrap();
    }
    tx.add_output(TransactionOutput::new(1, LockingScript::new()))
        .unwrap();
    let ef = tx.to_ef().unwrap();
    let hex = to_hex(&ef);
    assert_eq!(held(&Transaction::from_ef(&ef).unwrap()), 80_200);
    assert_eq!(
        Transaction::from_ef_bounded(&ef, 80_200).unwrap().id(),
        tx.id()
    );
    assert_eq!(
        Transaction::from_hex_ef_bounded(&hex, 80_200).unwrap().id(),
        tx.id()
    );
    let refusal = Some(Error::TransactionError(
        "EF inputs' source outputs exceed the bound of 80199".to_string(),
    ));
    assert_eq!(Transaction::from_ef_bounded(&ef, 80_199).err(), refusal);
    assert_eq!(
        Transaction::from_hex_ef_bounded(&hex, 80_199).err(),
        refusal
    );
}

/// What `from_ef` refuses, the bounded doors refuse in its words: a wrong
/// marker and an input past the per-input figure under any figure (both
/// are read before a source is counted); a byte after the frame and a
/// truncated frame under a figure the inputs do not pass; and text that is
/// not hex.
#[test]
fn the_bounded_doors_keep_from_efs_refusals() {
    let mut rng = Rng(0x82_6e_f0_04);
    let (tx, _) = honest(&mut rng);
    let ef = tx.to_ef().unwrap();
    let mut marker = ef.clone();
    marker[9] = 0xee;
    let mut trailing = ef.clone();
    trailing.push(0);
    let truncated = ef[..ef.len() - 1].to_vec();
    let mut far = Transaction::new();
    let mut input = TransactionInput::new("11".repeat(32), 200_000);
    input.unlocking_script = Some(UnlockingScript::new());
    let mut stand_in = Transaction::new();
    for _ in 0..=200_000 {
        stand_in
            .add_output(TransactionOutput::new(1, LockingScript::new()))
            .unwrap();
    }
    input.source_transaction = Some(Box::new(stand_in));
    far.add_input(input).unwrap();
    far.add_output(TransactionOutput::new(1, LockingScript::new()))
        .unwrap();
    let far = far.to_ef().unwrap();
    let any: &[usize] = &[0, 1_000, usize::MAX];
    let under: &[usize] = &[usize::MAX];
    for (bytes, figures) in [
        (marker, any),
        (far, any),
        (trailing, under),
        (truncated, under),
    ] {
        let plain = Transaction::from_ef(&bytes).expect_err("refused");
        for &figure in figures {
            assert_eq!(
                Transaction::from_ef_bounded(&bytes, figure).err(),
                Some(plain.clone())
            );
            assert_eq!(
                Transaction::from_hex_ef_bounded(&to_hex(&bytes), figure).err(),
                Some(plain.clone())
            );
        }
    }
    assert_eq!(
        Transaction::from_hex_ef_bounded("0g", 10).err(),
        Transaction::from_hex_ef("0g").err()
    );
}
