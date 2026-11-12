#![no_main]
//! The door that verifies one input of a transaction held as bytes (#855) on
//! arbitrary transaction bytes, locking script, amount, index and flag bits.
//!
//! The input: byte 0 the mode (bit 0: the word `bytes 1..5` name, read by
//! `ScriptFlags::from_bits` and `InputRules::under`, else the default mode;
//! bits 1 to 3: the default mode's push-only, minimal and Chronicle-opcode
//! overrides, each `bit 4` on or off), bytes 1 to 4 the flag bits
//! (little-endian), byte 5 the input index, bytes 6 to 13 the amount
//! (little-endian), bytes 14 and 15 the locking script's length
//! (little-endian), then the locking script, and the rest the spending
//! transaction. Every evaluation runs under `fuzz_script_spend`'s budgets
//! (50,000 units of work, 1 MiB of memory).
//!
//! The assertions: nothing panics; `SpendingTransaction::from_bytes` refuses
//! exactly what `Transaction::from_binary` refuses, with its error, save a
//! transaction whose only refusal there is an output amount of 2^53 or more
//! (the bytes with every such amount made 0 read by `from_binary`), which the
//! door reads as the node's deserializer does and the default mode refuses in
//! `from_binary`'s error at any index, before evaluation (#874);
//! the prepared form answers what the one-shot answers; a refusal before
//! evaluation never reaches the interpreter (bytes refused: the one-shot's
//! `Transaction` arm with the reader's error, whatever the index; an index
//! past the inputs: `InputIndex`, whatever the scripts); a decline carries
//! its budget, a verdict none; a valid input reports its work, at least 1.
use bsv_rs::script::ScriptFlags;
use bsv_rs::transaction::{
    verify_input, DefaultMode, InputRefusal, InputRules, SpendingTransaction, Transaction,
};
use bsv_rs::Error;
use libfuzzer_sys::fuzz_target;

const WORK_LIMIT: u64 = 50_000;
const MEMORY_LIMIT: usize = 1 << 20;

fn rules(mode: u8, bits: u32) -> Option<InputRules> {
    let rules = if mode & 1 == 1 {
        let word = ScriptFlags::from_bits(bits).ok()?;
        InputRules::under(word).ok()?
    } else {
        let on = mode & 0x10 != 0;
        let mut overrides = DefaultMode::new();
        if mode & 2 != 0 {
            overrides = overrides.with_require_push_only(on);
        }
        if mode & 4 != 0 {
            overrides = overrides.with_require_minimal(on);
        }
        if mode & 8 != 0 {
            overrides = overrides.with_utxo_after_chronicle(on);
        }
        InputRules::reference_default_with(overrides)
    };
    Some(
        rules
            .with_work_limit(WORK_LIMIT)
            .with_memory_limit(MEMORY_LIMIT),
    )
}

/// `bytes` with every output amount of 2^53 or more made 0.
fn amounts_made_safe(bytes: &[u8]) -> Vec<u8> {
    let mut out = bytes.to_vec();
    let Ok(offsets) = Transaction::parse_script_offsets(bytes) else {
        return out;
    };
    for script in offsets.outputs {
        let varint = match script.length {
            0..=0xfc => 1,
            0xfd..=0xffff => 3,
            0x1_0000..=0xffff_ffff => 5,
            _ => 9,
        };
        let at = script.offset - varint - 8;
        let mut amount = [0u8; 8];
        amount.copy_from_slice(&out[at..at + 8]);
        if u64::from_le_bytes(amount) >= 1 << 53 {
            out[at..at + 8].copy_from_slice(&[0; 8]);
        }
    }
    out
}

fn check_refusal(answer: &Result<bsv_rs::transaction::InputVerified, InputRefusal>) {
    match answer {
        Err(InputRefusal::Declined(error)) => assert!(error.resource_limit.is_some()),
        Err(InputRefusal::Invalid(error)) => assert!(error.resource_limit.is_none()),
        _ => {}
    }
}

fuzz_target!(|data: &[u8]| {
    let Some((head, rest)) = data.split_at_checked(16) else {
        return;
    };
    let mode = head[0];
    let bits = u32::from_le_bytes([head[1], head[2], head[3], head[4]]);
    let index = usize::from(head[5]);
    let mut amount = [0u8; 8];
    amount.copy_from_slice(&head[6..14]);
    let amount = u64::from_le_bytes(amount);
    let split = usize::from(u16::from_le_bytes([head[14], head[15]])).min(rest.len());
    let (lock, tx) = rest.split_at(split);

    let read = Transaction::from_binary(tx);
    let prepared = SpendingTransaction::from_bytes(tx);
    let Some(rules) = rules(mode, bits) else {
        // The word is refused when the rules are built: no input is judged.
        match (read, prepared) {
            (Err(reader), Err(door)) => assert_eq!(reader, door),
            (Ok(_), Ok(_)) => {}
            (Err(reader), Ok(_)) => assert_eq!(
                reader,
                Error::TransactionError("Number can only safely store up to 53 bits".into())
            ),
            (Ok(_), Err(door)) => panic!("the door refused what from_binary reads: {door}"),
        }
        return;
    };
    let once = verify_input(lock, amount, tx, index, &rules);
    match (read, prepared) {
        (Err(reader), Err(door)) => {
            assert_eq!(reader, door);
            assert_eq!(once, Err(InputRefusal::Transaction(reader)));
        }
        (Err(reader), Ok(prepared)) => {
            // Read by the door alone: the amount was from_binary's only refusal.
            assert_eq!(
                reader,
                Error::TransactionError("Number can only safely store up to 53 bits".into())
            );
            let safe = Transaction::from_binary(&amounts_made_safe(tx))
                .expect("from_binary refused more than the amount");
            assert_eq!(safe.inputs().len(), prepared.input_count());
            let answer = prepared.verify_input(index, lock, amount, &rules);
            assert_eq!(answer, once);
            if rules.word().is_none() {
                assert_eq!(answer, Err(InputRefusal::Transaction(reader)));
            } else if index >= prepared.input_count() {
                assert_eq!(
                    answer,
                    Err(InputRefusal::InputIndex {
                        index,
                        inputs: prepared.input_count(),
                    })
                );
            } else {
                assert!(!matches!(answer, Err(InputRefusal::Transaction(_))));
            }
            check_refusal(&answer);
        }
        (Ok(tx), Ok(prepared)) => {
            assert_eq!(tx.inputs().len(), prepared.input_count());
            let answer = prepared.verify_input(index, lock, amount, &rules);
            assert_eq!(answer, once);
            if index >= prepared.input_count() {
                assert_eq!(
                    answer,
                    Err(InputRefusal::InputIndex {
                        index,
                        inputs: prepared.input_count(),
                    })
                );
            }
            check_refusal(&answer);
            if let Ok(verified) = &answer {
                // The work is always counted: a valid input reached an opcode.
                assert!(verified.work_spent >= 1);
            }
        }
        (read, prepared) => panic!("the readers disagree: {read:?} against {prepared:?}"),
    }
});
