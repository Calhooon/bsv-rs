//! One input of a transaction held as bytes, verified in the node's shape
//! (#855): the locking script, the amount, the transaction, the index, the
//! rules. No network.
//!
//! Run with `cargo run --example verify_input --features transaction`.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)] // #134: example code: a failed unwrap is the example failing
use bsv_rs::primitives::PrivateKey;
use bsv_rs::script::templates::P2PKH;
use bsv_rs::script::{ProtocolEra, ScriptFlags, SignOutputs, UnlockingScript};
use bsv_rs::transaction::{
    verify_input, InputRefusal, InputRules, SpendingTransaction, Transaction, TransactionInput,
    TransactionOutput, Txid,
};

fn main() {
    // A coin paying a P2PKH address, and a transaction spending it twice
    // over (two outputs of the coin), signed by the template.
    let key = PrivateKey::random();
    let lock = P2PKH::lock_from_address(&key.public_key().to_address()).unwrap();
    let mut coin = Transaction::new();
    let earlier = Txid::from_hex(&"11".repeat(32)).expect("64 hex digits");
    let mut mined = TransactionInput::new(earlier, 0);
    mined.unlocking_script = Some(UnlockingScript::new());
    coin.add_input(mined).unwrap();
    for _ in 0..2 {
        coin.add_output(TransactionOutput::new(5_000, lock.clone()))
            .unwrap();
    }
    let mut spend = Transaction::new();
    for vout in 0..2 {
        let mut input = TransactionInput::with_source_transaction(coin.clone(), vout);
        input.set_unlocking_script_template(P2PKH::unlock(&key, SignOutputs::All, false));
        spend.add_input(input).unwrap();
    }
    spend
        .add_output(TransactionOutput::new(9_900, lock.clone()))
        .unwrap();
    futures::executor::block_on(spend.sign()).unwrap();

    // What a judge holds: the spending transaction's bytes and, for each
    // input, the locking script and amount of the output it spends.
    let bytes = spend.to_binary();
    let lock = lock.to_binary();

    // One input: the node's argument order. The rules are the reference
    // SDK's default mode, as `Transaction::verify` runs it; the work spent
    // is counted whatever the rules bound.
    let rules = InputRules::reference_default();
    let one = verify_input(&lock, 5_000, &bytes, 0, &rules).unwrap();
    println!("input 0 valid, {} units of work", one.work_spent);

    // Every input: read the bytes once, then judge each input under the
    // node's block word (checked when the rules are built) with a memory
    // budget, as a Worker passes one.
    let prepared = SpendingTransaction::from_bytes(&bytes).unwrap();
    let word = InputRules::under(ScriptFlags::block(ProtocolEra::PostChronicle))
        .unwrap()
        .with_memory_limit(1 << 20);
    for index in 0..prepared.input_count() {
        prepared.verify_input(index, &lock, 5_000, &word).unwrap();
    }
    println!(
        "{} inputs valid under the block word",
        prepared.input_count()
    );

    // A verdict and a decline are different arms: the wrong amount is a
    // verdict on the signature, a work budget of 10 units a decline.
    match prepared.verify_input(0, &lock, 4_999, &rules) {
        Err(InputRefusal::Invalid(error)) => println!("wrong amount: {}", error.message),
        other => panic!("expected a verdict, got {other:?}"),
    }
    match prepared.verify_input(0, &lock, 5_000, &rules.with_work_limit(10)) {
        Err(InputRefusal::Declined(error)) => println!("declined: {}", error.message),
        other => panic!("expected a decline, got {other:?}"),
    }

    // Refused before evaluation: an index past the inputs, a byte after
    // the transaction.
    let past = prepared.verify_input(2, &lock, 5_000, &rules).unwrap_err();
    println!("{past}");
    let mut trailing = bytes;
    trailing.push(0);
    let refused = verify_input(&lock, 5_000, &trailing, 0, &rules).unwrap_err();
    println!("{refused}");
}
