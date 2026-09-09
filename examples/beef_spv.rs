//! BEEF (BRC-62/95/96): write a chain into a BEEF, read the subject back out
//! with its ancestry linked, validate the container, and verify the subject.
//!
//! Run with `cargo run --example beef_spv --features transaction`.
use bsv_rs::primitives::PrivateKey;
use bsv_rs::script::templates::P2PKH;
use bsv_rs::script::SignOutputs;
use bsv_rs::transaction::{
    Beef, MockChainTracker, Transaction, TransactionInput, TransactionOutput,
};

fn main() {
    let key = PrivateKey::random();
    let address = key.public_key().to_address();

    // funding -> spend, both unproven (no merkle paths): the shape of a fresh
    // wallet chain before anything is mined.
    let mut funding = Transaction::new();
    funding
        .add_output(TransactionOutput::new(
            10_000,
            P2PKH::lock_from_address(&address).unwrap(),
        ))
        .unwrap();
    let mut spend = Transaction::new();
    let mut input = TransactionInput::with_source_transaction(funding.clone(), 0);
    input.set_unlocking_script_template(P2PKH::unlock(&key, SignOutputs::All, false));
    spend.add_input(input).unwrap();
    spend.add_p2pkh_output(&address, Some(9_900)).unwrap();
    futures::executor::block_on(spend.sign()).unwrap();
    let subject = spend.id();

    // The BEEF carries every transaction once, however many inputs source it;
    // `to_binary_atomic` prefixes the subject's txid (BRC-95) so a reader
    // knows which transaction the container is ABOUT.
    let mut beef = Beef::new();
    beef.merge_transaction(funding);
    beef.merge_transaction(spend);
    let bytes = beef.to_binary_atomic(&subject).unwrap();
    println!("beef {} bytes, subject {subject}", bytes.len());

    // Reading it back: the container is validated (structure, then the
    // merkle roots it claims, none here) and the subject comes out with its
    // input sources LINKED, each distinct parent linked once (linear in the
    // BEEF, never exponential on a diamond chain).
    let mut parsed = Beef::from_binary(&bytes).unwrap();
    let validation = parsed.verify_valid(false);
    assert!(validation.valid);
    assert!(validation.roots.is_empty(), "nothing here is mined");
    let tx = Transaction::from_beef(&bytes, None).unwrap();
    assert_eq!(tx.id(), subject);
    assert!(tx.inputs[0].source_transaction.is_some());

    // And the verdict: scripts executed against the linked sources; a proven
    // ancestor would instead be checked against the tracker and not descended.
    let tracker = MockChainTracker::new(0);
    let ok = futures::executor::block_on(tx.verify(&tracker, None)).unwrap();
    assert!(ok);
    println!("verified {ok}");
}
