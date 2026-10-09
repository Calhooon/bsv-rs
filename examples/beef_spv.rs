//! BEEF (BRC-62/95/96): write a chain into a BEEF, read the subject back out
//! with its ancestry linked, validate the container, and verify the subject.
//!
//! Run with `cargo run --example beef_spv --features transaction`.
use bsv_rs::primitives::PrivateKey;
use bsv_rs::script::templates::P2PKH;
use bsv_rs::script::{SignOutputs, UnlockingScript};
use bsv_rs::transaction::{
    Beef, MerklePath, MockChainTracker, Transaction, TransactionInput, TransactionOutput,
};

fn main() {
    let key = PrivateKey::random();
    let address = key.public_key().to_address();

    // funding -> spend: a mined transaction and a fresh one spending it, the
    // shape of a payment. The funding transaction spends a coin this BEEF
    // does not carry, which its merkle path vouches for (here it is the one
    // transaction of its block, so the block's root is its txid). Every
    // transaction has an input: a raw transaction with none is no
    // transaction, and a BEEF carrying one is not valid.
    let mut funding = Transaction::new();
    let mut mined = TransactionInput::new("11".repeat(32), 0);
    mined.unlocking_script = Some(UnlockingScript::new());
    funding.add_input(mined).unwrap();
    funding
        .add_output(TransactionOutput::new(
            10_000,
            P2PKH::lock_from_address(&address).unwrap(),
        ))
        .unwrap();
    let funding_txid = funding.id();
    let proof = MerklePath::from_coinbase_txid(&funding_txid, 800_000);
    funding.merkle_path = Some(proof.clone());
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
    let bump = beef.merge_bump(proof);
    beef.merge_raw_tx(funding.to_binary(), Some(bump));
    beef.merge_transaction(spend);
    let bytes = beef.to_binary_atomic(&subject).unwrap();
    println!("beef {} bytes, subject {subject}", bytes.len());

    // Reading it back: the container is validated (structure, then the
    // merkle roots it claims, one here, for a header service to confirm) and
    // the subject comes out with its input sources LINKED, each distinct
    // parent linked once (linear in the BEEF, never exponential on a diamond
    // chain).
    let mut parsed = Beef::from_binary(&bytes).unwrap();
    let validation = parsed.verify_valid(false);
    assert!(validation.valid);
    assert_eq!(validation.roots.get(&800_000), Some(&funding_txid));
    let tx = Transaction::from_beef(&bytes, None).unwrap();
    assert_eq!(tx.id(), subject);
    assert!(tx.inputs[0].source_transaction.is_some());

    // And the verdict: the spend's script executed against the linked
    // source; the proven ancestor checked against the tracker and not
    // descended.
    let mut tracker = MockChainTracker::new(800_000);
    tracker.add_root(800_000, funding_txid);
    let ok = futures::executor::block_on(tx.verify(&tracker, None)).unwrap();
    assert!(ok);
    println!("verified {ok}");
}
