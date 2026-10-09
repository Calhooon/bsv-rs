//! A transaction built, signed, serialized and VERIFIED, with no network.
//!
//! Run with `cargo run --example transaction --features transaction`.
use bsv_rs::primitives::PrivateKey;
use bsv_rs::script::templates::P2PKH;
use bsv_rs::script::{SignOutputs, UnlockingScript};
use bsv_rs::transaction::{
    MerklePath, MockChainTracker, Transaction, TransactionInput, TransactionOutput,
};

fn main() {
    let key = PrivateKey::random();
    let address = key.public_key().to_address();

    // A funding transaction that pays our address. It spends a coin this
    // program does not carry, which its merkle path vouches for (here it is
    // the one transaction of its block, so the block's root is its txid). A
    // transaction with no input, or with no output, is no transaction, and
    // `verify` refuses one.
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
    funding.merkle_path = Some(MerklePath::from_coinbase_txid(&funding_txid, 800_000));

    // The spend: one input sourcing the funding output (the whole source
    // transaction rides along, which is what SPV-style verification needs),
    // one P2PKH output, and the unlocking script produced by the P2PKH
    // template's signer at `sign()` time.
    let mut spend = Transaction::new();
    let mut input = TransactionInput::with_source_transaction(funding, 0);
    input.set_unlocking_script_template(P2PKH::unlock(&key, SignOutputs::All, false));
    spend.add_input(input).unwrap();
    spend.add_p2pkh_output(&address, Some(9_900)).unwrap();
    futures::executor::block_on(spend.sign()).unwrap();

    println!("txid {}", spend.id());
    println!("size {} bytes", spend.to_binary().len());

    // `verify` walks the ancestry by txid: a proven transaction is checked
    // against the chain tracker; an unproven one has every input's script
    // EXECUTED against its source output, and its outputs weighed against its
    // inputs. The spend is unproven, so the interpreter judges it; the
    // funding transaction is proven, so the tracker is asked for its root
    // and its own ancestry is not needed.
    let mut tracker = MockChainTracker::new(800_000);
    tracker.add_root(800_000, funding_txid);
    let ok = futures::executor::block_on(spend.verify(&tracker, None)).unwrap();
    assert!(ok);
    println!("verified {ok}");
}
