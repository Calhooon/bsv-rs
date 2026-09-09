//! A transaction built, signed, serialized and VERIFIED, with no network.
//!
//! Run with `cargo run --example transaction --features transaction`.
use bsv_rs::primitives::PrivateKey;
use bsv_rs::script::templates::P2PKH;
use bsv_rs::script::SignOutputs;
use bsv_rs::transaction::{MockChainTracker, Transaction, TransactionInput, TransactionOutput};

fn main() {
    let key = PrivateKey::random();
    let address = key.public_key().to_address();

    // A funding transaction that pays our address (synthetic: no inputs, so it
    // is a root the verifier never has to judge).
    let mut funding = Transaction::new();
    funding
        .add_output(TransactionOutput::new(
            10_000,
            P2PKH::lock_from_address(&address).unwrap(),
        ))
        .unwrap();

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
    // inputs. This chain is unproven end to end, so the tracker is never
    // asked and the interpreter is the whole verdict.
    let tracker = MockChainTracker::new(0);
    let ok = futures::executor::block_on(spend.verify(&tracker, None)).unwrap();
    assert!(ok);
    println!("verified {ok}");
}
