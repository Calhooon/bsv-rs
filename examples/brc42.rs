//! BRC-42 key derivation and the ProtoWallet: two parties derive matching
//! keys from their identity keys, then sign and verify under a protocol.
//!
//! Run with `cargo run --example brc42 --features wallet`.
use bsv_rs::primitives::PrivateKey;
use bsv_rs::wallet::{
    Counterparty, CreateSignatureArgs, KeyDeriver, ProtoWallet, Protocol, SecurityLevel,
    VerifySignatureArgs,
};

fn main() {
    let alice = KeyDeriver::new(Some(PrivateKey::random()));
    let bob = KeyDeriver::new(Some(PrivateKey::random()));
    let protocol = Protocol::new(SecurityLevel::App, "payment system");
    let key_id = "invoice-12345";

    // Bob derives a private key for talking to Alice; Alice derives the
    // matching public key for Bob. BRC-42 makes the two agree without either
    // party sharing anything but its identity key.
    let bob_private = bob
        .derive_private_key(
            &protocol,
            key_id,
            &Counterparty::Other(alice.identity_key()),
        )
        .unwrap();
    let bob_public = alice
        .derive_public_key(
            &protocol,
            key_id,
            &Counterparty::Other(bob.identity_key()),
            false,
        )
        .unwrap();
    assert_eq!(
        bob_private.public_key().to_compressed(),
        bob_public.to_compressed()
    );

    // The ProtoWallet is the same derivation behind a wallet-shaped API: sign
    // as Alice for Bob, verify as Bob against Alice.
    let alice_wallet = ProtoWallet::new(Some(PrivateKey::random()));
    let bob_wallet = ProtoWallet::new(Some(PrivateKey::random()));
    let protocol = Protocol::new(SecurityLevel::App, "secure messaging");
    let signed = alice_wallet
        .create_signature(CreateSignatureArgs {
            data: Some(b"Hello, Bob".to_vec()),
            hash_to_directly_sign: None,
            protocol_id: protocol.clone(),
            key_id: "msg-1".to_string(),
            counterparty: Some(Counterparty::Other(bob_wallet.identity_key())),
        })
        .unwrap();
    let verified = bob_wallet
        .verify_signature(VerifySignatureArgs {
            data: Some(b"Hello, Bob".to_vec()),
            hash_to_directly_verify: None,
            signature: signed.signature,
            protocol_id: protocol,
            key_id: "msg-1".to_string(),
            counterparty: Some(Counterparty::Other(alice_wallet.identity_key())),
            for_self: None,
        })
        .unwrap();
    assert!(verified.valid);
    println!("alice → bob signature verified: {}", verified.valid);
}
