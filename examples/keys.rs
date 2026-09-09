//! Keys, hashes and signatures: the default feature set, no network.
//!
//! Run with `cargo run --example keys`.
use bsv_rs::primitives::{sha256, to_hex, PrivateKey};

fn main() {
    // A fresh secp256k1 key pair. `PrivateKey::random()` draws from the platform
    // RNG (`getrandom`; on wasm32 with the `wasm` feature, the JS host's).
    let private_key = PrivateKey::random();
    let public_key = private_key.public_key();

    // The P2PKH address and the WIF export round-trip.
    let address = public_key.to_address();
    let wif = private_key.to_wif();
    assert_eq!(PrivateKey::from_wif(&wif).unwrap().to_wif(), wif);

    // ECDSA over a SHA-256 digest: RFC 6979 deterministic nonces, so the same
    // key and digest always give the same DER bytes.
    let digest = sha256(b"Hello, BSV!");
    let signature = private_key.sign(&digest).unwrap();
    assert!(public_key.verify(&digest, &signature));
    assert_eq!(
        private_key.sign(&digest).unwrap().to_der(),
        signature.to_der()
    );

    println!("address   {address}");
    println!("pubkey    {}", to_hex(&public_key.to_compressed()));
    println!("signature {}", to_hex(&signature.to_der()));
}
