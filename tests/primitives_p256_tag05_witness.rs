//! Witness: `P256PublicKey::from_bytes` refuses a SEC 1 tag `05` (the "compact"
//! form) rather than reinterpreting it as the compressed key `02 || X`.
//!
//! The P-256 key parser is a public item (`bsv_rs::primitives::p256::P256PublicKey`),
//! so an embedder can hand it outside bytes directly. The `p256` crate's SEC 1
//! point reader accepts a tag `05` as a compact point (the same shape as the
//! secp256k1 door closed by #550), so before the guard `from_bytes(05 || X)`
//! returned the key `02 || X` — a non-canonical encoding silently reinterpreted
//! as a valid key.
//!
//! The reference refuses it: `ts-stack` `packages/sdk/src/primitives/Secp256r1.ts`
//! `pointFromHex` (lines 91-107) reads only `02`/`03` (compressed) and `04`
//! (uncompressed) and throws `Invalid point encoding` for every other prefix;
//! the reference's own test (`Secp256r1.test.ts:31`) asserts
//! `pointFromHex('05abcdef')` throws. The guard carries the crate's own words
//! (`Invalid public key encoding: unknown point format`), uniform with the
//! secp256k1 root door.
//!
//! Every fixture is built by this crate's own P-256 writer, so it cannot drift
//! from the wire format (CLAUDE.md rule 2).
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use bsv_rs::primitives::p256::{P256PrivateKey, P256PublicKey};

/// A deterministic P-256 key, built by this crate's own writer.
fn sample_key() -> P256PublicKey {
    // A fixed 32-byte secret in [1, n-1]; `from_bytes` validates the range.
    P256PrivateKey::from_bytes(&[7u8; 32]).unwrap().public_key()
}

#[test]
fn p256_from_bytes_refuses_a_tag_05_compact_key_not_reinterpreting_it_as_02() {
    let key = sample_key();
    let compressed = key.to_compressed(); // 02/03 || X
    assert!(
        compressed[0] == 0x02 || compressed[0] == 0x03,
        "a compressed P-256 key starts with 02 or 03"
    );

    // Re-present the same X under the non-canonical compact tag 05.
    let mut forged = compressed;
    forged[0] = 0x05;

    let parsed = P256PublicKey::from_bytes(&forged);
    assert!(
        parsed.is_err(),
        "a 05-tag compact P-256 key must be refused, not reinterpreted as 02 || X"
    );

    // The guard rejects only the 05 tag: the real canonical compressed key still parses.
    assert!(
        P256PublicKey::from_bytes(&key.to_compressed()).is_ok(),
        "the canonical compressed P-256 key still parses after the guard"
    );
}

#[test]
fn p256_from_bytes_refuses_a_tag_05_with_the_crate_words() {
    let key = sample_key();
    let mut forged = key.to_compressed();
    forged[0] = 0x05;
    match P256PublicKey::from_bytes(&forged) {
        Err(e) => {
            let text = e.to_string();
            assert!(
                text.contains("unknown point format"),
                "the 05 refusal carries the crate's point-format words, got: {text}"
            );
        }
        Ok(_) => panic!("a 05-tag compact P-256 key must be refused"),
    }
}

#[test]
fn p256_from_hex_refuses_a_tag_05_key() {
    let key = sample_key();
    let mut forged = key.to_compressed();
    forged[0] = 0x05;
    let hex: String = forged.iter().map(|b| format!("{b:02x}")).collect();
    assert!(
        P256PublicKey::from_hex(&hex).is_err(),
        "from_hex must refuse a 05-tag compact P-256 key through the one root"
    );
}

#[test]
fn p256_from_bytes_still_accepts_canonical_compressed_and_uncompressed() {
    let key = sample_key();
    // Compressed (02/03 || X) round-trips.
    let c = P256PublicKey::from_bytes(&key.to_compressed()).unwrap();
    assert_eq!(c, key);
    // Uncompressed (04 || X || Y) round-trips.
    let u = P256PublicKey::from_bytes(&key.to_uncompressed()).unwrap();
    assert_eq!(u, key);
}
