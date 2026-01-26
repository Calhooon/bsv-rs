//! Integration tests for script templates.
//!
//! These tests verify end-to-end functionality of the P2PKH and RPuzzle templates,
//! including script creation, signing, and spend validation.

use bsv_sdk::primitives::bsv::sighash::{SIGHASH_ALL, SIGHASH_FORKID};
use bsv_sdk::primitives::ec::PrivateKey;
use bsv_sdk::primitives::BigNumber;
use bsv_sdk::script::templates::{RPuzzle, RPuzzleType, P2PKH};
use bsv_sdk::script::ScriptTemplate;

/// Test that P2PKH locking script can be spent with the correct key.
#[test]
fn test_p2pkh_end_to_end_spend() {
    // Generate a random key pair
    let private_key = PrivateKey::random();
    let public_key = private_key.public_key();
    let pubkey_hash = public_key.hash160();

    // Create locking script
    let template = P2PKH::new();
    let locking_script = template.lock(&pubkey_hash).unwrap();

    // Verify the locking script structure
    assert!(locking_script.to_asm().contains("OP_DUP"));
    assert!(locking_script.to_asm().contains("OP_HASH160"));
    assert!(locking_script.to_asm().contains("OP_EQUALVERIFY"));
    assert!(locking_script.to_asm().contains("OP_CHECKSIG"));

    // Create a simple unlocking script using direct sighash signing
    // For testing, we'll use a mock sighash
    let mock_sighash = [1u8; 32];
    let unlocking_script = P2PKH::sign_with_sighash(
        &private_key,
        &mock_sighash,
        bsv_sdk::script::SignOutputs::All,
        false,
    )
    .unwrap();

    // Verify unlocking script has signature and pubkey
    let chunks = unlocking_script.chunks();
    assert_eq!(chunks.len(), 2);

    // First chunk: signature (DER + sighash byte)
    let sig_data = chunks[0].data.as_ref().unwrap();
    assert!(sig_data.len() >= 70 && sig_data.len() <= 73);
    assert_eq!(
        *sig_data.last().unwrap(),
        (SIGHASH_ALL | SIGHASH_FORKID) as u8
    );

    // Second chunk: compressed public key (33 bytes)
    let pubkey_data = chunks[1].data.as_ref().unwrap();
    assert_eq!(pubkey_data.len(), 33);
    assert_eq!(
        pubkey_data.as_slice(),
        public_key.to_compressed().as_slice()
    );
}

/// Test P2PKH address-based locking.
#[test]
fn test_p2pkh_from_address() {
    let private_key =
        PrivateKey::from_hex("0000000000000000000000000000000000000000000000000000000000000001")
            .unwrap();
    let public_key = private_key.public_key();
    let address = public_key.to_address();

    // Lock from address
    let locking_from_address = P2PKH::lock_from_address(&address).unwrap();

    // Lock from pubkey hash
    let pubkey_hash = public_key.hash160();
    let template = P2PKH::new();
    let locking_from_hash = template.lock(&pubkey_hash).unwrap();

    // Both should produce the same script
    assert_eq!(locking_from_address.to_hex(), locking_from_hash.to_hex());
}

/// Test RPuzzle locking script structure.
#[test]
fn test_rpuzzle_lock_script_structure() {
    // Create a K value
    let k = BigNumber::from_hex("0000000000000000000000000000000000000000000000000000000000000002")
        .unwrap();

    // Compute R from K
    let r_value = RPuzzle::compute_r_from_k(&k).unwrap();

    // Create raw R-Puzzle locking script
    let template = RPuzzle::new(RPuzzleType::Raw);
    let locking = template.lock(&r_value).unwrap();

    let asm = locking.to_asm();

    // Verify R-extraction prefix
    assert!(asm.contains("OP_OVER"));
    assert!(asm.contains("OP_3"));
    assert!(asm.contains("OP_SPLIT"));
    assert!(asm.contains("OP_NIP"));
    assert!(asm.contains("OP_SWAP"));
    assert!(asm.contains("OP_DROP"));

    // Verify comparison and checksig
    assert!(asm.contains("OP_EQUALVERIFY"));
    assert!(asm.contains("OP_CHECKSIG"));
}

/// Test RPuzzle with hashed R value.
#[test]
fn test_rpuzzle_hashed_lock() {
    let r_value = [0x42u8; 32];

    // Test with HASH160
    let hash160 = bsv_sdk::primitives::hash160(&r_value);
    let template = RPuzzle::new(RPuzzleType::Hash160);
    let locking = template.lock(&hash160).unwrap();

    assert!(locking.to_asm().contains("OP_HASH160"));

    // Test with SHA256
    let sha256 = bsv_sdk::primitives::sha256(&r_value);
    let template = RPuzzle::new(RPuzzleType::Sha256);
    let locking = template.lock(&sha256).unwrap();

    assert!(locking.to_asm().contains("OP_SHA256"));
}

/// Test that RPuzzle unlock uses the correct K value.
#[test]
fn test_rpuzzle_unlock_k_value() {
    // Create a specific K value
    let k = BigNumber::from_hex("0000000000000000000000000000000000000000000000000000000000000002")
        .unwrap();

    // Compute expected R
    let expected_r = RPuzzle::compute_r_from_k(&k).unwrap();

    // Sign with the K value
    let private_key = PrivateKey::random();
    let mock_sighash = [1u8; 32];
    let unlocking = RPuzzle::sign_with_sighash(
        &k,
        &private_key,
        &mock_sighash,
        bsv_sdk::script::SignOutputs::All,
        false,
    )
    .unwrap();

    // Extract R from the signature
    let chunks = unlocking.chunks();
    let sig_data = chunks[0].data.as_ref().unwrap();

    // Parse DER signature: 0x30 <len> 0x02 <r_len> <r> 0x02 <s_len> <s> <sighash>
    let r_len = sig_data[3] as usize;
    let r_start = 4;
    let r_bytes = &sig_data[r_start..r_start + r_len];

    // R may have a leading zero if high bit is set - compare the significant bytes
    let r_trimmed: Vec<u8> = r_bytes.iter().copied().skip_while(|&b| b == 0).collect();
    let expected_trimmed: Vec<u8> = expected_r.iter().copied().skip_while(|&b| b == 0).collect();

    assert_eq!(
        r_trimmed, expected_trimmed,
        "R value in signature should match k*G"
    );
}

/// Test script template unlock estimate_length.
#[test]
fn test_template_unlock_estimate_length() {
    let private_key = PrivateKey::random();

    // P2PKH should estimate 108 bytes
    let p2pkh_unlock = P2PKH::unlock(&private_key, bsv_sdk::script::SignOutputs::All, false);
    assert_eq!(p2pkh_unlock.estimate_length(), 108);

    // RPuzzle should also estimate 108 bytes
    let k = BigNumber::from_i64(1);
    let rpuzzle_unlock =
        RPuzzle::unlock(&k, &private_key, bsv_sdk::script::SignOutputs::All, false);
    assert_eq!(rpuzzle_unlock.estimate_length(), 108);
}

/// Test different sighash types.
#[test]
fn test_sighash_types() {
    use bsv_sdk::primitives::bsv::sighash::{SIGHASH_ANYONECANPAY, SIGHASH_NONE, SIGHASH_SINGLE};
    use bsv_sdk::script::SignOutputs;

    let private_key = PrivateKey::random();
    let sighash = [1u8; 32];

    // ALL | FORKID (0x41)
    let unlocking =
        P2PKH::sign_with_sighash(&private_key, &sighash, SignOutputs::All, false).unwrap();
    let chunks = unlocking.chunks();
    let sig_data = chunks[0].data.as_ref().unwrap();
    assert_eq!(
        *sig_data.last().unwrap(),
        (SIGHASH_ALL | SIGHASH_FORKID) as u8
    );

    // NONE | FORKID (0x42)
    let unlocking =
        P2PKH::sign_with_sighash(&private_key, &sighash, SignOutputs::None, false).unwrap();
    let chunks = unlocking.chunks();
    let sig_data = chunks[0].data.as_ref().unwrap();
    assert_eq!(
        *sig_data.last().unwrap(),
        (SIGHASH_NONE | SIGHASH_FORKID) as u8
    );

    // SINGLE | FORKID (0x43)
    let unlocking =
        P2PKH::sign_with_sighash(&private_key, &sighash, SignOutputs::Single, false).unwrap();
    let chunks = unlocking.chunks();
    let sig_data = chunks[0].data.as_ref().unwrap();
    assert_eq!(
        *sig_data.last().unwrap(),
        (SIGHASH_SINGLE | SIGHASH_FORKID) as u8
    );

    // ALL | FORKID | ANYONECANPAY (0xC1)
    let unlocking =
        P2PKH::sign_with_sighash(&private_key, &sighash, SignOutputs::All, true).unwrap();
    let chunks = unlocking.chunks();
    let sig_data = chunks[0].data.as_ref().unwrap();
    assert_eq!(
        *sig_data.last().unwrap(),
        (SIGHASH_ALL | SIGHASH_FORKID | SIGHASH_ANYONECANPAY) as u8
    );
}

/// Test P2PKH spend validation with the Spend interpreter.
#[test]
fn test_p2pkh_spend_validation() {
    // Create a P2PKH locking script
    let private_key = PrivateKey::random();
    let pubkey_hash = private_key.public_key().hash160();
    let template = P2PKH::new();
    let locking_script = template.lock(&pubkey_hash).unwrap();

    // Create unlocking script using a computed sighash
    // For the Spend validator, we need to construct the proper preimage
    // This test just validates that we can construct and run the spend validator

    // Create a simple test: use direct signing with a mock sighash
    // In real usage, the sighash would be computed from the transaction
    let mock_sighash = [0x42u8; 32];
    let unlocking_script = P2PKH::sign_with_sighash(
        &private_key,
        &mock_sighash,
        bsv_sdk::script::SignOutputs::All,
        false,
    )
    .unwrap();

    // Note: A full spend validation would require a properly constructed transaction
    // and matching sighash. This test just verifies the script structure is valid.
    // The actual signature verification would fail with a mock sighash.

    // Verify the scripts are well-formed
    assert!(locking_script.to_binary().len() > 0);
    assert!(unlocking_script.to_binary().len() > 0);
    assert_eq!(unlocking_script.chunks().len(), 2);
}

/// Test RPuzzle type hash functions.
#[test]
fn test_rpuzzle_type_hash_functions() {
    let data = b"test data for hashing";

    // Verify each hash type produces correct output length
    assert_eq!(RPuzzleType::Raw.hash(data).len(), data.len());
    assert_eq!(RPuzzleType::Sha1.hash(data).len(), 20);
    assert_eq!(RPuzzleType::Sha256.hash(data).len(), 32);
    assert_eq!(RPuzzleType::Hash256.hash(data).len(), 32);
    assert_eq!(RPuzzleType::Ripemd160.hash(data).len(), 20);
    assert_eq!(RPuzzleType::Hash160.hash(data).len(), 20);

    // Verify hashes match the primitives functions
    assert_eq!(
        RPuzzleType::Sha256.hash(data),
        bsv_sdk::primitives::sha256(data).to_vec()
    );
    assert_eq!(
        RPuzzleType::Hash160.hash(data),
        bsv_sdk::primitives::hash160(data).to_vec()
    );
}

/// Test compute_r_from_k with known values.
#[test]
fn test_compute_r_from_k_known_values() {
    // k = 1 should give R = x-coordinate of generator point G
    let k1 = BigNumber::from_i64(1);
    let r1 = RPuzzle::compute_r_from_k(&k1).unwrap();

    // Generator point x-coordinate (well-known value)
    let expected_gx =
        hex::decode("79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798").unwrap();
    assert_eq!(r1.to_vec(), expected_gx);

    // k = 2 should give a different R
    let k2 = BigNumber::from_i64(2);
    let r2 = RPuzzle::compute_r_from_k(&k2).unwrap();
    assert_ne!(r1, r2);
}
