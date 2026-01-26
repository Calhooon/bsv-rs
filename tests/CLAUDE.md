# Integration Tests
> Cross-module and cross-SDK compatibility testing

## Overview

This directory contains integration tests that verify the BSV Rust SDK works correctly across modules and produces results identical to the TypeScript and Go SDK implementations. Tests use shared JSON test vectors to ensure byte-for-byte compatibility across all three SDK implementations.

## Files

| File | Purpose |
|------|---------|
| `cross_sdk_tests.rs` | Tests using shared vectors from TypeScript/Go SDKs |
| `ec_tests.rs` | Elliptic curve and BRC-42 key derivation tests |
| `integration_tests.rs` | Full workflow tests across all modules |
| `script_vectors_tests.rs` | Script interpreter tests with ~1,660 vectors |
| `sighash_tests.rs` | Transaction sighash computation with 499 vectors |
| `template_tests.rs` | Script template tests (P2PKH, RPuzzle) |
| `transaction_tests.rs` | Transaction module tests (BEEF, MerklePath, fee models) |
| `transaction/` | Transaction test vectors module |

## Test Vectors

Test vectors are stored in `tests/vectors/` and shared with the TypeScript and Go SDKs:

| Vector File | Contents |
|-------------|----------|
| `brc42_private.json` | BRC-42 private key derivation vectors |
| `brc42_public.json` | BRC-42 public key derivation vectors |
| `symmetric_key.json` | Symmetric encryption test vectors |
| `drbg.json` | HMAC-DRBG vectors (15 vectors for RFC 6979) |
| `sighash.json` | Transaction sighash vectors (499 vectors) |
| `spend_valid.json` | Valid spend execution vectors (~570+ vectors) |
| `script_valid.json` | Valid script parsing vectors (~590+ vectors) |
| `script_invalid.json` | Invalid scripts that should fail (~500+ vectors) |

Transaction test vectors are in `tests/transaction/vectors/`:

| File | Contents |
|------|----------|
| `mod.rs` | Module declarations for vector submodules |
| `tx_valid.rs` | Valid transaction hex strings for roundtrip testing |
| `tx_invalid.rs` | Invalid transaction vectors (semantically invalid) |
| `bump_valid.rs` | Valid BRC-74 BUMP (MerklePath) hex vectors |
| `bump_invalid.rs` | Invalid BUMP vectors with expected error messages |
| `bigtx.rs` | Large transaction test vectors |

## Test Categories

### Cross-SDK Compatibility (`cross_sdk_tests.rs`)

Tests that verify the Rust implementation matches TypeScript and Go SDK output:

**BRC-42 Key Derivation**
- `test_brc42_private_derivation_vectors` - Derives child private keys using sender public key
- `test_brc42_public_derivation_vectors` - Derives child public keys using sender private key

**Symmetric Encryption**
- `test_symmetric_key_cross_sdk_vectors` - Decrypts ciphertexts from other SDKs
- `test_31_byte_key_go_ciphertext_compatibility` - Tests keys with leading zero byte
- `test_32_byte_key_go_ciphertext_compatibility` - Tests full 32-byte keys
- `test_typescript_ciphertext_compatibility` - Decrypts TypeScript-generated ciphertexts
- `test_rust_encryption_roundtrip_with_31_byte_key` - Verifies Rust encrypt/decrypt with 31-byte keys
- `test_rust_encryption_roundtrip_with_32_byte_key` - Verifies Rust encrypt/decrypt with 32-byte keys

**WIF and Address Compatibility**
- `test_wif_compatibility_vectors` - Known Bitcoin WIF test vectors
- `test_public_key_compatibility_vectors` - Private key to public key derivation
- `test_address_compatibility_vectors` - Public key to address generation

**DRBG Verification**
- `test_drbg_vectors_loaded` - Verifies DRBG vectors can be loaded and parsed (15 vectors)

**Edge Cases**
- `test_symmetric_encryption_unicode` - Unicode text encryption
- `test_empty_message_encryption` - Empty message handling
- `test_large_message_encryption` - 1MB message handling
- `test_brc42_empty_invoice` - Empty invoice number derivation
- `test_brc42_long_invoice` - 1000-character invoice number

### EC Module Tests (`ec_tests.rs`)

Focused tests for elliptic curve operations:

**BRC-42 Key Derivation**
- `test_brc42_private_derivation` - Recipient derives child private key from sender's public key
- `test_brc42_public_derivation` - Sender derives child public key from recipient's public key
- `test_brc42_consistency` - Verifies private and public derivation produce matching key pairs

**Key Serialization**
- `test_wif_roundtrip_known_vectors` - WIF encoding/decoding with known test cases
- `test_public_key_known_vectors` - Known private to public key mappings
- `test_address_generation_known_vectors` - Known public key to address mappings

**Signing and Verification**
- `test_sign_and_verify_roundtrip` - Signs and verifies messages of various lengths
- `test_deterministic_signatures` - Verifies RFC 6979 deterministic signing
- `test_public_key_recovery` - Recovers public key from signature

**ECDH**
- `test_ecdh_shared_secret` - Verifies both parties derive identical shared secret

### Integration Tests (`integration_tests.rs`)

Full workflow tests combining multiple modules:

**Key Derivation Workflows**
- `test_full_key_derivation_workflow` - Complete BRC-42 key agreement
- `test_key_derivation_multiple_invoices` - Verifies different invoices produce unique keys
- `test_sign_and_verify_with_derived_keys` - Signs with BRC-42 derived keys
- `test_signature_recovery_with_derived_keys` - Recovers public key from derived key signature

**Symmetric Encryption**
- `test_symmetric_encryption_with_derived_key` - Encrypts using ECDH shared secret
- `test_symmetric_encryption_bidirectional` - Both parties can encrypt/decrypt

**WIF and Address**
- `test_wif_address_roundtrip` - Mainnet key export and address generation
- `test_testnet_wif_address` - Testnet key export (prefix 0xEF) and address (prefix 0x6F)

**Schnorr Proofs**
- `test_schnorr_proof_with_derived_keys` - Generates and verifies Schnorr proofs
- `test_schnorr_proof_fails_with_wrong_secret` - Verifies proof rejection with wrong secret

**Shamir Secret Sharing**
- `test_shamir_with_wif_export` - Splits key, recovers from shares, verifies WIF match
- `test_shamir_different_subsets` - Recovers from different 3-of-5 share combinations

**P-256 Curve**
- `test_p256_sign_verify_roundtrip` - P-256 signing and verification
- `test_p256_key_serialization` - P-256 key hex and compressed/uncompressed formats

**Hash Functions**
- `test_hash_chain_for_key_derivation` - SHA256, SHA256d, Hash160 chaining
- `test_hmac_for_key_derivation` - SHA256-HMAC and SHA512-HMAC

**Encoding**
- `test_encoding_roundtrips` - Hex, Base64, Base58 roundtrips
- `test_address_encoding_integration` - Address encoding with Base58Check

**Sighash**
- `test_sighash_with_signature` - Computes sighash and signs

**Complete Workflows**
- `test_complete_payment_workflow` - Full merchant/customer payment scenario with BRC-42, ECDH encryption, and signing
- `test_key_backup_and_recovery_workflow` - Complete Shamir split, backup, recover, and sign workflow
- `test_multi_party_schnorr_verification` - Both parties generate and cross-verify proofs

### Script Vectors Tests (`script_vectors_tests.rs`)

Comprehensive script interpreter tests using TypeScript SDK vectors:

**Spend Valid Vectors**
- `test_spend_valid_vectors` - Runs ~570+ spend execution test vectors
- `test_first_spend_vector_detailed` - Detailed debugging output for first vector

**Script Parsing Tests**
- `test_script_valid_vectors_parsing` - Tests ~590+ scripts can be parsed correctly
- `test_script_valid_vectors_execution` - Tests script execution (some skipped for BTC-specific behavior)

**Script Invalid Vectors**
- `test_script_invalid_vectors` - Verifies ~500+ invalid scripts fail during parsing or execution

**Individual Script Tests**
- `test_arithmetic_script` - Basic arithmetic (1 + 2 = 3)
- `test_op_depth` - OP_DEPTH operation
- `test_conditional` - IF/ELSE/ENDIF control flow
- `test_op_cat` - BSV re-enabled OP_CAT
- `test_op_split` - BSV re-enabled OP_SPLIT
- `test_op_mul` - BSV re-enabled OP_MUL (3 * 7 = 21)
- `test_op_div` - BSV re-enabled OP_DIV (21 / 7 = 3)
- `test_hash_operations` - OP_SHA256 with computed expected hash

### Sighash Tests (`sighash_tests.rs`)

Transaction sighash computation tests:

- `test_sighash_vectors` - Runs all 499 sighash test vectors
- `test_sighash_first_vector_detailed` - Detailed debugging output for first vector
- `test_parse_all_vectors_transactions` - Verifies transaction parsing for all vectors

### Template Tests (`template_tests.rs`)

Script template integration tests:

**P2PKH Template**
- `test_p2pkh_end_to_end_spend` - Full P2PKH locking script creation and unlocking
- `test_p2pkh_from_address` - P2PKH locking from Bitcoin address
- `test_p2pkh_spend_validation` - P2PKH spend with Spend interpreter

**RPuzzle Template**
- `test_rpuzzle_lock_script_structure` - Verifies RPuzzle script structure (OP_OVER, OP_SPLIT, etc.)
- `test_rpuzzle_hashed_lock` - RPuzzle with HASH160 and SHA256 R values
- `test_rpuzzle_unlock_k_value` - Verifies K value produces correct R in signature
- `test_compute_r_from_k_known_values` - Tests k=1 produces generator point x-coordinate

**Template Utilities**
- `test_template_unlock_estimate_length` - Verifies unlock script length estimation (108 bytes)
- `test_sighash_types` - Tests ALL, NONE, SINGLE, and ANYONECANPAY sighash flags
- `test_rpuzzle_type_hash_functions` - Verifies hash output lengths for all RPuzzle types

### Transaction Tests (`transaction_tests.rs`)

Transaction module tests (requires `transaction` feature flag):

**Transaction Parsing**
- `test_transaction_from_hex` - Parse valid transaction from hex
- `test_transaction_roundtrip_hex` - Hex serialization/deserialization roundtrip
- `test_transaction_roundtrip_binary` - Binary serialization/deserialization roundtrip
- `test_transaction_txid` - Transaction ID computation
- `test_transaction_hash_differs_from_id` - Hash vs TXID byte order
- `test_new_transaction_defaults` - Default transaction values
- `test_invalid_tx_can_be_parsed_structurally` - Invalid tx vectors can still be parsed

**Fee Models**
- `test_fixed_fee` - FixedFee model (constant fee)
- `test_satoshis_per_kilobyte_default` - Default 100 sat/KB rate
- `test_satoshis_per_kilobyte_new` - Custom sat/KB rate
- `test_satoshis_per_kilobyte_empty_tx` - Fee for empty transaction (10 bytes)
- `test_satoshis_per_kilobyte_ceiling_division` - Fees rounded up

**Chain Tracker (async)**
- `test_mock_chain_tracker` - MockChainTracker with merkle root validation
- `test_always_valid_chain_tracker` - AlwaysValidChainTracker accepts all roots

**Broadcaster (async)**
- `test_broadcaster_success` - Successful broadcast response
- `test_broadcaster_failure` - Failed broadcast with error code
- `test_broadcaster_many` - Batch broadcasting multiple transactions

**MerklePath (BUMP)**
- `test_merkle_path_from_hex` - Parse BRC-74 BUMP format
- `test_merkle_path_roundtrip` - BUMP hex roundtrip
- `test_merkle_path_from_coinbase` - Create MerklePath for coinbase tx
- `test_merkle_path_compute_root` - Compute merkle root from path
- `test_invalid_bump_vectors` - Invalid BUMP vectors fail parsing/validation

**BEEF Format**
- `test_beef_new` - Create empty BEEF container
- `test_beef_merge_txid_only` - Add txid-only references
- `test_beef_merge_bump` - Add MerklePath to BEEF
- `test_beef_empty_is_valid` - Empty BEEF validation

**Big Transaction Tests**
- `test_big_tx_constant_exists` - Verify big TX TXID constant
- `test_large_tx_parses` - Parse large coinbase transaction
- `test_multi_io_tx_parses` - Parse transaction with multiple inputs/outputs

**Transaction Construction**
- `test_estimate_size` - Size estimation accuracy
- `test_add_input_requires_txid_or_source` - Input validation
- `test_add_input_with_txid` - Add input with txid
- `test_add_output` - Add output
- `test_add_change_output` - Add change output with flag
- `test_metadata` - Transaction metadata updates

## Running Tests

```bash
# Run all integration tests
cargo test --test cross_sdk_tests
cargo test --test ec_tests
cargo test --test integration_tests
cargo test --test script_vectors_tests
cargo test --test sighash_tests
cargo test --test template_tests
cargo test --test transaction_tests --features transaction

# Run specific test
cargo test --test integration_tests test_complete_payment_workflow

# Run with output (for debugging tests that print)
cargo test --test sighash_tests -- --nocapture

# Run async tests (transaction module requires tokio)
cargo test --test transaction_tests --features transaction -- test_mock_chain_tracker
```

## Test Vector Structures

### BRC-42 Private Vector
```rust
struct Brc42PrivateVector {
    sender_public_key: String,      // Hex-encoded compressed public key
    recipient_private_key: String,  // Hex-encoded 32-byte private key
    invoice_number: String,         // Invoice string (used directly, not decoded)
    private_key: String,            // Expected derived private key (hex)
}
```

### BRC-42 Public Vector
```rust
struct Brc42PublicVector {
    sender_private_key: String,     // Hex-encoded 32-byte private key
    recipient_public_key: String,   // Hex-encoded compressed public key
    invoice_number: String,         // Invoice string
    public_key: String,             // Expected derived public key (hex)
}
```

### Symmetric Key Vector
```rust
struct SymmetricKeyVector {
    ciphertext: String,  // Base64-encoded ciphertext
    key: String,         // Base64-encoded 32-byte key
    plaintext: String,   // UTF-8 plaintext (not base64)
}
```

### Sighash Vector
```rust
struct SighashVector {
    raw_tx: String,       // Hex-encoded raw transaction
    script: String,       // Hex-encoded subscript
    input_index: usize,   // Input being signed
    hash_type: i32,       // Sighash flags (can be negative when high bit set)
    expected_hash: String, // Expected sighash (hex)
}
```

### Spend/Script Vector
```rust
struct SpendVector {
    script_sig: String,      // Hex-encoded unlocking script
    script_pub_key: String,  // Hex-encoded locking script
    comment: String,         // Description of what vector tests
}

struct ScriptVector {
    script_sig: String,      // Hex-encoded unlocking script
    script_pub_key: String,  // Hex-encoded locking script
    flags: String,           // Test flags (e.g., "P2SH", "STRICTENC")
    comment: String,         // Description of what vector tests
}
```

### DRBG Vector
```rust
struct DrbgVector {
    name: String,            // Vector identifier
    entropy: String,         // Hex-encoded entropy (32 bytes)
    nonce: String,           // Hex-encoded nonce (16 bytes)
    pers: Option<String>,    // Optional personalization string
    add: Vec<Option<String>>, // Additional data for each generate call
    expected: String,        // Expected HMAC-DRBG output (128 bytes hex)
}
```

### Invalid BUMP Vector
```rust
struct BumpInvalidVector {
    bump: &'static str,      // Invalid BUMP hex data
    error: &'static str,     // Expected error description
}
```

## Key Types Used

| Type | Import Path | Description |
|------|-------------|-------------|
| `PrivateKey` | `bsv_sdk::primitives::ec` | secp256k1 private key |
| `PublicKey` | `bsv_sdk::primitives::ec` | secp256k1 public key |
| `SymmetricKey` | `bsv_sdk::primitives::symmetric` | AES-256-GCM symmetric key |
| `P256PrivateKey` | `bsv_sdk::primitives::p256` | NIST P-256 private key |
| `P256PublicKey` | `bsv_sdk::primitives::p256` | NIST P-256 public key |
| `Schnorr` | `bsv_sdk::primitives::bsv::schnorr` | Schnorr proof generation/verification |
| `KeyShares` | `bsv_sdk::primitives::bsv::shamir` | Shamir secret sharing |
| `BigNumber` | `bsv_sdk::primitives` | Arbitrary precision integers |
| `Script` | `bsv_sdk::script` | Bitcoin script |
| `LockingScript` | `bsv_sdk::script` | Script for locking outputs |
| `UnlockingScript` | `bsv_sdk::script` | Script for unlocking inputs |
| `Spend` | `bsv_sdk::script` | Script spend validator/interpreter |
| `P2PKH` | `bsv_sdk::script::templates` | Pay-to-Public-Key-Hash template |
| `RPuzzle` | `bsv_sdk::script::templates` | R-Puzzle template |
| `Transaction` | `bsv_sdk::transaction` | Bitcoin transaction |
| `TransactionInput` | `bsv_sdk::transaction` | Transaction input |
| `TransactionOutput` | `bsv_sdk::transaction` | Transaction output |
| `MerklePath` | `bsv_sdk::transaction` | BRC-74 BUMP merkle proof |
| `Beef` | `bsv_sdk::transaction` | BRC-62 BEEF container |
| `FeeModel` | `bsv_sdk::transaction` | Fee computation trait |
| `SatoshisPerKilobyte` | `bsv_sdk::transaction` | Per-KB fee model |
| `FixedFee` | `bsv_sdk::transaction` | Constant fee model |
| `Broadcaster` | `bsv_sdk::transaction` | Transaction broadcast trait (async) |
| `ChainTracker` | `bsv_sdk::transaction` | Block header/merkle root tracker (async) |
| `AlwaysValidChainTracker` | `bsv_sdk::transaction` | ChainTracker that accepts all roots |
| `MockChainTracker` | `bsv_sdk::transaction` | ChainTracker with configurable roots |
| `BroadcastResponse` | `bsv_sdk::transaction` | Successful broadcast result |
| `BroadcastFailure` | `bsv_sdk::transaction` | Failed broadcast result |
| `BroadcastStatus` | `bsv_sdk::transaction` | Broadcast status enum (Success, Error) |

## Hash Functions Used

| Function | Import Path | Output |
|----------|-------------|--------|
| `sha256` | `bsv_sdk::primitives::hash` | 32 bytes |
| `sha256d` | `bsv_sdk::primitives::hash` | 32 bytes (double SHA256) |
| `hash160` | `bsv_sdk::primitives::hash` | 20 bytes (SHA256 + RIPEMD160) |
| `sha256_hmac` | `bsv_sdk::primitives::hash` | 32 bytes |
| `sha512_hmac` | `bsv_sdk::primitives::hash` | 64 bytes |

## Encoding Functions Used

| Function | Import Path | Description |
|----------|-------------|-------------|
| `from_hex` / `to_hex` | `bsv_sdk::primitives` | Hex encoding |
| `from_base64` / `to_base64` | `bsv_sdk::primitives` | Base64 encoding |
| `from_base58` / `to_base58` | `bsv_sdk::primitives` | Base58 encoding |
| `from_base58_check` | `bsv_sdk::primitives` | Base58Check decoding |

## Adding New Tests

When adding cross-SDK compatibility tests:

1. Add test vectors to `tests/vectors/` in JSON format
2. Use `serde` for deserialization with `#[serde(rename_all = "camelCase")]` for camelCase JSON
3. Load vectors using `fs::read_to_string` or `include_str!`
4. Iterate over vectors with index for clear error messages
5. Use `unwrap_or_else` with panic messages that include vector index

Example pattern:
```rust
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct MyVector {
    input_data: String,
    expected_output: String,
}

#[test]
fn test_my_vectors() {
    let data = fs::read_to_string("tests/vectors/my_vectors.json")
        .expect("Failed to read vectors");
    let vectors: Vec<MyVector> = serde_json::from_str(&data)
        .expect("Failed to parse vectors");

    for (i, v) in vectors.iter().enumerate() {
        let result = compute_something(&v.input_data)
            .unwrap_or_else(|e| panic!("Vector {}: {}", i, e));

        assert_eq!(result, v.expected_output, "Vector {}: mismatch", i);
    }
}
```

When adding transaction module tests:

1. Add Rust const vectors to `tests/transaction/vectors/` modules
2. Use `#[cfg(feature = "transaction")]` for tests requiring the transaction feature
3. Export vectors from module using `pub const` declarations
4. Wrap async tests with `#[tokio::test]` for ChainTracker and Broadcaster tests
5. Implement the `Broadcaster` trait with `#[async_trait(?Send)]` for test broadcasters

## Notes on BSV vs BTC Script Vectors

Some test vectors in `script_valid.json` may fail execution because:
- BSV requires push-only unlocking scripts
- BSV requires minimal push encoding
- BSV has different clean stack requirements
- Some vectors test BTC-specific behavior (P2SH, etc.)

The BSV-specific `spend_valid.json` vectors should all pass.

## Related Documentation

- `CLAUDE.md` - Root project documentation
- `src/primitives/CLAUDE.md` - Primitives module documentation
- `src/primitives/ec/CLAUDE.md` - Elliptic curve module documentation
- `src/script/CLAUDE.md` - Script module documentation
- `src/transaction/CLAUDE.md` - Transaction module documentation
