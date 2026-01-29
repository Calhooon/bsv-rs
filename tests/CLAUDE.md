# Integration Tests
> Cross-module and cross-SDK compatibility testing

## Overview

This directory contains integration tests that verify the BSV Rust SDK works correctly across modules and produces results identical to the TypeScript and Go SDK implementations. Tests use shared JSON test vectors to ensure byte-for-byte compatibility across all three SDK implementations.

## Files

| File | Purpose |
|------|---------|
| `auth_cross_sdk_tests.rs` | Auth cross-SDK certificate serialization tests (13 tests) |
| `auth_integration_tests.rs` | Auth module integration tests (26 tests: certificates, sessions, transport) |
| `compat_bip39_tests.rs` | BIP-39 mnemonic tests with official TREZOR vectors (29 tests) |
| `compat_integration_tests.rs` | Compat module integration tests (BIP-32/39, BSM, ECIES, 31 tests) |
| `cross_sdk_tests.rs` | Tests using shared vectors from TypeScript/Go SDKs (17 tests) |
| `drbg_tests.rs` | HMAC-DRBG tests with NIST SP 800-90A vectors (6 tests) |
| `ec_tests.rs` | Elliptic curve and BRC-42 key derivation tests (10 tests) |
| `identity_tests.rs` | Identity module tests (50+ tests: certificates, contacts, queries) |
| `integration_tests.rs` | Full workflow tests across all modules (22 tests) |
| `kvstore_integration_tests.rs` | KVStore module tests (70+ tests: LocalKVStore, interpreter, queries) |
| `memory_profiling.rs` | Heap allocation profiling with dhat (requires `dhat-profiling` feature) |
| `messages_tests.rs` | BRC-77/BRC-78 message signing/encryption tests (35+ tests) |
| `overlay_cross_sdk_tests.rs` | Overlay cross-SDK admin token and type tests (13 tests) |
| `overlay_integration_tests.rs` | Overlay module integration tests (60 tests) |
| `registry_integration_tests.rs` | Registry module integration tests (50 tests: definitions, queries, serialization) |
| `script_vectors_tests.rs` | Script interpreter tests with ~1,660 vectors (13 tests) |
| `sighash_tests.rs` | Transaction sighash computation with 499 vectors (3 tests) |
| `storage_tests.rs` | UHRP storage module tests (70 tests: URLs, downloader, uploader) |
| `template_tests.rs` | Script template tests (P2PKH, RPuzzle, 10 tests) |
| `transaction_tests.rs` | Transaction module tests (BEEF, MerklePath, fee models, 84 tests) |
| `wallet_tests.rs` | Wallet module tests (60+ tests: KeyDeriver, ProtoWallet, wire protocol) |
| `transaction/` | Transaction test vectors module |

## Test Vectors

Test vectors are stored in `tests/vectors/` and shared with the TypeScript and Go SDKs:

| Vector File | Contents |
|-------------|----------|
| `auth_certificate.json` | Auth certificate serialization vectors (4 vectors) |
| `brc42_private.json` | BRC-42 private key derivation vectors |
| `overlay_admin_token.json` | Overlay SHIP/SLAP admin token vectors (4 vectors) |
| `overlay_types.json` | Overlay type serialization vectors |
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
| `beef_cross_sdk.rs` | BEEF (BRC-62) and MerklePath vectors from TypeScript/Go SDKs |
| `CLAUDE.md` | Transaction vectors documentation |

## Test Categories

### BIP-39 Compatibility (`compat_bip39_tests.rs`)

BIP-39 mnemonic phrase tests using official TREZOR vectors (29 tests, requires `compat` feature):

**Entropy to Mnemonic**
- `test_entropy_to_mnemonic` - 22 vectors converting entropy to mnemonic phrases
- `test_entropy_roundtrip` - Verifies entropy extraction from mnemonic matches original

**Mnemonic to Seed**
- `test_mnemonic_to_seed` - 22 vectors with passphrase "TREZOR" producing 512-bit seeds
- `test_to_seed_empty_passphrase` - Empty passphrase matches `to_seed_normalized()`

**Mnemonic Validation**
- `test_mnemonic_validation` - All test vectors produce valid mnemonics
- `test_invalid_mnemonic_bad_sentences` - 16 bad sentences from Go SDK rejected
- `test_invalid_mnemonic_wrong_word_count` - 11 and 13 word mnemonics rejected
- `test_invalid_mnemonic_bad_checksum` - Invalid checksum detection
- `test_invalid_mnemonic_unknown_word` - Unknown word detection

**Mnemonic Generation**
- `test_generate_mnemonic_12_words` - Generate valid 12-word mnemonic
- `test_generate_mnemonic_15_words` - Generate valid 15-word mnemonic
- `test_generate_mnemonic_18_words` - Generate valid 18-word mnemonic
- `test_generate_mnemonic_21_words` - Generate valid 21-word mnemonic
- `test_generate_mnemonic_24_words` - Generate valid 24-word mnemonic

**Entropy Validation**
- `test_invalid_entropy_length` - Rejects 15, 17, and 33 byte entropy
- `test_valid_entropy_lengths` - Accepts 16, 20, 24, 28, 32 byte entropy

**Parsing**
- `test_phrase_case_insensitive` - Mixed case phrases normalize to lowercase
- `test_phrase_with_extra_spaces` - Extra whitespace is trimmed

**Utilities**
- `test_word_count_enum` - WordCount methods (entropy_bytes, word_count, checksum_bits)
- `test_language_default` - Default language is English
- `test_mnemonic_display` - Display trait implementation
- `test_zero_leading_entropy` - Zero-leading entropy roundtrips correctly

### Compat Integration Tests (`compat_integration_tests.rs`)

Full workflow integration tests for the compat module (31 tests, requires `compat` feature):

**BIP-39 + BIP-32 HD Wallet Integration**
- `test_full_hd_wallet_generation_flow` - Generate mnemonic, create master key, derive child keys, generate addresses
- `test_mnemonic_to_hd_key_helper` - Test generate_hd_key_from_mnemonic helper function
- `test_extended_key_serialization_roundtrip` - xprv/xpub string serialization roundtrip
- `test_hardened_derivation` - Hardened child key derivation (m/0')
- `test_public_key_derivation_only` - Derive public children from public extended key
- `test_testnet_hd_key_derivation` - Testnet network (tprv/tpub) derivation

**Bitcoin Signed Message (BSM)**
- `test_bsm_sign_verify_roundtrip` - Sign message, verify against address
- `test_bsm_public_key_recovery` - Recover public key from signature
- `test_bsm_compressed_and_uncompressed` - Both compressed and uncompressed signatures
- `test_bsm_different_messages_different_signatures` - Different messages produce different signatures
- `test_bsm_empty_and_long_messages` - Empty and 10KB message handling

**ECIES Encryption**
- `test_electrum_ecies_roundtrip` - Electrum-style ECIES encrypt/decrypt
- `test_electrum_ecies_no_key_mode` - Electrum ECIES with no_key=true (omit ephemeral pubkey)
- `test_bitcore_ecies_roundtrip` - Bitcore-style ECIES encrypt/decrypt
- `test_bitcore_ecies_with_fixed_iv` - Deterministic encryption with fixed IV
- `test_ecies_self_encryption` - Encrypt/decrypt with same key pair
- `test_ecies_empty_and_large_messages` - Empty and 1MB message handling
- `test_ecies_wrong_key_fails` - Decryption with wrong key fails

**Base58 Encoding**
- `test_base58_roundtrip` - Encode/decode roundtrip
- `test_base58_leading_zeros` - Leading zero preservation
- `test_base58_known_values` - Known Bitcoin Base58 test vectors

**Cross-Module Integration**
- `test_mnemonic_to_signed_message` - Generate mnemonic, derive key, sign message
- `test_mnemonic_to_ecies_encryption` - Generate mnemonic, derive key, encrypt/decrypt

**Error Handling**
- `test_invalid_mnemonic_phrase` - Invalid mnemonic phrase rejected
- `test_invalid_extended_key_string` - Invalid xprv/xpub strings rejected
- `test_invalid_derivation_path` - Invalid BIP-32 paths rejected
- `test_invalid_bsm_signature` - Invalid BSM signature format rejected
- `test_invalid_ecies_ciphertext` - Truncated/corrupted ciphertext rejected

**Type and Enum Tests**
- `test_word_count_enum` - WordCount enum methods
- `test_language_enum` - Language enum values
- `test_network_enum` - Network (Mainnet/Testnet) enum

### Cross-SDK Compatibility (`cross_sdk_tests.rs`)

Tests that verify the Rust implementation matches TypeScript and Go SDK output (17 tests):

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

### DRBG Tests (`drbg_tests.rs`)

HMAC-DRBG (Deterministic Random Bit Generator) tests using NIST SP 800-90A vectors (6 tests):

**NIST Vector Tests**
- `test_drbg_nist_vectors` - Runs 15 NIST test vectors with SHA-256

**DRBG Variants**
- `test_drbg_sha512_variant` - Tests SHA-512 HMAC-DRBG produces different output than SHA-256
- `test_drbg_empty_personalization` - Empty personalization string works correctly

**DRBG Operations**
- `test_drbg_reseed_changes_output` - Verifies reseed changes generator state
- `test_drbg_output_length` - Tests various output lengths (1, 16, 32, 64, 128, 256 bytes)
- `test_drbg_determinism` - Verifies same inputs produce same outputs

### EC Module Tests (`ec_tests.rs`)

Focused tests for elliptic curve operations using BRC-42 test vectors (10 tests):

**BRC-42 Key Derivation**
- `test_brc42_private_derivation` - Recipient derives child private key from sender's public key using JSON vectors
- `test_brc42_public_derivation` - Sender derives child public key from recipient's public key using JSON vectors
- `test_brc42_consistency` - Verifies private and public derivation produce matching key pairs

**Key Serialization**
- `test_wif_roundtrip_known_vectors` - WIF encoding/decoding with known test cases (k=1, k=known)
- `test_public_key_known_vectors` - Known private to public key mappings (generator point, 2G, 3G)
- `test_address_generation_known_vectors` - Known public key to address mappings (1BgGZ9...)

**Signing and Verification**
- `test_sign_and_verify_roundtrip` - Signs and verifies messages of various lengths (empty, 100 bytes, 256 bytes)
- `test_deterministic_signatures` - Verifies RFC 6979 deterministic signing (same message = same signature)
- `test_public_key_recovery` - Recovers public key from signature using recovery IDs 0-1

**ECDH**
- `test_ecdh_shared_secret` - Verifies both parties derive identical shared secret

### Integration Tests (`integration_tests.rs`)

Full workflow tests combining multiple modules (22 tests):

**Key Derivation Workflows**
- `test_full_key_derivation_workflow` - Complete BRC-42 key agreement between sender and recipient
- `test_key_derivation_multiple_invoices` - Verifies different invoices produce unique keys (4 invoices)
- `test_sign_and_verify_with_derived_keys` - Signs with BRC-42 derived keys, verifies low-S
- `test_signature_recovery_with_derived_keys` - Recovers public key from derived key signature

**Symmetric Encryption**
- `test_symmetric_encryption_with_derived_key` - Encrypts using ECDH X coordinate as key
- `test_symmetric_encryption_bidirectional` - Both parties can encrypt/decrypt using shared secret

**WIF and Address**
- `test_wif_address_roundtrip` - Mainnet key export and address generation (prefix '1')
- `test_testnet_wif_address` - Testnet WIF (prefix 0xEF) and address (prefix 0x6F, starts with 'm' or 'n')

**Schnorr Proofs**
- `test_schnorr_proof_with_derived_keys` - Generates and verifies Schnorr proofs using shared secret
- `test_schnorr_proof_fails_with_wrong_secret` - Verifies proof rejection with Carol's secret instead of Bob's

**Shamir Secret Sharing**
- `test_shamir_with_wif_export` - Splits key into 5 shares (threshold 3), recovers, verifies WIF match
- `test_shamir_different_subsets` - Recovers from 4 different 3-of-5 share combinations

**P-256 Curve**
- `test_p256_sign_verify_roundtrip` - P-256 signing and verification
- `test_p256_key_serialization` - P-256 key hex and compressed (33 bytes) / uncompressed (65 bytes) formats

**Hash Functions**
- `test_hash_chain_for_key_derivation` - SHA256 (32 bytes), SHA256d (32 bytes), Hash160 (20 bytes) chaining
- `test_hmac_for_key_derivation` - SHA256-HMAC (32 bytes) and SHA512-HMAC (64 bytes)

**Encoding**
- `test_encoding_roundtrips` - Hex, Base64, Base58 roundtrips
- `test_address_encoding_integration` - Address encoding with Base58Check (version byte 0x00)

**Sighash**
- `test_sighash_with_signature` - Computes sighash with SIGHASH_ALL | SIGHASH_FORKID and signs

**Complete Workflows**
- `test_complete_payment_workflow` - Full merchant/customer payment with BRC-42, ECDH encryption, signing
- `test_key_backup_and_recovery_workflow` - Complete Shamir split (3-of-5), backup, recover, sign workflow
- `test_multi_party_schnorr_verification` - Both Alice and Bob generate and cross-verify proofs

### Script Vectors Tests (`script_vectors_tests.rs`)

Comprehensive script interpreter tests using TypeScript SDK vectors (13 tests):

**Spend Valid Vectors**
- `test_spend_valid_vectors` - Runs ~570+ spend execution test vectors with SpendParams
- `test_first_spend_vector_detailed` - Detailed debugging output for first vector (ASM, hex)

**Script Parsing Tests**
- `test_script_valid_vectors_parsing` - Tests ~590+ scripts can be parsed and hex roundtrips
- `test_script_valid_vectors_execution` - Tests script execution (P2SH vectors skipped for BSV)

**Script Invalid Vectors**
- `test_script_invalid_vectors` - Verifies ~500+ invalid scripts fail during parsing or execution

**Individual Script Tests**
- `test_arithmetic_script` - Basic arithmetic (OP_1 OP_2 OP_ADD OP_3 OP_EQUAL)
- `test_op_depth` - OP_DEPTH operation (empty stack = 0)
- `test_conditional` - IF/ELSE/ENDIF control flow with OP_1 condition
- `test_op_cat` - BSV re-enabled OP_CAT ("ab" + "cd" = "abcd")
- `test_op_split` - BSV re-enabled OP_SPLIT ("abcd" at position 2)
- `test_op_mul` - BSV re-enabled OP_MUL (3 * 7 = 21)
- `test_op_div` - BSV re-enabled OP_DIV (21 / 7 = 3)
- `test_hash_operations` - OP_SHA256 with computed expected hash from primitives

### Sighash Tests (`sighash_tests.rs`)

Transaction sighash computation tests (3 tests, 499 vectors):

- `test_sighash_vectors` - Runs all 499 sighash test vectors using `compute_sighash` and `parse_transaction`
- `test_sighash_first_vector_detailed` - Detailed debugging output: raw_tx, script, hash_type, parsed inputs/outputs
- `test_parse_all_vectors_transactions` - Verifies all 499 transactions can be parsed from raw hex

### Template Tests (`template_tests.rs`)

Script template integration tests (10 tests):

**P2PKH Template**
- `test_p2pkh_end_to_end_spend` - Full P2PKH locking script creation (DUP HASH160 EQUALVERIFY CHECKSIG) and unlocking
- `test_p2pkh_from_address` - P2PKH locking from Bitcoin address matches locking from pubkey hash
- `test_p2pkh_spend_validation` - P2PKH spend with Spend interpreter (validates structure)

**RPuzzle Template**
- `test_rpuzzle_lock_script_structure` - Verifies RPuzzle script: OP_OVER, OP_3, OP_SPLIT, OP_NIP, OP_SWAP, OP_DROP, OP_EQUALVERIFY, OP_CHECKSIG
- `test_rpuzzle_hashed_lock` - RPuzzle with HASH160 (contains OP_HASH160) and SHA256 (contains OP_SHA256) R values
- `test_rpuzzle_unlock_k_value` - Verifies K value produces correct R in signature (DER R extraction)
- `test_compute_r_from_k_known_values` - Tests k=1 produces generator point x-coordinate (79BE667E...)

**Template Utilities**
- `test_template_unlock_estimate_length` - Both P2PKH and RPuzzle estimate 108 bytes
- `test_sighash_types` - Tests ALL|FORKID (0x41), NONE|FORKID (0x42), SINGLE|FORKID (0x43), ALL|FORKID|ANYONECANPAY (0xC1)
- `test_rpuzzle_type_hash_functions` - Verifies Raw (same length), Sha1 (20), Sha256 (32), Hash256 (32), Ripemd160 (20), Hash160 (20)

### Transaction Tests (`transaction_tests.rs`)

Transaction module tests (90+ tests, requires `transaction` feature flag):

**Transaction Parsing**
- `test_transaction_from_hex` - Parse valid transaction from hex (version=1, locktime=0)
- `test_transaction_roundtrip_hex` - Hex serialization/deserialization roundtrip for all TX_VALID_VECTORS
- `test_transaction_roundtrip_binary` - Binary serialization/deserialization roundtrip
- `test_transaction_txid` - Transaction ID computation matches TX_VALID_2_TXID
- `test_transaction_hash_differs_from_id` - Hash vs TXID byte order (reversed)
- `test_new_transaction_defaults` - Default: version=1, lock_time=0, empty inputs/outputs
- `test_invalid_tx_can_be_parsed_structurally` - Invalid tx vectors can still be parsed structurally

**Fee Models**
- `test_fixed_fee` - FixedFee model returns constant 500 sats
- `test_satoshis_per_kilobyte_default` - Default 100 sat/KB rate
- `test_satoshis_per_kilobyte_new` - Custom 1000 sat/KB rate
- `test_satoshis_per_kilobyte_empty_tx` - Fee for empty transaction: 10 bytes × 1000 sat/KB = 10 sats
- `test_satoshis_per_kilobyte_ceiling_division` - Fees rounded up (10 bytes × 100 sat/KB = 1 sat)

**Chain Tracker (async, tokio)**
- `test_mock_chain_tracker` - MockChainTracker with add_root and is_valid_root_for_height
- `test_always_valid_chain_tracker` - AlwaysValidChainTracker accepts all roots at any height

**Broadcaster (async, tokio)**
- `test_broadcaster_success` - BroadcastResponse::success with status Success
- `test_broadcaster_failure` - BroadcastFailure with code "REJECTED"
- `test_broadcaster_many` - broadcast_many for batch broadcasting

**MerklePath (BUMP)**
- `test_merkle_path_from_hex` - Parse BRC-74 BUMP format (all BUMP_VALID_VECTORS)
- `test_merkle_path_roundtrip` - BUMP hex roundtrip
- `test_merkle_path_from_coinbase` - Create MerklePath for coinbase tx at height 100
- `test_merkle_path_compute_root` - Compute merkle root from path (64 hex chars)
- `test_invalid_bump_vectors` - Invalid BUMP vectors with expected error descriptions

**BEEF Format**
- `test_beef_new` - Create empty BEEF container (empty bumps/txs)
- `test_beef_merge_txid_only` - Add txid-only references, find_txid works
- `test_beef_merge_bump` - Add MerklePath to BEEF (index 0)
- `test_beef_empty_is_valid` - Empty BEEF validation with is_valid(false)

**Big Transaction Tests**
- `test_big_tx_constant_exists` - Verify BIG_TX_TXID is 64 hex chars
- `test_large_tx_parses` - Parse LARGE_TX_HEX coinbase (1 input, 1 output)
- `test_multi_io_tx_parses` - Parse MULTI_IO_TX_HEX (2 inputs, 2 outputs)

**Transaction Construction**
- `test_estimate_size` - Size estimation within 10 bytes of actual
- `test_add_input_requires_txid_or_source` - Default TransactionInput fails
- `test_add_input_with_txid` - TransactionInput::new with 64-char txid
- `test_add_output` - TransactionOutput::new with satoshis and LockingScript
- `test_add_change_output` - TransactionOutput::new_change with change=true flag
- `test_metadata` - update_metadata with serde_json::json!

**Extended BEEF Tests** (in `beef_extended_tests` submodule, 17 tests)
- Transaction merging: parent/child, two BEEFs, duplicate deduplication, raw tx
- Sorting: `sort_txs` orders by dependency (grandparent → parent → child)
- Serialization: atomic (with target txid), V1/V2 roundtrip, hex/binary roundtrip
- Validation: empty BEEF, txid-only (strict vs lenient), verify_valid result structure
- MerklePaths: multiple bumps at heights 100-1000000

**BEEF Ancestry Collection Tests** (in `beef_ancestry_tests` submodule, 15 tests)
- `test_to_beef_single_transaction_no_ancestors` - Single tx with no inputs produces valid BEEF
- `test_to_beef_walks_two_level_ancestry` - grandparent → parent → child chain collection
- `test_to_beef_walks_three_level_ancestry` - great-grandparent → grandparent → parent → child
- `test_to_beef_stops_at_proven_transaction` - Stops walking at tx with merkle proof
- `test_to_beef_collects_merkle_proofs` - Collects proofs from multiple proven ancestors
- `test_to_beef_allow_partial_false_fails_on_missing` - Fails when source tx missing
- `test_to_beef_allow_partial_true_skips_missing` - Succeeds with missing source when partial allowed
- `test_to_beef_handles_diamond_dependency` - Deduplicates common ancestor in diamond pattern
- `test_to_beef_dependency_order` - Ancestors ordered before descendants in output
- `test_to_atomic_beef_includes_ancestry` - Atomic BEEF includes full ancestry
- `test_to_beef_with_proven_child` - Proven tx alone in BEEF with its proof
- `test_merkle_path_field_works` - Set and check merkle_path field on Transaction
- `test_to_beef_multiple_inputs_different_chains` - Merges two separate ancestry chains
- `test_to_beef_tip_is_last_transaction` - Tip transaction is always last in BEEF (BRC-62 requirement)
- `test_to_beef_tip_last_with_deep_chains` - Consolidation TX is last with deep ancestry chains

**Cross-SDK Compatibility Tests** (in `cross_sdk_tests` submodule, 13 tests)
- BRC-74 MerklePath: parse, hex roundtrip, compute root for 3 TXIDs
- Single-tx block: root equals coinbase txid
- BRC-62 BEEF: V1/V2 empty serialization, parse from Go SDK, find transactions
- BEEF set: parse multi-tx BEEF, find specific txid, binary roundtrip

**MerklePath Advanced Tests** (in `merkle_path_advanced_tests` submodule, 7 async tests)
- ChainTracker verification: correct root passes, wrong root/height fails
- Utility methods: contains, txids, compute_root(None), binary roundtrip

### Auth Cross-SDK Tests (`auth_cross_sdk_tests.rs`)

Certificate serialization tests for cross-SDK compatibility (13 tests, requires `auth` feature):

**Certificate Parsing**
- `test_certificate_vector_parsing` - Parses all certificate vectors, verifies fields match

**Binary Serialization**
- `test_certificate_binary_roundtrip` - Binary serialization roundtrip with and without signature
- `test_certificate_deterministic_serialization` - Verifies binary output is deterministic
- `test_certificate_binary_format_structure` - Verifies binary format matches TypeScript SDK layout

**Field Handling**
- `test_certificate_fields_sorted_alphabetically` - Fields sorted alphabetically for determinism
- `test_certificate_empty_fields` - Empty fields serialize/deserialize correctly

**Signature Tests**
- `test_certificate_with_signature_has_valid_format` - DER-encoded signatures start with 0x30

**JSON Serialization**
- `test_certificate_json_roundtrip` - JSON serialization roundtrip for all fields

**Type and Serial Number**
- `test_certificate_type_base64` - type_base64() and serial_number_base64() methods

**Outpoint Tests**
- `test_certificate_outpoint_parsing` - Outpoint parsing helper (txid.vout format)
- `test_certificate_without_revocation_outpoint` - None outpoint handles correctly
- `test_certificate_no_outpoint_sentinel_value` - No-outpoint encoded as all-zeros

**Vector Validation**
- `test_certificate_vector_count` - Verifies at least 4 certificate vectors loaded

### Auth Integration Tests (`auth_integration_tests.rs`)

Auth module integration tests (26 tests, requires `auth` feature):

**Session Manager Tests**
- `test_session_manager_lifecycle` - Session creation, lookup, removal, and clearing
- `test_session_manager_identity_lookup` - Lookup by identity key, prefer authenticated sessions
- `test_session_manager_prune_stale` - Prune sessions older than specified age

**AuthMessage Tests**
- `test_auth_message_validation` - Validation for different message types
- `test_auth_message_signing_data` - Signing data construction for InitialResponse and General
- `test_auth_message_key_id` - Key ID generation from nonces

**Mock Transport Tests**
- `test_mock_transport_multiple_responses` - Queue and receive multiple responses
- `test_mock_transport_receive_message` - Receive messages via callback

**HTTP Payload Tests**
- `test_http_request_payload_complex` - Complex HTTP request roundtrip
- `test_http_response_payload_with_headers` - HTTP response with headers roundtrip
- `test_http_request_empty_values` - Empty values handling
- `test_http_request_unicode_values` - Unicode content handling
- `test_http_request_large_header_count` - 100 headers roundtrip

**Certificate Tests**
- `test_certificate_creation_and_signing` - Create, sign, and verify certificate
- `test_certificate_binary_roundtrip` - Binary serialization roundtrip
- `test_certificate_wrong_signer_fails` - Signing with wrong key fails
- `test_verifiable_certificate_creation` - VerifiableCertificate with keyring
- `test_certificate_json_roundtrip` - JSON serialization roundtrip
- `test_verifiable_certificate_json_roundtrip` - VerifiableCertificate JSON roundtrip

**RequestedCertificateSet Tests**
- `test_requested_certificate_set_matching` - Certifier and type matching
- `test_requested_certificate_set_json_roundtrip` - JSON serialization roundtrip

**Peer Session Tests**
- `test_peer_session_ready_states` - Ready state logic based on authentication and certificates
- `test_peer_session_touch` - Touch updates last_update timestamp

**Error Handling Tests**
- `test_invalid_auth_version` - Invalid version is rejected
- `test_duplicate_session_nonce_rejected` - Duplicate nonces are rejected
- `test_session_without_nonce_rejected` - Sessions without nonce are rejected

### Identity Tests (`identity_tests.rs`)

Identity module integration tests (50+ tests, requires `identity` feature):

**KnownCertificateType Tests**
- `test_known_certificate_type_all_types` - All 9 certificate types (IdentiCert, DiscordCert, PhoneCert, XCert, Registrant, EmailCert, Anyone, SelfCert, CoolCert)
- `test_known_certificate_type_names` - Type name strings match expected values
- `test_known_certificate_type_ids_cross_sdk_compatible` - Base64 type IDs match TypeScript/Go SDKs
- `test_known_certificate_type_from_type_id` - Recover type from type ID
- `test_known_certificate_type_from_unknown_id` - Unknown IDs return None

**DisplayableIdentity Tests**
- `test_displayable_identity_from_key_long` - Abbreviation for 66-char public keys
- `test_displayable_identity_from_key_short` - No abbreviation for short keys
- `test_displayable_identity_unknown` - Default unknown identity values
- `test_displayable_identity_json_serialization` - camelCase JSON roundtrip

**Contact Tests**
- `test_contact_creation` - Contact with tags and metadata
- `test_contact_from_identity` - Create from DisplayableIdentity
- `test_contact_to_displayable_identity` - Convert back to DisplayableIdentity
- `test_contact_json_serialization` - JSON roundtrip with camelCase

**IdentityQuery Tests**
- `test_identity_query_by_identity_key` - Query by public key
- `test_identity_query_by_attribute` - Query by single attribute
- `test_identity_query_by_attributes` - Query by multiple attributes
- `test_identity_query_builder_pattern` - Fluent builder with limit, offset, certifier

**ContactsManager Tests** (async)
- `test_add_and_get_contact` - Add contact, retrieve by identity key
- `test_update_contact` - Update existing contact
- `test_remove_contact` - Remove contact by identity key
- `test_list_contacts` - List all contacts
- `test_search_contacts_by_name` - Case-insensitive name search
- `test_get_contacts_by_tag` - Filter by tag
- `test_cache_management` - Cache initialization, count, clearing

**Configuration Tests**
- `test_identity_client_config_default` - Default: Mainnet, protocol (1, "identity"), token_amount=1
- `test_contacts_manager_config_default` - Default: protocol (2, "contact"), basket="contacts"

### KVStore Tests (`kvstore_integration_tests.rs`)

KVStore module integration tests (70+ tests, requires `kvstore` feature):

**KVStoreConfig Tests**
- `test_kvstore_config_default_values` - Default: protocol_id="kvstore", service_name="ls_kvstore", encrypt=true
- `test_kvstore_config_builder_all_fields` - Builder pattern with all options
- `test_kvstore_config_clone` - Clone implementation

**KVStoreEntry Tests**
- `test_kvstore_entry_creation` - Entry with key, value, controller, protocol_id
- `test_kvstore_entry_with_tags` - Entry with tags array
- `test_kvstore_entry_with_token` - Entry with KVStoreToken
- `test_kvstore_entry_with_history` - Entry with value history
- `test_kvstore_entry_json_roundtrip` - JSON serialization roundtrip

**KVStoreToken Tests**
- `test_kvstore_token_creation` - Token with txid, output_index, satoshis
- `test_kvstore_token_with_beef` - Token with BEEF data
- `test_kvstore_token_outpoint_string` - "txid.vout" format

**KVStoreQuery Tests**
- `test_kvstore_query_builder_all_fields` - key, controller, protocol_id, tags, limit, skip, sort_order
- `test_kvstore_query_to_json` - JSON output for query parameters

**KVStoreInterpreter Tests**
- `test_interpreter_extract_basic_token` - Extract entry from PushDrop script
- `test_interpreter_extract_token_with_tags` - Extract entry with tags
- `test_interpreter_with_matching_context` - Context filtering
- `test_interpreter_is_kvstore_token` - Token format validation
- `test_interpreter_extract_fields` - Extract all KVStoreFields

**LocalKVStore Tests** (async)
- `test_local_kvstore_new_success` - Creation with MockWallet
- `test_local_kvstore_get_returns_default_when_not_found` - Default value fallback
- `test_local_kvstore_set_success` - Set key-value, returns outpoint
- `test_local_kvstore_remove_not_found_returns_empty` - Remove non-existent key
- `test_local_kvstore_has_not_found` - Existence check
- `test_local_kvstore_keys_empty` - List all keys
- `test_local_kvstore_count_empty` - Entry count
- `test_local_kvstore_clear_empty` - Clear all entries

**Signature Verification Tests**
- `test_verify_signature_missing` - Missing signature returns false
- `test_verify_signature_invalid_bytes` - Invalid DER signature returns false
- `test_verify_signature_invalid_controller` - Invalid pubkey returns false

**Cross-SDK Compatibility**
- `test_kvstore_config_matches_go_sdk_defaults` - Config defaults match Go SDK
- `test_kvstore_entry_json_field_names_match_typescript` - camelCase field names
- `test_pushdrop_field_order_matches_spec` - Field indices match specification

### Messages Tests (`messages_tests.rs`)

BRC-77 signed message and BRC-78 encrypted message tests (35+ tests, requires `messages` feature):

**BRC-77 Signed Message Tests**
- `test_sign_and_verify_roundtrip_specific_recipient` - Sign for specific recipient, verify
- `test_sign_and_verify_roundtrip_anyone` - Sign for anyone (recipient marker 0x00)
- `test_verify_with_different_key_fails` - Wrong recipient returns MessageRecipientMismatch
- `test_sign_and_verify_empty_message` - Empty message handling
- `test_sign_and_verify_large_message` - 100KB message handling
- `test_tampered_message_returns_false_not_error` - Tampered message returns false, not error
- `test_verify_without_recipient_when_required` - Missing recipient key error
- `test_signature_wrong_version` - Invalid version returns MessageVersionMismatch

**BRC-78 Encrypted Message Tests**
- `test_encrypt_and_decrypt_roundtrip` - Encrypt for recipient, decrypt
- `test_decrypt_with_wrong_key_fails` - Wrong key returns MessageRecipientMismatch
- `test_encrypt_and_decrypt_empty_message` - Empty message handling
- `test_encrypt_and_decrypt_large_message` - 1MB message handling
- `test_tampered_ciphertext_fails_decryption` - GCM authentication failure
- `test_encrypted_message_wrong_version` - Invalid version error
- `test_message_too_short` - Short message error
- `test_same_plaintext_different_ciphertext` - Random keyID/IV produces different output
- `test_different_senders_same_recipient` - Different senders, same recipient decrypts

**Cross-SDK Compatibility**
- `test_cross_sdk_sign_verify_specific_recipient` - Sender=15, recipient=21 vector
- `test_cross_sdk_sign_verify_anyone` - Sender=15, no recipient vector
- `test_cross_sdk_encrypt_decrypt` - Encrypt/decrypt with scalar keys
- `test_cross_sdk_wrong_version_signed_error_format` - Error format: "Expected 42423301, received..."
- `test_cross_sdk_rare_key_length_encrypted` - TypeScript test vector with rare key length

**Version Constants**
- `test_version_constants` - SIGNED_VERSION=0x42423301, ENCRYPTED_VERSION=0x42421033

### Storage Tests (`storage_tests.rs`)

UHRP storage module tests (70 tests, requires `storage` feature):

**UHRP URL Generation**
- `test_get_url_for_file_known_data` - TypeScript SDK test vector
- `test_get_url_for_file_empty` - Empty file produces valid URL
- `test_get_url_for_file_hello_world` - Hello World roundtrip
- `test_get_url_for_hash_known_hash` - Known hash to URL
- `test_get_url_for_hash_invalid_length` - 16/64 byte hashes rejected

**UHRP URL Parsing**
- `test_get_hash_from_url_extracts_correct_hash` - Extract hash from Base58Check
- `test_get_hash_from_url_with_uhrp_prefix` - Handle uhrp:// prefix
- `test_get_hash_from_url_with_web_prefix` - Handle web+uhrp:// prefix
- `test_get_hash_from_url_invalid_checksum` - Bad checksum rejected
- `test_get_hash_from_url_invalid_base58` - Invalid characters (0, O, l, I) rejected

**UHRP URL Validation**
- `test_is_valid_url_accepts_valid_urls` - Base58Check, uhrp://, web+uhrp://
- `test_is_valid_url_rejects_invalid_checksum` - Bad checksum rejected
- `test_is_valid_url_rejects_non_uhrp_urls` - https://, http://, file://, data: rejected
- `test_normalize_url_removes_uhrp_prefix` - Strip uhrp:// prefix
- `test_normalize_url_case_insensitive` - UHRP:// and uhrp:// handled

**Roundtrip Tests**
- `test_roundtrip_file_to_url_to_hash` - File → URL → Hash matches SHA256(file)
- `test_roundtrip_hash_to_url_to_hash` - Hash → URL → Hash identical
- `test_roundtrip_various_files` - Empty, short, 1000 bytes tests
- `test_roundtrip_with_different_prefixes` - All prefix formats

**StorageDownloader Configuration**
- `test_storage_downloader_config_default` - Default: Mainnet, timeout 30000ms
- `test_storage_downloader_config_testnet` - Testnet preset
- `test_storage_downloader_creation` - Create with default config
- `test_storage_downloader_creation_with_config` - Create with custom config

**StorageUploader Configuration**
- `test_storage_uploader_config_new` - Default retention 7 days
- `test_storage_uploader_config_with_retention` - Custom retention
- `test_storage_uploader_base_url` - URL accessor

**UploadableFile Tests**
- `test_uploadable_file_creation` - Data and MIME type
- `test_uploadable_file_empty` - Empty file
- `test_uploadable_file_large` - 1MB file

**Cross-SDK Compatibility**
- `test_cross_sdk_hash_to_url` - Hash→URL matches TypeScript SDK
- `test_cross_sdk_file_to_url` - File→URL matches TypeScript SDK
- `test_cross_sdk_url_to_hash` - URL→Hash matches TypeScript SDK

### Wallet Tests (`wallet_tests.rs`)

Wallet module tests (60+ tests, requires `wallet` feature):

**KeyDeriver Tests**
- `test_key_deriver_with_known_key` - PrivateKey(42) pattern from TypeScript SDK
- `test_anyone_key_is_scalar_one` - Anyone key is PrivateKey(1)
- `test_invoice_number_format` - Invoice format: "level-protocol-keyID"
- `test_derive_public_key_with_counterparty` - BRC-42 derivation with counterparty
- `test_derive_private_key_matches_public` - Private key's public matches derived public
- `test_derive_symmetric_key_consistency` - Deterministic symmetric keys
- `test_two_party_key_derivation` - Alice and Bob derive matching keys
- `test_reveal_counterparty_secret_fails_for_self` - Self counterparty rejected
- `test_different_security_levels_different_keys` - Silent/App/Counterparty produce unique keys
- `test_protocol_validation` - Protocol name < 5 chars rejected
- `test_key_id_validation` - Empty or > 800 chars rejected

**CachedKeyDeriver Tests**
- `test_cached_deriver_same_identity` - Identity key matches inner deriver
- `test_cache_hit_returns_same_value` - Cached values returned
- `test_lru_eviction` - LRU eviction with max_size=3
- `test_lru_access_updates_recentness` - Access refreshes LRU order
- `test_secrets_not_cached` - reveal_* methods not cached for security
- `test_private_and_symmetric_key_caching` - Both key types cached

**ProtoWallet Tests**
- `test_proto_wallet_creation` - Create with random key
- `test_proto_wallet_anyone` - Anyone wallets have identical identity
- `test_get_public_key_identity` - identity_key=true returns identity
- `test_get_public_key_derived` - Derived key differs from identity
- `test_encrypt_decrypt_roundtrip` - Self-encryption roundtrip
- `test_two_party_encryption` - Alice encrypts for Bob, Bob decrypts
- `test_decrypt_fails_with_wrong_protocol` - Protocol mismatch fails
- `test_create_verify_hmac_roundtrip` - HMAC create and verify
- `test_hmac_verification_fails_with_wrong_data` - Tampered data fails
- `test_hmac_cross_party_verification` - Alice creates, Bob verifies
- `test_create_verify_signature_roundtrip` - Signature create and verify
- `test_signature_with_direct_hash` - Sign pre-hashed data
- `test_cross_party_signature_verification` - Alice signs, Bob verifies

**Cross-SDK Compatibility**
- `test_brc3_signature_compliance` - BRC-3 signature vector from TypeScript SDK
- `test_brc2_hmac_compliance` - BRC-2 HMAC vector from TypeScript SDK
- `test_brc2_encryption_compliance` - BRC-2 encryption vector from TypeScript SDK
- `test_key_derivation_ts_pattern` - PrivateKey(42), PrivateKey(69) pattern

**Wire Protocol Tests**
- `test_varint_roundtrip` - VarInt encoding 0 to u64::MAX
- `test_signed_varint_roundtrip` - Signed VarInt including negatives
- `test_string_roundtrip` - UTF-8 string encoding
- `test_optional_string_roundtrip` - Optional string (Some/None)
- `test_counterparty_roundtrip` - Self_, Anyone, Other encoding
- `test_protocol_id_roundtrip` - Protocol with security level
- `test_outpoint_roundtrip` - Txid + vout encoding
- `test_string_array_roundtrip` - String array encoding
- `test_query_mode_roundtrip` - Any/All query mode
- `test_output_include_roundtrip` - LockingScripts/EntireTransactions
- `test_string_map_roundtrip` - HashMap<String, String> encoding
- `test_action_status_roundtrip` - Completed/Unprocessed/Sending/Failed

### Memory Profiling (`memory_profiling.rs`)

Heap allocation profiling tests (requires `dhat-profiling` feature):

**Encryption Profiling**
- `test_encryption_allocations` - AES-GCM encrypt/decrypt at 64/256/1024/4096/16384 bytes

**Key Derivation Profiling**
- `test_key_derivation_allocations` - BRC-42 and ECDH shared secret

**Shamir Profiling**
- `test_shamir_allocations` - 3-of-5 and 5-of-10 split/recover

**Signing Profiling**
- `test_signing_allocations` - ECDSA sign, verify, and sign+verify cycle

**Hashing Profiling**
- `test_hashing_allocations` - SHA-256 and Hash160 at 1KB/16KB

### Overlay Cross-SDK Tests (`overlay_cross_sdk_tests.rs`)

Cross-SDK compatibility tests for overlay types (13 tests, requires `overlay` feature):

**Admin Token Tests**
- `test_admin_token_creation_and_decoding` - Create/decode admin tokens, verify all fields match
- `test_admin_token_protocol_detection` - Protocol detection (is_ship_token, is_slap_token, is_overlay_admin_token)
- `test_admin_token_deterministic_encoding` - Token encoding is deterministic
- `test_admin_token_vector_count` - Verifies at least 4 admin token vectors loaded

**Protocol Tests**
- `test_protocol_parsing` - Protocol string parsing case-insensitive

**Network Preset Tests**
- `test_network_presets` - Mainnet/Testnet/Local preset configuration (allow_http, slap_trackers)

**LookupQuestion Tests**
- `test_lookup_question_creation` - Question creation with service and query, JSON roundtrip

**LookupAnswer Tests**
- `test_lookup_answer_output_list_json` - OutputList variant with 2 outputs and context
- `test_lookup_answer_freeform_json` - Freeform variant with status field
- `test_lookup_answer_formula_json` - Formula variant with outpoint and history_fn

**AdmittanceInstructions Tests**
- `test_admittance_instructions_json` - has_activity() and JSON roundtrip

**TaggedBEEF Tests**
- `test_tagged_beef_creation` - Creation with and without off_chain_values, JSON roundtrip

**Vector Validation**
- `test_overlay_types_vector_count` - Verifies minimum vector counts for all types

### Registry Integration Tests (`registry_integration_tests.rs`)

Registry module integration tests (50 tests, requires `registry` feature):

**DefinitionType Tests**
- `test_definition_type_as_str` - String conversion (basket, protocol, certificate)
- `test_definition_type_try_from_str` - Case-insensitive parsing
- `test_definition_type_from_str` - FromStr trait implementation
- `test_definition_type_lookup_service` - Lookup service names (ls_basketmap, ls_protomap, ls_certmap)
- `test_definition_type_broadcast_topic` - Broadcast topic names (tm_basketmap, tm_protomap, tm_certmap)
- `test_definition_type_wallet_basket` - Wallet basket names
- `test_definition_type_expected_field_count` - Field count (6 for basket/protocol, 7 for certificate)

**BasketDefinitionData Tests**
- `test_basket_definition_creation` - Builder pattern with all fields
- `test_basket_definition_identifier` - Identifier is basket_id
- `test_basket_definition_pushdrop_fields` - Encode to 6 PushDrop fields
- `test_basket_definition_from_pushdrop_fields` - Decode from PushDrop fields
- `test_basket_definition_from_pushdrop_fields_wrong_count` - Wrong field count rejected
- `test_basket_definition_json_serialization` - JSON with Go SDK compatible field names

**ProtocolDefinitionData Tests**
- `test_protocol_definition_creation` - Builder pattern with Protocol and fields
- `test_protocol_definition_identifier` - JSON identifier format ([level, "name"])
- `test_protocol_definition_pushdrop_fields` - Encode to 6 PushDrop fields
- `test_protocol_definition_all_security_levels` - Silent, App, Counterparty levels

**CertificateDefinitionData Tests**
- `test_certificate_definition_creation` - Builder pattern with field descriptors
- `test_certificate_field_descriptor_types` - text(), image_url(), custom types
- `test_certificate_definition_pushdrop_fields` - Encode to 7 PushDrop fields

**DefinitionData Enum Tests**
- `test_definition_data_from_basket` - Basket variant conversion and accessors
- `test_definition_data_from_protocol` - Protocol variant conversion and accessors
- `test_definition_data_from_certificate` - Certificate variant conversion and accessors
- `test_definition_data_set_registry_operator` - Set/get registry operator
- `test_definition_data_identifier` - Identifier dispatch by type

**TokenData Tests**
- `test_token_data_creation` - Basic creation with txid, output_index, satoshis, locking_script
- `test_token_data_with_beef` - Creation with optional BEEF data
- `test_token_data_outpoint` - Outpoint format (txid.vout)

**RegistryRecord Tests**
- `test_registry_record_basket` - Basket record with token data
- `test_registry_record_protocol` - Protocol record with token data
- `test_registry_record_certificate` - Certificate record with token data

**Query Types Tests**
- `test_basket_query_builder` - Builder with basket_id, operator, name
- `test_basket_query_multiple_operators` - Multiple registry operators
- `test_basket_query_json_serialization` - JSON with basketID field
- `test_protocol_query_builder` - Builder with protocol_id, name, operator
- `test_certificate_query_builder` - Builder with cert_type, name, operators
- `test_certificate_query_json_serialization` - JSON with type field

**Result Types Tests**
- `test_register_definition_result` - Success/failure states and is_success()/is_failure()
- `test_revoke_definition_result` - Revocation result states
- `test_update_definition_result` - Update result states

**RegistryClientConfig Tests**
- `test_registry_client_config_defaults` - Default: Mainnet, no resolver, no originator
- `test_registry_client_config_builder` - Builder with network, originator, delayed_broadcast
- `test_registry_client_config_local_network` - Local network preset

**Cross-SDK Compatibility Tests**
- `test_pushdrop_field_format_basket_matches_go_sdk` - Basket field order matches Go SDK
- `test_pushdrop_field_format_protocol_matches_go_sdk` - Protocol field order matches Go SDK
- `test_pushdrop_field_format_certificate_matches_go_sdk` - Certificate field order matches Go SDK
- `test_pushdrop_roundtrip_basket` - Basket encode/decode roundtrip
- `test_pushdrop_roundtrip_protocol` - Protocol encode/decode roundtrip
- `test_pushdrop_roundtrip_certificate` - Certificate encode/decode roundtrip

**Constants Tests**
- `test_registry_constants` - Verify LS_*, TM_*, REGISTRANT_* constants

### Overlay Integration Tests (`overlay_integration_tests.rs`)

Overlay module integration tests (60 tests, requires `overlay` feature):

**Network Preset Tests**
- `test_network_preset_slap_trackers` - SLAP tracker URLs for each preset
- `test_network_preset_allow_http` - HTTP allowed only for Local preset
- `test_network_preset_default_is_mainnet` - Default preset is Mainnet

**Protocol Tests**
- `test_protocol_parsing_case_insensitive` - SHIP/SLAP parsing case-insensitive
- `test_protocol_str_roundtrip` - Protocol string roundtrip
- `test_protocol_display` - Display trait implementation
- `test_protocol_json_roundtrip` - JSON serialization roundtrip

**LookupQuestion/Answer Tests**
- `test_lookup_question_creation` - Question creation with service and query
- `test_lookup_answer_output_list` - OutputList variant
- `test_lookup_answer_freeform` - Freeform variant
- `test_lookup_answer_empty_output_list` - Empty output list creation

**TaggedBEEF Tests**
- `test_tagged_beef_creation` - Basic creation with beef and topics
- `test_tagged_beef_with_off_chain_values` - Creation with off-chain values
- `test_tagged_beef_json_roundtrip` - JSON serialization roundtrip

**AdmittanceInstructions Tests**
- `test_admittance_instructions_empty` - Empty instructions has no activity
- `test_admittance_instructions_with_activity` - Various activity combinations
- `test_admittance_instructions_json_roundtrip` - JSON serialization roundtrip

**TopicBroadcaster Tests**
- `test_topic_broadcaster_valid_topics` - Valid topics accepted
- `test_topic_broadcaster_invalid_topic_prefix` - Topics must start with "tm_"
- `test_topic_broadcaster_empty_topics` - At least one topic required
- `test_topic_broadcaster_mixed_valid_invalid` - Mixed valid/invalid rejected
- `test_topic_broadcaster_config_defaults` - Default configuration values
- `test_ship_broadcaster_alias` - SHIPBroadcaster and SHIPCast aliases work

**RequireAck Tests**
- `test_require_ack_variants` - All RequireAck variants
- `test_require_ack_default_is_none` - Default is None

**LookupResolverConfig Tests**
- `test_lookup_resolver_default_config` - Default configuration values
- `test_lookup_resolver_config_custom_values` - Custom configuration values
- `test_lookup_resolver_config_with_host_overrides` - Host overrides
- `test_lookup_resolver_config_with_additional_hosts` - Additional hosts

**HostReputationTracker Tests**
- `test_host_reputation_tracker_basic` - Record success, verify metrics
- `test_host_reputation_tracker_failure` - Record failures, verify metrics
- `test_host_reputation_tracker_success_resets_consecutive_failures` - Success resets failures
- `test_host_reputation_tracker_ranking` - Host ranking by latency and failures
- `test_host_reputation_tracker_config` - Custom config affects EMA calculation
- `test_host_reputation_tracker_reset` - Reset clears all entries
- `test_host_reputation_tracker_with_storage` - Storage persistence
- `test_host_reputation_tracker_json_export_import` - JSON export/import
- `test_host_reputation_tracker_json_import_invalid` - Invalid JSON rejected
- `test_global_reputation_tracker` - Global singleton tracker

**SyncHistorian Tests**
- `test_sync_historian_single_transaction` - Single transaction processing
- `test_sync_historian_chain_traversal` - Chain traversal in chronological order
- `test_sync_historian_filtering` - Interpreter filtering
- `test_sync_historian_with_context` - Context passing to interpreter
- `test_sync_historian_cycle_prevention` - Cycle detection prevents infinite loops
- `test_sync_historian_with_debug` - Debug and version configuration

**Admin Token Tests**
- `test_create_and_decode_ship_token` - SHIP token creation and decoding
- `test_create_and_decode_slap_token` - SLAP token creation and decoding
- `test_is_ship_token` - SHIP token detection
- `test_is_slap_token` - SLAP token detection
- `test_is_overlay_admin_token` - Admin token detection
- `test_admin_token_identity_key_hex` - Identity key hex extraction
- `test_decode_invalid_admin_token` - Invalid tokens rejected

**HostResponse/ServiceMetadata Tests**
- `test_host_response_success` - Success response creation
- `test_host_response_failure` - Failure response creation
- `test_service_metadata_default` - Default metadata values
- `test_service_metadata_creation` - Custom metadata values

**Constants Tests**
- `test_overlay_constants` - Verify constants have reasonable values

## Running Tests

```bash
# Run all integration tests
cargo test --test auth_cross_sdk_tests --features auth
cargo test --test auth_integration_tests --features auth
cargo test --test compat_bip39_tests --features compat
cargo test --test compat_integration_tests --features compat
cargo test --test cross_sdk_tests
cargo test --test drbg_tests
cargo test --test ec_tests
cargo test --test identity_tests --features identity
cargo test --test integration_tests
cargo test --test kvstore_integration_tests --features kvstore
cargo test --test messages_tests --features messages
cargo test --test overlay_cross_sdk_tests --features overlay
cargo test --test overlay_integration_tests --features overlay
cargo test --test registry_integration_tests --features registry
cargo test --test script_vectors_tests
cargo test --test sighash_tests
cargo test --test storage_tests --features storage
cargo test --test template_tests
cargo test --test transaction_tests --features transaction
cargo test --test wallet_tests --features wallet

# Run all tests with full feature (includes all modules)
cargo test --features full

# Run all tests with transaction feature
cargo test --features transaction

# Run all tests with compat feature (includes BIP-39)
cargo test --features compat

# Run all tests with auth feature
cargo test --features auth

# Run all tests with overlay feature
cargo test --features overlay

# Run all tests with registry feature
cargo test --features registry

# Run all tests with identity feature
cargo test --features identity

# Run all tests with kvstore feature
cargo test --features kvstore

# Run all tests with messages feature
cargo test --features messages

# Run all tests with storage feature
cargo test --features storage

# Run all tests with wallet feature
cargo test --features wallet

# Run memory profiling tests (requires dhat-profiling feature)
cargo test --test memory_profiling --features dhat-profiling -- --test-threads=1 --nocapture

# Run specific test
cargo test --test integration_tests test_complete_payment_workflow

# Run with output (for debugging tests that print)
cargo test --test sighash_tests -- --nocapture

# Run async tests (transaction module requires tokio)
cargo test --test transaction_tests --features transaction -- test_mock_chain_tracker

# Run all BEEF tests
cargo test --test transaction_tests --features transaction -- beef
```

## Key Types Used

**Primitives** (`bsv_sdk::primitives`):
- `ec::PrivateKey`, `ec::PublicKey`, `ec::recover_public_key` - secp256k1 keys
- `symmetric::SymmetricKey` - AES-256-GCM encryption
- `p256::P256PrivateKey`, `p256::P256PublicKey` - NIST P-256 keys
- `bsv::schnorr::Schnorr` - Schnorr proof generation/verification
- `bsv::shamir::{KeyShares, split_private_key}` - Shamir secret sharing
- `drbg::HmacDrbg` - HMAC-based DRBG
- `BigNumber` - Arbitrary precision integers

**Compat** (`bsv_sdk::compat`, requires `compat` feature):
- `bip39::Mnemonic` - BIP-39 mnemonic phrase handling
- `bip39::WordCount` - Word count enum (Words12, Words15, Words18, Words21, Words24)
- `bip39::Language` - Language enum (currently English only)

**Script** (`bsv_sdk::script`):
- `Script`, `LockingScript`, `UnlockingScript` - Script types
- `Spend`, `SpendParams` - Script spend validator
- `templates::{P2PKH, RPuzzle, RPuzzleType, PushDrop}` - Script templates
- `ScriptTemplate`, `SignOutputs` - Template trait and sighash selection

**Transaction** (`bsv_sdk::transaction`):
- `Transaction`, `TransactionInput`, `TransactionOutput` - Transaction types
- `Transaction::to_beef(allow_partial)` - Serialize tx with ancestry to BEEF V2 format
- `Transaction::to_beef_v1(allow_partial)` - Serialize tx with ancestry to BEEF V1 format
- `Transaction::to_atomic_beef(allow_partial)` - Serialize as atomic BEEF with target txid
- `TransactionInput::with_source_transaction(tx, vout)` - Input with source tx for ancestry
- `MerklePath` - BRC-74 BUMP merkle proof
- `Beef`, `BEEF_V1`, `BEEF_V2` - BRC-62 BEEF container
- `FeeModel`, `SatoshisPerKilobyte`, `FixedFee` - Fee computation
- `Broadcaster`, `BroadcastResponse`, `BroadcastFailure`, `BroadcastStatus` - Broadcast (async)
- `ChainTracker`, `AlwaysValidChainTracker`, `MockChainTracker` - Chain tracking (async)

**Wallet** (`bsv_sdk::wallet`, requires `wallet` feature):
- `KeyDeriver`, `CachedKeyDeriver`, `KeyDeriverApi` - BRC-42 key derivation
- `ProtoWallet` - Lightweight wallet implementation
- `Protocol`, `SecurityLevel` - Protocol identification (Silent=0, App=1, Counterparty=2)
- `Counterparty` - Self_, Anyone, or Other(PublicKey)
- `wire::{WireReader, WireWriter}` - Binary protocol encoding
- `Outpoint`, `QueryMode`, `OutputInclude`, `ActionStatus` - Wire protocol types

**Identity** (`bsv_sdk::identity`, requires `identity` feature):
- `KnownCertificateType` - IdentiCert, DiscordCert, PhoneCert, XCert, etc.
- `DisplayableIdentity` - Identity with name, avatar, badge
- `Contact`, `ContactsManager`, `ContactsManagerConfig` - Contact management
- `IdentityQuery`, `IdentityClientConfig` - Identity queries and configuration
- `BroadcastResult`, `BroadcastSuccess`, `BroadcastFailure` - Broadcast results

**KVStore** (`bsv_sdk::kvstore`, requires `kvstore` feature):
- `LocalKVStore` - Local key-value store with wallet backend
- `KVStoreConfig` - Configuration (protocol_id, service_name, encrypt)
- `KVStoreEntry`, `KVStoreToken`, `KVStoreFields` - Entry and token types
- `KVStoreQuery`, `KVStoreContext` - Query and filtering
- `KVStoreGetOptions`, `KVStoreSetOptions`, `KVStoreRemoveOptions` - Operation options
- `KVStoreInterpreter` - PushDrop script interpretation

**Messages** (`bsv_sdk::messages`, requires `messages` feature):
- `sign`, `verify` - BRC-77 message signing/verification
- `encrypt`, `decrypt` - BRC-78 message encryption/decryption
- `SIGNED_VERSION`, `ENCRYPTED_VERSION` - Protocol version constants

**Storage** (`bsv_sdk::storage`, requires `storage` feature):
- `get_url_for_file`, `get_url_for_hash` - Generate UHRP URLs
- `get_hash_from_url`, `get_hash_hex_from_url` - Extract hash from URL
- `is_valid_url`, `normalize_url` - URL validation and normalization
- `StorageDownloader`, `StorageDownloaderConfig` - Download from overlay
- `StorageUploader`, `StorageUploaderConfig` - Upload to storage provider
- `UploadableFile`, `DownloadResult`, `UploadFileResult` - File types
- `UHRP_PREFIX`, `WEB_UHRP_PREFIX` - URL prefix constants

**Registry** (`bsv_sdk::registry`, requires `registry` feature):
- `DefinitionType` - Basket, Protocol, or Certificate
- `BasketDefinitionData`, `ProtocolDefinitionData`, `CertificateDefinitionData` - Definition data types
- `CertificateFieldDescriptor` - Field type definitions for certificates
- `DefinitionData` - Enum wrapping all definition types
- `TokenData` - Token/UTXO data for registry records
- `RegistryRecord` - Definition with associated token data
- `BasketQuery`, `ProtocolQuery`, `CertificateQuery` - Query builders
- `RegisterDefinitionResult`, `RevokeDefinitionResult`, `UpdateDefinitionResult` - Operation results
- `RegistryClientConfig` - Client configuration with network preset

## Utility Functions

**Hash Functions** (`bsv_sdk::primitives::hash`):
- `sha256` (32 bytes), `sha256d` (32 bytes, double SHA256), `hash160` (20 bytes)
- `sha256_hmac`, `sha512_hmac` - HMAC variants

**Encoding** (`bsv_sdk::primitives`):
- `from_hex`/`to_hex`, `from_base64`/`to_base64`, `from_base58`/`to_base58`, `from_base58_check`

**Sighash** (`bsv_sdk::primitives::bsv::sighash`):
- `compute_sighash`, `parse_transaction`, `SighashParams`, `TxInput`, `TxOutput`
- Flags: `SIGHASH_ALL`, `SIGHASH_NONE`, `SIGHASH_SINGLE`, `SIGHASH_FORKID`, `SIGHASH_ANYONECANPAY`

## Adding New Tests

**Cross-SDK Compatibility Tests:**
1. Add JSON vectors to `tests/vectors/`
2. Use `#[serde(rename_all = "camelCase")]` for deserialization (matching TypeScript/Go)
3. Load with `fs::read_to_string` or `include_str!`
4. Include vector index in panic messages: `panic!("Vector {}: {}", i, e)`
5. Use `unwrap_or_else` for detailed error context

**BIP-39 Compatibility Tests:**
1. Add test vectors to `test_vectors()` function in `compat_bip39_tests.rs`
2. Use `#[cfg(feature = "compat")]` gate for all compat tests
3. Test both entropy→mnemonic and mnemonic→seed directions
4. Add invalid cases to `bad_mnemonic_sentences()` for validation coverage

**Transaction Module Tests:**
1. Add const vectors to `tests/transaction/vectors/`
2. Use `#[cfg(feature = "transaction")]` gate for all transaction tests
3. Use `#[tokio::test]` for async tests (ChainTracker, Broadcaster)
4. Implement `Broadcaster` with `#[async_trait(?Send)]`
5. Group related tests in submodules (e.g., `beef_extended_tests`, `cross_sdk_tests`)

**Wallet Module Tests:**
1. Use `#[cfg(feature = "wallet")]` gate for all wallet tests
2. Use TypeScript SDK patterns: `PrivateKey(42)`, `PrivateKey(69)` for test keys
3. Test KeyDeriver, CachedKeyDeriver, and ProtoWallet separately in nested modules
4. Use `Protocol::new(SecurityLevel::*, "name")` with 5+ char protocol names
5. Wire protocol tests should verify roundtrip encoding/decoding

**Identity Module Tests:**
1. Use `#[cfg(feature = "identity")]` gate for all identity tests
2. Use `#[tokio::test]` for ContactsManager async operations
3. Test KnownCertificateType type IDs match TypeScript/Go SDKs
4. Verify camelCase JSON serialization for cross-SDK compatibility

**KVStore Module Tests:**
1. Use `#[cfg(feature = "kvstore")]` gate for all kvstore tests
2. Create MockWallet implementing WalletInterface for testing
3. Test KVStoreInterpreter with manually constructed PushDrop scripts
4. Verify field order matches specification (protocol_id, key, value, controller, tags, signature)

**Messages Module Tests:**
1. Use `#[cfg(feature = "messages")]` gate for all messages tests
2. Use `key_from_scalar(n)` helper for deterministic test keys
3. Test BRC-77 signing with specific recipient and "anyone" modes
4. Test BRC-78 encryption roundtrips and error conditions
5. Verify error format matches TypeScript/Go SDKs (MessageVersionMismatch, MessageRecipientMismatch)

**Storage Module Tests:**
1. Use `#[cfg(feature = "storage")]` gate for all storage tests
2. Use TypeScript SDK test vectors (TS_EXAMPLE_HASH_HEX, TS_EXAMPLE_FILE_HEX, TS_EXAMPLE_URL_BASE58)
3. Test URL generation, parsing, validation, and normalization
4. Verify roundtrip: file → URL → hash matches SHA256(file)

**Script Tests:**
1. Use `SpendParams` struct for Spend constructor
2. Set `source_satoshis: 1` for basic tests (or 0 for legacy sighash)
3. Test both parsing (from_hex) and execution (validate)
4. Script hex roundtrip should be case-insensitive match

**DRBG Tests:**
1. `HmacDrbg::new()` for SHA-256, `new_with_hash(..., true)` for SHA-512
2. Generate multiple times if required by vector specification (e.g., `add.len()` times)
3. Expected output is from the final generate call

**Memory Profiling Tests:**
1. Use `#[cfg(feature = "dhat-profiling")]` gate
2. Only one dhat profiler can be active at a time (use `--test-threads=1`)
3. Use `dhat::Profiler::new_heap()` to start profiling a section
4. Print `dhat::HeapStats::get()` for allocation metrics

## Notes on BSV vs BTC Script Vectors

Some test vectors in `script_valid.json` may fail execution because:
- BSV requires push-only unlocking scripts
- BSV requires minimal push encoding
- BSV has different clean stack requirements
- Some vectors test BTC-specific behavior (P2SH, etc.)

The BSV-specific `spend_valid.json` vectors should all pass. Vectors with `flags.contains("P2SH")` are skipped in `test_script_valid_vectors_execution`.

## Test Organization

Tests are organized by feature area:
- **primitives tests**: `cross_sdk_tests.rs`, `drbg_tests.rs`, `ec_tests.rs`, `integration_tests.rs`
- **script tests**: `script_vectors_tests.rs`, `template_tests.rs`
- **transaction tests**: `sighash_tests.rs`, `transaction_tests.rs`
- **wallet tests**: `wallet_tests.rs` (requires `wallet` feature)
- **identity tests**: `identity_tests.rs` (requires `identity` feature)
- **kvstore tests**: `kvstore_integration_tests.rs` (requires `kvstore` feature)
- **messages tests**: `messages_tests.rs` (requires `messages` feature)
- **storage tests**: `storage_tests.rs` (requires `storage` feature)
- **compat tests**: `compat_bip39_tests.rs`, `compat_integration_tests.rs` (requires `compat` feature)
- **auth tests**: `auth_cross_sdk_tests.rs`, `auth_integration_tests.rs` (requires `auth` feature)
- **overlay tests**: `overlay_cross_sdk_tests.rs`, `overlay_integration_tests.rs` (requires `overlay` feature)
- **registry tests**: `registry_integration_tests.rs` (requires `registry` feature)
- **profiling tests**: `memory_profiling.rs` (requires `dhat-profiling` feature)

The `transaction_tests.rs` file uses nested modules for organization:
- `transaction_tests` - Main test module (gated by `#[cfg(feature = "transaction")]`)
- `beef_extended_tests` - Extended BEEF format tests
- `beef_ancestry_tests` - BEEF ancestry collection tests for `to_beef()` method
- `cross_sdk_tests` - Cross-SDK compatibility using `beef_cross_sdk.rs` vectors
- `merkle_path_advanced_tests` - Advanced MerklePath verification with ChainTracker

The `wallet_tests.rs` file uses nested modules for organization:
- `key_deriver_tests` - KeyDeriver unit tests
- `cached_key_deriver_tests` - CachedKeyDeriver caching tests
- `proto_wallet_tests` - ProtoWallet cryptographic operations
- `cross_sdk_tests` - BRC-2/BRC-3 compliance vectors from TypeScript SDK
- `wire_protocol_tests` - Wire protocol encoding/decoding

The `identity_tests.rs` file uses nested modules for organization:
- `contacts_manager_tests` - ContactsManager async operations
- `identity_client_tests` - IdentityClient configuration tests

## Related Documentation

- `CLAUDE.md` - Root project documentation
- `src/primitives/CLAUDE.md` - Primitives module documentation
- `src/primitives/ec/CLAUDE.md` - Elliptic curve module documentation
- `src/script/CLAUDE.md` - Script module documentation
- `src/transaction/CLAUDE.md` - Transaction module documentation
- `src/wallet/CLAUDE.md` - Wallet module documentation
- `src/storage/CLAUDE.md` - Storage module documentation
- `src/overlay/CLAUDE.md` - Overlay module documentation
- `src/registry/CLAUDE.md` - Registry module documentation
- `tests/transaction/vectors/CLAUDE.md` - Transaction test vectors documentation
