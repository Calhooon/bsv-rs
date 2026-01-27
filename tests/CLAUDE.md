# Integration Tests
> Cross-module and cross-SDK compatibility testing

## Overview

This directory contains integration tests that verify the BSV Rust SDK works correctly across modules and produces results identical to the TypeScript and Go SDK implementations. Tests use shared JSON test vectors to ensure byte-for-byte compatibility across all three SDK implementations.

## Files

| File | Purpose |
|------|---------|
| `auth_cross_sdk_tests.rs` | Auth cross-SDK certificate serialization tests (11 tests) |
| `auth_integration_tests.rs` | Auth module integration tests (certificates, sessions, transport) |
| `compat_bip39_tests.rs` | BIP-39 mnemonic tests with official TREZOR vectors (22 vectors) |
| `compat_integration_tests.rs` | Compat module integration tests (BIP-32/39, BSM, ECIES, 31 tests) |
| `cross_sdk_tests.rs` | Tests using shared vectors from TypeScript/Go SDKs |
| `drbg_tests.rs` | HMAC-DRBG tests with NIST SP 800-90A vectors (15 vectors) |
| `ec_tests.rs` | Elliptic curve and BRC-42 key derivation tests |
| `integration_tests.rs` | Full workflow tests across all modules |
| `overlay_cross_sdk_tests.rs` | Overlay cross-SDK admin token and type tests (13 tests) |
| `overlay_integration_tests.rs` | Overlay module integration tests (60 tests) |
| `script_vectors_tests.rs` | Script interpreter tests with ~1,660 vectors |
| `sighash_tests.rs` | Transaction sighash computation with 499 vectors |
| `template_tests.rs` | Script template tests (P2PKH, RPuzzle) |
| `transaction_tests.rs` | Transaction module tests (BEEF, MerklePath, fee models) |
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

BIP-39 mnemonic phrase tests using official TREZOR vectors (requires `compat` feature):

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

### DRBG Tests (`drbg_tests.rs`)

HMAC-DRBG (Deterministic Random Bit Generator) tests using NIST SP 800-90A vectors:

**NIST Vector Tests**
- `test_drbg_nist_vectors` - Runs all 15 NIST test vectors with SHA-256

**DRBG Variants**
- `test_drbg_sha512_variant` - Tests SHA-512 HMAC-DRBG produces different output than SHA-256
- `test_drbg_empty_personalization` - Empty personalization string works correctly

**DRBG Operations**
- `test_drbg_reseed_changes_output` - Verifies reseed changes generator state
- `test_drbg_output_length` - Tests various output lengths (1, 16, 32, 64, 128, 256 bytes)
- `test_drbg_determinism` - Verifies same inputs produce same outputs

### EC Module Tests (`ec_tests.rs`)

Focused tests for elliptic curve operations using BRC-42 test vectors:

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

Full workflow tests combining multiple modules (25 tests):

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

Comprehensive script interpreter tests using TypeScript SDK vectors (716 lines):

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

Transaction sighash computation tests (227 lines):

- `test_sighash_vectors` - Runs all 499 sighash test vectors using `compute_sighash` and `parse_transaction`
- `test_sighash_first_vector_detailed` - Detailed debugging output: raw_tx, script, hash_type, parsed inputs/outputs
- `test_parse_all_vectors_transactions` - Verifies all 499 transactions can be parsed from raw hex

### Template Tests (`template_tests.rs`)

Script template integration tests (313 lines):

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

Transaction module tests (1027 lines, requires `transaction` feature flag):

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

**Extended BEEF Tests** (in `beef_extended_tests` submodule, 16 tests)
- Transaction merging: parent/child, two BEEFs, duplicate deduplication, raw tx
- Sorting: `sort_txs` orders by dependency (grandparent → parent → child)
- Serialization: atomic (with target txid), V1/V2 roundtrip, hex/binary roundtrip
- Validation: empty BEEF, txid-only (strict vs lenient), verify_valid result structure
- MerklePaths: multiple bumps at heights 100-1000000

**Cross-SDK Compatibility Tests** (in `cross_sdk_tests` submodule, 10 tests)
- BRC-74 MerklePath: parse, hex roundtrip, compute root for 3 TXIDs
- Single-tx block: root equals coinbase txid
- BRC-62 BEEF: V1/V2 empty serialization, parse from Go SDK, find transactions
- BEEF set: parse multi-tx BEEF, find specific txid, binary roundtrip

**MerklePath Advanced Tests** (in `merkle_path_advanced_tests` submodule, 7 async tests)
- ChainTracker verification: correct root passes, wrong root/height fails
- Utility methods: contains, txids, compute_root(None), binary roundtrip

### Auth Integration Tests (`auth_integration_tests.rs`)

Auth module integration tests (requires `auth` feature):

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
cargo test --test auth_integration_tests --features auth
cargo test --test compat_bip39_tests --features compat
cargo test --test compat_integration_tests --features compat
cargo test --test cross_sdk_tests
cargo test --test drbg_tests
cargo test --test ec_tests
cargo test --test integration_tests
cargo test --test overlay_integration_tests --features overlay
cargo test --test script_vectors_tests
cargo test --test sighash_tests
cargo test --test template_tests
cargo test --test transaction_tests --features transaction

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
- `templates::{P2PKH, RPuzzle, RPuzzleType}` - Script templates
- `ScriptTemplate`, `SignOutputs` - Template trait and sighash selection

**Transaction** (`bsv_sdk::transaction`):
- `Transaction`, `TransactionInput`, `TransactionOutput` - Transaction types
- `MerklePath` - BRC-74 BUMP merkle proof
- `Beef`, `BEEF_V1`, `BEEF_V2` - BRC-62 BEEF container
- `FeeModel`, `SatoshisPerKilobyte`, `FixedFee` - Fee computation
- `Broadcaster`, `BroadcastResponse`, `BroadcastFailure`, `BroadcastStatus` - Broadcast (async)
- `ChainTracker`, `AlwaysValidChainTracker`, `MockChainTracker` - Chain tracking (async)

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

**Script Tests:**
1. Use `SpendParams` struct for Spend constructor
2. Set `source_satoshis: 1` for basic tests (or 0 for legacy sighash)
3. Test both parsing (from_hex) and execution (validate)
4. Script hex roundtrip should be case-insensitive match

**DRBG Tests:**
1. `HmacDrbg::new()` for SHA-256, `new_with_hash(..., true)` for SHA-512
2. Generate multiple times if required by vector specification (e.g., `add.len()` times)
3. Expected output is from the final generate call

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
- **compat tests**: `compat_bip39_tests.rs` (requires `compat` feature)
- **auth tests**: `auth_integration_tests.rs` (requires `auth` feature)
- **overlay tests**: `overlay_integration_tests.rs` (requires `overlay` feature)

The `transaction_tests.rs` file uses nested modules for organization:
- `transaction_tests` - Main test module (gated by `#[cfg(feature = "transaction")]`)
- `beef_extended_tests` - Extended BEEF format tests
- `cross_sdk_tests` - Cross-SDK compatibility using `beef_cross_sdk.rs` vectors
- `merkle_path_advanced_tests` - Advanced MerklePath verification with ChainTracker

## Related Documentation

- `CLAUDE.md` - Root project documentation
- `src/primitives/CLAUDE.md` - Primitives module documentation
- `src/primitives/ec/CLAUDE.md` - Elliptic curve module documentation
- `src/script/CLAUDE.md` - Script module documentation
- `src/transaction/CLAUDE.md` - Transaction module documentation
- `tests/transaction/vectors/CLAUDE.md` - Transaction test vectors documentation
