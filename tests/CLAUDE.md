# Integration Tests
> Cross-module and cross-SDK compatibility testing

## Overview

This directory contains integration tests that verify the BSV Rust SDK works correctly across modules and produces results identical to the TypeScript and Go SDK implementations. Tests use shared JSON test vectors to ensure byte-for-byte compatibility across all three SDK implementations.

**Total: ~1,054 test functions across 29 test files + ~2,632 test vectors**

## Files

| File | Tests | Feature Gate | Description |
|------|------:|-------------|-------------|
| `auth_cross_sdk_tests.rs` | 13 | `auth` | Certificate serialization cross-SDK vectors |
| `auth_integration_tests.rs` | 26 | `auth` | Session manager, AuthMessage, certificates, HTTP payloads |
| `auth_peer_e2e_tests.rs` | 19 | `auth` | BRC-31 peer mutual authentication end-to-end via loopback |
| `broadcaster_http_tests.rs` | 26 | `transaction`+`http` | ARC, WoC, Teranode broadcasters with wiremock |
| `chaintracker_http_tests.rs` | 10 | `transaction`+`http` | WhatsOnChain chain tracker with wiremock |
| `compat_bip39_tests.rs` | 29 | `compat` | BIP-39 mnemonics with official TREZOR vectors |
| `compat_integration_tests.rs` | 31 | `compat` | BIP-32/39, BSM, ECIES, Base58 workflows |
| `cross_sdk_tests.rs` | 17 | default | BRC-42, symmetric encryption, WIF/address vectors |
| `drbg_tests.rs` | 6 | default | HMAC-DRBG with NIST SP 800-90A vectors |
| `ec_tests.rs` | 10 | default | Elliptic curve ops, BRC-42 derivation, ECDH |
| `identity_tests.rs` | 69 | `identity` | Certificates, contacts, queries, broadcast results |
| `integration_tests.rs` | 22 | default | Full workflows: key derivation, Schnorr, Shamir, P-256 |
| `kvstore_global_tests.rs` | 85 | `kvstore` | GlobalKVStore: construction, CRUD, batch, interpreter |
| `kvstore_integration_tests.rs` | 83 | `kvstore` | LocalKVStore: config, entries, queries, batch ops |
| `live_policy_http_tests.rs` | 20 | `transaction`+`http` | LivePolicy dynamic fee model with wiremock |
| `memory_profiling.rs` | 5 | `dhat-profiling` | Heap allocation profiling for crypto operations |
| `messages_tests.rs` | 33 | `messages` | BRC-77 signing, BRC-78 encryption, cross-SDK vectors |
| `overlay_cross_sdk_tests.rs` | 13 | `overlay` | Admin token and overlay type cross-SDK vectors |
| `overlay_http_tests.rs` | 49 | `overlay`+`http` | SHIP broadcast and SLAP lookup facilitators with wiremock |
| `overlay_integration_tests.rs` | 60 | `overlay` | Protocols, topics, reputation, historian, admin tokens |
| `registry_integration_tests.rs` | 50 | `registry` | Definitions, queries, PushDrop roundtrips, cross-SDK |
| `script_vectors_tests.rs` | 13 | default | Script interpreter with ~1,660 vectors |
| `sighash_tests.rs` | 3 | default | Transaction sighash computation with 499 vectors |
| `storage_http_tests.rs` | 35 | `storage`+`http` | Uploader/downloader HTTP flows with wiremock |
| `storage_tests.rs` | 70 | `storage` | UHRP URLs, downloader/uploader config, cross-SDK |
| `template_tests.rs` | 22 | default | P2PKH, P2PK, Multisig, RPuzzle script templates |
| `transaction_tests.rs` | 86 | `transaction` | BEEF, MerklePath, fee models, construction, ancestry |
| `wallet_tests.rs` | 56 | `wallet` | KeyDeriver, CachedKeyDeriver, ProtoWallet, wire protocol |
| `wire_method_roundtrip_tests.rs` | 90 | `wallet` | Wire protocol roundtrips for all 28 WalletInterface methods |
| `transaction/` | — | — | Transaction test vector constants module |

## Test Vectors

Test vectors in `tests/vectors/` are shared with the TypeScript and Go SDKs:

| Vector File | Contents |
|-------------|----------|
| `auth_certificate.json` | Auth certificate serialization vectors (4 vectors) |
| `brc42_private.json` | BRC-42 private key derivation vectors |
| `brc42_public.json` | BRC-42 public key derivation vectors |
| `symmetric_key.json` | Symmetric encryption test vectors |
| `overlay_admin_token.json` | Overlay SHIP/SLAP admin token vectors (4 vectors) |
| `overlay_types.json` | Overlay type serialization vectors |
| `drbg.json` | HMAC-DRBG vectors (15 vectors for RFC 6979) |
| `sighash.json` | Transaction sighash vectors (499 vectors) |
| `spend_valid.json` | Valid spend execution vectors (~570+ vectors) |
| `script_valid.json` | Valid script parsing vectors (~590+ vectors) |
| `script_invalid.json` | Invalid scripts that should fail (~500+ vectors) |

Transaction test vectors in `tests/transaction/vectors/`:

| File | Contents |
|------|----------|
| `tx_valid.rs` | Valid transaction hex strings for roundtrip testing |
| `tx_invalid.rs` | Invalid transaction vectors (semantically invalid) |
| `bump_valid.rs` | Valid BRC-74 BUMP (MerklePath) hex vectors |
| `bump_invalid.rs` | Invalid BUMP vectors with expected error messages |
| `bigtx.rs` | Large transaction test vectors |
| `beef_cross_sdk.rs` | BEEF (BRC-62) and MerklePath vectors from TypeScript/Go SDKs |

## Test Categories by Module

### Primitives (default features)
- **`cross_sdk_tests.rs`** — BRC-42 key derivation, symmetric encryption, WIF/address vectors, DRBG verification, edge cases (unicode, empty, large messages)
- **`drbg_tests.rs`** — NIST vector tests, SHA-512 variant, reseed, output length, determinism
- **`ec_tests.rs`** — BRC-42 derivation consistency, WIF/pubkey/address known vectors, sign/verify, ECDH
- **`integration_tests.rs`** — Full workflows: key derivation, symmetric encryption, Schnorr proofs, Shamir secret sharing (3-of-5, subset recovery), P-256, hash chains, sighash+signing, complete payment workflow

### Script (default features)
- **`script_vectors_tests.rs`** — ~570 spend valid vectors, ~590 script parsing vectors, ~500 invalid script vectors, individual opcode tests (OP_CAT, OP_SPLIT, OP_MUL, OP_DIV)
- **`sighash_tests.rs`** — 499 sighash vectors with `compute_sighash`, detailed first-vector debugging, transaction parsing verification
- **`template_tests.rs`** — P2PKH (lock/unlock/address/validation), P2PK (compressed detection, length estimate), Multisig (2-of-3, 1-of-1, 3-of-3, 16-of-16, validation errors), RPuzzle (hash types, K value, R computation)

### Transaction (`transaction` feature)
- **`transaction_tests.rs`** — Parsing/roundtrip (86 tests), fee models (Fixed, SatoshisPerKilobyte), MockChainTracker, broadcast, MerklePath/BUMP, BEEF format, ancestry collection (`to_beef`, `to_atomic_beef`), cross-SDK BEEF/MerklePath vectors. Organized into submodules: `beef_extended_tests`, `beef_ancestry_tests`, `cross_sdk_tests`, `merkle_path_advanced_tests`

### Transaction HTTP (`transaction`+`http` features, wiremock)
- **`broadcaster_http_tests.rs`** — ARC (9 tests: success, API key, errors, batch), WoC (9 tests: mainnet/testnet/STN, errors), Teranode (8 tests: EF format, timeout, batch)
- **`chaintracker_http_tests.rs`** — WoC tracker: valid/invalid root, case-insensitive, 404/500, current_height, testnet paths
- **`live_policy_http_tests.rs`** — LivePolicy dynamic fee model: refresh from ARC policy endpoint, error handling (500/404/malformed), fallback rates, cache expiry, sat/byte→sat/KB conversion, API key auth

### Wallet (`wallet` feature)
- **`wallet_tests.rs`** — KeyDeriver (14 tests: derivation, validation, security levels), CachedKeyDeriver (8 tests: LRU eviction, secrets not cached), ProtoWallet (16 tests: encrypt/decrypt, HMAC, signatures, cross-party), cross-SDK BRC-2/BRC-3 compliance (4 tests), wire protocol encoding (14 tests: VarInt, strings, Counterparty, Protocol, Outpoint, maps, enums)
- **`wire_method_roundtrip_tests.rs`** — All 28 WalletInterface methods via loopback transport (90 tests): get_public_key, encrypt/decrypt, HMAC, signatures, key linkage, status (auth/height/network/version), actions (create/sign/abort/list/internalize), outputs (list/relinquish), certificates (acquire/list/prove/relinquish/discover). Also tests complex type roundtrips, response roundtrips, call codes, request frames, and Counterparty variant encoding.

### Messages (`messages` feature)
- **`messages_tests.rs`** — BRC-77 signed messages (8 tests: specific/anyone recipient, empty/large, tampering), BRC-78 encrypted messages (9 tests: roundtrip, wrong key, GCM auth), cross-SDK vectors (8 tests: error format compatibility), unicode/binary data, multi-party

### Compat (`compat` feature)
- **`compat_bip39_tests.rs`** — TREZOR vectors: entropy↔mnemonic (22 vectors), mnemonic→seed, validation (bad sentences, wrong word count, bad checksum), generation (12/15/18/21/24 words), randomized roundtrips (100 iterations per entropy size)
- **`compat_integration_tests.rs`** — BIP-39+BIP-32 HD wallet flows, BSM sign/verify, ECIES (Electrum/Bitcore), Base58, cross-module integration, error handling, type/enum tests

### Auth (`auth` feature)
- **`auth_cross_sdk_tests.rs`** — Certificate binary/JSON roundtrip, deterministic serialization, field sorting, DER signature format, outpoint parsing, cross-SDK binary layout
- **`auth_integration_tests.rs`** — SessionManager lifecycle/pruning, AuthMessage validation/signing, mock transport, HTTP payloads (complex/unicode/100 headers), certificate signing/verification, RequestedCertificateSet, PeerSession states
- **`auth_peer_e2e_tests.rs`** — Full BRC-31 mutual authentication between two Peer instances via channel loopback: handshake, bidirectional messaging, session persistence, explicit `get_authenticated_session()`, listener registration, certificate request/response flow, empty/large (100KB) payloads, nonce uniqueness, error cases (invalid version, no session)

### Overlay (`overlay` feature)
- **`overlay_cross_sdk_tests.rs`** — Admin token creation/decoding/protocol detection, network presets, LookupQuestion/Answer types, AdmittanceInstructions, TaggedBEEF
- **`overlay_integration_tests.rs`** — Protocols, LookupQuestion/Answer, TaggedBEEF, AdmittanceInstructions, TopicBroadcaster validation, RequireAck, LookupResolverConfig, HostReputationTracker (ranking, reset, JSON export/import, global singleton), SyncHistorian (chain traversal, filtering, cycle prevention), admin tokens, HostResponse/ServiceMetadata

### Overlay HTTP (`overlay`+`http` features, wiremock)
- **`overlay_http_tests.rs`** — SHIP broadcast facilitator (25 tests: STEAK response, Content-Type/X-Topics headers, off-chain values, error responses 400/404/500, HTTP security, URL trimming) and SLAP lookup facilitator (24 tests: OutputList/Freeform/Formula answers, binary response format, request format verification, error handling, edge cases)

### Storage (`storage` feature)
- **`storage_tests.rs`** — UHRP URL generation/parsing/validation/normalization, roundtrip (file→URL→hash), StorageDownloader/Uploader config, UploadableFile, cross-SDK hash/file/URL vectors

### Storage HTTP (`storage`+`http` features, wiremock)
- **`storage_http_tests.rs`** — Two-step upload flow (POST /upload → PUT presigned URL), custom retention, required headers, error handling (400/401/413/500), find_file, list_uploads, renew_file, request body verification, MIME type headers, downloader URL validation (invalid/empty/HTTP/bad checksum URLs), timeout config

### Identity (`identity` feature)
- **`identity_tests.rs`** — KnownCertificateType (9 types, cross-SDK type IDs), DisplayableIdentity, Contact CRUD, IdentityQuery builder, ContactsManager async ops (add/update/remove/search/cache), CertifierInfo, BroadcastResult, static avatar URLs, default values, config builders, camelCase JSON compatibility

### KVStore (`kvstore` feature)
- **`kvstore_integration_tests.rs`** — LocalKVStore: config/entry/token/query/options types, KVStoreInterpreter (PushDrop script extraction), signature verification, constructor/get/set/remove/has/keys/list/count/clear operations, batch ops (9 tests), cross-SDK compatibility (field names, PushDrop order), edge cases (unicode, large values)
- **`kvstore_global_tests.rs`** — GlobalKVStore: construction with default/custom config, network presets, input validation (empty key/value), wallet error propagation, overlay error propagation, interpreter tests (19 tests: basic tokens, context filtering, unicode, large values, old/new format), signature verification, data model tests, cross-SDK compatibility, edge cases (special chars, JSON values, multiple tags)

### Registry (`registry` feature)
- **`registry_integration_tests.rs`** — DefinitionType (string conversion, lookup services, topics, baskets, field counts), BasketDefinitionData (builder, PushDrop encode/decode), ProtocolDefinitionData (security levels), CertificateDefinitionData (field descriptors), DefinitionData enum, TokenData, RegistryRecord, query builders, result types, RegistryClientConfig, cross-SDK PushDrop field order, constants

### Profiling (`dhat-profiling` feature)
- **`memory_profiling.rs`** — Heap allocation profiling: AES-GCM (64-16384 bytes), BRC-42/ECDH derivation, Shamir 3-of-5 and 5-of-10, ECDSA sign/verify, SHA-256/Hash160 hashing

## Running Tests

```bash
# All tests with all modules
cargo test --features full

# All tests including HTTP (requires http feature)
cargo test --features "full,http"

# By feature group
cargo test --features transaction          # Transaction, script, primitives
cargo test --features wallet               # Wallet, transaction, script, primitives
cargo test --features messages             # Messages, wallet chain
cargo test --features compat               # BIP-39/32, BSM, ECIES, Base58
cargo test --features auth                 # Auth, messages, wallet chain
cargo test --features overlay              # Overlay, wallet chain
cargo test --features storage              # Storage, overlay chain
cargo test --features registry             # Registry, overlay chain
cargo test --features kvstore              # KVStore, overlay chain
cargo test --features identity             # Identity, auth, overlay chain

# Specific test file
cargo test --test wire_method_roundtrip_tests --features wallet
cargo test --test overlay_http_tests --features "overlay,http"
cargo test --test live_policy_http_tests --features "transaction,http"

# Filter by test name
cargo test --features full -- test_complete_payment_workflow

# Memory profiling (single-threaded, with output)
cargo test --test memory_profiling --features dhat-profiling -- --test-threads=1 --nocapture
```

## Test Organization

Tests are organized by feature area:

| Area | Files |
|------|-------|
| **primitives** | `cross_sdk_tests`, `drbg_tests`, `ec_tests`, `integration_tests` |
| **script** | `script_vectors_tests`, `template_tests` |
| **transaction** | `sighash_tests`, `transaction_tests` |
| **transaction HTTP** | `broadcaster_http_tests`, `chaintracker_http_tests`, `live_policy_http_tests` |
| **wallet** | `wallet_tests`, `wire_method_roundtrip_tests` |
| **messages** | `messages_tests` |
| **compat** | `compat_bip39_tests`, `compat_integration_tests` |
| **auth** | `auth_cross_sdk_tests`, `auth_integration_tests`, `auth_peer_e2e_tests` |
| **overlay** | `overlay_cross_sdk_tests`, `overlay_integration_tests` |
| **overlay HTTP** | `overlay_http_tests` |
| **storage** | `storage_tests` |
| **storage HTTP** | `storage_http_tests` |
| **identity** | `identity_tests` |
| **kvstore** | `kvstore_integration_tests`, `kvstore_global_tests` |
| **registry** | `registry_integration_tests` |
| **profiling** | `memory_profiling` |

Notable multi-module test files use nested submodules:
- `transaction_tests.rs`: `beef_extended_tests`, `beef_ancestry_tests`, `cross_sdk_tests`, `merkle_path_advanced_tests`
- `wallet_tests.rs`: `key_deriver_tests`, `cached_key_deriver_tests`, `proto_wallet_tests`, `cross_sdk_tests`, `wire_protocol_tests`
- `identity_tests.rs`: `contacts_manager_tests`, `identity_client_tests`
- `wire_method_roundtrip_tests.rs`: 15 submodules covering all 28 WalletInterface methods

## Adding New Tests

- **Cross-SDK vectors**: Add JSON to `tests/vectors/`, use `#[serde(rename_all = "camelCase")]`, include vector index in panic messages
- **Feature gates**: Use `#![cfg(feature = "...")]` at file top, or `#![cfg(all(feature = "...", feature = "http"))]` for HTTP tests
- **HTTP tests**: Use `wiremock` crate, create broadcaster/tracker with `::with_base_url(&mock_server.uri(), network)`
- **Wire protocol**: Use loopback pattern with `WalletWireTransceiver` → `WalletWireProcessor` for method roundtrips
- **Auth peer tests**: Use channel-based loopback transport for full BRC-31 handshake testing
- **Async tests**: Use `#[tokio::test]` for anything involving ChainTracker, Broadcaster, Peer, or KVStore operations
- **Test keys**: Follow TypeScript SDK patterns: `PrivateKey(42)`, `PrivateKey(69)` for deterministic test keys
- **Protocol names**: Must be 5+ characters, use `Protocol::new(SecurityLevel::*, "name")`

## Notes on BSV vs BTC Script Vectors

Some `script_valid.json` vectors may fail execution because BSV requires push-only unlocking scripts, minimal push encoding, and has different clean stack requirements. Vectors with `flags.contains("P2SH")` are skipped. The BSV-specific `spend_valid.json` vectors should all pass.

## Related Documentation

- `CLAUDE.md` — Root project documentation
- `src/*/CLAUDE.md` — Per-module documentation (primitives, script, transaction, wallet, messages, compat, totp, auth, overlay, storage, registry, kvstore, identity)
- `tests/transaction/vectors/CLAUDE.md` — Transaction test vectors documentation
