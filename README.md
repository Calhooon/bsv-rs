# BSV SDK for Rust

The official Rust implementation of the BSV blockchain SDK, providing a complete toolkit for building BSV applications. Feature-complete and production-ready, with ~100,000 lines of Rust, 2,500 tests, 2,000+ cross-SDK test vectors, and byte-for-byte compatibility with the [TypeScript](https://github.com/bitcoin-sv/ts-sdk) and [Go](https://github.com/bitcoin-sv/go-sdk) SDKs.

[![Crates.io](https://img.shields.io/crates/v/bsv-sdk.svg)](https://crates.io/crates/bsv-sdk)
[![Documentation](https://docs.rs/bsv-sdk/badge.svg)](https://docs.rs/bsv-sdk)
[![License](https://img.shields.io/badge/license-MIT%2FApache--2.0-blue.svg)](LICENSE)

## Features

**Core Modules**
- **Primitives** - SHA-256, RIPEMD-160, HMAC, PBKDF2, AES-256-GCM, secp256k1, P-256, BigNumber
- **Script** - Full Bitcoin Script interpreter with all BSV opcodes, P2PKH/P2PK/Multisig/RPuzzle/PushDrop templates
- **Transaction** - Construction, signing, fee calculation, BEEF/MerklePath SPV proofs
- **Wallet** - BRC-42 key derivation, ProtoWallet, WalletClient with HTTP substrates

**Communication & Security**
- **Messages** - BRC-77/78 signed and encrypted peer-to-peer messaging
- **Auth** - BRC-31 mutual authentication with certificate-based identity (BRC-52/53)
- **TOTP** - RFC 6238 Time-based One-Time Passwords for two-factor authentication

**Overlay Network**
- **Overlay** - SHIP/SLAP overlay network client for transaction broadcasting and lookup
- **Storage** - UHRP content-addressed file storage via overlay network
- **Registry** - On-chain definition registry for baskets, protocols, and certificates
- **KVStore** - Blockchain-backed key-value storage (local encrypted, global public)
- **Identity** - Certificate-based identity resolution and contact management

**Compatibility**
- **Compat** - BIP-32 HD keys, BIP-39 mnemonics, Bitcoin Signed Messages, ECIES encryption

## Installation

Add to your `Cargo.toml`:

```toml
[dependencies]
bsv-sdk = "0.2"
```

Or with specific features:

```toml
[dependencies]
# All modules
bsv-sdk = { version = "0.2", features = ["full"] }

# With HTTP client (for ARC broadcaster, WhatsOnChain, WalletClient, storage)
bsv-sdk = { version = "0.2", features = ["full", "http"] }

# Just primitives and script (default)
bsv-sdk = "0.2"

# Common combinations
bsv-sdk = { version = "0.2", features = ["wallet"] }           # Keys, transactions, signing
bsv-sdk = { version = "0.2", features = ["auth", "http"] }     # Authentication with HTTP transport
bsv-sdk = { version = "0.2", features = ["overlay", "http"] }  # Overlay network operations
bsv-sdk = { version = "0.2", features = ["compat"] }           # BIP-32/39, BSM, ECIES
bsv-sdk = { version = "0.2", features = ["websocket"] }        # Auth with WebSocket transport
```

## Quick Start

### Key Generation and Signing

```rust
use bsv_sdk::{PrivateKey, PublicKey, sha256};

// Generate a key pair
let private_key = PrivateKey::random();
let public_key = private_key.public_key();

// Get the address
let address = public_key.to_address();
println!("Address: {}", address);

// Sign a message
let msg_hash = sha256(b"Hello, BSV!");
let signature = private_key.sign(&msg_hash).unwrap();

// Verify
assert!(public_key.verify(&msg_hash, &signature));
```

### Working with Scripts

```rust
use bsv_sdk::script::{Script, LockingScript, op};
use bsv_sdk::script::templates::P2PKH;

// Create a P2PKH locking script from an address
let locking = P2PKH::lock_from_address("1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2").unwrap();

// Or build a script programmatically
let mut script = Script::new();
script
    .write_opcode(op::OP_DUP)
    .write_opcode(op::OP_HASH160)
    .write_bin(&pubkey_hash)
    .write_opcode(op::OP_EQUALVERIFY)
    .write_opcode(op::OP_CHECKSIG);

// Parse from hex or ASM
let script = Script::from_hex("76a914...88ac").unwrap();
let script = Script::from_asm("OP_DUP OP_HASH160 <20-bytes> OP_EQUALVERIFY OP_CHECKSIG").unwrap();

// Script type detection
if script.is_p2pkh() {
    let hash = script.extract_pubkey_hash();
}
```

### Building Transactions

```rust
use bsv_sdk::transaction::{Transaction, TransactionInput, TransactionOutput, ChangeDistribution};
use bsv_sdk::script::LockingScript;

// Create a new transaction
let mut tx = Transaction::new();

// Add an input (with full source transaction for signing)
tx.add_input(TransactionInput::with_source_transaction(source_tx, 0)).unwrap();

// Add outputs
tx.add_output(TransactionOutput::new(
    100_000,
    LockingScript::from_hex("76a914...88ac").unwrap(),
)).unwrap();

// Add a change output (amount computed during fee calculation)
tx.add_p2pkh_output("1MyChangeAddress...", None).unwrap();

// Compute fees and sign
tx.fee(None, ChangeDistribution::Equal).await.unwrap();
tx.sign().await.unwrap();

// Serialize
let hex = tx.to_hex();
let txid = tx.id();
```

### BRC-42 Key Derivation

```rust
use bsv_sdk::wallet::{KeyDeriver, Protocol, SecurityLevel, Counterparty};
use bsv_sdk::PrivateKey;

// Create key derivers for Alice and Bob
let alice = KeyDeriver::new(Some(PrivateKey::random()));
let bob = KeyDeriver::new(Some(PrivateKey::random()));

// Define a protocol
let protocol = Protocol::new(SecurityLevel::App, "payment system");
let key_id = "invoice-12345";

// Bob derives a key for communication with Alice
let alice_counterparty = Counterparty::Other(alice.identity_key());
let bob_private = bob.derive_private_key(&protocol, key_id, &alice_counterparty).unwrap();

// Alice can derive the corresponding public key
let bob_counterparty = Counterparty::Other(bob.identity_key());
let bob_public = alice.derive_public_key(&protocol, key_id, &bob_counterparty, false).unwrap();

// They match
assert_eq!(bob_private.public_key().to_compressed(), bob_public.to_compressed());
```

### ProtoWallet Operations

```rust
use bsv_sdk::wallet::{ProtoWallet, Protocol, SecurityLevel, CreateSignatureArgs, EncryptArgs, Counterparty};
use bsv_sdk::PrivateKey;

let alice = ProtoWallet::new(Some(PrivateKey::random()));
let bob = ProtoWallet::new(Some(PrivateKey::random()));
let protocol = Protocol::new(SecurityLevel::App, "secure messaging");

// Sign data
let signed = alice.create_signature(CreateSignatureArgs {
    data: Some(b"Hello, BSV!".to_vec()),
    hash_to_directly_sign: None,
    protocol_id: protocol.clone(),
    key_id: "sig-1".to_string(),
    counterparty: None,
}).unwrap();

// Encrypt for Bob
let encrypted = alice.encrypt(EncryptArgs {
    plaintext: b"Secret message".to_vec(),
    protocol_id: protocol.clone(),
    key_id: "msg-1".to_string(),
    counterparty: Some(Counterparty::Other(bob.identity_key())),
}).unwrap();

// Bob decrypts
let decrypted = bob.decrypt(DecryptArgs {
    ciphertext: encrypted.ciphertext,
    protocol_id: protocol,
    key_id: "msg-1".to_string(),
    counterparty: Some(Counterparty::Other(alice.identity_key())),
}).unwrap();
```

### BRC-77/78 Messages (Signed & Encrypted)

```rust
use bsv_sdk::primitives::PrivateKey;
use bsv_sdk::messages::{sign, verify, encrypt, decrypt};

let sender = PrivateKey::random();
let recipient = PrivateKey::random();

// Sign for specific recipient (only they can verify)
let signature = sign(b"Hello!", &sender, Some(&recipient.public_key())).unwrap();
let valid = verify(b"Hello!", &signature, Some(&recipient)).unwrap();

// Sign for anyone to verify
let signature = sign(b"Public announcement", &sender, None).unwrap();
let valid = verify(b"Public announcement", &signature, None).unwrap();

// Encrypt and decrypt
let ciphertext = encrypt(b"Secret", &sender, &recipient.public_key()).unwrap();
let plaintext = decrypt(&ciphertext, &recipient).unwrap();
```

### BIP-32/39 HD Keys and Mnemonics

```rust
use bsv_sdk::compat::bip32::{ExtendedKey, Network, generate_hd_key_from_mnemonic};
use bsv_sdk::compat::bip39::{Mnemonic, WordCount};

// Generate a new mnemonic
let mnemonic = Mnemonic::new(WordCount::Words12).unwrap();
println!("Mnemonic: {}", mnemonic.phrase());

// Create HD key from mnemonic
let master = generate_hd_key_from_mnemonic(&mnemonic, "", Network::Mainnet).unwrap();

// Derive using BIP-44 path
let derived = master.derive_path("m/44'/0'/0'/0/0").unwrap();
let address = derived.address(true).unwrap();

// Parse existing extended key
let xprv = ExtendedKey::from_string("xprv9s21ZrQH143K...").unwrap();
let xpub = xprv.neuter().unwrap();
```

### TOTP Two-Factor Authentication

```rust
use bsv_sdk::totp::{Totp, TotpOptions, TotpValidateOptions, Algorithm};

// Shared secret (typically from base32-decoded QR code)
let secret = b"12345678901234567890";

// Generate a 6-digit code
let code = Totp::generate(secret, None);

// Validate with 1-period skew (handles clock drift)
assert!(Totp::validate(secret, &code, None));

// Use SHA-256 with 8 digits
let options = TotpOptions {
    digits: 8,
    algorithm: Algorithm::Sha256,
    ..Default::default()
};
let code = Totp::generate(secret, Some(options));
```

### Overlay Network Lookup and Broadcast

```rust
use bsv_sdk::overlay::{LookupResolver, LookupQuestion, TopicBroadcaster, TopicBroadcasterConfig};

// Query a lookup service
let resolver = LookupResolver::default();
let question = LookupQuestion::new("ls_myservice", serde_json::json!({"key": "value"}));
let answer = resolver.query(&question, Some(5000)).await?;

// Broadcast to overlay topics
let broadcaster = TopicBroadcaster::new(
    vec!["tm_mytopic".to_string()],
    TopicBroadcasterConfig::default(),
)?;
let result = broadcaster.broadcast_tx(&tx).await;
```

### UHRP File Storage

```rust
use bsv_sdk::storage::{StorageDownloader, get_url_for_file, get_hash_from_url};

// Generate UHRP URL from file content
let url = get_url_for_file(b"Hello, World!").unwrap();

// Download file from UHRP URL (requires http feature)
let downloader = StorageDownloader::default();
let result = downloader.download(&url).await?;
println!("Downloaded {} bytes", result.data.len());

// Parse hash from URL
let hash: [u8; 32] = get_hash_from_url(&url).unwrap();
```

### Key-Value Storage

```rust
use bsv_sdk::kvstore::{LocalKVStore, KVStoreConfig};
use bsv_sdk::wallet::ProtoWallet;

let wallet = ProtoWallet::new(Some(PrivateKey::random()));
let config = KVStoreConfig::new().with_protocol_id("my-app");
let store = LocalKVStore::new(wallet, config)?;

// Set and get values (encrypted by default)
store.set("user:name", "Alice", None).await?;
let name = store.get("user:name", "Unknown").await?;

// List all keys
let keys = store.keys().await?;
```

### Identity Resolution

```rust
use bsv_sdk::identity::{IdentityClient, IdentityClientConfig, IdentityQuery};

let client = IdentityClient::new(wallet, IdentityClientConfig::default());

// Resolve identity by public key
let identity = client.resolve_by_identity_key("02abc123...", true).await?;

// Discover certificates for an identity
let certs = client.discover_certificates("02abc123...").await?;

// Query by attribute (email, phone, etc.)
let results = client.resolve_by_attributes(
    [("email".to_string(), "user@example.com".to_string())].into(),
    true
).await?;
```

### Broadcasting Transactions

```rust
use bsv_sdk::transaction::{ArcBroadcaster, Broadcaster};

let broadcaster = ArcBroadcaster::new("https://arc.taal.com", Some(api_key));

match broadcaster.broadcast(&tx).await {
    Ok(response) => println!("Broadcast success: {}", response.txid),
    Err(failure) => println!("Broadcast failed: {}", failure.description),
}
```

### SPV Verification with BEEF

```rust
use bsv_sdk::transaction::{Beef, WhatsOnChainTracker, ChainTracker};

// Parse BEEF data
let beef = Beef::from_hex("0100beef...")?;

// Validate structure and get merkle roots
let validation = beef.verify_valid(false);
if validation.valid {
    // Verify roots against chain
    let tracker = WhatsOnChainTracker::mainnet();
    for (height, root) in validation.roots {
        let valid = tracker.is_valid_root_for_height(&root, height).await?;
    }
}
```

## Module Overview

### Primitives (`bsv_sdk::primitives`)

| Component | Description |
|-----------|-------------|
| `sha256`, `sha512`, `ripemd160`, `sha1` | Hash functions |
| `sha256d`, `hash160` | Bitcoin double-SHA256 and RIPEMD160(SHA256) |
| `sha256_hmac`, `sha512_hmac` | HMAC message authentication |
| `pbkdf2_sha512` | Password-based key derivation |
| `PrivateKey`, `PublicKey`, `Signature` | secp256k1 key pairs and ECDSA signatures |
| `P256PrivateKey`, `P256PublicKey`, `P256Signature` | P-256 (secp256r1) curve operations |
| `SymmetricKey` | AES-256-GCM authenticated encryption |
| `BigNumber` | Arbitrary-precision integers |
| `HmacDrbg` | Deterministic random bit generator (RFC 6979) |
| `Reader`, `Writer` | Binary serialization with Bitcoin varint support |
| `to_hex`, `from_hex` | Hexadecimal encoding |
| `to_base58`, `from_base58` | Base58 encoding (Bitcoin alphabet) |
| `to_base58_check`, `from_base58_check` | Base58Check with checksums |
| `to_base64`, `from_base64` | Base64 encoding |

### Script (`bsv_sdk::script`)

| Component | Description |
|-----------|-------------|
| `Script` | Core script type with parsing, serialization, builder methods |
| `LockingScript` | Output scripts (scriptPubKey) |
| `UnlockingScript` | Input scripts (scriptSig) |
| `ScriptChunk` | Individual opcode or data push |
| `Spend` | Full script interpreter/validator |
| `P2PKH` | Pay-to-Public-Key-Hash template |
| `P2PK` | Pay-to-Public-Key template |
| `Multisig` | M-of-N multisignature template (up to 16-of-16) |
| `RPuzzle` | R-puzzle template for knowledge-based locking |
| `PushDrop` | Data envelope template with P2PK lock |

### Transaction (`bsv_sdk::transaction`)

| Component | Description |
|-----------|-------------|
| `Transaction` | Transaction with inputs, outputs, signing, serialization |
| `TransactionInput` | Input referencing a previous output |
| `TransactionOutput` | Output with satoshis and locking script |
| `MerklePath` | BRC-74 BUMP merkle proofs |
| `Beef` | BRC-62/95/96 SPV proof container |
| `FeeModel`, `SatoshisPerKilobyte`, `LivePolicy` | Fee calculation (static and dynamic) |
| `Broadcaster`, `ArcBroadcaster` | Transaction broadcasting |
| `ChainTracker`, `WhatsOnChainTracker` | SPV chain verification |

### Wallet (`bsv_sdk::wallet`)

| Component | Description |
|-----------|-------------|
| `KeyDeriver` | BRC-42 key derivation |
| `CachedKeyDeriver` | LRU-cached key deriver for performance |
| `ProtoWallet` | Cryptographic operations (sign, encrypt, HMAC) |
| `WalletClient` | HTTP client for remote wallet communication |
| `Protocol` | BRC-43 protocol identifier |
| `SecurityLevel` | Key derivation security levels (0, 1, 2) |
| `Counterparty` | Key derivation counterparty specification |

### Messages (`bsv_sdk::messages`)

| Component | Description |
|-----------|-------------|
| `sign` | BRC-77 message signing for specific recipient or anyone |
| `verify` | BRC-77 signature verification |
| `encrypt` | BRC-78 message encryption using ECDH + AES-256-GCM |
| `decrypt` | BRC-78 message decryption |

### Compat (`bsv_sdk::compat`)

| Component | Description |
|-----------|-------------|
| `Mnemonic`, `Language`, `WordCount` | BIP-39 mnemonic phrase generation and seed derivation |
| `ExtendedKey`, `Network` | BIP-32 hierarchical deterministic key derivation |
| `sign_message`, `verify_message`, `verify_message_der` | Bitcoin Signed Message (BSM) format (compact and DER) |
| `electrum_encrypt`, `electrum_decrypt` | Electrum ECIES encryption |
| `bitcore_encrypt`, `bitcore_decrypt` | Bitcore ECIES encryption |

### TOTP (`bsv_sdk::totp`)

| Component | Description |
|-----------|-------------|
| `Totp` | RFC 6238 TOTP generator and validator |
| `TotpOptions` | Configuration for digits, algorithm, period |
| `TotpValidateOptions` | Validation with clock drift skew tolerance |
| `Algorithm` | HMAC algorithm selection (SHA-1, SHA-256, SHA-512) |

### Auth (`bsv_sdk::auth`)

| Component | Description |
|-----------|-------------|
| `Peer` | BRC-31 mutual authentication handler |
| `PeerSession` | Session state between authenticated peers |
| `SessionManager` | Concurrent session management with dual indexing |
| `Certificate` | BRC-52 base certificate with signing/verification |
| `MasterCertificate` | Certificate with master keyring for issuance |
| `VerifiableCertificate` | Certificate with verifier-specific keyring |
| `Transport`, `SimplifiedFetchTransport` | BRC-104 HTTP transport layer |
| `WebSocketTransport` | WebSocket transport (requires `websocket` feature) |
| `RequestedCertificateSet` | Certificate request specification |
| `validate_certificate_encoding` | Certificate field validation |
| `validate_requested_certificate_set` | Certificate request set validation |

### Overlay (`bsv_sdk::overlay`)

| Component | Description |
|-----------|-------------|
| `LookupResolver` | SLAP query resolution with host discovery and caching |
| `TopicBroadcaster` | SHIP topic broadcasting with acknowledgment requirements |
| `LookupQuestion`, `LookupAnswer` | Lookup service query and response types |
| `TaggedBEEF`, `Steak` | Transaction broadcast containers and acknowledgments |
| `HostReputationTracker` | Host performance tracking with exponential backoff |
| `Historian`, `SyncHistorian` | Transaction ancestry traversal |
| `NetworkPreset` | Mainnet/Testnet/Local network configuration |

### Storage (`bsv_sdk::storage`)

| Component | Description |
|-----------|-------------|
| `StorageDownloader` | Download files from UHRP URLs via overlay lookup |
| `StorageUploader` | Upload files with retention period management |
| `get_url_for_file`, `get_url_for_hash` | Generate UHRP URLs from content |
| `get_hash_from_url` | Extract SHA-256 hash from UHRP URL |
| `is_valid_url`, `normalize_url` | URL validation and normalization |
| `UploadableFile`, `DownloadResult` | File transfer types |

### Registry (`bsv_sdk::registry`)

| Component | Description |
|-----------|-------------|
| `RegistryClient` | On-chain definition registration and resolution |
| `BasketDefinitionData` | Output basket definition |
| `ProtocolDefinitionData` | Wallet protocol definition |
| `CertificateDefinitionData` | Certificate type definition with field schema |
| `RegistryRecord` | Combined definition and on-chain token reference |
| `DefinitionType` | Basket, Protocol, or Certificate enum |

### KVStore (`bsv_sdk::kvstore`)

| Component | Description |
|-----------|-------------|
| `LocalKVStore` | Private encrypted key-value store using wallet baskets |
| `GlobalKVStore` | Public key-value store via overlay network |
| `KVStoreConfig` | Store configuration (protocol ID, encryption, topics) |
| `KVStoreEntry`, `KVStoreQuery` | Entry and query types |
| `KVStoreInterpreter` | PushDrop token interpreter |

### Identity (`bsv_sdk::identity`)

| Component | Description |
|-----------|-------------|
| `IdentityClient` | Identity resolution, revelation, and certificate discovery |
| `ContactsManager` | Encrypted contact storage with caching and search |
| `DisplayableIdentity` | User-friendly identity for UI display |
| `Contact` | Stored contact with metadata and tags |
| `KnownCertificateType` | 9 known certificate types (IdentiCert, XCert, EmailCert, etc.) |
| `IdentityQuery` | Query builder for identity resolution |

## Feature Flags

| Feature | Default | Description |
|---------|---------|-------------|
| `primitives` | Yes | Cryptographic primitives (hash, EC, encoding, AES-256-GCM) |
| `script` | Yes | Script parsing, execution, templates (P2PKH, P2PK, Multisig, RPuzzle, PushDrop) |
| `transaction` | No | Transaction building, signing, BEEF/MerklePath, fee models |
| `wallet` | No | BRC-42 key derivation, ProtoWallet, WalletClient |
| `messages` | No | BRC-77/78 signed and encrypted messaging |
| `compat` | No | BIP-32/39, Bitcoin Signed Messages, ECIES encryption |
| `totp` | No | RFC 6238 Time-based One-Time Passwords |
| `auth` | No | BRC-31 mutual authentication, certificates (BRC-52/53) |
| `overlay` | No | SHIP/SLAP overlay network client |
| `storage` | No | UHRP content-addressed file storage |
| `registry` | No | On-chain definition registry |
| `kvstore` | No | Blockchain-backed key-value storage |
| `identity` | No | Certificate-based identity resolution |
| `full` | No | All modules above |
| `http` | No | HTTP client for network operations |
| `websocket` | No | WebSocket auth transport (tokio-tungstenite) |
| `wasm` | No | WebAssembly support |
| `dhat-profiling` | No | Heap profiling for benchmarks |

### Feature Dependency Hierarchy

```
full
 ├── wallet → transaction → script → primitives
 ├── messages → wallet
 ├── compat → primitives
 ├── totp → primitives
 ├── auth → wallet, messages, tokio
 ├── overlay → wallet, tokio
 ├── storage → overlay
 ├── registry → overlay
 ├── kvstore → overlay
 └── identity → auth, overlay

websocket (opt-in, not in full)
 └── auth + tokio-tungstenite + futures-util
```

## Cross-SDK Compatibility

This SDK maintains byte-for-byte compatibility with:
- [BSV TypeScript SDK](https://github.com/bitcoin-sv/ts-sdk)
- [BSV Go SDK](https://github.com/bitcoin-sv/go-sdk)

All implementations share test vectors to ensure cross-platform compatibility:

| Category | Test Count | Description |
|----------|------------|-------------|
| Sighash Computation | 500 | Transaction signature hash vectors |
| Script Execution | 1,488 | Valid scripts (598), invalid scripts (432), spend vectors (458) |
| BRC-42 Key Derivation | 10 | Private and public key derivation vectors |
| HMAC-DRBG | 15 | NIST SP 800-90A vectors |
| Symmetric Encryption | 5 | AES-256-GCM vectors |
| Auth Certificates | 4 | Certificate serialization vectors |
| Overlay Types | 22 | Admin tokens (4) + type serialization (18) |
| Wire Protocol | 90 | All 28 WalletInterface method roundtrips |
| Transaction/BEEF | 87 | Parsing, serialization, ancestry, cross-SDK BEEF |
| GlobalKVStore | 85 | CRUD, batch, PushDrop interpreter, signatures |
| LocalKVStore | 83 | Config, entries, queries, batch operations |
| Storage/UHRP | 70 | URL encoding, upload/download, cross-SDK |
| Identity | 69 | Certificate handling, contact management |
| Compat (BIP-32/39/BSM/ECIES) | 60 | Official TREZOR vectors, HD wallets, BSM, ECIES |
| Overlay | 75 | SHIP/SLAP, admin tokens, reputation, historian |
| Wallet | 56 | KeyDeriver, CachedKeyDeriver, ProtoWallet |
| Registry | 50 | Definitions, PushDrop roundtrips, cross-SDK |
| Auth + Peer E2E | 58 | Sessions, certificates, mutual auth handshake |
| Messages (BRC-77/78) | 33 | Sign/verify, encrypt/decrypt, cross-SDK vectors |

**Total: 2,500 tests (1,307 unit + 909 integration + 284 doc tests) across 29 test files + 2,044 cross-SDK vectors + 4 fuzz targets + 4 benchmark suites**

## Development

```bash
# Build with default features
cargo build

# Build with all features
cargo build --features full

# Run all tests
cargo test --features full

# Run all tests including HTTP mock tests
cargo test --features "full,http"

# Run all tests including WebSocket transport
cargo test --features "full,websocket"

# Run tests for specific module
cargo test --features wallet --test wallet_tests
cargo test --features wallet --test wire_method_roundtrip_tests
cargo test --features auth --test auth_peer_e2e_tests
cargo test --features "overlay,http" --test overlay_http_tests
cargo test --features "storage,http" --test storage_http_tests
cargo test --features kvstore --test kvstore_global_tests
cargo test --features "transaction,http" --test live_policy_http_tests

# Run benchmarks
cargo bench

# Run fuzz targets (requires cargo-fuzz)
cargo fuzz run fuzz_script_parser
cargo fuzz run fuzz_transaction_parser
cargo fuzz run fuzz_wire_protocol
cargo fuzz run fuzz_base58

# Lint
cargo clippy --all-targets --all-features

# Format
cargo fmt

# Generate documentation
cargo doc --open --features full
```

### Building for WebAssembly

```bash
cargo build --target wasm32-unknown-unknown --features wasm
```

## BRC Standards Implemented

| BRC | Name | Module |
|-----|------|--------|
| BRC-42 | Key derivation from master key | `wallet` |
| BRC-43 | Security levels and protocol ID | `wallet` |
| BRC-52 | Identity certificates | `auth` |
| BRC-53 | Certificate field encryption | `auth` |
| BRC-31 | Authrite mutual authentication | `auth` |
| BRC-62 | BEEF format | `transaction` |
| BRC-74 | BUMP merkle proofs | `transaction` |
| BRC-77 | Signed messages | `messages` |
| BRC-78 | Encrypted messages | `messages` |
| BRC-95/96 | Extended BEEF | `transaction` |
| BRC-104 | HTTP transport | `auth` |
| SHIP | Submit Hierarchical Information Protocol | `overlay` |
| SLAP | Service Lookup Availability Protocol | `overlay` |
| STEAK | Serialized Transaction Envelopes with Acknowledgments | `overlay` |
| UHRP | Universal Hash Resolution Protocol | `storage` |

## License

Licensed under either of:
- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE) or http://www.apache.org/licenses/LICENSE-2.0)
- MIT license ([LICENSE-MIT](LICENSE-MIT) or http://opensource.org/licenses/MIT)

at your option.

## Architecture

The SDK is organized into feature-gated modules with clear dependency boundaries:

```
┌─────────────────────────────────────────────────────────────────┐
│                         identity                                 │
│                    (certificate-based ID)                        │
└─────────────────────────────────────────────────────────────────┘
                              │
          ┌───────────────────┴───────────────────┐
          ▼                                       ▼
┌─────────────────┐   ┌─────────────────┐   ┌─────────────────┐
│      auth       │   │    registry     │   │     kvstore     │
│   (BRC-31/52)   │   │ (definitions)   │   │  (key-value)    │
└─────────────────┘   └─────────────────┘   └─────────────────┘
          │                   │                     │
          └───────────────────┼─────────────────────┘
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│                         overlay                                  │
│                    (SHIP/SLAP network)                           │
└─────────────────────────────────────────────────────────────────┘
                              │
          ┌───────────────────┴───────────────────┐
          ▼                                       ▼
┌─────────────────┐                     ┌─────────────────┐
│    messages     │                     │     storage     │
│  (BRC-77/78)    │                     │     (UHRP)      │
└─────────────────┘                     └─────────────────┘
          │
          ▼
┌─────────────────────────────────────────────────────────────────┐
│                         wallet                                   │
│              (BRC-42 keys, ProtoWallet, WalletClient)            │
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│                       transaction                                │
│              (TX building, signing, BEEF, SPV)                   │
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│                         script                                   │
│              (interpreter, templates, opcodes)                   │
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│                       primitives                                 │
│        (hash, EC, encoding, AES-GCM, BigNumber, DRBG)           │
└─────────────────────────────────────────────────────────────────┘

Independent modules (depend only on primitives):
┌─────────────────┐   ┌─────────────────┐
│     compat      │   │      totp       │
│ (BIP-32/39/BSM) │   │   (RFC 6238)    │
└─────────────────┘   └─────────────────┘

Optional transports (opt-in feature flags):
┌─────────────────┐   ┌─────────────────┐
│   websocket     │   │      http       │
│ (WS transport)  │   │ (ARC, WoC, etc) │
└─────────────────┘   └─────────────────┘
```

## Contributing

Contributions are welcome. Please ensure that:
1. All tests pass (`cargo test --features "full,http,websocket"`)
2. Code is formatted (`cargo fmt`)
3. No clippy warnings (`cargo clippy --all-targets --all-features`)
4. New functionality includes appropriate tests
5. Cross-SDK compatibility is maintained where applicable
6. HTTP-dependent tests use `wiremock` for mock servers
