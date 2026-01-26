# BSV SDK for Rust

The official Rust implementation of the BSV blockchain SDK, providing a complete toolkit for building BSV applications. Feature-complete and production-ready.

[![Crates.io](https://img.shields.io/crates/v/bsv-sdk.svg)](https://crates.io/crates/bsv-sdk)
[![Documentation](https://docs.rs/bsv-sdk/badge.svg)](https://docs.rs/bsv-sdk)
[![License](https://img.shields.io/badge/license-MIT%2FApache--2.0-blue.svg)](LICENSE)

## Features

- **Primitives** - SHA-256, RIPEMD-160, HMAC, PBKDF2, AES-256-GCM, secp256k1, P-256, BigNumber
- **Script** - Full Bitcoin Script interpreter with all BSV opcodes, P2PKH/RPuzzle/PushDrop templates
- **Transaction** - Construction, signing, fee calculation, BEEF/MerklePath SPV proofs
- **Wallet** - BRC-42 key derivation, ProtoWallet, WalletClient with HTTP substrates

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

# With HTTP client (for ARC broadcaster, WhatsOnChain, WalletClient)
bsv-sdk = { version = "0.2", features = ["full", "http"] }

# Just primitives and script (default)
bsv-sdk = "0.2"
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
| `FeeModel`, `SatoshisPerKilobyte` | Fee calculation |
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

## Feature Flags

| Feature | Default | Description |
|---------|---------|-------------|
| `primitives` | Yes | Cryptographic primitives |
| `script` | Yes | Script parsing, execution, templates |
| `transaction` | No | Transaction building, BEEF, fee models |
| `wallet` | No | BRC-42 key derivation, ProtoWallet |
| `full` | No | All of the above |
| `http` | No | HTTP client for ARC, WhatsOnChain, WalletClient |
| `wasm` | No | WebAssembly support |

Features follow a dependency hierarchy: `wallet` → `transaction` → `script` → `primitives`

## Cross-SDK Compatibility

This SDK maintains byte-for-byte compatibility with:
- [BSV TypeScript SDK](https://github.com/bitcoin-sv/ts-sdk)
- [BSV Go SDK](https://github.com/bitcoin-sv/go-sdk)

All implementations share test vectors to ensure cross-platform compatibility:
- 100+ BRC-42 key derivation vectors
- 499 sighash computation vectors
- 570+ script execution vectors
- Transaction serialization vectors
- BEEF/MerklePath encoding vectors

## Development

```bash
# Build with default features
cargo build

# Build with all features
cargo build --features full

# Run all tests
cargo test --features full

# Run tests for specific module
cargo test primitives
cargo test script --features script
cargo test transaction --features transaction
cargo test wallet --features wallet

# Run benchmarks
cargo bench

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

## License

Licensed under either of:
- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE) or http://www.apache.org/licenses/LICENSE-2.0)
- MIT license ([LICENSE-MIT](LICENSE-MIT) or http://opensource.org/licenses/MIT)

at your option.

## Contributing

Contributions are welcome. Please ensure that:
1. All tests pass (`cargo test --features full`)
2. Code is formatted (`cargo fmt`)
3. No clippy warnings (`cargo clippy --all-targets --all-features`)
4. New functionality includes appropriate tests
