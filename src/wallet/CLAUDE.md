# BSV Wallet Module
> BRC-42 Key Derivation, ProtoWallet, WalletClient, WalletInterface, and Validation for the BSV Rust SDK

## Overview

This module provides the wallet interface, key derivation, and cryptographic operations for interacting with BSV wallets. It implements the BRC-42 key derivation standard and provides types compatible with the TypeScript and Go BSV SDKs.

## Files

| File | Purpose | Lines |
|------|---------|-------|
| `mod.rs` | Module root with feature-gated exports | ~255 |
| `types.rs` | Core wallet type definitions (70+ types) | ~1550 |
| `interface.rs` | WalletInterface trait (28 methods) | ~298 |
| `key_deriver.rs` | BRC-42 key derivation with KeyDeriverApi trait | ~641 |
| `cached_key_deriver.rs` | Thread-safe LRU-cached key deriver | ~491 |
| `proto_wallet.rs` | ProtoWallet + WalletInterface impl | ~1342 |
| `validation.rs` | 40+ input validation helpers | ~1170 |
| `client.rs` | Multi-substrate WalletClient (requires `http` feature) | ~665 |
| `substrates/` | Transport substrate implementations | - |
| `wire/` | Wire protocol encoding/decoding | - |

## Submodules

### substrates/
Transport layer implementations for wallet communication:
- `http_json.rs` - JSON over HTTP substrate
- `http_wire.rs` - Binary wire protocol over HTTP substrate
- See `substrates/CLAUDE.md` for details

### wire/
Wire protocol implementation:
- `encoding.rs` - Binary encoding/decoding
- `calls.rs` - Call frame definitions
- `transceiver.rs` - Protocol transceiver
- `processor.rs` - Request/response processing
- See `wire/CLAUDE.md` for details

## Key Exports

### WalletInterface Trait

The `WalletInterface` trait defines all 28 wallet operations (async with `originator` parameter):

| Category | Methods |
|----------|---------|
| Key (9) | `get_public_key`, `encrypt`, `decrypt`, `create_hmac`, `verify_hmac`, `create_signature`, `verify_signature`, `reveal_counterparty_key_linkage`, `reveal_specific_key_linkage` |
| Action (5) | `create_action`, `sign_action`, `abort_action`, `list_actions`, `internalize_action` |
| Output (2) | `list_outputs`, `relinquish_output` |
| Certificate (4) | `acquire_certificate`, `list_certificates`, `prove_certificate`, `relinquish_certificate` |
| Discovery (2) | `discover_by_identity_key`, `discover_by_attributes` |
| Status (6) | `is_authenticated`, `wait_for_authentication`, `get_height`, `get_header_for_height`, `get_network`, `get_version` |

Marker traits: `CryptoWallet` (crypto-only), `FullWallet` (all methods supported).

### WalletClient (requires `http` feature)

```rust
pub enum SubstrateType {
    Auto,           // Auto-detect (SecureJsonApi -> JsonApi -> Cicada)
    JsonApi,        // HTTP JSON API (port 3321)
    Cicada,         // Wire protocol over HTTP (port 3301)
    SecureJsonApi,  // Secure local JSON API (port 2121)
}

pub struct WalletClient {
    pub fn new(substrate_type: SubstrateType, originator: Option<String>) -> Self
    pub fn substrate_type(&self) -> SubstrateType
    pub fn originator(&self) -> Option<&str>
    // Implements all wallet operations as async methods
}
```

### ProtoWallet

```rust
pub struct ProtoWallet {
    // Construction
    pub fn new(root_key: Option<PrivateKey>) -> Self
    pub fn anyone() -> Self

    // Identity
    pub fn key_deriver(&self) -> &CachedKeyDeriver
    pub fn identity_key(&self) -> PublicKey
    pub fn identity_key_hex(&self) -> String

    // Public Key
    pub fn get_public_key(&self, args: GetPublicKeyArgs) -> Result<GetPublicKeyResult>

    // Encryption (AES-256-GCM)
    pub fn encrypt(&self, args: EncryptArgs) -> Result<EncryptResult>
    pub fn decrypt(&self, args: DecryptArgs) -> Result<DecryptResult>

    // HMAC (SHA-256)
    pub fn create_hmac(&self, args: CreateHmacArgs) -> Result<CreateHmacResult>
    pub fn verify_hmac(&self, args: VerifyHmacArgs) -> Result<VerifyHmacResult>

    // Signatures (ECDSA)
    pub fn create_signature(&self, args: CreateSignatureArgs) -> Result<CreateSignatureResult>
    pub fn verify_signature(&self, args: VerifySignatureArgs) -> Result<VerifySignatureResult>

    // Key Linkage Revelation
    pub fn reveal_counterparty_key_linkage(&self, args: RevealCounterpartyKeyLinkageArgs) -> Result<RevealCounterpartyKeyLinkageResult>
    pub fn reveal_specific_key_linkage(&self, args: RevealSpecificKeyLinkageArgs) -> Result<RevealSpecificKeyLinkageResult>
}

// ProtoWallet implements WalletInterface
impl WalletInterface for ProtoWallet { ... }
```

#### ProtoWallet Capabilities

ProtoWallet can:
- Derive keys using BRC-42 (via internal CachedKeyDeriver)
- Create and verify ECDSA signatures
- Encrypt and decrypt data (AES-256-GCM via derived symmetric keys)
- Create and verify HMACs (SHA-256)
- Reveal key linkages for verification
- Implement all 28 `WalletInterface` methods (unsupported methods return errors)

ProtoWallet does NOT:
- Create transactions (returns error)
- Manage UTXOs (returns error)
- Interact with the blockchain
- Manage certificates (returns error)
- Store any persistent data

#### WalletInterface Implementation

ProtoWallet implements `WalletInterface` with full support for cryptographic operations:
- Key operations: All 8 methods fully implemented
- Action/Output/Certificate/Discovery operations: Return `Error::WalletError` indicating full wallet required
- Chain/Status operations: `is_authenticated` returns true, `get_network` returns mainnet, `get_version` returns SDK version

### Validation Module

The `validation` module provides 40+ validation functions:

| Category | Functions |
|----------|-----------|
| Satoshis | `validate_satoshis` |
| Integers | `validate_integer`, `validate_integer_u32` |
| Strings | `validate_string_length`, `validate_hex_string`, `validate_base64_string`, `is_hex_string` |
| Identifiers | `validate_basket`, `validate_label`, `validate_tag`, `validate_originator` (all normalize to lowercase) |
| Outpoints | `parse_wallet_outpoint`, `validate_outpoint_string` |
| Actions | `validate_create_action_args`, `validate_create_action_input`, `validate_create_action_output`, etc. |
| Certificates | `validate_certificate_fields`, `validate_keyring_revealer` |
| Protocol | `validate_protocol_tuple`, `validate_query_mode` |

### Core Types

**SecurityLevel** - User interaction level for key derivation:
- `Silent` (0): No user interaction
- `App` (1): Approval per application
- `Counterparty` (2): Approval per counterparty per application

**Protocol** - Combines `SecurityLevel` and `protocol_name` (5-400 chars, lowercase, no consecutive spaces).

**Counterparty** - Key derivation target: `Self_`, `Anyone` (publicly derivable), or `Other(PublicKey)`.

### Key Derivation

**KeyDeriver** - BRC-42 key derivation from root private key:
- `derive_public_key()`, `derive_private_key()`, `derive_symmetric_key()`
- `reveal_specific_secret()`, `reveal_counterparty_secret()` for linkage revelation
- `anyone_key()` returns the special "anyone" key pair (scalar value 1)

**CachedKeyDeriver** - Thread-safe LRU-cached wrapper (default 1000 entries).

**KeyDeriverApi** - Trait implemented by both `KeyDeriver` and `CachedKeyDeriver`.

## Usage Examples

### ProtoWallet - Signing

```rust
use bsv_sdk::wallet::{ProtoWallet, Protocol, SecurityLevel, CreateSignatureArgs};
use bsv_sdk::primitives::PrivateKey;

let wallet = ProtoWallet::new(Some(PrivateKey::random()));
let protocol = Protocol::new(SecurityLevel::App, "signing app");

let signed = wallet.create_signature(CreateSignatureArgs {
    data: Some(b"Hello, BSV!".to_vec()),
    hash_to_directly_sign: None,
    protocol_id: protocol,
    key_id: "sig-1".to_string(),
    counterparty: None,
}).unwrap();
```

### Two-Party Encryption

```rust
let alice = ProtoWallet::new(Some(PrivateKey::random()));
let bob = ProtoWallet::new(Some(PrivateKey::random()));
let protocol = Protocol::new(SecurityLevel::App, "secure messaging");

// Alice encrypts for Bob
let encrypted = alice.encrypt(EncryptArgs {
    plaintext: b"Secret message".to_vec(),
    protocol_id: protocol.clone(),
    key_id: "msg-1".to_string(),
    counterparty: Some(Counterparty::Other(bob.identity_key())),
}).unwrap();

// Bob decrypts using Alice as counterparty
let decrypted = bob.decrypt(DecryptArgs {
    ciphertext: encrypted.ciphertext,
    protocol_id: protocol,
    key_id: "msg-1".to_string(),
    counterparty: Some(Counterparty::Other(alice.identity_key())),
}).unwrap();
```

### WalletClient (Remote Wallet)

```rust
let mut client = WalletClient::new(SubstrateType::Auto, Some("myapp.com".into()));
let version = client.get_version().await?;
```

## BRC-42 Key Derivation Algorithm

### Private Key Derivation

1. Compute ECDH shared secret: `shared = other_pubkey * self`
2. Compute HMAC: `hmac = HMAC-SHA256(key=compressed_shared_secret, data=invoice_number)`
3. Derive new key: `new_key = (self + hmac) mod n`

### Public Key Derivation

1. Compute ECDH shared secret: `shared = self * other_privkey`
2. Compute HMAC: `hmac = HMAC-SHA256(key=compressed_shared_secret, data=invoice_number)`
3. Compute offset point: `offset = G * hmac`
4. Derive new key: `new_pubkey = self + offset`

### Invoice Number Format

The invoice number is computed as: `{security_level}-{protocol_name}-{key_id}`

Example: `1-my application-invoice-12345`

## Feature Flags

```toml
[dependencies]
# Basic wallet functionality (key derivation, ProtoWallet, validation)
bsv-sdk = { version = "0.2", features = ["wallet"] }

# With remote wallet communication (WalletClient)
bsv-sdk = { version = "0.2", features = ["wallet", "http"] }
```

## Error Types

| Error | Description |
|-------|-------------|
| `WalletError(String)` | General wallet error (includes validation failures) |
| `KeyDerivationError(String)` | Key derivation failed |
| `ProtocolValidationError(String)` | Invalid protocol name or parameters |
| `InvalidCounterparty(String)` | Invalid counterparty specification |

## Cross-SDK Compatibility

This module maintains API compatibility with:
- [TypeScript SDK](https://github.com/bitcoin-sv/ts-sdk) - `KeyDeriver`, `CachedKeyDeriver`, `ProtoWallet`, `WalletClient`
- [Go SDK](https://github.com/bitcoin-sv/go-sdk) - `KeyDeriver`, `ProtoWallet`

Key derivation uses the same algorithm (BRC-42) and produces identical keys across all SDK implementations.

### Type Mapping

| TypeScript | Rust |
|------------|------|
| `WalletProtocol` (tuple) | `Protocol` (struct) |
| `SecurityLevel` (0\|1\|2) | `SecurityLevel` (enum) |
| `Counterparty` (string\|PublicKey) | `Counterparty` (enum) |
| `KeyDeriverApi` (interface) | `KeyDeriverApi` (trait) |
| `WalletInterface` (interface) | `WalletInterface` (trait) |
| `ProtoWallet` (class) | `ProtoWallet` (struct, implements `WalletInterface`) |
| `Wallet` (class) | `WalletClient` (struct) |
| `validationHelpers.ts` functions | `validation` module functions |

## Dependencies

The wallet module uses:
- `PrivateKey`, `PublicKey`, `SymmetricKey`, `Signature` from primitives
- `sha256`, `sha256_hmac` from hash module
- `derive_child` methods for BRC-42 derivation
- `subtle` crate for constant-time comparison
- `async_trait` crate for async trait methods
- `serde` for serialization of types

## Testing

Run wallet module tests:

```bash
cargo test wallet --features wallet
```

Run with HTTP client tests:

```bash
cargo test wallet --features wallet,http
```

## Related Documentation

- `substrates/CLAUDE.md` - Transport substrate implementations
- `wire/CLAUDE.md` - Wire protocol encoding/decoding
- `../primitives/CLAUDE.md` - Cryptographic primitives
- `../primitives/ec/CLAUDE.md` - EC operations and BRC-42 derivation
