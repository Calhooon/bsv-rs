# BSV Wallet Module
> BRC-42 Key Derivation, ProtoWallet, WalletClient, WalletInterface, and Validation for the BSV Rust SDK

## Overview

This module provides the wallet interface, key derivation, and cryptographic operations for interacting with BSV wallets. It implements the BRC-42 key derivation standard and provides types compatible with the TypeScript and Go BSV SDKs.

## Files

| File | Purpose | Lines |
|------|---------|-------|
| `mod.rs` | Module root with feature-gated exports and re-exports | ~253 |
| `types.rs` | Core wallet type definitions (70+ types, hex serde helpers) | ~1905 |
| `interface.rs` | WalletInterface async trait (28 methods) + marker traits | ~297 |
| `key_deriver.rs` | BRC-42 key derivation with KeyDeriverApi trait | ~679 |
| `cached_key_deriver.rs` | Thread-safe LRU-cached key deriver (Mutex-based) | ~526 |
| `proto_wallet.rs` | ProtoWallet struct + WalletInterface impl | ~1414 |
| `validation.rs` | 40+ input validation helpers + validated structs | ~1170 |
| `client.rs` | Multi-substrate WalletClient (requires `http` feature) | ~665 |
| `substrates/` | Transport substrate implementations | - |
| `wire/` | Wire protocol encoding/decoding | - |

## Submodules

### substrates/
Transport layer implementations for wallet communication (requires `http` feature):
- `mod.rs` - Module definitions, re-exports, `SECURE_JSON_URL` constant
- `http_json.rs` - JSON over HTTP substrate (`HttpWalletJson`)
- `http_wire.rs` - Binary wire protocol over HTTP substrate (`HttpWalletWire`)
- See `substrates/CLAUDE.md` for details

### wire/
Wire protocol implementation for binary wallet communication:
- `mod.rs` - Module definitions and re-exports
- `encoding.rs` - Binary encoding/decoding for all wallet types (~87k lines)
- `calls.rs` - Call frame definitions for all 28 wallet operations
- `transceiver.rs` - Protocol transceiver (`WalletWireTransceiver`)
- `processor.rs` - Request/response processing (`WalletWireProcessor`)
- See `wire/CLAUDE.md` for details

## Key Exports

### WalletInterface Trait

The `WalletInterface` trait defines all 28 wallet operations (async with `originator: &str` parameter):

| Category | Methods |
|----------|---------|
| Key (9) | `get_public_key`, `encrypt`, `decrypt`, `create_hmac`, `verify_hmac`, `create_signature`, `verify_signature`, `reveal_counterparty_key_linkage`, `reveal_specific_key_linkage` |
| Action (5) | `create_action`, `sign_action`, `abort_action`, `list_actions`, `internalize_action` |
| Output (2) | `list_outputs`, `relinquish_output` |
| Certificate (4) | `acquire_certificate`, `list_certificates`, `prove_certificate`, `relinquish_certificate` |
| Discovery (2) | `discover_by_identity_key`, `discover_by_attributes` |
| Status (6) | `is_authenticated`, `wait_for_authentication`, `get_height`, `get_header_for_height`, `get_network`, `get_version` |

Marker traits: `CryptoWallet` (crypto-only), `FullWallet` (all methods supported).

The trait requires `Send + Sync` and uses `#[async_trait]`. Unsupported methods should return `Err(Error::WalletError(...))`.

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
    // All wallet operations as async methods (connect lazily on first call)
}
```

**Substrate Selection:**

| Type | Protocol | Default Port | Use Case |
|------|----------|--------------|----------|
| `Auto` | Various | - | Production apps (probes in order: Secure -> JSON -> Wire) |
| `JsonApi` | JSON | 3321 | Debugging, simple integration |
| `Cicada` | Binary | 3301 | High performance |
| `SecureJsonApi` | JSON/TLS | 2121 | Secure local communication |

Internally uses `ConnectedSubstrate` enum dispatching to either `HttpWalletJson` or `WalletWireTransceiver<HttpWalletWire>`.

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

// ProtoWallet implements WalletInterface (async trait)
impl WalletInterface for ProtoWallet { ... }
```

#### ProtoWallet Capabilities

ProtoWallet can:
- Derive keys using BRC-42 (via internal CachedKeyDeriver wrapped in Arc)
- Create and verify ECDSA signatures
- Encrypt and decrypt data (AES-256-GCM via derived symmetric keys)
- Create and verify HMACs (SHA-256 with constant-time comparison)
- Reveal key linkages for verification (with Schnorr ZK proofs for counterparty linkage)
- Implement all `WalletInterface` methods (unsupported methods return errors)

ProtoWallet does NOT:
- Create transactions (returns error)
- Manage UTXOs (returns error)
- Interact with the blockchain
- Manage certificates (returns error)
- Store any persistent data

#### Default Counterparty Behavior

- `create_signature`: Defaults counterparty to `Anyone` (publicly derivable), matching Go/TS SDK behavior
- All other operations (`encrypt`, `decrypt`, `create_hmac`, `verify_hmac`, `verify_signature`, `get_public_key`): Default counterparty to `Self_`

#### WalletInterface Implementation

ProtoWallet implements `WalletInterface` (via `#[async_trait]`) with full support for cryptographic operations:
- Key operations: All 9 methods fully implemented (synchronous internally, wrapped as async)
- Action/Output/Certificate/Discovery operations: Return `Error::WalletError` indicating full wallet required
- Status operations: `is_authenticated` returns true, `wait_for_authentication` returns true, `get_network` returns `Network::Mainnet`, `get_version` returns `"bsv-sdk-0.1.0"`, `get_height` returns 0, `get_header_for_height` returns error

#### Schnorr Proof for Counterparty Key Linkage

`reveal_counterparty_key_linkage` generates a real 98-byte Schnorr ZK proof demonstrating knowledge of the private key and correct ECDH computation. The proof is encoded as:
- `R` (33 bytes, compressed point)
- `S'` (33 bytes, compressed point)
- `z` (32 bytes, scalar)

Both the linkage and proof are encrypted for the verifier using the "counterparty linkage revelation" protocol with the revelation timestamp as key_id.

### Validation Module

The `validation` module (`validation.rs`) provides 40+ validation functions for wallet API inputs:

| Category | Functions |
|----------|-----------|
| Satoshis | `validate_satoshis` (with optional min) |
| Integers | `validate_integer`, `validate_integer_u32`, `validate_positive_integer_or_zero` |
| Strings | `validate_string_length`, `validate_optional_string_length`, `validate_hex_string`, `validate_optional_hex_string`, `validate_base64_string`, `validate_optional_base64_string`, `is_hex_string` |
| Identifiers | `validate_basket`, `validate_optional_basket`, `validate_label`, `validate_tag`, `validate_originator` (all normalize to lowercase, trim whitespace) |
| Outpoints | `parse_wallet_outpoint`, `validate_outpoint_string`, `validate_optional_outpoint_string` |
| Descriptions | `validate_description_5_2000`, `validate_description_5_50` |
| Actions | `validate_create_action_args`, `validate_create_action_input`, `validate_create_action_output`, `validate_create_action_options`, `validate_sign_action_spend` |
| Certificates | `validate_certificate_fields` (1-50 byte field names), `validate_keyring_revealer` ("certifier" or 66-char hex pubkey) |
| Protocol | `validate_protocol_tuple`, `validate_query_mode` |

Validated structs (used after validation):
- `ValidCreateActionInput`, `ValidCreateActionOutput`, `ValidCreateActionOptions`, `ValidCreateActionArgs`
- `ValidSignActionSpend`, `ValidListOutputsArgs`, `ValidListActionsArgs`
- Raw counterparts (`CreateActionInputRaw`, `CreateActionOutputRaw`, `CreateActionOptionsRaw`, `CreateActionArgsRaw`, `SignActionSpendRaw`) for unvalidated input

### Hex Serialization Helpers (in `types.rs`)

The `types.rs` module includes serde helper modules for cross-SDK JSON compatibility:
- `hex_bytes` - Serializes `Vec<u8>` as hex strings (use with `#[serde(with = "hex_bytes")]`)
- `hex_bytes_option` - Serializes `Option<Vec<u8>>` as optional hex strings (use with `skip_serializing_if`)
- `hex_txid` - Serializes `[u8; 32]` TxId as hex strings
- `hex_txid_vec_option` - Serializes `Option<Vec<[u8; 32]>>` as optional arrays of hex strings

These ensure byte fields serialize as hex strings (e.g., `"76a914"`) rather than JSON arrays (e.g., `[118, 169, 20]`), matching the TypeScript and Go SDK wire formats. All types use `#[serde(rename_all = "camelCase")]` for JSON field naming consistency.

### Core Types

**SecurityLevel** - User interaction level for key derivation:
- `Silent` (0): No user interaction required
- `App` (1): Requires user approval per application
- `Counterparty` (2): Requires user approval per counterparty per application

**Protocol** - Combines `SecurityLevel` and `protocol_name` (5-400 chars, or 430 for "specific linkage revelation" protocols; lowercase, no consecutive spaces, cannot end with " protocol").

**Counterparty** - Key derivation target: `Self_`, `Anyone` (publicly derivable), or `Other(PublicKey)`.

**Network** - Bitcoin network: `Mainnet` (default) or `Testnet`.

**ActionStatus** - Transaction status: `Completed`, `Unprocessed`, `Sending`, `Unproven`, `Unsigned`, `NoSend`, `NonFinal`, `Failed`.

**QueryMode** - Filter mode for lists: `Any` (default) or `All`.

**OutputInclude** - What to include in output listings: `LockingScripts` or `EntireTransactions`.

**Outpoint** - Transaction outpoint with `txid: TxId` and `vout: u32`. Parses from "txid.vout" string format. Supports both string and object serialization for cross-SDK compatibility.

**TxId** - Type alias for `[u8; 32]`.

**SatoshiValue** - Type alias for `u64`. Max: `MAX_SATOSHIS` (2.1 quadrillion).

### Key Derivation

**KeyDeriver** - BRC-42 key derivation from root private key:
- `new(root_key: Option<PrivateKey>)` - Creates deriver; None uses "anyone" key
- `anyone_key() -> (PrivateKey, PublicKey)` - Returns the special "anyone" key pair (scalar value 1)
- `root_key() -> &PrivateKey` - Returns the root private key
- `identity_key() -> PublicKey` - Returns the identity public key (root key's public key)
- `identity_key_hex() -> String` - Returns identity key as hex string
- `derive_public_key(protocol, key_id, counterparty, for_self)` - Derive public key
- `derive_private_key(protocol, key_id, counterparty)` - Derive private key
- `derive_private_key_raw(invoice_number, counterparty)` - Derive private key with raw invoice number (bypasses BRC-43 protocol name validation)
- `derive_symmetric_key(protocol, key_id, counterparty)` - Derive symmetric key for encryption
- `reveal_specific_secret()`, `reveal_counterparty_secret()` - For linkage revelation

**CachedKeyDeriver** - Thread-safe LRU-cached wrapper (default 1000 entries per cache):
- `new(root_key: Option<PrivateKey>, config: Option<CacheConfig>)`
- `inner() -> &KeyDeriver` - Access underlying deriver
- `root_key() -> &PrivateKey` - Returns the root private key
- Implements same `KeyDeriverApi` trait as `KeyDeriver`
- Maintains 3 separate `Mutex<LruCache<T>>` caches: public keys, private keys, symmetric keys
- Cache keys are formatted as `"{method}:{level}:{protocol}:{key_id}:{counterparty}:{for_self}"`
- Secrets (`reveal_specific_secret`, `reveal_counterparty_secret`) are NOT cached for security reasons

**KeyDeriverApi** - Trait implemented by both `KeyDeriver` and `CachedKeyDeriver`:
- `identity_key()`, `identity_key_hex()`
- `derive_public_key()`, `derive_private_key()`, `derive_private_key_raw()`, `derive_symmetric_key()`
- `reveal_specific_secret()`, `reveal_counterparty_secret()`

**CacheConfig** - Configuration for CachedKeyDeriver:
- `max_size: usize` - Maximum entries per cache (default 1000)

## Usage Examples

### ProtoWallet - Signing

```rust
let wallet = ProtoWallet::new(Some(PrivateKey::random()));
let signed = wallet.create_signature(CreateSignatureArgs {
    data: Some(b"Hello, BSV!".to_vec()),
    hash_to_directly_sign: None,
    protocol_id: Protocol::new(SecurityLevel::App, "signing app"),
    key_id: "sig-1".to_string(),
    counterparty: None, // defaults to Anyone
}).unwrap();
```

### Two-Party Encryption

```rust
let alice = ProtoWallet::new(Some(PrivateKey::random()));
let bob = ProtoWallet::new(Some(PrivateKey::random()));
let protocol = Protocol::new(SecurityLevel::App, "secure messaging");

let encrypted = alice.encrypt(EncryptArgs {
    plaintext: b"Secret message".to_vec(),
    protocol_id: protocol.clone(),
    key_id: "msg-1".to_string(),
    counterparty: Some(Counterparty::Other(bob.identity_key())),
}).unwrap();

let decrypted = bob.decrypt(DecryptArgs {
    ciphertext: encrypted.ciphertext,
    protocol_id: protocol,
    key_id: "msg-1".to_string(),
    counterparty: Some(Counterparty::Other(alice.identity_key())),
}).unwrap();
```

### WalletClient and Key Derivation

```rust
// Remote wallet via auto-detected substrate
let mut client = WalletClient::new(SubstrateType::Auto, Some("myapp.com".into()));
let version = client.get_version().await?;

// Direct key derivation
let deriver = KeyDeriver::new(Some(PrivateKey::random()));
let protocol = Protocol::new(SecurityLevel::App, "my application");
let pub_key = deriver.derive_public_key(&protocol, "key-1", &Counterparty::Self_, true).unwrap();

// Cached key derivation
let cached = CachedKeyDeriver::new(Some(PrivateKey::random()), None);
let pub_key = cached.derive_public_key(&protocol, "key-1", &Counterparty::Self_, true).unwrap();
```

## BRC-42 Key Derivation Algorithm

**Private key**: `new_key = (self + HMAC-SHA256(ECDH(self, counterparty), invoice_number)) mod n`
**Public key**: `new_pubkey = counterparty + G * HMAC-SHA256(ECDH(self_priv, counterparty), invoice_number)`
**Invoice number format**: `{security_level}-{protocol_name}-{key_id}` (e.g., `1-my application-invoice-12345`)

## Feature Flags

```toml
[dependencies]
# Basic wallet functionality (key derivation, ProtoWallet, validation)
bsv-sdk = { version = "0.2", features = ["wallet"] }

# With remote wallet communication (WalletClient)
bsv-sdk = { version = "0.2", features = ["wallet", "http"] }
```

## Argument and Result Types

ProtoWallet operations use dedicated argument/result structs:

| Operation | Args Type | Result Type |
|-----------|-----------|-------------|
| `get_public_key` | `GetPublicKeyArgs` | `GetPublicKeyResult` |
| `encrypt` | `EncryptArgs` | `EncryptResult` |
| `decrypt` | `DecryptArgs` | `DecryptResult` |
| `create_hmac` | `CreateHmacArgs` | `CreateHmacResult` |
| `verify_hmac` | `VerifyHmacArgs` | `VerifyHmacResult` |
| `create_signature` | `CreateSignatureArgs` | `CreateSignatureResult` |
| `verify_signature` | `VerifySignatureArgs` | `VerifySignatureResult` |
| `reveal_counterparty_key_linkage` | `RevealCounterpartyKeyLinkageArgs` | `RevealCounterpartyKeyLinkageResult` |
| `reveal_specific_key_linkage` | `RevealSpecificKeyLinkageArgs` | `RevealSpecificKeyLinkageResult` |

Additional types in `types.rs` cover all wallet operations (actions, outputs, certificates, discovery).

## Error Types

| Error | Description |
|-------|-------------|
| `WalletError(String)` | General wallet error (includes validation failures) |
| `KeyDerivationError(String)` | Key derivation failed |
| `ProtocolValidationError(String)` | Invalid protocol name or parameters |
| `InvalidCounterparty(String)` | Invalid counterparty specification |

## Cross-SDK Compatibility

This module maintains API compatibility with:
- [TypeScript SDK](https://github.com/bitcoin-sv/ts-sdk) - `KeyDeriver`, `CachedKeyDeriver`, `ProtoWallet`, `WalletClient`, all wallet methods
- [Go SDK](https://github.com/bitcoin-sv/go-sdk) - `KeyDeriver`, `ProtoWallet`

Key derivation uses the same algorithm (BRC-42) and produces identical keys across all SDK implementations.

**Notable difference:** Go SDK's `create_signature` defaults counterparty to `Anyone`; Rust and TS SDKs also default to `Anyone`.

### Type Mapping

| TypeScript | Rust |
|------------|------|
| `WalletProtocol` (tuple) | `Protocol` (struct with `from_tuple`/`to_tuple`) |
| `SecurityLevel` (0\|1\|2) | `SecurityLevel` (enum with `from_u8`/`as_u8`) |
| `Counterparty` (string\|PublicKey) | `Counterparty` (enum: `Self_`, `Anyone`, `Other(PublicKey)`) |
| `KeyDeriverApi` (interface) | `KeyDeriverApi` (trait) |
| `WalletInterface` (interface) | `WalletInterface` (async trait) |
| `ProtoWallet` (class) | `ProtoWallet` (struct, implements `WalletInterface`) |
| `Wallet` (class) | `WalletClient` (struct, multi-substrate) |
| `validationHelpers.ts` functions | `validation` module functions |

## Internal Dependencies

The wallet module uses:
- `PrivateKey`, `PublicKey`, `SymmetricKey`, `Signature` from primitives module
- `sha256`, `sha256_hmac` from `primitives::hash`
- `Schnorr`, `SchnorrProof` from `primitives::bsv::schnorr` for counterparty linkage ZK proofs
- `derive_child`, `derive_shared_secret` methods on `PrivateKey`/`PublicKey` for BRC-42 derivation
- `subtle` crate for constant-time comparison (HMAC verification in `proto_wallet.rs`)
- `async_trait` crate for async trait methods (`WalletInterface`)
- `serde` / `serde_json` for serialization of types (JSON API compatibility)
- `hex` crate for hex encoding/decoding in serde helpers
- `reqwest` (optional, with `http` feature) for HTTP substrate communication

## Testing

Run wallet module tests:

```bash
cargo test wallet --features wallet         # Core wallet tests
cargo test wallet --features wallet,http    # Including HTTP client tests
cargo test --features full -- wallet        # As part of full suite
```

Each source file includes inline `#[cfg(test)]` modules covering type conversions, hex serde roundtrips, key derivation determinism, two-party agreement, LRU cache eviction, ProtoWallet crypto operations, Schnorr proof generation/verification, and all validation boundary cases.

## Implementation Notes

- **Timestamp generation**: `proto_wallet.rs` implements ISO 8601 timestamps without external crate dependencies (uses `std::time::SystemTime` with manual date calculation)
- **Thread safety**: `CachedKeyDeriver` uses `std::sync::Mutex` (not `tokio::sync::Mutex`) since lock hold times are very short
- **Clone**: `ProtoWallet` wraps `CachedKeyDeriver` in `Arc` for cheap cloning
- **Debug**: Both `ProtoWallet` and `KeyDeriver` implement custom `Debug` that shows only the identity key hex (never the private key)
- **Serde**: `Counterparty` does not implement `Serialize`/`Deserialize` directly - it's converted to/from strings and `PublicKey` at API boundaries
- **Outpoint serde**: Custom `Serialize`/`Deserialize` impl accepts both string format (`"txid.vout"`) and object format (`{"txid":"...","vout":N}`)

## Related Documentation

- `substrates/CLAUDE.md` - Transport substrate implementations
- `wire/CLAUDE.md` - Wire protocol encoding/decoding
- `../primitives/CLAUDE.md` - Cryptographic primitives
- `../primitives/ec/CLAUDE.md` - EC operations and BRC-42 derivation
