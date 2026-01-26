# BSV Wallet Module
> BRC-42 Key Derivation, ProtoWallet, and Validation for the BSV Rust SDK

## Overview

This module provides the wallet interface, key derivation, and cryptographic operations for interacting with BSV wallets. It implements the BRC-42 key derivation standard and provides types compatible with the TypeScript and Go BSV SDKs.

## Files

| File | Purpose | Lines |
|------|---------|-------|
| `mod.rs` | Module root with feature-gated exports | ~180 |
| `types.rs` | Core wallet type definitions | ~800 |
| `key_deriver.rs` | BRC-42 key derivation | ~640 |
| `cached_key_deriver.rs` | LRU-cached key deriver | ~490 |
| `proto_wallet.rs` | ProtoWallet cryptographic operations | ~700 |
| `validation.rs` | Input validation helpers | ~850 |
| `CLAUDE.md` | This documentation file | ~600 |

## Key Exports

### ProtoWallet (NEW - W-Beta)

```rust
pub struct ProtoWallet {
    // Construction
    pub fn new(root_key: Option<PrivateKey>) -> Self
    pub fn anyone() -> Self

    // Identity
    pub fn identity_key(&self) -> PublicKey
    pub fn identity_key_hex(&self) -> String

    // Public Key
    pub fn get_public_key(&self, args: GetPublicKeyArgs) -> Result<GetPublicKeyResult>

    // Encryption
    pub fn encrypt(&self, args: EncryptArgs) -> Result<EncryptResult>
    pub fn decrypt(&self, args: DecryptArgs) -> Result<DecryptResult>

    // HMAC
    pub fn create_hmac(&self, args: CreateHmacArgs) -> Result<CreateHmacResult>
    pub fn verify_hmac(&self, args: VerifyHmacArgs) -> Result<VerifyHmacResult>

    // Signatures
    pub fn create_signature(&self, args: CreateSignatureArgs) -> Result<CreateSignatureResult>
    pub fn verify_signature(&self, args: VerifySignatureArgs) -> Result<VerifySignatureResult>

    // Key Linkage Revelation
    pub fn reveal_counterparty_key_linkage(&self, args: RevealCounterpartyKeyLinkageArgs) -> Result<RevealCounterpartyKeyLinkageResult>
    pub fn reveal_specific_key_linkage(&self, args: RevealSpecificKeyLinkageArgs) -> Result<RevealSpecificKeyLinkageResult>
}
```

#### ProtoWallet Capabilities

ProtoWallet can:
- Derive keys using BRC-42
- Create and verify ECDSA signatures
- Encrypt and decrypt data (AES-256-GCM via derived symmetric keys)
- Create and verify HMACs (SHA-256)
- Reveal key linkages for verification

ProtoWallet does NOT:
- Create transactions
- Manage UTXOs
- Interact with the blockchain
- Manage certificates
- Store any persistent data

### Validation Module (NEW - W-Beta)

The `validation` module provides 40+ validation functions for wallet API inputs:

```rust
// Satoshi validation
pub fn validate_satoshis(value: u64, name: &str, min: Option<u64>) -> Result<u64>

// Integer validation
pub fn validate_integer(value: Option<i64>, name: &str, default: Option<i64>, min: Option<i64>, max: Option<i64>) -> Result<i64>

// String validation
pub fn validate_string_length<'a>(s: &'a str, name: &str, min: Option<usize>, max: Option<usize>) -> Result<&'a str>
pub fn validate_hex_string(s: &str, name: &str, min_chars: Option<usize>, max_chars: Option<usize>) -> Result<String>
pub fn validate_base64_string(s: &str, name: &str, min_decoded_bytes: Option<usize>, max_decoded_bytes: Option<usize>) -> Result<String>

// Identifier validation
pub fn validate_basket(s: &str) -> Result<String>  // 1-300 bytes, trimmed, lowercase
pub fn validate_label(s: &str) -> Result<String>   // 1-300 bytes, trimmed, lowercase
pub fn validate_tag(s: &str) -> Result<String>     // 1-300 bytes, trimmed, lowercase
pub fn validate_originator(s: Option<&str>) -> Result<Option<String>>

// Outpoint validation
pub fn parse_wallet_outpoint(outpoint: &str) -> Result<Outpoint>
pub fn validate_outpoint_string(outpoint: &str, name: &str) -> Result<String>

// Action validation
pub fn validate_create_action_args(args: &CreateActionArgsRaw) -> Result<ValidCreateActionArgs>
pub fn validate_create_action_input(input: &CreateActionInputRaw) -> Result<ValidCreateActionInput>
pub fn validate_create_action_output(output: &CreateActionOutputRaw) -> Result<ValidCreateActionOutput>
pub fn validate_create_action_options(options: Option<&CreateActionOptionsRaw>) -> Result<ValidCreateActionOptions>
```

### Security Level

```rust
#[repr(u8)]
pub enum SecurityLevel {
    Silent = 0,        // Level 0: No user interaction
    App = 1,           // Level 1: Approval per application
    Counterparty = 2,  // Level 2: Approval per counterparty per application
}

impl SecurityLevel {
    pub fn from_u8(value: u8) -> Option<Self>
    pub fn as_u8(&self) -> u8
}
```

### Protocol

```rust
pub struct Protocol {
    pub security_level: SecurityLevel,
    pub protocol_name: String,  // 5-400 characters
}

impl Protocol {
    pub fn new(security_level: SecurityLevel, protocol_name: impl Into<String>) -> Self
    pub fn from_tuple(tuple: (u8, &str)) -> Option<Self>
    pub fn to_tuple(&self) -> (u8, &str)
}
```

**Protocol Name Rules:**
- 5 to 400 characters (430 for "specific linkage revelation" protocols)
- Lowercase letters, numbers, and single spaces only
- Cannot contain consecutive spaces
- Cannot end with " protocol"

### Counterparty

```rust
pub enum Counterparty {
    Self_,              // Derive for self
    Anyone,             // Publicly derivable
    Other(PublicKey),   // Specific counterparty
}

impl Counterparty {
    pub fn from_hex(hex: &str) -> Result<Self>
    pub fn is_self(&self) -> bool
    pub fn is_anyone(&self) -> bool
    pub fn public_key(&self) -> Option<&PublicKey>
}
```

### KeyDeriver

```rust
pub struct KeyDeriver {
    // Construction
    pub fn new(root_key: Option<PrivateKey>) -> Self
    pub fn anyone_key() -> (PrivateKey, PublicKey)

    // Identity
    pub fn root_key(&self) -> &PrivateKey
    pub fn identity_key(&self) -> PublicKey
    pub fn identity_key_hex(&self) -> String

    // Key Derivation
    pub fn derive_public_key(&self, protocol: &Protocol, key_id: &str, counterparty: &Counterparty, for_self: bool) -> Result<PublicKey>
    pub fn derive_private_key(&self, protocol: &Protocol, key_id: &str, counterparty: &Counterparty) -> Result<PrivateKey>
    pub fn derive_symmetric_key(&self, protocol: &Protocol, key_id: &str, counterparty: &Counterparty) -> Result<SymmetricKey>

    // Secret Revelation
    pub fn reveal_specific_secret(&self, counterparty: &Counterparty, protocol: &Protocol, key_id: &str) -> Result<Vec<u8>>
    pub fn reveal_counterparty_secret(&self, counterparty: &Counterparty) -> Result<PublicKey>
}
```

### CachedKeyDeriver

```rust
pub struct CacheConfig {
    pub max_size: usize,  // Default: 1000
}

pub struct CachedKeyDeriver {
    pub fn new(root_key: Option<PrivateKey>, config: Option<CacheConfig>) -> Self
    pub fn inner(&self) -> &KeyDeriver
    pub fn root_key(&self) -> &PrivateKey
}

// Implements KeyDeriverApi trait with caching
impl KeyDeriverApi for CachedKeyDeriver { ... }
```

### KeyDeriverApi Trait

```rust
pub trait KeyDeriverApi {
    fn identity_key(&self) -> PublicKey;
    fn identity_key_hex(&self) -> String;
    fn derive_public_key(...) -> Result<PublicKey>;
    fn derive_private_key(...) -> Result<PrivateKey>;
    fn derive_symmetric_key(...) -> Result<SymmetricKey>;
    fn reveal_specific_secret(...) -> Result<Vec<u8>>;
    fn reveal_counterparty_secret(...) -> Result<PublicKey>;
}
```

## Usage

### ProtoWallet - Signing and Verification

```rust
use bsv_sdk::wallet::{ProtoWallet, Protocol, SecurityLevel, CreateSignatureArgs, VerifySignatureArgs, Counterparty};
use bsv_sdk::primitives::PrivateKey;

let wallet = ProtoWallet::new(Some(PrivateKey::random()));
let protocol = Protocol::new(SecurityLevel::App, "signing app");

// Create a signature
let signed = wallet.create_signature(CreateSignatureArgs {
    data: Some(b"Hello, BSV!".to_vec()),
    hash_to_directly_sign: None,
    protocol_id: protocol.clone(),
    key_id: "sig-1".to_string(),
    counterparty: None,
}).unwrap();

// Verify the signature
let verified = wallet.verify_signature(VerifySignatureArgs {
    data: Some(b"Hello, BSV!".to_vec()),
    hash_to_directly_verify: None,
    signature: signed.signature,
    protocol_id: protocol,
    key_id: "sig-1".to_string(),
    counterparty: Some(Counterparty::Anyone),
    for_self: Some(true),
}).unwrap();
```

### ProtoWallet - Two-Party Encryption

```rust
use bsv_sdk::wallet::{ProtoWallet, Protocol, SecurityLevel, EncryptArgs, DecryptArgs, Counterparty};
use bsv_sdk::primitives::PrivateKey;

let alice = ProtoWallet::new(Some(PrivateKey::random()));
let bob = ProtoWallet::new(Some(PrivateKey::random()));
let protocol = Protocol::new(SecurityLevel::App, "secure messaging");
let message = b"Secret message from Alice to Bob".to_vec();

// Alice encrypts for Bob
let encrypted = alice.encrypt(EncryptArgs {
    plaintext: message.clone(),
    protocol_id: protocol.clone(),
    key_id: "message-1".to_string(),
    counterparty: Some(Counterparty::Other(bob.identity_key())),
}).unwrap();

// Bob decrypts using Alice as counterparty
let decrypted = bob.decrypt(DecryptArgs {
    ciphertext: encrypted.ciphertext,
    protocol_id: protocol,
    key_id: "message-1".to_string(),
    counterparty: Some(Counterparty::Other(alice.identity_key())),
}).unwrap();

assert_eq!(decrypted.plaintext, message);
```

### ProtoWallet - HMAC Operations

```rust
use bsv_sdk::wallet::{ProtoWallet, Protocol, SecurityLevel, CreateHmacArgs, VerifyHmacArgs};
use bsv_sdk::primitives::PrivateKey;

let wallet = ProtoWallet::new(Some(PrivateKey::random()));
let protocol = Protocol::new(SecurityLevel::App, "hmac example");

// Create HMAC
let hmac_result = wallet.create_hmac(CreateHmacArgs {
    data: b"data to authenticate".to_vec(),
    protocol_id: protocol.clone(),
    key_id: "hmac-1".to_string(),
    counterparty: None,
}).unwrap();

// Verify HMAC
wallet.verify_hmac(VerifyHmacArgs {
    data: b"data to authenticate".to_vec(),
    hmac: hmac_result.hmac,
    protocol_id: protocol,
    key_id: "hmac-1".to_string(),
    counterparty: None,
}).unwrap();
```

### Input Validation

```rust
use bsv_sdk::wallet::validation::{
    validate_satoshis, validate_hex_string, validate_basket,
    parse_wallet_outpoint, validate_create_action_args,
    CreateActionArgsRaw, CreateActionInputRaw, CreateActionOutputRaw,
};

// Validate satoshi amount with minimum
let sats = validate_satoshis(50000, "outputValue", Some(546)).unwrap();

// Validate hex string with length constraints
let txid = validate_hex_string("deadbeef...", "txid", Some(64), Some(64)).unwrap();

// Validate and normalize basket identifier
let basket = validate_basket("  MY-BASKET  ").unwrap(); // Returns "my-basket"

// Parse outpoint string
let outpoint = parse_wallet_outpoint("txid_hex.0").unwrap();

// Validate full action arguments
let args = CreateActionArgsRaw {
    description: "Payment for services".to_string(),
    inputs: vec![],
    outputs: vec![],
    lock_time: None,
    version: None,
    labels: vec![],
    options: None,
    input_beef: None,
};
let validated = validate_create_action_args(&args).unwrap();
```

### Basic Key Derivation

```rust
use bsv_sdk::wallet::{KeyDeriver, Protocol, SecurityLevel, Counterparty};
use bsv_sdk::primitives::PrivateKey;

let root_key = PrivateKey::random();
let deriver = KeyDeriver::new(Some(root_key));

let protocol = Protocol::new(SecurityLevel::App, "my application");
let key_id = "invoice-12345";

let pub_key = deriver.derive_public_key(&protocol, key_id, &Counterparty::Self_, true)?;
let priv_key = deriver.derive_private_key(&protocol, key_id, &Counterparty::Self_)?;

assert_eq!(priv_key.public_key().to_compressed(), pub_key.to_compressed());
```

### Two-Party Key Derivation

```rust
use bsv_sdk::wallet::{KeyDeriver, Protocol, SecurityLevel, Counterparty};
use bsv_sdk::primitives::PrivateKey;

let alice = KeyDeriver::new(Some(PrivateKey::random()));
let bob = KeyDeriver::new(Some(PrivateKey::random()));

let protocol = Protocol::new(SecurityLevel::App, "payment system");
let key_id = "payment-456";

// Bob derives his private key using Alice as counterparty
let alice_cp = Counterparty::Other(alice.identity_key());
let bob_priv = bob.derive_private_key(&protocol, key_id, &alice_cp)?;

// Alice can derive Bob's public key
let bob_pub = bob.derive_public_key(&protocol, key_id, &alice_cp, true)?;

assert_eq!(bob_priv.public_key().to_compressed(), bob_pub.to_compressed());
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

## Error Types

| Error | Description |
|-------|-------------|
| `WalletError(String)` | General wallet error (includes validation failures) |
| `KeyDerivationError(String)` | Key derivation failed |
| `ProtocolValidationError(String)` | Invalid protocol name or parameters |
| `InvalidCounterparty(String)` | Invalid counterparty specification |

## Test Coverage

The wallet module has comprehensive test coverage:

- **KeyDeriver**: 19 tests (creation, derivation, two-party, validation)
- **CachedKeyDeriver**: 13 tests (caching, LRU eviction, trait impl)
- **ProtoWallet**: 12 tests (signatures, encryption, HMAC, linkage)
- **Validation**: 14 tests (satoshis, strings, hex, base64, outpoints, identifiers)
- **Types**: 10 tests (security levels, protocols, outpoints)

**Total: 58 unit tests**

## Cross-SDK Compatibility

This module maintains API compatibility with:
- [TypeScript SDK](https://github.com/bitcoin-sv/ts-sdk) - `KeyDeriver`, `CachedKeyDeriver`, `ProtoWallet`
- [Go SDK](https://github.com/bitcoin-sv/go-sdk) - `KeyDeriver`, `ProtoWallet`

Key derivation uses the same algorithm (BRC-42) and produces identical keys across all SDK implementations.

### Type Mapping

| TypeScript | Rust |
|------------|------|
| `WalletProtocol` (tuple) | `Protocol` (struct) |
| `SecurityLevel` (0\|1\|2) | `SecurityLevel` (enum) |
| `Counterparty` (string\|PublicKey) | `Counterparty` (enum) |
| `KeyDeriverApi` (interface) | `KeyDeriverApi` (trait) |
| `ProtoWallet` (class) | `ProtoWallet` (struct) |
| `validationHelpers.ts` functions | `validation` module functions |

## Dependencies

The wallet module uses:
- `PrivateKey`, `PublicKey`, `SymmetricKey`, `Signature` from primitives
- `sha256`, `sha256_hmac` from hash module
- `derive_child` methods for BRC-42 derivation
- `subtle` crate for constant-time comparison

## Testing

Run wallet module tests:

```bash
cargo test wallet --features wallet
```

Run all tests including wallet:

```bash
cargo test --all-features
```

## Related Documentation

- `../primitives/CLAUDE.md` - Cryptographic primitives
- `../primitives/ec/CLAUDE.md` - EC operations and BRC-42 derivation
- `../CLAUDE.md` - Project root documentation
