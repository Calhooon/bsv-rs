# BSV SDK Compatibility Module
> Bitcoin compatibility standards for the BSV Rust SDK

## Overview

The `compat` module provides implementations of Bitcoin compatibility standards that are commonly used but not part of the core BSV protocol. These implementations ensure cross-SDK compatibility with the BSV TypeScript and Go SDKs.

**Status**: Complete

## Submodules

| Submodule | Status | Description |
|-----------|--------|-------------|
| `base58` | Complete | Base58 encoding/decoding (Bitcoin alphabet) |
| `bip32` | Complete | BIP-32 HD key derivation (xprv/xpub) |
| `bip39` | Complete | BIP-39 mnemonic phrase generation and seed derivation |
| `bsm` | Complete | Bitcoin Signed Message signing and verification |
| `ecies` | Complete | ECIES encryption (Electrum and Bitcore variants) |

## Base58 Encoding

Thin wrapper over existing `primitives::encoding` functions using the Bitcoin alphabet.

```rust
use bsv_sdk::compat::base58;

// Encode bytes to Base58
let encoded = base58::encode(&[0x00, 0x00, 0x00, 0x28, 0x7f, 0xb4, 0xcd]);
assert_eq!(encoded, "111233QC4");

// Decode Base58 to bytes
let decoded = base58::decode("111233QC4").unwrap();
```

## BIP-32 (HD Key Derivation)

Implements [BIP-32](https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki) for hierarchical deterministic wallets.

### Key Types

```rust
pub const HARDENED_KEY_START: u32 = 0x80000000;

pub enum Network {
    Mainnet,  // xprv/xpub
    Testnet,  // tprv/tpub
}

pub struct ExtendedKey {
    pub fn new_master(seed: &[u8], network: Network) -> Result<Self>
    pub fn from_string(s: &str) -> Result<Self>
    pub fn derive_child(&self, index: u32) -> Result<Self>
    pub fn derive_path(&self, path: &str) -> Result<Self>
    pub fn private_key(&self) -> Result<PrivateKey>
    pub fn public_key(&self) -> Result<PublicKey>
    pub fn neuter(&self) -> Result<Self>
    pub fn is_private(&self) -> bool
    pub fn fingerprint(&self) -> Result<[u8; 4]>
}

pub fn generate_hd_key(seed_length: usize, network: Network) -> Result<ExtendedKey>
pub fn generate_hd_key_from_mnemonic(mnemonic: &Mnemonic, passphrase: &str, network: Network) -> Result<ExtendedKey>
```

### Usage Example

```rust
use bsv_sdk::compat::bip32::{ExtendedKey, Network, HARDENED_KEY_START};
use bsv_sdk::compat::bip39::Mnemonic;

// From seed
let seed = [0u8; 32];
let master = ExtendedKey::new_master(&seed, Network::Mainnet)?;

// Derive using path notation
let derived = master.derive_path("m/44'/0'/0'/0/0")?;

// From mnemonic
let mnemonic = Mnemonic::from_phrase("abandon abandon...")?;
let master = generate_hd_key_from_mnemonic(&mnemonic, "", Network::Mainnet)?;

// Serialize/parse
let xprv = master.to_string();  // "xprv9s21ZrQH143K..."
let parsed = ExtendedKey::from_string(&xprv)?;

// Get public extended key
let xpub = master.neuter()?;
assert!(xpub.to_string().starts_with("xpub"));
```

## BIP-39 (Mnemonic Phrases)

Implements [BIP-39](https://github.com/bitcoin/bips/blob/master/bip-0039.mediawiki) for mnemonic code generation.

### Key Types

```rust
pub enum WordCount {
    Words12,  // 128 bits entropy
    Words15,  // 160 bits entropy
    Words18,  // 192 bits entropy
    Words21,  // 224 bits entropy
    Words24,  // 256 bits entropy
}

pub enum Language {
    English,
}

pub struct Mnemonic {
    pub fn new(word_count: WordCount) -> Result<Self>
    pub fn from_entropy(entropy: &[u8]) -> Result<Self>
    pub fn from_phrase(phrase: &str) -> Result<Self>
    pub fn phrase(&self) -> String
    pub fn words(&self) -> &[String]
    pub fn to_seed(&self, passphrase: &str) -> [u8; 64]
    pub fn to_seed_normalized(&self) -> [u8; 64]
    pub fn entropy(&self) -> Vec<u8>
    pub fn is_valid(&self) -> bool
}
```

### Usage Example

```rust
use bsv_sdk::compat::bip39::{Mnemonic, WordCount};

// Generate new mnemonic
let mnemonic = Mnemonic::new(WordCount::Words12)?;

// From entropy (test vector)
let entropy = [0u8; 16];
let mnemonic = Mnemonic::from_entropy(&entropy)?;
assert_eq!(mnemonic.phrase(), "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about");

// Convert to seed
let seed = mnemonic.to_seed("TREZOR");
```

## BSM (Bitcoin Signed Message)

Implements Bitcoin Signed Message format for message signing and verification.

### Key Functions

```rust
pub fn sign_message(private_key: &PrivateKey, message: &[u8]) -> Result<Vec<u8>>
pub fn sign_message_with_compression(private_key: &PrivateKey, message: &[u8], compressed: bool) -> Result<Vec<u8>>
pub fn verify_message(address: &str, signature: &[u8], message: &[u8]) -> Result<bool>
pub fn recover_public_key_from_signature(signature: &[u8], message: &[u8]) -> Result<(PublicKey, bool)>
```

### Message Format

```text
Hash = SHA256d(varint(len(magic)) || magic || varint(len(message)) || message)
where magic = "Bitcoin Signed Message:\n"
```

### Signature Format

```text
[recovery_flag (1)] [r (32)] [s (32)] = 65 bytes
recovery_flag = recovery_id + 27 + (compressed ? 4 : 0)
```

### Usage Example

```rust
use bsv_sdk::compat::bsm;
use bsv_sdk::primitives::ec::PrivateKey;

let key = PrivateKey::random();
let address = key.public_key().to_address();
let message = b"Hello, BSV!";

// Sign
let signature = bsm::sign_message(&key, message)?;
assert_eq!(signature.len(), 65);

// Verify
assert!(bsm::verify_message(&address, &signature, message)?);

// Recover public key
let (recovered, compressed) = bsm::recover_public_key_from_signature(&signature, message)?;
```

## ECIES (Encryption)

Provides ECIES encryption with two variants commonly used in the Bitcoin ecosystem.

### Electrum ECIES

```rust
pub fn electrum_encrypt(message: &[u8], to: &PublicKey, from: &PrivateKey, no_key: bool) -> Result<Vec<u8>>
pub fn electrum_decrypt(data: &[u8], to: &PrivateKey, from: Option<&PublicKey>) -> Result<Vec<u8>>
```

**Format**: `"BIE1" || [ephemeral_pubkey (33)] || ciphertext || mac (32)`

**Algorithm**:
1. ECDH: `shared = from_privkey * to_pubkey`
2. Key derivation: `SHA512(compressed_shared)` → iv[0:16], aes_key[16:32], hmac_key[32:64]
3. Encrypt: `AES-128-CBC(message, aes_key, iv)` with PKCS7 padding
4. MAC: `HMAC-SHA256(hmac_key, "BIE1" || [pubkey] || ciphertext)`

### Bitcore ECIES

```rust
pub fn bitcore_encrypt(message: &[u8], to: &PublicKey, from: &PrivateKey, iv: Option<&[u8; 16]>) -> Result<Vec<u8>>
pub fn bitcore_decrypt(data: &[u8], to: &PrivateKey) -> Result<Vec<u8>>
```

**Format**: `pubkey (33) || iv (16) || ciphertext || mac (32)`

**Algorithm**:
1. ECDH: `shared = from_privkey * to_pubkey`
2. Key derivation: `SHA512(shared.x)` → key_e[0:32], key_m[32:64]
3. Encrypt: `AES-256-CBC(message, key_e, iv)` with PKCS7 padding
4. MAC: `HMAC-SHA256(key_m, iv || ciphertext)`

### Convenience Functions

```rust
pub fn encrypt_single(message: &[u8], key: &PrivateKey) -> Result<Vec<u8>>
pub fn decrypt_single(data: &[u8], key: &PrivateKey) -> Result<Vec<u8>>
```

### Usage Example

```rust
use bsv_sdk::compat::ecies;
use bsv_sdk::primitives::ec::PrivateKey;

let alice = PrivateKey::random();
let bob = PrivateKey::random();
let message = b"Hello, BSV!";

// Electrum ECIES
let encrypted = ecies::electrum_encrypt(message, &bob.public_key(), &alice, false)?;
let decrypted = ecies::electrum_decrypt(&encrypted, &bob, Some(&alice.public_key()))?;
assert_eq!(decrypted, message);

// Bitcore ECIES
let encrypted = ecies::bitcore_encrypt(message, &bob.public_key(), &alice, None)?;
let decrypted = ecies::bitcore_decrypt(&encrypted, &bob)?;
assert_eq!(decrypted, message);

// Self-encryption
let encrypted = ecies::encrypt_single(message, &alice)?;
let decrypted = ecies::decrypt_single(&encrypted, &alice)?;
```

## Error Types

```rust
// BIP-39 errors
Error::InvalidMnemonic(String)
Error::InvalidEntropyLength { expected: String, actual: usize }
Error::InvalidMnemonicWord(String)

// BIP-32 errors
Error::InvalidExtendedKey(String)
Error::HardenedFromPublic
Error::InvalidDerivationPath(String)

// ECIES errors
Error::EciesDecryptionFailed(String)
Error::EciesHmacMismatch
```

## Feature Flag

Enable the compat module with the `compat` feature:

```toml
[dependencies]
bsv-sdk = { version = "0.2", features = ["compat"] }
```

Or use `full` to enable all features:

```toml
[dependencies]
bsv-sdk = { version = "0.2", features = ["full"] }
```

## Cross-SDK Compatibility

All implementations produce identical results to:
- [BSV Go SDK](https://github.com/bitcoin-sv/go-sdk/tree/master/compat)
- [BSV TypeScript SDK](https://github.com/bitcoin-sv/ts-sdk)

Verified using official BIP-32/BIP-39 test vectors and cross-SDK encryption/signing tests.

## Testing

```bash
# Run all compat module tests
cargo test --features compat

# Run specific submodule tests
cargo test --features compat base58
cargo test --features compat bip32
cargo test --features compat bip39
cargo test --features compat bsm
cargo test --features compat ecies
```

## Files

| File | Purpose |
|------|---------|
| `mod.rs` | Module declaration and re-exports |
| `base58.rs` | Base58 encoding wrapper |
| `bip32.rs` | BIP-32 HD key derivation |
| `bip39/` | BIP-39 mnemonic submodule |
| `bsm.rs` | Bitcoin Signed Message |
| `ecies.rs` | ECIES encryption (Electrum + Bitcore) |

## Dependencies

Uses existing SDK primitives:
- `primitives::hash::sha256`, `sha256d`, `sha512` - Hashing
- `primitives::hash::sha256_hmac`, `sha512_hmac` - HMAC
- `primitives::hash::pbkdf2_sha512` - Seed derivation
- `primitives::encoding::to_base58`, `from_base58` - Base58
- `primitives::ec::PrivateKey`, `PublicKey` - EC operations
- `primitives::ec::calculate_recovery_id`, `recover_public_key` - ECDSA recovery
- `getrandom` - Random entropy generation
- `aes`, `cbc` - AES-CBC encryption (for ECIES)

## Related Documentation

- `../primitives/CLAUDE.md` - Cryptographic primitives
- `../primitives/ec/CLAUDE.md` - EC operations
- `bip39/CLAUDE.md` - BIP-39 submodule details
