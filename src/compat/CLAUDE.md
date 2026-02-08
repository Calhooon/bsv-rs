# BSV SDK Compatibility Module
> Bitcoin compatibility standards for the BSV Rust SDK

## Overview

The `compat` module provides implementations of Bitcoin compatibility standards that are commonly used but not part of the core BSV protocol. These implementations ensure cross-SDK compatibility with the BSV TypeScript and Go SDKs.

**Status**: Complete

## Files

| File | Purpose |
|------|---------|
| `mod.rs` | Module declaration and re-exports |
| `base58.rs` | Base58 encoding wrapper (~133 lines) |
| `bip32.rs` | BIP-32 HD key derivation (~1288 lines) |
| `bip39/` | BIP-39 mnemonic submodule (see `bip39/CLAUDE.md`) |
| `bsm.rs` | Bitcoin Signed Message (~670 lines) |
| `ecies.rs` | ECIES encryption - Electrum + Bitcore (~1033 lines) |

## Submodules

| Submodule | Status | Description |
|-----------|--------|-------------|
| `base58` | Complete | Base58 encoding/decoding (Bitcoin alphabet) |
| `bip32` | Complete | BIP-32 HD key derivation (xprv/xpub) |
| `bip39` | Complete | BIP-39 mnemonic phrases, 9 languages, seed derivation |
| `bsm` | Complete | Bitcoin Signed Message signing/verification (compact + DER) |
| `ecies` | Complete | ECIES encryption (Electrum and Bitcore variants) |

## Re-exports

The module re-exports key types and functions for convenience:

```rust
pub use bip32::{
    derive_addresses_for_path, derive_public_keys_for_path, generate_hd_key,
    generate_hd_key_from_mnemonic, generate_key_pair_strings, ExtendedKey, Network,
    HARDENED_KEY_START,
};
pub use bip39::{Language, Mnemonic, WordCount};
```

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

### Constants

```rust
pub const HARDENED_KEY_START: u32 = 0x80000000;  // 2^31
pub const MIN_SEED_BYTES: usize = 16;            // 128 bits minimum
pub const MAX_SEED_BYTES: usize = 64;            // 512 bits maximum
pub const RECOMMENDED_SEED_LEN: usize = 32;      // 256 bits recommended
```

### Key Types

```rust
pub enum Network {
    Mainnet,  // xprv/xpub
    Testnet,  // tprv/tpub
}

pub struct ExtendedKey {
    // Construction
    pub fn new_master(seed: &[u8], network: Network) -> Result<Self>
    pub fn from_string(s: &str) -> Result<Self>

    // Derivation
    pub fn derive_child(&self, index: u32) -> Result<Self>
    pub fn derive_path(&self, path: &str) -> Result<Self>
    pub fn neuter(&self) -> Result<Self>  // Convert private to public

    // Key extraction
    pub fn private_key(&self) -> Result<PrivateKey>
    pub fn public_key(&self) -> Result<PublicKey>

    // Metadata
    pub fn is_private(&self) -> bool
    pub fn depth(&self) -> u8
    pub fn child_number(&self) -> u32
    pub fn parent_fingerprint(&self) -> [u8; 4]
    pub fn chain_code(&self) -> &[u8; 32]
    pub fn fingerprint(&self) -> Result<[u8; 4]>
    pub fn network(&self) -> Option<Network>

    // Address generation
    pub fn address(&self, mainnet: bool) -> Result<String>
}

// Helper functions
pub fn generate_hd_key(seed_length: usize, network: Network) -> Result<ExtendedKey>
pub fn generate_hd_key_from_mnemonic(mnemonic: &Mnemonic, passphrase: &str, network: Network) -> Result<ExtendedKey>
pub fn generate_key_pair_strings(seed_length: usize, network: Network) -> Result<(String, String)>
pub fn derive_addresses_for_path(key: &ExtendedKey, base_path: &str, start: u32, count: u32, mainnet: bool) -> Result<Vec<String>>
pub fn derive_public_keys_for_path(key: &ExtendedKey, base_path: &str, start: u32, count: u32) -> Result<Vec<PublicKey>>
```

### Path Notation

Derivation paths support multiple formats:
- `m/44'/0'/0'/0/0` - Standard BIP-44 path
- `m/0h/1` or `m/0H/1` - Alternative hardened notation
- `0'/1` or `/0'/1` - Relative paths (without `m` prefix)

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

// Generate Bitcoin address
let address = master.address(true)?;  // mainnet

// Generate xpriv/xpub pair directly
let (xpriv, xpub) = generate_key_pair_strings(32, Network::Mainnet)?;

// Batch derive addresses
let addresses = derive_addresses_for_path(&master, "m/44'/0'/0'/0", 0, 10, true)?;

// Batch derive public keys
let pubkeys = derive_public_keys_for_path(&master, "m/44'/0'/0'/0", 0, 10)?;
```

## BIP-39 (Mnemonic Phrases)

Implements [BIP-39](https://github.com/bitcoin/bips/blob/master/bip-0039.mediawiki) for mnemonic code generation.

### Key Types

```rust
pub enum WordCount {
    Words12,  // 128 bits entropy, 4 checksum bits
    Words15,  // 160 bits entropy, 5 checksum bits
    Words18,  // 192 bits entropy, 6 checksum bits
    Words21,  // 224 bits entropy, 7 checksum bits
    Words24,  // 256 bits entropy, 8 checksum bits

    // Methods
    pub fn entropy_bytes(self) -> usize
    pub fn word_count(self) -> usize
    pub fn checksum_bits(self) -> usize
}

// Implements Default (English)
pub enum Language {
    ChineseSimplified,
    ChineseTraditional,
    Czech,
    English,   // #[default]
    French,
    Italian,
    Japanese,  // Uses ideographic space (U+3000) as word separator
    Korean,
    Spanish,
}

pub struct Mnemonic {
    // Generation
    pub fn new(word_count: WordCount) -> Result<Self>
    pub fn from_entropy(entropy: &[u8]) -> Result<Self>
    pub fn from_entropy_with_language(entropy: &[u8], language: Language) -> Result<Self>
    pub fn from_phrase(phrase: &str) -> Result<Self>
    pub fn from_phrase_with_language(phrase: &str, language: Language) -> Result<Self>

    // Accessors
    pub fn phrase(&self) -> String
    pub fn words(&self) -> &[String]
    pub fn language(&self) -> Language

    // Seed derivation
    pub fn to_seed(&self, passphrase: &str) -> [u8; 64]
    pub fn to_seed_normalized(&self) -> [u8; 64]  // Empty passphrase

    // Entropy extraction
    pub fn entropy(&self) -> Vec<u8>
    pub fn entropy_with_checksum(&self) -> Vec<u8>  // Matches Go SDK's MnemonicToByteArray

    // Serialization
    pub fn to_binary(&self) -> Vec<u8>              // UTF-8 encoded phrase
    pub fn from_binary(data: &[u8]) -> Result<Self>  // Parse from UTF-8 bytes

    // Validation
    pub fn is_valid(&self) -> bool

    // Also implements Display (outputs phrase())
}

// Wordlist verification
pub fn verify_english_wordlist() -> bool
```

### Multilingual Support

9 languages are supported, each with a 2048-word wordlist per BIP-39 spec. Japanese uses ideographic space (U+3000) as word separator; all others use ASCII space.

**NFKD normalization**: The implementation passes through strings unchanged (matching Go SDK). For maximum cross-SDK compatibility, use only ASCII characters in passphrases.

### Usage Example

```rust
use bsv_sdk::compat::bip39::{Mnemonic, WordCount, Language};

// Generate new mnemonic (English by default)
let mnemonic = Mnemonic::new(WordCount::Words12)?;

// From entropy (test vector)
let entropy = [0u8; 16];
let mnemonic = Mnemonic::from_entropy(&entropy)?;
assert_eq!(mnemonic.phrase(), "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about");

// Non-English mnemonic
let mnemonic = Mnemonic::from_entropy_with_language(&entropy, Language::Japanese)?;
let phrase = mnemonic.phrase(); // Words separated by U+3000

// Parse back a non-English phrase
let restored = Mnemonic::from_phrase_with_language(&phrase, Language::Japanese)?;

// Convert to seed
let seed = mnemonic.to_seed("TREZOR");

// Binary serialization roundtrip
let binary = mnemonic.to_binary();
let restored = Mnemonic::from_binary(&binary)?;

// Extract entropy with checksum
let with_checksum = mnemonic.entropy_with_checksum();
```

## BSM (Bitcoin Signed Message)

Implements Bitcoin Signed Message format for message signing and verification.

### Key Functions

```rust
pub fn sign_message(private_key: &PrivateKey, message: &[u8]) -> Result<Vec<u8>>
pub fn sign_message_with_compression(private_key: &PrivateKey, message: &[u8], compressed: bool) -> Result<Vec<u8>>
pub fn verify_message(address: &str, signature: &[u8], message: &[u8]) -> Result<bool>
pub fn verify_message_der(der_signature: &[u8], public_key: &PublicKey, message: &[u8]) -> Result<bool>
pub fn recover_public_key_from_signature(signature: &[u8], message: &[u8]) -> Result<(PublicKey, bool)>
pub fn magic_hash(message: &[u8]) -> [u8; 32]
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

// Sign (compact 65-byte signature)
let signature = bsm::sign_message(&key, message)?;
assert_eq!(signature.len(), 65);

// Verify against address (recovers pubkey from compact signature)
assert!(bsm::verify_message(&address, &signature, message)?);

// Verify using DER signature + public key (TS SDK compatible)
let msg_hash = bsm::magic_hash(message);
let der_sig = key.sign(&msg_hash)?.to_der();
assert!(bsm::verify_message_der(&der_sig, &key.public_key(), message)?);

// Recover public key
let (recovered, compressed) = bsm::recover_public_key_from_signature(&signature, message)?;

// Compute magic hash directly
let hash = bsm::magic_hash(message);
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
// Binary format
pub fn encrypt_single(message: &[u8], key: &PrivateKey) -> Result<Vec<u8>>
pub fn decrypt_single(data: &[u8], key: &PrivateKey) -> Result<Vec<u8>>

// Base64 format (matches Go SDK API)
pub fn encrypt_single_base64(message: &[u8], key: &PrivateKey) -> Result<String>
pub fn decrypt_single_base64(data: &str, key: &PrivateKey) -> Result<Vec<u8>>
pub fn encrypt_shared_base64(message: &[u8], to: &PublicKey, from: &PrivateKey) -> Result<String>
pub fn decrypt_shared_base64(data: &str, to: &PrivateKey, from: &PublicKey) -> Result<Vec<u8>>
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

// Base64 format (Go SDK compatible)
let encrypted_b64 = ecies::encrypt_single_base64(message, &alice)?;
let decrypted = ecies::decrypt_single_base64(&encrypted_b64, &alice)?;

// Shared encryption with base64
let encrypted_b64 = ecies::encrypt_shared_base64(message, &bob.public_key(), &alice)?;
let decrypted = ecies::decrypt_shared_base64(&encrypted_b64, &bob, &alice.public_key())?;
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
Error::InvalidChecksum  // Base58Check checksum mismatch

// BSM errors
Error::InvalidSignature(String)

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

## Dependencies

Uses existing SDK primitives:
- `primitives::hash::sha256`, `sha256d`, `sha512` - Hashing
- `primitives::hash::sha256_hmac`, `sha512_hmac` - HMAC
- `primitives::hash::hash160` - Address generation
- `primitives::hash::pbkdf2_sha512` - Seed derivation (BIP-39)
- `primitives::encoding::to_base58`, `from_base58`, `to_base58_check` - Base58 encoding
- `primitives::encoding::Writer` - Varint encoding (BSM)
- `primitives::ec::PrivateKey`, `PublicKey`, `Signature` - EC operations
- `primitives::ec::calculate_recovery_id`, `recover_public_key` - ECDSA recovery (BSM)
- `primitives::BigNumber` - Modular arithmetic (BIP-32)
- `getrandom` - Random entropy generation
- `aes`, `cbc` - AES-CBC encryption (ECIES)
- `subtle` - Constant-time comparison (ECIES)
- `base64` - Base64 encoding/decoding (ECIES convenience functions)

## Related Documentation

- `../primitives/CLAUDE.md` - Cryptographic primitives
- `../primitives/ec/CLAUDE.md` - EC operations
- `bip39/CLAUDE.md` - BIP-39 mnemonic submodule details
- `bip39/wordlists/CLAUDE.md` - BIP-39 wordlists documentation
