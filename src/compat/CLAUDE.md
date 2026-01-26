# BSV SDK Compatibility Module
> Bitcoin compatibility standards for the BSV Rust SDK

## Overview

The `compat` module provides implementations of Bitcoin compatibility standards that are commonly used but not part of the core BSV protocol. These implementations ensure cross-SDK compatibility with the BSV TypeScript and Go SDKs.

**Status**: In Progress

## Submodules

| Submodule | Status | Description |
|-----------|--------|-------------|
| `bip39` | Complete | BIP-39 mnemonic phrase generation and seed derivation |

## BIP-39 (Mnemonic Phrases)

The `bip39` submodule implements [BIP-39](https://github.com/bitcoin/bips/blob/master/bip-0039.mediawiki) for mnemonic code generation.

### Features

- Generate random mnemonic phrases (12, 15, 18, 21, or 24 words)
- Create mnemonics from entropy bytes
- Parse and validate existing mnemonic phrases
- Convert mnemonics to 512-bit seeds with optional passphrase
- Extract entropy from valid mnemonics
- English wordlist support (2048 words)

### Key Types

```rust
/// Supported word counts
pub enum WordCount {
    Words12,  // 128 bits entropy
    Words15,  // 160 bits entropy
    Words18,  // 192 bits entropy
    Words21,  // 224 bits entropy
    Words24,  // 256 bits entropy
}

/// Supported languages
pub enum Language {
    English,  // Currently only English
}

/// BIP-39 mnemonic phrase
pub struct Mnemonic {
    // Generate new random mnemonic
    pub fn new(word_count: WordCount) -> Result<Self>;

    // Create from entropy bytes
    pub fn from_entropy(entropy: &[u8]) -> Result<Self>;

    // Parse from phrase string
    pub fn from_phrase(phrase: &str) -> Result<Self>;

    // Get phrase as string
    pub fn phrase(&self) -> String;

    // Get individual words
    pub fn words(&self) -> &[String];

    // Convert to 64-byte seed
    pub fn to_seed(&self, passphrase: &str) -> [u8; 64];

    // Convert to seed with empty passphrase
    pub fn to_seed_normalized(&self) -> [u8; 64];

    // Extract original entropy
    pub fn entropy(&self) -> Vec<u8>;

    // Validate checksum
    pub fn is_valid(&self) -> bool;
}
```

### Usage Examples

```rust
use bsv_sdk::compat::bip39::{Mnemonic, WordCount};

// Generate a new 12-word mnemonic
let mnemonic = Mnemonic::new(WordCount::Words12)?;
println!("Mnemonic: {}", mnemonic.phrase());

// Generate from specific entropy
let entropy = [0u8; 16]; // 128 bits = 12 words
let mnemonic = Mnemonic::from_entropy(&entropy)?;
assert_eq!(
    mnemonic.phrase(),
    "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
);

// Parse an existing mnemonic
let phrase = "legal winner thank year wave sausage worth useful legal winner thank yellow";
let mnemonic = Mnemonic::from_phrase(phrase)?;
assert!(mnemonic.is_valid());

// Convert to seed with passphrase
let seed = mnemonic.to_seed("TREZOR");
assert_eq!(seed.len(), 64);

// Extract original entropy
let entropy = mnemonic.entropy();
```

### Algorithm Details

**Entropy to Mnemonic:**
1. Take SHA-256 hash of entropy
2. Append first `entropy_bits / 32` bits of hash as checksum
3. Split result into 11-bit groups
4. Map each 11-bit value (0-2047) to word in wordlist

**Mnemonic to Seed:**
1. Normalize mnemonic and passphrase (NFKD)
2. Use PBKDF2-HMAC-SHA512
3. Salt = "mnemonic" + passphrase
4. Iterations = 2048
5. Output = 64 bytes

### Entropy Sizes

| Words | Entropy (bits) | Checksum (bits) | Total (bits) |
|-------|----------------|-----------------|--------------|
| 12 | 128 | 4 | 132 |
| 15 | 160 | 5 | 165 |
| 18 | 192 | 6 | 198 |
| 21 | 224 | 7 | 231 |
| 24 | 256 | 8 | 264 |

### Error Types

```rust
// Invalid mnemonic phrase
Error::InvalidMnemonic(String)

// Invalid entropy length
Error::InvalidEntropyLength { expected: String, actual: usize }

// Unknown word in mnemonic
Error::InvalidMnemonicWord(String)
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

The BIP-39 implementation produces identical results to:
- [BSV Go SDK](https://github.com/bitcoin-sv/go-sdk/tree/master/compat/bip39)
- [BSV TypeScript SDK](https://github.com/bitcoin-sv/ts-sdk) (Mnemonic class)

Test vectors from the official BIP-39 specification and TREZOR are used to verify compatibility.

## Testing

```bash
# Run compat module tests
cargo test --features compat

# Run only BIP-39 tests
cargo test --features compat compat_bip39
```

## Files

| File | Purpose |
|------|---------|
| `mod.rs` | Module declaration and re-exports |
| `bip39/mod.rs` | BIP-39 submodule declaration |
| `bip39/mnemonic.rs` | Mnemonic struct implementation |
| `bip39/wordlists/mod.rs` | Wordlist module declaration |
| `bip39/wordlists/english.rs` | English wordlist (2048 words) |

## Dependencies

Uses existing SDK primitives:
- `primitives::hash::sha256` - Checksum calculation
- `primitives::hash::pbkdf2_sha512` - Seed derivation
- `getrandom` - Random entropy generation

## Related Documentation

- `../primitives/CLAUDE.md` - Cryptographic primitives
- `../primitives/hash.rs` - Hash functions and PBKDF2
- `../../tests/compat_bip39_tests.rs` - Test vectors
