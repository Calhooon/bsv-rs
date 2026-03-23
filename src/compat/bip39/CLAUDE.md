# BIP-39 Mnemonic Phrases
> BIP-39 mnemonic code implementation for deterministic key generation

## Overview

The `bip39` submodule implements [BIP-39](https://github.com/bitcoin/bips/blob/master/bip-0039.mediawiki) for mnemonic code generation and seed derivation. It provides functionality to generate, parse, validate, and convert mnemonic phrases to cryptographic seeds that can be used for hierarchical deterministic wallet derivation.

**Status**: Complete

## Files

| File | Purpose |
|------|---------|
| `mod.rs` | Module declaration, documentation, and public re-exports |
| `mnemonic.rs` | `Mnemonic`, `WordCount`, `Language`, `NfkdNormalize` trait, and `Display` impl (~963 lines) |
| `wordlists/mod.rs` | Wordlist module declaration, re-exports, and `verify_english_wordlist()` |
| `wordlists/english.rs` | English BIP-39 wordlist (2048 words as `[&str; 2048]`) |
| `wordlists/chinese_simplified.rs` | Chinese Simplified wordlist |
| `wordlists/chinese_traditional.rs` | Chinese Traditional wordlist |
| `wordlists/czech.rs` | Czech wordlist |
| `wordlists/french.rs` | French wordlist |
| `wordlists/italian.rs` | Italian wordlist |
| `wordlists/japanese.rs` | Japanese wordlist |
| `wordlists/korean.rs` | Korean wordlist |
| `wordlists/spanish.rs` | Spanish wordlist |
| `wordlists/CLAUDE.md` | Wordlist submodule documentation |

## Key Exports

### Structs

```rust
/// A validated BIP-39 mnemonic phrase
#[derive(Debug, Clone)]
pub struct Mnemonic {
    words: Vec<String>,
    language: Language,
}
```

### Enums

```rust
/// Supported word counts (determines entropy size)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WordCount {
    Words12,  // 128 bits entropy, 4-bit checksum
    Words15,  // 160 bits entropy, 5-bit checksum
    Words18,  // 192 bits entropy, 6-bit checksum
    Words21,  // 224 bits entropy, 7-bit checksum
    Words24,  // 256 bits entropy, 8-bit checksum
}

/// Supported languages for wordlists
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Language {
    ChineseSimplified,
    ChineseTraditional,
    Czech,
    #[default]
    English,
    French,
    Italian,
    Japanese,   // Uses ideographic space (U+3000) as separator per BIP-39 spec
    Korean,
    Spanish,
}
```

## Public API

**Mnemonic Creation:**
- `Mnemonic::new(word_count: WordCount) -> Result<Self>` - Generate random mnemonic
- `Mnemonic::from_entropy(entropy: &[u8]) -> Result<Self>` - Create from entropy bytes
- `Mnemonic::from_entropy_with_language(entropy: &[u8], language: Language) -> Result<Self>`
- `Mnemonic::from_phrase(phrase: &str) -> Result<Self>` - Parse and validate phrase
- `Mnemonic::from_phrase_with_language(phrase: &str, language: Language) -> Result<Self>`

**Mnemonic Access:**
- `phrase(&self) -> String` - Get the full phrase (space-separated; Japanese uses ideographic space U+3000)
- `words(&self) -> &[String]` - Get individual words
- `language(&self) -> Language` - Get the language
- `entropy(&self) -> Vec<u8>` - Extract original entropy bytes
- `entropy_with_checksum(&self) -> Vec<u8>` - Extract entropy with checksum (Go SDK compatible)

**Serialization:**
- `to_binary(&self) -> Vec<u8>` - Serialize mnemonic to UTF-8 encoded phrase bytes
- `from_binary(data: &[u8]) -> Result<Self>` - Deserialize mnemonic from UTF-8 encoded phrase bytes

**Seed Derivation:**
- `to_seed(&self, passphrase: &str) -> [u8; 64]` - Convert to 64-byte seed with passphrase
- `to_seed_normalized(&self) -> [u8; 64]` - Convert to seed with empty passphrase

**Validation:**
- `is_valid(&self) -> bool` - Validate checksum

**WordCount Methods:**
- `entropy_bytes(self) -> usize` - Get entropy size in bytes
- `word_count(self) -> usize` - Get number of words
- `checksum_bits(self) -> usize` - Get checksum size in bits

**Language Methods (internal):**
- `wordlist(&self) -> &'static [&'static str; 2048]` - Returns the wordlist
- `separator(&self) -> &'static str` - Returns word separator
- `word_index(&self, word: &str) -> Option<usize>` - Finds word index

**Wordlist Utilities:**
- `verify_english_wordlist() -> bool` - Verify wordlist integrity (first/last words, 2048 count; `#[inline]`)

**Trait Implementations:**
- `Display` for `Mnemonic` - Displays the phrase via `phrase()` method
- `Clone` for `Mnemonic` - Enables cloning mnemonic instances
- `NfkdNormalize` for `str` and `String` (private) - Pass-through NFKD normalization matching Go SDK

## Usage

### Generate a New Mnemonic

```rust
use bsv_rs::compat::bip39::{Mnemonic, WordCount};

// Generate 12-word mnemonic (128 bits entropy)
let mnemonic = Mnemonic::new(WordCount::Words12)?;
println!("Mnemonic: {}", mnemonic.phrase());
assert_eq!(mnemonic.words().len(), 12);

// Generate 24-word mnemonic (256 bits entropy)
let mnemonic = Mnemonic::new(WordCount::Words24)?;
assert_eq!(mnemonic.words().len(), 24);
```

### Create from Entropy

```rust
use bsv_rs::compat::bip39::Mnemonic;

// All zeros produces the well-known test vector
let entropy = [0u8; 16]; // 128 bits = 12 words
let mnemonic = Mnemonic::from_entropy(&entropy)?;
assert_eq!(
    mnemonic.phrase(),
    "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
);

// All ones (0xff bytes)
let entropy = [0xffu8; 16];
let mnemonic = Mnemonic::from_entropy(&entropy)?;
assert_eq!(
    mnemonic.phrase(),
    "zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo wrong"
);
```

### Parse and Validate Existing Phrase

```rust
use bsv_rs::compat::bip39::Mnemonic;

let phrase = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
let mnemonic = Mnemonic::from_phrase(phrase)?;
assert!(mnemonic.is_valid());

// Handles multiple spaces and case normalization
let phrase = "ABANDON  Abandon   abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
let mnemonic = Mnemonic::from_phrase(phrase)?;
assert!(mnemonic.is_valid());
```

### Convert to Seed

```rust
use bsv_rs::compat::bip39::Mnemonic;

let phrase = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
let mnemonic = Mnemonic::from_phrase(phrase)?;

// With passphrase (TREZOR test vector)
let seed = mnemonic.to_seed("TREZOR");
assert_eq!(
    hex::encode(seed),
    "c55257c360c07c72029aebc1b53c05ed0362ada38ead3e3e9efa3708e53495531f09a6987599d18264c1e1c92f2cf141630c7a3c4ab7c81b2f001698e7463b04"
);

// Without passphrase
let seed = mnemonic.to_seed_normalized();
assert_eq!(seed.len(), 64);
```

### Extract Entropy

```rust
use bsv_rs::compat::bip39::Mnemonic;

let original = hex::decode("7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f")?;
let mnemonic = Mnemonic::from_entropy(&original)?;
let extracted = mnemonic.entropy();
assert_eq!(original, extracted);

// Extract entropy with checksum (Go SDK compatible)
let with_checksum = mnemonic.entropy_with_checksum();
// 128 bits entropy + 4 bits checksum = 132 bits = 17 bytes
assert_eq!(with_checksum.len(), 17);
```

### Binary Serialization

```rust
use bsv_rs::compat::bip39::Mnemonic;

let entropy = [0u8; 16];
let mnemonic = Mnemonic::from_entropy(&entropy)?;

// Serialize to binary (UTF-8 encoded phrase)
let binary = mnemonic.to_binary();

// Restore from binary
let restored = Mnemonic::from_binary(&binary)?;
assert_eq!(mnemonic.phrase(), restored.phrase());

// Parse directly from byte literal
let phrase = b"abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
let mnemonic = Mnemonic::from_binary(phrase)?;
assert!(mnemonic.is_valid());
```

### Multi-Language Mnemonics

```rust
use bsv_rs::compat::bip39::{Mnemonic, Language};

// Generate a Japanese mnemonic from entropy
let entropy = [0u8; 16];
let mnemonic = Mnemonic::from_entropy_with_language(&entropy, Language::Japanese)?;
// Japanese phrases use ideographic space (U+3000) as separator per BIP-39 spec
assert!(mnemonic.phrase().contains('\u{3000}'));

// Parse a non-English phrase back
let phrase = mnemonic.phrase();
let restored = Mnemonic::from_phrase_with_language(&phrase, Language::Japanese)?;
assert_eq!(mnemonic.entropy(), restored.entropy());

// All 9 languages supported: ChineseSimplified, ChineseTraditional, Czech,
// English (default), French, Italian, Japanese, Korean, Spanish
```

### Verify Wordlist Integrity

```rust
use bsv_rs::compat::bip39::verify_english_wordlist;

// Verifies the embedded wordlist matches BIP-39 specification
assert!(verify_english_wordlist());
```

## Algorithm Details

### Entropy to Mnemonic

1. Validate entropy length (128, 160, 192, 224, or 256 bits)
2. Compute SHA-256 hash of entropy
3. Append first `entropy_bits / 32` bits of hash as checksum
4. Split combined bits into 11-bit groups
5. Map each 11-bit value (0-2047) to corresponding word in wordlist

### Mnemonic to Seed

1. Normalize mnemonic phrase (see NFKD Normalization notes below)
2. Normalize passphrase
3. Apply PBKDF2-HMAC-SHA512:
   - Password: normalized mnemonic phrase
   - Salt: "mnemonic" + normalized passphrase
   - Iterations: 2048
   - Output length: 64 bytes

### Entropy Sizes

| Word Count | Entropy (bits) | Entropy (bytes) | Checksum (bits) | Total (bits) |
|------------|----------------|-----------------|-----------------|--------------|
| 12 | 128 | 16 | 4 | 132 |
| 15 | 160 | 20 | 5 | 165 |
| 18 | 192 | 24 | 6 | 198 |
| 21 | 224 | 28 | 7 | 231 |
| 24 | 256 | 32 | 8 | 264 |

## Error Handling

The module uses the SDK's unified error types:

```rust
// Invalid mnemonic phrase (wrong word count, invalid checksum)
Error::InvalidMnemonic(String)

// Entropy length not 128, 160, 192, 224, or 256 bits
Error::InvalidEntropyLength { expected: String, actual: usize }

// Word not found in wordlist
Error::InvalidMnemonicWord(String)

// Random number generation failed
Error::CryptoError(String)
```

## Implementation Notes

### NFKD Normalization

The implementation includes a simplified `NfkdNormalize` trait for Unicode normalization. The current behavior:

- **Go SDK**: Does NOT perform NFKD normalization (passes raw UTF-8 bytes)
- **TypeScript SDK**: DOES perform NFKD normalization via `String.normalize('NFKD')`
- **This implementation**: Matches Go SDK (no normalization, passes through unchanged)

For ASCII passphrases (recommended), all SDKs produce identical seeds. For non-ASCII passphrases, this implementation matches Go SDK but may differ from TypeScript SDK.

**Recommendation**: For maximum cross-SDK compatibility, use only ASCII characters in passphrases.

To add full NFKD Unicode normalization, add the `unicode-normalization` crate:
```rust
use unicode_normalization::UnicodeNormalization;
let normalized: String = input.nfkd().collect();
```

### Wordlists

Nine language wordlists are embedded as static arrays of 2048 strings (`[&str; 2048]`). Words are indexed 0-2047, corresponding to their 11-bit binary representation.

Supported wordlists: `CHINESE_SIMPLIFIED`, `CHINESE_TRADITIONAL`, `CZECH`, `ENGLISH`, `FRENCH`, `ITALIAN`, `JAPANESE`, `KOREAN`, `SPANISH`.

English wordlist integrity can be verified at runtime using `verify_english_wordlist()`, which checks:
- Array contains exactly 2048 words (enforced by type system: `[&str; 2048]`)
- First word is "abandon"
- Last word is "zoo"

### Japanese Separator

Per the BIP-39 specification, Japanese mnemonics use the ideographic space (U+3000) as the word separator instead of a regular ASCII space. The `Language::separator()` method handles this automatically. Note: the Go SDK uses regular space for all languages including Japanese; this implementation follows the BIP-39 spec.

### Thread Safety

`Mnemonic` is `Clone` but not `Copy` (contains `Vec<String>`). It can be safely shared across threads when wrapped in appropriate synchronization primitives.

Both `WordCount` and `Language` are `Copy + Clone + Debug + PartialEq + Eq`. `Language` additionally implements `Default` (defaulting to `English`).

## Dependencies

Internal SDK dependencies:
- `crate::primitives::hash::sha256` - Checksum calculation
- `crate::primitives::hash::pbkdf2_sha512` - Seed derivation
- `crate::Error` and `crate::Result` - Error types

External dependencies:
- `getrandom` - Cryptographically secure random number generation

## Cross-SDK Compatibility

This implementation produces identical results to:
- [BSV Go SDK](https://github.com/bitcoin-sv/go-sdk/tree/master/compat/bip39)
- [BSV TypeScript SDK](https://github.com/bitcoin-sv/ts-sdk)

Verified using official BIP-39 test vectors and TREZOR test vectors.

## Testing

```bash
# Run BIP-39 specific tests
cargo test --features compat bip39

# Run all compat module tests
cargo test --features compat
```

27 unit tests (23 in `mnemonic.rs`, 4 in `wordlists/mod.rs`) plus 29 integration tests in `compat_bip39_tests.rs`.

Test coverage includes:
- All word counts (12, 15, 18, 21, 24 words)
- Known test vectors (all zeros, all ones)
- TREZOR seed derivation test vector
- Entropy roundtrip validation
- Binary serialization roundtrip for all word counts
- Invalid inputs (wrong word count, bad checksum, invalid words, invalid entropy length)
- Invalid binary inputs (invalid UTF-8, invalid phrase)
- Wordlist integrity verification (all 9 languages verified to have 2048 words, first/last word checks)
- Multi-language mnemonic generation for all 9 languages
- Multi-language seed derivation (determinism, passphrase differentiation)
- Japanese ideographic space separator validation
- Non-English from_phrase roundtrip (entropy preservation across languages)
- Language default is English

## Related Documentation

- `../CLAUDE.md` - Parent compatibility module documentation
- `./wordlists/CLAUDE.md` - Wordlist submodule documentation
- `../../primitives/CLAUDE.md` - Cryptographic primitives used for hashing and PBKDF2
- `../../../tests/compat_bip39_tests.rs` - BIP-39 test vectors and cross-SDK compatibility tests
- `../../../tests/compat_integration_tests.rs` - Full workflow integration tests (BIP-39 + BIP-32)
