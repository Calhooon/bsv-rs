# Elliptic Curve Cryptography (secp256k1)
> ECDSA signing, verification, key derivation, and BRC-42 for Bitcoin SV

## Overview

This module provides secp256k1 elliptic curve operations for Bitcoin SV, including ECDSA digital signatures with BIP 62 low-S compliance, WIF (Wallet Import Format) encoding, P2PKH address generation, ECDH shared secret computation, and BRC-42 hierarchical key derivation. All cryptographic operations use the `k256` crate with RFC 6979 deterministic nonce generation.

## Files

| File | Purpose |
|------|---------|
| `mod.rs` | Module root; re-exports `PrivateKey`, `PublicKey`, `Signature`, `sign`, `verify`, `recover_public_key` |
| `private_key.rs` | secp256k1 private key: generation, WIF encoding, signing, ECDH, BRC-42 child derivation |
| `public_key.rs` | secp256k1 public key: serialization, address generation, verification, BRC-42 child derivation |
| `signature.rs` | ECDSA signature: DER/compact encoding, low-S normalization (BIP 62) |
| `ecdsa.rs` | Standalone ECDSA functions: `sign`, `verify`, `recover_public_key`, `calculate_recovery_id` |

## Key Exports

### PrivateKey

A 32-byte secp256k1 scalar in range [1, n-1]. Automatically zeros memory on drop.

```rust
pub struct PrivateKey {
    // Construction
    pub fn random() -> Self                           // CSPRNG via OsRng
    pub fn from_bytes(bytes: &[u8]) -> Result<Self>   // 32 bytes exactly
    pub fn from_hex(hex: &str) -> Result<Self>        // 64 hex chars
    pub fn from_wif(wif: &str) -> Result<Self>        // Base58Check (0x80 or 0xef prefix)

    // Export
    pub fn to_bytes(&self) -> [u8; 32]
    pub fn to_hex(&self) -> String
    pub fn to_wif(&self) -> String                    // Mainnet (0x80), compressed
    pub fn to_wif_with_prefix(&self, prefix: u8) -> String  // Custom version byte

    // Operations
    pub fn public_key(&self) -> PublicKey             // G * self
    pub fn sign(&self, msg_hash: &[u8; 32]) -> Result<Signature>  // RFC 6979, low-S
    pub fn derive_shared_secret(&self, other_pubkey: &PublicKey) -> Result<PublicKey>  // ECDH
    pub fn derive_child(&self, other_pubkey: &PublicKey, invoice_number: &str) -> Result<PrivateKey>  // BRC-42
}
```

### PublicKey

A point on the secp256k1 curve. Supports compressed (33 bytes) and uncompressed (65 bytes) formats.

```rust
pub struct PublicKey {
    // Construction
    pub fn from_bytes(bytes: &[u8]) -> Result<Self>   // 33 or 65 bytes
    pub fn from_hex(hex: &str) -> Result<Self>        // Compressed or uncompressed
    pub fn from_private_key(private_key: &PrivateKey) -> Self

    // Serialization
    pub fn to_compressed(&self) -> [u8; 33]           // 02/03 || X
    pub fn to_uncompressed(&self) -> [u8; 65]         // 04 || X || Y
    pub fn to_hex(&self) -> String                    // Compressed hex
    pub fn to_hex_uncompressed(&self) -> String

    // Coordinates
    pub fn x(&self) -> [u8; 32]                       // Big-endian X coordinate
    pub fn y(&self) -> [u8; 32]                       // Big-endian Y coordinate
    pub fn y_is_even(&self) -> bool                   // Determines 02 vs 03 prefix

    // Address generation
    pub fn hash160(&self) -> [u8; 20]                 // RIPEMD160(SHA256(compressed))
    pub fn to_address(&self) -> String               // P2PKH mainnet (version 0x00)
    pub fn to_address_with_prefix(&self, version: u8) -> String  // Custom version

    // Verification
    pub fn verify(&self, msg_hash: &[u8; 32], signature: &Signature) -> bool

    // ECDH and key derivation
    pub fn mul_scalar(&self, scalar: &[u8; 32]) -> Result<PublicKey>  // Point * scalar
    pub fn derive_shared_secret(&self, other_privkey: &PrivateKey) -> Result<PublicKey>  // ECDH
    pub fn derive_child(&self, other_privkey: &PrivateKey, invoice_number: &str) -> Result<PublicKey>  // BRC-42
}
```

### Signature

ECDSA signature with R and S components (32 bytes each).

```rust
pub struct Signature {
    // Construction
    pub fn new(r: [u8; 32], s: [u8; 32]) -> Self
    pub fn from_der(der: &[u8]) -> Result<Self>       // Variable length DER
    pub fn from_compact(data: &[u8; 64]) -> Result<Self>  // Fixed 64 bytes
    pub fn from_compact_slice(data: &[u8]) -> Result<Self>

    // Access
    pub fn r(&self) -> &[u8; 32]
    pub fn s(&self) -> &[u8; 32]

    // Serialization
    pub fn to_der(&self) -> Vec<u8>                   // Always outputs low-S
    pub fn to_compact(&self) -> [u8; 64]              // R || S

    // BIP 62 compliance
    pub fn is_low_s(&self) -> bool                    // S <= n/2
    pub fn to_low_s(&self) -> Signature               // Convert if needed

    // Verification
    pub fn verify(&self, msg_hash: &[u8; 32], public_key: &PublicKey) -> bool
}
```

### ECDSA Functions

```rust
pub fn sign(msg_hash: &[u8; 32], private_key: &PrivateKey) -> Result<Signature>
pub fn verify(msg_hash: &[u8; 32], signature: &Signature, public_key: &PublicKey) -> bool
pub fn recover_public_key(msg_hash: &[u8; 32], signature: &Signature, recovery_id: u8) -> Result<PublicKey>
pub fn calculate_recovery_id(msg_hash: &[u8; 32], signature: &Signature, public_key: &PublicKey) -> Result<u8>
```

## Usage

### Key Generation and Signing

```rust
use bsv_primitives::ec::{PrivateKey, sign, verify};
use bsv_primitives::hash::sha256;

// Generate random key pair
let private_key = PrivateKey::random();
let public_key = private_key.public_key();

// Sign a message
let msg_hash = sha256(b"Hello, BSV!");
let signature = private_key.sign(&msg_hash).unwrap();

// Signature is always low-S (BIP 62)
assert!(signature.is_low_s());

// Verify
assert!(public_key.verify(&msg_hash, &signature));
```

### WIF Encoding (Wallet Import/Export)

```rust
use bsv_primitives::ec::PrivateKey;

// Parse WIF
let wif = "KwDiBf89QgGbjEhKnhXJuH7LrciVrZi3qYjgd9M7rFU73sVHnoWn";
let key = PrivateKey::from_wif(wif).unwrap();

// Export to WIF
assert_eq!(key.to_wif(), wif);  // Mainnet (0x80)
let testnet_wif = key.to_wif_with_prefix(0xef);  // Testnet
```

### Address Generation

```rust
use bsv_primitives::ec::PrivateKey;

let key = PrivateKey::from_hex(
    "0000000000000000000000000000000000000000000000000000000000000001"
).unwrap();
let pubkey = key.public_key();

// P2PKH address (mainnet)
let address = pubkey.to_address();
assert_eq!(address, "1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH");

// Testnet address
let testnet_addr = pubkey.to_address_with_prefix(0x6f);
```

### ECDH Shared Secret

```rust
use bsv_primitives::ec::PrivateKey;

let alice = PrivateKey::random();
let bob = PrivateKey::random();

// Both parties compute the same shared secret
let alice_shared = alice.derive_shared_secret(&bob.public_key()).unwrap();
let bob_shared = bob.derive_shared_secret(&alice.public_key()).unwrap();

assert_eq!(alice_shared.to_compressed(), bob_shared.to_compressed());
```

### BRC-42 Key Derivation

```rust
use bsv_primitives::ec::PrivateKey;

let alice_priv = PrivateKey::random();
let bob_priv = PrivateKey::random();
let invoice = "payment-12345";

// Bob derives child private key using Alice's public key
let bob_child_priv = bob_priv.derive_child(&alice_priv.public_key(), invoice).unwrap();

// Alice derives corresponding child public key using Bob's public key
let bob_child_pub = bob_priv.public_key().derive_child(&alice_priv, invoice).unwrap();

// They arrive at the same public key
assert_eq!(bob_child_priv.public_key().to_compressed(), bob_child_pub.to_compressed());
```

### Public Key Recovery

```rust
use bsv_primitives::ec::{PrivateKey, sign, recover_public_key};
use bsv_primitives::hash::sha256;

let key = PrivateKey::random();
let pubkey = key.public_key();
let msg_hash = sha256(b"Hello!");
let signature = sign(&msg_hash, &key).unwrap();

// Try both recovery IDs (0 or 1)
for recovery_id in 0..2 {
    if let Ok(recovered) = recover_public_key(&msg_hash, &signature, recovery_id) {
        if recovered.to_compressed() == pubkey.to_compressed() {
            // Found the correct recovery ID
            break;
        }
    }
}
```

## BRC-42 Key Derivation Algorithm

The BRC-42 key derivation enables hierarchical deterministic key generation between two parties:

**Private Key Derivation:**
1. Compute ECDH shared secret: `shared = other_pubkey * self`
2. Compute HMAC: `hmac = HMAC-SHA256(key=compressed_shared_secret, data=invoice_number)`
3. Derive new key: `new_key = (self + hmac) mod n`

**Public Key Derivation:**
1. Compute ECDH shared secret: `shared = self * other_privkey`
2. Compute HMAC: `hmac = HMAC-SHA256(key=compressed_shared_secret, data=invoice_number)`
3. Compute offset point: `offset = G * hmac`
4. Derive new key: `new_pubkey = self + offset`

The HMAC parameter order matches the Go SDK (`sha256_hmac(key, data)`).

## DER Signature Format

```
0x30 <total_len>
  0x02 <r_len> <r_bytes>
  0x02 <s_len> <s_bytes>
```

- R and S are minimal DER integers (no leading zeros unless high bit is set)
- Leading 0x00 added when high bit is set (to indicate positive number)
- `to_der()` always produces low-S form

## Security Notes

- **Private Key Zeroization**: `k256::SecretKey` automatically zeros memory on drop
- **Debug Output**: PrivateKey debug shows only the public key, not the secret
- **Constant-Time Comparison**: PrivateKey equality uses `subtle::ConstantTimeEq`
- **RFC 6979**: Deterministic nonce prevents k-reuse vulnerabilities
- **BIP 62 Low-S**: Prevents transaction malleability; S normalized to <= n/2

## Dependencies

- `k256` - secp256k1 elliptic curve operations (RustCrypto)
- `subtle` - Constant-time operations
- Internal: `BigNumber` for BRC-42 scalar arithmetic, `hash::sha256_hmac` for HMAC

## Related

- [../CLAUDE.md](../CLAUDE.md) - Parent module overview, hash functions, encoding utilities
- `BigNumber` in `../bignum.rs` - Arbitrary-precision integers for EC scalars
- `hash::sha256_hmac` in `../hash.rs` - HMAC-SHA256 for BRC-42 derivation
