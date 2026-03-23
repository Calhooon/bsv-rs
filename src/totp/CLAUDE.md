# TOTP Module
> Time-based One-Time Password (RFC 6238) for two-factor authentication

## Overview

This module provides Time-based One-Time Password (TOTP) functionality following RFC 6238 and RFC 4226 (HOTP). It enables generating and validating time-based passcodes commonly used for two-factor authentication (2FA). The implementation supports multiple HMAC algorithms (SHA-1, SHA-256, SHA-512) and uses constant-time comparison to prevent timing attacks during validation.

**Status**: Complete - RFC 6238 compliant with cross-SDK compatibility verified.

## Files

| File | Lines | Purpose |
|------|-------|---------|
| `mod.rs` | ~42 | Module root with documentation and re-exports |
| `core.rs` | ~934 | Core TOTP implementation with extensive tests |

## Key Exports

```rust
// HMAC algorithm selection
pub enum Algorithm {
    Sha1,    // Default, most compatible
    Sha256,  // Stronger security
    Sha512,  // Maximum security
}

// Generation options
pub struct TotpOptions {
    pub digits: u32,              // Number of digits (default: 6)
    pub algorithm: Algorithm,     // HMAC algorithm (default: Sha1)
    pub period: u64,              // Time period in seconds (default: 30)
    pub timestamp: Option<u64>,   // Override timestamp for testing
}

// Validation options (extends TotpOptions)
pub struct TotpValidateOptions {
    pub options: TotpOptions,     // Base options
    pub skew: u32,                // Periods to check before/after (default: 1)
}

// Main implementation
pub struct Totp;

impl Totp {
    // Generate a TOTP code
    pub fn generate(secret: &[u8], options: Option<TotpOptions>) -> String;

    // Validate a TOTP code with skew window
    pub fn validate(secret: &[u8], passcode: &str, options: Option<TotpValidateOptions>) -> bool;
}
```

## Usage Examples

### Basic Generation and Validation

```rust
use bsv_rs::totp::{Totp, TotpOptions, Algorithm};

// Shared secret (typically from base32-decoded QR code)
let secret = b"12345678901234567890";

// Generate a 6-digit code with defaults
let code = Totp::generate(secret, None);
println!("Current TOTP: {}", code);

// Validate the code
assert!(Totp::validate(secret, &code, None));

// Invalid codes are rejected
assert!(!Totp::validate(secret, "000000", None));
```

### Using Different Algorithms

```rust
use bsv_rs::totp::{Totp, TotpOptions, Algorithm};

let secret = b"12345678901234567890123456789012"; // Longer secret for SHA-256

// SHA-256 with 8 digits
let options = TotpOptions {
    digits: 8,
    algorithm: Algorithm::Sha256,
    ..Default::default()
};
let code = Totp::generate(secret, Some(options));
assert_eq!(code.len(), 8);
```

### Testing with Fixed Timestamp

```rust
use bsv_rs::totp::{Totp, TotpOptions};

let secret = b"12345678901234567890";

// RFC 6238 test vector at time=59 seconds
let options = TotpOptions {
    digits: 8,
    timestamp: Some(59),
    ..Default::default()
};
let code = Totp::generate(secret, Some(options));
assert_eq!(code, "94287082");
```

### Custom Skew for Clock Drift

```rust
use bsv_rs::totp::{Totp, TotpOptions, TotpValidateOptions};

let secret = b"12345678901234567890";
let code = Totp::generate(secret, None);

// Accept codes from 2 periods before/after (60 seconds of drift)
let validate_options = TotpValidateOptions {
    options: TotpOptions::default(),
    skew: 2,
};
assert!(Totp::validate(secret, &code, Some(validate_options)));
```

## Algorithm Details

### RFC 4226 (HOTP) Base Algorithm

TOTP is built on HOTP with time-based counter:

1. **Counter calculation**: `counter = floor(unix_seconds / period)`
2. **HMAC computation**: `HMAC(secret, counter)` where counter is 8-byte big-endian
3. **Dynamic truncation**: `offset = hmac[len-1] & 0x0F`
4. **Code extraction**: 4 bytes at offset, masked with `0x7FFFFFFF`
5. **Digit reduction**: `code % 10^digits`, zero-padded

### Time Handling

- Timestamps are Unix time in **seconds** (not milliseconds)
- Default period is 30 seconds
- Counter = `timestamp / period` (integer division)

### Skew Window

The `skew` parameter allows validation to accept codes from adjacent time periods:

| Skew | Accepted Counters | Time Tolerance |
|------|-------------------|----------------|
| 0 | current | 0 |
| 1 | current +/- 1 | +/- 30 seconds |
| 2 | current +/- 2 | +/- 60 seconds |

## RFC 6238 Test Vectors

The implementation passes all RFC 6238 Appendix B test vectors:

| Time (sec) | SHA-1 (8-digit) | SHA-256 (8-digit) | SHA-512 (8-digit) |
|------------|-----------------|-------------------|-------------------|
| 59 | 94287082 | 46119246 | 90693936 |
| 1111111109 | 07081804 | 68084774 | 25091201 |
| 1111111111 | 14050471 | 67062674 | 99943326 |
| 1234567890 | 89005924 | 91819424 | 93441116 |
| 2000000000 | 69279037 | 90698825 | 38618901 |
| 20000000000 | 65353130 | 77737706 | 47863826 |

**Note**: Different secrets are used for each algorithm per RFC 6238:
- SHA-1: `"12345678901234567890"` (20 bytes)
- SHA-256: `"12345678901234567890123456789012"` (32 bytes)
- SHA-512: `"1234567890...1234"` (64 bytes)

## Cross-SDK Compatibility

Compatible with TypeScript SDK (`@bsv/sdk`):

| TypeScript | Rust |
|------------|------|
| `TOTP.generate(secret, options)` | `Totp::generate(secret, options)` |
| `TOTP.validate(secret, passcode, options)` | `Totp::validate(secret, passcode, options)` |
| `'SHA-1'` / `'SHA-256'` / `'SHA-512'` | `Algorithm::Sha1` / `Algorithm::Sha256` / `Algorithm::Sha512` |

**Important differences**:
- TypeScript uses milliseconds for timestamp, Rust uses seconds
- TypeScript trims trailing digits with `.slice(-digits)`, Rust uses modulo

Cross-SDK test vectors from TypeScript SDK pass:
- `secret = 0x48656c6c6f21deadbeef`, `time = 0` => `"282760"`
- `secret = 0x48656c6c6f21deadbeef`, `time = 1465324707` => `"341128"`
- `secret = 0x48656c6c6f21deadbeef`, `time = 1365324707` => `"089029"` (leading zero)

## Security Considerations

1. **Secret Length**: Use at least 16 bytes (128 bits) of high-entropy secret
2. **Constant-Time Comparison**: Validation uses `subtle::ConstantTimeEq` to prevent timing attacks
3. **Rate Limiting**: Consider implementing rate limiting on validation attempts
4. **Secure Transmission**: Codes should only be transmitted over secure channels
5. **SHA-1 Warning**: While SHA-1 is the default for compatibility, SHA-256/512 provide better security margins

## Feature Flag

Enable the TOTP module:

```toml
[dependencies]
bsv-rs = { version = "0.3", features = ["totp"] }
```

The `totp` feature is included in `full`:

```toml
[dependencies]
bsv-rs = { version = "0.3", features = ["full"] }
```

## Dependencies

- `subtle` - Constant-time comparison
- `sha1`, `sha2` - Hash algorithms (via primitives)
- `hmac` - HMAC implementation (via primitives)

## Testing

```bash
# Run TOTP tests
cargo test --features totp totp

# Run with all features
cargo test --features full totp
```

## Internal Functions

The module includes private helper functions used internally:

| Function | Purpose |
|----------|---------|
| `generate_hotp` | RFC 4226 HOTP algorithm implementation |
| `current_unix_seconds` | Gets current Unix timestamp |
| `constant_time_eq` | Timing-attack-resistant string comparison |

## Related Documentation

- [Primitives Module](../primitives/CLAUDE.md) - HMAC functions used by TOTP (`sha1_hmac`, `sha256_hmac`, `sha512_hmac`)
- [RFC 6238](https://datatracker.ietf.org/doc/html/rfc6238) - TOTP specification
- [RFC 4226](https://datatracker.ietf.org/doc/html/rfc4226) - HOTP specification
