# BSV SDK for Rust
> Official Rust implementation of the BSV blockchain SDK

## Overview

This is the Rust implementation of the BSV SDK, providing a complete toolkit for building BSV applications. It is designed to be API-compatible with the TypeScript and Go SDKs.

## Module Structure

| Module | Status | Description |
|--------|--------|-------------|
| `primitives` | Complete | Cryptographic primitives (hash, EC, encoding) |
| `script` | In Progress | Script parsing, execution, templates |
| `transaction` | Planned | Transaction construction and signing |
| `wallet` | Planned | HD wallets, BIP-32/39/44 |

## Files

| File | Purpose |
|------|---------|
| `Cargo.toml` | Package manifest with feature flags |
| `src/lib.rs` | Crate root, module declarations |
| `src/error.rs` | Unified error types |
| `src/primitives/` | Cryptographic primitives module |
| `src/script/` | Script module |
| `src/transaction/` | Transaction module (future) |
| `src/wallet/` | Wallet module (future) |

## Feature Flags

```toml
[features]
default = ["primitives", "script"]
primitives = []
script = ["primitives"]
transaction = ["script"]
wallet = ["transaction"]
full = ["primitives", "script", "transaction", "wallet"]
wasm = ["getrandom/js"]
```

## Building

```bash
# Build with default features
cargo build

# Build with all features
cargo build --features full

# Build for WASM
cargo build --target wasm32-unknown-unknown --features wasm
```

## Testing

```bash
# Run all tests
cargo test

# Run tests for specific module
cargo test primitives
cargo test script
```

## Cross-SDK Compatibility

This SDK maintains byte-for-byte compatibility with:
- [BSV TypeScript SDK](https://github.com/bitcoin-sv/ts-sdk)
- [BSV Go SDK](https://github.com/bitcoin-sv/go-sdk)

All implementations share test vectors to ensure cross-platform compatibility.

## Related Documentation

- `src/primitives/CLAUDE.md` - Primitives module documentation
- `src/primitives/ec/CLAUDE.md` - Elliptic curve module documentation
- `SCRIPT_MIGRATION_PROMPTS.md` - Migration prompts for Script module
