# BSV SDK for Rust
> Official Rust implementation of the BSV blockchain SDK

## Overview

This is the Rust implementation of the BSV SDK, providing a complete toolkit for building BSV applications. It is designed to be API-compatible with the TypeScript and Go SDKs.

## Module Structure

| Module | Status | Description |
|--------|--------|-------------|
| `primitives` | Complete | Cryptographic primitives (hash, EC, encoding) |
| `script` | Complete | Script parsing, execution, templates |
| `transaction` | Complete | Transaction construction and signing |
| `wallet` | Complete | BRC-42 key derivation, ProtoWallet, WalletClient |

## Files

| File | Purpose |
|------|---------|
| `Cargo.toml` | Package manifest with feature flags |
| `src/lib.rs` | Crate root, module declarations |
| `src/error.rs` | Unified error types |
| `src/primitives/` | Cryptographic primitives module |
| `src/script/` | Script module |
| `src/transaction/` | Transaction module |
| `src/wallet/` | Wallet module |

## Feature Flags

```toml
[features]
default = ["primitives", "script"]
primitives = []
script = ["primitives"]
transaction = ["script"]
wallet = ["transaction"]
wasm = ["getrandom/js"]
full = ["primitives", "script", "transaction", "wallet"]
http = ["dep:reqwest"]
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

### Module Documentation
- `src/CLAUDE.md` - Source root and error handling
- `src/primitives/CLAUDE.md` - Primitives module
- `src/primitives/ec/CLAUDE.md` - Elliptic curve submodule
- `src/primitives/bsv/CLAUDE.md` - BSV-specific primitives
- `src/script/CLAUDE.md` - Script module
- `src/script/templates/CLAUDE.md` - Script templates
- `src/transaction/CLAUDE.md` - Transaction module
- `src/transaction/fee_models/CLAUDE.md` - Fee calculation models
- `src/transaction/broadcasters/CLAUDE.md` - Transaction broadcasters
- `src/transaction/chain_trackers/CLAUDE.md` - Chain tracking
- `src/wallet/CLAUDE.md` - Wallet module
- `src/wallet/wire/CLAUDE.md` - Wire protocol types
- `src/wallet/substrates/CLAUDE.md` - Wallet substrates (HTTP, etc.)

### Test Documentation
- `tests/CLAUDE.md` - Integration tests and cross-SDK vectors
