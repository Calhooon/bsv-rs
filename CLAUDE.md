# BSV SDK for Rust
> Official Rust implementation of the BSV blockchain SDK (~66,700 lines, 13 modules)

## Overview

Production-ready Rust SDK for BSV blockchain applications. API-compatible with the [TypeScript](https://github.com/bitcoin-sv/ts-sdk) and [Go](https://github.com/bitcoin-sv/go-sdk) SDKs. All crypto primitives are byte-for-byte compatible across all three SDKs.

## Module Structure

| Module | Feature | Depends On | Description |
|--------|---------|------------|-------------|
| `primitives` | `primitives` (default) | - | SHA-256, RIPEMD-160, HMAC, AES-256-GCM, secp256k1, P-256, BigNumber, encoding |
| `script` | `script` (default) | primitives | Script parsing, interpreter, P2PKH/P2PK/Multisig/RPuzzle/PushDrop templates |
| `transaction` | `transaction` | script | Transaction construction, signing, BEEF format, MerklePath SPV proofs |
| `wallet` | `wallet` | transaction | BRC-42 key derivation, ProtoWallet, WalletClient, wire protocol |
| `messages` | `messages` | wallet | BRC-77/78 signed and encrypted messaging |
| `compat` | `compat` | primitives | BIP-32 HD keys, BIP-39 mnemonics, BSM, ECIES |
| `totp` | `totp` | primitives | RFC 6238 Time-based One-Time Passwords |
| `auth` | `auth` | wallet, messages, tokio | BRC-31 mutual authentication, certificates (BRC-52/53) |
| `overlay` | `overlay` | wallet, tokio | SHIP/SLAP overlay network, topic broadcasting, STEAK |
| `storage` | `storage` | overlay | UHRP content-addressed file storage |
| `registry` | `registry` | overlay | On-chain definition registry for baskets/protocols/certificates |
| `kvstore` | `kvstore` | overlay | Blockchain-backed key-value storage (local encrypted + global public) |
| `identity` | `identity` | auth, overlay | Certificate-based identity resolution and contacts |

## Key Files

| Path | Purpose |
|------|---------|
| `Cargo.toml` | Package manifest with 15 feature flags |
| `src/lib.rs` | Crate root with module declarations and convenience re-exports |
| `src/error.rs` | Unified `Error` enum (54 variants) and `Result<T>` type alias |
| `tests/` | 21 integration test files (~711 test functions) |
| `tests/vectors/` | Cross-SDK test vectors (~2,632 vectors: sighash, script, BRC-42, etc.) |
| `benches/` | 4 Criterion benchmark suites (hash, primitives, memory, script) |
| `fuzz/` | 4 libfuzzer fuzz targets (script, transaction, wire protocol, encoding) |
| `.github/workflows/ci.yml` | CI: test matrix, clippy, rustfmt, doc build, benchmark regression |

## Feature Flags

```toml
default = ["primitives", "script"]
full = ["primitives", "script", "transaction", "wallet", "messages", "compat",
        "totp", "auth", "overlay", "storage", "registry", "kvstore", "identity"]
http = ["dep:reqwest"]       # HTTP clients for ARC, WhatsOnChain, WalletClient
wasm = ["getrandom/js"]      # WebAssembly support
dhat-profiling = ["dep:dhat"] # Heap profiling
```

Feature dependency graph:
```
primitives ─── script ─── transaction ─── wallet ─┬── messages
    │                                              ├── overlay ─┬── storage
    ├── compat                                     │            ├── registry
    ├── totp                                       │            ├── kvstore
    │                                              │            └──┐
    └───────────────────────── auth (wallet+messages+tokio) ───── identity (auth+overlay)
```

## Building & Testing

```bash
cargo build                          # Default features (primitives + script)
cargo build --features full          # All modules
cargo test                           # Default feature tests
cargo test --features full           # Full test suite (~1,941 tests, 0 failures)
cargo test --features full -- wallet # Filter by module name
cargo bench --bench primitives_bench # Run specific benchmark
cargo bench                          # All benchmarks
```

## Architecture Notes

- **Sighash computation** lives in script templates (not transaction module) - deliberate design matching Go/TS SDKs
- **Script templates** implement `ScriptTemplate` trait for locking and `ScriptTemplateUnlock` for signing
- **Overlay module** has request coalescing via `tokio::sync::watch` - unique to Rust SDK
- **KVStore** uses per-key locking via `tokio::sync::oneshot` channels for atomic operations
- **Storage** wallet auth is optional (vs mandatory in Go/TS) - intentional lightweight design
- **Error type** implements `Clone + PartialEq + Eq` for easy test assertions
- **Wire protocol** (`wallet::wire`) handles binary serialization for all wallet interface types

## Cross-SDK Compatibility

Byte-for-byte compatible with Go and TS SDKs. Key details:
- BRC-42 key derivation, BEEF format, sighash preimage all identical
- UHRP URLs, wire protocol, admin tokens all compatible
- Go SDK defaults counterparty to `Anyone`; Rust/TS use `Self_` in `create_signature`
- Go SDK is missing: TOTP module, overlay caching/historian/reputation, RPuzzle template
- TS SDK bug: TOTP default digits=2 (should be 6, Rust has it correct)
- Reference SDKs: Go at `~/bsv/go-sdk/`, TS at `~/bsv/ts-sdk/src/`

## Testing Details

| Category | Count |
|----------|-------|
| Unit tests (in-module) | ~1,158 |
| Integration tests | ~711 across 21 files |
| Doc tests | ~159 |
| Sighash vectors | 500 |
| Script valid/invalid vectors | 1,030 |
| Spend vectors | 458 |
| BRC-42/auth/overlay vectors | 39 |
| **Total** | **~1,941 tests + 2,632 vectors** |

## Fuzzing

```bash
# Install cargo-fuzz, then:
cd fuzz && cargo fuzz run fuzz_script_parser
cargo fuzz run fuzz_transaction_parser
cargo fuzz run fuzz_wire_protocol
cargo fuzz run fuzz_base58
```

## Dependencies (Key)

| Crate | Purpose |
|-------|---------|
| `k256` | secp256k1 ECDSA (signing, verification, key derivation) |
| `p256` | P-256/secp256r1 ECDSA |
| `aes-gcm` | AES-256-GCM symmetric encryption |
| `sha2`, `sha1`, `ripemd` | Hash functions |
| `num-bigint` | Big integer arithmetic for script OP_NUM |
| `tokio` | Async runtime (optional, for auth/overlay modules) |
| `reqwest` | HTTP client (optional, for broadcasters/chain trackers) |
| `serde` / `serde_json` | Serialization |
| `thiserror` | Error derive macros |

## Module Documentation (CLAUDE.md files)

Each module has its own CLAUDE.md with detailed API docs, usage examples, and internal design notes:

- `src/CLAUDE.md` - Source root, error types, re-exports
- `src/primitives/CLAUDE.md` - Primitives (+ `ec/CLAUDE.md`, `bsv/CLAUDE.md`)
- `src/script/CLAUDE.md` - Script (+ `templates/CLAUDE.md`)
- `src/transaction/CLAUDE.md` - Transaction (+ `broadcasters/`, `fee_models/`, `chain_trackers/`)
- `src/wallet/CLAUDE.md` - Wallet (+ `wire/CLAUDE.md`, `substrates/CLAUDE.md`)
- `src/messages/CLAUDE.md` - Messages
- `src/compat/CLAUDE.md` - Compat (+ `bip39/CLAUDE.md`, `bip39/wordlists/CLAUDE.md`)
- `src/totp/CLAUDE.md` - TOTP
- `src/auth/CLAUDE.md` - Auth (+ `transports/`, `certificates/`, `utils/`)
- `src/overlay/CLAUDE.md` - Overlay
- `src/storage/CLAUDE.md` - Storage
- `src/registry/CLAUDE.md` - Registry
- `src/kvstore/CLAUDE.md` - KVStore
- `src/identity/CLAUDE.md` - Identity
- `tests/CLAUDE.md` - Tests (+ `transaction/vectors/CLAUDE.md`)
- `benches/CLAUDE.md` - Benchmarks

## Workflow Tips

- Always use `--features full` when testing or checking the complete codebase
- The `Result<T>` type alias in `error.rs` means you write `Result<T>` not `Result<T, Error>`
- Script template pattern: implement `ScriptTemplate::lock()` for locking, provide `unlock()` returning `ScriptTemplateUnlock` with signing closure and length estimator
- When adding new error variants, gate with `#[cfg(feature = "module")]` and follow existing naming
- Cross-SDK test vectors in `tests/vectors/` are the source of truth for compatibility
- CI runs clippy with `-D warnings` - fix all warnings before pushing
