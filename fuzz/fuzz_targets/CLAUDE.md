# Fuzz Targets
> Fuzz testing harnesses for crash-safety validation of BSV SDK parsers and decoders

## Overview

This directory contains `libfuzzer`-based fuzz targets that feed arbitrary byte sequences into the SDK's parsing and decoding functions. The goal is to verify that no input—no matter how malformed—causes a panic, out-of-bounds access, or other undefined behavior. Each target also validates encoding/decoding roundtrips where possible.

## Files

| File | Purpose |
|------|---------|
| `fuzz_base58.rs` | Fuzzes Base58, Base58Check, hex, and Base64 decoding plus encode/decode roundtrips |
| `fuzz_script_parser.rs` | Fuzzes `Script::from_binary` and `Script::from_hex`, exercises type detection and serialization; a script `PushDrop::decode` reads goes through the deprecated `KVStoreInterpreter::verify_signature_legacy` under its lock key and its controller field's key, whose `true` must come only for five or six fields whose controller field is the key checked (with the base's always-`true` body planted, the committed seed `corpus/fuzz_script_parser/script-valid-584`, a P2PK script and so a PushDrop of no fields, copied byte for byte from the `0.9.0-beta` line's `corpus-gen` output, fails it) |
| `fuzz_transaction_parser.rs` | Fuzzes `Transaction::from_binary`, `from_hex`, `from_ef`, `from_hex_ef`, `from_reader`, sighash `parse_transaction`, and `MerklePath::from_binary`; a transaction `from_binary` returns serializes to exactly its buffer (#840) |
| `fuzz_beef_parser.rs` | Fuzzes `Beef::from_binary` against the hinted parse and the streaming reader (`verify_stream_structure`: a verdict on any bytes, no root accepted without a header), links every subject (`find_atomic_transaction`), serializes, clones and drops it, then `verify_valid`, the round trip, `Transaction::from_beef` and `from_atomic_beef` |
| `fuzz_wire_protocol.rs` | Fuzzes `WireReader` deserialization of varint, string, counterparty, protocol ID, and raw bytes |
| `fuzz_signature_der.rs` | Fuzzes `Signature::from_der` (the reference's `Signature.fromDER`, #842) and `TransactionSignature::from_checksig_format`: an accepted DER has exactly the length its sequence header names, its lengths in the short form and S ending the input; an accepted checksig input is its last byte's scope over an accepted DER; the input's leading 64 bytes as (R, S), written by `to_der` and `to_checksig_format`, read back equal. Seeds `fuzz/corpus/fuzz_signature_der/` (98, taken from beta: 77 from `tests/vectors/signature_der_842.json`, its 36 DER cells with and without a scope byte and five of its six reader inputs, thirteen certificate signatures of beta's #305 vector, this crate's signer's DER over eight digests) |

## Target Details

### fuzz_base58

Tests encoding primitives in `bsv_rs::primitives`:
- Decoding: `from_base58`, `from_base58_check`, `from_hex`, `from_base64` with arbitrary UTF-8 input
- Roundtrip: `to_base58` -> `from_base58` asserts decoded bytes match original
- Roundtrip: `to_hex` -> `from_hex` asserts decoded bytes match original

### fuzz_script_parser

Tests `bsv_rs::script::Script`:
- `Script::from_binary` with arbitrary bytes, then roundtrip via `to_binary`
- Exercises `is_p2pkh()`, `is_p2pk()`, `is_p2sh()`, `is_data()`, `is_multisig()` type detectors
- Exercises `to_asm()`, `to_hex()`, `chunks()` serialization methods
- `Script::from_hex` with arbitrary UTF-8 input

### fuzz_transaction_parser

Tests transaction-level parsing:
- `bsv_rs::primitives::bsv::sighash::parse_transaction` — low-level sighash transaction parser
- `bsv_rs::transaction::Transaction::from_binary`: full transaction parsing; the transaction serializes to exactly the buffer and rebuilt from its fields to the same bytes and txid (#840: a byte after the lock time was kept and hashed until then)
- `bsv_rs::transaction::Transaction::from_reader`: one transaction from the front; its bytes are the prefix read, and `from_binary` accepts the buffer exactly when nothing is left (#840)
- `bsv_rs::transaction::Transaction::from_hex`: the buffer's hex, lower and upper case, reads to `from_binary`'s verdict and txid, the hex cache lower case (#840)
- `bsv_rs::transaction::Transaction::from_ef`, `from_hex_ef`: an accepted EF buffer is exactly what `to_ef` writes back, its plain bytes read back to its txid, and the hex door agrees (#840)
- `bsv_rs::transaction::MerklePath::from_binary` — Merkle path parsing with roundtrip via `to_binary()`

### fuzz_wire_protocol

Tests `bsv_rs::wallet::wire::WireReader` deserialization:
- `read_var_int()` — variable-length integer decoding
- `read_string()` — length-prefixed string decoding
- `read_optional_string()` — optional string decoding
- `read_counterparty()` — counterparty enum deserialization
- `read_protocol_id()` — protocol ID tuple deserialization
- `read_optional_protocol_id()` — optional protocol ID deserialization
- `read_bytes(n)` — raw byte slice reading (capped at 1024 bytes)

Each method is tested with a fresh `WireReader` instance to independently fuzz each code path.

## Usage

Requires [`cargo-fuzz`](https://github.com/rust-fuzz/cargo-fuzz) (which uses `libfuzzer-sys`):

```bash
# Install cargo-fuzz
cargo install cargo-fuzz

# List available targets
cargo fuzz list

# Run a specific target
cargo fuzz run fuzz_base58
cargo fuzz run fuzz_script_parser
cargo fuzz run fuzz_transaction_parser
cargo fuzz run fuzz_wire_protocol

# Run with a time limit (seconds)
cargo fuzz run fuzz_base58 -- -max_total_time=60

# Run with a specific corpus directory
cargo fuzz run fuzz_script_parser corpus/fuzz_script_parser
```

The fuzz crate depends on `bsv-rs` with the `full` feature flag enabled (see `fuzz/Cargo.toml`), so all modules are available to all targets.

## Related

- `../Cargo.toml` — Fuzz crate manifest, defines binary targets and `full` feature dependency
- `src/primitives/CLAUDE.md` — Base58/hex/Base64 encoding functions being fuzzed
- `src/script/CLAUDE.md` — Script parsing and type detection being fuzzed
- `src/transaction/CLAUDE.md` — Transaction and MerklePath parsing being fuzzed
- `src/wallet/wire/CLAUDE.md` — Wire protocol reader being fuzzed
