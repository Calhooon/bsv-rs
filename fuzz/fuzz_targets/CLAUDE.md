# Fuzz Targets
> Fuzz testing harnesses for crash-safety validation of BSV SDK parsers and decoders

## Overview

This directory contains `libfuzzer`-based fuzz targets that feed arbitrary byte sequences into the SDK's parsing and decoding functions. The goal is to verify that no input, no matter how malformed, causes a panic, out-of-bounds access, or other undefined behavior. Each target also validates encoding/decoding roundtrips where possible.

## Files

Each target's assertion is "returns, never panics"; the column says where a target also checks a round trip or a bound. Its seeds are `fuzz/corpus/<target>/`, written by `fuzz/corpus-gen` from the tree's vectors (byte for byte on a rerun: the signed and encrypted messages' seeds and the Shamir shares' take a fixed key id, IV and coefficients through `sign_with`, `encrypt_with` and `split_private_key_with`, bsv-rs#180); the nightly runs each for an hour (`docs/NIGHTLY.md`).

| Target | What it reads | Also checks | Seeds |
|---|---|---|---|
| `fuzz_base58` | Base58, Base58Check, hex, Base64 decoding | encode then decode is the input | a WIF, an address, hex, Base64 |
| `fuzz_script_parser` | `Script::from_binary`, `from_hex`; the type detectors, `to_asm` | | `script_valid.json`'s locking scripts |
| `fuzz_transaction_parser` | `Transaction::from_binary`, sighash `parse_transaction`, `MerklePath::from_binary` | | `tx_valid.rs`, `bigtx.rs` |
| `fuzz_beef_parser` | the two entry points, `Beef::from_binary` then `verify_structure` and `verify_stream_structure` under the leading roots, which must agree (accepted with the same roots, or refused with the same kind and offset), an input written ahead of its parent refused by both (bsv-rs#86); `Beef::from_binary` against the hinted parse; the streaming reader under no headers (no root accepted), then under headers that carry every root (`verify_stream_structure` and `verify_stream`, so the reader walks past the BUMPs to the later doors); `find_atomic_transaction` on every subject, `verify_valid`, `from_beef`, `from_atomic_beef` | the hinted and the plain parse agree | the Lean's 47 rows (`tests/vectors/beef_of_any_size/`), the cross-SDK BEEFs, `atomic-beef.json`, and one seed per refusal this crate's `Kind` names (the Lean's `Reason` in `BeefOfAnySize.lean`, and `DuplicateOffset` and `LeftDuplicateBelow` ahead of their constructors there, bsv-rs#86, #167; `LeftDuplicateBelow` by a written door, no byte mutation reaching it: all 26 reached, `corpus-gen` prints the census) |
| `fuzz_chain_primitives` | `BlockHeader`, CompactSize, `ChainWork`, `CompactTarget`, `merkle_root` | header and work round trips | the genesis header |
| `fuzz_wire_protocol` | `WireReader`'s field readers | | the wallet-wire vectors' parameters |
| `fuzz_merkle_path` | `MerklePath::from_binary`, `from_hex`; `compute_root` for each txid, `combine`, `trim`, `contains_and_mark` | the bytes reparse to themselves, the root per txid is the reparsed path's | `bump_valid.rs`, `bump_invalid.rs`, BRC-74, the Lean rows' BUMPs |
| `fuzz_wire_decoders` | the BRC-100 binary substrate per call, the call chosen by the leading byte: even, the frame to `WalletWireProcessor::process_message` over a `ProtoWallet` (the request decoders; the processor decodes the requests of 13 calls, the 15 action, output and certificate calls answer "requires a full wallet implementation" before they read); odd, `data[1]` picks one of the transceiver's 26 calls and the rest is its answer (the result decoders) | the processor never returns `Err` | the wallet-wire vectors (`tests/vectors/wallet_wire/`), an error frame per call |
| `fuzz_http_json_responses` | `HttpWalletJson`'s response decoding for each of its 28 calls (the status, the busy word, the error body, `Retry-After`, the JSON result), answered by a loopback listener in the process: byte 0 the call, byte 1 the status, byte 2 a `Retry-After` header | | each result vector's JSON at 200, a busy body at 503 with `Retry-After`, an error body at 400, a bare 502 |
| `fuzz_bip32` | `ExtendedKey::from_string`, `new_master` (the input as a seed), `derive_path` (the input as a path), `derive_public_keys_for_path`, every accessor | a parsed key prints the string it parsed from; a printed key parses back | masters, neutered keys and children on both networks, paths |
| `fuzz_ecies` | every Electrum and Bitcore decryptor, binary and base64 | the input as a plaintext round-trips through each scheme (one case skipped for #109) | envelopes written by each encryptor |
| `fuzz_script_spend` | an unlocking and locking script pair through `Spend` under the block and the standard word (byte 0: the word, the era, the version; bytes 1-2 the unlocking length), a work budget of 50,000 and a memory budget of 1 MiB | a counting allocator: no single allocation over twice the budget and no more than four times it live, plus a term linear in the input; never a verdict | the sibling harness's seed rows (`bsv-script-lean/corpus/seed/seed.jsonl`), one per family in git (75), the rest under `/Volumes/Lanes/out/bsv-rs/oracle-fuzz/corpus/`; `script_valid.json`, `spend_valid.json` |
| `fuzz_auth_messages` | `AuthMessage` from JSON (as the HTTP and WebSocket transports read it, and as the Socket.IO transport reads an event's second argument), `validate`, `signing_data`, key ids; the Engine.IO and Socket.IO frames; the General message's `HttpRequest`/`HttpResponse` payloads; `Certificate` from bytes and JSON; `RequestedCertificateSet`; the auth headers; a nonce's format | payload, certificate and frame encodings reparse to themselves (every decoded Socket.IO frame since #110: its encoding reads back to the packet); a requested set's JSON is a fixed point, `types` in insertion order (#288) | messages of each type, certificates from `auth_certificate.json`, frames, payloads, written by this crate; `socketio-event-long-float`, the #280 run's crash input kept as found (a 107-digit number in an event, #285); `socketio-connect-id-110` and `socketio-connect-nan-id-110`, #110's two inputs kept as found |
| `fuzz_messages_signed` | BRC-77's `messages::verify`: the input as a signature over a fixed message, for the fixed recipient, for anyone and for another key | the reader decodes no value; the input as a message, `sign`ed for the recipient and for anyone (version and sender in place), verifies as true | signatures written by `sign` with the target's fixed keys (bytes 6, 7, 8), each also cut to 102 bytes |
| `fuzz_messages_encrypted` | BRC-78's `messages::decrypt`: the input as a ciphertext, for the fixed recipient and another key | a plaintext's length is the frame's (the input less header, IV and tag); the input as a plaintext, `encrypt`ed, decrypts to itself (the writer's key id and IV are random, so its bytes are not compared) | ciphertexts written by `encrypt` to the recipient and to another key |
| `fuzz_bsm` | `compat::bsm`: the leading 65 bytes as a compact signature over the rest (`recover_public_key_from_signature`, `verify_message`), the input as DER (`verify_message_der`), a base64 signature and its message on two lines | a recovered key verifies for its own address; the input as a message, signed at both compressions, recovers the key and the compression and signs the same bytes again (RFC 6979) | signatures by the fixed key (bytes 9) over the crate's test messages in both shapes, a DER signature, the TypeScript SDK's "hello world" signature (`src/compat/bsm.rs`) |
| `fuzz_bip39` | `Mnemonic::from_phrase_with_language` in each of the nine languages, `from_binary`, `from_entropy` | the canonical form: a phrase prints a phrase that parses to the same words and whose entropy writes it again; an entropy's phrase parses back to the same bytes | TREZOR's vectors and the Go SDK's bad sentences (`tests/compat_bip39_tests.rs`), each entropy as a phrase of every language, the phrases upper-cased and re-spaced |
| `fuzz_shamir_backup` | `KeyShares::from_backup_format`, one share per line, then `recover_private_key` (up to 32 shares) | the canonical form: the parsed shares write lines that parse to the same shares and write the same lines; the input's hash as a key, split and written, parses and recovers that key | 3-of-5, 2-of-3 and 5-of-8 backups by `split_private_key`, a threshold's subset, one share short, a threshold mismatch, a zero point |

`support/mod.rs` holds the arguments of each wallet call (the serde-shaped ones read from the Go vectors, reshaped to this crate's serde form until #105 is ruled) and `call_shared!`, which both response-decoder targets use.

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
- `bsv_rs::primitives::bsv::sighash::parse_transaction`: low-level sighash transaction parser
- `bsv_rs::transaction::Transaction::from_binary`: full transaction parsing with roundtrip via `to_binary`, `id()`, and `to_hex()`
- `bsv_rs::transaction::MerklePath::from_binary`: Merkle path parsing with roundtrip via `to_binary()`

### fuzz_wire_protocol

Tests `bsv_rs::wallet::wire::WireReader` deserialization:
- `read_var_int()`: variable-length integer decoding
- `read_string()`: length-prefixed string decoding
- `read_optional_string()`: optional string decoding
- `read_counterparty()`: counterparty enum deserialization
- `read_protocol_id()`: protocol ID tuple deserialization
- `read_optional_protocol_id()`: optional protocol ID deserialization
- `read_bytes(n)`: raw byte slice reading (capped at 1024 bytes)

Each method is tested with a fresh `WireReader` instance to independently fuzz each code path.

## Usage

Requires [`cargo-fuzz`](https://github.com/rust-fuzz/cargo-fuzz) (which uses `libfuzzer-sys`):

```bash
# Install cargo-fuzz
cargo install cargo-fuzz

# List available targets
cargo fuzz list

# Run a target from its seeds for ten minutes
cargo +nightly fuzz run fuzz_merkle_path fuzz/corpus/fuzz_merkle_path -- -max_total_time=600

# Keep going past a crash (each crash input lands in fuzz/artifacts/<target>/)
cargo +nightly fuzz run fuzz_auth_messages -- -fork=1 -ignore_crashes=1 -max_total_time=600

# Rewrite the seeds from the vectors (and the sibling's rows, with the rest out of git)
cargo run --release --manifest-path fuzz/corpus-gen/Cargo.toml -- --rest /Volumes/Lanes/out/bsv-rs/oracle-fuzz/corpus
```

On a macOS host whose default SDK the linker cannot read (`ld: tapi error: malformed file`), build with `SDKROOT=/Library/Developer/CommandLineTools/SDKs/MacOSX26.5.sdk`.

The fuzz crate depends on `bsv-rs` with `full` and `http` (see `fuzz/Cargo.toml`), so every module and the HTTP substrate are available to every target.

## Related

- `../Cargo.toml`: Fuzz crate manifest, defines binary targets and `full` feature dependency
- `src/primitives/CLAUDE.md`: Base58/hex/Base64 encoding functions being fuzzed
- `src/script/CLAUDE.md`: Script parsing and type detection being fuzzed
- `src/transaction/CLAUDE.md`: Transaction and MerklePath parsing being fuzzed
- `src/wallet/wire/CLAUDE.md`: Wire protocol reader being fuzzed
