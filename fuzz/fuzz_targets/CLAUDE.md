# Fuzz Targets
> Fuzz testing harnesses for crash-safety validation of BSV SDK parsers and decoders

## Overview

This directory contains `libfuzzer`-based fuzz targets that feed arbitrary byte sequences into the SDK's parsing and decoding functions. The goal is to verify that no input, no matter how malformed, causes a panic, out-of-bounds access, or other undefined behavior. Each target also validates encoding/decoding roundtrips where possible.

## Files

Each target's assertion is "returns, never panics"; the column says where a target also checks a round trip or a bound. Its seeds are `fuzz/corpus/<target>/`, written by `fuzz/corpus-gen` from the tree's vectors (byte for byte on a rerun: the signed and encrypted messages' seeds and the Shamir shares' take a fixed key id, IV and coefficients through `sign_with`, `encrypt_with` and `split_private_key_with`, bsv-rs#180, the Shamir coordinate draws too since #854); the nightly runs each for an hour (`docs/NIGHTLY.md`).

| Target | What it reads | Also checks | Seeds |
|---|---|---|---|
| `fuzz_base58` | Base58, Base58Check, hex, Base64 decoding | encode then decode is the input | a WIF, an address, hex, Base64 |
| `fuzz_script_parser` | `Script::from_binary`, `from_hex`; the type detectors, `to_asm`; the seven write methods | the cache law of `Script` (#843d1, `tests/script_cache_agreement_843d1.rs`): before an edit the bytes are the bytes given, whatever the order of the reads, and the hex is the bytes' hex; after each of up to eight edits through the seven write methods, chosen by the input's bytes, the bytes are the chunks' serialization and the hex theirs; a clone taken before the edits still answers the bytes given; a text `from_hex` reads answers itself lower-cased | `script_valid.json`'s locking scripts |
| `fuzz_transaction_parser` | `Transaction::from_binary`, `from_hex`, `from_ef`, `from_hex_ef`, `Transaction::from_reader`, sighash `parse_transaction`, `MerklePath::from_binary`, `Cursor::from_binary` (including BSC5 work totals, #519) | transaction, merkle path and cursor serialization/reparse; a transaction `from_binary` returns serializes to exactly its buffer, its fields to the same bytes and txid, and `from_reader`'s bytes are the prefix it read, `from_binary` accepting exactly the buffers it reads whole (#840); `from_hex` of the buffer's hex in either case agrees with `from_binary`, a transaction `from_ef` returns writes the buffer back through `to_ef` and its plain bytes to its txid, `from_hex_ef` agrees with `from_ef`, arbitrary text through both hex doors never panics (#840's fold); no transaction `from_binary`, `from_reader` or `from_ef` accepts holds an output amount, or an EF source amount, of 2^53 or more (#844); #843's IDENTITY law under up to six edits through the doors chosen by the input's bytes, after each `id()` the hash of the target's own serialization of the fields and a fresh parse of `to_binary()` the same id (`support/identity_law.rs`, #869's fold) | `tx_valid.rs`, `bigtx.rs` |
| `fuzz_beef_parser` | the two entry points, `Beef::from_binary` then `verify_structure` and `verify_stream_structure` under the leading roots, which must agree (accepted with the same roots, or refused with the same kind and offset), an input written ahead of its parent refused by both (bsv-rs#86); `Beef::from_binary` against the hinted parse; the streaming reader under no headers (no root accepted), then under headers that carry every root (`verify_stream_structure` and `verify_stream`, so the reader walks past the BUMPs to the later doors); `find_atomic_transaction` on every subject, `verify_valid`, `from_beef`, `from_atomic_beef` | the hinted and the plain parse agree; `merge_beef`'s pre-pass verdict is the literal round trip's (`Beef::merge_snapshot_oracle`, built under cargo-fuzz's `cfg(fuzzing)`), the same `Ok` with the merged bytes the snapshot's or the same `Err`, on every BEEF parsed and sixteen states built from it by the input's bytes (seven refused BUMP shapes, a contradicting BUMP ahead of a refused one, a bad word, a 62-digit txid-only entry, a `tx_mut` edit; #621; and a parsed entry caching a held transaction twice, by `merge_transaction` and a hand push, built through `Transaction::with_cached_bytes_for_test`, `#[doc(hidden)]` under `cfg(any(test, feature = "internal-test-doors"))`, the feature `fuzz/Cargo.toml` turns on (#869's fold; `cfg(any(test, fuzzing))` until then, as `merge_snapshot_oracle` still is), since #840's `from_binary` refuses the buffer; #621's fold, its second fold: with `own_refusal`'s parsed-cache scan removed the target fails on its seeds; and an output of 2^53 satoshis or more, its amount from the input's bytes, in an entry edited through `edit_tx`, a hand-built transaction merged by `merge_transaction` and one pushed by hand, #844: the run of #844 found the hand-pushed one, never hashed, taken on trust by the writers' check, kept as found as `issue-844-hand-pushed-entry-amount-unchecked`); #843's IDENTITY law on every linked subject under the same edits as `fuzz_transaction_parser`'s, its linked sources included (`support/identity_law.rs`, #869's fold) | the Lean's 47 rows (`tests/vectors/beef_of_any_size/`), the cross-SDK BEEFs, `atomic-beef.json`, and one seed per refusal this crate's `Kind` names (the Lean's `Reason` in `BeefOfAnySize.lean`, and `DuplicateOffset` and `LeftDuplicateBelow` ahead of their constructors there, bsv-rs#86, #167; `LeftDuplicateBelow` by a written door, no byte mutation reaching it: all 26 reached, `corpus-gen` prints the census); `fold4-869-shared-text-edit` (#869's fourth fold), a V2 BEEF of a proven parent and its child whose bytes choose the identity law's shared-text edit on the linked child (the version byte two edits, the BUMP height's low byte 13), so the linker keyed by the raw text again fails on it at once, where five runs of 60 s from the other seeds did not reach it |
| `fuzz_chain_primitives` | `BlockHeader`, CompactSize, `ChainWork`, `CompactTarget`, `merkle_root` | header and work round trips | the genesis header |
| `fuzz_wire_protocol` | `WireReader`'s field readers and `InternalizeOutput`'s JSON intake, including null remittances (#393); #473 adds action/output/spend/insertion/result-array readers and in-memory height/page/create/sign/prove response reads via `support/wire_bounds_473.rs`; #487 adds signature/certificate/list and both linkage calls through `support/wire_results_487.rs`; #495 adds both discovery answers, completing all eleven result-validation paths | | the wallet-wire vectors' parameters; #393's null-remittance vector can seed the JSON intake |
| `fuzz_merkle_path` | `MerklePath::from_binary`, `from_hex`; `compute_root` for each txid, `combine`, `trim`, `contains_and_mark` | the bytes reparse to themselves, the root per txid is the reparsed path's | `bump_valid.rs`, `bump_invalid.rs`, BRC-74, the Lean rows' BUMPs |
| `fuzz_wire_decoders` | the BRC-100 binary substrate per call, the call chosen by the leading byte: even, the frame to `WalletWireProcessor::process_message` over a `ProtoWallet` (the request decoders; the processor decodes the requests of 13 calls, the 15 action, output and certificate calls answer "requires a full wallet implementation" before they read); odd, `data[1]` picks one of the transceiver's 26 calls and the rest is its answer (the result decoders) | above 256 MiB, the processor returns #505's exact `Err(WalletError)`; at or below the cap, every failure is framed | the wallet-wire vectors (`tests/vectors/wallet_wire/`), an error frame per call |
| `fuzz_http_json_responses` | `HttpWalletJson`'s response decoding for each of its 28 calls (the status, the busy word, the error body, `Retry-After`, the JSON result), built with the originator `fuzz.invalid` (a call with none is refused unsent, #323), answered by a loopback listener in the process: byte 0 the call, byte 1 the status, byte 2 a `Retry-After` header | | each result vector's JSON at 200, a busy body at 503 with `Retry-After`, an error body at 400, a bare 502 |
| `fuzz_bip32` | `ExtendedKey::from_string`, `new_master` (the input as a seed), `derive_path` (the input as a path), `derive_public_keys_for_path`, every accessor | a parsed key prints the string it parsed from; a printed key parses back | masters, neutered keys and children on both networks, paths |
| `fuzz_ecies` | every Electrum and Bitcore decryptor, binary and base64 | the input as a plaintext within 16 MiB round-trips through each scheme, every Electrum envelope with and without a key (#109); a plaintext above the reference's bound is refused (#333) | envelopes written by each encryptor; the #109 plaintext (`plain-32-bsv-rs-109`) |
| `fuzz_script_spend` | an unlocking and locking script pair through `Spend` under the block and the standard word (byte 0: the word, the era, the version; bytes 1-2 the unlocking length), a work budget of 50,000 and a memory budget of 1 MiB; the allocator, budgets and bounds are `spend/mod.rs`, shared with `fuzz_script_spend_default` (#398) | a counting allocator: no single allocation over twice the budget and no more than four times it live, plus six for one arithmetic opcode's big-number working memory, which the budget leaves out by design as the node's `limitedstack.cpp` and the reference's `Spend.ts:1562-1573` do (8.5 times the operands for a quotient, measured; a tolerance, not a budget miss; #348's shape is held by `tests/script_budget_before_allocation_348.rs`, bsv-rs#348), plus a term linear in the input; a reservation (an allocation freed before the allocator's next call: the step probe's `try_reserve_exact`, #374) is out of both reads: sized by operands already charged and freed before the step, still granted by the allocator (#331, the keeper's pick); never a verdict | the sibling harness's seed rows (`bsv-script-lean/corpus/seed/seed.jsonl`), one per family in git (75), the rest under `/Volumes/Lanes/out/bsv-rs/oracle-fuzz/corpus/`; `script_valid.json`, `spend_valid.json`; `9a3a2a98…` and `4810ebb9…`, the probe's two crash inputs on the single read kept as found (a 2,680,794-byte and a 2,414,844-byte `OP_MUL` reservation), and twelve on the live read (3.57 to 5.73 MB reservations, `OP_DIV` at 12 times), #331's fifth fold; `01e75c4f…` and `53ee39e8…`, #348's and #349's inputs kept as found; eight kept as found by #383 (`3c8497a5…`, `44d4c72f…`, `4914d789…`, `d44dc981…`, `e91f18e1…`, `ed740084…`, `27c51236…`, `e36fe93d…`), the huge counts and sizes written into an error's text at `bb80a525` and the live peak #331 brought under its bound, clean since #349 and #331; `3093a215…`, a 68-byte script's `OP_DIV` of a 1,015,808-byte square by a 7-byte number's 128th power, the working set `ARITHMETIC_WORKING_SET` covers |
| `fuzz_script_spend_default` | the same pair and layout through `Spend` in the default mode, no `set_flags` (the reference's verdicts; bsv-rs#398): byte 0's bit 2 the version, bit 3 the budget (1 MiB, or 128 MiB, where an operand past the reference's 536,870,888-bit read figure fits; under 1 MiB #331's inputs are declines), bits 0-1 read nothing | `fuzz_script_spend`'s allocator and bounds (`spend/mod.rs`), scaled to the budget chosen; never a verdict; the nightly builds it with `-s none` (under ASan an 8 MiB squaring chain's resident set passes libFuzzer's 2,048 MB limit, 133 MB without) | `fuzz_script_spend`'s 678 seeds, copied (bit 3 clear); six for the default mode's own verdicts: `issue-383-lshift-…` and `issue-383-rshift-count-above-int-max` (`shift count exceeds INT_MAX.`), `issue-382-left-nine-byte-length-twos-complement` and `issue-382-num2bin-size-above-int32-max` (the splice reader's and `OP_NUM2BIN`'s words), `issue-331-lshift-result-past-the-read-figure` and `issue-331-operand-past-the-read-figure` (`Invalid string length`, bit 3 set); the word target evaluates none of these in the default mode |
| `fuzz_auth_messages` | `AuthMessage` from JSON (as the HTTP and WebSocket transports read it, and as the Socket.IO transport reads an event's second argument), `validate`, `signing_data`, key ids; the Engine.IO and Socket.IO frames; the General message's `HttpRequest`/`HttpResponse` payloads; `Certificate` from bytes and JSON; `RequestedCertificateSet`; the auth headers; a nonce's format | payload, certificate and frame encodings reparse to themselves (every decoded Socket.IO frame since #110: its encoding reads back to the packet); a requested set's JSON is a fixed point, `types` in insertion order (#288) | messages of each type, certificates from `auth_certificate.json`, frames, payloads, written by this crate; `socketio-event-long-float`, the #280 run's crash input kept as found (a 107-digit number in an event, #285); `socketio-connect-id-110` and `socketio-connect-nan-id-110`, #110's two inputs kept as found |
| `fuzz_messages_signed` | BRC-77's `messages::verify`: the input as a signature over a fixed message, for the fixed recipient, for anyone and for another key | the reader decodes no value; the input as a message, `sign`ed for the recipient and for anyone (version and sender in place), verifies as true | signatures written by `sign` with the target's fixed keys (bytes 6, 7, 8), each also cut to 102 bytes |
| `fuzz_messages_encrypted` | BRC-78's `messages::decrypt`: the input as a ciphertext, for the fixed recipient and another key | a plaintext's length is the frame's (the input less header, IV and tag); the input as a plaintext, `encrypt`ed, decrypts to itself (the writer's key id and IV are random, so its bytes are not compared) | ciphertexts written by `encrypt` to the recipient and to another key |
| `fuzz_bsm` | `compat::bsm`: the leading 65 bytes as a compact signature over the rest (`recover_public_key_from_signature`, `verify_message`), the input as DER (`verify_message_der`), a base64 signature and its message on two lines | a recovered key verifies for its own address; the input as a message, signed at both compressions, recovers the key and the compression and signs the same bytes again (RFC 6979) | signatures by the fixed key (bytes 9) over the crate's test messages in both shapes, a DER signature, the TypeScript SDK's "hello world" signature (`src/compat/bsm.rs`) |
| `fuzz_bip39` | `Mnemonic::from_phrase_with_language` in each of the nine languages, `from_binary`, `from_entropy` | the canonical form: a phrase prints a phrase that parses to the same words and whose entropy writes it again; an entropy's phrase parses back to the same bytes | TREZOR's vectors and the Go SDK's bad sentences (`tests/compat_bip39_tests.rs`), each entropy as a phrase of every language, the phrases upper-cased and re-spaced |
| `fuzz_shamir_backup` | `KeyShares::from_backup_format` (BRC-140's, the reference's reader, #854), one share per line, then `recover_private_key` (up to 32 shares); `recover_private_key_from_legacy_backup` on the same lines (up to 32) | the reader is canonical: what it reads `to_backup_format` writes back as the very lines given; a set either reader takes holds no share at x = 0 and no repeated x, in the whole set (#854's security fix); the two forms are disjoint (the legacy reader refuses every set the standard reader reads, and the standard reader every set the legacy reader recovers); the input's hash as a key, split and written, parses back to the same lines and recovers that key | 3-of-5, 2-of-3 and 5-of-8 backups by `split_private_key_with` (fixed coefficients, seed and coordinate draws), a threshold's subset, one share short, a threshold mismatch, a zero point, BRC-140's example shares, a backup bsv-rs 0.8.5 wrote |
| `fuzz_signature_der` | `Signature::from_der` (the reference's `Signature.fromDER`, #842) and `TransactionSignature::from_checksig_format` | an accepted DER has exactly the length its sequence header names, its lengths in the short form and S ending the input; an accepted checksig input is its last byte's scope over an accepted DER; the input's leading 64 bytes as (R, S), both nonzero and S below the order, written by `to_der` (its low-S twin) and `to_checksig_format` and read back equal | the 42 DER cells of `tests/vectors/signature_der_842.json` (each also with a scope byte), the signatures of `auth_certificate_signature_der_305.json`, this crate's signer's DER over eight digests (98 seeds) |
| `fuzz_verify_input` | the one-input door (#855): byte 0 the mode (bit 0 a word, read by `ScriptFlags::from_bits` and `InputRules::under`; bits 1-3 the default mode's three overrides, bit 4 their value), bytes 1-4 the flag bits, byte 5 the index, bytes 6-13 the amount, bytes 14-15 the locking script's length, then the locking script and the spending transaction; `fuzz_script_spend`'s budgets (50,000 units, 1 MiB) | `SpendingTransaction::from_bytes` refuses exactly what `Transaction::from_binary` refuses, with its error, save a transaction whose only refusal there is an output amount of 2^53 or more (the bytes with every such amount made 0 read by `from_binary`), which the default mode answers in `from_binary`'s error at any index and a word judges (#874); the prepared form answers what the one-shot answers; a refusal before evaluation never reaches the interpreter (bytes refused: the one-shot's `Transaction` arm with the reader's error, whatever the index; an index past the inputs: `InputIndex`); a decline carries its budget, a verdict none | `spend_valid.json`'s pairs spent at versions 1 and 2 in the default mode and at version 2 under the post-Chronicle block word, and one seed per refusal before evaluation (653; `fuzz/corpus-gen -- --door-only` writes them alone) |

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
- The cache law (#843d1): `chunks()` read, then `to_binary()` the bytes given and `to_hex()` their hex; a clone given up to eight edits through the seven write methods (`write_opcode`, `write_bin`, `write_number`, `remove_codeseparators`, `find_and_delete`, `set_chunk_opcode`, `write_script`, each edit chosen by one of the input's leading bytes modulo 7), after each edit the bytes equal to `Script::from_chunks(chunks().to_vec()).to_binary()` and the hex theirs; a second clone, taken before the edits, still the bytes given
- `Script::from_hex` with arbitrary UTF-8 input: an accepted text answers the bytes' hex, the text lower-cased

### fuzz_transaction_parser

Tests transaction-level parsing:
- `bsv_rs::primitives::bsv::sighash::parse_transaction`: low-level sighash transaction parser
- `bsv_rs::transaction::Transaction::from_binary`: full transaction parsing; the transaction serializes to exactly the buffer and rebuilt from its fields to the same bytes and txid (#840: a byte after the lock time was kept and hashed until then)
- `bsv_rs::transaction::Transaction::from_reader`: one transaction from the front; its bytes are the prefix read, and `from_binary` accepts the buffer exactly when nothing is left (#840)
- `bsv_rs::transaction::Transaction::from_hex`: the buffer's hex, lower and upper case, reads to `from_binary`'s verdict and txid, the hex cache lower case (#840's fold)
- `bsv_rs::transaction::Transaction::from_ef`, `from_hex_ef`: an accepted EF buffer is exactly what `to_ef` writes back (fields read and written in one order, canonical varints, scripts held as read, the source amount and script on the placeholder source), its plain bytes read back to its txid, and the hex door agrees (#840's fold)
- No transaction a reader accepts holds an output amount, or an EF source amount, of 2^53 or more: the reference's readers refuse one (#844)
- `bsv_rs::transaction::MerklePath::from_binary`: Merkle path parsing with roundtrip via `to_binary()`
- `bsv_rs::transaction::Cursor::from_binary`: cursor parsing and serialization/reparse, including BSC5 charged work (#519)

### fuzz_wire_protocol

Tests `bsv_rs::wallet::wire::WireReader` deserialization:
- `read_var_int()`: variable-length integer decoding
- `read_string()`: length-prefixed string decoding
- `read_optional_string()`: optional string decoding
- `read_counterparty()`: counterparty enum deserialization
- `read_protocol_id()`: protocol ID tuple deserialization
- `read_optional_protocol_id()`: optional protocol ID deserialization
- `read_bytes(n)`: raw byte slice reading (capped at 1024 bytes)
- `Counterparty::from_hex`: UTF-8 encoded key validation before parsing (#420)

Each method is tested with a fresh `WireReader` instance to independently fuzz each code path.

#423 extends `fuzz_auth_messages` with `Response::from_authenticated_payload`
(the ID copied from the input so status/headers/body are reached) and
`parse_known_txids_header` and payment label decoding. The new seeds come directly from the Node 22 recorder's
parser cases in `tests/vectors/auth_fetch_423.json`.

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
