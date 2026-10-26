# Integration Tests
> Cross-module and cross-SDK compatibility testing

## Overview

This directory contains integration tests that verify the BSV Rust SDK works correctly across modules and produces results identical to the TypeScript and Go SDK implementations. Tests use shared JSON test vectors to ensure byte-for-byte compatibility across all three SDK implementations.

**Total: 1,332 integration tests across 47 test files (`cargo test --features "full,http,websocket"` at `1eff2d0`, 2026-10-05: 3,014 passed with the 1,513 unit and 169 doc tests; the 5 `memory_profiling` tests run behind `dhat-profiling`, alone, outside the count) + 2,049 JSON test vectors across the twelve files below (README's 2,031 counts the JSON arrays' lengths: `overlay_types.json` is an object of six categories) + 54 wallet-wire message files + Rust constant vectors**

## Files

| File | Tests | Feature Gate | Description |
|------|------:|-------------|-------------|
| `arch_ci_runs_every_test.rs` | 6 | none | Every top-level `tests/*.rs` is run by a whole-suite `cargo test --tests` step of `.github/workflows/ci.yml` on a feature set its `#![cfg]` gate compiles under, or allowlisted with its reason and the `--test` step that runs it (`memory_profiling` alone); every `--test <name>` in ci.yml names an existing file its step compiles (`docs/ARCH-RULES.md` section 6, #146) |
| `arch_ci_lines.rs` | 7 | none | Beta carries everything main carries, main nothing beta did not bear (`RELEASING.md`, "The direction rule"): a commit is on a line by sha, by patch (`git cherry`) or by a `(cherry picked from commit <sha>)` link in either direction. ci.yml's `main-in-beta` runs on every PR into and push to beta and the sync branch's dispatch, with the whole history, and reads `git cherry HEAD origin/main` and the link; `beta-born` runs on every PR into main and lets a release commit through (Cargo.toml and CHANGELOG.md alone); `sync-main-into-beta.yml` fires on a push to main and `git cherry-pick -x`s each missing commit onto beta for a rebase merge, never a merge, a rebase or a squash, picks onto a branch holding beta's tip (M2), aborts a conflicting pick and never falls back to main's tip (M3), holds `issues: write` for its label (M1); no log piped into `grep -q`; both files a workflow's shape, every action pinned by sha; each check refuses its mutated file |
| `arch_ci_runs_every_test.rs` | 6 | none | Every top-level `tests/*.rs` is run by a whole-suite `cargo test --tests` step of `.github/workflows/ci.yml` on a feature set its `#![cfg]` gate compiles under, or allowlisted with its reason and the `--test` step that runs it (`memory_profiling` alone, `wire_tracing_sink` under `tracing`); every `--test <name>` in ci.yml names an existing file its step compiles (`docs/ARCH-RULES.md` section 6, #146) |
| `auth_cross_sdk_tests.rs` | 15 | `auth` | Certificate serialization cross-SDK vectors; `auth_certificate.json` vector 0's signature verifies under no reading (derived or raw key), and it is `@bsv/sdk`'s `fromObject` fixture's signature (ts-sdk@27a93752), verifying under BRC-52's derivation over the fixture's own 21-byte type and serial only (`auth_certificate_origin_252.json`, #252) |
| `auth_certificate_signature_251.rs` | 6 | `auth` | BRC-52's certificate signature (#251): the reference's `email` certificate verifies under the derived key (protocol `[2, "certificate signature"]`, keyID `"<type> <serial>"`, counterparty anyone), this crate's signer writes its bytes, a certificate signed here verifies in the reference (`ts-stack@edf6e03`, Node v22.18.0, `tests/support/certificate_signature_251.mjs`), a wrong signature `Ok(false)`, 0.9.0-beta.1's raw-key signature `Ok(false)` |
| `auth_integration_tests.rs` | 70 | `auth` | Session manager, AuthMessage, certificates, HTTP payloads, nonce handling |
| `auth_reader_bounds.rs` | 7 | `auth` | A length the bytes remaining cannot hold is refused, never wrapped past the check: the #108 input and `usize::MAX - k` through `Certificate::from_binary` (`ReaderUnderflow`), the HTTP payload fields at lengths that wrap or truncate on a 32-bit target, valid inputs unchanged (Calhooon/bsv-rs#108) |
| `auth_peer_e2e_tests.rs` | 21 | `auth` | BRC-31 peer mutual authentication end-to-end via loopback |
| `broadcaster_http_tests.rs` | 27 | `transaction`+`http` | ARC, WoC, Teranode broadcasters with wiremock; the ARC 2xx verdict vector served through wiremock (bsv-stack-lean #35, P0-2) |
| `chain_difficulty.rs` | 10 | `block` | The difficulty rule (`next_work_required`) on bitcoin-sv v1.2.3's `pow_tests.cpp` tables, the regimes' edges and the real testnet run 1602530..=1602710 (`chain_vectors/test_1602530_1602710.bin`, sha256 pinned) |
| `chaintracker_http_tests.rs` | 10 | `transaction`+`http` | WhatsOnChain chain tracker with wiremock |
| `transport_fault_broadcasters.rs` | 9 | `transaction`+`http` | ARC, Teranode, WhatsOnChain: a refused connection `NEVER_SENT`, a timeout after the body was written `MAY_HAVE_BEEN_RECEIVED` (#65's witness), a 429 with `Retry-After: 5` and a text body `RATE_LIMITED` with its wait (#66's witness), a bare 503, a 502 and a 504, a 503 with `Retry-After`, a 500 the service's word, a body cut from a raw stub `MAY_HAVE_BEEN_RECEIVED`; the code word, `txid`, `more` and `transport_fault()` (Calhooon/bsv-rs#87) |
| `transport_fault_trackers.rs` | 7 | `transaction`+`http` | WhatsOnChain and the headers service: a fault is an error, never `Ok(false)`: `ChainTrackerError::TransportFault` with its class, wait and status for a refused connection, a timeout, a body cut, a 429 and a bare 503, a 500 `InvalidResponse`; `Transaction::verify` carries it to `Error::TransportFault` (Calhooon/bsv-rs#87) |
| `transport_fault_wallet.rs` | 7 | `wallet`+`http` | `HttpWalletJson` and `HttpWalletWire`: `WalletTransport` for a refused connection, a timeout, a body cut and a bare 503, `WalletError` for a success body that is not JSON, `TransportFault` rate limited for a 429, `WalletBusy` for `STORE_BUSY` (Calhooon/bsv-rs#87) |
| `transport_fault_auth.rs` | 9 | `auth`+`http` | `SimplifiedFetchTransport` on both paths and the Socket.IO sink: `TransportFault` with its class for a refused connection, a reset, a body cut, a timeout (30 s, the transport's own), a 429, a 503; any other status stays `AuthError` (Calhooon/bsv-rs#87) |
| `compat_bip39_tests.rs` | 29 | `compat` | BIP-39 mnemonics with official TREZOR vectors |
| `compat_bip39_nfkd.rs` | 8 | `compat` | BIP-39's NFKD rule (bsv-rs#163): NFD French, Spanish and Korean phrases (decomposed by hand) accepted, printed in the list's NFC, seeding BIP-39's bytes as Python's `hashlib` and `unicodedata` compute them; the 24 Japanese vectors (`bip39_japanese.json`) written, read and seeded with their non-NFKD passphrases, and read again with ASCII spaces; a token NFKD splits (U+00B4) refused by its count; an NFD passphrase seeding as the NFC one; every word of the nine lists its own NFKC form (the lookup's premise) |
| `compat_integration_tests.rs` | 31 | `compat` | BIP-32/39, BSM, ECIES, Base58 workflows |
| `beef_atomic_graph.rs` | 15 | `transaction` | The atomic rule on the subject's graph (0.8.1, BRC-95): one atomic BEEF in each of its 364 orders the BRC-62 clause allows (the TS partition order, a raw unproven ancestor after its proven descendant, the subject not last), accepted by the stream (with and without scripts) and the whole path; an unrelated entry (raw proven, raw unproven, txid-only) refused at every position; a subject not raw in the BEEF `SubjectMissing`; `to_binary_atomic`'s output accepted by both readers; a cursor at every `k`; the Lean's W4 bytes still refused; the edges kept only under a subject (`entries` counts them); a BSC2 cursor read as BSC3 with no edge; an edge list out of order refused; the X/Y pair in both trie orders, the stream naming the earliest unreached entry at its offset (`Y` at 124, `X` at 187) and the vectors' bytes this crate's writer's; the atomic writer's BRC-95 closure (the ancestor behind a proof and an unrelated branch dropped, TS 3's rule modelled) and every accepted vector round-tripped through it |
| `beef_cycle.rs` | 6 | `transaction` | A ring of source links is refused in bounded time (#160): rings of two and three written by their input fields (a raw entry's txid is its bytes' hash, so only the fields can close a ring), a pair with one real link, every rotation and its reverse, with and without a BUMP that proves none, V1, V2 and atomic: `from_binary` parses, the stream (both modes), `verify_structure` and `verify_valid` refuse `InputNamesNoElement`; `from_atomic_beef` returns the subject unlinked and it does not verify; a chain of one, two and three whose `T0` is pointed at the last link through `BeefTx::tx_mut` is renamed and stays a chain (#171): linked `n - 1` deep, `to_binary_atomic` written, `sort_txs` naming `T0` missing, `verify_structure` refusing it, the round trip carrying the renamed entry; a ring set by hand in the public `input_txids` cache: `sort_txs` holds every link not valid with no input missing, `verify_structure` refuses it, `trim_known_proven` stops, the round trip writes the bytes read; each call on its own thread under 5 s with `catch_unwind` |
| `beef_tx_mut.rs` | 3 | `transaction` | An entry mutated through `BeefTx::tx_mut` is one thing to every reader (#171): an input repointed to another entry of the BEEF read by `sort_txs` (the cache the new input, the order after the new parent, the entry found by its new txid and not its old), by `verify_structure` in the order held, by `to_binary_atomic` (the closure the new parent and the subject) and by the writer (the mutated bytes, read back the same); an input repointed outside the BEEF a missing input; a proven entry mutated keeps its BUMP index and is refused `TxidNotInBump`, on the wire too |
| `beef_two_readers_agree.rs` | 8 | `transaction` | The two entry points on every BEEF the tree holds (fixtures, vectors, the Lean's rows, the fuzz seeds, the ts-stack corpus when `BSV_CONFORMANCE_DIR` is set, a deep chain) and on what the tests build from each (every prefix of a short input, three single-byte changes at every byte, the transactions reversed): `Beef::from_binary` then `verify_structure` and `verify_stream_structure` under the leading roots accept the same, refuse the rest with the same kind and, where the parse names one, the same offset; no stated difference: a transaction written ahead of its parent refused by both, `InputNamesNoElement` (the reversed v1 fixture); `BEEF_TWO_READERS_TABLE` writes the table; a BUMP above a `u32` height refused, not cut to its low bits; a repeated leaf offset (level 0 with the same hash, level 0 with a different node, a higher level, a BUMP held in memory) refused on both paths, `MismatchedNode` at the second leaf's offset varint (bsv-rs#86) |
| `merkle_path_two_readers_agree.rs` | 5 | `transaction` | The two readers of a BUMP on every BUMP the tree holds (the fixtures' and vectors' BUMPs and those of every BEEF there, the Rust vector constants, the ts-stack corpus when `BSV_CONFORMANCE_DIR` is set, the seeds of `fuzz_merkle_path` and `fuzz_beef_parser`, the lone-leaf and cost tests' BUMPs, flags 0 to 4, a height of 2^32) and its prefixes, single-byte changes and a byte appended: `MerklePath::from_reader` (and `from_binary`, `from_hex`) and the BEEF reader on the bytes as a one-BUMP BEEF accept the same, to the same bytes taken, height, levels and root from every txid, and refuse the rest with the same kind at the same offset (35,747 disagreements on 0.9.0's tree, 0 since); `MERKLE_PATH_TWO_READERS_TABLE` writes the table; a duplicate at an even offset refused by both readers at its flag, `BadFlag { byte: 1 }` (at level 2, a computed node's left child, and at level 0), and held in memory by `new`, `new_unchecked` and `verify_structure`, `compute_root` computing no node from it; a byte after the BUMP refused by `from_binary` and `from_hex` (`TrailingBytes` at its offset) and left by `from_reader`, the slice accepting exactly what the reader accepts whole on every input (bsv-rs#167) |
| `conformance_beef.rs` | 4 | `transaction` | The ts-stack conformance corpus's BUMP, serialization, BEEF and transaction-regression suites, every mismatch classified against pinned counts; reads `$BSV_CONFORMANCE_DIR` (default `../ts-stack/conformance`) and skips loudly without it; `sdk.transactions.atomic-beef` (BRC-95, six vectors) from the corpus when it carries the file, else from the staged `transaction/vectors/atomic-beef.json`, so it runs either way |
| `conformance_scripts.rs` | 2 | `transaction` | The corpus's script domain (5,116 evaluation vectors pinned, the sighash and script regressions) through `Spend`, the sighash builder and the `Script` API, every mismatch classified against pinned counts; the same corpus and skip |
| `cross_sdk_tests.rs` | 17 | default | BRC-42, symmetric encryption, WIF/address vectors |
| `drbg_tests.rs` | 6 | default | HMAC-DRBG with NIST SP 800-90A vectors |
| `ec_tests.rs` | 39 | default | Elliptic curve ops, BRC-42 derivation, ECDH, pubkey validation |
| `hash_stream.rs` | 3 | default | `Sha256` and `Sha256d` equal `sha256` and `sha256d` for every row of bsv-stack-lean's BEEF-of-any-size corpus (`vectors/beef_of_any_size/`, 47 committed rows, the 5 generated ones from `$BSV_RS_BEEF_ROWS_DIR`) in chunks of 1, 7, 64 KiB, whole and seeded random, and for generated buffers of 0 to 300,000 bytes |
| `identity_tests.rs` | 69 | `identity` | Certificates, contacts, queries, broadcast results |
| `identity_spend_witness.rs` | 3 | `identity` | The identity token signatures (the revocation, the contact update and removal) through `Spend` under the Chronicle block word: each path signs the dispatcher's digest, not one SHA-256 of the preimage (0.7.0's review) |
| `integration_tests.rs` | 25 | default | Full workflows: key derivation, Schnorr, Shamir, P-256; `split_private_key_with` returns the plain form's shares given its coefficients, refuses a count other than threshold less one and a coefficient 0 modulo p (bsv-rs#180) |
| `kvstore_global_tests.rs` | 85 | `kvstore` | GlobalKVStore: construction, CRUD, batch, interpreter |
| `kvstore_integration_tests.rs` | 93 | `kvstore` | LocalKVStore: config, entries, queries, batch ops |
| `live_policy_http_tests.rs` | 20 | `transaction`+`http` | LivePolicy dynamic fee model with wiremock |
| `memory_profiling.rs` | 7 | `dhat-profiling` | Heap allocation profiling for crypto operations; the streaming BEEF reader's peak heap at 1,000, 10,000 and 100,000 links, and on 100 proven transactions of 1,000 inputs with and without a subject (the edges, 0.8.1) |
| `messages_tests.rs` | 41 | `messages` | BRC-77 signing, BRC-78 encryption, cross-SDK vectors; `sign_with` and `encrypt_with` write the plain forms' bytes given the key id and IV read back from them, and the same bytes for fixed values (bsv-rs#180) |
| `overlay_admin_token_ts_parity_tests.rs` | 2 | `overlay` | Byte-exact parity of `create_signed_overlay_admin_token` with `@bsv/sdk 1.10.1`'s `pushdrop.lock` output (`overlay_admin_token_ts_parity.json`, 5 cases) |
| `overlay_cross_sdk_tests.rs` | 13 | `overlay` | Admin token and overlay type cross-SDK vectors |
| `overlay_http_tests.rs` | 49 | `overlay`+`http` | SHIP broadcast and SLAP lookup facilitators with wiremock |
| `overlay_integration_tests.rs` | 62 | `overlay` | Protocols, topics, reputation, historian, admin tokens, lookup resolver |
| `overlay_mock_tests.rs` | 20 | `full` | Mock facilitator tests for LookupResolver/TopicBroadcaster |
| `readme_examples.rs` | 1 | default | Every ```rust block of `README.md` that names an `examples/<name>.rs` file equals that file byte for byte, and every example appears in the README |
| `registry_integration_tests.rs` | 50 | `registry` | Definitions, queries, PushDrop roundtrips, cross-SDK |
| `script_vectors_tests.rs` | 13 | default | Script interpreter with 1,488 vectors (458+598+432) |
| `script_flags_witnesses.rs` | 9 | default | The flag words (`ScriptFlags::block` / `standard`, the default mode) on seven witness transactions: policy-as-consensus at version 1 (five), the NULLDUMMY version gate, NULLFAIL (Calhooon/bsv-rs#10) |
| `script_low_s_order_witness.rs` | 3 | default | A signature with `s` at the curve order is the zero signature for the low-S check and NULLFAIL under version 1, as on the reference (0.3.28, Calhooon/bsv-rs#14) |
| `script_undefined_hashtype_witness.rs` | 7 | default | An undefined base hash type (the CHRONICLE, FORKID and ANYONECANPAY bits cleared, the rest not ALL, NONE or SINGLE) refused under STRICTENC and in the default mode, on the witness (`0x44`), its siblings (`0x40`, `0x5f`) and the re-typed boundary cases (Calhooon/bsv-rs#23) |
| `script_sighash_dispatch_witness.rs` | 6 | default | The signature hash dispatched on the CHRONICLE bit (0x20) to the original digest, as the reference's `SignatureHash` does, on the witness and the 21-row table of the class; the bit illegal under a pre-Chronicle word (Calhooon/bsv-rs#22) |
| `script_shift_count_witness.rs` | 9 | default | The two bounds of `OP_LSHIFTNUM`/`OP_RSHIFTNUM` under a word, on the witness (`1 OP_RSHIFTNUM 2147483648`: a count above `INT_MAX` is the big-integer error; a left shift's result size is tested against the era's number length before the shift; the default mode shifts by any count) and its boundary cases (Calhooon/bsv-rs#21) |
| `script_int64_operand_witness.rs` | 8 | default | The `int64` reading of the `OP_SUBSTR`/`OP_LEFT`/`OP_RIGHT` operands under a word, on the witness (a 9-byte offset whose ninth byte is `0x80` is 4, as the reference reads the first 8 bytes of a 9-byte element and drops the ninth; the default mode keeps the script-number reading) and its boundary cases (Calhooon/bsv-rs#20) |
| `script_int64_fold_witness.rs` | 15 | default | The `int64` operand reader above 8 bytes as the node reads it (the specification's ruling R1; bsv-script-lean `docs/records/20261006-010651-r1-reading-public.md`): the seven cases of the record's section 3 by their ids (`00 x8 04 01` is 4, the later bytes OR-ed onto the low positions with period 8, the last byte dropped), the boundary lengths 8, 9, 10, 11, 17, 18 (11 through 15 and 18 and above unmeasured), `OP_LEFT`/`OP_RIGHT`, the default mode unchanged (0.3.32) |
| `script_num_length_witness.rs` | 4 | default | The script-number length limit of the coin's era under a word, on the witness (a 1,048,577-byte number read by `OP_1ADD`: overflow under the block word at 750,000 and the standard word at 10,000; valid in the default mode and for a coin created after Chronicle) (0.3.28, Calhooon/bsv-rs#17) |
| `script_residual_witnesses.rs` | 11 | default | The five consensus rules fixed in 0.3.27 on ten witness transactions of eight rules: truncated pushes, undefined opcodes, a second OP_ELSE, the post-Chronicle UTXO opcodes, FindAndDelete of a FORKID signature (Calhooon/bsv-rs#12) |
| `script_mutators_keep_parsed_chunks.rs` | 6 | default | Every in-place `Script` mutator parses before it invalidates the byte cache (0.3.25) |
| `resource_limits.rs` | 4 | default | A local interpreter budget is a `ScriptResourceLimit`, never a verdict; `OP_NUM2BIN` refuses before allocating (0.3.23); the default mode's budget, in CI since 0.3.30 |
| `script_stack_memory_witness.rs` | 28 | default | The node's stack memory budget under a word (bsv-rs#30): the differential's witnesses (a 32,000,001-byte number read, the left shifts at the number length's edge, a 40,000,000-byte element) under both words and the default mode; the budget's edges at the node's figures (100,000,000 bytes on the node's count, the two stacks shared, the unlocking script's alt stack left charged, the policy of 0, explicit budgets) and at small figures; `OP_NUM2BIN`'s `INT32_MAX` bound; its large rows run one at a time (about 100 MB at its peak) |
| `sighash_tests.rs` | 4 | default | Transaction sighash computation with 499 vectors |
| `storage_http_tests.rs` | 35 | `storage`+`http` | Uploader/downloader HTTP flows with wiremock |
| `storage_tests.rs` | 70 | `storage` | UHRP URLs, downloader/uploader config, cross-SDK |
| `template_tests.rs` | 22 | default | P2PKH, P2PK, Multisig, RPuzzle script templates |
| `transaction_tests.rs` | 104 | `transaction` | BEEF, MerklePath, fee models, construction, ancestry, SPV verify |
| `wallet_tests.rs` | 57 | `wallet` | KeyDeriver, CachedKeyDeriver, ProtoWallet, wire protocol |
| `wallet_internalize_validation_tests.rs` | 8 | `wallet` (`http` for one) | internalizeAction's basket insertion `customInstructions` bound: 1,000 UTF-8 bytes accepted, 1,001 refused with the field and the count, four-byte characters at the boundary, absence, the second output's index, the createAction copy unbounded, the ProtoWallet and HTTP JSON doors (Calhooon/bsv-rs#117) |
| `wallet_brc56_hmac_tests.rs` | 8 | `wallet` | BRC-56's six HMAC key vectors (`5119a9b` `wallet/0056.md:81-96`): the inputs from their labels, the six 32-byte keys and tags reproduced, the six accepted, the four minimal-length-key tags refused as `HmacMinimalLengthKey` (sync and async), the two keys with no leading zero byte with no refusal path, any other tag `HMAC is not valid` (#148) |
| `wallet_wire_cross_sdk_tests.rs` | 55 | `wallet` (`http` for 13) | Cross-SDK wire protocol vectors from Go SDK (54 vectors); every args vector sent through the processor to a recording wallet and compared to its json (bsv-rs#191: 6 of 27 pass, 21 in an enumerated allowlist with reasons, the count pinned), the two linkage requests read the privileged parameters ahead of the keys; every result vector's json answered by a stub wallet and the processor's response compared to its wire (bsv-rs#194: 8 of 27 pass, 19 in an enumerated allowlist with reasons, the count pinned; bsv-rs#197: 15 pass, the 12 refusal stubs left), the two linkage responses opening with the three keys; the seven result vectors of bsv-rs#197 written by the processor and read by the transceiver as their json, a false verdict an error frame; the verifyHmac, createSignature and verifySignature args vectors read by the processor as their json, a data-type flag of 3 refused (bsv-rs#199); the seven key-related args vectors read whole with the privileged pair and seekPermission (bsv-rs#193: 13 of 27 pass, the allowlist 14 refusal stubs, the count pinned) and written whole by the transceiver, byte for byte; a byte after a request's last field refused on 15 calls in the reference's words (bsv-rs#193) |
| `wire_codec_bench_bytes.rs` | 2 | `wallet` | The wire_codec bench's frames are #76's recordings: every call's request and result layout (`benches/wire_codec/support.rs`) reads both recorded cases exactly and re-encodes them byte for byte (a recorded error frame, the minimal verdicts of bsv-rs#197, through the error layout); the bench measures the `full` case of all 28 calls (#138) |
| `wire_method_roundtrip_tests.rs` | 104 | `wallet` | Wire protocol roundtrips for all 28 WalletInterface methods; an error frame code 1, the bare words, the stack 0 (bsv-rs#202); the linkage requests in the reference's order with the privileged parameters, a reason length below -1 refused (bsv-rs#191); the linkage responses read in the reference's order to their end (bsv-rs#194); the seven result frames of bsv-rs#197 read to their last byte, a verdict true on the error byte alone, the error on an error frame, refused on a byte after it; verifyHmac's raw HMAC ahead of the data and the signature calls' data-type flag in both forms on the loopback, both or neither of the data and the hash refused (bsv-rs#199) |
| `wire_error_frames.rs` | 10 | `wallet`+`http` | The processor's error frame byte for byte the reference's (`WalletWireProcessor.ts:2379-2418` at `ts-stack@edf6e03`, bsv-rs#202), hand-assembled: an un-coded wallet error `01 17 Wallet operation failed 00` (`#invokeWallet`, `:2417`), every wallet error variant the same constant (this crate's `Error` carries no code, #137), a wallet erring on verifyHmac the constant, the processor's own reader refusal its sentence, the three false verdicts (thrown outside the wrapper) in the reference's words through the processor over a stub wallet; the transceiver reads each back as `wallet error (code 1): <words>`; the 4096-byte cut, the cut inside a character and the stack field 0 are the frame writer's unit tests in `src/wallet/wire/processor.rs`; abortAction (bsv-rs#206): a wallet's `aborted: false` framed `08 4d <the reference's words> 00` (`:797-804`), `aborted: true` the frame `00`, an empty reference code 6, the transceiver reading code 8 as `aborted: false` (`WalletWireTransceiver.ts:336-339`), every other frame the error it was and a byte after `00` refused |
| `wire_tracing_sink.rs` | 5 | `wallet`+`http`+`tracing` | The `tracing` sink at the processor's wrapper (bsv-rs#212), with a collector of its own on `tracing::Subscriber`: an un-coded wallet error raises one `warn` event, `call` the call's name and `error` the wallet's `Display` (getHeight, isAuthenticated); none for the processor's own refusal or a success; the frame `01 17 Wallet operation failed 00` with a listener and without. Outside `full`: CI runs it in its own step (`full,http,tracing`, `RUN_APART`) |
| `wire_method_roundtrip_tests.rs` | 106 | `wallet` | Wire protocol roundtrips for all 28 WalletInterface methods; an error frame code 1, the bare words, the stack 0 (bsv-rs#202); the linkage requests in the reference's order with the privileged parameters, a reason length below -1 refused (bsv-rs#191); the linkage responses read in the reference's order to their end (bsv-rs#194); the seven result frames of bsv-rs#197 read to their last byte, a verdict true on the error byte alone, the error on an error frame, refused on a byte after it; verifyHmac's raw HMAC ahead of the data and the signature calls' data-type flag in both forms on the loopback, both or neither of the data and the hash refused (bsv-rs#199); the seven key-related calls with the privileged pair and seekPermission present and absent, a privileged reason past 127 bytes refused before it is sent (bsv-rs#193) |
| `wire_processor_validation.rs` | 20 | `wallet` | The processor validates a request's arguments ahead of the wallet and its result after it, in the reference's rules and words (bsv-rs#216), each expected frame hand-assembled: the protocol name 5 to 400 bytes, the key ID 1 to 800, the privileged reason 5 to 50 bytes and required when `privileged`, on every call that carries them, code 6 and the wallet not called; verifySignature's signature length and canonical DER; getHeaderForHeight's height 0 and above `u32::MAX` in `#requireInteger`'s words, code 1; the two linkage calls' keys that are no point and revealSpecificKeyLinkage's absent counterparty, code 6, in the reference's order, and the points that pass; a security level outside 0 to 2 in `#decodeProtocolID`'s words, code 1 (#226); the results (getPublicKey's key, createSignature's signature, getHeight's 0, both linkages' time, keys, protocol and key ID against the request), code 1; the bounds themselves reach the wallet; the twelve stubs untouched (abortAction left them, #206); the ProtoWallet linkages pass the checks |
| `wire_error_frames.rs` | 5 | `wallet`+`http` | The processor's error frame byte for byte the reference's (`WalletWireProcessor.ts:2379-2396` at `ts-stack@edf6e03`, bsv-rs#202), hand-assembled: unknownError (1) for every wallet error (this crate's `Error` carries no code), the wallet's bare words (a `WalletError`'s words, a busy or transport answer's detail, another variant's `Display`), the three false verdicts through the processor over a stub wallet, a message cut at 4096 bytes (inside a character too), the stack field 0; the transceiver reads each back as `wallet error (code 1): <words>` |
| `wire_certificate_frames.rs` | 8 | `auth` | The transceiver reads the certificate results as the reference writes them (bsv-rs#177): acquireCertificate, listCertificates (the verifier 0 or 33 raw bytes, another length refused), proveCertificate, discoverByIdentityKey and discoverByAttributes (certifier info as plain strings, an empty one length 0) on the writer's frame, hand-assembled `Certificate.toBinary` bytes and the shared vectors, the certificate bytes read the same by `Certificate::from_binary` |
| `wire_identity_certificate_writer.rs` | 5 | `wallet` | `WireWriter::write_identity_certificate` writes one discovery entry as the reference and Go write it (bsv-rs#182): the writer's bytes read by the transceiver's discovery reader to the value, equal to `#serializeDiscoveryResult`'s bytes hand-assembled and to the shared vector's entry; an absent certifier info or map Go's zero value; a keyring value that is not base64 refused |
| `wire_identity_certificate_roundtrip.rs` | 7 | `wallet` | `WireReader::read_identity_certificate` and `read_optional_identity_certifier` read one discovery entry as the writer writes it and the reference reads it (bsv-rs#184): the writer's bytes read back to the value, Go's zero value read as the transceiver reads it (`Some` with empty strings, trust 0, maps `None`), the shared vector's entry read to the vector's fields, a keyring value of non-UTF-8 bytes round-tripped as base64, a map count past `2^53 - 1` refused in the strict reader's words (#236) and a certificate length past the bytes `ReaderUnderflow`, the layout before #182 refused, `read_identity_certifier` on three plain strings and the trust byte |
| `wire_identity_certificate_writer.rs` | 5 | `wallet` | `WireWriter::write_identity_certificate` writes one discovery entry as the reference and Go write it (bsv-rs#182): the writer's bytes read by the transceiver's discovery reader to the value, equal to `#serializeDiscoveryResult`'s bytes hand-assembled and to the shared vector's entry; an absent certifier info refused before a byte (#183), an absent iconUrl, description or map empty strings and counts; a keyring value that is not base64 refused |
| `wire_reader_strictness.rs` | 29 | `wallet` | The wire's readers refuse what the reference's refuse (bsv-rs#183), each on a valid frame hand-assembled to `Certificate.fromBinary` and the transceiver's readers at `ts-stack@edf6e03` and mutated at one byte: a header not 80 bytes (the transceiver, and the processor for a wallet's header), a certificate key that is not a compressed point, a field count past 100,000, past the bytes or nine 0xFF, a field name outside 1 to 50 bytes, unsafe or repeated, a value past 1 MiB, a signature that is not DER (kept as `toDER` re-encodes it), a listCertificates verifier not a point, a keyring flag not 0 or 1, record keys out of bounds or repeated, a discovery trust outside 1 to 10, a NIL or overlong discovery count; the writer refusing an identity certificate with no certifier info or a bad trust before a byte; the processor's linkage keys a point check, the reference's code-6 frame (#226); `read_identity_certificate` refusing a repeated record key as discovery does, and a wire length of 2^32 + 3 refused `ReaderUnderflow` on every target, never cut to its low bits on wasm32 (#192); `read_identity_certificate` refusing a record key outside 1 to 50 bytes or unsafe and a count past 100,000, past the bytes, past `2^53 - 1` or running long, as discovery does, in its words, and a listActions satoshis value outside the reference's -21e14 to 21e14 or past `2^53 - 1` (#236); the writer refusing an identity certificate with no certifier info or a bad trust before a byte, and every certificate writer refusing a key not a point, a field name outside 1 to 50 bytes or unsafe and a signature not DER before a byte (#189) |
| `wire_header_frame.rs` | 2 | `wallet` | getHeaderForHeight's result is the error byte and the header's 80 raw bytes (bsv-rs#178): the processor's frame equals the shared vector's, the transceiver reads both to the header, the version byte leading |
| `transaction/` | — | — | Transaction test vector constants module |

## Test Vectors

Test vectors in `tests/vectors/` are shared with the TypeScript and Go SDKs:

| Vector File | Contents |
|-------------|----------|
| `auth_certificate.json` | Auth certificate serialization vectors (4 vectors). Vectors 0 and 1 are `@bsv/sdk`'s `fromObject` fixtures (ts-sdk@27a93752) copied by 91dacc5 with the type and serial changed, so neither is the reference's bytes; vector 0's signature verifies over its bytes under no reading (#252, `auth_certificate_origin_252.json`) |
| `auth_certificate_origin_252.json` | Vector 0's provenance (#252): `@bsv/sdk`'s `fromObject` fixture as added at ts-sdk@27a93752 (type `CommonSource identity`, 21 bytes; the serial vector 0 changed at one character), the two values vector 0 changed, and the verdicts of `verify()` and the raw key at ts-sdk@27a93752 and `ts-stack@edf6e03` under Node v22.18.0, recorded by `tests/support/certificate_origin_252.mjs` |
| `auth_certificate_signature_251.json` | BRC-52 certificate signature witnesses (#251, 4): the reference-signed `email` certificate, one signed here, a wrong signature, 0.9.0-beta.1's raw-key signature, each with the reference's `verify()` verdict at `ts-stack@edf6e03` under Node v22.18.0 |
| `brc42_private.json` | BRC-42 private key derivation vectors (5 vectors) |
| `brc42_public.json` | BRC-42 public key derivation vectors (5 vectors) |
| `symmetric_key.json` | Symmetric encryption test vectors (5 vectors) |
| `overlay_admin_token.json` | Overlay SHIP/SLAP admin token vectors (4 vectors) |
| `overlay_admin_token_ts_parity.json` | Overlay admin token parity cases against `@bsv/sdk 1.10.1` (5 cases) |
| `arc_tx_status_verdicts.json` | ARC `POST /v1/tx` 2xx bodies and the verdict each must produce (17 cases; the reference's rule at `ts-stack@edf6e03 ARC.ts:110-180`; served through wiremock in `broadcaster_http_tests.rs` and replayed through the verdict in `src/transaction/broadcasters/arc.rs`) |
| `overlay_types.json` | Overlay type serialization vectors (18 entries across 6 categories) |
| `drbg.json` | HMAC-DRBG vectors (15 vectors from NIST SP 800-90A) |
| `bip39_japanese.json` | BIP-39 Japanese vectors (24), `bip32JP/bip32JP.github.io@5a43706` `test_JP_BIP39.json` byte for byte (public domain; named by `bip-0039.mediawiki:135`), sha256 `780d6a5f21827e5b455fdad35703e2c60ed9dfd47c625daaf50c01600dc4c9e2` |
| `sighash.json` | Transaction sighash vectors (500 entries, 499 used) |
| `spend_valid.json` | Valid spend execution vectors (458 vectors) |
| `script_valid.json` | Valid script parsing vectors (598 vectors) |
| `script_invalid.json` | Invalid scripts that should fail (432 vectors) |

Wire protocol vectors in `tests/vectors/wallet_wire/` (from Go SDK `wallet/substrates/testdata/`):

| Pattern | Contents |
|---------|----------|
| `*-args.json` | Wire-encoded request vectors for each WalletInterface method |
| `*-result.json` | Wire-encoded response vectors for each WalletInterface method |
| **54 files total** | Covers all 28 methods: createAction, signAction, abortAction, listActions, internalizeAction, createSignature, revealCounterpartyKeyLinkage, revealSpecificKeyLinkage, encrypt, decrypt, createHmac, verifyHmac, verifySignature, getPublicKey, acquireCertificate, listCertificates, proveCertificate, relinquishCertificate, discoverByIdentityKey, discoverByAttributes, isAuthenticated, waitForAuthentication, getHeight, getHeaderForHeight, getNetwork, getVersion, listOutputs, relinquishOutput |

Transaction test vectors in `tests/transaction/vectors/`:

| File | Contents |
|------|----------|
| `tx_valid.rs` | Valid transaction hex strings for roundtrip testing |
| `tx_invalid.rs` | Invalid transaction vectors (semantically invalid) |
| `bump_valid.rs` | Valid BRC-74 BUMP (MerklePath) hex vectors |
| `bump_invalid.rs` | Invalid BUMP vectors with expected error messages |
| `bigtx.rs` | Large transaction test vectors |
| `beef_cross_sdk.rs` | BEEF (BRC-62) and MerklePath vectors from TypeScript/Go SDKs |
| `atomic-beef.json` | BRC-95 vectors in the ts-stack corpus format, staged for `vectors/sdk/transactions/` (six: Go's dependency order, TS's partition order, a raw unproven ancestor after its proven descendant (TS), the subject not last (this crate's writer), an unrelated entry (TS's writer, refused), the subject missing (hand-built, refused), and the X/Y pair twice (a raw `X` nothing spends and its parent `Y`, both outside the graph; this crate's test writer, refused; the stream names the earlier by the trie order: `Y` in one, `X` in the other)) |

## Test Categories by Module

### Primitives (default features)
- **`cross_sdk_tests.rs`** — BRC-42 key derivation, symmetric encryption, WIF/address vectors, DRBG verification, edge cases (unicode, empty, large messages)
- **`drbg_tests.rs`** — NIST vector tests, SHA-512 variant, reseed, output length, determinism
- **`ec_tests.rs`** — BRC-42 derivation consistency, WIF/pubkey/address known vectors, sign/verify, ECDH, PublicKey::is_valid(), get_public_key from P2PK scripts, key serialization
- **`integration_tests.rs`** — Full workflows: key derivation, symmetric encryption, Schnorr proofs, Shamir secret sharing (3-of-5, subset recovery, the `_with` form given the plain form's coefficients), P-256, hash chains, sighash+signing, complete payment workflow

### Script (default features)
- **`script_vectors_tests.rs`** — 458 spend valid vectors, 598 script parsing vectors, 432 invalid script vectors, individual opcode tests (OP_CAT, OP_SPLIT, OP_MUL, OP_DIV)
- **`sighash_tests.rs`** — 499 sighash vectors (from 500 JSON entries) with `compute_sighash`, detailed first-vector debugging, transaction parsing verification
- **`template_tests.rs`** — P2PKH (lock/unlock/address/validation), P2PK (compressed detection, length estimate), Multisig (2-of-3, 1-of-1, 3-of-3, 16-of-16, validation errors), RPuzzle (hash types, K value, R computation)

### Transaction (`transaction` feature)
- **`transaction_tests.rs`** — Parsing/roundtrip (104 tests), fee models (Fixed, SatoshisPerKilobyte), MockChainTracker, broadcast, MerklePath/BUMP, BEEF format, ancestry collection (`to_beef`, `to_atomic_beef`), SPV verification (`Transaction::verify()`), cross-SDK BEEF/MerklePath vectors. Organized into submodules: `beef_extended_tests`, `beef_ancestry_tests`, `cross_sdk_tests`, `merkle_path_advanced_tests`

- **`beef_stream.rs`**: The streaming BEEF reader against the rows of the Lean definition `BeefOfAnySize` (bsv-stack-lean): each refusal with its offset and kind, the BRC-62 example cut and accepted with its script executed, the resumption at every `k`, chunks of every size, the spend refusals, the asynchronous reader; a raw transaction with no input refused as `NoInputs` at its offset, unproven beside a proven stranger and under a BUMP (0.4.1, bsv-stack-lean #58)
- **`beef_stream_deep.rs`**: The P0-5 chain at 1,000, 10,000 and 100,000 links read from a source that writes itself (`support/beef_chain.rs`) on a 1 MiB stack, the resumption at three points, the P0-5c wide BUMP at 8,192 and 16,384 leaves, the Lean's counts at those sizes
- **`beef_limits.rs`**: `BeefLimits` as memory hints: a BEEF over every one is read, a claimed count is refused for the bytes

### Conformance corpus (`transaction` feature; `$BSV_CONFORMANCE_DIR`, skipped loudly when absent)
- **`conformance_scripts.rs`** — The ts-stack corpus's script domain: 5,116 evaluation vectors (node script fixtures from bitcoin-sv and Teranode, the SDK's), the sighash and script regressions; every mismatch classified into an enumerated `unsupported` class or a pinned known failure, the per-class counts pinned (`EVALUATION_UNSUPPORTED_PINS`, `EVALUATION_KNOWN_FAILURES`), so corpus or interpreter drift is a red test. CI never sees the corpus (Calhooon/bsv-rs#31): run it before a release
- **`conformance_beef.rs`** — The corpus's BUMP (MerklePath), serialization, BEEF and transaction-regression suites, the same classification and pins

### Transaction HTTP (`transaction`+`http` features, wiremock)
- **`broadcaster_http_tests.rs`** — ARC (9 tests: success, API key, errors, batch), WoC (9 tests: mainnet/testnet/STN, errors), Teranode (8 tests: EF format, timeout, batch)
- **`chaintracker_http_tests.rs`** — WoC tracker: valid/invalid root, case-insensitive, 404/500, current_height, testnet paths
- **`live_policy_http_tests.rs`** — LivePolicy dynamic fee model: refresh from ARC policy endpoint, error handling (500/404/malformed), fallback rates, cache expiry, sat/byte→sat/KB conversion, API key auth

### Wallet (`wallet` feature)
- **`wallet_tests.rs`** — KeyDeriver (14 tests: derivation, validation, security levels), CachedKeyDeriver (8 tests: LRU eviction, secrets not cached), ProtoWallet (16 tests: encrypt/decrypt, HMAC, signatures, cross-party), cross-SDK BRC-2/BRC-3 compliance (4 tests), wire protocol encoding (14 tests: VarInt, strings, Counterparty, Protocol, Outpoint, maps, enums)
- **`wire_method_roundtrip_tests.rs`**: All 28 WalletInterface methods via loopback transport (106 tests): get_public_key, encrypt/decrypt, HMAC, signatures, key linkage, status (auth/height/network/version), actions (create/sign/abort/list/internalize), outputs (list/relinquish), certificates (acquire/list/prove/relinquish/discover). Also tests complex type roundtrips, response roundtrips, call codes, request frames, and Counterparty variant encoding.
- **`wallet_wire_cross_sdk_tests.rs`**: Cross-SDK wire protocol compatibility with Go SDK (55 tests; 13 need `http`, the recording wallet of `support/fixtures`). Loads 54 JSON vector files from Go SDK testdata. Tests request decoding (params extraction after call_code + originator) and response decoding (result extraction after error byte) for all 28 WalletInterface methods. Validates byte-level interoperability between Rust and Go wire encoders.

### Messages (`messages` feature)
- **`messages_tests.rs`** — BRC-77 signed messages (8 tests: specific/anyone recipient, empty/large, tampering), BRC-78 encrypted messages (9 tests: roundtrip, wrong key, GCM auth), cross-SDK vectors (8 tests: error format compatibility), unicode/binary data, multi-party, the `_with` forms (4 tests: the plain forms' bytes given their drawn key id and IV, fixed values reproducible)

### Compat (`compat` feature)
- **`compat_bip39_tests.rs`** — TREZOR vectors: entropy↔mnemonic (22 vectors), mnemonic→seed, validation (bad sentences, wrong word count, bad checksum), generation (12/15/18/21/24 words), randomized roundtrips (100 iterations per entropy size)
- **`compat_integration_tests.rs`** — BIP-39+BIP-32 HD wallet flows, BSM sign/verify, ECIES (Electrum/Bitcore), Base58, cross-module integration, error handling, type/enum tests

### Auth (`auth` feature)
- **`auth_cross_sdk_tests.rs`** — Certificate binary/JSON roundtrip, deterministic serialization, field sorting, DER signature format, outpoint parsing, cross-SDK binary layout
- **`auth_integration_tests.rs`** — SessionManager lifecycle/pruning, AuthMessage validation/signing, mock transport, HTTP payloads (complex/unicode/100 headers), certificate signing/verification, RequestedCertificateSet, PeerSession states, nonce handling (TS SDK `initial_nonce` fallback), error propagation through oneshot channels
- **`auth_peer_e2e_tests.rs`** — Full BRC-31 mutual authentication between two Peer instances via channel loopback: handshake, bidirectional messaging, session persistence, explicit `get_authenticated_session()`, listener registration, certificate request/response flow, empty/large (100KB) payloads, nonce uniqueness, error cases (invalid version, no session)

### Overlay (`overlay` feature)
- **`overlay_cross_sdk_tests.rs`** — Admin token creation/decoding/protocol detection, network presets, LookupQuestion/Answer types, AdmittanceInstructions, TaggedBEEF
- **`overlay_integration_tests.rs`** — Protocols, LookupQuestion/Answer, TaggedBEEF, AdmittanceInstructions, TopicBroadcaster validation, RequireAck, LookupResolverConfig, HostReputationTracker (ranking, reset, JSON export/import, global singleton), SyncHistorian (chain traversal, filtering, cycle prevention), admin tokens, HostResponse/ServiceMetadata, LookupResolver.find_competent_hosts() public API
- **`overlay_admin_token_ts_parity_tests.rs`** — `create_signed_overlay_admin_token` byte-exact against `@bsv/sdk 1.10.1`'s `pushdrop.lock` output on five recorded cases
- **`overlay_mock_tests.rs`** — MockLookupFacilitator and MockBroadcastFacilitator with pre-configured responses. Tests LookupResolver with mock SLAP facilitators (query routing, empty results, error handling, call counting), TopicBroadcaster with mock SHIP facilitators (broadcast routing, multi-host fan-out, partial failures, RequireAck handling). No network access required.

### Overlay HTTP (`overlay`+`http` features, wiremock)
- **`overlay_http_tests.rs`** — SHIP broadcast facilitator (25 tests: STEAK response, Content-Type/X-Topics headers, off-chain values, error responses 400/404/500, HTTP security, URL trimming) and SLAP lookup facilitator (24 tests: OutputList/Freeform/Formula answers, binary response format, request format verification, error handling, edge cases)

### Storage (`storage` feature)
- **`storage_tests.rs`** — UHRP URL generation/parsing/validation/normalization, roundtrip (file→URL→hash), StorageDownloader/Uploader config, UploadableFile, cross-SDK hash/file/URL vectors

### Storage HTTP (`storage`+`http` features, wiremock)
- **`storage_http_tests.rs`** — Two-step upload flow (POST /upload → PUT presigned URL), custom retention, required headers, error handling (400/401/413/500), find_file, list_uploads, renew_file, request body verification, MIME type headers, downloader URL validation (invalid/empty/HTTP/bad checksum URLs), timeout config

### Identity (`identity` feature)
- **`identity_tests.rs`** — KnownCertificateType (9 types, cross-SDK type IDs), DisplayableIdentity, Contact CRUD, IdentityQuery builder, ContactsManager async ops (add/update/remove/search/cache), CertifierInfo, BroadcastResult, static avatar URLs, default values, config builders, camelCase JSON compatibility

### KVStore (`kvstore` feature)
- **`kvstore_integration_tests.rs`** — LocalKVStore: config/entry/token/query/options types, KVStoreInterpreter (PushDrop script extraction), signature verification, constructor/get/set/remove/has/keys/list/count/clear operations, batch ops, cross-SDK compatibility (field names, PushDrop order), edge cases (unicode, large values)
- **`kvstore_global_tests.rs`** — GlobalKVStore: construction with default/custom config, network presets, input validation (empty key/value), wallet error propagation, overlay error propagation, interpreter tests (19 tests: basic tokens, context filtering, unicode, large values, old/new format), signature verification, data model tests, cross-SDK compatibility, edge cases (special chars, JSON values, multiple tags)

### Registry (`registry` feature)
- **`registry_integration_tests.rs`** — DefinitionType (string conversion, lookup services, topics, baskets, field counts), BasketDefinitionData (builder, PushDrop encode/decode), ProtocolDefinitionData (security levels), CertificateDefinitionData (field descriptors), DefinitionData enum, TokenData, RegistryRecord, query builders, result types, RegistryClientConfig, cross-SDK PushDrop field order, constants

### Documentation (default features)
- **`readme_examples.rs`** — The README's ```rust blocks that name an `examples/<name>.rs` file are those files byte for byte, and every example file appears in the README

### Profiling (`dhat-profiling` feature)
- **`memory_profiling.rs`** — Heap allocation profiling: AES-GCM (64-16384 bytes), BRC-42/ECDH derivation, Shamir 3-of-5 and 5-of-10, ECDSA sign/verify, SHA-256/Hash160 hashing

## Running Tests

```bash
# All tests with all modules
cargo test --features full

# All tests including HTTP (requires http feature)
cargo test --features "full,http"

# By feature group
cargo test --features transaction          # Transaction, script, primitives
cargo test --features wallet               # Wallet, transaction, script, primitives
cargo test --features messages             # Messages, wallet chain
cargo test --features compat               # BIP-39/32, BSM, ECIES, Base58
cargo test --features auth                 # Auth, messages, wallet chain
cargo test --features overlay              # Overlay, wallet chain
cargo test --features storage              # Storage, overlay chain
cargo test --features registry             # Registry, overlay chain
cargo test --features kvstore              # KVStore, overlay chain
cargo test --features identity             # Identity, auth, overlay chain

# Specific test file
cargo test --test wire_method_roundtrip_tests --features wallet
cargo test --test wallet_wire_cross_sdk_tests --features wallet
cargo test --test overlay_http_tests --features "overlay,http"
cargo test --test overlay_mock_tests --features full
cargo test --test live_policy_http_tests --features "transaction,http"

# Filter by test name
cargo test --features full -- test_complete_payment_workflow

# Memory profiling (single-threaded, with output)
cargo test --test memory_profiling --features dhat-profiling -- --test-threads=1 --nocapture
```

## Test Organization

Tests are organized by feature area:

| Area | Files |
|------|-------|
| **primitives** | `cross_sdk_tests`, `drbg_tests`, `ec_tests`, `integration_tests` |
| **script** | `script_vectors_tests`, `template_tests` |
| **transaction** | `sighash_tests`, `transaction_tests` |
| **conformance corpus** | `conformance_scripts`, `conformance_beef` |
| **transaction HTTP** | `broadcaster_http_tests`, `chaintracker_http_tests`, `live_policy_http_tests` |
| **wallet** | `wallet_tests`, `wire_method_roundtrip_tests`, `wallet_wire_cross_sdk_tests` |
| **messages** | `messages_tests` |
| **compat** | `compat_bip39_tests`, `compat_integration_tests` |
| **auth** | `auth_cross_sdk_tests`, `auth_integration_tests`, `auth_peer_e2e_tests` |
| **overlay** | `overlay_cross_sdk_tests`, `overlay_integration_tests`, `overlay_mock_tests`, `overlay_admin_token_ts_parity_tests` |
| **overlay HTTP** | `overlay_http_tests` |
| **storage** | `storage_tests` |
| **storage HTTP** | `storage_http_tests` |
| **identity** | `identity_tests` |
| **kvstore** | `kvstore_integration_tests`, `kvstore_global_tests` |
| **registry** | `registry_integration_tests` |
| **profiling** | `memory_profiling` |
| **documentation** | `readme_examples` |

Notable multi-module test files use nested submodules:
- `transaction_tests.rs`: `beef_extended_tests`, `beef_ancestry_tests`, `cross_sdk_tests`, `merkle_path_advanced_tests`
- `wallet_tests.rs`: `key_deriver_tests`, `cached_key_deriver_tests`, `proto_wallet_tests`, `cross_sdk_tests`, `wire_protocol_tests`
- `identity_tests.rs`: `contacts_manager_tests`, `identity_client_tests`
- `wire_method_roundtrip_tests.rs`: 18 submodules covering all 28 WalletInterface methods

## Adding New Tests

- **Cross-SDK vectors**: Add JSON to `tests/vectors/`, use `#[serde(rename_all = "camelCase")]`, include vector index in panic messages
- **Wire protocol vectors**: Add JSON to `tests/vectors/wallet_wire/`, following `{method}-{variant}-{args|result}.json` naming convention
- **Feature gates**: Use `#![cfg(feature = "...")]` at file top, or `#![cfg(all(feature = "...", feature = "http"))]` for HTTP tests
- **HTTP tests**: Use `wiremock` crate, create broadcaster/tracker with `::with_base_url(&mock_server.uri(), network)`
- **Wire protocol**: Use loopback pattern with `WalletWireTransceiver` → `WalletWireProcessor` for method roundtrips
- **Auth peer tests**: Use channel-based loopback transport for full BRC-31 handshake testing
- **Async tests**: Use `#[tokio::test]` for anything involving ChainTracker, Broadcaster, Peer, or KVStore operations
- **Test keys**: Follow TypeScript SDK patterns: `PrivateKey(42)`, `PrivateKey(69)` for deterministic test keys
- **Protocol names**: Must be 5+ characters, use `Protocol::new(SecurityLevel::*, "name")`

## Notes on BSV vs BTC Script Vectors

Some `script_valid.json` vectors may fail execution because BSV requires push-only unlocking scripts, minimal push encoding, and has different clean stack requirements. Vectors with `flags.contains("P2SH")` are skipped. The BSV-specific `spend_valid.json` vectors should all pass.

## Related Documentation

- `CLAUDE.md` — Root project documentation
- `src/*/CLAUDE.md` — Per-module documentation (primitives, script, transaction, wallet, messages, compat, totp, auth, overlay, storage, registry, kvstore, identity)
- `tests/transaction/vectors/CLAUDE.md` — Transaction test vectors documentation
