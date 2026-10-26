# Architecture: the primitives, the transaction model, the wallet interface and the substrates, in one picture

The crate's shape for whoever changes it ([#88](https://github.com/Calhooon/bsv-rs/issues/88)).
[CLAUDE.md](../CLAUDE.md) carries the rules, [README.md](../README.md) the guide, each
module its own `CLAUDE.md`; this page is the map between them. Every invariant
below names the test that fails when it breaks and the BRC or charter line it
rests on. The monorepo at `ts-stack@edf6e03` and the BRCs at `5119a9b`
(read with `git -C ~/bsv/brcs show 5119a9b:<path>`, never a working tree) are
the stack's pins (`~/bsv/bsv-stack-lean/docs/PROVENANCE.md`, the keeper's
page). The TypeScript SDK at `ts-sdk@9e3ede6` and the Go SDK at
`go-sdk@2ca481c` (`v1.7.2`) are the commits CLAUDE.md's divergence list
cites; PROVENANCE names no ts-sdk commit and names Go as `v1.7.1`.
A BRC citation is `<path>:<line>` at `5119a9b`.

## 1. The picture

```text
  [w] built on wasm32-unknown-unknown by a row of CI's matrix (a Cloudflare consumer's slice)
  <d> a transport directory at the edge: the only homes of a network client (ARCH-RULES rule 1)

                              [w] primitives
                             /      |       \
                  [w] script    [w] block     compat   totp      the two side modules,
                         \        /                              on primitives alone
                       [w] transaction        <src/transaction/broadcasters/>
                              |               <src/transaction/chain_trackers/>
                         [w] wallet           <src/wallet/substrates/>
                         /          \
                 [w] messages    [w] overlay  (src/overlay/facilitators.rs, the fifth home)
                        |         /   |   \
                   [w] auth   storage registry kvstore
                   <src/auth/transports/>
                   (socketio: a feature of auth, no new dependency)
                        \         |
                         \----- identity      (auth and overlay)
```

Fourteen feature-gated modules: twelve in one dependency chain and two at
the side (`compat`, `totp`) that stand on `primitives` alone. `block` sits in
the chain, under `transaction` since 0.6.0 (`Cargo.toml`'s `[features]` table
is the source). The wasm32 line runs
through `primitives`, `script`, `block`, `transaction`, `wallet`, `messages`,
`auth` and `overlay`: the six consumer slices CI builds on
`wasm32-unknown-unknown` ([ARCH-RULES.md](ARCH-RULES.md), "Feature and wasm
builds") are drawn from those eight. Every module, the four above `overlay`
and `auth` and the two side modules included, is type-checked on wasm32 by
the `msrv` job (`cargo check --lib --target wasm32-unknown-unknown
--no-default-features --features "full,wasm"` on 1.88); only the eight
marked are built and linked as a consumer's slice. Every network client
lives in one of the four transport directories or the overlay facilitator
file, and nowhere else.

What the crate is: a reference-parity port of `@bsv/sdk`, cross-checked
against the Go SDK, each wire format, verdict, derivation and error text read
from the reference before it is written here, and each divergence a stated
finding (CLAUDE.md rule 1 and its list). What it is not: it starts no
runtime (`tokio` is `sync`, `time`, `rt` only, for `watch`, `oneshot` and
timeouts); it retries nothing (a transport fault is typed and handed back; the
caller's tracker decides the re-ask); it reaches no network from a test (every
HTTP answer is `wiremock`'s, every overlay failure an injected resolver's);
it panics on no input (a parser refuses, a budget declines, both as `Err`).

## 2. The module map

Each row: the module, its feature, what its public surface promises, the
reference it conforms to at the pins above, and the `CLAUDE.md` that owns it.
Paths under "reference" are `src/` of `ts-sdk@9e3ede6` unless marked
`ts-stack` or `go-sdk`.

| Module | Feature | The promise | Reference at the pin | Owner |
|---|---|---|---|---|
| `primitives` | `primitives` | Hashes, secp256k1 and P-256, AES-256-GCM, `BigNumber`, HMAC-DRBG, the encodings, the sighash digests and `SighashCache`; byte-for-byte the reference's on the shared vectors | `primitives/` (`Hash.ts`, `ECDSA.ts`, `PrivateKey.ts`, `AESGCM.ts`, `DRBG.ts`, `BigNumber.ts`); go-sdk `primitives/` | [`src/primitives/CLAUDE.md`](../src/primitives/CLAUDE.md), [`ec/`](../src/primitives/ec/CLAUDE.md), [`bsv/`](../src/primitives/bsv/CLAUDE.md) |
| `script` | `script` | `Script` and its chunks, the templates, and `Spend`: the reference's default mode without a word, the node's block or standard word with one; a budget is its own error class | `script/Spend.ts`, `Script.ts`, `templates/`; go-sdk `script/`; the node at the pin `CLAUDE.md` names for the flag words | [`src/script/CLAUDE.md`](../src/script/CLAUDE.md), [`templates/`](../src/script/templates/CLAUDE.md) |
| `block` | `block` | `BlockHeader`, `CompactTarget`, proof of work, `ChainWork`, merkle roots, `next_work_required` as the node computes it | go-sdk `block/`; the node's difficulty rule (`tests/chain_difficulty.rs` names its tables); `@bsv/sdk` has no block module | [`src/block/CLAUDE.md`](../src/block/CLAUDE.md) |
| `transaction` | `transaction` | `Transaction` and its parts, signing through the templates, fee models, BEEF (whole and streaming), `MerklePath`, `verify` by txid, the broadcaster and chain tracker traits with the typed transport fault | `transaction/` (`Transaction.ts`, `Beef.ts`, `MerklePath.ts`, `broadcasters/`, `chaintrackers/`, `fee-models/`); ts-stack `packages/sdk` for BEEF 3.x; go-sdk `transaction/`, `spv/` | [`src/transaction/CLAUDE.md`](../src/transaction/CLAUDE.md), [`broadcasters/`](../src/transaction/broadcasters/CLAUDE.md), [`chain_trackers/`](../src/transaction/chain_trackers/CLAUDE.md), [`fee_models/`](../src/transaction/fee_models/CLAUDE.md) |
| `wallet` | `wallet` | BRC-42/43 derivation (`KeyDeriver`, cached), `ProtoWallet`, the 28-method `WalletInterface`, the BRC-100 binary wire (`wire/`) and the two HTTP substrates (`substrates/`): the frame and the body as BRC-100 reads them at the pin | `wallet/` (`KeyDeriver.ts`, `ProtoWallet.ts`, `WalletClient.ts`, `substrates/`); go-sdk `wallet/` (its `substrates/testdata/` are the 54 wire vectors) | [`src/wallet/CLAUDE.md`](../src/wallet/CLAUDE.md), [`wire/`](../src/wallet/wire/CLAUDE.md), [`substrates/`](../src/wallet/substrates/CLAUDE.md) |
| `messages` | `messages` | BRC-77 signed and BRC-78 encrypted messages over BRC-42 keys | `messages/` (`SignedMessage.ts`, `EncryptedMessage.ts`); go-sdk `message/` | [`src/messages/CLAUDE.md`](../src/messages/CLAUDE.md) |
| `compat` | `compat` | BIP-32, BIP-39 (nine wordlists), BSM, ECIES, base58: the legacy formats, as the reference writes them | `compat/` (`HD.ts`, `Mnemonic.ts`, `BSM.ts`, `ECIES.ts`); go-sdk `compat/` | [`src/compat/CLAUDE.md`](../src/compat/CLAUDE.md), [`bip39/`](../src/compat/bip39/CLAUDE.md), [`wordlists/`](../src/compat/bip39/wordlists/CLAUDE.md) |
| `totp` | `totp` | RFC 6238 codes, constant-time validation; six digits by default where the reference defaults to two (a stated divergence) | `totp/totp.ts`; go-sdk has none | [`src/totp/CLAUDE.md`](../src/totp/CLAUDE.md) |
| `auth` | `auth` (`socketio`, `websocket`) | BRC-103 mutual authentication (`Peer`, sessions, 48-byte nonces), BRC-52/53 certificates, the transports (BRC-104 HTTP, Socket.IO, WebSocket) | `auth/` (`Peer.ts`, `SessionManager.ts`, `certificates/`, `transports/`, `utils/`); ts-stack `packages/sdk/src/auth/`, `packages/messaging/authsocket`; go-sdk `auth/` | [`src/auth/CLAUDE.md`](../src/auth/CLAUDE.md), [`certificates/`](../src/auth/certificates/CLAUDE.md), [`transports/`](../src/auth/transports/CLAUDE.md), [`utils/`](../src/auth/utils/CLAUDE.md) |
| `overlay` | `overlay` | SHIP broadcast and SLAP lookup (`TopicBroadcaster`, `LookupResolver`), the facilitators, admin tokens, the historian, host reputation and request coalescing (the last two this crate's additions, documented) | `overlay-tools/` (`LookupResolver.ts`, `SHIPBroadcaster.ts`, `HostReputationTracker.ts`, `Historian.ts`, `OverlayAdminTokenTemplate.ts`); ts-stack `packages/overlays`; go-sdk `overlay/` | [`src/overlay/CLAUDE.md`](../src/overlay/CLAUDE.md) |
| `storage` | `storage` | UHRP URLs, the uploader and downloader over the overlay's `ls_uhrp` | `storage/`; go-sdk `storage/` | [`src/storage/CLAUDE.md`](../src/storage/CLAUDE.md) |
| `registry` | `registry` | Basket, protocol and certificate definitions as PushDrop tokens, found through SLAP and published through SHIP | `registry/`; go-sdk `registry/` | [`src/registry/CLAUDE.md`](../src/registry/CLAUDE.md) |
| `kvstore` | `kvstore` | `LocalKVStore` (wallet baskets, encrypted by default) and `GlobalKVStore` (overlay tokens) | `kvstore/`; go-sdk `kvstore/` | [`src/kvstore/CLAUDE.md`](../src/kvstore/CLAUDE.md) |
| `identity` | `identity` | Identity resolution by key or attribute, contacts, revelation and its revocation (signing the dispatched digest) | `identity/`; go-sdk `identity/` | [`src/identity/CLAUDE.md`](../src/identity/CLAUDE.md) |

Across every module: one `Error` enum ([`src/error.rs`](../src/error.rs),
`Clone + PartialEq + Eq`, `#[non_exhaustive]`, so tests assert on it and a
variant is additive); `TransportFault` and `WalletRefusalClass` (#137) re-exported at the crate root; the
`http` feature for reqwest (ARC, WhatsOnChain, the headers service, the HTTP
substrates, the overlay hosts), `websocket` opt-in and outside `full`, `wasm`
for the JS RNG and timers; the 18 fuzz targets of
[`fuzz/fuzz_targets/CLAUDE.md`](../fuzz/fuzz_targets/CLAUDE.md).

## 3. The invariants

One line each: the rule; where it lives; the test that fails when it breaks
(`tests/<file>.rs` unless a `src/` path is given); the BRC or charter line.
The charter (`docs/charters/`) and Lean (`lean/`) lines are the sibling's,
cited at `bsv-stack-lean@14dfdd9`.
A rule whose test is missing says so: that is a finding, never an invention.

- **A parser refuses before it allocates.** Every reader bounds a pre-allocation by the bytes remaining (`primitives::bounded_capacity`, [`src/primitives/encoding.rs`](../src/primitives/encoding.rs); the ten files that call it), indexes with `get`, and answers `Err` on a bad count; `a_claimed_count_is_refused_for_the_bytes_and_reserves_nothing` (`beef_limits`), `a_claimed_count_is_read_and_the_refusal_is_for_the_bytes` (`beef_stream`); the certificate and BRC-104 payload readers refuse a length the check would wrap on (#108): `a_certificate_length_that_wraps_the_bounds_check_is_refused`, `a_certificate_field_length_of_usize_max_minus_k_is_refused`, `an_http_request_length_that_wraps_a_32_bit_bounds_check_is_refused` (`auth_reader_bounds`); BRC-62 `transactions/0062.md:172` (Validation Process) and BRC-52 `peer-to-peer/0052.md:79` (Certificate Binary Format) cite the formats being read, not the bound, which is the crate's own (CLAUDE.md rule 5); the BEEF charter section 3 (`docs/charters/beef-of-any-size.md:26`), `BeefOfAnySize.lean` `takeExact?` (`:266`).
- **A varint above its field's bound is refused, never cast.** `WireReader::read_var_int_u32` and `read_optional_var_int_u32` ([`src/wallet/wire/mod.rs`](../src/wallet/wire/mod.rs), #120 and #122) name the field in the refusal; no `as u32` of a varint remains under `src/wallet/wire/` or `src/auth/`; `an_outpoint_index_above_u32_max_is_refused_not_truncated`, `a_sign_action_spend_index_above_u32_max_is_refused_not_truncated` (`wire_method_roundtrip_tests`), `a_sign_action_spend_sequence_number_above_u32_max_is_refused_not_truncated`, `a_header_height_above_u32_max_is_refused_not_truncated`, `a_list_outputs_total_above_u32_max_is_refused_not_truncated` (`wire_u32_field_bounds_tests`); a non-canonical varint is refused at every reader: `node_noncanonical_encodings_are_refused`, `streaming_noncanonical_refusal_survives_every_chunk_boundary` (`canonical_varint`); BRC-100 `wallet/0100.md:1629` (VarInt Encoding), BRC-52 `peer-to-peer/0052.md:79` (row 6, the outpoint's VarInt index).
- **The wallet interface is BRC-100 at the pin.** The 28 methods of [`src/wallet/interface.rs`](../src/wallet/interface.rs); the frame (call code, originator, parameters; the status byte and the result) in [`src/wallet/wire/`](../src/wallet/wire/); the JSON bodies in [`src/wallet/substrates/http_json.rs`](../src/wallet/substrates/http_json.rs); `fixtures_replay` (`fixtures_replay`: #76's recordings of every call's request and result bytes, two wire and two HTTP cases per call, the census refusing a file added or removed without replay, the twelve disagreements kept visible in [FIXTURES.md](FIXTURES.md)), `test_create_hmac_result_cross_sdk` and its 41 siblings on go-sdk's 54 message files (`wallet_wire_cross_sdk_tests`), the 90 round trips (loopback and reader/writer) of `wire_method_roundtrip_tests`; BRC-100 `wallet/0100.md:364` (The Wallet Interface), `:1533` (ABI Specification), `:1541` (Message Structure), `:1603` (Error Handling); the wallet charter section 1 (`docs/charters/wallet.md:11`), `Wallet.lean` `Action`, `Coin` (`:94`, `:75`).
- **A substrate never decides, it carries.** Busy is the body's word (`STORE_BUSY`, the toolbox's `ERR_SERVER_BUSY`), never the status's; a fault is typed by [`src/transaction/broadcasters/transport_fault.rs`](../src/transaction/broadcasters/transport_fault.rs), the one classifier the four transport directories call, and never retried (one request per answer: the stub's `expect(1)` in the broadcasters' `answered`, `tests/transport_fault_broadcasters.rs:106`, and the wallet substrate's `create_action_against`, `tests/wallet_http_json_busy_tests.rs:40`); `store_busy_on_a_503_is_wallet_busy_where_the_substrate_reads_one`, `a_503_without_a_busy_code_is_a_wallet_transport_fault` (`transport_fault_wallet`), `the_producers_store_busy_body_is_wallet_busy_with_the_delay`, `a_503_with_a_numeric_code_keeps_the_coded_wallet_error` (`wallet_http_json_busy_tests`), `transport_code_adds_no_text_classification` (`arch_no_string_errors`: no transport reads an error's text); BRC-100 `wallet/0100.md:289` (Error Handling and Validation); the wallet charter sections 2 and 4 (`docs/charters/wallet.md:30`, `:65`: the evidence rule, the re-ask policy).
- **A transport failure before any byte left is `NEVER_SENT`, after the body was written `MAY_HAVE_BEEN_RECEIVED`, a 429 `RATE_LIMITED` with its wait.** The status read before the body; `TransportFault` at the crate root (#87); `a_refused_connection_is_never_sent`, `a_timeout_after_the_body_was_written_may_have_been_received`, `a_429_with_retry_after_and_a_text_body_is_rate_limited_with_its_wait`, `a_500_is_the_services_answer_not_a_fault` (`transport_fault_broadcasters`), `a_refused_connection_is_never_sent_on_both_paths` (`transport_fault_auth`), `a_429_without_a_busy_code_is_rate_limited_with_its_wait` (`transport_fault_wallet`); the broadcaster charter section 1 (`docs/charters/broadcaster.md:11`, B1: a broadcaster's word is a hint), the matrix rows 26 and 30 (CLAUDE.md's divergence line); `Sdk.lean` `neverSent_unwritten` (`:237`), `timeout_after_write` (`:233`), `rateLimited_carries_wait` (`:263`).
- **A chain tracker's provider error is never a verdict.** `ChainTrackerError::TransportFault` carried to `Error::TransportFault` by `Transaction::verify`, never `Ok(false)`; a 500 stays `InvalidResponse`; `a_trackers_transport_fault_reaches_the_crate_error_typed`, `a_500_stays_the_providers_answer`, `a_refused_connection_is_a_transport_fault_never_sent` (`transport_fault_trackers`); the tracker charter section 2 (`docs/charters/tracker.md:29`: only headers and proofs are evidence); BRC-62 `transactions/0062.md:172` step 3 (the header service answers the roots).
- **BEEF: one reader.** `Beef::from_binary` is the streaming reader's decoder in a collect mode (`BeefDecoder::collecting`, [`src/transaction/beef/collect.rs`](../src/transaction/beef/collect.rs)), and `Beef::verify_structure` judges the entries in the order held by the stream's own rules ([`src/transaction/beef/in_memory.rs`](../src/transaction/beef/in_memory.rs)): both entry points accept the same BEEFs and refuse the rest with the same kind and, where the parse names one, the same offset, a transaction written ahead of its parent refused by both (`InputNamesNoElement`, BRC-62's order; the reference sorts); `the_whole_path_and_the_stream_agree_on_every_beef_the_tree_holds` (`beef_two_readers_agree`), `fuzz_beef_parser`'s assertion (bsv-rs#86); the BEEF charter's "one reader with one bound".
- **BEEF: one reader's rule for the atomic graph.** `beef_stream::atomic_unreached` serves both readers (0.8.1, the owner's ruling of 2026-10-22): the subject raw in the BEEF, every other entry reached from it through the inputs of every raw entry, position not judged; `an_atomic_beef_is_accepted_by_both_readers_in_every_order_its_dependencies_allow`, `an_unrelated_entry_is_refused_by_both_readers_in_every_order`, `a_subject_the_beef_does_not_carry_raw_is_missing_in_every_order` (`beef_atomic_graph`); BRC-95 `transactions/0095.md:39` (Transaction Inclusion Rules), `:65` (Error Conditions), BRC-62 `:72` (Ordering); `BeefOfAnySize.lean` `walk` (`:944`), `finish` (`:964`).
- **BEEF: cycles terminate.** The linker memoizes a stub before it descends ([`src/transaction/beef.rs`](../src/transaction/beef.rs), the comment at the memo), so a source graph with a cycle stops instead of walking forever and a diamond links in linear time; `a_deep_diamond_chain_links_and_verifies_in_linear_time` (`src/transaction/beef.rs`), `a_24_deep_diamond_parses_and_links_in_under_a_second_on_a_small_stack` (`beef_deep_chain`); a ring itself (#160): on the wire a ring of raw entries can be written only by its input fields (an entry's txid is its bytes' hash), and every reader refuses it `InputNamesNoElement` in bounded time, `a_ring_written_by_its_txid_fields_is_refused_by_every_reader_in_bounded_time`, `a_pair_with_one_real_link_and_one_named_link_is_refused_in_both_orders`, `the_atomic_form_of_a_ring_is_refused_by_the_readers_and_from_atomic_beef_stops`, `the_v2_form_of_a_ring_is_refused_as_the_v1_form_is`; in memory a ring is real (an entry keeps the txid it was read with, `BeefTx::tx_mut` points its input at its descendant) and the linker links each entry once, `a_ring_held_in_memory_links_each_entry_once_and_every_walk_stops` (`beef_cycle`, red with the memo inserted after the descent); `BeefOfAnySize.lean` `walk` (`:944`), `budget` (`:956`). BRC-62 `transactions/0062.md:172` step 2.4.1 (a parent is read before its child, so a valid BEEF has no cycle).
- **BEEF: a byte after the frame is refused.** `Beef::from_binary` (the decoder's `Step::Done`, [`src/transaction/beef/collect.rs`](../src/transaction/beef/collect.rs)) where TS's `fromBinary` is a prefix parser (CLAUDE.md's divergence list, 0.4.2); `the_whole_path_refuses_a_byte_after_the_frame` (`beef_stream`); BRC-62 `transactions/0062.md:52` (Specification); `BeefOfAnySize.lean` `run` (`:982`).
- **BEEF: the merkle path's lone leaf is refused off offset 0.** A one-level path with one hashed leaf is a one-transaction block; any other offset is `MissingSibling` at parse and at `compute_root`; `lone_at_one_parsers_refuse_missing_sibling`, `lone_compute_root_refuses_every_nonzero_offset_class`, `beef_and_merkle_path_agree_on_both_owned_bodies` (`merkle_path_lone_leaf`); BRC-74 `transactions/0074.md:43` (Binary Encoding), `:263` (Calculating the Merkle Root); `BeefOfAnySize.lean` `Bump.lone?` (`:552`), `Bump.root` (`:563`).
- **The interpreter: a budget is an error of its own class, never a hidden allocation.** `ScriptResourceLimit` (memory, work), the refusal before the allocation it would need ([`src/script/spend/limits.rs`](../src/script/spend/limits.rs), the declines; the bounds before the allocation in `spend/splice.rs` and `spend/stack.rs`); `the_stack_budget_trips_as_a_resource_limit_not_a_script_verdict`, `num2bin_refuses_an_oversized_element_before_allocating_it`, `a_script_verdict_is_never_a_resource_limit` (`resource_limits`), `r404_h1_one_input_declines_inside_its_script` (`script_work_budget`), `the_32000001_byte_read_is_the_default_modes_resource_limit` (`script_stack_memory_witness`); the node's `-maxstackmemoryusageconsensus` (CLAUDE.md's contracts); the BEEF charter section 3 (`docs/charters/beef-of-any-size.md:26`, a decline is never a verdict).
- **Consensus and policy are different words.** `ScriptFlags::block(era)` and `ScriptFlags::standard(era)` ([`src/script/flags.rs`](../src/script/flags.rs), every rule at the node's site under its version gate); a rule that is policy is never enforced under the block word; `the_standard_word_refuses_what_the_block_word_accepts_only_by_a_standard_only_rule`, `flags_policy_as_consensus_a_version_1_spend_leaving_two_stack_elements_is_valid_under_the_block_word`, `the_default_mode_changes_exactly_one_recorded_verdict_the_nulldummy_version_gate` (`script_flags_witnesses`); the node at the pin `CLAUDE.md` names; the sibling's harness is the oracle (`bsv-script-lean/harness/README.md`, lanes README rule 4).
- **The sighash the node dispatches.** `SigningContext::compute_sighash` signs `compute_sighash_dispatched_for_signing`'s digest ([`src/primitives/bsv/sighash.rs`](../src/primitives/bsv/sighash.rs)): BIP143 for FORKID without CHRONICLE, the original digest otherwise, the SINGLE sentinel `one` kept; `the_default_signing_digest_is_the_dispatchers_for_every_hash_type`, `a_single_beyond_the_outputs_under_the_original_digest_signs_the_constant_one`, `test_sighash_vectors` (`sighash_tests`), `every_row_of_the_class_agrees_with_the_reference_under_the_block_word` (`script_sighash_dispatch_witness`); the node's `SignatureHash` (CLAUDE.md's contracts, 0.7.0).
- **RFC 6979's digest-at-or-above-n pin.** k256 0.14 signs a digest at or above the order with the bytes `@bsv/sdk` and go-sdk produce ([`src/primitives/ec/private_key.rs`](../src/primitives/ec/private_key.rs), #125); `rfc6979_digest_ge_n_der_is_pinned` (`ec_tests`), so a dependency move that changes it is noticed.
- **HMAC keys are the 32-byte X coordinate; a minimal-length tag is refused by name (BRC-56).** `KeyDeriver` and `ProtoWallet::verify_hmac` ([`src/wallet/proto_wallet.rs`](../src/wallet/proto_wallet.rs)); `test_brc2_hmac_compliance` (`wallet_tests`) checks agreement with the reference on one TypeScript vector, whose X coordinate is not shown to start with a zero byte; the leading-zero keys and the refusal by name are pinned by `the_six_hmac_keys_are_the_32_byte_x_coordinate_with_its_leading_zeros`, `create_hmac_reproduces_the_six_brc56_tags`, `verify_hmac_accepts_the_six_32_byte_key_tags`, `a_minimal_length_key_tag_is_refused_naming_the_senders_encoding`, `a_minimal_length_key_tag_is_refused_through_the_async_interface` (`wallet_brc56_hmac_tests`, #148). BRC-56 `wallet/0056.md:56` (the X coordinate as exactly 32 big-endian bytes), `:66` (the recipient's), `:73` (the minimal-length divergence); BRC-42 `key-derivation/0042.md:25` (Key Derivation).
- **Tests are hermetic.** No test depends on the network being present or absent (CLAUDE.md rule 4): every HTTP answer is `wiremock`'s, every overlay failure an injected resolver's; `test_global_get_by_tags_overlay_error` (`kvstore_global_tests`, `hermetic_store`: a resolver with no host), `library_never_reads_the_environment` (`arch_no_env`), `network_clients_stay_in_their_homes` (`arch_network_sites`); lanes README rule 3; `docs/charters/messaging-auth.md:37` (The rules).
- **Every public behavior is pinned by a test.** CLAUDE.md rule 2 (a fix lands with a test that was RED before it); `fixtures_replay` (`fixtures_replay`: a wire byte, a body byte or a JSON value that moves fails with the file, case and path), `every_readme_snippet_is_an_example_file_and_every_example_is_in_the_readme` (`readme_examples`); [FIXTURES.md](FIXTURES.md).
- **The whole suite runs in CI; a file CI does not run is refused.** The `test` job's "Run every integration test" step runs `cargo test --features "full,http,websocket" --tests --no-fail-fast`, so cargo's own enumeration runs every `tests/*.rs` (an enumerated list had drifted to 34 of 73 files, #146); `memory_profiling` runs alone behind `dhat-profiling`, `wire_tracing_sink` in its own step behind `tracing` (outside `full`, #212). The guard is the step itself ([`.github/workflows/ci.yml`](../.github/workflows/ci.yml)); no test under `tests/` restates it.
- **The census only falls.** `tools/ratchet/run --check` against [ratchets.json](ratchets.json) (seven counters, a limit per oversized file); `unwrap_and_expect_counts_never_rise` (`arch_no_unwrap`), `every_counter_and_each_file_has_an_independent_limit` (`tools/ratchet/src/model.rs`), `conformance_scripts_evaluation` (`conformance_scripts`: the corpus total pinned, every mismatch in an enumerated class with its count); [RATCHETS.md](RATCHETS.md), CLAUDE.md rule 3.
- **The dependents build against every PR.** The `dependents-plan`, `dependent-check`, `dependents` and `semver` jobs ([`.github/workflows/ci.yml`](../.github/workflows/ci.yml)) build every admitted consumer of [dependents.lock](dependents.lock) against the PR tree and refuse a breaking change against the last tag; `test_alias_resolves_to_the_pr_tree`, `test_unused_patch_cannot_report_success` ([`.github/scripts/test_dependents.py`](../.github/scripts/test_dependents.py), Python); [DEPENDENTS.md](DEPENDENTS.md).

The exit test's three gaps are closed: BRC-56's refusal by name is pinned by
`tests/wallet_brc56_hmac_tests.rs` (#148), a BEEF whose source links form a
cycle by `tests/beef_cycle.rs` (#160), and `src/block/` has its `CLAUDE.md`
(#161); every invariant above names its test.

## 4. The lines and the gates

**The lines.** `main` is the stable line: every change through a PR, the
required checks green, rebase-merged, linear history. `beta` is the
programme's line (epic #101): every lane PR targets it, one concern each,
reviewed cold before the captain merges; `main` merges into `beta` after every
stable patch, `beta` into `main` at a phase exit as the next minor. A tag
`vX.Y.Z` on `main` is a release of record; `vX.Y.Z-beta.N` on `beta` a
prerelease; either runs `release.yml`, which re-runs CI and publishes through
crates.io trusted publishing, nothing from a laptop. A beta tag is never
admitted to the stack's line. [RELEASING.md](../RELEASING.md), [NORTH-STAR.md](NORTH-STAR.md).

**The ratchet.** The `ratchet` job measures the library (files over 800
lines, `unwrap`/`expect` calls, functions over 60 lines, cognitive complexity,
missing docs, duplicate token windows, pedantic warnings) and compares with
`docs/ratchets.json`; an increase fails with the counter and the excess, a
recorded baseline is compared against the PR base so a raised limit cannot hide
code. [RATCHETS.md](RATCHETS.md).

**Deny.** `cargo deny check` on all features, the Cloudflare wasm32 slice and
the defaults, `--locked` against one audit lockfile: RustSec findings and
yanked crates fail, the ignore list stays empty, licenses are allowlisted,
sources are crates.io only. [RELEASING.md](../RELEASING.md) step 2.

**Semver.** `cargo-semver-checks` against the last `v*` tag reachable from
the PR base, the release type read from the version (0.9.0 on `beta` is a
minor), so a breaking change cannot ride a patch or a beta suffix.
[DEPENDENTS.md](DEPENDENTS.md).

**The arch tests.** Five lexical guards over every file under `src/`:
network clients only in the four transport directories and the facilitator
file, `unwrap`/`expect` ceilings per file, no text classification of a
transport error, no `std::env`, no `SystemTime` or `thread::spawn` outside
`src/util/` or a native cfg; plus `cargo hack check --each-feature` and the six
wasm32 slices. [ARCH-RULES.md](ARCH-RULES.md).

**The fixtures.** `tests/fixtures/` records what the crate writes and reads
on every public surface (wire, HTTP JSON, BEEF, merkle path, transaction);
replayed on every PR, recorded only by `BSV_FIXTURES_RECORD=1` in a behavior
PR's own commit, the census refusing a silent addition or loss.
[FIXTURES.md](FIXTURES.md).

**The nightly.** Mutants on five surfaces (script, BEEF, merkle path, wallet
wire, wallet substrates) with a floor per file, and one hour of fuzzing per
target from its checked-in corpus, each crash filed as an issue naming the
panic site; never on a PR. [NIGHTLY.md](NIGHTLY.md), [`fuzz/fuzz_targets/CLAUDE.md`](../fuzz/fuzz_targets/CLAUDE.md).

**The dependents.** Every admitted consumer built against the PR tree with a
`patch.crates-io` override proven to resolve, each failure naming its consumer;
the pin ledger and the re-pin train. [DEPENDENTS.md](DEPENDENTS.md).

## 5. Where the numbers come from

Measured at `4dc505f` (the tip of `beta` at 0.9.0, 2026-10-24) on macOS,
rustc 1.95.0. Re-measure before you write one down.

The suite, compiled then run:

```sh
export CARGO_TARGET_DIR="$HOME/bsv/targets/bsv-rs-lanes/fix-88"
cargo test --features "full,http,websocket" --no-run
cargo test --features "full,http,websocket" --no-fail-fast 2>&1 | grep "^test result" \
  | awk '{p+=$4; f+=$6; i+=$8} END {print "passed="p" failed="f" ignored="i}'
```

| What | Count |
|---|---:|
| Unit tests (`src/`) | 1,560 |
| Integration tests, across 78 files under `tests/` (one binary each) | 1,598 passed, 2 ignored |
| Doc tests | 265 passed, 129 ignored (the `rust,ignore` illustrations) |
| Sum | 3,423 passed, 0 failed, 131 ignored |

The conformance files skipped their external corpus in this run (no
`BSV_CONFORMANCE_DIR`, no `../ts-stack` beside a lane worktree); their pinned
constants (5,116 evaluation vectors) hold whenever the corpus is present, and
CI's `vectors` job checks it out. The 7 `memory_profiling` tests sit behind
`dhat-profiling` and run alone, outside the sum.

The source, the vectors, the surfaces:

```sh
find src -name '*.rs' | xargs wc -l | tail -1                   # 102,200
for f in tests/vectors/*.json; do python3 -c "import json; d=json.load(open('$f')); \
  print('$f', len(d) if isinstance(d, list) else {k: len(v) for k, v in d.items() if isinstance(v, list)})"; done
ls tests/vectors/wallet_wire | wc -l                            # 54
ls tests/vectors/beef_of_any_size | wc -l                       # 49
find tests/fixtures -name '*.json' | wc -l                      # 65
ls fuzz/fuzz_targets/*.rs | wc -l                               # 18
ls examples | wc -l                                             # 6
find src -name CLAUDE.md | wc -l                                # 27 (28 from #161)
```

| Vector file | Entries |
|---|---:|
| `script_valid.json` | 598 |
| `script_invalid.json` | 432 |
| `spend_valid.json` | 458 |
| `sighash.json` | 500 |
| `brc42_private.json`, `brc42_public.json` | 5 and 5 |
| `symmetric_key.json` | 5 |
| `drbg.json` | 15 |
| `auth_certificate.json` | 4 |
| `overlay_admin_token.json` | 4 |
| `overlay_admin_token_ts_parity.json` | 5 cases |
| `arc_tx_status_verdicts.json` | 20 cases |
| `overlay_types.json` | 16 entries in its four list-valued categories |
| `wallet_wire/` | 54 files (go-sdk's) |
| `beef_of_any_size/` | 49 files (the Lean's rows) |
| `wycheproof/` | 2 files (HKDF-SHA256, HKDF-SHA512) |

Lines under `src/`: 102,200. Fixture files under `tests/fixtures/`: 65.
Fuzz targets: 13. README examples: 6. Module `CLAUDE.md` files under `src/`:
27 at that commit, 28 with `src/block/CLAUDE.md` (#161).
