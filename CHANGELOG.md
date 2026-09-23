# Changelog

All notable changes to `bsv-rs` are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.3.28] - 2026-09-23

### Fixed — the low-S check at the curve order (Calhooon/bsv-rs#14)

- A signature whose `r` or `s` is at or above the curve order was refused as
  high-S (`The signature must have a low S value.`) before verification. The
  reference's `CPubKey::CheckLowS` (`src/pubkey.cpp:356-365`) parses laxly
  (`ecdsa_signature_parse_der_lax`, `146-173`): such a value overflows into the
  all-zero signature, which is low, so the check passes and the signature then
  fails to verify; under version 1 with NULLFAIL the script is
  `SCRIPT_ERR_SIG_NULLFAIL` (`src/script/interpreter.cpp:1491-1497`), otherwise
  a false top element. `Spend::check_signature_encoding` now treats an `r` or
  `s` at or above the order as the zero signature for the low-S check; the
  high-S refusal applies to `n/2 < s < n` only. Both verdicts were invalid; the
  rule and the message differed, found by the same differential run against
  bitcoin-sv v1.2.2 (`879fc8b`). Pinned by `tests/script_low_s_order_witness.rs`
  (the witness, a version-1 P2PK spend with `s` = the order, under the block
  word, the standard word and the default mode; RED on 0.3.27) and by the
  boundary tests in `spend.rs` (`s = n/2` low, `s = n/2 + 1` and `s = n - 1`
  high, `s = n`, `s = n + 1` and `r = n` the zero signature).

### Corrected

- The 0.3.27 entry and the header of `tests/script_residual_witnesses.rs`
  said "nine witness transactions"; the file holds ten, of eight rules (two
  each for the truncated push and the undefined opcode, one each for the
  second `OP_ELSE`, `OP_VER`, `OP_2DIV`, `OP_2MUL`, `0xb7` as `OP_RSHIFTNUM`
  and the FORKID scriptCode). One count at every site now.

## [0.3.27] - 2026-09-23

### Fixed — five consensus rules the interpreter got wrong in every mode (Calhooon/bsv-rs#12)

The same differential run against bitcoin-sv v1.2.2 (`879fc8b`) that found #10
recorded five further divergences from the block-validation rules, each with a
witness transaction; they are `tests/script_residual_witnesses.rs` (ten
transactions of eight rules, each pinned under the block word and in the
default mode; all ten 0.3.26 verdicts move, by design; this sentence said nine
until 0.3.28 corrected it). Every citation is `src/script/interpreter.cpp`
unless named.

- **A truncated push is a parse failure, not a shorter push.** A push that
  declares more bytes than the script holds (a direct push cut short, a
  `OP_PUSHDATA1/2/4` whose length bytes or data are missing) is refused when
  the interpreter's walk reaches it, executed or not: the reference's `GetOp`
  returns false (`script.h:190-191`) and the script is
  `SCRIPT_ERR_BAD_OPCODE` (`450-451`). `Script::from_binary` stays lenient (a
  container, as the TypeScript SDK's is); the new `Script::truncated_push()`
  names the chunk, and `Spend` refuses there: `A push declares more bytes than
  the script holds; the script cannot be parsed past it (pc=N).` Bytes after a
  top-level `OP_RETURN` are data on both sides and are not examined.
- **An undefined opcode executed is a failure.** `0xba`-`0xff` were NOPs; the
  reference's `default:` is `SCRIPT_ERR_BAD_OPCODE` when one is executed
  (`1795`; the TypeScript SDK agrees). They now fall to the invalid-opcode arm
  (`Invalid opcode N (pc=M).`); in an unexecuted branch they are still skipped.
- **One `OP_ELSE` per `OP_IF` after Genesis.** A second `OP_ELSE` for the same
  `OP_IF`/`OP_NOTIF` is unbalanced (`conditional_tracker.cpp:51-55`,
  `829-831`): `OP_ELSE may only be used once for each OP_IF or OP_NOTIF after
  Genesis.` (the TypeScript SDK's text, which applies it only under explicit
  flags; every UTXO here is post-Genesis, so it applies in every mode).
- **The post-Chronicle UTXO opcodes are implemented.** For a coin created after
  Chronicle, `OP_2MUL` and `OP_2DIV` compute (`1247-1254`; `-7 OP_2DIV` is
  `-3`, toward zero), `OP_VER` pushes the transaction version as 4
  little-endian bytes (`598-608`), `OP_VERIF`/`OP_VERNOTIF` are conditionals on
  "the top element is exactly those 4 bytes" (`773-812`), and `0xb3`-`0xb7`
  are `OP_SUBSTR`, `OP_LEFT`, `OP_RIGHT`, `OP_LSHIFTNUM`, `OP_RSHIFTNUM`
  (`609-764`; the two shifts act on script numbers, a right shift toward zero
  as OpenSSL's `BN_rshift` does, a left shift refused before it is computed
  when its result would not fit the memory budget, a local `ScriptResourceLimit`
  where the reference's bound is its consensus number length). Before
  Chronicle the two arithmetic opcodes stay disabled, the three version opcodes
  are refused when executed (`OP_VER is disabled until Chronicle.`) and skipped
  when not (post-Genesis, `773-781`), and `0xb3`-`0xb7` are NOPs (discouraged
  under `DISCOURAGE_UPGRADABLE_NOPS`). The gate: a word's
  `UTXO_AFTER_CHRONICLE` bit (`ScriptFlags::block(PostChronicle)` sets it);
  without a word, the TypeScript SDK's `isAfterChronicle()`, which is its
  relaxed branch, transaction version > 1; `Spend::set_utxo_after_chronicle`
  overrides either. `0xb3`-`0xb7` keep their `OP_NOP4`-`OP_NOP8` names in ASM
  (this crate's `OP_SUBSTR`/`OP_LEFT`/`OP_RIGHT` constants are the legacy
  `0x7f`-`0x81` names, as before).
- **A FORKID signature's push stays in the scriptCode.** `CleanupScriptCode`
  (`255-263`, applied at `1484` and per signature at `1573-1578`) deletes a
  signature's push from the scriptCode only when the signature does not carry
  `SIGHASH_FORKID`; FORKID is always enabled here, so a non-empty signature is
  never deleted and a signature whose push appears in the scriptCode cannot
  verify (its own bytes are hashed in), as on the reference. An empty signature
  carries no hash type and is still deleted as an `OP_0` push, as on the
  reference. The TypeScript SDK deletes every signature (a stated divergence).
- **A RETURN inside a conditional stops execution but not the walk.** After
  Genesis a non-top-level `OP_RETURN` stops execution while the conditionals
  must still balance and every later opcode must still parse (`856-871` with
  `482`); the interpreter cleared its conditional stack and jumped to the end.
  A top-level `OP_RETURN` still ends the script successfully whatever follows.

### Added

- `Script::truncated_push() -> Option<usize>`, `Spend::set_utxo_after_chronicle(bool)`,
  `BigNumber::shl_bits` and `BigNumber::shr_bits_toward_zero`. `SpendParams`
  and every error text of 0.3.26 are unchanged; `is_opcode_disabled` is
  private.

### Notes — cross-SDK parity

- The TypeScript SDK's default mode already runs the Chronicle opcodes on its
  relaxed branch and refuses undefined opcodes; it applies the single-ELSE rule
  only under explicit flags, keeps a lenient parser that never refuses a
  truncated push, and deletes every signature from the scriptCode. This crate
  follows the reference's consensus rules in every mode and states the three
  differences here.
- The ts-stack census (`tests/conformance_scripts.rs`) re-pins the classes
  these rules touch; the fixtures that expected `BAD_OPCODE` for an undefined
  or truncated opcode, the Chronicle opcodes for a post-Chronicle UTXO, or
  the second-ELSE refusal now pass instead of being counted unsupported.

## [0.3.26] - 2026-09-23

### Added — the node's flag words (`script::flags`)

- `ScriptFlags`: the script verification flag word with bitcoin-sv v1.2.2's
  bit values (`src/script/script_flags.h:13-111`) and names (`from_names`,
  `names`; the node's RPC table, `src/rpc/misc.cpp:1284-1305`), `from_bits`
  (a bit this crate does not know is refused, never ignored), `check` (a word
  this interpreter cannot honor, or one the reference itself refuses, is named:
  no `SIGHASH_FORKID`, no `GENESIS`, no `UTXO_AFTER_GENESIS`, `CHRONICLE`
  without `GENESIS`, `UTXO_AFTER_CHRONICLE` without `UTXO_AFTER_GENESIS`,
  `CLEANSTACK` without `P2SH`), and the two derivations a node makes:
  `ScriptFlags::block(era)`, the block-validation word
  (`src/verify_script_flags.cpp:32-81` with the per-input flags of
  `src/policy/policy.h:226-245`), and `ScriptFlags::standard(era)`, the mempool
  word (`11-30`; `policy.h:178-223`). For a post-Chronicle block they are
  `0x3D462F` and `0x3D47FF`; the standard word is the block word plus exactly
  `NULLDUMMY | MINIMALDATA | DISCOURAGE_UPGRADABLE_NOPS | CLEANSTACK`, which a
  block never carries (`policy.h:178-190`).
- `ProtocolEra` (`PostGenesis`, `PostChronicle`) with the mainnet activation
  heights 620,538 and 943,816 (`src/chainparams.cpp:18,23`) and
  `ProtocolEra::mainnet(height)` (`src/protocol_era.cpp:21-39`).
- `Spend::set_flags(word)` and `Spend::flags()`: every rule the interpreter
  enforces is re-derived from the word and the transaction version exactly as
  the reference derives it at the rule's site, under the reference's version
  gate `EnforceNonMalleability` (`src/script/interpreter.cpp:40-44`: at
  Chronicle a transaction of version 2 or above is malleable and every
  malleability restriction is switched off for it). The rules and their
  sites: MINIMALDATA (`433`), LOW_S (`282-288`), CLEANSTACK (`2436-2445`),
  NULLDUMMY (`1664-1670`), NULLFAIL (`1491-1497`, `1640-1646`), MINIMALIF
  (`795-803`), SIGPUSHONLY (`2321-2334`: post-Chronicle only for version <= 1),
  DISCOURAGE_UPGRADABLE_NOPS (`522`, `565`, `765-771`), COMPRESSED_PUBKEYTYPE
  (`322-327`). A word `check` refuses is reported by `validate` as `Invalid
  verification flags: …`, as the reference reports `SCRIPT_ERR_INVALID_FLAGS`
  (`2312-2313`, `2436-2437`). `set_require_minimal` and `set_require_push_only`
  still override a derived rule when called afterwards. `SpendParams` is
  unchanged; nothing a downstream builds with a literal moved.
- Four rules the interpreter did not have, each active only under a word
  that carries its flag: NULLFAIL (a signature that fails must be the empty
  vector: `OP_CHECKSIG requires failing signatures to be empty.`; for
  CHECKMULTISIG, every signature when the operation fails), MINIMALIF
  (`OP_IF and OP_NOTIF require minimal truth values.`),
  DISCOURAGE_UPGRADABLE_NOPS (an executed `OP_NOP1`-`OP_NOP10`: `… is
  discouraged by verification flags.`; the three texts are the TypeScript
  SDK's), COMPRESSED_PUBKEYTYPE (`The public key must be compressed.`).
- `tests/script_flags_witnesses.rs`: seven witness transactions (200-byte
  transactions with a synthetic previous output), each the smallest case of a
  divergence the differential below found, each pinned under the block word,
  the standard word and the default mode, with the 0.3.24 verdict recorded
  beside it. `examples/script.rs` (and the README block that is that file)
  shows the three verdicts of one untidy version-1 spend.

### Fixed — a consensus oracle can select the block word (Calhooon/bsv-rs#10)

- Used as a consensus validator, the interpreter judged a version-1 spend by
  MINIMALDATA, CLEANSTACK and NULLDUMMY, relay-only rules that no block word
  carries, so it rejected consensus-valid version-1 spends; it had no NULLFAIL
  rule at all; and it applied NULLDUMMY regardless of the transaction version
  where the reference gates it. Found by a differential run of 0.3.24 against
  bitcoin-sv v1.2.2's flag derivation, one witness transaction per divergence.
  On 0.3.25, in its only mode, all seven witnesses diverge from the block word
  (RED, recorded in the pull request); on this release the block word agrees
  with the reference on all seven, and any consumer that judges on the
  network's behalf now selects it with one call.
- The default mode's NULLDUMMY is gated on the transaction version like its
  MINIMALDATA, LOW_S and CLEANSTACK (the TypeScript SDK's
  `shouldEnforceNullDummy` is `!isRelaxed()`): a version-2 CHECKMULTISIG with
  a non-empty dummy is accepted, as the reference accepts it in a block and at
  relay. **This is the only default-mode verdict this release changes**; the
  witness test pins it (one of seven recorded verdicts moves). Everything else
  in the default mode is 0.3.25's: strict for version <= 1, relaxed for
  version >= 2, push-only unlocking scripts at every version, no NULLFAIL.
- `tests/script_mutators_keep_parsed_chunks.rs` reformatted (the 0.3.25 file
  was not `cargo fmt --check`-clean).

### Notes — cross-SDK parity

- The TypeScript SDK's `verifyFlags` applies a flag as given: under explicit
  flags it enforces NULLDUMMY, MINIMALDATA, LOW_S and CLEANSTACK at every
  transaction version, and it has no `CHRONICLE` flag. This crate's words are
  the NODE's words: `set_flags` applies the reference's version gate at the
  reference's sites, so `ScriptFlags::standard(ProtocolEra::PostChronicle)` on
  a version-2 spend enforces none of the four, exactly as a relaying node
  does. The pre-Chronicle words (`ProtocolEra::PostGenesis`) have the gate
  always on, which is the TypeScript explicit-flags behavior for those four.
- The default mode still has no NULLFAIL rule at version <= 1 (TypeScript
  parity), although the reference's block word has carried NULLFAIL since the
  DAA fork (`src/verify_script_flags.cpp:65-69`): a version-1 spend with a
  failing non-empty signature verifies here by default and fails on the
  network. The Go SDK's interpreter takes the same rule as a flag
  (`scriptflag.VerifyNullFail`). Select a word to get the node's answer.
- `UTXO_AFTER_CHRONICLE` is accepted in a word, but the opcodes it re-enables
  on the reference for a coin created after Chronicle (`OP_2MUL`, `OP_2DIV`,
  `OP_VER`, `OP_VERIF`, `OP_VERNOTIF`; the Chronicle meanings of
  `OP_NOP4`-`OP_NOP8`) are not implemented: a script using one is refused as
  disabled, or treated as a NOP, regardless. The next interpreter gap.
- The ts-stack conformance census (`tests/conformance_scripts.rs`) still runs
  the default mode; its `unsupported` classes for NULLFAIL, MINIMALIF and
  DISCOURAGE_UPGRADABLE_NOPS therefore stand, and the class that counted
  "NULLDUMMY always enforced" is re-cut to the version gate. Driving the
  node fixtures through `ScriptFlags::from_names` is the next census step.

## [0.3.25] - 2026-09-22

### Fixed

- Every in-place mutator of `Script` (`write_script`, `write_opcode`, `write_bin`,
  `write_number`, `remove_codeseparators`, `find_and_delete`, `set_chunk_opcode`)
  invalidated the byte cache BEFORE parsing. On a script built with
  `Script::from_binary` (raw bytes cached, chunks parsed lazily) that dropped the
  only source of chunks, the parse ran on nothing, and the script came back EMPTY:
  `set_chunk_opcode` on a 25-byte P2PKH lock serialized to 0 bytes. A downstream
  mutation census (bolt-rs, 2026-08) tested a zero-byte lock and read it as a clean
  result; btg-token #11 fixed it here rather than carry the trap. The order is now
  parse, then invalidate, in all seven. Pinned by
  `tests/script_mutators_keep_parsed_chunks.rs` (six tests, RED on 0.3.24, GREEN here).
  No API or wire change; a `Script` built by `write_*` from empty was never affected.

## [0.3.24] - 2026-09-09

### Added

- `GlobalKVStore::with_resolver(wallet, config, network, resolver)`: build the
  store over a caller-owned `LookupResolver` (a custom facilitator, pinned
  SLAP trackers, host overrides, or a test double). `new`/`with_network` are
  unchanged and route through it.
- `examples/`: `keys`, `script`, `transaction`, `brc42`, `beef_spv`, `overlay`,
  each a runnable program that CI compiles (`cargo build --examples
  --all-features`). The README's code blocks are these files byte for byte,
  pinned by `tests/readme_examples.rs`.

### Fixed

- Five `GlobalKVStore` tests asserted an overlay ERROR by relying on the
  network being ABSENT ("without live SLAP hosts the resolver errors"): on
  any machine with a route to the public SLAP trackers the real resolver
  answered and the tests failed. They now inject a resolver with an empty
  host list for the service (the resolver refuses before any request) and a
  facilitator that refuses anyway. The full suite is green online and offline.

### Documented

- `README.md` and `CLAUDE.md` rewritten from scratch: what the crate is and is
  not, the feature matrix from `Cargo.toml`, the interpreter's and BEEF's
  contracts, the conformance discipline (shared vectors + the `ts-stack`
  corpus), the wasm32 story, the known cross-SDK divergences, the release
  procedure, and the measured test counts. The crate docs (`lib.rs`) match.
- The BRC naming: the `auth` module implements BRC-103 mutual authentication
  and its BRC-104 HTTP transport (the successors of BRC-31/Authrite); older
  comments that still say BRC-31 describe the same protocol.

## [0.3.23] - 2026-09-09

### Fixed — reference parity in the script interpreter (`Spend`)

- `OP_NUM2BIN` refuses a size operand larger than the local memory budget BEFORE
  allocating it (the TypeScript SDK's `element-size` check). Previously a
  9-byte script (`OP_1 <1e9> OP_NUM2BIN`) allocated up to
  `MAX_SCRIPT_ELEMENT_SIZE` (1 GB) and only then tripped the stack budget on
  the push — on a Cloudflare Worker that is an isolate kill, not a refusal.
- Resource exhaustion is its own error class: `ScriptEvaluationError` gains
  `resource_limit: Option<ScriptResourceLimit { resource: ScriptResource
  (Stack | AltStack | ElementSize), limit, attempted }>` and
  `is_resource_limit()`, mirroring the SDK's `ScriptResourceLimitError`
  (`'stack' | 'alt-stack' | 'element-size'`, the same message shape
  `<label> has exceeded <limit> bytes`). A caller whose bar is the network
  (an overlay door) can now tell the evaluator's budget from the script's
  verdict without matching message text. Every other error keeps
  `resource_limit: None`. (`ScriptEvaluationError` gained a public field; a
  struct literal elsewhere needs `resource_limit: None`.)
- Found by the bsv-low W-A money gate's delta-verify (2026-09-09).

## [0.3.22] - 2026-09-09

### Fixed — BEEF linking is linear and verify walks by txid

- **`Beef::find_atomic_transaction` / `Transaction::from_beef` link each
  distinct unproven parent ONCE, and every later input sourcing the same txid
  gets a bare stub.** 0.3.21 linked every input in full by cloning the
  memoized parent, which is EXPONENTIAL IN MEMORY on a diamond chain: when
  each level spends both outputs of the previous unproven level (a wallet's
  ordinary change chain), every level then carries two full copies of the
  level below it, so 24 levels means 2^24 subtrees and `from_beef` dies on
  memory before verification even starts. The stub is the parent transaction
  itself (its outputs are what the input spends, and it carries the BUMP when
  the BEEF proves it), with every one of ITS inputs' `source_transaction` left
  `None`, so structure and work are linear in the BEEF. A 24-level diamond now
  links to 47 source objects (2 per level) instead of ~2^24, in 57 ms.
  Building a stub never copies a subtree, and the memo is filled before the
  descent, so a BEEF whose source links form a cycle terminates instead of
  recursing forever.
- **`Transaction::verify` walks BY TXID, not by object graph.** It first
  gathers every transaction reachable through `source_transaction` into a map
  keyed by txid (a copy carrying a merkle path wins outright, otherwise the
  copy with the most linked sources, and only the winner is descended), then
  processes each txid exactly once: a proven transaction is checked against
  the chain tracker and not descended; an unproven one is fee-checked when a
  fee model is given, and has every input's script executed with the source
  looked up BY TXID (the txid the input names, falling back to the id of
  whatever source object it holds, as TS does). Nothing is cloned in the walk,
  and no result depends on which copy of a parent an input happens to hold, so
  the linear structure above verifies exactly like a fully duplicated one.
  This is what 0.3.20 lacked: its walk reached a bare clone and refused a
  complete BEEF with `Input N has no source transaction`, which is what pushed
  0.3.21 into cloning everything. Error texts are unchanged (`Input N has no
  source transaction`, `Script validation failed for input N: ...`, `Fee is
  too low`, `Invalid merkle path for transaction ...`).
- **The reference's value rule is now enforced**: an unproven transaction whose
  outputs pay out more than its inputs bring in makes `verify` return
  `Ok(false)`, matching the TS SDK's `outputTotal > inputTotal` check, which
  the Rust walk had never carried. A transaction with no inputs at all is
  exempt (there is no ancestry to weigh it against; it is a synthetic root,
  never something the walk can judge).
- Regression tests: `a_deep_diamond_chain_links_and_verifies_in_linear_time`
  (24 levels: `from_beef` + `verify` in well under a second, and an upper
  bound on the number of linked source objects), the middle-level
  `a_corrupted_signature_in_the_middle_of_the_chain_is_refused`,
  `an_unproven_spend_creating_satoshis_is_refused`, and
  `two_inputs_from_one_unproven_parent_are_both_linked` (now asserting the
  linear structure: input 0 fully linked, input 1 a stub, both verifying).
  The exponential shape was found by the zanaadu overlay engine's own
  regression suite (2026-09-08).

## [0.3.21] - 2026-09-09 (YANKED: links every duplicate input by cloning, exponential on diamond chains; use 0.3.22)

### Fixed — BEEF ancestry linking for every input (ts-sdk parity)

- **`Beef::find_atomic_transaction` / `Transaction::from_beef` link EVERY input's
  `source_transaction` fully, however many inputs source the same
  transaction.** The previous walk kept a `visited` set keyed by txid and
  attached a bare clone to every input after the first, so two inputs sourcing
  the same unproven parent (a covenant output plus that transaction's own
  change, the ordinary shape of a wallet's second spend) left the second copy
  with no sources and no merkle path, and `Transaction::verify` failed it with
  `Input N has no source transaction` for a BEEF that carried everything. The
  TS SDK never sees this because its inputs share one `Transaction` object by
  reference; Rust owns a `Box` per input. The walk now memoizes the fully
  linked transaction per txid and reuses it for every later input: the linked
  structure equals the TS one and the work is linear in the BEEF, never
  exponential along a chain whose spends source two outputs of their parent.
  Regression test `two_inputs_from_one_unproven_parent_are_both_linked`; found
  live on zanaadu beta (2026-09-08) the first day its overlay executed scripts
  on submit.

### Added — midstate-reuse sighash API (`SighashCache`)

- **`primitives::bsv::sighash::SighashCache`** — a cache over one
  transaction's BIP-143 midstates (`hashPrevouts`, `hashSequence`,
  `hashOutputs`), following rust-bitcoin's `SighashCache` pattern. Each
  midstate is computed lazily at most once per scope class and reused across
  inputs; the free functions recompute all three per call, making per-input
  signing of an n-input transaction O(n²) in hashing (a measured ~9× penalty
  at n=50). One cache instance safely serves mixed sighash scopes
  (ALL/NONE/SINGLE × ANYONECANPAY × FORKID). API:
  `SighashCache::new(&RawTransaction)` / `from_parts(...)`,
  `hash_prevouts(scope)`, `hash_sequence(scope)`,
  `hash_outputs(input_index, scope)`,
  `preimage(input_index, subscript, satoshis, scope)`,
  `sighash(...)` (display order), `sighash_for_signing(...)` (signing order).
- `build_sighash_preimage` (and therefore `compute_sighash` /
  `compute_sighash_for_signing`) is now a thin wrapper over a fresh
  single-use `SighashCache` — one preimage implementation in the crate,
  public API and behavior unchanged. Byte-equality is pinned by scope-class
  unit tests, by the 499-vector cross-SDK sighash suite run through the cache
  across every input, and by the 5,116-vector ts-stack conformance census
  (`tests/conformance_scripts.rs`), whose sighash path now exercises the
  cache directly.

### Documented

- RFC 6979 digest-domain note on `PrivateKey::sign` and in the `sighash`
  module docs: for a digest >= n (P ≈ 2⁻¹²⁸ for sha256d output), k256 seeds
  the nonce DRBG with `bits2octets(digest)` per the RFC while libsecp256k1
  and `@bsv/sdk` seed it with the raw digest bytes — deterministic signature
  bytes differ across stacks in that regime only; in-range digests are signed
  byte-identically. Pinned by `rfc6979_in_range_digest_der_is_pinned` and
  `rfc6979_digest_ge_n_der_is_pinned` in `tests/ec_tests.rs`.

## [0.3.19] — 2026-08-25

### Fixed — BEEF merkle-path reattachment (ts-sdk parity)

- **`Transaction::from_beef` and `Beef::find_atomic_transaction` dropped the
  merkle path.** Both cloned the parsed transaction out of the BEEF, so the
  returned transaction carried `merkle_path: None` even when the BEEF proved
  it — every caller asking "is this mined?" got "no" forever. Bumps live in
  `Beef::bumps` and are referenced by `BeefTx::bump_index` rather than being
  stored inside the transaction, so they must be reattached explicitly.
  This diverged from the TypeScript reference: `@bsv/sdk`'s
  `Transaction.fromBEEF` resolves the target txid and calls
  `Beef.findAtomicTransaction`, which runs `addInputProof` to set
  `current.merklePath` and link input sources.
- **`Beef::add_input_proof`** (private) ports that traversal: walk the
  transaction graph, attach the BUMP where one exists and stop descending that
  branch (a proven transaction needs no ancestry), otherwise link each input's
  `source_transaction` from the BEEF and continue into it. `from_beef` now
  routes through `find_atomic_transaction` the way `fromBEEF` routes through
  `findAtomicTransaction`, so both entry points behave identically.
- Regression tests are proven non-vacuous (reverting the fix fails them), and
  the fixture builds its BEEF through this crate's own writer so it cannot
  drift from the wire format.

## [0.3.16] — 2026-07-09

### Fixed — Spend engine ts-sdk parity

Four `Spend` divergences from the TypeScript `@bsv/sdk` engine, surfaced by
executing large OP_PUSH_TX-style covenant scripts that are valid under ts-sdk
and accepted by mainnet nodes but failed bsv-rs local validation:

- **Version-based relaxed mode.** ts-sdk runs transactions with version > 1
  under post-Genesis "relaxed" semantics (`Spend.isRelaxed()`): MINIMALDATA,
  LOW_S and CLEANSTACK are not enforced. bsv-rs enforced all three
  unconditionally. `Spend` now mirrors ts-sdk (version <= 1 keeps the strict
  behavior), with explicit overrides via `set_require_minimal()`.
  27 previously-unsupported cross-SDK conformance vectors now execute and
  pass (census repinned in `tests/conformance_scripts.rs`).
- **Combined-script CHECKSIG subscript.** When a CHECKSIG executes in the
  unlocking script after an OP_CODESEPARATOR, the signed subscript continues
  across the unlock/lock boundary into the full locking script (legacy
  combined-script consensus semantics, matching ts-sdk and node behavior).
  bsv-rs previously truncated the subscript at the unlocking script, wrongly
  rejecting OP_PUSH_TX-style in-script signatures. The unlock→lock context
  switch now also resets `last_code_separator`, clears the alt stack, and
  requires terminated conditionals, as ts-sdk does.
- **High-S signature verification.** `ecdsa::verify` normalizes signatures to
  low-S before k256 `verify_prehash`, which rejects high-S by default. ECDSA
  (and consensus) accepts both `(r, s)` and `(r, n − s)`; low-S remains a
  script-layer *policy*, now correctly scoped to strict (version <= 1) mode.
- **Push-only opt-out.** `Spend::set_require_push_only(false)` allows
  executable code in unlocking scripts, which ts-sdk permits (the default
  remains enforced).

### Added

- `Transaction::invalidate_caches()` is now public: `inputs`/`outputs` are
  public fields, and mutating them directly (e.g. setting an output's
  satoshis or an input's `unlocking_script`) left `to_binary()`/`hash()`/
  `id()` returning stale cached serializations with no way to flush them.

## [0.3.14] — 2026-07-04

### Fixed

- **Panic / OOM-abort on adversarial length prefixes (bounded pre-allocation).**
  Every parser that pre-allocated a collection sized by an attacker-controlled
  count read from the input (`Vec::with_capacity(count)`,
  `HashMap::with_capacity(count)`, `vec![default; count]`) could be made to
  abort the process with a capacity-overflow / OOM panic *before a single
  element was read*. A ~20-byte crafted BEEF whose transaction input-count
  varint is `0xFE FF FF FF FF` (u32::MAX) makes `Transaction::from_beef` /
  `Transaction::from_binary` allocate billions of `TransactionInput`s and
  abort — a trivially cheap denial-of-service (and on `wasm32`, where the build
  is `panic = abort`, it is unrecoverable: `.ok()` cannot catch it).

  All such sites now bound the pre-allocation to what the remaining buffer could
  actually contain via the new `primitives::bounded_capacity(count, remaining,
  min_elem_bytes)` helper — `count.min(remaining / min_elem_bytes)`. The read
  loop already errors the instant the buffer is exhausted, so parse results are
  unchanged for both valid and malicious input; only the (now bounded) capacity
  hint changes. A bogus count now yields `Err`, never a panic.

  Hardened sites: `transaction::Transaction::{from_reader, from_ef}`
  (input/output counts, and the EF `source_output_index` placeholder-output
  fabrication, which is now rejected above a 16 MiB allocation budget — the
  placeholder length is computed in `u64` via `ef_source_placeholder_len` so the
  `+ 1` cannot overflow on 32-bit targets: on `wasm32` `source_output_index as
  usize + 1` wrapped `u32::MAX` to `0`, defeating the budget check and then
  index-OOB-panicking on a zero-length vec),
  `primitives::bsv::sighash::parse_transaction`, `overlay` binary lookup
  responses, `wallet::wire` (string arrays/maps, action/output/certificate
  arrays, keyrings), and `auth` certificate/header parsing. Purely defensive;
  no API change beyond the additive `bounded_capacity` export → patch bump.

## [0.3.11] — 2026-05-20

### Fixed

- **wasm32 `Peer::to_peer` / BRC-103 handshake hang.** The `wasm` feature now
  enables `futures-timer/wasm-bindgen`. The wasm `wait_with_timeout` helper
  (the `Peer` handshake timeout) races the handshake future against a
  `futures_timer::Delay`, but the `wasm` feature previously pulled
  `futures-timer` *without* its `wasm-bindgen` feature. On
  `wasm32-unknown-unknown` that selected `futures-timer`'s native timer-thread
  backend, so `Delay::new` panicked (`thread::spawn` is unsupported) on the
  first poll — hanging/aborting any `Peer::to_peer` call that initiates a
  handshake inside a Cloudflare Worker or browser `wasm-bindgen-futures`
  executor. Enabling `futures-timer/wasm-bindgen` flips it to the
  `gloo-timers`/`setTimeout` backend, which works in those environments.
  Pure additive feature wiring (no API change) → patch bump.

## [0.3.7] — 2026-04-21

### Added

- **`bsv_rs::overlay::create_signed_overlay_admin_token`** — produces
  TS-parity 5-field signed SHIP/SLAP advertisement tokens. Byte-exact
  match with `@bsv/sdk 1.10.1`'s
  `pushdrop.lock(fields, [2, protocol_name], '1', 'anyone', forSelf=true,
  includeSignature=true, lockPosition='before')` — the exact call
  `@bsv/overlay-discovery-services/src/WalletAdvertiser.ts` makes and
  what `nanostore.babbage.systems` / `overlay-us-1.bsvb.tech` validators
  admit under `tm_ship` / `tm_slap`.

  PushDrop layout:
  ```
  <locking_pubkey:33>  OP_CHECKSIG
  <"SHIP"|"SLAP">
  <identity_key:33>
  <domain>
  <topic_or_service>
  <signature_der>
  OP_2DROP OP_2DROP OP_DROP
  ```

  Locking pubkey + signing key are BRC-42 children of `root_key` for
  `protocolID = (SecurityLevel::Counterparty, "service host interconnect"
  | "service lookup availability")`, `keyID = "1"`, `counterparty =
  Anyone`, `forSelf = true`. Signature is ECDSA (RFC 6979 deterministic)
  over `sha256(concat(fields[0..4]))`.

  Takes `&PrivateKey` (not `&PublicKey`) because the function has to
  SIGN the advert.

- **`tests/vectors/overlay_admin_token_ts_parity.json`** — byte-exact
  parity vectors generated from `@bsv/sdk 1.10.1`. 5 cases covering SHIP
  (3 inputs, including long topic) + SLAP (2 inputs).

- **`tests/overlay_admin_token_ts_parity_tests.rs`** — blocking parity
  gate: loads the TS vectors and asserts
  `create_signed_overlay_admin_token(...)` reproduces them verbatim,
  plus a determinism guard for RFC-6979 signing.

### Deprecated

- **`bsv_rs::overlay::create_overlay_admin_token`** (soft deprecation,
  still compiles). It emits a 4-field unsigned PushDrop with the
  identity key as locking key — a shape `@bsv/overlay-discovery-services`
  requires but never admits, so any advert built with it is silently
  rejected by peer validators. See the `#[deprecated]` attribute for
  the migration pointer. The `decode_overlay_admin_token` reader still
  accepts both 4- and 5-field shapes for backward-compat.

### Notes — cross-SDK parity

- **Matches TS (`@bsv/sdk` 1.10.1)** byte-exact — the version deployed
  at `nanostore.babbage.systems` and `overlay-us-1.bsvb.tech`. Locking
  key + signing key both use `counterparty=Anyone, forSelf=true`, which
  is what `pushdrop.lock(...)` emits when `WalletAdvertiser.ts` calls
  it.

- **Diverges from Go SDK** (`github.com/bsv-blockchain/go-sdk/overlay/admin-token`).
  Go uses `counterparty=Self, forSelf=false`. By BRC-42 symmetry that
  yields the same locking pubkey, but `createSignature` with
  `counterparty=Self` derives a different signing key, so signatures
  differ and Go-produced tokens fail TS validators too. The Go SDK
  needs its own fix; `bsv-rs` matches the deployed reality.

## Earlier releases (from the release commits; no entries were written at the time)

- 0.3.20 (2026-09-09): the `Transaction::verify` walk that 0.3.21/0.3.22 replaced (refused a complete BEEF whose duplicate-input parents were bare clones).
- 0.3.18 (2026-07-21): `SighashCache`, the midstate-reuse sighash API (documented under 0.3.21 above).
- 0.3.17 (2026-07): the 0.3.16 parity work's follow-up release.
- 0.3.15 (2026-07-07): three conformance-surfaced fixes (two panics, the fee formula).
- 0.3.13 (2026-05-26): the BRC-104 transport timeout fix.
- 0.3.10 (2026-05-20): `SocketIoTransport` (Socket.IO 5 / Engine.IO 4 + BRC-103, substrate-agnostic).
- 0.3.9 (2026-05-19): the wasm32 `SystemTime::now` panic fixed (`js_sys::Date` behind the `wasm` feature).
- 0.3.8 (2026-05-19): the wasm32 runtime-agnostic `Peer` timeout (`futures-timer`).
- 0.3.6 (2026-04-20): the canonical 48-byte nonce, with the legacy 32-byte accept window.
- 0.3.4 and earlier: tracked in git history.

[0.3.7]: https://github.com/Calhooon/bsv-rs/releases/tag/v0.3.7
