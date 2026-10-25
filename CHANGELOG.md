# Changelog

All notable changes to `bsv-rs` are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Changed: the interpreter is split by opcode group (#85)

`src/script/spend.rs` (4,419 lines) is the directory `src/script/spend/`:
`mod.rs` keeps `Spend`, its parameters, `validate`, `step` and the dispatcher
(one static `match`, each arm a direct call to a `pub(super)` method); the
handlers live in `push`, `flow`, `stack_ops`, `splice`, `bitwise`,
`arithmetic` and `crypto`, the stack and its memory count in `stack`, the
budgets and their `ScriptResourceLimit` declines in `limits`, the
script-number reads in `num`, the flag word's setters in `word`, and the six
unit-test modules in files of their own. A refactor: no verdict, error text,
budget or flag site changed, and no public item moved
(`bsv_rs::script::spend::{Spend, SpendParams, TxSpendParams}` and every
public method keep their paths and signatures). The sibling's harness
(`bsv-script-lean` at `8840488`, `harness/run --impl bsv-rs`) is GREEN on all
nine corpora before (run `20261024-215622`) and after (`20261024-222200`),
the per-corpus counts and witness files identical; the ts-stack corpus
totals in `tests/conformance_scripts.rs` and the script witnesses are
unchanged. The census falls: no file over 800 lines under `src/script/spend/`
(40 to 39 files), cognitive complexity over 25 from 2 to 1 (the dispatcher's
52), duplicate windows 8,726 to 8,723, pedantic warnings 2,678 to 2,676;
functions over 60 lines stay 93. The nightly's mutation surface
(`src/script/**/*.rs`) already covers the new files and no per-file floor
named `spend.rs`.

### Changed: the whole-BEEF reader is a mode of the streaming reader (#86)

Two readers were two parsers: `Beef::from_binary` (with `from_hex`,
`from_reader`, `from_binary_with_limits`, and through it
`Transaction::from_beef` and `from_atomic_beef`) read a BEEF with its own
`Reader` code, `MerklePath::from_reader` and `BeefTx::from_reader`, while
`beef_stream` read it with `BeefDecoder`. They disagreed. The differential
`tests/beef_two_readers_agree.rs` feeds every BEEF the tree holds (the
fixtures, the vectors, the Lean's 49 rows, the fuzz seeds, the ts-stack
corpus when `BSV_CONFORMANCE_DIR` is set, a deep chain, and from each of
them every prefix, three single-byte changes at every byte and the
transactions in reverse order) to `Beef::from_binary` then
`Beef::verify_structure`, and to `verify_stream_structure`. On 0.9.0's tree:
64,370 inputs, 29,726 disagreements in 85 classes. Now: 0, and no stated
difference.

The whole reader is the streaming reader's decoder in a collect mode
(`BeefDecoder::collecting`, crate-private): `src/transaction/beef/collect.rs`
builds the `Beef` from the decoder's elements in one pass, the BUMPs by
`Bump::to_merkle_path` (each level's leaves by offset, as before), the
transactions from the bytes the decoder read, in the order written. One
parser, one set of bounds, one set of refusals. The collect mode yields a
transaction whatever its content and keeps the decoder's refusal of it
beside the collection, so a BEEF whose bytes are a frame still parses and
`verify_structure` judges it, as it has since 0.4.1; each element is also
folded into a structure-only `BeefIndex`, so a BEEF whose bytes are refused is
refused with the stream's verdict: the earliest refusal of the reading.
`verify_structure` judges the entries in the order held, one pass, as the
decoder and the fold judge them (`src/transaction/beef/in_memory.rs`: the
stream's `bump_root` on a `MerklePath`, its `check_transaction` on a
`BeefTx`, the atomic table). `beef.rs` keeps the type, the writers, the
merges and the public functions; `merkle_path_root`, `wire_hash` and
`Bump::to_merkle_path` moved from `beef_stream.rs` to `in_memory.rs` (the
method's path is unchanged). No public item was renamed, retyped or moved: a
scratch crate naming every public item of `beef`, `beef_stream` and
`beef_tx`, each fn at its exact signature, each pub-field struct by literal,
each enum matched exhaustively, compiles against 0.9.0 and this tree.

What moved, each where the readers disagreed and the whole path now says
what the stream said:

- **The text of a parse refusal is the stream's**: `BEEF error: invalid BEEF
  at byte N: Reason`, the variant `Error::BeefError`, for every BEEF whose
  bytes are no frame. Through 0.9.0 the whole reader answered
  `Error::ReaderUnderflow`, `BeefError("Invalid BEEF version: 0x...")`,
  `MerklePathError(...)` ("Path cannot be empty", "Missing hash at height",
  "Invalid tree height", "Duplicate offset", `MissingSibling { .. }`),
  `CryptoError` ("non-canonical varint", "exceeds maximum usize"), with no
  offset. Migration: match `Error::BeefError(m)` and read the offset and the
  kind from `m`. The three tests that asserted the old text moved to the
  stream's in their own commit:
  `a_claimed_count_is_refused_for_the_bytes_and_reserves_nothing`
  (`beef_limits`: `ReaderUnderflow`, now `Truncated { needed: 1 }` at the
  byte the first entry was due), `beef_and_merkle_path_agree_on_both_owned_bodies`
  (`merkle_path_lone_leaf`: `MerklePathError("MissingSibling ...")`, now at
  byte 12), `the_whole_path_refuses_a_lone_leaf_at_an_offset_other_than_0`
  (`beef_stream`).
- **Refused by the parse, read before**: a V2 format byte other than 0, 1
  or 2 (read as a raw transaction), a V1 has-BUMP byte other than 0 or 1
  (read as an index), a BUMP leaf flag other than `00`, `01` or `02` (read
  by its bits): `BadFlag`; a leaf offset outside its level:
  `OffsetOutsideTree`; a BUMP above a `u32` height, which was cut to its low
  32 bits and its root keyed there: `RootNotCarried` at the BUMP, the
  stream's refusal under a chain's headers (the in-memory height is a `u32`;
  `a_bump_above_a_u32_height_is_refused_not_cut_to_its_low_bits`, red on
  0.9.0).
- **Refused by `verify_structure`, accepted before**: the node's rules on a
  transaction's content, which the stream applies since 0.5.0 (bsv-stack-lean
  #68) and the
  whole path never did: an unproven coinbase, a value or a running total
  outside `MoneyRange`, a null outpoint in a regular transaction, a repeated
  outpoint (`UnprovenCoinbase`, `ValueOutOfRange`, `NullOutpoint`,
  `DuplicateInput`).
- **A repeated leaf offset, refused on both paths**: a BUMP level that
  carries a second leaf at an offset, agreeing with the earlier one or not,
  is `MismatchedNode { level, offset }` at the second leaf's offset varint
  (the decoder refuses it as it reads the offset; `bump_root` refuses one
  held in memory ahead of its walk). Through 0.9.0 the whole reader refused
  it as `MerklePath::new_unchecked`'s "Duplicate offset", naming no byte, and
  the stream let the earlier leaf stand, accepting a repeat its walk accepted
  (the same hash, a flag-`01` leaf after a hash, a higher level's sibling);
  the lane's draft accepted it on both. The stack's Lean names the refusal
  `duplicateOffset (level, offset)`; `Reason` and `Kind` are exhaustive
  public enums (no `#[non_exhaustive]`, `Kind::ALL: [Kind; 24]`), so no
  variant is added here: a new one is the owner's word. Red before the fold:
  `a_level_0_leaf_repeated_with_the_same_hash_is_refused_on_both_paths`,
  `a_level_0_leaf_repeated_with_a_different_node_is_refused_on_both_paths`,
  `a_higher_level_leaf_repeated_is_refused_on_both_paths`,
  `a_repeated_leaf_offset_in_a_bump_held_in_memory_is_refused_by_verify_structure`
  (`beef_two_readers_agree`).
- **Refused by `verify_structure`, accepted before: a transaction written
  ahead of the parent it spends.** The order is BRC-62's, parents before
  children (`5119a9b` `transactions/0062.md:43,74`; the charter's validity
  clause), as the stream reads it: an input of an unproven transaction that
  names an entry held after it is `InputNamesNoElement`, judged in the order
  held, before `sort_txs` runs. Through 0.9.0 (and the lane's draft)
  `verify_structure` sorted ahead of judging and accepted it, or named the
  next fault. The tests that asserted acceptance moved in their own commit:
  `a_reversed_deep_chain_sorts_in_linear_time_on_a_small_stack`
  (`beef_deep_chain`), now
  `a_reversed_deep_chain_is_refused_and_sorts_in_linear_time_on_a_small_stack`,
  and the differential's exemption of the class (30 inputs without the
  corpus, `fixtures/beef/v1.json#0 reversed` among them, which disagreed
  before the fold).
  `a_transaction_written_ahead_of_its_parent_is_refused_on_the_whole_path`
  (`beef_two_readers_agree`), red before the fold.
- **The kind named when a BEEF holds two faults** is the one the stream
  meets first: the parse's for an earlier element's content or fold, and
  `verify_structure`'s in the order held (through 0.9.0: no input before any
  BUMP index, every stub before any BUMP index, every BUMP index before any
  input).

`fuzz_beef_parser` drives both entry points on every input and asserts they
agree: 60 seconds, 178,958 runs, no disagreement and no
crash.

The cost, against 0.9.0's tree run beside it: `Beef::from_binary` alone 16
to 20 percent faster, and parse then `verify_structure` 12 to 16 percent
faster (3.10 to 3.26 ms against 3.67 to 3.82 ms at 1 MB, 32.6 to 34.2 ms
against 37.7 to 38.8 ms at 10 MB), on the `benches/beef_stream.rs` fixtures,
p50 of 30 runs, three rounds interleaved, load average 9.8 to 10.3. The
node's transaction rules the whole path never ran were not the cost: the lane's
draft measured 10 to 13 percent slower than 0.9.0 because the collector left
each entry's txid unset, so every `txid()` in `verify_structure` (once per
entry for the fold, several times per entry in `sort_txs`, once more for the
atomic table) serialized and hashed the transaction again. The collector now
keeps the hash the decoder computed as the bytes passed (`BeefTx::with_txid`,
crate-private): parse then `verify_structure` went from 3.90 to 4.10 ms and
40.7 to 41.7 ms to the figures above. The streaming reader's bench is
unchanged within 3 percent.

### Fixed: a read BEEF entry names each input txid once (#86)

`BeefTx::update_input_txids` appended without clearing, and the reader
called it twice for an unproven raw transaction (`from_raw_tx`, then again
once the parse was set): `BeefTx::input_txids` named each parent twice and
`SortResult::missing_inputs` a missing parent twice; a second
`set_bump_index` did the same. Each call now computes the list afresh.
`a_read_entry_names_each_input_txid_once` (`beef_tx`), red on 0.9.0.

### Notes: cross-SDK parity (#86)

The whole-BEEF path follows the streaming reader where the reference does
not (CLAUDE.md's divergence list, 0.4.2); the merge adds the stream's
existing rules to it where TS reads otherwise (`ts-stack@4d0ea63`): TS
reads any V2 format byte other than 2 as a raw transaction
(`packages/sdk/src/transaction/BeefTx.ts:293-301`), any nonzero V1 has-BUMP
byte as an index (`:306`), and a leaf flag by its bits
(`MerklePath.ts:133-140`), where both readers here refuse `BadFlag`; TS's
`verifyValid` does not apply the node's transaction rules. A repeated leaf
offset: TS refuses it as it builds the `MerklePath` (`MerklePath.ts:221`,
`Duplicate offset`, at `edf6e03` and `4d0ea63`), Go accepts it with the later
leaf standing (`go-sdk@2ca481c` `transaction/merklepath.go:87-90`), and this
crate refuses it on both paths.

The order of the transactions is BRC-62's on both paths. TS's `verifyValid`
sorts before judging (`ts-stack@edf6e03`
`packages/sdk/src/transaction/Beef.ts:1065`, `sortTxs`), and so does Go's
(`go-sdk@2ca481c` `transaction/beef.go:1240-1243`, `ValidateTransactions`):
both accept a transaction written ahead of its parent, the reference's
leniency against the BRC's "must". This crate refuses it on both paths, by
the charter (`InputNamesNoElement`); the stack records the divergence row
(child before parent, two transactions).

### Changed: the BIP-39 wordlists are data, not code (#89)

The nine `src/compat/bip39/wordlists/<language>.rs` tables (11,055 lines of
string literals) are nine text files, `<language>.txt`: one word per line,
2048 lines, LF. Each `pub static` (`ENGLISH`, `JAPANESE`, ...) keeps its name
and its type `[&str; 2048]`; its initializer is now a private `const fn` over
`include_str!` of the file, so the arrays are built by the compiler as before
(no build script, no lazy initialization, nothing at runtime), and a file with
another line count, an empty line, a CR or no final LF fails the build. No
public item moved; no word changed: the files are the old arrays byte for
byte, pinned by sha256 in `tests/compat_bip39_wordlist_files.rs`.
`.gitattributes` keeps the files out of line-ending conversion. The ratchet's
path exemption for the nine `.rs` files went with them (`tools/ratchet`; the
census reads `.rs` only, so no counter moves). `verify_english_wordlist`
gains `#[must_use]` (additive; a caller that drops its `bool` now gets a
warning), which offsets the one pedantic warning the parser's local array
adds, so the pedantic census stays where it was.

### Notes: cross-SDK parity

The English, Chinese Simplified, Chinese Traditional, Czech and Italian files
are byte-identical to `bitcoin/bips@100ba872` `bip-0039/`. Upstream's French,
Japanese, Korean and Spanish files are Unicode NFD, as the Go SDK ships them
(`go-sdk@2ca481c` `compat/bip39/wordlists/{french,japanese,korean,spanish}.go`,
its `init` checking upstream's crc32) and as BIP-39 asks of a wordlist
(`bip-0039.mediawiki:86-87` at that commit: NFKD); this crate's arrays have
always been their NFC form, and the files keep that, a refactor carrying no
behavior change. The behavior it keeps: `Mnemonic::word_index` compares bytes,
so an NFD phrase from Go or a Trezor-style wallet is refused here as
`InvalidMnemonicWord` and never reaches `to_seed`; a phrase that parses seeds
the same either way (`to_seed` normalizes to NFKD). The fix, normalizing both
sides of the lookup, changes what a phrase is and waits on the owner's word
(the follow-up issue in CLAUDE.md's divergence list).

### Changed: the transport fault typed end to end (#87)

0.8.2 (#73) typed the bare 502, 503, 504, connection error and timeout in
`HttpWalletJson` only. Every other transport classified a failure by where it
happened, not by what it meant: every broadcaster send error was
`NETWORK_ERROR`, so a wallet could not tell a refused connection (the inputs
may be released) from a timeout after the transaction was written (the stub
relayed it: the inputs must be held; witness #65, W-SDK-1); each broadcaster
decoded the body before it read the status, so a 429 with a `text/plain` body
was `PARSE_ERROR` and its `Retry-After` was read nowhere (witness #66,
W-SDK-2); the auth transports answered `AuthError(String)` for a fault.

One classifier (`src/transaction/broadcasters/transport_fault.rs`,
`pub(crate)`) reads a `reqwest::Error`'s kind and an answer's status, before
the body, into the class `TransportFault` (new, `#[non_exhaustive]`,
re-exported at the crate root and from `transaction`): `NeverSent` (no byte
left: a connection never made, a request that could not be built),
`MayHaveBeenReceived` (a timeout, a reset or a body cut after the request was
written, a 502, 503 or 504), `RateLimited { retry_after_ms }` (a 429, or a 503
with `Retry-After`, whatever the body; delta seconds or an HTTP date,
saturating, `None` when absent or unreadable). A body cut is a body read
that fails on the way: reqwest gives every failure of `bytes`, `text` and
`json` the decode kind, so the classifier reads the error's source by type,
a decode error whose source is not a `serde_json::Error` a cut, one whose
source is the parse failure it is (`PARSE_ERROR`, `InvalidResponse`,
`WalletError`). On wasm32 the fetch API does not say whether a connection
was made, so a send failure there is never `NeverSent`. Every HTTP site of the four transport directories asks it; none
classifies by text. Busy stays the body's word. What each directory answers:

- **Broadcasters** (ARC, Teranode, WhatsOnChain): `BroadcastFailure.code` is
  `NEVER_SENT`, `MAY_HAVE_BEEN_RECEIVED` or `RATE_LIMITED` beside the
  services' own codes; `txid` is set; `more` is `{"status": n}` for an
  answered fault and `{"status": 429, "retry_after_ms": n|null}` for a rate
  limit; `BroadcastFailure::transport_fault()` reads the class back. A 500, a
  4xx and a 2xx are read as before (an ARC 500 with no body is still
  `PARSE_ERROR`, #65's S2 half). No field was added to the struct.
- **Auth transports**: `Error::TransportFault { fault, status, detail }`
  (new variant; `Error` is `#[non_exhaustive]`, so it is additive) for a send
  or body-read fault on both `SimplifiedFetchTransport` paths, a handshake
  answered 429, 502, 503 or 504, and a Socket.IO sink failure
  (`MayHaveBeenReceived`); the detail is the old `AuthError` text. Any other
  handshake status stays `AuthError`; a General answer of any status is still
  passed to the caller as its `HttpResponse`. The WebSocket transport keeps
  `TransportError` (below).
- **Wallet substrates**: `Error::WalletTransport` as in 0.8.2, now from both
  `HttpWalletJson` and `HttpWalletWire` (which answered `WalletError` for a
  connection error, a timeout and a 502, 503 or 504), and for a body cut (was
  `WalletError`); a 429 without a busy code is `Error::TransportFault` with
  `RateLimited` and its wait (was `WalletError`). A 503 with `Retry-After`
  and no busy code stays `WalletTransport { status: Some(503) }` at both
  substrates (a 503 whose body carries a numeric wallet code stays
  `WalletError`, as in 0.8.2), the one place the rule's "a 503 with `Retry-After` is
  `RATE_LIMITED`" is set aside, to keep the shape 0.8.2's `HttpWalletJson`
  answered and pinned (`an_html_503_from_a_proxy_is_a_transport_fault`); its
  wait is not carried there. `Error::transport_fault()` reads the class of either variant
  (`WalletTransport` as `MayHaveBeenReceived`; busy is `None`).
- **Chain trackers** (WhatsOnChain, the headers service):
  `ChainTrackerError::TransportFault { fault, status, detail }` (new variant,
  the three fields of `Error::TransportFault`, the same class; the enum
  becomes `#[non_exhaustive]`, below) for a send fault (`NeverSent` or
  `MayHaveBeenReceived`, status `None`), a body cut (`MayHaveBeenReceived`)
  and a 429, 502, 503 or 504 (the class and its wait, status `Some`, detail
  `HTTP 429 Too Many Requests`). `InvalidResponse` stays for a body that
  parsed wrong and any other status; `BlockNotFound` and `Other` are
  unchanged; `NetworkError` stays for a tracker built without `http`.
  `ChainTrackerError::transport_fault()` reads the class back, and the new
  `From<ChainTrackerError> for Error` carries it to `Error::TransportFault`,
  so `Transaction::verify` answers a tracker's fault as
  `Error::TransportFault` (was `TransactionError("Chain tracker error: ...")`,
  which every other tracker error still is). A fault is never `Ok(false)`.

**The old words.** A code word is a rule's word, not a compatibility
promise; each gives way here:

- `NETWORK_ERROR` (a broadcaster's send error) to `NEVER_SENT` (a connection
  never made, a request that could not be built) or `MAY_HAVE_BEEN_RECEIVED`
  (every other send error, a timeout included).
- `PARSE_ERROR` (ARC's 429 and its 503 without a body; a body cut at every
  broadcaster) to `RATE_LIMITED` (a 429, a 503 with `Retry-After`) or
  `MAY_HAVE_BEEN_RECEIVED` (a 502, 503 or 504, a body cut).
- Teranode's and WhatsOnChain's `"429"` and `"503"` (and `"502"`, `"504"`)
  to `RATE_LIMITED` or `MAY_HAVE_BEEN_RECEIVED` the same way, the status in
  `more["status"]`.
- `Error::AuthError` on a transport failure (a connection error, a timeout,
  a body cut, a handshake answered 429, 502, 503 or 504) to
  `Error::TransportFault`, its detail the old text; `HttpWalletWire`'s
  `WalletError` on one to `Error::WalletTransport` (a 429 to
  `Error::TransportFault`); a tracker's `NetworkError` on a send error or a
  body cut, and its `InvalidResponse` on a 429, 502, 503 or 504, to
  `ChainTrackerError::TransportFault`, and `Transaction::verify`'s
  `TransactionError` on one to `Error::TransportFault`.

**Migration.** A downstream that matched any of those texts reads
`transport_fault()` instead (`BroadcastFailure::transport_fault()`,
`Error::transport_fault()`, `ChainTrackerError::transport_fault()`): `Some`
of the class for a fault, `None` for the far side's answer. A `match` on
`Error` already has a wildcard arm (`#[non_exhaustive]`).
`ChainTrackerError` is `#[non_exhaustive]` from this release (the owner's
word of 2026-10-24): an exhaustive `match` on it downstream adds a wildcard
arm (`_ => ...`), and the semver check reads the release as a minor; a
downstream that builds a `ChainTrackerError` variant (bsv-wallet-toolbox-rs's
`NetworkError` at `chaintracks_client.rs:262` and
`fallback_chain_tracker.rs:282,306,342`) still compiles, and the toolbox has
no exhaustive `match` on the enum (its tests read it with `matches!`).

Tests, RED on the pre-fix sites (the type present, the sites unchanged) and
GREEN after: `tests/transport_fault_broadcasters.rs` (9; #65's and #66's
witnesses as `a_timeout_after_the_body_was_written_may_have_been_received`
and `a_429_with_retry_after_and_a_text_body_is_rate_limited_with_its_wait`),
`transport_fault_trackers.rs` (7, the typed variant from the fold of
2026-10-24, `a_trackers_transport_fault_reaches_the_crate_error_typed`
among them), `transport_fault_wallet.rs` (7),
`transport_fault_auth.rs` (9). The cold review found the body cut read as a
parse failure (the classifier asked `is_body()`, which reqwest 0.12.28 never
sets for a body read): each file's `body_cut` test answers 200 with
`Content-Length: 200`, twelve body bytes and a close from a raw
`tokio::net::TcpListener` (wiremock cannot cut a body), RED on the classifier
before the fold (`PARSE_ERROR`, `InvalidResponse`, `WalletError`,
`AuthError`) and GREEN after;
`a_success_body_that_is_not_json_stays_the_wallet_error` pins the other half. Two existing tests,
`test_arc_broadcast_with_config_timeout` and `test_teranode_broadcast_timeout`,
pinned `NETWORK_ERROR` for a timeout after the request was written, which is
#65's defect; they now read `MAY_HAVE_BEEN_RECEIVED` (their own commit).
`test_woc_tracker_current_height_server_error` pinned a bare 503 as
`InvalidResponse`; it now reads `ChainTrackerError::TransportFault`
(`MayHaveBeenReceived`, status 503).

### Notes: cross-SDK parity

The references do not type the fault. TS's `ARC.broadcast` answers code
`'500'` for a thrown fetch and the status as a string for a non-2xx
(`ts-sdk@9e3ede6` `src/transaction/broadcasters/ARC.ts:189-195, 219-222`);
`HTTPWalletJSON` throws an `Error` of a JSON text for a non-2xx (`:87-107`);
`SimplifiedFetchTransport` throws its network error (`:66, 147`); nothing
under `src/` reads `Retry-After`. Go's `Arc.BroadcastCtx` answers `"500"` for
any error of `ArcBroadcast`, which decodes the body as JSON before it records
the status, so a 429 with a text body is `"500"` (`go-sdk@2ca481c`
`transaction/broadcaster/arc.go:162-180, 245-249`), and the status as a
string otherwise (`:318-321`); no `Retry-After`. This crate goes beyond both
by the stack's rule (the owner's, matrix rows 26 and 30, `lean/Sdk.lean`):
busy is the body's word, a 502, 503 or 504 without it, a connection error or
a timeout is a fault with no promise, a broadcaster's fault says whether the
request was sent, and a rate limit is never a verdict. The wire, every
request the crate sends and every success path are unchanged.

### Added: a minimal-length-key HMAC tag refused by name (#148)

BRC-56 keys the HMAC with the shared point's X coordinate as exactly 32
big-endian bytes, leading zero bytes included (`bsv-blockchain/BRCs` at
`5119a9b`, `wallet/0056.md:66`); an implementation that encodes the key
minimal-length drops those bytes and makes another tag, for about one derived
key in 256 (`:73`). This crate keeps the 32 bytes. `verify_hmac` still accepts
the 32-byte-key tag only; on a miss whose key begins with a zero byte it
computes the tag once more under the minimal-length key and, when that one
matches, answers the new `Error::HmacMinimalLengthKey { leading_zero_bytes }`
("HMAC is not valid: the tag was made under a minimal-length key ..."), which
names the sender's encoding. Nothing is accepted twice. A tag matching neither
key is `WalletError("HMAC is not valid")` as before; `create_hmac` is
unchanged. The async `WalletInterface::verify_hmac` goes through the same
path. `tests/wallet_brc56_hmac_tests.rs` holds the six vectors of
`wallet/0056.md:91-96` (inputs at `:81-85`): `create_hmac` reproduces the six
tags and `derive_symmetric_key` the six keys byte for byte, `verify_hmac`
accepts the six, the four minimal-length tags (the rows whose key begins with
one or two zero bytes) are refused by name, RED before this change (they read
`HMAC is not valid`), and the two rows with no leading zero byte have one
encoding and no refusal path. The line's pin `ed1b015` carries no BRC-56
vectors and no paragraph on the encoding; the vectors are upstream, not on the
line, taken by the owner's word. The variant is additive under the
`#[non_exhaustive]` `Error`. The crate holds no counter a host reads: the
refusal is the count's event, and a host counts it.

### Notes: cross-SDK parity

ts-sdk makes the HMAC under the minimal-length key: `deriveSymmetricKey`
builds the key from `x.toArray()` (`ts-stack@edf6e03`
`packages/sdk/src/wallet/KeyDeriver.ts:270`; `ts-sdk@9e3ede6`
`src/wallet/KeyDeriver.ts:202`) and `createHmac` and `verifyHmac` key the HMAC
with `key.toArray()` (ts-stack@edf6e03 `ProtoWallet.ts:295,311`; ts-sdk@9e3ede6 `:212,226`), a `BigNumber`'s minimal
big-endian bytes. This crate makes it under the 32 bytes, as the Go SDK does
(`NewSymmetricKey` left-pads to 32, go-sdk@`2ca481c`
`primitives/ec/symmetric.go:82-90`), and as Python and rs-sdk do by the
keeper's ruling of 2026-10-24. For one key in 256 a ts-sdk tag fails here; the
refusal names that gap rather than accept it.

### Security: RUSTSEC-2026-0387, k256 and p256 to the 0.14 line (#125)

RUSTSEC-2026-0387 (timing variability in crypto-bigint's constant-time
operations) reached every dependent through k256 0.13.4 and p256 0.13.2, both
on crypto-bigint 0.5.5, which no 0.5 release fixes. k256 and p256 move to
0.14.0 (elliptic-curve 0.14.1, crypto-bigint 0.7.6); the hashes move with them
to their digest 0.11 releases so the crate signs and hashes on one digest
generation: sha2 0.10 to 0.11, sha1 0.10 to 0.11, hmac 0.12 to 0.13, pbkdf2
0.12 to 0.13, ripemd 0.1 to 0.2. aes-gcm, aes, cbc and subtle stay where they
were (the resolver asks nothing of them). No public type, function signature
or error text of bsv-rs changed. `cargo deny --locked check` is clean on the
three graphs with an empty ignore list.

k256 and p256 are built without their default features: their `std` turns on
`getrandom` 0.4, which has no wasm32-unknown-unknown backend without its own
`wasm_js` feature. `PrivateKey::random` and `P256PrivateKey::random` draw 32
bytes from the OS CSPRNG through this crate's `getrandom` 0.2 and refuse zero
and values at or above n, the rejection sampling the 0.13 `SecretKey::random`
did. `primeorder` is named with only `std` so the curves keep their
precomputed basepoint tables.

### Notes: cross-SDK parity

For a digest at or above n, k256 0.14's deterministic signature is the one
`@bsv/sdk` 2.0.16 (`ECDSA.sign`) and the Go SDK (`signRFC6979`, the clone at
`2ca481c`) produce: derived with both on 2026-10-24 for the pinned key and
digest, `3045022100dd92…cf39`, byte for byte. k256 0.13 signed that regime
differently, which this crate pinned and listed as a divergence; the pin
(`rfc6979_digest_ge_n_der_is_pinned`, `tests/ec_tests.rs`) now holds the
references' bytes and the divergence left the list (the captain's ruling
under rule 1). Every digest below n signs as before. Which step of the nonce
derivation differed between the two k256 lines is not stated here: the
derivation is the evidence, not a reading of the libraries.

### Fixed: a dead function under every slice without `script` (#115)

`after_last_code_separator` (`primitives/bsv/sighash.rs`) has one caller, the
script templates' signing path, but compiled under `primitives`, so a consumer
building `block`, `primitives`, `compat` or `totp` alone with warnings denied
(the Cloudflare workers' CI) could not build the crate. Found by the dependents
check (#83) on its first hosted run, on chaintracks-cloudflare's `block` slice.
The function is gated on `script`; the `clippy` job now checks each published
slice alone with `-D warnings`, which was RED on the pre-fix tree for the four
slices and is the pin.

### Fixed: a certificate length that wrapped the reader's bounds check (#108)

`Certificate::from_binary` panicked on a field length near `usize::MAX`: its
reader checked `pos + n > len`, the sum wrapped, the check passed and the
slice panicked (an abort on wasm32, and a peer's certificate bytes reach this
reader). The reader now compares a length to the bytes remaining, slices
through `get`, and refuses a varint length that does not fit `usize` rather
than truncating it; the refusal is `Error::ReaderUnderflow`, as for any short
read. `HttpRequest::from_payload` and `HttpResponse::from_payload` had the same
sum, which wrapped on a 32-bit target (a length near `u32::MAX` on wasm32), and
cast an `i64` length to `usize`; they now take each field the same way, with
their error texts unchanged. A valid certificate or payload parses as before.
Found by #82's fuzz lane (`fuzz_auth_messages`); pinned by
`tests/auth_reader_bounds.rs` (`a_certificate_length_that_wraps_the_bounds_check_is_refused`
on the issue's 189 bytes, a constructed `usize::MAX - k`, the HTTP fields):
the three certificate tests RED on the pre-fix tree; the HTTP sites RED on
wasm32 only, a length near `u32::MAX`, which no 64-bit run can show; the 535
crash inputs of the class replay with no panic.

### Fixed: a varint index above `u32::MAX` is refused, never cast (#120)

Five readers took an output or input index as a varint and cast it with
`as u32`, so `u32::MAX + 1` read as index 0 and a frame named a different
outpoint in silence: the wallet wire's outpoint, its `signAction` spend
index, `internalizeAction`'s output index and an action output's index
(`wallet/wire/encoding.rs`), and a certificate's revocation outpoint index
(`auth/certificates/certificate.rs`). The keeper's reading: an index is a
`u32` by the transaction format, so a larger value is not one the wire can
mean, and invalid bytes get a typed refusal naming the field, never a
reinterpretation. The wire reader refuses with its own malformed-field
error, `Error::WalletError("invalid <field>: expected at most 4294967295,
got <n>")`, and the certificate reader with
`Error::CertificateValidationError` in the same words; no valid byte reads
differently. Pinned by one test per site, `u32::MAX` read back exactly and
`u32::MAX + 1` refused, each RED on the pre-fix code
(`*_index_above_u32_max_is_refused_not_truncated`).

### Fixed: nine more `u32` fields of the wallet wire refused above `u32::MAX`, never cast (#122)

The wallet wire read nine more `u32` fields as a varint and cast them, so
`u32::MAX + 1` read as 0: `signAction`'s spend `sequenceNumber` and an action
input's `sequenceNumber`, an action's `version` and `lockTime`
(`wallet/wire/encoding.rs`), `getHeaderForHeight`'s `height`
(`wallet/wire/processor.rs`), and `totalActions`, `totalOutputs` and the two
`totalCertificates` (`listCertificates`, and the one parser both discover methods share) in the
results (`wallet/wire/transceiver.rs`). The keeper's reading of #120 by its own
reasoning: each is a `u32` by the transaction format or by BRC-100's
`PositiveIntegerOrZero` (at most `2^32 - 1`, `ed1b015` `wallet/0100.md:393-401`;
the height `PositiveInteger`, `:403-411`), so a larger value is not one the
wire can mean. #120's helper is now `read_var_int_u32` with an optional
twin for `signAction`'s `-1`-for-absent field, and the refusal is the same
`Error::WalletError("invalid <field>: expected at most 4294967295, got <n>")`,
the field as the frame's table names it. No valid byte reads differently.
Pinned by `tests/wire_u32_field_bounds_tests.rs`, one test per site
(`*_above_u32_max_is_refused_not_truncated`), each RED on the pre-fix code;
a total drives the count of entries read after it, so its `u32::MAX` is shown
accepted by the reader going on to the entry after it.

### Notes: cross-SDK parity

TypeScript's `Reader.readVarIntNum` (`ts-sdk@9e3ede6`
`src/primitives/utils.ts:743-763`, called for these indexes in
`Certificate.ts:169`, `WalletWireProcessor.ts:20` (the outpoint), `:387`
(the spend's input index), `:803` (the internalized output's index) and
`WalletWireTransceiver.ts:756` (the action output's index)) returns any
number up to 2^53 with no `u32` bound, so it reads the same frames as an
index no transaction has. Go's `ReadVarInt32` (go-sdk v1.7.2
`util/reader.go:123-126`, called at `sign_action_args.go:63`,
`internalize_action.go:72` and `list_actions.go:281`) casts to `uint32` and
truncates as this crate did. Both are the references' own gap, not followed
here (rule 1: the divergence stated, the keeper's reading the reason).

The nine fields of #122 the same: TypeScript's unbounded `readVarIntNum` reads
them at `WalletWireProcessor.ts:398` (the spend's `sequenceNumber`) and
`:1407` (`height`), and `WalletWireTransceiver.ts:603` (`totalActions`),
`:699-700` (`version`, `lockTime`), `:738` (the input's `sequenceNumber`),
`:987` (`totalOutputs`), `:1675` and `:1822` (`totalCertificates`); Go's
truncating `ReadVarInt32` (go-sdk v1.7.2 `util/reader.go:123-126`) reads
`totalActions` at `wallet/serializer/list_actions.go:199`, version and lock
time at `:235-236`, the input's sequence number at `:259`, `totalOutputs` at
`list_outputs.go:134` and `height` at `get_header.go:20`, and the two
`totalCertificates` cast `uint32(r.ReadVarInt())` at
`list_certificates.go:132` and `discover_certificates_result.go:37`. The
references' own gap, not followed.

### Added: a guard that CI runs every integration test binary (#146)

`tests/arch_ci_runs_every_test.rs` reads `.github/workflows/ci.yml`,
`Cargo.toml`'s features and every top-level `tests/*.rs`, and refuses, naming
the file, any binary no whole-suite `cargo test --tests` step compiles (its
`#![cfg]` gate read against the step's features), unless allowlisted with its
reason and step (`memory_profiling`, alone under `dhat-profiling`); and any
`--test <name>` in ci.yml with no file behind it. The Test Suite's enumerated
list had drifted to 34 of 73 files; the guard keeps it from drifting again
(`docs/ARCH-RULES.md` section 6).

### Added: internalizeAction refuses a basket insertion's `customInstructions` over 1,000 UTF-8 bytes (#117)

BRC-100 bounds the field since `5119a9b` (`wallet/0100.md:867`, upstream,
not on the line): "at most 1000 UTF-8 bytes unless a supported module
explicitly defines a scoped exception, such as BRC-207. Strings exceeding the
applicable limit must be rejected." At the line's pin `ed1b015`
(`wallet/0100.md:860`) it carries no bound. The TypeScript SDK already refuses
it: `validateBasketInsertion` calls `validateOptionalStringLength(...,
'customInstructions', 0, 1000)` (`ts-stack@edf6e03`
`packages/sdk/src/wallet/validationHelpers.ts:942-946`), which counts UTF-8
bytes (`utf8Bytes(s).length`, `:348-356`). This crate had no internalize
validator at all. By the owner's word of 2026-10-24 (conform), the new
`validation::validate_internalize_action_args` refuses one with
`Error::WalletError("Invalid outputs[i].insertionRemittance.customInstructions:
must be no more than 1000 bytes, got N")`, the shape of the file's byte-length
refusal (`validate_string_length`) (bytes by `str::len`, not characters), and
`ProtoWallet`, `WalletClient`, `HttpWalletJson` and `WalletWireTransceiver`
call it before they act or send. The wire processor's handler does not read
its arguments yet and is unchanged. The scoped exception is not modelled: no
module defines one here. The createAction output's `customInstructions` stays
unbounded, as BRC-100 and TS leave it (`validationHelpers.ts:638`). The
stack's scenario is `2026-10-24-wallet-internalize-custom-instructions-bound`.
Pinned by `tests/wallet_internalize_validation_tests.rs` (1,000 bytes
accepted, 1,001 refused with the field and the count, 250 four-byte
characters accepted and 251 refused, an absent field accepted, a second
output named by its index, the createAction copy unbounded, the ProtoWallet
and HTTP JSON doors refusing before acting or sending), RED on the tree
without the bound. No wire byte or JSON shape changed.

## [0.8.2] - 2026-10-23

### Added: the wallet's transport fault (Calhooon/bsv-rs#73)

The owner's ruling of 2026-10-23 (bsv-stack-lean DECISIONS 13.2): busy is the
body word, never the HTTP status, and a 503 without it is a proxy's or an
edge's answer. 0.8.1 put that answer in `Error::WalletError`, the variant of
a refusal, so a caller could not tell "the way failed, ask again" from "the
wallet refused".

- `Error::WalletTransport { status: Option<u16>, detail: String }`: a caller
  may retry it; it carries no promise about what the wallet did (the request
  may or may not have reached it), which is the one way it differs from
  `WalletBusy`. `Error` is `#[non_exhaustive]`, so the variant is additive.
- `HttpWalletJson` answers it for a 502, 503 or 504 whose body carries no
  busy code (`STORE_BUSY`, `ERR_SERVER_BUSY`) and no numeric wallet code
  (`status` the code, `detail` the usual `HTTP <status> for <method>: <body>`
  text), and for a connection error (refused, reset, DNS) or a timeout
  (`status` `None`). A caller that matched the bare 503's `WalletError` text
  matches `WalletTransport` now.
- Unchanged: `WalletBusy` is read from the body's code at any status; a 4xx,
  a 500, and a 5xx with a numeric wallet code stay `WalletError`;
  `HttpWalletWire` keeps `WalletError`. Nothing in the crate retries.
- The docs rows: `src/wallet/CLAUDE.md` (the error table) and
  `src/wallet/substrates/CLAUDE.md` (error handling) carry the transport
  fault beside the busy row.

## [0.8.1] - 2026-10-22

A patch. The atomic BEEF rule is judged on the subject's graph (BRC-95), not
on wire position. Both readers accept more and refuse no BEEF they accepted
before; no public type changes shape. One persisted format moves: a stream
`Cursor` is written BSC3, and a BSC2 cursor still reads (as BSC3 with no
edge), so no reading restarts.

### Fixed: the atomic rule on the subject's graph (BRC-95; the bsv-dd x402 refund, P0-65)

The rule was positional: the subject the last raw transaction, and every
other entry spent by a LATER raw transaction. The stream marked a parent only
when it was in the index when its child was read (`beef_stream.rs`, the
`referenced` mark in the fold), and `Beef::verify_structure` did the same
walk in the order held (`atomic_rule`). BRC-95 (`BRCs transactions/0095.md`)
defines the rule on the graph (every transaction in the subject's dependency
graph, nothing else present) and says nothing about order. The TypeScript
writer (`@bsv/sdk` 2.1.4 `Beef.sortTxs` / `partitionTxs`) writes every proven
transaction first in encounter order, then the unproven ones in dependency
order: a raw unproven ancestor can follow the proven transaction that spends
it. That wire is legal, and bsv-rs refused it `UnrelatedTransaction` (the
bsv-dd x402 refund). This crate's own `to_binary_atomic`, whose sort mirrors
the reference's, wrote BEEFs its own two readers refused.

- The rule, one walk for both readers (`beef_stream::atomic_unreached`,
  called by `BeefIndex::finish` and `Beef::verify_structure`; the Lean's
  `finish`, bsv-stack-lean `lean/BeefOfAnySize.lean` `walk`/`finish`): the
  subject is a raw transaction of the BEEF, else `SubjectMissing`; every
  other entry, raw or txid-only, is reached from the subject by following
  the inputs of raw entries, proven or not (the owner's ruling, 2026-10-22),
  else `UnrelatedTransaction`. Position is not judged.
- The entry a refusal names (the ruled text, 2026-10-22): the earliest, by
  the trie order (the txid's bytes, each byte's bits reversed, least first),
  of the entries the walk does not reach, at its offset in the stream (the
  whole path's verdict is a `Kind`, naming none). The first cut of this
  release read one flag per entry (some raw entry spends it). That gives the
  same verdict, since the refusal set is empty exactly when every entry is
  reachable (a txid is a hash, so no chain of spends returns), but it names
  a different entry. Beside the subject, take a raw `X` that nothing spends
  and its parent `Y` that only `X` spends. Both are unreached; the flag named
  `X` even when `Y` is earlier, and the walk names `Y`. No flag stands in for
  the edges: two BEEFs with the same flags can leave different entries
  unreached.
- The stream keeps the edges: under a subject, each raw transaction's entry
  holds the txids its inputs name (the Lean's `prevs`), and the walk marks
  entries in place. They are kept only when a subject is known (the caller's,
  or the prefix's: the header precedes the first element;
  `BeefIndex::hold_to_subject`, new); without one nothing walks them.
  `entries()` counts them. `spec_size()` is the Lean's `Index.size`, which
  counts one edge per input of every raw transaction read, with or without a
  subject (a counter here, not a table), and `model_work()` adds the Lean's
  atomic end (one pass over the table and the walk's fuel three times). So the
  Lean's deep rows move, as the Lean's own did (bsv-stack-lean@3bb286e
  `lean/BeefOfAnySize/Scenarios.lean:141,148`): 100,000 links, index 100,004
  to 200,005; 10,000 links atomic, work 680,133 to 740,145 and index 10,004
  to 20,005 (`tests/beef_stream_deep.rs`). The deep chain's `entries` under
  its subject is 2n + 2 (one edge per link).
- The bound: per element, plus 32 bytes per input of a raw transaction, only
  under a subject. An input is 41 bytes or more on the wire, so this is
  linear in the bytes read, but it is not per element. Measured
  (`memory_profiling`): the deep chain under its subject peaks at 352, 281
  and 225 B per element at 1,000, 10,000 and 100,000 links (0.8.0: 274, 219,
  175; the test's bound moves from 320 to 400 B, and the flatness check
  holds). The new row
  (`test_beef_stream_memory_on_proven_transactions_with_many_inputs`, 100
  proven transactions of 1,000 inputs, a 4.1 MB BEEF) peaks at 262 KB
  without a subject and adds 32 B per input under one. The cursor after one
  proven transaction of 10,000 inputs is 238 B without a subject (structure
  only; 249 B with scripts) and 320,305 B under one.
- Unchanged: the spend checks, the BRC-62 clause that a transaction without a
  BUMP spends earlier transactions, the offsets, the twenty-four `Kind`s, the
  `Reason` list.
- The words of two refused shapes move. A subject that is a raw transaction
  of the BEEF is no longer missing: the Lean's W4 rows `wrong_subject` and
  `wrong_subject_true` (the second link of three named) refuse
  `UnrelatedTransaction` at the third link (278, 282; `SubjectMissing` at 4
  until 0.8.0), and `example_atomic_parent` (the BRC-62 example behind a
  prefix naming the parent) `UnrelatedTransaction` at the payment (521).
  `unrelated` and `unrelated_true` keep 278 and 282. All five still refuse;
  with scripts, the rows without `OP_TRUE` outputs are a refused spend first,
  as at 0.8.0. `SubjectMissing` is now a subject the BEEF holds only as a
  txid-only entry, or not at all.
- `Cursor` bytes are BSC3. After the transactions come the inputs counted
  and the edges, one list per raw transaction, by txid strictly ascending
  (`Cursor::from_binary` refuses a list out of order, with a repeat, or
  naming a txid the index does not hold raw). A BSC2 cursor (0.5.0 to 0.8.0)
  reads as BSC3 with no edge. That is sound: the walk from it lacks the edges
  of the transactions read before the cursor, reaches less, and only refuses
  more, never accepting wrongly. A stored atomic reading resumed from BSC2
  accepts when the transactions read before the cursor spend nothing the
  walk needs, and otherwise refuses `UnrelatedTransaction`. The precedent for a cursor format change is
  0.5.0 (BSC1 to BSC2, a minor, BSC1 refused); a patch may move to BSC3
  because a BSC2 cursor still reads. One downstream hand-parses the magic:
  bsv-messagebox-cloudflare-public `src/beef_door.rs:665` (`tip_of` checks
  `b"BSC2"` and answers `DoorError::Internal`, a 500 on every at-rest pause).
  It pins `=0.7.0`, so nothing breaks now; when it moves to 0.8.x, `tip_of`
  must accept BSC3 (the layout it reads is unchanged).
- Tests (`tests/beef_atomic_graph.rs`): one atomic BEEF of seven transactions
  (a raw unproven ancestor that only a proven transaction spends, a proven
  parent and child) in each of its 364 orders the BRC-62 clause allows,
  accepted by the stream with and without scripts and by `verify_structure`
  and `verify_valid`
  (`an_atomic_beef_is_accepted_by_both_readers_in_every_order_its_dependencies_allow`,
  `a_raw_unproven_ancestor_after_its_proven_descendant_is_accepted`); an
  unrelated entry (raw proven, raw unproven, txid-only) at every position,
  refused by all four (`an_unrelated_entry_is_refused_by_both_readers_in_every_order`);
  a subject the BEEF does not carry raw, `SubjectMissing` in every order
  (`a_subject_the_beef_does_not_carry_raw_is_missing_in_every_order`);
  `to_binary_atomic`'s output from each merge order, the closure, accepted by
  both readers (`what_this_crates_writer_writes_its_own_two_readers_accept`,
  rewritten with the writer change below); a cursor at
  every `k` (`a_cursor_carries_the_edges_the_walk_needs`); the
  W4 bytes (`the_leans_w4_bytes_are_refused_under_the_graph_rule`). Six of
  the seven were red on 0.8.0. The review's folds add three, red on the
  first cut of this release: the edges kept only under a subject, counted
  by `entries` (`the_edges_are_kept_only_under_a_subject`), a BSC2 cursor
  read at every `k` (`a_bsc2_cursor_reads_as_bsc3_with_no_edges`), a list
  out of order refused (`a_cursor_whose_edges_are_not_strictly_ascending_is_refused`).
  The walk adds the X/Y pair in both trie orders, both readers refusing and
  the stream naming the earliest unreached entry at its offset:
  `an_unreached_parent_earlier_by_the_trie_order_is_the_entry_named` (`Y`,
  at 124; red on the flag predicate, which named `X` at 187) and
  `an_unreached_child_earlier_by_the_trie_order_is_the_entry_named` (`X`, at
  187). `the_xy_vectors_are_the_pair_this_crates_writer_writes` pins the
  vectors' bytes.
  `tests/beef_stream.rs` pins the moved words
  (`a_subject_whose_graph_leaves_a_later_link_out_is_refused`, the example's
  and the W4 test's).
- Vectors: `tests/transaction/vectors/atomic-beef.json`
  (`sdk.transactions.atomic-beef`, the ts-stack corpus's format, eight vectors)
  is staged for the corpus's `vectors/sdk/transactions/`;
  `tests/conformance_beef.rs` runs it (`conformance_atomic_beef`) from the
  corpus when it carries the file, else from the staged copy. The accepted
  bytes are the writers': Go's `AtomicBytes` (dependency order), TypeScript's
  `toBinaryAtomic` (the partition order; the raw ancestor after its proven
  descendant; an unrelated entry, refused), this crate's `to_binary_atomic`
  before the writer change below (the subject not last); the missing subject
  is hand-built (no writer writes
  an atomic BEEF for a txid it does not hold). Two vectors were red on 0.8.0.
  Those two, `raw-unproven-ancestor-after-proven-descendant` and
  `subject-present-not-last`, are `parity_class` `intended` (with a
  `skip_reason`): `@bsv/sdk` 3.x refuses them (below), so the corpus cannot
  hold them as `required`; `reference_impl` says the expected values are this
  crate's ruling. `conformance_atomic_beef` pins which two. The X/Y pair is
  two vectors, `unrelated-pair-parent-named` and `unrelated-pair-child-named`
  (refused, `required` by the file's class: `@bsv/sdk` 3.x refuses them too,
  as its model in the tests does). Each description names the entry each
  reader names: the stream names `Y` at 124 in the first and `X` at 187 in
  the second, and `conformance_atomic_beef` pins both. The whole path and
  TS 3 name none. The first was red on the flag predicate.

### Changed: the atomic writer emits the BRC-95 closure (what TS 3 and Go write)

`Beef::to_binary_atomic` wrote every entry the `Beef` held. A `Beef` that
merged ancestors behind a proof then emitted a raw ancestor of a proven
transaction, which `@bsv/sdk` 3's readers refuse, and an entry outside the
subject's graph, which every reader but 2.1.4's refuses. It now writes the
subject's closure: from the subject, the inputs of raw entries are
followed, stopping at a transaction a BUMP of this BEEF proves (its BUMP
index names a BUMP whose level 0 carries its txid) and at txid-only
entries; every other entry is dropped, with the BUMPs no kept entry needs,
and the kept BUMPs are renumbered (a txid-only entry keeps the first BUMP
that carries it). The order is the reference's sort, the subject last. This
is `@bsv/sdk` 3's `#collectAtomicTransactions` / `#copySelectedTransactions`
(ts-stack `Beef.ts:375-472`) and go-sdk's `selectAtomicBeef`
(`transaction/beef.go:1719-1749`). The output shrinks by what no reader
needs; nothing it writes is refused by a reader of 0.8.0, TS 2, TS 3 or Go
that accepted the subject's graph. `to_binary` (non-atomic) is unchanged.
A raw entry whose BUMP index is out of range is now an error
(`BeefError`), as Go's is; it was written as is before.

- Tests (`tests/beef_atomic_graph.rs`): a `Beef` holding a proven parent
  and child, a raw unproven ancestor of a proven transaction and an
  unrelated branch writes the closure, accepted by both readers and by the
  TS 3 rule modelled in the test, the ancestor behind the proof and the
  branch absent, three BUMPs renumbered
  (`the_atomic_writer_emits_the_brc95_closure_and_drops_the_rest`); every
  accepted vector of `atomic-beef.json` read and written again is accepted by
  both readers and the TS 3 model, which also refuses exactly the two
  `intended` vectors as they stand
  (`every_accepted_vector_round_trips_through_the_atomic_writer`); the 364
  merge orders write one closure (`what_this_crates_writer_writes_its_own_two_readers_accept`).
  All three red before the change.
- Downstreams that call `to_binary_atomic` (bsv-overlay-cloudflare,
  rust-message-box, bsv-messagebox-cloudflare-public, bsv-wallet-toolbox-rs)
  get the smaller BEEF on their next `cargo update -p bsv-rs`.

### Notes: cross-SDK parity

A stated divergence from the current reference. `@bsv/sdk` 3 (ts-stack
`4d0ea63`, sdk 3.0.0; npm 3.2.1) judges the graph but cuts it at each proven
transaction: `Beef.ts:420-434` (`#collectAtomicTransactions` does not follow
the inputs of an entry `#hasMatchingBump` proves), used by `isAtomic`
(`:482-491`), `verifyValid` (`:1064`) and `Transaction.fromAtomicBEEF`
(`Transaction.ts:311`, "Atomic BEEF contains unrelated transaction data"),
as BRC-95's "up to the point where each input can be confirmed with a Merkle
proof" reads. This crate's readers follow the inputs of every raw entry,
proven or not (the owner's ruling of 2026-10-22), so they accept a raw
ancestor behind a proof that TS 3 refuses: the vectors
`raw-unproven-ancestor-after-proven-descendant` (the bsv-dd shape) and
`subject-present-not-last`. They accept everything TS 3 and Go write, and
what `@bsv/sdk` 2.1.4 writes save an entry outside the graph. 2.1.4's reader
sorts and does not judge the graph: `Transaction.fromAtomicBEEF` and
`Beef.verifyValid` accept the vector with an unrelated entry; its
`toBinaryAtomic` writes that entry, and cuts every entry the sort puts after
the subject (`getBeefForAtomic`, `txs.splice(i + 1)`). go-sdk@v1.7.2's reader
asks only that the subject be present (`NewBeefFromAtomicBytes`); its
`AtomicBytes` writes the subject last and cuts the ancestry at each proof.
`Transaction::from_atomic_beef` finds the subject and does not judge the
graph, where TS 3's `fromAtomicBEEF` does (a divergence older than this
release, now listed in `CLAUDE.md`). A reference bug found on the way, not
followed: 2.1.4's `BeefTx` names an entry built from raw bytes by the
unreversed hash (`BeefTx.ts:51-53`, `toHex(hash256(rawTx))`), and a proven
entry is never parsed, so `Beef.mergeRawTx(raw, bumpIndex)` gives a proven
transaction a byte-reversed txid that nothing finds (the vectors' TypeScript
generator uses `mergeTransaction`). The writer emits the cut closure (the
change above), so what this crate writes, TS 3 reads.

## [0.8.0] - 2026-10-21

Breaking: 0.8.0. `Error` is now `#[non_exhaustive]` and gains `WalletBusy`;
a downstream exhaustive `match` adds a wildcard arm. bsv-wallet-toolbox-rs
(which answers the new variant), bsv-tracker and bsv-wallet-cli repin to
`"0.8"`. The stack's precedent (bsv-stack-lean `docs/RULINGS-2026-10-09.md`
section 2, bsv-middleware-rs 0.3.0): a variant added to an exhaustive public
enum makes the enum `#[non_exhaustive]` and the release a minor.

### Added: `Error::WalletBusy`, a typed busy answer (Calhooon/bsv-wallet-cli#44)

A wallet daemon answered a served `createAction` with 400 `database is locked
(code 517)`. The store's fix lands in bsv-wallet-toolbox-rs (one writer
connection, `BEGIN IMMEDIATE`, a typed `StoreBusy`), but the toolbox's
`WalletInterface` impl could only erase it into `WalletError(String)`, and a
host could only string-match the text. The SDK now has the word, so the path
is typed end to end.

- `Error::WalletBusy { detail: String, retry_after_ms: Option<u64> }`, behind
  `wallet`, Display `wallet busy: {detail}`. The contract (the variant's doc):
  the wallet answered that it refused the call before acting (a contended
  store, a lock not acquired) and promised that nothing was written, built or
  locked, so the caller may repeat the same call unchanged after
  `retry_after_ms`, or after a moment when it is `None`. The SDK reports the
  server's promise; it cannot check it. `retry_after_ms` is unbounded, the
  server's word.
- `HttpWalletJson` reads the body's code `STORE_BUSY` or `ERR_SERVER_BUSY`,
  at any status, as `WalletBusy`: the detail is the body's `message`, else
  its `description`, else the code; `Retry-After` in delta-seconds becomes
  `retry_after_ms` (saturating; the first header when there are two), and an
  HTTP-date, or anything else, reads as `None`. A 503 without it keeps its
  `WalletError` text, as does every other answer, byte for byte. The stack's
  rule (bsv-stack-lean `docs/BSV-NORTH-STAR.md` section 5): the SDK reads the
  status word, never the HTTP code; a proxy's HTML 503 promises nothing.
- Tests: `tests/wallet_http_json_busy_tests.rs` (wiremock; RED on the code
  without the busy branch for the four busy cases):
  `the_producers_store_busy_body_is_wallet_busy_with_the_delay`,
  `store_busy_on_a_500_is_wallet_busy`,
  `the_ts_toolbox_err_server_busy_body_is_wallet_busy_with_its_description`,
  `the_first_of_two_retry_after_headers_wins`,
  `an_html_503_from_a_proxy_stays_wallet_error`,
  `a_503_with_a_message_and_no_code_stays_wallet_error`,
  `a_503_with_a_numeric_code_keeps_the_coded_wallet_error`,
  `a_busy_body_with_an_http_date_retry_after_has_no_delay`,
  `every_other_status_keeps_the_wallet_error_mapping`,
  `wallet_busy_displays_its_detail_and_compares_on_both_fields`; the
  `Retry-After` reader and the body reader in `http_json`'s unit tests.

### Notes: cross-SDK parity

Neither reference SDK's wallet substrate, nor the BRC-100 wire, has a busy
word. ts-stack@edf6e03 `packages/sdk/src/wallet/substrates/HTTPWalletJSON.ts:335-340`
deserializes a wallet error only from a 400 carrying `isError` (codes 5, 6, 7:
`WERR_REVIEW_ACTIONS`, `WERR_INVALID_PARAMETER`, `WERR_INSUFFICIENT_FUNDS`) and
throws `HTTPWalletJSON <call> failed with HTTP status <status>` for every other
failure, the body unread; go-sdk@v1.7.1 `wallet/substrates/http_wallet_json.go:62-64`
(read at the tag; v1.7.2 holds the same lines) reads every non-200 as
`HTTP request failed with status <status>: <body>`. A TS or Go client reading
a busy answer gets that generic error, not this crate's detail. The busy codes
are servers' words: bsv-wallet-cli answers `STORE_BUSY` (503,
`Retry-After: 1`), and the TS wallet toolbox's edge answers capacity with 503
`{code: 'ERR_SERVER_BUSY'}` and `Retry-After: 1`
(`packages/wallet/wallet-toolbox/src/storage/remoting/edgePolicy.ts:668-672`;
overlay-express the same, `packages/overlays/overlay-express/src/security/edgePolicy.ts:671`); this crate's client reads them.
The BRC-100 wire is unchanged: its result frame carries one error byte, the
references define codes 5, 6 and 7 on it (TS's `WERR_*`; Go's
`wallet.Error.Code` names none) and none for busy, so `WalletWireTransceiver`
keeps reading every non-zero byte as `WalletError`.

## [0.7.2] - 2026-10-19

Additive, no migration, as 0.7.1 was: new public API in `block`, nothing existing
changes shape (the stack's keeper on the owner's word of 2026-10-19; a 0.8.0 if the
crate's captain prefers it before the tag).

### Added: the node's difficulty rule (`block`)

0.7.0 left difficulty adjustment to the host. The rule moves here from
chaintracks-cloudflare@74cc110 `src/consensus.rs`, where it was ported from
bitcoin-sv v1.2.3 (`6504a3aff65ba97c0f6c80962b033e35ecbfed4b`); each
function's doc names the node function and the lines it ports. Behind the
existing `block` feature; no new dependency.

- `ChainParams::{main, test, regtest}`: `powLimit`, `nPowTargetSpacing`,
  `nPowTargetTimespan`, `fPowAllowMinDifficultyBlocks`, `fPowNoRetargeting`
  and `daaHeight` (`src/chainparams.cpp:1047-1068`, `:1343-1364`,
  `:1471-1490`), with `difficulty_adjustment_interval`, `pow_limit_bits` and
  `window_depth` (how many ancestors the rule may read). Checkpoints and the
  genesis hash stay the host's. `#[non_exhaustive]`: start from a constructor.
- `next_work_required(params, chain, prev_height, new_time) -> Result<u32,
  DifficultyError>`: `GetNextWorkRequired` (`src/pow.cpp:95-117`) with its
  three regimes: regtest's no-retarget, the legacy retarget with the
  emergency adjustment and testnet's minimum-difficulty rule (`:22-93`,
  `:119-148`), and the DAA (`:177-297`). Also public, as the node exports
  them: `calculate_next_work_required` and `next_cash_work_required`.
- `HeaderAncestry`, the smallest view of the chain the rule reads
  (`link_at(height) -> Option<HeaderLink>`, `HeaderLink { height, time, bits
  }`), implemented for `[HeaderLink]`; its `work_between` defaults to
  `chain_work_between`, the `GetBlockProof` sum the node's `nChainWork`
  difference is (`src/block_index.h:661-666`), and a host that stores chain
  work may override it. `median_time_past` is `GetMedianTimePast`
  (`src/block_index.h:720-737`).
- `DifficultyError` (`#[non_exhaustive]`): `MissingAncestor` (the host does
  not hold a header the rule reads), `ChainTooShort` and `ZeroWork` (where the
  node asserts or throws), `InvalidParams` (a host's parameters with no
  adjustment interval). Nothing panics, on any chain or parameters.
- Tests (`tests/chain_difficulty.rs`, in CI's chain vector step): the node's
  `pow_tests.cpp` tables (`get_next_work` and its three bounds,
  `retargeting_test`, `cash_difficulty_test`) carried over from chaintracks
  with their citations, the regimes' edges, and the real testnet run
  1602530..=1602710 (Teranode v0.16.0's file, sha256 pinned): the 34 headers
  with a full DAA window carry the rule's bits, 8 of them under the
  20-minute rule, and a header mined 600 s after 1602682 at the minimum
  difficulty does not.

### Notes: cross-SDK parity

Neither `@bsv/sdk` (ts-sdk `src/`) nor go-sdk carries a difficulty rule;
there is no SDK function to conform to, so the node decides.

## [0.7.1] - 2026-10-19

### Added: HKDF (RFC 5869), SHA-256 and SHA-512

`primitives::hash` gains HKDF beside PBKDF2: `hkdf_sha256` and
`hkdf_sha512` (extract then expand into a caller's buffer),
`hkdf_sha256_extract` / `hkdf_sha512_extract` (the pseudorandom key) and
`hkdf_sha256_expand` / `hkdf_sha512_expand`, with `HKDF_SHA256_MAX_OKM`
and `HKDF_SHA512_MAX_OKM` (`255 * HashLen`). An empty salt is the RFC's
"not provided" (HashLen zero bytes, the same HMAC key). Expand refuses an
output over `255 * HashLen` (`Error::InvalidDataLength`) and a PRK shorter
than HashLen (`Error::InvalidKeyLength`) without writing the output. No new
dependency: the construction runs on the crate's `hmac` 0.12 and `sha2`
0.10. Additive, no migration.

- RFC 5869 Appendix A, all seven cases: A.1 to A.3 through the public
  HKDF-SHA256 functions (PRK and OKM), A.4 to A.7 (HKDF-SHA1, A.7 with the
  salt not provided) through the same private extract and expand
  (`src/primitives/hash.rs` tests).
- Project Wycheproof `hkdf_sha256_test.json` (86 tests: 83 valid, 3
  `SizeTooLarge` refused) and `hkdf_sha512_test.json` (83 tests: 80 valid, 3
  refused), C2SP/wycheproof at `e0df04e0`, copied under
  `tests/vectors/wycheproof/` with their sha256 pinned
  (`tests/hkdf_wycheproof.rs`).
- HKDF-SHA512 on A.1's and A.3's inputs against OpenSSL's `openssl kdf ...
  HKDF`.

### Notes: cross-SDK parity

Neither `@bsv/sdk` nor go-sdk exposes HKDF; there is no reference function
to conform to, so RFC 5869 and the vectors above decide.

## [0.7.0] - 2026-10-17

### The default signing digest is the node's

`SigningContext::compute_sighash`, the digest every template's `unlock`
(`P2PKH`, `P2PK`, `Multisig`, `RPuzzle`, `PushDrop`) and `Transaction::sign`
sign, disagreed with bitcoin-sv v1.2.3 in three places; each produced a
signature the node refuses.

- The dispatch. The context computed the BIP143 digest for every hash type.
  The node's `SignatureHash` computes BIP143 only for a type that carries
  `SIGHASH_FORKID` and not `SIGHASH_CHRONICLE` (0x20), and the original
  digest for every other type (`src/script/interpreter.cpp:2112-2124`). The
  context now computes through `compute_sighash_dispatched_for_signing`, the
  dispatch the interpreter's verdicts already use
  (`TxSighashCache::sighash_dispatched_for_signing`, pinned equal to it): one
  rule for the signer and the verifier.
- The SINGLE sentinel. Under the original digest, `SIGHASH_SINGLE` with the
  input index at or beyond the outputs signs the constant `one` (`0x01` then
  31 zero bytes in signing order; `interpreter.cpp:2089`, `:2095-2100`). The
  context built a BIP143 preimage with a zero hashOutputs instead. It now
  returns the constant, as the dispatcher does.
- The scriptCode. The context always signed over the source output's locking
  script. Post-Chronicle, a CHECKSIG executing inside the unlocking script
  signs the unlocking script from its last executed `OP_CODESEPARATOR` to
  its end, followed by the locking script (`interpreter.cpp:1471-1481`,
  CHECKMULTISIG `:1569-1576`, gated on `IsChronicle(flags)`; `VerifyScript`
  passes the scriptPubKey as `checksigData`, `:2336-2342`). The context
  cannot know where the CHECKSIG executes, so the scriptCode is now an
  explicit input: the new field `SigningContext::script_code:
  Option<&Script>` and the builder `SigningContext::with_script_code(self,
  &Script) -> Self` set it, and the new function
  `script::chronicle_unlocking_script_code(unlocking: &Script, locking:
  &Script) -> Script` forms the Chronicle one. The default (`None`) stays the
  locking script, which is right for a CHECKSIG in the lock that no executed
  separator precedes. The type's documentation says when it is wrong and what
  to pass.
- An input index the transaction does not have is now an `Err`
  (`Error::CryptoError`) from `compute_sighash`; before, it panicked in the
  preimage builder.

The templates sign `FORKID` types without `CHRONICLE`, so their digests and
signatures are byte-identical to 0.6.1's; what changes is the digest of a
custom template that calls `compute_sighash` with a type without FORKID or
with CHRONICLE.

Pinned in `tests/sighash_tests.rs` (in the CI's sighash step):
`the_default_signing_digest_is_the_dispatchers_for_every_hash_type` (the 18
types of {ALL, NONE, SINGLE} x {with, without ANYONECANPAY} x {FORKID,
FORKID|CHRONICLE, no FORKID}, over every input of generated transactions,
SINGLE beyond the outputs included, and two locks, one with a separator;
2,880 of 4,320 digests differed on 0.6.1),
`a_single_beyond_the_outputs_under_the_original_digest_signs_the_constant_one`,
`a_chronicle_hash_type_signed_through_the_context_verifies_under_the_node_word`
(P2PK spends signed through the context and run under the Chronicle block
word; 0.6.1's 0x61 signature was a false top),
`a_signing_context_naming_an_absent_input_is_an_error_not_a_panic`,
`the_chronicle_script_code_is_the_unlock_after_its_last_separator_then_the_lock`,
`the_chronicle_script_code_reads_separators_as_the_parser_reads_them`,
`a_check_in_the_unlocking_script_signed_over_the_helpers_script_code_verifies`
(the shape `<utxoSig> <sig> OP_CODESEPARATOR <pub> OP_CHECKSIGVERIFY` over
`<utxoPub> OP_CHECKSIG`: valid with the helper's scriptCode for ALL|FORKID
and ALL|FORKID|CHRONICLE, refused with the locking script alone), and the
guard `the_forkid_digest_of_the_templates_is_unchanged`.

Semver: minor. `SigningContext` gains a public field, so a struct literal of
it no longer compiles. The migration is one line: add `script_code: None`,
or build it with `SigningContext::new`. The digest of a non-FORKID or
CHRONICLE type changes.

### The identity token signatures (the review of 0.7.0)

The review of this release found three signing paths that did not reach the
dispatcher: `IdentityClient::revoke_certificate_revelation`, and the contact
update and removal of `ContactsManager` (`add_contact` over a listed contact,
`remove_contact`). Each built the BIP143 preimage, took ONE SHA-256 of it and
passed that to the wallet as `hash_to_directly_sign`, which the wallet signs
as given; the node verifies against the double SHA-256 (`SignatureHashBIP143`,
`ss.GetHash()`). The reference passes `data: sha256(preimage)` and its wallet
hashes `data` again (`@bsv/sdk` 3.0.0 `src/script/templates/PushDrop.ts:245-248`,
`ProtoWallet.ts:62`). Every signature these paths produced was one the node
refuses; the bug predates this release (since `ee3adff`). They now sign
`compute_sighash_dispatched_for_signing` of the same parameters (scope
ALL|FORKID, so the BIP143 digest, double SHA-256). No public signature
changed.

Pinned in `tests/identity_spend_witness.rs`:
`an_identity_revocation_signature_verifies_under_the_node_word`,
`a_contact_update_signature_verifies_under_the_node_word` and
`a_contact_removal_signature_verifies_under_the_node_word` drive each path
against a wallet that records the unlocking script and run it through `Spend`
under `ScriptFlags::block(ProtocolEra::PostChronicle)`; on the code before
the fix each verdict was the NULLFAIL error ("OP_CHECKSIG requires failing
signatures to be empty.").

### Notes: cross-SDK parity

- The scriptCode: the go-sdk and `@bsv/sdk` default templates also sign the
  locking script alone (`go-sdk@v1.7.2`
  `transaction/template/p2pkh/p2pkh.go:83-91`,
  `transaction/signaturehash.go:277`; `@bsv/sdk` 3.0.0
  `src/script/templates/P2PKH.ts:92-100`, `SignatureUtils.ts:153`), so they
  share the default's disagreement for a CHECKSIG in a post-Chronicle
  unlocking script. This crate keeps that default and adds the explicit
  override and helper.
- The SINGLE sentinel is shared with @bsv/sdk 3.0.0's original-digest formatter (7 of the same 241 measured transactions); the Chronicle-bit dispatch was this crate's own disagreement.
  go-sdk's signer dispatches on the CHRONICLE bit (`go-sdk@v1.7.2`
  `transaction/signaturehash.go:26-30`).

### The lint bar (bsv-stack-lean #134, #135, #137, #139, #140, #144, #145)

No public signature changed.

- `[lints]` in `Cargo.toml`: `unsafe_code = "forbid"` (the crate has no
  `unsafe`), `missing_docs = "deny"`, and clippy's `unwrap_used`,
  `expect_used`, `panic`, `todo`, `unimplemented` and `dbg_macro` denied.
  `clippy.toml` lets a test function unwrap, expect and panic; each test,
  bench and example file that needs them carries one allow naming #134.
- The library's 115 unwrap, expect and panic sites: the infallible ones
  rewritten without a panic path (slice-to-array conversions, guarded pops
  and lookups, the curve constants built from bytes); the documented
  `# Panics` contracts and infallible public signatures allowed at the site
  with the reason. `Script::write_bin` and `LookupResolver::new` now document
  their panics.
- Behavior: the host reputation tracker and the cached key deriver read a
  lock poisoned by a panic elsewhere instead of panicking again.
- Docs on every public item: the 261 opcode constants of `script::op`, the
  fields of the `Error` struct variants and of `PowError`, and the wallet
  serde helpers.
- `rust-version = "1.88"` (1.87 refuses `slice::as_chunks`); the gate's
  `msrv` job checks the library on 1.88.0, native and wasm32.
- New gate jobs: `secrets` (gitleaks 8.30.1 over the history, built from a
  sha256-pinned source; judged findings in `.gitleaksignore`), `actionlint`
  (1.7.12, the same way, with a check that every `uses:` is pinned by a
  commit sha) and `unused dependencies` (cargo-machete 0.9.2, non-blocking;
  none found).

Correction (2026-10-17): the parity note above first said both the dispatch and the SINGLE sentinel were this crate's own; the sentinel is shared with @bsv/sdk 3.0.0, as the sentence now reads.

## [0.6.1] - 2026-10-15

### Incremental hashing

- New `primitives::hash::Sha256` and `primitives::hash::Sha256d`: `new()`,
  `update(&[u8])` (returns `&mut Self`, so calls chain), `finalize(self) ->
  [u8; 32]`, `Default`, `Clone`, and a `Debug` that prints no state.
  `Sha256d::finalize` is SHA256(SHA256(everything updated)). The types wrap
  `sha2`; none of its types appear in the public API.
- `sha256` and `sha256d` are now defined through the hashers (one
  implementation); their signatures and results are unchanged.
- The site they serve: the relay's `inline_spool_key`
  (`src/beef_door.rs`), which hashes an inline payment 64 KiB at a time and
  kept a direct `sha2` for it while bsv-rs had one-shot hashes only.
- `tests/hash_stream.rs`: every row of bsv-stack-lean's BEEF-of-any-size
  corpus (`tests/vectors/beef_of_any_size/`) hashed whole and in chunks of 1,
  7, 64 KiB, its full length and seeded random boundaries, against the
  corpus's pinned digests; generated buffers of 0 to 300,000 bytes. Run by
  the vectors job.

## [0.6.0] - 2026-10-14

### Chain primitives

The design is `docs/p0/bsv-rs-060-primitives-design.md` in bsv-stack-lean.
Node rules are cited through bsv-script-lean@50d437b
`lean/BsvChain/{Header,Pow,Merkle}.lean` and `lean/BsvScript/Tx.lean`,
which cite bitcoin-sv v1.2.3 at 6504a3af (#63, #64, #65).

- New `block` feature, enabled by `transaction` and listed in `full`:
  `BlockHeader` (exact 80-byte frame, `version: i32`, internal-order hashes,
  `hash`/`id`), `CompactTarget` (`SetCompact`, negative and overflow flags),
  `U256::to_compact` and `to_compact_signed` (`GetCompact`),
  `check_proof_of_work` with network limits and non-exhaustive `PowError`,
  `ChainWork` (`GetBlockProof`, numeric order, strict 1-to-64-digit hex input),
  `merkle_root`, `block_merkle_root` and `merkle_parent`. List roots carry the
  node's `mutated` flag; a caller accepting a list must refuse a mutated result
  (CVE-2012-2459). Difficulty adjustment remains the host's responsibility.
- New `primitives::U256`: four little-endian u64 limbs, modulo-2^256
  arithmetic, checked division, fixed-width bytes and numeric hex.
- `primitives::Hash32` moves from `transaction::beef_stream`, with a
  compatible re-export at the old path.
- `Reader::read_var_int` now refuses non-canonical encodings, as the node's
  `ReadCompactSize` and ts-sdk's `readVarIntNumStrict` do. This also applies
  to transactions, whole and streaming BEEF, and BUMP parsers.
  `read_var_int_lenient` preserves 0.5's reading. Streaming refusals reuse
  `BadVarint` at the field's leading byte, including across chunk boundaries.
- New `read_compact_size`, `write_compact_size` and `MAX_COMPACT_SIZE` apply
  the node's `MAX_SIZE = u32::MAX`; general varints retain the u64 range.
  `var_int_len`, `to_var_int` and `from_var_int` expose the shared encoding.
  New exhaustive `Error` variants `NonCanonicalVarInt { width, value }`
  (width includes the marker) and `CompactSizeTooLarge`: update exhaustive
  matches. Stored non-canonical transaction, BEEF or BUMP bytes must be
  revalidated when a consumer adopts 0.6.0; no stored data is rewritten here.
- Base58Check signatures and behavior stay unchanged. Rust transcriptions
  of the node's 12 raw base58 rows and 50 key rows, compact-target tables,
  varint refusals, merkle properties and three pinned header runs are tested.
- No dependency added, no serde on the new types. wasm32 builds cover
  `block`, `transaction` and the existing application feature combination.

### Notes - cross-SDK parity

Raw `from_base58` retains the TypeScript SDK's refusal of empty input and
surrounding whitespace (`ts-stack@edf6e03`, `utils.ts:288-296`), differing
from the node's `DecodeBase58` (`src/base58.cpp:25-79` at 6504a3af).
Canonical varints agree with the node and TS strict readers; Go v1.7.1
`util/varint.go:71-105` remains lenient. A host wanting the node's size bound
uses the CompactSize methods. The tests are `canonical_varint`,
`chain_encoding` and `chain_primitives`; the vectors CI job runs all three.

## [0.5.0] - 2026-10-12

### Mining checks in the streaming BEEF reader (bsv-stack-lean #68)

The reading is `docs/readings/mining-checks-against-the-reader.md` in
bsv-stack-lean, sections 1-3. Node rules are cited through
bsv-script-lean@87f0461 `lean/BsvScript/TxRules.lean:25,31-38,85-110`
and `docs/BLOCK-CONSENSUS.md:68,83-88`; the latter cites
bitcoin-sv@879fc8b42 `IsFinalTx` and `COINBASE_MATURITY`.

- Four new exhaustive `Kind` and `Reason` variants, in the decoder and
  hand-built fold, also under `structure_only`: `UnprovenCoinbase` at the
  transaction's leading byte (ahead of `NoOutputs`); `NullOutpoint` at
  the input's previous txid; `DuplicateInput` at the repeating input's
  previous txid; `ValueOutOfRange` at the output value field that leaves
  MoneyRange, individually or in running total. The checks use the
  sibling's order: coinbase, no inputs, no outputs, output values, then
  null and duplicate outpoints in input order. Proven coinbases remain
  allowed; the other byte checks apply with a BUMP index too.
- `Kind::ALL` has 24 entries. `OutputRef` gains public `at: u64`, the
  absolute value-field offset. Update exhaustive matches and hand-built
  output literals. These public changes require the minor release 0.5.0.
- New `SpendRefusal::InputValueOutOfRange` at the input leaving MoneyRange,
  replacing the overflow `Script` string. The unreachable output overflow
  branch of `CreatesValue` is removed; a debug assertion records the bound.
- `Headers::mining_tip() -> Option<ChainTip>` defaults to `None`, and the
  object-safe async `ChainTracker::mining_tip()` defaults to `Ok(None)`.
  Existing implementors compile. `ChainTip` carries `height: u32`,
  `median_time_past: u32`, network `genesis_height: u32` and
  `csv_height: u32`, and `next_block_time: Option<u32>` for a candidate
  block before CSV. References forward the synchronous method.
- `SpendRefusal::P2shOutput { vout }` names the output value field of an
  exact 23-byte P2SH template in an unproven transaction when the next
  block is after Genesis. With no tip, the Genesis era defaults to after
  Genesis. Proven transactions and near-shapes are unchanged.
- `SpendRefusal::NonFinal { lock_time }` names an unproven transaction's
  leading byte when the supplied next-block context fails the node's
  `IsFinalTx`. After CSV time locks use tip median time past; before CSV
  they need the candidate block time. Zero lock time or all-final
  sequences need no tip. A caller that never supplies a tip now receives
  `Verdict::Unverifiable { check: MiningCheck::Finality, .. }` for any
  nonzero lock time with a non-final sequence. This is a fail-closed
  decline, never `Invalid` or `NonFinal`; no tip is guessed. The fold
  returns `Stop::Unverifiable` with the same offset and check.
- `SpendRefusal::PrematureCoinbase { height }` names the spending input
  when a verified coinbase is fewer than 100 blocks old at the next
  block. With no tip the reader declines with
  `Unverifiable { check: MiningCheck::CoinbaseMaturity, .. }`.
  Verified coinbase heights survive retention and cursor round trips.
  Cursors now use `BSC2`; `BSC1` lacks maturity evidence and is rejected.
  Restart old cursors from the beginning of their BEEF.
- Contextual spend checks run only in full mode on unproven transactions.
  `ParentIsTxidOnly`, `OutputNotAvailable`, `Script` and `CreatesValue`
  are unchanged otherwise. Cross-transaction respend stays
  `OutputNotAvailable`; a repeat within one transaction is now invalid
  bytes. Script evaluation keeps the TypeScript default mode; spend-era
  flags and confiscation rules remain the sibling's separate work.

### Notes - cross-SDK parity

Intentional differences from ts-stack@edf6e03: the node's output checks
precede duplicate inputs; the reader also checks P2SH, mining finality and
coinbase maturity. Against go-sdk@v1.7.2, a missing tip is an explicit
unverifiable decline, including a GullibleHeadersClient-style absence,
not a guessed height or an invalid transaction. With a tip the SV node's
block path decides finality, including the pre-CSV candidate block time.
The boundary and refusal-offset witnesses are `tests/beef_stream.rs`;
`tests/mining_tip_api.rs` checks default and reference compatibility.

## [0.4.5] - 2026-10-12

Two rules of bsv-stack-lean L2: the lone leaf at offset 0 only (PR #51) and a LOCAL work bound inside one input's script (LOW's R404-H1, bsv-stack-lean #75 B; PR #52). No verdict moves under the defaults.

### Fixed

- `MerklePath` refuses a one-level proof holding one hashed leaf at a
  nonzero offset, with `MissingSibling` and the missing sibling's level
  and offset. Parsing and `compute_root` share the check in `RootWalker`,
  including paths built in memory. Offset 0 remains the one-transaction
  block, its root the txid; `from_coinbase_txid` is unchanged. This closes
  the disagreement with the BEEF reader. The six witnesses in
  `tests/merkle_path_lone_leaf.rs` pin the parse, root, combine and BEEF
  answers on the stack's `lone` and `lone_at_one` bodies.

### Notes - cross-SDK parity

- Intentional divergence: TS returns the txid for a lone leaf at any
  offset (`ts-stack@edf6e03`, `MerklePath.ts:345,390-391`), as does Go
  (`go-sdk@v1.7.1`, `transaction/merklepath.go:354-363`). This crate accepts
  only offset 0: the node requires the leading transaction to be the
  coinbase, so a block of one transaction holds it at index 0 (bitcoin-sv
  v1.2.3, `src/validation.cpp:5823-5824`, `CheckBlock`, calling
  `CheckCoinbase` at `:577-579`, `bad-cb-missing`). BRC-62 reads the level-0
  offset as the transaction's index in the block (`BRCs@ed1b015`,
  `transactions/0062.md:179-180`); BRC-74 defines it as the position from
  the left (`transactions/0074.md:66`), and its illustrative routine
  refuses a lone leaf at a nonzero offset (`:326-335`). Every builder
  writes 0: `MerklePath.fromCoinbaseTxidAndHeight` (`ts-stack@edf6e03`,
  `MerklePath.ts:181-183`), `NewMerklePathFromCoinbaseTxid`
  (`go-sdk@v1.7.1`, `transaction/merklepath.go:156-178`), and go-sdk#348's
  testnet vector (`transaction/merklepath_test.go:325-341`). The same
  refusal is proposed to the TypeScript and Go SDKs. Callers holding a
  nonzero lone-leaf proof must obtain a valid proof; its offset must not
  be rewritten on trust. No public type changes.

### Added: a LOCAL work bound inside one input's script

LOW's R404-H1 on the relay's 0.4.4 (bsv-stack-lean #75 B): the clock of
0.4.4 pauses between inputs, but one input with many original-digest
signature checks hashes its wide transaction repeatedly before that clock
is asked again. `SpendParams` and `TxSpendParams` now take
`work_limit: Option<u64>`. The default `None` preserves every verdict and
runs without calculating hash costs. Under `Some(n)`, each reached opcode
costs one unit plus the bytes hashed: the signature's serialized preimage,
the 32-byte intermediate of a double hash, and BIP-143 midstates only when
the shared cache does not cover them (SINGLE outputs are not cached).
Every charge precedes its work; an exhausted budget is
`ScriptResource::Work`, a LOCAL evaluator decline, never an invalid script.
`ScriptResourceLimit` carries `work_spent: Some(n)` for Work, the budget and
the attempted charge as `u64` on native and wasm32. Memory resources keep
their byte counts, now `u64`, and have `work_spent: None`.

`StreamVerifier::set_work_limit` and `AsyncStreamVerifier::set_work_limit`
set that bound per input. The reader returns
`SpendRefusal::Resource(ScriptResourceLimit)` at the named input, preserving
memory declines too. The cursor's bytes and `step_until`'s between-input
pause are unchanged: reapply the local budget after `resume`. A declined
Spend stays declined until `reset`; no within-script resume is introduced.
This is a work bound, not a wall clock: parsing, allocation, arithmetic and
curve verification are not measured in hash bytes.

The witness is `tests/script_work_budget.rs`: one 1 MB subject input with
10,000 valid original-digest checks, declined within its script under the
budget; the identical body under an ample budget keeps its verdict. It
also pins hash charging, exact boundaries, CHECKMULTISIG propagation, a
wrong digest's unchanged refusal, and the reader's named decline. The
explicit native release control measures 1,000 and 10,000 checks. No
version bump here; the release joins this lane and L2-offset0.

Migration: add `work_limit: None` to spend parameter literals and
`work_spent: None` to memory resource literals; resource byte fields are
`u64`. Match the new `ScriptResource::Work` and `SpendRefusal::Resource`
variants as local declines before interpreting validity.

### Notes: cross-SDK parity

The opt-in work budget is this crate's local evaluator contract, extending
the TS SDK's memory resource distinction (`ts-stack@edf6e03`,
`ScriptResourceLimitError.ts`). It changes no wire format, digest or node
rule. The default evaluation keeps the existing reference verdicts.

## [0.4.4] - 2026-10-10

The spend of an unproven transaction is linear in its inputs, and the reader
can pause between two inputs and resume from the input reached (bsv-low
#591: LOW's R400-H1 and R403-H1, found on the relay's payment door over
0.4.3). LOW's shape: a proven parent with n `OP_TRUE` outputs, a subject
spending all n with empty unlocks. On the relay's door over 0.4.3 they
measured 4,000 inputs in 0.10 s, 16,000 in 1.8 s, 64,000 (3.3 MB) in 18.5 to
24.9 s and 128,000 (6.5 MB) in 186 s.

### Fixed: the spend of a wide transaction grew with its inputs squared

- At 0.4.3 `BeefIndex::check_spends_of` cloned the other inputs and the
  outputs for every input; every `OP_CHECKSIG` rebuilt the input list and
  recomputed hashPrevouts, hashSequence and hashOutputs over it; and spending
  an output walked its parent's whole output table. Now the reader and
  `Transaction::verify` build one input list and one output list per
  transaction, shared by every input's spend with its sighash midstates
  (each computed at most once per transaction and scope class), and an
  output table keeps its unspent count.
- The witness (`tests/beef_stream_linear_spend.rs`, release, `--ignored`),
  `verify_stream` of LOW's shape on the studio (aarch64-apple-darwin):

  | n | 0.4.3 | 0.4.4 |
  |---|---|---|
  | 4,000 | 0.072 s | 0.002 s |
  | 16,000 | 0.804 s | 0.006 s |
  | 64,000 | 11.994 s | 0.022 s |

  Quadruple the inputs: 14.92 times the time at 0.4.3, 3.81 here.
- The digests do not move: 1,000 P2PKH spends signed over 0.4.3's free
  function under six scopes verify, and a signature over another digest is
  refused at its input; `TxSighashCache` equals
  `compute_sighash_dispatched_for_signing` for every scope byte and input.
- The original (pre-fork) digest, for a scope without FORKID or with the
  CHRONICLE bit, still serializes every input per signature, as the
  reference's `SignatureHashOriginal` does: a transaction of n such
  signatures is still n squared bytes hashed. The clock between inputs is
  what bounds a request's share of it.

### Added: a clock between inputs

- `StreamVerifier::step_until(spent)` asks the caller's budget between two
  inputs of an unproven transaction and answers `Timed::Paused` when it is
  spent, at least one input of the step having run; the next call continues
  in place. `step` is `step_until` with a budget never spent.
- The cursor of a paused reading is the state before the transaction
  (`Cursor::offset` its element's first byte, the index unchanged) and names
  the input reached (`Cursor::input_reached`). `StreamVerifier::resume` and
  `AsyncStreamVerifier::resume` re-read that one transaction and run its
  scripts from that input on; the inputs before it never run again. A
  resumed slice re-reads the transaction's bytes and re-resolves its inputs
  (linear in it), never its scripts.
- Cursor bytes: a cursor between two elements has 0.4.3's bytes exactly; a
  paused one appends a presence byte, the offset, the txid and the input.
  0.4.3 refuses a paused cursor's bytes ("bytes after its end").
- The witness (`tests/beef_stream_pause.rs`): a 64,000-input subject read in
  slices of 10,000 inputs pauses at inputs 10,000, 20,000, ..., 60,000 (a
  restart would pause at 10,000 each time), each cursor through its bytes and
  a fresh reader, to the verdict of the whole; a refusal at input 60,000 is
  the same paused or not; the asynchronous reader resumes a paused cursor; a
  reading with no slice never pauses.

### Changed

- **`Spend`** holds the transaction as an `Arc<TxSighashCache>`.
  `Spend::new(SpendParams)` keeps its shape and its verdicts and builds the
  list once per spend. New: `Spend::with_transaction(TxSpendParams)` (the
  shared transaction, the input index, the source satoshis, the two scripts,
  the memory limit), which copies nothing per input, the constructor for a
  caller that checks every input of a transaction (the CLI, the toolbox, the
  relay); `Err` when the index names no input.
- **New public items**, nothing removed: `primitives::bsv::sighash::TxSighashCache`,
  `script::TxSpendParams`, `Spend::with_transaction`,
  `transaction::Timed`, `StreamVerifier::step_until`, `Cursor::input_reached`.
  `Progress` is unchanged, so no caller's `match` breaks.

## [0.4.3] - 2026-10-10

A raw transaction with no output is invalid bytes, as one with no input has
been since 0.4.1, and `Transaction::verify` refuses both (bsv-stack-lean #59,
found by the NL-3b lane while closing #58). The rule is the node's, cited not
restated: bsv-script-lean@87f0461 `lean/BsvScript/TxRules.lean:85-86`
(`checkTransactionCommon`: `vinEmpty`, then `voutEmpty`; the theorems
`checkTransactionCommon_vinEmpty` and `checkTransactionCommon_voutEmpty`). The
posture of 0.4.0 stands: a refusal is for invalid bytes only, never for a
size or a count; `NoOutputs` refuses the one count, zero, that makes the bytes
no transaction, and bounds nothing from above.

### Fixed: a transaction with no output was read as valid

- The streaming reader, `BeefStream`, `verify_stream` (with or without
  scripts, under a subject, in two passes) and `verify_stream_async` refuse a
  raw transaction with at least one input and no output as
  `Invalid { offset, kind: Kind::NoOutputs, reason: Reason::NoOutputs }`, the
  offset its leading byte, with or without a BUMP index. One with neither is
  `NoInputs`, the node's order. The index's fold holds an `Element` built by
  hand to the same rule.
- `Beef::verify_valid`, `is_valid` and `verify_structure` refuse a BEEF that
  carries one (`Kind::NoOutputs`; `BeefTx::has_no_outputs`, new). The kind is
  the first such transaction's in the order held when it is called, the
  reader's order, before the sort.
- One helper answers both counts in the node's order for every path
  (`beef_stream::no_transaction`, crate-private).
- Witnesses, red at 0.4.2 and green here (`tests/beef_stream.rs`):
  `a_transaction_with_no_output_is_invalid_bytes_at_its_offset` (V1 and V2,
  every reader and the whole path), `a_transaction_with_no_output_is_invalid_under_a_bump_too`,
  `the_leans_no_output_rows_have_the_leans_offsets` (the Lean's rows of
  `BeefOfAnySize`: 111, 147 behind the Atomic prefix, 49 under a BUMP, and
  neither at 111 as `NoInputs`), `the_asynchronous_reader_refuses_a_transaction_with_no_output`;
  `a_transaction_with_neither_is_refused_for_its_inputs_first` holds the order.

### Fixed: `Transaction::verify` exempted a root with no input

- Through 0.4.2 the linked walk treated a transaction with no inputs as a
  synthetic root and skipped the value rule for it, and judged a transaction
  with no output like any other. Every transaction the walk reaches (the one
  verified, each popped ancestor, each source it resolves), proven by a
  merkle path or not, is now refused with either:
  `transaction error: invalid transaction <txid>: NoInputs` (or `NoOutputs`),
  the reader's kinds. The value rule's exemption is gone; nothing reaches it.
- Witnesses, red at 0.4.2 (`Ok(true)`) and green here (`tests/beef_stream.rs`):
  `verify_refuses_a_root_with_no_input` (unproven, proven, the transaction
  itself), `verify_refuses_a_transaction_with_no_output` (the subject, a
  proven ancestor, neither; the control `Ok(true)`).

### Changed

- **`Kind` and `Reason` gain the variant `NoOutputs`**, last; `Kind::ALL` is
  `[Kind; 20]`. Neither is `#[non_exhaustive]`, so an exhaustive `match` needs
  the new arm and a binding typed `[Kind; 19]` needs `20`, as at 0.4.1.
- **A root needs an input.** A test or a caller that built a funding
  transaction with outputs and no inputs and verified a spend of it gets the
  refusal. Give the root one input and, so the walk need not descend it, a
  merkle path (for a block of one transaction,
  `MerklePath::from_coinbase_txid`) and a tracker that carries its root.
  `examples/transaction.rs` (and the README block that is its body) and
  `tests/transaction_tests.rs`'s `build_source_tx` moved so.
- Nothing stored changes: a BEEF stored by an earlier version is held to
  these rules on its next read.

### Notes: cross-SDK parity

Read at the pin, not run against the reference:

- The reference's `Beef.verifyValid` has no such check
  (`ts-stack@edf6e03 packages/sdk/src/transaction/Beef.ts:1054-1075`).
- The reference's `Transaction.verify` refuses an unmined transaction with no
  inputs, then one with no outputs (`Transaction.ts:1336-1342`, called for an
  unmined transaction at `:1654`), and does not ask it of a proven one. This
  crate's walk asks it of every transaction it reaches, as its reader does;
  through 0.4.2 its walk exempted what the reference refuses.

## [0.4.2] - 2026-10-10

The whole-BEEF path (`Beef::from_binary` then `Beef::verify_valid`) walks a
BUMP once, in time linear in its leaves, and refuses the bytes the streaming
reader refuses, with the reader's kinds (bsv-stack-lean #61, found by the
replay NL-8, `docs/p0/nl-8.md` W1 to W5). The posture of 0.4.0 stands: a
refusal is for invalid bytes only, never for a size or a count; every refusal
added here is of bytes the reader and the Lean definition `BeefOfAnySize`
already refuse.

### Fixed: the whole path walked a BUMP once per leaf (W1)

- `verify_valid` computed each flagged level-0 leaf's root by
  `MerklePath::compute_root`, and each call built a fresh walker that
  recomputed every node it needed from level 0: quadratic in the leaves. A
  BEEF of one BUMP of 4,096 leaves (146,976 bytes) took 29.8 s in release;
  8,192 leaves (294,433 bytes) gave no answer in 120 s, where the streaming
  reader answers in 0.012 s.
- Each BUMP's root is now the streaming reader's walk (`bump_root`, the one
  walker under both paths), once per BUMP; a transaction's BUMP index is held
  to an index of each BUMP's level 0 built once. The same probe at this
  release: 0.031 s at 4,096 leaves, 0.066 s at 8,192 (release, parse and
  verdict together).
- Witness, red at 0.4.1 and green here: `tests/beef_stream.rs`
  `the_whole_path_walks_a_wide_bump_in_linear_time` (4,096 and 8,192 leaves,
  each under `WHOLE_PATH_BOUND`, 10 s, generous for a debug build).
- `MerklePath::compute_root` and the parse's own root check are unchanged:
  one call is linear, and the parse's check shares its nodes since 0.3.35.

### Fixed: the whole path accepted bytes the reader refuses (W2 to W5)

Each of these is invalid bytes, refused by the streaming reader at its offset
with the kind named, and accepted by 0.4.1's whole path:

- **A lone leaf at an offset other than 0** (`MissingSibling`). The block of
  one transaction is the one leaf at offset 0, and its root is that txid; the
  same leaf at any other offset has no sibling. `MerklePath` alone keeps the
  reference's reading (below).
- **A byte after the frame** (`TrailingBytes`). `Beef::from_binary`,
  `Beef::from_hex`, the deprecated `from_binary_with_limits`, and
  `Transaction::from_beef` and `from_atomic_beef` through them, refuse it with
  the reader's words: `invalid BEEF at byte N: TrailingBytes`.
  `Beef::from_reader` still reads one BEEF out of a longer stream and leaves
  what follows to its caller.
- **An atomic BEEF whose subject is not the last raw transaction**
  (`SubjectMissing`), **or that carries a transaction or txid-only entry no
  later raw transaction spends** (`UnrelatedTransaction`). "Last" and "later"
  are the order the transactions hold when `verify_valid` is called, before
  its sort: the wire's for a BEEF just read.
- **A txid-only entry no BUMP of the BEEF proves** (`StubNotProven`), with
  `allow_txid_only` true. A txid-only entry is now read on its own: valid when
  a BUMP of this BEEF carries its txid at level 0, refused otherwise.
- Witnesses, each red at 0.4.1 and green here, each holding the whole path's
  kind to the reader's on the same bytes (`tests/beef_stream.rs`):
  `the_whole_path_refuses_a_lone_leaf_at_an_offset_other_than_0`,
  `the_whole_path_refuses_a_byte_after_the_frame`,
  `the_whole_path_holds_an_atomic_beef_to_its_subject`,
  `the_whole_path_reads_each_txid_only_entry_as_the_reader_does`.

### Added

- `Beef::verify_structure() -> Result<HashMap<u32, String>, Kind>`: the
  roots, or the reader's `Kind` for what is wrong (the in-memory BEEF has no
  offsets to name). `verify_valid` and `is_valid` are it without the kind.

### Changed

- **`allow_txid_only` decides nothing.** Through 0.4.1, `true` accepted every
  txid-only entry and `false` refused every one; now a proven entry is valid
  and an unproven one is not, under either value. The parameter stays for the
  signature. A caller that passed `true` for txids it holds elsewhere (a
  wallet's known txids) must carry their BUMPs in the BEEF or check those
  txids itself; a caller that passed `false` now accepts a txid-only entry
  this BEEF's own BUMP proves. `tests/transaction_tests.rs`
  `test_beef_txid_only_validation` pinned the old flag and now pins the
  refusal.
- `verify_valid`'s `roots` holds every BUMP's height, flagged leaf or not, and
  a BUMP whose walk fails is not valid (0.4.1 skipped a root it could not
  compute). Two BUMPs at one height with different roots stay not valid.
- No signature changed and no type gained a field or a variant.

### Notes: cross-SDK parity

Read at the pin, not run against the reference:

- The lone leaf: the reference accepts one at any offset and returns the txid
  as the root (`ts-stack@edf6e03 packages/sdk/src/transaction/MerklePath.ts:345`,
  `:390-391`); so do this crate's `MerklePath::from_binary` and
  `compute_root`, unchanged. The whole-BEEF verdict follows the reader and the
  chain: the only transaction of a block is its coinbase, at index 0
  (bsv-stack-lean `docs/readings/one-transaction-block-lone-leaf.md`).
- The trailing byte: the reference's `Beef.fromBinary` is the prefix parser
  and `fromBinaryStrict` the framed one, which throws "Serialized BEEF
  contains trailing data" (`Beef.ts:1286-1309`); its `fromString` is strict
  (`:1319`). This crate's `from_binary` is now the framed one; `from_reader`
  is the prefix parser.
- The atomic rule: the reference refuses an atomic BEEF unless every
  transaction is in the subject's ancestry (`Beef.ts:482-491`, `:420`, checked
  by `verifyValid` at `:1064`), which refuses the same rows by another rule.
- The txid-only flag: the reference's `verifyValid` refuses every txid-only
  entry unless `allowTxidOnly` is true and then accepts every one
  (`Beef.ts:1070`, `:1101-1104`). This crate reads each entry, as its reader
  does.

## [0.4.1] - 2026-10-09

A raw transaction with no input is invalid bytes (bsv-stack-lean #58, found by
the middleware's door, bsv-middleware-rs 0.4.0). The rule is the node's and is
cited, not restated: bsv-script-lean at `87f0461`,
`lean/BsvScript/TxRules.lean:85` (`checkTransactionCommon`, the verdict
`vinEmpty`; the theorem `checkTransactionCommon_vinEmpty`, `:216-219`), its
page `docs/BLOCK-CONSENSUS.md:31-32`, the S6 issue #61 under the charter #58.
The posture of 0.4.0 stands: nothing is refused for a size or a count.

### Fixed: a transaction with no input was read as valid

- The streaming reader held an unproven transaction by its inputs alone, so
  one with no input passed with nothing proven beneath it, and a payment
  spending it was `Valid` whenever the BEEF also carried any BUMP the headers
  knew (a proven stranger beside it was enough). `Beef::verify_valid` read the
  same bytes as valid for the same reason. Under a BUMP index the bytes were
  taken on the BUMP's word, though no block holds such a transaction.
- `verify_stream`, `verify_stream_structure`, `verify_stream_two_pass`,
  `verify_stream_async` and `BeefStream` itself now refuse it as
  `Invalid { offset, kind: Kind::NoInputs, reason: Reason::NoInputs }`, the
  offset the transaction's leading byte, with or without a BUMP index, in V1
  and V2. The decoder refuses the element when its last byte is read
  (`BeefDecoder`), and `BeefIndex::fold` holds an element built by hand to the
  same rule.
- `Beef::verify_valid` and `Beef::is_valid` answer not valid for a BEEF that
  carries one (`BeefTx::has_no_inputs`, new).
- The witnesses, red at 0.4.0 (`Valid` in every one) and green here, in
  `tests/beef_stream.rs`:
  `a_transaction_with_no_input_is_invalid_bytes_at_its_offset` (the
  middleware's BEEF: a proven stranger, the transaction with no input, a
  payment spending it), `a_transaction_with_no_input_is_invalid_under_a_bump_too`
  and `the_asynchronous_reader_refuses_a_transaction_with_no_input`;
  `the_leans_no_input_rows_have_the_leans_offsets` holds the Lean rows'
  offsets (111, 147 behind an Atomic prefix, 49 under a BUMP).
- The specification moved with it: `BeefOfAnySize` of bsv-stack-lean gains
  `Reason.noInputs` and its theorem (NL-1c). The rows this crate replays gave
  their proven anchor one input; `tests/beef_stream_deep.rs` holds the Lean's
  new counts (6,000,112 bytes and 6,700,132 units of work at 100,000 links).

### Changed

- `Kind` and `Reason` gain the variant `NoInputs`, and `Kind::ALL` is
  `[Kind; 19]`. Neither enum is `#[non_exhaustive]`: an exhaustive `match` on
  `Kind` or `Reason` needs the one new arm, and a binding typed `[Kind; 18]`
  needs `19`.
- A BEEF built for a test around a synthetic root (a `Transaction::new()` with
  outputs and no input) is no longer valid to `verify_valid` or the streaming
  reader. Give the root an input and a merkle path, as `examples/beef_spv.rs`
  now does (the README's block follows it).
- `Transaction::verify` is unchanged: it still walks a linked object graph and
  still exempts a transaction with no inputs from the value rule.

### Notes: cross-SDK parity

- The reference's `Beef.verifyValid` has no such check
  (`ts-stack@edf6e03 packages/sdk/src/transaction/Beef.ts:1054-1075`, and the
  sort at `:1456-1470` queues an unproven transaction with no input with
  nothing to wait on), so it reads these bytes as valid. This crate follows
  the node. Read at the pin, not run against the reference.

## [0.4.0] - 2026-10-09

The posture (bsv-stack-lean, the charter "a BEEF of any size", the owner's
ruling of 2026-10-09): a valid BEEF is never refused for its size or its
counts. A refusal is for invalid bytes only, and names them. 0.3.35 gave doors
a verdict by size (`BeefLimits`); 0.4.0 takes that verdict away and gives them
a reader whose memory does not grow with the body.

### Added: the streaming BEEF reader (`transaction::beef_stream`)

- `verify_stream(source, headers, subject) -> io::Result<Verdict>` reads a BEEF
  from any `std::io::Read` in one pass, one step per element. Each BUMP's root
  is computed by a linear walk and checked against the `Headers` as it streams
  (no header at a height is fail closed); each unproven transaction's inputs
  are resolved against the index and their scripts executed against the parent
  output the index kept; a subject is held to the Atomic rule (it is the last
  transaction, and every other transaction is spent by a later one).
- The verdict is `Valid { subject, roots }`, `Invalid { offset, kind, reason }`
  or `SpendRefused { offset, txid, input, why }`. An `Invalid` carries the
  offset of the byte it names and one of eighteen `Kind`s (`Kind::ALL`), none
  of which is a size or a count. A spend the interpreter refuses is not one of
  the eighteen: it is the script's verdict on a transaction, and
  `verify_stream_structure` leaves it out.
- `BeefStream` yields the elements one at a time (`Element::Bump` with its
  root, `Element::Tx` with its txid hashed while the bytes passed,
  `Element::TxidOnly`) and holds one chunk of the source and the one element
  in hand. `BeefDecoder` is the same reader fed slices, for a source that is
  not a `Read`; `AsyncByteSource` and `verify_stream_async` read a request
  body or an object store's body stream against a `ChainTracker`.
- `BeefIndex` is what the reader keeps: one entry per element and one per txid
  a BUMP carries at level 0; with scripts, each unspent output until a later
  input spends it. Never a sibling hash, never a transaction's bytes after its
  step.
- `verify_stream_two_pass` reads a source that can be read again (an object
  at rest) twice: `referenced_outpoints` learns which outputs are spent, and
  the verifying pass keeps those alone. One pass cannot know which outputs
  will be spent and keeps every unspent one, which for transactions carrying
  large outputs nothing spends is their bytes.
- `Cursor` is the state after `k` elements, with `to_binary` / `from_binary`;
  `StreamVerifier::resume(cursor, source, headers)` over the rest of the stream
  yields the verdict of the whole, refusal for refusal.
- The specification is the Lean definition `BeefOfAnySize` of bsv-stack-lean
  (six theorems: `accept_iff_valid`, `accept_independent_of_size`,
  `memory_bounded_per_element`, `refusal_names_invalid_bytes`, `work_linear`,
  `resume_sound`). `tests/beef_stream.rs` replays its rows with their offsets
  and kinds, the BRC-62 example among them; `tests/beef_stream_deep.rs` reads
  the P0-5 chain at 1,000, 10,000 and 100,000 links on a 1 MiB stack and the
  P0-5c wide BUMP at 8,192 and 16,384 leaves, and holds the Lean's own counts
  at those sizes; `tests/memory_profiling.rs` measures the peak heap: 16,988
  bytes for the stream alone at every depth, about 128 bytes per element for
  the verdict at 100,000 links.
- One shape is accepted that the Lean definition refuses: the one-leaf BUMP of
  a block with only one transaction, whose root is the txid, as the reference
  and `MerklePath` read it (`MerklePath::from_coinbase_txid`).

### Changed (breaking): `BeefLimits` has no verdict

- `BeefLimits::max_bytes` is removed. `max_txs` and `max_bumps` are memory
  hints: how many entries the in-memory parse may reserve room for, never more
  than the bytes left could fill.
- `Beef::from_binary_with_limits` is deprecated and refuses nothing it did not
  refuse without limits. The three `BeefError` refusals of 0.3.35 (`BEEF of N
  bytes is over max_bytes`, `BEEF claims N BUMPs, over max_bumps`, `BEEF claims
  N transactions, over max_txs`) are gone. A count the bytes cannot honor is
  refused where the bytes run out (`ReaderUnderflow`), never for the count.
- Migration: delete `max_bytes` from a `BeefLimits { .. }` literal. A door
  that called `from_binary_with_limits` to bound a stranger's BEEF calls
  `verify_stream` on the body's reader instead and drops its 413. Code that
  matched on the three messages has nothing left to match. `Beef::from_binary`
  is unchanged and stays the reader for small bodies and for building.

## [0.3.35] - 2026-10-08

### Fixed: no walk over a BEEF's ancestry recurses (bsv-stack-lean #57, P0-5)

- A stranger's BEEF that is one chain of unproven transactions took the stack
  one frame (or several) per link: on a 1 MiB thread, the order of a WASM
  stack in a Worker, release builds aborted by 1,000 links in the link of
  `Transaction::from_beef` / `from_atomic_beef` (`Beef::find_atomic_transaction`),
  by 2,000 in `to_beef` / `to_atomic_beef` (and `to_beef_v1`, the same walk),
  in `Clone` of the linked result and in `id()` of a chain built with
  `add_input_from_tx`, by 4,000 in the overlay's `Historian` / `SyncHistorian`, and by 16,000 in the
  `Drop` of the linked result. A stack overflow is an abort, not a panic: in a
  Worker it takes every request in flight on the instance.
- Every one of those walks now keeps its work on the heap, in the recursive
  walk's order: the link (one full link per txid, a bare stub per repeat,
  cycle-safe, the same `source_transaction` shape), the serializers' ancestor
  collection, the historians, and `Transaction`'s `Clone` and `Drop`. `id()`
  hashes a chain's txid-less sources deepest first before it reads them. The
  witness, `tests/beef_deep_chain.rs`, runs each walk alone on a 1 MiB thread
  at 100,000 links; `iterative_equivalence_tests` in `beef.rs` holds each new
  walk to the 0.3.34 form on seeded random BEEFs.
- `Beef::sort_txs` rescanned the pending list once per resolved link, so a
  chain written newest first sorted in quadratic time (767.8 s for 128,000
  links in a release build). It now computes the same order in one pass, as
  the reference does (`@bsv/sdk` `Beef.#topoSort`).
- `to_beef` cloned each ancestor's whole ancestry into the BEEF it was
  building (quadratic in a chain's depth); it stores each ancestor without its
  sources, and writes the same bytes.

### Added: `Beef::from_binary_with_limits` and `BeefLimits`

- `BeefLimits { max_txs, max_bumps, max_bytes }` and
  `Beef::from_binary_with_limits(bin, &limits)`: a door that reads a stranger's
  BEEF refuses one over its byte length, BUMP count or transaction count with a
  `BeefError` naming the limit and the count, each count checked on its prefix
  before an entry of that kind is read. `Beef::from_binary` is unchanged (no
  bound beyond the bytes). `tests/beef_limits.rs`.

### Changed: `Transaction` implements `Drop`

- The ancestry is dropped one transaction at a time. A type with `Drop`
  cannot have a field moved out of an owned value, so code such as
  `if let Some(mp) = tx.merkle_path { .. }` or `let inputs = tx.inputs;` on an
  owned `Transaction` no longer compiles (E0509). Migration, one line:
  `tx.merkle_path.take()` / `std::mem::take(&mut tx.inputs)`, or borrow
  (`tx.merkle_path.as_ref()`). Compiled against this tree:
  bsv-wallet-toolbox-rs, bsv-wallet-cli, bsv-middleware-rs, rust-message-box,
  bsv-middleware-cloudflare, bsv-storage-cloudflare, rust-wallet-infra build
  unchanged; the overlay engine's `GET /tx/bump` route
  (`crates/overlay-cloudflare/src/routes.rs`) needs the one-line migration.

### Fixed: the BUMP parse is linear in its leaves (bsv-stack-lean #57, P0-5c)

- `MerklePath::from_reader` (under `from_binary`, `from_hex` and every BEEF
  parse) checks that every level-0 leaf computes the same root, and each check
  walked the tree again: a linear scan of each level for the sibling, a missing
  sibling recomputed from level 0. One BUMP of 8,192 flagged leaves with empty
  upper levels (294,433 bytes) took 225.7 s to parse in a release build, about
  five times per doubling, inside any `BeefLimits`. The check now shares every
  node it finds or computes across the walks, each level indexed by offset
  once, as the reference does (`@bsv/sdk` `MerklePath.computeRootCached`):
  0.051 s for the same bytes. `compute_root` uses the same walk. The answers
  and the errors are the 0.3.34 ones (`linear_root_equivalence_tests` holds
  the new walk to the old one on seeded random paths); the witness is
  `tests/merkle_path_cost.rs`.
- A tree-height byte over 64 shifted an offset by 64 or more: `attempt to
  shift right with overflow` in a debug build (or any build with
  `overflow-checks`), a wrong error in a release one. It is refused at the
  parse, before any shift, with `MerklePathError("Invalid tree height: 65,
  over the maximum height 64")`; `MerklePath::new` and `new_unchecked` refuse a
  path of more than 64 levels the same way, and no shift by a height can panic.

### Changed: `{:?}` of a `Transaction` prints a linked source as its txid

- `Transaction` and `TransactionInput` implement `Debug` by hand: an input's
  `source_transaction` prints as `Some("<txid>")`, never as the source's whole
  ancestry. The derived `Debug` printed every linked ancestor, one recursion
  per link, so `format!("{:?}", tx)` of a 1,000-link chain overflowed a 1 MiB
  stack and aborted. Every other field prints as the derive printed it. Code
  that parses `{:?}` output of a linked transaction sees the change.

## [0.3.34] - 2026-10-08

### Changed: QUEUED, REQUESTED_BY_NETWORK and CONFIRMED are accepted on a 2xx

- The reference's spec (`specs/broadcast/arc.yaml`) and go-sdk accept these three
  non-error states; the reference's TypeScript code reports them as an invalid
  response. bsv-rs follows the spec: the word is carried as the success message,
  a hint about the transaction and never evidence. An unknown word is still an
  invalid response. (bsv-stack-lean #35, the owner's ruling of 2026-10-08.)

### Fixed: an ARC answer is judged by its `txStatus`, never by the HTTP code

- `ArcBroadcaster::broadcast` read the HTTP code and nothing else: every 2xx
  was a `BroadcastResponse` with the body's `txStatus` as its message, so a
  wallet recorded as accepted a transaction the node refused (REJECTED,
  DOUBLE_SPEND_ATTEMPTED, MINED_IN_STALE_BLOCK, the ORPHAN statuses), and a
  2xx with no `txStatus` at all was a success. ARC answers 2xx whenever it
  processed the request and puts the verdict in the body
  (`arc@e7efc5b internal/api/handler/default.go:489-500`).
- Now the body's `txStatus` decides, by the reference's rule
  (`ts-stack@edf6e03 packages/sdk/src/transaction/broadcasters/ARC.ts:110-180`):
  `DOUBLE_SPEND_ATTEMPTED`, `REJECTED`, `INVALID`, `MALFORMED`,
  `MINED_IN_STALE_BLOCK` and any status or `extraInfo` containing `ORPHAN` are
  a `BroadcastFailure` whose `code` is the status word, whose `description` is
  the status word and the `extraInfo`, and whose `more` carries `extraInfo`
  and `competingTxs` when sent; a missing `txStatus`, a status word outside
  the reference's accepted set, or a malformed `competingTxs` list is
  `ERR_INVALID_RESPONSE`; a failure naming another transaction's id is
  `ERR_TXID_MISMATCH`. An accepted status is a success whose `message` is the
  status word and whose `competing_txs` are ARC's, lower-cased. The non-2xx
  path is unchanged.
- Pinned by `tests/vectors/arc_tx_status_verdicts.json` (17 recorded 2xx
  bodies and their verdicts; shared with the other ports), served through
  wiremock in `tests/broadcaster_http_tests.rs`
  (`an_arc_2xx_answer_is_judged_by_its_tx_status_not_by_the_http_code`, 14 of
  17 wrong before the fix) and replayed through the verdict alone in
  `src/transaction/broadcasters/arc.rs`. bsv-stack-lean #35, P0-2.
- Migration: none in the API. Callers that matched `Ok(_)` on every 2xx now
  receive `Err(BroadcastFailure)` with the real verdict; a caller that treated
  `response.message == "REJECTED"` as a failure by hand can drop that check.

### Notes: cross-SDK parity

- The success `message` stays the status word alone; the reference appends
  the `extraInfo` (`ARC.ts:176`). The success path keeps ARC's echoed `txid`
  without the reference's mismatch check (`ARC.ts:161-171`); the failure path
  has it (`ARC.ts:136-146`). A `BroadcastFailure` always carries the
  submitted `txid`; the reference sets it only when ARC echoed a valid one
  (`ARC.ts:152`).
- An explicit `"competingTxs": null`, which ARC sends on an ordinary 2xx
  (`arc@e7efc5b pkg/api/arc.go:429`, no `omitempty`; `doc/api.md:1512`), is
  read as absent. Read as written, the reference refuses it as
  `ERR_INVALID_RESPONSE` (`ARC.ts:129-132`); not run here.
- The accepted set is the reference's nine words. The Go port adds `QUEUED`,
  `REQUESTED_BY_NETWORK` and `CONFIRMED` (`go-sdk@511b58c
  transaction/broadcaster/arc.go:198-216`); ARC's own enum has `QUEUED` and
  `REQUESTED_BY_NETWORK` (`metamorph_api.proto:13-28`). Here, as in the
  reference, those two words on a 2xx are `ERR_INVALID_RESPONSE`.

## [0.3.33] - 2026-10-06

### Changed

- follows bitcoin-sv v1.2.3's fixed-width operand decoding and OP_SPLIT position bound (int_serialization.h:61-118, interpreter.cpp:1708-1721 at 6504a3a).
- Under a flag word, `OP_SUBSTR`'s offset and length and `OP_LEFT`'s and
  `OP_RIGHT`'s count use checked signed 64-bit decoding. The era-width and
  minimal-encoding checks precede conversion; `getint` saturation follows it.
  Decode failures use the node's script-number error mapping
  (`script_num.cpp:80-91`, `interpreter.cpp:1807-1809` at
  `6504a3aff65ba97c0f6c80962b033e35ecbfed4b`). `OP_SPLIT` positions under a
  flag word are bounded by `INT32_MAX` and the data length.
- Tests cover nine-byte sign encodings, ten-byte encodings, the signed
  minimum and signed-range boundary, all four splice operands, check order,
  and `OP_SPLIT` at `INT32_MAX` and `INT32_MAX + 1`. The split boundary is
  tested with a synthetic data length, without a multi-gigabyte allocation.
  The existing splice witness cases carry v1.2.3 expectations.

### Notes: cross-SDK parity

- The default mode retains the TypeScript SDK's unrestricted number reader.
  Under a flag word the splice operands follow the pinned node's fixed-width
  construction sites (`interpreter.cpp:622-625`, `655-656`, `680-681`).

## [0.3.32] - 2026-10-05

### Fixed: the `int64` operand reader above 8 bytes follows the node's measured reading

- Under a word, the offset and length operands of `OP_SUBSTR`, `OP_LEFT` and
  `OP_RIGHT` (the reference's `int64` path, `CScriptNum` with `big_int`
  false, `src/script/interpreter.cpp:622-625`, `651-653`, `676-678`;
  `bsv::deserialize<int64_t>`, `src/script/int_serialization.h:64-95`) are now
  read, at 9 bytes and more, as the node's build reads them. Before: the
  two's-complement `int64` of the element's first 8 bytes, the rest never
  read. After: every byte but the last OR-ed into a 64-bit pattern at bit
  position `8 * (i mod 8)` (byte 8 lands on byte 0's position, byte 9 on byte
  1's, with period 8), the last byte dropped, no sign bit read, the pattern a
  two's-complement `int64`. The two readings are the same at 9 bytes and
  whenever the bytes from the ninth to the last but one are zero; they differ
  from 10 bytes: `00 00 00 00 00 00 00 00 04 01` was 0 and is 4, as the node
  reads it on the block path and the mempool path. Elements of 0 to 8 bytes
  (the reference's code as written, the sign-magnitude reading), the length
  test and the minimal-encoding rule before the read, `getint`'s saturation
  to the `int` range after it, the routing (the three opcodes, under the block
  and the standard word) and the default mode (a script number of any length,
  as the TypeScript SDK reads it) are unchanged. No operand is refused that
  was not refused before: the node refuses none on this path.
- Why it was wrong: the reference's loop shifts an `int64_t` by 64 bits and
  more from the tenth byte (`int_serialization.h:75`), undefined in C++, and
  0.3.29 took the one determinate case (zero tail bytes) as the rule. The
  specification's owner ruled on 2026-10-05 (bsv-script-lean,
  `docs/records/20261005-221333-owner-rulings-32.md`, R1) that where the
  pinned reference leaves this reader undefined the node's measured reading
  is consensus; the measurements and the rule are public in bsv-script-lean,
  `docs/records/20261006-010651-r1-reading-public.md` (section 3 the cases,
  section 4 the rule).
- What is measured and what is not: on the node (bitcoin-sv v1.2.2,
  `879fc8b`) lengths 1, 9 and 10; at 16 and 17 bytes builds of the same
  source carry the fold and the node's own runs are owed (at 17 bytes one
  vectorized arm64 build of that source reads 0 where this crate, with the
  scalar builds, reads 4); 11 through 15 bytes and 18 and above are
  unmeasured, the rule extended by its mechanism. The rule is the measured
  builds', not a reading of the C++, and claims nothing for another binary of
  the same source (the specification's D178). `fold_int64_operand`
  (`src/script/spend.rs`) says so at the site.
- Pinned by `tests/script_int64_fold_witness.rs` (15 tests): one for each
  case of the record's section 3, named by its id (`f1_offset_10_bytes`,
  `f1_control_offset_op4`, `f1_control_offset_9_bytes`, `gen_00796`,
  `f1_offset_16_bytes`, `f1_offset_17_bytes`,
  `f1_control_offset_17_bytes_byte0`), each asserting the value read under
  both words; the boundary lengths 8, 9, 10, 11 (the smallest unmeasured), 17
  (the largest measured) and 18; the same reader on `OP_LEFT` and `OP_RIGHT`;
  the default mode unchanged. Eight of the fifteen were RED on 0.3.31 (the
  10-byte, 16-byte and 17-byte cases, the 10, 11, 17 and 18 boundaries,
  `OP_LEFT`/`OP_RIGHT`). `tests/script_int64_operand_witness.rs` (0.3.29) stays
  green, its assertions unchanged.

### Notes: cross-SDK parity

- The TypeScript SDK reads these operands as script numbers of any length;
  this crate's default mode keeps that. Under a word this crate follows the
  node's measured build where the reference source is undefined: a stated
  finding, scoped as above.

## [0.3.31] - 2026-09-29

### Documented: the block path's stack budget (the guard of Calhooon/bsv-rs#30)

- The docs of `Spend` (the module's memory budget section, `Spend::memory_limit`,
  `Spend::stack_memory_policy`, `Spend::set_stack_memory_policy`),
  `SpendParams::memory_limit`, `ScriptFlags::max_stack_memory_usage`,
  `flags::DEFAULT_STACK_MEMORY_USAGE_POLICY`,
  `ScriptEvaluationError::resource_limit` and `is_resource_limit`, the README,
  the crate guides and the witnesses' module doc
  (`tests/script_stack_memory_witness.rs`) now state the block path's budget
  as the reference sets it: a node's is its operator's mandatory
  `-maxstackmemoryusageconsensus`
  (bitcoin-sv v1.2.2 does not start without it, `src/bitcoind.cpp:140-157`),
  in which 0 means `INT64_MAX` (`src/configscriptpolicy.cpp:280-283`), not a
  constant. They give the recipe for a caller modelling a node run with 0,
  `memory_limit: Some(usize::MAX)` (the evaluation then allocates what the
  script asks, `OP_NUM2BIN` alone up to `INT32_MAX` bytes, and decides as that
  node does), and they say that a decline is an `Err` whose `resource_limit`
  is `Some`, which a caller that judges validity must not read as invalid. No
  behaviour changes.

### Corrected

- The 0.3.30 entry gave the block path's figure as "`INT64_MAX` on the block
  path (`consensus.h:82`)" and "the block path's own figure is unbounded": both
  now read as the operator's mandatory setting, 0 meaning `INT64_MAX`.
- The witnesses' module doc (`tests/script_stack_memory_witness.rs`, 0.3.30)
  gave the block path's budget as "`INT64_MAX` on the block path
  (`consensus.h:82`)" and the node's own figure as "unbounded", and the doc of
  its `INT32_MAX` row named "the reference's consensus instance" as the one
  that allocates 2 GiB: they now read as the operator's mandatory setting and
  as a node run with `-maxstackmemoryusageconsensus=0`.

## [0.3.30] - 2026-09-27

### Fixed: the stack memory budget under a word (Calhooon/bsv-rs#30)

- The interpreter held one local budget in every mode, 32,000,000 bytes for
  each stack apart, counting the bytes alone, and stopped a script that
  exceeded it with a resource limit (`ScriptEvaluationError::resource_limit`,
  no verdict). After Genesis the reference bounds a script's memory by the
  stack memory budget of the path and by nothing else
  (`src/consensus/consensus.h:81-82`): on the block path the operator's
  mandatory `-maxstackmemoryusageconsensus` (`src/bitcoind.cpp:140-157`; 0
  means `INT64_MAX`, `consensus.h:82`) and the node's
  `-maxstackmemoryusagepolicy` on the
  mempool path, 100,000,000 bytes by default (`src/policy/policy.h:153`;
  `GetMaxStackMemoryUsage`, `src/configscriptpolicy.cpp:139-154`). It counts
  the main and the alt stack as one budget (the alt stack is a child stack,
  `src/script/interpreter.cpp:1993`, whose growth the parent counts,
  `src/script/limitedstack.cpp:196-199`), each element at its size plus 32
  bytes (`LimitedVector::ELEMENT_OVERHEAD`, `src/script/limitedstack.h:43`),
  and refuses a growth that would exceed the budget before it happens
  (`limitedstack.cpp:194-209`; `OP_NUM2BIN`'s pad is charged before the
  resize, `:66` then `:68`), `SCRIPT_ERR_STACK_SIZE`
  (`interpreter.cpp:1815-1817`). Under a word the interpreter now counts as
  the node counts. `SpendParams::memory_limit: None` selects a local budget of
  100,000,000 bytes on the node's count on both paths (`Spend::memory_limit`):
  the block path's own figure is the operator's setting, which a library
  cannot know and, at 0, embedded in a wallet cannot honor, so above the local
  budget the evaluator still declines
  with a resource limit, at the higher figure and on the node's count. On the
  mempool path the policy's excess is a verdict with a fixed message,
  `Stack size limit exceeded: N bytes, the stack memory policy is M bytes.`
  (`resource_limit: None`; `Spend::stack_memory_policy`;
  `Spend::set_stack_memory_policy` for a node configured otherwise, 0
  selecting no policy verdict as the node's 0 does,
  `configscriptpolicy.cpp:289-292`; `ScriptFlags::max_stack_memory_usage`;
  `flags::DEFAULT_STACK_MEMORY_USAGE_POLICY`, `flags::STACK_ELEMENT_OVERHEAD`).
  An explicit `memory_limit` wins in every mode and stays a resource limit;
  the policy's verdict fires at its own figure whatever the local budget. An
  alt stack the unlocking script leaves non-empty stays charged while the
  locking script runs, as on the node, whose alt stack is created per script
  and dropped without releasing its elements' charge (`LimitedStack` declares
  no destructor, `limitedstack.h:78-151`). Every refusal of the budget under a
  word comes before the allocation it would need: `OP_NUM2BIN`'s pad on the
  node's count after the minimal-encoding test, as the reference orders the
  two, and the numeric left shift's result on its exact length (the
  magnitude's bits plus the count, one byte for each 8 bits and one for the
  sign's room) after the size tests of Calhooon/bsv-rs#21; that exact length
  also decides the reference's size test after the shift
  (`src/script/script_num.cpp:315-316`, `SCRIPT_ERR_SCRIPTNUM_OVERFLOW`)
  before the shift is computed. The default mode is unchanged: 32,000,000
  bytes for each stack apart, the bytes alone, the `element-size` refusals
  before allocation (`tests/resource_limits.rs`). Found by the same
  differential run against bitcoin-sv v1.2.2 (`879fc8b`): four transactions
  the reference decides stopped here at the local budget, two under both
  words (a 32,000,001-byte number built by `OP_NUM2BIN` and read by `OP_1ADD`
  on a coin created after Chronicle, `SCRIPT_ERR_SCRIPTNUM_OVERFLOW` on both
  paths; a 40,000,000-byte element built and dropped, valid on both paths)
  and two under the block word (the number 1 shifted left to exactly
  32,000,000 bytes, valid, and to 32,000,001 bytes past the size test before
  the shift, `SCRIPT_ERR_SCRIPTNUM_OVERFLOW` at the test after it; on the
  mempool path both overflow the policy's number length first). Pinned by
  `tests/script_stack_memory_witness.rs`: the four witnesses and a fifth of
  the same family (the size test before the shift) under the block word, the
  standard word and the default mode, and the budget's edges at the node's
  figures (exactly 100,000,000 bytes on the node's count admitted on both
  paths and one byte more refused, the policy's verdict on the mempool path
  and the resource limit on the block path; the same total split across the
  two stacks; the unlocking script's alt stack left charged; a policy of 0;
  an explicit budget of 1,000 bytes and one of 200,000,000 bytes) and at
  small figures (the 32 bytes of each element, the shared budget, the pad
  charged before the resize, the shift's exact length and charge). RED on 0.3.29: 18 of the file's 22 rows that
  use no 0.3.30 API (the other six set or read the new knobs), run on the
  published crate; the four that pass are the default mode's row of the
  32,000,001-byte read, the shifts refused before the shift on the mempool
  path and on both, and the shift's exact length at a number length of 16.

### Fixed: `OP_NUM2BIN`'s size bound under a word (Calhooon/bsv-rs#30)

- Under a word a size below 0 or above `INT32_MAX` is refused before anything
  is allocated, `SCRIPT_ERR_PUSH_SIZE` on every path, as the reference
  refuses it (`src/script/interpreter.cpp:1747-1749`), with the message
  `OP_NUM2BIN requires a size from 0 to 2147483647, found N.`. The
  interpreter's 1 GiB element bound, which is not the reference's after
  Genesis, applies in the default mode only (to `OP_NUM2BIN`'s size and to
  `OP_CAT`'s result, with the message it had); under a word a size between
  1 GiB and `INT32_MAX` is decided by the budget, its growth charged before
  the resize (on the mempool path the policy's verdict, on the block path the
  local budget's resource limit, nothing allocated). The verdict on a size
  above `INT32_MAX` is unchanged (`SCRIPT_ERR_PUSH_SIZE`); its message under a
  word is new. Pinned by the same file: a size of 2^31, of `INT32_MAX` and of
  -1 under both words and in the default mode.

### Tests

- The CI step of the consensus witness files also runs
  `tests/script_stack_memory_witness.rs` (about 100 MB at its peak: its large
  rows run one at a time) and `tests/resource_limits.rs`, which pins the
  default mode's budget and had never run in CI.

## [0.3.29] - 2026-09-27

### Fixed: an undefined base hash type refused under STRICTENC (Calhooon/bsv-rs#23)

- `Spend::check_signature_encoding` tested the DER form, the low-S rule and
  the FORKID bit and never the base type, so a signature made over the BIP143
  digest of a hash type such as `0x44` (base 4 | FORKID) verified. Under
  `SCRIPT_VERIFY_STRICTENC` the reference refuses a signature whose hash type
  is not defined (`src/script/interpreter.cpp:291-294`,
  `SCRIPT_ERR_SIG_HASHTYPE`): `SigHashType::isDefined`
  (`src/script/sighashtype.h:82-90`) clears the CHRONICLE, FORKID and
  ANYONECANPAY bits and requires what is left to be ALL (1), NONE (2) or
  SINGLE (3); both node words carry STRICTENC (`src/script/standard.h:57`,
  `:64`). The interpreter now applies the test under a word carrying STRICTENC
  and in the default mode (the TypeScript SDK refuses such a type too), after
  the DER and low-S rules and before the CHRONICLE and FORKID rules, as the
  reference orders them; the message is
  `The signature's hash type (0xNN) has no defined base type.`. Found by the
  same differential run against bitcoin-sv v1.2.2 (`879fc8b`), three
  transactions (bases 0, 4 and 31). Pinned by
  `tests/script_undefined_hashtype_witness.rs`: the witness (`0x44`) refused
  under the block word, the standard word and the default mode, its two
  siblings (`0x40`, `0x5f`) refused, the witness valid under the block word
  without STRICTENC (the reference does not test the base without the flag);
  the boundary cases re-type the witness's signature: every defined base with
  any of the other bits passes the test and then fails to verify (a false
  top), every undefined base is refused. RED on 0.3.28: 5 of 7 rows.

### Fixed: the signature hash dispatched on the CHRONICLE bit (Calhooon/bsv-rs#22)

- The interpreter computed the BIP143 digest for every hash type. The
  reference's `SignatureHash` (`src/script/interpreter.cpp:2112-2124`) does
  so only when `SCRIPT_ENABLE_SIGHASH_FORKID` is in the flags and the type
  carries the FORKID bit and not the CHRONICLE bit (`SIGHASH_CHRONICLE = 0x20`,
  `src/script/sighashtype.h:14`); every other type is hashed by the original
  serializer (`SignatureHashOriginal`, `2086-2110`;
  `CTransactionSignatureSerializer`, `1841-1958`: the version; the inputs, only
  the signed one under ANYONECANPAY, the others with an empty script and, under
  SINGLE or NONE, a zero sequence; the scriptCode as `SerializeScriptCode`
  writes it, `1864-1892`, a length prefix of the scriptCode's size minus its
  `OP_CODESEPARATOR`s and the bytes the parser reads with the separators
  removed, stopping where `GetOp` fails, `script.h:164-195`; the outputs, none
  under NONE, the null output at every index but the signed one under SINGLE;
  the lock time; the 4-byte type), and the constant `one` when SINGLE names an
  output the transaction does not have (`2094-2102`). So a signature made over
  the original digest with the CHRONICLE bit, valid on the reference under a
  post-Chronicle word, was a false top here, and one made over BIP143 with that
  bit verified here where the reference refuses it. `Spend::verify_signature`
  now dispatches as `SignatureHash` does (FORKID is always enabled in this
  interpreter: the CHRONICLE bit selects the original digest, its absence
  BIP143), in every mode, as the TypeScript SDK does; under a word carrying
  STRICTENC and not CHRONICLE the bit is refused before verification, as the
  reference's `CheckSignatureEncoding` does (`291-303`,
  `SCRIPT_ERR_ILLEGAL_CHRONICLE`; the message
  `The signature must not use SIGHASH_CHRONICLE before Chronicle.`). New in
  `primitives::bsv::sighash`: `SIGHASH_CHRONICLE`,
  `compute_sighash_dispatched_for_signing`,
  `compute_sighash_original_for_signing` and
  `build_sighash_preimage_original`; `compute_sighash`,
  `compute_sighash_for_signing` and `build_sighash_preimage` keep computing
  BIP143. Found by the same differential run against bitcoin-sv v1.2.2
  (`879fc8b`), 21 transactions. Pinned by
  `tests/script_sighash_dispatch_witness.rs`: the witness (a P2PK spend whose
  locking script ends in `OP_RETURN 0x4c`, signed `0x61` over the original
  digest) valid under the block word, the standard word and the default mode,
  refused under a block word of the era before Chronicle; and the whole class
  as one table under both words (the six defined types with the bit, each
  with and without ANYONECANPAY; three-input spends under ALL, NONE, SINGLE
  with and without its output, ANYONECANPAY, one and two `OP_CODESEPARATOR`s;
  five more truncated pushes after a top-level `OP_RETURN`; the bit on a coin
  created before Chronicle; a CHRONICLE-bit signature made over BIP143, which
  the reference refuses). RED on 0.3.28: 21 of 21 rows.

### Fixed: the two bounds of the numeric shifts (Calhooon/bsv-rs#21)

- `OP_LSHIFTNUM` and `OP_RSHIFTNUM` shifted by a count of any size, so
  `1 OP_RSHIFTNUM 2147483648` was 0 and a valid spend, and a left shift's size
  was tested only against the interpreter's local memory budget (a resource
  limit, not a verdict). The reference reads the count and the value as big
  integers (`src/script/interpreter.cpp:708-711`, `744-747`) and applies
  `CScriptNum::operator<<=` / `operator>>=`: a left shift first refuses a
  result whose size, the value's serialized size plus `count / 8` bytes,
  would exceed the era's maximum number length (`src/script/script_num.cpp:305-308`,
  `SCRIPT_ERR_SCRIPTNUM_OVERFLOW`, `interpreter.cpp:1807-1810`), before any
  shift; then on both shifts a count above `INT_MAX` throws `big_int_error`
  (`src/big_int.cpp:359-369`, `383-393`), caught as `SCRIPT_ERR_BIG_INT`
  (`interpreter.cpp:1819-1821`); a right shift has no size test
  (`script_num.cpp:363-367`). Under a word the interpreter now applies both,
  in that order, before its memory budget; the message of the second is
  `<opcode> count (N) does not fit an int.`. The negative-count refusal, the
  shifts, the result's length test and the default mode (the TypeScript SDK
  shifts by any count) are unchanged. Found by the same differential run
  against bitcoin-sv v1.2.2 (`879fc8b`). Pinned by
  `tests/script_shift_count_witness.rs` (the witness under the block word and
  the standard word: the big-integer error; the default mode: valid; RED on
  0.3.28) and its boundary cases (a right shift by `INT_MAX` is 0 and valid;
  left shifts of 1 by `INT_MAX` and `INT_MAX + 1` overflow the number length
  before any allocation, at the block path's 32,000,000 bytes and the mempool
  path's 10,000; a zero value follows the same tests; an ordinary shift and a
  coin created before Chronicle are unchanged).

### Fixed: the `int64` reading of the `OP_SUBSTR`, `OP_LEFT` and `OP_RIGHT` operands (Calhooon/bsv-rs#20)

- The three Chronicle splice opcodes read their length and offset operands as
  script numbers of any length under the era's limit. The reference builds
  them as a `CScriptNum` on its `int64` path (`src/script/interpreter.cpp:622-625`,
  `651-653`, `676-678`; the constructor's default `big_int = false`,
  `src/script/script_num.h:60-63`), where `bsv::deserialize<int64_t>`
  (`src/script/int_serialization.h:64-95`) returns the two's-complement
  `int64` of the first 8 bytes of an element longer than 8 bytes and never
  reads the rest (`:78-79`), then `getint` saturates the value to the `int`
  range (`src/script/script_num.cpp:394-420`). So a 9-byte operand
  `04 00 00 00 00 00 00 00 80` is 4 to the reference and was −4 here, a range
  refusal. Under a word `Spend::read_splice_operand` now reads the operands
  that way (the length test and the minimal-encoding rule first, as at every
  read); an element of 1 to 8 bytes decodes exactly as before. The default
  mode is unchanged: the TypeScript SDK reads a script number of any length.
  Found by the same differential run against bitcoin-sv v1.2.2 (`879fc8b`).
  Pinned by `tests/script_int64_operand_witness.rs` (the witness under the
  block word and the standard word: valid; the default mode: the range
  refusal; RED on 0.3.28) and its boundary cases (an 8-byte operand with its
  sign bit set is −4 on both sides, a 9-byte operand with a zero ninth byte
  and a 10-byte operand with zero tail bytes are 4, `OP_LEFT` and `OP_RIGHT`
  read their length the same way, an 8-byte `INT64_MAX` offset is out of
  range on both sides).

## [0.3.28] - 2026-09-23

### Fixed: the low-S check at the curve order (Calhooon/bsv-rs#14)

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

### Fixed: the script-number length limit (Calhooon/bsv-rs#17)

- The interpreter read a script number of any length. The reference builds
  every number it reads with the maximum length of the coin's era and throws
  `scriptnum_overflow_error` before the minimal-encoding check
  (`src/script/script_num.cpp:62-68`; `SCRIPT_ERR_SCRIPTNUM_OVERFLOW`,
  `src/script/interpreter.cpp:1807-1810`): 750,000 bytes for a coin created
  after Genesis and 32,000,000 after Chronicle on the block path
  (`src/consensus/consensus.h:64`, `:66`), the node's
  `-maxscriptnumlengthpolicy` on the mempool path, 10,000 by default
  (`src/policy/policy.h:156`; `GetMaxScriptNumLength`,
  `src/configscriptpolicy.cpp:79-110`, the era from the coin's flags,
  `interpreter.cpp:2269-2274`). Under a word the interpreter now applies that
  limit before the decode at every read (`ScriptFlags::max_script_num_length`,
  `Spend::max_script_num_length`; the mempool path's policy through
  `Spend::set_script_num_length_policy`, 0 selecting the consensus limit; a
  word carrying the mempool word's four bits is judged on the mempool path,
  `ScriptFlags::is_mempool_word`), on every arithmetic result before it is
  pushed (`script_num.cpp:164`, `194`, `214`, `301-315`), at `OP_BIN2NUM`'s
  result (`interpreter.cpp:1789-1790`, the same refusal as a non-minimal
  result), and as the 4-byte limit on `OP_CHECKMULTISIG`'s two counts
  (`1519-1525`, `1550-1552`). The message is `Script number overflow: N bytes,
  the limit is M bytes.`. The default mode is unchanged: the TypeScript SDK
  reads a number of any length. Found by the same differential run against
  bitcoin-sv v1.2.2 (`879fc8b`): a version-2 spend of a coin created between
  Genesis and Chronicle whose script builds the number 1 followed by 2^20 zero
  bytes (1,048,577 bytes) and reads it with `OP_1ADD` was valid here under
  every word and mode. Pinned by `tests/script_num_length_witness.rs` (the
  witness under the block word and the standard word: overflow; the default
  mode: valid; the same coin created after Chronicle: within 32,000,000,
  valid) and by the boundary tests in `spend.rs` (750,000 / 750,001 for a coin
  created after Genesis, 32,000,000 / 32,000,001 after Chronicle, 10,000 /
  10,001 under the standard word, a policy of 0 falling back to the consensus
  limit, the length test before the minimal-encoding test, a product longer
  than the limit refused before the push, an `OP_BIN2NUM` result beyond the
  limit refused, a 5-byte `OP_CHECKMULTISIG` count refused under a word).
### Tests

- Nine assertions that a fresh signature is 70 to 73 bytes long replaced by
  what the reference admits: the element parses as a DER signature with its
  sighash byte, re-encodes to the same bytes and is 9 to 73 bytes long
  (`IsValidSignatureEncoding`, `src/script/interpreter.cpp:177-194`); the
  multisig unlock test signs with fixed keys. A minimal DER `r` or `s` is
  shorter than 32 bytes when its leading byte is zero, so the old lower bound
  failed on about one key in 13,000 (`test_multisig_unlock_has_dummy_op_0` on
  `main`, Calhooon/bsv-rs#16). Test-only; the interpreter is unchanged.

### Corrected

- The 0.3.27 entry and the header of `tests/script_residual_witnesses.rs`
  said "nine witness transactions"; the file holds ten, of eight rules (two
  each for the truncated push and the undefined opcode, one each for the
  second `OP_ELSE`, `OP_VER`, `OP_2DIV`, `OP_2MUL`, `0xb7` as `OP_RSHIFTNUM`
  and the FORKID scriptCode). One count at every site now.

## [0.3.27] - 2026-09-23

### Fixed: five consensus rules the interpreter got wrong in every mode (Calhooon/bsv-rs#12)

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

### Notes: cross-SDK parity

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

### Added: the node's flag words (`script::flags`)

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

### Fixed: a consensus oracle can select the block word (Calhooon/bsv-rs#10)

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

### Notes: cross-SDK parity

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

### Fixed: reference parity in the script interpreter (`Spend`)

- `OP_NUM2BIN` refuses a size operand larger than the local memory budget BEFORE
  allocating it (the TypeScript SDK's `element-size` check). Previously a
  9-byte script (`OP_1 <1e9> OP_NUM2BIN`) allocated up to
  `MAX_SCRIPT_ELEMENT_SIZE` (1 GB) and only then tripped the stack budget on
  the push, on a Cloudflare Worker that is an isolate kill, not a refusal.
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

### Fixed: BEEF linking is linear and verify walks by txid

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

### Fixed: BEEF ancestry linking for every input (ts-sdk parity)

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

### Added: midstate-reuse sighash API (`SighashCache`)

- **`primitives::bsv::sighash::SighashCache`**, a cache over one
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
  single-use `SighashCache`, one preimage implementation in the crate,
  public API and behavior unchanged. Byte-equality is pinned by scope-class
  unit tests, by the 499-vector cross-SDK sighash suite run through the cache
  across every input, and by the 5,116-vector ts-stack conformance census
  (`tests/conformance_scripts.rs`), whose sighash path now exercises the
  cache directly.

### Documented

- RFC 6979 digest-domain note on `PrivateKey::sign` and in the `sighash`
  module docs: for a digest >= n (P ≈ 2⁻¹²⁸ for sha256d output), k256 seeds
  the nonce DRBG with `bits2octets(digest)` per the RFC while libsecp256k1
  and `@bsv/sdk` seed it with the raw digest bytes, deterministic signature
  bytes differ across stacks in that regime only; in-range digests are signed
  byte-identically. Pinned by `rfc6979_in_range_digest_der_is_pinned` and
  `rfc6979_digest_ge_n_der_is_pinned` in `tests/ec_tests.rs`.

## [0.3.19] - 2026-08-25

### Fixed: BEEF merkle-path reattachment (ts-sdk parity)

- **`Transaction::from_beef` and `Beef::find_atomic_transaction` dropped the
  merkle path.** Both cloned the parsed transaction out of the BEEF, so the
  returned transaction carried `merkle_path: None` even when the BEEF proved
  it, every caller asking "is this mined?" got "no" forever. Bumps live in
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

## [0.3.16] - 2026-07-09

### Fixed: Spend engine ts-sdk parity

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

## [0.3.14] - 2026-07-04

### Fixed

- **Panic / OOM-abort on adversarial length prefixes (bounded pre-allocation).**
  Every parser that pre-allocated a collection sized by an attacker-controlled
  count read from the input (`Vec::with_capacity(count)`,
  `HashMap::with_capacity(count)`, `vec![default; count]`) could be made to
  abort the process with a capacity-overflow / OOM panic *before a single
  element was read*. A ~20-byte crafted BEEF whose transaction input-count
  varint is `0xFE FF FF FF FF` (u32::MAX) makes `Transaction::from_beef` /
  `Transaction::from_binary` allocate billions of `TransactionInput`s and
  abort, a trivially cheap denial-of-service (and on `wasm32`, where the build
  is `panic = abort`, it is unrecoverable: `.ok()` cannot catch it).

  All such sites now bound the pre-allocation to what the remaining buffer could
  actually contain via the new `primitives::bounded_capacity(count, remaining,
  min_elem_bytes)` helper, `count.min(remaining / min_elem_bytes)`. The read
  loop already errors the instant the buffer is exhausted, so parse results are
  unchanged for both valid and malicious input; only the (now bounded) capacity
  hint changes. A bogus count now yields `Err`, never a panic.

  Hardened sites: `transaction::Transaction::{from_reader, from_ef}`
  (input/output counts, and the EF `source_output_index` placeholder-output
  fabrication, which is now rejected above a 16 MiB allocation budget, the
  placeholder length is computed in `u64` via `ef_source_placeholder_len` so the
  `+ 1` cannot overflow on 32-bit targets: on `wasm32` `source_output_index as
  usize + 1` wrapped `u32::MAX` to `0`, defeating the budget check and then
  index-OOB-panicking on a zero-length vec),
  `primitives::bsv::sighash::parse_transaction`, `overlay` binary lookup
  responses, `wallet::wire` (string arrays/maps, action/output/certificate
  arrays, keyrings), and `auth` certificate/header parsing. Purely defensive;
  no API change beyond the additive `bounded_capacity` export → patch bump.

## [0.3.11] - 2026-05-20

### Fixed

- **wasm32 `Peer::to_peer` / BRC-103 handshake hang.** The `wasm` feature now
  enables `futures-timer/wasm-bindgen`. The wasm `wait_with_timeout` helper
  (the `Peer` handshake timeout) races the handshake future against a
  `futures_timer::Delay`, but the `wasm` feature previously pulled
  `futures-timer` *without* its `wasm-bindgen` feature. On
  `wasm32-unknown-unknown` that selected `futures-timer`'s native timer-thread
  backend, so `Delay::new` panicked (`thread::spawn` is unsupported) on the
  first poll, hanging/aborting any `Peer::to_peer` call that initiates a
  handshake inside a Cloudflare Worker or browser `wasm-bindgen-futures`
  executor. Enabling `futures-timer/wasm-bindgen` flips it to the
  `gloo-timers`/`setTimeout` backend, which works in those environments.
  Pure additive feature wiring (no API change) → patch bump.

## [0.3.7] - 2026-04-21

### Added

- **`bsv_rs::overlay::create_signed_overlay_admin_token`**, produces
  TS-parity 5-field signed SHIP/SLAP advertisement tokens. Byte-exact
  match with `@bsv/sdk 1.10.1`'s
  `pushdrop.lock(fields, [2, protocol_name], '1', 'anyone', forSelf=true,
  includeSignature=true, lockPosition='before')`, the exact call
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

- **`tests/vectors/overlay_admin_token_ts_parity.json`**, byte-exact
  parity vectors generated from `@bsv/sdk 1.10.1`. 5 cases covering SHIP
  (3 inputs, including long topic) + SLAP (2 inputs).

- **`tests/overlay_admin_token_ts_parity_tests.rs`**, blocking parity
  gate: loads the TS vectors and asserts
  `create_signed_overlay_admin_token(...)` reproduces them verbatim,
  plus a determinism guard for RFC-6979 signing.

### Deprecated

- **`bsv_rs::overlay::create_overlay_admin_token`** (soft deprecation,
  still compiles). It emits a 4-field unsigned PushDrop with the
  identity key as locking key, a shape `@bsv/overlay-discovery-services`
  requires but never admits, so any advert built with it is silently
  rejected by peer validators. See the `#[deprecated]` attribute for
  the migration pointer. The `decode_overlay_admin_token` reader still
  accepts both 4- and 5-field shapes for backward-compat.

### Notes: cross-SDK parity

- **Matches TS (`@bsv/sdk` 1.10.1)** byte-exact, the version deployed
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
