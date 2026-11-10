# Lane fix-tx-trailing: a transaction's readers refuse bytes after the transaction (#840)

Base: `origin/beta` at `fa75921b` (the worktree's HEAD, no reset needed). Reference: `ts-stack@edf6e03` `packages/sdk/src/transaction/Transaction.ts`; Go: `go-sdk@2ca481c` `transaction/transaction.go`. Logs: `/Volumes/Lanes/out/bsv-rs/fix-tx-trailing/`.

## The finding, as run

On `fa75921b`, `Transaction::from_binary` and `from_hex` read one transaction from the front of their input and cached the whole input: block 170's transaction followed by one byte read `Ok` with id `9529fd4a2da1eb59324757bf4d82ea2900f9b5a8ab9ae17a0a980bfbdf4d8356` (the transaction is `f4184fc596403b9d638783cf57adfe4c75c605f6356fbc91338530e9831e9e16`), `to_binary()` 276 bytes. `from_ef` read a prefix with no cache (id right); `parse_script_offsets` never read the lock time.

## The reference and Go at their pins

| Door | Reference (`Transaction.ts` at `edf6e03`) | go-sdk at `2ca481c` |
|---|---|---|
| `fromBinary` / `fromBinaryView` | refuses: `Serialized transaction contains trailing data` (`:523-538`) | `NewTransactionFromBytes`: refuses, `nLockTime length must be 4 bytes long` (`used != len(b)`, `:56-67`, `errors.go:10`) |
| `fromHex` | through `fromBinaryView` (`:548-553`); odd length padded with a leading zero (`utils.ts` `hexToUint8Array`) | `NewTransactionFromHex`: `hex.DecodeString` (odd length refused) then `NewTransactionFromBytes` (`:45-53`) |
| `fromEF` / `fromHexEF` | refuses: `Serialized EF transaction contains trailing data` (`:419`, `:562-564`) | no separate door: `ReadFrom` detects the EF marker (`:81-140`), so `NewTransactionFromBytes` refuses the same way |
| `parseScriptOffsets` | reads the lock time, refuses: `Serialized transaction contains trailing data` (`:460-462`) | none |
| `fromReader` | prefix reader, no check (`:466-468`) | `NewTransactionFromStream` / `ReadFrom` return the bytes used (`:72-81`) |
| `fromBEEF` | `Beef.fromBinaryView`, strict: `Serialized BEEF contains trailing data` | `NewTransactionFromBEEF` |

## The survey: every whole-buffer reader of this crate

Command: `grep -rn 'pub fn from_binary\|pub fn from_hex\|pub fn from_bytes\|pub fn from_ef\|pub fn from_hex_ef\|pub fn from_beef\|pub fn from_atomic_beef\|pub fn from_asm\|pub fn from_string\|pub fn from_json\|pub fn from_reader\|pub fn from_base58\|pub fn from_der\|pub fn from_wif' src/`, plus `sighash::parse_transaction` (found by the dependents' survey). Classes: (A) refuses trailing data today; (B) reads a prefix and returns a value right in itself; (C) reads a prefix and returns a value carrying the extra bytes or a wrong identity.

| Door | Class (before) | Reference twin | After this lane |
|---|---|---|---|
| `Transaction::from_binary` | C (cache = whole input; id the input's hash) | `fromBinary`: refuses | fixed: refuses in its words |
| `Transaction::from_hex` | C (same; hex cache the input) | `fromHex`: refuses | fixed |
| `Transaction::from_json` (`hex` member) | C (through `from_hex`) | none in TS; Go's `UnmarshalJSON` through `NewTransactionFromHex`: refuses | fixed (through `from_hex`) |
| `Transaction::from_ef` | B (no cache, id right) | `fromEF`: refuses | fixed: the EF words (one line) |
| `Transaction::from_hex_ef` | B (through `from_ef`) | `fromHexEF`: refuses | fixed |
| `Transaction::parse_script_offsets` | B (offsets right; lock time never read) | `parseScriptOffsets`: refuses | fixed: reads the lock time, refuses what follows |
| `Transaction::from_reader` (was private) | prefix by design | `fromReader`: prefix | made public: the migration door; caches nothing |
| `Transaction::from_beef`, `from_atomic_beef` | A (`Beef::from_binary`: `TrailingBytes`, #86) | `fromBEEF`: refuses | unchanged; words differ (stated) |
| `Beef::from_binary`, `from_hex` | A (`TrailingBytes`) | `Beef.fromBinary`: prefix at the pin (`Beef.ts:1286-1290`, "intentionally ignores any trailing bytes"; the 0.4.2 stated row); `Beef.fromBinaryStrict` and `fromString` refuse (`:1296-1308`, `:1316-1319`) | unchanged |
| `Beef::from_reader`, `BeefTx::from_reader` | reader form | `fromReader` | unchanged |
| `MerklePath::from_binary`, `from_hex` | A (`TrailingBytes`, #167) | `fromBinary`: prefix (`legalOffsetsOnly`) | unchanged (stated row, #167) |
| `MerklePath::from_reader` | reader form | `fromReader` | unchanged |
| `beef_stream::Cursor::from_binary` | A (`not a cursor: bytes after its end`) | none | unchanged |
| `BlockHeader::from_binary`, `from_hex` | A (exactly 80 bytes) | node frame | unchanged |
| `BlockHeader::from_reader` | reader form | none | unchanged |
| `auth::Certificate::from_binary` | A-equivalent: the signature is the rest, read by the reference's `fromDER` (refuses trailing) | `Certificate.fromBinary` | unchanged |
| `Script` / `LockingScript` / `UnlockingScript` `from_binary`, `from_hex`, `from_asm` | no frame: the whole input is the script | `Script.fromBinary` | unchanged |
| `PublicKey::from_bytes`, `from_hex`; `PrivateKey::from_bytes`, `from_hex`, `from_wif`; `SymmetricKey::from_bytes`; `p256` keys | exact lengths | as cited in their modules | unchanged |
| `p256::Signature::from_der` | strict (the `p256` crate's DER) | none | unchanged |
| `compat::bip32::ExtendedKey::from_string` | exact 82 decoded bytes | Go `NewKeyFromString` | unchanged |
| `Mnemonic::from_binary`, `Polynomial::from_string`, `Outpoint::from_string`, `Counterparty::from_hex`, `BigNumber::from_hex`, `U256::from_hex`, `ChainWork::from_hex`, `from_hex`/`from_base58*` | whole text read or refused | as cited | unchanged |
| `HostReputationTracker::from_json` | serde (refuses trailing JSON) | none | unchanged |
| `primitives::ec::Signature::from_der` | **B, listed**: reads the sequence its length names, ignores bytes after it | `Signature.fromDER`: refuses (`Signature DER invalid`, `Signature.ts:64-65`) | **listed, not fixed**: a DER signature followed by bytes verifies as the signature alone at `messages::verify` (the signature is the bytes after the key ID, `src/messages/signed.rs:232-234`), `compat::bsm::verify_message_der` and the overlay admin token's signature field (`src/overlay/admin_token_validation.rs:258`); a change of verdicts across three modules, its own lane |
| `primitives::bsv::sighash::parse_transaction` | **B, listed**: fields from the front, no cache, no txid | none | **listed, not fixed**: a sighash computed over bytes with a suffix is the prefix transaction's; its error type is `primitives`' (`TransactionError` is gated on `transaction`), so not the same one line |

## In-crate callers of the changed doors

`grep -rn 'Transaction::from_binary\|Transaction::from_hex' src/`: no production caller outside `src/transaction/`. Inside it, every caller hands one framed transaction: `beef/collect.rs:171` (the decoder's `body.raw`, one transaction's bytes), `beef_tx.rs` `parse_raw` and `has_no_outputs` (an entry's `raw_tx`, framed by `merge_raw_tx`'s and `from_raw_tx`'s scan, #817, or by the reader), `beef/in_memory.rs:191` (same), `beef/index.rs:295` (`edit_tx` on an entry's raw bytes), `tx_json.rs:124` (`from_json`'s `hex`, a caller's text: now refused with a suffix, as Go's `UnmarshalJSON` does). `BeefTx::from_reader`'s `read_tx` moved from the crate-private `from_reader_internal` to the public `from_reader` (the alias removed). The one behaviour that changed is a crate-only state: a raw entry built by `BeefTx::from_framed_raw_tx` (`pub(crate)`, fed only framed bytes) with a byte after the transaction is now refused by `edit_tx` (`an_edit_of_raw_bytes_with_a_trailing_byte_is_refused_840`, replacing #817's `a_no_op_edit_of_raw_bytes_with_a_trailing_byte_moves_nothing_817`), as the reference's `BeefTx` throws parsing such bytes (`BeefTx.ts:121`).

## PR #836's and #839's doors, and `from_reader`'s cache

`merge_raw_tx` and `BeefTx::from_raw_tx` frame their bytes by `beef_raw_frame::one_transaction` before anything is stored; the check stays (it refuses in the reference scan's words, before a parse; no line is dead). `from_reader` builds through `with_params` and caches nothing: a transaction read from the front of a longer reader serializes and hashes its fields alone (`the_reader_form_reads_one_transaction_and_leaves_the_rest_840` asserts the id, bytes and hex for the reader followed by 0, 1, 4 and 275 bytes). With `from_binary` strict, no path of this crate holds a `Transaction` whose cached bytes carry more than the transaction.

## The recording

`tests/support/transaction_trailing_data_840.mjs` on the reference bundle at `edf6e03` (`git archive` then `bun build mod.ts --target node --format esm`), Node v22.18.0; two runs `cmp`-identical. 30 cells: `fromBinary` and `fromHex` on the clean transaction, plus one byte (`00`), plus four (`01020304`), plus itself; `fromHex` plus two digits and plus one digit; `fromEF` and `fromHexEF` on the EF form the same way and plus one digit; `fromBEEF` on a BEEF of it clean, plus one and four bytes; `parseScriptOffsets` clean, plus one and four bytes, without its lock time; `fromReader` clean, plus one, four and itself. Every suffixed cell but `fromReader`'s refuses; `fromReader` answers the clean id with 0, 1, 4 and 275 bytes left.

## RED on the base

Scratch copy `git archive fa75921b` under `$TMPDIR`, its own target dir (`~/bsv/targets/fix-tx-trailing-red`), the test file and vector copied in, and the base's private `from_reader` made `pub` (the one line the file needs to compile): 5 of 10 RED.

```
fromJson plus_four_bytes: Ok with id b5f0b327e4fb58e51ebf5d803898a55ed6072f61467965770bdd8a77d4250a1b where the reference refuses
fromBinary plus_one_byte: Ok with id 9529fd4a2da1eb59324757bf4d82ea2900f9b5a8ab9ae17a0a980bfbdf4d8356 where the reference refuses
fromHex plus_one_byte: Ok with id 9529fd4a2da1eb59324757bf4d82ea2900f9b5a8ab9ae17a0a980bfbdf4d8356 where the reference refuses
fromEF plus_one_byte: Ok with id f4184fc596403b9d638783cf57adfe4c75c605f6356fbc91338530e9831e9e16 where the reference refuses
called `Result::unwrap_err()` on an `Ok` value: ScriptOffsets { inputs: [ScriptOffset { index: 0, offset: 42, length: 72 }], outputs: [...] }
```

The other five (the clean pin, the reader form, the three stated cells, the census) are green on both.

## The sweep

Every `tests/transaction_*`, `beef_*`, `script_*`, `spend_*` file and every other file calling a changed door (89 files) green; no vector carried bytes after a transaction. Two counts moved, both from this lane's own vector: the #817 sweeps over every vector BEEF (`beef_v1_txid_only_writer_817.rs` `SWEPT`, `beef_writer_refusals_817.rs` `6 * N`) read 338 BEEFs, 337 with the new vector removed for one run (the vector's clean V2 BEEF the one added; its suffixed copies refused). Conformance with `BSV_CONFORMANCE_DIR=~/bsv/ts-stack/conformance` (the corpus identical between `edf6e03` and the clone's HEAD): scripts 5,116 total, 4,121 run, 4,110 passed, 958 unsupported, 37 skipped, 11 known failures, 0 failures, 0 panics (unchanged since #816); BEEF the four classes' totals unchanged (15, 16, 16, 8).

## The dependents

Each path grepped by its own name for `Transaction::from_(binary|hex|ef|hex_ef)`; production sites are those outside `tests/`, `benches/`, `examples/`, `*_tests.rs` and the first `#[cfg(test)]` of each file. `~/bsv/rust-message-box/src`: 0. `~/bsv/chaintracks-cloudflare`: 0. `~/bsv/bsv-wallet-toolbox-rs/src`: 6 (4 production). `~/bsv/bsv-wallet-cli/src`: 1 (1). `~/bsv/bsv-overlay-cloudflare/crates`: 178 (35). `~/bsv/bsv-middleware-rs`: 1 (1). Sources traced by a read-only agent and spot-checked here.

| Dependent | Production sites traced | A peer's or a service's suffix reachable | A peer's suffix reached `id()` or `to_binary()` with no comparison against an expected txid, before this fix |
|---|---|---|---|
| bsv-wallet-toolbox-rs | 4 | 2 (a service's, a caller's) | 0 |
| bsv-wallet-cli | 1 | 0 (a store's, if corrupt) | 0 |
| bsv-overlay-cloudflare | 35 | 19 (a peer's, a service's, or a store a peer filed into) | 5 |
| bsv-middleware-rs | 1 | 1 (a peer's; outputs only, the verdict moving from verified to unverifiable) | 0 |
| rust-message-box, chaintracks-cloudflare | 0 | 0 | 0 |

The sites, file by file and line by line, were handed privately to each downstream's captain (root `CLAUDE.md` rule 12); they are not listed in this public record. The sites comparing `id()` with an expected txid were reached too, and refused there as a mismatch; their outcome does not move. Rows a peer filed before the fix with a suffix (in two of the overlay's stores) now read as unparsable at the store readers: a dependent's migration question, not this crate's. A suffix passed the filers' signature checks because `sighash::parse_transaction` reads a prefix too (the listed reader above), and the suffix is outside every signature.

## The fold (the three reads of 2026-11-09)

The reads: the cold read MERGE (0.86), the rule read ACCEPT (0.9), the strength read ACCEPT (0.88). Folded on `lane/fix-tx-trailing-fold` from `0a3744e2`, no reset needed.

- The readers' docs. The rule read's `c93b9a5b` cherry-picked (the missing-lock-time words in the CHANGELOG entry and the root row; this record's `Beef.fromBinary` twin, a prefix parser at the pin). The cold read's `492e6063` corrected the same sentence; its true part `c93b9a5b` lacked (`fromEF` and `fromReader` given a `Reader` say `Reader read exceeds available data` too; `fromHex` and `fromHexEF` read a `Uint8Array` always) is carried into one sentence true to both reads: `Reader read exceeds available data` over a `number[]` (`fromEF`, `parseScriptOffsets`, a `fromReader` handed a `Reader`), `ReaderUint8Array read exceeds available data` over a `Uint8Array`, which `fromBinary`, `fromHex` and `fromHexEF` always read (`ReaderUint8Array.ts:13-19,46`, `Transaction.ts:523-536,562-564`; `fromEF` takes `ReaderUint8Array.makeReader`, which picks by the input's type).
- The base. This record and the CHANGELOG name `fa75921b`; the cold read reproduced the same 5 of 10 RED on `2c464e81`, the branch's base.
- The 53-bit cell (the cold read's item 7, older than #840; #844 conforms it): stated, not conformed. The recorder appends `cells_53` (ten cells: an output of 2^53 - 1, 2^53 and 2^64 - 1 satoshis through `fromBinary`, `fromHex`, `fromReader`; an EF source of 2^53 through `fromEF`) and `writer_53` (the reference's `toHex` of a transaction built with 2^53 and 2^64 as numbers: `The number is larger than 2 ^ 53 (unsafe)`, `BigNumber.ts:462`), inserted before `cells` so the vector's diff is additions only (109 lines, 0 removed; the 30 cells byte for byte); Node v22.18.0, two runs `cmp`-identical. Five tests, each asserting the recording's refusal on the reference's side and `Ok`, the amount and the id the hash of the bytes here; the root `CLAUDE.md` row (the node: `int64_t` amount, `MAX_MONEY` at `amount.h:130`, `CheckTransactionCommon` at `validation.cpp:543-551`, so no such output is valid there); `from_reader`'s rustdoc names the cell; the CHANGELOG parity note.
- The fuzz gap (the cold read's item 8): `fuzz_transaction_parser` reads the buffer's hex through `from_hex` (both cases) against `from_binary`, every UTF-8 buffer through `from_hex` and `from_hex_ef`, and asserts that a transaction `from_ef` returns writes the buffer back through `to_ef` exactly (the fields are read and written in one order, the varints canonical, the scripts held as read) with its plain bytes reading back to its txid, `from_hex_ef` agreeing. Two runs of 60 s from the six seeds plus the vector's EF, its 53-bit EF and both hex texts (a scratch corpus, the committed one unchanged): 448,200 and 371,364 runs, no crash.

RED. The 53-bit pins share their reading with `0a3744e2`, so a scratch copy of it (`git archive`, the test file and vector overlaid, its own target dir) with the conforming refusal planted at the two amount reads: 4 of 15 RED. The fold's cold re-read at `d4f8fd1a` could not reproduce the fourth: the refusal planted above 2^53 - 1 (as `toNumber` refuses, `BigNumber.ts:625-628`) at all three reads (`transaction.rs:283,329,428`) turns 3 of 15 red, `an_output_of_two_to_the_53_satoshis_is_read_where_the_reference_refuses_840`, `an_output_of_two_to_the_64_minus_1_satoshis_is_read_where_the_reference_refuses_840` and `an_ef_source_of_two_to_the_53_satoshis_is_read_where_the_reference_refuses_840`, the 2^53 - 1 pin green; a fourth red would be that pin, under a refusal at 2^53 - 1 itself. The records say 3.

```
fromBinary output_two_to_the_53: transaction error: Number can only safely store up to 53 bits (#844 conformed? the cell's test moves with it)
fromBinary output_two_to_the_53_minus_1: transaction error: Number can only safely store up to 53 bits (#844 conformed? the cell's test moves with it)
fromBinary output_two_to_the_64_minus_1: transaction error: Number can only safely store up to 53 bits (#844 conformed? the cell's test moves with it)
fromEF: transaction error: Number can only safely store up to 53 bits (#844 conformed? the cell's test moves with it)
```

The plant is at `> 2^53 - 2`, so the agreeing 2^53 - 1 cell turns red too; the writer pin reads the recording alone. The EF invariant: on the same scratch copy with `from_ef`'s trailing check removed, the target on the vector's EF plus one byte: `assertion left == right failed: from_ef returned a transaction other than its buffer`.

Outside the subject, filed by the reads and not changed here: `Signature::from_der` accepts a DER suffix (the rule read: blocks-cut; its own lane, #842); `sighash::parse_transaction` reads a prefix (the rule read: after-cut); one downstream verdict moves on the bump (the site handed privately to that downstream's captain, rule 12; the strength read: after-cut); the stable line carries #840, a cherry-pick or a dependents note the owner's and the keeper's (the strength read: after-cut).
