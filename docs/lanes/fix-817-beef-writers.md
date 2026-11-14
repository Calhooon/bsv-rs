# Lane fix-817-beef-writers: the BEEF writers, `merge_beef` and `merge_raw_tx` return `Result` (#817)

Started from `9ab384c97ad440848c716551ca98e3735b68157c`, `origin/lane/fix-817-door-sync`
(PR #832's head) after `git fetch origin`, on beta `cfbe3c98` (PR #823, `merge_beef`'s
snapshot, and PR #831, `MerklePath`'s fallible writers and `check_writable`). No reset was
needed; the lenient writer `to_writer_lenient_until_beef_817` was found at
`src/transaction/beef.rs:868` and `merkle_path.rs:415`.

## Provenance

A reader found that `Beef::to_binary` panics on a V1 BEEF holding a txid-only entry
(`BeefTx::write_tx_data`), reachable from wire bytes; on wasm32 an abort. The owner's
standard (2026-11-10): "we in no rush.. we love soundness"; "for choices.. they need to be
god tier and north star decision". Eleven independent design reads in three rounds decided
the shape (the three comments on #817); the owner's ruling of 2026-10-26 allows a
public-shape change on the 0.9.0 line that takes the reference's own shape. This lane is the
second of the two changes; the other, `MerklePath`'s writers, is PR #831.

The rule applied to every cell: a writer refuses only a state it cannot write faithfully
(bytes that would not frame, or would read back as a different state); it writes every other
state, valid or not, as the reference does (validity is the readers' and `verify`'s); the
reference's words where it refuses; where it writes bytes no reader reads back as written,
this crate refuses in its own words, states the row, and the difference is drafted for
upstream (row 63 of the #375 queue; row 62 until the fold's rebase onto #832's fold, which took 62).

## The table of states

Reference `ts-stack@edf6e03` (run, Node v22.18.0, `tests/vectors/beef_v1_txid_only_writer_817.json`);
Go `go-sdk@2ca481c` (read). "Before" is `9ab384c9`.

| State | Reachable by | The reference | Go | Before | After | The rule's clause |
|---|---|---|---|---|---|---|
| a txid-only entry under V1 or any word but V2 | wire bytes (a V1 BEEF read, then `merge_txid_only`, `make_txid_only`, `merge_beef` of a V2 BEEF holding one), the public `version` and `txs` | `toBinary` throws `a valid serialized Transaction is expected` | `Bytes` errs | panic (`beef_tx.rs:478:13` at `9ab384c9`, `:453:13` at `192b2c10`) | `Err` in the reference's words, every writer, `BeefTx::to_writer` too | the reference refuses: its words |
| a version word other than V1 or V2 | the public `version`, `with_version` | writes it; its reader refuses `Serialized BEEF must start with ...` | refuses (`invalid BEEF version`) | written, V1 layout | `Err` in the reference reader's sentence, after the reference writer's throws | written unreadably there: refused, stated |
| a V2 txid-only txid with a non-hex character | `merge_txid_only`, `BeefTx::from_txid`, `txs` | throws `Invalid hex string` | unrepresentable | written as nothing | `Err`, the reference's words | the reference refuses |
| a V2 txid-only txid of other than 64 hex digits (`""`, 62, 63, 66) | the same | writes it at its length or pads 63; `""` throws `Internal` | unrepresentable | written as its bytes or none | `Err`, `Invalid txid-only entry txid: expected 64 hex digits, got N`; `""` ahead of everything, the reference's position | written unreadably there (or another txid): refused, stated |
| a raw entry not exactly one transaction | `merge_raw_tx`, `BeefTx::from_raw_tx`, then `txs` | `mergeRawTx` throws its scan's words without an index; keeps the bytes with one, and keeps trailing bytes; writes them | `MergeRawTx` errs | kept, written | refused at both doors, the BEEF untouched (the scan's words; trailing bytes in this crate's); the writers scan an entry held unparsed | the reference refuses (no index): its words; else written unreadably there: refused, stated |
| a BUMP `MerklePath`'s writer refuses | the public `bumps`, `merge_bump` | throws or misframes (PR #831's table) | (#831) | written leniently | `Err`, `MerklePath`'s words | PR #831's rule |
| a BUMP index naming no BUMP | the public fields | writes it | errs | written | written | valid or not: written |
| `merge_beef` of a source in any refused state, or one the snapshot's reader refuses | the source's public fields | `mergeBeef` throws (writer, then `fromBinaryStrict`), target untouched | `MergeBeef` errs on some | merged | `Err`, the target untouched | the snapshot's verdict |
| `merge_beef` of a source BUMP whose duplicate carries a hash | `bumps` | merged, the hash dropped by its reader | n/a | merged | `Err` (#831's words) | reads back as another state: refused, stated |
| `merge_txid_only("")` | the door | throws `Internal` after pushing | unrepresentable | taken | taken (unchanged, six of six reads); the writer refuses | stated |
| `merge_bump` of a BUMP whose root does not compute, a BUMP of its height held | `merge_bump`, `merge_transaction` | throws `computeRoot`'s error | returns `-1` | appended | appended (unchanged, four of six reads, the owner's default) | the readers' to judge: stated |

The order of the check (`beef_writable.rs`), the reference's (`#getSerializedBytes`,
`Beef.ts:360-373`): (1) an empty txid-only txid, where `#ensureSerializableState` meets the
`Internal` getter, before the sort and the BUMPs; (2) a non-hex BUMP hash, `toWriter`
writing the BUMPs first; (3) each entry's reference refusal in written order; (4) the version
word, which the reference meets at its reader's byte 0 (`mergeBeef`'s snapshot) after every
writer throw; (5) each BUMP's own refusals; (6) each entry's own. `to_binary(&mut self)` sorts
before it refuses, as the reference's `toBinary` does. `to_binary_atomic` checks the closure
before it reads the subject's txid (`Beef.ts:409-410`).

## The signatures as built

```rust
impl Beef {
    pub fn to_binary(&mut self) -> Result<Vec<u8>>;
    pub fn to_hex(&mut self) -> Result<String>;
    pub fn to_writer(&self, writer: &mut Writer) -> Result<()>;
    pub fn to_binary_atomic(&mut self, txid: &str) -> Result<Vec<u8>>; // unchanged; its panic an Err
    pub fn merge_beef(&mut self, other: &Beef) -> Result<()>;
    pub fn merge_raw_tx(&mut self, raw_tx: Vec<u8>, bump_index: Option<usize>) -> Result<&BeefTx>;
    // unchanged: merge_bump -> usize, merge_transaction -> &BeefTx, merge_txid_only -> &BeefTx
}
impl BeefTx {
    pub fn from_raw_tx(raw_tx: Vec<u8>, bump_index: Option<usize>) -> Result<Self>;
    pub fn to_writer(&self, writer: &mut Writer, version: u32) -> Result<()>;
}
impl MerklePath {
    pub(crate) fn combine_verified(&mut self, other: &MerklePath); // combine's merge, its checks made at the call
}
```

Removed: `MerklePath::to_writer_lenient_until_beef_817` and the `#[allow(clippy::panic)]` on
`write_tx_data` (which now writes nothing for an entry with no data, a state the check keeps
from it).

## `merge_beef`'s verdict

The literal round trip, not a pre-pass: `snapshot_verdict` runs the writer's check over the
source's entries in `written_order` (the order the reference's `toBinary` writes them, #621),
writes the source in that order (each entry as `merge_beef` merges it, `written_tx_bytes`) and
reads the bytes back with `Beef::from_binary`. One write and one read of the source per merge,
before the target changes; the merge itself is #621's, from the source's objects, so the
#621 bytes are unchanged. The differential
(`merge_beef_s_verdict_is_the_write_then_read_round_trip_on_every_vector_beef_817`) compares
the verdict with `Beef::from_binary(&source.clone().to_binary()?)` on six states of each of
the 321 sweep BEEFs: 1,926 comparisons, 0 disagreements (the words compared where the writer
refuses; a reader's offsets may differ, its sort and the reference's order apart).
`fuzz_beef_parser` asserts that every BEEF `from_binary` returns merges.

## The survey of panic sites

From the lane `fix-v1-txid-panic` (`7b3a60b7`), re-read at `9ab384c9`: the one reachable
panic was `beef_tx.rs:478` at `9ab384c9` (`BeefTx has no transaction data to write`, moved from `:417`;
`beef_tx.rs:453:13` at `192b2c10`, the rebuilt base, the cold read's RED), now removed. `txid()`'s `panic!` (no constructor leaves an entry without data or txid), the
stream's `expect`s and `unreachable!`s stay as that survey listed them. The non-panic it
listed (a txid-only txid written through `from_hex(..).unwrap_or_default()`) is the
txid-length row above.

## RED

On a scratch `git archive 9ab384c9` with its own target
(`~/bsv/targets/bsv-rs-fix-817-beef-writers-red`), the two test files, the vector and the
seed helper overlaid: `beef_v1_txid_only_writer_817` compile-RED (16 errors),
`beef_writer_refusals_817` compile-RED (30 errors), the doors returning values. A probe there
(`tests/beef_writers_817_base_probe.rs`, scratch only):

```
thread 'v1_txid_only_to_binary' panicked at src/transaction/beef_tx.rs:478:13:
BeefTx has no transaction data to write
```

(and the same line for `BeefTx::to_writer` under V1 and for `merge_beef` then `to_hex`), and
without a word: `version word written: 0300beef`; `62 digits: 0200beef000102abab..ab` (31
bytes); `non-hex: 0200beef000102` and `empty: 0200beef000102` (no txid bytes); `raw trailing
kept: 1 entries, 0200beef00010100...0000` (the extra byte written); `raw truncated kept: 1
entries`; `merge_beef of a two-leaves-at-one-offset BUMP: 1 bumps merged`; `merge_beef of a
bad version word: 2 entries merged`. The scan's units (`src/transaction/raw_frame_817_tests.rs`)
are new code (no module on the base).

## The recording

`tests/support/beef_v1_txid_only_writer_817.mjs` (the lane `fix-v1-txid-panic`'s recorder,
additions only), the reference bundle built at the pin (`git archive edf6e03 packages/sdk`,
`bun build mod.ts --target node --format esm`), run twice under Node v22.18.0, byte-identical.
The four original cases unchanged (each `a valid serialized Transaction is expected`; this
crate's words equal, the V2 bytes the remedy's and the reference's own). Added: 19 writer
cells (16 built here: 5 refused in the reference's words, 3 written to its bytes, 8 refused as
stated rows: 6 written unreadably there, 2 the empty txid's `Internal`; 3 raw states the door refuses here, the reference writing them unreadably), 14
raw-door cells (5 refused there in words this crate equals, 9 taken there: 7 refused here,
stated), 3 txid-door cells, 12 merge-door cells (6 in the reference's words, 2 in this crate's
reader's, 1 stated in ours, 1 a duplicate with a hash merged there and refused here, 1 a
source this crate's door cannot build, 1 valid), 2 bump-door cells (1 stated).

## The sweep

`support/beef_seeds_817.rs`: the hex BEEFs of every JSON file under `tests/fixtures`,
`tests/vectors` and `tests/transaction/vectors` and the `beef_of_any_size` binaries,
deduplicated: 321 that `Beef::from_binary` reads, 113 of them V1, each written `Ok`, read back
to the same entries, BUMPs and version, and a fixed point.

## The fuzz run

`cargo +nightly fuzz build` (all targets, target dir outside the checkout), then
`fuzz_beef_parser` 60 s on a copy of its corpus: 211,209 runs in 61 s, cov 6,238, ft 19,652,
corpus 958 inputs, no failure; the checked-in corpus unchanged.

## The dependents (survey only)

Each grepped by its own path; counts by call text, "tests" the files under a `tests` path
(inline `#[cfg(test)]` modules counted as production).

| Dependent | `merge_raw_tx` | `merge_beef` | BEEF `to_binary`/`to_hex` (by receiver name) | `to_writer` | `BeefTx::from_raw_tx` |
|---|---:|---:|---:|---:|---:|
| `bsv-wallet-toolbox-rs@a3377ef0` `src` | 52 (8 tests) | 2 (1) | about 22 (4) | 0 | 0 |
| `bsv-wallet-cli@f4285bf` `src` | 0 | 0 | 0 | 0 | 0 |
| `bsv-overlay-cloudflare@2efad2f0` `crates` | 56 (13) | 5 (0) | about 63 (14) | 3 | 0 |
| `rust-message-box@08418ec` `src` | 0 | 0 | 0 | 0 | 0 |

`to_binary_atomic` keeps its signature (toolbox 6, cli 5, overlay 26, message-box 1).

Added for #906 on 2026-11-14: the CLI's row is its `src` at `f4285bf` alone. That ref holds 3
`merge_raw_tx` lines under `tests/` (`tests/compact_tracker_off.rs`), and its beta line at
`6dc14ef5`, by a compile, 31 `merge_raw_tx` statements in 16 files (8 in the library and the
binary), 1 `merge_beef` statement, `Beef::to_binary` at 23 sites and `Beef::to_hex` at 2. The
counts by dependent, and how the compile ran, are in the CHANGELOG entry's Migration block.

The overlay engine's three accumulators, traced:

- `crates/overlay-engine/src/engine.rs:4014-4042` (`hydrate_utxo_history`): the stored BEEF
  (V1 if it was submitted V1) parsed into `acc`, each hydrated child parsed and
  `acc.merge_beef(&child)`, then `acc.to_binary()`. After this change `merge_beef` of a parsed
  child is `Ok` (a BEEF `from_binary` returned always writes and reads back); where `acc` is
  V1 and a child holds a txid-only entry the write panicked and now returns
  `Err(BeefError("a valid serialized Transaction is expected"))`, inside a closure that
  returns `Result` (`EngineError` mapping theirs).
- `crates/overlay-engine/src/gasp_overlay.rs:1350-1366` (`validate_graph_anchor`): the root
  BEEF merged with each stored BEEF, then `merged.to_binary()`: the same, inside a function
  returning `Result<(), GASPError>`.
- `crates/overlay-cloudflare/src/routes.rs:3017-3028` (the lookup answer): the outputs' BEEFs
  merged into the leading one, then `beef.to_binary()` appended: the same, inside a function
  returning `Result<_, String>`.

`docs/DEPENDENTS.md` lists consumers and re-pins, not migrations; the table stays here.

## Rows and sentences answered

The #764 row's residues: "a V1 source holding a txid-only entry ... is merged here where the
reference's `toBinary` throws ..." deleted; "A source BUMP built through the public fields with
two leaves at one offset, an empty level 0, more than 54 levels or two roots is merged here ...
and a duplicate leaf's `txid` flag and `hash` are kept here ..." replaced by the 55 to 64 levels
alone (the #603 row) and a pointer to the #817 rows. `src/transaction/CLAUDE.md`'s "`Beef`'s
writers stay infallible until the second lane of #817 ..." replaced. PR #831's changelog
sentence on the lenient writer stands as history.

## Named for the captain (the rule did not decide)

1. The version word against this crate's own refusals: the rule puts the reference's throws in
   its order; the version word is the reference's reader's, met after its writer's throws, so it
   sits between those and this crate's own refusals (the merge cell
   `source_version_word_and_bump_no_levels` agrees with that order).
2. The empty txid-only txid: the reference's `Internal` is met before the sort and the BUMPs; it
   is refused there in this crate's length words (a stated row), not in `Internal`.
3. The writers' raw-framing scan is kept although no public door can hold an unframed raw entry
   since `from_raw_tx` scans: it guards a crate-private constructor's future use and is pinned by
   a unit test through `from_framed_raw_tx`. It costs one linear scan per raw entry held without
   its parse (those merged with a BUMP index) per write.
4. One draft (row 63 since the fold; 62 before) carries the three "written unreadably" cells, a section each, as row 58
   carries #831's five; the brief's "a draft for each cell" read as the queue's precedent.

## The gate

`CARGO_BUILD_JOBS=4`, one cargo at a time, the lane's own target dirs under `~/bsv/targets/`
(`bsv-rs-fix-817-beef-writers`, `-red`, `-fuzz`, `-ratchet`), `SDKROOT` at MacOSX26.5 (the
host's link workaround). On the final tree (after the writers moved into `beef_writable.rs`
and `beef_tx_writer.rs` for the ratchet's line ceilings):

| Step | Result |
|---|---|
| `cargo fmt --check` | clean |
| `cargo clippy --all-targets --all-features -- -D warnings` | clean |
| `RUSTDOCFLAGS="-D warnings" cargo doc --no-deps --all-features` | clean |
| `cargo test --doc --all-features` | 296 passed, 128 ignored |
| the lane's files three times (the third `--test-threads=1`): `beef_v1_txid_only_writer_817` 8, `beef_writer_refusals_817` 11, `--lib beef_raw_frame` 4 | 69 passed |
| `--lib transaction`, `beef`, `kvstore`, `overlay`, `identity`, `wallet` (one filter per run) | 238, 97, 76, 102, 108, 198 passed |
| every `tests/beef_*.rs` (27), `merkle_*` (7), `transaction_*` (6) and every other file a changed signature or support file touched: 121 binaries in two pieces | 1,332 passed, 4 ignored |
| `conformance_beef`, `conformance_scripts` with `BSV_CONFORMANCE_DIR=~/bsv/ts-stack/conformance` (the checkout at `4d0ea63`) | 7 passed; the census 5,116 total, 4,121 run, 4,110 passed, 958 unsupported, 37 skipped, 11 known, 0 failures, 0 panics |
| `--test 'arch_*' --test fixtures_replay` | 20 binaries, 98 passed (the fixtures guard's hash of `examples/beef_spv.rs` moved with the example) |
| `cargo build --examples --all-features`, `cargo run --example beef_spv`, `cargo test --test readme_examples` | built; `beef 362 bytes, subject 4ea97bf3...`, `verified true`; 1 passed |
| `cargo build --benches --all-features` | built |
| `cargo +nightly fuzz build` (all targets) and `fuzz_beef_parser` 60 s | built; 211,903 runs, no failure |
| `cargo build --target wasm32-unknown-unknown --no-default-features --features "auth,wallet,transaction,overlay,socketio,wasm"` | built |
| `tools/ratchet/run --check --against 9ab384c9` | all 7 counters, oversized-file limits and mutation floors pass (`beef.rs` 3,062 under 3,074; `beef_tx.rs` 785 under 800) |
| `python3 -B .github/scripts/mutants_entries.py` | PASS, 28 entries (the `dependency_order` entry re-pointed from `beef.rs:1163:29` to `:1159:29`, the writers' move) |
| `python3 -B .github/scripts/rows_from_sources.py --check` | 0 refusals |
| `gitleaks git --redact --no-banner --exit-code 1 --log-opts="9ab384c9..HEAD" .` | run after the commit (the REPORT) |

Summed `test result:` lines: 2,622 passed, 0 failed, 132 ignored.

## The rebase (lane `fix-817-beef-writers-rebase`, 2026-11-10)

Started from `ec50792b` (on `9ab384c9`, PR #832's withdrawn head) after `git fetch origin`;
no reset was needed. Carried onto `origin/lane/fix-817-door-sync` at `192b2c10` (PR #832
rebuilt on the ensemble's design: `Beef::edit_tx`, `Beef::reindex`, `tx_mut` deprecated).
`grep -rn 'EDIT_EPOCH\|synced_at\|synced_view\|BumpSync\|refresh_edited' src/` prints
nothing.

The conflicts, by hand:

- `src/transaction/beef_bump_sync.rs` (deleted by the rebuild, edited here): deleted;
  `merge_bump`'s `combine_verified` and its handled result re-applied to `merge_bump` in
  `beef.rs`, with no `note_combined`.
- `src/transaction/beef.rs`: `merge_raw_tx` and `merge_beef` keep this change's signatures
  and refusals with the rebuild's `refresh_mutated` and no `refresh_edited` or
  `sync_bumps`; the old writers removed (they live in `beef_writable.rs`); `to_binary` there
  loses its `sync_bumps`. With the rebuild's `merge_bump` back in `beef.rs` the file was
  3,106 lines, over the ratchet's 3,074: `merge_raw_tx` and `merge_beef` (this change's
  doors) moved into `beef_writable.rs`; `beef.rs` is 3,040.
- `src/transaction/beef/index.rs`: the rebuild's whole; its `edit_tx` doc example takes
  `merge_raw_tx(..)?`.
- `tests/beef_door_sync_817.rs`: the rebuild's whole (the withdrawn tests this change had
  touched are gone with it), its door calls taking the `Result`; so do
  `tests/beef_edit_door_817.rs` and `tests/beef_tx_mut.rs` (new or changed on the base). No
  test of this change calls the deprecated `tx_mut`.
- `CHANGELOG.md`: both entries whole under one `## [Unreleased]`, this one above.
- `CLAUDE.md`: the rebuild's rows kept; the #764 row is the rebuild's with this change's
  edit applied (its BEEF-writer residues removed, the #817 pointer kept); the rebuild's
  removal of the lazy-repair sentences kept.
- `src/transaction/CLAUDE.md`, `tests/CLAUDE.md`: both sides' rows; the `beef_bump_sync.rs`
  row and the "Door synchronization" note dropped; `BeefTx`'s line carries both.
- `docs/lanes/375-filings/QUEUE.md`: the rebuild's row 61 kept; this draft is row 62 (the
  three root rows, the changelog note and this record renumbered).
- `.cargo/mutants.toml`: the `dependency_order` entry at `beef.rs:1136:29`, read from the
  file; `mutants_entries.py` passes.

`Beef::edit_tx` re-serializes an edited raw entry with `Transaction::to_binary` and holds
it with its parse (`BeefTx::from_parts`, no scan); a transaction's serialization is one
frame, so no writer refusal can meet the entry it repairs, and it refuses a txid-only entry
before the edit. It returns `Result` already; nothing changed there.

### The doubled-txid cell

The recorder gained `doubled_txid` (additions only; Node v22.18.0, two runs byte-identical):
seven states holding one txid twice, each read from bytes written by hand and pushed into
`txs` by hand. The reference writes all fourteen and both its readers read two entries
back; its `mergeBeef` holds one, the raw one. This crate's reader keeps both, its writer
writes the reference's bytes on twelve and on the other two (read from bytes, sorted here
where the reference returns the bytes read, the #621 writer residue) the bytes the reference
writes for the same entries pushed; every one reads back as held; `merge_beef` holds the
reference's one entry. By the rule the writer writes them; nothing is stated. The sweep's
pinned counts move with the vector: 334 BEEFs (115 V1), 2,004 differential states.

### `merge_beef`'s cost

A scratch test (never committed): 2,000 sources of ten chained raw entries merged one after
another into one accumulator, and one source of 20,000 raw entries merged into an empty
target; three runs each (`cost.log` in the lane's out folder):

| Tree | release, 2,000 x 10 | release, 1 x 20,000 | debug, 2,000 x 10 | debug, 1 x 20,000 |
|---|---|---|---|---|
| beta `cfbe3c98` | 23.2 to 23.6 ms | 11.2 to 11.4 ms | 218 to 255 ms | 113 to 117 ms |
| rebuilt head `192b2c10` | 23.9 to 24.1 ms | 11.8 to 12.4 ms | 178 to 181 ms | 100 to 101 ms |
| this tip | 44.0 to 45.1 ms | 31.5 to 31.8 ms | 412 to 415 ms | 335 to 335 ms |

The round trip is linear, about 1.9 times beta on the accumulator and 2.8 times on the one
large source in release (1.8 and 2.9 in debug). A pre-pass with the same verdict would save
the source's serialization, its parse and the hash `from_binary` runs on every raw entry
(the difference above); it would have to prove the verdict equal to the round trip on every
state, which the differential (2,004 states) and `fuzz_beef_parser`'s merge invariant pin
today. Not built here.

## The fold (lane `fix-817-beef-writers-fold`, 2026-11-10)

The three reads of PR #836 at `23f8f2df`: the cold read MERGE (0.9), the rule read FIX (0.8,
one line), the strength read ACCEPT (0.85, three surviving mutations).

The rebase: `git rebase --onto origin/lane/fix-817-door-sync 192b2c10`, onto #832's folded
head `65369528`. `CHANGELOG.md` merged by itself (this entry above #832's, one
`## [Unreleased]`, #832's entry byte for byte); `CLAUDE.md`: the `merge_transaction` (#764)
row this change's, the edit-door and hand-edit rows #832's; `src/transaction/CLAUDE.md` and
`tests/CLAUDE.md`: #832's rows kept, this change's added; `QUEUE.md`: #832 holds 60, 61 and
62, this draft is row 63 (the three root rows, the changelog and this record renumbered);
`.cargo/mutants.toml`: the `dependency_order` entry at `beef.rs:1132:29`
(`mutants_entries.py` 28 entries pass). The door calls #832's fold added: its
`index_817_tests.rs` units and `tests/beef_edit_door_817.rs` take the fallible doors;
`tests/beef_door_sync_817.rs`' `wire` step `to_writer(..).expect`. Two of #832's pins built
states the public doors now refuse (`merge_raw_tx(vec![0xde, 0xad])`, a byte after the lock
time): moved into the unit module, built by `BeefTx::from_framed_raw_tx`, their "no byte
moves" read on each entry's txid and raw bytes (the writers refuse such an entry), and the
public refusal pinned in their place
(`the_unframed_raw_states_are_refused_at_the_public_doors_817`): `beef_edit_door_817` 25 to
24 tests, the unit module 6 to 8. #832's three recorded cases move the sweep to 337 BEEFs
(115 V1) and the differential to 2,022 states.

The readers' commits, each taken after the rebase (their lines conflicted with #832's
neighbours, so each was applied by its own diff and committed with its own message):
`f7bfe35f` (cold), `37e89bf9` (rule), `de0ea340` (strength). The cold and rule commits
corrected the same `merge_beef` row for the same cell (a source BUMP leaf flagged duplicate
and txid): the rule read's later wording kept (it names that cell beside the 63-digit
txid and states `merge_bump`'s held uncomputable BUMP, true of the code: `merge_bump`'s
`same` needs the held root to compute and equal the new one), the cold read's clause dropped
with it; the strength read's sentence follows in the same row.

FIX (rule read): `to_binary` refuses an empty txid-only txid before its sort
(`refuse_empty_txid`, `src/transaction/beef_writable.rs`), as `#getSerializedBytes` throws
`Internal` from `#ensureSerializableState` before `#ensureSortedForSerialization`
(`Beef.ts:367-368`); every other refusal after it. The recorder gained `sort_on_refusal`
(additions only; Node v22.18.0, two runs byte-identical, every earlier key unchanged): four
cells, a child merged raw ahead of its parent, then an empty txid, a non-hex txid, a V1
txid-only entry, a version word; the reference's entries unchanged after the empty txid's throw,
sorted after the other two and after writing the fourth. RED on a scratch `git archive
23f8f2df` (its own target), the test and vector overlaid:

```
assertion `left == right` failed: empty_txid: after
  left: ["735889..2a6b", "195b86..a414", ""]
 right: ["195b86..a414", "735889..2a6b", ""]
```

The CHANGELOG sentence "on `Err` the sort has happened, as there" replaced by which refusal
comes before the sort and which after.

The survivors (strength read), each RED under its planted mutation on a scratch copy of the
tip: `merge_bump` with `root.is_some() &&` dropped (`left: 0, right: 1`, "the second
rootless BUMP appended"); `beef_raw_frame.rs:70` `>=` (`[ff, ff, ff, ff, ff, ff, ff, 1f,
00]`: `number too large ...` for `ReaderUint8Array read exceeds available data`);
`beef_raw_frame.rs:67` `<=` (`[fd, fd, 00]`: `non-canonical varInt` for the read's words).
The reference's words on the four boundary counts by a probe of its scan (Node v22.18.0,
not committed): all four `ReaderUint8Array read exceeds available data`, 2^53 `number too
large`.

The panic on the base: `src/transaction/beef_tx.rs:478:13` at `9ab384c9`, `:453:13` at
`192b2c10` (the cold read's RED).

The gate (`CARGO_BUILD_JOBS=4`, one cargo at a time): fmt; clippy `-D warnings` (no
deprecation warning); doc; doc tests 297; the five #817 files three times (13, 8, 24, 45, 32;
the third single-threaded); lib `transaction` 245, `beef` 104, `kvstore` 76, `overlay` 102,
`identity` 108, `wallet` 204, `raw_frame` 4, `index_817` 8; 62 files (every `beef_*`,
`merkle_*`, `transaction_*`, every test file the change touches, `fixtures_replay`) 774
passed; conformance with the corpus 5,116 total, 4,121 run, 4,110 passed, 958 unsupported,
0 failures; `arch_*` 19 files, 97 passed; examples; `readme_examples`; benches built; fuzz
targets built, `fuzz_beef_parser` 175,117 runs in 61 s; the wasm32 slice; the ratchet
against `987c0e48`; `mutants_entries.py`; `rows_from_sources.py --check` 0 refusals;
gitleaks. Logs: `/Volumes/Lanes/out/bsv-rs/fix-817-beef-writers-fold/`.

Rows the reads filed outside the subject: the strength read's "pin the three surviving
mutations" (`after-cut`), answered here; the cost of `merge_beef`'s round trip and
`refresh_mutated`'s scan of the target, the figures already above, left to the lane after.
