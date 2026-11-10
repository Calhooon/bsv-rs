# fix-817-door-sync: the merge doors and the lookups synchronize an edited entry, and a combined BUMP's txids take its index

Bucket #817, three rows from the rule read of PR #823's fourth fold. Opened
from `origin/lane/fix-621` at `d63aaafb` (PR #823's head; `git fetch origin
&& git rev-parse HEAD` named `d63aaafbd40d73e9d6ea6bd10ffd4faebb61ce32`).
Reference `ts-stack@edf6e03` `packages/sdk/src/transaction/Beef.ts` (below
`Beef.ts`), Go `go-sdk@2ca481c` `transaction/beef.go`.

> **Read this first.** The sections from here to "The design changed" are the record of PR #832's lazy repair, withdrawn by the ensemble of 2026-11-10: the "After" column, `beef_bump_sync.rs`, `BumpSync`, the edit epoch, the stamp and the per-door refreshes describe code that is not on the tip. The tip's design, its tests and its costs are in "The design changed", at the end.

## The doors, side by side

"Tx sync" is `synchronizeNestedTransactionMutations` (`Beef.ts:342-352`: every
entry's `syncRawTxFromTransaction`, then the index rebuilt if one changed).
"BUMP sync" is `#synchronizeNestedBumpMutations` (`:296-309`: the snapshot
taken if none, else the BUMP txid map dropped if the BUMPs moved since it).
Go keeps `Transactions` keyed by the txid at merge, never re-keyed, and a
transaction's BUMP as a pointer; it has no sync of either kind.

| Door (this crate) | Reference twin, its sync | This crate before | After | Cell that differed (scenario) | Go at `2ca481c` |
| --- | --- | --- | --- | --- | --- |
| `merge_bump` | `mergeBump` `:687-692`: tx sync `:688`, BUMP sync `:689`, then `#mergeBumpEntry` | neither | both at its top, then `merge_bump_entry` | edit U to V, `merge_bump(V's BUMP)`, `find_txid(V)`: `None` (the lookup's window) | `MergeBump` `:747-789`: combines or appends, gives the BUMP pointer to unproven transactions it proves |
| `merge_raw_tx` | `mergeRawTx` `:835-840`: tx sync `:836` | none | tx sync at its top | edit U to V, `merge_raw_tx(V)`: a second V appended, `to_binary` wrote V twice | `MergeRawTx` `:820-850`: removes the key, stores under the new txid (the edited entry stays under U) |
| `merge_transaction` | `mergeTransaction` `:875-880`: tx sync `:876`; no BUMP sync, `#mergeBumpEntry` per path | none (its paths through `merge_bump`, no sync then) | tx sync at its top; paths through `merge_bump_entry` | edit U to V, `merge_transaction(V)`: a second V | `MergeTransaction` `:870-918`: by map key |
| `merge_txid_only` | `mergeTxidOnly` `:919-929` through `findTxid`: tx sync `:498` | none | tx sync at its top | edit U to V, `merge_txid_only(V)`: a txid-only V beside the raw V | `MergeTxidOnly` `:952-965`: by map key |
| `make_txid_only` | `makeTxidOnly` `:552-565`: none | none | none (as there) | edit U to V, `make_txid_only(U)`: the reference replaces V with U alone; here `None`, V kept (stated) | `MakeTxidOnly` `:801-818`: by map key, finds the edited entry under U and replaces it, as the reference |
| `merge_beef` | `mergeBeef` `:971-990`: tx sync `:976`, BUMP sync `:977` | tx sync (#621's fourth fold) | both | the combine's index (finding 2) | `MergeBeef` `:1010-1028`: per BUMP `MergeBump`, per entry by map key |
| `find_txid` (`&self`) | `findTxid` `:497-500`: tx sync `:498` | the index as it stood | the index the refresh would rebuild (`synced_view`, only while an edited entry waits) | edit U to V, `find_txid(V)`: `None` | `findTxid` `:791-799`: map lookup |
| `find_txid_mut` | (no twin; `findTxid`'s mut form) | none | tx sync at its top | as `find_txid` | none |
| `find_transaction_for_signing` (`&self`) | `findTransactionForSigning` `:615-631`: through `findTxid` `:616` | none | the synced view, root and inputs | edit U to V, `(V)`: `None` | `FindTransactionForSigningByHash` `:655-671`: map lookups |
| `find_atomic_transaction` (`&self`) | `findAtomicTransaction` `:639-646`: through `findTxid` `:640`, then `findBump` per transaction (BUMP sync `:571`) | none; its own last-BUMP index | the synced view; BUMP sync once, the map's index | edit U to V, `(V)`: `None` | `FindAtomicTransactionByHash` `:681-737`: map lookups, `FindBumpByHash` |
| `find_bump` (`&self`) | `findBump` `:570-574`: BUMP sync `:571`, then the map | the last BUMP holding it | BUMP sync, the map's index | a combine before any BUMP sync: the reference answers the combined BUMP | `FindBumpByHash` `:620-630`: the EARLIEST BUMP proving it |
| `sort_txs` | `sortTxs` `:1352-1406`: both `:1359-1360` | tx sync | both | the combine's precedence dropped here | none |
| `verify_structure`, `verify_valid`, `is_valid` | `verifyValid` `:1054-1089`: BUMP sync `:1058`, tx sync through `isAtomic`/`sortTxs` | tx sync | both | as `sort_txs` | `IsValid`/`verifyValid` `:1030-1310`: no sync |
| `to_binary`, `to_hex` | `toBinary`/`toHex` through `#getSerializedBytes` `:360-373`: both `:361-362` | tx sync | both | as `sort_txs` | `Bytes` `:1532-1624`: no sync |
| `to_binary_atomic` | `toBinaryAtomic` through `#getAtomicSerializedBytes` `:392-418`: both `:393-394` | tx sync | both | as `sort_txs` | `AtomicBytes` `:1700`: no sync |
| `trim_known_proven` | (no twin; `trimKnownTxids` `:1628-1635` differs, its `#reindexBumps` drops the map `:1682`) | tx sync | tx sync; the precedence dropped when BUMPs are renumbered | none recorded | `TrimknownTxIDs` `:1427-1444` |
| `to_log_string` | `toLogString` `:1698-1733` through `isValid` | through `is_valid` | through `is_valid` | none | `ToLogString` |
| `is_atomic` (`&self`) | (no twin: `isAtomic(txid)` `:482-491` judges the graph; this crate's reports `atomic_txid`) | none | none | none | none |
| `clone_shallow` | `clone()` `:1605-1625`: drops the maps `:1613` and takes the BUMP snapshot again when its byte cache stands `:1619-1620` (`#captureSerializationState`, `:207`) | copied the index | the BUMP record reset; since the fold the snapshot taken when the source was read from bytes and untouched (`BumpSync::for_clone`), a source serialized since stated | three clone cases (fold) | `Clone` `:1366-1425` |
| readers (`from_binary`, `from_hex`, `from_reader`) | `fromReader` `:1240-1272`: snapshot `:1268-1270` | none | the snapshot taken (`bumps_read`) | a combine after a read dropped at the next BUMP sync | `NewBeefFromBytes` |
| `to_writer`, `find_txid`'s `index_of` inside a door, `merge_bump_entry` | `toWriter` `:1169-1182`, `#findTxidIndexed`, `#mergeBumpEntry`: none | none | none | none | none |

## The combined index (finding 2): the order of sets

The reference's map (`#bumpIndexByTxid`) at the pin:

1. Built lazily by `#ensureBumpTxidIndex` (`:576-586`): for each BUMP `i` in
   order, `set(hash, i)` for every level-0 leaf with a hash (the last BUMP
   holding a hash wins).
2. `#findOrInsertBump` (`:791-811`) builds it first (`:793`), then on a
   combine into `existing` sets every level-0 hash of the combined BUMP to
   `existing` (`indexBumpTxids`, `:60-64`, at `:800`), or on a push sets the
   new BUMP's hashes to its index (`:808`).
3. `#tryToValidateBumpIndex` (`:1329-1340`) reads it (`get(txid)`), sets the
   entry's index and flags the first leaf with that hash.
4. Dropped (`#invalidateBumpIndexes`, `:601-604`) by
   `#synchronizeNestedBumpMutations` where the BUMPs moved since its snapshot
   (`:302-307`; a combine always, `MerklePath.combine` building new level
   arrays, `MerklePath.ts:508-537`; a push by the length; a flag flipped by
   value), by `#reindexBumps` (`:1682`) and by `clone()` (`:1613`). The
   snapshot is taken by the reader (`:1268-1270`), by `#getSerializedBytes`
   after writing (`:371`), by `clone()` when its byte cache stands
   (`:1619-1620`) and by the BUMP sync itself, never by a merge.

Ported (`src/transaction/beef_bump_sync.rs`): the live scan answers step 1
(the last BUMP holding the hash, read from `bumps` each time, as before);
`note_combined` records step 2's combine sets as a precedence;
`note_pushed` removes a pushed BUMP's hashes from it (step 2's push set equals
the live scan's answer); `bump_index_for` answers the precedence where it
stands and the BUMP still holds the hash, else the live scan (step 3);
`sync_bumps` drops the precedence as step 4 drops the map (the crate's own
pushes, combines and flipped flags marked `changed`; a caller's edit through
`bumps` caught by a snapshot kept only while a precedence stands); the reader
marks the snapshot taken (`bumps_read`); `clone_shallow` resets it, taking
it again when the source was read from bytes and untouched (the fold);
`trim_known_proven` drops it when it renumbers.

The #757 and #765 sentences: the #757 row of `src/transaction/CLAUDE.md`
("takes the LAST one's index, as the reference's `#tryToValidateBumpIndex`
reads its index") now reads "takes the index last set (the LAST one's where
no combine came between, #817)"; the #732 row ("answer the LAST BUMP holding a
txid at level 0, as the reference's `Map.set` index does") now names the
combine's exception; `tests/beef_bump_index_757.rs`' module and test doc
comments name it too. `tests/beef_sibling_leaf_765.rs` says nothing of the
last BUMP; its pins (any level-0 leaf, flagged) are unchanged and green. The
root `CLAUDE.md` #757/#766 row's "the last BUMP holding the txid" is
historical (what #766 closed) and stays true.

## `make_txid_only` (finding 3)

The reference's `makeTxidOnly(A)` after `findTxid(A).tx` is edited to A'
reads its stale position index and replaces the A' entry with a txid-only A
(recorded: `an_edit_then_make_txid_only_of_the_old_txid`). Reachable through
public doors here (`find_txid_mut`, `tx_mut`, `make_txid_only`), but porting it
loses the caller's edited transaction and writes a txid the BEEF no longer
holds: stated, not followed. This crate answers `None` and keeps A'; both
answer `None` for A'.

## The recording

`tests/support/beef_door_sync_817.mjs` over the bundle built from `git archive
edf6e03 packages/sdk` with `bun build`, Node v22.23.3; two runs
byte-identical (`cmp`). 17 cases (the test file's 18 tests: one per case and
the count pin).

## RED

A scratch copy of `d63aaafb` (`git archive`, `$TMPDIR/scratch817`, its own
target dir `$TMPDIR/target-scratch817`) with only the test file and vector
overlaid: 11 of 18 RED, 7 green (the mirror, the two forgotten-at-sync cells,
the after-read cell, both `make_txid_only` cells and the count). The failing
lines (`/Volumes/Lanes/out/bsv-rs/fix-817-door-sync/red_base.log`):

- signing lookups: `left: [{"answer": Null, "step": "sign:v"}, {"answer": Null, "step": "atomic:v"}]`, right `"v"` twice
- txid-only after a combine: `left: [{"bump_index": 1, "form": "txid", "name": "x"}]`, right `0`
- `merge_txid_only`, `merge_transaction`, `merge_raw_tx` after an edit: `left: "0200beef0002..."` (two entries), right `"0200beef0001..."`
- `merge_bump` after an edit: `left: [{"answer": Null, "step": "find:v"}]`, right `"v"`
- the reader's combine and the combine surviving `merge_raw_tx`: the entry's index byte `01` for `00`
- `find_txid` after an edit: `find:v` `Null` for `"v"`
- before any BUMP sync (both cells): `findbump:x` `1` for `0`

One older pin moved: `tests/beef_tx_mut.rs`
`an_input_repointed_outside_the_beef_through_tx_mut_is_missing` asserted
`find_txid(new txid).is_none()` (the #171 window); it now asserts the
reference's answer.

## Beside the findings (not built)

- The #171 CHANGELOG note's "a scan of every entry per lookup would make a
  loop of lookups quadratic" held in full at `e740be7c`, where this paragraph
  said "in part" (one flag read per entry per call is a scan): the cold read
  measured `find_txid` per entry 7.4 ms on the base and 1,070 ms on the tip
  at 20,000 entries, and `tests/beef_deep_chain.rs` 8.2 s and 99 s. The fold
  gates the scan behind a constant-time stamp (below).
- `merge_bump` ignores a `combine` error and still returns the BUMP's index;
  the reference throws (`MerklePath.ts:509-516`). Older than #817.
- `tests/CLAUDE.md`'s **Total** line is dated `1eff2d0` (2026-10-05) and far
  out of date; not re-measured here.

## The fold (the three reads of 2026-11-09)

The reads: the cold read FIX (the cost, measured: every door a scan, BEEF
building and lookup quadratic); the rule read FIX (FIX-1 `clone_shallow`
keeps no snapshot where `Beef.ts:1619-1620` takes one; FIX-2 the `&self`
lookups' stale `input_txids`, `BeefTx.ts:160-166`; the `makeTxidOnly` draft,
after-cut); the strength read FIX, tests only (S1 to S4, the S5 sync sites and
S6 unpinned). No reader commits existed (each REPORT said none).

Folded:

1. The cost. `BeefTx::tx_mut` bumps a process-wide edit count (one static
   `AtomicU64`, `beef_tx::edit_epoch`); each `Beef` holds a `Cell<(u64,
   usize)>` stamp, the count and its entry count when it last found nothing
   waiting. `refresh_edited` (the per-entry doors: `merge_bump`,
   `merge_raw_tx`, `merge_transaction`, `merge_txid_only`, `merge_beef`,
   `find_txid_mut`) and `synced_view` (the `&self` lookups) skip their scan
   while the stamp stands; `push_tx` moves it with a door's own fresh entry;
   the whole-BEEF readers scan as on the base. The captain's two candidates
   weighed: a counter shared between a BEEF and its entries misses an entry
   pushed into `txs` by hand or moved between BEEFs (its counter is another
   BEEF's or none); the epoch sees every edit made while the entry is inside
   any BEEF, costs one scan per BEEF per edit anywhere, and keeps no state in
   the entry. The entry count in the stamp catches a hand push or removal;
   an entry edited outside after the stamp and put in another's place by hand
   (the count unmoved) may wait for the next edit or whole-BEEF reader, stated.
   Requirements: (a) `an_edit_through_txs_after_a_lookup_is_found_by_its_new_txid_817`;
   (b) `beef_and_beef_tx_are_send_and_not_sync_as_on_the_base_817` (Send, not
   Sync, as the same assertion passes on a scratch of `2356b581`; with `Send`
   in the assertion's place of `Sync` it fails to compile, so it tests what it
   names); (c) the wasm32 slice builds; (d)
   `a_clone_edited_leaves_the_original_and_the_originals_edit_is_seen_817` and
   the unit test `a_door_after_an_edit_scans_once_and_the_stamp_stands_again_817`;
   (e) the probe and `beef_deep_chain` below.
2. FIX-1 ported: `BumpSync::for_clone(self.wire_order)` in `clone_shallow`;
   the read clone recorded (1 there, 0 on `e740be7c`), the never-serialized
   clone recorded (0 on both), the serialized clone recorded and stated (the
   reference's byte cache, none here).
3. FIX-2 stated: a `&self` door cannot refresh the entry's public
   `input_txids`; recorded and pinned as `_stated_817`; the `tx_mut` doc's
   false sentence ("a lookup by the new txid misses") corrected.
4. The strength read's cases, recorded (16 cases added, 17 to 33, two runs
   byte-identical under Node v22.23.3, the 17 earlier cases and the earlier
   `txs`/`bumps` keys unchanged).
5. The draft `375-filings/beef-make-txid-only-stale-index-ts-stack.md`,
   queue row 60; nothing filed.

The cost, measured on scratch copies (`git archive`, own target dirs), three
runs each, 20,000 entries (2,000 the same shape):

| | base `2356b581` | tip `e740be7c` | fold |
|---|---|---|---|
| `find_txid` per entry, debug | 6.7 to 6.9 ms | 1,024 ms | 5.9 to 6.5 ms (7.3 to 9.3 on a loaded rerun) |
| `find_txid` per entry, release | 0.6 to 1.0 ms | 211 to 214 ms | 0.6 to 0.7 ms (two alternated reruns) |
| `merge_raw_tx` per entry, debug | 149 to 150 ms | 930 to 940 ms | 146 to 150 ms |
| `merge_raw_tx` per entry, release | 9.5 to 11.7 ms | 123 to 124 ms | 9.5 to 11.2 ms |
| `tests/beef_deep_chain.rs`, debug, parallel | 6.98 to 7.27 s (three alternated) | 99 s (the cold read's) | 7.07 to 7.36 s |
| the same, one thread | 46.95 s | | 45.25 s |

Two earlier parallel fold runs (9.5 s, 23.4 s, 14.5 s) were taken while the
host's load stood at 14 to 27, against a base run of 11.6 s in the same
window; the three alternated runs above are the comparison.

RED (logs in `/Volumes/Lanes/out/bsv-rs/fix-817-door-sync-fold/`): on a
scratch of `e740be7c` with the fold's tests overlaid, 35 of 36 green and
`a_combine_on_a_clone_of_a_read_beef_is_forgotten_at_find_bump_817` RED
(`left: [{"answer": 0, ...}]`, `right: [{"answer": 1, ...}]`;
`red_tip_e740be7c.log`). The cases both already share are pinned by planted
removals on a scratch of the fold (`plants.log`): S1 (`merge_bump`'s refresh)
RED `an_edit_then_merge_bump_then_make_txid_only_of_the_new_txid_817`; S2
(`find_txid_mut`'s) RED `an_edit_then_find_txid_mut_answers_the_edited_txid_817`
and the stated input-list test; S3 (`note_pushed`'s removal) RED
`a_push_after_an_unsynced_combine_takes_the_pushed_index_817`; S4
(`bump_index_map`'s precedence) RED `an_unsynced_combine_is_the_atomic_paths_index_817`;
S5 each `sync_bumps` RED its case (`find_atomic_transaction`, `merge_beef`,
`to_hex`, `to_binary_atomic`; `verify_structure`'s survived the case that
sorts, its `sort_txs` syncing again, and is RED on the case refusing before
its sort, recorded for it); S6 (the `changed` term) RED
`a_combine_changing_no_leaf_is_forgotten_at_the_next_sync_817`; the epoch
bump in `tx_mut` removed, 11 tests and the unit test RED; the entry count
out of the stamp, `an_entry_edited_outside_and_pushed_by_hand_is_seen_817`
RED; the clone's snapshot reset, the read clone RED. (A "clean" run in that
log after the S6 plant was a stale binary, `mv` restoring an older mtime; the
rerun after `touch` is 37 of 37.)

Rows outside the subject, unchanged: `merge_bump` ignoring a `combine` error
(`beef_bump_sync.rs`, the second change of #817); the stale **Total** line of
`tests/CLAUDE.md`; the strength read's S5 witnesses row (folded here as cases).


## The design changed (the edit door's lane, 2026-11-10)

PR #832's lazy repair was stopped after two rounds of three reads found new
cells each time, two of them quadratic. The captain put the design to an
ensemble of five independent reads (parity, dependents, adversary, API, north
star); the owner's standard for the choice: soundness over speed, a north
star decision. The decision, built by lane `fix-817-edit-door` on this
branch's head:

- **The BUMP an entry names (five of five):** the last BUMP in `bumps` holding
  the txid at level 0, read live, a function of `bumps` alone: beta's rule
  (#732, #757, #765). The reference's txid map (the sections above) answers
  by which doors ran; its cells stay in the vector, untouched, and the seven
  where it differs are asserted as stated (`_stated_817`), with a draft for
  upstream (`375-filings/beef-bump-map-history-ts-stack.md`, row 61).
- **Entries edited in place (five of five against the lazy repair):**
  `Beef::edit_tx(txid, |tx| ..) -> Result<R>`, an eager door (a copy edited,
  the entry repaired and re-keyed at once); `Beef::reindex()` after a hand
  edit of `txs`; `#[deprecated]` on `BeefTx::tx_mut`, which keeps beta's #171
  window; the lookups plain index reads again.
- **The index notices a hand edit of `txs`** (the dependents read's finding:
  a hand `retain`, as the toolbox's `wallet.rs:1505`, made `find_txid` answer
  `None` and `merge_raw_tx` store a held entry twice on beta, with no edit):
  the entry count the index was built for and the hit check, a read-only
  scan for a `&self` lookup, a rebuild at the next `&mut` door (since the
  fold of the rebuild, below: the pushed tail indexed alone, a rebuild on a
  shrink or a mismatched hit). The stated window: a hand replacement keeping
  the count that makes a lookup miss (a reorder misses nothing); `reindex`
  is its door.

Removed: `EDIT_EPOCH` and `edit_epoch`, `synced_at`, `synced_view`,
`find_in`, `refresh_edited`, `no_edit_since_sync`, `note_synced_len`,
`waits_on_refresh`, the refresh calls at the top of the doors, and
`beef_bump_sync.rs` whole (`BumpSync`, the precedence, the snapshot,
`for_clone`, `sync_bumps`, `bumps_read`, `bump_index_for`, `bump_index_map`,
`note_combined`, `note_pushed`, `forget_bump_precedence`, `mark_in_bump`,
`merge_bump_entry`). `merge_bump`, `update_bump_indices` and
`try_to_validate_bump_index` are back in `beef.rs` as on beta: the ratchet's
ceiling for `beef.rs` is beta's 3,074 lines, and with `push_tx` moved into
`beef/index.rs` the file is 3,071. `Beef` and `BeefTx` are `Send` and not
`Sync` (Transaction's `RefCell` caches), as on beta, with no `RefCell` or
`Cell` of this change; pinned at compile time.

The recorded vector grew by seven cases, additions only (the 33 above
byte-identical): an edit then `toHex` and `mergeBeef`, an edit onto a held
txid, and the four hand edits of `txs` (`drop:`, `push:`, `swap:`,
`replace:`). Of the 40, 25 are asserted as recorded and 15 as stated (24 and 16 until the cold read of the rebuild counted them). Two of
PR #832's stated cells are agreements now: the edited entry's input list at
`find_txid` (the eager door reads it) and the clone of a serialized BEEF (no
precedence to keep).

The costs (three runs each; release, then debug; `cost.log` in the lane's
out folder):

| Case | beta `cfbe3c98` | PR #832 `9ab384c9` | tip |
|---|---|---|---|
| one edit, then `find_txid` of each of 5,000 (release) | 0.2 ms | 1,391 to 1,644 ms | 0.2 to 3.1 ms |
| the same (debug) | 1.5 to 1.9 ms | 17,120 to 17,802 ms | 1.5 to 2.8 ms |
| `merge_raw_tx` of each of 20,000 chained entries (release) | 11.4 to 12.7 ms | 11.2 to 11.5 ms | 11.1 to 14.5 ms |
| `find_txid` of each of 20,000 (release) | 0.9 to 1.6 ms | 1.0 to 1.1 ms | 1.0 to 1.9 ms |
| `retain` of one of 5,000, then `find_txid` of each (found) | 0.1 to 0.2 ms (0) | 0.2 to 0.4 ms (0) | 0.2 ms (4,999) |
| `tests/beef_deep_chain.rs` alone, debug, alternated | 7.30 to 7.43 s | | 7.59 to 7.69 s |

## The fold of the rebuild (the three reads of 2026-11-09)

Three reads judged the rebuild at `192b2c10`: cold (`review-fix-817-door-sync-rebuild`),
rule (`review-rule-...`) and strength (`review-strength-...`), each FIX. The edit door
was judged sound by all three and stands; every finding was in the index's answer to a
hand edit of `txs`, in three unpinned lines and in the records. Lane
`fix-817-door-sync-fold3` folded them on `192b2c10`:

- The readers' docs commits cherry-picked in the order cold, rule, strength
  (`d9e7a33f`, the count 25 and 15; `a2bb6637`, queue row 62 and this record's
  banner; `5925c150`, a reorder misses nothing), the one conflict (the root row)
  resolved to the strength read's sentence with the rule read's row-62 link, then
  every sentence rewritten true of the code after the fold.
- The cost (the cold read's FIX, the rule read's FIX-2): `sync_index` indexes the
  pushed tail alone when the count grew and the indexed prefix still ends where it
  did (`indexed_prefix_holds`, one lookup), and rebuilds whole on a shrink or a moved
  prefix; `position` rebuilds whole on a hit naming another entry (a swap), so the
  doors after it read the index alone; `index_of` scans the unindexed tail alone on a
  miss after pushes. No interior mutability, no new field. The table (three runs each,
  release; the CHANGELOG has debug): a hand push then `merge_raw_tx`, 5,000 times,
  4.2 to 5.1 ms on beta, 1,796 to 2,401 ms on `192b2c10`, 5.3 to 5.6 ms here; a hand
  push then `find_txid_mut`, 1.5 ms (0 found) / 1,310 to 1,518 ms / 3.6 ms; a hand
  swap, one `&mut` door, then 5,000 lookups, 0.1 ms (0 right) / 21.6 to 34.9 ms /
  0.3 to 0.4 ms. Stated, with figures: hand pushes with only `&self` lookups (each
  miss scans the pushed tail: 1,079 to 1,159 ms against beta's 1.4 to 1.7 ms) and a
  hand `retain` before every door (each rebuilds whole: 593 to 602 ms against 249 to
  267 ms). Logs: `cost_release*.txt`, `cost_debug.txt` in
  `/Volumes/Lanes/out/bsv-rs/fix-817-door-sync-fold3/`.
- The unpinned lines: the cold read's scratch case committed
  (`a_hand_push_a_door_then_a_retain_back_to_the_count_finds_the_pushed_entry_817`);
  S1 and S2 as unit tests (`src/transaction/beef/index_817_tests.rs`); S3 as two
  recorded cases (a BEEF read children first, an entry edited keeping its txid,
  merged into an empty `Beef`: C, P as the reference; a write, then Y's input moved
  to U, U written first), the recorder's `wire:`, `noop:`, `edit:y_input_to_u`,
  `order:` and `after`, additions only, two runs byte-identical under Node v22.23.3;
  S4 (`a_no_op_edit_keeps_the_entrys_is_valid_817`).
- `edit_tx`'s edges: raw bytes that do not parse are `BeefError` (the parser's error
  until then); a no-op compares the edited copy's bytes with the original's before
  anything is rewritten, so raw bytes with a trailing byte keep their txid and bytes
  (re-keyed under the canonical txid, or refused when that was held, until then); the
  rustdoc says a closure's `Err` value still has its edit stored. Found by the fold's
  own run: computing the original's bytes fills the copy's cache, so the caches are
  cleared again before the closure (`beef_tx_mut`'s proven-entry test caught it).
- The records: 42 cases, 27 recorded and 15 stated, the counting test renamed
  `the_stated_cells_counted_are_fifteen_of_forty_two_817`; the hand push of a held
  txid stated (the earlier entry before a `&mut` door, the later after); the rule
  read's two cells inside the window pinned
  (`the_two_edit_tx_cells_inside_the_window_stated_817`; after a `tx_mut` edit the
  old txid's mismatched hit now rebuilds, so the new is found after it).

RED (logs in the fold's out folder): on a scratch of `192b2c10` with the tests
overlaid, 5 RED (`red_base_192b2c10.log`: the trailing-byte no-op, the unparsable
bytes, the grown count's tail, the swap's rebuild, and
`the_two_edit_tx_cells_inside_the_window_stated_817`, the old code rebuilding on no
mismatched hit: the cold read of `ba0dc50e` counted it, where this record said 4); on a scratch of the tip seven
planted mutations each RED (`red_plants_tip.log`: the doors' index update, the miss
guard, the no-change return, `mark_mutated`, the `is_valid` restore, the tail
indexed first-wins, the rebuild on a mismatched hit).

### The second fold of the rebuild (the three reads of `ba0dc50e`)

The reads: the cold read FIX (no test pinned `indexed_prefix_holds`: forced true,
every suite green, and a removal then two pushes then misses the pushed entry and
stores it twice; the RED count on `192b2c10` 5, not 4; the stated `retain` cost
without its debug figure), the rule read ACCEPT with its docs commit `f651338e`
(the window also holds when hand pushes follow a replacement), the strength read FIX
(F1: `edit_tx` dropped the old txid's key while another entry still held the txid,
reachable from `Beef::from_binary` of a txid-only T then raw T; F2 to F4: the
rebuild in `sync_index`'s else branch, the prefix check in `index_of` and the tail
scan's `.rev()` unpinned; its docs commit `48218eec`, a `truncate` or `retain` back
to the count). `lane/fix-817-door-sync-fold4` folded them on `ba0dc50e`:

- The readers' docs commits cherry-picked in the order rule, strength (the cold
  read made none), the one conflict (the module rustdoc's window) resolved to one
  sentence covering both readings, then the window written once, truly, in the
  rustdoc (module, `reindex`, `index_of`), the root row, the CHANGELOG, the
  module's `CLAUDE.md` and the test file's header: hand edits that leave a txid the
  index was never given below the entry count it was built for (a replacement
  inside the indexed prefix, whatever pushes follow it; a `truncate` then pushes
  back to the count; a push then a `retain` that moves a pushed entry into the
  prefix), the count back at the indexed one or past it with the prefix's last
  position in place. The strength read's R1 (a twin of the last indexed entry
  holding the prefix after a `retain`) is inside those words.
- F1: the index notes two entries of one txid when it indexes them
  (`holds_twins`, a private field: `rebuild_index`, the pushed tail, `push_tx`
  through `index_entry`), and `edit_tx` keeps the old key on such a BEEF, so a
  lookup of the old txid hits the edited entry, finds another txid and scans or
  rebuilds to the twin, as the reference's index rebuilt after the edit finds it
  (`Beef.ts:342-352,516-524`). Chosen over dropping the removal (every later lookup
  of an edited-away txid would then scan or rebuild on a BEEF without twins) and
  over re-inserting the last other holder (a scan on every edit): the edit and the
  lookups after it stay constant on a BEEF without twins. Recorded: the vector's
  43rd case (`twin:`, Node v22.23.3, additions only, two runs byte-identical).
- The pins: `a_hand_removal_then_two_pushes_finds_each_pushed_entry_817` (the
  cold read's attack C), `a_grown_count_with_a_moved_prefix_rebuilds_whole_817`
  looking up the never-indexed Y first (F2),
  `a_self_lookup_after_a_retain_and_pushes_scans_whole_817` (F3),
  `two_hand_pushed_twins_are_answered_by_the_later_817` (F4), and for F1
  `an_edit_of_a_hand_pushed_twin_keeps_the_other_entry_found_817`,
  `an_edit_of_a_twin_after_reindex_keeps_the_other_entry_found_817`.
- The CHANGELOG's stated `retain` cost gains the cold read's debug figure (4.0 to
  4.2 s against beta's 0.35 s). The cost rows the fold touched re-measured
  release, three runs against `ba0dc50e`: every row inside its range
  (`cost_release.txt`).
- The line ratchet: `beef.rs` passed its ceiling by 6 with the new field, so
  `clone_shallow` is written as the derived `Clone` it equalled field for field;
  the declared-equivalent mutant of `dependency_order` re-pointed to `1197:29`.

RED (logs in `/Volumes/Lanes/out/bsv-rs/fix-817-door-sync-fold/`): on a scratch of
`ba0dc50e` with the tests overlaid, own target dir (`red_base_own_target.log`), 4
RED: the recorded twin case (`find:u` `null` where the reference answers `u`), the
stated count (the twin case differing), the two hand-pushed twin tests (at
`find_txid(U).unwrap()`); the pins green there (behaviour shared). On a scratch of
the tip (`plants.log`), each planted removal RED: the prefix check forced true
(attack C and both unit tests), the rebuild in `sync_index` deleted (attack C, the
moved-prefix unit test), the check dropped from `index_of` (attack C, the `&self`
unit test), `.rev()` dropped (the twins test), the twin note dropped at the push
(the three twin tests), at the rebuild (the `reindex` twin test), and the kept key
dropped (the three twin tests). One survivor, cost only: the old key kept on every
BEEF moves no answer.

