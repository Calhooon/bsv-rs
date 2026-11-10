# Lane fix-817-merkle-writers: `MerklePath`'s writers return `Result` (#817)

Started from `cebd819abe6f897fbf9f20ade3138e1b31d65bda`, which was `origin/beta`'s tip when
the lane opened (2026-11-09). No reset was needed.

## Provenance

A reader found that `Beef::to_binary` panics on a V1 BEEF holding a txid-only entry
(Calhooon/bsv-rs#817). The owner's standard for the choice (2026-11-10): "we in no rush..
we love soundness" and "for choices.. they need to be god tier and north star decision".
Eleven independent design reads in three rounds, recorded on #817, decided it: the BEEF
writers and `merge_beef` become fallible (the second change, another lane, after PR #823
lands), and, three of three in round 2, `MerklePath::to_binary`, `to_hex` and `to_writer`
return `Result` in the same cut. This lane is that part alone. The owner's ruling of
2026-10-26 allows a public-shape change on the 0.9.0 line that takes the reference's own
shape; the reference's `MerklePath.toBinary` throws.

The rule applied to every cell: a writer refuses only a state it cannot write faithfully
(bytes that would not frame, or would read back as a different state); it writes every
other state, valid or not, as the reference does (validity is the readers' and
`verify`'s); it uses the reference's words where the reference refuses; where the
reference writes bytes no reader reads back as written, this crate refuses in its own
words, states the row, and the difference is drafted for upstream.

## The survey

Reference: `ts-stack@edf6e03` `packages/sdk/src/transaction/MerklePath.ts:271-293`
(`toWriter`), `primitives/utils.ts:93` (`toArray(undefined)` is `[]`), `:127-128`
(`assertValidHex`, then an odd length padded with a leading `0`), `:470-475` (`writeUInt8`,
`n & 0xff`), `primitives/hex.ts:6-17` (`Invalid hex string`). Go: `go-sdk@2ca481c`
`transaction/merklepath.go:293-317` (`Bytes()`), the hash a `*chainhash.Hash` (32 bytes).
"Reaches it": the readers (`from_binary`, `from_hex`, `from_reader`, the BEEF readers)
never produce any of these states: they read 32-byte hashes, the flags `00`, `01`, `02`,
1 to 64 levels. The public `path` field and `MerklePathLeaf`'s public fields reach every
state. The reference column is the recording (`tests/vectors/merkle_path_writer_refusals_817.json`).

| # | State | Reached by (besides the public fields) | Reference `toWriter` | Go `Bytes()` | This crate before | This crate after | Clause that decides |
|---|---|---|---|---|---|---|---|
| 1 | A leaf not flagged duplicate whose hash has a non-hex character | `from_coinbase_txid` (checks nothing); `new`/`new_unchecked` with a lone leaf (its root is its text, unread, on both sides) or a leaf no walk reads | throws `Invalid hex string` | unrepresentable (32-byte array) | flag, then nothing (`from_hex(..).unwrap_or_default()`): the frame breaks | refused, `Invalid hex string` | the reference refuses: its words |
| 2 | A leaf not flagged duplicate with no hash | `new`/`new_unchecked` accept it (the walk pairs `""`, as the reference's `hashPair(undefined)` does) | flag, then nothing (`toArray(undefined)`) | nil dereference, panic (`:311`) | flag, then nothing | refused, `Missing hash at height H, offset O` | bytes would not frame; the reference writes them: our words, a stated row, drafted |
| 3a | A hash of hex digits, 62, 66 or any length other than 63 or 64 | as 1 | written at its length (31, 33 bytes) | unrepresentable | written at its length | refused, `Invalid hash at height H, offset O: expected 64 hex digits, got N` | would not frame; stated, drafted |
| 3b | The empty hash text | as 1 | nothing (`assertValidHex` allows `""`) | unrepresentable | nothing | refused, same words, `got 0` | would not frame; stated, drafted |
| 3c | A hash of 63 hex digits | as 1 | padded to `0` + 63 digits, 32 bytes | unrepresentable | nothing (Rust's hex reader refuses odd lengths) | refused, same words, `got 63` | the reference's bytes frame but read back as another text: stated, drafted |
| 4 | More than 255 levels | none (both constructors refuse more than 64) | height byte `n & 0xff` (256 levels written `00`) | `byte(treeHeight)` | `as u8` | refused, `Invalid tree height: N, over the 255 levels a BUMP's tree height byte writes` | would not frame; stated, drafted |
| 5 | A leaf flagged duplicate that carries a hash | `new` accepts it where it is a right sibling (the walk pairs the working hash with itself) | flag `01` alone | flag `01` alone | flag `01` alone | refused, `Duplicate leaf at height H, offset O carries a hash, which a BUMP's duplicate flag cannot write` | reads back as another path (the hash, which a walk reads where the leaf is a left child, is gone); stated, drafted |
| 6 | No level at all | none (#649) | `fe00350c0000` | the same | the same | written | the format carries it; no reader accepts it (`TreeHeightZero`) |
| 7 | 65 to 255 levels | none | written | written | written | written | the byte carries it; no reader accepts it (BRC-74's 64) |
| 8 | An empty level 0 | none (`Empty level at height: 0`) | written | written | written | written | the format carries it |
| 9 | A repeated offset | none | written | written | written | written | the format carries it; the readers refuse `DuplicateOffset` |
| 10 | An illegal offset, mismatched roots | `new_unchecked` (illegal offsets) | written | written | written | written | validity is the readers' |
| 11 | A duplicate also flagged txid (flag `03`) | `new` accepts it | `03` | `03` | `03` | written `03` | the brief's explicit list ("a flag byte the reader refuses": written); this crate's reader refuses `03`, the reference's reads a duplicate with the txid dropped. Named for the captain below |
| 12 | An upper-case hash | `new`, `from_coinbase_txid` | the same 32 bytes as lower case | unrepresentable | the same bytes | written | the bytes carry the hash; its text's case is representation, read back lower case. Named below |
| 13 | Leaves out of offset order | `new` accepts them | written as held | written as held | written as held | written | the bytes carry the order; the readers sort |
| 14 | A txid flag above level 0 | `new` | written | written | written | written | the format carries it |
| 15 | A lone leaf at offset 1 | none (`MissingSibling`) | written | written | written | written | the format carries it; the readers refuse it |
| 16 | A leaf not flagged txid | every sibling leaf | `{ txid: false }` written `02` (`:284-286`, the member's presence, not its value); an absent member `00` | the value (`*leaf.Txid`) | `00` | `00` | this crate's state is written faithfully; the reference's explicit `false` is its defect, drafted |

The constructors and the root (task 3, checked at the pin first): the reference's
`hashPair` (`MerklePath.ts:30-32`) runs `toArray(left + right, 'hex')`, which throws
`Invalid hex string` for a non-hex character, so its constructor (`computeRootCached`)
and `computeRoot` throw where a walk pairs such a hash; with a lone leaf both return the
text unread (`:345`, `:390-391`), and a leaf no walk reads is not read. This crate's
`hash_pair` dropped the text it could not decode and hashed the rest. It now refuses a
text with a non-hex character in `Invalid hex string` (`merkle_path_walk.rs`), reached by
`new`, `new_unchecked` and `compute_root` through `RootWalker`; the lone leaf and the
unread leaf stay accepted on both sides (cells `constructor_non_hex_sibling`,
`constructor_non_hex_txid`, `constructor_non_hex_hash_no_walk_reads`, and the lone leaf of
`non_hex_leaf_hash`). Every other text keeps the legacy reading (an odd-length text, which
the reference pads after concatenating, is unchanged and not in this lane).

## The change

- `pub fn to_binary(&self) -> Result<Vec<u8>>`, `pub fn to_hex(&self) -> Result<String>`,
  `pub fn to_writer(&self, writer: &mut Writer) -> Result<()>`, receivers unchanged. One
  private read-only check, `check_writable`, runs before any byte: the level count, then
  each leaf in written order (no hash; a non-hex character; not 64 digits; a duplicate
  carrying a hash).
- `Beef::to_writer` writes each BUMP through `MerklePath::to_writer_lenient_until_beef_817`
  (`pub(crate)`), the bytes 0.9.0-beta wrote, so no `Beef` byte or signature moves; the
  second lane of #817 removes it.
- `hash_pair` returns `Result<String, String>`; `RootWalker` carries its refusal as it
  carries `Missing hash`. The three equivalence entries of `.cargo/mutants.toml` move from
  `merkle_path_walk.rs:141` to `:142` (the pairing's `?` on a line of its own).
- Callers: 78 call sites in 29 files take the `Result`: `src/` 2 files (the module's
  own tests, `merkle_path.rs` and `merkle_path_603_tests.rs`), `tests/` 25 (24 top-level
  files and `support/fixtures/binary.rs`), `fuzz/fuzz_targets/` 2, with `.expect("the path holds only states a
  BUMP writes (#817)")` in tests; `examples/`, `benches/` and the README call none of the
  three. The `linear_root_equivalence_tests` parse differential writes its damaged paths
  through the unchecked writer, the 0.9.0-beta bytes, as its subject is the reader.

## RED

On a scratch copy of the base (`git archive cebd819a`, its own target under `$TMPDIR`),
`tests/merkle_path_writer_refusals_817.rs` fails to compile:

```
error[E0599]: no method named `map` found for struct `Vec<u8>` in the current scope
  --> tests/merkle_path_writer_refusals_817.rs:71:35
error[E0308]: mismatched types
  --> tests/merkle_path_writer_refusals_817.rs:77:10
error[E0277]: can't compare `std::string::String` with `Result<_, bsv_rs::Error>`
   --> tests/merkle_path_writer_refusals_817.rs:122:5
error[E0599]: no method named `unwrap_or_else` found for struct `Vec<u8>` in the current scope
   --> tests/merkle_path_writer_refusals_817.rs:527:14
error: could not compile `bsv-rs` (test "merkle_path_writer_refusals_817") due to 10 previous errors
```

A probe on the same copy (scratch only, the vector's cells held through the fields) shows
the stated reason for each refusal: the base writes every refused cell and accepts the
non-hex sibling at `new`:

```
BASE non_hex_leaf_hash: to_hex=fe00350c0001010002 new=Ok(()) ...
BASE hashless_leaf: to_hex=fe00350c0001020002c7cf...  (the second leaf's flag, no hash)
BASE hash_of_63_digits: to_hex=fe00350c0001010002 ...
BASE hash_of_62_digits: to_hex=fe00350c0001010002c7cf... (31 bytes)
BASE empty_hash: to_hex=fe00350c0001010002 ...
BASE levels_256: to_hex=fe00350c0000010002c7cf... (height byte 00)
BASE duplicate_carrying_a_hash: to_hex=fe00350c0001020002c7cf... (flag 01, no hash)
BASE constructor_non_hex_sibling: ... new=Ok(()) new_unchecked=Ok(()) compute_root=Ok("13f79147bfb52bd0")
BASE constructor_non_hex_txid: ... new=Ok(()) new_unchecked=Ok(()) compute_root=Ok("f50c0009bfab9873")
```

On the tip: 27 passed, three runs (one with `--test-threads=1`).

## The recording

`tests/support/merkle_path_writer_refusals_817.mjs` against the bundle of
`ts-stack@edf6e03` `packages/sdk` (`bun build`), Node v22.18.0, two runs byte-identical:
24 cells, each `toHex`, `toBinary`, the constructor with and without `legalOffsetsOnly`,
`computeRoot` on the held path. This crate against it, cell by cell: 16 equal (five refused
in `Invalid hex string` on both sides, eleven written byte for byte; the constructor
cells' three doors equal too), 8 stated (`REFUSED_HERE_WRITTEN_THERE`: row 2, row 3a's 62
and 66 digits, rows 3b, 3c, 4 and 5, refused here and written there, and row 16, written by
both with another flag byte), each named in the test.

## The sweep

Every merkle path the tree's vectors hold (`tests/vectors/` and `tests/transaction/vectors/`:
JSON and JSONL hex strings, Rust string literals, `.bin` files; a string read as a BUMP, or
as a BEEF whose BUMPs are taken): 601 paths from 256 files, each written `Ok`, read back
with the same height and levels, and written again to the same bytes.

## The dependents (survey only)

Each repo grepped by its own path on 2026-11-09, every candidate's receiver read to its type
(a read-only agent's classification, every site read in context; none uncertain). Only
`to_hex` and `to_binary` are called on a `MerklePath`; the four `to_writer(&mut w)` calls in
the overlay are on a `Beef`, which this lane does not change.

| Repo | Production | Test | Total |
|---|---:|---:|---:|
| `~/bsv/bsv-wallet-toolbox-rs/src` | 5 | 14 | 19 |
| `~/bsv/bsv-wallet-cli/src` | 0 | 0 | 0 |
| `~/bsv/bsv-overlay-cloudflare/crates` | 10 | 102 | 112 |
| `~/bsv/rust-message-box/src` | 0 | 0 | 0 |
| total | 15 | 116 | 131 |

The production sites and what each does with the bytes:

| Site | Method | Use |
|---|---|---|
| toolbox `tsc_proof.rs:31` | `to_binary` | `tsc_json_to_bump_binary` returns the BUMP bytes (an `Option`: `.ok()?`) |
| toolbox `tsc_proof.rs:51` | `to_hex` | `tsc_json_to_bump_hex` returns the BUMP hex (an `Option`) |
| toolbox `storage/sqlx/internalize_action.rs:1062` | `to_binary` | `BumpClaim.merkle_path`, the `proven_txs.merkle_path` column |
| toolbox `storage/sqlx/create_action.rs:3109`, `:3161` | `to_binary` | `BeefTxData.merkle_path` from a stored input BEEF's BUMP (a struct field: needs handling) |
| overlay `overlay-cloudflare/src/proof_fetcher.rs:1547` | `to_hex` | `tsc_json_to_bump_hex` (an `Option`) |
| overlay `overlay-cloudflare/src/proof_fetcher.rs:2535` | `to_hex` | `own_bump_hex`, compared and pushed (an `Option`) |
| overlay `overlay-cloudflare/src/reorg_sweep.rs:128` | `to_hex` | `stored_bump_hex`, the reorg re-check (an `Option`) |
| overlay `low-app-layer/src/txany.rs:214` | `to_hex` | `courier_tsc_bump` (an `Option`) |
| overlay `low-app-layer/src/tracker_host/stored.rs:41` | `to_hex` | a stored row's `proof_hex` (persisted) |
| overlay `low-app-layer/src/tracker_host/served.rs:20` | `to_hex` | the `merklePath` JSON field served to clients |
| overlay `overlay-engine/src/engine.rs:4290`, `:4335`; `gasp_overlay.rs:907`, `:945` | `to_hex` | `GASPNode.proof`, the GASP wire JSON |

Whether any production path can hold a refused state was not judged site by site (no
dependent was built against this branch); a path read from bytes cannot, so for the sites
whose path comes from a reader or a BEEF the change is a type change alone. Two
test sites use the function path `.map(MerklePath::to_hex)` (`gasp_topic_manager.rs:567`,
`beef_limits.rs:487`), which becomes an `Option<Result<..>>` and fails to compile only where
the value is used.

## Named for the captain (the rule did not decide)

- Row 11, flag `03`: the brief's own list writes "a flag byte the reader refuses", and this
  crate's reader refuses `03` rather than reading another state; but the reference's reader
  reads it as a duplicate with the txid dropped, which is "reads back as a different state"
  under the rule's second clause. Written here, as the brief's list says; round 2's parity
  lens refused it.
- Row 12, an upper-case hash: written (the same 32 bytes); it reads back lower case. If the
  text is the state, it is "read back as a different state"; if the hash is, it is not. The
  reference writes it.
- Row 5 is this lane's addition to the lenses' lists (no lens named it).

## The fold (the reads of 2026-11-09)

Three reads of `2e313b48`: the cold read FIX (0.8), the rule read FIX (0.8), the strength
read ACCEPT (0.87). Folded on `lane/fix-817-merkle-writers-fold`, rebased onto beta
`2356b581` (#621 landed while the reads ran; `.cargo/mutants.toml` keeps beta's
`beef.rs:1204:29` entry and this lane's `merkle_path_walk.rs:142` lines, the CHANGELOG
both entries, this one above; `tests/beef_merge_beef_held_621.rs:62`'s `mp.to_hex()` now
`.unwrap()`ed), the rule read's `508fece0` (the migration line on `new`, `new_unchecked`,
`compute_root`, `verify`) cherry-picked. The cold and strength reads committed nothing.

- **The non-hex scan first** (cold read c1, c3, c4; rule read FIX one; strength read row
  one): the reference's writer throws `Invalid hex string` at a non-hex hash wherever it
  sits, so `check_writable` scans every leaf not flagged duplicate before the height check
  and every other refusal. A duplicate's hash is never read by the reference's writer, so a
  duplicate carrying a non-hex hash stays the duplicate-carrying-a-hash refusal (the cold
  read's c2, the strength read's second cell).
- **A duplicate flagged txid refused** (rule read cell (a)): the reference writes `03` and
  reads it back as a plain duplicate; this crate's readers refuse `03`. The same ground as a
  duplicate carrying a hash: refused, a stated row, draft 58 extended. `combine` produces it
  from two paths `new` accepts (`a` = a txid at 0 and a duplicate at 1; `b` = the same hash
  at 0 and as a txid at 1, a txid equal to its sibling, no honest block's; `b` also reads
  back from its bytes); the probe's output is the lane log `combine-probe.log`. `combine`
  unchanged.
- **Six cells recorded** (additions only, the 24 earlier cells byte-identical, two runs
  byte-identical under Node v22.18.0 at `edf6e03`): `levels_256_with_non_hex_leaf`,
  `hashless_leaf_then_non_hex`, `hash_of_62_digits_then_non_hex`,
  `hashless_leaf_at_1_then_non_hex_above`, `duplicate_carrying_a_non_hex_hash`,
  `computed_node_pairing_non_hex`.

RED on a scratch copy of `2e313b48` with the tip's test file and vector: 5 of 32 failed:

```
test a_duplicate_flagged_txid_is_refused_by_the_writer_817 ... FAILED
test a_non_hex_hash_after_a_hashless_leaf_is_refused_in_the_reference_words_817 ... FAILED
test a_non_hex_hash_after_a_62_digit_hash_is_refused_in_the_reference_words_817 ... FAILED
test a_non_hex_hash_after_256_levels_is_refused_in_the_reference_words_817 ... FAILED
test every_recorded_cell_is_written_or_refused_as_the_reference_save_the_stated_rows_817 ... FAILED
  left: "Missing hash at height 0, offset 0"
 right: "Invalid hex string"
  left: "Invalid hash at height 0, offset 0: expected 64 hex digits, got 62"
 right: "Invalid hex string"
  left: "Invalid tree height: 256, over the 255 levels a BUMP's tree height byte writes"
 right: "Invalid hex string"
```

The two pins the base already shares, RED on planted mutations of a tip copy: the scan
reading duplicates too (`a_duplicate_carrying_a_non_hex_hash_..._817`, `left: "Invalid hex
string"`), the computed node's `hash_pair` error dropped
(`a_computed_node_pairing_a_non_hex_hash_..._817`, `left: Ok(())`,
`right: Err("Invalid hex string")`).

Rows the reads filed outside the subject, unchanged here: the strength read's `hash_pair`
reading odd-length texts apart where the reference concatenates first (`after-cut`,
pre-existing); the cold read's residual `hash: null` (a `TypeError` there) with no
counterpart here; the upper-case hash written and read back lower case (the captain's call,
the rule read holds it written).

## The cold re-read of the fold (2026-11-09, `b9aa82f1`)

The `combine` finding, recorded on both sides (scratch probes, never committed; the logs
`ref-probe.json` and `tip-probe.log` in the re-read's lane folder). Path `a` =
`[[{0, H(0), txid}, {1, duplicate}]]`, path `b` = `[[{0, H(0), txid}, {1, H(0), txid}]]`,
both accepted by the constructor on both sides, the same root. The reference at
`edf6e03` (Node v22.18.0): `a.combine(b)` holds `{offset: 1, duplicate: true, txid: true}`
at offset 1 (`MerklePath.ts:508-536`: the held duplicate kept, `existingLeaf.txid = true`),
`toHex()` writes `...0103`, and `fromHex` reads back `{offset: 1, duplicate: true}`, the
txid flag lost; `b.combine(a)` keeps `b`'s hashed txid leaf and writes `02`. This crate's
`combine` makes the same leaf in each order, its writer refuses `a`'s in `Duplicate leaf at
height 0, offset 1 is flagged txid, ...`, and its reader refuses the reference's bytes
(`BadFlag { byte: 3 }`). The two `combine`s agree; the difference is the writer's, stated.
The txid lost is the hash at offset 0, so no txid the path proves is lost; the state needs
a txid equal to its sibling. `Beef::to_binary` still writes `03` through the lenient
writer after a `merge_bump` that combines such paths (the second lane of #817).
