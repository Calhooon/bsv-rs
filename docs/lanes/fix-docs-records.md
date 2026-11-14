# Lane fix-docs-records: four sentences that were no longer true of the code

Opened from `origin/beta` at `cb950611` (2026-11-14). Documents and comments
alone: `//!` and `///` comments, `CLAUDE.md` files, the CHANGELOG's
`[Unreleased]` section and this record. No code line moved (the check is at
the end). No cargo, rustc or build ran on the lane's host (a bench was being
recorded there): CI builds the comments.

The brief's premises were read at `b701c06f`; `cb950611` is two commits
later (#908 `6232488b`, #912 `cb950611`). Every cited line was checked on
`cb950611` before a sentence was touched. One citation of the brief is
written here as read: the rename of the #621 witness is #843's landing (pull
request #869, `1a3e4c5a`), so "#843 (PR #869)" names it.

## The four

| # | From | Where | Fate |
|---|---|---|---|
| 1 | #910 line 2 | `src/script/templates/pushdrop_wallet.rs:18-27`; root `CLAUDE.md`, the #782 row | mended, both |
| 2 | #910 line 5 | root `CLAUDE.md`, "Downstreams to keep in mind"; sibling `src/block/CLAUDE.md` | mended, both |
| 3 | #817 line C1's residue | root `CLAUDE.md`, the `merge_transaction` row; `src/transaction/beef/merge_entry.rs:22-32`; siblings `src/transaction/beef_tx.rs:274-280`, `src/transaction/CLAUDE.md` | mended, all four |
| 4 | #912 line 3 | root `CLAUDE.md`, a new row closing the list; `src/primitives/ec/CLAUDE.md` | stated |

### 1. "As the crate's five wallet sites do"

Before (`pushdrop_wallet.rs`): `refuses a text that is no key in that
parser's words (as the crate's five wallet sites do), after the key call
alone`. Before (root `CLAUDE.md`): `refuses a text that is no key in that
parser's words, as the five sites do:`.

Why untrue: since #816 four of the five are this door's own callers
(`src/identity/reveal.rs:292`, `src/identity/contacts_actions.rs:90`,
`src/registry/token.rs:169`, `src/kvstore/local_token.rs:16`, each read on
the tip), so the clause counted the door among the sites it compared itself
with. The one lock outside the door, the global key-value store's
(`src/kvstore/global_actions.rs:193`, `wallet_key_lock`), reads the key
through the same reader: `wallet_key_lock` is
`read_wallet_key(key_hex)?.lock(..)`
(`src/script/templates/pushdrop_key_bytes.rs:62-63`).

After (`pushdrop_wallet.rs`): `words (through `read_wallet_key`, the reader
the crate-visible `wallet_key_lock` reads through too), after the key call
alone`. After (root `CLAUDE.md`): `in that parser's words, through
`read_wallet_key` (`src/script/templates/pushdrop_key_bytes.rs`), the reader
the crate-visible `wallet_key_lock` reads through too:`. The reader is named
and no count is left for the next change to move.

Pinned bytes: none. `tests/arch_pushdrop_wallet_key_order_816.rs` reads code
tokens under `src/` through `arch_support`, comments and literals opaque (its
own count of `wallet_key_lock` in the definition's file is 1 while that
file's `//!` header names it once more), and reads no `CLAUDE.md`; naming
`read_wallet_key` in the door's `//!` header adds no site to its count of 2.
`tests/front_page.rs` (F3) reads the root list for a row count above zero,
the two words `ts-stack` and `go-sdk`, and rule 1's two sentences: none of
them touched.

Left as written, each true as history or by enumeration: the #545 row's
"the five sites locking with a wallet's `getPublicKey` answer" (the five
files listed, "until #545"), the #782 row's "`wallet_key_lock` at the five
sites" ("until #782"), `tests/CLAUDE.md`'s row for
`script_pushdrop_key_bytes_545.rs` (five wallet sites, each named),
`pushdrop_key_bytes.rs:8` ("Four wallet sites lock through ..", true on the
tip and held by the arch test's one stated caller).

### 2. Two downstream paths that do not exist

Before: the section was one paragraph naming `~/bsv/bsv-overlay-cloudflare`,
`~/bsv/rust-message-box`, `~/bsv/bsv-low/workers/low-watchtower`,
`low-monitor`, `crates/low-tower-key`, `~/bsv/bsv-middleware-cloudflare-public`
and `~/bsv/rust-chaintracks`.

Why untrue, by `test -d` on each named path on the captain's host (the
Studio) on 2026-11-14 (no listing of `~/bsv` as a whole):
`~/bsv/bsv-middleware-cloudflare-public` and `~/bsv/rust-chaintracks` are
no folder; `~/bsv/bsv-overlay-cloudflare`,
`~/bsv/rust-message-box`, `~/bsv/bsv-middleware-cloudflare`,
`~/bsv/bsv-middleware-rs` and `~/bsv/chaintracks-cloudflare` are.
`docs/DEPENDENTS.md:99,100,105` holds the rows of the repositories that exist
(`bsv-middleware-rs`, `chaintracks-cloudflare`, `bsv-middleware-cloudflare`).
Every path under `~/bsv/bsv-low`: not checked (this lane reads nothing
there).

After: the section points at `docs/DEPENDENTS.md` (its pin table and its app
trees) as the one list and keeps three things that document does not say:
the overlay engine's own `Spend` at its submit door (the cited lines read at
`9a0f3c29` in the local clone: 557, 649 and 857 of
`crates/overlay-engine/src/script_door.rs` are its push-only checks), the LOW
workers (no row in the document's tables; kept as named, marked not
checked), and the local clones present that day with the two dead paths
named as dead. The closing sentence (grep before you publish) is unchanged.

Dropped because the document says it: the overlay's `overlay-cloudflare`
and app-layer features (its row 97), and the relay's `auth`, `socketio`,
`wasm`, which is #80's relay slice name (`docs/DEPENDENTS.md:62-66`), not the
relay manifest's feature list.

Sibling, by `git grep` for the two names outside the CHANGELOG, the lane
records and `HANDOFF.md`: `src/block/CLAUDE.md`'s "Downstreams" named
`~/bsv/rust-chaintracks` "(root `CLAUDE.md`'s downstream list)". Mended to
point at the same document; its consumer is the chaintracks-cloudflare line
that opens that section.

For the captain's next refresh of the table, read and not changed here (the
table is refreshed by its own pull request, `RELEASING.md` step 3): the
relay's row says its features were not read; the local clone's manifest at
the row's commit `44a63204` asks `auth`, `wallet`, `transaction`, `wasm`
(`Cargo.toml:55`).

### 3. A witness name that no longer exists

Before (root `CLAUDE.md`, the `merge_transaction` row's residues): `and a
`tx_mut` entry whose stale serialization `raw_tx_or_compute` cached (a
crate-only state) is ordered under its edited fields' hash and merged as its
stale bytes under theirs (`written_order`; the witness of the state
`a_stale_cached_entry_is_filed_under_its_bytes_hash_621`)`. Before
(`merge_entry.rs`): `never under `txid()`'s reading of its fields, which a
stale serialization cached after `tx_mut` can part from`.

Why untrue: `git grep` finds the old name nowhere under `src/`, `tests/` or
`fuzz/`; `git log -S` names the commit that removed it, `1a3e4c5a` (#843's
landing, pull request #869 by `gh pr view 869`), which renamed the test
`an_entry_edited_inside_tx_mut_is_filed_under_its_fields_hash_843`
(`src/transaction/beef/merge_entry_621_tests.rs:62-106`) and reversed what it
pins: the id read inside the `tx_mut` borrow fills the caches, the edit's
door empties them, so `raw_tx_or_compute` answers the edited fields' bytes
and the merged entry is found under their hash and not under the old one.
Before that commit the test asserted the stale bytes (`assert_eq!(stale,
bytes)`) and found the entry under the old txid. A cached serialization that
is not its fields' is planted only by `Transaction::with_cached_bytes_for_test`
(`src/transaction/transaction/fields.rs:539`, the crate's tests and the
`internal-test-doors` feature); its two uses (`beef/prepass_621_tests.rs:345`,
`fuzz/fuzz_targets/fuzz_beef_parser.rs:228`) plant a transaction and more,
not a stale one. `merge_beef_entry` itself is unchanged: a raw entry is filed
under the txid it holds, else its bytes' hash.

After (root): the clause says the residue is gone since #843, what the
renamed witness pins, and that only the test door plants such a cache.
After (`merge_entry.rs`): `never under `txid()`'s reading of its fields.
Until #843 a stale serialization cached after `tx_mut` could part from that
reading; since #843 an edit's door empties the transaction's caches, and
only the test door `Transaction::with_cached_bytes_for_test` plants a cache
that is not its fields' serialization.`

Siblings, by `git grep` for the sentence's words: the comment on
`BeefTx::held_txid` (`src/transaction/beef_tx.rs`: "which a stale cache after
`raw_tx_or_compute` can part from", now "could part from until #843, whose
doors empty the caches before every edit") and the `beef/merge_entry.rs` row
of `src/transaction/CLAUDE.md` ("never `txid()`'s reading of a stale cache",
now its fields' reading, with the same two clauses). The brief named two
places; these two carry the same sentence and are mended with them (root
rule 11), a third `.rs` file among them, comment lines alone.

### 4. `derive_child` takes no shared-secret cache callbacks

The captain's ruling on the question fix-912-primitives left
(`docs/lanes/fix-912-primitives.md`, "Line 3"): a stated row, no new public
door. Read again at the pin: `PrivateKey.ts:439-444` and
`PublicKey.ts:205-210` are the two signatures, `:446-458` and `:212-224`
their use; `wallet/KeyDeriver.ts:137-141` the constructor's two optional
callbacks, `:172-173`, `:180-181`, `:202-203` where `derivePublicKey` and
`derivePrivateKey` hand them on, `:226-241` where `derivePrivateKeys` hands
closures of its own, `:288-308` its async path's own use;
`wallet/CachedKeyDeriver.ts:50-58` the one construction across `packages/`
(outside tests and docs) that supplies them. This crate:
`src/primitives/ec/private_key.rs:339`, `public_key.rs:247` (two
arguments), `src/wallet/key_deriver.rs:75` (`KeyDeriver::new(root_key)`),
`src/wallet/cached_key_deriver.rs:142-147` (three caches of derived keys).
go-sdk at `2ca481c`: `primitives/ec/privatekey.go:208`, `publickey.go:305`.

The row closes the root list (after `Polynomial::value_at`'s, the other
primitives row), and the same sentence stands in `src/primitives/ec/CLAUDE.md`
under "BRC-42 Key Derivation Algorithm", where `derive_child` is described.
Its witness is the differential that already reads the derived keys from
both sides, `tests/shared_secret_bytes_843d6.rs` on
`tests/vectors/shared_secret_843d6.json`.

## The other-implementation rule

Row 4 says what this crate does and what the other side does at a named
sha and line, in neutral words; nothing is filed and no filing is drafted.
The difference is no peer's input reaching a verdict: a cache parameter is
how a caller's own process holds its own values.

## The checks

Run, each without cargo (logs under `/Volumes/Lanes/out/bsv-rs/fix-docs-records/`):

- `python3 -B .github/scripts/rows_from_sources.py --check`: `0 refusals`.
- `python3 -B .github/scripts/test_rows_from_sources.py`: 10 tests, OK.
- `python3 -B -m unittest discover -s .github/scripts -p 'test_front_pages.py'`
  (the `front-pages` gate's own line in `ci.yml`): 88 tests, OK. The live
  `front_pages.py check` was not run: it reads the release pages over the
  network and none of its pages is touched here.
- `tests/front_page.rs` F3 by a reading (a script of its four conditions on
  the root `CLAUDE.md`): 153 rows, `ts-stack` and `go-sdk` present, rule 1's
  two sentences present. The test itself is cargo's.
- Added words (`git diff --word-diff=porcelain`, this record included):
  none of the wording rule 7 of `docs/lanes/README.md` refuses.
- `git diff -U0` over the three `.rs` files: every added and removed line
  opens with `//!` or `///`.
- `gitleaks git --redact --no-banner --exit-code 1 -v --log-opts="origin/beta..HEAD" .`
  (8.30.1, the version `ci.yml` builds): no leaks.

Not run: every cargo command of the gate (`cargo fmt`'s three lines, clippy,
the tests, the doc tests, the wasm32 build) and `tools/ratchet/run`, which
builds. What the comments could move there, by reading: the ratchet's file
counter (`pushdrop_wallet.rs` 106 lines, `merge_entry.rs` 109, `beef_tx.rs`
748, each under 800), its
function counter (the three comments sit above their items, outside any
body), its pedantic count (every identifier in the new comment lines is in
backticks, so no new `doc_markdown`), rustdoc (no new intra-doc link: the
new names are code spans, `with_cached_bytes_for_test` being `cfg`-gated),
and `.cargo/mutants.toml` (no entry names any of the three files).
