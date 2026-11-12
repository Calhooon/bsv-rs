# Record for #843: identity and framing (the class of #840)

**Who keeps this record current:** the pull request that lands a change this record names (a PR, an issue's fix, a decision built) updates this record's state lines (sections 1, 2, 5, 6, 8 and 9) in the same commit.

Written on 2026-11-10 from `origin/beta` at `2c464e81`, after the owner agreed to #843's recommendation, so that whoever works here next knows what was found, what was decided, why, and what is built. `[X]` marks a claim read at the line or run (by the named lane or read), `[D]` one told or proposed. Every figure below is quoted from an issue comment, from a design read named by its file under the captain's notes (`reports-1109/design-*.md`), or from the `fix-tx-trailing` lane record (`docs/lanes/fix-tx-trailing.md` on `origin/lane/fix-tx-trailing`); none was measured for this record. A `file:line` citation into `src/` names the line at `0a3744e2` (PR #841's head, the commit the #843 reads read), not at `2c464e81`; re-find it by its text on any other commit (beta at `7df16cf6`, with #841 merged, holds them within five lines). The state lines were refreshed with `gh` on 2026-11-10 after 14:34Z, at beta `7df16cf6`; section 9 holds what was decided after the record was written.

This is a record, not a design: it changes no source. Where a thing is decided and not yet built, it says **decided, not built**. Where a pull request is open, it says open. The states were read with `gh` on 2026-11-10 (PR #841 merged as `7df16cf6` at 14:16Z; #846, #839 and #850 open); re-read them before you rely on one.

## 1. The class, and its instances

**The class in one sentence:** a value answered an identity (a txid, a byte form, an index entry) that is not the identity of what it holds, because a reader took more than the value, or because the value changed after its identity was computed and nothing recomputed it.

| Finding | Issue | How it was found | What a run showed | The fix and its state |
|---|---|---|---|---|
| `Transaction::from_binary` and `from_hex` read one transaction from the front and cache the whole input | [#840](https://github.com/Calhooon/bsv-rs/issues/840) | a cold read of PR #839, confirmed by the captain's run on beta `fa75921b` | `[X]` a 275-byte transaction followed by four bytes answers `Ok`; `to_binary()` 279 bytes; `id()` `a10aefc1…` where the transaction is `f4184fc5…`; the transaction twice answers `Ok` and 550 bytes. The same probe on main's tip `8729f8a5` (0.8.3) gives the same; the lines date from the original implementation (`e4646386`) and `v0.3.1` holds them | PR [#841](https://github.com/Calhooon/bsv-rs/pull/841), **merged** as `7df16cf6` on 2026-11-10 14:16Z (lane `fix-tx-trailing`; it also makes `Transaction::from_reader` public, the reference's prefix reader); the stable patch 0.8.4 is tracked by [#849](https://github.com/Calhooon/bsv-rs/issues/849). As it happened: picked onto `main` by PR [#852](https://github.com/Calhooon/bsv-rs/pull/852) (`ed2789fb`, 18:47Z), **released as 0.8.5** on 2026-11-10 (20:51:59Z on crates.io; 0.8.4 was tagged and never published, section 6), advisory GHSA-j8hr-pjhm-6h27 |
| On the stable line, after #840's port: a raw BEEF entry whose bytes are not exactly one transaction (a transaction and more, a cut transaction, bytes that are no transaction) is held unparsed and answered valid at the verdict doors (`verify_valid`, `is_valid`, `sort_txs`), since 0.8's `from_raw_tx` returns no `Result` and cannot refuse it at the door | PR [#852](https://github.com/Calhooon/bsv-rs/pull/852) (its fold; no issue) | the reads of the stable port at `649d746f` (the cold read and the rule read, both FIX) | `[X]` `tests/beef_held_entry_852.rs`, 72 cells (twelve shapes by six states): on `8729f8a5` (0.8.3) five of the six tests fail and 66 of the 72 cells, on a scratch copy of `649d746f` four of the six and the same 66 (the 0.8.5 `CHANGELOG.md` entry) | the fold decided by six design reads, 5 of 6: every verdict door refuses such an entry in the streaming reader's kind; **released in 0.8.5** with #840, the same advisory. On `beta` the doors refuse such bytes when the entry is built (#817), in no published prerelease yet |
| `Signature::from_der` ignores bytes after the sequence, takes a sequence length byte with its high bit set as a plain length, strips a leading zero the reference refuses: one signature, many byte forms | [#842](https://github.com/Calhooon/bsv-rs/issues/842) | the survey of the `fix-tx-trailing` lane (every whole-buffer reader of the crate, by name) | `[D]` read, not run as a differential at filing: the issue's table against `Signature.ts:44-99`; eight production callers named | PR [#846](https://github.com/Calhooon/bsv-rs/pull/846), **open** (lane `fix-der-strict`); its fold ports the node's lax signature parse for the interpreter (section 9). Since: **merged** as `01946931` on 2026-11-10 16:01Z; the stable port is 0.8.6's (#849) |
| `Transaction`'s `id()`, `to_binary()`, `to_hex()` answer the bytes before a hand edit of a public field until `invalidate_caches()` is called | [#843](https://github.com/Calhooon/bsv-rs/issues/843) | the captain, while answering the owner's question on #840 (the owner asked for the north-star solution of that finding) | `[X]` on beta `2c464e81`: after `tx.lock_time = 7`, `id()`, `to_binary()` (last four bytes `00 00 00 00`) and `to_hex()` are the ones before the edit; after `invalidate_caches()` the bytes end `07 00 00 00`. The adversary read's probe: a linked parent edited, `invalidate_caches()` called on the child, and the child's `id()` stayed stale (`transaction.rs:1347,1380` at PR #841's head `0a3744e2`, where the reads ran; `:1301,1334` at `2c464e81`); `PartialEq` compares `to_binary()` (`:2025` there, `:1979` at `2c464e81`); `Clone` and the JSON form carry the stale cache | the transaction's half **built on lane `break-tx-fields`** (the four fields private behind `&mut` doors, `invalidate_caches` removed, the caches `OnceLock`s; PR #869); the BEEF's fields and the typed id are its next PRs, **decided, not built**; #843 stays open |
| A transaction output of 2^53 satoshis or more is read here; the reference refuses it at every transaction reader | [#844](https://github.com/Calhooon/bsv-rs/issues/844) | the cold read of PR #841 | `[X]` one cell run on both sides: the reference throws `Number can only safely store up to 53 bits`; PR #841's head reads the amount, and the newly public `from_reader` answers `Ok` | the readers' half **landed** on lane fix-844-amount (`docs/lanes/fix-844-amount.md`): `from_binary`, `from_hex`, `from_reader`, `from_ef`, `from_hex_ef` refuse it in the reference's words, the raw-entry scan and the writers' check the same; remaining: the writer's half (`to_binary` writes a hand-built amount the readers refuse, the reference's writer refusing it), decided with the break (section 3) |
| An input's `source_txid` that is not 64 hex digits is written as 32 zero bytes; `from_json` stores one from outside text unchecked | [#845](https://github.com/Calhooon/bsv-rs/issues/845) | the API read of #843's ensemble, run by the captain on beta `2c464e81` | `[X]` `from_json` with an input `txid` of `"zz"`, `"abcd"` or `""` answers `Ok` and writes 32 zero bytes, one id for the three documents; the tie-break's reads added: that id is the null outpoint's, `is_coinbase` answers true for `""` (`transaction.rs:1738` at `0a3744e2`; the function at `:1680` at `2c464e81`), an upper-case txid writes the same bytes but misses its held parent (`beef.rs:170`) | reader half **landed** with #844 (lane fix-844-amount): `from_json` refuses an input `txid` of other than 64 hex digits, holds upper or mixed case in lower case; writer half: **decided, not built** (section 3, the tie-break); the other doors that set `source_txid` from text are rows for the captain (`docs/lanes/fix-844-amount.md`) |
| The BEEF instances: a V1 BEEF holding a txid-only entry panicked in its writer; the merge doors did not see an entry edited through `tx_mut`; a hand `txs.retain` left the index stale | [#817](https://github.com/Calhooon/bsv-rs/issues/817) (its comments) | the reads of PRs #823 and #832, and the dependents read of the second ensemble | `[X]` the panic `BeefTx has no transaction data to write` (`beef_tx.rs:417` on beta then); `merge_raw_tx` of an edited txid stored it twice | PRs [#823](https://github.com/Calhooon/bsv-rs/pull/823), [#831](https://github.com/Calhooon/bsv-rs/pull/831), [#832](https://github.com/Calhooon/bsv-rs/pull/832), [#836](https://github.com/Calhooon/bsv-rs/pull/836), **merged** on 2026-11-10; PR [#839](https://github.com/Calhooon/bsv-rs/pull/839), **open** (since: merged as `842e5cc4`, 16:27Z) |

No other pull request is linked to #840 to #845 at this record's date (`gh pr list --search '840 OR 842 OR 843 OR 844 OR 845'`: #841, merged, and #846, open; the other results of that search are older PRs that only mention those numbers). Two later instances are in section 8: #847 (an R or S past 32 bytes against the node) and #848 (an input's txid that differs from its linked source's id).

What the instances share: #840 and #842 are a reader that accepts more than the value it returns; #843 and #817's index are a derived value (a cache, an index) that outlives an edit of the fields it came from; #845 is a value whose written identity is not the one it holds; #844 is a reader that accepts a value the reference cannot hold. Each was found by a read of something else, and each found the next: the class surfaced one door at a time until the captain named it.

## 2. The two laws

These are decided. They become rules of the code (`CLAUDE.md`) with the pull requests that make them true, not before.

### FRAMING

**A reader that takes a whole buffer or a whole text consumes all of it or refuses. A reader of the front of a longer input is a separate door, named for it** (`from_reader`, the reference's `fromReader`).

What enforces it today `[X]`:
- `Beef::from_binary` refuses a byte after the frame (`TrailingBytes`, #86); `MerklePath::from_binary` the same (#167); the BEEF stream's cursor and `BlockHeader::from_binary` (exactly 80 bytes) frame themselves. The `fix-tx-trailing` lane's survey (`docs/lanes/fix-tx-trailing.md` on `origin/lane/fix-tx-trailing`) classes every whole-buffer reader of the crate by name.
- The transaction readers since PR #841 (merged, `7df16cf6`): `from_binary`, `from_hex`, `from_ef` and `from_hex_ef` consume their whole input or refuse; `from_reader` is the public prefix door.
- Not yet on beta: the DER reader (PR #846, open). `sighash::parse_transaction` still reads a prefix (section 8).

Decided, not built:
- An architecture test over **every** reader door, found by signature, not by name: any public function taking `&[u8]` or `&str` and returning `Result<Self>`, plus `FromStr`, `TryFrom<&[u8]>`, `Deserialize`, `parse_*`, `decode*`, `read_*` (four of the five #843 reads named the name-based survey as too narrow). Each door has a row: whole, or prefix by name.
- Every fuzz target asserts the round trip **through the fields**: bytes, value, fields re-serialized, the same bytes (the adversary read: a round trip through a cache that holds the input cannot fail). PR #841's fold extended `fuzz_transaction_parser` with an EF round trip (merged).
- Cells recorded from the reference for each door (the #840 recorder, `tests/support/transaction_trailing_data_840.mjs`, is the model: 30 cells; on beta since PR #841).
- A nightly differential against the reference, per reader door.
- Two refinements the reads named: a value inside a length-prefixed field consumes the whole field (#842's shape, invisible to a plus-one-byte test on the outer frame); a text reader states its canonical form (`from_hex` caches the lower-cased input, `transaction.rs:205` at `2c464e81`, `:226` at `0a3744e2`).

### IDENTITY

**A value's id is always the hash of its current fields. No caller duty.**

What enforces it today `[X]`:
- `Script` owns its chunks; every mutator clears its own caches.
- `Beef::edit_tx` re-keys an edited entry at once; the index notices a hand edit of `txs` (PR #832, merged).
- `Transaction` did **not** until lane `break-tx-fields`: its fields were public and `invalidate_caches()` was the caller's duty (`transaction.rs:806-816` at `2c464e81`; `:852-862` at `0a3744e2`, the lines #843's body cites, which are PR #841's head and not `2c464e81` as the body says; `:857-867` at `7df16cf6`; documented since 0.3.14). That is #843.
- `Transaction` does since lane `break-tx-fields` (built; PR #869): the four serialized fields are private, written only through `&mut` doors that empty the caches first (`src/transaction/transaction/fields.rs`), `invalidate_caches` removed; the law is root `CLAUDE.md` rule 14, enforced by `tests/arch_owned_fields_843.rs` (no public field on a struct that holds a cache or an index, save a list that only shrinks) and `tests/transaction_identity_843.rs` (the law as a seeded property over every door). The BEEF's half is #843's next PR.

Decided, not built:
- **The compiler, through owned fields.** A type that stores something derived from its fields owns those fields and lends them only through `&mut` doors that repair or clear the derived value (section 3, ensemble 3, Part O). While a `&mut` borrow lives no `&self` read can refill a cache, so a stale identity is a compile error, not a convention.
- **The typed id.** Text becomes a `Txid` only through a checked door, so a txid that cannot be written cannot be held (section 3, the tie-break).
- The same four test machines as FRAMING: the architecture test (no type that caches or indexes has a public field it derives from), the round trip through the fields after any edit through a public door (`id() == sha256d(to_binary())` and equal to a fresh parse's id), recorded cells, the nightly differential.

## 3. The decisions

Each was put to independent design reads, each read alone with its own lens and a bounded block (decision, confidence, rationale, residual risks); the captain counted them. The confidences are the reads' own.

### Ensemble 1: what a BEEF writer does with a state it cannot write (2026-11-10, recorded on #817)

**The rule:** a writer refuses only a state it cannot write faithfully, before any byte, and writes every other state, valid or not, as the reference writes it; in the reference's words where it refuses; where the reference writes bytes no reader reads back, this crate refuses in its own words, states the row and drafts the difference for upstream.

| Part | Decision | Count | Confidence |
|---|---|---|---|
| Round 1 (five reads: parity, dependents, adversary, API, north star; counted out of 5) | Option A: `Beef::to_binary(&mut self) -> Result<Vec<u8>>`, `to_hex -> Result<String>`, `to_writer(&self, &mut Writer) -> Result<()>`, `BeefTx::to_writer -> Result<()>`; `to_binary_atomic`'s inner panic an `Err`; the V1 txid-only state answers `a valid serialized Transaction is expected` (`BeefTx.ts:253-258`) | 5 of 5 | 0.82 to 0.85 (mean 0.84) |
| Round 2 (three reads: parity, adversary, API; each detail counted out of 3) | `merge_beef -> Result<()>`, the verdict of the reference's snapshot, the target untouched on `Err`; `MerklePath`'s writers fallible in the same cut; a version word other than V1 or V2 refused in the reference reader's sentence; a txid-only txid not 64 hex digits refused; a raw entry that is not one transaction refused | 3 of 3 on each | 0.72 to 0.85 over the questions' bounded blocks, the overall blocks 0.8 (parity), 0.82 (adversary) and 0.82 (API); the 0.72 the parity read's, on a `merge_beef` answer that also made `merge_bump`, `merge_transaction` and `merge_raw_tx` fallible (the three reads' report files, `reports-1109/design-beef-writer2-{parity,adversary,api}.md`; the range is not in #817's comments) |
| Tie-break (three reads: freeze, callers, a skeptic of fallible doors; the merge doors counted out of 6, below) | `merge_raw_tx` and `BeefTx::from_raw_tx -> Result` | 5 of 6 | |
| | `merge_txid_only` unchanged, the writer refusing `''` and non-hex | 6 of 6 | |
| | `merge_bump` (and `merge_transaction`) unchanged with a stated row | 4 of 6 (API, adversary, callers, skeptic) against 2 (parity, freeze) | |

**How the counts add up** (#817's comments of 2026-11-10 01:51Z and 02:15Z): round 1 had five reads and each part is out of 5; round 2 had three reads and each detail it settled is out of 3; the tie-break had three more reads and answered the merge doors alone, and the round 2 reads had answered the merge doors too, so each merge door is counted over the six reads of round 2 and the tie-break together ("All six reached the same rule on their own"). The tie-break is three lenses; the 6 is those three plus round 2's three.

Rejected, with the deciding fact: **B, a writer that silently upgrades to V2**: both references refuse, and the toolbox asks for V1 on purpose for ARC (`wallet.rs:1515-1521` in the toolbox), so it would be handed V2 unasked. **C, the merge doors raise the version**: the reference's keep it, and `version` and `txs` were public fields a caller sets after the merges, so the writer still meets the state. **D, a `try_to_binary` beside an infallible `to_binary`**: the door named for the reference's `toBinary` would still answer where it throws, and every existing caller would stay on it. On `merge_bump`, the split: the reference's throw there depends on what the BEEF already holds and needs a path edited after construction; an uncomputable root is a state the format carries, the readers' and `verify`'s to judge.

**Built:** PR #831 (`MerklePath` writers), PR #836 (the BEEF writers, `merge_beef`, `merge_raw_tx`, `from_raw_tx`), both merged 2026-11-10. `merge_bump` was built unchanged, the majority's default; the root `CLAUDE.md` row says it was put to the owner on 2026-11-10.

### Ensemble 2: the BEEF's mutation model (2026-11-10, recorded on #817)

PR #832, as opened, ported the reference's lazy repair (a refresh at every door, a process-wide edit epoch, a snapshot of the reference's txid-to-BUMP map). Two rounds of reads found new cells every time, two of them quadratic: `find_txid` per entry at 20,000 entries went from 7.4 ms to 1,070 ms; after one edit, 5,000 lookups from 1.6 ms to 16.5 s. The captain stopped folding and put the design to five lenses.

| Part | Decision | Count | Confidence |
|---|---|---|---|
| The BUMP an entry names | the last BUMP in `bumps` holding the txid, read live, a function of `bumps` alone; the reference's history-dependent map cells stated and drafted upstream | 5 of 5 | 0.70 to 0.85 |
| The lazy repair | rejected | 5 of 5 | |
| `Beef::edit_tx`, an eager door, additive | built | 5 of 5 (one lens preferred a guard on `find_txid_mut`) | 0.75 to 0.80 |
| `BeefTx::tx_mut` | deprecated | 5 of 5 | |
| The index noticing a hand edit of `txs` | built (the dependents lens found the toolbox's hand `txs.retain`) | the finding of one lens | |
| How far `Beef` owns `txs` | keep `pub txs` with `edit_tx` and `reindex()` | 3 of 5 (parity, adversary, API) against 2 (dependents, north star) | |

Rejected: **E1, the lazy repair**: correct `&self` lookups need a full rebuild per lookup (the 16.5 s above) or caches behind `&self` and a process-wide atomic linking unrelated BEEFs. **A guard that repairs on drop**: `mem::forget` in safe code skips the repair. **The reference's map with its lifetime**: equal bytes give two `find_bump` answers depending on whether a snapshot was ever taken.

**What stands:** `edit_tx` and the live BUMP rule (PR #832, merged). **What ensemble 3 replaced:** `pub txs` (now decided private), `tx_mut` (deprecated; now decided removed), `reindex` (now decided removed: with `txs` private there is nothing to repair). Those three are **decided, not built**.

### Ensemble 3: how a `Transaction` keeps `id()` true (#843, 2026-11-10 13:3xZ)

Five reads (reference parity, the dependents, the adversary, the API at the stable cut, the north star), each at `0a3744e2` on beta `2c464e81`, none seeing another.

| Part | Decision | Count | Confidence |
|---|---|---|---|
| I | **I2: the type owns its four serialized fields** | 5 of 5 | 0.80 to 0.85 |
| I, the timing | one cut on the next beta, no deprecated-field stage | 4 of 5 (the north star read: stage it) | |
| O | **the ownership rule** (below) | 5 of 5 | 0.75 to 0.80 |
| O, `Beef.bumps` | private, with `retain_bumps` and `edit_bump` that re-point the entries | 4 of 5 (the parity read: public, the BUMP index is read live) | |
| S | **S1**, the stable line (section 6) | 5 of 5 | 0.80 |

**I2, with the signatures the five reads wrote:** `version`, `inputs`, `outputs`, `lock_time` private; `version()`, `lock_time()`, `inputs() -> &[TransactionInput]`, `outputs() -> &[TransactionOutput]`; `set_version`, `set_lock_time`, `inputs_mut() -> &mut Vec<TransactionInput>`, `outputs_mut() -> &mut Vec<TransactionOutput>`, each clearing the caches before it lends; `from_parts`, `into_parts`; `invalidate_caches` removed; `metadata`, `merkle_path` and every field of `TransactionInput` and `TransactionOutput` stay public. The reads differed in detail, for the implementing PR to settle under its own reads: `into_parts` returning a tuple or a `TransactionParts` struct (parity); a `parts_mut()` for split borrows (adversary); `set_*` returning `&mut Self` (API); the caches as `OnceLock`, which the two reads said makes `Transaction` `Sync` (adversary, API; reasoned, not compiled; it does not alone: `Script` holds its chunks and caches in `RefCell`s, `src/script/script.rs:22-30`, and every input and output holds a `Script`, so `Transaction` stays `!Sync` until `Script` changes too).

**Why it is sound:** every cache refill takes `&self`; the borrow checker forbids that while a door's `&mut` lives; a linked source transaction is reachable mutably only through its child's `inputs_mut()`, which has already cleared the child.

**O, the rule:** a type that stores something derived from its fields (a cache, an index, a position another field points at) owns those fields and lends them only through `&mut` doors that repair or clear the derived value; a field nothing is derived from stays public and its fallible door judges it. Applied: `Transaction` as above; `Beef.txs` private (5 of 5), `bumps` private (4 of 5), `version` and `atomic_txid` public; `BeefTx.input_txids` and `is_valid` read-only; `tx_mut` removed; `MerklePath`, `Script`, `TransactionInput`, `TransactionOutput` unchanged (`MerklePath` stores nothing derived; `Script` already owns its chunks; the input and output types store nothing and are reachable mutably only through their owner's door).

Rejected, with the deciding fact:
- **I1, the reference's way** (fields public, the cache checked against a captured state at every read, `Transaction.ts:610-690,1097-1103`). The parity read's probe at the pin: the reference notices 14 of 15 edit cells (the 15th is its own `fromBinaryView` buffer alias, which this crate cannot reach). It can because JavaScript compares object identity: its captured state holds each input's and output's object reference, with each script's bytes compared chunk by chunk (`Script.ts:17-19,512-537`); the parity read measured a warm `id()` there at 45 µs with 10,000 outputs (Node 22.18.0). Rust has no object identity, so the same check compares every field and every script's bytes: the API read measured `id()` at 10,000 inputs (1,650,014 bytes) at **1.98 ms recomputed against 93 ns cached** (sha256d alone 0.51 ms; rebuilding the bytes about 1.47 ms), so a check costs about one serialization per read, and it recurses through every linked source, which makes the linear-time walks quadratic.
- **I3, no cache on an editable value**: the same 1.98 ms per `id()`, and the serializer reads `source.id()` per input without a txid, so a chain of unproven links returns to the quadratic hashing a 0.3 release removed.
- **I4, today's contract, stated**: wrong even when obeyed (the adversary's probe above); the cache copied by `Clone` is a stale read the compiler cannot see.
- **A `DerefMut` to a plain fields struct** (the API read considered it): breaks the guideline that only smart pointers implement `Deref`, and two-phase borrows.
- **Staging through deprecated public fields**: keeps the stale window open while the dependents migrate once anyway.
- **`pub txs` with a repair door (the 3-of-5 of ensemble 2)**: it keeps the window #817 states; with #843 on the table all five reads chose the owning type.

**The cost, measured by compiling the dependents against a scratch copy with the fields private** (the dependents read): toolbox library 75 sites for `Transaction` and `Beef` (79 with `MerklePath.path`; 367 with its unit tests), overlay engine library 36 (37 with `MerklePath.path`); about 100 more production sites by grep in three crates not compiled. Nearly all are reads, a one-token edit, and the compiler finds every one.

**The reach, as read:** after #841 wire bytes alone cannot reach a stale cache (a parsed transaction's fields serialize back to exactly its bytes); every instance needs a caller's own edit; the sighash reads fields only (`sighash.rs:257-274`), so no signature or spend is affected. The dependents read found no live instance in production and all 12 `invalidate_caches` calls in test code.

**Part I built on lane `break-tx-fields`** (PR #869), with the details left to it settled by the captain's brief: `into_parts`/`from_parts` take a `TransactionParts` of four named fields, not a tuple (two `u32`s cannot be swapped silently); the setters return `()` (not a builder; `()` can become `&mut Self` later without a break, never the reverse); `parts_mut()` lends the four fields at once as `TransactionPartsMut`; the caches are `OnceLock`s, but `Transaction` stays `!Sync` (the `Script` it holds is its own later PR, `src/script/script.rs` untouched); the debug check of a cache hit against a fresh serialization was measured and left out (it moved `tests/beef_deep_chain.rs` from 7.4 s to 8.8 s, a pin; `docs/lanes/break-tx-fields.md`). After its three reads, PR #869's fold (lane `break-tx-fields-fold`, on the captain's rulings) settled two more: the parts are lossless, `TransactionParts` carrying the six fields (the four, `metadata`, `merkle_path`) and deriving `Default`, not `#[non_exhaustive]`, `TransactionPartsMut` lending the six, so `from_parts(tx.into_parts())` is `tx` in every field (the rule read's FIX: the four-field parts lost a merkle proof with `==` still true); and the four fields and the three caches live in `Fields`, a struct private to `fields.rs`, so the compiler refuses a write past a door from the module's own code (the strength read's machine), the textual guard re-pointed to `fields.rs` alone; the test door `with_cached_bytes_for_test` behind the internal `internal-test-doors` feature (it was public in any crate's cargo-fuzz build); the law a fuzz invariant of `fuzz_transaction_parser` and `fuzz_beef_parser`; the property's reach counted with floors. **Part O:** its architecture test is built with Part I (the BEEF rows listed as #843's next PR); `Beef` and `BeefTx` themselves are **decided, not built**. **The owner's word:** given (section 4).

### The tie-break: the typed id (#845, 2026-11-10)

Three reads (the API at the freeze, the callers, the skeptic). **T1, 3 of 3** (0.80, 0.75, 0.80).

`pub struct Txid([u8; 32])` in wire order (as `Transaction::hash()`, the outpoint on the wire, Go's `chainhash`); text enters only through `Txid::from_hex` and `FromStr` (exactly 64 hex digits, either case, no trim) and leaves as lower-case display hex; the byte doors name their order (`from_wire_bytes`, `as_wire_bytes`, `from_display_bytes`, `to_display_bytes`) and there is no `From<[u8; 32]>`; `TransactionInput::source_txid: Option<Txid>`, the input's fields public; `TransactionInput::new(Txid, u32)`; `Transaction::txid() -> Txid` beside `id() -> String`; `from_json` refuses a txid that is not 64 hex digits; the `Beef` doors that take a txid take a `Txid` in the same cut as the private `txs`. The reads differed in detail, for the implementing PR to settle: the byte doors' names are the freeze's and the skeptic's (the callers read wrote `from_bytes` and `as_bytes` for the wire order); the callers read also typed `Utxo.txid` and had `is_coinbase` read `is_null()`; the freeze read asked the owner for a second word on replacing the wallet's display-order `TxId` alias in the same break, which a second tie-break answered after this record was written (W1, section 9).

**The one fact that decided it:** the reference's string is safe because its writer throws (`requireTXID`, `Transaction.ts:95-100`, called at `:1070`: `sourceTXID must be a 32-byte hexadecimal transaction ID.`), and this crate's `to_binary` cannot throw, so the check moves to where the value is built.

Rejected: **T2, typed everywhere now**: every witnessed cell enters through a door that takes text; typing the returns breaks about 860 `.id()` sites by grep (a count that includes other types' `id()`) and closes no cell. **T3, text behind a checked door**: `TransactionInput::new(String)` cannot fail, so a checked T3 changes `new` anyway, loses the struct literal (about 46 sites by the callers read's grep, 64 in two dependents by the skeptic's) and keeps the text `Beef` compares as text. **T4, text kept public**: `"zz"` still writes the null outpoint silently. **A required `source_txid: Txid`**: it captures the txid when the input is built, so a child linked to an unsigned parent would spend the parent's stale txid after the parent is signed.

The callers read measured T1's break with `cargo check --lib`: this crate compiles after 21 edits; the toolbox library gains 3 sites, the overlay engine library 4 errors at 3 sites (T3 breaks the same sites). Facts the reads added: Go holds a typed wire-order hash but its text reader zero-pads a short text (`chainhash/hash.go:128-157`), so it accepts `"abcd"` and `""`: it is not the strict twin #845's body assumed.

**Decided, not built.**

## 4. The owner's words

Quoted verbatim, with their spelling, from #843's comment of 2026-11-10 14:10Z ("The owner's words of 2026-11-10 that this issue's decisions rest on"), given to the captain in its session; times in UTC, to the ten minutes:

- Before 08:1xZ: "you can do as many rounds as you need.. we in no rush.. we love soundness"
- Before 08:1xZ: "and for choices.. they need to be god tier and north star deciosn"
- 13:1xZ, of the captain's report of #840 (the question that started this record): "what is god tier nrothstar soltuion for this?"
- 13:4xZ, after the captain handed him three open decisions: "what is god tier and north star? we hate shortcuts... what is your reccomendiaotn for this stuff? godtier north star"
- 13:5xZ, to the one recommendation (#843's comment of 13:56Z: the break in one cut before beta.8; the typed id subject to the tie-break; 0.8.4 and 0.8.5 on the stable line; an advisory on GitHub and RustSec the day each patch is on crates.io, no yank; private vulnerability reporting turned on; both laws in CI and a nightly differential; beta.8 only when all of it is in): "okay I agree with all of it man... and I iaminge future captains need this info etc..."

Quoted verbatim, with their spelling, from #843's comment of 2026-11-10 14:34Z ("More of the owner's words of 2026-11-10, verbatim, and what was decided on them"); times in UTC, to the ten minutes:

- 14:1xZ: "what is god tier and north star for what I need to decide on? think god tier and the ecosystem and standards etc"
- 14:1xZ, of PR #846's reads: "and this seems bad? The signature fix moved a consensus verdict away from the node"
- 14:2xZ: "gosdk and tssdk both have a security thing.. weve filed stuff there before.. we need god tier north star decions and reccomendtaios...."
- 14:2xZ: "and you have all the green lights for the upstream stuff too"

What was decided on these is section 9.

#817's comment of 2026-11-10 01:51Z cites the second as "his word of 2026-11-10 that a choice be the north-star one".
Two older words the decisions rest on, as the issues cite them: the owner's ruling of 2026-10-26 that a public change outside the reference's shape on the 0.9.0 line is his word (#817, #845's reads); his word of 2026-11-04 that the reference's behaviour is the port's unless the north star is indifferent (#844).

## 5. The order of the build

The present order, from #843's comments of 2026-11-10 13:56Z and 14:34Z (section 9 holds the decisions of the second):

1. #841, the reader fix of #840: **merged** (`7df16cf6`, 14:16Z). Then #839, #842's PR #846 with its fold (the node's lax signature parse for the interpreter, which also closes #847), and #844 with #845's reader half.
2. The node's oracle a required check before the cut (#97: the script-lean corpus on every pull request that touches script or signature parsing).
3. #843's three PRs, each with three reads: the transaction owns its fields (**built on lane `break-tx-fields`**, the `OnceLock` caches in `Transaction` with it; `Script`'s `OnceLock` caches and `Script::chunks()` lending a slice left to a PR of their own); the BEEF owns `txs` and `bumps`; one transaction id type for the whole crate, the wallet included (W1).
4. The API read's other breaks before the freeze: `#[non_exhaustive]` on the 44 enums and the 30 config and parameter structs (with constructors), the duplicate wallet types unified, `num_bigint::BigInt` and the `futures_channel` receiver out of public signatures, the serde helper modules private (the API read files these as their own break PRs); `Debug` that never prints a secret.
5. The laws in CI and the nightly differential.
6. Then beta.8.

Beside the line: the stable patches 0.8.4 and 0.8.5 (section 6, #849), and the upstream work (section 10).

What each PR must carry:
- **RED from the probes.** The probes in the issues (#840's 275-plus-four, #843's `lock_time = 7` table and the adversary's linked-parent cell, #845's three documents and the case split) become tests that fail on the base and pass on the PR (rule 2: a scratch copy, never a checkout of a dirty tree). For the ownership PRs the stale read is a compile error, so the RED is the probe on the base and a compile-fail or a property test on the tip (random edits through the doors, then `id()` equals `sha256d(to_binary())` and a fresh parse's id).
- **The migration line a dependent reads**, in the CHANGELOG entry (rule 9). The reads wrote it: `tx.inputs` becomes `tx.inputs()`; `tx.inputs.push(x)` becomes `tx.inputs_mut().push(x)`; `tx.lock_time = n` becomes `tx.set_lock_time(n)`; delete every `invalidate_caches()`; `beef.txs.retain(f)` becomes `beef.retain_txs(f)`; `TransactionInput::new(s, i)` becomes `TransactionInput::new(s.parse()?, i)`.
- The divergence rows each change moves, and the reference cells recorded.

## 6. The stable line

`RELEASING.md`'s direction rule admits a main commit in four classes only; #840 enters as a security advisory (a RustSec entry against this crate). The path, as S1 (5 of 5) and the owner's agreement give it, written as a procedure in `RELEASING.md` step 23 (#840's findings were public before rule 12 and follow step 23's older order, which it names):

1. #841 lands on beta with its test: **done**, `7df16cf6` on 2026-11-10 14:16Z.
2. `git cherry-pick -x` of it onto a branch from `main`, its RED shown on main (main's tip `8729f8a5` carries the defect by the captain's run), and its reads.
3. The release commit (`Cargo.toml` 0.8.4 and the CHANGELOG heading), the tag, `release.yml`.
4. A GitHub security advisory drafted before the tag and published, with a CVE requested and a RustSec entry (both feed OSV), the day the version is on crates.io: patched in 0.8.4 (`>=0.8.4, <0.9.0-0`) and in the next beta prerelease that carries the fix; every published `0.9.0-beta.N` before it is affected too (it orders above 0.8.4, so "affected below 0.8.4" would omit the betas the toolbox's and the CLI's beta lines pin). No yank: every version back to `v0.3.1` very likely carries the reader, and a yank reaches no lockfile and leaves a build with nothing to resolve to (root rule 9, `RELEASING.md` step 9).
5. 0.8.5 the same way with #842's fix and #845's reader half.

The tracker of both patches is [#849](https://github.com/Calhooon/bsv-rs/issues/849).

**As it happened (2026-11-10, times UTC; the list above is the plan as written and stays):**

- Step 2 was PR [#852](https://github.com/Calhooon/bsv-rs/pull/852) on `main` (`ed2789fb`, 18:47Z). Its reads at `649d746f` found the held entry (section 1's #852 row), and its fold, decided by six design reads (5 of 6), went into the same patch.
- **RED on `main` before the fix**, by PR #852's own body (`gh pr view 852 --json body`): "RED on main: 5 of 15 of the test file on a scratch copy of 8729f8a5 with `from_reader` made public, the same five as beta's base", and for the held entry's table "66 cells RED on 8729f8a5 and 66 on the port as first built" (`8729f8a5` is `main`'s tip at 0.8.3).
- **The advisory was drafted at 18:35:19Z** (its `created_at`, `gh api repos/Calhooon/bsv-rs/security-advisories/GHSA-j8hr-pjhm-6h27`), twelve minutes before PR #852 merged at 18:47:11Z.
- **0.8.4 was tagged and never published.** The release commit, PR [#858](https://github.com/Calhooon/bsv-rs/pull/858), failed `ratchet` on its pull request's run: the tool's lock recorded the crate's own version, and a release commit is `Cargo.toml` and `CHANGELOG.md` alone. The tool was fixed by PR #859 on `beta` (`9a111843`), picked as PR #860 on `main` (`5dae3f4c`). The release commit then landed as `9caa38b4` and was tagged `v0.8.4`. The captain cancelled its release run (42889201476) before the publish step, at 20:01Z, because one entry under the new heading described code `main` does not have: `### Changed ... (#258)` and its parity note, carried into main's changelog by `c014150e`, a CI cherry-pick of 2026-10-26 that brought changelog lines without their code. An audit of every heading under the section found two false (both #258's). Corrected by PR #861 on `beta` (`78bd301e`) and PR #862 on `main` (`bae13711`). The tag stays: the ruleset `v* tags: no deletion` forbids deleting it, so the next patch number shipped, and both changelogs carry a `## [0.8.4]` paragraph saying it was tagged and never published (`RELEASING.md` steps 3 and 8 now carry both lessons).
- **0.8.5** (#840's reader fix and #852's held entry): release commit PR #863 on `main` (`a8186851`), tagged `v0.8.5` at 20:35:44Z, release run 42896848824 green (38 jobs succeeded, 3 skipped), on crates.io at 20:51:59Z, linked on `beta` by PR #864 (`7ab65f65`).
- **The advisory** [GHSA-j8hr-pjhm-6h27](https://github.com/Calhooon/bsv-rs/security/advisories/GHSA-j8hr-pjhm-6h27), published at 20:53:11Z: affected `< 0.8.5` (patched in 0.8.5) and `>= 0.9.0-beta.1, <= 0.9.0-beta.7` (no patched prerelease yet), where step 4 above wrote `>=0.8.4`; a CVE requested, none assigned when this was written. Corrected three times that evening, each correction dated inside it: at 20:58Z, one leg of the workaround (comparing `to_binary().len()` with the input's length) always passes on an affected version, found by running it on published versions; at 21:25Z, every behavioural sentence was run on the crates as crates.io serves them: by the advisory's own corrections section one sentence was partly wrong (`to_binary_atomic` does return a `Result`) and one false (the 0.9.0 line's refusal at the entry is the unreleased `beta` branch's, not a published prerelease's), and six omissions were added (`from_json`, the cut-lock-time case of `parse_script_offsets`, three doors that hand back the entry's transaction, the case with no BUMP and no parent, the EF readers' error text, a workaround for 0.2.0 to 0.3.15); at 21:32Z, the severity raised from 5.9 to 7.5 (`CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N`) after three independent reads, 3 of 3, of the CVSS 3.1 user guide's section 3.7 (a library scored for its reasonable worst-case use). Its correction note's count was then reworded once, at 21:42Z. The ranges held under a sweep of all 60 published versions. Nothing was yanked.
- **RustSec:** [rustsec/advisory-db#3539](https://github.com/rustsec/advisory-db/pull/3539), opened 21:32Z, open when this was written; its file's `patched` is `[">= 0.8.5, < 0.9.0-beta.1"]`, and a prerelease carrying the fix is added by a second pull request there (`RELEASING.md` step 23 (f)(iv), step 14).
- **The dependents** were read from crates.io's reverse-dependency list after the publication (13 crates, `docs/DEPENDENTS.md`, "The ledger on crates.io"); a read of their published sources was made the same evening, and its result is each keeper's, privately (`RELEASING.md` step 23 (g)).
- **Next on the stable line: 0.8.6**, holding #842's port and #845's reader half (where step 5 above named 0.8.5), tracked by #849.

**Ported:** #840 (with `Transaction::from_reader` public, an additive migration door), #842, the reader half of #845. **Not ported:** the break (Parts I and O, the typed id): a public shape change is not one of the four classes. #844 is not named for the stable line in the owner's agreement.

**The dependents' pins**, as the dependents read measured them at their live tips (`git archive`, 2026-11-10; `design-identity-dependents.md`). This table is that day's reading, kept for the decision it informed; the current pins are the ledger's, [`docs/DEPENDENTS.md`](../DEPENDENTS.md), which the captain refreshes before every release by its own pull request on `beta` (`RELEASING.md` step 3). Read the ledger, not this table:

| Dependent | Ref read | Requirement | Does a 0.8 patch reach it? |
|---|---|---|---|
| bsv-wallet-toolbox-rs | `origin/main` | `^0.8.0` (resolves 0.8.3) | yes, on `cargo update -p bsv-rs` |
| bsv-wallet-toolbox-rs | `origin/beta` `184c4182` | `=0.9.0-beta.7` | no: the beta line, which gets the fix on beta |
| bsv-wallet-cli | `origin/main` | `=0.8.3` | no: an exact pin; a pin edit to `=0.8.4` |
| bsv-wallet-cli | `origin/beta` `3be1401` | `=0.9.0-beta.6` | no: the beta line |
| bsv-overlay-cloudflare | `origin/main` `2efad2f0` | `=0.7.2` (root and `workers/`; its registry dependencies middleware-core 0.4.0, middleware-cloudflare 0.7.1 and tracker 0.7.0 pin `0.7.2` too) | no: the whole graph must move to the 0.8 line; its main workspace builds against `v0.8.3` with no errors |
| rust-message-box | `origin/main` `44a6320` | `=0.6.0` | no |
| bsv-middleware-rs | `origin/main` `5a1fd27` | `^0.8.0` | yes, on `cargo update` |
| chaintracks-cloudflare | `origin/main` `af5a480` | `^0.8.1`, `block` only | yes, and unaffected by #840 |

The overlay's own sites and any stop-gap there are the overlay captain's, handed over privately (rule 12). Withdrawing the site table from `docs/lanes/fix-tx-trailing.md` at this record's tip does not unpublish it. The overlay's captain was told the sites privately on 2026-11-10 and answered that its stores hold no affected row.

## 7. How to work a finding here

The method this class taught, for the next captain:

1. **Name the invariant the instance broke**, not the door. #840 was not "`from_binary` is wrong"; it was "a whole reader consumed less than its input".
2. **In the same turn, look for the siblings by a run:** every door of the same shape (the survey that found #842), the stable line (main's tip carried #840), and the reference's mechanism at the pin (how `fromBinary` refuses; how the reference keeps its cache true, read at the pin for #843).
3. **Ask the four questions a survey of same-shape doors does not.** Applied to #840 as first reported, steps 1 and 2 reach #842 and the stable line and nothing else; the strength read of this record found that these four would have reached #843 to #848:
   - **What derives an identity from this value, and how can the two drift?** An edit after the identity was computed (#843, #817's index); two fields that name one thing (#848: an input's txid and its linked source's id).
   - **For every door that builds a value from text or bytes, does the writer write back exactly what the reader held?** A round trip through the fields, not through a cache that holds the input (#845: `"zz"` read, 32 zero bytes written).
   - **For every field, where is its domain's edge, in the reference and at the node?** A length byte at `0x7f` and `0x80`, an integer of zero, an amount at 2^53 (#844), an R or S past 32 bytes (#847).
   - **Which oracle judges this code, and was it run before the lane reported?** For anything that touches script or signature parsing, the node through the script-lean corpus: PR #846 passed its lane's whole gate while moving a consensus verdict away from the node, and a reader who ran that corpus saw it (`crypto-00035`, `crypto-00077`; #97 makes it a required check).
4. **Fix the class by a machine, not the door alone:** a type the compiler holds, an architecture test that finds every door by signature, a fuzz invariant, recorded cells, a nightly differential. A door fixed alone is the next finding's sibling.
5. **A choice with a public, wire or verdict consequence goes to independent design reads**, three to five, each with a distinct lens (reference parity, the dependents, the adversary, the API at the freeze, the north star; a skeptic or the callers for a tie-break) and a bounded block. Count them. A split goes to a tie-break, not to the owner as a list.
6. **Give the owner ONE recommendation**, with the count, the rejected options and the fact that decided each.
7. **Say plainly what was measured and what was only read.** `[X]` and `[D]`; a read of the reference is not a run of it.
8. **Correct a number the moment a measurement replaces a grep.** The dependents' counts in this record are compile-error counts where a compile was run, and are said to be grep counts where not.

## 8. What is still open

| Item | Issue |
|---|---|
| #843's three PRs: the transaction owns its fields (**built on lane `break-tx-fields`**); the BEEF owns `txs` and `bumps`; the one id type, the wallet included | #843, #845 |
| `Script`'s caches as `OnceLock`s and `Script::chunks()` lending a slice, so that `Transaction` becomes `Sync` (left out of the transaction's PR by its brief) | #843 |
| The writer's 2^53 refusal (the readers' half landed with #844's lane) | #844, #843 |
| The wallet's `TxId` alias (`wallet/types.rs:161`), a bare `[u8; 32]` in display order beside the wire-order `Txid` decided above (named by the T1 reads) | **decided, not built**: W1, 3 of 3, after this record was written (section 9); built in #843's third PR |
| The reference refuses at sign and at verify an input whose txid differs from its linked source's id (`Transaction.ts:973-983`, `:1424-1432`, `:2164-2169`); this crate has no such check | [#848](https://github.com/Calhooon/bsv-rs/issues/848) (filed in the open, 2026-11-10 13:59Z) |
| An input with neither a txid nor a source transaction (`TransactionInput::default()`) is written as 32 zero bytes where the reference throws; `add_input` refuses it, a struct literal or `inputs_mut()` reaches it under any txid type | to be filed, or stated as a row (named on #845) |
| `from_json` ignores members that contradict `hex` (`tx_json.rs:116-126`) | to be filed (named on #843) |
| `sighash::parse_transaction` reads a prefix (`fix-tx-trailing`'s survey; after-cut by the rule read) | to be filed |
| An R or S past 32 bytes: refused here after the strip, a `BigNumber` of any length in the reference (#842's table); under a word the node's lax parse decides, so the interpreter against the node needs its own cells | [#847](https://github.com/Calhooon/bsv-rs/issues/847) (filed in the open, 2026-11-10 13:59Z); **decided, not built**: closed by PR #846's fold, the node's lax signature parse for the interpreter (section 9) |
| `BeefTx`'s stored `bump_index` against the live rule of ensemble 2 | to be filed (named on #843) |
| Private vulnerability reporting on this repository's Security tab (`SECURITY.md` describes it) | **done**: off when this record was written, turned on by the owner at 14:1xZ (`gh api repos/Calhooon/bsv-rs/private-vulnerability-reporting --jq .enabled` answers `true`, read 2026-11-10) |
| The stable patch 0.8.6: #842's port and #845's reader half, with its advisory | [#849](https://github.com/Calhooon/bsv-rs/issues/849) (0.8.5 released 2026-11-10, section 6) |
| GHSA-j8hr-pjhm-6h27's prerelease end: the next `0.9.0-beta.N` that carries #840's fix added to the advisory's patched versions and, by a second pull request, to the RustSec file (`RELEASING.md` step 14) | open; the RustSec entry itself is [rustsec/advisory-db#3539](https://github.com/rustsec/advisory-db/pull/3539), open on 2026-11-10; the CVE requested, none assigned on 2026-11-10 |

From this record on, an item of this list that a peer's bytes or text can reach while a published line carries it is worked off the public repository until its patch can be released in the same sitting: a draft security advisory, a fix and its `main` port built and read on the advisory's private fork, then in one sitting the public pull requests (the fix on `beta`, then the `cherry-pick -x` of `beta`'s commit on `main`), the release and the publication (`CLAUDE.md` rule 12, `RELEASING.md` step 23, `SECURITY.md`). The findings of 2026-11-10 (#840, #842, #844, #845, #847, #848) were public before that rule existed and follow the older order; #849 tracks their stable patches.

## 9. What was decided after this record was written

On the owner's words of 14:1xZ and 14:2xZ (section 4), recorded on #843's comment of 2026-11-10 14:34Z, each the captain's recommendation by the ecosystem's standard. **Decided, not built**, all of it.

1. **One transaction id type for the whole crate, the wallet included (W1).** A second tie-break of three reads (the freeze, the callers, the skeptic; `reports-1109/design-walletid-{freeze,callers,skeptic}.md`): **W1, 3 of 3** (0.85, 0.82, 0.82). The wallet's `TxId` alias (a bare `[u8; 32]` in display order, `wallet/types.rs:161`) goes; `Outpoint` and every wallet type hold `Txid` (wire order inside); the wallet wire and the certificate binary convert at their codec through one private `write_txid`/`read_txid` pair, the display order being the wallet wire's own (the reference writes the decoded hex unreversed, and BRC-100 names no order). Measured by the callers read with a compile: 58 sites in this crate's library, 24 in the toolbox's (11 of them one token). Rejected: **W2, keep the alias** (once `Txid` lands, `Outpoint::new(*t.as_wire_bytes(), v)` type-checks and is byte-reversed); **W3, two newtypes, one per order** (a txid is one identity and the order belongs to an encoding; no measured site keeps a display-order id as a value). What rust-bitcoin and go-sdk already do (Go: one `chainhash.Hash`, reversed at the outpoint codec, `wallet/serializer/serializer.go:20-25,82-94` at `2ca481c`). Built in #843's third PR.
2. **The public surface audited against the Rust API Guidelines before the freeze** (one read of all 54 items over 303 structs, 69 enums, 1,425 methods at beta `7df16cf6`; `reports-1109/audit-api-guidelines.md`; 0.78). Seven breaks in the same window as #843's: (1) the one id type above; (2) `#[non_exhaustive]` on 44 enums that will grow; (3) the same on 30 config and parameter structs, with constructors; (4) the duplicate wallet types unified; (5) `num_bigint::BigInt` and a `futures_channel` receiver out of public signatures; (6) `Script::chunks()` lending a slice; (7) the serde helper modules private. Additive and taken with them: **`OnceLock` caches in `Script` and `Transaction`**, so that `Transaction`, `Script` and `Beef` are `Sync` and a future that awaits `tx.verify(..)` is `Send` (the read's probes: today it cannot be spawned on tokio, and `Arc<Transaction>` is not `Send`); `Debug` that never prints a secret. (1) and (6) and the `OnceLock` change ride inside #843's own PRs.
3. **The node's oracle a required check before the cut** (#97: the sibling harness, the script-lean corpus, on every pull request that touches script or signature parsing). PR #846 passed its lane's whole gate while moving a consensus verdict away from the node; a reader who ran the corpus saw it (`crypto-00035`, `crypto-00077`).
4. **The lax-parser fold of #846 and #847.** The fold of PR #846 ports the node's lax signature parse for the interpreter, which also closes #847.
5. **The advisories** for this crate: a GitHub advisory with a CVE requested, and a RustSec entry; both feed OSV (section 6, `RELEASING.md` step 23).

## 10. Upstream

- **The channels.** GitHub's private vulnerability reporting is on for `bsv-blockchain/go-sdk` and `bsv-blockchain/ts-stack`, and the owner's account has reported there before.
- **What goes privately, what publicly.** A defect a peer's bytes can reach in a published upstream release goes to that upstream's private channel; the rest goes to the public queue (`docs/lanes/375-filings/QUEUE.md`), each row classed public or private before it is filed (below).
- **Sent.** As of 2026-11-10 15:1xZ, sent that day under the owner's word: two public issues on ts-stack (#1537, #1538), one private report to ts-stack and two to go-sdk (the go-sdk two after a run at its master); the private reports' content stays in those channels until their upstreams publish. The go-sdk rows of the public queue wait for a run at go-sdk's head. Later the same day, after a run at go-sdk's master: two public issues on go-sdk ([#417](https://github.com/bsv-blockchain/go-sdk/issues/417), [#418](https://github.com/bsv-blockchain/go-sdk/issues/418), 20:59Z) and a comment on its #401 (20:59Z); the private reports of the day came to two to ts-stack and five to go-sdk, and one more to go-sdk is held by GitHub's daily limit of five reports to a repository. Their ids and subjects stay in those channels.
- **The queue before the cadence resumes.** The public queue's rows 26 to 63 are being verified against the upstreams' current heads, each row classed public or private, before any more are filed.
- **Then:** this crate's recorded vectors offered to the shared conformance corpus, and clarifications proposed to the BRCs where their silence let three SDKs disagree (exact framing; strict DER outside script; the text form of a transaction id).

## 11. The reads of this record

PR #850 was read on 2026-11-10; the fold took the rule read's and the strength read's REPORTs. The rule read (FIX, 0.8) corrected the round 2 confidences, the byte-door names, beta's line numbers and rule 11's history, and quoted the owner's words verbatim with their times; the strength read (FIX, 0.8) named #847, #848 and #849, the betas in the advisory's range, the `Sync` claim, the commit the `src/` citations name, and withdrew the record's pointer at a downstream's sites. Both found three of the record's rules against the release steps (rule 12 against step 23, the yank against step 9, `SECURITY.md` before private reporting was on) and a stale ledger. The captain decided each: rule 12 and step 23 rewritten to one order (the fix built off the public repository, released within the hour of its public pull requests, made the same sitting by the fold below); the yank sentence in rule 9 and step 9; `SECURITY.md` lands with reporting on; `docs/DEPENDENTS.md`'s pin table refreshed and its refresh a duty of every release (step 3); this record's keeper line, the counts of ensemble 1, the owner's later words, section 9, section 10 and the four questions of section 7, step 3; the downstream's sites withdrawn from `docs/lanes/fix-tx-trailing.md` too. Documents only: no source, test or vector moved.

The fold's own reads (2026-11-10): the rule re-read of `33bd08c5` (FIX, 0.8) found the record traced to its sources save one build-order drift (the serde helper modules, moved back to the API read's own breaks by its commit `720ef349`, which also withdrew a line of `docs/lanes/fix-tx-trailing.md` that named a downstream's site to a count), and two steps of `RELEASING.md` that told a captain two different things. The captain decided both. The ledger refresh is not in the release commit (step 17, and `beta-born` admits `Cargo.toml` and `CHANGELOG.md` alone on `main`): it lands before the release pull request, by its own pull request on `beta`, and the release cites its date (step 3; step 23 points at it). Step 23 has one pick source, `beta`'s commit: the fix and its `main` port are built and read on the private fork, the fix lands on `beta` by its public pull request, and the `main` pull request is the `cherry-pick -x` of that `beta` commit, the patch the reads judged, re-made so its `-x` line names a commit `beta` carries. "Within the hour" became "in the same sitting" in step 23, rule 12, `SECURITY.md` and section 8, since the two public CI runs are part of it. Ensemble 1's round 2 range now cites the three reads' report files, where it stands (it is not in #817's comments); section 10 names what was sent upstream that day; section 6 says that withdrawing the downstream's sites does not unpublish them. Documents only.
