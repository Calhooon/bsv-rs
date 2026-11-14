# Lane fix-wallet-buckets: the bucket issues #819 and #908, every line answered

The two wallet buckets (#819, the reads of 2026-11-09; #908, the reads of
pull request #896 on 2026-11-12), seven lines, nobody's until this lane.
Started from beta `2b419d90` (`origin/beta`'s tip at the start and at the
gate). No file under `src/` changed.

## The table

| Bucket, line | Fate | Evidence |
|---|---|---|
| #819, 1: an on-chain abort refusal framed as code 1 where the reference answers `aborted: false` (code 8) | NEEDS A DECISION (question 1) | The two sides by a run, below. Nothing built: either way changes a wire answer or is the toolbox's change |
| #819, 2: the abort kind is unreachable behind a substrate | NEEDS A DECISION (question 2) | Stated at `src/wallet/wire/CLAUDE.md:87` and `src/error/wallet_fault.rs:90-91`, pinned by `tests/abort_kind_604.rs` `the_kind_moves_no_wire_byte_604`. A carrier is a wire form the reference does not have |
| #819, 3: `AbortKind`'s `Hash` and `#[non_exhaustive]` are unpinned | ALREADY TRUE | `0eb96572` (pull request #896) and its folds: `tests/wallet_fault_shapes_819.rs:45` (`the_abort_kind_hashes_as_it_compares_819`, compile-RED without `Hash`); `src/error/wallet_fault.rs:78-79` defines the enum inside `non_exhaustive_enum!`, whose two doc tests hold the attribute; `tests/arch_non_exhaustive_pins_819.rs` requires the pin of every `#[non_exhaustive]` type under `src/` |
| #908, 1: no CI job reads a `compile_fail` block's error number | BUILT | `.github/workflows/docs.yml` job `doc-error-numbers`; `tests/arch_ci_doc_error_numbers_908.rs` (4 tests); the runs below |
| #908, 2: `Hash` on four public types has no pin | BUILT | `tests/hash_derives_908.rs` (5 tests); compile-RED four times, below |
| #908, 3: `#[non_exhaustive]` under a feature's `cfg_attr` would pass | ALREADY TRUE | `tests/arch_non_exhaustive_pins_819.rs:430-434`: a line of code naming `non_exhaustive` that is not exactly `#[non_exhaustive]` is refused (`names \`non_exhaustive\` in a spelling this reader does not read`); its own plant at `:1471-1474` (`#[cfg_attr(all(), non_exhaustive)]`). `git grep 'cfg_attr.*non_exhaustive' -- 'src/*.rs'` at `2b419d90`: 0 |
| #908, 4: a test message says the opposite of its failure | ALREADY TRUE | `tests/wallet_fault_shapes_819.rs:35` at `2b419d90`: `"{value:?} was not held by the set"` (the fold of #896 took it) |

Counts: 2 built, 3 already true, 2 need a decision, 0 not a defect.

#908's opening paragraph says the fold's own list of types left with no pin
belongs on the bucket when it reports. No comment carries it; it stands in the
tree as `LISTED` of `tests/arch_non_exhaustive_pins_819.rs` (six: `Error`,
`Stop`, `Verdict`, `AsyncVerifyError`, `InputVerified`, `InputRefusal`, each
with its reason, the list only shrinking). Not a line of the bucket; named
here so it is not lost.

## #819, line 1: the two sides, run

The reference: the unmodified `ts-stack@edf6e03` `packages/sdk/src` (a `git
archive` of the pin, bundled with esbuild 0.25.0), its `WalletWireProcessor`
over a stub wallet and its own `WalletWireTransceiver` reading the frame back,
Node v22.18.0. This crate: the frames its tests pin (`tests/wire_error_frames.rs`
`a_wallets_refused_abort_is_framed_code_8_in_the_references_words`,
`tests/wallet_fault_wire_439.rs` `an_accepted_abort_keeps_every_refusal_class_frame`,
`tests/abort_kind_604.rs` `the_kind_moves_no_wire_byte_604`), run green in
this lane's gate.

| The wallet's answer to abortAction | The reference's frame | Its client reads | This crate's frame | Same bytes |
|---|---|---|---|---|
| `{ aborted: true }` | `00` | `{ aborted: true }` | `00` | yes |
| `{ aborted: false }` (what the reference toolbox answers for a `nosend` action the chain reports `mined` or `known`, `StorageProvider.ts:870,878,889,927-932`) | `08`, 77 bytes `The wallet refused to abort this action because it has already been broadcast`, `00` (`WalletWireProcessor.ts:797-804`) | `{ aborted: false }` (`WalletWireTransceiver.ts:336-339`) | the same (#206) | yes |
| a thrown toolbox `WERR_INVALID_OPERATION` (its `code` its name) | `01 17` `Wallet operation failed` `00` | throws `WalletError`, code 1 | `Error::WalletRefusal` or `Error::AbortAccepted` of class `InvalidOperation`, any kind: `01 17` `Wallet operation failed` `00` | yes |
| a thrown toolbox `WERR_INVALID_PARAMETER` | `01 17` `Wallet operation failed` `00` | throws `WalletError`, code 1 | class `InvalidParameter`: `06`, the message, `00` (the SDK's code of the same name; #137's stated row) | no, stated |

So the wire layer answers each wallet answer as the reference's does. The
bucket's line is one level up: for the same wallet FACT (the chain holds the
transaction) the reference toolbox returns `{ aborted: false }` (row 2) and a
Rust wallet that returns `Err(AbortAccepted { class: InvalidOperation, kind:
OnChain })` reaches row 3. A TypeScript client reads `aborted: false` from the
reference and a thrown `Wallet operation failed` from that wallet.

Not verified: the Rust toolbox's emission itself. The checkout at
`~/bsv/bsv-wallet-toolbox-rs` (`a3377ef0`) depends on `bsv-rs` 0.3.20 and
names no `AbortAccepted`; the line's scenario is taken from the bucket.

## The questions

**Question 1 (#819, line 1).** For an abortAction whose wallet answers
`Error::AbortAccepted` of kind `OnChain`, does this crate's processor write
the class's frame (today: code 1 for `InvalidOperation`) or the reference's
refused-abort frame (code 8, read back as `aborted: false`)?

- (a) Leave it, stated (#604's fold). The toolbox answers `Ok(aborted:
  false)` for the chain-confirmed refusal where it serves the wire, as the
  reference toolbox does. Cost to a caller: none here; the toolbox's hosts in
  process lose the typed record on that path unless it keeps both answers.
- (b) The processor frames kind `OnChain` on abortAction as code 8 in the
  reference's words. Cost to a caller: a client of the wire reads `aborted:
  false` where it read an error (`wallet error (code 1): Wallet operation
  failed` through this crate's transceiver), the same answer the reference
  gives for the same fact; `the_kind_moves_no_wire_byte_604`, the rustdoc of
  `AbortKind` and the wire manual's paragraph move; no public shape changes.
- (c) Every `AbortAccepted`, whatever its kind, as code 8. Wider than the
  reference's predicate (`:878` is the chain's word alone); a stored-acceptance
  refusal would read `already been broadcast`.

Recommendation: (b). `AbortKind::OnChain` is defined as the reference's
predicate at `StorageProvider.ts:878`, and the reference's answer to that
predicate is `aborted: false`; (b) makes the bytes follow the fact for every
wallet that supplies the record, and (a) leaves each wallet to do it.

The cold read's note on the framing (2026-11-14): the reference toolbox
answers `{ aborted: false }` for more facts than the chain's word. At
`edf6e03` its `abortAction` returns it after a BRC-177 reclaim whose
action was since broadcast, won by its target or conflicted
(`StorageProvider.ts:915-920`) and for a target-protected action (`:926`),
beside the chain-confirmed refusal (`:927-932`). `AbortKind` has no case
for those (a record of such a refusal would be `Other` or `AcceptedInStore`),
so (b) carries the chain's refusal to code 8 alone and leaves the BRC-177
refusals framed by their class; (c) would carry them too, with the
stored-acceptance refusal beside them. The owner's choice is between (b)
and (c) on that fact, not only on the words of `:878`.

**Question 2 (#819, line 2).** Does the abort kind travel behind a substrate?

- (a) No carrier (today, stated): a host over HTTP JSON or the wire reads
  `WalletRefusal` or `WalletError`, and maps by kind in process alone.
- (b) No new carrier, and question 1's (b): the one kind the reference itself
  distinguishes arrives as `aborted: false` on the wire, the reference's own
  carrier; `AcceptedInStore` and `Other` stay in process.
- (c) A carrier of this crate's (the error frame's stack field, or a member of
  the JSON error body). Cost: a wire form the reference does not write; a
  reference client ignores or refuses it; a stated divergence to keep.

Recommendation: (b), and never (c): the kind is this crate's addition, and the
wire is the reference's.

**Question 3 (#908, line 1, what was not built).** Does the nightly doc job
also hold a tag's publish? Built: on a dispatch alone, so `RELEASING.md` step
4's dispatch of `docs.yml` reads it before any tag and no publish waits on a
nightly compiler. The other way is one line (the job's `if:` removed, the pin
moved with it); its cost is a release held by a nightly's regression, with a
tag that cannot be remade. Recommendation: stay on the dispatch.

## #908, line 1: what was built and run

- The job: `docs.yml` `doc-error-numbers`, `cargo test --doc --all-features`
  on `nightly-2026-10-19` (the date `nightly.yml`'s fuzz job builds with),
  `RUSTFLAGS` emptied so a nightly lint judges nothing, `if:
  github.event_name == 'workflow_dispatch'`.
- The pin: `tests/arch_ci_doc_error_numbers_908.rs`. 2 of 4 RED on a scratch
  copy of `2b419d90` with the file overlaid (`.github/workflows/docs.yml: no
  job \`doc-error-numbers\``).
- The property, by a run in the scratch copy (macOS, the same nightly):
  `WalletFault`'s `compile_fail,E0639` block with its body made to fail with
  E0308 alone reads `compile fail ... ok` on stable and, on the nightly,
  `FAILED`, `Some expected error codes were not found: ["E0639"]`.
- The bound, by a run: the same block with a line `use bsv_rs::NoSuchName;`
  added (E0432 beside E0639) passes on BOTH. A nightly requires the named
  number among the errors, not alone. A misspelt path that leaves the named
  error standing is not seen by this job.
- The tree today: `cargo +nightly-2026-10-19 test --doc --all-features` at
  `2b419d90`: 382 passed, 0 failed, 128 ignored, the 49 compile-fail doc tests
  among the passed. No block of the tree names a number it does not fail with.
- Six fences name no number (`src/primitives/bignum.rs` 1,
  `src/primitives/ec/shared_secret.rs` 5): listed in the test with the reason,
  the list only shrinking. Numbering them is a change under `src/`, left to a
  lane that has one.
- Not run: the job itself on a Linux runner. It is a dispatch's
  (`gh workflow run docs.yml --ref beta`) after the landing.
- Not changed: `README.md`'s sentence on `docs.yml` (`workflow lint`). The
  README is `main`'s front page, and `main`'s `docs.yml` does not carry the
  job (the change is none of the six classes `main` takes).

## #908, line 2: RED

A scratch copy of `2b419d90` (`git archive` under
`/Volumes/Lanes/out/bsv-rs/fix-wallet-buckets/scratch`, target
`/Volumes/Lanes/targets/fix-wallet-buckets-red`, both removed at the end) with
`tests/hash_derives_908.rs` overlaid, `Hash` removed from one derive at a time
(`src/error.rs` `TransportFault`, `src/transaction/spending.rs`
`InputVerified`, `src/wallet/hmac_tag.rs` `HmacKeyEncoding` and
`HmacVerifyPolicy`), `cargo test --features "full,http" --test
hash_derives_908 --no-run`: exit 101 each time, `error[E0277]: the trait bound
\`<the type>: std::hash::Hash\` is not satisfied` at the type's line of
`the_four_types_keep_the_bound_a_map_key_needs_908`, every error located in
the test file and none under `src/` (the library builds without the derive).
Not run: the whole suite with a derive removed (the bucket's "passes every
test" is its read's claim).

## Commits

Written as three, grouped by line: one for #908 line 2 (the test and its
row), one for #908 line 1 (the job, its test and row, the two documents'
sentences), one for the records (the changelog entry and this file). Landed
as one commit, `efa1cd25`, the three folded into it and rebased onto beta
`22ee5df2`; the cold read re-ran the RED there (2 of 4 of
`arch_ci_doc_error_numbers_908.rs`, the four compile-RED of
`hash_derives_908.rs`), each as this record states it at `2b419d90`.
