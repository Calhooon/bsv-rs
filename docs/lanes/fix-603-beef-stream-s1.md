Do every edit and every gate yourself, in the foreground, in your turn: no background job, no subagent; the REPORT is the last thing you write, and a turn that ends with a command still running is a stopped lane. Your logs and evidence live under `/Volumes/Lanes/out/bsv-rs/fix-603-beef-stream-s1/`, never the shared `$TMPDIR` or `/tmp`.

# #603, `src/transaction/beef_stream.rs`: its 44 surviving mutants under the widened oracle, each killed by a test from the sibling's rule and vector or declared equivalent by the sibling's rule

Branch `lane/fix-603-beef-stream-s1` from `origin/beta`'s tip (name the base sha in your REPORT); the other three shards run in their own lanes and branches, so take nothing from and give nothing to them; #632 (beef.rs) may land meanwhile with its recorder, which you extend after a rebase rather than duplicate. Never push. The owner's word (2026-11-01 14:1xZ, 14:3xZ; the keeper's 14:4xZ reading): each survivor on the interpreter, BEEF and Merkle paths is killed by a test written from the sibling's rule and vector for that file (`~/bsv/bsv-script-lean`: its `corpus/` families, its Lean definition under `lean/BsvScript/`, its spec pages), the sibling's issue or page cited per test, never from a guess at the behaviour; an equivalent mutant is declared with the sibling's rule as its reason, never for convenience; no test selection that passes without the corpus; "no cheating, no shortcuts". Three independent reads judge every equivalence you declare; a declaration they do not all accept is a test to write.

## The survivors

The list for `src/transaction/beef_stream.rs` is in `docs/census/mutants-2026-11-01.md` on beta (the widened run 41327640129; `file:line:column`, function, genre, replacement), 44 entries. Read every one against the code at the line before you start.

## This lane's shard: S1, the stream's cursor and element reading (44 of the file's 132 survivors; functions `BeefDecoder::elements_read`, `BeefDecoder::finish`, `BeefDecoder::header_read`, `BeefDecoder::on_run_done`, `BeefDecoder::on_varint`, `BeefDecoder::take_deferred`, `BeefStream<R>::elements_read`, `BeefStream<R>::next_element`, `BeefStream<R>::offset`, `BeefStream<R>::subject`, `BeefStream<R>::version`, `Cursor::from_binary`, `Cursor::input_reached`, `Cursor::to_binary`, `StreamVerifier<R, H>::cursor`, `StreamVerifier<R, H>::step_until`)

`src/transaction/beef_stream.rs` (74.42 percent under the widened oracle, 384 of 516 viable caught; 130 missed and 2 timed out) is killed in four shards by function, each its own lane, branch and PR: S1 the stream's cursor and element reading, S2 the index's folds, S3 the index's sizes, roots and finish, S4 the judge and the remainder. This lane takes shard S1 alone: the survivors below and no other (another shard's mutant you happen to kill is named in the REPORT, not claimed). Its test file is `tests/beef_stream_603_s1.rs` (an integration test file of its own; no module line in `src/transaction/beef_stream.rs` or `mod.rs`, so the four shards never touch the same line; if a kill needs a crate-private item, say which and why in the REPORT and use the public path instead where one reaches the mutant), its `CHANGELOG.md` entry `### Added: src/transaction/beef_stream.rs's surviving mutants, shard S1 (the stream's cursor and element reading), killed from the sibling's rules and vectors (#603)`, its `tests/CLAUDE.md` row of its own. The re-measure (the method's step 4) runs on this shard's functions alone: `cargo mutants --file src/transaction/beef_stream.rs --re 'BeefDecoder::elements_read|BeefDecoder::finish|BeefDecoder::header_read|BeefDecoder::on_run_done|BeefDecoder::on_varint|BeefDecoder::take_deferred|BeefStream.*::elements_read|BeefStream.*::next_element|BeefStream.*::offset|BeefStream.*::subject|BeefStream.*::version|Cursor::from_binary|Cursor::input_reached|Cursor::to_binary|StreamVerifier.*::cursor|StreamVerifier.*::step_until' --jobs 1` with the surface's selection (the regex matches the mutant descriptions `cargo mutants --list` prints; a mutant of this shard that the regex misses is run by its line and column, and the REPORT says so); the whole file's figure is the witness's after the four land, so the REPORT gives this shard's caught, missed, timed out and unviable, not a whole-file score. A timed-out mutant of this shard (two in the file, a loop that stops advancing) is killed by a test with its own bound, never counted as caught.

The survivors of this shard (the census on beta, `docs/census/mutants-2026-11-01.md`; `file:line:column`, function, operator):

- `src/transaction/beef_stream.rs:788:9` BeefDecoder::take_deferred: FnValue `None`
- `src/transaction/beef_stream.rs:809:9` BeefDecoder::elements_read: FnValue `0`
- `src/transaction/beef_stream.rs:809:9` BeefDecoder::elements_read: FnValue `1`
- `src/transaction/beef_stream.rs:824:9` BeefDecoder::header_read: FnValue `true`
- `src/transaction/beef_stream.rs:899:20` BeefDecoder::finish: BinaryOperator `!=`
- `src/transaction/beef_stream.rs:1196:57` BeefDecoder::on_varint: BinaryOperator `+`
- `src/transaction/beef_stream.rs:1263:9` BeefDecoder::on_run_done: FnValue `()` *timeout*
- `src/transaction/beef_stream.rs:1413:9` BeefStream<R>::offset: FnValue `0`
- `src/transaction/beef_stream.rs:1413:9` BeefStream<R>::offset: FnValue `1`
- `src/transaction/beef_stream.rs:1418:9` BeefStream<R>::elements_read: FnValue `0`
- `src/transaction/beef_stream.rs:1418:9` BeefStream<R>::elements_read: FnValue `1`
- `src/transaction/beef_stream.rs:1423:9` BeefStream<R>::version: FnValue `None`
- `src/transaction/beef_stream.rs:1423:9` BeefStream<R>::version: FnValue `Some(0)`
- `src/transaction/beef_stream.rs:1423:9` BeefStream<R>::version: FnValue `Some(1)`
- `src/transaction/beef_stream.rs:1428:9` BeefStream<R>::subject: FnValue `None`
- `src/transaction/beef_stream.rs:1428:9` BeefStream<R>::subject: FnValue `Some(Default::default())`
- `src/transaction/beef_stream.rs:1450:31` BeefStream<R>::next_element: MatchArmGuard `false`
- `src/transaction/beef_stream.rs:1450:31` BeefStream<R>::next_element: MatchArmGuard `true`
- `src/transaction/beef_stream.rs:1450:40` BeefStream<R>::next_element: BinaryOperator `!=`
- `src/transaction/beef_stream.rs:2570:9` Cursor::input_reached: FnValue `None`
- `src/transaction/beef_stream.rs:2570:9` Cursor::input_reached: FnValue `Some(0)`
- `src/transaction/beef_stream.rs:2570:9` Cursor::input_reached: FnValue `Some(1)`
- `src/transaction/beef_stream.rs:2728:33` Cursor::to_binary: UnaryOperator ``
- `src/transaction/beef_stream.rs:2766:22` Cursor::from_binary: MatchArmGuard `false`
- `src/transaction/beef_stream.rs:2767:22` Cursor::from_binary: MatchArmGuard `false`
- `src/transaction/beef_stream.rs:2769:22` Cursor::from_binary: MatchArmGuard `true`
- `src/transaction/beef_stream.rs:2828:22` Cursor::from_binary: BinaryOperator `==`
- `src/transaction/beef_stream.rs:2828:22` Cursor::from_binary: BinaryOperator `>=`
- `src/transaction/beef_stream.rs:2828:26` Cursor::from_binary: BinaryOperator `&&`
- `src/transaction/beef_stream.rs:2828:44` Cursor::from_binary: BinaryOperator `^`
- `src/transaction/beef_stream.rs:2828:44` Cursor::from_binary: BinaryOperator `|`
- `src/transaction/beef_stream.rs:2861:32` Cursor::from_binary: BinaryOperator `|`
- `src/transaction/beef_stream.rs:2886:36` Cursor::from_binary: MatchArmGuard `true`
- `src/transaction/beef_stream.rs:2886:46` Cursor::from_binary: BinaryOperator `||`
- `src/transaction/beef_stream.rs:2910:17` Cursor::from_binary: MatchArm ``
- `src/transaction/beef_stream.rs:2911:17` Cursor::from_binary: MatchArm ``
- `src/transaction/beef_stream.rs:2933:29` Cursor::from_binary: BinaryOperator `==`
- `src/transaction/beef_stream.rs:2941:23` Cursor::from_binary: BinaryOperator `<=`
- `src/transaction/beef_stream.rs:2941:23` Cursor::from_binary: BinaryOperator `==`
- `src/transaction/beef_stream.rs:2941:23` Cursor::from_binary: BinaryOperator `>`
- `src/transaction/beef_stream.rs:2941:35` Cursor::from_binary: BinaryOperator `||`
- `src/transaction/beef_stream.rs:2941:38` Cursor::from_binary: UnaryOperator ``
- `src/transaction/beef_stream.rs:3175:13` StreamVerifier<R, H>::cursor: MatchArm ``
- `src/transaction/beef_stream.rs:3214:32` StreamVerifier<R, H>::step_until: BinaryOperator `||` *timeout*

## This lane's rule source

BRC-62's binary frame at the BRC repository's pin named in `CLAUDE.md` (the version word, the BUMP count and the BUMPs, the transaction count and each entry's form: a raw transaction with its BUMP index or none, the txid-only form), the streaming reader's rules of 0.4.1 and 0.4.2 in `CLAUDE.md`'s divergence list (a byte after the frame refused, a raw transaction with no input or no output refused, the lone leaf at a nonzero offset; this crate follows the node and its stated rule where TS's `fromBinary` is a prefix parser and `fromBinaryStrict` refuses: judge by the stated rule, cite the line, never silently by the reference's lenient reading), the reference's `Beef.ts` reader at `ts-stack@edf6e03` where the two agree (`fromBinary`, `fromReader`, `BeefTx.ts`), the ts-stack conformance corpus's BEEF structure families (`$BSV_CONFORMANCE_DIR`, your own sparse clone at the pin; `tests/conformance_beef.rs` names the families, the `unsupported` allowlist and the pinned totals, which must not move), the sibling's `corpus/wire` rows (taken by id through a scratch copy of its `run_wire` harness linked to this tree, as the beef.rs lane of #632 did; read its `tests/support/beef_reference_603.mjs` and extend, never duplicate, a recorder), and this crate's own witnesses (`tests/beef_stream_*`, `tests/vectors/beef_*`, the `BeefDecoder` and `StreamVerifier` tests); a cursor or accessor mutant is killed by a vector whose reading, offset, element count or verdict the mutant flips, never by a read-back of the accessor's own value.

## The method

1. **The corpus as the mutant killer** (the interpreter's files, the parsers, the Merkle reader): from a scratch copy of the sibling's harness (`~/bsv/bsv-script-lean/harness`, its `Cargo.toml` pin `bsv-rs = "=0.7.0"` replaced by `path = <your lane's tree>`, one `cargo metadata` to settle the lock; never edit the sibling's clone), run `harness/run --impl bsv-rs --corpus all --spec recorded` against the tip's tree once (the base column), then for each survivor apply the mutant in a second scratch copy of the tree (the `diff/` file from the shard artifact, or `cargo mutants --file src/transaction/beef_stream.rs --line N --col C` with `--in-place` on the copy) and run the same corpora: every entry whose verdict moves is the test's vector. For the BEEF readers, `corpus/chain`'s transaction-rule rows (`TxRules.lean`) and this crate's own BEEF vectors and witnesses are the sources; for a template file, the reference's vectors and the crate's own.
2. **The test**: in the file's test module or the matching `tests/*.rs`, named for the rule and the sibling's citation (`<rule>_<family>_<entry id>` with the Lean file and line in a comment), the vector copied by its id and corpus with its recorded verdict as the expectation; RED on the mutant (shown in your log: the mutant applied, the test failing) and GREEN on the tree. Several survivors may fall to one test; say which.
3. **A candidate equivalence**: only when no entry of the whole corpus moves and the Lean rule shows the replacement cannot change a verdict, and never for a mutant a hand vector could kill; the lane names it in the REPORT and the changelog entry as a candidate with the sibling's rule (`lean/BsvScript/<file>.lean:<line>` at the sibling's pin) and the reason, and writes nothing into `.cargo/mutants.toml`: the ensemble rule puts every equivalence under three independent reads (the PR's cold read, an adversarial read, a rule read), and the captain's fold declares it in `exclude_re` only when all three accept; a candidate a read distinguishes gets a test instead.
4. **Re-measure**: `cargo mutants --file src/transaction/beef_stream.rs` with the surface's selection from `nightly_mutants.py`'s `mutation_args` and `BSV_CONFORMANCE_DIR` set to your own sparse clone of ts-stack at `edf6e03dad39bd7bc4fc6e73e64de3a2b6f805c9` under your lane folder: the file's new caught, missed, timeout, unviable and score; the target is at or above 80 percent caught of viable, or every remaining survivor named with the reason it stands.
5. **Docs**: `CHANGELOG.md` `[Unreleased]`: `### Added: src/transaction/beef_stream.rs's surviving mutants killed from the sibling's rules and vectors (#603)` with the counts (killed by tests, declared equivalent, remaining) and the sibling's pin; no parity note unless a vector revealed a divergence from the reference, which is then a `### Notes: cross-SDK parity` paragraph and a census row, never silent.
6. **The gate, in the foreground**: the file's own tests and the tests you added; `cargo test --features "full,http"` with one `--test` per file matching `arch_*` and `fixtures_replay*` and every `--test` of the surface's selection; `cargo test --doc --all-features`; `cargo clippy --all-targets --all-features -- -D warnings`; `cargo fmt --check`; `tools/ratchet/run --check --against <base>` with `CARGO_TARGET_DIR` outside the checkout; `gitleaks git --redact --no-banner --exit-code 1 --log-opts="origin/beta..HEAD" .` from the repo root; the wasm32 build of `CLAUDE.md` rule 6 if a `src/` file changed. One commit: `test(beef-stream-s1): the file's surviving mutants killed from the sibling's rules and vectors (#603)`.

## REPORT

The base sha and the tip; for every survivor: killed (the test's name, the vector's id and corpus, RED and GREEN shown) or declared equivalent (the Lean rule) or remaining (why); the re-measured score; the gate table; anything unverified; nothing else.

Rules: no VM and no container on this machine (a Linux witness is CI's, a dispatch after the landing); never end your turn with a command running in the background; commit on the branch, never push; no test or probe on a default URL or port (a MetaNet Client listens on 3301, 3321 and 2121 on this machine; another session's process on 3390); do not read `~/bsv/bsv-low/` or `~/vault/`, and do not grep across `~/bsv/` as a whole (the reference and the downstreams are read by their named paths); vectors are written by recorders, never by hand; scratch copies under `$TMPDIR` with their own `CARGO_TARGET_DIR`, removed at the end; never `rustup default` or `rustup override` (use `cargo +1.99.0`); a new dependency needs the captain's word first; your logs, scratch copies and evidence live under your own folder on the lane volume, `/Volumes/Lanes/out/bsv-rs/<lane name>/`, never the shared `$TMPDIR` or `/tmp`, and no command of yours globs or lists a shared folder (the captains' channel line 1082, 2026-10-31).

The bounded block (the owner's form, 2026-11-01): every REPORT ends with four lines: the decision or verdict in one line; a confidence in [0.0, 1.0]; a rationale of at most three lines; the residual risks, each named and scored in [0.0, 1.0] (none is written "none, 0.0"). A read's verdict without the block is not a verdict; a lane's REPORT without it is not done.
Rules: no VM and no container on this machine (a Linux witness is CI's, a dispatch after the landing); never end your turn with a command running in the background; commit on the branch, never push; no test or probe on a default URL or port (a MetaNet Client listens on 3301, 3321 and 2121 on this machine; another session's process on 3390); do not read `~/bsv/bsv-low/` or `~/vault/`, and do not grep across `~/bsv/` as a whole (the reference and the downstreams are read by their named paths); vectors are written by recorders, never by hand; scratch copies under `$TMPDIR` with their own `CARGO_TARGET_DIR`, removed at the end; never `rustup default` or `rustup override` (use `cargo +1.99.0`); a new dependency needs the captain's word first; your logs, scratch copies and evidence live under your own folder on the lane volume, `/Volumes/Lanes/out/bsv-rs/<lane name>/`, never the shared `$TMPDIR` or `/tmp`, and no command of yours globs or lists a shared folder (the captains' channel line 1082, 2026-10-31).

The bounded block (the owner's form, 2026-11-01): every REPORT ends with four lines: the decision or verdict in one line; a confidence in [0.0, 1.0]; a rationale of at most three lines; the residual risks, each named and scored in [0.0, 1.0] (none is written "none, 0.0"). A read's verdict without the block is not a verdict; a lane's REPORT without it is not done.

The per-host rule (the captains' channel line 1093, the keeper's 20:5xZ word): `export CARGO_BUILD_JOBS=4` at the start of every shell you open and before every `cargo` command (a build, a test, clippy, the ratchet, cargo-mutants); never two `cargo` invocations at once; `cargo mutants` only with `--jobs 1`; no `--all-targets` build you do not need. A lane that holds hundreds of `rustc` processes is stopped.
