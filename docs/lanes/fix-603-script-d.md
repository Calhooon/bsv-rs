Do every edit and every gate yourself, in the foreground, in your turn: no background job, no subagent; the REPORT is the last thing you write, and a turn that ends with a command still running is a stopped lane. Your logs and evidence live under `/Volumes/Lanes/out/bsv-rs/fix-603-script-d/`, never the shared `$TMPDIR` or `/tmp`.

# #603, `src/script/script.rs`: its 27 surviving mutants under the widened oracle, each killed by a test from the sibling's rule and vector or declared equivalent by the sibling's rule

Branch `lane/fix-603-script-d` from `origin/beta`'s tip (name the base sha in your REPORT); the other three shards run in their own lanes and branches, so take nothing from and give nothing to them. Never push. The owner's word (2026-11-01 14:1xZ, 14:3xZ; the keeper's 14:4xZ reading): each survivor on the interpreter, BEEF and Merkle paths is killed by a test written from the sibling's rule and vector for that file (`~/bsv/bsv-script-lean`: its `corpus/` families, its Lean definition under `lean/BsvScript/`, its spec pages), the sibling's issue or page cited per test, never from a guess at the behaviour; an equivalent mutant is declared with the sibling's rule as its reason, never for convenience; no test selection that passes without the corpus; "no cheating, no shortcuts". Three independent reads judge every equivalence you declare; a declaration they do not all accept is a test to write.

## The survivors

The list for `src/script/script.rs` is in `docs/census/mutants-2026-11-01.md` on beta (the widened run 41327640129; `file:line:column`, function, genre, replacement), 27 entries. Read every one against the code at the line before you start.

## This lane's shard: D, the truncated-push index (27 of the file's 115 survivors)

`src/script/script.rs` (74.33 percent under the widened oracle, 333 of 448 viable caught; 112 missed and 3 timed out) is killed in four shards by function, each its own lane, branch and PR: A the ASM parser and the predicates, B the chunk parser, C the writers, D the truncated-push index. This lane takes shard D alone: the survivors below and no other (another shard's mutant you happen to kill is named in the REPORT, not claimed). Its test file is `tests/script_script_603_d.rs` (an integration test file of its own; no module line in `src/script/script.rs`, so the four shards never touch the same line), its `CHANGELOG.md` entry `### Added: src/script/script.rs's surviving mutants, shard D (the truncated-push index), killed from the sibling's rules and vectors (#603)`, its `tests/CLAUDE.md` row of its own. The re-measure (the method's step 4) runs on this shard's functions alone: `cargo mutants --file src/script/script.rs --re 'truncated_push_index' --jobs 1` with the surface's selection; the whole file's figure is the witness's after the four land, so the REPORT gives this shard's caught, missed, timed out and unviable, not a whole-file score.

The survivors of this shard (the census on beta, `docs/census/mutants-2026-11-01.md`; `file:line:column`, function, operator):

- `src/script/script.rs:784:13` truncated_push_index: BinaryOperator `*=` *timeout*
- `src/script/script.rs:788:15` truncated_push_index: BinaryOperator `!=`
- `src/script/script.rs:788:30` truncated_push_index: BinaryOperator `!=`
- `src/script/script.rs:788:42` truncated_push_index: BinaryOperator `&&`
- `src/script/script.rs:788:48` truncated_push_index: BinaryOperator `!=`
- `src/script/script.rs:788:60` truncated_push_index: BinaryOperator `&&`
- `src/script/script.rs:788:66` truncated_push_index: BinaryOperator `!=`
- `src/script/script.rs:789:34` truncated_push_index: BinaryOperator `-=`
- `src/script/script.rs:790:22` truncated_push_index: BinaryOperator `!=`
- `src/script/script.rs:791:58` truncated_push_index: BinaryOperator `+`
- `src/script/script.rs:791:58` truncated_push_index: BinaryOperator `/`
- `src/script/script.rs:793:45` truncated_push_index: BinaryOperator `>=`
- `src/script/script.rs:800:17` truncated_push_index: BinaryOperator `*=`
- `src/script/script.rs:800:17` truncated_push_index: BinaryOperator `-=` *timeout* **new** (narrow: caught)
- `src/script/script.rs:806:41` truncated_push_index: BinaryOperator `&`
- `src/script/script.rs:806:41` truncated_push_index: BinaryOperator `^`
- `src/script/script.rs:806:70` truncated_push_index: BinaryOperator `>>`
- `src/script/script.rs:810:20` truncated_push_index: BinaryOperator `*`
- `src/script/script.rs:814:17` truncated_push_index: BinaryOperator `^`
- `src/script/script.rs:814:46` truncated_push_index: BinaryOperator `>>`
- `src/script/script.rs:815:17` truncated_push_index: BinaryOperator `&`
- `src/script/script.rs:815:17` truncated_push_index: BinaryOperator `^`
- `src/script/script.rs:815:46` truncated_push_index: BinaryOperator `>>`
- `src/script/script.rs:816:17` truncated_push_index: BinaryOperator `&`
- `src/script/script.rs:816:17` truncated_push_index: BinaryOperator `^`
- `src/script/script.rs:816:46` truncated_push_index: BinaryOperator `>>`
- `src/script/script.rs:826:17` truncated_push_index: BinaryOperator `-=` *timeout*

## This lane's rule source

the node's parser refusing a push whose declared size runs past the end (`GetScriptOp` returning false at bitcoin-sv v1.2.3, cited by line) and this crate's rule of 0.3.27 (bsv-rs#12: a truncated push reached is a failure in every mode; `tests/script_residual_witnesses.rs` and the 0.3.27 entry), the sibling's parser definition of a truncated push (`lean/BsvScript/` at the sibling's pin, by file and line) and its `corpus/bytes` and `corpus/fuzz` families (every entry whose script ends inside a push's size word or data, at each PUSHDATA width and at the direct-push sizes, cited by id with the recorded verdict); the three timed-out mutants (`784`, `800`, `826`: an arithmetic replacement making the loop fail to advance) are killed by a test with its own bound (`#[timeout]`-free: a script of bounded length whose parse must end, asserted through a thread with a deadline or the test harness's own timeout of the brief's gate), never left as timeouts counted as caught.

## The method

1. **The corpus as the mutant killer** (the interpreter's files, the parsers, the Merkle reader): from a scratch copy of the sibling's harness (`~/bsv/bsv-script-lean/harness`, its `Cargo.toml` pin `bsv-rs = "=0.7.0"` replaced by `path = <your lane's tree>`, one `cargo metadata` to settle the lock; never edit the sibling's clone), run `harness/run --impl bsv-rs --corpus all --spec recorded` against the tip's tree once (the base column), then for each survivor apply the mutant in a second scratch copy of the tree (the `diff/` file from the shard artifact, or `cargo mutants --file src/script/script.rs --line N --col C` with `--in-place` on the copy) and run the same corpora: every entry whose verdict moves is the test's vector. For the BEEF readers, `corpus/chain`'s transaction-rule rows (`TxRules.lean`) and this crate's own BEEF vectors and witnesses are the sources; for a template file, the reference's vectors and the crate's own.
2. **The test**: in the file's test module or the matching `tests/*.rs`, named for the rule and the sibling's citation (`<rule>_<family>_<entry id>` with the Lean file and line in a comment), the vector copied by its id and corpus with its recorded verdict as the expectation; RED on the mutant (shown in your log: the mutant applied, the test failing) and GREEN on the tree. Several survivors may fall to one test; say which.
3. **A candidate equivalence**: only when no entry of the whole corpus moves and the Lean rule shows the replacement cannot change a verdict, and never for a mutant a hand vector could kill; the lane names it in the REPORT and the changelog entry as a candidate with the sibling's rule (`lean/BsvScript/<file>.lean:<line>` at the sibling's pin) and the reason, and writes nothing into `.cargo/mutants.toml`: the ensemble rule puts every equivalence under three independent reads (the PR's cold read, an adversarial read, a rule read), and the captain's fold declares it in `exclude_re` only when all three accept; a candidate a read distinguishes gets a test instead.
4. **Re-measure**: `cargo mutants --file src/script/script.rs` with the surface's selection from `nightly_mutants.py`'s `mutation_args` and `BSV_CONFORMANCE_DIR` set to your own sparse clone of ts-stack at `edf6e03dad39bd7bc4fc6e73e64de3a2b6f805c9` under your lane folder: the file's new caught, missed, timeout, unviable and score; the target is at or above 80 percent caught of viable, or every remaining survivor named with the reason it stands.
5. **Docs**: `CHANGELOG.md` `[Unreleased]`: `### Added: src/script/script.rs's surviving mutants killed from the sibling's rules and vectors (#603)` with the counts (killed by tests, declared equivalent, remaining) and the sibling's pin; no parity note unless a vector revealed a divergence from the reference, which is then a `### Notes: cross-SDK parity` paragraph and a census row, never silent.
6. **The gate, in the foreground**: the file's own tests and the tests you added; `cargo test --features "full,http"` with one `--test` per file matching `arch_*` and `fixtures_replay*` and every `--test` of the surface's selection; `cargo test --doc --all-features`; `cargo clippy --all-targets --all-features -- -D warnings`; `cargo fmt --check`; `tools/ratchet/run --check --against <base>` with `CARGO_TARGET_DIR` outside the checkout; `gitleaks git --redact --no-banner --exit-code 1 --log-opts="origin/beta..HEAD" .` from the repo root; the wasm32 build of `CLAUDE.md` rule 6 if a `src/` file changed. One commit: `test(script-d): the file's surviving mutants killed from the sibling's rules and vectors (#603)`.

## REPORT

The base sha and the tip; for every survivor: killed (the test's name, the vector's id and corpus, RED and GREEN shown) or declared equivalent (the Lean rule) or remaining (why); the re-measured score; the gate table; anything unverified; nothing else.

Rules: no VM and no container on this machine (a Linux witness is CI's, a dispatch after the landing); never end your turn with a command running in the background; commit on the branch, never push; no test or probe on a default URL or port (a MetaNet Client listens on 3301, 3321 and 2121 on this machine; another session's process on 3390); do not read `~/bsv/bsv-low/` or `~/vault/`, and do not grep across `~/bsv/` as a whole (the reference and the downstreams are read by their named paths); vectors are written by recorders, never by hand; scratch copies under `$TMPDIR` with their own `CARGO_TARGET_DIR`, removed at the end; never `rustup default` or `rustup override` (use `cargo +1.99.0`); a new dependency needs the captain's word first; your logs, scratch copies and evidence live under your own folder on the lane volume, `/Volumes/Lanes/out/bsv-rs/<lane name>/`, never the shared `$TMPDIR` or `/tmp`, and no command of yours globs or lists a shared folder (the captains' channel line 1082, 2026-10-31).

The bounded block (the owner's form, 2026-11-01): every REPORT ends with four lines: the decision or verdict in one line; a confidence in [0.0, 1.0]; a rationale of at most three lines; the residual risks, each named and scored in [0.0, 1.0] (none is written "none, 0.0"). A read's verdict without the block is not a verdict; a lane's REPORT without it is not done.
Rules: no VM and no container on this machine (a Linux witness is CI's, a dispatch after the landing); never end your turn with a command running in the background; commit on the branch, never push; no test or probe on a default URL or port (a MetaNet Client listens on 3301, 3321 and 2121 on this machine; another session's process on 3390); do not read `~/bsv/bsv-low/` or `~/vault/`, and do not grep across `~/bsv/` as a whole (the reference and the downstreams are read by their named paths); vectors are written by recorders, never by hand; scratch copies under `$TMPDIR` with their own `CARGO_TARGET_DIR`, removed at the end; never `rustup default` or `rustup override` (use `cargo +1.99.0`); a new dependency needs the captain's word first; your logs, scratch copies and evidence live under your own folder on the lane volume, `/Volumes/Lanes/out/bsv-rs/<lane name>/`, never the shared `$TMPDIR` or `/tmp`, and no command of yours globs or lists a shared folder (the captains' channel line 1082, 2026-10-31).

The bounded block (the owner's form, 2026-11-01): every REPORT ends with four lines: the decision or verdict in one line; a confidence in [0.0, 1.0]; a rationale of at most three lines; the residual risks, each named and scored in [0.0, 1.0] (none is written "none, 0.0"). A read's verdict without the block is not a verdict; a lane's REPORT without it is not done.

The per-host rule (the captains' channel line 1093, the keeper's 20:5xZ word): `export CARGO_BUILD_JOBS=4` at the start of every shell you open and before every `cargo` command (a build, a test, clippy, the ratchet, cargo-mutants); never two `cargo` invocations at once; `cargo mutants` only with `--jobs 1`; no `--all-targets` build you do not need. A lane that holds hundreds of `rustc` processes is stopped.
