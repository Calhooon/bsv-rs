# Lane fix-218-fold: the review's three edits on the mock's synthetic tip (#218)

**Repository.** `bsv-rs`, the same worktree as the #218 lane (`/Volumes/Lanes/worktrees/bsv-rs/fix-218-mock-mining-tip`, branch `lane/fix-218-mock-mining-tip`, tip `d665bf0`, pushed as draft PR #219). You add one commit on top. `docs/lanes/README.md` binds you: rule 11 (never let one command run ten minutes: compile with `--no-run`, then run; everything in the foreground; the REPORT last). Rule 1: never read under `~/bsv/bsv-low/` or `~/vault/`. Never push. Forty minutes.

**The fold (the cold review's, Fable; its REPORT is below the brief: read it).** Under the synthetic mainnet tip a mock whose `height` is below 620,537 is a pre-Genesis tip, so `verify_stream`'s `after_genesis` read (`beef_stream.rs:2141-2142`) does not refuse a P2SH output where the old `None` refused it (`P2shOutput`); and below 419,327 a time lock (lock time at or above 500,000,000) is `Unverifiable { check: Finality }`, the tip carrying no `next_block_time`. Rule 1: never a silent difference; rule 2: a behaviour the mock now has gets a test.

1. `CHANGELOG.md` (the #218 entry, after the sentence ending "a lock time at the next height `NonFinal`."): one sentence stating both readings above with the lines.
2. `src/transaction/chain_tracker.rs` (the struct's rustdoc at `:194-198`): one line ("mainnet's heights: a mock below 620,537 is a pre-Genesis tip").
3. `tests/beef_stream.rs`, after `the_mock_tracker_set_to_no_tip_holds_at_the_door`: a test pinning the pre-Genesis reading, the review's probe as the test minus its prints: a proven spend of a P2SH output with the mock at 620,536 is Valid, at 620,537 `P2shOutput` (read the existing P2SH-output test in that file for how such a BEEF is built; `with_mining_tip(None)` at 1,000 `P2shOutput` as a third case if cheap).

**Gate.** `cargo fmt --all -- --check`; `cargo clippy --all-targets --all-features -- -D warnings`; `tests/beef_stream.rs` on its own (RED before for the new test: on a scratch copy of `d665bf0` with the test added but the assertion inverted is not RED-before in the house's sense; say instead that the test fails on beta's `None` mock at 620,536 since the door refuses there, if you can run it against beta's mock by `with_mining_tip(None)`: say what you ran); `cargo test --doc --all-features -- chain_tracker` (the rustdoc builds); the wording rule over the files you touched; `tools/ratchet/run --check --against origin/beta` with `CARGO_TARGET_DIR=$HOME/bsv/targets/bsv-rs-lanes/ratchet-218`.

**Bounds.** The three edits; no behaviour change; nothing else. Lanes never push.

**Report.** `REPORT: STATUS done|blocked`, the tip commit, the three edits, the test's tail, the gate's tails. Write the full REPORT before your turn ends.

===== the cold review's REPORT =====
Everything I need is in hand. The probe confirms one unstated side effect: under the synthetic tip a mock below height 620,537 is a pre-Genesis tip, so a P2SH output passes the door where the old `None` refused it (`P2shOutput`). Nothing else turned up.
## Review of `lane/fix-218-mock-mining-tip` (d665bf0 over beta 7c86b71)
**Verdict: fold**, three small edits, then merge. The code is right and every gate is green; the fold is one behaviour the changelog does not state.
1. `CHANGELOG.md:23` (after "a lock time at the next height `NonFinal`."): add a sentence that the tip is mainnet's, so a mock whose `height` is below 620,537 is a pre-Genesis tip and the door does not refuse a P2SH output (`verify_stream`'s `after_genesis` read, `beef_stream.rs:2141-2142`), where the old `None` refused it; and below 419,327 a time lock (lock time at or above 500,000,000) is `Unverifiable { check: Finality }`, the tip carrying no `next_block_time`. Reason: rule 1's "never a silent difference"; a host test asserting `P2shOutput` on a low mock flips to Valid. Probe on a scratch copy of HEAD: height 1000 and 620,536 Valid, 620,537 and 800,000 `P2shOutput`, `with_mining_tip(None)` at 1000 `P2shOutput`.
2. `src/transaction/chain_tracker.rs:194-198` (the struct's rustdoc): the same clause in one line ("mainnet's heights: a mock below 620,537 is a pre-Genesis tip").
3. `tests/beef_stream.rs` after `the_mock_tracker_set_to_no_tip_holds_at_the_door`: pin the pre-Genesis reading (rule 2: a behaviour the mock now has gets a test). The probe's body is the test, minus the prints: a P2SH output at 620,536 Valid, at 620,537 `P2shOutput`.
**The tip's fields**
| Field | Value | Source | Judgement |
|---|---|---|---|
| `height` | the mock's `height`, read at call time | `tip()` | right; the unit test mutates `height` and sees 1001; both traits share `tip()` |
| `median_time_past` | 1,700,000,000 | private constant | the door compares it only to a time lock (lock time ≥ 500,000,000) when `height + 1 ≥ csv_height` (`beef_stream.rs:2173-2178`); no test here uses a time lock; height locks compare to `height + 1` |
| `genesis_height` | 620,538 | `ProtocolEra::MAINNET_GENESIS_HEIGHT` (`flags.rs:94`, node `chainparams.cpp:18`) | right; drives only the P2SH-output rule (the fold above) |
| `csv_height` | 419,328 | private `MAINNET_CSV_HEIGHT`, cites `chainparams.cpp:1046` | verified at `~/bsv/bitcoin-sv` 879fc8b: line 1046 reads `consensus.CSVHeight = 419328` (mainnet); the crate had no constant |
| `next_block_time` | `None` | | read only when `height + 1 < csv_height` for a time lock, then `Unverifiable { Finality }` (`:2177`); never at 800,xxx |
No real tracker in this crate answers `mining_tip` (WoC and BlockHeadersService keep the default); the toolbox's chaintracks client does, on its branch `lane/hot-103-fix`.
**The door's boundaries** (`beef_stream.rs:2340-2357`, `:2162-2190`): coinbase at 800,000, depth = `tip.height + 1 - 800,000`, refused below 100: tip 800,098 is depth 99 `PrematureCoinbase`, 800,099 is 100 Valid. Lock time 800,001 with sequence 0: limit = `tip.height + 1`, refused when `lock_time >= limit`: tip 800,000 `NonFinal`, 800,001 Valid. The tests sit exactly on these edges, on both the sync `Headers` path and the async `ChainTracker` path. The moved test sets `None` explicitly and still asserts `Unverifiable { CoinbaseMaturity }` on the async path; on the beta scratch with the setter call removed it passes, the same semantics.
**Shape.** The only public addition is `with_mining_tip(Option<ChainTip>)`. The private `tip` field makes an outside struct literal fail to compile; the changelog states it with the migration. None of the downstreams builds this crate's mock by literal: the toolbox's literal at `services/mock.rs:602` is its own `struct MockChainTracker` (`mock.rs:135`); the CLI, overlay, message-box and chaintracks checkouts build it by `new`. The `impl Headers` move is behaviour-free (same `carries` body) and the ratchet is green. The rustdoc example is `rust,ignore`, as it was before, so it is not compiled; it reads consistently with the new line.
**Downstreams.** The toolbox door reads `ChainTracker::mining_tip` through a `Headers` wrapper (`lane/hot-103-fix` `beef_verification.rs:40-58`, "the header service supplied no mining tip"). No toolbox or CLI test asserts that hold on this crate's mock (grep of both trees and branches); the 20 toolbox files using this crate's mock on that branch would now pass the door. The CLI's `main` pins `=0.8.2` and reads no `mining_tip`; its 9 tests are proven only by running the CLI against a toolbox on `lane/hot-103-fix` patched to this tree. The stack's scenario runner names the mock at a 0.7.0 pin and asserts nothing of the tip.
**Not run.** The script-lean harness: the diff touches no evaluator path and the harness does not reference the mock. The CLI's 9 tests, as above.
**Wording.** No em dash, no "first", no "conformant" in the added lines or the commit message. No vector, fixture or `Cargo.toml` touched.
**RED tail** (scratch copy of beta carrying only the tests, its own target dir; `with_mining_tip` cannot compile there, so its two callers were stripped):
```
the_mock_answers_a_synthetic_mainnet_tip_at_its_height ... FAILED  left: Ok(None)  right: Ok(Some(ChainTip { height: 1000, ... }))
the_mock_tracker_s_tip_is_judged_at_its_height ... FAILED
the_mock_tracker_s_tip_lets_a_proven_spend_through_the_door ... FAILED
the_mock_tracker_set_to_no_tip_holds_at_the_door ... ok   mining_async_and_two_pass_enforce_coinbase_maturity ... ok
test result: FAILED. 74 passed; 2 failed
```
`the_mock_with_a_mining_tip_answers_it_on_both_traits` is RED by construction (no setter on beta).
**Gate tails** (`CARGO_TARGET_DIR=~/bsv/targets/bsv-rs-lanes/fix-218-review`, all foreground, none past 3 minutes):
```
cargo fmt --all -- --check                         FMT_OK
cargo clippy --all-targets --all-features -D warnings   Finished, no warnings
cargo test --lib                                   test result: ok. 1565 passed; 0 failed
integration, 92 files in two halves (beef_deep_chain apart)   half1 806 passed 0 failed; half2 918 passed 0 failed
--test beef_stream   76 passed   --test beef_atomic_graph   15 passed   --test beef_deep_chain (alone)   11 passed, 62.76s
cargo test --doc --all-features                    test result: ok. 265 passed; 0 failed; 129 ignored
cargo build --examples --all-features              Finished
cargo test --test readme_examples                  test result: ok. 1 passed
wasm32 build (auth,wallet,transaction,overlay,socketio,wasm; llvm clang)   Finished
tools/ratchet/run --check --against origin/beta    ratchet: all 7 counters and oversized-file limits pass
```
**The six tests (l2-README).** The synthetic default tip: T1 (scale with our use, a helper answers in process), T3 (computed, no allocation), T6 (pinned, RED before). The `Option<Option<ChainTip>>` setter: T5 (one additive word, the `pub` fields kept), T6. Genesis from the crate's constant, CSV from the node's line: T5 (the citation is checkable), T4 (the door's rule stays math on heights). The `impl Headers` move: T6 (the ratchet and the suite say behaviour-free). The boundary tests on both paths: T2 (the proof still verified against the roots; the tip is context), T6.
REPORT: STATUS done
VERDICT: fold, three edits above (changelog sentence, rustdoc clause, one pin test for the pre-Genesis reading), then merge; the code and every gate are green.
Base 7c86b71 (origin/beta), tip d665bf0; commits by me: none; no file of the lane edited.
Fields: height computed at call on both traits; MTP 1.7e9 compared only to a time lock; genesis 620,538 from `ProtocolEra`; CSV 419,328 verified at bitcoin-sv 879fc8b `chainparams.cpp:1046`; `next_block_time` None never read at the tests' heights.
Finding: below height 620,537 the mock is a pre-Genesis tip and a P2SH output passes the door (probe: 620,536 Valid, 620,537 refused); unstated in the changelog.
Door boundaries right: depth 99 premature, 100 valid; lock 800,001 non-final at tip 800,000, final at 800,001; `None` holds `Finality`.
RED on a beta scratch: unit test Ok(None) vs tip, two door tests FAILED, the no-tip and moved tests ok.
Gate: fmt, clippy -D warnings, 1565 lib + 1724 integration + 265 doc tests, examples, readme_examples, wasm32, ratchet all green; beef_deep_chain alone 11 passed.
Shape: `with_mining_tip` the only addition; private field breaks an outside literal; no downstream builds one by literal (the toolbox's is its own type).
Downstreams: the toolbox door on `lane/hot-103-fix` reads `ChainTracker::mining_tip`; no toolbox or CLI test asserts the hold on this mock.
Unverified: the CLI's 9 tests (need the CLI run against a toolbox on that branch patched to this tree); the script harness not run (evaluator untouched, harness never uses the mock).
Wording clean in the diff and the commit message; no vector, fixture or Cargo.toml touched.
Next: the lane applies the fold; the captain lands on beta, then the `-x` cherry-pick onto main for 0.8.4 if the toolbox and CLI want it.
