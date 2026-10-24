# HANDOFF: captain-bsv-rs

The captain's running record. Re-orient from this file and `cca runs --project bsv-rs --open` after any restart. The rules are `CLAUDE.md`; the programme is the epic Calhooon/bsv-rs#101 and issues #75 to #100; the lane briefs are `docs/lanes/`.

## The green light (John, 2026-10-23, relayed by captain-bsv-wallet-cli and matching his own words to this captain)

The programme runs continuously: brief a lane, launch it, land it, launch the next. The owner's word is needed for, and only for: any tag or release (prerelease included), any pin move in a consumer, any change to a public API's shape, any spend from a wallet. The one gate before cutting is the keeper's `v0.8.2` tag.

## The lines

- `main`: the stable line. Quick fixes only. Any tag is the owner's word. `main` merges into `beta` after every stable patch.
- `release/0.8.2`: the keeper's (captain-bsv-stack-lean). PR #102 (release/0.8.2 into main) is open and green on every job. Nothing here touches it, the tag `v0.8.2`, the `lane/*` branches or the `[Unreleased]` heading until the tag exists.
- `beta`: this captain's line (#75). CUT 2026-10-23 22:1xZ from `main` at `v0.8.2` (`efe12e6`); protection copied from `main` (the four contexts, strict, admins, linear history, no force push or delete; read back with `gh api repos/Calhooon/bsv-rs/branches/beta/protection`); CI on `[main, beta]` by PR #103; every programme PR targets `beta`; `vX.Y.Z-beta.N` publishes a prerelease (the owner's word); `beta` merges into `main` at a phase exit as the next minor after the toolbox's and the CLI's betas built against a prerelease and the CLI's gate ran.

## Where it stands (2026-10-24, 18:0xZ)

- **Wave 1 complete.** `beta` at `819b4f3`. Every oracle issue #75 to #84 closed; the last, fuzz #82, landed at `746571d` (PR #142). Since 14:4xZ also landed: #121 fix-120 (`02765cf`, #120 closed), #124 benches (`eb7751c`, #77 closed), #144 the nine casts (`90eff04`, #122 closed), #145 the one red test, #153 the BRC-56 allowlist.
- **The gate of record was 34 of 73 files** (#146, found 15:2xZ): CI's Test Suite enumerated binaries by hand; the five arch tests, the wire tests, `wallet_tests`, `readme_examples` and 34 more never ran on a PR. PR #147 runs the whole suite on the house's feature set (green on all six cells after a `.gitleaks`-style fix of a different kind: a `.gitattributes` keeping vectors, fixtures and corpora byte for byte, Windows's git having converted the Wycheproof vectors under their sha256 pin); merging. #146's step 2, a guard that reads ci.yml, is still to do.
- **0.8.3 on main.** PR #135 (the advisory) and PR #151 (the whole-suite CI and the `.gitattributes`, stacked on it) are green; the three legs the owner put before the tag (DECISIONS 15.4, relayed 15:4xZ) are all green and recorded on #135: public surface unchanged (semver-checks 202 pass, public-api diff empty), the live dependents on fresh locks (message box v0.8.1 guard 4 of 4 and 639 tests, middleware v0.6.2 84 tests, one copy of bsv-rs, k256 0.14 only), the whole suite on main's matrix. The merge and the tag `v0.8.3` await the owner's own line in this session (a publish); then the keeper gets the sha and the tag and removes the template's RUSTSEC-2026-0387 entry.
- **Wave 2.** #87 (PR #143): written on Opus, reviewed on Fable (fold), folds applied, the owner's three readings applied (the tracker enum `#[non_exhaustive]` with a typed fault; the WebSocket transport left; the old words give way as a minor), a second Fable review of the fold commits (merge), out of draft and merging; closes #65 and #66 with it. #148 BRC-56 (PR #150): reviewed on Fable, one citation fold applied, merging. #149 the signed varint's form (PR #155, the keeper ruled conform): reviewed on Fable, merge; DRAFT on one [D], the `write_signed_var_int` signature now a `Result` with the field (0.9.0 is the bump regardless; the reviewer and the captain lean to keeping it). #154 the pin move to `5119a9b` (the owner's word, DECISIONS 15.3): filed, runs after #149 lands.
- **Findings filed today:** #138 (wire_codec bench schema), #139 (verify_nonce's slice), #140 (five fuzz targets), #146 (CI's 34 of 73), #149 (ruled, in flight), #152 (wasm32 with http does not build), #154 (the pin move). #117 corrected by the keeper (TS already bounds the internalize field; no bsv-rs validator exists at all).
- **The owner's words of the day:** "we have so much fable and opus 5.5" (13:1xZ: reviews run on Opus when Fable is out, never held); "I love all of your recommendations" (15:4xZ in the keeper's window: 0.8.3 behind three legs, the BRC-56 row, the #87 readings, the pin move).

## Where it stood (2026-10-24, 14:4xZ)

- `beta` at `eb7751c`. Landed since 06:3xZ: #132 the ratchet (`f71923e`, #78 closed), #136 HANDOFF, #119 fix-108 (`6cdd0a8`, #108 closed), #124 benches (`eb7751c`, #77 closed). Nine of the ten oracle issues are closed; fuzz #82 is the last, its fold lane running.
- John's word at 13:1xZ: "we have so much fable and opus 5.5": the four Opus-written branches were reviewed on Opus 5.5 at once (pool accounts' week quota; the Fable column is the Fable half only, not the Opus quota). Every review came back fold, none bounced: benches (three folds, applied by a fold lane), fuzz (six folds, fold lane running), fix-108 (one changelog sentence, applied), fix-120 (two changelog clauses, applied; then the ratchet refused encoding.rs +135, so a fold lane moved the helper to `wire/mod.rs` and the tests to the roundtrip file; PR #121 rebased on beta after a changelog conflict with #119, merging on green).
- Wave 2 opened: #87 (the transport fault typed end to end) launched 14:1xZ on Opus 5.5 from `docs/lanes/wave2-87-transport-fault.md`; the lane committed three commits and stopped with its gate in the background; a foreground-only finisher runs in its worktree (`lane/wave2-87-transport-fault`).
- PR #135 into `main` (the 0.8.3 advisory patch, with the gitleaks allowlist carried because main's secrets job scans every fetched ref) is green on main's required checks; its merge and the tag are the owner's word. The keeper holds `98499b9` and #135's number.
- Issues filed today from the reviews: #138 (wire_codec bench schema drift), #139 (verify_nonce slices a short HMAC), #140 (five readers with no fuzz target). #117 corrected by the keeper (TS already bounds the internalize field; bsv-rs has no internalize validator at all).
- The Studio's rustup stable is 1.95.0, CI's 1.99.1: a lane's local clippy misses new lints (#124's `chunks_exact_to_as_chunks`); told John once; `rustup update` is his.

## Where it stood (2026-10-24, 06:3xZ)

- `beta` at `f71923e` (#132 the ratchet merged 06:37Z, #78 closed). Landed since `32e8ad5` (PR #128): #129 the interim deny ignore entry (`f2f1676`); #134 `.gitleaks.toml` allowlisting `tests/fixtures/` and `fuzz/corpus/` (`88b25a9`; a planted key still fires); #130 fixtures (`86c0517`, #76 closed); #127 the RUSTSEC-2026-0387 move (`98499b9`, #125 closed; `deny` green with an empty ignore list); #133 nightly mutants (`baafa5e`, #81 closed); #131 arch rules and the feature matrix (`4e4b40c`, #80 closed). Each merged on its five required checks after a cold review; the merges ran as one background loop that rebased the rest after each landing.
- PR #135 into `main`: the advisory fix cherry-picked (`-x`) onto `main` for the 0.8.3 patch, without the `deny.toml` edit or the #115 section, with #134's `.gitleaks.toml` carried (main's `secrets` job scans every fetched ref and found beta's fixtures); the version bump and the tag are the owner's word. The keeper has `98499b9` and waits for #135's number green, then the owner's tag before the template's entry leaves.
- Ratchet #132 (landed `f71923e`): the `ratchet` job had refused the v0.8.2 bootstrap baseline against beta's tree (#116's gate and the k256 move moved four counters). The captain refreshed `library.Cargo.lock` by the documented procedure and re-recorded the baseline at `4e4b40c` (`--record --revision`), RATCHETS.md naming what moved; `--check` passed locally and the job on the PR; merged on the six checks.
- The review model: John's word via the CLI captain (Fable from the soonest-expiring weeks, then Opus) applied to the Codex-written branches: fixtures, arch, nightly and ratchet were reviewed on Opus, each came back fold, folds applied. #127 (Opus-written) had the captain's own Fable review (no Fable pool account; John may overrule). Still waiting for Fable or John's word that Opus may review Opus: fuzz, benches #124, fix-108 #119, fix-120 #121 (the queue below).
- Cross-CLI comparison of the HTTP JSON substrate at the CLI's `d93e077` fixtures: findings recorded on #105 as items 5 to 8 (protocolID/keyID casing, byte arrays against hex); the owner's and the keeper's word before any shape moves.

## Where it stood (2026-10-24, 04:3xZ)

- Landed on main: 0.8.2 (`efe12e6`, PR #102 merged 21:59Z, tagged `v0.8.2`, on crates.io 22:10Z, the Release run green).
- `beta` cut and protected (above). PR #103 merged 22:4xZ (rebase; `beta` at `77fe502`): ci.yml on both lines, release.yml's tag-shape check, RELEASING steps 11 to 16, `docs/lanes/`, this file. #75's exit test held: the PR ran every check. Merged on the four required checks with the captain's own review (the captain's work).
- Wave 1 launched 22:15Z: nine code lanes (table below), each in its worktree from `origin/beta` at `efe12e6`, task = README + brief, no model named. Each was told to rebase onto `origin/beta` before its report so its PR runs CI once #103 is in.
- Lane oracle-fuzz: the Codex run was stopped by its classifier at 3 minutes (rule 18: recorded, never retried by the tool). John named Opus 5.5 (22:5xZ, "try opus 55 for the fuzz") and pointed at `~/bsv/bsv-fuzz` (the house's differential harness); relaunched `--model opus` in the same worktree with the drafts left there, on the box.
- Findings filed: #105 (the HTTP JSON substrate's `certificateType` and nested hex key-linkage results diverge from BRC-100 and the TS JSON substrate; the CLI serves these shapes; found by the CLI's #69 fixtures). A wire shape: on the stack's rulings page, the owner's and the keeper's word before anything moves; the keeper's reading is a coordinated beta of bsv-rs and the CLI conforming to the BRC, the CLI accepting both shapes for one minor. #104 (duplicate dependency versions in the supply-chain gate) was filed by the owner's account at 22:16Z; it belongs to `oracle-deny`'s review.
- Blocked: nothing.
- Stale cca records: five `cli44-bsv-rs-review` lanes and one `lens-readme-bsvrs` lane show `blocked` with no account (the #44 wave); not this wave's.
- Two untracked symlinks at the checkout root (`bsv-rs` to itself, `rust-sdk` broken), dated August; left in place.

## The hour the tag landed (the captain's checklist; steps 1 to 3 done 2026-10-23)

1. `git fetch origin`; confirm the tag's commit is on `origin/main`; `git push origin <tag commit>:refs/heads/beta`; copy `main`'s protection to `beta` (`gh api` read back).
2. Commit `docs/lanes/`, `HANDOFF.md` and the #75 workflow edits on `lane/beta-line` from `beta`; PR into `beta`; cold review; merge. (Until `[main, beta]` is in `ci.yml` on `beta`, a PR into `beta` runs no CI: the #75 PR is the one exception, merged on the captain's own gate run, said so in the PR.)
3. Launch wave 1 from this folder, each as a background command, worktree per lane, no model named unless John says so:
   `cca run --name oracle-ratchet --class code --worktree oracle-ratchet "$(cat docs/lanes/oracle-ratchet.md)"` and the same for oracle-deny, oracle-arch, oracle-fixtures, oracle-benches, oracle-fuzz, oracle-nightly, oracle-dependents, oracle-northstar (nine at once; `oracle-benches` alone owns `Cargo.toml`). Note: `cca run --help` prints no `--name`/`--worktree`, but the script's `RUN_FLAGS` accept both, and `--worktree` defaults to `--name`.
4. Per lane at `done`: read the REPORT; `cca run --name <lane>-review --class review "Review the diff of branch lane/<lane> against origin/beta cold, given the issue text and the diff only: ..."`; fold or bounce; PR into `beta`; merge on green; update the wave table below.
5. Wave 2 after wave 1 merges: #87 (the CLI and the toolbox wait on it), #89, #85, #86, #88. Briefs to write when wave 1 is half landed.

## Wave 1 (opens on the tag)

| lane | issue | status | PR | review |
|---|---|---|---|---|
| beta-line | #75 | merged | #103 | captain's own |
| oracle-ratchet | #78 | MERGED `f71923e`, #78 closed; baseline at `4e4b40c`; `ratchet` job live | #132 | Opus: fold (the lock-refresh procedure documented and tested), applied |
| oracle-deny | #79 | MERGED `64c7013`, #79 closed; `deny` a required check on beta | #113 | Fable: merge, no edits |
| oracle-arch | #80 | MERGED `4e4b40c`, #80 closed; `features` and `wasm32` jobs live | #131 | Opus: fold (baseline paragraph names #115's fix; duplicate step dropped), applied |
| oracle-fixtures | #76 | MERGED `86c0517`, #76 closed; `fixtures` job live; the `.gitleaks.toml` allowlist (#134) went in ahead of it | #130 | Opus: fold (pin `ed1b015`, 67 commit lines re-recorded; FIXTURES.md), applied |
| oracle-benches | #77 | MERGED `eb7751c`, #77 closed; a Linux baseline entry and three comparison runs still ahead before the job is required | #124 | Opus: fold (token-absent skip, missing-entry warning, docs), applied by a fold lane; the old row: done (third pass, Opus, foreground) `05da1ad`: five benches, bench-compare, the macOS baseline (207 rows, Apple M1 Max, load 12 to 34); the first recording's abort was the capture pipe closing | #124 DRAFT | review queued; fold item: the benchmarks job fails closed without `BSV_SCRIPT_CORPUS_TOKEN` (skip script_spend with a warning instead) |
| oracle-fuzz | #82 | reviewed on Opus 5.5 (third attempt, foreground only): fold, six items; fold lane running on `lane/oracle-fuzz-review` from `f0b92d5` (rebase onto beta, one nightly workflow with #81's, gitleaks `[[allowlists]]`, crash titles, two wordings, the #140 gap line); the old row: done on the box (Opus 5.5) `box/lane/oracle-fuzz` `f0b92d5`, five commits (its origin push removed, see the lessons); filed #108, #109, #110, a comment on #105; review blocked on the box's pool; relaunch `--host box --reuse`; the review brief carries the `.gitleaks.toml` fold | | |
| oracle-nightly | #81 | MERGED `baafa5e`, #81 closed; `mutation-summary.json` is the scoreboard's file; the fuzz lane's `nightly.yml` reconciles with this one | #133 | Opus: fold (a skip never matches inside the kept root, pinned by the checker's test), applied |
| oracle-dependents | #83 | MERGED, #83 closed; `dependents` and `semver` jobs live, not required yet | #114 | Fable: fold (messagebox's version guard excluded; private rows skipped without the token); the captain cut the private app trees' repository paths and SHAs from the public lock pending the owner's word |
| oracle-northstar | #84 | MERGED `a3a8446`, #84 closed | #107 | Fable: fold, three edits applied |
| fix-108-certificate-reader | #108 | MERGED `6cdd0a8`, #108 closed | #119 | Opus: fold (one changelog sentence), applied |
| fix-120-index-varint | #120 | rebased on beta `d592ea5`, merge loop armed; #122 queued behind it | #121 | Opus: fold (parity note), applied; the ratchet's refusal folded by a lane (helper in `wire/mod.rs`, tests in the roundtrip file) |
| fix-0387-k256-0.14 | #125 | MERGED `98499b9`, #125 closed; the main patch is #135 | #127 | the captain's own (Fable); fold applied (`bdc0642`) |

## Lessons of the night (2026-10-23, late)

- Codex code lanes and one Fable review lane ended their turns with the gate running in the background and no REPORT written (the lane's session ends with its turn; the background wakeup never arrives). `cca runs --resume <lane>` picks a lane up, but the resumed lanes did it again. The answer that works: every brief ends with "Write the full REPORT before your turn ends: never leave the gate in the background and stop", and the cold review lane runs the full gate itself; CI on the PR is the gate of record for a cold-path change.
- The Studio reached a load of 255 on 10 cores with every captain's lanes on it (22:5xZ to 23:1xZ). The CLI captain's ask, honoured: no new Studio launch for an hour, benches never measured on a loaded machine (the brief's Linux baseline on the runner is the one that counts). New launches go `--host box` (the box needs a Claude login with room). The `--host box` launch pushes the checkout's HEAD as the lane's base: detach the checkout at the wanted commit before launching, then return to `main`.
- Issues on `beta` do not auto-close from a PR's "Closes": close them by hand with the landing note.
- A lane's worktree keeps its commits when stopped; relaunch with the same `--worktree` to continue.
- The Studio's internal disk fell under cca's 20 GB launch floor (19.2 GB) at 23:4xZ: Claude Code scratch under /private/tmp (the LOW captain's 6.7 GB, cleared at my ask) and the owner's app caches; `cca disk` reads it. Every launch anywhere refuses until it clears.
- A blocked launch leaves its worktree folder behind; the relaunch needs `--reuse` or a new name.
- Reviews default to Fable; when every Studio account's Fable points are out, review launches block until the reset (`cca status`); the owner has not named Opus for reviews.
- The dependents job's first hosted run caught #115: a function dead under every slice without `script`, fatal for a consumer on `block` alone under `-Dwarnings`. The fix carries a clippy step per published slice (#116). #80's `cargo hack --each-feature` is the general gate.
- The cause of the background-gate failures is the harness's ten-minute cap on one command: the full suite exceeds it in one command, the tool backgrounds it, the lane waits for a notification that never comes. Fable fell to it too (the BRC-56 review, 16:3xZ). The cure is README rule 11 as it now reads: compile with `--no-run`, then run; split what nears the cap. Every brief opens with it.
- CI's Test Suite had enumerated 34 of 73 integration files for months; the lanes' local full runs were the only whole-suite gate. The whole-suite step is one line; the first run found one platform fact (Windows CRLF on sha-pinned vectors), fixed by `.gitattributes`. Check the gate of record, not the badge.
- gitleaks reads any 64-hex literal in a test as a key: a lane that pushes a test with published vectors turns the secrets job red on every open PR until an allowlist entry by the literals (never the file) is on the base. Land the entry ahead of the PR as its own one-line PR.
- Two fixes each green alone can be red together (#119 and #121 on the 189-byte input): the loop merges on each PR's own head; a whole-suite run on the merged beta is what tells. With #147 in, every PR's run is that.
- A lane that ends its turn with the gate "in the background" writes no REPORT and its gate dies with the session: four lanes on 2026-10-24 (fuzz review twice, #87, and Codex lanes the night before), Opus and Codex alike. `cca runs --resume` repeats it. What works: the brief's opening rule "every command in the foreground; the last thing you print is the REPORT" (README rule 11 now), and for a lane that already stopped, a fresh lane in the same worktree with `--reuse` and that rule, told what is committed and what the partial logs hold.
- The ratchet's bootstrap baseline is the line's tree at the moment the ratchet lands, not the tag's: recorded at v0.8.2, it refused the four landings between. Re-record with `--record --revision <beta tip>` after a rebase, with the lock refresh when a dependency moved, and say in RATCHETS.md what moved and from which PRs. Any later red ratchet is a real increase.
- gitleaks runs over every fetched branch and reads identity-key hex in fixtures as generic API keys: `.gitleaks.toml` allowlists `tests/fixtures/` and `fuzz/corpus/` by path (#134); a planted key outside them still fires. A fixture lane's branch trips it until the allowlist is on the base.
- A PR to `main` is prepared, never merged, without the owner's word: `main` is the stable line and the patch's merge is the step before the tag.
- Lanes never push (the stack's rule; the first briefs said only "not to main or beta"). The fuzz lane pushed `lane/oracle-fuzz` to origin; the `secrets` job (gitleaks over every fetched branch) then failed on EVERY PR with 17 generic-api-key findings in the fuzz seed corpus (identity-key hex in `fuzz/corpus/fuzz_auth_messages/*` and one string in `fuzz/corpus-gen/src/main.rs`, none a secret). The captain removed the origin copy (the commits are on the box and in the captain's local `lane/oracle-fuzz`); the fix is a `.gitleaks.toml` allowlisting `fuzz/corpus/` and the generator's literal, folded into the fuzz review. The README now says: never push; the captain pushes and opens the PR.

## What the dependents' captains asked (captain-bsv-wallet-cli, 2026-10-23)

- The CLI pins bsv-rs exactly (`=0.8.1`); it re-pins to `=0.8.2` the moment the keeper's tag is on the index.
- Its order of need: #87, then #76, then #83 (the dependents job builds bsv-wallet-toolbox-rs and bsv-wallet-cli by path override; the six Cloudflare workers once their captains name the slices).
- The BRC pin for every citation: `~/bsv/brcs` upstream/master at `5119a9b` (2026-10-19), the CLI's #69 pin. The CLI captain sends the path of its wire fixtures when #69 lands; #76's lane diffs against them.
- A beta prerelease is announced to the toolbox's captain (captain-bsv-wallet-toolbox-rs, epic Calhooon/bsv-wallet-toolbox-rs#80) and the CLI's captain (epic Calhooon/bsv-wallet-cli#106) with the fixtures' diff before it publishes.
- The script oracle's captain is captain-bsv-script-lean; its `harness/run --impl bsv-rs --corpus seed` is the before-and-after on every change under `src/script/` or `src/transaction/`; #97 makes it a PR check.
- The picture of the layers and the loop: http://127.0.0.1:8790/ on this machine.

## The queue (2026-10-24 18:0xZ)

Merging on green: #147 (whole suite), #143 (#87), #150 (#148). Draft on a word: #155 (#149, the writer's signature), #135 and #151 (the 0.8.3 merge and tag, the owner's line). Next lanes: #154 (the pin move) after #155 lands; #146 step 2 (the ci.yml guard); then #89, #85, #86, #88 with briefs to write. The nightly's fuzz and mutation jobs have not yet run on GitHub; the next scheduled run is their proof.

Open issues, in queue order: #126 (P-256 verify 2x slower), #117 (the internalize validator, behind #87's landing now), #139 (verify_nonce), #140 (five fuzz targets), #138 (wire_codec), #152 (wasm32 with http), #109 and #110 (rulings pending), #105 items 1 to 8 (the coordinated beta; #117 and the pin move touch it), #104. Owner decisions outstanding: the 0.8.3 merge and tag; #149's signature; the private app trees' paths in `docs/dependents.lock`; `DEPENDENTS_READ_TOKEN` and `BSV_SCRIPT_CORPUS_TOKEN`; the box's Claude login; `rustup update` on the Studio.

## Rulings received 2026-10-24 00:1xZ (the keeper, relaying the owner)

- #117: internalizeAction refuses `insertionRemittance.customInstructions` over 1,000 UTF-8 bytes (BRC-100 at `5119a9b`:867; no bound at `ed1b015`:860); lands in the coordinated beta with the CLI and the toolbox after the CLI captain's reading of today's app traffic; queued behind #87.
- BRC-56: bsv-rs holds the 32-byte X with leading zeros (as Go, Python, rs-sdk); ts-sdk at `edf6e03` drops them, one key in 256 differs. Nothing of ours emits the wrong tag; an acceptance window waits for the owner's word.
- RUSTSEC-2026-0387 (03:4xZ, raised by the CLI captain): recorded by the keeper with #125 as the tracking issue; the ignore entry leaves the template on the 0.8.3 tag's day.
- The CLI's wire fixtures (#69) are merged on bsv-wallet-cli beta `d93e077` (tests/wire/*.json, 106 files; docs/WIRE.md); the #76 review diffs each call against them.
- #120 (01:0xZ): refuse a varint output index above u32::MAX with a typed error naming the field; no owner's word needed (no valid wire changes). Done on `lane/fix-120-index-varint`.
- The deny.toml departures from the stack's seed are the record (stricter, by design); take the seed's new words the same way when it is re-stamped.

## What the keeper said (captain-bsv-stack-lean, 2026-10-23 22:3xZ)

- The division: bsv-rs's day-to-day is this captain's; the stack, the line of record (`~/bsv/epoch/LINE.md`), the pins and every charter word stay with the keeper. A pin move, a wire-shape change or a charter word (a transition, a word, the evidence rule) goes through the keeper by message or a bsv-stack-lean issue, and this captain waits for the word. The captains' channel is `~/bsv/epoch/IDENTITY-PROGRAM-2026-10.md`, one line per captain per round, committed by pathspec.
- 0.8.2 is on crates.io (22:10Z), the Release run green. `lane/bsv-rs-73-transport-fault` is the stack's branch and stays until the keeper removes it.
- Two inputs to Phase 0: the stack's matrix (`docs/MATRIX.md`, the SDK column) names bsv-rs's gaps at v0.8.1 (rows 26, 30, 23, 35: NETWORK_ERROR for a post-write transport failure, bsv-rs #65; a bare 429 lost with no Retry-After, bsv-rs #66; one courier per call, composition the caller's; no pending state or deadline on a wallet call), to enter the research queue under #87, #94, #95 (folded into the northstar brief); `lean/BeefOfAnySize.lean` (177 theorems) is the definition the BEEF fuzz corpus should cover (folded into the fuzz brief; the running fuzz lane did not get this line, so it is checked at its review).

## The BRC pin (the keeper's word, 2026-10-23 23:0xZ)

The line's pin of `bsv-blockchain/BRCs` is `ed1b015` (2026-10-05; the stack's `docs/PROVENANCE.md`). `5119a9b` (2026-10-19, upstream/master, the CLI's #69 pin) is not on the line. BRC-100 differs between them in wire-shape ways (listOutputs' `totalOutputs` as a decimal string for a BRC-112 balance query, `spendable` as a boolean under BRC-207, internalizeAction's 1000-byte `customInstructions` bound); the keeper runs a recon lane to list each change as an extension or a divergence and propose the re-pin to the owner; the fixtures move pins in one step across the three crates, never one crate ahead. Every bsv-rs citation is at `ed1b015` with the `5119a9b` clause (README rule 4). The running fixtures lane was briefed with `5119a9b`: re-cite at its review. Each beta prerelease gets one channel line, "a prerelease, not on the line", with its sha.

## Lane rules (the stack's; the short form)

Worktrees, scratch and `CARGO_TARGET_DIR` under `$TMPDIR` or `~/bsv/targets`, never a literal `/tmp`; evidence under `/Volumes/Lanes/out/bsv-rs/`. A lane names an account, provider or model only on the owner's word (the relay says John's rule is Fable from the soonest-expiring weeks, then Opus; this captain applies it when John says it here). Read a lane's REPORT, never its transcript. Hazard material goes to `cca run --hazard`. Never `/login` or `/model` in a session.
