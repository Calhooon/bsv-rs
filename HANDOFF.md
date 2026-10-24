# HANDOFF: captain-bsv-rs

The captain's running record. Re-orient from this file and `cca runs --project bsv-rs --open` after any restart. The rules are `CLAUDE.md`; the programme is the epic Calhooon/bsv-rs#101 and issues #75 to #100; the lane briefs are `docs/lanes/`.

## The green light (John, 2026-10-23, relayed by captain-bsv-wallet-cli and matching his own words to this captain)

The programme runs continuously: brief a lane, launch it, land it, launch the next. The owner's word is needed for, and only for: any tag or release (prerelease included), any pin move in a consumer, any change to a public API's shape, any spend from a wallet. The one gate before cutting is the keeper's `v0.8.2` tag.

## The lines

- `main`: the stable line. Quick fixes only. Any tag is the owner's word. `main` merges into `beta` after every stable patch.
- `release/0.8.2`: the keeper's (captain-bsv-stack-lean). PR #102 (release/0.8.2 into main) is open and green on every job. Nothing here touches it, the tag `v0.8.2`, the `lane/*` branches or the `[Unreleased]` heading until the tag exists.
- `beta`: this captain's line (#75). CUT 2026-10-23 22:1xZ from `main` at `v0.8.2` (`efe12e6`); protection copied from `main` (the four contexts, strict, admins, linear history, no force push or delete; read back with `gh api repos/Calhooon/bsv-rs/branches/beta/protection`); CI on `[main, beta]` by PR #103; every programme PR targets `beta`; `vX.Y.Z-beta.N` publishes a prerelease (the owner's word); `beta` merges into `main` at a phase exit as the next minor after the toolbox's and the CLI's betas built against a prerelease and the CLI's gate ran.

## Where it stands (2026-10-24, 01:3xZ)

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
| oracle-ratchet | #78 | committed `826a041`, `d1a3cbb`; review brief ready (`tasks/review-oracle-ratchet.txt` in the captain's scratchpad); launch at the reset | | |
| oracle-deny | #79 | MERGED `64c7013`, #79 closed; `deny` a required check on beta | #113 | Fable: merge, no edits |
| oracle-arch | #80 | committed `33ee129`; review blocked on the pool; relaunch with `--reuse` | | |
| oracle-fixtures | #76 | committed `28d0c6f`; review launch blocked twice (Fable points out on the Studio); relaunch with `--reuse` at the reset | | |
| oracle-benches | #77 | relaunched 01:0xZ `--reuse` (Opus); three commits (`13884dd`, `939def4`, `d57cb77`); its baseline recording runs detached, waiting for a 5-minute load under 20, giving up after 90 minutes (a timer checks at 02:3xZ); the committed `baseline.json` is the first run's, recorded under load, so the review judges the Linux runner's as the one that counts | | review queued |
| oracle-fuzz | #82 | done on the box (Opus 5.5) `box/lane/oracle-fuzz` `f0b92d5`, five commits (its origin push removed, see the lessons); filed #108, #109, #110, a comment on #105; review blocked on the box's pool; relaunch `--host box --reuse`; the review brief carries the `.gitleaks.toml` fold | | |
| oracle-nightly | #81 | committed `14fb672`; review brief ready; launch at the reset (coordinate with the fuzz lane's `nightly.yml`) | | |
| oracle-dependents | #83 | MERGED, #83 closed; `dependents` and `semver` jobs live, not required yet | #114 | Fable: fold (messagebox's version guard excluded; private rows skipped without the token); the captain cut the private app trees' repository paths and SHAs from the public lock pending the owner's word |
| oracle-northstar | #84 | MERGED `a3a8446`, #84 closed | #107 | Fable: fold, three edits applied |
| fix-108-certificate-reader | #108 | briefed 23:1xZ; the box had no Claude login with room, relaunch pending (brief `docs/lanes/fix-108-certificate-reader.md`) | | |

## Lessons of the night (2026-10-23, late)

- Codex code lanes and one Fable review lane ended their turns with the gate running in the background and no REPORT written (the lane's session ends with its turn; the background wakeup never arrives). `cca runs --resume <lane>` picks a lane up, but the resumed lanes did it again. The answer that works: every brief ends with "Write the full REPORT before your turn ends: never leave the gate in the background and stop", and the cold review lane runs the full gate itself; CI on the PR is the gate of record for a cold-path change.
- The Studio reached a load of 255 on 10 cores with every captain's lanes on it (22:5xZ to 23:1xZ). The CLI captain's ask, honoured: no new Studio launch for an hour, benches never measured on a loaded machine (the brief's Linux baseline on the runner is the one that counts). New launches go `--host box` (the box needs a Claude login with room). The `--host box` launch pushes the checkout's HEAD as the lane's base: detach the checkout at the wanted commit before launching, then return to `main`.
- Issues on `beta` do not auto-close from a PR's "Closes": close them by hand with the landing note.
- A lane's worktree keeps its commits when stopped; relaunch with the same `--worktree` to continue.
- The Studio's internal disk fell under cca's 20 GB launch floor (19.2 GB) at 23:4xZ: Claude Code scratch under /private/tmp (the LOW captain's 6.7 GB, cleared at my ask) and the owner's app caches; `cca disk` reads it. Every launch anywhere refuses until it clears.
- A blocked launch leaves its worktree folder behind; the relaunch needs `--reuse` or a new name.
- Reviews default to Fable; when every Studio account's Fable points are out, review launches block until the reset (`cca status`); the owner has not named Opus for reviews.
- The dependents job's first hosted run caught #115: a function dead under every slice without `script`, fatal for a consumer on `block` alone under `-Dwarnings`. The fix carries a clippy step per published slice (#116). #80's `cargo hack --each-feature` is the general gate.
- Lanes never push (the stack's rule; the first briefs said only "not to main or beta"). The fuzz lane pushed `lane/oracle-fuzz` to origin; the `secrets` job (gitleaks over every fetched branch) then failed on EVERY PR with 17 generic-api-key findings in the fuzz seed corpus (identity-key hex in `fuzz/corpus/fuzz_auth_messages/*` and one string in `fuzz/corpus-gen/src/main.rs`, none a secret). The captain removed the origin copy (the commits are on the box and in the captain's local `lane/oracle-fuzz`); the fix is a `.gitleaks.toml` allowlisting `fuzz/corpus/` and the generator's literal, folded into the fuzz review. The README now says: never push; the captain pushes and opens the PR.

## What the dependents' captains asked (captain-bsv-wallet-cli, 2026-10-23)

- The CLI pins bsv-rs exactly (`=0.8.1`); it re-pins to `=0.8.2` the moment the keeper's tag is on the index.
- Its order of need: #87, then #76, then #83 (the dependents job builds bsv-wallet-toolbox-rs and bsv-wallet-cli by path override; the six Cloudflare workers once their captains name the slices).
- The BRC pin for every citation: `~/bsv/brcs` upstream/master at `5119a9b` (2026-10-19), the CLI's #69 pin. The CLI captain sends the path of its wire fixtures when #69 lands; #76's lane diffs against them.
- A beta prerelease is announced to the toolbox's captain (captain-bsv-wallet-toolbox-rs, epic Calhooon/bsv-wallet-toolbox-rs#80) and the CLI's captain (epic Calhooon/bsv-wallet-cli#106) with the fixtures' diff before it publishes.
- The script oracle's captain is captain-bsv-script-lean; its `harness/run --impl bsv-rs --corpus seed` is the before-and-after on every change under `src/script/` or `src/transaction/`; #97 makes it a PR check.
- The picture of the layers and the loop: http://127.0.0.1:8790/ on this machine.

## The review queue (blocked 2026-10-24 00:4xZ onward)

Seven branches await a cold review on a model other than their lane's: fixtures `28d0c6f` (Codex), arch `33ee129` (Codex), nightly `14fb672` (Codex), ratchet `d1a3cbb` (Codex), fuzz `box/lane/oracle-fuzz` `f0b92d5` (Opus; its review brief carries the `.gitleaks.toml` fold), fix-108 `afe0f83` (Opus, PR #119 draft), fix-120 `7638e00` (Opus, PR #121 draft). Review lanes default to Fable; every POOL account's Fable is at 0 until its week resets (the soonest about 13:00Z on 2026-10-24); the accounts holding Fable are captains' own (rule 4). The owner has been asked (01:0xZ) whether reviews may run on Opus meanwhile (`--model opus`; for the Opus-written branches that is the same model, so those three need Fable or Codex, and Codex's week is at 0%). The box has no Claude login with room (`cca login` there is the owner's). The task files are in the captain's scratchpad `tasks/review-*.txt`; relaunch with `--reuse` where a worktree folder exists.

Open issues filed tonight, in queue order: #117 (the 1,000-byte customInstructions cap, the owner's ruling; the coordinated beta, behind #87), #122 (nine more varint-to-u32 casts, after #121 lands), #109 and #110 (the fuzz lane's divergences, rulings pending), #105 (the JSON substrate's two shapes, the owner's and the keeper's word), #104 (duplicate dependency versions). #120 and #115 are fixed on branches or beta.

## Rulings received 2026-10-24 00:1xZ (the keeper, relaying the owner)

- #117: internalizeAction refuses `insertionRemittance.customInstructions` over 1,000 UTF-8 bytes (BRC-100 at `5119a9b`:867; no bound at `ed1b015`:860); lands in the coordinated beta with the CLI and the toolbox after the CLI captain's reading of today's app traffic; queued behind #87.
- BRC-56: bsv-rs holds the 32-byte X with leading zeros (as Go, Python, rs-sdk); ts-sdk at `edf6e03` drops them, one key in 256 differs. Nothing of ours emits the wrong tag; an acceptance window waits for the owner's word.
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
