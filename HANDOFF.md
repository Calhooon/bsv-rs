# HANDOFF: captain-bsv-rs

The captain's running record. Re-orient from this file and `cca runs --project bsv-rs --open` after any restart. The rules are `CLAUDE.md`; the programme is the epic Calhooon/bsv-rs#101 and issues #75 to #100; the lane briefs are `docs/lanes/`.

## The green light (John, 2026-10-23, relayed by captain-bsv-wallet-cli and matching his own words to this captain)

The programme runs continuously: brief a lane, launch it, land it, launch the next. The owner's word is needed for, and only for: any tag or release (prerelease included), any pin move in a consumer, any change to a public API's shape, any spend from a wallet. The one gate before cutting is the keeper's `v0.8.2` tag.

## The lines

- `main`: the stable line. Quick fixes only. Any tag is the owner's word. `main` merges into `beta` after every stable patch.
- `release/0.8.2`: the keeper's (captain-bsv-stack-lean). PR #102 (release/0.8.2 into main) is open and green on every job. Nothing here touches it, the tag `v0.8.2`, the `lane/*` branches or the `[Unreleased]` heading until the tag exists.
- `beta`: this captain's line (#75). CUT 2026-10-23 22:1xZ from `main` at `v0.8.2` (`efe12e6`); protection copied from `main` (the four contexts, strict, admins, linear history, no force push or delete; read back with `gh api repos/Calhooon/bsv-rs/branches/beta/protection`); CI on `[main, beta]` by PR #103; every programme PR targets `beta`; `vX.Y.Z-beta.N` publishes a prerelease (the owner's word); `beta` merges into `main` at a phase exit as the next minor after the toolbox's and the CLI's betas built against a prerelease and the CLI's gate ran.

## Where it stands (2026-10-23, 22:20Z)

- Landed on main: 0.8.2 (`efe12e6`, PR #102 merged 21:59Z, tagged `v0.8.2`, on crates.io 22:10Z, the Release run green).
- `beta` cut and protected (above). PR #103 (`lane/beta-line` into `beta`): ci.yml on both lines, release.yml's tag-shape check, RELEASING steps 11 to 16, `docs/lanes/`, this file. Merge on green; it is the one PR merged on the captain's own review (it is the captain's work).
- Wave 1 launched 22:15Z: nine code lanes (table below), each in its worktree from `origin/beta` at `efe12e6`, task = README + brief, no model named. Each was told to rebase onto `origin/beta` before its report so its PR runs CI once #103 is in.
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
| beta-line | #75 | PR open | #103 | captain's own |
| oracle-ratchet | #78 | running | | |
| oracle-deny | #79 | running | | |
| oracle-arch | #80 | running | | |
| oracle-fixtures | #76 | running | | |
| oracle-benches | #77 | running | | |
| oracle-fuzz | #82 | running | | |
| oracle-nightly | #81 | running | | |
| oracle-dependents | #83 | running | | |
| oracle-northstar | #84 | running | | |

## What the dependents' captains asked (captain-bsv-wallet-cli, 2026-10-23)

- The CLI pins bsv-rs exactly (`=0.8.1`); it re-pins to `=0.8.2` the moment the keeper's tag is on the index.
- Its order of need: #87, then #76, then #83 (the dependents job builds bsv-wallet-toolbox-rs and bsv-wallet-cli by path override; the six Cloudflare workers once their captains name the slices).
- The BRC pin for every citation: `~/bsv/brcs` upstream/master at `5119a9b` (2026-10-19), the CLI's #69 pin. The CLI captain sends the path of its wire fixtures when #69 lands; #76's lane diffs against them.
- A beta prerelease is announced to the toolbox's captain (captain-bsv-wallet-toolbox-rs, epic Calhooon/bsv-wallet-toolbox-rs#80) and the CLI's captain (epic Calhooon/bsv-wallet-cli#106) with the fixtures' diff before it publishes.
- The script oracle's captain is captain-bsv-script-lean; its `harness/run --impl bsv-rs --corpus seed` is the before-and-after on every change under `src/script/` or `src/transaction/`; #97 makes it a PR check.
- The picture of the layers and the loop: http://127.0.0.1:8790/ on this machine.

## What the keeper said (captain-bsv-stack-lean, 2026-10-23 22:3xZ)

- The division: bsv-rs's day-to-day is this captain's; the stack, the line of record (`~/bsv/epoch/LINE.md`), the pins and every charter word stay with the keeper. A pin move, a wire-shape change or a charter word (a transition, a word, the evidence rule) goes through the keeper by message or a bsv-stack-lean issue, and this captain waits for the word. The captains' channel is `~/bsv/epoch/IDENTITY-PROGRAM-2026-10.md`, one line per captain per round, committed by pathspec.
- 0.8.2 is on crates.io (22:10Z), the Release run green. `lane/bsv-rs-73-transport-fault` is the stack's branch and stays until the keeper removes it.
- Two inputs to Phase 0: the stack's matrix (`docs/MATRIX.md`, the SDK column) names bsv-rs's gaps at v0.8.1 (rows 26, 30, 23, 35: NETWORK_ERROR for a post-write transport failure, bsv-rs #65; a bare 429 lost with no Retry-After, bsv-rs #66; one courier per call, composition the caller's; no pending state or deadline on a wallet call), to enter the research queue under #87, #94, #95 (folded into the northstar brief); `lean/BeefOfAnySize.lean` (177 theorems) is the definition the BEEF fuzz corpus should cover (folded into the fuzz brief; the running fuzz lane did not get this line, so it is checked at its review).

## Lane rules (the stack's; the short form)

Worktrees, scratch and `CARGO_TARGET_DIR` under `$TMPDIR` or `~/bsv/targets`, never a literal `/tmp`; evidence under `/Volumes/Lanes/out/bsv-rs/`. A lane names an account, provider or model only on the owner's word (the relay says John's rule is Fable from the soonest-expiring weeks, then Opus; this captain applies it when John says it here). Read a lane's REPORT, never its transcript. Hazard material goes to `cca run --hazard`. Never `/login` or `/model` in a session.
