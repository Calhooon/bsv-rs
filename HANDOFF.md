# HANDOFF: captain-bsv-rs

The captain's running record. Re-orient from this file and `cca runs --project bsv-rs --open` after any restart. The rules are `CLAUDE.md`; the programme is the epic Calhooon/bsv-rs#101 and issues #75 to #100; the lane briefs are `docs/lanes/`.

## The green light (John, 2026-10-23, relayed by captain-bsv-wallet-cli and matching his own words to this captain)

The programme runs continuously: brief a lane, launch it, land it, launch the next. The owner's word is needed for, and only for: any tag or release (prerelease included), any pin move in a consumer, any change to a public API's shape, any spend from a wallet. The one gate before cutting is the keeper's `v0.8.2` tag.

## The lines

- `main`: the stable line. Quick fixes only. Any tag is the owner's word. `main` merges into `beta` after every stable patch.
- `release/0.8.2`: the keeper's (captain-bsv-stack-lean). PR #102 (release/0.8.2 into main) is open and green on every job. Nothing here touches it, the tag `v0.8.2`, the `lane/*` branches or the `[Unreleased]` heading until the tag exists.
- `beta`: this captain's line (#75). Cut from `main` the hour `v0.8.2` exists, never under the release branch; protected like `main`; CI on `[main, beta]`; every programme PR targets `beta`; `vX.Y.Z-beta.N` publishes a prerelease; `beta` merges into `main` at a phase exit as the next minor after the toolbox's and the CLI's betas built against a prerelease and the CLI's gate ran. NOT YET CUT.

## Where it stands (2026-10-23, evening)

- Landed on main: 0.8.1 (the atomic rule on the subject's graph), then the #73 transport-fault commits under `[Unreleased]`, which release/0.8.2 carries.
- In flight: PR #102 (0.8.2), the keeper's to merge and tag. A background watch in this captain's session polls origin for the tag every five minutes (48 h) and wakes the captain.
- Written, uncommitted, in the checkout: `docs/lanes/README.md` and the ten wave-1 briefs (beta-line, oracle-fixtures, oracle-benches, oracle-ratchet, oracle-deny, oracle-arch, oracle-nightly, oracle-fuzz, oracle-dependents, oracle-northstar), and this file. They land in the #75 PR into `beta`.
- Blocked: the beta cut and every lane launch, on the `v0.8.2` tag.
- Stale cca records: five `cli44-bsv-rs-review` lanes and one `lens-readme-bsvrs` lane show `blocked` with no account (the #44 wave); not this wave's.
- Two untracked symlinks at the checkout root (`bsv-rs` to itself, `rust-sdk` broken), dated August; left in place.

## The hour the tag lands (the captain's checklist)

1. `git fetch origin`; confirm the tag's commit is on `origin/main`; `git push origin <tag commit>:refs/heads/beta`; copy `main`'s protection to `beta` (`gh api` read back).
2. Commit `docs/lanes/`, `HANDOFF.md` and the #75 workflow edits on `lane/beta-line` from `beta`; PR into `beta`; cold review; merge. (Until `[main, beta]` is in `ci.yml` on `beta`, a PR into `beta` runs no CI: the #75 PR is the one exception, merged on the captain's own gate run, said so in the PR.)
3. Launch wave 1 from this folder, each as a background command, worktree per lane, no model named unless John says so:
   `cca run --name oracle-ratchet --class code --worktree oracle-ratchet "$(cat docs/lanes/oracle-ratchet.md)"` and the same for oracle-deny, oracle-arch, oracle-fixtures, oracle-benches, oracle-fuzz, oracle-nightly, oracle-dependents, oracle-northstar (nine at once; `oracle-benches` alone owns `Cargo.toml`). Note: `cca run --help` prints no `--name`/`--worktree`, but the script's `RUN_FLAGS` accept both, and `--worktree` defaults to `--name`.
4. Per lane at `done`: read the REPORT; `cca run --name <lane>-review --class review "Review the diff of branch lane/<lane> against origin/beta cold, given the issue text and the diff only: ..."`; fold or bounce; PR into `beta`; merge on green; update the wave table below.
5. Wave 2 after wave 1 merges: #87 (the CLI and the toolbox wait on it), #89, #85, #86, #88. Briefs to write when wave 1 is half landed.

## Wave 1 (opens on the tag)

| lane | issue | status | PR | review |
|---|---|---|---|---|
| beta-line | #75 | briefed | | |
| oracle-ratchet | #78 | briefed | | |
| oracle-deny | #79 | briefed | | |
| oracle-arch | #80 | briefed | | |
| oracle-fixtures | #76 | briefed | | |
| oracle-benches | #77 | briefed | | |
| oracle-fuzz | #82 | briefed | | |
| oracle-nightly | #81 | briefed | | |
| oracle-dependents | #83 | briefed | | |
| oracle-northstar | #84 | briefed | | |

## What the dependents' captains asked (captain-bsv-wallet-cli, 2026-10-23)

- The CLI pins bsv-rs exactly (`=0.8.1`); it re-pins to `=0.8.2` the moment the keeper's tag is on the index.
- Its order of need: #87, then #76, then #83 (the dependents job builds bsv-wallet-toolbox-rs and bsv-wallet-cli by path override; the six Cloudflare workers once their captains name the slices).
- The BRC pin for every citation: `~/bsv/brcs` upstream/master at `5119a9b` (2026-10-19), the CLI's #69 pin. The CLI captain sends the path of its wire fixtures when #69 lands; #76's lane diffs against them.
- A beta prerelease is announced to the toolbox's captain (captain-bsv-wallet-toolbox-rs, epic Calhooon/bsv-wallet-toolbox-rs#80) and the CLI's captain (epic Calhooon/bsv-wallet-cli#106) with the fixtures' diff before it publishes.
- The script oracle's captain is captain-bsv-script-lean; its `harness/run --impl bsv-rs --corpus seed` is the before-and-after on every change under `src/script/` or `src/transaction/`; #97 makes it a PR check.
- The picture of the layers and the loop: http://127.0.0.1:8790/ on this machine.

## Lane rules (the stack's; the short form)

Worktrees, scratch and `CARGO_TARGET_DIR` under `$TMPDIR` or `~/bsv/targets`, never a literal `/tmp`; evidence under `/Volumes/Lanes/out/bsv-rs/`. A lane names an account, provider or model only on the owner's word (the relay says John's rule is Fable from the soonest-expiring weeks, then Opus; this captain applies it when John says it here). Read a lane's REPORT, never its transcript. Hazard material goes to `cca run --hazard`. Never `/login` or `/model` in a session.
