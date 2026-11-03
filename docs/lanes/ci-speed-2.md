# CI speed, round 1, cut 2 (with cut 3): the small gates bundled into `lint` and `checks`, the required contexts re-pointed, the twin runs

Branch `lane/ci-speed-2` from `origin/beta` at `ffff16d0` (the worktree opened at
`efe12e63`, main's tip, and was reset to `origin/beta` before any work). The fleet's speed
line on the owner's word: free cuts, no own hardware, no paid runners. The sibling lane
`ci-speed-1` cuts the `test` job and its cache in the same file; this lane touches every
other job and nothing of `test` (lines 1 to 247 of `ci.yml`, the `on:` block, the header,
the dependents jobs, `semver` and `test`, are byte for byte `ffff16d0`'s but for two
comment lines of the header).

## The measurement: run 41537280176 (a pull request into `beta`, `lane/fix-654`)

Created 2026-11-02T22:26:27Z, completed 22:55:38Z: 29 m 11 s, the `Test Suite` its
critical path (started 22:29:37Z, 1,561 s). Read from
`gh api repos/Calhooon/bsv-rs/actions/runs/41537280176/jobs`, `steps[].started_at` to
`completed_at`. Setup steps: `Set up job`, the checkouts, the toolchain, the cache
restore, a tool's install or build, the scratch-directory and lockfile steps, the `Post`
steps; gate steps: the commands that judge. "Outside the steps" is the job's wall clock
less both (runner start and teardown the steps do not cover).

| Job | Queued (from the run's creation) | Job wall | Setup steps | Gate steps | Outside the steps |
|---|---:|---:|---:|---:|---:|
| `Test Suite (ubuntu-latest, stable)` | 3m10s | 1561 s | 171 s | 1386 s | 4 s |
| `secrets` | 3m54s | 41 s | 35 s | 0 s | 6 s |
| `deny` | 4m20s | 144 s | 139 s | 3 s | 2 s |
| `Documentation` | 5m52s | 32 s | 13 s | 16 s | 3 s |
| `wasm32 (combined)` | 6m35s | 87 s | 10 s | 63 s | 14 s |
| `semver` | 6m43s | 366 s | 300 s | 46 s | 20 s |
| `Clippy` | 7m04s | 95 s | 9 s | 84 s | 2 s |
| `fixtures` | 7m46s | 66 s | 11 s | 33 s | 22 s |
| `main-in-beta` | 8m53s | 7 s | 3 s | 1 s | 3 s |
| `ratchet` | 9m13s | 60 s | 18 s | 38 s | 4 s |
| `vectors` | 9m25s | 61 s | 19 s | 40 s | 2 s |
| `Rustfmt` | 9m34s | 39 s | 4 s | 5 s | 30 s |

The ten small jobs (all but `Test Suite` and `semver`): 632 s of runner time, 261 s of it
setup steps, 283 s gate steps, 88 s outside the steps; each held a slot of the account's
twenty and queued 4 to 9.5 minutes for it. The largest setups: `deny` 128 s building
cargo-deny from source (no cache), `secrets` 31 s building gitleaks, `semver` 287 s
building cargo-semver-checks. `semver`'s tool cache misses on every pull request: it is
saved under the pull request's own ref, which no other pull request reads, and `semver`
never runs on a push to a line, so the line never holds the entry (a finding for a next
cut; `semver` is unchanged here). The raw job list is
`/Volumes/Lanes/out/bsv-rs/ci-speed-2/run-41537280176-jobs.json`.

## The bundling

`lint` (one runner): checkout (full history, for ratchet's base), the 1.95.0 toolchain
(clippy, rustfmt: ratchet's measurement toolchain) then stable (clippy, rustfmt, the
wasm32 target; installed after, so it is the default), cargo-deny 0.20.2 through
`taiki-e/install-action@682ce6c3c696a4cd5168a05f98e51aa02b877941` (v2.89.1; its manifest
carries 0.20.2 with checksums; the release binary in place of a 2-minute build), one
`Swatinem/rust-cache@d1527c8f67ef9af357290475d4af4b0fab8f12e0` (v2.9.3, `shared-key:
lint`, ratchet's target directory under `cache-directories`), the lockfile resolved once
(`cargo generate-lockfile`, after the cache's key is taken; deny reads it `--locked`), then
the gates:

| Step (`id`) | Gate | What it runs (as before) |
|---|---|---|
| `fmt` | Rustfmt | `cargo fmt --all -- --check`, the two fuzz manifests |
| `clippy` | Clippy | `cargo clippy --all-targets --all-features -- -D warnings`, then each of the twelve published slices alone |
| `deny` | deny | `cargo-deny --locked` on all features, the Cloudflare slice for wasm32, default features |
| `ratchet` | ratchet | the measurement tool's fmt, clippy and tests at 1.95.0, then `tools/ratchet/run --check --against <base>` (`RUSTFLAGS=""`, its own target directory) |

`checks` (one runner): checkout (full history, for secrets on a push), the ts-stack
corpus at `edf6e03` (sparse), stable with the wasm32 target, one `Swatinem/rust-cache`
(`shared-key: checks`), the lockfile when none is committed, then:

| Step (`id`) | Gate | What it runs (as before) |
|---|---|---|
| `vectors` | vectors | the corpus asserted present, the chain primitive vectors, the vector-backed tests |
| `fixtures` | fixtures | `cargo test --features "full,http" --test fixtures_replay --locked`, `BSV_FIXTURES_RECORD=0` |
| `secrets` | secrets | gitleaks 8.30.1 built from its sha256-pinned source, the scan of the commits the event brings |
| `docs` | Documentation | `cargo doc --no-deps --all-features`, `RUSTDOCFLAGS=-Dwarnings` |
| `wasm32` | wasm32 (combined) | the combined slice built, the slice with `http` refused at build.rs, the diagnostic cdylib measured |

Every gate step: `if: ${{ !cancelled() && steps.ready.outcome == 'success' }}` (it runs
when an earlier gate failed; it does not run on a broken setup, and the verdict step
reads it `FAIL (skipped)`), and an exit trap printing `PASS <gate>` or `FAIL <gate>`. The
last step, `Every gate passed` on `!cancelled()`, reads every gate's outcome, prints its
line and fails naming the gates that did not pass (`::error::lint: 2 gate(s) failed:
Clippy, deny`). The wasm32 consumer stays no matrix: one consumer here (the other five are
`features.yml`'s), so nothing needs one. One cache per job, saved only by a push to a line
(`save-if`): a pull request restores its line's build, never fills the account's cache
budget with its own ref's entries, and a second run of the same pull request restores
the line's too. The cache holds Clippy's `--all-targets --all-features` build and each
slice's (and ratchet's 1.95.0 build) for `lint`, and the test, doc and wasm32 builds for
`checks`. The two old per-gate target directories (`fixtures`, `wasm32`) fold into the
job's `target`, so the cache keeps them.

Kept apart, and why: `semver` (its own toolchain, tool and baseline; pull requests alone);
`main-in-beta` (a context of `beta` alone, on a pull request into beta, a push to beta
and the sync branch's dispatch; in `checks` it would be a step that skips on `main`, one
context meaning two things on two lines; a 7 s job); `beta-born` (a pull request into
main alone); `dependents-plan`, `dependent-check`, `dependents` (main's and the full
set's). Every `if:` of theirs is unchanged.

## The contexts

| | Before (read 2026-11-02, the protection and the test's constants) | After |
|---|---|---|
| `beta` | twelve: `Test Suite (ubuntu-latest, stable)`, `Clippy`, `Rustfmt`, `vectors`, `deny`, `main-in-beta`, `ratchet`, `fixtures`, `secrets`, `semver`, `wasm32 (combined)`, `Documentation` | five: `Test Suite (ubuntu-latest, stable)`, `lint`, `checks`, `main-in-beta`, `semver` |
| `main` | thirteen: `Test Suite (ubuntu-latest, stable)`, `Clippy`, `Rustfmt`, `Documentation`, `vectors`, `deny`, `dependents`, `semver`, `beta-born`, `ratchet`, `fixtures`, `secrets`, `wasm32 (combined)` | unchanged until the pull request that promotes this commit to `main`, whose PATCH happens at it (after its run is green, before its merge); then six: `Test Suite (ubuntu-latest, stable)`, `lint`, `checks`, `dependents`, `semver`, `beta-born` |

The four sites in the tree, moved: `docs/ARCH-RULES.md` (section 7, new; the wasm32 and
section 6 lines), `tests/arch_ci_pr_runs_the_required_set.rs` (`REQUIRED_ON_BETA`,
`REQUIRED_ON_MAIN`, `FULL_MATRIX` without `wasm32`, the mutation tests on `lint` and
`checks`) with `tests/arch_ci_lines.rs` (`BUNDLES`, the guard) and
`tests/arch_secrets_scan_scope.rs` (its doc line), `.github/scripts/*.py` (none names a
job: read, nothing to move), `tests/CLAUDE.md` (the three rows). Also `RELEASING.md` step
2, `CLAUDE.md` rule 7 and `features.yml`'s header comment, which named them. Left as
written: every record under `docs/lanes/`, the `CHANGELOG.md` entries of past releases,
and `HANDOFF.md` (the captain's, naming the protection as it stands until the PATCH).

For the captain at the landing (none of this is done by the lane):

1. `beta`'s protection, sent as the `checks` form so that each context keeps its binding to GitHub Actions' app 15368, as the twelve carry it today (a `contexts[]` list binds none, and `-f strict=true` sends a string):

   ```
   gh api -X PATCH repos/Calhooon/bsv-rs/branches/beta/protection/required_status_checks --input - <<'EOF'
   {"strict":true,"checks":[{"context":"Test Suite (ubuntu-latest, stable)","app_id":15368},{"context":"lint","app_id":15368},{"context":"checks","app_id":15368},{"context":"main-in-beta","app_id":15368},{"context":"semver","app_id":15368}]}
   EOF
   gh api repos/Calhooon/bsv-rs/branches/beta/protection --jq '.required_status_checks|[.strict,(.checks|length),(.checks[]|"\(.context)@\(.app_id)")]'
   ```

   The read-back shows `true`, `5` and each of the five names `@15368`: 12 contexts to 5.
2. The sequencer's required names for `beta`: `REQ='^(Test Suite \(ubuntu-latest, stable\)|lint|checks|main-in-beta|semver)$'`, `REQN=5` (12 to 5).
3. `main`'s protection: thirteen until the pull request that promotes this commit to `main`. That pull request runs its merge ref's `ci.yml`, so it reports `lint` and `checks` and never `Clippy` or the other replaced contexts; with admins enforced it can never merge under the thirteen. `main`'s PATCH to six (`Test Suite (ubuntu-latest, stable)`, `lint`, `checks`, `semver`, `dependents`, `beta-born`, each `app_id` 15368, the same `checks` form and read-back with `main` for `beta` and `6`) happens at that pull request: after its run is green on the six, before its merge, with the sequencer's `main` list (13 to 6) in the same change.
4. The order on `beta`: #665 (`ci-speed-1`, the `test` job) lands before this pull request; this pull request is rebased on it and its own run goes green on its five (`Test Suite (ubuntu-latest, stable)`, `lint`, `checks`, `main-in-beta`, `semver`); only then the PATCH (1) and its read-back (if this run were red under the five, nothing on `beta` could report `lint` or `checks`); then the merge at once, with the sequencer's names and threshold at five (2); the queue held between the PATCH and the merge; then every open pull request into `beta` rebased on it before it is judged (#662, #659, #658, #656, #655, #652, #647 at the read), so that it reports the new contexts.

## Cut 3, the twin runs

None to end. `on:` before and after (unchanged):

```yaml
on:
  push:
    branches: [main, beta]
  pull_request:
    branches: [main, beta]
  workflow_dispatch:
  workflow_call:
    secrets:
      DEPENDENTS_READ_TOKEN: ...
```

A push to a lane branch starts no run: the thirty latest runs of `ci.yml`
(`gh run list --workflow ci.yml --limit 30`) are `pull_request` runs on the lane branches
and `push` runs on `beta`, none a `push` on a lane branch. A tag drives the matrix
through `release.yml` (`on: push: tags: ['v*']`, which calls `ci.yml`), not through
`ci.yml`'s own `push`, and is unchanged. `pull_request` stays filtered to `[main, beta]`:
the filter is the base, so widening it to every branch would add runs (a pull request
into another pull request's branch) that no protection reads, the opposite of the cut, and
`tests/arch_ci_lines.rs` pins both filters. `beta-born` needs a `pull_request` into
`main`; `main-in-beta` a `pull_request` into `beta`, a `push` to `beta` and the sync
branch's `workflow_dispatch`: each still gets it. The concurrency group exists
(`ci-${{ github.event_name }}-${{ github.ref }}`, `cancel-in-progress` on every ref but a
tag): it cancels a superseded run of the same pull request (each has its own
`refs/pull/N/merge`). It also cancels a superseded push run on a line, the rule since the
group carried the event (`CHANGELOG.md`, "CI's concurrency group carries the event";
`RELEASING.md` step 2: a cancelled run is superseded, never a red). The brief's form
(`cancel-in-progress` on pull requests alone) applied where no group existed; this lane
left the standing rule. To keep every push run of a line, the one-line change is
`cancel-in-progress: ${{ github.event_name == 'pull_request' }}`, the captain's call.

## The four figures, before

| Figure | Before | After |
|---|---|---|
| A pull request's CI wall clock | 29 m 11 s, run 41537280176 (22:26:27Z to 22:55:38Z), the `Test Suite` 26 m of it | (from the PR's opening run) |
| The queue wait | 3 m 10 s to the earliest job (created 22:26:27Z, `Test Suite` started 22:29:37Z); the last small job (`Rustfmt`) started 9 m 34 s after the creation | (from the PR's opening run) |
| The nightly's length | run 41347058507 (`beta`, conclusion failure: 42 of 43 jobs green), the last complete one: created 2026-11-01T20:28:54Z, its earliest job started 23:52:16Z (queued 3 h 23 m behind run 41327640129, which ended 23:52:15Z), its last job ended 2026-11-02T07:11:58Z: 10 h 43 m from creation, 7 h 19 m 42 s running | (from the next nightly) |
| A cold read's length | 16 m 49 s: the #660 cold read on the Studio, 23:16Z to 23:33Z | (from the next cold read) |

## Verified here, and not

Locally (a scratch copy, its own target directory, `CARGO_BUILD_JOBS=4`, one cargo at a
time; logs under `/Volumes/Lanes/out/bsv-rs/ci-speed-2/`): `actionlint` (with
shellcheck) clean on `ci.yml` and `features.yml`; the five `arch_*` files that read the
workflows and `fixtures_replay` green (`cargo test --features "full,http" --test
arch_ci_lines` 9 passed, `--test arch_ci_pr_runs_the_required_set` 16, `--test
arch_ci_runs_every_test` 6, `--test arch_secrets_scan_scope` 1, `--test
arch_fuzz_targets_dispatched` 3, `--test fixtures_replay` 1); the two `arch_ci` files
against `ffff16d0`'s `ci.yml`: 2 of 9 and 12 of 16 RED; `cargo fmt --all -- --check`;
`tools/ratchet/run --check --against ffff16d0` (all 7 counters pass); `gitleaks git
--redact --no-banner --exit-code 1 --log-opts="origin/beta..HEAD" .` clean.

Not verified here (GitHub's to run, at the PR's run and the push after the landing):
`lint` and `checks` executing on a runner; `Swatinem/rust-cache` restoring and saving as
configured; `taiki-e/install-action` placing cargo-deny 0.20.2 on the path; the earliest
pull request after the landing restoring a cold cache until the line's push saves one;
the wall clock and the queue after.
