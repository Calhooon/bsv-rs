# Releasing bsv-rs

The beta canary order starts with the toolbox's and CLI's `beta` lines taking
an explicitly pinned bsv-rs beta prerelease. After the CLI's gate passes, the
workers' captains and LOW's captain re-pin on their own trains; the apps'
captains follow the layer they consume. The current pins, feature slices,
owners and dated re-pin proposals live in [docs/DEPENDENTS.md](docs/DEPENDENTS.md).
Each pin-move PR refreshes [docs/dependents.lock](docs/dependents.lock) from the
consumer's remote default branch. Stable requirements do not admit beta
prereleases. This canary paragraph does not authorize a pin, tag, deployment
or release; #100 owns the full release policy.

1. Every change reaches `main` through a pull request; `main` is protected, admins included, linear history.
2. The PR merges (rebase-merge) once its required checks are green: `Test Suite (ubuntu-latest, stable)`, `Clippy`, `Rustfmt`, `vectors`, `deny`.

   From north-star wave 1, `deny` is a required check; the captain adds it to branch protection at landing. The job builds cargo-deny from its pinned crates.io version, resolves one audit lockfile, then checks all features, the Cloudflare wasm32 slice and default features with `--locked`. RustSec findings and yanked crates fail the gate, the advisory ignore list stays empty, licenses are allowlisted, and dependency sources are restricted to crates.io.

3. A release is a PR like any other: bump `version` in `Cargo.toml`, add the `CHANGELOG.md` heading, merge it green.
4. Tag the merged commit on `main`: `git tag vX.Y.Z <sha> && git push origin vX.Y.Z` (the tag must equal `Cargo.toml`'s version).
5. The tag runs `.github/workflows/release.yml`: it checks the tag against the manifest and that the commit is on `main`, re-runs the CI jobs, then `cargo publish --dry-run` and `cargo publish`.
6. Nothing publishes from a laptop; no crates.io token is stored anywhere, in this repository or its secrets.
7. Publishing uses crates.io trusted publishing: the crate's Trusted Publishing setting names owner `Calhooon`, repository `bsv-rs`, workflow `release.yml`, no environment.
8. A failed release job publishes nothing; fix through a PR, then delete and re-push the tag, or tag the next patch.
9. A published version is never re-published; a bad release is yanked on crates.io and superseded by the next patch.
10. Without the trusted-publishing setting on crates.io the publish step fails closed.

## The two lines (2026-10-23, the owner's word: every crate on a beta line)

11. `main` is the stable line: steps 1 to 10 above, unchanged. A quick fix anyone needs lands there as a patch.
12. `beta` is the programme's line (the epic #101; the lane briefs under `docs/lanes/`). It is protected as `main` is (the same required checks, linear history, admins included); CI runs on both lines. A pull request runs exactly its base line's required checks (the jobs `dependents` needs with it) and nothing else; a push to either line, the sync's dispatch and the nightly's dispatch of `ci.yml` on each line run every job (2026-10-26; `tests/arch_ci_pr_runs_the_required_set.rs` pins both sets against the contexts read from each line's protection, so a context added to or dropped from a protection moves the test with it). Every programme PR targets `beta`, one concern each, reviewed cold before the captain merges.
13. `main`'s commits come back to `beta` after every stable patch, so `beta` never lacks a fix `main` has: the sync PR below (cherry-picks, landed by rebase merge), checked by `main-in-beta`.
14. A prerelease is a tag `vX.Y.Z-beta.N` on `beta`, cut by the owner's word like any tag, with `Cargo.toml` at `X.Y.Z-beta.N` by a PR that says so; `release.yml` admits a `-beta.` tag only on `beta` and a plain tag only on `main`, and publishes either. A beta tag is never admitted to the stack's line.
15. Before a prerelease publishes, it is announced to the toolbox's captain and the CLI's captain with the fixtures' diff since the last minor (`docs/FIXTURES.md` once #76 lands). Their beta lines are the canary; the Cloudflare workers and LOW re-pin by their own captains after the CLI's gate has run.
16. `beta` merges into `main` at a phase exit as the next minor, after the toolbox's and the CLI's beta lines have built against a `vX.Y.0-beta.N` prerelease and the CLI's gate has run.

## The direction rule (2026-10-25, the owner's word)

Every fix is born on `beta`. `main` accepts a quick fix of four classes only:

- a security advisory (a RustSec entry against this crate or a dependency);
- a panic on input;
- a wrong consensus or BEEF verdict;
- a break in a live dependent (`docs/DEPENDENTS.md`).

17. Every main commit is `git cherry-pick -x` of a beta commit with its test. The `-x` line, `(cherry picked from commit <sha>)`, is the link both guards read; a pick made without it (a hand-resolved one whose patch differs) fails them until the line is added with `git commit --amend`. The one main-born commit is the release commit (step 3): `Cargo.toml`'s `version` and `CHANGELOG.md`'s headings, nothing else.
18. `main-in-beta` (`.github/workflows/ci.yml`) runs on every PR into `beta` (on the PR's merge commit: after this lands, does beta carry main), every push to `beta`, and a dispatch on `sync/main-into-beta`. A commit of `origin/main` is on the tree by sha, by patch (`git cherry`), or by a cherry-pick link in either direction: main's commit names a beta source on the tree, or a commit of the tree names main's. It fails naming each commit that is none of these. `beta-born`, on every PR into `main`, asks the same of each commit of the PR against `origin/beta`, and lets a release commit through, saying so in its log.
19. `.github/workflows/sync-main-into-beta.yml` runs on every push to `main`. When `main-in-beta`'s filter finds commits of main beta lacks, it opens, or updates in place, one PR from `sync/main-into-beta` into `beta`, titled `sync: main into beta at <sha>`: each such commit `git cherry-pick -x`'d onto beta's tip in main's order. **Land it by rebase merge**: both lines keep linear history, and each pick's `-x` line lives in its message, so the link survives the new sha. A pick that conflicts is aborted; the branch keeps beta's tip and the picks before it, the PR names the commit and its conflicted files and carries the label `needs-hand` (the workflow creates the label; it holds `issues: write` for that). Resolve on the branch by `git cherry-pick -x <sha>`, push, and run `gh workflow run sync-main-into-beta.yml`: a branch that holds beta's tip is picked onto, never rebuilt, so a hand resolution survives main moving again; when beta moves, the branch's own commits are carried onto its tip. A release commit that picks cleanly is labelled `needs-hand` too: its pick moves beta's `[Unreleased]` under main's heading, so a person amends it to what beta should say before it lands. A conflicting commit with no pick before it opens no PR (GitHub opens none without a commit): the run fails with the hand's steps in its summary.
20. A PR or a push made with the `GITHUB_TOKEN` starts no workflow, so the sync workflow starts `ci.yml` on its branch by a `workflow_dispatch`; the required checks report on the branch's tip from that run. The protection the captain adds: `main-in-beta` a required check on `beta`, `beta-born` on `main`; linear history stays on both lines.
21. A change to `main`'s own gate (`ci.yml`'s jobs on `main`, `docs/RELEASING.md`'s words on them) is the one class of main commit with no beta source, and the guards do not know it: a captain links it back by a commit on `beta` that carries each main commit's `(cherry picked from commit <sha>)` line, under a PR like any other. The link commit has content (this point was its first); GitHub's rebase merge and `gh pr update-branch --rebase` drop an empty commit, and a PR of empty commits closes itself when its branch is updated (PR #224, 2026-10-25). Run the guard's shell by hand on the line's tip before it is required (`main-in-beta` on `beta` was required while `main` held five unlinked gate commits, and every open beta PR was held until the link landed).
