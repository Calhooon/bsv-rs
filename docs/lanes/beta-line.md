# Lane beta-line: the programme's line (#75)

**Repository.** `bsv-rs`. The captain's own step, run the hour the keeper's `v0.8.2` tag exists; the workflow edits may be a lane. `docs/lanes/README.md` binds. One hour.

**Read in this order.** #75 and the epic #101. `RELEASING.md` (the ten steps of the stable line). `.github/workflows/ci.yml` (`on:` is `[main]` for push and pull_request; the four required checks named in RELEASING step 2; the `benchmarks` job checks out `github.base_ref`), `.github/workflows/release.yml` (the `version` job's two checks: tag equals manifest, commit on main). The CLI's shape at `git -C ~/bsv/bsv-wallet-cli show origin/beta:.github/workflows/ci.yml` (`branches: [main, beta]`) and `origin/beta:.github/workflows/release.yml` ("The tagged commit is on its line": `*-beta.*` reads beta, a plain tag reads main).

**The work.**
1. The captain: `git fetch origin && git push origin origin/main:refs/heads/beta` from the commit `v0.8.2` names; branch protection on `beta` copied from `main` (the same required checks, linear history, admins included), read back with `gh api repos/Calhooon/bsv-rs/branches/beta/protection` in the report.
2. `ci.yml`: `on.push.branches` and `on.pull_request.branches` become `[main, beta]`; nothing else moves (the job names are the protection's contexts).
3. `release.yml`: the `version` job's second step becomes the CLI's: a `vX.Y.Z-beta.N` tag must be on `beta`, a plain `vX.Y.Z` on `main`; the publish step passes through unchanged (crates.io takes a prerelease version as its own; `Cargo.toml` carries `X.Y.Z-beta.N` on beta when a prerelease is cut, by a PR that says so).
4. `RELEASING.md`: a section "The two lines": `main` the stable line (the ten steps as they are); `beta` the programme's; `main` merges into `beta` after every stable patch; `beta` merges into `main` at a phase exit as the next minor, after the toolbox's and the CLI's beta lines have built against a `vX.Y.0-beta.N` prerelease and the CLI's gate has run; a prerelease is announced to the toolbox's and the CLI's captains with the fixtures' diff before it publishes; a beta tag is never admitted to the stack's line.
5. The PR into `beta` carrying 2 to 4, plus `docs/lanes/` and `HANDOFF.md` as the programme's records.

**Bounds.** No tag, no prerelease, no change to `Cargo.toml`'s version: those are the owner's word. Nothing touches `release/0.8.2` or `main`.

**Report.** `REPORT: STATUS done|blocked`, the protection JSON's required contexts, the CI run on the PR, the six tests each choice passes.
