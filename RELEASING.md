# Releasing bsv-rs

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
12. `beta` is the programme's line (the epic #101; the lane briefs under `docs/lanes/`). It is protected as `main` is (the same required checks, linear history, admins included); CI runs on both lines. Every programme PR targets `beta`, one concern each, reviewed cold before the captain merges.
13. `main` merges into `beta` after every stable patch, so `beta` never lacks a fix `main` has.
14. A prerelease is a tag `vX.Y.Z-beta.N` on `beta`, cut by the owner's word like any tag, with `Cargo.toml` at `X.Y.Z-beta.N` by a PR that says so; `release.yml` admits a `-beta.` tag only on `beta` and a plain tag only on `main`, and publishes either. A beta tag is never admitted to the stack's line.
15. Before a prerelease publishes, it is announced to the toolbox's captain and the CLI's captain with the fixtures' diff since the last minor (`docs/FIXTURES.md` once #76 lands). Their beta lines are the canary; the Cloudflare workers and LOW re-pin by their own captains after the CLI's gate has run.
16. `beta` merges into `main` at a phase exit as the next minor, after the toolbox's and the CLI's beta lines have built against a `vX.Y.0-beta.N` prerelease and the CLI's gate has run.
