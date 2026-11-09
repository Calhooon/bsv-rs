# Design for #99: release evidence (reproducible package, SBOM, signed release, semver on every tag)

Read at `origin/beta` `e228c61a`, 2026-11-09. `[X]` read at the line or run in this lane; `[D]` told, proposed, or tool knowledge not checked here. This lane ran no cargo.

## 1. The exit test and the scoreboard row

The issue (#99, open, `hardening`, `after-cut`) `[X]`: "**Exit test.** Two builds of a tag are identical; a breaking change cannot publish as a minor." Its alignment: "The stack's rule 2."

The row it moves: Dependents (`docs/NORTH-STAR.md:30` `[X]`), whose target on epic #101 reads "semver checked on every tag" `[X]`. The package, the SBOM and the signature have no row today (Q99.7).

"At target with recorded evidence" `[D]`:

- **Command.** `gh workflow run release-evidence.yml --ref <ref>`, and the same workflow called by `release.yml` on every tag before `publish`.
- **Record.** `release-evidence.json`, the artifact `release-evidence-<tag>`, attached to the tag's GitHub Release: `tag`, `commit`, `run`, `cargo` (version text), `lock_sha256`, `crate_sha256` per builder, `identical`, `file_list_sha256`, `semver` (`baseline`, `release_type`, `verdict`, lint names), `sbom_sha256`, `attestation`, and after publish `index_cksum`, `index_matches`. At target: `identical` and `index_matches` true, `semver.verdict` pass, on each line's latest tag.

## 2. Today on beta

| Fact | Where | |
|---|---|---|
| A `v*` tag runs `release.yml`: tag against manifest, commit on its line, `ci.yml`, five measurement workflows, publish | `.github/workflows/release.yml:6-8,34-56,58-112` | `[X]` |
| `publish` needs `version, ci, docs, msrv, features, machete`; `contents: read`, `id-token: write` | `release.yml:116-120` | `[X]` |
| The package is built twice there (`--dry-run`, then publish), neither `--locked`, on floating `stable` | `release.yml:127,130,137` | `[X]` |
| Trusted publishing: the OIDC exchange by `crates-io-auth-action` v1.0.5; the crate's setting names owner, repository, `release.yml`; no stored token | `release.yml:132-139`; `RELEASING.md:21-22` | `[X]` |
| `semver` runs on a pull request alone: `cargo-semver-checks` 0.51.0, Rust 1.95.0, baseline the last tag reachable from the PR base, release type inferred; docs-only skipped | `.github/workflows/ci.yml:159-161,199,207,213,220-233` | `[X]` |
| A tag's call skips `semver` (beta.5's Release run 41214030939) | `HANDOFF.md:93` | `[X]` |
| Pins on the semver job (command text; the cache seed equal to the job) | `tests/arch_ci_docs_only_exit.rs:95`; `tests/arch_ci_semver_tool_seed.rs` | `[X]` |
| Pin on `release.yml`: it calls each measurement workflow, each on dispatch and call only | `tests/arch_ci_pr_runs_the_required_set.rs:874-899` | `[X]` |
| No root `Cargo.lock` tracked (`.gitignore:3`); CI resolves one per run | `ci.yml:381,548-553` | `[X]` |
| One library lock is tracked and moved at each cut: `tools/ratchet/library.Cargo.lock` (2,905 lines) | `docs/RATCHETS.md:152-168`; `HANDOFF.md:93` | `[X]` |
| Package contents: four `exclude` paths, no `include` | `Cargo.toml:14` | `[X]` |
| Tags annotated, unsigned (`git cat-file -p v0.9.0-beta.7`); GitHub Releases stop at `v0.7.2` (`gh release list`) | this lane's runs | `[X]` |
| A called workflow asking more than its caller grants kills the tag's run at startup | `RELEASING.md:50` | `[X]` |

**Not on record** (the tree holds no line on reproducible builds, SBOM, CycloneDX, sigstore, cosign or attestations `[X]`): any comparison of two packages of one tag; any published `.crate`'s sha256 against the index; the `.crate`'s size and file count; whether it carries a `Cargo.lock`; how `cargo-semver-checks` 0.51.0 reads a prerelease-to-prerelease change; the tool's build time on a tag ref (241 to 294 s on a PR's cache miss, `ci.yml:237` `[X]`).

What `cargo package` makes deterministic is not on record here. From tool knowledge `[D]`: entry order, fixed mtimes and owners, and the normalized manifest follow from the cargo version and the tree; `.cargo_vcs_info.json` carries the commit; what varies is the cargo version and the `Cargo.lock` written into the package, resolved from the index at package time when none is present. Step 1's command proves or corrects this.

## 3. The gap

1. Semver is never judged at the tag, where the version is final.
2. The two varying inputs of the package (lock, cargo version) are unpinned in `release.yml`.
3. Nothing builds the package twice, compares it, or compares the registry's bytes with it.
4. No SBOM, no signature, no GitHub Release since 0.7.2 to carry them.
5. No record; the collector reads no release input (`.github/workflows/bench.yml:187` `[X]`).

## 4. The design

One new workflow, `.github/workflows/release-evidence.yml`, on `workflow_dispatch` and `workflow_call` only (the measurement workflows' shape), `contents: read`; `release.yml` calls it and `publish` needs it. `ci.yml` is untouched. No step touches `src/`, the vectors, the fixtures or the public API, so verdicts, error texts and the sibling harness are unchanged by construction and no harness run applies.

| # | Step | Risk | Size |
|---|---|---|---|
| 1 | Measure: rebuild `v0.9.0-beta.7`, compare with the registry | 0.10 | one lane, a record |
| 2 | Semver judged at the tag, holding the publish | 0.25 | one lane, one PR |
| 3 | The package built twice from pinned inputs, compared, checked against the index | 0.35 | one lane, one PR |
| 4 | SBOM, GitHub Release, keyless attestation | 0.40 | one lane, one PR |
| 5 | The record on the scoreboard and the pages | 0.10 | one lane, docs and collector |

**Step 1, the measurement.** In a scratch checkout of `v0.9.0-beta.7` (`22f03d84`) under `$TMPDIR`:

```sh
curl -sSL https://static.crates.io/crates/bsv-rs/bsv-rs-0.9.0-beta.7.crate -o pub.crate
shasum -a 256 pub.crate; tar -tzf pub.crate | wc -l
tar -xzOf pub.crate bsv-rs-0.9.0-beta.7/Cargo.lock > Cargo.lock
cargo +<V> package --locked --no-verify --target-dir "$A"
cmp "$A/package/bsv-rs-0.9.0-beta.7.crate" pub.crate
```

with `<V>` the cargo of that publish job's log; again from a second checkout path; once at `e228c61a` with `tools/ratchet/library.Cargo.lock` as the lock; and `check-release --baseline-rev v0.9.0-beta.6` at beta.7. It settles every "not on record" line steps 2 to 4 rest on. `--no-verify` compiles nothing. Proof: the hashes and `cmp` exits in `docs/lanes/release-evidence-measure.md`. If `cmp` differs with lock and version equal, step 3 is re-designed from the differing entry before it is briefed.

**Step 2, semver at the tag.** Files: `.github/scripts/release_baseline.py` and its test (new: from a ref and the manifest version, the baseline tag and the release type), `release-evidence.yml` job `semver` (tool, toolchain, cache path and key of `ci.yml:199-213` byte for byte), `release.yml` (the `evidence` call; `publish.needs`), `tests/arch_ci_release_evidence.rs` (new), `RELEASING.md` step 5. The baseline is described from the tagged commit's parent (a re-pushed tag never meets itself); the type is passed with `--release-type`, never inferred:

| Tag | Baseline | Type | Holds publish |
|---|---|---|---|
| `vX.Y.Z`, Z > 0 | previous plain tag | `minor` (additive, `CLAUDE.md` rule 9) | yes |
| `vX.Y.0` | previous plain tag | `major` before 1.0, `minor` after (Q99.2) | yes |
| `vX.Y.Z-beta.N` | previous plain tag | as its `X.Y.Z` | yes |
| `vX.Y.Z-beta.N`, N > 1 | previous beta of `X.Y.Z` | `minor` | no: the lints go to the record and the canary announcement (`RELEASING.md:33`) |

Unchanged: the PR `semver` job and its pins. Proof: RED, the new arch test on today's `release.yml` and the script's tests without the script; the witness after landing, a dispatch on a scratch branch that deletes one public function under a patch version, `semver` red, its run id in the lane record. Risk: the tool cache on a tag ref (a miss is minutes, not a red) and the prerelease reading step 1 measures.

**Step 3, two builds identical.** Files: `release-evidence.yml` jobs `package-a` (`ubuntu-latest`), `package-b` (`macos-latest`), `compare`; `release.yml` `publish`; the arch test; `RELEASING.md`. Each builder: the one named toolchain (Q99.6), the lock placed (Q99.1), `cargo package --locked` (verify build on `a` only), the sha256 of the `.crate` and of `cargo package --list`. `compare` fails unless the hashes are equal, and uploads the `.crate` and the draft record. `publish`: same toolchain and lock, `cargo package --locked`, refuse unless its hash equals `compare`'s, `cargo publish --locked`, then read the version's line of `https://index.crates.io/bs/v-/bsv-rs` and fail unless `cksum` equals it. The dry-run step goes (the verify build ran in `package-a`). Unchanged: the package's contents; the OIDC exchange. Proof: RED, the arch test; a dispatch on `beta` reading `identical: true`; the next tag's `index_matches: true`. Risk: a cross-OS byte difference in the gzip stream (then `package-b` moves to a second Linux image, the record says so) and a mismatch after publish (Q99.8).

Fact-check (2026-11-09): ts-stack packs once and attests the bytes (`release.yaml:163-165`); two builders is this design's, read from the exit test.

**Step 4, SBOM, Release, signature.** Files: `release-evidence.yml` job `sbom` (a pinned `cargo-cyclonedx` through `taiki-e/install-action`, as deny at `ci.yml:530-534`; the locked all-features graph; `serialNumber` and timestamp normalized so two runs give equal bytes); `release.yml` job `attest` after `publish`, alone holding `contents: write`, `id-token: write`, `attestations: write` (in `release.yml` itself, so the called workflow stays inside `contents: read`): `actions/attest-build-provenance` on the `.crate`, `actions/attest-sbom`, then `gh release create` with the `.crate`, the SBOM and the record (prerelease flag on a `-beta.` tag). Actions pinned by commit as at `release.yml:25`; the shas are read at the lane, none is on record. Verified by `gh attestation verify <crate> --repo Calhooon/bsv-rs`. No key is made or stored (`RELEASING.md:21`). Proof: RED, the arch test pins the three permissions to `attest` alone; the witness is the next tag. Risk: a permission slip stops a tag at startup; `attest` runs after `publish`, so its failure leaves a correct crate without a Release, fixed forward.

**Step 5, the record.** `bench.yml:187` gains `*release-evidence*` and the collector a `release` input; `docs/NORTH-STAR.md:30`, `docs/ARCHITECTURE.md` section 4, `RELEASING.md` steps 5 to 10 and `CLAUDE.md` rule 10 say what a tag now proves.

## 5. The slicing

| Lane | Waits on | Gate |
|---|---|---|
| L0 measure (step 1) | nothing | the record with every hash and `cmp` exit |
| L1 semver (step 2) | Q99.2; beside L0 | python tests, the arch test, actionlint, the planted-break dispatch |
| L2 two builds (step 3) | L0, L1, Q99.1, Q99.6, Q99.8 | as L1, the dispatch on `beta` `identical: true` |
| L3 SBOM, attestation (step 4) | L2, Q99.3 to Q99.5 | as L1; the next tag |
| L4 record (step 5) | L3, Q99.7 | the scoreboard JSON names the input |

L1 to L3 share `release.yml`, `release-evidence.yml`, the arch test and `RELEASING.md`: serial. #99 is `after-cut`: it opens after beta.8 and its tag witness is the tag after.

Collisions:

- **The blocking set** (#734, #735, #751, #756, #775, #782, #785, #786, #796): under `src/` and `tests/`; shared `CHANGELOG.md` only, and at the cut `Cargo.toml:3` and the library lock (read here, never written).
- **#603**: `nightly.yml`, `docs/ratchets.json`; nothing shared.
- **#100**: `RELEASING.md`, `docs/DEPENDENTS.md`. #100 owns the canary paragraph and points 15 to 16; #99 edits steps 5 to 10. Step 2's beta-to-beta lint list feeds its announcement.
- **#96, #97, #98**: each adds a job, so edits `ci.yml` and `tests/arch_ci_pr_runs_the_required_set.rs`; #99 touches neither. #96 editing `bench.yml:187` `[D]` (not found: it reads `*wasm*` already; #96's body names no collector edit).
- **#90 to #93**: `benches/`, `bench.yml`'s producers, the scoreboard table (L4, keep-both).
- **#92, #94, #95**: a new dependency moves the library lock by the ratchet's rule; under Q99.1 (b) no new duty.
- Every design: `docs/ARCHITECTURE.md` section 4, `CHANGELOG.md`.

## 6. The owner's questions

No reference decides these, but ts-stack at `edf6e03` has the practice: pack once, CycloneDX SBOMs, GitHub attestations, registry digest reconciliation (`.github/SECURITY.md:88-90`; `release.yaml:163-180,246-278`, `actions/attest` v4.2.2) `[X]`; the node's v1.2.2 has gitian descriptors for binaries; the BRCs none (section 7). Downstreams are `docs/DEPENDENTS.md`'s rows.

- **Q99.1, the release's lock (policy).** (a) track a root `Cargo.lock`: every PR then tests the locked graph where it tests a fresh resolve today (`ci.yml:381`); (b) the release places `tools/ratchet/library.Cargo.lock`, already moved at each cut; (c) package with no lock, if cargo's `--exclude-lockfile` holds at the pin `[D]`. Recommend (b): the lock the cut already keeps, proven to package by step 1. Downstream cost: none; a dependent's resolve never reads it.
- **Q99.2, the exit test before 1.0 (policy).** Cargo lets `0.9 -> 0.10` break; rule 9 makes a patch additive. (a) cargo's rule: the gate binds patches now and minors from 1.0, each 0.x minor and beta recording its breaking lints; (b) a 0.x minor with a breaking lint publishes only when a checked-in allowance file lists it. Recommend (a) now, (b) at 1.0 planning. Cost: (a) gives a consumer on `"0.9"` a gate where it has a convention; (b) adds a file to each breaking release PR.
- **Q99.3, the signature (policy).** (a) GitHub artifact attestations, keyless by the workflow's OIDC identity; (b) cosign keyless; (c) a long-lived key the owner guards; (d) signed tags beside any. Recommend (a): nothing stored, as the publish. Cost: none.
- **Q99.4, a GitHub Release per tag (a release, a permission).** One job gains `contents: write`; every tag gets a Release, betas flagged. Or artifacts only, which expire. Recommend the Release, written by `attest` alone. Cost: none.
- **Q99.5, the SBOM (schema).** CycloneDX JSON or SPDX; the all-features graph or one per consumer slice. Recommend one CycloneDX JSON over the locked all-features graph, the superset. Cost: a worker captain derives a slice's exact graph from their own lock.
- **Q99.6, the release toolchain (pin).** (a) one named cargo for package and publish, moved by PR; (b) floating `stable`, recorded. Recommend (a), at the version the semver tool names (`ci.yml:199`), one pin not two; under (b) the exit test holds only inside one run. Cost: none; `rust-version` is untouched.
- **Q99.7, the scoreboard (schema).** Recommend semver under the Dependents row and a new row "Release evidence" on epic #101 for package, SBOM and signature. Cost: none.
- **Q99.8, a registry mismatch after publish (a release).** (a) the run is red and the owner decides the yank; (b) automatic yank. Recommend (a): a yank breaks the canaries' exact pins (`HANDOFF.md:333`) and is the owner's (`RELEASING.md:24`).

## 7. Stack alignment

At bsv-stack-lean `13e1fa5d748b`: `NORTH-STAR.md` section 2, constitution **02** ("Every rule cites its reference at a pin ... Memory is not a source") `[X]`: a release becomes citeable by its sha256, checked against the index. `docs/RELEASE.md` `[X]`: the keeper's `tools/manifest.py --check` already reads the sparse index for unyanked releases; `index_cksum` is a value that manifest could carry, the keeper's choice. No charter, Lean rule, matrix row, wire shape or verdict is touched.

- T1 to T4: not applicable; no chain fact is made or served.
- T5: the trusted words fall from "the runner built what the tag says" to two builders and the registry compared, plus a keyless signature.
- T6: the claim is a command (`cmp`, `gh attestation verify`, the dispatch) and a JSON record.

## 8. Not in this design

- Reproducible compiled artifacts (rlib, wasm): the crate ships source; the wasm slices' bytes are #96's.
- An `include` list or size budget for the package: step 1 records size and file count; a ratchet on them is a `hardening` row filed from that record.
- The canary order and pin train: #100. Mutation and fuzz before a minor tag (`RELEASING.md:18`): unchanged.
- crates.io-side settings (the trusted publisher entry): unchanged, the owner's.
- `cargo vet`; backfilled Releases for 0.8.x and the seven betas: not proposed.
