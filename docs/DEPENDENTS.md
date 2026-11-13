# bsv-rs dependents

Snapshot: 2026-10-23 for the features, targets, production cells and app trees; the Rust consumers' pin table refreshed on 2026-11-12 from the dependents' live branch tips (21:53Z to 21:59Z; the table's date line below); the ledger from crates.io's reverse-dependency list is 2026-11-10's, read after 0.8.5 was published (below). `[X]` means read from the named remote commit or run;
`[D]` means reported, including historical production records. A manifest
version is not evidence of the version running in production. The source of
the build matrix is [dependents.lock](dependents.lock); all its revisions were
default-branch heads when read. Consumer captains refresh the lock in each
pin-move PR. The map and scope come from [#83](https://github.com/Calhooon/bsv-rs/issues/83)
and [#101](https://github.com/Calhooon/bsv-rs/issues/101).

## The ledger on crates.io (2026-11-10)

Read on 2026-11-10 after 0.8.5 was on crates.io (20:51:59Z), with
`curl -s -A <client> "https://crates.io/api/v1/crates/bsv-rs/reverse_dependencies?per_page=50"`
(13 crates, `meta.total` 13), each crate's newest version from
`https://crates.io/api/v1/crates/<crate>` (`max_version`, `max_stable_version`)
and a prerelease's requirement from
`https://crates.io/api/v1/crates/<crate>/<version>/dependencies`. These are the
published crates' requirements, not their branch tips (the table after this one).
Pins and actions only. `RELEASING.md` step 23 (g) makes this list, read that
day, the list of who is told.

| Crate on crates.io | Newest stable: requirement | Does 0.8.5 satisfy it? | Newest prerelease: requirement | Action |
|---|---|---|---|---|
| bsv-wallet-toolbox-rs | 0.13.1: `^0.8.0` | yes | 0.14.0-beta.6: `=0.9.0-beta.6` (inside the advisory's prerelease range) | stable: `cargo update -p bsv-rs`; beta: a pin edit to the bsv-rs prerelease that carries the fix, when published |
| bsv-tracker | 0.8.0: `^0.8.0` | yes | 0.9.0-beta.7: `=0.9.0-beta.7` (inside the advisory's prerelease range) | stable: `cargo update -p bsv-rs`; beta: a pin edit, as above |
| bsv-wallet-cli | 0.18.2: `=0.8.3` | no: an exact pin | 0.19.0-beta.7: `=0.9.0-beta.6` (inside the advisory's prerelease range) | stable: a pin edit to `=0.8.5`; beta: a pin edit, as above |
| bsv-middleware-cloudflare | 0.7.2: `^0.8` | yes | none | `cargo update -p bsv-rs` |
| bsv-middleware-core | 0.4.1: `^0.8` | yes | none | `cargo update -p bsv-rs` |
| bsv-middleware-rs | 0.6.2: `^0.8.0` | yes | none | `cargo update -p bsv-rs` |
| bsv-messagebox-cloudflare | 0.8.4: `^0.8.2` | yes | none | `cargo update -p bsv-rs` |
| bsv-chaintracks-cloudflare | 0.7.3: `^0.8.1` | yes | none | `cargo update -p bsv-rs` |
| bsv-wallet-infra-cloudflare | 0.6.0: `^0.8.1` | yes | none | `cargo update -p bsv-rs` |
| bsv-overlay-engine | 0.3.1: `=0.7.0` | no: an exact pin on the 0.7 line | none | a port onto the 0.8 line (no 0.7 patch is published); its repository's `main` pins `=0.7.2` (the table below) |
| bsv-overlay-discovery | 0.3.1: `=0.7.0` | no, as above | none | as above |
| bsv-overlay-cloudflare | 0.3.1: `=0.7.0` | no, as above | none | as above |
| bsv-storage-cloudflare | 0.2.3: `=0.4.5` | no: an exact pin on the 0.4 line | none | a port onto the 0.8 line (no 0.4 patch is published) |

Eight of the thirteen take 0.8.5 on `cargo update -p bsv-rs`; five need a pin
edit or a port; three prereleases pin a `=0.9.0-beta.N` inside the advisory's prerelease range. Two rows of
the table below are not on crates.io's list that day (rust-message-box and
bsv-agent-template): they keep their earlier cells.

## Rust consumers

Features below are bsv-rs features. `default` means the dependency also enables
`primitives,script`. Slices name the actual feature sets, for the architecture
lane's wasm matrix ([#80](https://github.com/Calhooon/bsv-rs/issues/80)). In
this 0.8.2 tree, enabling `transaction` also enables `block,script,primitives`.
Worker checks compile the library on `wasm32-unknown-unknown`; their hermetic
tests run natively.

In #80's slice names, the auth/wallet workers match the watchtower slice,
the wasm tracker matches the monitor, `block` is chaintracks, and
`overlay,wasm` is the overlay worker. That lane also checks the broader
`auth,wallet,transaction,overlay,socketio,wasm` slice and the
`auth,socketio,wasm` relay slice. Each dependent here takes its own manifest's
features; the current messagebox manifest requests auth/wallet/transaction/wasm.

The pin table was refreshed on 2026-11-12, every row read between 21:53Z and
21:59Z at its branch's live tip on GitHub with `gh api` (the tip from
`repos/<owner>/<repo>/commits/<branch>`, every `Cargo.toml` and `Cargo.lock`
of its tree from `contents/<path>?ref=<sha>`; no local clone). The requirement
is the manifest's own text (a bare `0.8.0` is cargo's caret, `^0.8.0`), the
resolved version is what a lockfile committed at that tip holds, and the date
beside a sha is its commit's committer date (UTC). Crates.io's
reverse-dependency list was read at 21:55Z (13 crates, `meta.total` 13; the
same thirteen at the same newest versions and requirements as the 2026-11-10
ledger above; bsv-rs's newest stable there was 0.8.7): every crate on it lives
in a repository with a row here (the overlay's row names its three crates, the
middleware worker's its two), and the two rows it lacks say so. The captain
refreshes this table before every release, by its own pull request on
`beta` ahead of the release pull request (`RELEASING.md` step 3). The features,
targets, test selections, production cells and captains are the 2026-10-23
snapshot's unless a cell says otherwise.

| Consumer and remote manifest | Ref read | bsv-rs requirement | Resolved version | Features and slice (2026-10-23 `[X]`) | Target; hermetic test selection | Production bsv-rs | Captain `[D]` |
|---|---|---|---|---|---|---|---|
| [bsv-wallet-cli](https://github.com/Calhooon/bsv-wallet-cli), alias `bsv-sdk` | `main` `2cc76c9d` (2026-11-04), read 2026-11-12 `[X]` | `=0.8.3` `[X]` | 0.8.3 (`Cargo.lock`) `[X]` | default + `full` | Native, CLI and MCP workspace; an exact pin admits no patch without a pin edit | [D] Unknown | CLI captain |
| bsv-wallet-cli, beta line | `beta` `6dc14ef5` (2026-11-04), read 2026-11-12 `[X]` | `=0.9.0-beta.6` in the root and in `fuzz/` `[X]` | 0.9.0-beta.6 (`Cargo.lock` and `fuzz/Cargo.lock`) `[X]` | as above | as above | [D] Unknown | CLI captain |
| [bsv-wallet-toolbox-rs](https://github.com/Calhooon/bsv-wallet-toolbox-rs) | `main` `3ddf48db` (2026-11-03), read 2026-11-12 `[X]` | `0.8.0` `[X]` | no lock committed `[X]` | default + `full,http` | Native, `sqlite`; library and integration tests | [D] Unknown | Toolbox captain, stack keeper |
| bsv-wallet-toolbox-rs, beta line | `beta` `184c4182` (2026-11-04), read 2026-11-12 `[X]` | `=0.9.0-beta.7` in the root and in `fuzz/` `[X]` | no lock committed `[X]` | as above | as above | [D] Unknown | Toolbox captain, stack keeper |
| [bsv-overlay-cloudflare](https://github.com/Calhooon/bsv-overlay-cloudflare), crates `bsv-overlay-engine`, `bsv-overlay-discovery` and `bsv-overlay-cloudflare` | `main` `8137d2de` (2026-11-11), read 2026-11-12 `[X]` | `=0.7.2` in the root and in `workers/` `[X]` | 0.7.2 (`Cargo.lock` and `workers/Cargo.lock`); the registry packages of `workers/Cargo.lock` that depend on bsv-rs (`bsv-middleware-core 0.4.0`, `bsv-middleware-cloudflare 0.7.1` and `bsv-tracker 0.7.0`, each requiring `^0.7.0`) resolve to it too `[X]` | default + `overlay`; overlay worker adds `wasm`, app-layer tests add `auth` | Native engine workspace and wasm32 worker workspace; no 0.8 patch reaches it until the whole graph moves to the 0.8 line | `[D]` 0.5.0 with worker 0.1.3 on 2026-10-13; current unknown | Stack keeper until named |
| rust-message-box (the relay); not on crates.io's reverse-dependency list on 2026-11-12 | `main` `44a63204` (2026-10-21), read 2026-11-12 `[X]` | `=0.6.0` `[X]` | 0.6.0 (`Cargo.lock`) `[X]` | not read on 2026-10-23 or 2026-11-10 | not read | [D] Unknown | Stack keeper until named |
| [bsv-middleware-rs](https://github.com/Calhooon/bsv-middleware-rs) | `main` `5a1fd275` (2026-10-22), read 2026-11-12 `[X]` | `0.8.0` `[X]` | no lock committed `[X]` | default + `auth,wallet,transaction` | Native with consumer feature `axum`; library and integration tests | [D] Unknown | Stack keeper until named |
| [chaintracks-cloudflare](https://github.com/Calhooon/chaintracks-cloudflare), crate `bsv-chaintracks-cloudflare` | `main` `eff96cbc` (2026-11-04), read 2026-11-12 `[X]` | `0.8.1` `[X]` | no lock committed `[X]` | `block`, no defaults `[X]` | wasm32; native library and integration tests | [D] Unknown | Stack keeper until named |
| [bsv-tracker](https://github.com/Calhooon/bsv-tracker/blob/4a8501593c1cbed3972a60611cd32444d824f592/Cargo.toml) | `main` `4a850159` (2026-11-12), read 2026-11-12 `[X]` | `0.8.0` `[X]` | 0.8.7 (`Cargo.lock`) `[X]` | `transaction`, no defaults; wasm adds `wasm` | Native and wasm32; native library and integration tests | [D] Unknown | Stack keeper until named |
| bsv-tracker, beta line | `beta` `3cfba165` (2026-11-04), read 2026-11-12 `[X]` | `=0.9.0-beta.7` `[X]` | 0.9.0-beta.7 (`Cargo.lock`) `[X]` | `transaction`, no defaults (read 2026-11-12 `[X]`) | not read | [D] Unknown | Stack keeper until named |
| [bsv-wallet-infra-cloudflare](https://github.com/Calhooon/bsv-wallet-infra-cloudflare/blob/2025fcde98664dd69a6305c60e87fa12c3930cde/Cargo.toml), alias `bsv-sdk` | `main` `2025fcde` (2026-10-27), read 2026-11-12 `[X]` | `0.8.1` `[X]` | 0.8.1 (`Cargo.lock`) `[X]` | default + `auth,wallet,transaction,wasm` | wasm32; native library and integration tests | [D] Unknown | Stack keeper until named |
| [bsv-messagebox-cloudflare](https://github.com/Calhooon/bsv-messagebox-cloudflare/blob/32afeeed9ad4cebf484b04c481442174b6bcfb26/Cargo.toml) | `main` `32afeeed` (2026-11-03), read 2026-11-12 `[X]` | `0.8.2` in the root, `0.8.1` in `tests/load_gen/` `[X]` | no lock committed at the root; 0.8.1 in `tests/load_gen/Cargo.lock` `[X]` | default + `auth,wallet,transaction,wasm` | wasm32; native library tests; the integration suite's version guard pins bsv-rs 0.8.1 in the lock and is excluded until the row re-pins; `tests/load_gen` is a separate live client, excluded | [D] Unknown | Stack keeper until named |
| [bsv-middleware-cloudflare](https://github.com/Calhooon/bsv-middleware-cloudflare/blob/d7ccb6c1a56708687c6d044989f9ff06ea024823/Cargo.toml), alias `bsv-sdk`; crates `bsv-middleware-cloudflare` and `bsv-middleware-core` (the `core/` member) | `main` `d7ccb6c1` (2026-10-22; the linked commit, still the tip), read 2026-11-12 `[X]` | `0.8` in the root and in `core/` `[X]` | no lock committed `[X]` | default + `auth,wallet,transaction,wasm`; workspace `core` takes the same slice without `wasm` | wasm32 with consumer features `refund,d1-claims`; native workspace library and integration tests | [D] Unknown; see Zanaadu's historical embedded worker below | Stack keeper until named |
| [bsv-agent-template](https://github.com/Calhooon/bsv-agent-template/blob/b1dcbdbfa9d8beab6783dc515789f5690968f462/Cargo.toml), alias `bsv-sdk`; not on crates.io's reverse-dependency list on 2026-11-12 | `main` `b1dcbdbf` (2026-10-13; the linked commit, still the tip), read 2026-11-12 `[X]` | `0.6.0` `[X]` | 0.6.0 (`Cargo.lock`) `[X]` | default + `auth,wallet,transaction,wasm` | wasm32 | [D] Unknown | Stack keeper until named |
| [bsv-storage-cloudflare](https://github.com/Calhooon/bsv-storage-cloudflare/blob/2563293557849a29007fa1c1b5d2001a3fc8a17d/Cargo.toml) | `main` `25632935` (2026-10-21; the linked commit, still the tip), read 2026-11-12 `[X]` | `=0.4.5` in the root and in `tests/parity/` `[X]` | 0.4.5 (`Cargo.lock`) `[X]` | default + `auth,wallet,transaction,script,wasm`; parity member adds `auth,http,overlay` | wasm32 worker; native parity client is live and excluded | `[D]` 0.4.5 with worker 0.2.1 on 2026-10-13; current unknown | Stack keeper until named |

The selected native suites use in-memory data, local databases or local mocks;
their existing ignored live tests remain ignored. No `--ignored`, load
generator, wallet, broadcaster example or deployment command is run. The
toolbox's test rules identify its ignored network tests explicitly. The wasm
checks exclude host-only dev dependencies such as SQLite.

The CLI's exact pin does **not** admit a patch (on 2026-10-23 it was `=0.8.1`
and did not admit 0.8.2; on 2026-11-10 it is `=0.8.3` and does not admit
0.8.4 or 0.8.5; 0.8.4 was tagged and never published). It is recorded and reported as skipped, rather than silently compiled
against its registry copy. On 2026-10-23 seven public Rust repositories
admitted that tree. A stable caret does not admit a
beta prerelease either. The planner prints every exclusion and builds all
admitted rows without a best-effort or continue-on-error path.

## App trees

Not measured on 2026-11-10: every row of this section is the 2026-10-23
snapshot's, and the pins below (Zanaadu's `=0.4.5` among them) are not reached
by a 0.8 patch.

These private remote manifests were read with the available read credential,
not from local app checkouts. The epic's older app pins are superseded by this
snapshot. There is one app row here even when the lock needs several distinct
Rust requirements for that app.

| App and remote revision `[X]` | Direct and layer pins `[X]` | Features, target and test scope | Production bsv-rs | Captain `[D]` |
|---|---|---|---|---|
| `~/bsv/agents` (private) | Twelve agent crates plus `viewer` use `0.8`; middleware `0.7.2`. `manage` uses bsv-rs `0.5.0`, toolbox `0.7.7` | Agents: default + `auth,wallet,transaction,wasm`; viewer omits explicit `transaction` (wallet enables it). wasm32 compile only; no agent execution or unreviewed app tests. `manage`: native `full`, excluded | [D] Unknown | Agents captain; keeper coordinates |
| `~/bsv/zanaadu` (private) | `overlay-lib`, `parity-harness`, `middleware`, `app-layer-lib`: `=0.4.5`; tracker `=0.2.1`; middleware `=0.5.2`; overlay engine/discovery git `bd6cdb47`. Audit `door-census` also carries `0.3.35`. Frontend SDK `^1.8.11`, toolbox-client `^1.7.13`; contracts SDK `^1.8.8`, toolbox `^1.2.48` | Default + `wasm`; middleware/app-layer add `transaction`. wasm32 libraries, native parity harness. Excluded Rust pin; TS consumes worker contracts, not a Cargo patch | `[D]` embedded middleware 0.5.2 / bsv-rs 0.4.5 on 2026-10-12; current unknown | Zanaadu captain; keeper coordinates |
| `~/bsv/teragunv2` (private) | API, gun, signer workspace: `0.7`; identity resolver `=0.4.5`; identity node uses Zanaadu overlay-lib git `94214d9f` and engine git `3028a3a9`; frontend/test-harness SDK `^3.2.1`, gun tests SDK `^1.1.25` | Default + `wallet,auth,transaction,wasm` workspace; resolver defaults. wasm32 API/identity, native test utilities. Excluded Rust pins | [D] Unknown | Teragun captain to be confirmed by keeper |
| `~/bsv/the-composer` (private) | SDK `^1.10.4`; no Cargo manifest | TypeScript app consumes the workers; no direct Rust build | [D] Unknown | Composer captain to be confirmed by keeper |

Twelve agent crates are admitted at this snapshot. The matrix checks all thirteen libraries.

Historical production cells above are reports from the keeper's
`bsv-stack-lean/docs/p0/versions-2026-10-10.md`, read 2026-10-23. That page's
later dated entries are history, not a fresh deployment inventory. No service
was contacted to infer its current version. Captains owe a fresh production
version and named owner before the proposed re-pin date.

## Proposed re-pin train

Dates are proposed review targets, subject to each captain's acceptance and
the CLI gate. They do not authorize pin moves or deployments. The keeper
owns unnamed worker rows until a captain is recorded.

| Proposed date | Captain | Re-pin scope and gate |
|---|---|---|
| 2026-10-24 | CLI and toolbox captains | CLI exact `=0.8.1` to the approved stable pin, then both beta lines explicitly take the chosen bsv-rs beta prerelease; refresh lock revisions and run the CLI gate |
| 2026-10-24 | Stack keeper, overlay captain when named | Overlay's two workspaces and worker members off `=0.7.2`; align its tracker/middleware pins in its own PR, run engine and worker fixtures |
| 2026-10-25 | Stack keeper, agent-template captain when named | Template off `0.6.0`, with its middleware line; wasm32 and hermetic route fixtures after the CLI gate |
| 2026-10-26 | Stack keeper, storage captain when named | Storage off `=0.4.5`, including its parity member and engine/middleware dependencies; check the existing registry dependency, then the storage fixtures; a live parity run needs separate authority |
| 2026-10-26 | Agents captain | Keep the admitted agent/viewer `0.8` rows current; move `manage` off `0.5.0` with its toolbox in the app's own PR |
| 2026-10-27 | Zanaadu captain | Move the four `=0.4.5` library/harness rows together with tracker, middleware and overlay dependencies; audit tools stay explicitly separate; review the TS worker contracts |
| 2026-10-27 | Teragun captain via keeper | Move the `0.7` workspace and `=0.4.5` identity resolver with the embedded overlay dependencies; review both TS SDK lines and worker contracts |
| 2026-10-27 | Composer captain via keeper | Review the worker API/recorded exchanges against the CLI canary; no Cargo pin to change |

Other admitted workers and LOW re-pin by their captains after the CLI gate,
as [RELEASING.md](../RELEASING.md) describes. Re-pin PRs update the exact remote
revision, requirement, manifests, features, targets and test selection in the
lock; new feature/target shapes also update the architecture lane's matrix.

## How the checks work

`dependents-plan` validates the lock and selects admitted requirements on pull
requests into `main` (where `dependents` is required), on pushes to `beta` and
`main`, in the nightly and on release workflow calls, before publication; a pull
request into `beta` does not run it (the set a pull request runs is its line's
required set, 2026-10-26).
Each `dependent` matrix entry checks out its immutable revision, verifies its declared SDK
requirement/features, applies Cargo's `patch.crates-io.bsv-rs.path` override,
updates an admitted locked registry copy, and inspects Cargo metadata to prove
the direct dependency resolves to the PR tree. Each failure names its consumer.
Unrelated older SDK lines in the same graph are not widened or replaced.
The stable `dependents` status fails if planning or any selected matrix entry
fails or is cancelled, so branch protection does not need a changing list of
consumer check names.

The lock supports exact and caret requirements. Beta entries use an explicit
exact prerelease; unsupported requirement syntax fails closed for review.
Run the same check locally in an external consumer checkout with an external
`CARGO_TARGET_DIR`:

```sh
python3 -B .github/scripts/dependents.py plan --sdk "$PWD"
python3 -B .github/scripts/dependents.py run --sdk "$PWD" \
  --checkout "$DEPENDENT_CHECKOUT" --consumer bsv-tracker
```

The compatible private app rows require the Actions secret
`DEPENDENTS_READ_TOKEN`, with repository contents read access to
the private app trees (and other private apps when their pins become eligible).
The captain requests it from the owner. The workflow fails with that name
when the secret is missing; it neither prints nor persists the credential.
The release caller forwards this one named secret to CI. Fork PRs without
that secret cannot complete those private checks.

`semver` runs on every pull request that changes code, using
`cargo-semver-checks 0.51.0` and Rust `1.95.0` (the pinned compiler avoids drift
in rustdoc JSON formats), with `--all-features`. The
[tool's baseline-rev mode](https://github.com/obi1kenobi/cargo-semver-checks/tree/v0.51.0#does-the-crate-im-checking-have-to-be-published-on-cratesio)
reads the baseline's tree, and the tool documents its
[release-type override](https://github.com/obi1kenobi/cargo-semver-checks/blob/v0.51.0/src/main.rs).
Into `beta` (#886): the baseline is the commit the pull request is tested on
(`HEAD^1` of the merge ref) and the release type is named, `--release-type minor`,
since every version on `beta` is a prerelease and the tool, left to infer the
type, reads any prerelease step as a major one and runs no check; a lint
failure passes only under the `api-break` label, read live before the check
(`RELEASING.md` step 2, `tests/arch_ci_semver_holds_beta_886.rs`). Into any
other base this line's `ci.yml` compares with the last `v*` tag reachable from
the PR base commit, the release type inferred from the version change; a pull
request into `main` runs `main`'s own `ci.yml`, which holds a version on the
baseline's `major.minor` to `--release-type patch` against the last stable tag.
What the tool has no lint for it passes on either line: a changed return type
(beyond a value gained or lost) and a changed parameter type among them, so a
green `semver` is no evidence for such a change.

Design alignment: the bounded, pinned consumer matrix serves T1 (work scales
with the consumers) and T3 (targeted checks); exact revisions and resolution
witnesses serve T2 (verifiable evidence) and T5 (fewer trusted claims); Cargo
requirements and semver lints serve T4 (executable rules); CI and reproducible
commands serve T6 (executable). These are design connections, not claims of
chain or script verification by this lane.
