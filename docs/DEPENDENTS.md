# bsv-rs dependents

Snapshot: 2026-10-23. `[X]` means read from the named remote commit or run;
`[D]` means reported, including historical production records. A manifest
version is not evidence of the version running in production. The source of
the build matrix is [dependents.lock](dependents.lock); all its revisions were
default-branch heads when read. Consumer captains refresh the lock in each
pin-move PR. The map and scope come from [#83](https://github.com/Calhooon/bsv-rs/issues/83)
and [#101](https://github.com/Calhooon/bsv-rs/issues/101).

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

| Consumer and remote manifest `[X]` | bsv-rs requirement `[X]` | Features and slice `[X]` | Target; hermetic test selection | Production bsv-rs | Captain `[D]` |
|---|---|---|---|---|---|
| [bsv-wallet-cli](https://github.com/Calhooon/bsv-wallet-cli/blob/5e0dbb06ccfa5c237bce22a445fce3613db4da92/Cargo.toml), alias `bsv-sdk` | `=0.8.1` | default + `full` | Native, CLI and MCP workspace; excluded at 0.8.2 by the exact pin | [D] Unknown | CLI captain |
| [bsv-wallet-toolbox-rs](https://github.com/Calhooon/bsv-wallet-toolbox-rs/blob/e9857b8b7494b56c6b44abce7bdff1de9f952d1b/Cargo.toml) | `0.8.0` | default + `full,http` | Native, `sqlite`; library and integration tests | [D] Unknown | Toolbox captain, stack keeper |
| [bsv-tracker](https://github.com/Calhooon/bsv-tracker/blob/c127bccd983a1f4c32f92c1ef637c1ac0d24c838/Cargo.toml) | `0.8.0` | `transaction`, no defaults; wasm adds `wasm` | Native and wasm32; native library and integration tests | [D] Unknown | Stack keeper until named |
| [bsv-wallet-infra-cloudflare](https://github.com/Calhooon/bsv-wallet-infra-cloudflare/blob/d0dba8d2ef4d956614a7cf99787dec951dadb813/Cargo.toml), alias `bsv-sdk` | `0.8.1` | default + `auth,wallet,transaction,wasm` | wasm32; native library and integration tests | [D] Unknown | Stack keeper until named |
| [chaintracks-cloudflare](https://github.com/Calhooon/chaintracks-cloudflare/blob/dcfa491a33d21e7acfa800327c3850bc047a6211/Cargo.toml), crate `bsv-chaintracks-cloudflare` | `0.8.1` | `block`, no defaults | wasm32; native library and integration tests | [D] Unknown | Stack keeper until named |
| [bsv-messagebox-cloudflare](https://github.com/Calhooon/bsv-messagebox-cloudflare/blob/190a8a78f99733af47b3c789e88112257f13c8ed/Cargo.toml) | `0.8.1` | default + `auth,wallet,transaction,wasm` | wasm32; native library tests; the integration suite's version guard pins bsv-rs 0.8.1 in the lock and is excluded until the row re-pins; `tests/load_gen` is a separate live client, excluded | [D] Unknown | Stack keeper until named |
| [bsv-middleware-rs](https://github.com/Calhooon/bsv-middleware-rs/blob/5a1fd275e0fc5cb2fc3982aa157769d44f0729bf/Cargo.toml) | `0.8.0` | default + `auth,wallet,transaction` | Native with consumer feature `axum`; library and integration tests | [D] Unknown | Stack keeper until named |
| [bsv-middleware-cloudflare](https://github.com/Calhooon/bsv-middleware-cloudflare/blob/d7ccb6c1a56708687c6d044989f9ff06ea024823/Cargo.toml), alias `bsv-sdk` | `0.8` | default + `auth,wallet,transaction,wasm`; workspace `core` takes the same slice without `wasm` | wasm32 with consumer features `refund,d1-claims`; native workspace library and integration tests | [D] Unknown; see Zanaadu's historical embedded worker below | Stack keeper until named |
| [bsv-overlay-cloudflare](https://github.com/Calhooon/bsv-overlay-cloudflare/blob/a10ada00a00c6d8f0333010c6231b216951e03c7/Cargo.toml) | `=0.7.2` in both workspaces | default + `overlay`; overlay worker adds `wasm`, app-layer tests add `auth` | Native engine workspace and wasm32 worker workspace; excluded at 0.8.2 | `[D]` 0.5.0 with worker 0.1.3 on 2026-10-13; current unknown | Stack keeper until named |
| [bsv-agent-template](https://github.com/Calhooon/bsv-agent-template/blob/b1dcbdbfa9d8beab6783dc515789f5690968f462/Cargo.toml), alias `bsv-sdk` | `0.6.0` | default + `auth,wallet,transaction,wasm` | wasm32; excluded at 0.8.2 | [D] Unknown | Stack keeper until named |
| [bsv-storage-cloudflare](https://github.com/Calhooon/bsv-storage-cloudflare/blob/2563293557849a29007fa1c1b5d2001a3fc8a17d/Cargo.toml) | `=0.4.5` | default + `auth,wallet,transaction,script,wasm`; parity member adds `auth,http,overlay` | wasm32 worker; native parity client is live and excluded | `[D]` 0.4.5 with worker 0.2.1 on 2026-10-13; current unknown | Stack keeper until named |

The selected native suites use in-memory data, local databases or local mocks;
their existing ignored live tests remain ignored. No `--ignored`, load
generator, wallet, broadcaster example or deployment command is run. The
toolbox's test rules identify its ignored network tests explicitly. The wasm
checks exclude host-only dev dependencies such as SQLite.

The CLI's exact pin does **not** admit 0.8.2. It is recorded and reported as
skipped, rather than silently compiled against its registry copy. Seven public
Rust repositories currently admit this tree. A stable caret does not admit a
beta prerelease either. The planner prints every exclusion and builds all
admitted rows without a best-effort or continue-on-error path.

## App trees

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

`semver` runs on every PR against the last `v*` tag reachable from the immutable
PR base commit, using `cargo-semver-checks 0.51.0` and Rust `1.95.0`.
The [tool's baseline-rev mode](https://github.com/obi1kenobi/cargo-semver-checks/tree/v0.51.0#does-the-crate-im-checking-have-to-be-published-on-cratesio)
reads the tagged tree. `--all-features --release-type minor` keeps breaking
API changes fatal even when a 0.x minor bump or beta suffix would otherwise
be treated as permission to break. The tool documents its
[release-type override](https://github.com/obi1kenobi/cargo-semver-checks/blob/v0.51.0/src/main.rs).
Its pinned compiler avoids drift in rustdoc JSON formats. Baseline today:
`v0.8.2` (`efe12e6`).

Design alignment: the bounded, pinned consumer matrix serves T1 (work scales
with the consumers) and T3 (targeted checks); exact revisions and resolution
witnesses serve T2 (verifiable evidence) and T5 (fewer trusted claims); Cargo
requirements and semver lints serve T4 (executable rules); CI and reproducible
commands serve T6 (executable). These are design connections, not claims of
chain or script verification by this lane.
