# Lane fix-843dforeign: the three `tokio` types leave the public surface, the guard reads `indexmap` and holds a rule for its list, three small items leave (#843, the captain's rulings of 2026-11-12)

Base: `origin/beta` at `d892e206` (pull request #900 landed: `AppEventReceiver` is under `src/`). BREAKING on beta: the pull request carries the `api-break` label. The rulings (`rulings-843d-foreign.md` in the captain's notes, three independent design reads, counted) decide each site and are not reopened here. No wire byte, verdict or error text moves; no vector is recorded or edited.

## The invariant

A type of another crate in a public signature makes that crate's major release this crate's break (rule 9). #843d23 took `num-bigint` and `futures` out and left three `tokio` sites listed as the captain's candidates. This lane takes them out, and makes the list that remains answer to one sentence a machine holds where a machine can.

## The sites, side by side

| Site on `d892e206` | Before | After |
|---|---|---|
| `src/auth/peer.rs:546` | `pub fn session_manager(&self) -> &Arc<RwLock<SessionManager>>` (tokio's lock, `:33`) | `-> &SessionManagerHandle` (`:551`): this crate's type, `src/auth/session_handle.rs` (121 lines), `Clone`, the lock private inside, `read().await -> SessionManagerReadGuard<'_>`, `write().await -> SessionManagerWriteGuard<'_>`, each `Deref` (the write guard `DerefMut`) to `SessionManager`; `new` is `pub(crate)`, the door of `Peer::new` and of `AuthFetch`, which shares one store across its per-origin peers through `Peer::share_session_manager` (`pub(crate)`, `:276`); `Debug` of the three prints `Name { .. }`. Re-exported at `auth::` beside `SessionManager` (with the two guards) and at the crate root |
| `src/overlay/host_reputation_tracker.rs:478` | `pub fn subscribe(&self) -> broadcast::Receiver<RankChangeEvent>` | `-> RankChangeReceiver` (`:486`): this crate's type, `src/overlay/rank_change_receiver.rs` (82 lines; the tracker's file is past the ratchet's 800 lines and went 986 to 963), `recv`, `try_recv`, `missed`, `Send`, a `Debug` printing the count alone. Re-exported at `overlay::` beside `RankChangeEvent` |
| `:501` | `pub fn on_rank_change(&self, callback: impl Fn(RankChangeEvent) + Send + Sync + 'static) -> tokio::task::JoinHandle<()>` | removed: no caller under `src/`, `tests/`, `examples/`, `benches/`, `fuzz/` or in the dependents (below); it called `tokio::spawn` in a module of the wasm32 slice and its loop ended at one lag. No callback form was kept: no caller was found that `subscribe` cannot serve |
| `src/auth/transports/fetch_client.rs:9` | `pub type NativeFetchClient = reqwest::Client;` (re-exported at `auth::transports::`) | `pub(crate) type`, the re-export removed; `AuthFetch::with_client` (`src/auth/clients/auth_fetch.rs:158-163`) names `reqwest::Client` |
| `src/auth/certificates/verifiable.rs:285` | `pub fn to_json_value(&self) -> serde_json::Value` | removed (its one unit-test use takes `serde_json::to_value(&verifiable)`) |
| `src/kvstore/types.rs:337` | `pub fn to_json(&self) -> serde_json::Value` | `pub(crate)` (`:345`), the store's two uses unchanged |

The callers of `peer.session_manager()` keep their text: 18 sites in 8 files under `tests/` (14 `read`, 3 `write`, 1 `clone` moved into a `'static` callback), none edited. The four unit tests of the tracker (`test_subscribe_receives_rank_change` and the three after it) keep their text: `.expect(..)` reads an `Option` as it read a `Result`. Six test sites took a Migration line: `tests/auth_certificate_json_268.rs` (1), `tests/kvstore_global_tests.rs` (4), `tests/kvstore_integration_tests.rs` (1).

## The lag, stated

The tracker's channel keeps 64 events (`DEFAULT_BROADCAST_CHANNEL_CAPACITY`). On the base a receiver more than 64 behind got `Err(RecvError::Lagged(n))` once, its cursor moved to the oldest event kept, which the next `recv` answered (tokio 1.54.1 `src/sync/broadcast.rs:41-52`). On the tip `recv` and `try_recv` pass over the lag, add `n` to `missed()` and answer that event: the same events in the same order, the lag a count where it was an `Err`. Built on one design read (the API read; the other two say nothing of a lag).

## The references at the same doors (`ts-stack@edf6e03`, `packages/sdk/src/`; read with `git show`)

- `auth/Peer.ts:55` `public sessionManager: SessionManager`; `:163` `this.sessionManager = (sessionManager ?? new SessionManager()) as SessionManager`; the store's doors `addSession`, `updateSession`, `getSession`, `removeSession`, `hasSession` (`auth/SessionManager.ts:130,174,195,250,264`); `AsyncSessionManager` (`:17-33`), which has no counterpart here (stated in the root `CLAUDE.md`'s new row, older than this lane). go-sdk@2ca481c `auth/peer.go:54` `sessionManager SessionManager`, no getter.
- `overlay-tools/HostReputationTracker.ts:87` the class; `reset` `:98`, `recordSuccess` `:103`, `recordFailure` `:126`, `rankHosts` `:166`, `snapshot` `:198`, `flush` `:205`: no callback, emitter or subscription. Where the reference listens, a callback and an id: `auth/Peer.ts:538-540`.
- The list's classes: `auth/transports/SimplifiedFetchTransport.ts:66` `fetchClient: typeof fetch = defaultFetch,`; `auth/clients/AuthFetch.ts:197` `fetchClient?: typeof fetch`; `overlay-tools/LookupResolver.ts:43` `query: unknown`; `auth/certificates/Certificate.ts:179` `fields: Record<CertificateFieldNameUnder50Bytes, Base64String>`.

## The guard (`tests/arch_no_foreign_type_843d23.rs`, 6 tests to 11)

- **Roots from the manifest.** `manifest_dependencies` reads `[dependencies]` (the inline and the table form, a hyphen as an underscore) and every name is a root, less `VOCABULARY`: `serde` (the serialization traits) and `thiserror` (a derive macro alone; its `Error` derive is imported in `src/error.rs` under the name of this crate's own `Error`, so with it read every `Result` in a signature was a `thiserror` site: found by the run, 100 and more false sites). `COUNTS_AS` keeps the families (`futures_channel`, `futures_util`, `futures_core` as `futures`; `tokio_tungstenite` as `tokio`). A dependency that is neither a root nor a vocabulary name, and a vocabulary name that is no dependency, each fail.
- **A site of a further crate: none found.** With all 39 dependencies read, the only crates with a site are `serde_json`, `reqwest` and `indexmap` (and, on the base, `tokio`).
- **The alias pre-pass.** `learn_aliases` reads every `pub type Name = ..;` whose right-hand side names a read crate, to a fixed point, and the name counts as that crate at every site, bare or as a path's segment. `RequestedCertificateTypes` (`src/auth/types.rs`, an `IndexMap`) reaches `RequestedCertificateSet.types`. Stated in the header: a local item that shares an alias's name is read as the alias.
- **Totals.** `num_bigint`, `futures`, `k256`, `p256`, `tokio` 0; `reqwest` 4 (the three `with_client` of #320 and `fn AuthFetch::with_client`; the alias's row out); `serde_json` 26 (28 less the two restatements); `indexmap` 36. 66 rows.
- **The rule.** The header carries the ruling's sentence: "A foreign type may be listed when its crate is at 1.0 or later, the type is data and not behaviour, and either the reference exposes the same thing as an untyped, ordered or signed value or the instance is the caller's own." `row_refusal` holds it: every row's reason opens with one of four classes followed by `: ` (`untyped member` 21, `text as received` 5, `ordered record` 36, `caller's instance` 4) and any other opening fails; a row of the three data classes for a crate the manifest has below 1.0, or does not have, fails naming the crate and its version; a `caller's instance` row stands on the last clause alone, and must say that the crate's next breaking release is this crate's. **For the captain:** read as one conjunction the sentence refuses the `reqwest` rows that ruling Q3 keeps (`reqwest` is at 0.12); the guard reads the last clause as standing alone, and its header says so. Whether a type is data, and what the reference exposes, no machine reads: the class is the row's claim.

### The `indexmap` sites (36, found by the scan, unlisted until now)

- `src/auth/certificates/certificate.rs` (3): `Certificate.fields`, `fn Certificate::with_fields`, `fn Certificate::set_fields`
- `src/auth/certificates/master.rs` (6): `MasterCertificate.master_keyring`, `fn MasterCertificate::new`, `fn MasterCertificate::create_certificate_fields`, `fn MasterCertificate::create_keyring_for_verifier`, `fn MasterCertificate::issue_for_subject`, `fn MasterCertificate::decrypt_fields`
- `src/auth/certificates/verifiable.rs` (4): `VerifiableCertificate.keyring`, `fn VerifiableCertificate::new`, `fn VerifiableCertificate::decrypt_fields`, `fn VerifiableCertificate::get_decrypted_fields`
- `src/auth/clients/auth_fetch.rs` (2): `AuthFetchOptions.headers`, `fn AuthFetchOptions::with_headers`
- `src/auth/clients/response.rs` (1): `Response.headers`
- `src/auth/types.rs` (2): `type RequestedCertificateTypes`, `RequestedCertificateSet.types`
- `src/identity/client.rs` (1): `fn IdentityClient::resolve_by_attributes`
- `src/identity/types.rs` (4): `IdentityQuery.attributes`, `fn IdentityQuery::by_attributes`, `IdentityCertificate.publicly_revealed_keyring`, `IdentityCertificate.decrypted_fields`
- `src/wallet/types.rs` (9): `Certificate.fields`, `WalletCertificate.fields`, `AcquireCertificateArgs.fields`, `AcquireCertificateArgs.keyring_for_subject`, `CertificateResult.keyring`, `ProveCertificateResult.keyring_for_verifier`, `IdentityCertificate.publicly_revealed_keyring`, `IdentityCertificate.decrypted_fields`, `DiscoverByAttributesArgs.attributes`
- `src/wallet/validation.rs` (1): `fn validate_certificate_fields`
- `src/wallet/wire/encoding.rs` (3): `fn WireReader::read_string_map`, `fn WireReader::read_optional_string_map`, `fn WireWriter::write_string_map`

The design reads counted 35, which is the rustdoc JSON's count (below): the JSON shows `RequestedCertificateSet.types` as this crate's alias, the 36th is that field, read through the alias pre-pass.

## One more machine moved: `tests/arch_network_sites.rs`

`AuthFetch::with_client`'s parameter now says `reqwest::Client` in `src/auth/clients/auth_fetch.rs`, outside the transport homes, where the alias had kept the crate's name out of the file. The rule failed (`src/auth/clients/auth_fetch.rs:162: network client outside a transport home`); the field stays typed by the crate-private alias, and the one parameter line is an exact-line allowance with ceiling 1 and its reason (the caller's own instance, handed to the transport home as given), recorded in `docs/ARCH-RULES.md`. **For the captain:** this is an allowance the brief did not name.

## RED on the base

A scratch copy of `d892e206` by `git archive` under the lane's out folder, the tip's three test files overlaid, target `/Volumes/Lanes/targets/fix-843dforeign-red`; both removed after.

- `arch_no_foreign_type_843d23`: 9 passed, 2 failed. `no_public_signature_names_a_foreign_type_843d23` names exactly six sites: `fn VerifiableCertificate::to_json_value` (serde_json), `fn Peer::session_manager` (tokio), `type NativeFetchClient` (reqwest), `fn KVStoreQuery::to_json` (serde_json), `fn HostReputationTracker::subscribe` (tokio), `fn HostReputationTracker::on_rank_change` (tokio). `the_scan_reads_indexmap_and_an_alias_of_this_crates_own_843dforeign` fails at its `tokio` count (`left: 3, right: 0`). (`fn AuthFetch::with_client` is a `reqwest` site on the base too, through the alias, and its row matches.)
- The same file with its 36 `indexmap` rows taken out: the 36 `indexmap` sites named, `src/auth/types.rs:562: RequestedCertificateSet.types` among them.
- `auth_session_handle_843dforeign`: compile-RED, `error[E0432]: unresolved imports bsv_rs::auth::SessionManagerHandle, bsv_rs::auth::SessionManagerReadGuard, bsv_rs::auth::SessionManagerWriteGuard` (the one error: the import fails ahead of the binding).
- `overlay_rank_change_receiver_843dforeign`: compile-RED, 27 errors: `E0432` (unresolved import `bsv_rs::overlay::RankChangeReceiver`), `E0308` ×11 (mismatched types: an `Option` where the base answers a `Result`), `E0599` ×15 (`is_none`, `is_some` on a `Result`; `missed` on `tokio::sync::broadcast::Receiver<T>`).
- The five `compile_fail` doc blocks (the four doors that left and a binding of the session door typed by the lock), appended to the scratch copy's `src/lib.rs` and run by `cargo test --doc --all-features red_843dforeign`: 0 passed, 5 failed, each `compile fail ... FAILED` (each compiles on the base). On the tip each is `compile fail ... ok`.
- In memory, on the tip (the guard's own tests): `pub fn planted() -> tokio::sync::broadcast::Receiver<u8>` refused as `("fn planted", "tokio")`; an `indexmap::IndexMap` return and a field typed by a planted alias refused; a row classed `untyped member` for `reqwest` refused naming `reqwest` and `0.12`, the same row as `caller's instance` accepted; a reason with no class refused.

## BREAKING: the evidence

**The rustdoc JSON diff.** `cargo +nightly rustdoc --lib --all-features -- -Z unstable-options --output-format json`, outside target dirs, read by a script kept in the lane's out folder (`scripts/survey.py`): every item of `bsv_rs`'s index whose function signature, field, variant, alias, re-export or non-synthetic, non-blanket trait impl names a path of another crate (`std`, `core`, `alloc` aside), one row an item.

| Crate | `d892e206` | tip |
|---|---:|---:|
| `tokio` | 3 | 0 |
| `reqwest` | 4 | 4 |
| `serde_json` | 29 | 27 |
| `indexmap` | 35 | 35 |
| `serde_core` (the vocabulary) | 115 | 115 |

No other crate appears. The diff is six rows removed and one added: `session_manager` (`RwLock`), `subscribe` (`broadcast::Receiver`), `on_rank_change` (`tokio::task::JoinHandle`), the alias `NativeFetchClient` (`reqwest::Client`), `to_json_value` and `to_json` (`serde_json::Value`) removed; `AuthFetch::with_client` (`reqwest::Client`) added. The `serde_json` 29 against the guard's 28 on the base is #843d23's stated difference (the trait-impl copies of `lookup_ordered` and `lookup_bounded`, `list_uploads` twice).

**`cargo semver-checks check-release --baseline-rev d892e206 --all-features --release-type patch`** (0.51.0): 229 checks, 228 pass, 1 fail. The one lint, `inherent_method_missing`, on `HostReputationTracker::on_rank_change`, `VerifiableCertificate::to_json_value` and `KVStoreQuery::to_json`. The two changed return types and the removed alias draw no lint: the JSON diff is their evidence.

**The dependents** (`git -C <path> grep -nP`, read-only; the columns: `session_manager\(\)`, `\bon_rank_change\b`, `\bRankChange(Event|Receiver)\b`, `\bNativeFetchClient\b`, `\bto_json_value\b`, `\bKVStoreQuery\b`, `AuthFetch(::<[^>]*>)?::with_client`, `HostReputationTracker`):

| Folder | Ref | Counts |
|---|---|---|
| `~/bsv/bsv-overlay-cloudflare` | `HEAD` `2efad2f0` | 0 0 0 0 0 0 0 0 |
| `~/bsv/rust-message-box` | `HEAD` `08418ec` | 0 0 0 0 0 0 0 0 |
| `~/bsv/bsv-wallet-toolbox-rs` | `HEAD` `a3377ef0` (main) | 0 0 0 0 0 0 0 0 |
| `~/bsv/bsv-wallet-toolbox-rs` | `origin/beta` `184c4182` | 3 0 0 0 0 0 0 0 |
| `~/bsv/bsv-wallet-cli` | `HEAD` `f4285bf`, `origin/beta` `6dc14ef` | 0 0 0 0 0 0 0 0 each |
| `~/bsv/bsv-middleware-rs` | `HEAD` `3cb76f0` | 0 0 0 0 0 0 0 0 |

The toolbox's three are in its test modules on its beta line (`src/storage/client/brc104_bounds_tests.rs:38`, `transport_fault_tests.rs:86`, `volunteered_certificate_tests.rs:160`), each `session_manager()` then `write().await.add_session(..)`: they keep their text. `~/bsv/bsv-middleware-cloudflare`, which the brief names, is no folder on this host; `~/bsv/bsv-middleware-rs` was read in its place. No caller of `on_rank_change`: removed, no callback form kept.

**Migration** (the CHANGELOG's lines):

- `peer.session_manager()`: `.read().await`, `.write().await` and `.clone()` keep their text; a binding typed `Arc<RwLock<SessionManager>>` becomes `SessionManagerHandle`.
- `while let Ok(e) = rx.recv().await`: `while let Some(e) = rx.recv().await`; `Err(RecvError::Lagged(n))`: `rx.missed()`.
- `let h = tracker.on_rank_change(cb); h.abort();`: `let mut rx = tracker.subscribe();` then, on the caller's own executor, `while let Some(e) = rx.recv().await { cb(e) }`, stopped by dropping the task.
- `NativeFetchClient`: `reqwest::Client`; `cert.to_json_value()`: `serde_json::to_value(&cert)?`; `query.to_json()`: `serde_json::to_value(&query)?`.

## The design reads the build rests on (lines for the captain)

Built on two reads of three, the third's named: the handle keeps `read` and `write` (the API read: the store's doors as async methods, no guard); the roots come from `Cargo.toml` (the API read: `indexmap` on the hand list); the rows carry a class and no more (the parity read: the reference's line in every row; the callers read: a crate below 1.0 only behind a feature outside `full`). Built on one read: `missed()`.

## The gate (macOS, `CARGO_BUILD_JOBS=4`, one cargo at a time, every run under ten minutes)

- The three Rustfmt lines of `ci.yml`'s `lint` job: clean. `cargo clippy --all-targets --all-features -- -D warnings`: clean. `RUSTDOCFLAGS="-D warnings" cargo doc --no-deps --all-features`: clean.
- `cargo test --features "full,http" --lib auth`: 147 passed; `--lib overlay`: 119 passed.
- The two new files three times, one run with `-- --test-threads=1`: 4 and 6 passed each run.
- `cargo test --features "full,http" --no-fail-fast` with `--test 'auth_*'`: 46 binaries, 395 passed, 7 ignored; `'socketio_*'`: 4, 16 passed; `'lookup_*'`: 12, 93 passed, 2 ignored; `'overlay_*'`: 13, 200 passed; `'kvstore_*'`: 19, 290 passed; `'arch_*'`: 38, 206 passed, 1 ignored.
- The wasm32 slice of rule 6: built.
- The whole suite: `--test '[a-k]*'` 205 binaries, 1,888 passed, 0 failed, 14 ignored; `--test '[l-z]*'` 213 binaries, 2,278 passed, 0 failed, 21 ignored; `--lib` 1,853 passed, 4 ignored; `cargo test --doc --all-features` 390 passed, 126 ignored (`--features "full,http"`: 388 passed, 125 ignored). Summed: 6,409 passed, 0 failed, 165 ignored. The two conformance files ran with the corpus at `../ts-stack/conformance` and their pinned totals held (4 passed each).
- CI's doc-log reader (`the_doc_suite_ran_every_pinned_block_819` over the doc suite's log): passed.
- `cargo build --examples --all-features`; `cargo test --test readme_examples` (1 passed).
- `tools/ratchet/run --check --against d892e206` (an outside target dir): all 7 counters, oversized-file limits and mutation floors pass.
- `python3 -B .github/scripts/mutants_entries.py`: PASS, 28 entries; `python3 -B .github/scripts/rows_from_sources.py --check`: 0 refusals.
- `gitleaks git --redact --no-banner --exit-code 1 --log-opts="d892e206..HEAD" .`: no leaks.

Not run here: Linux and Windows (CI's, after the landing); the nightly's mutation and fuzz stages.
