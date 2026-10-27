# #353 fold: the cold review's two findings and notes on `lane/fix-353-peer-client-verifies` (at 5dc89cc on 1cdd149)

Work in this worktree on the branch as it stands (three commits; reviewed on Opus: FIX, two findings, four notes; the review's REPORT and its evidence are in `cca runs --show review-353` on this box and `/Volumes/Lanes/out/bsv-rs/review-353/`, its leak probe at `leak_probe_353.rs`). Read `src/auth/CLAUDE.md`, `tests/CLAUDE.md`, `docs/RATCHETS.md`, the branch's changelog entry. Do not read `~/bsv/bsv-low/` or `~/vault/`. Run every gate in the foreground; never end your turn with a gate running in the background. Never push. No test or probe on a default URL or a live host.

## The review's findings

- F1 `src/auth/peer.rs:200-230`: a `Peer` dropped after `start()` leaks (the review's probe `leak_probe_353.rs` is red on the tip and green on 1cdd149: the new one-path callback holds the `Peer` alive, an `Arc` cycle or a task that never ends). Fix it so a dropped `Peer` is freed (a `Weak` in the callback, or the callback cleared on drop, as the reference's `Peer` holds no self-reference); the probe becomes the RED test (`tests/auth_peer_client_verifies_353.rs` or a sibling), red on the tip as it stands, green after.
- F2 the changelog's claim "a signing server is unaffected" is untested over HTTP: add a wiremock round trip (a server answering a signed initial response and a signed general message, built with this crate's own signer over the recorded shapes, the client on `start()` accepting them), so the claim is a pin.

## The review's notes

- `docs/ratchets.json`: the record was hand-edited (two lines) where `docs/RATCHETS.md:56` says the record is the tool's whole output (`tools/ratchet/run --record`, the measured commit named by the tool), in its own commit: re-record with the tool on the branch's docs commit and replace the hand edit; the PR says it records the lower bound.
- `peer.rs:697` and `src/auth/transports/http.rs:794-801`: read the review's note on each (the REPORT names them) and apply or state.
- A general message's certificate-validation wait (`Peer.ts:1318-1325`: the reference awaits the session's pending certificate validation before handing a general message to the callbacks): read it and conform in this fold if it is one guarded await in the one path; else state it in the parity note (the captain files it).

## Gate

`cargo fmt --check`; `cargo clippy --all-targets --all-features -- -D warnings`; `cargo test --features "full,http"` on every test file matching `auth_*`, `socketio_*`, `transport_*`, `identity_*`, `arch_*` (not the `arch_support` module), `fixtures_replay`; `--lib auth`; the doc tests; `cargo build --examples --all-features`; `cargo test --test readme_examples`; the wasm32 build of the CLAUDE.md feature set; `cargo semver-checks --release-type minor --baseline-rev 1cdd149`; the ratchet against `origin/beta`.

## Report

A REPORT: the tip, each commit, F1's cause and fix with the probe's RED and green, F2's round trip, the ratchet re-recorded by the tool, the notes applied or stated, the gate's results, anything unverified.
