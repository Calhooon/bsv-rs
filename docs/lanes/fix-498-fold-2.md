Every gate and every test runs in the foreground, in your turn: no background job, no subagent; the REPORT is the last thing you write, and a turn that ends with a command still running is a stopped lane.

# #498 fold 2: the HTTP transports' identity-key header reads strictly (two sites), one comment corrected, the rebase onto beta's tip

You are on the lane's worktree `lane/fix-498-public-key-forms` at `6481787b`: two commits on `ef16c71d` (the squashed lane with its first fold, 854bff00; the third review's tests commit, 6481787b). PR #538. Never push. Nothing is filed on any tracker.

## The third review's finding (Opus; read PR #538's comments: `gh pr view 538 --comments`)

1. `src/auth/transports/http/unauthenticated.rs:117` reads the `x-bsv-auth-identity-key` header through the lenient `from_hex`, where the reference (`~/bsv/ts-stack/packages/sdk/src/auth/utils/AuthMessageValidation.ts:344` at edf6e03) and the base (`aa5d60db`) read it strictly: a probe on the tip reads hybrid and odd-length headers as the canonical key. `src/auth/transports/http/payment.rs:190` the same. The fix: `from_strict_hex` (the base's strict reading, its words and error class) at both sites, plus a pin RED on the current tip (a hybrid, an odd-length and a `02`+(p+1) header each refused; the inputs from `tests/vectors/public_key_forms_498.json`), green after.
2. The comment at `src/auth/utils/validation.rs:218` (and the test's words at `tests/auth_key_strictness_sites_498.rs:8-10`) cites `toBinary`; the reference's certifier refusal is the requested-set check at `getVerifiableCertificates.ts:76-81`: correct the citation (read the reference line yourself). The skip-versus-throw difference there is older than #498: leave it, say so.
3. Any other `from_hex` caller the third review did not judge: `git grep -n 'from_hex' src` on the tip; for each caller outside the known sites (the serde visitor and `KeyringRevealer` strict; the four re-review sites strict; the two header sites above; `requested_set.rs:97` round-trips to canonical hex): parse (lenient, right) or validation (strict, a fix here with a pin). Name each in the REPORT.

## The rebase (after the fold, in the same turn)

`git fetch origin beta`; beta's tip is `0eac9651` or later (#346 and #347 landed; #540, a docs PR touching `docs/lanes/375-filings/` only, may have landed; #539 touches `CHANGELOG.md`'s head, the root `CLAUDE.md` list's end, `tests/CLAUDE.md`, `src/wallet/substrates/result_values/lists.rs` and the 408 recorder, vector and test). `git rebase origin/beta`: the `CHANGELOG.md` head keeps both (this PR's entry above beta's); `tests/CLAUDE.md` and the root `CLAUDE.md` take both sides' rows; every beta line kept (`diff <(git show origin/beta:CHANGELOG.md) CHANGELOG.md` shows only this PR's additions). Three commits at the end (the two you were given, rebased, and your fold on top), or fewer if the rebase forces it, said why; the captain squashes.

## Gate (foreground, on the rebased tip, each result in the REPORT)

`cargo fmt --check`; `cargo clippy --all-targets --all-features -- -D warnings`; `cargo test --features "full,http" --lib auth`, `--lib primitives`, `--lib wallet` (one filter per run); one `--test` per file matching `auth_*`, `ec_*`, `primitives_*`, `wallet_*`, `kvstore_*`, `identity_*`, `arch_*` (the `.rs` files) and `fixtures_replay`; `cargo test --doc --all-features`; `cargo build --target wasm32-unknown-unknown --no-default-features --features "auth,wallet,transaction,overlay,socketio,wasm"` (`CC_wasm32_unknown_unknown` to LLVM clang if ring asks); `cargo semver-checks check-release --baseline-rev <beta tip> --release-type minor`; `tools/ratchet/run --check --against <beta tip>` with `CARGO_TARGET_DIR` outside the checkout; `gitleaks git --redact --no-banner --exit-code 1 --log-opts="origin/beta..HEAD" .` from the repo root; hermetic (no default URL or port: a MetaNet Client listens on 3301, 3321 and 2121).

## REPORT

The base (beta's tip) and the tips; the two header sites' change with the reference's line; the pin's results on the pre-fold tip (RED) and after; the comment's correction with the reference line; the other callers' table; the rebase's resolutions; the gate's results in a table; anything unverified; nothing else.

Rules: never end your turn with a command running in the background; commit on the branch, never push; no test or probe on a default URL or port (a MetaNet Client listens on 3301, 3321 and 2121 on this machine; another session's process on 3390); do not read `~/bsv/bsv-low/` or `~/vault/`, and do not grep across `~/bsv/` as a whole (the reference and the downstreams are read by their named paths); vectors are written by recorders, never by hand; scratch copies under `$TMPDIR` with their own `CARGO_TARGET_DIR`, removed at the end; never `rustup default` or `rustup override` (use `cargo +1.99.0`); a new dependency needs the captain's word first.
