Every gate and every test runs in the foreground, in your turn: no background job, no subagent; the REPORT is the last thing you write, and a turn that ends with a command still running is a stopped lane.

# #498 fold: serde's `PublicKey` and `KeyringRevealer` read strictly (the reference's argument paths are strict); the rebase onto beta's tip with the review's resolution

You are on the lane's worktree `lane/fix-498-public-key-forms` at `82d0944b` (one commit on `aa5d60db`). PR #538. Never push. Nothing is filed on any tracker.

## The review's finding (Opus, PR #538's cold review; the one reason for FIX)

The parser matches the reference on all three forms, the vector reproduces, RED holds, the gate is green. But serde's `PublicKey` reading now goes through the lenient parser (`src/primitives/ec/public_key.rs:448`, the serde visitor) and so does `KeyringRevealer` (`src/wallet/types/json_forms.rs:84`), on paths where the reference validates strictly:
- `AuthMessage.identityKey` (`src/auth/types.rs:434`): the reference's `assertAuthIdentityKey` requires a lower-case compressed key with `toString() === value` (`AuthMessageValidation.ts:81-89,344` at edf6e03); on the tip a hybrid, odd-length or `02`+(p+1) key is accepted (an uncompressed `04` key was already accepted on the base: an older gap, say so in the entry, do not widen the fold to it unless the strict read closes it for free).
- `KeyringRevealer`: the reference's `validateKeyringRevealer` → `validatePublicKey` (`validationHelpers.ts:1243-1246,185-191`) is strict.
- `auth::Certificate` subject/certifier (`src/auth/certificate_json.rs:28,30`): the reference's `toBinary` requires compressed hex and `assertCompressedPublicKey` (`Certificate.ts:240-245`); the subject compared as a string (`validateCertificates.ts:82`). The review read this from the code only: check it and treat it the same way if the serde visitor is the reader there.
The keeper's word covers `from_hex`; it does not cover these paths.

## The fold

1. `Deserialize for PublicKey` and `KeyringRevealer`'s reading go strict: the hex decoded as it was before #498 (even length, the strict prefixes), then `from_bytes`; the words of the refusal as the base had them (read `git show aa5d60db:src/primitives/ec/public_key.rs` for the base's serde path and keep its error text). `from_hex` stays lenient (the keeper's word). Every other serde path that reads a key through the visitor is covered by the same change; name them in the REPORT (`git grep -n 'PublicKey' src --include='*.rs' | grep -i -E 'serde|deserial|visitor'`).
2. The pin: an `AuthMessage` deserialisation test (in `tests/auth_*` or the auth unit tests) with a hybrid, an odd-length and a `02`+(p+1) `identityKey`: each refused; green on the base (`aa5d60db`, a scratch copy with its own target dir) and RED on the current tip (`82d0944b`) before the fold, green after; a `KeyringRevealer` case the same way. Reuse the vector's forms (`tests/vectors/public_key_forms_498.json`) for the inputs so the forms are the recorded ones.
3. Reword the root `CLAUDE.md:80` row and the entry's "and serde's reading" sentence: `from_hex` and the kvstore point check lenient as the reference's `fromString`; serde's argument paths strict as the reference's validators; the older `04` acceptance on `AuthMessage.identityKey` stated if it remains.

## The rebase (after the fold, in the same turn; beta has moved: `git fetch origin beta`, name the tip in the REPORT)

`git rebase origin/beta` with the review's resolution of the five textual conflicts: `tests/kvstore_local_parser_words_489.rs` keep `assert_accepted_key` and drop `assert_lock_after` (beta removed it with #499; the merged tree passed 12/12 and 6/6 on the review's scratch copy); `CHANGELOG.md` keep both head entries (#498 above beta's), take Row 1's census line from this branch and Row 2's from beta, every other line beta's; root `CLAUDE.md` take this branch's #498 row and beta's #499 row, drop this branch's "also tries lock-after" row (stale after #499); `src/kvstore/CLAUDE.md` beta's table rows with the #498 note and beta's paragraph plus the #498 key sentence, drop "lock-after tokens reach later field-count/envelope checks"; `tests/CLAUDE.md` beta's 489 row (12 tests) plus the new 498 rows. If #535 (#347: `tests/arch_support/`, `tests/arch_no_string_errors.rs`, `tests/arch_ci_pr_runs_the_required_set.rs`, `docs/ARCH-RULES.md`, the changelog head) has landed too, its entry stays below #498's at the head and nothing else of it conflicts. Two commits at the end: the lane's rebased commit and the fold's commit on top (the captain squashes); or one commit if the rebase makes two impossible to keep clean, said why.

## Gate (foreground, on the rebased tip, each result in the REPORT)

`cargo fmt --check`; `cargo clippy --all-targets --all-features -- -D warnings`; `cargo test --features "full,http" --lib primitives`, `--lib wallet`, `--lib auth`, `--lib kvstore` (one filter per run); one `--test` per file matching `auth_*`, `ec_*`, `primitives_*`, `wallet_*`, `kvstore_*`, `script_*`, `arch_*` (the `.rs` files) and `fixtures_replay`; `cargo test --doc --all-features`; `cargo build --target wasm32-unknown-unknown --no-default-features --features "auth,wallet,transaction,overlay,socketio,wasm"` (`CC_wasm32_unknown_unknown` to LLVM clang if ring asks); `cargo semver-checks check-release --baseline-rev <beta tip> --release-type minor`; `tools/ratchet/run --check --against <beta tip>` with `CARGO_TARGET_DIR` outside the checkout; `gitleaks git --redact --no-banner --exit-code 1 --log-opts="origin/beta..HEAD" .` from the repo root.

## REPORT

The base (beta's tip) and the two tips; the serde paths found and made strict (a table: path, reference site, before, after); the pin's results on the base, the pre-fold tip and the fold; the rebase's five resolutions as done; the gate's results in a table; anything unverified; nothing else.

Rules: never end your turn with a command running in the background; commit on the branch, never push; no test or probe on a default URL or port (a MetaNet Client listens on 3301, 3321 and 2121 on this machine; another session's process on 3390); do not read `~/bsv/bsv-low/` or `~/vault/`, and do not grep across `~/bsv/` as a whole (the reference and the downstreams are read by their named paths); vectors are written by recorders, never by hand; scratch copies under `$TMPDIR` with their own `CARGO_TARGET_DIR`, removed at the end; never `rustup default` or `rustup override` (use `cargo +1.99.0`); a new dependency needs the captain's word first.
