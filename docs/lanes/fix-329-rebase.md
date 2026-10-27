# #329 rebase: `lane/fix-329-originator-option` onto beta after #323 (PR #332) landed

This worktree holds the branch as it stands (one commit, d1880e84 on f0f236e6, reviewed MERGE on Fable; its review's REPORT is in `cca runs --show review-329` on the studio, or read PR #334's comments and issue #329); the worktree's branch name may be `lane/fix-329-rebase`: the tip is what matters, the captain pushes it to `lane/fix-329-originator-option`. Rebase it onto `origin/beta` (which now carries #323, the HTTP wallet substrates' originator rule, and #110, #109, #320), resolve the seven conflicting files with the text the review named below, re-gate, and report. Read `CLAUDE.md`, `src/wallet/CLAUDE.md`, `src/wallet/substrates/CLAUDE.md`, `tests/CLAUDE.md`, #323's and #329's changelog entries. Do not read `~/bsv/bsv-low/` or `~/vault/`. Run every gate in the foreground; never end your turn with a gate running in the background. Never push. A MetaNet Client listens on 3301, 3321 and 2121 on this host: no test or probe on a default URL.

## The merged text (the review's section 2)

- `src/wallet/substrates/http_json.rs` (the request builder, #323's `:128-146`): #323's body wins (the configured originator required at the call in the reference's words, both `Origin` and `Originator` in the origin form, the call's argument not sent); keep #329's parameter type on the trait methods, `_originator: Option<&str>` where the substrate ignores it.
- `src/wallet/client.rs:189-209`: #323's constructions, `HttpWalletJson::new(self.originator.clone(), ...)?` (the `Result` constructors), with #329's calls, `get_version(originator.as_deref())`.
- `src/auth/utils/nonce.rs:325`: #323's configured constructor with its `.expect(...)`, #329's `Some("test.app")` in the call.
- `src/wallet/substrates/CLAUDE.md:237`: the sentence "Per-request originator takes precedence" goes; #323's paragraph is the rule.
- `tests/wallet_originator_option_329.rs:228`: the "no header for an absent originator" pin contradicts #323 (a call with none configured is refused before a request): it becomes a refusal pin in #323's words; `:234` stays, with `HttpWalletJson::new(...)` unwrapped at `:219`.
- `tests/wallet_http_originator_323.rs`: its three `&str` originators (`:89`, `:109`, `:216`) become `Some(...)`; the nine `HttpWalletJson::new`/`HttpWalletWire::new` sites in the tests #329 touches take `?` or `.unwrap()`.
- `CHANGELOG.md`: both entries kept, #329's above #323's under `[Unreleased]` (the landing order is the file's order: #323 landed first, so its entry sits below); `scratchpad/rebuild-changelog.py`'s rule if you know it, else by hand, no heading split, no line lost (diff the result against `origin/beta`'s CHANGELOG: only #329's own sections added).
- One docs note from the review: `CHANGELOG.md:69` of the #329 entry says the relay's five `create_nonce` calls pass a literal; one passes a literal and the rest a variable: say it as it is.

## #326 and #327 landed too (e0f1c447 and after)

Beta also carries #327 (the revocation's checks: `src/identity/revoke.rs`, `src/identity/double_spend.rs`, `src/wallet/review_actions.rs`, the recording wallet extended in `tests/support/identity_reveal_wallet.rs`, `tests/identity_revocation_checks_327.rs`) and #326 (the contacts manager's and kvstores' signAction as the text: `src/kvstore/bound.rs`, the recording wallet extended again, `tests/contacts_signaction_326.rs`, `tests/kvstore_signaction_326.rs`, `tests/support/signaction_reference_326.rs`). Every wallet call those files make takes the `Option` (`None` where the client has no configured originator, as the branch does elsewhere; `Some(..)` where configured), every mock they add implements the trait with `Option<&str>`, and their assertions keep what they pin (a `""` that became `None` only where no originator was configured). The recording wallet merges both extensions and this branch's parameter type.

## Gate

`cargo fmt --check`; `cargo clippy --all-targets --all-features -- -D warnings`; the full suite, `cargo test --features "full,http"` in two `--test` halves to files; the doc tests; `cargo build --examples --all-features`; `cargo test --test readme_examples`; the wasm32 build of the CLAUDE.md feature set; `cargo semver-checks --release-type minor --baseline-rev <origin/beta's sha>` (the trait change named, nothing else unexpected); the ratchet against `origin/beta`.

## Report

A REPORT: the base sha rebased onto, the tip, each conflict and the text taken, the diff of the rebased tip against the reviewed d1880e84 (the conflict resolutions only), the full suite's totals, the gate's results, anything unverified.
