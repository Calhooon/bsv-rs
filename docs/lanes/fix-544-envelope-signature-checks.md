Every gate and every test runs in the foreground, in your turn: no background job, no subagent; the REPORT is the last thing you write, and a turn that ends with a command still running is a stopped lane.

# #544: the six token-decode sites run the reference's canonical-envelope, signature and hash-binding checks and read the reference's record; one lane, six commits (the keeper's words of 2026-10-31 07:1xZ and 09:1xZ)

Branch `lane/fix-544-envelope-signature-checks` from `origin/beta` (name the base sha in your REPORT; #542 landed at 72f83617 and #543 lands as PR #547 before you start: read both landings first, `git log origin/beta -12`). SIX commits, one per site, each with its test RED on the base; the changelog entry and the rows in the SIXTH commit only. Never push. Nothing is filed on any tracker.

## The words (the keeper's; `gh issue view 544 --comments`, read whole)

07:1xZ: the port accepts what the reference refuses at the record level; a parity row at the pin with the reference lines, a witness vector recorded from the pinned bundle, a test RED on the base. 09:1xZ, the contacts site exactly, and every other site read the same way (the reference's envelope, signature and field set at the pin):
1. The contacts token is the signed two-field PushDrop: `#encryptAndLock` (`ContactsManager.ts:748-772` at edf6e03) locks `[ciphertext]` under `[2, 'contact']`, the keyID and self with PushDrop's signature on, so the output carries the ciphertext and the signature over it; `#authenticateContactScript` (`:431-456`) decodes exactly two fields (`:433`), the ciphertext 1 to 65 KiB plus 1 KiB, the signature 8 to 80 bytes, the canonical five-chunk script (`assertCanonicalSignedPushDrop` `:225-241`: the 33-byte key, OP_CHECKSIG, the two pushes, OP_2DROP), the lock key equal to the wallet's key for the protocol, keyID and self, then `verifySignature` over the ciphertext.
2. The contacts plaintext is `validateContact`'s record (`:171-192`): exactly the seven display fields `name`, `avatarURL`, `abbreviatedKey`, `identityKey`, `badgeIconURL`, `badgeLabel`, `badgeClickURL` (`:35-43`) with the reference's spellings, plus optional `metadata`; any other key is refused as unexpected field (`:173-177`), so `addedAt` leaves the token's plaintext: a saved-at time lives in the port's own cache or store beside the token, never inside it.
3. The witness is cross-implementation both ways on the pinned bundle: the reference's output decoded, authenticated and decrypted by the port, and the port's token decoded by the reference's validator with no refusal; RED on the base.

## The six sites (this crate after #537, #542 and #543) and the reference's checks (read each counterpart whole at `~/bsv/ts-stack/packages/sdk/src`)

| Commit | Site | Reference checks the port lacks (the #541 review's table; confirm each) |
|---|---|---|
| 1 | contacts (`src/identity/contacts*.rs`) | the two-field signed token (write and read), `assertCanonicalSignedPushDrop`, the lock key equal to the derived key, `verifySignature` over the ciphertext (`ContactsManager.ts:431-464`); the record of item 2 |
| 2 | identity client (`src/identity/client.rs`) | field count, envelope, locking key and field signatures (`IdentityClient.ts:774-815`) |
| 3 | registry client (`src/registry/`) | whatever `registryTokenValidation.ts:20-64` checks that #543's reader does not yet (read #543's landing first: it may be complete; then this commit is the statement that it is, with a test) |
| 4 | kvstore interpreter (`src/kvstore/interpreter.rs`) | the envelope and signature checks of `kvStoreTokenValidation.ts` the interpreter skips |
| 5 | overlay admin token (`src/overlay/overlay_admin_token_template.rs`) | the static decode's envelope check (`OverlayAdminTokenTemplate.ts:237`) and the author check the reference runs where it does |
| 6 | storage downloader (`src/storage/downloader.rs`) | the envelope and signature check and the hash binding (`StorageDownloader.ts:117` drops an advertisement for a different file; `UHRPAdvertisementValidation.ts`) |

Each commit: the site runs the reference's checks in the reference's order with the reference's refusal words (recorded, never by hand) or the reference's silent outcome (skip, drop, `None`) where the reference swallows; the writer at the site (where the port writes such a token) writes the reference's shape; a test RED on the base; the witness both ways where the reference writes such a token (one recorder for the six sites, `tests/support/token_envelope_544.mjs` in the pattern of `tests/support/contacts_protocol_542.mjs` and `registry_token_fields_543.mjs`, Node 22 against the edf6e03 bundle, the vector `tests/vectors/token_envelope_544.json`).

## The sixth commit also carries

`CHANGELOG.md` under `## [Unreleased]`: a `### Fixed: the six token-decode sites run the reference's envelope, signature and hash-binding checks (#544)` section (never a bare bullet) with the per-site table (old and new, the reference lines), the keeper's words, the recorder and vector, `addedAt`'s move out of the contacts plaintext stated for the toolbox's and the CLI's tables (the toolbox has no contacts path; the CLI none); the root `CLAUDE.md` divergence rows for these sites rewritten as closed (the #544 row and whatever #541's landing left open at the record level), every copy of a changed census line rewritten identically (`grep -c '^- Row N:'`); the module `CLAUDE.md` rows.

## Gate (foreground, on the sixth commit, each result in the REPORT)

`cargo fmt --check`; `cargo clippy --all-targets --all-features -- -D warnings`; `cargo test --features "full,http" --lib identity`, `--lib registry`, `--lib kvstore`, `--lib overlay`, `--lib storage` (one filter per run); one `--test` per file matching `identity_*`, `registry_*`, `kvstore_*`, `overlay_*`, `storage_*`, `arch_*` (the `.rs` files) and `fixtures_replay`; `cargo test --doc --all-features`; `cargo build --target wasm32-unknown-unknown --no-default-features --features "auth,wallet,transaction,overlay,socketio,wasm"` (`CC_wasm32_unknown_unknown` to LLVM clang if ring asks); `cargo semver-checks check-release --baseline-rev <base> --release-type patch` (a public shape that changes is a finding to state, not to hide; a reference-shaped addition is allowed under ruling (c), named); `tools/ratchet/run --check --against <base>` with `CARGO_TARGET_DIR` outside the checkout; `gitleaks git --redact --no-banner --exit-code 1 --log-opts="origin/beta..HEAD" .` from the repo root; hermetic (rule 4).

## REPORT

The base; the six commits' shas and messages; per site: the reference's checks and lines, the old and new outcome, the witness both ways; the recorder's command and the vector's cases; the RED evidence per site; `addedAt`'s new home; the rows rewritten (counted); semver's reading; the gate's results in a table; anything unverified; nothing else.

Rules: never end your turn with a command running in the background; commit on the branch, never push; no test or probe on a default URL or port (a MetaNet Client listens on 3301, 3321 and 2121 on this machine; another session's process on 3390); do not read `~/bsv/bsv-low/` or `~/vault/`, and do not grep across `~/bsv/` as a whole (the reference and the downstreams are read by their named paths); vectors are written by recorders, never by hand; scratch copies under `$TMPDIR` with their own `CARGO_TARGET_DIR`, removed at the end; never `rustup default` or `rustup override` (use `cargo +1.99.0`); a new dependency needs the captain's word first.
