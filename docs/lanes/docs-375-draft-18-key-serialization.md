Do every edit and every gate yourself, in the foreground, in your turn: no background job, no subagent; the REPORT is the last thing you write, and a turn that ends with a command still running is a stopped lane.

# The #375 queue's eighteenth draft: the reference serializes an unreduced-coordinate public key as its negation (ts-stack), FILE at the owner's cadence word (docs only)

Branch `lane/docs-375-draft-18-key-serialization` from `origin/beta` (name the base sha in your REPORT). Docs only: `docs/lanes/375-filings/`. Nothing is filed on any tracker: the draft is filed on `bsv-blockchain/ts-stack` under the owner's name at the owner's cadence word (21.5 of the brief), by the keeper and the owner, never by a lane or the captain before that word.

## The keeper's word (2026-10-31 06:1xZ, recorded on PR #538; read it: `gh pr view 538 --comments`)

The defect reading holds at the pin: `Point.fromDER` (`Point.ts:303-321` at edf6e03) builds the point with y unreduced, the constructor marks it red without reducing (`Point.ts:472-478`, `forceRed`), the arithmetic computes in the field (y = 1, odd), and encode (`Point.ts:527-536`) takes the compact prefix from `getY().isEven()` on the unreduced p+1, so it writes `02`+x, the negation of the point it computed with. A FILE draft in the #375 queue: the ecosystem split and the five cases as the witness; the ask upstream: reduce or refuse at parse, and serialize the point computed with. This crate's `03`+x is the port's row with the reference's `02`+x beside it, labeled the reference's defect, never as parity.

## What to do

1. Write `docs/lanes/375-filings/public-key-unreduced-coordinate-serialization.md` in the shape of the existing drafts (read two: `certificate-response-preimage-go-sdk.md` and `der-length-witness.md` or the DER draft the queue names; the first line of a FILE draft names its place in the keeper's order and "pending the owner's cadence word"): the finding in the reference's own terms with the four `Point.ts` sites and lines; the witness: the ecosystem table (TS, go-sdk `2ca481c`, py-sdk `4c30e2e`, this crate) from PR #538's body and review comments, and the five recorded cases of `tests/vectors/public_key_forms_498.json` where the reference's `toString` differs from the point it read (name them by their inputs; read the vector on `origin/lane/fix-498-public-key-forms`, since #538 has not landed: `git fetch origin lane/fix-498-public-key-forms && git show origin/lane/fix-498-public-key-forms:tests/vectors/public_key_forms_498.json`); the standard's reading (SEC 1 §2.3.4: a coordinate must be below p, so neither form is in the standard); the ask upstream exactly as the word says; this crate's row (`03`+x, the point read) with the reference's `02`+x beside it labeled the reference's defect, never parity; the references by file and line.
2. `docs/lanes/375-filings/QUEUE.md`: row 18, repository `bsv-blockchain/ts-stack`, the draft linked, the one-line ask; the queue's count where the file states it (seventeen becomes eighteen); the keeper's order stated as "eighteenth".
3. The gate, in the foreground: every relative link in the two files resolving; `cargo test --features "full,http" --test arch_ci_lines --test arch_secrets_scan_scope` (docs files are read by no other test: say so); `gitleaks git --redact --no-banner --exit-code 1 --log-opts="origin/beta..HEAD" .` from the repo root. One commit, no push.

Rules: never end your turn with a command running in the background; commit on the branch, never push; no test or probe on a default URL or port (a MetaNet Client listens on 3301, 3321 and 2121 on this machine; another session's process on 3390); do not read `~/bsv/bsv-low/` or `~/vault/`, and do not grep across `~/bsv/` as a whole (the references are read by their named paths); no filing on any tracker (the captain files); scratch copies under `$TMPDIR` with their own `CARGO_TARGET_DIR`, removed at the end; never `rustup default` or `rustup override` (use `cargo +1.99.0`).

## Report

The base sha and the tip; the draft's sections; the five cases named; the queue row; the gate; anything unverified; nothing else.
