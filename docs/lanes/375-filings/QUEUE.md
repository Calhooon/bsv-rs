# Filing queue for #375

The keeper files under the owner's name only on the owner's cadence word
(21.5 of the 2026-10-30 brief). Nothing in this queue is authorization to file.
After filing, put the filed number on bsv-rs#375 and in the row's verdict clause.
The review briefs under `docs/lanes/` are not filings.

The keeper read the seventeen keeper-first drafts at `859116f1` and gave
[the per-draft word](https://github.com/Calhooon/bsv-rs/issues/375#issuecomment-6517160425) at 07:14Z on 2026-10-30.
The sixteen approved drafts are FILE in that relative order of consequence, pending the owner's
cadence word; the keeper recommends a few a day per repository, with later
threads following answers to the earlier ones.

| Order | Repository | Draft path | Title |
|---|---|---|---|
| 1 | bsv-blockchain/go-sdk | [docs/lanes/375-filings/wire-originator.md](./wire-originator.md) | Prevent originator length wrapping and normalize wallet wire originators |
| 2 | bsv-blockchain/go-sdk | [docs/lanes/375-filings/wire-numeric-collection-bounds.md](./wire-numeric-collection-bounds.md) | Check wallet response widths and collection counts before reading or allocating |
| 3 | bsv-blockchain/ts-stack | [docs/lanes/375-filings/merkle-lone-leaf-offset.md](./merkle-lone-leaf-offset.md) | Reject a one-transaction Merkle proof with a nonzero leaf offset |
| 4 | bsv-blockchain/ts-stack | [docs/lanes/375-filings/beef-empty-transactions.md](./beef-empty-transactions.md) | Reject raw zero-input and zero-output transactions in BEEF structure validation |
| 5 | bsv-blockchain/go-sdk | [docs/lanes/375-filings/atomic-unrelated-data.md](./atomic-unrelated-data.md) | Enforce the subject dependency graph when validating parsed Atomic BEEF |
| 6 | bsv-blockchain/go-sdk | [docs/lanes/375-filings/beef-duplicate-offsets-go-sdk.md](./beef-duplicate-offsets-go-sdk.md) | Reject contradictory repeated BUMP offsets |
| 7 | bsv-blockchain/ts-stack | [docs/lanes/375-filings/beef-reserved-flags-ts-stack.md](./beef-reserved-flags-ts-stack.md) | Reject reserved BEEF discriminators |
| 8 | bsv-blockchain/go-sdk | [docs/lanes/375-filings/canonical-varint-reader.md](./canonical-varint-reader.md) | Provide a canonical CompactSize reader for protocol parsing |
| 9 | bsv-blockchain/go-sdk | [docs/lanes/375-filings/certificate-bounds-der.md](./certificate-bounds-der.md) | Certificate wallet conversion rewrites valid high-S signature bytes |
| 10 | bsv-blockchain/go-sdk | [docs/lanes/375-filings/certificate-response-preimage-go-sdk.md](./certificate-response-preimage-go-sdk.md) | Preserve certificate-response property order when signing and verifying |
| 11 | bsv-blockchain/ts-stack | [docs/lanes/375-filings/certificate-outpoint-bound.md](./certificate-outpoint-bound.md) | Reject certificate outpoint indexes that the writer cannot serialize |
| 12 | bsv-blockchain/ts-stack | [docs/lanes/375-filings/wire-input-index-width.md](./wire-input-index-width.md) | Bound internalizeAction outputIndex consistently with PositiveIntegerOrZero |
| 13 | bsv-blockchain/ts-stack | [docs/lanes/375-filings/create-action-positive-script-length-ts-stack.md](./create-action-positive-script-length-ts-stack.md) | Refuse zero unlockingScriptLength as BRC-100 specifies |
| 14 | bsv-blockchain/go-sdk | [docs/lanes/375-filings/create-action-positive-script-length-go-sdk.md](./create-action-positive-script-length-go-sdk.md) | Validate positive createAction unlockingScriptLength |
| 15 | bsv-blockchain/go-sdk | [docs/lanes/375-filings/discovery-trust-range.md](./discovery-trust-range.md) | Validate discovery certificate trust on read and write |
| 16 | bsv-blockchain/go-sdk | [docs/lanes/375-filings/linkage-reason-and-result-validation.md](./linkage-reason-and-result-validation.md) | Use the linkage reason width and validate returned linkage context |
| 17 | bsv-blockchain/go-sdk | [docs/lanes/375-filings/http-json-result-validation.md](./http-json-result-validation.md) | Validate HTTP wallet results against their requests and BRC-100 shapes |

The keeper's 2026-10-30 11:1xZ word inserts the certificate-response
preimage witness tenth, after the DER witness. The queue now has seventeen
entries; the new draft starts with `keeper's word first` and awaits its own
per-draft word, then the owner's cadence. The sixteen earlier FILE decisions
stand in their shifted positions. Nothing has been filed.

## HOLD

- bsv-blockchain/go-sdk — [hmac-minimal-key](./hmac-minimal-key.md),
  “Use the amended BRC-56 minimal-length ECDH X coordinate for HMAC”. The
  keeper's reason: go-sdk PR #389 was described as in flight, the maintainers'
  own, so a new filing would duplicate it; reviews 2 and 3 also read this as
  outside the charter. The row now points to that PR instead of ts-stack #1369.
  [PR #389](https://github.com/bsv-blockchain/go-sdk/pull/389), “fix(wallet): key HMAC with minimal-length X coordinate
  per BRC-56”, is by **deggen (@sirdeggen)**. GitHub reports **MERGED** at
  2026-10-28 20:39:45Z when checked for this record, in conflict with the
  keeper's “in flight” wording. The merge is after the `2ca481c` pin (v1.7.2)
  and in no release through v1.7.3, so go-sdk diverges at the pin and in its
  releases and conforms on `master`. The keeper's word of 08:1xZ: the hold holds, a filing would ask go-sdk for
  what its master already carries; the row reads fixed on master at `a8159c77`
  after the pin, in no release through v1.7.3, re-read at the monthly recon and
  closed when a release names it; no duplicate is filed.

- bsv-blockchain/go-sdk — [wire-request-frame-cap-go-sdk](./wire-request-frame-cap-go-sdk.md),
  “Bound a complete wallet wire request before transmitting it”. The keeper's word of 08:1xZ: HOLD as a stated row, on the line drawn
  for the certificate byte bounds (a frame cap is the reference's own resource safeguard
  and not a BRC number, Go's choice to make); the row names the difference; this crate's
  processor cap (#505) runs as hardening.

## AMEND (the keeper's 08:1xZ word: FILE, ninth)

- bsv-blockchain/go-sdk — [certificate-bounds-der](./certificate-bounds-der.md),
  “Certificate wallet conversion rewrites valid high-S signature bytes” (the draft as rewritten to its one claim by the DER witness, PR #506 at `8e57ee46`: go-sdk's certificate adapter rewrites a valid high-S signature to low S where the reference and this crate preserve the bytes; the byte bounds a stated row, ours). The
  keeper's reason: byte bounds on the field, frame and keyring entry are the
  reference's safeguards, not BRC numbers, and stay a stated row. File DER
  preservation alone once a round-trip witness shows Go re-serializing the
  certificate's signature bytes (BER parsing and high-S normalization at
  `primitives/ec/signature.go:77-102,297-299`). The sibling
  `fix-375-der-witness` lane owns the draft rewrite, row 60 and its census;
  this queue records the word without changing that work.

  The keeper's word of 08:1xZ on the witness (PR #506): FILE, ninth in the queue, after
  canonical-varint-reader and before the BRC-100 widths; a signed certificate whose bytes
  change through an adapter is a defect a user meets when a certificate crosses SDKs.