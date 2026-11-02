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
| 1 | bsv-blockchain/go-sdk | [docs/lanes/375-filings/wire-originator.md](./wire-originator.md) | Prevent originator length wrapping and normalize wallet wire originators (filed as bsv-blockchain/go-sdk#399 on 2026-11-01 under the owner's name (cadence (b), the owner's word of 2026-10-31 16:2xZ through the keeper); answer pending) |
| 2 | bsv-blockchain/go-sdk | [docs/lanes/375-filings/wire-numeric-collection-bounds.md](./wire-numeric-collection-bounds.md) | Check wallet response widths and collection counts before reading or allocating (filed as bsv-blockchain/go-sdk#400 on 2026-11-01 under the owner's name (cadence (b), the owner's word of 2026-10-31 16:2xZ through the keeper); answer pending) |
| 3 | bsv-blockchain/ts-stack | [docs/lanes/375-filings/merkle-lone-leaf-offset.md](./merkle-lone-leaf-offset.md) | Reject a one-transaction Merkle proof with a nonzero leaf offset (filed as bsv-blockchain/ts-stack#1460 on 2026-10-31 under the owner's name (cadence (b), the owner's word of 16:2xZ through the keeper); answer pending) |
| 4 | bsv-blockchain/ts-stack | [docs/lanes/375-filings/beef-empty-transactions.md](./beef-empty-transactions.md) | Reject raw zero-input and zero-output transactions in BEEF structure validation (filed as bsv-blockchain/ts-stack#1461 on 2026-10-31 under the owner's name (cadence (b), the owner's word of 16:2xZ through the keeper); answer pending) |
| 5 | bsv-blockchain/go-sdk | [docs/lanes/375-filings/atomic-unrelated-data.md](./atomic-unrelated-data.md) | Enforce the subject dependency graph when validating parsed Atomic BEEF (filed as bsv-blockchain/go-sdk#396 on 2026-10-31 under the owner's name (cadence (b), the owner's word of 16:2xZ through the keeper); answer pending) |
| 6 | bsv-blockchain/go-sdk | [docs/lanes/375-filings/beef-duplicate-offsets-go-sdk.md](./beef-duplicate-offsets-go-sdk.md) | Reject contradictory repeated BUMP offsets (filed as bsv-blockchain/go-sdk#397 on 2026-10-31 under the owner's name (cadence (b), the owner's word of 16:2xZ through the keeper); answer pending) |
| 7 | bsv-blockchain/ts-stack | [docs/lanes/375-filings/beef-reserved-flags-ts-stack.md](./beef-reserved-flags-ts-stack.md) | Reject reserved BEEF discriminators (filed as bsv-blockchain/ts-stack#1462 on 2026-10-31 under the owner's name (cadence (b), the owner's word of 16:2xZ through the keeper); answer pending) |
| 8 | bsv-blockchain/go-sdk | [docs/lanes/375-filings/canonical-varint-reader.md](./canonical-varint-reader.md) | Provide a canonical CompactSize reader for protocol parsing (filed as bsv-blockchain/go-sdk#398 on 2026-10-31 under the owner's name (cadence (b), the owner's word of 16:2xZ through the keeper); answer pending) |
| 9 | bsv-blockchain/go-sdk | [docs/lanes/375-filings/certificate-bounds-der.md](./certificate-bounds-der.md) | Certificate wallet conversion rewrites valid high-S signature bytes (filed as bsv-blockchain/go-sdk#401 on 2026-11-02 under the owner's name (cadence (b), the keeper's detached script at 00:00Z from the draft as it stood on beta); answer pending) |
| 10 | bsv-blockchain/go-sdk | [docs/lanes/375-filings/certificate-response-preimage-go-sdk.md](./certificate-response-preimage-go-sdk.md) | Preserve certificate-response property order when signing and verifying (filed as bsv-blockchain/go-sdk#402 on 2026-11-02 under the owner's name (cadence (b), the keeper's detached script at 00:00Z from the draft as it stood on beta); answer pending) |
| 11 | bsv-blockchain/ts-stack | [docs/lanes/375-filings/certificate-outpoint-bound.md](./certificate-outpoint-bound.md) | Reject certificate outpoint indexes that the writer cannot serialize (filed as bsv-blockchain/ts-stack#1463 on 2026-11-01 under the owner's name (cadence (b), the owner's word of 2026-10-31 16:2xZ through the keeper); answer pending) |
| 12 | bsv-blockchain/ts-stack | [docs/lanes/375-filings/wire-input-index-width.md](./wire-input-index-width.md) | Bound internalizeAction outputIndex consistently with PositiveIntegerOrZero (filed as bsv-blockchain/ts-stack#1464 on 2026-11-01 under the owner's name (cadence (b), the owner's word of 2026-10-31 16:2xZ through the keeper); answer pending) |
| 13 | bsv-blockchain/ts-stack | [docs/lanes/375-filings/create-action-positive-script-length-ts-stack.md](./create-action-positive-script-length-ts-stack.md) | Refuse zero unlockingScriptLength as BRC-100 specifies (filed as bsv-blockchain/ts-stack#1466 on 2026-11-02 under the owner's name (cadence (b), the keeper's detached script at 00:00Z from the draft as it stood on beta); answer pending) |
| 14 | bsv-blockchain/go-sdk | [docs/lanes/375-filings/create-action-positive-script-length-go-sdk.md](./create-action-positive-script-length-go-sdk.md) | Validate positive createAction unlockingScriptLength |
| 15 | bsv-blockchain/go-sdk | [docs/lanes/375-filings/discovery-trust-range.md](./discovery-trust-range.md) | Validate discovery certificate trust on read and write |
| 16 | bsv-blockchain/go-sdk | [docs/lanes/375-filings/linkage-reason-and-result-validation.md](./linkage-reason-and-result-validation.md) | Use the linkage reason width and validate returned linkage context |
| 17 | bsv-blockchain/go-sdk | [docs/lanes/375-filings/http-json-result-validation.md](./http-json-result-validation.md) | Validate HTTP wallet results against their requests and BRC-100 shapes |
| 18 | bsv-blockchain/ts-stack | [docs/lanes/375-filings/public-key-unreduced-coordinate-serialization.md](./public-key-unreduced-coordinate-serialization.md) | Reduce or refuse an unreduced public key coordinate at parse, and serialize the point computed with rather than the coordinates given (filed as bsv-blockchain/ts-stack#1467 on 2026-11-02 under the owner's name (cadence (b), the keeper's detached script at 00:00Z from the draft as it stood on beta); answer pending) |
| 19 | bsv-blockchain/go-sdk | [docs/lanes/375-filings/decode-outpoints-count-bound-go-sdk.md](./decode-outpoints-count-bound-go-sdk.md) | Bound the outpoint count read off the wire by the body's remaining bytes before allocating |
| 20 | bsv-blockchain/go-sdk | [docs/lanes/375-filings/no-send-change-framing-go-sdk.md](./no-send-change-framing-go-sdk.md) | createAction's noSendChange is framed behind an extra byte length, so a Go wallet and a TypeScript client cannot read each other's list |
| 21 | bsv-blockchain/go-sdk | [docs/lanes/375-filings/send-with-results-marker-go-sdk.md](./send-with-results-marker-go-sdk.md) | createAction and signAction results: an absent sendWithResults panics on the wire's absent marker, and a nil one is written as a zero count instead of the marker |
| 22 | bsv-blockchain/go-sdk | [docs/lanes/375-filings/create-action-result-success-byte-go-sdk.md](./create-action-result-success-byte-go-sdk.md) | createAction's result carries an extra success byte inside the frame that the wire does not define, so a Go client refuses every TypeScript result that carries a txid and a TypeScript client misreads Go's |

The keeper's 2026-10-30 11:1xZ word inserts the certificate-response
preimage witness tenth, after the DER witness. The queue now has seventeen
entries; the new draft starts with `keeper's word first` and awaits its own
per-draft word, then the owner's cadence. The sixteen earlier FILE decisions
stand in their shifted positions. Nothing has been filed.

The keeper's word of 2026-10-31 06:1xZ, [on PR #538](https://github.com/Calhooon/bsv-rs/pull/538#issuecomment-6539950425),
adds an eighteenth draft, FILE, eighteenth in the keeper's order: the
reference's `Point.fromDER` keeps an unreduced coordinate and `encode`
writes it back, so `04`+x+(p+1) is written as `02`+x, the negation of the
point it computed with (the ask: reduce or refuse at parse, and serialize
the point computed with). The queue now has eighteen entries, pending the
owner's cadence word. Nothing has been filed.

The owner's word of 2026-10-31 16:2xZ, relayed by the keeper at 16:3xZ, is
cadence (b). The first six drafts (third to eighth in the keeper's order) were
filed under the owner's name on 2026-10-31 from the drafts as they stood on
beta, the internal provenance lines dropped and a census pointer added (and,
in go-sdk#397, the BRC-reading line's closing sentence addressed to the
keeper); each row above carries its number. The four of 2026-11-01 (rows 1,
2, 11 and 12: go-sdk#399, go-sdk#400, ts-stack#1463, ts-stack#1464) were filed
the same way, and ts-stack#1463 and #1464 also omit their drafts' line
"Existing related filing(s): go-sdk #387. Keep these numbers; confirm their
scope before opening a duplicate." The four of 2026-11-02 (rows 9, 10, 13 and
18: go-sdk#401, go-sdk#402, ts-stack#1466, ts-stack#1467) were filed at 00:00Z
by the keeper's detached script from the drafts as they stood on beta. Fourteen
of the twenty-two entries are filed; ts-stack's seven (rows 3, 4, 7, 11, 12, 13
and 18) are all filed. The remaining eight, all go-sdk (rows 14 to 17 and 19 to
22), are filed two a day in queue order, from the drafts as they stand on beta
on their day: rows 14 and 15 at 00:00Z on 2026-11-03, then rows 16 and 17, then
rows 19 to 22 in the order the keeper's words placed them (row 21 ahead of row
20). Rows 1 and 2 were neither deferred nor dropped: the owner's cadence put the six verifier rows first by consequence; rows 1 and 2 are the first go-sdk pair of 2026-11-01 and rows 11 and 12 ts-stack's (the certificate outpoint bound, the internalize output index width); then two a day per repository in queue order (the keeper, the rulings page's entry of 2026-10-31 17:1xZ).

The keeper's word of 2026-11-01 02:1xZ adds a nineteenth draft, FILE,
nineteenth in the keeper's order: go-sdk PR #392 (the fix of #387, merged
2026-10-30 as `9f4c4a658`) names `decodeOutpoints`' `make(..., 0, count)` from
an unbounded wire count as a hazard it leaves (census row 10). The queue now has
nineteen entries; the new draft is filed on its day of cadence (b), from the
draft as it stands on beta. Nothing new has been filed.

The keeper's word of 2026-11-01 03:1xZ (the rulings page) adds a twentieth
draft, FILE, twentieth in the keeper's order, against go-sdk: the #583 lane
found that go-sdk frames createAction's `noSendChange` (args and result) behind
an outer byte length that BRC-100 and the reference do not write, so a Go
wallet and a TypeScript client refuse each other's list. It is go-sdk's
divergence from the wire, not a stated row. The queue now has twenty entries;
the new draft is filed in the go-sdk pairs' turn of cadence (b), from the draft
as it stands on beta. Nothing new has been filed.

The keeper's word of 2026-11-01 04:1xZ (the rulings page) adds a twenty-first
draft, FILE, against go-sdk, filed ahead of row 20 in the go-sdk turn: go-sdk's
`readTxidSliceWithStatus` sizes the createAction and signAction results'
`sendWithResults` from the wire's absent marker (nine `ff`) and panics
(`makeslice: cap out of range`, `status.go:54`) on every reference result that
carries no `sendWithResults`, and its writer writes a nil list as `00` where the
marker is nine `ff` (one field, one issue). The queue now has twenty-one
entries; the new draft is filed in the go-sdk pairs' turn of cadence (b), ahead
of row 20, from the draft as it stands on beta. Nothing new has been filed.

The keeper's words of 2026-11-01 05:1xZ (the rulings page) add a
twenty-second draft, FILE, against go-sdk: go-sdk's `SerializeCreateActionResult`
writes a success byte of its own inside the result frame (`create_action_result.go:15-16`),
and `DeserializeCreateActionResult` expects it (`:58-61`). BRC-100 and the
reference do not write that byte, so go-sdk's own client refuses every reference
createAction result that carries a txid (`response indicates failure: 1`), and
the reference's client reads go-sdk's inner byte as the txid flag. One frame per issue, so a
maintainer's thread stays one fix. Its consequence is the same as row 20's, and
it is filed in the go-sdk turn beside row 20, from the draft as it stands on beta. The same words
ask row 20's evidence line to state its probe method (bytes handed straight
to go-sdk's serializer functions), and it now does. The queue now has
twenty-two entries. Nothing new has been filed.

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