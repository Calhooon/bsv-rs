FILE — eighteenth in [the keeper's order](https://github.com/Calhooon/bsv-rs/pull/538#issuecomment-6539950425); pending the owner's cadence word.

# Reduce or refuse an unreduced public key coordinate at parse, and serialize the point computed with

Repository: bsv-blockchain/ts-stack

Prepared for filing by Calhooon (owner). Draft only; no issue was created.
Eighteenth in the queue, on the keeper's word of 2026-10-31 06:1xZ
(recorded on bsv-rs PR #538); pending the owner's cadence word.

`PublicKey.fromString` accepts an uncompressed or hybrid key whose x or y
is at or above the field prime p, computes with the coordinate reduced in
the field, and writes it back unreduced. Where y is p + 1 the point it
computes with has y = 1 (odd), but `toString` writes `02`+x: the negation
of that point. Where x is p + 1 it writes the 32 bytes of p + 1 back where
the point it computes with has x = 1.

## The finding, in the reference's terms (ts-stack@edf6e03)

- [Point.ts:303-321](https://github.com/bsv-blockchain/ts-stack/blob/edf6e03dad39bd7bc4fc6e73e64de3a2b6f805c9/packages/sdk/src/primitives/Point.ts#L303):
  `fromDER` builds a `04`, `06` or `07` key as `new Point(x, y)` from the
  bytes as given (`:319`), with no bound against p. The hybrid parity check
  (`:309-317`) reads the last byte of the unreduced y, so `06`+x+(p+1)
  passes as even while the point's y = 1 is odd. The compressed path
  reduces x first (`fromX`, `:365-367`), so `02`/`03` keys are not affected.
- [Point.ts:453,470-479](https://github.com/bsv-blockchain/ts-stack/blob/edf6e03dad39bd7bc4fc6e73e64de3a2b6f805c9/packages/sdk/src/primitives/Point.ts#L470):
  the constructor's default `isRed = true` marks both coordinates red with
  `forceRed` (`BigNumber.ts:1346-1349`: the context is set, the value kept);
  the reducing `toRed` path (`:474-479`, `ReductionContext.ts:500-504`'s
  `umod`) is skipped. Field arithmetic then computes with the reduced value,
  and `validate` (`:495-510`) reduces before it checks the curve equation,
  so `_assertOnCurve` (`:321`) accepts the key.
- [Point.ts:527-536](https://github.com/bsv-blockchain/ts-stack/blob/edf6e03dad39bd7bc4fc6e73e64de3a2b6f805c9/packages/sdk/src/primitives/Point.ts#L527):
  `encode` writes `getX()` and `getY()` (`fromRed`, which clears the
  context without reducing, `:735-748`, `ReductionContext.ts:520-524`) and
  takes the compact prefix from `getY().isEven()` on the unreduced value.
  For y = p + 1 that is even, so the prefix is `02`; the point computed with
  has y = 1 and is `03`+x. `toString` (`:558-560`) and `PublicKey.toDER`
  ([PublicKey.ts:149-151](https://github.com/bsv-blockchain/ts-stack/blob/edf6e03dad39bd7bc4fc6e73e64de3a2b6f805c9/packages/sdk/src/primitives/PublicKey.ts#L149))
  both reach `encode(true)`; the entry point is
  [PublicKey.ts:49-51](https://github.com/bsv-blockchain/ts-stack/blob/edf6e03dad39bd7bc4fc6e73e64de3a2b6f805c9/packages/sdk/src/primitives/PublicKey.ts#L49).

A key that passes through `fromString` and `toString` therefore names
another public key (the negation) or is not a SEC 1 encoding at all (the
x = p + 1 cases), and an address, a hash160 or a signed text built from
the written form does not match the key verified with.

## The witness

Five recorded cases of bsv-rs's
[`tests/vectors/public_key_forms_498.json`](https://github.com/Calhooon/bsv-rs/blob/22ad442e3e3158456a392114dbd08bfd2cc52f23/tests/vectors/public_key_forms_498.json)
(39 cases, recorded by
[`tests/support/public_key_forms_498.mjs`](https://github.com/Calhooon/bsv-rs/blob/22ad442e3e3158456a392114dbd08bfd2cc52f23/tests/support/public_key_forms_498.mjs)
against the bun bundle of ts-stack@edf6e03 under Node v22.18.0, a second
run byte-identical; SHA-256 `eb8b1d5c35ad572557ff097c318534944fc3db8971a3e4bf77dae0f52eeb5cde`,
reproduced by the cold review) are accepted by the reference and written
back other than the point it read. `G'` below is the point with x = 1
(y even `4218f2…a7ee`, y odd `bde70d…5441`); `X` is
`1fe1e5ef3fceb5c135ab7741333ce5a6e80d68167653f6b2b24bcbcfaaaff507`, whose
square root of x³ + 7 is 1; `p+1` is
`fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc30`.

| Case (input) | The point read (x, y reduced) | Reference `toString()` | Reference `encode(false)` |
|---|---|---|---|
| `x_above_p_uncompressed` (`04`+(p+1)+y even) | `02`+`00…01` | `02`+(p+1) | `04`+(p+1)+y |
| `x_above_p_hybrid_even` (`06`+(p+1)+y even) | `02`+`00…01` | `02`+(p+1) | `04`+(p+1)+y |
| `x_above_p_hybrid_odd` (`07`+(p+1)+y odd) | `03`+`00…01` | `03`+(p+1) | `04`+(p+1)+y |
| `y_above_p_uncompressed` (`04`+X+(p+1)) | `03`+X | `02`+X, the negation | `04`+X+(p+1) |
| `y_above_p_hybrid_even` (`06`+X+(p+1)) | `03`+X | `02`+X, the negation | `04`+X+(p+1) |

The other 34 cases (14 accepted, 20 refused) write back the point read.

The ecosystem is split on these forms (PR #538's body and its cold review;
go-sdk run at the pin, py-sdk read from source in the review):

| SDK | Coordinate at or above p | Written back |
|---|---|---|
| TypeScript, ts-stack@edf6e03 | accepted in all forms (compressed x reduced at `fromX`; uncompressed/hybrid unreduced) | the five cases above: unreduced, or the negation |
| go-sdk@`2ca481c` | compressed x accepted, kept unreduced; uncompressed coordinate refused | `02`+(p+1) for the compressed form |
| py-sdk@`4c30e2e` (coincurve 20.0.0, no pin recorded) | refused (hybrid keys alone accepted of the lenient forms) | — |
| bsv-rs (PR #538 at `22ad442e`, not yet landed) | accepted as the reference accepts, reduced mod p at parse | the point read: `03`+X for the y = p + 1 cases |

The four SDKs agree only on hybrid keys of the right parity.

## The standard's reading

SEC 1 v2.0 §2.3.4 (Octet-String-to-Elliptic-Curve-Point) converts each
coordinate with §2.3.6 (Octet-String-to-Field-Element), which fails unless
the integer is in [0, p − 1]. A coordinate at or above p is therefore not a
SEC 1 encoding: neither the input nor the reference's written form is in
the standard, and only the reduced coordinates (`03`+X or `04`+X+`00…01`
for the y = p + 1 cases) are SEC 1 encodings of the point the reference
computes with. No BRC defines another
key encoding (BRC-100 `wallet/0100.md` at `5119a9b` names `PubKeyHex` as
compressed).

## Requested maintainer action

Reduce or refuse at parse: in `Point.fromDER`, either refuse an x or y at
or above p (SEC 1 §2.3.6), or reduce both coordinates mod p before the
hybrid parity check and the constructor; and serialize the point computed
with, so `encode` and `toString` never write a prefix or coordinate other
than the reduced point's. Add the five cases above as regressions. The
compressed path's reduction at `fromX` (`:365-367`) already reads as the
second option.

## This crate's row

bsv-rs (from PR #538, issue #498) accepts the reference's lenient forms and
reduces at parse, so it writes the point it read: `03`+X for
`04`+X+(p+1), where the reference writes `02`+X. That `02`+X is recorded
beside our row as **the reference's defect**, not as parity: this crate
does not reproduce the negation and does not write an unreduced coordinate.
Until the upstream answers, bsv-rs's serialization and the reference's
differ on exactly these five recorded inputs.
