FILE — nineteenth in the keeper's order, on the keeper's word of 2026-11-01 02:1xZ; pending its day of the owner's cadence (b).

# Bound the outpoint count read off the wire by the body's remaining bytes before allocating

Repository: bsv-blockchain/go-sdk

Prepared for filing by Calhooon (owner). Draft only; no issue was created. Census row 10: The wallet wire's client-side bounds (#473) are the reference's (WalletWireTransceiver.ts…

PR #392 (the fix of #387) notes that a separate hazard remains: `decodeOutpoints` calls `make([]transaction.Outpoint, 0, count)` with the count read off the wire and no bound. It is reached on both sides of createAction's `noSendChange`: a wallet's processor reading a client's arguments and a client reading the wallet's result. A count that the bytes after it cannot hold panics before the first outpoint is read.

Steps to reproduce (go-sdk at 9f4c4a658, and identically at 2ca481c):

1. `DeserializeCreateActionResult` on `000000` `09` `fffeffffffffffffff`: the success byte, absent txid and tx, then go-sdk's own `noSendChange` framing (`WriteOptionalBytes(encodeOutpoints(...))`: a 9-byte body) whose count is 2^64-2, not the absent sentinel 2^64-1, with no outpoint after it.
2. Or `decodeOutpoints` directly on `fffeffffffffffffff`.

Expected: the count is refused before allocating, because it exceeds what the remaining bytes can hold at 33 bytes per outpoint (32-byte txid, at least one index byte), as the reference refuses it. bsv-rs refuses the reference's recorded bytes the same way: `create_no_send_change_at` in the linked vector (`000000fea0860100`, a count of 100000 with no entries, recorded from the unmodified reference) gives `Wallet Wire createAction noSendChange count exceeds the remaining response data`, and `create_no_send_change_short` (`00000001`) the same; pinned by `create_no_send_change_size_473` and `create_no_send_change_remaining_473`.

Actual: both inputs panic with `runtime error: makeslice: cap out of range` at `serializer.go:59`, which no caller recovers. A smaller impossible count allocates its capacity first (a 5-byte body claiming 100000 outpoints reserves about 3.6 MB before `read past end of data`). go-sdk wraps the list in a byte length that the reference does not write, so the reference's recorded bytes stop at that outer length in go-sdk and never reach this count; the steps above use go-sdk's own framing.

Witness:

- [tests/wallet_wire_bounds_473.rs](https://github.com/Calhooon/bsv-rs/blob/49789b2712d2c4eeb3e4d2776a047dc27c9314fe/tests/wallet_wire_bounds_473.rs#L133) (`create_no_send_change_size_473`, `create_no_send_change_remaining_473`)
- [tests/vectors/wallet_wire/bounds_473.json](https://github.com/Calhooon/bsv-rs/blob/49789b2712d2c4eeb3e4d2776a047dc27c9314fe/tests/vectors/wallet_wire/bounds_473.json#L7) (`create_no_send_change_at`, `_past`, `_short`)

Pinned reference reading:

- [ts-stack@edf6e03da packages/sdk/src/wallet/substrates/WalletWireTransceiver.ts:246-257,1955-1969](https://github.com/bsv-blockchain/ts-stack/blob/edf6e03dad39bd7bc4fc6e73e64de3a2b6f805c9/packages/sdk/src/wallet/substrates/WalletWireTransceiver.ts#L246): the result's count checked against 100000 and `remaining() / 33` before the list is built
- [ts-stack@edf6e03da packages/sdk/src/wallet/substrates/WalletWireProcessor.ts:109-125,524-539](https://github.com/bsv-blockchain/ts-stack/blob/edf6e03dad39bd7bc4fc6e73e64de3a2b6f805c9/packages/sdk/src/wallet/substrates/WalletWireProcessor.ts#L524): the request's count, the same two checks
- [go-sdk@9f4c4a658 wallet/serializer/serializer.go:45-79](https://github.com/bsv-blockchain/go-sdk/blob/9f4c4a6584ac9db7a64e1537cb4fe0d02546eec9/wallet/serializer/serializer.go#L45) (`make(..., 0, count)` at line 59; the same count read and `make` at [2ca481c59](https://github.com/bsv-blockchain/go-sdk/blob/2ca481c5931b987a0c8f48bb341c70b7477b6b07/wallet/serializer/serializer.go#L45))
- [go-sdk@9f4c4a658 wallet/serializer/create_action_args_deserialize.go:161-167](https://github.com/bsv-blockchain/go-sdk/blob/9f4c4a6584ac9db7a64e1537cb4fe0d02546eec9/wallet/serializer/create_action_args_deserialize.go#L161) and [create_action_result.go:70-76](https://github.com/bsv-blockchain/go-sdk/blob/9f4c4a6584ac9db7a64e1537cb4fe0d02546eec9/wallet/serializer/create_action_result.go#L70): the two callers

BRC reading: [BRCs@5119a9b51 wallet/0100.md:274-278](https://github.com/bsv-blockchain/BRCs/blob/5119a9b5148e9ec90eb4865b16f9f732a29703df/wallet/0100.md#L274). A wire count is a claim about the bytes that follow; it is not an allocation size.

Existing related filing(s): go-sdk #387 (fixed on master at 9f4c4a658, PR #392; this is the count PR #392 names and leaves). go-sdk #400 (row 2, filed 2026-11-01: the wallet response widths and collection counts). This is not a duplicate of #400: #400 names the response readers' wrong values and missing caps (getHeight, listActions, listOutputs, the string slices) and impossible counts against the remaining bytes in general words, but its pinned Go lines do not include `decodeOutpoints` and its witness bytes do not reach this count under go-sdk's outer length. This draft names one allocation that panics, on the request path that a wallet runs for a client as well as on the result path, at the site that PR #392 itself names. Keep these numbers; confirm their scope before opening a duplicate.

Evidence status: source-read at the pins in this lane; the linked Rust tests/recorded fixtures are the reproducible witness. go-sdk was also run once, in a scratch copy of 9f4c4a658 with 2ca481c's go.mod/go.sum (offline module cache) and in one of 2ca481c: both inputs above panic with `makeslice: cap out of range`. TypeScript was not rerun here. This draft contains no private-key literal.
