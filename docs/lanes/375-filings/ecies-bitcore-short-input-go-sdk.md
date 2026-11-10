keeper's word first

# BitcoreDecrypt slices its input without a length check and panics on an envelope shorter than 65 bytes

Repository: bsv-blockchain/go-sdk

Prepared for filing by Calhooon (owner). Draft only; no issue was created. Census pointer: bsv-rs#375; bsv-rs CLAUDE.md's divergence row "ECIES byte bounds (#333)" ("Go's `ElectrumDecrypt` has no upper bound ..., nor do its Bitcore reader or writers"; "Theirs: go-sdk, filing pending"). The row's upper bounds are the reference's own safeguards and are held as a stated row by the keeper's 2026-10-30 08:1xZ line (a resource cap is Go's choice); this draft asks only the short input, which crashes. The batch-1 draft `ecies-byte-bounds.md` named it in a sentence. Drafted by the filings-older-1110 lane on 2026-11-10.

A go-sdk service that decrypts a Bitcore ECIES message it received (a message-box payload, a peer's attachment) panics with `slice bounds out of range` when the message is shorter than 65 bytes: `BitcoreDecrypt` takes `encryptedMessage[:33]` and then `encryptedMessage[33 : len-32]` with no length check. Unrecovered, the panic stops the process on one malformed message.

```go
func BitcoreDecrypt(encryptedMessage []byte, toPrivatKey *ec.PrivateKey) ([]byte, error) {
	fromPublicKey, err := ec.ParsePubKey(encryptedMessage[:33])
	...
	cipherText := encryptedMessage[33 : len(encryptedMessage)-32]
	mac := encryptedMessage[len(encryptedMessage)-32:]
```

A slice past the length panics (`[:33]` on fewer than 33 bytes); between 33 and 64 bytes the key may parse and `[33 : len-32]` has its low bound above its high bound, which panics too. `ElectrumDecrypt` checks a 52-byte minimum before it slices (`ecies.go:106-108`). The reference refuses an envelope under `33 + 16 + 16 + 32` bytes, and one out of 16-byte framing, before any work (`ECIES.ts:700-711`).

Steps to reproduce (go-sdk read from the code at 2ca481c, not run): `ecies.BitcoreDecrypt([]byte{0x02}, key)` panics at `[:33]`; 33 bytes of a valid compressed key followed by 10 bytes panics at `[33:11]`.

Expected: an error for an input shorter than the smallest envelope (the reference's minimum, or at least 33 + 32), never a panic.

Actual: a panic.

bsv-rs refuses a short or unframed Bitcore envelope with an error before reading it.

Witness:

- [tests/compat_ecies_short_envelope_463.rs](https://github.com/Calhooon/bsv-rs/blob/beta/tests/compat_ecies_short_envelope_463.rs) (`a_bitcore_envelope_one_byte_under_the_reference_minimum_uses_bounded_words`, `a_bitcore_envelope_at_the_reference_minimum_reaches_the_mac`)
- `test_bitcore_too_short` in [src/compat/ecies.rs](https://github.com/Calhooon/bsv-rs/blob/beta/src/compat/ecies.rs) (50 bytes refused with an error)

Pinned reference reading:

- [go-sdk@2ca481c59 compat/ecies/ecies.go:191-208](https://github.com/bsv-blockchain/go-sdk/blob/2ca481c5931b987a0c8f48bb341c70b7477b6b07/compat/ecies/ecies.go#L191-L208) (`BitcoreDecrypt`) and [:105-108](https://github.com/bsv-blockchain/go-sdk/blob/2ca481c5931b987a0c8f48bb341c70b7477b6b07/compat/ecies/ecies.go#L105-L108) (`ElectrumDecrypt`'s minimum, for contrast)

Sibling reading: [ts-stack@edf6e03da packages/sdk/src/compat/ECIES.ts:700-711](https://github.com/bsv-blockchain/ts-stack/blob/edf6e03dad39bd7bc4fc6e73e64de3a2b6f805c9/packages/sdk/src/compat/ECIES.ts#L700-L711) (the minimum and the framing check).

Existing related filing(s): none found (`--search "BitcoreDecrypt"`, `"ECIES Bitcore"`, 2026-11-10).

Requested maintainer action: check the length (and the 16-byte framing) at the top of `BitcoreDecrypt` and return an error, as `ElectrumDecrypt` and the reference do.

Evidence status: go-sdk source-read at 2ca481c, not run; a slice outside its bounds panics by the Go specification. This draft contains no private-key literal.
