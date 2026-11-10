keeper's word first

# ElectrumDecrypt decides whether an envelope embeds the sender's key by its length alone, so a no-key envelope of 32 plaintext bytes or more, and every uncompressed-key envelope, fails to open

Repository: bsv-blockchain/go-sdk

Prepared for filing by Calhooon (owner). Draft only; no issue was created. Census pointer: bsv-rs#375; bsv-rs CLAUDE.md's divergence row "An Electrum ECIES envelope's embedded key is found by the reference's rule" (#109; "go-sdk@2ca481c keeps the length rule ... so it refuses a no-key envelope of a plaintext of 32 bytes or more and an uncompressed key"; "Theirs: go-sdk, filing pending"). Supersedes the short batch-1 draft `electrum-envelope-key-detection.md`. Drafted by the filings-older-1110 lane on 2026-11-10.

A go-sdk user decrypting an Electrum (BIE1) message written without the sender's key (`ElectrumEncrypt` with `noKey`, or the TypeScript `electrumEncrypt(..., true)`) fails as soon as the plaintext is 32 bytes or longer: with the sender's key given, go-sdk skips 33 bytes it takes to be a key because the envelope is longer than 69 bytes, and decrypts the wrong slice. An envelope embedding an uncompressed (65-byte) key fails on both branches.

```go
if fromPublicKey != nil {
	...
	if len(encryptedData) > 69 { // 4 (magic) + 33 (pubkey) + 32 (mac)
		cipherText = encryptedData[37 : len(encryptedData)-32]
	} else {
		cipherText = encryptedData[4 : len(encryptedData)-32]
	}
} else {
	ephemeralPublicKey, err := ec.ParsePubKey(encryptedData[4:37])
```

The reference decides from the byte after the magic and the framing of what is left (`02`/`03` with `(available - 33) % 16 == 0`, `04` with `(available - 65) % 16 == 0`), refuses a no-key envelope without a sender (`Sender public key is required`), refuses an embedded key beside another expected sender (`Embedded sender public key does not match the expected sender`), and refuses a ciphertext out of 16-byte framing before the MAC (`ECIES.ts:607-647`). go-sdk also never compares an embedded key with the sender it was given.

Steps to reproduce (the reference's envelopes and verdicts recorded under Node 22.18.0 for the fixed keys of the linked vector; go-sdk read from the code at 2ca481c, not run):

1. Case `plaintext-32-the-issue-input`, `no_key`: the 84-byte envelope `4249453179e688321c12cc244d25883302882ee340c125d5196019c5abe717ca704e7a05b8b1da0ba39e03d3b7281fc954748b97e340067ddc4f6ce04def54d32500b820cd721b4b3f211966db5b426112b69486` opens with the sender's key to `afaf209f…bdcfc2` in the reference. go-sdk takes `encryptedData[37:52]`, a 15-byte slice, and fails.
2. Refusal case `uncompressed-key-with-the-sender` (`4249453104…`, a 65-byte key): the reference opens it to the same plaintext; go-sdk strips 33 bytes and fails, and without a sender `ParsePubKey` of a 33-byte `04…` slice fails.

Expected: the reference's rule (the prefix and the 16-byte framing decide; an embedded key compared with an expected sender; a no-key envelope needs the sender).

Actual: the length rule.

bsv-rs follows the reference's rule and opens the reference's envelopes, and the reference opens this crate's (#109).

Witness:

- [tests/compat_ecies_envelope_109.rs](https://github.com/Calhooon/bsv-rs/blob/beta/tests/compat_ecies_envelope_109.rs) (`a_no_key_envelope_of_any_length_opens_with_its_sender`, `the_references_refusals_and_the_uncompressed_key_read_here_as_there`, `an_embedded_key_beside_another_expected_sender_is_refused`)
- [tests/vectors/compat_ecies_envelope_109.json](https://github.com/Calhooon/bsv-rs/blob/beta/tests/vectors/compat_ecies_envelope_109.json) (11 plaintext lengths with and without a key, 10 refusals; recorded from the reference)

Pinned reference reading:

- [go-sdk@2ca481c59 compat/ecies/ecies.go:105-135](https://github.com/bsv-blockchain/go-sdk/blob/2ca481c5931b987a0c8f48bb341c70b7477b6b07/compat/ecies/ecies.go#L105-L135)

Sibling reading: [ts-stack@edf6e03da packages/sdk/src/compat/ECIES.ts:600-653](https://github.com/bsv-blockchain/ts-stack/blob/edf6e03dad39bd7bc4fc6e73e64de3a2b6f805c9/packages/sdk/src/compat/ECIES.ts#L600-L653).

Existing related filing(s): none found (`--search "ElectrumDecrypt"`, `"ECIES Bitcore"`, 2026-11-10). The ecies-bitcore-short-input draft (this lane's, unfiled) is the Bitcore reader's slicing, another function.

Requested maintainer action: decide the embedded key from its prefix and the remaining framing as the reference does, compare an embedded key with an expected sender, and require a sender for a no-key envelope.

Evidence status: the reference's envelopes and verdicts are the recorded vector (Node 22.18.0); go-sdk source-read at 2ca481c, not run. This draft contains no private-key literal (the vector's keys are fixed byte patterns, named, not written).
