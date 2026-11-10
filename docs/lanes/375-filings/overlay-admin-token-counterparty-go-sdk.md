keeper's word first

# OverlayAdminToken.Lock signs and locks a SHIP or SLAP advertisement for counterparty self, so the TypeScript validator refuses every go-sdk advertisement

Repository: bsv-blockchain/go-sdk

Prepared for filing by Calhooon (owner). Draft only; no issue was created. Census pointer: bsv-rs#375; bsv-rs CLAUDE.md's divergence row "Go signs overlay admin tokens with `counterparty = Self`" (census row 26; "Theirs: go-sdk, filing pending"). Supersedes the short batch-1 draft `overlay-admin-derivation.md`. Drafted by the filings-older-1110 lane on 2026-11-10.

A go-sdk host that advertises itself with `OverlayAdminToken.Lock` publishes a SHIP or SLAP token whose locking key and field signature are derived for counterparty self, where the reference derives both for counterparty anyone with `forSelf`. A TypeScript lookup resolver or topic broadcaster authenticates an advertisement against the anyone derivation of its identity key, so it skips the go-sdk host and never asks it.

```go
return o.PushDrop.Lock(
	ctx,
	[][]byte{ []byte(protocol), pub.PublicKey.Compressed(), []byte(domain), []byte(topicOrService) },
	protocolID,
	"1",
	wallet.Counterparty{ Type: wallet.CounterpartyTypeSelf },
	false,               // forSelf
	true,                // includeSignature
	pushdrop.LockBefore, // lockPosition
)
```

The reference locks with `'anyone', true` (`OverlayAdminTokenTemplate.ts:290-300`) and verifies an advertisement against `PublicKey.fromString(identityKey).deriveChild(new PrivateKey(1), invoice)` (`:210-219`), the anyone derivation, refusing `Signature is not valid` or `Discovery advertisement locking key is not linked to its identity`. The self derivation gives another child key, so both checks fail on a go-sdk token. The `Unlock` at `admin-token.go:117-133` uses the same self counterparty, so a token locked the reference's way is not spendable through go-sdk's unlocker either.

Steps to reproduce (the reference's bytes from the linked vector, recorded against `@bsv/sdk` 1.10.1 and the validator at edf6e03 read; go-sdk read from the code at 2ca481c, not run):

1. Admin key the scalar 1, protocol SHIP, domain `https://overlay.example.com`, topic `tm_uhrp`.
2. The reference's locking script begins `2102d7245996c0abb8323c4780f4e7c5f7938e5498e35daa5325641df6fa5129f86bac` (the anyone-derived key; case 0 of the vector).
3. go-sdk locks with the self-derived key, so its script differs at that push, and `decodeAndVerifyOverlayAdvertisement` refuses it.

Expected: the advertisement locked and signed for counterparty anyone with `forSelf` true, and unlocked the same way, so any SDK's validator authenticates it from the identity key alone.

Actual: locked, signed and unlocked for counterparty self.

bsv-rs writes the reference's bytes (`create_signed_overlay_admin_token`).

Witness:

- [tests/overlay_admin_token_ts_parity_tests.rs](https://github.com/Calhooon/bsv-rs/blob/beta/tests/overlay_admin_token_ts_parity_tests.rs) (`create_signed_overlay_admin_token_matches_at_bsv_sdk_1_10_1`)
- [tests/vectors/overlay_admin_token_ts_parity.json](https://github.com/Calhooon/bsv-rs/blob/beta/tests/vectors/overlay_admin_token_ts_parity.json) (five cases, SHIP and SLAP, byte-exact against `@bsv/sdk` 1.10.1)

Pinned reference reading:

- [go-sdk@2ca481c59 overlay/admin-token/admin-token.go:97-113](https://github.com/bsv-blockchain/go-sdk/blob/2ca481c5931b987a0c8f48bb341c70b7477b6b07/overlay/admin-token/admin-token.go#L97-L113) (the lock) and [:117-133](https://github.com/bsv-blockchain/go-sdk/blob/2ca481c5931b987a0c8f48bb341c70b7477b6b07/overlay/admin-token/admin-token.go#L117-L133) (the unlock)

Sibling reading: [ts-stack@edf6e03da packages/sdk/src/overlay-tools/OverlayAdminTokenTemplate.ts:199-222](https://github.com/bsv-blockchain/ts-stack/blob/edf6e03dad39bd7bc4fc6e73e64de3a2b6f805c9/packages/sdk/src/overlay-tools/OverlayAdminTokenTemplate.ts#L199-L222) (the validator) and [:286-302](https://github.com/bsv-blockchain/ts-stack/blob/edf6e03dad39bd7bc4fc6e73e64de3a2b6f805c9/packages/sdk/src/overlay-tools/OverlayAdminTokenTemplate.ts#L286-L302) (the lock).

Existing related filing(s): queue row 35's draft (`overlay-discovery-advertisement-admission-go-sdk.md`, unfiled) asks go-sdk's resolver and broadcaster to authenticate advertisements; this one asks its writer to produce advertisements that authenticate. They are separate fixes. No upstream issue found (`--search "admin token counterparty"` and `"overlay advertisement signature"`, 2026-11-10).

Requested maintainer action: lock, sign and unlock overlay advertisements with counterparty anyone and `forSelf` true, as the reference's template does.

Evidence status: the reference's bytes are the recorded vector; the TypeScript validator and go-sdk source-read at the pins, neither run here. This draft contains no private-key literal (the admin key is the scalar 1, named).
