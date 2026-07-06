# Changelog

All notable changes to `bsv-rs` are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.3.14] — 2026-07-04

### Fixed

- **Panic / OOM-abort on adversarial length prefixes (bounded pre-allocation).**
  Every parser that pre-allocated a collection sized by an attacker-controlled
  count read from the input (`Vec::with_capacity(count)`,
  `HashMap::with_capacity(count)`, `vec![default; count]`) could be made to
  abort the process with a capacity-overflow / OOM panic *before a single
  element was read*. A ~20-byte crafted BEEF whose transaction input-count
  varint is `0xFE FF FF FF FF` (u32::MAX) makes `Transaction::from_beef` /
  `Transaction::from_binary` allocate billions of `TransactionInput`s and
  abort — a trivially cheap denial-of-service (and on `wasm32`, where the build
  is `panic = abort`, it is unrecoverable: `.ok()` cannot catch it).

  All such sites now bound the pre-allocation to what the remaining buffer could
  actually contain via the new `primitives::bounded_capacity(count, remaining,
  min_elem_bytes)` helper — `count.min(remaining / min_elem_bytes)`. The read
  loop already errors the instant the buffer is exhausted, so parse results are
  unchanged for both valid and malicious input; only the (now bounded) capacity
  hint changes. A bogus count now yields `Err`, never a panic.

  Hardened sites: `transaction::Transaction::{from_reader, from_ef}`
  (input/output counts, and the EF `source_output_index` placeholder-output
  fabrication, which is now rejected above a 16 MiB allocation budget — the
  placeholder length is computed in `u64` via `ef_source_placeholder_len` so the
  `+ 1` cannot overflow on 32-bit targets: on `wasm32` `source_output_index as
  usize + 1` wrapped `u32::MAX` to `0`, defeating the budget check and then
  index-OOB-panicking on a zero-length vec),
  `primitives::bsv::sighash::parse_transaction`, `overlay` binary lookup
  responses, `wallet::wire` (string arrays/maps, action/output/certificate
  arrays, keyrings), and `auth` certificate/header parsing. Purely defensive;
  no API change beyond the additive `bounded_capacity` export → patch bump.

## [0.3.11] — 2026-05-20

### Fixed

- **wasm32 `Peer::to_peer` / BRC-103 handshake hang.** The `wasm` feature now
  enables `futures-timer/wasm-bindgen`. The wasm `wait_with_timeout` helper
  (the `Peer` handshake timeout) races the handshake future against a
  `futures_timer::Delay`, but the `wasm` feature previously pulled
  `futures-timer` *without* its `wasm-bindgen` feature. On
  `wasm32-unknown-unknown` that selected `futures-timer`'s native timer-thread
  backend, so `Delay::new` panicked (`thread::spawn` is unsupported) on the
  first poll — hanging/aborting any `Peer::to_peer` call that initiates a
  handshake inside a Cloudflare Worker or browser `wasm-bindgen-futures`
  executor. Enabling `futures-timer/wasm-bindgen` flips it to the
  `gloo-timers`/`setTimeout` backend, which works in those environments.
  Pure additive feature wiring (no API change) → patch bump.

## [0.3.7] — 2026-04-21

### Added

- **`bsv_rs::overlay::create_signed_overlay_admin_token`** — produces
  TS-parity 5-field signed SHIP/SLAP advertisement tokens. Byte-exact
  match with `@bsv/sdk 1.10.1`'s
  `pushdrop.lock(fields, [2, protocol_name], '1', 'anyone', forSelf=true,
  includeSignature=true, lockPosition='before')` — the exact call
  `@bsv/overlay-discovery-services/src/WalletAdvertiser.ts` makes and
  what `nanostore.babbage.systems` / `overlay-us-1.bsvb.tech` validators
  admit under `tm_ship` / `tm_slap`.

  PushDrop layout:
  ```
  <locking_pubkey:33>  OP_CHECKSIG
  <"SHIP"|"SLAP">
  <identity_key:33>
  <domain>
  <topic_or_service>
  <signature_der>
  OP_2DROP OP_2DROP OP_DROP
  ```

  Locking pubkey + signing key are BRC-42 children of `root_key` for
  `protocolID = (SecurityLevel::Counterparty, "service host interconnect"
  | "service lookup availability")`, `keyID = "1"`, `counterparty =
  Anyone`, `forSelf = true`. Signature is ECDSA (RFC 6979 deterministic)
  over `sha256(concat(fields[0..4]))`.

  Takes `&PrivateKey` (not `&PublicKey`) because the function has to
  SIGN the advert.

- **`tests/vectors/overlay_admin_token_ts_parity.json`** — byte-exact
  parity vectors generated from `@bsv/sdk 1.10.1`. 5 cases covering SHIP
  (3 inputs, including long topic) + SLAP (2 inputs).

- **`tests/overlay_admin_token_ts_parity_tests.rs`** — blocking parity
  gate: loads the TS vectors and asserts
  `create_signed_overlay_admin_token(...)` reproduces them verbatim,
  plus a determinism guard for RFC-6979 signing.

### Deprecated

- **`bsv_rs::overlay::create_overlay_admin_token`** (soft deprecation,
  still compiles). It emits a 4-field unsigned PushDrop with the
  identity key as locking key — a shape `@bsv/overlay-discovery-services`
  requires but never admits, so any advert built with it is silently
  rejected by peer validators. See the `#[deprecated]` attribute for
  the migration pointer. The `decode_overlay_admin_token` reader still
  accepts both 4- and 5-field shapes for backward-compat.

### Notes — cross-SDK parity

- **Matches TS (`@bsv/sdk` 1.10.1)** byte-exact — the version deployed
  at `nanostore.babbage.systems` and `overlay-us-1.bsvb.tech`. Locking
  key + signing key both use `counterparty=Anyone, forSelf=true`, which
  is what `pushdrop.lock(...)` emits when `WalletAdvertiser.ts` calls
  it.

- **Diverges from Go SDK** (`github.com/bsv-blockchain/go-sdk/overlay/admin-token`).
  Go uses `counterparty=Self, forSelf=false`. By BRC-42 symmetry that
  yields the same locking pubkey, but `createSignature` with
  `counterparty=Self` derives a different signing key, so signatures
  differ and Go-produced tokens fail TS validators too. The Go SDK
  needs its own fix; `bsv-rs` matches the deployed reality.

## [0.3.6] — 2025-12-??

Prior releases tracked in git history. This changelog begins with 0.3.7.

[0.3.7]: https://github.com/Calhooon/bsv-rs/releases/tag/v0.3.7
