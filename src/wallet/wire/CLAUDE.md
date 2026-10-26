# WalletWire Protocol Module
> Binary protocol for efficient wallet communication

## Overview

The WalletWire protocol provides efficient binary serialization for wallet operations. It enables remote wallet communication over any transport (HTTP, WebSocket, IPC) with minimal overhead. The protocol is binary-compatible with the TypeScript and Go BSV SDK implementations.

## Files

| File | Purpose | Lines |
|------|---------|-------|
| `mod.rs` | Module root, WalletWire trait, status/counterparty codes, the u32 field readers, the reference's strict certificate and record readers (#183), the signature calls' data-type flag writer (#199), the key-related parameters' and privileged pair's writers (#193) | ~551 |
| `calls.rs` | WalletCall enum (28 call codes), TryFrom/Display/method_name impls | ~197 |
| `encoding.rs` | WireReader/WireWriter with Go-compatible nil sentinel and complex type support | ~2521 |
| `processor.rs` | Generic server-side processor over WalletInterface; every call it reads ends in `assert_request_consumed` (#193), then the reference's argument validation, the wallet, the result check (#216) | ~890 |
| `validation.rs` | The processor's `validateWalletArgs` and `validateWalletResult` (`ts-stack@edf6e03` `validationHelpers.ts`, `WalletResultValidation.ts`) for the wired calls, in the reference's words: an argument refused code 6 (`WERR_INVALID_PARAMETER`), a result refused code 1; `Refusal` (the code and the words a frame carries); getHeaderForHeight's height in `#requireInteger`'s words (#216) | ~633 |
| `requests.rs` | The processor's request readers for the two linkage calls, the privileged flag and reason ahead of the keys as the reference reads them (#191); for verifyHmac, the 32 raw HMAC bytes ahead of the data, and for createSignature and verifySignature, the data-type flag (`1` the data, `2` the hash, another refused), verifySignature's signature ahead of it (#199); the seven key-related calls' requests whole, the privileged pair inside the key-related parameters and seekPermission last, getPublicKey's identityKey byte ahead, and `assert_request_consumed`, a byte after the last field refused (#193) | ~284 |
| `results.rs` | The processor's result writers for the two linkage calls, the three keys ahead of everything as the reference writes them (#194); for encrypt, decrypt, createHmac and createSignature, the bytes alone, and for verifyHmac, verifySignature and waitForAuthentication, nothing after the error byte, a false verdict an error frame (#197) | ~128 |
| `transceiver.rs` | Client-side message serialization: 26 of the 28 methods, no linkage methods (docs/FIXTURES.md F2) | ~1610 |

## Architecture

```
┌───────────────────────────┐         ┌───────────────────────────┐
│  WalletWireTransceiver    │         │  WalletWireProcessor      │
│        (Client)           │         │        (Server)           │
└───────────┬───────────────┘         └───────────┬───────────────┘
            │                                     │
            │       Binary Message                │
            │ ───────────────────────────────────>│
            │                                     │
            │       Binary Response               │
            │ <───────────────────────────────────│
            │                                     │
            └─────────────────────────────────────┘
                        WalletWire
                       (Transport)
```

## Wire Protocol Format

### Request Frame

```
┌─────────┬──────────────┬────────────┬────────────────┐
│ Call    │ Originator   │ Originator │ Serialized     │
│ Code    │ Length       │ String     │ Parameters     │
│ (1 byte)│ (1 byte)     │ (N bytes)  │ (variable)     │
└─────────┴──────────────┴────────────┴────────────────┘
```

### Response Frame (Success)

```
┌─────────┬────────────────────────────────────────────┐
│ Error=0 │ Serialized Result                          │
│ (1 byte)│ (variable length)                          │
└─────────┴────────────────────────────────────────────┘
```

### Response Frame (Error)

```
┌─────────┬────────────────┬────────────────┬──────────┐
│ Error≠0 │ Message Length │ Error Message  │ Stack    │
│ (1 byte)│ (varint)       │ (UTF-8)        │ (varint) │
└─────────┴────────────────┴────────────────┴──────────┘
```

The processor writes the reference's error frame (`WalletWireProcessor.ts:2370-2418` at `ts-stack@edf6e03`, #202). Every wallet call goes through `invoke_wallet`, the reference's `#invokeWallet` (`:2402-2418`): a wallet error with a code 2 to 8 (`explicit_wallet_code`; none today, this crate's `Error` carrying no code, #137) keeps its words and code; every other is replaced by `Wallet operation failed`, code 1 (`:2417`), so a wallet's words never reach the wire. The processor's own errors (its reading of the request, the three false verdicts raised after the wallet answers, the thirteen full-wallet stubs) keep their words: a `WalletError` its words, any other variant its `Display` sentence, never the crate's `Display` prefix. The message is cut at 4096 bytes at the byte; the stack an empty string, a varint 0. The wallet's words are not on the wire; with the `tracing` feature (off by default, not in `full`, #212) `invoke_wallet` emits one `warn` event where it chooses the constant: `call` (`WalletCall::method_name`), `error` (the wallet error's `Display`), the message `wallet error framed as Wallet operation failed`; nothing else is instrumented and the frame is the same bytes either way (`tests/wire_tracing_sink.rs`). The transceiver reads a frame as `WalletError("wallet error (code N): <message>")`.

## Call Codes

| Code | Method | Code | Method |
|------|--------|------|--------|
| 1 | createAction | 15 | createSignature |
| 2 | signAction | 16 | verifySignature |
| 3 | abortAction | 17 | acquireCertificate |
| 4 | listActions | 18 | listCertificates |
| 5 | internalizeAction | 19 | proveCertificate |
| 6 | listOutputs | 20 | relinquishCertificate |
| 7 | relinquishOutput | 21 | discoverByIdentityKey |
| 8 | getPublicKey | 22 | discoverByAttributes |
| 9 | revealCounterpartyKeyLinkage | 23 | isAuthenticated |
| 10 | revealSpecificKeyLinkage | 24 | waitForAuthentication |
| 11 | encrypt | 25 | getHeight |
| 12 | decrypt | 26 | getHeaderForHeight |
| 13 | createHmac | 27 | getNetwork |
| 14 | verifyHmac | 28 | getVersion |

`WalletCall` provides: `as_u8()`, `method_name()` (returns camelCase name), `TryFrom<u8>`, and `Display`.

## Serialization Rules

### Go-Compatible Nil Sentinel

Optional strings, bytes, string arrays, and string maps use `VarInt(u64::MAX)` (9 bytes: `FF FF FF FF FF FF FF FF FF`) as a nil/absent sentinel, matching the Go SDK's `VarInt(math.MaxUint64)` encoding. This is used in `read/write_optional_string`, `read/write_optional_bytes`, `read/write_string_array`, `read/write_string_map`, and `read_optional_string_map` (its writer removed in 0.9.0, bsv-rs#184). No frame the reference reads strictly is read through a sentinel reader (#183): a certificate's fields, the listCertificates keyring and the discovery maps are `readVarIntNumStrict` counts, nine 0xFF refused; `read_string_map` has no caller in the crate, `read_optional_string_map` has no caller in the crate; its writer was removed (bsv-rs#184).

Empty optional strings and empty optional bytes are treated the same as `None` — both write the nil sentinel. This matches Go SDK behavior.

### Optional and Signed VarInt (#149)

Optional numeric fields (sequence numbers, lockTime, version, every `limit` and `offset`) are the plain varint when present and `VarInt(u64::MAX)` (nine `0xFF`, BRC-100's `-1`) when absent, as TS `writeVarIntNum` and Go `WriteOptionalUint32` write them; `10` is `0x0A`. `write_signed_var_int(field, v)` writes `-1` as nine `0xFF` and refuses any other negative naming the field; `read_signed_var_int` reads nine `0xFF` as `-1` and refuses a value above `i64::MAX`. listOutputs' `offset` is an `i32`: `-1` (the newest output) leaves as absence's bytes, as TS's does, and below `-1` the transceiver refuses. A `u32` field's reader refuses above `u32::MAX` (`read_optional_var_int_u32`, `mod.rs`). Until 0.8.x this was ZigZag (`10` as `0x14`, absence as `0x01`).

### Type Encoding

| Type | Encoding |
|------|----------|
| `u8`, `i8` | 1 byte |
| `u16`, `u32`, `u64` | Little-endian |
| `varint` | Variable (1-9 bytes) |
| `signed_varint` | Plain varint; `-1` as `u64::MAX` (nine `0xFF`) |
| UTF-8 string | `varint(len) + bytes` |
| Optional string | `varint(len or MaxUint64) + bytes` (Go-compat nil sentinel) |
| Optional bytes | `varint(len or MaxUint64) + bytes` (Go-compat nil sentinel) |
| Optional bool | `i8(-1=None, 0=false, 1=true)` |
| String array | `varint(count or MaxUint64) + strings...` (Go-compat nil sentinel) |
| String map | `varint(count or MaxUint64) + sorted (key, value)...` (Go-compat nil sentinel) |
| Optional string map | `varint(count or MaxUint64) + sorted (key, value)...` (Go-compat nil sentinel) |
| Outpoint | `32 bytes (txid) + varint(vout)` |
| Public key | 33 bytes (compressed) |
| Counterparty | `0=None, 11=Self, 12=Anyone, else=33-byte pubkey` |
| Protocol ID | `u8(security_level) + string(name)` |
| Optional Protocol ID | `u8(255) + empty string` for None (no request uses it since #193: getPublicKey writes the reference's `[0, "default"]` for an absent protocol) |
| Privileged pair | `i8` flag (-1 absent) + `i8` reason length (-1 absent) + UTF-8 bytes, a reason past 127 bytes refused before writing (#193) |
| Action status | `i8(1-8 or -1=unknown)` |
| Query mode | `0=any, 1=all` |
| Output include | `0=locking scripts, 1=entire transactions` |
| SendWithResultStatus | `0=unproven, 1=sending, 2=failed` |

### Counterparty Encoding

```rust
pub mod counterparty_codes {
    pub const UNDEFINED: u8 = 0;   // None
    pub const SELF: u8 = 11;       // Counterparty::Self_
    pub const ANYONE: u8 = 12;     // Counterparty::Anyone
    // Other values: first byte of 33-byte compressed public key
}
```

### Action Status Codes

```rust
pub mod status_codes {
    pub const COMPLETED: i8 = 1;
    pub const UNPROCESSED: i8 = 2;
    pub const SENDING: i8 = 3;
    pub const UNPROVEN: i8 = 4;
    pub const UNSIGNED: i8 = 5;
    pub const NOSEND: i8 = 6;
    pub const NONFINAL: i8 = 7;
    pub const FAILED: i8 = 8;
    pub const UNKNOWN: i8 = -1;
}
```

## WireReader / WireWriter

`WireReader<'a>` and `WireWriter` wrap the primitives `Reader`/`Writer` with Go-compatible nil sentinel support and wallet-specific type methods.

**Basic types:** `read/write_u8`, `i8`, `u16_le`, `u32_le`, `u64_le`, `var_int`, `signed_var_int`, `optional_var_int`, `bytes`, plus `read_remaining`/`remaining`/`is_empty`/`position` on reader and `len`/`is_empty`/`as_bytes`/`into_bytes`/`with_capacity` on writer.

**Wire protocol types (both reader and writer):**
- `string`, `optional_string`, `optional_bytes`, `string_array`
- `optional_bool`, `outpoint`, `outpoint_string`, `counterparty`
- `protocol_id`, `optional_protocol_id`, `action_status`
- `txid_hex`, `pubkey_hex` (reader only), `query_mode`, `optional_query_mode`
- `output_include`, `optional_output_include`
- `string_map`, `optional_string_map`
- `send_with_result_status`, `send_with_result`, `send_with_result_array`
- `sign_action_spend`, `sign_action_spends`
- `wallet_certificate`, `optional_wallet_certificate`
- `identity_certifier`, `optional_identity_certifier`, `identity_certificate`
- `wallet_payment`, `optional_wallet_payment`
- `basket_insertion`, `optional_basket_insertion`
- `internalize_output`
- `wallet_action_input`, `wallet_action_output`, `wallet_action`
- `wallet_output`

**Writer-only:** `optional_string_array` (writes `None` as nil sentinel, `Some` as count + elements).

`WireWriter` implements `Default`.

**WalletCertificate wire format (Go-compatible):** `type(32 raw bytes, base64) -> serial(32 raw bytes, base64) -> subject(33 pubkey) -> certifier(33 pubkey) -> revocation outpoint -> fields(sorted map) -> signature(remaining bytes, no length prefix)`. `read_wallet_certificate` reads it as `Certificate.fromBinary` does (`ts-stack@edf6e03` `Certificate.ts:329-408`, #183): the keys 33 bytes that decompress to a point (`:342`, `:347`), the field count strict, at most 100,000 and a third of the bytes remaining (`:357-363`), each name 1 to 50 bytes, safe, unique (`:367-374`), each value at most 1 MiB, the signature at most 72 bytes through `Signature.fromDER`'s checks and kept as `toDER` re-encodes it (`:390-397`); the checks are `mod.rs`'s (`read_compressed_key`, `read_certificate_fields`, `read_certificate_signature`).

**IdentityCertificate wire format (the writer's, the reference's `#serializeDiscoveryResult` and Go's `SerializeIdentityCertificate`, bsv-rs#182):** `VarInt(cert_len) + cert_bytes (WalletCertificate format) -> name, iconUrl, description (plain varint-length strings, an absent one empty) -> trust (u8) -> keyring (varint count + sorted (varint-length key, varint-length raw bytes of the base64 value)) -> decrypted fields (string map)`; no present-flag byte, no NIL sentinel, an absent map a count of 0; an absent certifier info or a trust outside 1 to 10 refused before a byte is written (the reference's reader refuses the frame, `WalletWireTransceiver.ts:1710`; bsv-rs#183). `read_identity_certificate` and `read_optional_identity_certifier` read the same bytes as the transceiver's discovery reader does (bsv-rs#184): an empty iconUrl or description is `Some("")`, Go's zero value is `Some` with empty strings and trust 0 (never `None`), an empty map is `None`; the old layout's bytes are refused. The three writer helpers of the old layout, `write_identity_certifier`, `write_optional_identity_certifier` and `write_optional_string_map`, deprecated by bsv-rs#184, are removed in 0.9.0 (the owner's word of 2026-10-25): no reference frame carries a present flag or a NIL-sentinel map; a test that needs the old bytes assembles them by hand (`the_layout_before_182_is_refused`).

**WalletAction wire format (Go-compatible):** `txid(32) -> satoshis(unsigned VarInt) -> status(i8) -> isOutgoing(optional bool) -> description(string) -> labels(string array) -> version(VarInt) -> lockTime(VarInt) -> inputs(VarInt count or MaxUint64) -> outputs(VarInt count or MaxUint64)`.

**WalletActionOutput field order:** `OutputIndex -> Satoshis -> LockingScript -> Spendable -> OutputDescription -> Basket -> Tags -> CustomInstructions`.

**WalletOutput field order:** `Outpoint -> Satoshis -> LockingScript -> CustomInstructions -> Tags -> Labels` (no `spendable` field on wire, defaults to `true`).

**WalletActionInput:** `sequence_number` is VarInt (not u32_le), matching Go.

**String maps:** Keys sorted lexicographically before writing, matching Go SDK.

**Tests:** Comprehensive roundtrip tests for every type including edge cases (empty collections, unicode strings, large data, all security levels, all action statuses, negative satoshis).

## Processor (Server-Side)

`WalletWireProcessor<W: WalletInterface>` handles incoming binary messages, dispatches to wallet methods, and returns serialized responses.

**Configuration:**
- `new(wallet)` - the processor over its wallet
- `with_config(wallet, network, version)` - deprecated (#222): the network and version reach no frame, getNetwork and getVersion answering the wallet's
- `wallet()` - accessor; `network()`, `version()` deprecated with `with_config`, returning what it was given

**Fully implemented handlers (delegated to wallet):**
- getPublicKey, encrypt, decrypt, createHmac, verifyHmac
- verifyHmac, createSignature, verifySignature: the requests in the reference's order (`requests.rs`, #199): verifyHmac the key-related parameters, the HMAC's 32 raw bytes, then the data behind its length (`WalletWireProcessor.ts:1502-1509`); the signature calls a data-type flag, `1` then the data behind its length or `2` then the 32-byte hash, another value refused as `Invalid <call> data type flag: expected 1 or 2, received N` (`:1533-1543`, `:1576-1586`), verifySignature's forSelf and signature ahead of it (`:1569-1573`)
- the seven key-related calls (#193): the key-related parameters are the protocol, key ID, counterparty, then the privileged flag and reason (`#decodeKeyRelatedParams`, `WalletWireProcessor.ts:2564-2583`), each call's own fields after them and seekPermission last; getPublicKey's identityKey a byte 0 or 1, then the privileged pair alone, or the key-related parameters and forSelf (`:1386-1403`). The three fields pass through to the wallet. A request with a byte after its last field is refused, `Wallet Wire <call> request contains trailing data` (`#assertRequestConsumed`, `:2433-2437`), for every call the processor reads (the seven, the two linkage calls, getHeaderForHeight, the five with no parameters); the thirteen stubs read nothing
- createSignature, verifySignature: the results as the reference writes them (`results.rs`, #197): encrypt, decrypt, createHmac and createSignature the error byte then the ciphertext, plaintext, 32 HMAC bytes or DER alone, no length (`WalletWireProcessor.ts:1443-1444`, `:1470-1471`, `:1495-1496`, `:1559-1560`); verifyHmac and verifySignature the error byte alone, a false verdict the reference's error frame (`HMAC is not valid`, `Signature is not valid`; `:1520-1525`, `:1597-1602`)
- revealCounterpartyKeyLinkage, revealSpecificKeyLinkage: the request in the reference's order (`requests.rs`, #191): counterparty linkage the privileged flag (`i8`) and reason (`i8` length, -1 absent) then the two keys (`WalletWireProcessor.ts:1739-1747`); specific linkage the protocol, key ID, counterparty, privileged flag and reason, then the verifier (`:1790-1797`, `:2564-2583`); both passed through into the args. The responses in the reference's order (`results.rs`, #194): the prover, verifier and counterparty, then revelationTime, encryptedLinkage, encryptedLinkageProof (`WalletWireProcessor.ts:1761-1781`); or the protocol, keyID, encryptedLinkage, encryptedLinkageProof, proofType (`:1811-1841`)
- isAuthenticated, waitForAuthentication, getHeight, getHeaderForHeight: waitForAuthentication's result the error byte alone, a false verdict an error frame (`Wallet did not affirmatively authenticate`, `:1636-1643`, #197); isAuthenticated keeps its verdict byte (`:1618-1622`)
- getNetwork, getVersion: the wallet's `get_network` and `get_version` forwarded through `invoke_wallet`, never the processor's own (`WalletWireProcessor.ts:1701-1705`, `:1721-1725` at `ts-stack@edf6e03`, #222); the network one byte, 0 mainnet, 1 testnet (`:1710`), its rule (`mainnet or testnet`, `WalletResultValidation.ts:2299-2303`) the `Network` type's; the version its UTF-8 bytes with no length prefix (`:1730`), refused outside 7 to 30 bytes, code 1, `Invalid getVersion result version: expected 7–30 UTF-8 bytes` (`:2304-2306`). `ProtoWallet` answers mainnet and `bsv-rs-<CARGO_PKG_VERSION>`

**Stub handlers (return error, require full wallet implementation):**
- createAction, signAction, abortAction, listActions, internalizeAction
- listOutputs, relinquishOutput
- acquireCertificate, listCertificates, proveCertificate, relinquishCertificate
- discoverByIdentityKey, discoverByAttributes

All 28 call codes are dispatched in the match statement. Stub handlers return descriptive errors indicating a full wallet implementation is required.

**Error codes:** 0=success; 6 (invalidParameter) for an argument the reference's `validateWalletArgs` refuses, `The <parameter> parameter must be <mustBe>`, the wallet never called (#216); 1 (unknownError) for every other frame: a result the reference's `validateWalletResult` refuses (`Invalid <call> result <field>: expected <expectation>`, #216), the processor's own reading, and a wallet's error, the reference taking 2 to 8 from an explicit wallet error's `code`, which this crate's `Error` does not carry (#137); a wallet's un-coded error is `Wallet operation failed` (#202).

**Validation (#216, `validation.rs`):** ahead of the wallet, the protocol name 5 to 400 bytes and the key ID 1 to 800 (the eight calls that carry them), the privileged reason 5 to 50 bytes and required when `privileged` (those eight, getPublicKey for the identity key, revealCounterpartyKeyLinkage), verifySignature's signature at most 72 bytes and canonical DER, the byte arrays at most 256 MiB, getHeaderForHeight's height 1 to 2^32-1; after it, getPublicKey's key, createSignature's signature, getHeight's height, getVersion's version (#222), the byte results' bound, both linkages' bytes, revelation time, key ID and protocol name, and the requested verifier, counterparty, protocol and key ID. A rule the reader already enforces (the security level, a key that is no point, the data-type flag, a 32-byte field) or a type carries is not repeated, and keeps the reader's words.

## Transceiver (Client-Side)

`WalletWireTransceiver<T: WalletWire>` serializes 26 of the 28 wallet methods into binary messages and deserializes responses; it has no revealCounterpartyKeyLinkage or revealSpecificKeyLinkage method (docs/FIXTURES.md F2).

- `new(wire)` - creates transceiver with wire transport
- `wire()` - access underlying transport

**The 26 methods:**
- **Key ops:** get_public_key, encrypt, decrypt, create_hmac, verify_hmac, create_signature, verify_signature
- **Action ops:** create_action (with full options: sign_and_process, trust_self, known_txids, no_send, no_send_change, send_with, randomize_outputs), sign_action, abort_action, list_actions, internalize_action
- **Output ops:** list_outputs, relinquish_output
- **Certificate ops:** acquire_certificate (both Direct and Issuance protocols), list_certificates, prove_certificate, relinquish_certificate
- **Discovery ops:** discover_by_identity_key, discover_by_attributes
- **Chain ops:** get_height, get_network, get_version, get_header, wait_for_authentication, is_authenticated

**Helper methods:** `parse_certificate_from_binary`, `parse_discovery_result` (internal).

**The three requests of #199:** verify_hmac writes the HMAC's 32 raw bytes then the data behind its length (`WalletWireTransceiver.ts:1048-1050`); create_signature and verify_signature the data-type flag, `1` and the data or `2` and the hash (`:1082-1090`, `:1137-1144`, `write_data_or_hash` in `mod.rs`), verify_signature's signature ahead of it (`:1135-1136`); both or neither of the data and the hash refused before a byte is written (`The data, hashToDirectlySign parameter must be exactly one value`, `validationHelpers.ts:1777-1787`).

**The seven key-related requests (#193):** the privileged pair inside the key-related parameters (`write_key_related_params`, `#encodeKeyRelatedParams`, `WalletWireTransceiver.ts:1351-1376`) and seekPermission last; getPublicKey's identityKey byte, then the pair alone or the key-related parameters (an absent protocol and key ID as the reference's `[0, "default"]` and `""`, `:761-762`) and forSelf, then seekPermission (`:756-779`). Each Go args vector of the seven is the transceiver's request over its json, byte for byte.

**The seven results of #197:** encrypt, decrypt and createSignature read the rest of the frame as the bytes, createHmac exactly 32 bytes; verifyHmac, verifySignature and waitForAuthentication read an empty result as true and refuse a byte after the error byte (`Wallet Wire <call> response has an invalid length`, the reference's `#requireEmptyResponse`, `WalletWireTransceiver.ts:953-957`, `:988`, `:1019-1021`, `:1093-1101`, `:1053-1055`, `:1147-1149`, `:1870-1872`), so a bsv-rs 0.9.0 processor's `00 00` (its false verdict) is never read as true.

**Certificate binary format in transceiver response parsing:** the reference's `Certificate.toBinary` (`ts-stack@edf6e03` `Certificate.ts:229-321`), Go's and `WireWriter::write_wallet_certificate`'s: `type(32) -> serial(32) -> subject(33) -> certifier(33) -> outpoint (txid 32 + varint index) -> fields map (sorted) -> signature (the bytes remaining, no length prefix)` (bsv-rs#177; BRC-100 section 19's table, subject before serial and a length-prefixed signature before the fields, departs from these bytes). listCertificates' verifier is `varint(0)` or `varint(33)` + 33 bytes that decompress to a point, read as hex, any other length refused; its keyring flag 0 or 1; discovery's certifierInfo is three plain varint-length strings (an empty one length 0) and the trust byte (1 to 10, `:1710`), no present flag. Every record (the listCertificates keyring, the discovery keyring and decrypted fields) is a strict collection count bounded by the bytes remaining, keys 1 to 50 bytes, safe and unique (`#readRecordKey`, `#setUniqueWireRecordEntry`, `:1955-2002`; #183).

**getHeaderForHeight result:** the error byte, then the header's 80 raw bytes with no length prefix, on both sides (`WalletWireProcessor.ts:1687-1690`, `WalletWireTransceiver.ts:1903`; BRC-100 `0100.md:2478` at `5119a9b`; bsv-rs#178); another length refused by the transceiver (`#requireResponseLength`) and by the processor for a wallet's header (`WalletResultValidation.ts:2297`; #183).

## Public Exports

```rust
pub use calls::WalletCall;
pub use encoding::{WireReader, WireWriter};
pub use processor::WalletWireProcessor;
pub use transceiver::WalletWireTransceiver;

#[async_trait]
pub trait WalletWire: Send + Sync {
    async fn transmit_to_wallet(&self, message: &[u8]) -> Result<Vec<u8>, Error>;
}

pub mod counterparty_codes { /* UNDEFINED=0, SELF=11, ANYONE=12 */ }
pub mod status_codes { /* COMPLETED=1 .. FAILED=8, UNKNOWN=-1 */ }
```

## Testing

Tests use a loopback wire pattern connecting transceiver directly to processor:

```rust
struct LoopbackWire {
    processor: Arc<WalletWireProcessor<ProtoWallet>>,
}

impl WalletWire for LoopbackWire {
    async fn transmit_to_wallet(&self, message: &[u8]) -> Result<Vec<u8>, Error> {
        self.processor.process_message(message).await
    }
}
```

**Test coverage:**
- encoding.rs: Roundtrip tests for all primitive and complex types (signed varint, strings, optional values, outpoints, counterparty, protocol IDs, action status, query mode, output include, string maps, optional string arrays, send-with-results, sign-action-spends, wallet certificates, wallet payments, basket insertions, internalize outputs, wallet action inputs/outputs/actions, wallet outputs). Edge cases include unicode strings, large data, empty collections, negative satoshis, and all enum variants.
- `tests/wire_identity_certificate_writer.rs` and `tests/wire_identity_certificate_roundtrip.rs`: the identity certificate's writer and readers against the reference's bytes and the shared discovery vector (#182, #184).
- processor.rs: Tests for getPublicKey, getNetwork and getVersion (ProtoWallet's answers forwarded, #222), isAuthenticated, invalid call codes, and createAction error.
- transceiver.rs: End-to-end loopback tests for get_public_key, encrypt/decrypt roundtrip, create/verify HMAC, create/verify signature, is_authenticated, get_network, get_version.

Run tests:

```bash
cargo test wallet::wire --features wallet
```

## Cross-SDK Compatibility

The wire format is binary-compatible with:
- [TypeScript SDK](https://github.com/bitcoin-sv/ts-sdk) - `WalletWireProcessor`, `WalletWireTransceiver`
- [Go SDK](https://github.com/bitcoin-sv/go-sdk) - `wallet/serializer`

Messages serialized by one SDK can be deserialized by another. Key compatibility details:
- **Nil sentinel**: `VarInt(u64::MAX)` (9 bytes) matches Go's `VarInt(math.MaxUint64)`
- **getNetwork**: Single byte (0x00=mainnet, 0x01=testnet), not a length-prefixed string
- **getVersion**: Raw UTF-8 bytes with no length prefix
- **WalletAction satoshis**: Unsigned VarInt (cast to i64 on read)
- **WalletAction version/lockTime**: VarInt (not u32 little-endian)
- **WalletActionInput sequence_number**: VarInt (not u32 little-endian)
- **WalletOutput**: No `spendable` field on wire (defaults to `true`)
- **String maps**: Keys sorted lexicographically before writing
- **Empty optional strings/bytes**: Treated same as None (both write nil sentinel)

54 Go wire test vectors in `tests/vectors/wallet_wire/` validate cross-SDK compatibility. See `tests/wallet_wire_cross_sdk_tests.rs` for the 55 cross-SDK tests, among them every args vector decoded through the processor to its json (#191), every result vector written through it to its wire (#194), the verifyHmac and signature requests read and written as Go's vectors (#199), the seven key-related requests read and written whole, and a trailing byte refused on 15 calls (#193).

## Dependencies

- `async-trait` - For async trait methods in `WalletWire`
- Internal: `primitives::encoding::{Reader, Writer}` for base serialization
- Internal: `primitives::{from_hex, to_hex, PublicKey, from_base64, to_base64}` for type conversions
- Internal: `wallet::types` for all wallet type definitions
- Internal: `wallet::interface::WalletInterface` for processor generics

## Related Documentation

- `../CLAUDE.md` - Wallet module documentation
- `../interface.rs` - WalletInterface trait definition
- `../types.rs` - Core wallet type definitions
- `../proto_wallet.rs` - ProtoWallet implementation
- `../../primitives/encoding/` - Base Reader/Writer
