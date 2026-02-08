# WalletWire Protocol Module
> Binary protocol for efficient wallet communication

## Overview

The WalletWire protocol provides efficient binary serialization for wallet operations. It enables remote wallet communication over any transport (HTTP, WebSocket, IPC) with minimal overhead. The protocol is binary-compatible with the TypeScript and Go BSV SDK implementations.

## Files

| File | Purpose | Lines |
|------|---------|-------|
| `mod.rs` | Module root, WalletWire trait, status/counterparty codes | ~173 |
| `calls.rs` | WalletCall enum (28 call codes), TryFrom/Display/method_name impls | ~197 |
| `encoding.rs` | WireReader/WireWriter with Go-compatible nil sentinel and complex type support | ~2554 |
| `processor.rs` | Generic server-side processor over WalletInterface | ~949 |
| `transceiver.rs` | Client-side message serialization and full wallet interface (all 28 methods) | ~1628 |

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

Optional strings, bytes, string arrays, and string maps use `VarInt(u64::MAX)` (9 bytes: `FF FF FF FF FF FF FF FF FF`) as a nil/absent sentinel, matching the Go SDK's `VarInt(math.MaxUint64)` encoding. This is used in `read/write_optional_string`, `read/write_optional_bytes`, `read/write_string_array`, `read/write_string_map`, and `read/write_optional_string_map`.

Empty optional strings and empty optional bytes are treated the same as `None` — both write the nil sentinel. This matches Go SDK behavior.

### Signed VarInt (ZigZag Encoding)

Used for optional numeric values and signed counts (e.g., optional input/output arrays). ZigZag encoding maps signed integers to unsigned:
- Non-negative `n` is encoded as `2n`
- Negative `n` is encoded as `2|n| - 1`

This allows -1 (representing `null`/`None`) to be encoded as a single byte (0x01).

### Type Encoding

| Type | Encoding |
|------|----------|
| `u8`, `i8` | 1 byte |
| `u16`, `u32`, `u64` | Little-endian |
| `varint` | Variable (1-9 bytes) |
| `signed_varint` | ZigZag encoded |
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
| Optional Protocol ID | `u8(255) + empty string` for None |
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

**WalletCertificate wire format (Go-compatible):** `type(32 raw bytes, base64) -> serial(32 raw bytes, base64) -> subject(33 pubkey) -> certifier(33 pubkey) -> revocation outpoint -> fields(sorted map) -> signature(remaining bytes, no length prefix)`.

**IdentityCertificate wire format (Go-compatible):** `VarInt(cert_len) + cert_bytes (WalletCertificate format) -> optional certifier_info -> optional publicly_revealed_keyring -> optional decrypted_fields`.

**WalletAction wire format (Go-compatible):** `txid(32) -> satoshis(unsigned VarInt) -> status(i8) -> isOutgoing(optional bool) -> description(string) -> labels(string array) -> version(VarInt) -> lockTime(VarInt) -> inputs(VarInt count or MaxUint64) -> outputs(VarInt count or MaxUint64)`.

**WalletActionOutput field order:** `OutputIndex -> Satoshis -> LockingScript -> Spendable -> OutputDescription -> Basket -> Tags -> CustomInstructions`.

**WalletOutput field order:** `Outpoint -> Satoshis -> LockingScript -> CustomInstructions -> Tags -> Labels` (no `spendable` field on wire, defaults to `true`).

**WalletActionInput:** `sequence_number` is VarInt (not u32_le), matching Go.

**String maps:** Keys sorted lexicographically before writing, matching Go SDK.

**Tests:** Comprehensive roundtrip tests for every type including edge cases (empty collections, unicode strings, large data, all security levels, all action statuses, negative satoshis).

## Processor (Server-Side)

`WalletWireProcessor<W: WalletInterface>` handles incoming binary messages, dispatches to wallet methods, and returns serialized responses.

**Configuration:**
- `new(wallet)` - default (mainnet, version "0.1.0")
- `with_config(wallet, network, version)` - custom network/version
- `wallet()`, `network()`, `version()` - accessors

**Fully implemented handlers (delegated to wallet):**
- getPublicKey, encrypt, decrypt, createHmac, verifyHmac
- createSignature, verifySignature
- revealCounterpartyKeyLinkage, revealSpecificKeyLinkage
- isAuthenticated, waitForAuthentication, getHeight, getHeaderForHeight

**Processor-local handlers:**
- getNetwork (uses processor's configured network, single byte: 0x00=mainnet, 0x01=testnet)
- getVersion (uses processor's configured version, raw UTF-8 bytes, no length prefix)

**Stub handlers (return error, require full wallet implementation):**
- createAction, signAction, abortAction, listActions, internalizeAction
- listOutputs, relinquishOutput
- acquireCertificate, listCertificates, proveCertificate, relinquishCertificate
- discoverByIdentityKey, discoverByAttributes

All 28 call codes are dispatched in the match statement. Stub handlers return descriptive errors indicating a full wallet implementation is required.

**Error codes:** 0=success, 1=generic, 6=invalid parameter, 7=insufficient funds.

## Transceiver (Client-Side)

`WalletWireTransceiver<T: WalletWire>` serializes all 28 wallet methods into binary messages and deserializes responses.

- `new(wire)` - creates transceiver with wire transport
- `wire()` - access underlying transport

**All 28 methods fully implemented:**
- **Key ops:** get_public_key, encrypt, decrypt, create_hmac, verify_hmac, create_signature, verify_signature
- **Key linkage:** reveal_counterparty_key_linkage, reveal_specific_key_linkage
- **Action ops:** create_action (with full options: sign_and_process, trust_self, known_txids, no_send, no_send_change, send_with, randomize_outputs), sign_action, abort_action, list_actions, internalize_action
- **Output ops:** list_outputs, relinquish_output
- **Certificate ops:** acquire_certificate (both Direct and Issuance protocols), list_certificates, prove_certificate, relinquish_certificate
- **Discovery ops:** discover_by_identity_key, discover_by_attributes
- **Chain ops:** get_height, get_network, get_version, get_header, wait_for_authentication, is_authenticated

**Helper methods:** `parse_certificate_from_binary`, `parse_discovery_result` (internal).

**Certificate binary format in transceiver response parsing:** `type(32 bytes) -> subject(33 bytes) -> serial(32 bytes) -> certifier(33 bytes) -> outpoint -> varint(sig_len) + sig -> fields map`. Note: this order differs from the `WireWriter::write_wallet_certificate` Go-compatible format (which puts serial before subject).

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
- encoding.rs: Roundtrip tests for all primitive and complex types (signed varint, strings, optional values, outpoints, counterparty, protocol IDs, action status, query mode, output include, string maps, optional string arrays, send-with-results, sign-action-spends, wallet certificates, identity certifiers/certificates, wallet payments, basket insertions, internalize outputs, wallet action inputs/outputs/actions, wallet outputs). Edge cases include unicode strings, large data, empty collections, negative satoshis, and all enum variants.
- processor.rs: Tests for getPublicKey, getNetwork, getVersion, isAuthenticated, invalid call codes, and createAction error.
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

54 Go wire test vectors in `tests/vectors/wallet_wire/` validate cross-SDK compatibility. See `tests/wallet_wire_cross_sdk_tests.rs` for the 42 cross-SDK roundtrip tests.

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
