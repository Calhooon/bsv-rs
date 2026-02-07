# WalletWire Protocol Module
> Binary protocol for efficient wallet communication

## Overview

The WalletWire protocol provides efficient binary serialization for wallet operations. It enables remote wallet communication over any transport (HTTP, WebSocket, IPC) with minimal overhead. The protocol is binary-compatible with the TypeScript and Go BSV SDK implementations.

## Files

| File | Purpose | Lines |
|------|---------|-------|
| `mod.rs` | Module root, WalletWire trait, status/counterparty codes | ~172 |
| `calls.rs` | WalletCall enum (28 call codes), TryFrom/Display impls | ~197 |
| `encoding.rs` | WireReader/WireWriter with signed varint and complex type support | ~1476 |
| `processor.rs` | Generic server-side processor over WalletInterface | ~943 |
| `transceiver.rs` | Client-side message serialization and full wallet interface | ~1619 |

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

## Serialization Rules

### Signed VarInt (ZigZag Encoding)

The protocol uses ZigZag encoding for signed varints to efficiently encode negative values:
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
| Optional string | `signed_varint(len or -1) + bytes` |
| Optional bytes | `signed_varint(len or -1) + bytes` |
| Optional bool | `i8(-1=None, 0=false, 1=true)` |
| String array | `signed_varint(count or -1) + strings...` |
| String map | `signed_varint(count or -1) + (key, value)...` |
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

`WireReader<'a>` and `WireWriter` wrap the primitives `Reader`/`Writer` with signed varint support and wallet-specific type methods.

**Basic types:** `read/write_u8`, `i8`, `u16_le`, `u32_le`, `u64_le`, `var_int`, `signed_var_int`, `optional_var_int`, `bytes`, plus `read_remaining`/`remaining`/`is_empty`/`position` on reader and `len`/`is_empty`/`as_bytes`/`into_bytes`/`with_capacity` on writer.

**Wire protocol types (both reader and writer):**
- `string`, `optional_string`, `optional_bytes`, `string_array`, `optional_string_array`
- `optional_bool`, `outpoint`, `outpoint_string`, `counterparty`
- `protocol_id`, `optional_protocol_id`, `action_status`
- `txid_hex`, `query_mode`, `optional_query_mode`
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

`WireWriter` implements `Default`.

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
- getNetwork (uses processor's configured network)
- getVersion (uses processor's configured version)

**Stub handlers (return error, require full wallet):**
- createAction, signAction, abortAction, listActions, internalizeAction
- listOutputs, relinquishOutput
- acquireCertificate, listCertificates, proveCertificate, relinquishCertificate
- discoverByIdentityKey, discoverByAttributes

**Error codes:** 0=success, 1=generic, 6=invalid parameter, 7=insufficient funds.

## Transceiver (Client-Side)

`WalletWireTransceiver<T: WalletWire>` serializes all 28 wallet methods into binary messages and deserializes responses.

- `new(wire)` - creates transceiver with wire transport
- `wire()` - access underlying transport

**Implemented methods:**
- **Key ops:** get_public_key, encrypt, decrypt, create_hmac, verify_hmac, create_signature, verify_signature
- **Action ops:** create_action, sign_action, abort_action, list_actions, internalize_action
- **Output ops:** list_outputs, relinquish_output
- **Certificate ops:** acquire_certificate, list_certificates, prove_certificate, relinquish_certificate
- **Discovery ops:** discover_by_identity_key, discover_by_attributes
- **Chain ops:** get_height, get_network, get_version, get_header, wait_for_authentication, is_authenticated

**Helper methods:** `parse_certificate_from_binary`, `parse_discovery_result` (internal).

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

Run tests:

```bash
cargo test wallet::wire --features wallet
```

## Cross-SDK Compatibility

The wire format is binary-compatible with:
- [TypeScript SDK](https://github.com/bitcoin-sv/ts-sdk) - `WalletWireProcessor`, `WalletWireTransceiver`
- [Go SDK](https://github.com/bitcoin-sv/go-sdk) - `wallet/serializer`

Messages serialized by one SDK can be deserialized by another.

## Dependencies

- `async-trait` - For async trait methods in `WalletWire`
- Internal: `primitives::encoding::{Reader, Writer}` for base serialization
- Internal: `wallet::types` for all wallet type definitions
- Internal: `wallet::interface::WalletInterface` for processor generics

## Related Documentation

- `../CLAUDE.md` - Wallet module documentation
- `../interface.rs` - WalletInterface trait definition
- `../types.rs` - Core wallet type definitions
- `../proto_wallet.rs` - ProtoWallet implementation
- `../../primitives/encoding/` - Base Reader/Writer
