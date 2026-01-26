# WalletWire Protocol Module
> Binary protocol for efficient wallet communication

## Overview

The WalletWire protocol provides efficient binary serialization for wallet operations. It enables remote wallet communication over any transport (HTTP, WebSocket, IPC) with minimal overhead. The protocol is binary-compatible with the TypeScript and Go BSV SDK implementations.

## Files

| File | Purpose | Lines |
|------|---------|-------|
| `mod.rs` | Module root, WalletWire trait, re-exports | ~150 |
| `calls.rs` | WalletCall enum (28 call codes) | ~180 |
| `encoding.rs` | WireReader/WireWriter with signed varint support | ~500 |
| `processor.rs` | Server-side message processing | ~450 |
| `transceiver.rs` | Client-side message serialization | ~400 |
| `CLAUDE.md` | This documentation | ~350 |

## Architecture

```
┌─────────────────────┐         ┌─────────────────────┐
│  WalletWireTransceiver │       │  WalletWireProcessor   │
│      (Client)         │         │      (Server)          │
└──────────┬──────────┘         └──────────┬───────────┘
           │                                │
           │   Binary Message               │
           │ ──────────────────────────────>│
           │                                │
           │   Binary Response              │
           │ <──────────────────────────────│
           │                                │
           └────────────────────────────────┘
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
| `varint` | Variable (1-9 bytes) |
| `signed_varint` | ZigZag encoded |
| UTF-8 string | `varint(len) + bytes` |
| Optional string | `signed_varint(len or -1) + bytes` |
| Optional bytes | `signed_varint(len or -1) + bytes` |
| Optional bool | `i8(-1=None, 0=false, 1=true)` |
| String array | `signed_varint(count or -1) + strings...` |
| Outpoint | `32 bytes (txid) + varint(vout)` |
| Public key | 33 bytes (compressed) |
| Counterparty | `0=None, 11=Self, 12=Anyone, else=33-byte pubkey` |
| Protocol ID | `u8(security_level) + string(name)` |
| Action status | `i8(1-8 or -1=unknown)` |

### Counterparty Encoding

The counterparty field uses special sentinel values:

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

## Usage

### Server-Side (Processor)

```rust
use bsv_sdk::wallet::wire::WalletWireProcessor;
use bsv_sdk::wallet::ProtoWallet;

// Create processor with a wallet
let wallet = ProtoWallet::new(Some(private_key));
let processor = WalletWireProcessor::new(wallet);

// Process incoming request
let response = processor.process_message(&request_bytes).await?;
```

### Client-Side (Transceiver)

```rust
use bsv_sdk::wallet::wire::{WalletWire, WalletWireTransceiver};
use bsv_sdk::wallet::{GetPublicKeyArgs, Protocol, SecurityLevel};

// Implement transport
struct HttpWire { url: String }

#[async_trait::async_trait]
impl WalletWire for HttpWire {
    async fn transmit_to_wallet(&self, message: &[u8]) -> Result<Vec<u8>, Error> {
        // HTTP POST to wallet endpoint
    }
}

// Create transceiver
let wire = HttpWire { url: "https://wallet.example.com".into() };
let wallet = WalletWireTransceiver::new(wire);

// Make wallet calls
let result = wallet.get_public_key(
    GetPublicKeyArgs {
        protocol_id: Protocol::new(SecurityLevel::App, "my app"),
        key_id: "key-1".to_string(),
        counterparty: None,
        for_self: Some(true),
    },
    "app.example.com"
).await?;
```

### Direct Encoding

```rust
use bsv_sdk::wallet::wire::encoding::{WireReader, WireWriter};
use bsv_sdk::wallet::types::{Counterparty, Protocol, SecurityLevel};

// Writing
let mut writer = WireWriter::new();
writer.write_protocol_id(&Protocol::new(SecurityLevel::App, "test"));
writer.write_string("key-id");
writer.write_counterparty(Some(&Counterparty::Self_));
writer.write_optional_bool(Some(true));

let bytes = writer.into_bytes();

// Reading
let mut reader = WireReader::new(&bytes);
let protocol = reader.read_protocol_id()?;
let key_id = reader.read_string()?;
let counterparty = reader.read_counterparty()?;
let for_self = reader.read_optional_bool()?;
```

## Implemented Methods

Currently implemented in the processor:

- [x] getPublicKey
- [x] encrypt
- [x] decrypt
- [x] createHmac
- [x] verifyHmac
- [x] createSignature
- [x] verifySignature
- [x] revealCounterpartyKeyLinkage
- [x] revealSpecificKeyLinkage
- [x] isAuthenticated
- [x] getHeight
- [x] getNetwork
- [x] getVersion

Not yet implemented (require full wallet):

- [ ] createAction
- [ ] signAction
- [ ] abortAction
- [ ] listActions
- [ ] internalizeAction
- [ ] listOutputs
- [ ] relinquishOutput
- [ ] acquireCertificate
- [ ] listCertificates
- [ ] proveCertificate
- [ ] relinquishCertificate
- [ ] discoverByIdentityKey
- [ ] discoverByAttributes
- [ ] waitForAuthentication
- [ ] getHeaderForHeight

## Error Codes

| Code | Meaning |
|------|---------|
| 0 | Success |
| 1 | Generic error |
| 5 | Review actions required |
| 6 | Invalid parameter |
| 7 | Insufficient funds |

## Testing

The module includes comprehensive round-trip tests using a loopback wire:

```rust
#[tokio::test]
async fn test_roundtrip_encrypt_decrypt() {
    let transceiver = create_loopback();
    let plaintext = b"Hello, BSV!".to_vec();

    let encrypted = transceiver.encrypt(/* ... */).await.unwrap();
    let decrypted = transceiver.decrypt(/* ... */).await.unwrap();

    assert_eq!(decrypted.plaintext, plaintext);
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

Messages serialized by one SDK can be deserialized by another, enabling cross-platform wallet communication.

## Dependencies

- `async-trait` - For async trait methods in `WalletWire`
- Internal: `primitives::encoding::{Reader, Writer}` for base serialization

## Related Documentation

- `../CLAUDE.md` - Wallet module documentation
- `../types.rs` - Core wallet type definitions
- `../proto_wallet.rs` - ProtoWallet implementation
- `../../primitives/encoding.rs` - Base Reader/Writer
