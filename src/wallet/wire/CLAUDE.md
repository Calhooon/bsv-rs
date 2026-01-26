# WalletWire Protocol Module
> Binary protocol for efficient wallet communication

## Overview

The WalletWire protocol provides efficient binary serialization for wallet operations. It enables remote wallet communication over any transport (HTTP, WebSocket, IPC) with minimal overhead. The protocol is binary-compatible with the TypeScript and Go BSV SDK implementations.

## Files

| File | Purpose | Lines |
|------|---------|-------|
| `mod.rs` | Module root, WalletWire trait, status/counterparty codes | ~172 |
| `calls.rs` | WalletCall enum (28 call codes), TryFrom/Display impls | ~197 |
| `encoding.rs` | WireReader/WireWriter with signed varint and complex type support | ~1474 |
| `processor.rs` | Generic server-side processor over WalletInterface | ~939 |
| `transceiver.rs` | Client-side message serialization and full wallet interface | ~1616 |

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

The processor is generic over `W: WalletInterface`, allowing any wallet implementation:

```rust
use bsv_sdk::wallet::wire::WalletWireProcessor;
use bsv_sdk::wallet::{ProtoWallet, Network};
use bsv_sdk::wallet::interface::WalletInterface;

// Create processor with ProtoWallet (crypto-only operations)
let wallet = ProtoWallet::new(Some(private_key));
let processor = WalletWireProcessor::new(wallet);

// Or create with custom network/version
let processor = WalletWireProcessor::with_config(
    wallet,
    Network::Testnet,
    "1.0.0"
);

// Access processor properties
let network = processor.network();     // Network::Testnet
let version = processor.version();     // "1.0.0"
let wallet_ref = processor.wallet();   // &ProtoWallet

// Process incoming request
let response = processor.process_message(&request_bytes).await?;

// Can also use with any WalletInterface implementor
struct MyFullWallet { /* ... */ }
impl WalletInterface for MyFullWallet { /* all 28 methods */ }

let full_wallet = MyFullWallet::new();
let processor = WalletWireProcessor::new(full_wallet);
```

### Client-Side (Transceiver)

```rust
use bsv_sdk::wallet::wire::{WalletWire, WalletWireTransceiver};
use bsv_sdk::wallet::{GetPublicKeyArgs, Protocol, SecurityLevel, Counterparty};

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
let transceiver = WalletWireTransceiver::new(wire);

// Access the wire transport
let wire_ref = transceiver.wire();

// Make wallet calls - get a derived public key
let result = transceiver.get_public_key(
    GetPublicKeyArgs {
        identity_key: false,  // Derive from protocol/key_id
        protocol_id: Some(Protocol::new(SecurityLevel::App, "my app")),
        key_id: Some("key-1".to_string()),
        counterparty: Some(Counterparty::Self_),
        for_self: Some(true),
    },
    "app.example.com"
).await?;

// Or get the identity public key
let identity_key = transceiver.get_public_key(
    GetPublicKeyArgs {
        identity_key: true,
        protocol_id: None,
        key_id: None,
        counterparty: None,
        for_self: None,
    },
    "app.example.com"
).await?;
```

### Direct Encoding

```rust
use bsv_sdk::wallet::wire::{WireReader, WireWriter};
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

## Complex Type Encoding

The encoding module supports many wallet-specific types:

### WireReader Methods

**Basic Types:**
| Method | Returns | Description |
|--------|---------|-------------|
| `read_u8()` / `read_i8()` | `u8` / `i8` | Single byte |
| `read_u16_le()` / `read_u32_le()` / `read_u64_le()` | integers | Little-endian |
| `read_var_int()` | `u64` | Unsigned varint |
| `read_signed_var_int()` | `i64` | ZigZag-encoded signed varint |
| `read_bytes(len)` | `&[u8]` | Fixed-length bytes |
| `read_remaining()` | `&[u8]` | All remaining bytes |

**Wire Protocol Types:**
| Method | Returns | Description |
|--------|---------|-------------|
| `read_string()` | `String` | Length-prefixed UTF-8 |
| `read_optional_string()` | `Option<String>` | -1 = None |
| `read_optional_bytes()` | `Option<Vec<u8>>` | -1 = None |
| `read_string_array()` | `Vec<String>` | Count + strings |
| `read_optional_bool()` | `Option<bool>` | -1=None, 0=false, 1=true |
| `read_outpoint()` | `Outpoint` | 32-byte txid + varint vout |
| `read_counterparty()` | `Option<Counterparty>` | Sentinel or 33-byte pubkey |
| `read_protocol_id()` | `Protocol` | Security level + name |
| `read_optional_protocol_id()` | `Option<Protocol>` | 255 = None |
| `read_action_status()` | `Option<ActionStatus>` | Status code (1-8 or -1) |
| `read_query_mode()` | `QueryMode` | Any (0) or All (1) |
| `read_output_include()` | `OutputInclude` | Locking scripts or full tx |
| `read_string_map()` | `HashMap<String, String>` | Key-value pairs |
| `read_send_with_result()` | `SendWithResult` | Txid + status |
| `read_sign_action_spend()` | `SignActionSpend` | Unlocking script + sequence |
| `read_sign_action_spends()` | `HashMap<u32, SignActionSpend>` | Index -> spend map |
| `read_wallet_certificate()` | `WalletCertificate` | Certificate with fields |
| `read_identity_certifier()` | `IdentityCertifier` | Certifier info |
| `read_identity_certificate()` | `IdentityCertificate` | Full identity cert |
| `read_wallet_payment()` | `WalletPayment` | Payment derivation info |
| `read_basket_insertion()` | `BasketInsertion` | Basket + tags |
| `read_internalize_output()` | `InternalizeOutput` | Output with remittance |
| `read_wallet_action_input()` | `WalletActionInput` | Action input |
| `read_wallet_action_output()` | `WalletActionOutput` | Action output |
| `read_wallet_action()` | `WalletAction` | Full action with inputs/outputs |
| `read_wallet_output()` | `WalletOutput` | Output with metadata |

### WireWriter Methods

All reader methods have corresponding writer methods with matching signatures:
- Basic: `write_u8()`, `write_i8()`, `write_u16_le()`, `write_u32_le()`, `write_u64_le()`, `write_var_int()`, `write_signed_var_int()`, `write_bytes()`
- Strings: `write_string()`, `write_optional_string()`, `write_string_array()`, `write_optional_string_array()`
- Protocol: `write_outpoint()`, `write_counterparty()`, `write_protocol_id()`, `write_optional_protocol_id()`
- Status: `write_action_status()`, `write_query_mode()`, `write_optional_query_mode()`, `write_output_include()`, `write_optional_output_include()`
- Maps: `write_string_map()`, `write_optional_string_map()`
- Actions: `write_send_with_result()`, `write_send_with_result_array()`, `write_sign_action_spend()`, `write_sign_action_spends()`
- Certificates: `write_wallet_certificate()`, `write_optional_wallet_certificate()`, `write_identity_certifier()`, `write_identity_certificate()`
- Outputs: `write_wallet_payment()`, `write_basket_insertion()`, `write_internalize_output()`, `write_wallet_action_input()`, `write_wallet_action_output()`, `write_wallet_action()`, `write_wallet_output()`

## Implemented Methods

### Processor (Server-Side)

The `WalletWireProcessor<W>` is generic over `W: WalletInterface`. With `ProtoWallet`, the following operations are fully implemented:

**Crypto Operations (delegated to wallet):**
- [x] getPublicKey
- [x] encrypt / decrypt
- [x] createHmac / verifyHmac
- [x] createSignature / verifySignature
- [x] revealCounterpartyKeyLinkage / revealSpecificKeyLinkage

**Status/Chain Operations:**
- [x] isAuthenticated (delegates to wallet)
- [x] waitForAuthentication (delegates to wallet)
- [x] getHeight (delegates to wallet)
- [x] getHeaderForHeight (delegates to wallet)
- [x] getNetwork (uses processor's configured network)
- [x] getVersion (uses processor's configured version)

**Requires full wallet implementation** (returns error with ProtoWallet):
- createAction, signAction, abortAction
- listActions, internalizeAction
- listOutputs, relinquishOutput
- acquireCertificate, listCertificates, proveCertificate, relinquishCertificate
- discoverByIdentityKey, discoverByAttributes

### Transceiver (Client-Side)

The `WalletWireTransceiver` implements serialization for ALL 28 methods:

**Key Operations:** getPublicKey, encrypt, decrypt, createHmac, verifyHmac, createSignature, verifySignature

**Action Operations:** createAction, signAction, abortAction, listActions, internalizeAction

**Output Operations:** listOutputs, relinquishOutput

**Certificate Operations:** acquireCertificate, listCertificates, proveCertificate, relinquishCertificate

**Discovery Operations:** discoverByIdentityKey, discoverByAttributes

**Chain Operations:** getHeight, getNetwork, getVersion, getHeader (getHeaderForHeight)

**Auth Operations:** isAuthenticated, waitForAuthentication

**Key Linkage:** revealCounterpartyKeyLinkage, revealSpecificKeyLinkage

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

## WalletCall Enum

The `WalletCall` enum provides type-safe call codes with helper methods:

```rust
#[repr(u8)]
pub enum WalletCall {
    CreateAction = 1,
    SignAction = 2,
    // ... through GetVersion = 28
}

impl WalletCall {
    pub fn as_u8(self) -> u8;
    pub fn method_name(self) -> &'static str;  // e.g., "createAction"
}

impl TryFrom<u8> for WalletCall { /* ... */ }
impl Display for WalletCall { /* ... */ }
```

## Public Exports

```rust
// From mod.rs
pub use calls::WalletCall;
pub use encoding::{WireReader, WireWriter};
pub use processor::WalletWireProcessor;
pub use transceiver::WalletWireTransceiver;

#[async_trait]
pub trait WalletWire: Send + Sync {
    async fn transmit_to_wallet(&self, message: &[u8]) -> Result<Vec<u8>, Error>;
}

pub mod counterparty_codes {
    pub const UNDEFINED: u8 = 0;
    pub const SELF: u8 = 11;
    pub const ANYONE: u8 = 12;
}

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

## WalletWireProcessor Configuration

The processor can be configured with network and version:

```rust
// Default configuration (mainnet, "0.1.0")
let processor = WalletWireProcessor::new(wallet);

// Custom configuration
let processor = WalletWireProcessor::with_config(
    wallet,
    Network::Testnet,
    "2.0.0-beta"
);
```

## Dependencies

- `async-trait` - For async trait methods in `WalletWire`
- Internal: `primitives::encoding::{Reader, Writer}` for base serialization
- Internal: `wallet::types` for all wallet type definitions (Outpoint, Counterparty, Protocol, etc.)

## Related Documentation

- `../CLAUDE.md` - Wallet module documentation
- `../interface.rs` - WalletInterface trait definition
- `../types.rs` - Core wallet type definitions
- `../proto_wallet.rs` - ProtoWallet implementation
- `../../primitives/encoding/` - Base Reader/Writer
