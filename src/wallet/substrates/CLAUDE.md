# Wallet Substrates Module
> HTTP transport substrates for wallet communication

## Overview

This module provides transport substrates for communicating with BSV wallets over HTTP. Substrates implement the [`WalletWire`] trait or provide direct method implementations, handling the actual network communication.

## Files

| File | Purpose | Lines |
|------|---------|-------|
| `mod.rs` | Module root, constants, re-exports | ~60 |
| `http_wire.rs` | Binary wire protocol over HTTP | ~200 |
| `http_json.rs` | JSON API over HTTP | ~500 |
| `CLAUDE.md` | This documentation | ~200 |

## Available Substrates

| Substrate | Protocol | Default Port | Use Case |
|-----------|----------|--------------|----------|
| `HttpWalletWire` | Binary | 3301 | High performance, low overhead |
| `HttpWalletJson` | JSON | 3321 | Debugging, simple integration |

## Platform-Specific Substrates (Not Included)

The following TypeScript SDK substrates are NOT included in the Rust SDK:

| Substrate | Reason |
|-----------|--------|
| `XDM` | Requires browser `window.parent.postMessage()` API |
| `ReactNativeWebView` | Requires React Native bridge |
| `WindowCWI` | Requires browser extension injection |

**Rationale**: These substrates require a JavaScript browser/WebView runtime with the `window` global, which doesn't exist in native Rust code. The Go SDK also excludes these for the same reason.

## HttpWalletWire

Binary wire protocol transport over HTTP.

### Usage

```rust
use bsv_sdk::wallet::substrates::HttpWalletWire;
use bsv_sdk::wallet::wire::WalletWireTransceiver;

// Create wire transport
let wire = HttpWalletWire::new(
    Some("myapp.example.com".into()),
    None, // Uses default http://localhost:3301
);

// Wrap with transceiver for wallet operations
let wallet = WalletWireTransceiver::new(wire);

// Make wallet calls
let version = wallet.get_version("myapp.example.com").await?;
```

### HTTP Request Format

- **Method**: POST
- **URL**: `{base_url}/{call_name}` (e.g., `http://localhost:3301/getPublicKey`)
- **Content-Type**: `application/octet-stream`
- **Headers**: `Origin` header set from originator
- **Body**: Raw binary payload (excluding call code and originator)

### Wire Message Parsing

The wire extracts the call name and originator from the binary message:

```
[call_code: 1 byte][originator_len: 1 byte][originator: N bytes][payload: ...]
```

The call code maps to endpoint names via `WalletCall::as_str()`.

## HttpWalletJson

JSON API transport over HTTP.

### Usage

```rust
use bsv_sdk::wallet::substrates::HttpWalletJson;
use bsv_sdk::wallet::{GetPublicKeyArgs, Protocol, SecurityLevel};

let client = HttpWalletJson::new(
    Some("myapp.example.com".into()),
    None, // Uses default http://localhost:3321
);

let result = client.get_public_key(
    GetPublicKeyArgs {
        identity_key: true,
        protocol_id: None,
        key_id: None,
        counterparty: None,
        for_self: None,
    },
    "myapp.example.com",
).await?;
```

### HTTP Request Format

- **Method**: POST
- **URL**: `{base_url}/{method_name}` (e.g., `http://localhost:3321/getPublicKey`)
- **Content-Type**: `application/json`
- **Headers**: `Originator` header set from originator
- **Body**: JSON-encoded method arguments

### Implemented Methods

- `get_public_key`
- `encrypt`
- `decrypt`
- `create_hmac`
- `verify_hmac`
- `create_signature`
- `verify_signature`
- `is_authenticated`
- `get_height`
- `get_network`
- `get_version`

### Binary Data Encoding

Binary data in JSON requests/responses uses base64 encoding:
- `plaintext`, `ciphertext`, `data` - base64
- `hmac`, `signature` - base64
- `hash_to_directly_sign`, `hash_to_directly_verify` - hex (32 bytes)
- `public_key` - hex (33 bytes compressed)

## WalletClient

The [`WalletClient`] provides a unified interface with auto-detection.

### Usage

```rust
use bsv_sdk::wallet::{WalletClient, SubstrateType};
use bsv_sdk::wallet::{GetPublicKeyArgs, Protocol, SecurityLevel};

// Create client with auto-detection
let mut client = WalletClient::new(SubstrateType::Auto, Some("myapp.example.com".into()));

// First call triggers auto-detection
let version = client.get_version().await?;

// Subsequent calls use the detected substrate
let result = client.get_public_key(GetPublicKeyArgs {
    identity_key: true,
    protocol_id: None,
    key_id: None,
    counterparty: None,
    for_self: None,
}).await?;
```

### Substrate Types

| Type | Description |
|------|-------------|
| `Auto` | Auto-detect available substrate |
| `JsonApi` | HTTP JSON API (http://localhost:3321) |
| `Cicada` | Wire protocol over HTTP (http://localhost:3301) |
| `SecureJsonApi` | Secure JSON API (https://localhost:2121) |

### Auto-Detection Order

1. Secure JSON API (https://localhost:2121)
2. Standard JSON API (http://localhost:3321)
3. Wire protocol (http://localhost:3301)

Detection works by calling `getVersion` on each substrate until one responds.

## Constants

```rust
pub const DEFAULT_WIRE_PORT: u16 = 3301;
pub const DEFAULT_JSON_PORT: u16 = 3321;
pub const DEFAULT_WIRE_URL: &str = "http://localhost:3301";
pub const DEFAULT_JSON_URL: &str = "http://localhost:3321";
pub const SECURE_JSON_URL: &str = "https://localhost:2121";
```

## Feature Flag

All substrate implementations require the `http` feature:

```toml
[dependencies]
bsv-sdk = { version = "0.2", features = ["wallet", "http"] }
```

## Error Handling

Substrates return `Error::WalletError` for:
- HTTP request failures
- Non-2xx status codes
- JSON parsing errors
- Invalid response data

Error responses from the wallet include error codes:
- Code 0: Success
- Code 5: Review actions required
- Code 6: Invalid parameter
- Code 7: Insufficient funds

## Testing

Run substrate tests:

```bash
cargo test wallet::substrates --features "wallet http"
```

Note: Integration tests require a running wallet server.

## Cross-SDK Compatibility

The substrates are compatible with:
- [TypeScript SDK](https://github.com/bitcoin-sv/ts-sdk) wallet servers
- [Go SDK](https://github.com/bitcoin-sv/go-sdk) wallet servers

Both JSON and wire protocols use identical message formats across SDKs.

## Related Documentation

- `../wire/CLAUDE.md` - Wire protocol documentation
- `../CLAUDE.md` - Wallet module documentation
- `../../CLAUDE.md` - Project root documentation
