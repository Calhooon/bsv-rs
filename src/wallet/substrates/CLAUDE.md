# Wallet Substrates Module
> HTTP transport substrates for wallet communication

## Overview

This module provides transport substrates for communicating with BSV wallets over HTTP. Substrates implement the [`WalletWire`] trait or provide direct method implementations, handling the actual network communication.

## Files

| File | Purpose | Lines |
|------|---------|-------|
| `mod.rs` | Module root, constants, re-exports | ~64 |
| `http_wire.rs` | Binary wire protocol over HTTP | ~238 |
| `http_json.rs` | JSON API over HTTP | ~811 |
| `CLAUDE.md` | This documentation | ~260 |

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

Binary wire protocol transport over HTTP. Implements the `WalletWire` trait.

### Constructors

```rust
// Basic constructor with optional originator and base URL
HttpWalletWire::new(originator: Option<String>, base_url: Option<String>) -> Self

// Constructor with custom reqwest::Client for timeouts, TLS, proxies
HttpWalletWire::with_client(client: Client, originator: Option<String>, base_url: Option<String>) -> Self
```

### Accessors

- `base_url(&self) -> &str` - Returns the base URL
- `originator(&self) -> Option<&str>` - Returns the originator

### Usage

```rust
use bsv_rs::wallet::substrates::HttpWalletWire;
use bsv_rs::wallet::wire::WalletWireTransceiver;

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
- **Headers**: `Origin` header set from originator (converted to URL format)
- **Body**: Raw binary payload (excluding call code and originator)

### Wire Message Parsing

The wire extracts the call name and originator from the binary message:

```
[call_code: 1 byte][originator_len: 1 byte][originator: N bytes][payload: ...]
```

The call code maps to endpoint names via `WalletCall::method_name()`.

## HttpWalletJson

JSON API transport over HTTP. Provides direct method implementations rather than implementing `WalletWire`.

### Constructors

```rust
// Basic constructor with optional originator and base URL
HttpWalletJson::new(originator: Option<String>, base_url: Option<String>) -> Self

// Constructor with custom reqwest::Client for timeouts, TLS, proxies
HttpWalletJson::with_client(client: Client, originator: Option<String>, base_url: Option<String>) -> Self
```

### Accessors

- `base_url(&self) -> &str` - Returns the base URL
- `originator(&self) -> Option<&str>` - Returns the originator

### Usage

```rust
use bsv_rs::wallet::substrates::HttpWalletJson;
use bsv_rs::wallet::{GetPublicKeyArgs, Protocol, SecurityLevel};

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
- **Headers**: `Originator` header set from originator (converted to URL format)
- **Body**: JSON-encoded method arguments

### Implemented Methods

**Cryptographic Methods:**
- `get_public_key` - Get wallet public key (identity or derived)
- `encrypt` / `decrypt` - Encrypt/decrypt data with derived keys
- `create_hmac` / `verify_hmac` - Create/verify HMACs
- `create_signature` / `verify_signature` - Create/verify ECDSA signatures

**Wallet Status Methods:**
- `is_authenticated` - Check authentication status
- `wait_for_authentication` - Wait until authenticated
- `get_height` - Get current block height
- `get_network` - Get network (mainnet/testnet)
- `get_version` - Get wallet version string

**Action Methods:**
- `create_action` - Create a new transaction action
- `sign_action` - Sign a previously created action
- `abort_action` - Abort an in-progress action
- `list_actions` - List wallet actions (transactions)
- `internalize_action` - Internalize an external transaction

**Output Methods:**
- `list_outputs` - List wallet outputs
- `relinquish_output` - Relinquish an output from a basket

**Certificate Methods:**
- `acquire_certificate` - Acquire a certificate
- `list_certificates` - List certificates
- `prove_certificate` - Prove a certificate
- `relinquish_certificate` - Relinquish a certificate

**Discovery Methods:**
- `discover_by_identity_key` - Discover certificates by identity key
- `discover_by_attributes` - Discover certificates by attributes

**Chain Methods:**
- `get_header` - Get a block header for a given height

### Binary Data Encoding

Binary data in JSON requests/responses uses base64 encoding:
- `plaintext`, `ciphertext`, `data` - base64
- `hmac`, `signature` - base64
- `hash_to_directly_sign`, `hash_to_directly_verify` - hex (32 bytes)
- `public_key` - hex (33 bytes compressed)

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
bsv-rs = { version = "0.3", features = ["wallet", "http"] }
```

## Error Handling

Substrates return `Error::WalletError` for:
- Empty or malformed messages (HttpWalletWire)
- HTTP request failures
- Non-2xx status codes
- JSON parsing errors (HttpWalletJson)
- Invalid response data (base64 decoding, wrong HMAC length, etc.)

JSON error responses are parsed to extract error codes and descriptions. The wallet server may return structured error responses with `code` and `description` fields.

## Originator Handling

Both substrates convert the originator string to an HTTP origin header:
- If originator starts with `http://` or `https://`, use as-is
- Otherwise, prepend `http://` (e.g., `example.com` → `http://example.com`)

The originator can be set:
1. At construction time (applies to all requests)
2. Per-request (extracted from wire message or passed to method)

Per-request originator takes precedence over constructor originator.

## Testing

Run substrate tests:

```bash
cargo test wallet::substrates --features "wallet http"
```

Tests cover:
- Origin header conversion
- Default and custom URL handling
- Originator accessor methods
- Protocol and counterparty JSON serialization

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
